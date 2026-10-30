use std::{cell::RefCell, collections::HashMap, rc::Rc, sync::OnceLock};

#[cfg(feature = "use-node")]
use dioxus::prelude::{ReadableExt, Signal, WritableExt};
use freenet_mail_wire_v1::aft::{TokenAllocationSummary, TokenDelegateMessage};
use freenet_stdlib::client_api::{ClientError, ClientRequest, HostResponse};
use futures::SinkExt;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::DynError;
use crate::app::ContractType;

type ClientRequester = UnboundedSender<ClientRequest<'static>>;
type HostResponses = UnboundedReceiver<Result<HostResponse, ClientError>>;

pub(crate) type NodeResponses = UnboundedSender<AsyncActionResult>;

pub(crate) static WEB_API_SENDER: OnceLock<WebApiRequestClient> = OnceLock::new();

#[cfg(feature = "use-node")]
struct WebApi {
    requests: UnboundedReceiver<ClientRequest<'static>>,
    host_responses: HostResponses,
    client_errors: UnboundedReceiver<AsyncActionResult>,
    send_half: ClientRequester,
    error_sender: NodeResponses,
    api: freenet_stdlib::client_api::WebApi,
    connecting: Option<futures::channel::oneshot::Receiver<()>>,
}

#[cfg(not(feature = "use-node"))]
struct WebApi {}

impl WebApi {
    #[cfg(not(feature = "use-node"))]
    fn new() -> Result<Self, String> {
        Ok(Self {})
    }

    #[cfg(all(not(target_family = "wasm"), feature = "use-node"))]
    fn new() -> Result<Self, String> {
        unimplemented!()
    }

    #[cfg(all(target_family = "wasm", feature = "use-node"))]
    fn new() -> Result<Self, String> {
        use futures::SinkExt;
        // Derive the WebSocket URL from the current document origin so the
        // app talks to whichever gateway served it (production, local
        // sandbox, alt-port test node). The Freenet gateway shell rejects
        // `ws://localhost:7509` when served from `http://127.0.0.1:7509`
        // (origin equality check on `host`, not just port), so a hardcoded
        // host breaks the moment the user opens the page by IP instead of
        // by hostname (or vice versa).
        let location = web_sys::window()
            .ok_or_else(|| "no window".to_string())?
            .location();
        let host = location
            .host()
            .map_err(|e| format!("location.host: {e:?}"))?;
        let scheme = match location
            .protocol()
            .map_err(|e| format!("location.protocol: {e:?}"))?
            .as_str()
        {
            "https:" => "wss",
            _ => "ws",
        };
        // GlobalSettings.advanced.custom_relay overrides the default
        // gateway-served WS endpoint. Empty string disables the override.
        let advanced = crate::local_state::global_settings().advanced;
        let url = if advanced.custom_relay && !advanced.custom_relay_url.trim().is_empty() {
            advanced.custom_relay_url.trim().to_string()
        } else {
            format!("{scheme}://{host}/v1/contract/command?encodingProtocol=native")
        };
        let conn = web_sys::WebSocket::new(&url).unwrap();
        let (send_host_responses, host_responses) = futures::channel::mpsc::unbounded();
        let (send_half, requests) = futures::channel::mpsc::unbounded();
        let result_handler = move |result: Result<HostResponse, ClientError>| {
            let mut send_host_responses_clone = send_host_responses.clone();
            let _ = wasm_bindgen_futures::future_to_promise(async move {
                send_host_responses_clone
                    .send(result)
                    .await
                    .expect("channel open");
                Ok(wasm_bindgen::JsValue::NULL)
            });
        };
        let (tx, rx) = futures::channel::oneshot::channel();
        let onopen_handler = move || {
            let _ = tx.send(());
            crate::log::debug!("connected to websocket");
        };
        let api = freenet_stdlib::client_api::WebApi::start(
            conn,
            result_handler,
            |err| {
                crate::log::error(format!("host error: {err}"), None);
            },
            onopen_handler,
        );
        let (error_sender, client_errors) = futures::channel::mpsc::unbounded();

        Ok(Self {
            requests,
            host_responses,
            client_errors,
            send_half,
            error_sender,
            api,
            connecting: Some(rx),
        })
    }

    #[cfg(feature = "use-node")]
    fn sender_half(&self) -> WebApiRequestClient {
        WebApiRequestClient {
            sender: self.send_half.clone(),
            responses: self.error_sender.clone(),
        }
    }

    #[cfg(not(feature = "use-node"))]
    fn sender_half(&self) -> WebApiRequestClient {
        WebApiRequestClient
    }
}

#[cfg(feature = "use-node")]
#[derive(Clone, Debug)]
pub(crate) struct WebApiRequestClient {
    sender: ClientRequester,
    responses: NodeResponses,
}

#[cfg(not(feature = "use-node"))]
#[derive(Clone, Debug)]
pub(crate) struct WebApiRequestClient;

// The error type is freenet-stdlib's own; boxing it here would only move
// the size into every caller's `map_err`.
#[allow(clippy::result_large_err)]
impl WebApiRequestClient {
    #[cfg(feature = "use-node")]
    pub async fn send(
        &mut self,
        request: freenet_stdlib::client_api::ClientRequest<'static>,
    ) -> Result<(), freenet_stdlib::client_api::Error> {
        self.sender
            .send(request)
            .await
            .map_err(|_| freenet_stdlib::client_api::Error::ChannelClosed)?;
        self.sender.flush().await.unwrap();
        Ok(())
    }

    #[cfg(not(feature = "use-node"))]
    pub async fn send(
        &mut self,
        request: freenet_stdlib::client_api::ClientRequest<'static>,
    ) -> Result<(), freenet_stdlib::client_api::Error> {
        tracing::debug!(?request, "emulated request");
        Ok(())
    }
}

#[cfg(feature = "use-node")]
impl From<WebApiRequestClient> for NodeResponses {
    fn from(val: WebApiRequestClient) -> Self {
        val.responses
    }
}

#[cfg(not(feature = "use-node"))]
impl From<WebApiRequestClient> for NodeResponses {
    fn from(_val: WebApiRequestClient) -> Self {
        unimplemented!()
    }
}

/// #260: pop the awaiting-ack entry whose key matches `acked`, returning its
/// alias. Shared by the inbox and AFT `PutResponse` handlers — when a
/// migration re-PUT is acknowledged, this is how the handler finds which
/// alias's pending-migration marker to clear. Returns `None` if the acked key
/// isn't a migration we're tracking (the common case: ordinary create PUTs).
#[cfg(feature = "use-node")]
fn take_awaiting_ack(
    awaiting: &mut Vec<(std::rc::Rc<str>, freenet_stdlib::prelude::ContractKey)>,
    acked: &freenet_stdlib::prelude::ContractKey,
) -> Option<std::rc::Rc<str>> {
    let pos = awaiting.iter().position(|(_, k)| k == acked)?;
    Some(awaiting.remove(pos).0)
}

/// True if `key` addresses an AFT token-allocation-record contract under
/// the current or any legacy code hash. Used as a race-safe backstop in the
/// UpdateNotification arm: own-AFT-record echoes (enabled by the #288
/// GET-with-subscribe) are normally recognized via the `token_rec_to_id`
/// routing map, but an echo that arrives before `AftRecords::load_all`
/// inserts the key would otherwise be misclassified as an unknown contract
/// (#204). The record's `code_hash` is shared by every identity's AFT
/// record, so this can't distinguish own from foreign — but the only AFT
/// records this client subscribes to are its own, so a code-hash match is a
/// sufficient and safe drop condition.
#[cfg(feature = "use-node")]
fn is_own_aft_record_key(key: &freenet_stdlib::prelude::ContractKey) -> bool {
    let key_hash = bs58::encode(key.code_hash().as_ref()).into_string();
    key_hash == crate::aft::TOKEN_RECORD_CODE_HASH
        || crate::aft::LEGACY_TOKEN_RECORD_CODE_HASHES
            .iter()
            .any(|h| *h == key_hash)
}

/// How a `ContractResponse::NotFound` should be handled, decided purely from
/// which routing table the not-found key belongs to. Kept separate from the
/// (async, thread-local-touching) arm so the priority ordering is unit
/// testable without a live node — see `notfound_routing` tests.
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(not(feature = "use-node"), allow(dead_code))]
enum NotFoundRoute {
    /// Key is a pending contact-import fetch: resolve the modal with a
    /// failure immediately instead of waiting out the 30s GET timeout.
    ContactImport,
    /// Key is this client's own inbox: reconstruct + re-PUT to self-heal an
    /// inbox that fell off the network (#288).
    OwnInbox,
    /// Key is this client's own AFT token-allocation-record: same self-heal.
    OwnAftRecord,
    /// Not attributable to any of the above — log quietly, do not re-PUT.
    Unattributed,
}

/// Pure routing decision for a NotFound. The three sources are mutually
/// exclusive in practice, so the order encodes priority: import first
/// (cheapest, definitive), then own-inbox, then own-AFT, else unattributed.
#[cfg_attr(not(feature = "use-node"), allow(dead_code))]
fn classify_notfound(
    in_import_pending: bool,
    is_own_inbox: bool,
    is_own_aft: bool,
) -> NotFoundRoute {
    if in_import_pending {
        NotFoundRoute::ContactImport
    } else if is_own_inbox {
        NotFoundRoute::OwnInbox
    } else if is_own_aft {
        NotFoundRoute::OwnAftRecord
    } else {
        NotFoundRoute::Unattributed
    }
}

#[cfg(test)]
mod notfound_routing {
    use super::{NotFoundRoute, classify_notfound};

    #[test]
    fn import_pending_wins_over_everything() {
        // A pending import key can never collide with an own key in
        // practice, but priority must still favour resolving the modal.
        assert_eq!(
            classify_notfound(true, true, true),
            NotFoundRoute::ContactImport
        );
        assert_eq!(
            classify_notfound(true, false, false),
            NotFoundRoute::ContactImport
        );
    }

    #[test]
    fn own_inbox_when_not_import() {
        assert_eq!(
            classify_notfound(false, true, false),
            NotFoundRoute::OwnInbox
        );
        // Inbox takes priority over AFT if both somehow matched.
        assert_eq!(
            classify_notfound(false, true, true),
            NotFoundRoute::OwnInbox
        );
    }

    #[test]
    fn own_aft_when_only_aft() {
        assert_eq!(
            classify_notfound(false, false, true),
            NotFoundRoute::OwnAftRecord
        );
    }

    #[test]
    fn unattributed_when_no_table_owns_it() {
        // The case that previously fell through to "message not handled".
        assert_eq!(
            classify_notfound(false, false, false),
            NotFoundRoute::Unattributed
        );
    }
}

/// #191: prime a contact's inbox contract on this node (GET with subscribe),
/// so the first send to a known contact after a reload does not fail for
/// lack of the contract's parameters. Derived under the contact's advertised
/// WASM hash (#251 improvement 4), so a cross-version contact primes under
/// its real id.
#[cfg(feature = "use-node")]
pub(crate) async fn prime_contact_inbox(
    client: &mut WebApiRequestClient,
    contact: &crate::app::address_book::Contact,
) {
    match crate::app::address_book::vk_from_bytes(&contact.ml_dsa_vk_bytes) {
        Ok(vk) => {
            let code_hash = contact
                .inbox_wasm_hash
                .as_deref()
                .unwrap_or(crate::inbox::INBOX_CODE_HASH);
            match crate::inbox::inbox_key_for_with_hash(&vk, code_hash) {
                Ok(inbox_key) => {
                    let req = freenet_stdlib::client_api::ContractRequest::Get {
                        key: inbox_key.into(),
                        return_contract_code: true,
                        subscribe: true,
                        blocking_subscribe: false,
                    };
                    if let Err(e) = client.send(req.into()).await {
                        crate::log::error(
                            format!(
                                "rehydrate prime contact inbox {inbox_key} for {} failed: {e}",
                                contact.local_alias
                            ),
                            None,
                        );
                    } else {
                        crate::log::info(format!(
                            "rehydrate primed contact inbox {inbox_key} for {} (#191)",
                            contact.local_alias
                        ));
                    }
                }
                Err(e) => crate::log::error(
                    format!(
                        "rehydrate derive inbox_key for contact {}: {e}",
                        contact.local_alias
                    ),
                    None,
                ),
            }
        }
        Err(e) => crate::log::error(
            format!(
                "rehydrate decode ml_dsa_vk for contact {}: {e}",
                contact.local_alias
            ),
            None,
        ),
    }
}

#[cfg(feature = "use-node")]
mod contract_api {
    use freenet_stdlib::{client_api::ContractRequest, prelude::*};

    use super::*;

    pub(super) async fn create_contract(
        client: &mut WebApiRequestClient,
        contract_code: &[u8],
        contract_state: impl Into<Vec<u8>>,
        params: &Parameters<'static>,
    ) -> Result<ContractKey, DynError> {
        let contract = ContractContainer::try_from((contract_code.to_vec(), params))?;
        let key = contract.key();
        crate::log::debug!("putting contract {key}");
        let state = contract_state.into().into();
        // `subscribe: true` so the creating node becomes a durable
        // subscriber/holder of the contract it just PUT. Without this the PUT
        // seeds the contract at topologically-responsible peers but the
        // creator keeps no local copy, so once those peers churn the contract
        // falls off the network and every GET returns NotFound (issue #288).
        let request = ContractRequest::Put {
            contract,
            state,
            related_contracts: Default::default(),
            subscribe: true,
            blocking_subscribe: false,
        };
        client.send(request.into()).await?;
        Ok(key)
    }
}

/// Checks for the embedded artifacts: the WASM a module uploads and the
/// code hash it derives keys from must be the same artifact. Each module
/// that embeds one calls these on its own consts.
#[cfg(all(test, feature = "use-node"))]
pub(crate) mod embedded_artifact {
    use freenet_stdlib::prelude::*;

    /// A container built from `code` (as `contract_api::create_contract`
    /// builds it) has the key `code_hash` derives (as every lookup does).
    pub(crate) fn assert_contract(code: &[u8], code_hash: &str) {
        let params = Parameters::from(vec![1u8, 2, 3]);
        let container = ContractContainer::try_from((code.to_vec(), &params))
            .expect("embedded contract WASM loads");
        let key = ContractKey::from_params(code_hash, params).expect("embedded code hash decodes");
        assert_eq!(
            container.key(),
            key,
            "the embedded contract WASM does not have the embedded code hash"
        );
    }

    /// The same for a delegate (as `delegate_api::create_delegate` builds it).
    pub(crate) fn assert_delegate(code: &[u8], code_hash: &str) {
        let params = Parameters::from(vec![1u8, 2, 3]);
        let container = DelegateContainer::try_from((code.to_vec(), &params))
            .expect("embedded delegate WASM loads");
        let key = DelegateKey::from_params(code_hash, &params).expect("embedded code hash decodes");
        assert_eq!(
            *container.key(),
            key,
            "the embedded delegate WASM does not have the embedded code hash"
        );
    }
}

#[cfg(feature = "use-node")]
pub(crate) use delegate_api::{V0_2_CIPHER, V0_2_NONCE};
#[cfg(feature = "use-node")]
pub(crate) use token_generator_management::ensure_registered as ensure_token_generator_registered;

#[cfg(feature = "use-node")]
mod delegate_api {
    use freenet_stdlib::{client_api::DelegateRequest, prelude::*};

    use super::*;

    pub(crate) async fn create_delegate(
        client: &mut WebApiRequestClient,
        delegate_code_hash: &str,
        delegate_code: &[u8],
        params: &Parameters<'static>,
    ) -> Result<DelegateKey, DynError> {
        let key = DelegateKey::from_params(delegate_code_hash, params)?;
        let delegate = DelegateContainer::try_from((delegate_code.to_vec(), params))?;
        assert_eq!(&key, delegate.key());
        client.send(register_request(delegate)).await?;
        Ok(key)
    }

    /// stdlib 0.3.5's `DelegateRequest::DEFAULT_CIPHER`, which every v0.2.x
    /// client sent. stdlib 0.12 dropped the constant. Nodes since v0.2.60
    /// ignore the cipher and nonce and derive each delegate's secret key
    /// from their own key (freenet-core #4146); an older node encrypted the
    /// delegate's secrets with them, so a different value would orphan
    /// every secret it had stored.
    pub(crate) const V0_2_CIPHER: [u8; 32] = [
        0, 24, 22, 150, 112, 207, 24, 65, 182, 161, 169, 227, 66, 182, 237, 215, 206, 164, 58, 161,
        64, 108, 157, 195, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    /// stdlib 0.3.5's `DelegateRequest::DEFAULT_NONCE`; see [`V0_2_CIPHER`].
    pub(crate) const V0_2_NONCE: [u8; 24] = [
        57, 18, 79, 116, 63, 134, 93, 39, 208, 161, 156, 229, 222, 247, 111, 79, 210, 126, 127, 55,
        224, 150, 139, 80,
    ];

    fn register_request(delegate: DelegateContainer) -> ClientRequest<'static> {
        ClientRequest::DelegateOp(DelegateRequest::RegisterDelegate {
            delegate,
            cipher: V0_2_CIPHER,
            nonce: V0_2_NONCE,
        })
    }

    #[test]
    fn register_request_sends_the_v0_2_cipher_and_nonce() {
        let code = include_bytes!("../../published-contract/wasm/v1/mail_local_state");
        let params = Parameters::from(vec![1u8, 2, 3]);
        let delegate = DelegateContainer::try_from((code.to_vec(), &params)).unwrap();
        let ClientRequest::DelegateOp(DelegateRequest::RegisterDelegate { cipher, nonce, .. }) =
            register_request(delegate)
        else {
            panic!("not a RegisterDelegate");
        };
        assert_eq!(cipher, V0_2_CIPHER);
        assert_eq!(nonce, V0_2_NONCE);
    }

    /// `register_defaults_v1.txt` is stdlib 0.3.5's own DEFAULT_CIPHER and
    /// DEFAULT_NONCE, printed by `wire-v1/capture -- defaults`.
    #[test]
    fn v0_2_cipher_and_nonce_are_stdlib_0_3_5s_defaults() {
        use crate::test_util::hex;
        let fixture = include_str!("register_defaults_v1.txt");
        let field = |name: &str| {
            fixture
                .lines()
                .find_map(|l| l.strip_prefix(name)?.strip_prefix(' '))
                .unwrap()
                .to_string()
        };
        assert_eq!(hex(&V0_2_CIPHER), field("register_cipher"));
        assert_eq!(hex(&V0_2_NONCE), field("register_nonce"));
    }
}

/// Decode an import-fetch `GetResponse` into an
/// `ImportFetchOutcome`. Pulls the recipient's ML-DSA vk from the
/// contract's parameters, the ek + tier policy from the inbox state,
/// and the inbox WASM code hash from the response's contract key.
#[cfg(feature = "use-node")]
fn decode_import_fetch(
    contract: &Option<freenet_stdlib::prelude::ContractContainer>,
    state: &[u8],
    key: &freenet_stdlib::prelude::ContractKey,
) -> contact_import::ImportFetchOutcome {
    use freenet_mail_wire_v1::inbox::{Inbox as InboxState, InboxParams};

    let parsed: InboxState = match serde_json::from_slice(state) {
        Ok(v) => v,
        Err(e) => {
            return contact_import::ImportFetchOutcome::Failed(format!("decode inbox state: {e}"));
        }
    };
    let container = match contract.as_ref() {
        Some(c) => c,
        None => {
            return contact_import::ImportFetchOutcome::Failed(
                "GetResponse missing contract container (return_contract_code wasn't honored?)"
                    .into(),
            );
        }
    };
    let params: InboxParams = match InboxParams::try_from(container.params()) {
        Ok(p) => p,
        Err(e) => {
            return contact_import::ImportFetchOutcome::Failed(format!("decode InboxParams: {e}"));
        }
    };
    if parsed.owner_ek_bytes.is_empty() {
        return contact_import::ImportFetchOutcome::Failed(
            "recipient inbox is missing ek (legacy state pre-#249)".into(),
        );
    }
    // #251 improvement 4: capture the recipient's inbox WASM code
    // hash from the GetResponse key so the sender can derive the
    // recipient's inbox `ContractKey` against the recipient's hash
    // (not the sender's embedded `INBOX_CODE_HASH`) at send time.
    //
    // Encoded with a plain `bs58::encode` (no `to_lowercase`) so the
    // string roundtrips through `ContractKey::from_params` cleanly.
    // `CodeHash::encode` would lowercase the output, which then fails
    // bs58 decode back to the original bytes.
    let inbox_wasm_hash = bs58::encode(key.code_hash().as_ref())
        .with_alphabet(bs58::Alphabet::BITCOIN)
        .into_string();
    contact_import::ImportFetchOutcome::Ok {
        ml_dsa_vk_bytes: params.pub_key,
        ml_kem_ek_bytes: parsed.owner_ek_bytes,
        required_tier: parsed.settings.minimum_tier,
        max_age_secs: parsed.settings.max_age_secs,
        inbox_wasm_hash,
    }
}

/// State for the address → pubkey fetch driven by the Import Contact
/// modal. The modal pastes a bs58 inbox address, the api dispatcher
/// issues a `Get` against that contract, and the `GetResponse` arm
/// drops the deserialized `Inbox` here for the modal to read.
///
/// Lives outside `inbox_management` because the modal and the
/// GetResponse handler both need to touch it, and `inbox_management`
/// is `use-node` gated.
pub(crate) mod contact_import {
    use std::cell::RefCell;
    use std::collections::HashMap;

    use freenet_stdlib::prelude::ContractInstanceId;

    /// What the modal sees after a fetch completes. The bs58 address
    /// the modal asked for is the lookup key in `RESULTS`, so it's
    /// not duplicated on the value.
    #[derive(Clone, Debug)]
    pub struct ImportFetched {
        pub outcome: ImportFetchOutcome,
    }

    #[derive(Clone, Debug)]
    pub enum ImportFetchOutcome {
        /// Inbox state arrived. Carries the raw vk + ek bytes ready for
        /// `StoredContactKeys::from_inbox_state`-style construction.
        Ok {
            ml_dsa_vk_bytes: Vec<u8>,
            ml_kem_ek_bytes: Vec<u8>,
            required_tier: freenet_mail_wire_v1::aft::Tier,
            max_age_secs: u64,
            /// bs58-encoded inbox contract WASM code hash, captured
            /// from the GetResponse's `key.code_hash()` at import time
            /// (#251 improvement 4). The sender uses this hash —
            /// rather than its own embedded `INBOX_CODE_HASH` — to
            /// derive the recipient's inbox `ContractKey` when sending,
            /// so a non-upgraded recipient still receives messages
            /// from an upgraded sender. The recipient advertised this
            /// hash implicitly by publishing under the corresponding
            /// contract id; capturing the wire value avoids any
            /// schema bump on the user-facing `ContactCard`.
            inbox_wasm_hash: String,
        },
        /// Fetch failed (network error, contract unknown, malformed state, etc.).
        Failed(String),
    }

    thread_local! {
        /// Latest fetch result keyed by the bs58 inbox address the modal
        /// requested. The modal polls this in a `use_future` after
        /// dispatching `NodeAction::FetchContactKeys`.
        pub(crate) static RESULTS: RefCell<HashMap<String, ImportFetched>> =
            RefCell::new(HashMap::new());

        /// Inbox contract instance ids we've dispatched a Get for on
        /// behalf of the modal. Used by the GetResponse arm to recognise
        /// the response and route it here (vs the inbox-owner /
        /// migration paths). Maps the instance id back to the bs58
        /// address the modal used (the modal's lookup key in `RESULTS`).
        pub(crate) static PENDING: RefCell<HashMap<ContractInstanceId, String>> =
            RefCell::new(HashMap::new());
    }

    /// Drop any pending / completed entries for `addr` so closing the
    /// modal (or pasting a fresh address into the same modal) doesn't
    /// leak thread-local state across the session. Cheap to call on
    /// every modal close — no-op if nothing is registered.
    pub(crate) fn cancel(addr: &str) {
        if let Ok(id) = addr.parse::<ContractInstanceId>() {
            PENDING.with(|m| {
                m.borrow_mut().remove(&id);
            });
        }
        RESULTS.with(|m| {
            m.borrow_mut().remove(addr);
        });
    }
}

#[cfg(feature = "use-node")]
mod inbox_management {

    use freenet_stdlib::{client_api::ContractRequest, prelude::*};

    use freenet_mail_wire_v1::inbox::InboxParams;

    use super::*;

    const INBOX_CODE: &[u8] =
        include_bytes!("../../published-contract/wasm/v1/freenet_email_inbox");

    #[test]
    fn embedded_inbox_wasm_has_the_embedded_code_hash() {
        crate::api::embedded_artifact::assert_contract(INBOX_CODE, crate::inbox::INBOX_CODE_HASH);
    }

    thread_local! {
        pub(super) static CREATED_INBOX: RefCell<Vec<(Rc<str>, ContractKey)>> = const { RefCell::new(Vec::new()) };

        /// #260: migration PUTs whose network ACK we are still awaiting.
        /// `put_migrated_inbox` enqueues the re-PUT and returns immediately
        /// (the PUT is NOT yet acknowledged). The pending-migration marker
        /// on the delegate must survive until the `PutResponse` for the new
        /// key actually lands — otherwise a PUT that enqueues then never
        /// reaches the network leaves the marker cleared, the hash stamped,
        /// and the migration silently abandoned forever. Entries are
        /// `(alias, new_inbox_key)`; the `PutResponse` arm matches on the
        /// key, clears the pending marker, and removes the entry.
        pub(super) static AWAITING_MIGRATION_ACK: RefCell<Vec<(Rc<str>, ContractKey)>> =
            const { RefCell::new(Vec::new()) };

        /// #213 inbox migration: maps an OLD inbox `ContractKey` (derived
        /// with a prior `INBOX_CODE_HASH`) to the identity that owns it.
        /// On the corresponding `GetResponse`, the api.rs handler decodes
        /// the old state and PUTs it under the identity's CURRENT inbox
        /// key. Entries are removed once the migration completes (or
        /// after a timeout — currently best-effort).
        pub(super) static PENDING_MIGRATION: RefCell<HashMap<ContractKey, crate::app::Identity>> =
            RefCell::new(HashMap::new());

        /// #251 improvement 2: tracks identities whose migration is
        /// either already in-flight or completed this session, keyed by
        /// ML-DSA verifying-key bytes (NOT alias — aliases mutate via
        /// rename). Chained migration dispatches GETs against several
        /// historical inbox keys for the same identity; the entry is
        /// inserted BEFORE the PUT await so a second GetResponse
        /// arriving during the await is suppressed (closes TOCTOU). On
        /// PUT failure the entry is removed to allow retry on the next
        /// candidate response.
        pub(super) static MIGRATED_IDENTITIES: RefCell<std::collections::HashSet<Vec<u8>>> =
            RefCell::new(std::collections::HashSet::new());
    }

    /// PUT the migrated inbox state under the identity's CURRENT inbox
    /// key. Called from the GetResponse arm when a `PENDING_MIGRATION`
    /// entry resolves. Reuses `Inbox::new` to produce a freshly-signed
    /// state — the signature is over a fixed `STATE_UPDATE` salt and
    /// the identity key is unchanged, so the re-signed state validates
    /// identically.
    /// #254: decide which ML-KEM ek a migration re-PUT should advertise.
    ///
    /// The migration writer re-PUTs a prior inbox state under the current
    /// code hash. It must NOT silently overwrite an ek already published on
    /// chain — a user who re-keyed from backup between the original PUT and
    /// the migration would otherwise have the migration clobber the
    /// chain-advertised ek with a stale/new local one, breaking senders who
    /// imported the on-chain ek.
    ///
    /// - on-chain ek empty (pre-#249 legacy state) → stamp the local ek
    ///   (the migration's whole point).
    /// - on-chain ek present and equal to local → use it (no surprise).
    /// - on-chain ek present and DIFFERENT from local → preserve the
    ///   on-chain ek and surface the divergence so the user can confirm an
    ///   intended rotation (re-keying is a separate explicit action).
    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum OwnerEkChoice {
        /// Legacy state had no ek; stamp the local identity ek.
        StampLocal,
        /// On-chain ek matches local; reuse it.
        UseOnChain,
        /// On-chain ek diverges from local; preserve on-chain and warn.
        PreserveOnChainDiverged,
    }

    pub(super) fn select_owner_ek(on_chain_ek: &[u8], local_ek: &[u8]) -> OwnerEkChoice {
        if on_chain_ek.is_empty() {
            OwnerEkChoice::StampLocal
        } else if on_chain_ek == local_ek {
            OwnerEkChoice::UseOnChain
        } else {
            OwnerEkChoice::PreserveOnChainDiverged
        }
    }

    pub(super) async fn put_migrated_inbox(
        client: &mut WebApiRequestClient,
        identity: &crate::app::Identity,
        parsed: freenet_mail_wire_v1::inbox::Inbox,
    ) -> Result<ContractKey, DynError> {
        let vk = identity.ml_dsa_vk();
        let params: Parameters = InboxParams {
            pub_key: crate::inbox::inbox_params_pub_key_bytes(&vk),
        }
        .try_into()?;
        // #254: never silently overwrite an ek already on chain. Prefer the
        // on-chain ek when present; only stamp the local ek for legacy
        // (pre-#249) states that carry none. Surface a divergence so a
        // re-key is a deliberate, user-confirmed action.
        let local_ek = identity.ml_kem_ek_bytes();
        let local_ek_for_signing = local_ek.clone();
        let owner_ek_bytes = match select_owner_ek(&parsed.owner_ek_bytes, &local_ek) {
            OwnerEkChoice::StampLocal => local_ek,
            OwnerEkChoice::UseOnChain => parsed.owner_ek_bytes,
            OwnerEkChoice::PreserveOnChainDiverged => {
                crate::log::error(
                    format!(
                        "inbox migration: on-chain ek differs from local for \
                         identity=`{}` — preserving the on-chain ek. If you \
                         intended to rotate keys, use Re-key inbox (#254).",
                        identity.alias()
                    ),
                    None,
                );
                crate::toast::push_toast(
                    format!(
                        "Inbox `{}` advertises a different encryption key than \
                         this device. Keeping the published key. Re-key the \
                         inbox if you meant to rotate.",
                        identity.alias()
                    ),
                    crate::toast::ToastLevel::Warning,
                );
                parsed.owner_ek_bytes
            }
        };
        // The delegate signs with this identity's own encapsulation key
        // only, so an inbox advertising another key cannot be re-signed.
        if owner_ek_bytes != local_ek_for_signing {
            return Err("the inbox advertises a different encryption key than \
                        this identity's; it was not migrated"
                .into());
        }
        let (last_update, signature) =
            crate::inbox::sign_authority(identity.addr, &parsed.settings).await?;
        let rebuilt = freenet_mail_wire_v1::inbox::Inbox::with_signature(
            parsed.settings,
            parsed.messages,
            last_update,
            owner_ek_bytes,
            signature,
        );
        let state = rebuilt.serialize()?;
        let new_key = contract_api::create_contract(client, INBOX_CODE, state, &params).await?;
        // #260: this PUT is only ENQUEUED, not yet acked. The caller records
        // `(alias, new_key)` in AWAITING_MIGRATION_ACK and defers clearing the
        // pending-migration marker until the matching `PutResponse` lands.
        crate::log::info(format!(
            "inbox migration: PUT enqueued new_key={new_key} identity=`{}` (#213)",
            identity.alias()
        ));
        Ok(new_key)
    }

    /// Dispatch a `Get` for `identity`'s inbox under the prior contract
    /// code hash so the GetResponse arm in `node_comms` can decode the
    /// old state and PUT it under the current inbox key. Best-effort:
    /// the old contract may have been GC'd off the network; on Get
    /// failure the caller stamps the current hash anyway so subsequent
    /// reloads don't retry forever.
    pub(super) async fn migrate_inbox(
        client: &mut WebApiRequestClient,
        identity: &crate::app::Identity,
        prior_hash: &str,
    ) -> Result<(), DynError> {
        let vk = identity.ml_dsa_vk();
        let pub_key = crate::inbox::inbox_params_pub_key_bytes(&vk);

        // #251 improvement 2: chained migration. Build the candidate
        // chain via `build_migration_candidates` — always starts with
        // `prior_hash` itself, then every legacy entry that follows
        // it (or every legacy entry, if `prior_hash` is not in the
        // list — see the helper for the rationale). GET each in turn;
        // the GetResponse arm in `node_comms` picks the first one
        // that resolves and re-PUTs under the CURRENT key, suppressing
        // duplicate responses via `MIGRATED_IDENTITIES`.
        let candidates = crate::inbox::build_migration_candidates(
            prior_hash,
            crate::inbox::LEGACY_INBOX_CODE_HASHES,
        );

        for candidate in candidates {
            let params: Parameters = InboxParams {
                pub_key: pub_key.clone(),
            }
            .try_into()?;
            let old_key = ContractKey::from_params(&candidate, params)
                .map_err(|e| format!("derive old inbox key: {e}"))?;
            PENDING_MIGRATION.with(|m| {
                m.borrow_mut().insert(old_key, identity.clone());
            });
            let request = ContractRequest::Get {
                key: old_key.into(),
                return_contract_code: false,
                subscribe: false,
                blocking_subscribe: false,
            };
            client.send(request.into()).await?;
            crate::log::info(format!(
                "inbox migration: GET dispatched for old key {old_key} (identity=`{}`, hash={candidate}) (#213, #251)",
                identity.alias()
            ));
        }
        Ok(())
    }

    /// PUT `identity`'s inbox with `state`, its initial state as the mail
    /// delegate signed it (`identity_store::initial_inbox_state`).
    pub(super) async fn create_contract(
        client: &mut WebApiRequestClient,
        identity: &crate::app::Identity,
        state: Vec<u8>,
    ) -> Result<ContractKey, DynError> {
        let vk = identity.ml_dsa_vk();
        let identity_key = vk.encode().to_vec();
        let params: Parameters = InboxParams {
            pub_key: crate::inbox::inbox_params_pub_key_bytes(&vk),
        }
        .try_into()?;
        let contract_key =
            contract_api::create_contract(client, INBOX_CODE, state, &params).await?;
        super::identity_management::PENDING_CONFIRMATION.with(|pend| {
            let pend = &mut *pend.borrow_mut();
            let pend = pend.entry(identity_key).or_default();
            pend.inbox_key = Some(contract_key);
        });
        Ok(contract_key)
    }

    #[cfg(test)]
    mod tests {
        use super::{OwnerEkChoice, select_owner_ek};

        #[test]
        fn select_owner_ek_stamps_local_for_legacy_empty_254() {
            // Pre-#249 state carries no ek → migration stamps the local one.
            assert_eq!(select_owner_ek(&[], &[1, 2, 3]), OwnerEkChoice::StampLocal,);
        }

        #[test]
        fn select_owner_ek_reuses_matching_on_chain_254() {
            assert_eq!(
                select_owner_ek(&[9, 9, 9], &[9, 9, 9]),
                OwnerEkChoice::UseOnChain,
            );
        }

        #[test]
        fn select_owner_ek_preserves_diverged_on_chain_254() {
            // The bug: previously the migration silently used whichever ek
            // without flagging that the on-chain ek diverges from local.
            // A diverged on-chain ek must be preserved AND surfaced.
            assert_eq!(
                select_owner_ek(&[1, 2, 3], &[4, 5, 6]),
                OwnerEkChoice::PreserveOnChainDiverged,
            );
        }
    }
}

#[cfg(feature = "use-node")]
mod token_record_management {

    use freenet_mail_wire_v1::aft::{TokenAllocationRecord, TokenDelegateParameters};
    use freenet_stdlib::{client_api::ContractRequest, prelude::*};

    use super::*;

    const TOKEN_RECORD_CODE: &[u8] =
        include_bytes!("../../published-contract/wasm/v1/freenet_token_allocation_record");

    #[test]
    fn embedded_token_record_wasm_has_the_embedded_code_hash() {
        crate::api::embedded_artifact::assert_contract(
            TOKEN_RECORD_CODE,
            crate::aft::TOKEN_RECORD_CODE_HASH,
        );
    }

    thread_local! {
        pub(super) static CREATED_AFT_RECORD: RefCell<Vec<(Rc<str>, ContractKey)>> = const { RefCell::new(Vec::new()) };

        /// #260: AFT-record migration PUTs awaiting their network ACK.
        /// Mirror of `inbox_management::AWAITING_MIGRATION_ACK` — the pending
        /// AFT-migration marker is cleared only when the `PutResponse` for
        /// the new token-record key lands, not when the PUT is enqueued.
        pub(super) static AWAITING_AFT_MIGRATION_ACK: RefCell<Vec<(Rc<str>, ContractKey)>> =
            const { RefCell::new(Vec::new()) };

        /// #251 improvement 3 AFT migration: maps an OLD AFT-record
        /// `ContractKey` (derived with a prior `TOKEN_RECORD_CODE_HASH`)
        /// to the identity that owns it. On the corresponding
        /// `GetResponse`, the api.rs handler decodes the old state and
        /// PUTs it under the identity's CURRENT AFT-record key. Mirrors
        /// `inbox_management::PENDING_MIGRATION`.
        pub(super) static PENDING_AFT_MIGRATION: RefCell<HashMap<ContractKey, crate::app::Identity>> =
            RefCell::new(HashMap::new());

        /// Tracks identities whose AFT migration is either in-flight or
        /// completed this session, keyed by ML-DSA verifying-key bytes.
        /// Parallel to `inbox_management::MIGRATED_IDENTITIES`; closes
        /// the same TOCTOU window for the chained-candidate dispatch.
        pub(super) static MIGRATED_AFT_IDENTITIES: RefCell<std::collections::HashSet<Vec<u8>>> =
            RefCell::new(std::collections::HashSet::new());
    }

    pub(super) async fn create_contract(
        client: &mut WebApiRequestClient,
        identity: &crate::app::Identity,
    ) -> Result<ContractKey, DynError> {
        let vk = identity.ml_dsa_vk();
        let identity_key = vk.encode().to_vec();
        let params: Parameters = TokenDelegateParameters::new(&vk).try_into()?;
        let contract_key = contract_api::create_contract(
            client,
            TOKEN_RECORD_CODE,
            TokenAllocationRecord::default().serialized()?,
            &params,
        )
        .await?;
        super::identity_management::PENDING_CONFIRMATION.with(|pend| {
            let pend = &mut *pend.borrow_mut();
            let pend = pend.entry(identity_key).or_default();
            pend.aft_rec = Some(contract_key);
        });
        Ok(contract_key)
    }

    /// PUT the migrated AFT token-allocation-record state under the
    /// identity's CURRENT AFT-record key. Called from the GetResponse
    /// arm when a `PENDING_AFT_MIGRATION` entry resolves. The record's
    /// validity is tied to the identity's ML-DSA verifying key (the
    /// `TokenDelegateParameters.generator_public_key` the contract uses
    /// to verify every assignment), which is unchanged across an AFT
    /// contract bump — so the old state re-validates under the new
    /// contract id.
    ///
    /// Unlike `inbox_management::put_migrated_inbox`, the migrated
    /// state is NOT re-signed here. Inbox state carries an ML-DSA
    /// signature over `(state, params)` that has to be regenerated
    /// under the new params hash, so the inbox path calls
    /// `Inbox::new` to re-sign. AFT records carry NO contract-id-
    /// dependent signature: every `TokenAssignment` is signed by the
    /// generator-delegate key over fields that do not include the
    /// contract id, and `validate_state` only checks those per-
    /// assignment signatures. A straight re-PUT is sufficient.
    pub(super) async fn put_migrated_aft_record(
        client: &mut WebApiRequestClient,
        identity: &crate::app::Identity,
        parsed: TokenAllocationRecord,
    ) -> Result<ContractKey, DynError> {
        let vk = identity.ml_dsa_vk();
        let params: Parameters = TokenDelegateParameters::new(&vk).try_into()?;
        let state = parsed.serialized()?;
        let new_key =
            contract_api::create_contract(client, TOKEN_RECORD_CODE, state, &params).await?;
        // #260: enqueued, not acked — caller records the key and defers the
        // pending-marker clear to the matching `PutResponse`.
        crate::log::info(format!(
            "AFT migration: PUT enqueued new_key={new_key} identity=`{}` (#251)",
            identity.alias()
        ));
        Ok(new_key)
    }

    /// Dispatch a `Get` for `identity`'s AFT record under each prior
    /// `TOKEN_RECORD_CODE_HASH` so the GetResponse arm in `node_comms`
    /// can decode the old state and PUT it under the current AFT-record
    /// key. Mirrors `inbox_management::migrate_inbox`.
    pub(super) async fn migrate_aft_record(
        client: &mut WebApiRequestClient,
        identity: &crate::app::Identity,
        prior_hash: &str,
    ) -> Result<(), DynError> {
        let vk = identity.ml_dsa_vk();
        let candidates = crate::inbox::build_migration_candidates(
            prior_hash,
            crate::aft::LEGACY_TOKEN_RECORD_CODE_HASHES,
        );

        for candidate in candidates {
            let params: Parameters = TokenDelegateParameters::new(&vk).try_into()?;
            let old_key = ContractKey::from_params(&candidate, params)
                .map_err(|e| format!("derive old AFT-record key: {e}"))?;
            PENDING_AFT_MIGRATION.with(|m| {
                m.borrow_mut().insert(old_key, identity.clone());
            });
            let request = ContractRequest::Get {
                key: old_key.into(),
                return_contract_code: false,
                subscribe: false,
                blocking_subscribe: false,
            };
            client.send(request.into()).await?;
            crate::log::info(format!(
                "AFT migration: GET dispatched for old key {old_key} (identity=`{}`, hash={candidate}) (#251)",
                identity.alias()
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "use-node")]
mod token_generator_management {

    use freenet_mail_wire_v1::aft::DelegateParameters;
    use freenet_stdlib::prelude::DelegateKey;

    use super::*;

    const TOKEN_GEN_CODE_HASH: &str =
        include_str!("../../published-contract/wasm/v1/token_generator_code_hash");
    const TOKEN_GEN_CODE: &[u8] =
        include_bytes!("../../published-contract/wasm/v1/freenet_token_generator");

    #[test]
    fn embedded_token_generator_wasm_has_the_embedded_code_hash() {
        crate::api::embedded_artifact::assert_delegate(TOKEN_GEN_CODE, TOKEN_GEN_CODE_HASH);
        assert_eq!(
            TOKEN_GEN_CODE_HASH,
            crate::aft::TOKEN_GENERATOR_DELEGATE_CODE_HASH
        );
    }

    #[test]
    fn delegate_key_matches_the_v0_2_client() {
        use crate::test_util::{frozen_key, hex};
        let params: freenet_stdlib::prelude::Parameters =
            DelegateParameters::new([7; 32]).try_into().unwrap();
        let key = DelegateKey::from_params(TOKEN_GEN_CODE_HASH, &params).unwrap();
        assert_eq!(hex(key.bytes()), frozen_key("token_generator_delegate"));
    }

    thread_local! {
        pub(super) static CREATED_AFT_GEN: RefCell<Vec<(Rc<str>, DelegateKey)>> = const { RefCell::new(Vec::new()) };
        /// Token-generator delegates registered in this page session.
        static REGISTERED: RefCell<std::collections::HashSet<Vec<u8>>> =
            RefCell::new(std::collections::HashSet::new());
    }

    /// Register the token-generator delegate with `params` once per page
    /// session, just before its first use. Registering every identity's on
    /// load would make the page fetch every signing seed on every load.
    pub(crate) async fn ensure_registered(
        client: &mut WebApiRequestClient,
        params: &freenet_stdlib::prelude::Parameters<'static>,
    ) -> Result<(), DynError> {
        let key = DelegateKey::from_params(TOKEN_GEN_CODE_HASH, params)?;
        if REGISTERED.with(|r| r.borrow().contains(key.bytes())) {
            return Ok(());
        }
        delegate_api::create_delegate(client, TOKEN_GEN_CODE_HASH, TOKEN_GEN_CODE, params).await?;
        REGISTERED.with(|r| r.borrow_mut().insert(key.bytes().to_vec()));
        Ok(())
    }

    /// Register `identity`'s v1 token-generator delegate. `aft_params` are
    /// its parameters as the mail delegate gives them (`V1AftParams`, the
    /// JSON `DelegateParameters`).
    pub(super) async fn create_delegate(
        client: &mut WebApiRequestClient,
        identity: &crate::app::Identity,
        aft_params: &[u8],
    ) -> Result<DelegateKey, DynError> {
        let identity_key = identity.ml_dsa_vk_bytes();
        let params = serde_json::from_slice::<DelegateParameters>(aft_params)?.try_into()?;
        let delegate_key =
            delegate_api::create_delegate(client, TOKEN_GEN_CODE_HASH, TOKEN_GEN_CODE, &params)
                .await?;
        super::identity_management::PENDING_CONFIRMATION.with(|pend| {
            let pend = &mut *pend.borrow_mut();
            let pend = pend.entry(identity_key).or_default();
            pend.aft_gen = Some(delegate_key.clone());
        });
        Ok(delegate_key)
    }
}

/// Identities live in the mail delegate (`app::identity_store`). This tracks
/// a new identity until its inbox, AFT record and token-generator delegate
/// are published, and keeps the frozen v0.2.x identity delegate's artifacts
/// pinned for the migration from it.
#[cfg(feature = "use-node")]
mod identity_management {
    use std::cell::RefCell;
    use std::collections::HashMap;

    use freenet_stdlib::prelude::{ContractKey, DelegateKey};

    use crate::aft::AftRecords;
    use crate::app::Identity;
    use crate::inbox::InboxModel;

    use super::*;

    /// The v0.2.x identity-management delegate. Not used at runtime: its data
    /// is carried over by the migration from it.
    #[cfg(test)]
    mod frozen_v1 {
        use freenet_stdlib::prelude::*;

        const ID_MANAGER_CODE_HASH: &str =
            include_str!("../../published-contract/wasm/v1/identity_management_code_hash");
        const ID_MANAGER_CODE: &[u8] =
            include_bytes!("../../published-contract/wasm/v1/identity_management");
        const ID_MANAGER_KEY: &[u8] =
            include_bytes!("../../published-contract/wasm/v1/identity-manager-params");

        /// The committed parameters, exactly as the v0.2.x client sent them.
        fn params() -> Parameters<'static> {
            Parameters::from(ID_MANAGER_KEY.to_vec())
        }

        #[test]
        fn embedded_identity_wasm_has_the_embedded_code_hash() {
            crate::api::embedded_artifact::assert_delegate(ID_MANAGER_CODE, ID_MANAGER_CODE_HASH);
        }

        #[test]
        fn delegate_key_matches_the_v0_2_client() {
            use crate::test_util::{frozen_key, hex};
            let key = DelegateKey::from_params(ID_MANAGER_CODE_HASH, &params()).unwrap();
            assert_eq!(hex(key.bytes()), frozen_key("identity_delegate"));
        }
    }

    /// Once all three of a new identity's contracts are published, surface
    /// it as fully created.
    pub(super) async fn alias_creation(
        client: &mut WebApiRequestClient,
        identity_key: &[u8],
        token_rec_to_id: &mut HashMap<ContractKey, Identity>,
        user: Signal<crate::app::User>,
        mut login_controller: Signal<crate::app::LoginController>,
    ) {
        let Some(NewIdentity {
            identity: Some(identity),
            inbox_key: Some(inbox_key),
            aft_rec,
            ..
        }) = PENDING_CONFIRMATION.with(|pend| pend.borrow_mut().remove(identity_key))
        else {
            return;
        };
        let identity = Identity::set_alias(identity, inbox_key, user);
        crate::inbox::InboxModel::set_contract_identity(inbox_key, identity.clone());
        if let Some(aft_rec) = aft_rec {
            token_rec_to_id.insert(aft_rec, identity);
        }
        // ALIASES is a thread-local RefCell, not a Signal: bump the
        // controller so the just-created identity shows without a reload.
        login_controller.write().updated = true;

        // Bootstrap the inbox + AFT-record subscriptions via
        // GET-with-subscribe: a standalone Subscribe is rejected when the
        // contract isn't cached locally (#288). The GET also surfaces any
        // pre-existing messages.
        if let Err(e) = InboxModel::get_state(&mut client.clone(), inbox_key).await {
            crate::log::error(format!("inbox get-with-subscribe failed: {e}"), None);
        }
        if let Some(aft_rec) = aft_rec
            && let Err(e) = AftRecords::get_state(&mut client.clone(), aft_rec).await
        {
            crate::log::error(format!("aft record get-with-subscribe failed: {e}"), None);
        }
    }

    #[derive(Default)]
    pub(super) struct NewIdentity {
        pub identity: Option<Identity>,
        pub created_inbox: bool,
        pub inbox_key: Option<ContractKey>,
        pub created_aft_rec: bool,
        pub aft_rec: Option<ContractKey>,
        pub created_aft_gen: bool,
        pub aft_gen: Option<DelegateKey>,
    }

    impl NewIdentity {
        pub fn created(&self) -> bool {
            self.created_inbox
                && self.created_aft_gen
                && self.created_aft_rec
                && self.identity.is_some()
        }
    }

    thread_local! {
        /// Keyed by the encoded ML-DSA-65 verifying key bytes (1952 bytes),
        /// the per-identity stable correlator.
        pub(super) static PENDING_CONFIRMATION: RefCell<HashMap<Vec<u8>, NewIdentity>> = RefCell::new(HashMap::new());
    }
}

/// Await a settings change the mail delegate signs (`prepared`), then send
/// it. In a task: the node loop delivers the delegate's answers, so it must
/// never wait for one.
#[cfg(feature = "use-node")]
fn send_signed_in_background(
    mut client: WebApiRequestClient,
    prepared: futures::future::LocalBoxFuture<
        'static,
        Result<freenet_stdlib::client_api::ContractRequest<'static>, DynError>,
    >,
    what: &'static str,
) {
    crate::app::identity_store::spawn_detached(async move {
        match prepared.await {
            Ok(request) => {
                if let Err(e) = client.send(request.into()).await {
                    crate::log::error(format!("{what} failed: {e}"), None);
                }
            }
            Err(e) => crate::log::error(format!("{what}: signing failed: {e}"), None),
        }
    });
}

/// Show `identity`'s inbox `state`: replaces the settings, keeps the
/// messages already decrypted that the state still holds, and has the mail
/// delegate decrypt the rest in a task ([`spawn_decrypt`]).
#[cfg(feature = "use-node")]
fn set_inbox_state(
    mut inboxes: crate::app::InboxesData,
    identity: &crate::app::Identity,
    key: freenet_stdlib::prelude::ContractKey,
    state: freenet_mail_wire_v1::inbox::Inbox,
) {
    use crate::inbox::InboxModel;
    // Release-visible: the live-node suite reads it as proof the node holds
    // this identity's inbox (#288 self-heal).
    crate::log::info(format!(
        "own inbox state loaded (key={key}, alias=`{}`)",
        identity.alias
    ));
    reclaim_flags_once(
        identity.addr,
        state
            .messages
            .iter()
            .map(|m| crate::local_state::full_message_id(&m.content))
            .collect(),
    );
    let mut models = inboxes.0.write();
    let pending = match models.iter().position(|e| e.borrow().key == key) {
        Some(pos) => models[pos].borrow_mut().replace_state(state),
        None => InboxModel::from_state(identity.addr, identity.ml_kem_ek_bytes(), state, key).map(
            |(model, pending)| {
                models.push(Rc::new(RefCell::new(model)));
                pending
            },
        ),
    };
    drop(models);
    match pending {
        Ok(pending) => spawn_decrypt(inboxes, key, pending),
        Err(e) => crate::log::error(format!("inbox {key}: bad state: {e}"), None),
    }
}

#[cfg(feature = "use-node")]
thread_local! {
    /// Identities whose stale message marks were reclaimed this page.
    static FLAGS_RECLAIMED: RefCell<std::collections::HashSet<freenet_mail_protocol::Addr>> =
        RefCell::new(std::collections::HashSet::new());
}

/// Once per page and identity, on its first whole inbox state, drop the
/// marks of messages that are gone ([`crate::local_state::reclaim_flags`]).
/// A failure is retried on the next whole state.
#[cfg(feature = "use-node")]
fn reclaim_flags_once(
    owner: freenet_mail_protocol::Addr,
    live: std::collections::HashSet<[u8; 16]>,
) {
    if !FLAGS_RECLAIMED.with(|r| r.borrow_mut().insert(owner)) {
        return;
    }
    crate::app::identity_store::spawn_detached(async move {
        match crate::local_state::reclaim_flags(owner, &live).await {
            Ok(n) if n > 0 => crate::log::debug!("reclaimed {n} stale message marks"),
            Ok(_) => {}
            Err(e) => {
                FLAGS_RECLAIMED.with(|r| r.borrow_mut().remove(&owner));
                crate::log::error(format!("reclaiming message marks failed: {e}"), None);
            }
        }
    });
}

/// Retries of a decryption call that failed as a whole.
#[cfg(feature = "use-node")]
const DECRYPT_RETRIES: u32 = 3;

/// Retries of the startup contacts load before it is reported as failed.
#[cfg(feature = "use-node")]
const CONTACT_LOAD_RETRIES: u32 = 3;

/// Decrypt `pending` in the mail delegate and add the messages to inbox
/// `key`. Runs in a task: the node loop delivers the delegate's answers, so
/// it must never wait for one.
#[cfg(feature = "use-node")]
fn spawn_decrypt(
    inboxes: crate::app::InboxesData,
    key: freenet_stdlib::prelude::ContractKey,
    pending: crate::inbox::PendingDecrypt,
) {
    if pending.is_empty() {
        return;
    }
    let mut inboxes = inboxes;
    crate::app::identity_store::spawn_detached(async move {
        let mut pending = pending;
        let mut attempt = 0u32;
        loop {
            let hashes = pending.hashes();
            let retry_with = pending.messages.clone();
            let outcome = crate::inbox::decrypt_pending(pending).await;
            let models = inboxes.0.write();
            let Some(model) = models.iter().find(|e| e.borrow().key == key) else {
                return;
            };
            match outcome {
                Ok(decrypted) => {
                    model.borrow_mut().add_decrypted(decrypted);
                    return;
                }
                Err(e) => {
                    // The call failed as a whole (no answer, a busy or
                    // failing delegate): nothing was learned about the
                    // messages, so they are released and tried again,
                    // after a pause, a few times.
                    model.borrow_mut().release(&hashes);
                    crate::log::error(format!("inbox {key}: {e}"), None);
                    if attempt >= DECRYPT_RETRIES {
                        // Not silently: the messages stay hidden until a
                        // later inbox state (or a reload) asks again.
                        crate::toast::push_toast_detached(
                            crate::inbox::decrypt_gave_up_text(hashes.len()),
                            crate::toast::ToastLevel::Warning,
                        );
                        return;
                    }
                    attempt += 1;
                    drop(models);
                    gloo_timers::future::TimeoutFuture::new(2_000 << attempt).await;
                    let models = inboxes.0.write();
                    let Some(model) = models.iter().find(|e| e.borrow().key == key) else {
                        return;
                    };
                    pending = model.borrow_mut().retake(retry_with);
                    if pending.is_empty() {
                        return;
                    }
                }
            }
        }
    });
}

#[cfg(feature = "use-node")]
#[allow(unused_mut)]
pub(crate) async fn node_comms(
    mut rx: UnboundedReceiver<crate::app::NodeAction>,
    login_controller: Signal<crate::app::LoginController>,
    user: Signal<crate::app::User>,
    inboxes: crate::app::InboxesData,
    ab_gen: crate::app::AddressBookGen,
) {
    // todo don't unwrap inside this function, propagate errors to the UI somehow
    use freenet_mail_wire_v1::inbox::Inbox as StoredInbox;
    use freenet_stdlib::{
        client_api::{ContractError, ContractResponse, ErrorKind, RequestError},
        prelude::*,
    };
    use futures::StreamExt;

    use crate::{
        aft::AftRecords,
        app::{Identity, InboxesData, NodeAction},
        inbox::InboxModel,
    };

    // The encoded-VK correlator PENDING_CONFIRMATION is keyed by. Expects
    // `id.identity.is_some()`, which `created()` checks.
    fn identity_key_of(id: &identity_management::NewIdentity) -> Vec<u8> {
        id.identity
            .as_ref()
            .expect("pending identity must be set before created() returns true")
            .ml_dsa_vk_bytes()
    }

    let mut token_contract_to_id = HashMap::new();
    let mut api = WebApi::new()
        .map_err(|err| {
            crate::log::error(format!("error while connecting to node: {err}"), None);
            err
        })
        .expect("open connection");
    api.connecting.take().unwrap().await.unwrap();
    let mut req_sender = api.sender_half();
    {
        let contracts = user.read().identities.clone();
        crate::inbox::InboxModel::load_all(&mut req_sender, &contracts).await;
        crate::aft::AftRecords::load_all(&mut req_sender, &contracts, &mut token_contract_to_id)
            .await;
    }
    // Local mail state (drafts, sent, read marks, settings) lives in the
    // mail delegate; it is loaded with the identities
    // (`identity_store::load_and_report`).

    WEB_API_SENDER.set(req_sender).unwrap();

    // Identities live in the mail delegate. Read them in a task of their own
    // (this loop delivers the delegate's answers); the task hands them back
    // as `NodeAction::IdentitiesLoaded`.
    crate::app::identity_store::spawn_detached(crate::app::identity_store::load_and_report());

    // Contacts live in the mail delegate. Load them into the address book;
    // the call runs in its own task because this loop is what delivers the
    // delegate's answers.
    {
        let (mut login_controller, mut ab_gen) = (login_controller, ab_gen);
        // spawn_forever: this loop can be polled with no scope on the stack,
        // where a scoped `spawn` panics (empty scope stack).
        let _task = dioxus::core::spawn_forever(async move {
            // A failed load is retried a few times, then reported: an empty
            // address book must never look like having no contacts.
            let mut attempt = 0u32;
            let loaded = loop {
                match crate::app::contact_store::load_all().await {
                    Err(e) if attempt < CONTACT_LOAD_RETRIES => {
                        crate::log::error(format!("loading contacts failed, retrying: {e}"), None);
                        attempt += 1;
                        gloo_timers::future::TimeoutFuture::new(1_000 << attempt).await;
                    }
                    other => break other,
                }
            };
            match loaded {
                Ok(contacts) => {
                    let (contacts, clashed) =
                        crate::app::contact_store::disambiguate(contacts, |alias| {
                            crate::app::login::Identity::get_alias(alias).is_some()
                        });
                    if !clashed.is_empty() {
                        crate::toast::push_toast_detached(
                            format!(
                                "Some contacts share a name ({}). Each is shown with the start of its address; rename them in Contacts.",
                                clashed.join(", ")
                            ),
                            crate::toast::ToastLevel::Warning,
                        );
                    }
                    let mut client = WEB_API_SENDER.get().cloned();
                    for contact in contacts {
                        // #191: contacts arrive here after a reload, so prime
                        // their inboxes as the rehydrate path does.
                        if let Some(client) = client.as_mut() {
                            prime_contact_inbox(client, &contact).await;
                        }
                        if let Err(e) = crate::app::address_book::insert_contact(contact) {
                            crate::log::error(
                                format!("address book rejected stored contact: {e}"),
                                None,
                            );
                        }
                    }
                    login_controller.write().updated = true;
                    let prev = *ab_gen.0.read();
                    *ab_gen.0.write() = prev.wrapping_add(1);
                }
                Err(e) => {
                    crate::log::error(format!("loading contacts failed: {e}"), None);
                    crate::toast::push_toast_detached(
                        format!(
                            "Couldn't load your contacts ({e}). Your address book looks empty until it loads: reload the page to try again."
                        ),
                        crate::toast::ToastLevel::Error,
                    );
                }
            }
        });
    }

    /// The identities the mail delegate holds, read at startup: restore
    /// their runtime wiring lost on reload (inbox routing + AFT-record
    /// subscriptions, the AFT generator delegate registration), prime the
    /// contacts' inboxes, and dispatch the contract migrations whose markers
    /// the loader task already recorded.
    async fn identities_loaded(
        client: &mut WebApiRequestClient,
        loaded: Vec<crate::app::identity_store::LoadedIdentity>,
        token_rec_to_id: &mut HashMap<ContractKey, Identity>,
        user: Signal<crate::app::User>,
        mut login_controller: Signal<crate::app::LoginController>,
        mut ab_gen: crate::app::AddressBookGen,
    ) {
        let infos: Vec<_> = loaded.iter().map(|l| l.info.clone()).collect();
        crate::log::info(format!(
            "identities loaded from the mail delegate: count={}",
            infos.len()
        ));
        let new_ids = crate::app::Identity::set_identities(&infos, user);
        // ALIASES is a thread_local Vec, not a Dioxus signal: bump
        // login_controller so the Identities component re-renders, and the
        // address-book generation so message views re-render (#143).
        login_controller.write().updated = true;
        let prev = *ab_gen.0.read();
        *ab_gen.0.write() = prev.wrapping_add(1);
        if !new_ids.is_empty() {
            InboxModel::load_all(client, &new_ids).await;
            AftRecords::load_all(client, &new_ids, token_rec_to_id).await;
        }
        // The token-generator delegates are registered when first used
        // (`ensure_token_generator_registered`), not here: their parameters
        // carry the identity's signing seed, so the page fetches them only
        // to send.
        // #191: after a reload the local node's contract store is empty, so
        // prime every contact's inbox before the first send to it.
        for contact in crate::app::address_book::all_contacts() {
            prime_contact_inbox(client, &contact).await;
        }
        // #213 / #251: the loader recorded the markers (pending set, current
        // hash stamped) before handing these over; dispatch the GETs.
        for (id, l) in new_ids.iter().zip(&loaded) {
            if let Some(prior_hash) = &l.inbox_migrate_from {
                crate::log::info(format!(
                    "inbox migration: detected drift for `{}` prior_hash={prior_hash} current_hash={} (#213, #251)",
                    id.alias(),
                    crate::inbox::INBOX_CODE_HASH,
                ));
                if let Err(e) = inbox_management::migrate_inbox(client, id, prior_hash).await {
                    crate::log::error(
                        format!("inbox migration: failed for `{}`: {e} (#213)", id.alias()),
                        None,
                    );
                }
            }
            if let Some(prior_hash) = &l.aft_migrate_from {
                crate::log::info(format!(
                    "AFT migration: detected drift for `{}` prior_hash={prior_hash} current_hash={} (#251)",
                    id.alias(),
                    crate::aft::TOKEN_RECORD_CODE_HASH,
                ));
                if let Err(e) =
                    token_record_management::migrate_aft_record(client, id, prior_hash).await
                {
                    crate::log::error(
                        format!("AFT migration: failed for `{}`: {e} (#251)", id.alias()),
                        None,
                    );
                }
            }
        }
    }

    async fn handle_action(
        req: NodeAction,
        api: &WebApi,
        // Forwarded by callers but not consumed in `handle_action` since
        // #185 moved the eager identity persist out of `alias_creation`
        // (which had been the sole consumer). The map is still owned by
        // `responses_loop` for the PutResponse / DelegateResponse handlers
        // below; we accept it here so the call sites don't have to thread
        // a smaller param list.
        _token_rec_to_id: &mut HashMap<ContractKey, Identity>,
        mut user: Signal<crate::app::User>,
        mut login_controller: Signal<crate::app::LoginController>,
        inboxes: &InboxesData,
        mut ab_gen: crate::app::AddressBookGen,
    ) {
        let mut client = api.sender_half();
        match req {
            NodeAction::LoadMessages(identity) => {
                match InboxModel::load(&mut client, &identity).await {
                    Err(err) => {
                        node_response_error_handling(
                            client.into(),
                            Err(err),
                            TryNodeAction::LoadInbox,
                        )
                        .await;
                    }
                    Ok(key) => {
                        InboxModel::set_contract_identity(key, *identity);
                    }
                }
            }
            NodeAction::IdentitiesLoaded { identities } => {
                identities_loaded(
                    &mut client,
                    identities,
                    _token_rec_to_id,
                    user,
                    login_controller,
                    ab_gen,
                )
                .await;
            }
            NodeAction::CreateIdentity {
                identity,
                backed_up,
            } => {
                // #185 / #186: the mail delegate already holds the keys (the
                // create or restore answered before this action was sent),
                // so surface the identity in the UI now, BEFORE waiting on
                // any contract PUT acks. Inbox + AFT contracts derive
                // deterministically from the keys and can be republished.
                let identity = *identity;
                let alias = identity.alias.clone();
                let identity_key = identity.ml_dsa_vk_bytes();
                identity_management::PENDING_CONFIRMATION.with(|pend| {
                    let pend = &mut *pend.borrow_mut();
                    let pend = pend.entry(identity_key.clone()).or_default();
                    crate::log::debug!("waiting for confirmation for identity {alias}");
                    pend.identity = Some(identity.clone());
                });
                crate::app::login::record_backup_after_create(&alias, backed_up);

                // `inbox_key` is `hash(wasm, InboxParams::from(vk))` —
                // deterministic, no network round-trip needed.
                let inbox_key = match crate::inbox::inbox_key_for(&identity.ml_dsa_vk()) {
                    Ok(k) => k,
                    Err(e) => {
                        crate::log::error(
                            format!("derive inbox_key for {alias}: {e}"),
                            Some(TryNodeAction::CreateIdentity(alias.to_string())),
                        );
                        return;
                    }
                };
                identity_management::PENDING_CONFIRMATION.with(|pend| {
                    let pend = &mut *pend.borrow_mut();
                    if let Some(slot) = pend.get_mut(&identity_key)
                        && slot.inbox_key.is_none()
                    {
                        // So the PutResponse handler matches even if the
                        // network ack arrives before the set_alias below.
                        slot.inbox_key = Some(inbox_key);
                    }
                });
                let identity = crate::app::login::Identity::set_alias(identity, inbox_key, user);
                crate::inbox::InboxModel::set_contract_identity(inbox_key, identity);
                // ALIASES is a thread_local RefCell, not a Signal: bump the
                // controller so the row appears without a reload (#186).
                login_controller.write().updated = true;
            }
            NodeAction::CreateContract {
                alias,
                contract_type,
                identity,
                inbox_state,
            } => match contract_type {
                ContractType::InboxContract => {
                    crate::log::debug!("creating inbox contract for {alias}");
                    match inbox_management::create_contract(&mut client, &identity, inbox_state)
                        .await
                    {
                        Ok(key) => {
                            inbox_management::CREATED_INBOX.with(|k| {
                                crate::log::debug!("waiting inbox contract for {alias}");
                                k.borrow_mut().push((alias, key));
                            });
                        }
                        Err(e) => crate::log::error(
                            format!("{e}"),
                            Some(TryNodeAction::CreateContract(contract_type)),
                        ),
                    }
                }
                ContractType::AFTContract => {
                    crate::log::debug!("creating AFT record contract for {alias}");
                    match token_record_management::create_contract(&mut client, &identity).await {
                        Ok(key) => {
                            token_record_management::CREATED_AFT_RECORD.with(|k| {
                                crate::log::debug!("waiting AFT record contract for {alias}");
                                k.borrow_mut().push((alias, key));
                            });
                        }
                        Err(e) => crate::log::error(
                            format!("{e}"),
                            Some(TryNodeAction::CreateContract(contract_type)),
                        ),
                    }
                }
            },
            NodeAction::CreateDelegate {
                alias,
                identity,
                aft_params,
            } => {
                crate::log::debug!("creating AFT gen delegate for {alias}");
                match token_generator_management::create_delegate(
                    &mut client,
                    &identity,
                    &aft_params.0,
                )
                .await
                {
                    Ok(key) => {
                        token_generator_management::CREATED_AFT_GEN.with(|k| {
                            crate::log::debug!("waiting AFT gen delegate for {alias}");
                            k.borrow_mut().push((alias, key));
                        });
                    }
                    Err(e) => {
                        crate::log::error(format!("{e}"), Some(TryNodeAction::CreateDelegate))
                    }
                }
            }
            NodeAction::UpdateInboxPolicy {
                identity,
                required_tier,
                max_age_secs,
            } => {
                // Match the loaded InboxModel by identity vk-bytes;
                // skip silently if the inbox isn't loaded yet (caller
                // shouldn't be able to surface the form pre-load, but
                // avoid panicking either way).
                let target_vk = identity.ml_dsa_vk_bytes();
                let mut found = None;
                for cell in inboxes.snapshot() {
                    let key_owner = {
                        let m = cell.borrow();
                        crate::inbox::InboxModel::contract_identity(&m.key)
                    };
                    if let Some(owner) = key_owner
                        && owner.ml_dsa_vk_bytes() == target_vk
                    {
                        found = Some(cell);
                        break;
                    }
                }
                let Some(cell) = found else {
                    crate::log::error(
                        format!(
                            "UpdateInboxPolicy: no loaded inbox for alias `{}`",
                            identity.alias()
                        ),
                        None,
                    );
                    return;
                };
                let prepared = {
                    let mut model = cell.borrow_mut();
                    model.update_policy_prepare(required_tier, max_age_secs)
                };
                // The delegate signs the change: wait for it in a task, never
                // in this loop, which delivers the delegate's answers.
                let alias = identity.alias.clone();
                crate::app::identity_store::spawn_detached(async move {
                    match prepared.await {
                        Ok(request) => {
                            if let Err(e) = client.send(request.into()).await {
                                crate::log::error(
                                    format!("UpdateInboxPolicy send failed: {e}"),
                                    Some(TryNodeAction::SendMessage),
                                );
                            } else {
                                crate::log::info(format!(
                                    "UpdateInboxPolicy dispatched for `{alias}` tier={required_tier:?} max_age_secs={max_age_secs} (#85)"
                                ));
                            }
                        }
                        Err(e) => {
                            crate::log::error(
                                format!("UpdateInboxPolicy prepare failed: {e}"),
                                Some(TryNodeAction::SendMessage),
                            );
                        }
                    }
                });
            }
            NodeAction::UpdateVerifiedBypass {
                identity,
                allow_verified_skip_token,
                verified_senders,
            } => {
                // Same lookup pattern as UpdateInboxPolicy.
                let target_vk = identity.ml_dsa_vk_bytes();
                let mut found = None;
                for cell in inboxes.snapshot() {
                    let key_owner = {
                        let m = cell.borrow();
                        crate::inbox::InboxModel::contract_identity(&m.key)
                    };
                    if let Some(owner) = key_owner
                        && owner.ml_dsa_vk_bytes() == target_vk
                    {
                        found = Some(cell);
                        break;
                    }
                }
                let Some(cell) = found else {
                    crate::log::error(
                        format!(
                            "UpdateVerifiedBypass: no loaded inbox for alias `{}`",
                            identity.alias()
                        ),
                        None,
                    );
                    return;
                };
                let prepared = {
                    let mut model = cell.borrow_mut();
                    model
                        .update_verified_bypass_prepare(allow_verified_skip_token, verified_senders)
                };
                // The delegate signs the change: wait for it in a task, never
                // in this loop, which delivers the delegate's answers.
                let alias = identity.alias.clone();
                crate::app::identity_store::spawn_detached(async move {
                    match prepared.await {
                        Ok(request) => {
                            if let Err(e) = client.send(request.into()).await {
                                crate::log::error(
                                    format!("UpdateVerifiedBypass send failed: {e}"),
                                    Some(TryNodeAction::SendMessage),
                                );
                            } else {
                                crate::log::info(format!(
                                    "UpdateVerifiedBypass dispatched for `{alias}` allow={allow_verified_skip_token} (#157)"
                                ));
                            }
                        }
                        Err(e) => {
                            crate::log::error(
                                format!("UpdateVerifiedBypass prepare failed: {e}"),
                                Some(TryNodeAction::SendMessage),
                            );
                        }
                    }
                });
            }
            NodeAction::CreateContact { contact } => {
                // The address book updates now and, only if it accepts the
                // contact, it is stored in the mail delegate in the
                // background. A refused or unanswered save is reported.
                if let Err(e) = crate::app::contact_store::accept(contact.clone()) {
                    crate::log::error(format!("address book rejected contact: {e}"), None);
                } else {
                    // ContactsSection reads ADDRESS_BOOK directly (not via a
                    // Signal) so bump the controller to force re-render.
                    login_controller.write().updated = true;
                    // Bump generation so MessageList / OpenMessage re-render
                    // and pick up the new contact's verification state (#134).
                    let prev = *ab_gen.0.read();
                    *ab_gen.0.write() = prev.wrapping_add(1);

                    // #191: prime the local node with the contact's inbox
                    // contract so a future Send works. The webapp dispatches
                    // sends as `UpdateData::Delta`, which the originating
                    // node tries to apply locally before forwarding to a
                    // hosting peer. That local apply needs the contract's
                    // wasm + parameters cached, which we don't have until
                    // we've seen the contract once. A `Get` with
                    // `return_contract_code=true, subscribe=true` populates
                    // the local store and registers us as a subscriber so
                    // future updates also propagate back to the sender's
                    // node when delivered. Without this, send fails with
                    // "missing contract parameters" at update.rs:619 and
                    // the message silently never reaches the recipient.
                    // #251 improvement 4: prime under the contact's
                    // advertised WASM hash, not the sender's
                    // `INBOX_CODE_HASH`. A cross-version contact's
                    // actual contract id is derived from the
                    // recipient's hash + params; priming under the
                    // sender's hash fetches a ghost key and the
                    // subsequent send re-derives correctly but finds
                    // an empty local store → "missing contract
                    // parameters at update.rs:619".
                    match crate::app::address_book::vk_from_bytes(&contact.ml_dsa_vk_bytes) {
                        Ok(vk) => {
                            let code_hash = contact
                                .inbox_wasm_hash
                                .as_deref()
                                .unwrap_or(crate::inbox::INBOX_CODE_HASH);
                            match crate::inbox::inbox_key_for_with_hash(&vk, code_hash) {
                                Ok(inbox_key) => {
                                    let req = freenet_stdlib::client_api::ContractRequest::Get {
                                        key: inbox_key.into(),
                                        return_contract_code: true,
                                        subscribe: true,
                                        blocking_subscribe: false,
                                    };
                                    if let Err(e) = client.send(req.into()).await {
                                        crate::log::error(
                                            format!(
                                                "prime contact inbox {inbox_key} for {} failed: {e}",
                                                contact.local_alias
                                            ),
                                            None,
                                        );
                                    } else {
                                        crate::log::info(format!(
                                            "primed contact inbox {inbox_key} for {} (#191)",
                                            contact.local_alias
                                        ));
                                    }
                                }
                                Err(e) => crate::log::error(
                                    format!(
                                        "derive inbox_key for contact {}: {e}",
                                        contact.local_alias
                                    ),
                                    None,
                                ),
                            }
                        }
                        Err(e) => crate::log::error(
                            format!("decode ml_dsa_vk for contact {}: {e}", contact.local_alias),
                            None,
                        ),
                    }

                    // #150: if this contact was just marked verified AND the
                    // active identity has the bypass toggle ON, push an updated
                    // `verified_senders` set to the inbox contract so the new
                    // VK is immediately exempted from the token requirement.
                    if contact.verified {
                        let active_alias = user.read().logged_id().map(|id| id.alias.to_string());
                        if let Some(alias) = active_alias {
                            let aft_prefs = crate::local_state::identity_settings_for(&alias).aft;
                            if aft_prefs.allow_verified_skip_token {
                                // Rebuild the full set from the address book
                                // (post-insert, so the new contact is included).
                                let verified_senders: std::collections::BTreeSet<Vec<u8>> =
                                    crate::app::address_book::all_contacts()
                                        .into_iter()
                                        .filter(|c| c.verified)
                                        .map(|c| c.ml_dsa_vk_bytes)
                                        .collect();
                                // Find the inbox model for this identity.
                                let target_vk =
                                    user.read().logged_id().map(|id| id.ml_dsa_vk_bytes());
                                if let Some(target_vk) = target_vk {
                                    let mut found = None;
                                    for cell in inboxes.snapshot() {
                                        let key_owner = {
                                            let m = cell.borrow();
                                            InboxModel::contract_identity(&m.key)
                                        };
                                        if let Some(owner) = key_owner
                                            && owner.ml_dsa_vk_bytes() == target_vk
                                        {
                                            found = Some(cell);
                                            break;
                                        }
                                    }
                                    if let Some(cell) = found {
                                        let prepared = {
                                            let mut model = cell.borrow_mut();
                                            model.update_verified_bypass_prepare(
                                                true,
                                                verified_senders,
                                            )
                                        };
                                        send_signed_in_background(
                                            client.clone(),
                                            prepared,
                                            "verified-bypass sync on CreateContact",
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
            NodeAction::FetchContactKeys { inbox_address } => {
                use std::str::FromStr;
                let id_result =
                    freenet_stdlib::prelude::ContractInstanceId::from_str(inbox_address.trim());
                let inbox_id = match id_result {
                    Ok(id) => id,
                    Err(e) => {
                        contact_import::RESULTS.with(|m| {
                            m.borrow_mut().insert(
                                inbox_address.clone(),
                                contact_import::ImportFetched {
                                    outcome: contact_import::ImportFetchOutcome::Failed(format!(
                                        "invalid inbox address: {e}"
                                    )),
                                },
                            );
                        });
                        return;
                    }
                };
                contact_import::PENDING.with(|m| {
                    m.borrow_mut().insert(inbox_id, inbox_address.clone());
                });
                let req = freenet_stdlib::client_api::ContractRequest::Get {
                    key: inbox_id,
                    // Pulls `WasmContractV1.parameters` alongside state
                    // so we can recover the owner's ML-DSA vk (the
                    // ek lives on state). Single round trip.
                    return_contract_code: true,
                    subscribe: false,
                    blocking_subscribe: false,
                };
                if let Err(e) = client.send(req.into()).await {
                    contact_import::PENDING.with(|m| {
                        m.borrow_mut().remove(&inbox_id);
                    });
                    contact_import::RESULTS.with(|m| {
                        m.borrow_mut().insert(
                            inbox_address.clone(),
                            contact_import::ImportFetched {
                                outcome: contact_import::ImportFetchOutcome::Failed(format!(
                                    "send Get failed: {e}"
                                )),
                            },
                        );
                    });
                }
            }
            NodeAction::DeleteContact { alias } => {
                let vk = crate::app::address_book::all_contacts()
                    .into_iter()
                    .find(|c| &*c.local_alias == alias.as_str())
                    .map(|c| c.ml_dsa_vk_bytes);
                let removed: Result<(), DynError> = match vk {
                    Some(vk) => {
                        crate::app::contact_store::remove_in_background(alias.clone(), vk);
                        Ok(())
                    }
                    None => Err(format!("no contact named {alias}").into()),
                };
                if let Err(e) = removed {
                    crate::log::error(format!("failed to delete contact {alias}: {e}"), None);
                } else {
                    crate::app::address_book::remove_contact(&alias);
                    login_controller.write().updated = true;
                    // Bump generation so inbox rows that showed the
                    // removed contact as "verified" revert to
                    // "unknown sender" (#134).
                    let prev = *ab_gen.0.read();
                    *ab_gen.0.write() = prev.wrapping_add(1);

                    // #150: if bypass is ON for the active identity, rebuild
                    // the `verified_senders` set (minus the deleted contact)
                    // and push it to the inbox contract.
                    let active_alias = user.read().logged_id().map(|id| id.alias.to_string());
                    if let Some(active_alias) = active_alias {
                        let aft_prefs =
                            crate::local_state::identity_settings_for(&active_alias).aft;
                        if aft_prefs.allow_verified_skip_token {
                            let verified_senders: std::collections::BTreeSet<Vec<u8>> =
                                crate::app::address_book::all_contacts()
                                    .into_iter()
                                    .filter(|c| c.verified)
                                    .map(|c| c.ml_dsa_vk_bytes)
                                    .collect();
                            let target_vk = user.read().logged_id().map(|id| id.ml_dsa_vk_bytes());
                            if let Some(target_vk) = target_vk {
                                let mut found = None;
                                for cell in inboxes.snapshot() {
                                    let key_owner = {
                                        let m = cell.borrow();
                                        InboxModel::contract_identity(&m.key)
                                    };
                                    if let Some(owner) = key_owner
                                        && owner.ml_dsa_vk_bytes() == target_vk
                                    {
                                        found = Some(cell);
                                        break;
                                    }
                                }
                                if let Some(cell) = found {
                                    let prepared = {
                                        let mut model = cell.borrow_mut();
                                        model.update_verified_bypass_prepare(true, verified_senders)
                                    };
                                    send_signed_in_background(
                                        client.clone(),
                                        prepared,
                                        "verified-bypass sync on DeleteContact",
                                    );
                                }
                            }
                        }
                    }
                }
            }
            NodeAction::RenameIdentity { old, new, identity } => {
                // The delegate renames in place (same keys, same address);
                // wait for it in a task, never in this loop.
                crate::app::identity_store::spawn_detached(async move {
                    let outcome =
                        crate::app::identity_store::rename_identity(&identity, &old, &new, user)
                            .await;
                    match crate::app::identity_store::rename_failure_text(&old, &outcome) {
                        None => login_controller.write().updated = true,
                        Some(text) => {
                            crate::log::error(
                                format!("renaming identity {old} → {new}: {outcome:?}"),
                                None,
                            );
                            // Detached task: no component scope to find the
                            // toast queue in.
                            crate::toast::push_toast_detached(
                                text,
                                crate::toast::ToastLevel::Error,
                            );
                        }
                    }
                });
            }
            NodeAction::DeleteIdentity { identity } => {
                // The delegate asks the user, then deletes the identity and
                // everything it owns in bounded steps.
                crate::app::identity_store::spawn_detached(async move {
                    let alias = identity.alias.clone();
                    let deleted = crate::app::identity_store::delete_with_progress(
                        identity.addr,
                        identity.generation,
                        &alias,
                    )
                    .await;
                    match deleted {
                        Ok(()) => {
                            // Drop from in-memory ALIASES + User.identities so
                            // the IdentifiersList re-renders without the row.
                            // The on-chain inbox + AFT contracts stay (no
                            // delete primitive); without the keys nobody can
                            // sign for them.
                            crate::app::identity_store::drop_from_page(
                                &identity,
                                &mut user.write(),
                            );
                            // Re-render inbox rows that had this identity
                            // wired up as a sender.
                            let prev = *ab_gen.0.read();
                            ab_gen.0.set(prev.wrapping_add(1));
                            login_controller.write().updated = true;
                        }
                        Err(text) => {
                            // Detached task: no component scope for
                            // `push_toast`'s `use_context`. A deletion that
                            // stopped midway is offered for finishing, and
                            // the identity, which the delegate no longer
                            // lets anyone use, leaves the page.
                            crate::toast::push_toast_detached(
                                text,
                                crate::toast::ToastLevel::Error,
                            );
                            let unfinished =
                                crate::app::identity_store::refresh_unfinished_deletions().await;
                            if crate::app::identity_store::settle_after_failed_deletion(
                                &identity,
                                unfinished.as_deref(),
                                &mut user.write(),
                            ) {
                                let prev = *ab_gen.0.read();
                                ab_gen.0.set(prev.wrapping_add(1));
                                login_controller.write().updated = true;
                            }
                        }
                    }
                });
            }
        }
    }

    async fn handle_response(
        res: Result<HostResponse, ClientError>,
        token_rec_to_id: &mut HashMap<ContractKey, Identity>,
        mut inboxes: InboxesData,
        mut login_controller: dioxus::prelude::Signal<crate::app::LoginController>,
        user: Signal<crate::app::User>,
        _ab_gen: crate::app::AddressBookGen,
    ) {
        let mut client = WEB_API_SENDER.get().unwrap().clone();
        let res = match res {
            Ok(r) => r,
            Err(e) => {
                match e.kind() {
                    ErrorKind::RequestError(e) => {
                        // FIXME: handle the different possible errors
                        match e {
                            RequestError::ContractError(ContractError::Update { key, .. }) => {
                                if let Some(id) = token_rec_to_id.get(key) {
                                    // FIXME: in case this is for a token record which is PENDING_CONFIRMED_ASSIGNMENTS
                                    // we should reject that pending assignment
                                    let alias = id.alias();
                                    crate::log::error(
                                        format!(
                                            "the message for {alias} (aft contract: {key}) wasn't delivered successfully, so may need to try again and/or notify the user"
                                        ),
                                        None,
                                    );
                                } else if let Some(id) = InboxModel::contract_identity(key) {
                                    // A failed UPDATE to a recipient inbox is the
                                    // terminal signal that the send didn't land
                                    // (e.g. the recipient-node hang / GET-starvation
                                    // of freenet-core#4345, or any other UPDATE
                                    // rejection). Mirror the AFT-`Failure` path
                                    // (#85) and the import-`Get` path (#302): flip
                                    // every Sent row queued against this inbox from
                                    // Pending → Failed and toast the user, instead
                                    // of leaving the row spinning Pending forever
                                    // (#288).
                                    let alias = id.alias();
                                    crate::log::error(
                                        format!(
                                            "message for {alias} (inbox contract: {key}) wasn't delivered — flipping queued sends to Failed"
                                        ),
                                        Some(TryNodeAction::SendMessage),
                                    );
                                    crate::toast::push_toast(
                                        format!(
                                            "Message to {alias} wasn't delivered. The recipient's node may be temporarily unreachable — try sending again."
                                        ),
                                        crate::toast::ToastLevel::Error,
                                    );
                                    crate::inbox::fail_pending_sent_for_inbox(*key);
                                }
                            }
                            RequestError::ContractError(ContractError::Get { key, cause }) => {
                                // A failed inbox GET is the terminal signal for
                                // an in-flight contact import (the modal issued
                                // `FetchContactKeys` → Get). Core surfaces a
                                // stream-assembly timeout / not-found as
                                // `ContractError::Get`; without resolving the
                                // pending entry here the import modal's poll loop
                                // (login.rs) spins on "Fetching keys…" forever.
                                // Drain PENDING by instance id and publish a
                                // Failed outcome under the address string the
                                // modal polls on.
                                let inbox_id = *key.id();
                                let import_addr = contact_import::PENDING
                                    .with(|m| m.borrow_mut().remove(&inbox_id));
                                if let Some(addr) = import_addr {
                                    crate::log::error(
                                        format!("inbox GET failed for {key}: {cause}"),
                                        None,
                                    );
                                    contact_import::RESULTS.with(|m| {
                                        m.borrow_mut().insert(
                                            addr,
                                            contact_import::ImportFetched {
                                                outcome: contact_import::ImportFetchOutcome::Failed(
                                                    format!("fetch from node failed: {cause}"),
                                                ),
                                            },
                                        );
                                    });
                                } else {
                                    crate::log::error(
                                        format!("GET error for contract {key}: {cause}"),
                                        None,
                                    );
                                }
                            }
                            RequestError::ContractError(err) => {
                                crate::log::error(format!("FIXME: {err}"), None)
                            }
                            RequestError::DelegateError(error) => {
                                crate::log::error(
                                    format!("received delegate request error: {error}"),
                                    None,
                                );
                                // It carries no request id: end the mail
                                // calls it may belong to now, as unknown,
                                // rather than let them wait out their whole
                                // timeout.
                                if crate::mail_delegate::may_be_mail_delegate_error(
                                    error,
                                    crate::mail_delegate::node::key(),
                                ) {
                                    crate::mail_delegate::fail_all_pending();
                                }
                            }
                            RequestError::Disconnect => {
                                todo!("lost connection to node, should retry connecting")
                            }
                            _ => {}
                        }
                    }
                    ErrorKind::Unhandled { cause } => {
                        crate::log::error(format!("unhandled error, cause: {cause}"), None);
                    }
                    _ => {}
                }
                return;
            }
        };
        crate::log::debug!("got node response: {res}");
        match res {
            HostResponse::ContractResponse(ContractResponse::GetResponse {
                key,
                contract,
                state,
                ..
            }) => {
                crate::log::info(format!(
                    "GetResponse: key={key} state_size={}",
                    state.as_ref().len()
                ));
                match InboxModel::contract_identity(&key) {
                    Some(identity) => {
                        crate::log::info(format!(
                            "GetResponse: matched inbox key={key} alias={}",
                            identity.alias()
                        ));
                        let parsed: StoredInbox = match serde_json::from_slice(state.as_ref()) {
                            Ok(v) => v,
                            Err(e) => {
                                crate::log::error(
                                    format!("GetResponse: StoredInbox deser failed: {e}"),
                                    None,
                                );
                                return;
                            }
                        };
                        crate::log::info(format!(
                            "GetResponse: StoredInbox decoded, {} messages",
                            parsed.messages.len()
                        ));
                        set_inbox_state(inboxes, &identity, key, parsed);
                    }
                    _ => {
                        match token_rec_to_id.remove(&key) {
                            Some(identity) => {
                                // is a AFT record contract
                                if let Err(e) = AftRecords::set_identity_contract(
                                    identity.clone(),
                                    state.into(),
                                    &key,
                                ) {
                                    crate::log::error(
                                        format!("error setting an AFT record: {e}"),
                                        None,
                                    );
                                }
                                token_rec_to_id.insert(key, identity);
                            }
                            _ => {
                                // Import-contact fetch (#249): if this
                                // response is for a key the Import modal
                                // is waiting on, decode state + params and
                                // drop the result into `contact_import::RESULTS`
                                // for the modal's polling loop to pick up.
                                let import_addr = contact_import::PENDING
                                    .with(|m| m.borrow_mut().remove(key.id()));
                                if let Some(inbox_address) = import_addr {
                                    let outcome =
                                        decode_import_fetch(&contract, state.as_ref(), &key);
                                    contact_import::RESULTS.with(|m| {
                                        m.borrow_mut().insert(
                                            inbox_address,
                                            contact_import::ImportFetched { outcome },
                                        );
                                    });
                                    return;
                                }
                                // GetResponse for a contact's inbox: arrives
                                // because the rehydrate-prime path (#191) and
                                // CreateContact handler send Get-with-subscribe
                                // for every known contact to populate the local
                                // node's contract store + register interest.
                                // We only care about the side-effects (subscribe,
                                // local store populated); the state itself is
                                // useless to the webapp because a contact's
                                // inbox is opaque (encrypted to the contact's
                                // ml_kem key, not ours).
                                if crate::app::address_book::is_contact_inbox_key(&key) {
                                    // Decode the contact's `InboxSettings` so the
                                    // sender can mint at the recipient's *live*
                                    // tier rather than the stale value in the
                                    // contact card (#221). The state envelope
                                    // is plaintext (only message bodies are
                                    // encrypted); deser failures degrade the
                                    // cache to a miss, sender falls back to
                                    // the card value.
                                    match serde_json::from_slice::<StoredInbox>(state.as_ref()) {
                                        Ok(parsed) => {
                                            crate::contact_tier_cache::record_with_last_update(
                                                key,
                                                &parsed.settings,
                                                parsed.last_update,
                                            );
                                        }
                                        Err(e) => {
                                            crate::log::error(
                                                format!(
                                                    "GetResponse: contact inbox {key} settings deser failed: {e}"
                                                ),
                                                None,
                                            );
                                        }
                                    }
                                    crate::log::debug!(
                                        "GetResponse: contact inbox {key} \
                                        primed (#191) — drop"
                                    );
                                } else if let Some(identity) = inbox_management::PENDING_MIGRATION
                                    .with(|m| m.borrow_mut().remove(&key))
                                {
                                    // #213 inbox migration: this is a GetResponse
                                    // for the identity's OLD inbox key (derived
                                    // under the prior INBOX_CODE_HASH). Decode
                                    // the state and re-PUT it under the current
                                    // inbox key. The signature is over a fixed
                                    // STATE_UPDATE salt and the identity key is
                                    // unchanged, so we can reconstruct the
                                    // serialized state by calling Inbox::new
                                    // with the same settings + messages.
                                    //
                                    // #251 improvement 2: chained migration may
                                    // dispatch GETs against several historical
                                    // keys. The first one to land wins; later
                                    // responses for the same identity are
                                    // ignored via MIGRATED_IDENTITIES (keyed
                                    // by ML-DSA verifying-key bytes — alias
                                    // mutates via rename). The insert happens
                                    // BEFORE awaiting the PUT to close the
                                    // TOCTOU window between guard check and
                                    // PUT completion. On PUT failure we
                                    // remove the entry so the next candidate
                                    // response can retry.
                                    let alias_str = identity.alias().to_string();
                                    let vk_key = crate::inbox::inbox_params_pub_key_bytes(
                                        &identity.ml_dsa_vk(),
                                    );
                                    let claimed = inbox_management::MIGRATED_IDENTITIES.with(|s| {
                                        let mut set = s.borrow_mut();
                                        if set.contains(&vk_key) {
                                            false
                                        } else {
                                            set.insert(vk_key.clone());
                                            true
                                        }
                                    });
                                    if !claimed {
                                        crate::log::debug!(
                                            "inbox migration: skipping duplicate GetResponse for {key} (identity=`{alias_str}`) — already claimed this session"
                                        );
                                    } else {
                                        match serde_json::from_slice::<StoredInbox>(state.as_ref())
                                        {
                                            Ok(parsed) => {
                                                // The delegate re-signs the
                                                // state: wait for it in a
                                                // task, never in this loop.
                                                let mut client = client.clone();
                                                crate::app::identity_store::spawn_detached(
                                                    async move {
                                                        match inbox_management::put_migrated_inbox(
                                                            &mut client,
                                                            &identity,
                                                            parsed,
                                                        )
                                                        .await
                                                        {
                                                            Err(e) => {
                                                                crate::log::error(
                                                                    format!(
                                                                        "inbox migration: PUT failed for `{alias_str}`: {e} (#213)"
                                                                    ),
                                                                    None,
                                                                );
                                                                inbox_management::MIGRATED_IDENTITIES
                                                                .with(|s| {
                                                                    s.borrow_mut().remove(&vk_key);
                                                                });
                                                            }
                                                            Ok(new_key) => {
                                                                // #260: the PUT is only
                                                                // enqueued; the marker is
                                                                // cleared when its
                                                                // `PutResponse` lands.
                                                                inbox_management::AWAITING_MIGRATION_ACK
                                                                .with(|a| {
                                                                    a.borrow_mut().push((
                                                                        alias_str.clone().into(),
                                                                        new_key,
                                                                    ));
                                                                });
                                                            }
                                                        }
                                                    },
                                                );
                                            }
                                            Err(e) => {
                                                crate::log::error(
                                                    format!(
                                                        "inbox migration: deser old state for `{alias_str}` failed: {e} (#213)"
                                                    ),
                                                    None,
                                                );
                                                inbox_management::MIGRATED_IDENTITIES.with(|s| {
                                                    s.borrow_mut().remove(&vk_key);
                                                });
                                            }
                                        }
                                    }
                                } else if let Some(identity) =
                                    token_record_management::PENDING_AFT_MIGRATION
                                        .with(|m| m.borrow_mut().remove(&key))
                                {
                                    // #251 improvement 3: GetResponse for
                                    // an identity's OLD AFT-record key
                                    // (derived under the prior
                                    // TOKEN_RECORD_CODE_HASH). Decode the
                                    // TokenAllocationRecord and re-PUT it
                                    // under the current AFT-record key.
                                    // Mirrors the inbox-migration arm
                                    // above.
                                    let alias_str = identity.alias().to_string();
                                    let vk_key = crate::inbox::inbox_params_pub_key_bytes(
                                        &identity.ml_dsa_vk(),
                                    );
                                    let claimed = token_record_management::MIGRATED_AFT_IDENTITIES
                                        .with(|s| {
                                            let mut set = s.borrow_mut();
                                            if set.contains(&vk_key) {
                                                false
                                            } else {
                                                set.insert(vk_key.clone());
                                                true
                                            }
                                        });
                                    if !claimed {
                                        crate::log::debug!(
                                            "AFT migration: skipping duplicate GetResponse for {key} (identity=`{alias_str}`) — already claimed this session"
                                        );
                                    } else {
                                        match serde_json::from_slice::<
                                            freenet_mail_wire_v1::aft::TokenAllocationRecord,
                                        >(
                                            state.as_ref()
                                        ) {
                                            Ok(parsed) => {
                                                match token_record_management::put_migrated_aft_record(
                                                    &mut client,
                                                    &identity,
                                                    parsed,
                                                )
                                                .await
                                                {
                                                    Err(e) => {
                                                        crate::log::error(
                                                            format!(
                                                                "AFT migration: PUT failed for `{alias_str}`: {e} (#251)"
                                                            ),
                                                            None,
                                                        );
                                                        token_record_management::MIGRATED_AFT_IDENTITIES
                                                            .with(|s| {
                                                                s.borrow_mut().remove(&vk_key);
                                                            });
                                                    }
                                                    Ok(new_key) => {
                                                        // #260: enqueued only —
                                                        // defer the pending-marker
                                                        // clear to the matching
                                                        // `PutResponse`.
                                                        token_record_management::AWAITING_AFT_MIGRATION_ACK
                                                            .with(|a| {
                                                                a.borrow_mut().push((
                                                                    alias_str.clone().into(),
                                                                    new_key,
                                                                ));
                                                            });
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                crate::log::error(
                                                    format!(
                                                        "AFT migration: deser old state for `{alias_str}` failed: {e} (#251)"
                                                    ),
                                                    None,
                                                );
                                                token_record_management::MIGRATED_AFT_IDENTITIES
                                                    .with(|s| {
                                                        s.borrow_mut().remove(&vk_key);
                                                    });
                                            }
                                        }
                                    }
                                } else {
                                    crate::log::error(
                                        format!("GetResponse for unknown contract key: {key}"),
                                        None,
                                    );
                                }
                            }
                        }
                    }
                }
            }
            HostResponse::ContractResponse(ContractResponse::UpdateNotification {
                key,
                update,
            }) => {
                match InboxModel::contract_identity(&key) {
                    Some(identity) => {
                        match update {
                            UpdateData::Delta(delta) => {
                                match serde_json::from_slice::<
                                    freenet_mail_wire_v1::inbox::UpdateInbox,
                                >(delta.as_ref())
                                {
                                    Ok(parsed) => {
                                        let models = inboxes.0.write();
                                        if let Some(pos) =
                                            models.iter().position(|e| e.borrow().key == key)
                                        {
                                            let pending =
                                                models[pos].borrow_mut().apply_delta(parsed);
                                            drop(models);
                                            spawn_decrypt(inboxes, key, pending);
                                        } else {
                                            // Notification raced GetResponse: a
                                            // Delta on its own can't materialise
                                            // the inbox (no settings, no key on
                                            // the wire). The follow-up
                                            // GetResponse will populate it.
                                            crate::log::debug!(
                                                "UpdateNotification(Delta) before GetResponse for {key}; dropping"
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        crate::log::error(
                                            format!(
                                                "UpdateNotification: failed to decode UpdateInbox delta for {key}: {e}"
                                            ),
                                            None,
                                        );
                                    }
                                }
                            }
                            UpdateData::State(state) => {
                                match serde_json::from_slice::<StoredInbox>(state.as_ref()) {
                                    Ok(parsed) => set_inbox_state(inboxes, &identity, key, parsed),
                                    Err(e) => crate::log::error(
                                        format!(
                                            "UpdateNotification: bad inbox state for {key}: {e}"
                                        ),
                                        None,
                                    ),
                                }
                            }
                            _ => unreachable!(),
                        }
                    }
                    _ => {
                        match token_rec_to_id.remove(&key) {
                            Some(identity) => {
                                // is a AFT record contract
                                if let Err(e) = AftRecords::update_record(identity.clone(), update)
                                {
                                    crate::log::error(
                                        format!("error updating an AFT record from delta: {e}"),
                                        None,
                                    );
                                }
                                token_rec_to_id.insert(key, identity);
                            }
                            _ => {
                                // UpdateNotification for a contact's inbox:
                                // arrives because the rehydrate-prime path
                                // (#191) subscribed us to every contact's
                                // inbox to populate the local node's store.
                                // The state is opaque (encrypted to the
                                // contact's ml_kem key, not ours), so we
                                // can't decrypt or display it — just drop
                                // the notification. Without this guard the
                                // arm panicked with `unreachable!` and took
                                // the whole webapp down (#198).
                                if crate::app::address_book::is_contact_inbox_key(&key) {
                                    // Refresh the recipient-policy cache when
                                    // the contact rotates `InboxSettings`
                                    // (#221). State carries the full snapshot;
                                    // Delta::ModifySettings carries just the
                                    // new settings. Anything else (AddMessages,
                                    // RemoveMessages) is opaque to us.
                                    match &update {
                                        UpdateData::State(state) => {
                                            match serde_json::from_slice::<StoredInbox>(
                                                state.as_ref(),
                                            ) {
                                                Ok(parsed) => {
                                                    crate::contact_tier_cache::record_with_last_update(
                                                        key,
                                                        &parsed.settings,
                                                        parsed.last_update,
                                                    );
                                                }
                                                Err(e) => {
                                                    crate::log::error(
                                                        format!(
                                                            "UpdateNotification(State): contact inbox {key} settings deser failed: {e}"
                                                        ),
                                                        None,
                                                    );
                                                }
                                            }
                                        }
                                        UpdateData::Delta(delta) => {
                                            if let Ok(
                                                freenet_mail_wire_v1::inbox::UpdateInbox::ModifySettings {
                                                    settings,
                                                    last_update,
                                                    ..
                                                },
                                            ) = serde_json::from_slice::<
                                                freenet_mail_wire_v1::inbox::UpdateInbox,
                                            >(
                                                delta.as_ref()
                                            ) {
                                                // The ModifySettings delta now
                                                // carries the owner-signed
                                                // `last_update` (#253); use it
                                                // so cache freshness matches the
                                                // authoritative LWW timestamp.
                                                crate::contact_tier_cache::record_with_last_update(
                                                    key,
                                                    &settings,
                                                    last_update,
                                                );
                                            }
                                        }
                                        _ => {}
                                    }
                                    crate::log::debug!(
                                        "UpdateNotification: contact inbox \
                                        {key} (#198) — drop"
                                    );
                                } else if is_own_aft_record_key(&key) {
                                    // Own AFT-record echo that raced ahead of
                                    // the `token_rec_to_id` insert (the GET-
                                    // with-subscribe from #288 means the node
                                    // echoes our own token-burn UPDATEs). The
                                    // synchronous registration in
                                    // `AftRecords::load_all` normally has the
                                    // key in the map by now; this code-hash
                                    // check is the race-safe backstop so a
                                    // pre-load echo is dropped quietly instead
                                    // of logging "unknown contract key" (#204).
                                    crate::log::debug!(
                                        "UpdateNotification: own AFT record {key} \
                                        before routing insert (#204) — drop"
                                    );
                                } else {
                                    crate::log::error(
                                        format!(
                                            "UpdateNotification for unknown contract key: {key}"
                                        ),
                                        None,
                                    );
                                }
                            }
                        }
                    }
                }
            }
            HostResponse::ContractResponse(ContractResponse::UpdateResponse { key, summary }) => {
                // Sent-folder delivery ack (#58): if this UpdateResponse is
                // for a recipient inbox we sent to, flip the next pending
                // Sent row's delivery_state from Pending → Delivered.
                if let Some((sender_alias, sent_id)) =
                    crate::inbox::take_next_pending_sent_ack(&key)
                {
                    // Only persist the Delivered flip if the row actually
                    // transitioned from Pending. A late UpdateResponse that
                    // arrives after the stale-send sweep already failed this
                    // (or mis-pairs onto a sibling already terminal) must not
                    // resurrect a Failed row to Delivered (#288).
                    if crate::local_state::local_set_sent_delivery_state(
                        &sender_alias,
                        &sent_id,
                        freenet_mail_wire_v1::local_state::DeliveryState::Delivered,
                    ) {
                        let alias_async = sender_alias;
                        let id_async = sent_id;
                        wasm_bindgen_futures::spawn_local(async move {
                            if let Err(e) = crate::local_state::set_sent_delivery_state(
                                alias_async,
                                id_async,
                                freenet_mail_wire_v1::local_state::DeliveryState::Delivered,
                            )
                            .await
                            {
                                crate::log::local_state_failure("update delivery state", e);
                            }
                        });
                    }
                }

                if let Some(identity) = token_rec_to_id.remove(&key) {
                    // The host's UpdateResponse `summary` field has, in
                    // practice, sometimes carried the full
                    // TokenAllocationRecord JSON (`{"tokens_by_tier":...}`)
                    // instead of the contract's TokenAllocationSummary
                    // (`{"Day1":[...]}`). Accept either: try Summary first,
                    // then fall back to deserializing as Record and
                    // summarizing locally. Bail with an error log instead
                    // of panicking — the AFT allocation has already
                    // committed at this point, the panic was just losing
                    // the post-commit hook.
                    let bytes = summary.as_ref();
                    let summary = match TokenAllocationSummary::try_from(summary.clone()) {
                        Ok(s) => Some(s),
                        Err(_) => match serde_json::from_slice::<
                            freenet_mail_wire_v1::aft::TokenAllocationRecord,
                        >(bytes)
                        {
                            Ok(record) => Some(record.summarize()),
                            Err(e) => {
                                crate::log::error(
                                    format!(
                                        "UpdateResponse summary deser failed as both Summary and Record: {e}"
                                    ),
                                    None,
                                );
                                None
                            }
                        },
                    };
                    if let Some(summary) = summary
                        && let Err(e) = AftRecords::confirm_allocation(
                            &mut client,
                            *key.id(),
                            summary,
                            Some(identity.clone()),
                        )
                        .await
                    {
                        crate::log::error(format!("confirm_allocation failed: {e}"), None);
                    }
                    token_rec_to_id.insert(key, identity.clone());
                }
            }
            HostResponse::ContractResponse(ContractResponse::PutResponse { key: contract_key }) => {
                let found = inbox_management::CREATED_INBOX.with(|keys| {
                    let pos = keys.borrow().iter().position(|(_, k)| k == &contract_key);
                    if let Some(pos) = pos {
                        let (_alias, _key) = keys.borrow_mut().remove(pos);
                        crate::log::debug!("inbox contract `{_key}` for alias `{_alias}` put");
                        return true;
                    }
                    false
                });
                if found {
                    let created = identity_management::PENDING_CONFIRMATION.with(|pend| {
                        if let Some(id) = pend
                            .borrow_mut()
                            .values_mut()
                            .find(|id| id.inbox_key.as_ref() == Some(&contract_key))
                        {
                            id.created_inbox = true;
                            id.created().then(|| identity_key_of(id))
                        } else {
                            None
                        }
                    });
                    if let Some(private_key) = created {
                        identity_management::alias_creation(
                            &mut client,
                            &private_key,
                            token_rec_to_id,
                            user,
                            login_controller,
                        )
                        .await;
                    }
                    return;
                }
                let found = token_record_management::CREATED_AFT_RECORD.with(|keys| {
                    let pos = keys.borrow().iter().position(|(_, k)| k == &contract_key);
                    if let Some(pos) = pos {
                        let (_alias, _key) = keys.borrow_mut().remove(pos);
                        crate::log::debug!("AFT record `{_key}` for alias `{_alias}` put");
                        return true;
                    }
                    false
                });
                if found {
                    let created = identity_management::PENDING_CONFIRMATION.with(|pend| {
                        if let Some(id) = pend
                            .borrow_mut()
                            .values_mut()
                            .find(|id| id.aft_rec.as_ref() == Some(&contract_key))
                        {
                            id.created_aft_rec = true;
                            id.created().then(|| identity_key_of(id))
                        } else {
                            None
                        }
                    });
                    if let Some(private_key) = created {
                        identity_management::alias_creation(
                            &mut client,
                            &private_key,
                            token_rec_to_id,
                            user,
                            login_controller,
                        )
                        .await;
                    }
                    return;
                }

                // #260: a migration re-PUT's ACK has landed. Only now is it
                // safe to clear the persistent pending-migration marker — the
                // new state is durably on the network. Until this point the
                // marker survived so a never-acked PUT re-attempts next
                // session instead of being silently abandoned.
                let awaiting_inbox = inbox_management::AWAITING_MIGRATION_ACK
                    .with(|a| take_awaiting_ack(&mut a.borrow_mut(), &contract_key));
                if let Some(alias) = awaiting_inbox {
                    // #260: the migration PUT is durably on the network now —
                    // clear the persistent marker. Only surface the success
                    // toast if the clear lands; if it fails the marker stays
                    // set (re-attempted next session), so a "migrated"
                    // toast would over-promise.
                    if let Some(id) = crate::app::login::Identity::get_alias(&alias) {
                        crate::app::identity_store::migration_landed(
                            id.addr,
                            alias.to_string(),
                            false,
                        );
                    }
                    return;
                }

                let awaiting_aft = token_record_management::AWAITING_AFT_MIGRATION_ACK
                    .with(|a| take_awaiting_ack(&mut a.borrow_mut(), &contract_key));
                if let Some(alias) = awaiting_aft {
                    // #260: same deferred-clear discipline as the inbox branch.
                    if let Some(id) = crate::app::login::Identity::get_alias(&alias) {
                        crate::app::identity_store::migration_landed(
                            id.addr,
                            alias.to_string(),
                            true,
                        );
                    }
                }
            }
            HostResponse::DelegateResponse { key, values }
                if &key == crate::mail_delegate::node::key() =>
            {
                // The mail delegate answers every request with exactly one
                // response carrying its id; anything else for its key is the
                // node's answer to the registration.
                let mut delivered = false;
                for msg in values {
                    if let freenet_stdlib::prelude::OutboundDelegateMsg::ApplicationMessage(app) =
                        msg
                    {
                        crate::mail_delegate::deliver(&app.payload);
                        delivered = true;
                    }
                }
                if !delivered {
                    crate::mail_delegate::node::note_registration_answer();
                }
            }
            HostResponse::DelegateResponse { key, values } => {
                // Empty-values response on the identities delegate previously
                // re-issued `load_aliases`, but the node returns the same empty
                // result and the UI re-issues again — a tight loop hammering the
                // delegate executor. The identities reload path is dead until the
                // Phase 1 restore lands; for now, just ignore empty responses on
                // the identities key.
                if values.is_empty() {
                    let found = token_generator_management::CREATED_AFT_GEN.with(|keys| {
                        let pos = keys.borrow().iter().position(|(_, k)| k == &key);
                        if let Some(pos) = pos {
                            let (_alias, _key) = keys.borrow_mut().remove(pos);
                            crate::log::debug!("AFT gen delegate `{_key}` for `{_alias}` put");
                            return true;
                        }
                        false
                    });
                    if found {
                        let private_key = identity_management::PENDING_CONFIRMATION.with(|pend| {
                            if let Some(id) = pend
                                .borrow_mut()
                                .values_mut()
                                .find(|id| id.aft_gen.as_ref() == Some(&key))
                            {
                                id.created_aft_gen = true;
                                id.created().then(|| identity_key_of(id))
                            } else {
                                None
                            }
                        });
                        if let Some(key) = private_key {
                            identity_management::alias_creation(
                                &mut client,
                                &key,
                                token_rec_to_id,
                                user,
                                login_controller,
                            )
                            .await;
                        }
                    }
                }
                for msg in values {
                    match msg {
                        freenet_stdlib::prelude::OutboundDelegateMsg::ApplicationMessage(msg) => {
                            // Identities-delegate response: payload is a serialized
                            // `IdentityManagement` (HashMap<alias, AliasInfo>). Restore
                            // it into the user's identity list so the login screen
                            // shows previously-created aliases. Without this branch
                            // the bytes get parsed as a `TokenDelegateMessage` and
                            // fail with a deser error.
                            let token = match TokenDelegateMessage::try_from(msg.payload.as_slice())
                            {
                                Ok(r) => r,
                                Err(e) => {
                                    crate::log::error(
                                        format!("error deserializing delegate msg: {e}"),
                                        None,
                                    );
                                    return;
                                }
                            };
                            match token {
                                TokenDelegateMessage::AllocatedToken { assignment, .. } => {
                                    let mut code_hash_bytes = [0u8; 32];
                                    bs58::decode(crate::aft::TOKEN_RECORD_CODE_HASH)
                                        .with_alphabet(bs58::Alphabet::BITCOIN)
                                        .onto(&mut code_hash_bytes)
                                        .unwrap();
                                    let code_hash =
                                        freenet_stdlib::prelude::CodeHash::new(code_hash_bytes);
                                    let token_contract_key = ContractKey::from_id_and_code(
                                        assignment.token_record,
                                        code_hash,
                                    );
                                    match token_rec_to_id.remove(&token_contract_key) {
                                        Some(identity) => {
                                            if let Err(e) = AftRecords::allocated_assignment(
                                                &mut client,
                                                assignment,
                                            )
                                            .await
                                            {
                                                // todo: if a collision occurs, the operation should be retried until there are no more tokens available
                                                crate::log::error(
                                                    format!(
                                                        "error registering the token assignment: {e}"
                                                    ),
                                                    None,
                                                );
                                            }
                                            token_rec_to_id.insert(token_contract_key, identity);
                                        }
                                        _ => {
                                            unreachable!("tried to get wrong contract key: {key}")
                                        }
                                    }
                                }
                                TokenDelegateMessage::Failure(reason) => {
                                    // #85: when the delegate refuses to mint
                                    // (NoFreeSlot at the recipient's tier, or
                                    // user denial), every send queued against
                                    // this delegate is now stuck. Drain the
                                    // pending queue for this delegate and flip
                                    // each affected Sent row from Pending →
                                    // Failed so the user sees the truth in the
                                    // sidebar instead of a spinner that never
                                    // resolves. The delegate response carries
                                    // no `assignment_hash`, so we conservatively
                                    // fail all queued sends for the delegate.
                                    crate::log::error(
                                        format!("token assignment failure: {reason}"),
                                        Some(TryNodeAction::SendMessage),
                                    );
                                    crate::toast::push_toast(
                                        crate::aft::format_failure_toast(&reason, None),
                                        crate::toast::ToastLevel::Error,
                                    );
                                    let drained = AftRecords::drain_pending_for_delegate(&key);
                                    for (inbox_key, _hash) in drained {
                                        crate::inbox::fail_pending_sent_for_inbox(inbox_key);
                                    }
                                }
                                TokenDelegateMessage::RequestNewToken(_) => {
                                    // Delegate echoes the original request back to itself
                                    // (with updated context) while it's waiting on user
                                    // permission input. Not a UI-side action — ignore.
                                }
                            }
                        }
                        // NOTE: the original code had a second guarded
                        // `ApplicationMessage` arm here for the identities
                        // delegate response (gated on `&key == IDENTITIES_KEY`).
                        // It was unreachable because the arm above matches
                        // unconditionally. The identities path is currently
                        // dead — restoring it is tracked as Phase 1 work.
                        other => {
                            crate::log::error(
                                format!("received wrong delegate msg: {other:?}"),
                                None,
                            );
                        }
                    }
                }
            }
            HostResponse::Ok => {}
            HostResponse::ContractResponse(ContractResponse::SubscribeResponse { .. }) => {
                // Confirms a subscription bookkeeping ack; nothing to drive
                // off it on the UI side. Logging produces a noisy "message
                // not handled" line every time we subscribe to inbox/AFT.
            }
            HostResponse::ContractResponse(ContractResponse::NotFound { instance_id }) => {
                // A GET resolved to NotFound: the contract isn't on the
                // network. Three distinct sources land here, handled in
                // priority order. They're mutually exclusive in practice
                // (an own-inbox/own-AFT key is never in the import PENDING
                // map, and an import key is never in INBOX_TO_ID /
                // token_rec_to_id), so the first match wins.
                //
                // `ContractKey`'s `PartialEq`/`Hash` are keyed only on the
                // instance id (the code hash is ignored), so a key built
                // with a placeholder code hash matches the real key in the
                // INBOX_TO_ID / token_rec_to_id maps.
                let key = ContractKey::from_id_and_code(instance_id, CodeHash::new([0u8; 32]));

                // Resolve which routing table owns this key, then act. The
                // import-PENDING removal is also the side effect for the
                // ContactImport branch, so take it here and feed the boolean
                // into the pure classifier (see `notfound_routing` tests).
                let import_addr =
                    contact_import::PENDING.with(|m| m.borrow_mut().remove(&instance_id));
                let own_identity = InboxModel::contract_identity(&key);
                let own_aft_identity = token_rec_to_id.get(&key).cloned();
                let route = classify_notfound(
                    import_addr.is_some(),
                    own_identity.is_some(),
                    own_aft_identity.is_some(),
                );
                match route {
                    NotFoundRoute::ContactImport => {
                        // Resolve the import modal immediately with a failure
                        // instead of letting it spin for the full 30s GET
                        // timeout (#302).
                        let inbox_address = import_addr.expect("classified ContactImport");
                        contact_import::RESULTS.with(|m| {
                            m.borrow_mut().insert(
                                inbox_address,
                                contact_import::ImportFetched {
                                    outcome: contact_import::ImportFetchOutcome::Failed(
                                        "inbox not found on the network — the recipient may be \
                                         offline or their inbox has not propagated yet"
                                            .into(),
                                    ),
                                },
                            );
                        });
                    }
                    NotFoundRoute::OwnInbox => {
                        // Own-inbox NotFound -> reconstruct + re-PUT (#288
                        // self-heal). An identity that loads via GET-with-
                        // subscribe never durably PUT its inbox, so the
                        // contract fell off the network. Reconstruct
                        // `Inbox::new` state and PUT with subscribe:true.
                        let identity = own_identity.expect("classified OwnInbox");
                        crate::log::info(format!(
                            "own inbox not found on the network (key={key}, alias=`{}`) — re-PUTting to self-heal (#288)",
                            identity.alias()
                        ));
                        let mut client = client.clone();
                        crate::app::identity_store::spawn_detached(async move {
                            let put = async {
                                let state = crate::app::identity_store::initial_inbox_state(
                                    &identity,
                                    identity.required_tier,
                                    identity.max_age_secs,
                                )
                                .await?;
                                inbox_management::create_contract(&mut client, &identity, state)
                                    .await
                            };
                            if let Err(e) = put.await {
                                crate::log::error(
                                    format!(
                                        "own-inbox re-PUT failed for `{}`: {e} (#288)",
                                        identity.alias()
                                    ),
                                    None,
                                );
                            }
                        });
                    }
                    NotFoundRoute::OwnAftRecord => {
                        // Same self-heal shape for the identity's
                        // token-allocation-record contract.
                        let identity = own_aft_identity.expect("classified OwnAftRecord");
                        crate::log::info(format!(
                            "own AFT record not found on the network (key={key}, alias=`{}`) — re-PUTting to self-heal (#288)",
                            identity.alias()
                        ));
                        if let Err(e) =
                            token_record_management::create_contract(&mut client.clone(), &identity)
                                .await
                        {
                            crate::log::error(
                                format!(
                                    "own-AFT-record re-PUT failed for `{}`: {e} (#288)",
                                    identity.alias()
                                ),
                                None,
                            );
                        }
                    }
                    NotFoundRoute::Unattributed => {
                        // Not an import, own inbox, or own AFT record. Log
                        // quietly so we stop misreporting it as "message not
                        // handled" via the catch-all (#288).
                        crate::log::debug!("GET NotFound for unattributed key {instance_id}");
                    }
                }
            }
            other => {
                crate::log::error(format!("message not handled: {other:?}"), None);
            }
        }
    }

    let mut pending_sweep =
        gloo_timers::future::IntervalStream::new(crate::aft::PENDING_ASSIGNMENT_SWEEP_INTERVAL_MS)
            .fuse();

    loop {
        futures::select! {
            r = api.host_responses.next() => {
                let Some(res) = r else { panic!("async action ch closed") };
                handle_response(
                    res,
                    &mut token_contract_to_id,
                    inboxes,
                    login_controller,
                    user,
                    ab_gen,
                )
                .await;
            }
            req = rx.next() => {
                let Some(req) = req else { panic!("async action ch closed") };
                handle_action(
                    req,
                    &api,
                    &mut token_contract_to_id,
                    user,
                    login_controller,
                    &inboxes,
                    ab_gen,
                )
                .await;
            }
            req = api.requests.next() => {
                let Some(req) = req else { panic!("request ch closed") };
                crate::log::debug!("sending request to API: {req}");
                api.api.send(req).await.unwrap();
            }
            error = api.client_errors.next() => {
                match error {
                    Some(Err((msg, action))) => {
                        crate::log::error(format!("{msg}"), Some(action.clone()));
                        // Surface send failures to the user. A "no token
                        // record loaded" error from `assign_token` lands here
                        // via the `start_sending` async future. We detect the
                        // pattern by action rather than by parsing the message
                        // string to keep the check stable across refactors.
                        if matches!(action, TryNodeAction::SendMessage) {
                            let msg_str = msg.to_string();
                            let user_msg = if msg_str.contains(crate::aft::NO_TOKEN_RECORD_MSG_PREFIX) {
                                crate::aft::format_no_record_toast()
                            } else {
                                format!(
                                    "Can't send: {msg_str}. Check Settings → AFT or try again."
                                )
                            };
                            crate::toast::push_toast(user_msg, crate::toast::ToastLevel::Error);
                        }
                    }
                    Some(Ok(_)) => {}
                    None => panic!("error ch closed"),
                }
            }
            _ = pending_sweep.next() => {
                // Reap AFT assignments whose `confirm_allocation` never
                // arrived. Without this the user's send hangs silently;
                // with it, surfaces as a SendMessage error so the UI can
                // mark the Sent row failed.
                let expired = AftRecords::expire_stale(
                    crate::aft::PENDING_ASSIGNMENT_TIMEOUT_SECS,
                );
                let mut aft_failed_inboxes: Vec<ContractKey> = Vec::new();
                for (assignment, inbox) in expired {
                    crate::log::error(
                        format!(
                            "AFT assignment confirmation timed out (>{}s) for tier={} slot={} hash={}",
                            crate::aft::PENDING_ASSIGNMENT_TIMEOUT_SECS,
                            assignment.tier,
                            assignment.time_slot,
                            bs58::encode(assignment.assignment_hash).into_string(),
                        ),
                        Some(TryNodeAction::SendMessage),
                    );
                    crate::toast::push_toast(
                        crate::aft::format_expired_assignment_toast(assignment.tier),
                        crate::toast::ToastLevel::Error,
                    );
                    if !aft_failed_inboxes.contains(&inbox) {
                        aft_failed_inboxes.push(inbox);
                    }
                }
                // Flip the Sent rows for AFT-timed-out sends to Failed right
                // away rather than waiting out the longer send-sweep window
                // (#288 review): an AFT stall is terminal for that send.
                for inbox in aft_failed_inboxes {
                    crate::inbox::fail_pending_sent_for_inbox(inbox);
                }

                // #288 "no terminal reply at all": a send whose recipient
                // inbox UPDATE got neither an `UpdateResponse` nor a
                // `ContractError::Update` (e.g. the recipient node hung and
                // the request was silently dropped) would otherwise leave
                // the Sent row spinning Pending forever. Fail rows older
                // than `PENDING_SENT_TIMEOUT_SECS` and toast once.
                let now_ms = chrono::Utc::now().timestamp_millis();
                let expired_sends = crate::inbox::expire_stale_pending_sent(
                    crate::inbox::PENDING_SENT_TIMEOUT_SECS,
                    now_ms,
                );
                if !expired_sends.is_empty() {
                    crate::toast::push_toast(
                        format!(
                            "{} message(s) got no delivery confirmation within {}s and were marked failed. The recipient's node may be unreachable — try sending again.",
                            expired_sends.len(),
                            crate::inbox::PENDING_SENT_TIMEOUT_SECS,
                        ),
                        crate::toast::ToastLevel::Error,
                    );
                }
            }
        }
    }
}

pub(crate) type AsyncActionResult = Result<(), (DynError, TryNodeAction)>;

pub(crate) async fn node_response_error_handling(
    mut error_channel: NodeResponses,
    res: Result<(), DynError>,
    action: TryNodeAction,
) {
    // todo: all errors should be handled properly and propagated to the UI if fitting
    if let Err(error) = res {
        crate::log::error(format!("{error}"), Some(action.clone()));
        error_channel
            .send(Err((error, action)))
            .await
            .expect("error channel closed");
    } else {
        error_channel
            .send(Ok(()))
            .await
            .expect("error channel closed");
    }
}

#[derive(Clone, Debug)]
pub(crate) enum TryNodeAction {
    LoadInbox,
    LoadTokenRecord,
    SendMessage,
    RemoveMessages,
    GetAlias,
    CreateIdentity(String),
    CreateContract(ContractType),
    CreateDelegate,
}

impl std::fmt::Display for TryNodeAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TryNodeAction::LoadInbox => write!(f, "loading messages"),
            TryNodeAction::LoadTokenRecord => write!(f, "loading token record"),
            TryNodeAction::SendMessage => write!(f, "sending message"),
            TryNodeAction::RemoveMessages => write!(f, "removing messages"),
            TryNodeAction::GetAlias => write!(f, "get alias"),
            TryNodeAction::CreateIdentity(alias) => write!(f, "create alias {alias}"),
            TryNodeAction::CreateContract(contract_type) => {
                write!(f, "creating contract {contract_type}")
            }
            TryNodeAction::CreateDelegate => {
                write!(f, "creating AFT delegate")
            }
        }
    }
}

#[cfg(all(test, feature = "use-node"))]
mod awaiting_ack_tests {
    use std::rc::Rc;

    use freenet_stdlib::prelude::{ContractCode, ContractKey, Parameters};

    use super::take_awaiting_ack;

    fn key(n: u8) -> ContractKey {
        // Distinct params per n → distinct contract id, so each key is unique.
        ContractKey::from_params_and_code(Parameters::from(vec![n]), ContractCode::from(vec![0u8]))
    }

    /// #260: the pending-migration marker must NOT be cleared on PUT enqueue.
    /// The clear is keyed off the migration PUT's `PutResponse`; until the
    /// acked key matches an awaiting entry, `take_awaiting_ack` returns None
    /// and the marker survives — so a never-acked PUT re-attempts next session.
    #[test]
    fn awaiting_ack_only_clears_on_matching_key_260() {
        let mut awaiting: Vec<(Rc<str>, ContractKey)> =
            vec![(Rc::from("alice"), key(1)), (Rc::from("bob"), key(2))];

        // A PutResponse for an unrelated key (e.g. an ordinary create) must
        // not consume any awaiting entry — the markers stay pending.
        assert!(
            take_awaiting_ack(&mut awaiting, &key(9)).is_none(),
            "unrelated ack must not clear a pending migration",
        );
        assert_eq!(awaiting.len(), 2, "no entry consumed on non-match");

        // The ack for alice's new key clears exactly alice's entry.
        assert_eq!(
            take_awaiting_ack(&mut awaiting, &key(1)).as_deref(),
            Some("alice"),
        );
        assert_eq!(awaiting.len(), 1, "exactly one entry consumed");
        assert_eq!(awaiting[0].0.as_ref(), "bob", "bob still awaits its ack");

        // A duplicate ack for the same (now-removed) key is a no-op.
        assert!(
            take_awaiting_ack(&mut awaiting, &key(1)).is_none(),
            "duplicate ack must not double-clear",
        );
    }
}
