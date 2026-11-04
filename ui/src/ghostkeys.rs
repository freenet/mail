//! The Ghost Key vault (the ghostkeys delegate), for the compose flow's
//! "Use Ghost Key": which keys this app may use, and a signature over a
//! RequireGhost inbox's admission payload (decision 1). The vault asks the
//! user once per key and app; this side never decides that.
//!
//! On a node the vault is addressed through ghostkeys' pointer record
//! (FREENET.md in freenet/ghostkeys), never by a key pinned here, because
//! the delegate re-keys on every release. Its answers carry no request id, so
//! one request is out at a time.
//!
//! With the `test-ghost-master` feature (offline builds, and the real-node
//! test's build) the page answers its own requests with the test keys of
//! `contracts/inbox-v2/tests/fixtures/ghost-keys.txt`, as a vault holding
//! them would, and inbox parameters name that fixture's master.

use freenet_mail_protocol::inbox_v2::GhostProof;
use ghostkey_common::{GhostKeyInfo, GhostkeyRequest, GhostkeyResponse};
use ghostkey_verify::GhostkeyCertificate;
use serde_bytes::{ByteArray, ByteBuf};

/// The webapp contract the vault attests as the requestor, and where the
/// purchase page sends the user back to. Every inbox pins it.
const WEBAPP_ID: &str = include_str!("../../published-contract/contract-id.txt");

/// One key the vault lets this app use.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Key {
    pub fingerprint: String,
    pub label: Option<String>,
    /// The donation tier, in US dollars, as the notary wrote it.
    pub usd: Option<u64>,
    pub vk: Option<[u8; 32]>,
}

impl Key {
    fn from_info(k: GhostKeyInfo) -> Self {
        Key {
            usd: ghostkey_verify::NotaryInfo::parse(&k.notary_info)
                .ok()
                .map(|i| i.amount),
            vk: k
                .verifying_key_bytes
                .as_deref()
                .and_then(|b| b.try_into().ok()),
            fingerprint: k.fingerprint,
            label: k.label,
        }
    }

    /// How the picker names it.
    pub(crate) fn name(&self) -> String {
        let tier = self.usd.map(|u| format!(" (${u})")).unwrap_or_default();
        match &self.label {
            Some(l) => format!("{l}{tier}"),
            None => format!("{}{tier}", self.fingerprint),
        }
    }
}

/// How many keys the user holds: counts only, never which (`HasIdentity`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Presence {
    pub usable: usize,
    /// Keys whose certificate is there and whose signing key is lost.
    pub unusable: usize,
}

/// Why the vault did not sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The user has no key that can sign (`NoIdentityAvailable`).
    NoKey,
    /// The user said no (`AccessDenied` or `PermissionDenied`).
    Denied,
    /// No answer, or one this page cannot use.
    Failed(String),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::NoKey => f.write_str("you have no Ghost Key that can sign"),
            Refusal::Denied => f.write_str("Ghost Key access was declined"),
            Refusal::Failed(e) => write!(f, "Ghost Key did not answer: {e}"),
        }
    }
}

fn unexpected(r: &GhostkeyResponse) -> Refusal {
    match r {
        GhostkeyResponse::NoIdentityAvailable => Refusal::NoKey,
        GhostkeyResponse::AccessDenied { .. } | GhostkeyResponse::PermissionDenied { .. } => {
            Refusal::Denied
        }
        GhostkeyResponse::Error { message } => Refusal::Failed(message.clone()),
        other => Refusal::Failed(format!("an unexpected answer: {other:?}")),
    }
}

/// Whether the user holds a key, without a prompt.
pub(crate) async fn presence() -> Result<Presence, Refusal> {
    match ask(GhostkeyRequest::HasIdentity, false).await? {
        GhostkeyResponse::IdentityPresence { usable, unusable } => {
            Ok(Presence { usable, unusable })
        }
        other => Err(unexpected(&other)),
    }
}

/// The keys this app may use, and which is the default, without a prompt.
pub(crate) async fn keys() -> Result<(Vec<Key>, Option<String>), Refusal> {
    let keys = match ask(GhostkeyRequest::ListGhostKeys, false).await? {
        GhostkeyResponse::GhostKeyList { keys } => keys.into_iter().map(Key::from_info).collect(),
        other => return Err(unexpected(&other)),
    };
    let default = match ask(GhostkeyRequest::GetDefaultKey, false).await? {
        GhostkeyResponse::DefaultKeyResult { fingerprint } => fingerprint,
        other => return Err(unexpected(&other)),
    };
    Ok((keys, default))
}

/// Ask the user to let this app use one of their keys (the vault prompts
/// and the user picks). Returns the key they chose.
pub(crate) async fn request_access() -> Result<Vec<Key>, Refusal> {
    match ask(GhostkeyRequest::RequestAnyAccess, true).await? {
        GhostkeyResponse::GhostKeyList { keys } => {
            Ok(keys.into_iter().map(Key::from_info).collect())
        }
        other => Err(unexpected(&other)),
    }
}

/// A key's verifying key, from its certificate when the list did not carry
/// it (a vault older than 0.2.2).
pub(crate) async fn verifying_key(key: &Key) -> Result<[u8; 32], Refusal> {
    if let Some(vk) = key.vk {
        return Ok(vk);
    }
    let request = GhostkeyRequest::GetCertificate {
        fingerprint: key.fingerprint.clone(),
    };
    match ask(request, true).await? {
        GhostkeyResponse::Certificate {
            certificate_pem, ..
        } => GhostkeyCertificate::from_armored(&certificate_pem)
            .map(|c| c.claimed_ghost_key().to_bytes())
            .map_err(|e| Refusal::Failed(format!("its certificate does not read: {e}"))),
        other => Err(unexpected(&other)),
    }
}

/// A signature the vault made, as a proof the inbox contract checks.
#[derive(Clone, Debug)]
pub(crate) struct Signed {
    pub proof: GhostProof,
    /// The key that signed: the certificate's, which the contract checks.
    pub vk: [u8; 32],
    pub fingerprint: String,
    /// The tier, read from the certificate after checking it chains to this
    /// network's master.
    pub usd: u64,
}

/// Sign `payload` with `key`, or with the user's default key when `key` is
/// the default (the vault may then let the user pick another: the result
/// names the key that signed).
pub(crate) async fn sign(key: &Key, default: bool, payload: Vec<u8>) -> Result<Signed, Refusal> {
    let message = payload.clone();
    let request = if default {
        GhostkeyRequest::SignWithDefault { message: payload }
    } else {
        GhostkeyRequest::SignMessage {
            fingerprint: key.fingerprint.clone(),
            message: payload,
        }
    };
    match ask(request, true).await? {
        GhostkeyResponse::SignResult {
            scoped_payload,
            signature,
            certificate_pem,
        } => {
            let signed = proof(scoped_payload, signature, &certificate_pem)?;
            answers(&message, &signed)?;
            Ok(signed)
        }
        other => Err(unexpected(&other)),
    }
}

fn proof(scoped: Vec<u8>, signature: Vec<u8>, pem: &str) -> Result<Signed, Refusal> {
    let bad = |what: &str| Refusal::Failed(format!("the signature it returned {what}"));
    let cert = GhostkeyCertificate::from_armored(pem).map_err(|_| bad("has no certificate"))?;
    let master = ed25519_dalek::VerifyingKey::from_bytes(&crate::v2::ghost_master())
        .map_err(|_| bad("cannot be checked"))?;
    let verified = cert
        .verify(&master)
        .map_err(|_| bad("is from a Ghost Key this network does not accept"))?;
    let sig: [u8; 64] = signature
        .as_slice()
        .try_into()
        .map_err(|_| bad("is malformed"))?;
    let vk = verified.ghost_key().to_bytes();
    let info = verified
        .notary_info()
        .map_err(|_| bad("names no donation"))?;
    Ok(Signed {
        usd: donation_usd(&info.action, info.amount)?,
        fingerprint: fingerprint(&vk),
        vk,
        proof: GhostProof {
            cert: ByteBuf::from(cert.to_cbor()),
            scoped_payload: ByteBuf::from(scoped),
            ghost_sig: ByteArray::new(sig),
        },
    })
}

/// The tier a certificate's notary line gives: inboxes count only a
/// donation (`freenet-donation`), whatever the amount.
fn donation_usd(action: &str, amount: u64) -> Result<u64, Refusal> {
    if action != "freenet-donation" {
        return Err(Refusal::Failed(
            "this Ghost Key is not a donation key, and inboxes accept only those".into(),
        ));
    }
    Ok(amount)
}

/// Whether `s` answers a request to sign `payload` for this app.
/// The vault's answers carry no request id, so an answer to an earlier
/// prompt the user approved late must not pass for this one: the payload
/// signed must be this one, for this app, under the certificate's key.
fn answers(payload: &[u8], s: &Signed) -> Result<(), Refusal> {
    let other = || {
        Err(Refusal::Failed(
            "Ghost Key answered another request; send again".into(),
        ))
    };
    let Ok(scoped) =
        ghostkey_common::from_cbor::<ghostkey_common::ScopedPayload>(&s.proof.scoped_payload)
    else {
        return other();
    };
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&s.vk) else {
        return other();
    };
    if scoped.payload != payload
        || scoped.requestor != requestor()
        || ghostkey_verify::verify_payload_signature(
            &vk,
            &s.proof.scoped_payload,
            s.proof.ghost_sig.as_slice(),
        )
        .is_err()
    {
        return other();
    }
    Ok(())
}

/// The vault's name for a key: base58 of the first 8 bytes of its BLAKE3.
pub(crate) fn fingerprint(vk: &[u8; 32]) -> String {
    bs58::encode(&blake3::hash(vk).as_bytes()[..8]).into_string()
}

/// Where to get a Ghost Key, coming back to `draft`: freenet.org's purchase
/// page carries `return_to` (this app's contract) and `return_path` (the
/// draft's route, percent-encoded) through to the vault's return link.
pub(crate) fn get_link(draft: &str) -> String {
    let path = format!("#/compose?draft={draft}");
    let encoded: String = path
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect();
    format!(
        "https://freenet.org/ghostkey/create/?return_to={}&return_path={encoded}",
        WEBAPP_ID.trim()
    )
}

/// The draft a `#/compose?draft=<id>` route names.
#[cfg(any(test, target_family = "wasm"))]
pub(crate) fn draft_in_route(hash: &str) -> Option<String> {
    let id = hash.strip_prefix("#/compose?draft=")?;
    (!id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
    .then(|| id.to_string())
}

/// This app, as the vault names the requestor of a signature.
fn requestor() -> ghostkey_common::SignatureRequestor {
    let id: [u8; 32] = bs58::decode(WEBAPP_ID.trim())
        .into_vec()
        .ok()
        .and_then(|v| v.try_into().ok())
        .expect("the committed webapp id is 32 bytes");
    ghostkey_common::SignatureRequestor::WebApp(freenet_stdlib::prelude::ContractInstanceId::new(
        id,
    ))
}

#[cfg(feature = "test-ghost-master")]
use mock::ask;
#[cfg(all(feature = "use-node", not(feature = "test-ghost-master")))]
use node::ask;

#[cfg(all(not(feature = "use-node"), not(feature = "test-ghost-master")))]
async fn ask(_: GhostkeyRequest, _: bool) -> Result<GhostkeyResponse, Refusal> {
    Err(Refusal::Failed("this build has no node".into()))
}

#[cfg(feature = "use-node")]
pub(crate) use node::{missing, response, takes};

/// The ghostkeys delegate on the user's node.
#[cfg(feature = "use-node")]
mod node {
    use std::cell::RefCell;
    use std::rc::Rc;

    use freenet_migrate::{PointerFloor, PointerOutcome, PointerResolver};
    use freenet_stdlib::client_api::DelegateRequest;
    use freenet_stdlib::prelude::*;
    use futures::channel::oneshot;

    use super::*;
    use crate::v2::net::{self, Got};

    /// ghostkeys' author key, from its FREENET.md: the pointer record's
    /// trust anchor (`river:v1:vk:6kWWDBPRne385neUxXmzqpabUYxRbBYCTYSS8BAcPb29`).
    const AUTHOR_VK: &str = "6kWWDBPRne385neUxXmzqpabUYxRbBYCTYSS8BAcPb29";
    const APP_ID: &[u8] = b"ghostkeys.ghostkey-delegate";
    /// The delegate's code hash in pointer record version 1, used only when
    /// the network says the pointer was never published.
    const FALLBACK_CODE_HASH: &str =
        "0d0e2043c5242953b6e8705179ca6847f1d83fce8e23a4ae314118d9b22ffd62";
    const FLOOR_KEY: &str = "fmail-ghostkeys-pointer-floor";
    /// A request that may prompt waits for the user; others answer at once.
    const QUICK_MS: u32 = 30_000;
    const PROMPT_MS: u32 = 10 * 60_000;

    type Answer = Result<GhostkeyResponse, Refusal>;

    thread_local! {
        static KEY: RefCell<Option<DelegateKey>> = const { RefCell::new(None) };
        static WAITER: RefCell<Option<oneshot::Sender<Answer>>> = const { RefCell::new(None) };
        static ONE_AT_A_TIME: Rc<futures::lock::Mutex<()>> = Rc::new(futures::lock::Mutex::new(()));
    }

    pub(crate) fn takes(key: &DelegateKey) -> bool {
        KEY.with(|k| k.borrow().as_ref() == Some(key))
    }

    /// The vault's answer to the request out.
    pub(crate) fn response(values: &[OutboundDelegateMsg]) {
        for msg in values {
            if let OutboundDelegateMsg::ApplicationMessage(app) = msg {
                let answer = ghostkey_common::from_cbor::<GhostkeyResponse>(&app.payload)
                    .map_err(Refusal::Failed);
                if let Some(w) = WAITER.with(|w| w.borrow_mut().take()) {
                    let _ = w.send(answer);
                }
                return;
            }
        }
    }

    /// The node has no such delegate: the vault is not installed here.
    pub(crate) fn missing() {
        if let Some(w) = WAITER.with(|w| w.borrow_mut().take()) {
            let _ = w.send(Err(Refusal::Failed(
                "the Ghost Key vault is not installed on this node".into(),
            )));
        }
    }

    fn hex32(s: &str) -> Option<[u8; 32]> {
        let bytes: Option<Vec<u8>> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
            .collect();
        bytes?.try_into().ok()
    }

    #[cfg(target_family = "wasm")]
    fn storage() -> Option<web_sys::Storage> {
        web_sys::window()?.local_storage().ok()?
    }

    #[cfg(not(target_family = "wasm"))]
    fn storage() -> Option<NoStorage> {
        None
    }

    #[cfg(not(target_family = "wasm"))]
    struct NoStorage;

    #[cfg(not(target_family = "wasm"))]
    impl NoStorage {
        fn get_item(&self, _: &str) -> Result<Option<String>, ()> {
            Ok(None)
        }
        fn set_item(&self, _: &str, _: &str) -> Result<(), ()> {
            Ok(())
        }
    }

    /// The highest pointer version seen, so an older record is refused. Kept
    /// in this browser: losing it only allows a record already superseded.
    fn load_floor() -> PointerFloor {
        let saved = storage().and_then(|s| s.get_item(FLOOR_KEY).ok()?);
        let parsed = saved.as_deref().and_then(|s| {
            let (version, hash) = s.split_once(':')?;
            let version = version.parse().ok()?;
            match hash {
                "withdrawn" => PointerFloor::withdrawn_at(version).ok(),
                h => PointerFloor::at(version, hex32(h)?).ok(),
            }
        });
        parsed.unwrap_or_else(PointerFloor::never_resolved)
    }

    fn save_floor(floor: PointerFloor) {
        let hash = match floor.code_hash() {
            Some(h) => h.iter().map(|b| format!("{b:02x}")).collect(),
            None if floor.is_withdrawn() => "withdrawn".to_string(),
            None => return,
        };
        if let Some(s) = storage() {
            let _ = s.set_item(FLOOR_KEY, &format!("{}:{hash}", floor.version()));
        }
    }

    fn key_for(code_hash: [u8; 32]) -> DelegateKey {
        let key = blake3::hash(&code_hash);
        DelegateKey::new(*key.as_bytes(), CodeHash::new(code_hash))
    }

    async fn delegate_key() -> Result<DelegateKey, Refusal> {
        if let Some(k) = KEY.with(|k| k.borrow().clone()) {
            return Ok(k);
        }
        let fail = |e: String| Refusal::Failed(format!("the Ghost Key vault was not found: {e}"));
        let author: [u8; 32] = bs58::decode(AUTHOR_VK)
            .into_vec()
            .ok()
            .and_then(|v| v.try_into().ok())
            .expect("the author key is 32 bytes");
        let author =
            ed25519_dalek::VerifyingKey::from_bytes(&author).expect("the author key is a key");
        let mut resolver =
            PointerResolver::new(&author, APP_ID, load_floor()).map_err(|e| fail(e.to_string()))?;
        let id = resolver.pointer_id();
        let _ = resolver.next_action();
        match net::get_id(id).await {
            Ok(Got::State(s)) => resolver.on_response(id, &s),
            Ok(Got::Missing) => resolver.on_absent(id),
            Err(_) => resolver.on_unreachable(id),
        };
        let outcome = match resolver.take_outcome() {
            Some(Ok(o)) => o,
            Some(Err(e)) => return Err(fail(e.to_string())),
            None => return Err(fail("no answer".into())),
        };
        if let Some(floor) = outcome.next_floor() {
            save_floor(floor);
        }
        let key = match &outcome {
            o if o.resolved().is_some() => {
                let r = o.resolved().expect("checked");
                r.delegate_key(&Parameters::from(Vec::<u8>::new()))
            }
            PointerOutcome::NeverPublished => {
                key_for(hex32(FALLBACK_CODE_HASH).expect("the fallback code hash is hex"))
            }
            other => return Err(fail(format!("{other:?}"))),
        };
        KEY.with(|k| *k.borrow_mut() = Some(key.clone()));
        Ok(key)
    }

    /// How long a request that got no answer in time (or whose caller
    /// stopped waiting) keeps the vault's turn, waiting for its late answer.
    const LATE_MS: i64 = 5 * 60_000;

    thread_local! {
        /// The answer still owed to a request that stopped waiting, and until
        /// when it is waited for. Answers carry no request id, so the next
        /// request is sent only once this one's answer came (and is dropped)
        /// or its wait is over.
        static LATE: RefCell<Option<Owed>> = const { RefCell::new(None) };
    }

    /// An answer owed to a request. Dropped unanswered (timed out, or the
    /// call cancelled), it is left in [`LATE`] for the next request to wait on.
    struct Owed {
        rx: Option<oneshot::Receiver<Answer>>,
        until: i64,
    }

    impl Drop for Owed {
        fn drop(&mut self) {
            if let Some(rx) = self.rx.take() {
                let until = self.until;
                LATE.with(|l| {
                    *l.borrow_mut() = Some(Owed {
                        rx: Some(rx),
                        until,
                    })
                });
            }
        }
    }

    fn now_ms() -> i64 {
        crate::mail_delegate::ops::now_ms()
    }

    #[cfg(not(test))]
    fn timer(ms: i64) -> impl std::future::Future<Output = ()> {
        gloo_timers::future::TimeoutFuture::new(u32::try_from(ms.max(0)).unwrap_or(u32::MAX))
    }

    #[cfg(test)]
    thread_local! {
        /// Tests: the timers running, fired by the test.
        static TIMERS: RefCell<Vec<oneshot::Sender<()>>> = const { RefCell::new(Vec::new()) };
        /// Tests: the client requests go to.
        static TEST_SENDER: RefCell<Option<crate::api::WebApiRequestClient>> =
            const { RefCell::new(None) };
    }

    #[cfg(test)]
    fn timer(_ms: i64) -> impl std::future::Future<Output = ()> {
        let (tx, rx) = oneshot::channel();
        TIMERS.with(|t| t.borrow_mut().push(tx));
        async move {
            let _ = rx.await;
        }
    }

    fn sender() -> Option<crate::api::WebApiRequestClient> {
        #[cfg(test)]
        if let Some(s) = TEST_SENDER.with(|t| t.borrow().clone()) {
            return Some(s);
        }
        crate::api::WEB_API_SENDER.get().cloned()
    }

    /// Wait out a request that stopped waiting: for its answer (dropped:
    /// it is not this request's) or the end of its wait, whichever is first.
    async fn wait_for_late() {
        use futures::FutureExt;
        let Some(mut late) = LATE.with(|l| l.borrow_mut().take()) else {
            return;
        };
        let Some(rx) = late.rx.as_mut() else {
            return;
        };
        let mut timer = Box::pin(timer(late.until - now_ms())).fuse();
        let answered = futures::select! {
            _ = rx.fuse() => true,
            _ = timer => now_ms() >= late.until,
        };
        if answered {
            // Answered or given up: owed no longer.
            late.rx = None;
            WAITER.with(|w| w.borrow_mut().take());
        }
        // Not over (a timer fired early): `late` goes back to LATE on drop,
        // and the caller waits again.
    }

    #[cfg_attr(feature = "test-ghost-master", allow(dead_code))]
    pub(super) async fn ask(request: GhostkeyRequest, prompts: bool) -> Answer {
        let lock = ONE_AT_A_TIME.with(Rc::clone);
        let _turn = lock.lock().await;
        while LATE.with(|l| l.borrow().is_some()) {
            wait_for_late().await;
        }
        let key = delegate_key().await?;
        let bytes = ghostkey_common::to_cbor(&request).map_err(Refusal::Failed)?;
        let message = DelegateRequest::ApplicationMessages {
            key,
            params: Parameters::from(Vec::<u8>::new()),
            inbound: vec![InboundDelegateMsg::ApplicationMessage(
                ApplicationMessage::new(bytes),
            )],
        };
        let mut client =
            sender().ok_or_else(|| Refusal::Failed("not connected to the node".into()))?;
        let (tx, rx) = oneshot::channel();
        WAITER.with(|w| *w.borrow_mut() = Some(tx));
        if let Err(e) = client.send(message.into()).await {
            WAITER.with(|w| w.borrow_mut().take());
            return Err(Refusal::Failed(e.to_string()));
        }
        // From here its answer is owed: a timeout or a cancelled call leaves
        // it for the next request to wait on.
        let mut owed = Owed {
            rx: Some(rx),
            until: now_ms(),
        };
        use futures::FutureExt;
        let ms = if prompts { PROMPT_MS } else { QUICK_MS };
        let mut timer = Box::pin(timer(i64::from(ms))).fuse();
        let got = {
            let rx = owed.rx.as_mut().expect("just set").fuse();
            futures::pin_mut!(rx);
            futures::select! {
                a = rx => Some(a),
                _ = timer => None,
            }
        };
        owed.until = now_ms() + LATE_MS;
        match got {
            Some(a) => {
                owed.rx = None;
                a.unwrap_or_else(|_| Err(Refusal::Failed("no answer".into())))
            }
            None => Err(Refusal::Failed(
                "the Ghost Key vault did not answer in time, so whether it acted is unknown".into(),
            )),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use freenet_stdlib::client_api::ClientRequest;

        type Requests = futures::channel::mpsc::UnboundedReceiver<ClientRequest<'static>>;

        fn connect() -> Requests {
            let (tx, rx) = futures::channel::mpsc::unbounded();
            let (responses, _) = futures::channel::mpsc::unbounded();
            TEST_SENDER.with(|t| {
                *t.borrow_mut() = Some(crate::api::WebApiRequestClient::for_tests(tx, responses))
            });
            KEY.with(|k| *k.borrow_mut() = Some(key_for([7; 32])));
            rx
        }

        fn fire() {
            TIMERS.with(|t| {
                t.borrow_mut().drain(..).for_each(|t| {
                    let _ = t.send(());
                })
            });
        }

        fn answer(r: &GhostkeyResponse) {
            let payload = ghostkey_common::to_cbor(r).unwrap();
            response(&[OutboundDelegateMsg::ApplicationMessage(
                ApplicationMessage::new(payload),
            )]);
        }

        type Out = Rc<RefCell<Option<Answer>>>;

        fn start(pool: &futures::executor::LocalPool) -> Out {
            use futures::task::LocalSpawnExt;
            let out: Out = Default::default();
            let o = out.clone();
            pool.spawner()
                .spawn_local(async move {
                    *o.borrow_mut() = Some(ask(GhostkeyRequest::HasIdentity, false).await);
                })
                .unwrap();
            out
        }

        fn sent(requests: &mut Requests) -> usize {
            std::iter::from_fn(|| requests.try_recv().ok()).count()
        }

        /// Class C: request A times out and is told so as unknown; B waits.
        /// A's late answer is A's and is dropped; only then is B sent, and
        /// B gets its own answer. The wait for a late answer is bounded.
        #[test]
        fn a_late_vault_answer_is_never_the_next_requests() {
            let mut requests = connect();
            let mut pool = futures::executor::LocalPool::new();
            let a = start(&pool);
            pool.run_until_stalled();
            fire();
            pool.run_until_stalled();
            assert!(
                matches!(&*a.borrow(), Some(Err(Refusal::Failed(e))) if e.contains("unknown")),
                "{:?}",
                a.borrow()
            );
            let b = start(&pool);
            pool.run_until_stalled();
            assert_eq!(sent(&mut requests), 1, "B waits for A's answer");
            answer(&GhostkeyResponse::NoIdentityAvailable);
            pool.run_until_stalled();
            assert!(
                b.borrow().is_none(),
                "A's answer resolved B: {:?}",
                b.borrow()
            );
            assert_eq!(sent(&mut requests), 1, "B goes out after A's answer");
            answer(&GhostkeyResponse::Error {
                message: "own".into(),
            });
            pool.run_until_stalled();
            assert!(
                matches!(&*b.borrow(), Some(Ok(GhostkeyResponse::Error { .. }))),
                "{:?}",
                b.borrow()
            );

            // C times out and its answer never comes: D goes out only once
            // the wait is over, not when a timer fires early.
            let c = start(&pool);
            pool.run_until_stalled();
            fire();
            pool.run_until_stalled();
            assert!(c.borrow().is_some());
            let d = start(&pool);
            pool.run_until_stalled();
            fire();
            pool.run_until_stalled();
            assert_eq!(sent(&mut requests), 1, "C sent, D still waiting");
            futures::executor::block_on(crate::mail_delegate::ops::pause_ms(LATE_MS as u32));
            fire();
            pool.run_until_stalled();
            assert_eq!(sent(&mut requests), 1, "D sent once the wait is over");
            answer(&GhostkeyResponse::Error {
                message: "own".into(),
            });
            pool.run_until_stalled();
            assert!(matches!(
                &*d.borrow(),
                Some(Ok(GhostkeyResponse::Error { .. }))
            ));
            TEST_SENDER.with(|t| t.borrow_mut().take());
        }
    }
}

/// The page's own vault, holding the fixture's test keys.
#[cfg(feature = "test-ghost-master")]
pub(crate) mod mock {
    use ed25519_dalek::{Signer, SigningKey};
    use serde::{Deserialize, Serialize};

    use super::*;

    /// In this build's WASM only with the feature: the release check refuses
    /// a build that has it.
    pub(crate) const MARKER: &str = if cfg!(feature = "test-ghost-master") {
        "freenet-mail:test-ghost-master-built-in"
    } else {
        ""
    };

    const FIXTURE: &str = include_str!("../../contracts/inbox-v2/tests/fixtures/ghost-keys.txt");

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("fixture hex"))
            .collect()
    }

    /// The fixture's master.
    pub(crate) fn master() -> [u8; 32] {
        let line = FIXTURE.lines().find_map(|l| l.strip_prefix("master_vk "));
        hex(line.expect("the fixture names its master").trim())
            .try_into()
            .expect("32 bytes")
    }

    /// Fixture key `i`: its signing key and its certificate.
    fn fixture(i: usize) -> Option<(SigningKey, GhostkeyCertificate)> {
        let line = FIXTURE.lines().filter(|l| l.starts_with("cert ")).nth(i)?;
        let f: Vec<&str> = line.split_whitespace().collect();
        let sk: [u8; 32] = hex(f[2]).try_into().ok()?;
        Some((
            SigningKey::from_bytes(&sk),
            GhostkeyCertificate::from_cbor(&hex(f[3])).ok()?,
        ))
    }

    /// What the mock vault holds, in `localStorage` under [`STATE_KEY`] so a
    /// test sets it: fixture indices (0 to 3 are $1, 4 to 7 $5, 8 and 9 $20).
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(default)]
    pub(crate) struct State {
        pub keys: Vec<usize>,
        pub default: Option<usize>,
        /// Keys this app may use: granted at the first prompt for each.
        pub granted: Vec<usize>,
        /// The user says no to every prompt.
        pub deny: bool,
        /// Keys whose signing key is lost.
        pub unusable: usize,
        /// Prompts shown so far.
        pub prompts: u32,
    }

    impl Default for State {
        fn default() -> Self {
            State {
                keys: vec![4],
                default: Some(4),
                granted: Vec::new(),
                deny: false,
                unusable: 0,
                prompts: 0,
            }
        }
    }

    pub(crate) const STATE_KEY: &str = "fmail-ghostkeys-mock";

    thread_local! {
        /// The state when the page has no localStorage (a sandboxed frame).
        static STATE: std::cell::RefCell<State> = std::cell::RefCell::new(State::default());
    }

    #[cfg(target_family = "wasm")]
    fn storage() -> Option<web_sys::Storage> {
        web_sys::window()?.local_storage().ok()?
    }

    #[cfg(not(target_family = "wasm"))]
    fn storage() -> Option<NoStorage> {
        None
    }

    #[cfg(not(target_family = "wasm"))]
    struct NoStorage;

    #[cfg(not(target_family = "wasm"))]
    impl NoStorage {
        fn get_item(&self, _: &str) -> Result<Option<String>, ()> {
            Ok(None)
        }
        fn set_item(&self, _: &str, _: &str) -> Result<(), ()> {
            Ok(())
        }
    }

    pub(crate) fn load() -> State {
        storage()
            .and_then(|s| s.get_item(STATE_KEY).ok()?)
            .and_then(|j| serde_json::from_str(&j).ok())
            .unwrap_or_else(|| STATE.with(|s| s.borrow().clone()))
    }

    pub(crate) fn save(state: &State) {
        STATE.with(|s| *s.borrow_mut() = state.clone());
        if let Some(s) = storage() {
            let _ = s.set_item(STATE_KEY, &serde_json::to_string(state).expect("encodes"));
        }
    }

    fn info(i: usize) -> Option<GhostKeyInfo> {
        let (sk, cert) = fixture(i)?;
        let master = ed25519_dalek::VerifyingKey::from_bytes(&master()).ok()?;
        let verified = cert.verify(&master).ok()?;
        let vk = sk.verifying_key().to_bytes();
        Some(GhostKeyInfo {
            fingerprint: fingerprint(&vk),
            label: Some(format!("test key {i}")),
            notary_info: verified.info().to_string(),
            verifying_key_bytes: Some(vk.to_vec()),
            backed_up: true,
        })
    }

    fn index_of(state: &State, fp: &str) -> Option<usize> {
        state
            .keys
            .iter()
            .copied()
            .find(|&i| info(i).is_some_and(|k| k.fingerprint == fp))
    }

    /// A prompt for key `i`: granted once, as the vault asks once per key
    /// and app.
    fn consent(state: &mut State, i: usize) -> bool {
        if state.granted.contains(&i) {
            return true;
        }
        state.prompts += 1;
        if state.deny {
            return false;
        }
        state.granted.push(i);
        true
    }

    fn signed(i: usize, message: Vec<u8>) -> GhostkeyResponse {
        let (sk, cert) = fixture(i).expect("a fixture key");
        let scoped = ghostkey_common::to_cbor(&ghostkey_common::ScopedPayload {
            requestor: requestor(),
            payload: message,
        })
        .expect("encodes");
        GhostkeyResponse::SignResult {
            signature: sk.sign(&scoped).to_bytes().to_vec(),
            scoped_payload: scoped,
            certificate_pem: cert.to_armored(),
        }
    }

    pub(super) async fn ask(
        request: GhostkeyRequest,
        _prompts: bool,
    ) -> Result<GhostkeyResponse, Refusal> {
        let mut state = load();
        let denied = GhostkeyResponse::AccessDenied {
            requestor: requestor(),
        };
        let default = state
            .default
            .filter(|d| state.keys.contains(d))
            .or(state.keys.first().copied());
        let answer = match request {
            GhostkeyRequest::HasIdentity => GhostkeyResponse::IdentityPresence {
                usable: state.keys.len(),
                unusable: state.unusable,
            },
            GhostkeyRequest::ListGhostKeys => GhostkeyResponse::GhostKeyList {
                keys: state
                    .keys
                    .iter()
                    .filter(|i| state.granted.contains(i))
                    .filter_map(|&i| info(i))
                    .collect(),
            },
            GhostkeyRequest::GetDefaultKey => GhostkeyResponse::DefaultKeyResult {
                fingerprint: default
                    .filter(|i| state.granted.contains(i))
                    .and_then(info)
                    .map(|k| k.fingerprint),
            },
            GhostkeyRequest::RequestAnyAccess => match default {
                None => GhostkeyResponse::NoIdentityAvailable,
                Some(i) if consent(&mut state, i) => GhostkeyResponse::GhostKeyList {
                    keys: info(i).into_iter().collect(),
                },
                Some(_) => denied,
            },
            GhostkeyRequest::SignWithDefault { message } => match default {
                None => GhostkeyResponse::NoIdentityAvailable,
                Some(i) if consent(&mut state, i) => signed(i, message),
                Some(_) => denied,
            },
            GhostkeyRequest::SignMessage {
                fingerprint,
                message,
            } => match index_of(&state, &fingerprint) {
                None => GhostkeyResponse::KeyNotFound { fingerprint },
                Some(i) if consent(&mut state, i) => signed(i, message),
                Some(_) => GhostkeyResponse::PermissionDenied {
                    fingerprint,
                    requestor: requestor(),
                },
            },
            other => GhostkeyResponse::Error {
                message: format!("the test vault does not do {other:?}"),
            },
        };
        save(&state);
        Ok(answer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// N4: inboxes count only a donation key's tier.
    #[test]
    fn only_a_donation_key_has_a_tier() {
        assert_eq!(donation_usd("freenet-donation", 5).ok(), Some(5));
        assert!(donation_usd("other-action", 50).is_err());
    }

    /// S1: an answer is checked against the request: one signed over
    /// another payload (a late answer to an earlier prompt), with a
    /// signature that does not verify, or for another requestor is refused.
    #[cfg(feature = "test-ghost-master")]
    #[test]
    fn an_answer_for_another_request_is_refused() {
        mock::save(&mock::State {
            keys: vec![8],
            ..Default::default()
        });
        let key = futures::executor::block_on(request_access())
            .unwrap()
            .remove(0);
        let s = futures::executor::block_on(sign(&key, true, b"message 1".to_vec())).unwrap();
        assert!(answers(b"message 1", &s).is_ok());
        assert!(answers(b"message 2", &s).is_err(), "another payload");
        let mut forged = s.clone();
        forged.proof.ghost_sig = ByteArray::new([7; 64]);
        assert!(answers(b"message 1", &forged).is_err(), "a bad signature");
        let mut other = s.clone();
        let mut scoped: ghostkey_common::ScopedPayload =
            ghostkey_common::from_cbor(&s.proof.scoped_payload).unwrap();
        scoped.requestor = ghostkey_common::SignatureRequestor::WebApp(
            freenet_stdlib::prelude::ContractInstanceId::new([9; 32]),
        );
        other.proof.scoped_payload = ByteBuf::from(ghostkey_common::to_cbor(&scoped).unwrap());
        assert!(answers(b"message 1", &other).is_err(), "another requestor");
    }

    #[test]
    fn the_link_carries_the_app_and_the_draft_route() {
        let link = get_link("d-1");
        assert!(link.starts_with("https://freenet.org/ghostkey/create/?return_to="));
        assert!(link.contains(&format!("return_to={}&", WEBAPP_ID.trim())));
        assert!(link.ends_with("&return_path=%23%2Fcompose%3Fdraft%3Dd-1"));
        assert_eq!(
            draft_in_route("#/compose?draft=d-1").as_deref(),
            Some("d-1")
        );
        assert_eq!(draft_in_route("#/compose?draft="), None);
        assert_eq!(draft_in_route("#/compose?draft=a&b"), None);
    }

    /// The test vault's signature is a proof the inbox contract's checks
    /// accept: the payload signature under the certified key, the chain to
    /// the test master, the tier, and the pinned requestor.
    #[cfg(feature = "test-ghost-master")]
    #[test]
    fn the_test_vault_signs_proofs_that_chain_to_the_test_master() {
        mock::save(&mock::State {
            keys: vec![8],
            ..Default::default()
        });
        let key = futures::executor::block_on(request_access())
            .unwrap()
            .remove(0);
        assert_eq!(key.usd, Some(20));
        let s = futures::executor::block_on(sign(&key, true, b"payload".to_vec())).unwrap();
        assert_eq!(s.usd, 20);
        assert_eq!(Some(s.vk), key.vk);
        assert_eq!(s.fingerprint, key.fingerprint);
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&s.vk).unwrap();
        ghostkey_verify::verify_payload_signature(
            &vk,
            &s.proof.scoped_payload,
            s.proof.ghost_sig.as_slice(),
        )
        .unwrap();
        let scoped: ghostkey_common::ScopedPayload =
            ghostkey_common::from_cbor(&s.proof.scoped_payload).unwrap();
        assert_eq!(scoped.payload, b"payload");
        assert_eq!(scoped.requestor, requestor());
        // A user who says no is told so, and has no key: told that.
        mock::save(&mock::State {
            keys: vec![8],
            deny: true,
            ..Default::default()
        });
        assert_eq!(
            futures::executor::block_on(sign(&key, true, vec![1])).unwrap_err(),
            Refusal::Denied
        );
        mock::save(&mock::State {
            keys: vec![],
            default: None,
            ..Default::default()
        });
        assert_eq!(
            futures::executor::block_on(sign(&key, true, vec![1])).unwrap_err(),
            Refusal::NoKey
        );
    }
}
