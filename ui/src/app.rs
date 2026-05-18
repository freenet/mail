#[cfg(feature = "example-data")]
use std::collections::HashMap;
use std::fmt::Display;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::{borrow::Cow, cell::RefCell, rc::Rc};

use chrono::Utc;
use dioxus::prelude::*;
use freenet_stdlib::prelude::ContractKey;
use futures::FutureExt;
use futures::future::LocalBoxFuture;
use ml_dsa::{MlDsa65, SigningKey as MlDsaSigningKey};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem768};
use wasm_bindgen::JsValue;

pub(crate) use login::{Identity, LoginController};

use crate::api::{TryNodeAction, node_response_error_handling};
use crate::testid;
use crate::{
    DynError,
    api::WebApiRequestClient,
    inbox::{DecryptedMessage, InboxModel, MessageModel},
};

pub(crate) mod address_book;
pub(crate) mod login;
pub(crate) mod settings;

// In-memory mailbox for offline (`example-data`, `!use-node`) mode.
// Messages composed via `send_message` are stored here keyed by
// recipient alias and picked up by `load_example_messages` when
// the recipient logs in.
#[cfg(feature = "example-data")]
thread_local! {
    static MOCK_SENT_MESSAGES: RefCell<HashMap<String, Vec<Message>>> =
        RefCell::new(HashMap::new());
}

#[derive(Clone, Debug)]
pub(crate) enum NodeAction {
    LoadMessages(Box<Identity>),
    CreateIdentity {
        alias: Rc<str>,
        ml_dsa_key: Arc<MlDsaSigningKey<MlDsa65>>,
        ml_kem_dk: Box<DecapsulationKey<MlKem768>>,
        description: String,
    },
    CreateContract {
        alias: Rc<str>,
        contract_type: ContractType,
        /// ML-DSA-65 signing key used for both inbox ownership and AFT
        /// token signing (same key serves both subsystems post-Stage-4).
        ml_dsa_key: Arc<MlDsaSigningKey<MlDsa65>>,
        /// Initial recipient anti-flood policy seeded into the inbox's
        /// `InboxSettings` at creation. Only consulted for
        /// `ContractType::InboxContract`; the AFT record contract id is
        /// derived from the sender's key alone. Owner can mutate later
        /// via `UpdateInboxPolicy` (#85).
        required_tier: freenet_aft_interface::Tier,
        max_age_secs: u64,
    },
    /// Push a signed `ModifySettings` delta updating the recipient
    /// anti-flood policy on the inbox contract owned by `identity`
    /// (#85). Owner-only; the contract verifies the signature against
    /// `params.pub_key` before accepting.
    UpdateInboxPolicy {
        identity: Box<Identity>,
        required_tier: freenet_aft_interface::Tier,
        max_age_secs: u64,
    },
    /// Push a signed `ModifySettings` delta updating the verified-sender
    /// bypass setting and the `verified_senders` allow-list on the inbox
    /// contract owned by `identity` (#150). Owner-only — same gate as
    /// `UpdateInboxPolicy`. The full current `verified_senders` set is
    /// sent; the contract replaces its stored set atomically.
    UpdateVerifiedBypass {
        identity: Box<Identity>,
        allow_verified_skip_token: bool,
        verified_senders: std::collections::BTreeSet<Vec<u8>>,
    },
    CreateDelegate {
        alias: Rc<str>,
        /// ML-DSA-65 signing key used by the AFT token-generator delegate.
        ml_dsa_key: Arc<MlDsaSigningKey<MlDsa65>>,
    },
    /// Store a new contact in the identity-management delegate.
    CreateContact {
        contact: address_book::Contact,
    },
    /// Remove a contact from the identity-management delegate.
    DeleteContact {
        alias: String,
    },
    /// Rename an own identity. The keypair is preserved — this is a
    /// purely local relabel. Implemented as DeleteIdentity{old} +
    /// CreateIdentity{new, same key, same extra} to avoid a delegate
    /// version bump (see issue #32). Identity is moved through the
    /// action so the keypair travels with it without re-reading
    /// ALIASES on the consumer side.
    RenameIdentity {
        old: Rc<str>,
        new: Rc<str>,
        identity: Box<Identity>,
    },
    /// Delete an own identity from this device. Removes the entry from the
    /// identity-management delegate and from local in-memory stores
    /// (ALIASES, User.identities). The inbox + AFT contracts themselves
    /// remain on-chain but become unreachable from this device: there is
    /// no on-chain "delete contract" primitive, and without the keypair
    /// nobody can sign deltas against them anyway. Irreversible without
    /// the backup file.
    DeleteIdentity {
        identity: Box<Identity>,
    },
}

#[derive(Clone, Debug)]
pub(crate) enum ContractType {
    InboxContract,
    AFTContract,
}

impl Display for ContractType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContractType::InboxContract => write!(f, "InboxContract"),
            ContractType::AFTContract => write!(f, "AFTContract"),
        }
    }
}

pub(crate) fn app() -> Element {
    use_context_provider(|| Signal::new(login::LoginController::new()));
    let login_controller = use_context::<Signal<login::LoginController>>();
    // Initialize and fetch shared state for User and InboxView.
    use_context_provider(|| Signal::new(User::new()));
    let user = use_context::<Signal<User>>();
    use_context_provider(|| Signal::new(InboxView::new()));
    let inbox = use_context::<Signal<InboxView>>();
    use_context_provider(InboxesData::new);
    let inbox_data = use_context::<InboxesData>();
    // Address-book generation counter (#134). Bumped on every
    // CreateContact / DeleteContact so inbox components subscribed via
    // `.read()` re-render and pick up the updated verification state.
    use_context_provider(|| AddressBookGen(Signal::new(0u32)));
    let ab_gen = use_context::<AddressBookGen>();
    // Toast queue is provided at the root so both the node-comms coroutine
    // (which surfaces async AFT failures) and all UI components can push/read
    // toasts without an extra Signal thread-local.
    use_context_provider(|| crate::toast::ToastQueue::new(Vec::new()));
    let toast = use_context::<crate::toast::ToastQueue>();
    // Modal signals lifted to the root so that both the login pane
    // (IdentifiersList) and the inbox (UserInbox → Settings → Contacts)
    // can open these modals. Fixes #158.
    //
    // The actual modal *components* are rendered inside their respective
    // CSS-scope roots (div.fm-pre in IdentifiersList, div.fm-app in
    // UserInbox) so that the `.veil`/`.modal` CSS rules apply correctly.
    // These context providers are still here so both subtrees share the
    // same signal instances.
    use_context_provider(|| Signal::new(login::ImportBackup(false)));
    use_context_provider(|| Signal::new(login::ImportContact(false)));
    use_context_provider(|| Signal::new(login::ShareContact(false)));
    use_context_provider(|| Signal::new(login::SharePending::default()));

    #[cfg(all(feature = "use-node", not(feature = "no-sync")))]
    {
        let _ = toast;
        let _sync: Coroutine<NodeAction> = use_coroutine(move |rx| {
            let login_controller = login_controller;
            let user = user;
            let fut = crate::api::node_comms(rx, login_controller, user, inbox_data, ab_gen)
                .map(|_| Ok(JsValue::NULL));
            let _ = wasm_bindgen_futures::future_to_promise(fut);
            async {}.boxed_local()
        });
    }
    #[cfg(any(not(feature = "use-node"), feature = "no-sync"))]
    {
        let _ = inbox_data;
        let _ = toast;
        let mut login_ctl = login_controller;
        let mut ab_gen = ab_gen;
        let mut user_sig = user;
        let _sync: Coroutine<NodeAction> =
            use_coroutine(move |mut rx: UnboundedReceiver<NodeAction>| async move {
                use futures::StreamExt;
                while let Some(action) = rx.next().await {
                    // Branches don't compose into a let-chain because
                    // CreateContact moves `contact` and the match would
                    // bind it inside a guard.
                    #[allow(clippy::collapsible_match)]
                    match action {
                        NodeAction::CreateContact { contact } => {
                            if address_book::insert_contact(contact).is_ok() {
                                login_ctl.write().updated = true;
                                // Bump generation so MessageList / OpenMessage
                                // re-render and reflect the new contact (#134).
                                let prev = *ab_gen.0.read();
                                ab_gen.0.set(prev.wrapping_add(1));
                            }
                        }
                        NodeAction::DeleteContact { alias } => {
                            address_book::remove_contact(&alias);
                            login_ctl.write().updated = true;
                            // Bump generation so inbox rows that showed the
                            // removed contact as "verified" revert to
                            // "unknown sender" (#134).
                            let prev = *ab_gen.0.read();
                            ab_gen.0.set(prev.wrapping_add(1));
                        }
                        NodeAction::RenameIdentity { old, new, .. } => {
                            // Offline mode: just relabel the in-memory
                            // ALIASES entries. The delegate isn't
                            // around, so there's no delete+create round
                            // trip.
                            Identity::rename_in_place(&old, &new);
                            login_ctl.write().updated = true;
                        }
                        NodeAction::DeleteIdentity { identity } => {
                            Identity::remove_in_place(&identity.alias);
                            let mut user_w = user_sig.write();
                            let was_logged_in = user_w
                                .logged_id()
                                .map(|i| i.id == identity.id)
                                .unwrap_or(false);
                            user_w.identities.retain(|i| i.id != identity.id);
                            if was_logged_in {
                                user_w.logout();
                            }
                            drop(user_w);
                            login_ctl.write().updated = true;
                            address_book::remove_contact(&identity.alias);
                            let prev = *ab_gen.0.read();
                            ab_gen.0.set(prev.wrapping_add(1));
                        }
                        _ => {}
                    }
                }
            });
    }
    #[allow(unused_variables)]
    let actions = use_coroutine_handle::<NodeAction>();

    // Render login page if user not identified, otherwise render the inbox or identifiers list based on user's logged in state
    let body = if !user.read().identified {
        rsx! {
            login::GetOrCreateIdentity {}
        }
    } else if let Some(id) = user.read().logged_id() {
        #[cfg(all(feature = "use-node", not(feature = "no-sync")))]
        {
            inbox
                .read()
                .load_messages(id, &actions)
                .expect("load messages");
        }
        #[cfg(feature = "example-data")]
        {
            inbox
                .read()
                .load_example_messages(id)
                .expect("load mock messages");
        }
        rsx! {
           UserInbox {}
        }
    } else {
        rsx! {
           login::IdentifiersList {}
        }
    };
    let app_name = crate::app_name();
    rsx! {
        document::Title { "{app_name}" }
        {body}
    }
}

/// Reactive store of loaded inbox models. Mirror of freenet-river's
/// `ROOMS` Signal pattern (issue #101). Wrapping a `Signal` rather than
/// an `ArcSwap` means component reads (`inboxes.read()`) auto-subscribe
/// for re-render on writes — no separate bump-signal needed.
#[derive(Clone, Copy)]
pub(crate) struct InboxesData(pub(crate) Signal<Vec<Rc<RefCell<InboxModel>>>>);

/// Generation counter for address-book mutations (issue #134).
///
/// Provided as Dioxus context in `app()` and bumped on every
/// `CreateContact` / `DeleteContact` action so that inbox components
/// that call `verification_state()` (which reads the address book
/// directly) are subscribed to changes. Any component that calls
/// `.read()` on this value is re-rendered the next time the counter
/// increments.
#[derive(Clone, Copy)]
pub(crate) struct AddressBookGen(pub(crate) Signal<u32>);

impl InboxesData {
    pub fn new() -> Self {
        Self(Signal::new(vec![]))
    }

    pub fn snapshot(&self) -> Vec<Rc<RefCell<InboxModel>>> {
        self.0.read().clone()
    }
}

#[derive(Debug, Clone)]
pub struct InboxView {
    active_id: Rc<RefCell<UserId>>,
    /// loaded messages for the currently selected `active_id`
    messages: Rc<RefCell<Vec<Message>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub(crate) struct UserId(usize);

impl UserId {
    pub fn new() -> Self {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
        Self(NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst))
    }
}

impl std::ops::Deref for UserId {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl InboxView {
    fn new() -> Self {
        Self {
            messages: Rc::new(RefCell::new(vec![])),
            active_id: Rc::new(RefCell::new(UserId(0))),
        }
    }

    pub(crate) fn set_active_id(&mut self, user: UserId) {
        let mut id = self.active_id.borrow_mut();
        *id = user;
    }

    #[allow(clippy::too_many_arguments)]
    fn send_message(
        &mut self,
        client: WebApiRequestClient,
        from: &str,
        recipient_ek: EncapsulationKey<MlKem768>,
        recipient_ml_dsa_vk: ml_dsa::VerifyingKey<MlDsa65>,
        recipient_required_tier: freenet_aft_interface::Tier,
        recipient_max_age_secs: u64,
        title: &str,
        content: &str,
        // Optional `(sender_alias, sent_id, inbox_key)` so the future can
        // flip the local Sent row to `Failed` if `start_sending` errors
        // out (AFT denied, encryption, etc.). None during legacy paths.
        ack_meta: Option<(String, String, ContractKey)>,
    ) -> Result<Vec<LocalBoxFuture<'static, ()>>, DynError> {
        use crate::inbox::MlKemEncapsKey;
        tracing::debug!("sending message from {from}");
        let content = DecryptedMessage {
            title: title.to_owned(),
            content: content.to_owned(),
            from: from.to_owned(),
            to: vec![MlKemEncapsKey::from_key(&recipient_ek)],
            cc: vec![],
            time: Utc::now(),
        };
        let mut futs = Vec::with_capacity(content.to.len());
        #[cfg(feature = "use-node")]
        {
            crate::log::debug!("sending message from {from}");
            let content_clone = content.clone();
            let mut client = client.clone();
            let Some(id) = crate::inbox::InboxModel::id_for_alias(from) else {
                crate::log::error(
                    format!("alias `{from}` not stored"),
                    Some(TryNodeAction::SendMessage),
                );
                return Ok(futs);
            };
            let ack_meta_async = ack_meta.clone();
            let f = async move {
                let res = content_clone
                    .start_sending(
                        &mut client,
                        recipient_ek,
                        recipient_ml_dsa_vk,
                        recipient_required_tier,
                        recipient_max_age_secs,
                        &id,
                    )
                    .await;
                let is_err = res.is_err();
                node_response_error_handling(
                    client.clone().into(),
                    res,
                    TryNodeAction::SendMessage,
                )
                .await;
                if is_err && let Some((sender_alias, sent_id, inbox_key)) = ack_meta_async {
                    // `start_sending` failed before the inbox UPDATE was
                    // queued, so the pending entry we enqueued
                    // synchronously will never get acked. Drop just our
                    // entry from the queue (concurrent sends to the same
                    // recipient should be unaffected) and flip the row
                    // to Failed so the user sees the truth.
                    crate::inbox::remove_pending_sent_ack(&inbox_key, &sender_alias, &sent_id);
                    crate::local_state::local_set_sent_delivery_state(
                        &sender_alias,
                        &sent_id,
                        mail_local_state::DeliveryState::Failed,
                    );
                    let mut client_clone = client.clone();
                    if let Err(e) = crate::local_state::set_sent_delivery_state(
                        &mut client_clone,
                        sender_alias,
                        sent_id,
                        mail_local_state::DeliveryState::Failed,
                    )
                    .await
                    {
                        crate::log::local_state_failure("update delivery state", e);
                    }
                }
            };
            futs.push(f.boxed_local());
        }
        // ack_meta is unused on the offline path; explicitly ignored.
        #[cfg(not(feature = "use-node"))]
        let _ = ack_meta;
        #[cfg(all(feature = "example-data", not(feature = "use-node")))]
        {
            // In offline mode, deliver the message to an in-memory mailbox
            // keyed by recipient alias so that switching identities reveals it.
            use ml_kem::kem::KeyExport;
            if let Some(ek_key) = content.to.first()
                && let Some(to_alias) = Identity::alias_for_encaps_key(ek_key.0.as_slice())
            {
                let msg = Message {
                    id: 0, // reassigned on load
                    from: content.from.clone().into(),
                    title: content.title.clone().into(),
                    content: content.content.clone().into(),
                    read: false,
                    time: content.time,
                    sender_vk: Vec::new(),
                    signature_valid: false,
                    assignment_hash: [0u8; 32],
                };
                MOCK_SENT_MESSAGES.with(|map| {
                    map.borrow_mut()
                        .entry(to_alias.to_string())
                        .or_default()
                        .push(msg);
                });
            }
        }
        let _ = client;
        Ok(futs)
    }

    fn remove_messages(
        &mut self,
        client: WebApiRequestClient,
        ids: &[u64],
        inbox_data: InboxesData,
    ) -> Result<LocalBoxFuture<'static, ()>, DynError> {
        tracing::debug!("removing messages: {ids:?}");
        // In offline mode the real `InboxesData` store is never populated,
        // so skip the contract-state mutation and just return a no-op.
        #[cfg(all(feature = "example-data", not(feature = "use-node")))]
        {
            let _ = client;
            let _ = ids;
            let _ = inbox_data;
            Ok(async {}.boxed_local())
        }
        #[cfg(not(all(feature = "example-data", not(feature = "use-node"))))]
        {
            // FIXME: indexing by id fails cause all not aliases inboxes has been loaded initially
            let inbox_data = inbox_data.snapshot();
            let mut inbox = inbox_data[**self.active_id.borrow()].borrow_mut();
            inbox.remove_messages(client, ids)
        }
    }

    // Remove the messages from the inbox contract, and move them to local storage
    fn mark_as_read(
        &mut self,
        client: WebApiRequestClient,
        ids: &[u64],
        inbox_data: InboxesData,
    ) -> Result<LocalBoxFuture<'static, ()>, DynError> {
        {
            let messages = &mut *self.messages.borrow_mut();
            let mut removed_messages = Vec::with_capacity(ids.len());
            for e in messages {
                if ids.contains(&e.id) {
                    e.read = true;
                    let m = e.clone();
                    removed_messages.push(m);
                }
            }
        }
        // todo: persist in a delegate `removed_messages`
        self.remove_messages(client, ids, inbox_data)
    }

    #[cfg(feature = "example-data")]
    fn load_example_messages(&self, id: &Identity) -> Result<(), DynError> {
        // Idempotent: only reload from MOCK_SENT_MESSAGES + seed mocks
        // when the active identity changes. `app()` re-renders many
        // times per session (toast set, signal writes, etc.) and each
        // re-render used to call this — which drained MOCK_SENT_MESSAGES
        // on the *first* render after login, then repopulated `messages`
        // with only the seed mocks on subsequent renders, losing any
        // cross-identity reply that had just been merged in.
        {
            let active = self.active_id.borrow();
            if *active == id.id && !self.messages.borrow().is_empty() {
                return Ok(());
            }
        }
        *self.active_id.borrow_mut() = id.id;

        let body: Cow<'static, str> = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
             Sed do eiusmod tempor incidunt ut labore et dolore magna aliqua."
            .into();
        let now = chrono::Utc::now();
        let t = |minutes_ago: i64| now - chrono::Duration::minutes(minutes_ago);
        let mut emails = if id.id == UserId(0) {
            vec![
                Message {
                    id: 0,
                    from: "Ian's Other Account".into(),
                    title: "Welcome to the offline preview".into(),
                    content: body.clone(),
                    read: false,
                    time: t(15),
                    sender_vk: Vec::new(),
                    signature_valid: false,
                    assignment_hash: [0u8; 32],
                },
                Message {
                    id: 1,
                    from: "Mary".into(),
                    title: "Lunch tomorrow?".into(),
                    content: body.clone(),
                    read: false,
                    time: t(60 * 26),
                    sender_vk: Vec::new(),
                    signature_valid: false,
                    assignment_hash: [0u8; 32],
                },
                Message {
                    id: 2,
                    from: "freenet-bot".into(),
                    title: "Your weekly digest".into(),
                    content: body,
                    read: true,
                    time: t(60 * 24 * 4),
                    sender_vk: Vec::new(),
                    signature_valid: false,
                    assignment_hash: [0u8; 32],
                },
            ]
        } else {
            vec![
                Message {
                    id: 0,
                    from: "Ian Clarke".into(),
                    title: "Welcome to the offline preview".into(),
                    content: body.clone(),
                    read: false,
                    time: t(35),
                    sender_vk: Vec::new(),
                    signature_valid: false,
                    assignment_hash: [0u8; 32],
                },
                Message {
                    id: 1,
                    from: "Jane".into(),
                    title: "Re: design review".into(),
                    content: body,
                    read: false,
                    time: t(60 * 50),
                    sender_vk: Vec::new(),
                    signature_valid: false,
                    assignment_hash: [0u8; 32],
                },
            ]
        };
        // Append any messages sent to this identity via the mock in-memory
        // mailbox (composed in a previous session by another identity).
        let alias = id.alias.to_string();
        MOCK_SENT_MESSAGES.with(|map| {
            if let Some(sent) = map.borrow_mut().remove(&alias) {
                let base_id = emails.len() as u64;
                for (i, mut msg) in sent.into_iter().enumerate() {
                    msg.id = base_id + i as u64;
                    emails.push(msg);
                }
            }
        });

        self.messages.replace(emails);
        Ok(())
    }

    #[cfg(all(feature = "use-node", not(feature = "no-sync")))]
    fn load_messages(
        &self,
        id: &Identity,
        actions: &Coroutine<NodeAction>,
    ) -> Result<(), DynError> {
        actions.send(NodeAction::LoadMessages(Box::new(id.clone())));
        Ok(())
    }
}

pub(crate) struct User {
    logged: bool,
    identified: bool,
    active_id: Option<UserId>,
    pub identities: Vec<Identity>,
}

impl User {
    #[cfg(feature = "example-data")]
    fn new() -> Self {
        use ml_dsa::KeyGen;

        let ml_dsa0 = Arc::new(MlDsa65::from_seed(&rand::random::<[u8; 32]>().into()));
        let ml_dsa1 = Arc::new(MlDsa65::from_seed(&rand::random::<[u8; 32]>().into()));
        // Use rand::random (getrandom 0.2 + js feature) rather than ml-kem's
        // generate_keypair() which needs getrandom 0.4 + wasm_js on WASM.
        let ml_kem_dk0 = DecapsulationKey::<MlKem768>::from_seed({
            use rand::RngCore;
            let mut seed = [0u8; 64];
            rand::thread_rng().fill_bytes(&mut seed);
            seed.into()
        });
        let ml_kem_dk1 = DecapsulationKey::<MlKem768>::from_seed({
            use rand::RngCore;
            let mut seed = [0u8; 64];
            rand::thread_rng().fill_bytes(&mut seed);
            seed.into()
        });

        let identities = vec![
            Identity::new(
                "address1".into(),
                UserId(0),
                "Mock identity (example-data)".into(),
                ml_dsa0,
                ml_kem_dk0,
            ),
            Identity::new(
                "address2".into(),
                UserId(1),
                "Mock identity (example-data)".into(),
                ml_dsa1,
                ml_kem_dk1,
            ),
        ];
        // Register with the shared ALIASES store so IdentifiersList
        // (which reads from ALIASES, not User.identities) sees them.
        for id in &identities {
            Identity::register_example(id.clone());
        }
        // Seed a pre-imported contact so the compose-sheet autocomplete
        // has something to suggest in offline / Playwright test mode.
        // Gated on `not(use-node)` because the fake 0xAA/0xBB key bytes
        // are placeholders and must never be used against a real node.
        #[cfg(not(feature = "use-node"))]
        let _ = address_book::insert_contact(address_book::Contact {
            local_alias: "alice-example".into(),
            description: "Example contact for offline testing".into(),
            ml_dsa_vk_bytes: vec![0xAA; 1952],
            ml_kem_ek_bytes: vec![0xBB; 1184],
            required_tier: freenet_aft_interface::Tier::Min10,
            max_age_secs: freenet_email_inbox::DEFAULT_MAX_AGE_SECS,
            verified: true,
        });
        User {
            logged: false,
            identified: true,
            active_id: None,
            identities,
        }
    }

    #[cfg(not(feature = "example-data"))]
    fn new() -> Self {
        User {
            logged: false,
            identified: true,
            active_id: None,
            identities: vec![],
        }
    }

    pub(crate) fn logged_id(&self) -> Option<&Identity> {
        self.active_id.and_then(|id| self.identities.get(id.0))
    }

    pub(crate) fn set_logged_id(&mut self, id: UserId) {
        assert!(id.0 < self.identities.len());
        self.active_id = Some(id);
    }

    /// Clear the active-identity selection without logging out the user
    /// entirely. Used when an identity is deleted while open.
    pub(crate) fn logout(&mut self) {
        self.logged = false;
        self.active_id = None;
    }
}

#[derive(Debug, Clone, Eq)]
struct Message {
    id: u64,
    from: Cow<'static, str>,
    title: Cow<'static, str>,
    content: Cow<'static, str>,
    read: bool,
    /// Sender-stamped (`DecryptedMessage.time`). Used for list-card
    /// short timestamp + detail-header full timestamp + descending
    /// sort. See issue #49.
    time: chrono::DateTime<chrono::Utc>,
    /// Sender's ML-DSA-65 verifying key bytes (FIPS 204 encoded). Empty
    /// for legacy unsigned messages. Used for the per-message verified
    /// badge + sender-fingerprint surface (#51).
    sender_vk: Vec<u8>,
    /// Pure-crypto signature check result. Combined with the address-
    /// book lookup at render time to produce a `VerificationState`.
    signature_valid: bool,
    /// Deterministic per-message hash derived from content + token + sender
    /// (`TokenAssignment.assignment_hash`). Used as the inbox-sort secondary
    /// key so two nodes that hold the same set of messages render them in
    /// the same order regardless of contract-vec position (#233). Zero for
    /// kept-locally rows reconstructed from `KeptMessage` since the
    /// assignment hash isn't persisted there yet.
    assignment_hash: [u8; 32],
}

impl Message {
    /// Three-valued verification: combines crypto check + address-book
    /// trust (#51). Verified-known requires both a signature that
    /// validates AND an address-book contact whose `verified` flag is
    /// set; verified-unknown is a valid signature without a verified
    /// contact; everything else (missing/forged signature) is
    /// unverified.
    fn verification_state(&self) -> crate::inbox::VerificationState {
        use crate::inbox::VerificationState;
        if !self.signature_valid {
            return VerificationState::Unverified;
        }
        match address_book::contact_by_vk(&self.sender_vk) {
            Some(c) if c.verified => VerificationState::VerifiedKnown,
            _ => VerificationState::VerifiedUnknown,
        }
    }
}

// ── Sort comparators ────────────────────────────────────────────────────────
//
// One function per folder shape.  All comparators sort newest-first with a
// deterministic tie-break so that HashMap-backed collections do not reorder on
// re-render (issue #137).  Use these at every sort site AND in unit tests so
// the two cannot drift apart.

/// Inbox: newest `Message` first; tie-break by `assignment_hash` descending.
///
/// **Why `assignment_hash` and not `id`:** `Message.id` is the *enumerate
/// index* from `InboxModel::from_state` (the position of the row in the
/// contract's `StoredInbox.messages` vec at build time). Vec order is
/// non-deterministic across nodes — `Inbox::merge` appends in
/// `other.messages` iteration order, so the same set of messages received
/// via different paths can sit in different vec positions, giving two
/// clients different `id`s for the same message (#233).
/// `TokenAssignment.assignment_hash` is content-derived (token + content +
/// sender) and stable across nodes by construction, so any two clients
/// holding the same set render the same order.
fn sort_cmp_inbox(a: &Message, b: &Message) -> std::cmp::Ordering {
    b.time
        .cmp(&a.time)
        .then(b.assignment_hash.cmp(&a.assignment_hash))
}

/// Drafts: newest first by `updated_at`; tie-break by UUID string descending
/// (for stability only — UUID v4 ordering is not chronological).
fn sort_cmp_drafts(
    a: &(String, mail_local_state::Draft),
    b: &(String, mail_local_state::Draft),
) -> std::cmp::Ordering {
    b.1.updated_at.cmp(&a.1.updated_at).then(b.0.cmp(&a.0))
}

/// Sent: newest first by `sent_at`; tie-break by UUID string descending
/// (for stability only — UUID v4 ordering is not chronological).
fn sort_cmp_sent(
    a: &(String, mail_local_state::SentMessage),
    b: &(String, mail_local_state::SentMessage),
) -> std::cmp::Ordering {
    b.1.sent_at.cmp(&a.1.sent_at).then(b.0.cmp(&a.0))
}

/// Archive: newest first by `archived_at`; tie-break by `id` descending for
/// stability.  The `id` key is the stringified `MessageId` used in the
/// archived map — its ordering is for render-stability only, not chronological
/// arrival.
fn sort_cmp_archive(
    a: &(u64, mail_local_state::ArchivedMessage),
    b: &(u64, mail_local_state::ArchivedMessage),
) -> std::cmp::Ordering {
    b.1.archived_at.cmp(&a.1.archived_at).then(b.0.cmp(&a.0))
}

// ────────────────────────────────────────────────────────────────────────────

/// Post-send UI follow-up: what the compose handler must do after
/// `inbox.send_message` returns. Captured as a tiny value type so the
/// branching can be unit-tested without spinning up Dioxus runtime
/// (#230).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ComposePostSend {
    /// True only on success: delete the draft from the local stash AND
    /// dispatch the delegate `DeleteDraft` write.
    pub clear_draft: bool,
    /// True only on success: close the compose sheet and return to the
    /// inbox view.
    pub navigate_away: bool,
    /// True only on success: push the green "Sent" toast. The `Err` arm
    /// of `send_message` pushes its own contextual error toast.
    pub push_success_toast: bool,
}

/// All-or-nothing decision driven by `send_succeeded`. Encodes the
/// invariant that compose-form-finalization is gated on send success.
pub(crate) fn compose_post_send(send_succeeded: bool) -> ComposePostSend {
    ComposePostSend {
        clear_draft: send_succeeded,
        navigate_away: send_succeeded,
        push_success_toast: send_succeeded,
    }
}

/// Time column shown for a kept-locally row whose live contract entry has
/// been evicted. Prefer the sender's send time (`sent_at`) over the
/// MarkRead click time (`kept_at`). Legacy entries (pre-#229) lack
/// `sent_at`; they fall back to `kept_at` — wrong but matches the
/// pre-#229 behaviour and self-heals the next time the row is read.
fn kept_render_time(kept: &mail_local_state::KeptMessage) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp_millis(kept.sent_at.unwrap_or(kept.kept_at))
        .unwrap_or_else(chrono::Utc::now)
}

/// Reconstruct a `Message` from a kept-locally snapshot when the live
/// contract row has been evicted. Propagates verification metadata
/// (`sender_vk`, `signature_valid`) captured at MarkRead so verified
/// senders keep their ✓ badge after eviction (#240). Legacy pre-#240
/// snapshots default both to empty/false and demote to `Unverified` at
/// render time — self-heals on the next MarkRead.
fn kept_to_message(
    mid: mail_local_state::MessageId,
    kept: mail_local_state::KeptMessage,
) -> Message {
    let time = kept_render_time(&kept);
    Message {
        id: mid,
        from: kept.from.into(),
        title: kept.title.into(),
        content: kept.content.into(),
        read: true,
        time,
        sender_vk: kept.sender_vk,
        signature_valid: kept.signature_valid,
        assignment_hash: [0u8; 32],
    }
}

impl From<MessageModel> for Message {
    fn from(value: MessageModel) -> Self {
        Message {
            id: value.id,
            from: value.content.from.into(),
            title: value.content.title.into(),
            content: value.content.content.into(),
            read: false,
            time: value.content.time,
            sender_vk: value.sender_vk,
            signature_valid: value.signature_valid,
            assignment_hash: value.token_assignment.assignment_hash,
        }
    }
}

impl PartialEq for Message {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl PartialOrd for Message {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Message {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

/// Format a timestamp for message-list cards. Buckets:
///   today    → `H:MM`
///   yesterday→ `Yesterday`
///   this week→ short weekday (`Mon`, `Tue`, …)
///   older    → `MMM D` (or `MMM D, YYYY` if a different year)
pub(crate) fn format_time_short(t: chrono::DateTime<chrono::Utc>) -> String {
    use chrono::{Datelike, Local};
    let local: chrono::DateTime<Local> = chrono::DateTime::from(t);
    let now = Local::now();
    let days = now
        .date_naive()
        .signed_duration_since(local.date_naive())
        .num_days();
    if days <= 0 {
        local.format("%-H:%M").to_string()
    } else if days == 1 {
        "Yesterday".into()
    } else if days < 7 {
        local.format("%a").to_string()
    } else if local.year() == now.year() {
        local.format("%b %-d").to_string()
    } else {
        local.format("%b %-d, %Y").to_string()
    }
}

/// Format a timestamp for the detail-header.
///   today    → `Today, H:MM`
///   yesterday→ `Yesterday, H:MM`
///   older    → `MMM D, YYYY · H:MM`
pub(crate) fn format_time_full(t: chrono::DateTime<chrono::Utc>) -> String {
    use chrono::Local;
    let local: chrono::DateTime<Local> = chrono::DateTime::from(t);
    let now = Local::now();
    let days = now
        .date_naive()
        .signed_duration_since(local.date_naive())
        .num_days();
    let hm = local.format("%-H:%M");
    if days <= 0 {
        format!("Today, {hm}")
    } else if days == 1 {
        format!("Yesterday, {hm}")
    } else {
        local.format("%b %-d, %Y · %-H:%M").to_string()
    }
}

mod menu {
    #[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
    pub(super) enum Folder {
        #[default]
        Inbox,
        Sent,
        Drafts,
        Archive,
    }

    impl Folder {
        pub fn label(self) -> &'static str {
            match self {
                Folder::Inbox => "Inbox",
                Folder::Sent => "Sent",
                Folder::Drafts => "Drafts",
                Folder::Archive => "Archive",
            }
        }

        pub fn icon(self) -> &'static str {
            match self {
                Folder::Inbox => "▤",
                Folder::Sent => "↗",
                Folder::Drafts => "✎",
                Folder::Archive => "▦",
            }
        }
    }

    /// Initial values handed to the compose sheet on open. `draft_id` is set
    /// when the user re-opens an existing draft from the Drafts folder; the
    /// sheet keeps that id so SaveDraft / DeleteDraft target the same row.
    #[derive(Default, Clone)]
    pub(super) struct ComposePrefill {
        pub to: String,
        pub subject: String,
        pub body: String,
        pub draft_id: Option<String>,
    }

    /// Which Settings screen is open. `None` means the mailbox is showing.
    #[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
    pub(super) enum SettingsScreen {
        #[default]
        Account,
        Privacy,
        Aft,
        Inbox,
        Contacts,
        Appearance,
        Advanced,
    }

    impl SettingsScreen {
        pub fn label(self) -> &'static str {
            match self {
                Self::Account => "Account & profile",
                Self::Privacy => "Privacy & security",
                Self::Aft => "Anti-Flood (AFT)",
                Self::Inbox => "Inbox & folders",
                Self::Contacts => "Contacts",
                Self::Appearance => "Appearance",
                Self::Advanced => "Advanced & Diagnostics",
            }
        }

        /// Stable kebab-case identifier for `data-screen` attributes used
        /// by Playwright tests. Decoupled from `label()` (which is user-
        /// facing copy and can change).
        pub fn slug(self) -> &'static str {
            match self {
                Self::Account => "account",
                Self::Privacy => "privacy",
                Self::Aft => "aft",
                Self::Inbox => "inbox",
                Self::Contacts => "contacts",
                Self::Appearance => "appearance",
                Self::Advanced => "advanced",
            }
        }

        pub fn is_global(self) -> bool {
            matches!(self, Self::Appearance | Self::Advanced)
        }
    }

    #[derive(Default)]
    pub(super) struct MenuSelection {
        folder: Folder,
        email: Option<u64>,
        sent_id: Option<String>,
        archived_id: Option<u64>,
        new_msg: bool,
        search: String,
        compose_prefill: Option<ComposePrefill>,
        settings: Option<SettingsScreen>,
    }

    impl MenuSelection {
        pub fn at_new_msg(&mut self) {
            if self.new_msg {
                self.new_msg = false;
                self.compose_prefill = None;
            } else {
                self.new_msg = true;
                self.email = None;
                self.sent_id = None;
                self.archived_id = None;
            }
        }

        pub fn open_compose_with(&mut self, to: String, subject: String) {
            self.new_msg = true;
            self.email = None;
            self.sent_id = None;
            self.compose_prefill = Some(ComposePrefill {
                to,
                subject,
                body: String::new(),
                draft_id: None,
            });
        }

        pub fn open_draft(&mut self, prefill: ComposePrefill) {
            self.new_msg = true;
            self.email = None;
            self.sent_id = None;
            self.compose_prefill = Some(prefill);
        }

        pub fn open_sent(&mut self, id: String) {
            self.sent_id = Some(id);
        }

        pub fn sent_id(&self) -> Option<&str> {
            self.sent_id.as_deref()
        }

        pub fn open_archived(&mut self, id: u64) {
            self.archived_id = Some(id);
        }

        pub fn archived_id(&self) -> Option<u64> {
            self.archived_id
        }

        pub fn take_compose_prefill(&mut self) -> Option<ComposePrefill> {
            self.compose_prefill.take()
        }

        pub fn is_new_msg(&self) -> bool {
            self.new_msg
        }

        pub fn at_inbox_list(&mut self) {
            self.email = None;
            self.sent_id = None;
            self.archived_id = None;
            self.new_msg = false;
            self.compose_prefill = None;
        }

        pub fn open_email(&mut self, id: u64) {
            self.email = Some(id);
        }

        pub fn email(&self) -> Option<u64> {
            self.email
        }

        pub fn folder(&self) -> Folder {
            self.folder
        }

        pub fn set_folder(&mut self, f: Folder) {
            if self.folder != f {
                self.folder = f;
                self.email = None;
                self.sent_id = None;
                self.archived_id = None;
            }
        }

        pub fn search(&self) -> &str {
            &self.search
        }

        pub fn set_search(&mut self, q: String) {
            self.search = q;
        }

        pub fn settings(&self) -> Option<SettingsScreen> {
            self.settings
        }

        pub fn open_settings(&mut self, screen: SettingsScreen) {
            self.settings = Some(screen);
            self.new_msg = false;
            self.compose_prefill = None;
        }

        pub fn close_settings(&mut self) {
            self.settings = None;
        }
    }
}

thread_local! {
    static DELAYED_ACTIONS: RefCell<Vec<LocalBoxFuture<'static, ()>>> = RefCell::new(Vec::new());
}

fn folder_count(emails: &[Message], folder: menu::Folder, alias: &str) -> usize {
    match folder {
        menu::Folder::Inbox => emails.iter().filter(|m| !m.read).count(),
        menu::Folder::Drafts => crate::local_state::drafts_for(alias).len(),
        menu::Folder::Sent => crate::local_state::sent_for(alias).len(),
        menu::Folder::Archive => crate::local_state::archived_for(alias).len(),
    }
}

fn matches_search(m: &Message, q: &str) -> bool {
    if q.is_empty() {
        return true;
    }
    let q = q.to_lowercase();
    m.from.to_lowercase().contains(&q)
        || m.title.to_lowercase().contains(&q)
        || m.content.to_lowercase().contains(&q)
}

#[allow(non_snake_case)]
fn UserInbox() -> Element {
    use_context_provider(|| Signal::new(menu::MenuSelection::default()));
    // ImportBackup / ImportContact / ShareContact / SharePending are all
    // provided by app() at the root (lifted in #158 fix) so that the modals
    // are reachable from both the login pane and the inbox view.
    // No re-provides needed here.

    let menu_selection = use_context::<Signal<menu::MenuSelection>>();
    let settings_open = menu_selection.read().settings().is_some();

    let _local_gen = crate::local_state::GENERATION();
    let appearance = crate::local_state::global_settings().appearance;
    let theme_attr = match appearance.theme {
        ::mail_local_state::Theme::System => "system",
        ::mail_local_state::Theme::Light => "light",
        ::mail_local_state::Theme::Dark => "dark",
    };
    let density_attr = match appearance.density {
        ::mail_local_state::Density::Comfortable => "comfortable",
        ::mail_local_state::Density::Compact => "compact",
    };
    let serif_class = if appearance.serif_subjects {
        " serif-subjects"
    } else {
        ""
    };
    let app_class = format!("fm-app{serif_class}");

    let import_contact = use_context::<Signal<crate::app::login::ImportContact>>();
    let share_contact = use_context::<Signal<crate::app::login::ShareContact>>();

    rsx! {
        div {
            class: "{app_class}",
            "data-testid": testid::FM_APP,
            "data-theme": theme_attr,
            "data-density": density_attr,
            Topbar {}
            div { class: "main",
                Sidebar {}
                MessageList {}
                DetailPanel {}
            }
            if settings_open {
                { settings::SettingsShell() }
            }
            if menu_selection.read().is_new_msg() {
                ComposeSheet {}
            }
            ToastView {}
            // Modals rendered inside div.fm-app so that `.veil`/`.modal`
            // CSS rules (scoped to .fm-app via @scope) apply correctly.
            // Signals are provided at app() root so Settings → Contacts
            // buttons can toggle them without re-providing. (#158)
            if share_contact.read().0 {
                login::ShareContactModal {}
            }
            if import_contact.read().0 {
                login::ImportContactForm {}
            }
        }
    }
}

#[allow(non_snake_case)]
fn Topbar() -> Element {
    let user = use_context::<Signal<User>>();
    let mut menu_selection = use_context::<Signal<menu::MenuSelection>>();
    let alias_initial = user
        .read()
        .logged_id()
        .map(|id| id.alias.chars().next().unwrap_or('·').to_string())
        .unwrap_or_else(|| "·".to_string());
    let search = menu_selection.read().search().to_string();
    let app_name = crate::app_name();
    rsx! {
        div { class: "topbar",
            div { class: "brand",
                span { class: "brand-glyph", "f" }
                div { class: "brand-text",
                    span { class: "brand-name", "{app_name}" }
                    span { class: "brand-tag", "Private · Decentralized" }
                }
            }
            div { class: "topbar-mid",
                div { class: "search",
                    span { class: "search-icon", "⌕" }
                    input {
                        r#type: "text",
                        placeholder: "Search",
                        value: "{search}",
                        "data-testid": testid::FM_SEARCH,
                        oninput: move |ev| { menu_selection.write().set_search(ev.value()); },
                    }
                }
            }
            div { class: "topbar-right",
                button {
                    class: "fm-icon-btn fm-set-icon",
                    "aria-label": "Settings",
                    title: "Settings",
                    "data-testid": testid::FM_SETTINGS_BTN,
                    onclick: move |_| {
                        let mut sel = menu_selection.write();
                        if sel.settings().is_some() {
                            sel.close_settings();
                        } else {
                            sel.open_settings(menu::SettingsScreen::Account);
                        }
                    },
                    "⚙"
                }
                div { class: "avatar", "data-testid": testid::FM_AVATAR, "{alias_initial}" }
            }
        }
    }
}

#[allow(non_snake_case)]
fn Sidebar() -> Element {
    let mut user = use_context::<Signal<User>>();
    let mut menu_selection = use_context::<Signal<menu::MenuSelection>>();
    let inbox = use_context::<Signal<InboxView>>();
    let emails_snapshot: Vec<Message> = inbox.read().messages.borrow().clone();
    let active = menu_selection.read().folder();
    let (active_alias, active_fp_short, active_fp_full) = {
        let user_ref = user.read();
        match user_ref.logged_id() {
            Some(id) => {
                let words =
                    address_book::fingerprint_words(&id.ml_dsa_vk_bytes(), &id.ml_kem_ek_bytes());
                (
                    id.alias.to_string(),
                    format!("{}-{}-{}", words[0], words[1], words[2]),
                    words.join("-"),
                )
            }
            None => (String::new(), String::new(), String::new()),
        }
    };
    // Track local-state generation so Drafts count re-renders when the
    // user types into the compose sheet (autosave bumps `GENERATION`).
    let _local_gen = crate::local_state::GENERATION();
    rsx! {
        nav { class: "sidebar",
            button {
                class: "compose-btn",
                "data-testid": testid::FM_COMPOSE_BTN,
                onclick: move |_| {
                    let mut sel = menu_selection.write();
                    if !sel.is_new_msg() {
                        sel.at_new_msg();
                    }
                },
                span { class: "pen", "✎" }
                "New message"
            }
            div { class: "sect-label", "Folders" }
            div { class: "nav",
                {
                    [menu::Folder::Inbox, menu::Folder::Sent, menu::Folder::Drafts, menu::Folder::Archive]
                        .into_iter()
                        .map(|f| {
                            let cls = if f == active { "nav-item active" } else { "nav-item" };
                            let count = folder_count(&emails_snapshot, f, &active_alias);
                            let count_text = if count > 0 { count.to_string() } else { String::new() };
                            let testid = format!("fm-folder-{}", f.label().to_lowercase());
                            rsx! {
                                button {
                                    class: "{cls}",
                                    "data-testid": "{testid}",
                                    onclick: move |_| { menu_selection.write().set_folder(f); },
                                    span { class: "icon", "{f.icon()}" }
                                    span { class: "label", "{f.label()}" }
                                    span { class: "count", "{count_text}" }
                                }
                            }
                        })
                }
            }
            div { class: "sect-label", "People" }
            div { class: "nav",
                button {
                    class: "nav-item",
                    "data-testid": testid::FM_SIDEBAR_CONTACTS,
                    onclick: move |_| {
                        menu_selection.write().open_settings(menu::SettingsScreen::Contacts);
                    },
                    span { class: "icon", "☺" }
                    span { class: "label", "Contacts" }
                    span { class: "count", "" }
                }
            }
            div { class: "sidebar-bottom",
                div { class: "conn-card",
                    div { class: "conn-row",
                        span { class: "lbl",
                            span { class: "pulse-dot" }
                            "connection"
                        }
                        span { class: "val", "live" }
                    }
                    if !active_fp_short.is_empty() {
                        div { class: "conn-row",
                            span { class: "lbl", "key" }
                            span {
                                class: "val",
                                "data-testid": testid::FM_SIDEBAR_FINGERPRINT,
                                title: "{active_fp_full}",
                                "{active_fp_short}"
                            }
                        }
                    }
                    div { class: "conn-row",
                        span { class: "lbl", "version" }
                        span {
                            class: "val",
                            "data-testid": testid::FM_SIDEBAR_VERSION,
                            title: "Webapp build version",
                            "{crate::app_version()}"
                        }
                    }
                }
                button {
                    class: "nav-item",
                    "data-testid": testid::FM_LOGOUT,
                    onclick: move |_| {
                        let mut state = user.write();
                        state.logged = false;
                        state.active_id = None;
                        // Clear the per-identity message cache so the next
                        // login re-runs `load_example_messages` instead of
                        // hitting the idempotency guard with stale rows.
                        inbox.read().messages.borrow_mut().clear();
                    },
                    span { class: "icon", "⏏" }
                    span { class: "label", "Log out" }
                }
            }
        }
    }
}

#[allow(non_snake_case)]
fn MessageList() -> Element {
    let inbox = use_context::<Signal<InboxView>>();
    let inbox_data = use_context::<InboxesData>();
    let mut menu_selection = use_context::<Signal<menu::MenuSelection>>();
    let user = use_context::<Signal<User>>();

    {
        let current_active_id: UserId = user.read().active_id.unwrap();
        let all_data = inbox_data.snapshot();
        if let Some((current_model, id)) = all_data.iter().find_map(|ib| {
            crate::log::debug!("trying to get identity for {key}", key = &ib.borrow().key);
            let id = crate::inbox::InboxModel::contract_identity(&ib.borrow().key).unwrap();
            (id.id == current_active_id).then_some((ib, id))
        }) {
            let inbox = inbox.read();
            let mut emails = inbox.messages.borrow_mut();
            emails.clear();
            let alias = id.alias.to_string();
            for msg in &current_model.borrow().messages {
                let mut m = Message::from(msg.clone());
                // Hide archived rows from the Inbox list (#47c). Until the
                // contract eviction round-trips, the live contract may still
                // serve a row the user has archived; we drop it client-side.
                if crate::local_state::is_archived(&alias, m.id) {
                    continue;
                }
                // Read-state survives reload because it lives in the
                // mail-local-state delegate, not just `mark_as_read`'s
                // local mutation. See issue #47/47a.
                if crate::local_state::is_read(&alias, m.id) {
                    m.read = true;
                }
                emails.push(m);
            }
            // Merge kept-locally messages (b): rows the inbox contract has
            // already evicted but the user has read. They are always read,
            // and dedup by id against the live contract messages. Archived
            // rows are excluded — they belong to the Archive folder, not Inbox.
            for (mid, kept) in crate::local_state::kept_for(&alias) {
                if emails.iter().any(|m| m.id == mid) {
                    continue;
                }
                if crate::local_state::is_archived(&alias, mid) {
                    continue;
                }
                emails.push(kept_to_message(mid, kept));
            }
            crate::log::debug!("active id: {:?}; emails number: {}", id.alias, emails.len());
        }
    }

    DELAYED_ACTIONS.with(|queue| {
        let mut queue = queue.borrow_mut();
        for fut in queue.drain(..) {
            let _ = spawn(fut);
        }
    });

    let folder = menu_selection.read().folder();
    let search = menu_selection.read().search().to_string();
    let selected_id = menu_selection.read().email();
    // Touch the local-state generation so this component re-renders when
    // drafts are added/removed.
    let _local_gen = crate::local_state::GENERATION();
    // Subscribe to address-book mutations so verification badges on
    // inbox rows update immediately after a contact is imported (#134).
    let ab_gen_ctx = use_context::<AddressBookGen>();
    let _ab_gen = ab_gen_ctx.0.read();

    let inbox_view = inbox.read();
    let emails = inbox_view.messages.borrow();
    let active_alias = user
        .read()
        .logged_id()
        .map(|id| id.alias.to_string())
        .unwrap_or_default();
    let inbox_settings = crate::local_state::global_settings().inbox;
    let privacy_prefs = crate::local_state::identity_settings_for(&active_alias).privacy;
    let visible: Vec<Message> = if matches!(folder, menu::Folder::Inbox) {
        let mut v: Vec<Message> = emails
            .iter()
            // Hide archived/deleted rows. In offline mode the populate loop
            // above is a no-op (no inbox_data), so emails are seeded once at
            // login and never re-filtered without this guard. Same call also
            // hides them in use-node mode if the contract eviction is still
            // in flight.
            .filter(|m| !crate::local_state::is_archived(&active_alias, m.id))
            .filter(|m| !crate::local_state::is_deleted(&active_alias, m.id))
            .filter(|m| matches_search(m, &search))
            // IdentityPrivacyPrefs.hide_unsigned: drop rows whose signature
            // didn't validate. Sender-vk empty also counts as unsigned.
            .filter(|m| {
                if !privacy_prefs.hide_unsigned {
                    return true;
                }
                m.signature_valid && !m.sender_vk.is_empty()
            })
            // GlobalSettings.inbox.quarantine_unknown: when set, hide rows
            // from senders not in the verified address book. Until a
            // dedicated Quarantine folder ships, "hide" is the safe
            // interpretation — visible drops, count drops, no surface.
            .filter(|m| {
                if !inbox_settings.quarantine_unknown {
                    return true;
                }
                if m.sender_vk.is_empty() {
                    return false;
                }
                matches!(
                    address_book::contact_by_vk(&m.sender_vk),
                    Some(c) if c.verified
                )
            })
            .cloned()
            .collect();
        // Newest first (#49). Sender-stamped time is what the design assumes.
        // Tie-break by id descending so that messages with identical 1-second
        // timestamps always appear in a deterministic order regardless of the
        // HashMap iteration order of the underlying kept-message map (#137).
        v.sort_by(sort_cmp_inbox);
        v
    } else {
        Vec::new()
    };
    let drafts: Vec<(String, mail_local_state::Draft)> = if matches!(folder, menu::Folder::Drafts)
        || (matches!(folder, menu::Folder::Inbox) && inbox_settings.drafts_in_inbox)
    {
        let mut d = crate::local_state::drafts_for(&active_alias);
        // Newest first; tie-break by UUID string for stability only — UUID v4
        // order is not chronological (#137).
        d.sort_by(sort_cmp_drafts);
        d
    } else {
        Vec::new()
    };
    let sent_msgs: Vec<(String, mail_local_state::SentMessage)> =
        if matches!(folder, menu::Folder::Sent) {
            let mut s = crate::local_state::sent_for(&active_alias);
            // Newest first; tie-break by UUID string for stability only — UUID v4
            // order is not chronological (#137).
            s.sort_by(sort_cmp_sent);
            s
        } else {
            Vec::new()
        };
    let archived_msgs: Vec<(u64, mail_local_state::ArchivedMessage)> =
        if matches!(folder, menu::Folder::Archive) {
            let mut a = crate::local_state::archived_for(&active_alias);
            // Newest first; tie-break by message id for deterministic order (#137).
            a.sort_by(sort_cmp_archive);
            a
        } else {
            Vec::new()
        };
    let count = match folder {
        menu::Folder::Drafts => drafts.len(),
        menu::Folder::Sent => sent_msgs.len(),
        menu::Folder::Archive => archived_msgs.len(),
        menu::Folder::Inbox if inbox_settings.drafts_in_inbox => visible.len() + drafts.len(),
        _ => visible.len(),
    };
    let selected_sent_id = menu_selection.read().sent_id().map(str::to_string);
    let selected_archived_id = menu_selection.read().archived_id();

    rsx! {
        section { class: "list-col",
            div { class: "list-head",
                span { class: "list-title", "{folder.label()}" }
                span { class: "list-count", "{count}" }
            }
            div { class: "list-scroll", "data-testid": testid::FM_LIST,
                if matches!(folder, menu::Folder::Archive) {
                    if archived_msgs.is_empty() {
                        div { style: "padding:24px 18px; font-family:'Geist Mono',monospace; font-size:10px; letter-spacing:0.1em; text-transform:uppercase; color:var(--ink4);",
                            "Archive is empty"
                        }
                    } else {
                        {
                            archived_msgs.into_iter().map(|(mid, a)| {
                                let from_disp = if a.from.is_empty() { "(no sender)".to_string() } else { a.from.clone() };
                                let subj_disp = if a.title.is_empty() { "(no subject)".to_string() } else { a.title.clone() };
                                let preview = a.content.clone();
                                let mut classes = String::from("msg-card");
                                if Some(mid) == selected_archived_id { classes.push_str(" selected"); }
                                let time_short = chrono::DateTime::from_timestamp_millis(a.archived_at)
                                    .map(format_time_short)
                                    .unwrap_or_default();
                                rsx! {
                                    article {
                                        class: "{classes}",
                                        "data-testid": testid::FM_ARCHIVE_CARD,
                                        "data-msg-id": "{mid}",
                                        onclick: move |_| {
                                            menu_selection.write().open_archived(mid);
                                        },
                                        div { class: "msg-row1",
                                            span { class: "msg-sender", "{from_disp}" }
                                            span { class: "msg-time", "{time_short}" }
                                        }
                                        div { class: "msg-subj", "{subj_disp}" }
                                        div { class: "msg-prev", "{preview}" }
                                    }
                                }
                            })
                        }
                    }
                } else if matches!(folder, menu::Folder::Sent) {
                    if sent_msgs.is_empty() {
                        div { style: "padding:24px 18px; font-family:'Geist Mono',monospace; font-size:10px; letter-spacing:0.1em; text-transform:uppercase; color:var(--ink4);",
                            "Sent is empty"
                        }
                    } else {
                        {
                            sent_msgs.into_iter().map(|(id, m)| {
                                let to_disp = if m.to.is_empty() { "(no recipient)".to_string() } else { m.to.clone() };
                                let subj_disp = if m.subject.is_empty() { "(no subject)".to_string() } else { m.subject.clone() };
                                let preview = m.body.clone();
                                let mut classes = String::from("msg-card");
                                if Some(&id) == selected_sent_id.as_ref() { classes.push_str(" selected"); }
                                let id_for_dom = id.clone();
                                let id_for_click = id.clone();
                                // Small inline state pill — Delivered is the
                                // happy path so we hide it; Pending and Failed
                                // are the user-actionable states.
                                let (state_class, state_label): (&'static str, Option<&'static str>) =
                                    match m.delivery_state {
                                        mail_local_state::DeliveryState::Pending =>
                                            ("badge badge-pending", Some("pending")),
                                        mail_local_state::DeliveryState::Failed =>
                                            ("badge badge-failed", Some("failed")),
                                        mail_local_state::DeliveryState::Delivered =>
                                            ("", None),
                                    };
                                let time_short = chrono::DateTime::from_timestamp_millis(m.sent_at)
                                    .map(format_time_short)
                                    .unwrap_or_default();
                                rsx! {
                                    article {
                                        class: "{classes}",
                                        "data-testid": testid::FM_SENT_CARD,
                                        "data-sent-id": "{id_for_dom}",
                                        "data-delivery-state": "{m.delivery_state:?}",
                                        onclick: move |_| {
                                            menu_selection.write().open_sent(id_for_click.clone());
                                        },
                                        div { class: "msg-row1",
                                            span { class: "msg-sender", "{to_disp}" }
                                            {state_label.map(|l| rsx! {
                                                span { class: "{state_class}", "{l}" }
                                            })}
                                            span { class: "msg-time", "{time_short}" }
                                        }
                                        div { class: "msg-subj", "{subj_disp}" }
                                        div { class: "msg-prev", "{preview}" }
                                    }
                                }
                            })
                        }
                    }
                } else if matches!(folder, menu::Folder::Drafts) {
                    if drafts.is_empty() {
                        div { style: "padding:24px 18px; font-family:'Geist Mono',monospace; font-size:10px; letter-spacing:0.1em; text-transform:uppercase; color:var(--ink4);",
                            "Drafts is empty"
                        }
                    } else {
                        {
                            drafts.into_iter().map(|(id, d)| {
                                let to_disp = if d.to.is_empty() { "(no recipient)".to_string() } else { d.to.clone() };
                                let subj_disp = if d.subject.is_empty() { "(no subject)".to_string() } else { d.subject.clone() };
                                let preview = d.body.clone();
                                let time_short = chrono::DateTime::from_timestamp_millis(d.updated_at)
                                    .map(format_time_short)
                                    .unwrap_or_default();
                                let prefill = menu::ComposePrefill {
                                    to: d.to.clone(),
                                    subject: d.subject.clone(),
                                    body: d.body.clone(),
                                    draft_id: Some(id.clone()),
                                };
                                let id_for_dom = id.clone();
                                rsx! {
                                    article {
                                        class: "msg-card",
                                        "data-testid": testid::FM_DRAFT_CARD,
                                        "data-draft-id": "{id_for_dom}",
                                        onclick: move |_| {
                                            menu_selection.write().open_draft(prefill.clone());
                                        },
                                        div { class: "msg-row1",
                                            span { class: "msg-sender", "{to_disp}" }
                                            span { class: "msg-time", "{time_short}" }
                                        }
                                        div { class: "msg-subj", "{subj_disp}" }
                                        div { class: "msg-prev", "{preview}" }
                                    }
                                }
                            })
                        }
                    }
                } else if visible.is_empty() && drafts.is_empty() {
                    div { style: "padding:24px 18px; font-family:'Geist Mono',monospace; font-size:10px; letter-spacing:0.1em; text-transform:uppercase; color:var(--ink4);",
                        "No messages"
                    }
                } else {
                    // GlobalSettings.inbox.drafts_in_inbox = true → drafts
                    // render at top of Inbox alongside received messages.
                    if matches!(folder, menu::Folder::Inbox) && inbox_settings.drafts_in_inbox {
                        {
                            drafts.iter().map(|(id, d)| {
                                let to_disp = if d.to.is_empty() { "(no recipient)".to_string() } else { d.to.clone() };
                                let subj_disp = if d.subject.is_empty() { "(no subject)".to_string() } else { d.subject.clone() };
                                let preview = d.body.clone();
                                let time_short = chrono::DateTime::from_timestamp_millis(d.updated_at)
                                    .map(format_time_short)
                                    .unwrap_or_default();
                                let prefill = menu::ComposePrefill {
                                    to: d.to.clone(),
                                    subject: d.subject.clone(),
                                    body: d.body.clone(),
                                    draft_id: Some(id.clone()),
                                };
                                let id_for_dom = id.clone();
                                rsx! {
                                    article {
                                        class: "msg-card",
                                        "data-testid": testid::FM_DRAFT_CARD,
                                        "data-draft-id": "{id_for_dom}",
                                        onclick: move |_| {
                                            menu_selection.write().open_draft(prefill.clone());
                                        },
                                        div { class: "msg-row1",
                                            span { class: "msg-sender", "Draft → {to_disp}" }
                                            span { class: "msg-time", "{time_short}" }
                                        }
                                        div { class: "msg-subj", "{subj_disp}" }
                                        div { class: "msg-prev", "{preview}" }
                                    }
                                }
                            })
                        }
                    }
                    {
                        visible.into_iter().map(|email| {
                            let id = email.id;
                            let mut classes = String::from("msg-card");
                            if !email.read { classes.push_str(" unread"); }
                            if Some(id) == selected_id { classes.push_str(" selected"); }
                            let from = email.from.clone();
                            let title = email.title.clone();
                            let preview = email.content.clone();
                            let time_short = format_time_short(email.time);
                            rsx! {
                                article {
                                    class: "{classes}",
                                    id: "email-inbox-accessor-{id}",
                                    "data-testid": testid::FM_MSG_CARD,
                                    "data-msg-id": "{id}",
                                    onclick: move |_| { menu_selection.write().open_email(id); },
                                    div { class: "msg-row1",
                                        span { class: "msg-sender", "{from}" }
                                        span {
                                            class: "msg-time",
                                            "data-testid": testid::FM_MSG_TIME,
                                            "{time_short}"
                                        }
                                    }
                                    div { class: "msg-subj", "{title}" }
                                    div { class: "msg-prev", "{preview}" }
                                }
                            }
                        })
                    }
                }
            }
        }
    }
}

#[allow(non_snake_case)]
fn DetailPanel() -> Element {
    let inbox = use_context::<Signal<InboxView>>();
    let menu_selection = use_context::<Signal<menu::MenuSelection>>();
    let user = use_context::<Signal<User>>();
    let folder = menu_selection.read().folder();
    let selected_id = menu_selection.read().email();
    let selected_sent_id = menu_selection.read().sent_id().map(str::to_string);
    let selected_archived_id = menu_selection.read().archived_id();
    let view = inbox.read();
    let emails = view.messages.borrow();
    let selected = selected_id.and_then(|id| emails.iter().find(|m| m.id == id).cloned());
    let _local_gen = crate::local_state::GENERATION();

    if matches!(folder, menu::Folder::Inbox) {
        if let Some(msg) = selected {
            rsx! { OpenMessage { msg } }
        } else {
            rsx! {
                section { class: "detail-col",
                    div { class: "empty",
                        div { class: "empty-glyph", "✉" }
                        div { class: "empty-hint", "Select a message" }
                    }
                }
            }
        }
    } else if matches!(folder, menu::Folder::Archive) {
        let alias = user
            .read()
            .logged_id()
            .map(|id| id.alias.to_string())
            .unwrap_or_default();
        let archived = selected_archived_id.and_then(|aid| {
            crate::local_state::archived_for(&alias)
                .into_iter()
                .find(|(mid, _)| *mid == aid)
        });
        if let Some((mid, msg)) = archived {
            rsx! { OpenArchivedMessage { msg_id: mid, msg } }
        } else {
            rsx! {
                section { class: "detail-col",
                    div { class: "empty",
                        div { class: "empty-glyph", "✉" }
                        div { class: "empty-hint", "Select an archived message" }
                    }
                }
            }
        }
    } else if matches!(folder, menu::Folder::Sent) {
        let alias = user
            .read()
            .logged_id()
            .map(|id| id.alias.to_string())
            .unwrap_or_default();
        let sent = selected_sent_id.as_ref().and_then(|id| {
            crate::local_state::sent_for(&alias)
                .into_iter()
                .find(|(sid, _)| sid == id)
                .map(|(_, m)| m)
        });
        if let Some(msg) = sent {
            rsx! { OpenSentMessage { msg } }
        } else {
            rsx! {
                section { class: "detail-col",
                    div { class: "empty",
                        div { class: "empty-glyph", "✉" }
                        div { class: "empty-hint", "Select a sent message" }
                    }
                }
            }
        }
    } else {
        rsx! {
            section { class: "detail-col",
                div { class: "empty",
                    div { class: "empty-glyph", "✉" }
                    div { class: "empty-hint", "{folder.label()} is empty" }
                }
            }
        }
    }
}

/// Quote `body` as plain-text reply/forward block (each line prefixed with
/// "> "). Mirrors the Drafts/compose-sheet's plain-text body model.
fn quote_body(body: &str) -> String {
    body.lines()
        .map(|l| format!("> {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[component]
fn OpenArchivedMessage(msg_id: u64, msg: mail_local_state::ArchivedMessage) -> Element {
    let mut menu_selection = use_context::<Signal<menu::MenuSelection>>();
    let user = use_context::<Signal<User>>();
    let client = crate::api::WEB_API_SENDER.get().unwrap();

    let from = msg.from.clone();
    let from_initial = from.chars().next().unwrap_or('·').to_string();
    let title = msg.title.clone();
    let content = msg.content.clone();
    let reply_to = from.clone();
    let reply_subj = format!("Re: {title}");
    let time_full = chrono::DateTime::from_timestamp_millis(msg.archived_at)
        .map(format_time_full)
        .unwrap_or_default();

    let alias = user
        .read()
        .logged_id()
        .map(|id| id.alias.to_string())
        .unwrap_or_default();
    let delete_alias = alias.clone();

    rsx! {
        section { class: "detail-col",
            div { class: "detail-head",
                h1 { class: "detail-subj", "{title}" }
                div { class: "detail-from",
                    div { class: "sender-orb", "{from_initial}" }
                    div { class: "from-text",
                        span { class: "from-name", "from {from}" }
                        span { class: "from-addr", "archived" }
                    }
                    span {
                        class: "from-time",
                        "data-testid": testid::FM_DETAIL_TIME,
                        "{time_full}"
                    }
                }
            }
            div { class: "toolbar",
                button {
                    class: "btn btn-primary",
                    "data-testid": testid::FM_ARCHIVE_REPLY,
                    onclick: move |_| {
                        menu_selection.write().open_compose_with(reply_to.to_string(), reply_subj.clone());
                    },
                    "Reply"
                }
                // Unarchive intentionally hidden: blocked on inbox contract
                // OwnerInsert (#60). Showing a no-op button is more confusing
                // than no affordance at all.
                button {
                    class: "btn btn-secondary",
                    "data-testid": testid::FM_ARCHIVE_DELETE,
                    onclick: move |_| {
                        if !delete_alias.is_empty() {
                            crate::local_state::local_delete_message(&delete_alias, msg_id);
                            #[cfg(feature = "use-node")]
                            {
                                let mut c = client.clone();
                                let a = delete_alias.clone();
                                spawn(async move {
                                    if let Err(e) = crate::local_state::delete_message(
                                        &mut c, a, msg_id,
                                    )
                                    .await
                                    {
                                        crate::log::error(
                                            format!("delete_message failed: {e}"),
                                            None,
                                        );
                                    }
                                });
                            }
                        }
                        menu_selection.write().at_inbox_list();
                        crate::toast::push_toast("Deleted", crate::toast::ToastLevel::Success);
                    },
                    "Delete"
                }
                div { class: "spacer" }
            }
            div { class: "detail-scroll",
                div { class: "detail-body", "data-testid": testid::FM_ARCHIVE_BODY,
                    {
                        content.split("\n\n").map(|para| rsx! {
                            p { "{para}" }
                        })
                    }
                }
            }
        }
    }
}

#[component]
fn OpenSentMessage(msg: mail_local_state::SentMessage) -> Element {
    let mut menu_selection = use_context::<Signal<menu::MenuSelection>>();
    let to = msg.to.clone();
    let to_initial = to.chars().next().unwrap_or('·').to_string();
    let subject = msg.subject.clone();
    let body = msg.body.clone();
    let fingerprint = msg.recipient_fingerprint.clone();
    let fingerprint_full = if msg.recipient_fingerprint_full.is_empty() {
        msg.recipient_fingerprint.clone()
    } else {
        msg.recipient_fingerprint_full.clone()
    };
    let time_full = chrono::DateTime::from_timestamp_millis(msg.sent_at)
        .map(format_time_full)
        .unwrap_or_default();
    let delivery = match msg.delivery_state {
        mail_local_state::DeliveryState::Pending => "pending",
        mail_local_state::DeliveryState::Delivered => "delivered",
        mail_local_state::DeliveryState::Failed => "failed",
    };

    // Reply: same recipient, "Re: <subject>".
    let reply_prefill = menu::ComposePrefill {
        to: to.clone(),
        subject: format!("Re: {subject}"),
        body: String::new(),
        draft_id: None,
    };
    // Forward: blank recipient, "Fwd: <subject>", body quoted.
    let forward_prefill = menu::ComposePrefill {
        to: String::new(),
        subject: format!("Fwd: {subject}"),
        body: quote_body(&body),
        draft_id: None,
    };
    // Resend: identical fields, fresh draft id (a new send → new Sent row).
    let resend_prefill = menu::ComposePrefill {
        to: to.clone(),
        subject: subject.clone(),
        body: body.clone(),
        draft_id: None,
    };

    rsx! {
        section { class: "detail-col",
            div { class: "detail-head",
                h1 { class: "detail-subj", "{subject}" }
                div { class: "detail-from",
                    div { class: "sender-orb", "{to_initial}" }
                    div { class: "from-text",
                        span { class: "from-name", "to {to}" }
                        span {
                            class: "from-addr",
                            "data-testid": testid::FM_SENT_FINGERPRINT,
                            title: "{fingerprint_full}",
                            "fingerprint: {fingerprint}"
                        }
                    }
                    span {
                        class: "from-time",
                        "data-testid": testid::FM_DETAIL_TIME,
                        "{time_full}"
                    }
                    span {
                        class: "from-time",
                        "data-testid": testid::FM_SENT_DELIVERY,
                        "{delivery}"
                    }
                }
            }
            div { class: "toolbar",
                button {
                    class: "btn btn-primary",
                    "data-testid": testid::FM_SENT_REPLY,
                    onclick: move |_| {
                        menu_selection.write().open_draft(reply_prefill.clone());
                    },
                    "Reply"
                }
                button {
                    class: "btn btn-secondary",
                    "data-testid": testid::FM_SENT_FORWARD,
                    onclick: move |_| {
                        menu_selection.write().open_draft(forward_prefill.clone());
                    },
                    "Forward"
                }
                button {
                    class: "btn btn-secondary",
                    "data-testid": testid::FM_SENT_RESEND,
                    onclick: move |_| {
                        menu_selection.write().open_draft(resend_prefill.clone());
                    },
                    "Resend"
                }
                div { class: "spacer" }
            }
            div { class: "detail-scroll",
                div { class: "detail-body", "data-testid": testid::FM_SENT_BODY,
                    {
                        body.split("\n\n").map(|para| rsx! {
                            p { "{para}" }
                        })
                    }
                }
            }
        }
    }
}

#[component]
fn OpenMessage(msg: Message) -> Element {
    let mut menu_selection = use_context::<Signal<menu::MenuSelection>>();
    let client = crate::api::WEB_API_SENDER.get().unwrap();
    let mut inbox = use_context::<Signal<InboxView>>();
    let inbox_data = use_context::<InboxesData>();
    let user = use_context::<Signal<User>>();
    let email_id = [msg.id];

    let result = inbox
        .write()
        .mark_as_read(client.clone(), &email_id, inbox_data)
        .unwrap();
    DELAYED_ACTIONS.with(|queue| {
        queue.borrow_mut().push(result);
    });

    // Persist read flag + a local snapshot of the message in the
    // mail-local-state delegate (issue #47/47a). This is additive to the
    // existing inbox-contract `remove_messages` call above: the contract
    // still evicts the row, but the kept-locally copy lets the UI keep
    // showing the message after reload.
    {
        let alias = user
            .read()
            .logged_id()
            .map(|id| id.alias.to_string())
            .unwrap_or_default();
        if !alias.is_empty() {
            let kept = mail_local_state::KeptMessage {
                from: msg.from.to_string(),
                title: msg.title.to_string(),
                content: msg.content.to_string(),
                kept_at: chrono::Utc::now().timestamp_millis(),
                sent_at: Some(msg.time.timestamp_millis()),
                sender_vk: msg.sender_vk.clone(),
                signature_valid: msg.signature_valid,
            };
            crate::local_state::local_mark_read(&alias, msg.id, kept.clone());
            #[cfg(feature = "use-node")]
            {
                let mut client_clone = client.clone();
                let alias_for_send = alias.clone();
                spawn(async move {
                    if let Err(e) = crate::local_state::mark_read(
                        &mut client_clone,
                        alias_for_send,
                        msg.id,
                        kept,
                    )
                    .await
                    {
                        crate::log::local_state_failure("mark message read", e);
                    }
                });
            }
        }
    }

    let from = msg.from.clone();
    let from_initial = from.chars().next().unwrap_or('·').to_string();
    let title = msg.title.clone();
    let content = msg.content.clone();
    let id = msg.id;
    let reply_to = from.clone();
    let reply_subj = format!("Re: {}", title);
    let time_full = format_time_full(msg.time);
    // Subscribe to address-book mutations so the verification badge
    // updates immediately when the user imports the sender's contact
    // without requiring a full page reload (#134).
    let ab_gen_ctx = use_context::<AddressBookGen>();
    let _ab_gen = ab_gen_ctx.0.read();
    // Sender trust state (#51) — three-valued: verified-known (sig OK +
    // contact verified), verified-unknown (sig OK, sender VK not in AB),
    // unverified (no sig / forged sig). Fingerprint short-form is shown
    // when the VK is present (i.e. the message was signed).
    let verification = msg.verification_state();
    let (verif_class, verif_label) = match verification {
        crate::inbox::VerificationState::VerifiedKnown => ("verif-badge verif-known", "verified"),
        crate::inbox::VerificationState::VerifiedUnknown => {
            ("verif-badge verif-unknown", "signed · unknown sender")
        }
        crate::inbox::VerificationState::Unverified => ("verif-badge verif-none", "unverified"),
    };
    let (sender_fp_short, sender_fp_full) = if msg.sender_vk.is_empty() {
        (String::new(), String::new())
    } else {
        // Address-book fingerprint mixes both VK and EK; for messages
        // we only have the sender's VK, so use it twice (the message's
        // unique key here is the VK alone).
        let words = address_book::fingerprint_words(&msg.sender_vk, &msg.sender_vk);
        (
            format!("{}-{}-{}", words[0], words[1], words[2]),
            words.join("-"),
        )
    };
    let show_add_to_ab = matches!(
        verification,
        crate::inbox::VerificationState::VerifiedUnknown
    );

    let archive_client = client.clone();
    let archive_inbox_data = inbox_data;
    let delete_client = client.clone();
    let delete_inbox_data = inbox_data;
    let active_alias = user
        .read()
        .logged_id()
        .map(|id| id.alias.to_string())
        .unwrap_or_default();
    let archive_alias = active_alias.clone();
    let archive_from = msg.from.to_string();
    let archive_title = msg.title.to_string();
    let archive_content = msg.content.to_string();
    let delete_alias = active_alias.clone();

    rsx! {
        section { class: "detail-col",
            div { class: "detail-head",
                h1 { class: "detail-subj", "{title}" }
                div { class: "detail-from",
                    div { class: "sender-orb", "{from_initial}" }
                    div { class: "from-text",
                        span { class: "from-name", "{from}" }
                        if !sender_fp_short.is_empty() {
                            span {
                                class: "from-addr",
                                "data-testid": testid::FM_DETAIL_FINGERPRINT,
                                title: "{sender_fp_full}",
                                "{sender_fp_short}"
                            }
                        } else {
                            span { class: "from-addr", "" }
                        }
                    }
                    span {
                        class: "{verif_class}",
                        "data-testid": testid::FM_DETAIL_VERIF,
                        "{verif_label}"
                    }
                    span {
                        class: "from-time",
                        "data-testid": testid::FM_DETAIL_TIME,
                        "{time_full}"
                    }
                }
            }
            div { class: "toolbar",
                if show_add_to_ab {
                    button {
                        class: "btn btn-secondary",
                        "data-testid": testid::FM_ADD_TO_AB,
                        onclick: move |_| {
                            // Stub: opens the existing address-book import
                            // modal. Pre-filling it with this sender's VK
                            // is a follow-up — the affordance is wired now
                            // so the verified-unknown flow has a path
                            // (#51).
                            crate::toast::push_toast(
                                "Open the address book to add this sender",
                                crate::toast::ToastLevel::Info,
                            );
                        },
                        "Add to address book"
                    }
                }
                button {
                    class: "btn btn-primary",
                    "data-testid": testid::FM_REPLY,
                    onclick: move |_| {
                        menu_selection.write().open_compose_with(reply_to.to_string(), reply_subj.clone());
                    },
                    "Reply"
                }
                button {
                    class: "btn btn-secondary",
                    "data-testid": testid::FM_ARCHIVE,
                    onclick: move |_| {
                        // Archive: stash a local copy in mail-local-state then
                        // remove from the inbox contract. Phase 1 of #47c —
                        // re-PUT-on-unarchive lands in #60.
                        let archived = mail_local_state::ArchivedMessage {
                            from: archive_from.clone(),
                            title: archive_title.clone(),
                            content: archive_content.clone(),
                            archived_at: chrono::Utc::now().timestamp_millis(),
                        };
                        if !archive_alias.is_empty() {
                            crate::local_state::local_archive_message(
                                &archive_alias,
                                id,
                                archived.clone(),
                            );
                            #[cfg(feature = "use-node")]
                            {
                                let mut c = archive_client.clone();
                                let a = archive_alias.clone();
                                let ar = archived.clone();
                                spawn(async move {
                                    if let Err(e) = crate::local_state::archive_message(
                                        &mut c, a, id, ar,
                                    )
                                    .await
                                    {
                                        crate::log::local_state_failure("archive message", e);
                                    }
                                });
                            }
                        }
                        let result = inbox
                            .write()
                            .remove_messages(archive_client.clone(), &[id], archive_inbox_data)
                            .unwrap();
                        DELAYED_ACTIONS.with(|queue| { queue.borrow_mut().push(result); });
                        menu_selection.write().at_inbox_list();
                        crate::toast::push_toast("Archived", crate::toast::ToastLevel::Success);
                    },
                    "Archive"
                }
                button {
                    class: "btn btn-secondary",
                    "data-testid": testid::FM_DELETE,
                    onclick: move |_| {
                        // Delete: drop any local kept/archived copies AND
                        // remove from the inbox contract. Distinct from
                        // Archive because it leaves no trace.
                        if !delete_alias.is_empty() {
                            crate::local_state::local_delete_message(&delete_alias, id);
                            #[cfg(feature = "use-node")]
                            {
                                let mut c = delete_client.clone();
                                let a = delete_alias.clone();
                                spawn(async move {
                                    if let Err(e) = crate::local_state::delete_message(
                                        &mut c, a, id,
                                    )
                                    .await
                                    {
                                        crate::log::error(
                                            format!("delete_message failed: {e}"),
                                            None,
                                        );
                                    }
                                });
                            }
                        }
                        let result = inbox
                            .write()
                            .remove_messages(delete_client.clone(), &[id], delete_inbox_data)
                            .unwrap();
                        DELAYED_ACTIONS.with(|queue| { queue.borrow_mut().push(result); });
                        menu_selection.write().at_inbox_list();
                        crate::toast::push_toast("Deleted", crate::toast::ToastLevel::Success);
                    },
                    "Delete"
                }
                div { class: "spacer" }
            }
            div { class: "detail-scroll",
                div { class: "detail-body", id: "email-content-{id}",
                    {
                        content.split("\n\n").map(|para| rsx! {
                            p { "{para}" }
                        })
                    }
                }
            }
        }
    }
}

use crate::toast::ToastView;

#[allow(non_snake_case)]
fn ComposeSheet() -> Element {
    let mut menu_selection = use_context::<Signal<menu::MenuSelection>>();
    let client = crate::api::WEB_API_SENDER.get().unwrap();
    let mut inbox = use_context::<Signal<InboxView>>();
    let user = use_context::<Signal<User>>();
    let user_alias = user.read().logged_id().unwrap().alias.to_string();
    // "Sending as <fingerprint>" surface (#51) — shows the user which
    // ML-DSA key the outgoing message will be signed under.
    let (sender_fp_short, sender_fp_full) = {
        let user_ref = user.read();
        match user_ref.logged_id() {
            Some(id) => {
                let words =
                    address_book::fingerprint_words(&id.ml_dsa_vk_bytes(), &id.ml_kem_ek_bytes());
                (
                    format!("{}-{}-{}", words[0], words[1], words[2]),
                    words.join("-"),
                )
            }
            None => (String::new(), String::new()),
        }
    };

    let prefill = menu_selection.write().take_compose_prefill();
    let initial_to = prefill.as_ref().map(|p| p.to.clone()).unwrap_or_default();
    let initial_subj = prefill
        .as_ref()
        .map(|p| p.subject.clone())
        .unwrap_or_default();
    let initial_body = prefill.as_ref().map(|p| p.body.clone()).unwrap_or_default();
    // Reuse the draft id when re-opening an existing draft so SaveDraft
    // overwrites the same row instead of creating a duplicate.
    let initial_draft_id = prefill
        .as_ref()
        .and_then(|p| p.draft_id.clone())
        .unwrap_or_else(crate::local_state::new_draft_id);

    let mut to = use_signal(|| initial_to.clone());
    let mut title = use_signal(|| initial_subj.clone());
    let mut content = use_signal(|| initial_body.clone());
    let draft_id = use_signal(|| initial_draft_id.clone());
    // Autocomplete state: index of the highlighted suggestion (-1 = none).
    let mut ac_highlighted: Signal<i32> = use_signal(|| -1i32);
    // Whether the autocomplete dropdown is open. Closed by default; opened
    // only by oninput or onfocus so the dropdown doesn't appear on mount.
    let mut ac_open: Signal<bool> = use_signal(|| false);
    // Blur-guard: set to true on pointerdown over a suggestion item so that
    // the onblur handler (which fires before click/mouseup on touch) does not
    // prematurely close the dropdown before the selection is committed.
    let mut ac_ignore_blur: Signal<bool> = use_signal(|| false);
    // Monotonic token bumped by every keystroke. The debounced delegate save
    // captures the token at scheduling time and only fires the wire call if
    // it still matches when the timer elapses — older keystrokes are silently
    // dropped. Send / Discard bump the token to cancel a pending save.
    let mut autosave_token = use_signal(|| 0u64);
    /// Idle window before a draft is flushed to the delegate. Picked to feel
    /// instant for normal typing while still coalescing fast bursts.
    const AUTOSAVE_DEBOUNCE_MS: u32 = 500;

    // Persist the draft on every keystroke. The optimistic local snapshot is
    // updated immediately so the Drafts folder reflects the typing without
    // delay; the delegate roundtrip is debounced to avoid hammering the
    // WebSocket bridge with one SaveDraft per character.
    let alias_for_save = user_alias.clone();
    let autosave = use_callback(move |()| {
        let to_v = to.read().clone();
        let subj_v = title.read().clone();
        let body_v = content.read().clone();
        if to_v.is_empty() && subj_v.is_empty() && body_v.is_empty() {
            return;
        }
        let id = draft_id.read().clone();
        let updated_at = chrono::Utc::now().timestamp_millis();
        let draft = mail_local_state::Draft {
            to: to_v,
            subject: subj_v,
            body: body_v,
            updated_at,
        };
        crate::local_state::local_save_draft(&alias_for_save, &id, draft.clone());

        // Bump the token, then schedule a delayed delegate save that
        // double-checks the token before firing. If another keystroke landed
        // first the saved-token won't match and this send is a no-op.
        let my_token = *autosave_token.read() + 1;
        autosave_token.set(my_token);
        #[cfg(feature = "use-node")]
        {
            let mut client_clone = client.clone();
            let alias = alias_for_save.clone();
            let token_signal = autosave_token;
            spawn(async move {
                gloo_timers::future::TimeoutFuture::new(AUTOSAVE_DEBOUNCE_MS).await;
                if *token_signal.read() != my_token {
                    return;
                }
                if let Err(e) =
                    crate::local_state::save_draft(&mut client_clone, alias, id, draft).await
                {
                    crate::log::local_state_failure("save draft", e);
                }
            });
        }
    });

    // Subscribe to address-book mutations so the recipient badge re-renders
    // when a contact is imported after the alias was already typed (#143).
    let ab_gen_ctx = use_context::<AddressBookGen>();
    let recipient_lookup = use_memo(move || {
        let _ab = ab_gen_ctx.0.read();
        address_book::lookup(&to.read())
    });

    // Autocomplete suggestions: case-insensitive substring over all contacts.
    // Empty when input is blank or exactly matches a known alias.
    let ac_suggestions = use_memo(move || {
        let needle = to.read().clone();
        // Exact match → no suggestions (user already resolved the contact).
        if needle.is_empty() || address_book::lookup(&needle).is_some() {
            return vec![];
        }
        address_book::filter_contacts(&needle, 8)
    });

    let alias = user_alias.clone();
    let alias_for_delete = user_alias.clone();
    // Delete the draft both locally (immediate UI update) and via the
    // delegate. Used on Send (success) and Discard.
    let delete_draft_now = use_callback(move |()| {
        let id = draft_id.read().clone();
        // Invalidate any in-flight debounced SaveDraft so it can't race the
        // DeleteDraft that follows.
        let bumped = *autosave_token.read() + 1;
        autosave_token.set(bumped);
        crate::local_state::local_delete_draft(&alias_for_delete, &id);
        #[cfg(feature = "use-node")]
        {
            let mut client_clone = client.clone();
            let alias = alias_for_delete.clone();
            spawn(async move {
                if let Err(e) = crate::local_state::delete_draft(&mut client_clone, alias, id).await
                {
                    crate::log::local_state_failure("delete draft", e);
                }
            });
        }
    });
    let send_msg = move |_| {
        let to_val = to.read().clone();
        let recipient = match address_book::lookup(&to_val) {
            Some(r) => r,
            None => {
                crate::log::error(
                    format!("couldn't find key for `{to_val}`"),
                    Some(TryNodeAction::GetAlias),
                );
                crate::toast::push_toast(
                    format!(
                        "Recipient `{to_val}` is not in your address book. Import their contact card before sending."
                    ),
                    crate::toast::ToastLevel::Error,
                );
                return;
            }
        };
        // IdentityPrivacyPrefs.verify_on_send: refuse to send if the
        // address-book contact has not been confirmed by the user. Own-
        // identity sends bypass (no verification required to message self).
        let id_privacy = crate::local_state::identity_settings_for(&alias).privacy;
        if id_privacy.verify_on_send && !recipient.verified && !recipient.is_own {
            crate::log::error(
                format!("verify_on_send is on; recipient `{to_val}` is not a verified contact"),
                Some(TryNodeAction::GetAlias),
            );
            crate::toast::push_toast(
                format!(
                    "Recipient `{to_val}` is not verified. Verify the fingerprint in Contacts before sending."
                ),
                crate::toast::ToastLevel::Warning,
            );
            return;
        }
        let recipient_ek = match address_book::ek_from_bytes(&recipient.ml_kem_ek_bytes) {
            Ok(ek) => ek,
            Err(e) => {
                crate::log::error(
                    format!("bad EK for `{to_val}`: {e}"),
                    Some(TryNodeAction::GetAlias),
                );
                return;
            }
        };
        let recipient_vk = match address_book::vk_from_bytes(&recipient.ml_dsa_vk_bytes) {
            Ok(vk) => vk,
            Err(e) => {
                crate::log::error(
                    format!("bad VK for `{to_val}`: {e}"),
                    Some(TryNodeAction::GetAlias),
                );
                return;
            }
        };
        let title_val = title.read().clone();
        let mut content_val = content.read().clone();

        // IdentitySettings.auto_sign + signature: append a separator + the
        // signature block when enabled and the user hasn't already pasted
        // the signature into the body. Idempotent against re-send/forward.
        let id_settings = crate::local_state::identity_settings_for(&alias);
        if id_settings.auto_sign && !id_settings.signature.trim().is_empty() {
            let sig = id_settings.signature.trim_end();
            if !content_val.contains(sig) {
                if !content_val.ends_with('\n') {
                    content_val.push('\n');
                }
                content_val.push_str("\n-- \n");
                content_val.push_str(sig);
            }
        }

        // Derive the recipient's inbox key BEFORE moving `recipient_vk` into
        // `send_message` so we can pair the eventual UpdateResponse back to
        // the Sent row's `SentId`.
        #[cfg(feature = "use-node")]
        let inbox_key_for_ack = crate::inbox::inbox_key_for(&recipient_vk);

        // #221: prefer the live `InboxSettings` cached from the contact's
        // inbox state over the values frozen in the contact card. Cards
        // age out the moment the recipient retunes their tier; the
        // contract enforces against `InboxSettings.minimum_tier` so
        // minting at the card's tier silently fails. The cache is
        // populated by the rehydrate-prime path's Get-with-subscribe
        // (api.rs) — fall back to the card on miss (first send after
        // import, before the GetResponse lands).
        #[cfg(feature = "use-node")]
        let (recipient_required_tier, recipient_max_age_secs) = match inbox_key_for_ack
            .as_ref()
            .ok()
            .and_then(crate::contact_tier_cache::lookup)
        {
            Some(p) => {
                if p.minimum_tier != recipient.required_tier
                    || p.max_age_secs != recipient.max_age_secs
                {
                    crate::log::info(format!(
                        "send: contact-tier-cache hit for `{to_val}` tier={:?} max_age_secs={} (overrides stale card tier={:?} max_age_secs={}) (#221)",
                        p.minimum_tier,
                        p.max_age_secs,
                        recipient.required_tier,
                        recipient.max_age_secs
                    ));
                }
                (p.minimum_tier, p.max_age_secs)
            }
            None => (recipient.required_tier, recipient.max_age_secs),
        };
        #[cfg(not(feature = "use-node"))]
        let (recipient_required_tier, recipient_max_age_secs) =
            (recipient.required_tier, recipient.max_age_secs);

        // Allocate the SentId up-front so the sync enqueue and the async
        // failure-flip both name the same row.
        let sent_id = crate::local_state::new_sent_id();
        let sender_alias = alias.clone();

        // Build ack_meta only when we have an inbox_key in hand (use-node
        // path). The future will use it to flip Pending → Failed if
        // start_sending errors out post-enqueue.
        #[cfg(feature = "use-node")]
        let ack_meta = inbox_key_for_ack
            .as_ref()
            .ok()
            .map(|k| (sender_alias.clone(), sent_id.clone(), *k));
        #[cfg(not(feature = "use-node"))]
        let ack_meta: Option<(String, String, ContractKey)> = None;

        let send_succeeded = match inbox.write().send_message(
            client.clone(),
            &alias,
            recipient_ek,
            recipient_vk,
            recipient_required_tier,
            recipient_max_age_secs,
            &title_val,
            &content_val,
            ack_meta,
        ) {
            Ok(futs) => {
                // spawn_forever, not spawn: send future outlives this
                // component (we navigate away below). spawn() ties the
                // task to the current scope and cancels on unmount,
                // which silently killed every send before the AFT
                // request hit the wire.
                futs.into_iter().for_each(|f| {
                    let _task = dioxus_core::spawn_forever(f);
                });
                true
            }
            Err(e) => {
                let msg = e.to_string();
                crate::log::error(msg.clone(), Some(TryNodeAction::SendMessage));
                let user_msg = if msg.contains(crate::aft::NO_TOKEN_RECORD_MSG_PREFIX) {
                    crate::aft::format_no_record_toast()
                } else {
                    format!("Can't send: {msg}. Check Settings → AFT or try again.")
                };
                crate::toast::push_toast(user_msg, crate::toast::ToastLevel::Error);
                false
            }
        };
        // Stash a Sent copy locally. Under `use-node` the real ack is
        // driven by the recipient's inbox UpdateResponse (api.rs flips
        // Pending → Delivered) or by an AFT/UPDATE error (Pending →
        // Failed). Under `example-data,no-sync` the mock delivery is
        // synchronous and unconditional — there is no future ack signal,
        // so we set Delivered up-front. See issue #58.
        if send_succeeded {
            #[cfg(feature = "use-node")]
            let initial_state = mail_local_state::DeliveryState::Pending;
            #[cfg(not(feature = "use-node"))]
            let initial_state = mail_local_state::DeliveryState::Delivered;

            let sent = mail_local_state::SentMessage {
                to: to_val.clone(),
                recipient_fingerprint: recipient.fingerprint_short(),
                recipient_fingerprint_full: recipient.fingerprint_full(),
                subject: title_val.clone(),
                body: content_val.clone(),
                sent_at: chrono::Utc::now().timestamp_millis(),
                delivery_state: initial_state,
            };
            crate::local_state::local_save_sent(&sender_alias, &sent_id, sent.clone());

            // Enqueue against the recipient's inbox key so the
            // UpdateResponse handler can flip the right Sent row.
            #[cfg(feature = "use-node")]
            match inbox_key_for_ack {
                Ok(inbox_key) => {
                    crate::inbox::enqueue_pending_sent_ack(
                        inbox_key,
                        sender_alias.clone(),
                        sent_id.clone(),
                    );
                }
                Err(e) => {
                    crate::log::error(
                        format!("inbox_key_for failed; sent row will stay Pending: {e}"),
                        None,
                    );
                }
            }

            #[cfg(feature = "use-node")]
            {
                let mut client_clone = client.clone();
                let alias_async = sender_alias.clone();
                let id_async = sent_id.clone();
                spawn(async move {
                    if let Err(e) = crate::local_state::save_sent(
                        &mut client_clone,
                        alias_async,
                        id_async,
                        sent,
                    )
                    .await
                    {
                        crate::log::local_state_failure("save sent message", e);
                    }
                });
            }
        }
        // On success only: drop the draft, navigate away, surface success
        // toast. On failure the Err arm above already pushed an error toast
        // and the draft must stay so the user can retry. The branching
        // lives in `compose_post_send` so the gating is unit-testable
        // (#230).
        let post = compose_post_send(send_succeeded);
        if post.clear_draft {
            delete_draft_now(());
        }
        if post.navigate_away {
            menu_selection.write().at_new_msg();
        }
        if post.push_success_toast {
            crate::toast::push_toast("Sent", crate::toast::ToastLevel::Success);
        }
    };

    rsx! {
        div { class: "veil",
            onclick: move |_| { menu_selection.write().at_new_msg(); },
            div { class: "sheet",
                "data-testid": testid::FM_COMPOSE_SHEET,
                onclick: move |ev| { ev.stop_propagation(); },
                div { class: "sheet-head",
                    span { class: "sheet-title", "New message" }
                    button {
                        class: "sheet-x",
                        onclick: move |_| { menu_selection.write().at_new_msg(); },
                        "✕"
                    }
                }
                div { class: "sheet-field",
                    span { class: "field-lbl", "From" }
                    span { class: "field-input", style: "color:var(--ink2);", "{user_alias}" }
                    if !sender_fp_short.is_empty() {
                        span {
                            class: "from-addr",
                            style: "margin-left:8px;",
                            "data-testid": testid::FM_COMPOSE_SENDING_AS,
                            title: "{sender_fp_full}",
                            "Sending as: {sender_fp_short}"
                        }
                    }
                }
                div { class: "sheet-field compose-autocomplete-wrap",
                    span { class: "field-lbl", "To" }
                    {
                        let dropdown_open = *ac_open.read();
                        let suggestions_len = ac_suggestions.read().len();
                        let has_suggestions = dropdown_open && suggestions_len > 0;
                        rsx! {
                            input {
                                class: "field-input",
                                r#type: "text",
                                placeholder: "alias or address",
                                value: "{to}",
                                role: "combobox",
                                aria_autocomplete: "list",
                                aria_expanded: "{has_suggestions}",
                                oninput: move |ev| {
                                    to.set(ev.value());
                                    ac_highlighted.set(-1);
                                    ac_open.set(true);
                                    autosave(());
                                },
                                onkeydown: move |ev| {
                                    let suggestions = ac_suggestions.read();
                                    let len = suggestions.len() as i32;
                                    // Consume Escape only when the dropdown is visible;
                                    // otherwise let the event bubble to parent handlers.
                                    if ev.key() == Key::Escape && *ac_open.read() && len > 0 {
                                        ac_open.set(false);
                                        ac_highlighted.set(-1);
                                        return;
                                    }
                                    if len == 0 || !*ac_open.read() {
                                        return;
                                    }
                                    match ev.key() {
                                        Key::ArrowDown => {
                                            let next = (*ac_highlighted.read() + 1).min(len - 1);
                                            ac_highlighted.set(next);
                                        }
                                        Key::ArrowUp => {
                                            let prev = (*ac_highlighted.read() - 1).max(-1);
                                            ac_highlighted.set(prev);
                                        }
                                        Key::Enter => {
                                            let idx = *ac_highlighted.read();
                                            if idx >= 0 && idx < len {
                                                let alias = suggestions[idx as usize].local_alias.to_string();
                                                to.set(alias);
                                                ac_highlighted.set(-1);
                                                ac_open.set(false);
                                                autosave(());
                                            }
                                        }
                                        _ => {}
                                    }
                                },
                                // Dismiss on blur — but skip if a suggestion item just received
                                // a pointerdown (ac_ignore_blur guard prevents premature close
                                // on long-press and touch devices where blur fires before click).
                                onblur: move |_| {
                                    if *ac_ignore_blur.read() {
                                        // The blur was caused by a pointer interaction with a
                                        // suggestion item; the onpointerdown handler on the item
                                        // will commit the selection and clear the guard.
                                        return;
                                    }
                                    ac_open.set(false);
                                    ac_highlighted.set(-1);
                                },
                                onfocus: move |_| { ac_open.set(true); },
                            }
                        }
                    }
                    // Dropdown — rendered inside the same relative wrapper.
                    {
                        let suggestions = ac_suggestions.read().clone();
                        let highlighted = *ac_highlighted.read();
                        let open = *ac_open.read();
                        let n = suggestions.len();
                        if open && !suggestions.is_empty() {
                            rsx! {
                                div {
                                    class: "compose-autocomplete",
                                    role: "listbox",
                                    "data-testid": testid::FM_COMPOSE_AUTOCOMPLETE,
                                    for (idx, contact) in suggestions.iter().enumerate() {
                                        {
                                            let alias = contact.local_alias.to_string();
                                            let alias_fill = alias.clone();
                                            let fp_short = contact.fingerprint_short();
                                            let (trust_class, trust_label) = if contact.verified {
                                                ("known", "✓")
                                            } else {
                                                ("unknown", "⚠")
                                            };
                                            let item_class = if highlighted == idx as i32 {
                                                "compose-ac-item highlighted"
                                            } else {
                                                "compose-ac-item"
                                            };
                                            let item_id = format!("ac-item-{idx}");
                                            let _ = n; // silence unused-variable lint
                                            rsx! {
                                                div {
                                                    key: "{alias}",
                                                    id: "{item_id}",
                                                    class: "{item_class}",
                                                    role: "option",
                                                    aria_selected: "{highlighted == idx as i32}",
                                                    "data-testid": testid::FM_COMPOSE_AUTOCOMPLETE_ITEM,
                                                    // pointerdown fires before blur on both mouse and
                                                    // touch, allowing us to set the guard before the
                                                    // input's onblur clears the dropdown.
                                                    onpointerdown: move |ev| {
                                                        ev.prevent_default();
                                                        ac_ignore_blur.set(true);
                                                        to.set(alias_fill.clone());
                                                        ac_highlighted.set(-1);
                                                        ac_open.set(false);
                                                        ac_ignore_blur.set(false);
                                                        autosave(());
                                                    },
                                                    span { class: "compose-ac-alias", "{alias}" }
                                                    span { class: "compose-ac-trust {trust_class}", "{trust_label}" }
                                                    span { class: "compose-ac-fp", "{fp_short}" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            rsx! {}
                        }
                    }
                }
                {
                    let to_val = to.read().clone();
                    let lookup = recipient_lookup.read().clone();
                    if let Some(r) = lookup {
                        let (badge_class, badge_label): (&str, &str) =
                            if r.is_own {
                                ("badge badge-trust", "you")
                            } else if r.verified {
                                ("badge badge-trust", "verified")
                            } else {
                                ("badge badge-warn", "unverified")
                            };
                        let fp_short = r.fingerprint_short();
                        let fp_full = r.fingerprint_full();
                        rsx! {
                            div { class: "sheet-recipient-badge", "data-testid": "compose-recipient-badge",
                                span {
                                    class: "{badge_class}",
                                    "data-testid": "compose-recipient-badge-label",
                                    "{badge_label}"
                                }
                                span {
                                    class: "badge-fp",
                                    "data-testid": "compose-recipient-fingerprint",
                                    title: "{fp_full}",
                                    "fingerprint: {fp_short}"
                                }
                            }
                        }
                    } else if !to_val.trim().is_empty() {
                        rsx! {
                            div {
                                class: "sheet-recipient-hint",
                                "data-testid": testid::FM_COMPOSE_RECIPIENT_HINT,
                                role: "status",
                                "aria-live": "polite",
                                "Not in address book — import their contact card first."
                            }
                        }
                    } else {
                        rsx! {}
                    }
                }
                div { class: "sheet-field",
                    span { class: "field-lbl", "Re" }
                    input {
                        class: "field-input",
                        r#type: "text",
                        placeholder: "subject",
                        value: "{title}",
                        oninput: move |ev| { title.set(ev.value()); autosave(()); },
                    }
                }
                div { class: "sheet-body",
                    textarea {
                        class: "sheet-textarea",
                        placeholder: "Write something thoughtful…",
                        value: "{content}",
                        oninput: move |ev| { content.set(ev.value()); autosave(()); },
                    }
                }
                div { class: "sheet-foot",
                    div { class: "foot-meta",
                        span { class: "pulse-dot" }
                        span { "Encrypted · routed through Freenet" }
                    }
                    div { class: "foot-actions",
                        button {
                            class: "btn btn-ghost",
                            onclick: move |_| {
                                delete_draft_now(());
                                menu_selection.write().at_new_msg();
                            },
                            "Discard"
                        }
                        button {
                            class: "btn btn-primary",
                            "data-testid": testid::FM_SEND,
                            onclick: send_msg,
                            "Send"
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod compose_post_send_tests {
    use super::compose_post_send;

    /// Regression for #230. Before the fix, `delete_draft_now`, navigation,
    /// and the green "Sent" toast all ran unconditionally after the
    /// `send_message` match arm, even when send failed. The bug deleted
    /// the user's draft and covered the error toast with a success one.
    /// All three flags must be `false` when `send_succeeded == false`.
    #[test]
    fn failure_does_nothing() {
        let p = compose_post_send(false);
        assert!(!p.clear_draft, "must keep the draft on failure");
        assert!(!p.navigate_away, "must stay on compose on failure");
        assert!(
            !p.push_success_toast,
            "must not push success toast on failure (Err arm already pushed error)"
        );
    }

    /// Sanity: on success all three follow-ups fire.
    #[test]
    fn success_runs_all_follow_ups() {
        let p = compose_post_send(true);
        assert!(p.clear_draft);
        assert!(p.navigate_away);
        assert!(p.push_success_toast);
    }
}

#[cfg(test)]
mod time_format_tests {
    use super::{format_time_full, format_time_short};
    use chrono::{Duration, Local, Utc};

    #[test]
    fn short_today_is_h_colon_mm() {
        let s = format_time_short(Utc::now());
        assert!(s.contains(':'), "expected H:MM, got {s:?}");
        assert!(!s.eq_ignore_ascii_case("yesterday"));
    }

    #[test]
    fn short_yesterday_says_yesterday() {
        let now = Local::now();
        let y = (now - Duration::days(1)).with_timezone(&Utc);
        assert_eq!(format_time_short(y), "Yesterday");
    }

    #[test]
    fn short_older_than_week_uses_month_day() {
        let now = Local::now();
        let old = (now - Duration::days(20)).with_timezone(&Utc);
        let s = format_time_short(old);
        assert!(!s.eq_ignore_ascii_case("yesterday"));
        assert!(!s.contains(':'), "{s:?} should not be H:MM");
        assert!(s.chars().any(char::is_alphabetic) && s.chars().any(char::is_numeric));
    }

    #[test]
    fn full_today_starts_with_today() {
        let s = format_time_full(Utc::now());
        assert!(s.starts_with("Today, "), "got {s:?}");
    }

    #[test]
    fn full_yesterday_starts_with_yesterday() {
        let now = Local::now();
        let y = (now - Duration::days(1)).with_timezone(&Utc);
        let s = format_time_full(y);
        assert!(s.starts_with("Yesterday, "), "got {s:?}");
    }

    #[test]
    fn full_older_uses_month_day_year_dot_time() {
        let now = Local::now();
        let old = (now - Duration::days(40)).with_timezone(&Utc);
        let s = format_time_full(old);
        assert!(s.contains('·'), "got {s:?}");
        assert!(s.contains(':'), "got {s:?}");
    }
}

#[cfg(test)]
mod kept_render_time_tests {
    use super::kept_render_time;
    use mail_local_state::KeptMessage;

    /// Regression for #229: the live row had time = sender's send time
    /// (9:39). After eviction the kept-path row used to render with
    /// click time (10:20). With the fix the row keeps the send time.
    #[test]
    fn prefers_sent_at_over_kept_at_when_present() {
        let kept = KeptMessage {
            from: "bob".into(),
            title: "hi".into(),
            content: "yo".into(),
            kept_at: 10_000,      // "click time"
            sent_at: Some(1_000), // "send time"
            ..Default::default()
        };
        let t = kept_render_time(&kept);
        assert_eq!(t.timestamp_millis(), 1_000, "must use sender's send time");
    }

    /// Legacy entries (pre-#229 stored snapshots) lack `sent_at` and
    /// must still render with `kept_at` as a graceful fallback.
    #[test]
    fn falls_back_to_kept_at_for_legacy_entries() {
        let kept = KeptMessage {
            from: "bob".into(),
            title: "hi".into(),
            content: "yo".into(),
            kept_at: 5_000,
            sent_at: None,
            ..Default::default()
        };
        let t = kept_render_time(&kept);
        assert_eq!(t.timestamp_millis(), 5_000);
    }

    /// Out-of-range millis (e.g. corrupt or future-dated entries) must
    /// not panic; helper falls back to `Utc::now()`. We just assert the
    /// call returns without panicking — the actual value depends on
    /// wall-clock.
    #[test]
    fn out_of_range_falls_back_to_now() {
        let kept = KeptMessage {
            from: "x".into(),
            title: "x".into(),
            content: "x".into(),
            kept_at: i64::MAX,
            sent_at: Some(i64::MAX),
            ..Default::default()
        };
        let _ = kept_render_time(&kept);
    }
}

#[cfg(test)]
mod kept_to_message_tests {
    use super::kept_to_message;
    use crate::inbox::VerificationState;
    use mail_local_state::KeptMessage;

    /// Regression for #240: a verified-sender row that gets evicted
    /// from the live contract must keep its `sender_vk` +
    /// `signature_valid` so the badge stays ✓ instead of demoting to ⚠.
    #[test]
    fn propagates_verification_metadata() {
        let kept = KeptMessage {
            from: "bob".into(),
            title: "hi".into(),
            content: "yo".into(),
            kept_at: 100,
            sent_at: Some(50),
            sender_vk: vec![9, 8, 7, 6, 5],
            signature_valid: true,
        };
        let msg = kept_to_message(42, kept);
        assert_eq!(&*msg.sender_vk, &[9, 8, 7, 6, 5]);
        assert!(msg.signature_valid);
        assert!(msg.read);
    }

    /// Legacy pre-#240 entries lack the verification fields entirely;
    /// the helper must default `signature_valid` to false so the row
    /// renders as `Unverified` (matches pre-#240 behaviour). It self-
    /// heals on next MarkRead.
    #[test]
    fn legacy_entries_demote_to_unverified() {
        let kept = KeptMessage {
            from: "bob".into(),
            title: "hi".into(),
            content: "yo".into(),
            kept_at: 100,
            sent_at: Some(50),
            ..Default::default()
        };
        let msg = kept_to_message(42, kept);
        assert!(msg.sender_vk.is_empty());
        assert!(!msg.signature_valid);
        assert!(matches!(
            msg.verification_state(),
            VerificationState::Unverified
        ));
    }
}

#[cfg(test)]
mod inbox_sort_tests {
    use super::{Message, sort_cmp_inbox};
    use chrono::{TimeZone, Utc};
    use std::borrow::Cow;

    fn make_msg(id: u64, timestamp_secs: i64, hash_byte: u8) -> Message {
        let mut assignment_hash = [0u8; 32];
        assignment_hash[0] = hash_byte;
        Message {
            id,
            from: Cow::Borrowed("test@test"),
            title: Cow::Borrowed("subject"),
            content: Cow::Borrowed("body"),
            read: false,
            time: Utc.timestamp_opt(timestamp_secs, 0).unwrap(),
            sender_vk: Vec::new(),
            signature_valid: false,
            assignment_hash,
        }
    }

    /// Messages with distinct timestamps should be sorted newest-first.
    #[test]
    fn sort_by_time_desc() {
        let mut v = [
            make_msg(1, 1_000, 1),
            make_msg(2, 3_000, 2),
            make_msg(3, 2_000, 3),
        ];
        v.sort_by(sort_cmp_inbox);
        let ids: Vec<u64> = v.iter().map(|m| m.id).collect();
        assert_eq!(ids, vec![2, 3, 1]);
    }

    /// When timestamps tie, higher `assignment_hash` comes first. This is the
    /// content-derived per-message hash (`TokenAssignment.assignment_hash`),
    /// stable across nodes by construction — see #233 for why the previous
    /// id-based tie-break was non-deterministic across peers.
    #[test]
    fn tie_break_by_assignment_hash_desc() {
        let ts = 5_000;
        // Vary `id` (enumerate index — non-deterministic across nodes) AND
        // `assignment_hash` independently to assert that the comparator only
        // looks at the hash.
        let mut v = [
            make_msg(10, ts, 0x11),
            make_msg(30, ts, 0x33),
            make_msg(20, ts, 0x22),
        ];
        v.sort_by(sort_cmp_inbox);
        let ids: Vec<u64> = v.iter().map(|m| m.id).collect();
        // Highest hash (0x33 → id 30) first, descending.
        assert_eq!(ids, vec![30, 20, 10]);
    }

    /// Two clients holding the same set of messages in different vec
    /// positions (= different `id`s) must produce the same order after sort.
    /// This is the cross-node consistency guarantee #233 is about.
    #[test]
    fn cross_node_order_matches_when_hashes_match() {
        let ts = 5_000;
        // Node A holds the messages in one order; node B in another. Same
        // logical messages (same assignment_hash), different positions.
        let mut node_a = [
            make_msg(0, ts, 0xAA),
            make_msg(1, ts, 0xBB),
            make_msg(2, ts, 0xCC),
        ];
        let mut node_b = [
            make_msg(0, ts, 0xCC),
            make_msg(1, ts, 0xAA),
            make_msg(2, ts, 0xBB),
        ];
        node_a.sort_by(sort_cmp_inbox);
        node_b.sort_by(sort_cmp_inbox);
        let a_hashes: Vec<u8> = node_a.iter().map(|m| m.assignment_hash[0]).collect();
        let b_hashes: Vec<u8> = node_b.iter().map(|m| m.assignment_hash[0]).collect();
        assert_eq!(a_hashes, b_hashes);
        assert_eq!(a_hashes, vec![0xCC, 0xBB, 0xAA]);
    }

    /// Regression check for #234: a row that transitions from live →
    /// kept_for (eviction on MarkRead) keeps the same position in the
    /// rendered inbox list, because the time-primary key is preserved
    /// (#229) and the assignment_hash tie-break only matters at
    /// identical timestamps. Three messages with distinct send times;
    /// the middle one evicts. The render order must be unchanged.
    #[test]
    fn eviction_preserves_position_for_distinct_timestamps() {
        let live_a = make_msg(100, 3_000, 0xAA);
        let mut live_b = make_msg(200, 2_000, 0xBB);
        let live_c = make_msg(300, 1_000, 0xCC);

        let mut before = [live_a.clone(), live_b.clone(), live_c.clone()];
        before.sort_by(sort_cmp_inbox);
        let positions_before: Vec<u64> = before.iter().map(|m| m.id).collect();

        // Simulate eviction of B: kept_to_message zeroes assignment_hash
        // but `sent_at` (via kept_render_time) preserves the original
        // time, so primary-key ordering is intact.
        live_b.assignment_hash = [0u8; 32];

        let mut after = [live_a, live_b, live_c];
        after.sort_by(sort_cmp_inbox);
        let positions_after: Vec<u64> = after.iter().map(|m| m.id).collect();

        assert_eq!(
            positions_before, positions_after,
            "eviction must not reorder rows with distinct timestamps"
        );
    }

    /// Same idea but stresses the tie-break case: two rows with
    /// identical timestamps where the second one evicts. With the
    /// kept row's hash zeroed, the live row sorts ahead of it (hash
    /// 0xAA > 0x00) — still deterministic, just predictably "live
    /// before kept" when times collide. Asserts the order is stable
    /// across renders, not which row wins (that's an implementation
    /// detail of the hash zero).
    #[test]
    fn eviction_with_tied_timestamps_is_deterministic() {
        let ts = 5_000;
        let live = make_msg(100, ts, 0xAA);
        let mut evicted = make_msg(200, ts, 0xBB);
        evicted.assignment_hash = [0u8; 32];

        let mut v1 = [live.clone(), evicted.clone()];
        v1.sort_by(sort_cmp_inbox);
        let mut v2 = [evicted.clone(), live.clone()];
        v2.sort_by(sort_cmp_inbox);

        let ids1: Vec<u64> = v1.iter().map(|m| m.id).collect();
        let ids2: Vec<u64> = v2.iter().map(|m| m.id).collect();
        assert_eq!(
            ids1, ids2,
            "tied-timestamp order must be insertion-invariant"
        );
    }

    /// Calling sort twice on the same vec must produce the same order —
    /// i.e. the sort is stable and deterministic across re-renders.
    #[test]
    fn sort_is_idempotent() {
        let ts = 7_000;
        let mut v = [
            make_msg(5, ts, 5),
            make_msg(1, ts, 1),
            make_msg(3, ts, 3),
            make_msg(4, 8_000, 4),
        ];
        v.sort_by(sort_cmp_inbox);
        let first: Vec<u64> = v.iter().map(|m| m.id).collect();
        v.sort_by(sort_cmp_inbox);
        let second: Vec<u64> = v.iter().map(|m| m.id).collect();
        assert_eq!(first, second, "sort must be idempotent");
    }
}

#[cfg(test)]
mod folder_sort_tests {
    use super::{sort_cmp_archive, sort_cmp_drafts, sort_cmp_sent};
    use mail_local_state::{ArchivedMessage, Draft, SentMessage};

    fn make_draft(id: &str, updated_at: i64) -> (String, Draft) {
        (
            id.to_string(),
            Draft {
                to: "a@b".to_string(),
                subject: "s".to_string(),
                body: "b".to_string(),
                updated_at,
            },
        )
    }

    fn make_sent(id: &str, sent_at: i64) -> (String, SentMessage) {
        (
            id.to_string(),
            SentMessage {
                to: "a@b".to_string(),
                recipient_fingerprint: String::new(),
                recipient_fingerprint_full: String::new(),
                subject: "s".to_string(),
                body: "b".to_string(),
                sent_at,
                delivery_state: mail_local_state::DeliveryState::Delivered,
            },
        )
    }

    fn make_archived(id: u64, archived_at: i64) -> (u64, ArchivedMessage) {
        (
            id,
            ArchivedMessage {
                from: "a@b".to_string(),
                title: "t".to_string(),
                content: "c".to_string(),
                archived_at,
            },
        )
    }

    // ── Drafts ───────────────────────────────────────────────────────────────

    /// Drafts should appear newest-first by `updated_at`.
    #[test]
    fn drafts_sort_time_desc() {
        let mut d = [
            make_draft("id-1", 1_000),
            make_draft("id-2", 3_000),
            make_draft("id-3", 2_000),
        ];
        d.sort_by(sort_cmp_drafts);
        let ids: Vec<&str> = d.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids, vec!["id-2", "id-3", "id-1"]);
    }

    /// Drafts with the same `updated_at` must tie-break deterministically
    /// (UUID string descending — for stability, not chronological ordering).
    #[test]
    fn drafts_tie_break_by_id_desc() {
        let ts = 5_000;
        let mut d = [
            make_draft("aaa", ts),
            make_draft("ccc", ts),
            make_draft("bbb", ts),
        ];
        d.sort_by(sort_cmp_drafts);
        let ids: Vec<&str> = d.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids, vec!["ccc", "bbb", "aaa"]);
    }

    /// Sorting drafts twice must produce the same order.
    #[test]
    fn drafts_sort_idempotent() {
        let ts = 7_000;
        let mut d = [
            make_draft("x", ts),
            make_draft("y", ts),
            make_draft("z", ts),
            make_draft("w", 8_000),
        ];
        d.sort_by(sort_cmp_drafts);
        let first: Vec<String> = d.iter().map(|(id, _)| id.clone()).collect();
        d.sort_by(sort_cmp_drafts);
        let second: Vec<String> = d.iter().map(|(id, _)| id.clone()).collect();
        assert_eq!(first, second, "drafts sort must be idempotent");
    }

    // ── Sent ─────────────────────────────────────────────────────────────────

    /// Sent messages should appear newest-first by `sent_at`.
    #[test]
    fn sent_sort_time_desc() {
        let mut s = [
            make_sent("id-1", 1_000),
            make_sent("id-2", 3_000),
            make_sent("id-3", 2_000),
        ];
        s.sort_by(sort_cmp_sent);
        let ids: Vec<&str> = s.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids, vec!["id-2", "id-3", "id-1"]);
    }

    /// Sent messages with the same `sent_at` must tie-break deterministically.
    #[test]
    fn sent_tie_break_by_id_desc() {
        let ts = 5_000;
        let mut s = [
            make_sent("aaa", ts),
            make_sent("ccc", ts),
            make_sent("bbb", ts),
        ];
        s.sort_by(sort_cmp_sent);
        let ids: Vec<&str> = s.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(ids, vec!["ccc", "bbb", "aaa"]);
    }

    /// Sorting sent twice must produce the same order.
    #[test]
    fn sent_sort_idempotent() {
        let ts = 7_000;
        let mut s = [
            make_sent("x", ts),
            make_sent("y", ts),
            make_sent("z", ts),
            make_sent("w", 8_000),
        ];
        s.sort_by(sort_cmp_sent);
        let first: Vec<String> = s.iter().map(|(id, _)| id.clone()).collect();
        s.sort_by(sort_cmp_sent);
        let second: Vec<String> = s.iter().map(|(id, _)| id.clone()).collect();
        assert_eq!(first, second, "sent sort must be idempotent");
    }

    // ── Archive ───────────────────────────────────────────────────────────────

    /// Archived messages should appear newest-first by `archived_at`.
    #[test]
    fn archive_sort_time_desc() {
        let mut a = [
            make_archived(1, 1_000),
            make_archived(2, 3_000),
            make_archived(3, 2_000),
        ];
        a.sort_by(sort_cmp_archive);
        let ids: Vec<u64> = a.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids, vec![2, 3, 1]);
    }

    /// Archived messages with the same `archived_at` must tie-break by id
    /// descending (monotonic u64).
    #[test]
    fn archive_tie_break_by_id_desc() {
        let ts = 5_000;
        let mut a = [
            make_archived(10, ts),
            make_archived(30, ts),
            make_archived(20, ts),
        ];
        a.sort_by(sort_cmp_archive);
        let ids: Vec<u64> = a.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids, vec![30, 20, 10]);
    }

    /// Sorting archived twice must produce the same order.
    #[test]
    fn archive_sort_idempotent() {
        let ts = 7_000;
        let mut a = [
            make_archived(5, ts),
            make_archived(1, ts),
            make_archived(3, ts),
            make_archived(4, 8_000),
        ];
        a.sort_by(sort_cmp_archive);
        let first: Vec<u64> = a.iter().map(|(id, _)| *id).collect();
        a.sort_by(sort_cmp_archive);
        let second: Vec<u64> = a.iter().map(|(id, _)| *id).collect();
        assert_eq!(first, second, "archive sort must be idempotent");
    }
}
