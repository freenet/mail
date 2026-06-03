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
        /// ML-KEM-768 encapsulation key bytes for the inbox owner. Stamped
        /// into the inbox state's `owner_ek_bytes` field so senders can
        /// recover the recipient's encryption key by Get-ing the inbox.
        /// Ignored for `ContractType::AFTContract`.
        ml_kem_ek_bytes: Vec<u8>,
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
    /// Fetch the inbox state for `inbox_address` (bs58 ContractInstanceId)
    /// so the ImportContact modal can populate the contact's pubkeys +
    /// fingerprint preview. On `GetResponse`, the api.rs handler routes
    /// the parsed state back into `IMPORT_FETCH_RESULT` for the modal to
    /// observe. See the import flow in `ui/src/app/login.rs`
    /// (`ImportContactForm`).
    FetchContactKeys {
        inbox_address: String,
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
    use_context_provider(|| Signal::new(login::ImportContact::default()));
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

    // Storybook short-circuit (#270): when the URL carries `?story=<name>`
    // AND this is an `example-data` build, render the isolated thread-component
    // host instead of the normal app. Fully cfg-gated so `use-node` builds
    // never compile it and the production path is untouched when no `?story=`
    // is present.
    #[cfg(feature = "example-data")]
    if let Some(story) = storybook::story_param() {
        let app_name = crate::app_name();
        return rsx! {
            document::Title { "{app_name}" }
            storybook::Storybook { story }
        };
    }

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
        recipient_inbox_wasm_hash: Option<String>,
        title: &str,
        content: &str,
        // #270 threading linkage carried through to the wire `DecryptedMessage`.
        // `thread_id` is the (possibly freshly-minted) conversation id;
        // `in_reply_to` / `quoted_excerpt` link a reply to its parent. All
        // `None` for a brand-new standalone compose.
        thread_id: Option<String>,
        in_reply_to: Option<String>,
        quoted_excerpt: Option<String>,
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
            thread_id,
            in_reply_to,
            quoted_excerpt,
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
            let recipient_hash_async = recipient_inbox_wasm_hash.clone();
            let f = async move {
                let res = content_clone
                    .start_sending(
                        &mut client,
                        recipient_ek,
                        recipient_ml_dsa_vk,
                        recipient_required_tier,
                        recipient_max_age_secs,
                        recipient_hash_async.as_deref(),
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
        #[cfg(not(feature = "use-node"))]
        let _ = recipient_inbox_wasm_hash;
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
                    // #270: propagate threading metadata into the in-memory
                    // mock mailbox so offline replies thread correctly.
                    thread_id: content.thread_id.clone(),
                    in_reply_to: content.in_reply_to.clone(),
                    quoted_excerpt: content.quoted_excerpt.clone(),
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

    /// Mark messages as read in the in-memory view. Read-state persistence
    /// to the mail-local-state delegate is the caller's responsibility (see
    /// `OpenMessage`). Crucially this does NOT evict the message from the
    /// inbox contract — read mail stays in the inbox just like every other
    /// mail client. Pre-fix this called `remove_messages`, which triggered
    /// a `GetResponse → from_state` renumber on the next refresh; the kept
    /// snapshot's id then collided with a different surviving message and
    /// the merge in `MessageList` silently dropped the row.
    #[allow(clippy::unnecessary_wraps)]
    fn mark_as_read(
        &mut self,
        _client: WebApiRequestClient,
        ids: &[u64],
        _inbox_data: InboxesData,
    ) -> Result<LocalBoxFuture<'static, ()>, DynError> {
        let messages = &mut *self.messages.borrow_mut();
        for e in messages {
            if ids.contains(&e.id) {
                e.read = true;
            }
        }
        Ok(async {}.boxed_local())
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
        // #270: a stable conversation id shared by the seeded multi-message
        // thread so the Nested / Compact views are exercisable offline (and
        // by the Playwright suite) without a node.
        const EXAMPLE_THREAD_ID: &str = "example-thread-0001";
        let mut emails = if id.id == UserId(0) {
            vec![
                // ── #270 seeded thread (3 messages, root + 2 replies) ──────
                Message {
                    id: 0,
                    from: "Mary".into(),
                    title: "Lunch tomorrow?".into(),
                    content: "Are you free for lunch tomorrow around noon?".into(),
                    read: true,
                    time: t(60 * 28),
                    sender_vk: Vec::new(),
                    signature_valid: false,
                    assignment_hash: [0u8; 32],
                    thread_id: Some(EXAMPLE_THREAD_ID.to_string()),
                    in_reply_to: None,
                    quoted_excerpt: None,
                },
                Message {
                    id: 1,
                    from: "address1".into(),
                    title: "Re: Lunch tomorrow?".into(),
                    content: "Noon works for me — the usual place?".into(),
                    read: true,
                    time: t(60 * 27),
                    sender_vk: Vec::new(),
                    signature_valid: false,
                    assignment_hash: [0u8; 32],
                    thread_id: Some(EXAMPLE_THREAD_ID.to_string()),
                    in_reply_to: Some("0".into()),
                    quoted_excerpt: Some("Are you free for lunch tomorrow around noon?".into()),
                },
                Message {
                    id: 2,
                    from: "Mary".into(),
                    title: "Re: Lunch tomorrow?".into(),
                    content: "Perfect, see you there!".into(),
                    read: false,
                    time: t(60 * 26),
                    sender_vk: Vec::new(),
                    signature_valid: false,
                    assignment_hash: [0u8; 32],
                    thread_id: Some(EXAMPLE_THREAD_ID.to_string()),
                    in_reply_to: Some("1".into()),
                    quoted_excerpt: Some("Noon works for me — the usual place?".into()),
                },
                // ── standalone messages (no thread_id) so list grouping is
                //    visibly mixed ───────────────────────────────────────────
                Message {
                    id: 3,
                    from: "Ian's Other Account".into(),
                    title: "Welcome to the offline preview".into(),
                    content: body.clone(),
                    read: false,
                    time: t(15),
                    sender_vk: Vec::new(),
                    signature_valid: false,
                    assignment_hash: [0u8; 32],
                    thread_id: None,
                    in_reply_to: None,
                    quoted_excerpt: None,
                },
                Message {
                    id: 4,
                    from: "freenet-bot".into(),
                    title: "Your weekly digest".into(),
                    content: body,
                    read: true,
                    time: t(60 * 24 * 4),
                    sender_vk: Vec::new(),
                    signature_valid: false,
                    assignment_hash: [0u8; 32],
                    thread_id: None,
                    in_reply_to: None,
                    quoted_excerpt: None,
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
                    thread_id: None,
                    in_reply_to: None,
                    quoted_excerpt: None,
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
                    thread_id: None,
                    in_reply_to: None,
                    quoted_excerpt: None,
                },
                // ── #287 seeded LEGACY two-party thread (no thread_id) ──────
                // A real back-and-forth between "Carol" and this identity on
                // one subject, but pre-#270 mail carries no shared thread_id.
                // Since the #287 fix, `group_into_threads` keys legacy mail by
                // normalized subject ALONE, so this folds into ONE group
                // carrying both sides — the guard for the "threaded view only
                // shows one side" report. Lives on UserId(1) so it doesn't
                // disturb the address1 row-count assertions in threads.spec.ts.
                Message {
                    id: 2,
                    from: "Carol".into(),
                    title: "Picnic this weekend?".into(),
                    content: "Want to join the picnic on Saturday?".into(),
                    read: true,
                    time: t(60 * 20),
                    sender_vk: Vec::new(),
                    signature_valid: false,
                    assignment_hash: [0u8; 32],
                    thread_id: None,
                    in_reply_to: None,
                    quoted_excerpt: None,
                },
                Message {
                    id: 3,
                    from: "address2".into(),
                    title: "Re: Picnic this weekend?".into(),
                    content: "Sounds great — what should I bring?".into(),
                    read: true,
                    time: t(60 * 19),
                    sender_vk: Vec::new(),
                    signature_valid: false,
                    assignment_hash: [0u8; 32],
                    thread_id: None,
                    in_reply_to: None,
                    quoted_excerpt: None,
                },
                Message {
                    id: 4,
                    from: "Carol".into(),
                    title: "Re: Picnic this weekend?".into(),
                    content: "Just drinks. See you at noon!".into(),
                    read: false,
                    time: t(60 * 18),
                    sender_vk: Vec::new(),
                    signature_valid: false,
                    assignment_hash: [0u8; 32],
                    thread_id: None,
                    in_reply_to: None,
                    quoted_excerpt: None,
                },
            ]
        };
        // Append any messages sent to this identity via the mock in-memory
        // mailbox (composed in a previous session by another identity).
        //
        // The append id MUST NOT collide with the parent id that a delivered
        // reply carries in its `in_reply_to`. A reply minted by the Reply
        // button references its parent by the parent's id *in the sender's
        // inbox*. The old `base_id = emails.len()` made the Nth delivered
        // message land at the same id in EVERY inbox, so a reply whose parent
        // sat at index N on the sender's side could land at id N on the
        // recipient's side too — i.e. `msg.id == msg.in_reply_to`, a
        // self-referential link that breaks thread grouping (the parent of a
        // received reply isn't in the recipient's own inbox vec anyway). Make
        // the append id space large and per-identity-disjoint so a delivered
        // message can never reuse the id its own `in_reply_to` points at, and
        // so it can't collide with the small seeded ids either.
        let alias = id.alias.to_string();
        let inbox_id_offset = 1_000_000 + (id.id.0 as u64) * 10_000;
        MOCK_SENT_MESSAGES.with(|map| {
            if let Some(sent) = map.borrow_mut().remove(&alias) {
                for (i, mut msg) in sent.into_iter().enumerate() {
                    msg.id = inbox_id_offset + i as u64;
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
            suggested_alias: None,
            description: "Example contact for offline testing".into(),
            ml_dsa_vk_bytes: vec![0xAA; 1952],
            ml_kem_ek_bytes: vec![0xBB; 1184],
            required_tier: freenet_aft_interface::Tier::Min10,
            max_age_secs: freenet_email_inbox::DEFAULT_MAX_AGE_SECS,
            verified: true,
            inbox_wasm_hash: None,
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
pub(crate) struct Message {
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
    /// Stable conversation id (#270). Shared by every message in a thread.
    /// `None` for legacy messages — those fall back to the heuristic
    /// subject+participant grouping in `crate::threads::group_into_threads`.
    thread_id: Option<String>,
    /// Parent message id this is a reply to (#270). Drives the nested-view
    /// depth calculation. `None` for thread roots and forwards.
    in_reply_to: Option<String>,
    /// The specific parent line being replied to (#270), surfaced as a
    /// collapsible "in reply to" chip. `None` for fresh sends / forwards.
    quoted_excerpt: Option<String>,
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
        // #270: kept-locally snapshots don't persist threading metadata yet;
        // such rows group via the heuristic fallback (subject+participants).
        thread_id: None,
        in_reply_to: None,
        quoted_excerpt: None,
    }
}

/// Build the inbox-list `Vec<Message>` from the live contract messages plus
/// the kept-locally snapshot. Pulled out of `MessageList` so the merge rules
/// (archive hiding, read-state overlay, kept-row dedup) can be unit-tested
/// without a Dioxus runtime.
///
/// The dedup between `live` and `kept` is by `Message.id` — which is
/// positional (`enumerate` index from `InboxModel::from_state`) and therefore
/// changes when the contract evicts a message. Callers must NOT rely on
/// `Message.id` being stable across contract-state reloads.
fn merge_inbox_list(
    live: Vec<Message>,
    kept: Vec<(mail_local_state::MessageId, mail_local_state::KeptMessage)>,
    is_archived: impl Fn(u64) -> bool,
    is_read: impl Fn(u64) -> bool,
) -> Vec<Message> {
    let mut out = Vec::with_capacity(live.len() + kept.len());
    for mut m in live {
        // Hide archived rows from the Inbox list (#47c). Until the
        // contract eviction round-trips, the live contract may still
        // serve a row the user has archived; we drop it client-side.
        if is_archived(m.id) {
            continue;
        }
        // Read-state survives reload because it lives in the
        // mail-local-state delegate, not just `mark_as_read`'s
        // local mutation. See issue #47/47a.
        if is_read(m.id) {
            m.read = true;
        }
        out.push(m);
    }
    // Merge kept-locally messages: rows the inbox contract has already
    // evicted but the user has read. They are always read, and dedup by
    // id against the live contract messages. Archived rows are excluded —
    // they belong to the Archive folder, not Inbox.
    for (mid, kept) in kept {
        if out.iter().any(|m| m.id == mid) {
            continue;
        }
        if is_archived(mid) {
            continue;
        }
        out.push(kept_to_message(mid, kept));
    }
    out
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
            // #270: carry the threading metadata through from the decrypted
            // wire message so the inbox-list grouping + threaded detail view
            // can reconstruct conversations.
            thread_id: value.content.thread_id,
            in_reply_to: value.content.in_reply_to,
            quoted_excerpt: value.content.quoted_excerpt,
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

/// #270 message threading: pure grouping logic.
///
/// `group_into_threads` collapses a flat `&[Message]` into conversations.
/// The primary key is the wire `thread_id`; for legacy messages that predate
/// threading (`thread_id == None`) it falls back to a heuristic key built
/// from the normalized subject (leading `Re:` / `Fwd:` prefixes stripped,
/// repeatedly + case-insensitively) plus the message's participant (the
/// `from` field — inbox `Message`s only carry the sender). Mixed groups
/// (some members carry a `thread_id`, some don't) resolve to the shared
/// `thread_id` so a legacy root + threaded replies still cluster.
///
/// Kept deliberately Dioxus-free so it is unit-testable without a runtime;
/// the phase-2 Nested / Compact views build on the `ThreadGroup` + per-message
/// depth map this module produces.
pub(crate) mod threads {
    use super::Message;
    use std::collections::HashMap;

    /// Maximum nesting depth for the indentation tree (#270). Replies deeper
    /// than this render at the cap so the tree stays readable on narrow
    /// viewports — matches the design's `.depth-4` ceiling.
    pub(crate) const MAX_THREAD_DEPTH: usize = 4;

    /// One collapsed conversation. `messages` is sorted oldest→newest so the
    /// views can render the chain top-down and default-expand the leaf.
    // `PartialEq` so it can be passed as a Dioxus component prop (#270).
    #[derive(Debug, Clone, PartialEq)]
    pub(crate) struct ThreadGroup {
        /// Resolved group key: the shared `thread_id` when any member has one,
        /// else the `heuristic:<normalized-subject>` fallback (or
        /// `heuristic-blank:<id>` for a subjectless legacy message, which
        /// stands alone). See `heuristic_key`.
        pub key: String,
        /// Conversation members, oldest→newest (sender send time, tie-break
        /// by `id`).
        pub messages: Vec<Message>,
        /// `id` of the oldest message — the conversation root for the tree.
        pub root_id: u64,
        /// Number of unread members. Drives the inbox-row count/badge styling.
        pub unread_count: usize,
        /// Total member count — the inbox row's "N messages" badge (#270).
        pub count: usize,
    }

    /// Strip leading reply/forward prefixes (`Re:`, `Fwd:`, `Fw:`),
    /// repeatedly and case-insensitively, then lower-case + trim. Used as the
    /// subject half of the heuristic key so `Re: Re: Lunch` and `Lunch`
    /// collapse together.
    pub(crate) fn normalize_subject(subject: &str) -> String {
        let mut s = subject.trim();
        loop {
            let lower = s.to_ascii_lowercase();
            let stripped = if let Some(rest) = lower.strip_prefix("re:") {
                &s[s.len() - rest.len()..]
            } else if let Some(rest) = lower.strip_prefix("fwd:") {
                &s[s.len() - rest.len()..]
            } else if let Some(rest) = lower.strip_prefix("fw:") {
                &s[s.len() - rest.len()..]
            } else {
                break;
            };
            s = stripped.trim_start();
        }
        s.trim().to_ascii_lowercase()
    }

    /// Heuristic group key for a legacy (thread-id-less) message. Prefixed
    /// `heuristic:` so it can never collide with a real UUID `thread_id`.
    ///
    /// Legacy (no-`thread_id`) mail is grouped by NORMALIZED SUBJECT ALONE.
    ///
    /// #287: keying on `subject|sender` split a two-party back-and-forth into
    /// one single-sided group per author — the threaded view showed only one
    /// side of the conversation. Since every inbox `Message` is addressed to
    /// the same logged-in identity (the recipient half carries no
    /// distinguishing information), two legacy messages that share a normalized
    /// subject are overwhelmingly the same conversation, so we fold them
    /// together regardless of sender.
    ///
    /// Tradeoff: distinct same-subject legacy conversations the user happens to
    /// have (e.g. a recurring mailing-list digest subject) fold into one
    /// heuristic group. That's strictly less wrong than splitting every
    /// two-party thread, and only ever applies to pre-#270 mail — anything sent
    /// via Reply carries a real `thread_id` and threads precisely.
    ///
    /// EXCEPTION (blank subjects): a message whose subject normalizes to the
    /// empty string (`""`, `"Re:"`, whitespace-only) gets a per-message key
    /// keyed on its `id`, NOT the shared empty-subject key. Otherwise every
    /// subjectless legacy message from every sender would collapse into one
    /// giant pseudo-conversation — an over-merge worse than the #287 split. A
    /// blank subject carries no grouping signal, so each such message stands
    /// alone (matching pre-#287 behaviour for these).
    fn heuristic_key(msg: &Message) -> String {
        let subject = normalize_subject(&msg.title);
        if subject.is_empty() {
            format!("heuristic-blank:{}", msg.id)
        } else {
            format!("heuristic:{subject}")
        }
    }

    /// Group `msgs` into conversations (#270).
    ///
    /// Two-pass to handle mixed `thread_id`/legacy conversations:
    /// 1. bucket every message by a provisional key (`thread_id` if present,
    ///    else the heuristic key);
    /// 2. for a legacy (`heuristic:`) bucket that shares its normalized
    ///    subject with a real `thread_id` bucket, fold the legacy bucket into
    ///    the threaded one (deterministically, smallest key wins on ties) so a
    ///    legacy root and its threaded replies cluster. `heuristic-blank:`
    ///    buckets (subjectless legacy mail) never fold.
    ///
    /// The returned groups are NOT ordered — callers sort for display.
    pub(crate) fn group_into_threads(msgs: &[Message]) -> Vec<ThreadGroup> {
        // Pass 1: provisional bucketing.
        let mut buckets: HashMap<String, Vec<Message>> = HashMap::new();
        for m in msgs {
            let key = match &m.thread_id {
                Some(t) => t.clone(),
                None => heuristic_key(m),
            };
            buckets.entry(key).or_default().push(m.clone());
        }

        // Pass 2: fold legacy (heuristic:) buckets into a threaded bucket that
        // shares the same normalized subject. This lets a legacy root message
        // join the thread its replies (which DO carry a thread_id) created.
        // We compute, for each thread_id bucket, the set of normalized
        // subjects it spans; a legacy bucket merges into the first thread_id
        // bucket whose span contains the legacy bucket's subject. Matching on
        // subject alone (not subject+sender) keeps Pass 2 consistent with the
        // sender-agnostic legacy key (#287).
        // A "real thread_id" bucket is anything not produced by heuristic_key:
        // neither the subject-keyed `heuristic:` nor the per-message
        // `heuristic-blank:` (blank subjects never fold — see heuristic_key).
        let is_legacy = |k: &str| k.starts_with("heuristic:") || k.starts_with("heuristic-blank:");
        let thread_subjects: HashMap<String, Vec<String>> = buckets
            .iter()
            .filter(|(k, _)| !is_legacy(k))
            .map(|(k, ms)| {
                let subjects: Vec<String> =
                    ms.iter().map(|m| normalize_subject(&m.title)).collect();
                (k.clone(), subjects)
            })
            .collect();

        // Only subject-keyed legacy buckets fold; `heuristic-blank:` stand alone.
        let legacy_keys: Vec<String> = buckets
            .keys()
            .filter(|k| k.starts_with("heuristic:"))
            .cloned()
            .collect();
        for legacy_key in legacy_keys {
            // Reconstruct the legacy subject from the key: "heuristic:<subj>".
            let subj = legacy_key["heuristic:".len()..].to_string();
            // Find a thread_id bucket whose span contains this subject. When
            // several thread_id buckets share the subject, pick the
            // lexicographically smallest key so the fold target is DETERMINISTIC
            // (buckets is a HashMap with randomized iteration order; an
            // unsorted `find` would fold into a different conversation per
            // process — the #137/#233 determinism class).
            let mut candidates: Vec<&String> = thread_subjects
                .iter()
                .filter(|(_, subjects)| subjects.contains(&subj))
                .map(|(k, _)| k)
                .collect();
            candidates.sort();
            let target = candidates.first().map(|k| (*k).clone());
            if let Some(target_key) = target
                && let Some(moved) = buckets.remove(&legacy_key)
            {
                buckets.entry(target_key).or_default().extend(moved);
            }
        }

        // Finalize: sort each bucket oldest→newest and compute aggregates.
        buckets
            .into_iter()
            .map(|(key, mut messages)| {
                messages.sort_by(|a, b| a.time.cmp(&b.time).then(a.id.cmp(&b.id)));
                let root_id = messages.first().map(|m| m.id).unwrap_or(0);
                let unread_count = messages.iter().filter(|m| !m.read).count();
                let count = messages.len();
                ThreadGroup {
                    key,
                    messages,
                    root_id,
                    unread_count,
                    count,
                }
            })
            .collect()
    }

    /// Flat fallback when threading is disabled (Settings → Appearance,
    /// `threading_enabled = false`). Each message becomes its own
    /// single-member `ThreadGroup`, so the inbox renders one row per
    /// message with no grouping and no count badge. Mirrors the
    /// finalize step of `group_into_threads` for a 1-message bucket.
    pub(crate) fn group_flat(msgs: &[Message]) -> Vec<ThreadGroup> {
        msgs.iter()
            .map(|m| ThreadGroup {
                key: format!("flat:{}", m.id),
                messages: vec![m.clone()],
                root_id: m.id,
                unread_count: usize::from(!m.read),
                count: 1,
            })
            .collect()
    }

    /// Deterministic display order for the grouped inbox list (#270; the
    /// #137/#233 determinism class).
    ///
    /// Primary key is the group's newest member via `super::sort_cmp_inbox`
    /// (newest time first, then `assignment_hash` descending). When two groups'
    /// newest members collide on BOTH time AND `assignment_hash` — e.g. two
    /// seeded example threads, or two messages minted in the same millisecond
    /// with an all-zero hash — that comparator returns `Equal` and `sort_by`'s
    /// stability is no longer enough to guarantee a fixed order across renders
    /// (the upstream `Vec<ThreadGroup>` arrives in `HashMap` iteration order,
    /// which is randomized per process). The FINAL tie-break on `root_id`
    /// descending makes the order total and reproducible.
    pub(crate) fn sort_cmp_group(a: &ThreadGroup, b: &ThreadGroup) -> std::cmp::Ordering {
        let primary = match (a.messages.last(), b.messages.last()) {
            (Some(am), Some(bm)) => super::sort_cmp_inbox(am, bm),
            _ => std::cmp::Ordering::Equal,
        };
        // Total tie-break: newest root_id first. `root_id` is unique per group
        // (it's the oldest member's message id), so this can never itself tie.
        primary.then_with(|| b.root_id.cmp(&a.root_id))
    }

    /// Per-message nesting depth for the Nested view (#270).
    ///
    /// Depth is the length of the `in_reply_to` chain from the root, capped at
    /// [`MAX_THREAD_DEPTH`]. Returns a map keyed by `Message.id`. Roots (no
    /// `in_reply_to`, or an `in_reply_to` that doesn't resolve within the
    /// group) are depth 0. `in_reply_to` is the parent's stringified `id`.
    pub(crate) fn depth_map(group: &ThreadGroup) -> HashMap<u64, usize> {
        // id (as string) → parent id (as string), for members of this group.
        let parent_of: HashMap<String, String> = group
            .messages
            .iter()
            .filter_map(|m| m.in_reply_to.clone().map(|p| (m.id.to_string(), p)))
            .collect();
        let present: std::collections::HashSet<String> =
            group.messages.iter().map(|m| m.id.to_string()).collect();

        let mut out = HashMap::with_capacity(group.messages.len());
        for m in &group.messages {
            let mut depth = 0usize;
            let mut cursor = m.id.to_string();
            // Walk up the parent chain. Guard against cycles (malformed
            // in_reply_to) with a hop budget == group size.
            let mut budget = group.messages.len();
            while let Some(parent) = parent_of.get(&cursor) {
                if !present.contains(parent) {
                    break; // dangling parent → treat current as a root branch
                }
                depth += 1;
                cursor = parent.clone();
                budget = budget.saturating_sub(1);
                if budget == 0 {
                    break;
                }
            }
            out.insert(m.id, depth.min(MAX_THREAD_DEPTH));
        }
        out
    }
}

/// In-app storybook for the #270 thread components (`example-data` builds
/// only). Renders the REAL `ThreadDetail` / `ThreadNested` / `ThreadCompact`
/// from hand-built `ThreadGroup` props — not from URL-seeded mailbox data —
/// so the views can be screenshotted in isolation with prefilled state. Gated
/// twice over: the module only compiles under `feature = "example-data"`, and
/// the host only renders when the URL carries `?story=<name>` (see
/// [`story_param`]). Zero surface in the production `use-node` build.
#[cfg(feature = "example-data")]
pub(crate) mod storybook {
    use super::threads::ThreadGroup;
    use super::{Message, User, UserId};
    use crate::testid;
    use chrono::{TimeZone, Utc};
    use dioxus::prelude::*;
    use std::borrow::Cow;

    /// Read the `story` query parameter from the current URL in WASM. Returns
    /// `Some(name)` when `?story=<name>` is present (and non-empty), else
    /// `None`. Used by `app()` to decide whether to mount the storybook host
    /// instead of the normal login/app routing.
    pub(crate) fn story_param() -> Option<String> {
        query_param("story").filter(|s| !s.is_empty())
    }

    /// Generic single-value query-param reader. Parses
    /// `window.location.search` by hand (no extra dep) — the search string is
    /// `?a=b&c=d`; we split on `&`, then `=`, and URL-decode `+` → space.
    /// `web_sys` is wasm-only (gated in `ui/Cargo.toml`), so on native host
    /// builds (cargo test) this always returns `None`.
    fn query_param(key: &str) -> Option<String> {
        #[cfg(target_family = "wasm")]
        {
            let search = web_sys::window()?.location().search().ok()?;
            let q = search.strip_prefix('?').unwrap_or(&search);
            for pair in q.split('&') {
                let mut it = pair.splitn(2, '=');
                let k = it.next()?;
                if k == key {
                    let v = it.next().unwrap_or("");
                    return Some(v.replace('+', " "));
                }
            }
            None
        }
        #[cfg(not(target_family = "wasm"))]
        {
            let _ = key;
            None
        }
    }

    /// Build a `Message` for a story. `from` is the displayed sender (set it to
    /// the logged-in alias to trigger `.is-me` styling in Nested view).
    #[allow(clippy::too_many_arguments)]
    fn msg(
        id: u64,
        from: &str,
        title: &str,
        content: &str,
        secs: i64,
        read: bool,
        tid: &str,
        irt: Option<u64>,
        quoted: Option<&str>,
    ) -> Message {
        Message {
            id,
            from: Cow::Owned(from.to_string()),
            title: Cow::Owned(title.to_string()),
            content: Cow::Owned(content.to_string()),
            read,
            time: Utc.timestamp_opt(1_700_000_000 + secs, 0).unwrap(),
            sender_vk: Vec::new(),
            signature_valid: false,
            assignment_hash: [0u8; 32],
            thread_id: Some(tid.to_string()),
            in_reply_to: irt.map(|p| p.to_string()),
            quoted_excerpt: quoted.map(str::to_string),
        }
    }

    /// Finalize a `Vec<Message>` into a `ThreadGroup` (messages already
    /// oldest→newest). Mirrors the aggregates `group_into_threads` computes.
    fn group(key: &str, messages: Vec<Message>) -> ThreadGroup {
        let root_id = messages.first().map(|m| m.id).unwrap_or(0);
        let unread_count = messages.iter().filter(|m| !m.read).count();
        let count = messages.len();
        ThreadGroup {
            key: key.to_string(),
            messages,
            root_id,
            unread_count,
            count,
        }
    }

    /// Story 1 — interleaved own↔other conversation. Messages alternate
    /// `from = "address1"` (the logged-in identity → `.is-me`) and
    /// `from = "Mary"`, all under one `thread_id`, oldest→newest. Visualizes
    /// the INTENDED look in which the user's Sent messages fold into the inbox
    /// thread. NOTE: production does not yet fold Sent into the inbox thread
    /// (the inbox `Message` vec carries inbound mail only); the storybook
    /// builds the interleaved group directly to show the target rendering.
    pub(crate) fn story_sender_sent() -> ThreadGroup {
        let tid = "story-sender-sent";
        group(
            tid,
            vec![
                msg(
                    0,
                    "Mary",
                    "Lunch tomorrow?",
                    "Are you free for lunch tomorrow around noon?",
                    0,
                    true,
                    tid,
                    None,
                    None,
                ),
                msg(
                    1,
                    "address1",
                    "Re: Lunch tomorrow?",
                    "Yes! Noon works great for me.",
                    60,
                    true,
                    tid,
                    Some(0),
                    Some("Are you free for lunch tomorrow around noon?"),
                ),
                msg(
                    2,
                    "Mary",
                    "Re: Lunch tomorrow?",
                    "Perfect — the usual place?",
                    120,
                    true,
                    tid,
                    Some(1),
                    Some("Yes! Noon works great for me."),
                ),
                msg(
                    3,
                    "address1",
                    "Re: Lunch tomorrow?",
                    "Sounds good, see you there.",
                    180,
                    true,
                    tid,
                    Some(2),
                    Some("Perfect — the usual place?"),
                ),
            ],
        )
    }

    /// Story 2 — a single thread with an `in_reply_to` chain 6 deep
    /// (0←1←2←3←4←5). `depth_map` clamps at `MAX_THREAD_DEPTH = 4`, so the
    /// rendered depths are 0,1,2,3,4,4 — exercising the connector rails and
    /// the cap in `ThreadNested`.
    pub(crate) fn story_deep_nest() -> ThreadGroup {
        let tid = "story-deep-nest";
        let mut messages = Vec::new();
        for i in 0u64..6 {
            let parent = if i == 0 { None } else { Some(i - 1) };
            messages.push(msg(
                i,
                if i % 2 == 0 { "Mary" } else { "address1" },
                if i == 0 {
                    "Deploy plan"
                } else {
                    "Re: Deploy plan"
                },
                &format!("Reply number {i} in the chain — drilling one level deeper."),
                (i as i64) * 60,
                true,
                tid,
                parent,
                if i == 0 {
                    None
                } else {
                    Some("Reply number above in the chain — drilling one level deeper.")
                },
            ));
        }
        group(tid, messages)
    }

    /// Story 3 — a 4-message thread with `quoted_excerpt` chips, rendered both
    /// ways. The spec drives Nested vs Compact via `?view=`; the group itself
    /// is identical for both.
    pub(crate) fn story_nested_vs_compact() -> ThreadGroup {
        let tid = "story-nested-vs-compact";
        group(
            tid,
            vec![
                msg(
                    0,
                    "Mary",
                    "Quarterly roadmap",
                    "Sharing the draft roadmap for Q3. Thoughts welcome.",
                    0,
                    true,
                    tid,
                    None,
                    None,
                ),
                msg(
                    1,
                    "address1",
                    "Re: Quarterly roadmap",
                    "Looks solid. One concern about the timeline on item 2.",
                    60,
                    true,
                    tid,
                    Some(0),
                    Some("Sharing the draft roadmap for Q3. Thoughts welcome."),
                ),
                msg(
                    2,
                    "Mary",
                    "Re: Quarterly roadmap",
                    "Good catch — I'll push item 2 a week.",
                    120,
                    true,
                    tid,
                    Some(1),
                    Some("One concern about the timeline on item 2."),
                ),
                msg(
                    3,
                    "address1",
                    "Re: Quarterly roadmap",
                    "Great, that works. Approving.",
                    180,
                    true,
                    tid,
                    Some(2),
                    Some("I'll push item 2 a week."),
                ),
            ],
        )
    }

    /// Resolve a story name to its `ThreadGroup`. Unknown names fall back to
    /// story 1 so a typo'd URL still renders something.
    fn group_for(story: &str) -> ThreadGroup {
        match story {
            "deep-nest" => story_deep_nest(),
            "nested-vs-compact" => story_nested_vs_compact(),
            _ => story_sender_sent(),
        }
    }

    /// The storybook host. Provides the SAME Dioxus contexts the root `app()`
    /// provides (with mock/default values) so the thread components'
    /// `use_context` reads don't panic, logs in as `address1` so `.is-me`
    /// styling resolves, sets the requested `thread_view`, then renders the
    /// real `ThreadDetail` inside a `.fm-app` wrapper (so the `@scope`d
    /// component CSS applies).
    #[component]
    pub(crate) fn Storybook(story: String) -> Element {
        // Mirror the root-app provider block (app.rs ~149-178) so every
        // `use_context::<…>()` the thread subtree performs resolves.
        use_context_provider(|| Signal::new(super::login::LoginController::new()));
        use_context_provider(|| {
            let mut u = User::new();
            // Log in as the first seeded identity ("address1", UserId(0)) so
            // the active alias matches the story's own-message `from`,
            // lighting up `.is-me` styling in the Nested view.
            u.set_logged_id(UserId(0));
            Signal::new(u)
        });
        let user = use_context::<Signal<User>>();
        use_context_provider(|| Signal::new(super::InboxView::new()));
        use_context_provider(super::InboxesData::new);
        use_context_provider(|| super::AddressBookGen(Signal::new(0u32)));
        use_context_provider(|| crate::toast::ToastQueue::new(Vec::new()));
        use_context_provider(|| Signal::new(super::login::ImportBackup(false)));
        use_context_provider(|| Signal::new(super::login::ImportContact::default()));
        use_context_provider(|| Signal::new(super::login::ShareContact(false)));
        use_context_provider(|| Signal::new(super::login::SharePending::default()));
        // MenuSelection is normally provided by UserInbox, not app(); the
        // thread rows read it, so provide it here too.
        use_context_provider(|| Signal::new(super::menu::MenuSelection::default()));

        // Pick the thread_view from `?view=` (defaults to Nested). Story 3
        // uses this to request each rendering; stories 1 & 2 ignore it and
        // get the Nested default.
        let view = query_param("view").unwrap_or_default();
        let thread_view = if view == "compact" {
            mail_local_state::ThreadView::Compact
        } else {
            mail_local_state::ThreadView::Nested
        };
        let mut settings = crate::local_state::global_settings();
        settings.inbox.thread_view = thread_view;
        crate::local_state::local_set_global_settings(settings);

        let _ = user; // touched only to anchor the provider above
        let group = group_for(&story);
        let label = story.clone();

        rsx! {
            div {
                class: "fm-app",
                "data-testid": testid::FM_STORYBOOK,
                "data-story": "{label}",
                "data-font-size": "default",
                div { class: "main",
                    super::ThreadDetail { group }
                }
            }
        }
    }
}

#[cfg(test)]
mod thread_grouping_tests {
    use super::Message;
    use super::threads::{MAX_THREAD_DEPTH, depth_map, group_into_threads, normalize_subject};
    use chrono::{TimeZone, Utc};
    use std::borrow::Cow;

    /// Build a `Message` for grouping tests. `secs` orders messages within a
    /// thread; `from` is the participant; `tid` / `irt` are the threading
    /// linkage.
    #[allow(clippy::too_many_arguments)]
    fn m(
        id: u64,
        from: &'static str,
        title: &'static str,
        secs: i64,
        read: bool,
        tid: Option<&str>,
        irt: Option<&str>,
    ) -> Message {
        Message {
            id,
            from: Cow::Borrowed(from),
            title: Cow::Borrowed(title),
            content: Cow::Borrowed("body"),
            read,
            time: Utc.timestamp_opt(1_700_000_000 + secs, 0).unwrap(),
            sender_vk: Vec::new(),
            signature_valid: false,
            assignment_hash: [0u8; 32],
            thread_id: tid.map(str::to_string),
            in_reply_to: irt.map(str::to_string),
            quoted_excerpt: None,
        }
    }

    fn group_with_key<'a>(
        groups: &'a [super::threads::ThreadGroup],
        key: &str,
    ) -> &'a super::threads::ThreadGroup {
        groups
            .iter()
            .find(|g| g.key == key)
            .unwrap_or_else(|| panic!("no group with key {key}; got {:?}", keys(groups)))
    }

    fn keys(groups: &[super::threads::ThreadGroup]) -> Vec<String> {
        groups.iter().map(|g| g.key.clone()).collect()
    }

    fn group_with_key_opt<'a>(
        groups: &'a [super::threads::ThreadGroup],
        key: &str,
    ) -> Option<&'a super::threads::ThreadGroup> {
        groups.iter().find(|g| g.key == key)
    }

    /// (a) Messages sharing a `thread_id` group together regardless of
    /// subject, and the group reports the right count / unread / root / order.
    #[test]
    fn groups_by_thread_id() {
        let msgs = vec![
            m(0, "mary", "Lunch?", 0, true, Some("t1"), None),
            m(2, "mary", "Re: Lunch?", 20, false, Some("t1"), Some("1")),
            m(1, "me", "Re: Lunch?", 10, true, Some("t1"), Some("0")),
        ];
        let groups = group_into_threads(&msgs);
        assert_eq!(groups.len(), 1);
        let g = group_with_key(&groups, "t1");
        assert_eq!(g.count, 3);
        assert_eq!(g.unread_count, 1);
        assert_eq!(g.root_id, 0, "oldest message is root");
        // oldest→newest by time then id
        let order: Vec<u64> = g.messages.iter().map(|x| x.id).collect();
        assert_eq!(order, vec![0, 1, 2]);
    }

    /// (b) Legacy messages (no thread_id) group via the heuristic key by
    /// NORMALIZED SUBJECT ALONE, with "Re:"/"Fwd:" normalization. Different
    /// senders on the same subject fold into ONE group (#287) — a two-party
    /// legacy conversation is one thread, not one-per-author.
    #[test]
    fn groups_legacy_by_heuristic_subject_across_senders() {
        let msgs = vec![
            m(0, "jane", "Design review", 0, false, None, None),
            m(1, "jane", "Re: Design review", 10, false, None, None),
            m(2, "jane", "Re: Re: Design review", 20, false, None, None),
            // Different sender, same normalized subject → SAME group (#287).
            m(3, "bob", "Design review", 30, false, None, None),
        ];
        let groups = group_into_threads(&msgs);
        assert_eq!(
            groups.len(),
            1,
            "same normalized subject folds across senders (#287)"
        );
        let g = group_with_key(&groups, "heuristic:design review");
        assert_eq!(g.count, 4, "all four messages in one conversation");
    }

    /// (#287) A two-party LEGACY back-and-forth (both participants alternating
    /// on one subject, NO `thread_id` on any message) FOLDS into a single
    /// conversation carrying both sides.
    ///
    /// Pre-#287 the heuristic key was `subject|sender`, so this split into one
    /// single-sided group per author and the threaded view showed only one
    /// side (#287). The key is now normalized-subject alone, so both sides
    /// merge. Mail carrying a shared `thread_id` (post-#270 Reply) threads the
    /// same way — see `legacy_two_party_with_shared_thread_id_folds` below.
    #[test]
    fn legacy_two_party_back_and_forth_folds_across_senders() {
        // alice and bob alternate four turns on "Project sync", none carrying a
        // thread_id (legacy / pre-#270 mail).
        let msgs = vec![
            m(0, "alice", "Project sync", 0, true, None, None),
            m(1, "bob", "Re: Project sync", 10, true, None, None),
            m(2, "alice", "Re: Project sync", 20, true, None, None),
            m(3, "bob", "Re: Project sync", 30, false, None, None),
        ];
        let groups = group_into_threads(&msgs);
        assert_eq!(
            groups.len(),
            1,
            "legacy two-party back-and-forth folds into one conversation (#287)"
        );
        let g = group_with_key(&groups, "heuristic:project sync");
        assert_eq!(g.count, 4, "all four turns — both sides — in one thread");
        assert_eq!(g.root_id, 0, "oldest message is the thread root");
    }

    /// (#287 review M2) Legacy messages whose subject normalizes to empty
    /// ("", "Re:", whitespace) must each stand ALONE, not collapse into one
    /// giant pseudo-conversation. The blank subject carries no grouping signal,
    /// so the key falls back to per-message `heuristic-blank:<id>`.
    #[test]
    fn blank_subject_legacy_messages_stand_alone() {
        let msgs = vec![
            m(0, "alice", "", 0, false, None, None),
            m(1, "bob", "   ", 10, false, None, None),
            m(2, "carol", "Re:", 20, false, None, None),
        ];
        let groups = group_into_threads(&msgs);
        assert_eq!(
            groups.len(),
            3,
            "blank-subject legacy mail must NOT merge across senders (#287 M2)"
        );
        for id in 0..3 {
            assert!(
                group_with_key_opt(&groups, &format!("heuristic-blank:{id}")).is_some(),
                "message {id} stands alone under its per-id blank key"
            );
        }
    }

    /// (#287 review M1) When two distinct `thread_id` conversations share a
    /// normalized subject and a legacy orphan also carries that subject, the
    /// fold target must be DETERMINISTIC (smallest thread_id key wins), not
    /// dependent on HashMap iteration order (the #137/#233 determinism class).
    #[test]
    fn legacy_fold_target_is_deterministic_across_shared_subject_threads() {
        // The fold target must be the lexicographically SMALLEST thread key,
        // regardless of HashMap iteration order. A single same-seed run cannot
        // observe the old `.find()` nondeterminism (one process = one hasher
        // seed → one fixed iteration order), so instead we assert the property
        // that distinguishes sort-and-pick-first from find-first: which thread
        // wins must follow KEY ORDER, not insertion or iteration order.
        //
        // Two scenarios with the winner's key flipped. The buggy `.find()`
        // (iteration-order dependent) cannot satisfy BOTH deterministically —
        // it would have to pick the orphan's target by subject-iteration, which
        // is independent of which key is smallest. Only sort-by-key + first()
        // makes the smallest key win in both, so a regression to `.find()`
        // fails at least one scenario on most seeds.
        //
        // `aaa` < `zzz`: orphan must fold into the `aaa` thread in BOTH, even
        // though scenario 2 inserts/sees them in the opposite relative position.
        let scenario = |first_key: &str, second_key: &str| {
            let msgs = vec![
                m(0, "a", "Standup", 0, true, Some(first_key), None),
                m(1, "b", "Standup", 10, true, Some(second_key), None),
                m(2, "c", "Re: Standup", 20, false, None, None), // legacy "standup"
            ];
            let groups = group_into_threads(&msgs);
            // Whichever key is smaller must be the one carrying the orphan.
            let (small, large) = if first_key < second_key {
                (first_key, second_key)
            } else {
                (second_key, first_key)
            };
            assert_eq!(
                group_with_key(&groups, small).count,
                2,
                "orphan folds into the lexicographically smallest thread key ({small})",
            );
            assert_eq!(
                group_with_key(&groups, large).count,
                1,
                "the larger key ({large}) never receives the orphan",
            );
        };
        // Run each ordering many times: every run must agree (catches any
        // residual per-call nondeterminism) AND the smaller key must always win.
        for _ in 0..50 {
            scenario("aaa", "zzz"); // smaller listed first
            scenario("zzz", "aaa"); // smaller listed second — winner must flip to follow key order, not position
        }
    }

    /// Counterpart to the split above: the SAME two-party alternating
    /// conversation, but every message carries a shared `thread_id` (as a
    /// post-#270 Reply-button exchange would). Now it folds into ONE group
    /// across both senders. This is the regime in which #270's "two identities
    /// exchanging N messages render as one expandable thread" acceptance holds.
    #[test]
    fn legacy_two_party_with_shared_thread_id_folds() {
        let msgs = vec![
            m(0, "alice", "Project sync", 0, true, Some("ts"), None),
            m(
                1,
                "bob",
                "Re: Project sync",
                10,
                true,
                Some("ts"),
                Some("0"),
            ),
            m(
                2,
                "alice",
                "Re: Project sync",
                20,
                true,
                Some("ts"),
                Some("1"),
            ),
            m(
                3,
                "bob",
                "Re: Project sync",
                30,
                false,
                Some("ts"),
                Some("2"),
            ),
        ];
        let groups = group_into_threads(&msgs);
        assert_eq!(
            groups.len(),
            1,
            "a shared thread_id threads both senders into one conversation"
        );
        let g = group_with_key(&groups, "ts");
        assert_eq!(g.count, 4);
        assert_eq!(g.root_id, 0);
    }

    /// `normalize_subject` strips repeated, mixed-case Re:/Fwd:/Fw: prefixes.
    #[test]
    fn normalize_subject_strips_repeated_prefixes() {
        assert_eq!(normalize_subject("Re: Re: Lunch"), "lunch");
        assert_eq!(normalize_subject("FWD: re: Hello"), "hello");
        assert_eq!(normalize_subject("fw: Status"), "status");
        assert_eq!(normalize_subject("Plain"), "plain");
        assert_eq!(normalize_subject("  Re:  Spaced  "), "spaced");
    }

    /// (c) A mixed conversation — a legacy root (no thread_id) plus threaded
    /// replies sharing the same normalized subject + participant — folds into
    /// a single group keyed by the real thread_id.
    #[test]
    fn mixed_thread_id_and_legacy_fold_together() {
        let msgs = vec![
            // legacy root, no thread_id
            m(0, "mary", "Lunch?", 0, true, None, None),
            // threaded replies carrying the (same-participant) thread_id
            m(1, "mary", "Re: Lunch?", 10, false, Some("t9"), Some("0")),
            m(2, "mary", "Re: Lunch?", 20, false, Some("t9"), Some("1")),
        ];
        let groups = group_into_threads(&msgs);
        assert_eq!(
            groups.len(),
            1,
            "legacy root folds into the threaded bucket"
        );
        let g = group_with_key(&groups, "t9");
        assert_eq!(g.count, 3);
        assert_eq!(g.root_id, 0);
    }

    /// (d) Depth is the in_reply_to chain length from the root, capped at 4.
    #[test]
    fn depth_computed_from_chain_and_capped() {
        // 0 ← 1 ← 2 ← 3 ← 4 ← 5 ← 6 : depths 0,1,2,3,4,4,4 (cap 4)
        let mut msgs = vec![m(0, "a", "Hi", 0, false, Some("t"), None)];
        for i in 1..=6u64 {
            msgs.push(m(
                i,
                "a",
                "Re: Hi",
                (i as i64) * 10,
                false,
                Some("t"),
                Some(&(i - 1).to_string()),
            ));
        }
        let groups = group_into_threads(&msgs);
        let g = group_with_key(&groups, "t");
        let depths = depth_map(g);
        assert_eq!(depths[&0], 0);
        assert_eq!(depths[&1], 1);
        assert_eq!(depths[&2], 2);
        assert_eq!(depths[&3], 3);
        assert_eq!(depths[&4], 4);
        assert_eq!(depths[&5], MAX_THREAD_DEPTH, "capped at 4");
        assert_eq!(depths[&6], MAX_THREAD_DEPTH, "still capped at 4");
    }

    /// A dangling `in_reply_to` (parent not in the group) is treated as a
    /// root branch (depth 0), not an infinite walk.
    #[test]
    fn depth_dangling_parent_is_root() {
        let msgs = vec![
            m(0, "a", "Hi", 0, false, Some("t"), None),
            m(1, "a", "Re: Hi", 10, false, Some("t"), Some("999")),
        ];
        let groups = group_into_threads(&msgs);
        let g = group_with_key(&groups, "t");
        let depths = depth_map(g);
        assert_eq!(depths[&1], 0, "dangling parent → depth 0");
    }

    /// (e) A conversation interleaving sent (from "me") and received messages
    /// orders strictly chronologically oldest→newest.
    #[test]
    fn chronological_interleave_of_sent_and_received() {
        let msgs = vec![
            m(2, "me", "Re: Hi", 20, true, Some("t"), Some("0")),
            m(0, "alice", "Hi", 0, true, Some("t"), None),
            m(3, "alice", "Re: Hi", 30, false, Some("t"), Some("2")),
            m(1, "me", "Re: Hi", 10, true, Some("t"), Some("0")),
        ];
        let groups = group_into_threads(&msgs);
        let g = group_with_key(&groups, "t");
        let order: Vec<u64> = g.messages.iter().map(|x| x.id).collect();
        assert_eq!(order, vec![0, 1, 2, 3], "sorted by time then id");
    }

    /// Sanity: standalone (no thread_id, unique subject+participant) messages
    /// each land in their own single-message group, mixed with grouped ones.
    #[test]
    fn standalone_messages_stay_separate() {
        let msgs = vec![
            m(0, "mary", "Lunch?", 0, false, Some("t1"), None),
            m(1, "mary", "Re: Lunch?", 10, false, Some("t1"), Some("0")),
            m(2, "bot", "Weekly digest", 20, false, None, None),
            m(3, "ian", "Welcome", 30, false, None, None),
        ];
        let groups = group_into_threads(&msgs);
        assert_eq!(groups.len(), 3, "one thread + two standalone");
        assert_eq!(group_with_key(&groups, "t1").count, 2);
    }

    /// SHOULD-4 (#270, #137/#233 determinism class): two groups whose newest
    /// members collide on BOTH time AND `assignment_hash` (the `m()` helper
    /// uses an all-zero hash) must still sort into a single, stable order
    /// driven by the final `root_id`-descending tie-break — not by `HashMap`
    /// iteration order. Asserts the comparator is a total order (newest
    /// root_id first) regardless of input order.
    #[test]
    fn groups_with_identical_time_and_hash_sort_deterministically() {
        use super::threads::sort_cmp_group;
        // Two single-message groups, same time (secs=0) and same all-zero
        // assignment_hash, differing only in root_id (5 vs 9).
        let msgs_ab = vec![
            m(5, "a", "Alpha", 0, true, Some("ta"), None),
            m(9, "b", "Beta", 0, true, Some("tb"), None),
        ];
        let mut groups = group_into_threads(&msgs_ab);
        groups.sort_by(sort_cmp_group);
        let order_ab: Vec<u64> = groups.iter().map(|g| g.root_id).collect();
        assert_eq!(order_ab, vec![9, 5], "newest root_id first on a full tie");

        // Reversed input must yield the SAME order — the comparator, not the
        // (randomized) bucket iteration order, decides.
        let msgs_ba = vec![
            m(9, "b", "Beta", 0, true, Some("tb"), None),
            m(5, "a", "Alpha", 0, true, Some("ta"), None),
        ];
        let mut groups2 = group_into_threads(&msgs_ba);
        groups2.sort_by(sort_cmp_group);
        let order_ba: Vec<u64> = groups2.iter().map(|g| g.root_id).collect();
        assert_eq!(order_ba, order_ab, "order is independent of input order");

        // And the comparator never returns Equal for distinct groups.
        assert_ne!(
            sort_cmp_group(&groups[0], &groups[1]),
            std::cmp::Ordering::Equal,
            "distinct groups must compare as a strict order"
        );
    }

    /// #289 root cause (unit-level): the reply prefill addresses the To field
    /// by the incoming message's *display sender* (`m.from`) — the alias the
    /// SENDER chose — not by the sender's VK / inbox key. So when the
    /// recipient imported that sender under a DIFFERENT local nickname, the
    /// reply's To carries a string that won't resolve against their address
    /// book, and the send is blocked until they hand-edit it.
    ///
    /// This pins the load-bearing claim. The full UI reply round-trip is
    /// covered by the deferred iso test tracked in #291. Once #289 is fixed
    /// (reply resolves by VK / inbox key, and/or the contact-add modal
    /// pre-fills the nickname from the incoming sender), the prefill should
    /// carry a stable handle rather than the raw sender alias and this
    /// assertion will need to move to the new contract.
    #[test]
    fn reply_prefill_addresses_by_display_sender_not_vk_289() {
        // A received message whose sender called themselves "alice-from-work".
        let received = m(
            7,
            "alice-from-work",
            "Project kickoff",
            0,
            true,
            Some("thread-x"),
            None,
        );

        let prefill = super::thread_reply_prefill(&received);

        // The reply is addressed to the raw display-sender string. If the
        // recipient imported alice under a different local label (e.g.
        // "ally"), `address_book::lookup("alice-from-work")` misses and the
        // reply can't be sent — exactly #289.
        assert_eq!(
            prefill.to, "alice-from-work",
            "reply To is the incoming sender's display alias (#289 root cause); \
             a recipient who imported them under a different nickname can't resolve it",
        );
        // Sanity: the prefill keeps the conversation in-thread and quotes the
        // parent — only the recipient resolution is broken, not the threading.
        assert_eq!(prefill.thread_id.as_deref(), Some("thread-x"));
        assert_eq!(prefill.in_reply_to.as_deref(), Some("7"));
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
        Quarantine,
        Sent,
        Drafts,
        Archive,
    }

    impl Folder {
        pub fn label(self) -> &'static str {
            match self {
                Folder::Inbox => "Inbox",
                Folder::Quarantine => "Quarantine",
                Folder::Sent => "Sent",
                Folder::Drafts => "Drafts",
                Folder::Archive => "Archive",
            }
        }

        pub fn icon(self) -> &'static str {
            match self {
                Folder::Inbox => "▤",
                Folder::Quarantine => "⚠",
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
        /// #270 threading linkage carried into the compose sheet. A reply
        /// sets all three: `thread_id` (the parent's, or freshly minted),
        /// `in_reply_to` (parent message id), `quoted_excerpt` (the parent
        /// line being replied to). A fresh compose / forward leaves them
        /// `None`, starting a new conversation on send.
        pub thread_id: Option<String>,
        pub in_reply_to: Option<String>,
        pub quoted_excerpt: Option<String>,
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
        /// #270: the `root_id` of the conversation opened from the grouped
        /// inbox list. When set, the Inbox/Quarantine detail pane renders the
        /// whole `ThreadGroup` (Nested or Compact) instead of a single
        /// message. Resolved back to its group by `root_id` in `DetailPanel`.
        thread_root: Option<u64>,
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
                self.thread_root = None;
            }
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
            self.thread_root = None;
            self.new_msg = false;
            self.compose_prefill = None;
        }

        // #270: Inbox/Quarantine rows now open as threads via `open_thread`;
        // this single-message opener is retained for deep-link / search-result
        // selection (the DetailPanel `OpenMessage` fallback) but currently has
        // no caller, hence the allow.
        #[allow(dead_code)]
        pub fn open_email(&mut self, id: u64) {
            self.email = Some(id);
            // Opening a single message clears any thread selection so the two
            // detail-pane paths can't both fire (#270).
            self.thread_root = None;
        }

        pub fn email(&self) -> Option<u64> {
            self.email
        }

        /// #270: open the conversation rooted at `root_id` (the oldest message
        /// of a `ThreadGroup`). The detail pane renders the whole group.
        pub fn open_thread(&mut self, root_id: u64) {
            self.thread_root = Some(root_id);
            self.email = None;
        }

        pub fn thread_root(&self) -> Option<u64> {
            self.thread_root
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
                self.thread_root = None;
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

/// True when `m`'s sender is in the address book AND verified. Drives the
/// Inbox/Quarantine split: when `quarantine_unknown` is on, only senders for
/// which this returns true stay in the Inbox; everyone else (including
/// signature-less rows) lands in Quarantine. Empty sender-vk never counts as
/// known.
fn is_sender_verified(m: &Message) -> bool {
    if m.sender_vk.is_empty() {
        return false;
    }
    matches!(
        address_book::contact_by_vk(&m.sender_vk),
        Some(c) if c.verified
    )
}

/// Predicate matching the Inbox/Quarantine render filter in `MessageList`
/// (#268). The sidebar badge MUST count only rows that would actually appear
/// in the folder's list — otherwise the badge over-counts deleted/archived
/// rows the list hides, so the number never matches the contents. Keep this in
/// sync with the `visible` filter chain in `MessageList`.
fn is_inbox_row_visible(m: &Message, alias: &str, hide_unsigned: bool) -> bool {
    if crate::local_state::is_archived(alias, m.id) || crate::local_state::is_deleted(alias, m.id) {
        return false;
    }
    if hide_unsigned && (!m.signature_valid || m.sender_vk.is_empty()) {
        return false;
    }
    true
}

fn folder_count(emails: &[Message], folder: menu::Folder, alias: &str) -> usize {
    // Only split Inbox/Quarantine counts when the user opted in; otherwise the
    // Quarantine folder is hidden and every row is an Inbox row.
    let quarantine_on = crate::local_state::global_settings()
        .inbox
        .quarantine_unknown;
    let hide_unsigned = crate::local_state::identity_settings_for(alias)
        .privacy
        .hide_unsigned;
    match folder {
        // Inbox/Quarantine badge = unread count, but only over rows that
        // survive the same archived/deleted/hide_unsigned exclusions the
        // list applies (#268). Search is intentionally NOT applied — the
        // badge reflects the folder, not the current search box.
        menu::Folder::Inbox => emails
            .iter()
            .filter(|m| !m.read)
            .filter(|m| is_inbox_row_visible(m, alias, hide_unsigned))
            .filter(|m| !quarantine_on || is_sender_verified(m))
            .count(),
        menu::Folder::Quarantine => emails
            .iter()
            .filter(|m| !m.read)
            .filter(|m| is_inbox_row_visible(m, alias, hide_unsigned))
            .filter(|m| quarantine_on && !is_sender_verified(m))
            .count(),
        menu::Folder::Drafts => crate::local_state::drafts_for(alias).len(),
        menu::Folder::Sent => crate::local_state::sent_for(alias).len(),
        menu::Folder::Archive => crate::local_state::archived_for(alias).len(),
    }
}

/// Build the visible Inbox/Quarantine message set for `folder`, applying the
/// same archived/deleted/hide-unsigned/quarantine-split filters the
/// `MessageList` render uses, then sorting newest-first. Shared by the list
/// (#270 grouping) and the detail pane (thread resolution) so the two agree
/// on the population a `root_id` is grouped against. `search` is applied only
/// when non-empty — the detail pane passes "" so an open thread isn't lost
/// when the search box changes.
fn visible_inbox_messages(
    emails: &[Message],
    alias: &str,
    folder: menu::Folder,
    search: &str,
) -> Vec<Message> {
    let inbox_settings = crate::local_state::global_settings().inbox;
    let hide_unsigned = crate::local_state::identity_settings_for(alias)
        .privacy
        .hide_unsigned;
    let mut v: Vec<Message> = emails
        .iter()
        .filter(|m| !crate::local_state::is_archived(alias, m.id))
        .filter(|m| !crate::local_state::is_deleted(alias, m.id))
        .filter(|m| matches_search(m, search))
        .filter(|m| {
            if !hide_unsigned {
                return true;
            }
            m.signature_valid && !m.sender_vk.is_empty()
        })
        .filter(|m| {
            if !inbox_settings.quarantine_unknown {
                return matches!(folder, menu::Folder::Inbox);
            }
            if matches!(folder, menu::Folder::Quarantine) {
                !is_sender_verified(m)
            } else {
                is_sender_verified(m)
            }
        })
        .cloned()
        .collect();
    v.sort_by(sort_cmp_inbox);
    v
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
    let font_size_attr = match appearance.font_size {
        ::mail_local_state::FontSize::Small => "small",
        ::mail_local_state::FontSize::Default => "default",
        ::mail_local_state::FontSize::Large => "large",
        ::mail_local_state::FontSize::Larger => "larger",
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
            "data-font-size": font_size_attr,
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
            if import_contact.read().open {
                login::ImportContactForm {}
            }
        }
    }
}

// Freenet logo, inlined (vendored in the WASM bundle, not hot-linked to
// freenet.org) so the offline/decentralized build has no clearnet dependency.
// Source: https://freenet.org/freenet_logo.svg
pub(crate) fn brand_logo() -> Element {
    rsx! {
        svg {
            class: "brand-logo",
            view_box: "0 0 640 471",
            xmlns: "http://www.w3.org/2000/svg",
            "aria-label": "Freenet",
            defs {
                linearGradient {
                    id: "freenetBrandGrad",
                    x1: "0%", y1: "50%", x2: "100%", y2: "50%",
                    stop { offset: "0%", "stop-color": "#7ecfef" }
                    stop { offset: "50%", "stop-color": "#007FFF" }
                    stop { offset: "100%", "stop-color": "#0052cc" }
                }
            }
            path {
                fill: "url(#freenetBrandGrad)",
                fill_rule: "evenodd",
                d: "M358.864 40.470 C 358.605 40.728,354.143 42.467,348.947 44.334 C 284.621 67.446,232.573 113.729,201.443 175.500 C 193.895 190.478,184.375 213.708,185.375 214.708 C 185.621 214.954,187.715 211.857,190.030 207.827 C 211.190 170.984,229.863 146.093,255.968 119.933 C 274.854 101.008,282.998 94.207,302.034 81.466 C 334.671 59.621,367.531 47.376,401.250 44.492 L 409.000 43.829 408.984 47.165 C 408.958 52.704,405.255 68.515,401.010 81.213 C 382.392 136.898,338.799 184.709,277.000 217.224 C 271.225 220.263,263.913 223.788,260.750 225.058 C 254.629 227.517,254.126 228.307,256.511 231.712 C 258.282 234.241,258.484 234.089,249.500 237.002 C 226.868 244.341,200.420 256.771,183.918 267.825 C 173.918 274.522,156.961 289.225,158.000 290.296 C 158.275 290.579,163.450 287.694,169.500 283.883 C 175.550 280.073,186.125 274.083,193.000 270.573 C 264.905 233.856,345.414 226.155,422.387 248.633 C 434.634 252.210,468.194 264.823,465.830 264.961 C 465.461 264.982,459.741 263.440,453.118 261.534 C 422.666 252.769,376.068 246.967,347.500 248.384 C 320.590 249.719,284.052 255.527,283.798 258.510 C 283.694 259.727,291.796 264.541,298.477 267.231 C 306.163 270.326,319.360 270.612,338.812 268.103 C 385.602 262.070,433.627 269.250,469.963 287.712 C 475.721 290.638,480.874 293.474,481.416 294.016 C 482.061 294.661,476.225 295.004,464.450 295.010 C 407.520 295.043,349.853 308.084,300.500 332.086 C 290.412 336.992,272.833 346.834,271.147 348.519 C 269.278 350.389,273.301 349.263,283.966 344.933 C 302.548 337.389,332.479 327.629,351.000 323.074 C 386.266 314.400,413.893 311.393,450.000 312.298 C 474.559 312.914,491.602 315.535,509.306 321.421 C 520.784 325.236,519.954 325.640,504.924 323.552 C 419.615 311.701,330.506 332.225,238.000 385.033 C 224.991 392.460,221.855 394.386,200.762 407.913 C 184.591 418.282,178.817 420.978,172.750 420.990 C 167.060 421.002,164.441 418.869,163.413 413.387 C 160.912 400.055,178.394 366.762,202.136 339.644 L 206.387 334.788 197.443 335.644 C 183.073 337.019,158.519 336.519,150.152 334.681 C 132.833 330.876,120.785 321.947,117.439 310.437 C 112.326 292.850,123.492 270.717,146.912 252.015 C 154.528 245.934,155.702 244.562,156.798 240.464 C 158.983 232.296,168.599 206.900,174.208 194.482 C 184.044 172.710,197.989 150.083,213.332 131.000 C 229.597 110.770,255.612 87.415,277.277 73.590 C 286.990 67.393,310.855 55.436,323.062 50.653 C 335.623 45.730,360.750 38.583,358.864 40.470 M375.000 209.596 C 430.712 216.655,477.541 237.609,509.241 269.661 C 514.049 274.523,518.765 279.625,519.721 281.000 C 521.404 283.419,521.347 283.408,517.980 280.669 C 500.484 266.434,486.556 257.516,468.000 248.668 C 452.323 241.193,438.766 236.261,424.000 232.663 C 395.297 225.667,374.955 223.024,349.705 223.010 C 333.212 223.000,332.865 222.956,330.455 220.545 C 329.105 219.195,328.000 217.046,328.000 215.768 C 328.000 212.845,330.558 209.125,333.357 207.978 C 336.189 206.817,360.536 207.763,375.000 209.596",
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
                {brand_logo()}
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
                    // Quarantine only appears once the user opts in via
                    // Settings > Inbox; until then there's no quarantine concept
                    // so an empty folder would just confuse.
                    let quarantine_on = crate::local_state::global_settings().inbox.quarantine_unknown;
                    let folders: Vec<menu::Folder> = if quarantine_on {
                        vec![
                            menu::Folder::Inbox,
                            menu::Folder::Quarantine,
                            menu::Folder::Sent,
                            menu::Folder::Drafts,
                            menu::Folder::Archive,
                        ]
                    } else {
                        vec![
                            menu::Folder::Inbox,
                            menu::Folder::Sent,
                            menu::Folder::Drafts,
                            menu::Folder::Archive,
                        ]
                    };
                    folders
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
            let alias = id.alias.to_string();
            let live: Vec<Message> = current_model
                .borrow()
                .messages
                .iter()
                .cloned()
                .map(Message::from)
                .collect();
            let kept = crate::local_state::kept_for(&alias);
            *emails = merge_inbox_list(
                live,
                kept,
                |id| crate::local_state::is_archived(&alias, id),
                |id| crate::local_state::is_read(&alias, id),
            );
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
    // #270: the open conversation's root id, so the grouped inbox row that
    // owns it can show as `selected`. Inbox/Quarantine rows always open as
    // threads now, so the per-message `selected_id` is no longer consulted
    // here (the single-message `OpenMessage` path is a DetailPanel fallback).
    let selected_thread_root = menu_selection.read().thread_root();
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
    // Inbox and Quarantine share every filter except the verified-sender
    // split; `visible_inbox_messages` applies them (and the search box) and
    // sorts newest-first (#49/#137). Shared with `DetailPanel` so the grouped
    // list and the thread it opens agree on the population (#270).
    let visible: Vec<Message> = if matches!(folder, menu::Folder::Inbox | menu::Folder::Quarantine)
    {
        visible_inbox_messages(&emails, &active_alias, folder, &search)
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
                                    // #270: carry the draft's persisted thread
                                    // linkage back into compose so reopening a
                                    // reply-draft stays in the same thread.
                                    thread_id: d.thread_id.clone(),
                                    in_reply_to: d.in_reply_to.clone(),
                                    quoted_excerpt: d.quoted_excerpt.clone(),
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
                                    // #270: carry the draft's persisted thread
                                    // linkage back into compose so reopening a
                                    // reply-draft stays in the same thread.
                                    thread_id: d.thread_id.clone(),
                                    in_reply_to: d.in_reply_to.clone(),
                                    quoted_excerpt: d.quoted_excerpt.clone(),
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
                        let in_quarantine = matches!(folder, menu::Folder::Quarantine);
                        let card_testid = if in_quarantine {
                            testid::FM_QUARANTINE_CARD
                        } else {
                            testid::FM_MSG_CARD
                        };
                        // #270: collapse back-and-forth conversations into one
                        // row per thread. `visible` is already filtered + sorted
                        // newest-first; group it, then order groups by their
                        // newest member descending so the list stays "newest
                        // conversation on top". A single-message thread renders
                        // like an ordinary row (count badge suppressed).
                        // When threading is disabled globally (Settings →
                        // Appearance), fall back to a flat one-row-per-message
                        // list via `group_flat` — `sort_cmp_group` still orders
                        // newest-first.
                        let threading_on =
                            crate::local_state::global_settings().inbox.threading_enabled;
                        let mut groups = if threading_on {
                            threads::group_into_threads(&visible)
                        } else {
                            threads::group_flat(&visible)
                        };
                        groups.sort_by(threads::sort_cmp_group);
                        groups.into_iter().map(move |group| {
                            // Newest member drives the row's sender / time /
                            // preview; subject is the conversation's normalized
                            // base subject (without the Re:/Fwd: churn).
                            let newest = group.messages.last().cloned().unwrap_or_else(|| group.messages[0].clone());
                            let root_id = group.root_id;
                            let count = group.count;
                            let unread = group.unread_count > 0;
                            // Distinct senders across the conversation, newest
                            // first, for the row's sender label.
                            let mut seen = std::collections::HashSet::new();
                            let mut senders: Vec<String> = Vec::new();
                            for m in group.messages.iter().rev() {
                                let name = m.from.to_string();
                                if seen.insert(name.clone()) {
                                    senders.push(name);
                                }
                            }
                            let sender_label = if senders.len() > 1 {
                                format!("{} +{}", senders[0], senders.len() - 1)
                            } else {
                                senders.first().cloned().unwrap_or_default()
                            };
                            let subj = newest.title.clone();
                            let preview = newest.content.clone();
                            let time_short = format_time_short(newest.time);
                            // The .ft-thread-group row mirrors .msg-card so a
                            // conversation and a single-message row sit flush in
                            // the list; the .ft-count badge is the only addition
                            // and is suppressed for one-message threads.
                            let mut classes = String::from("ft-thread-group");
                            if unread { classes.push_str(" unread"); }
                            if Some(root_id) == selected_thread_root { classes.push_str(" selected"); }
                            rsx! {
                                article {
                                    class: "{classes}",
                                    id: "email-inbox-accessor-{root_id}",
                                    "data-testid": testid::FM_THREAD_GROUP,
                                    "data-msg-card-testid": "{card_testid}",
                                    "data-msg-id": "{root_id}",
                                    "data-thread-count": "{count}",
                                    onclick: move |_| { menu_selection.write().open_thread(root_id); },
                                    div { class: "ft-group-row1",
                                        span { class: "ft-group-people", "{sender_label}" }
                                        if in_quarantine {
                                            span { class: "badge badge-failed", "unverified" }
                                        }
                                        span {
                                            class: "ft-group-time",
                                            "data-testid": testid::FM_MSG_TIME,
                                            "{time_short}"
                                        }
                                    }
                                    div { class: "ft-group-subjwrap",
                                        div { class: "ft-group-subj", "{subj}" }
                                        if count > 1 {
                                            span { class: "ft-count", "{count}" }
                                        }
                                    }
                                    div { class: "ft-group-prev", "{preview}" }
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
    let selected_thread_root = menu_selection.read().thread_root();
    let selected_sent_id = menu_selection.read().sent_id().map(str::to_string);
    let selected_archived_id = menu_selection.read().archived_id();
    // Subscribe to address-book mutations so re-grouping picks up freshly
    // imported contacts (verification can move a sender Inbox↔Quarantine).
    let ab_gen_ctx = use_context::<AddressBookGen>();
    let _ab_gen = ab_gen_ctx.0.read();
    let view = inbox.read();
    let emails = view.messages.borrow();
    let selected = selected_id.and_then(|id| emails.iter().find(|m| m.id == id).cloned());
    let _local_gen = crate::local_state::GENERATION();

    // Quarantine rows are ordinary inbox Messages keyed by id, so they open
    // through the same OpenMessage path as the Inbox.
    if matches!(folder, menu::Folder::Inbox | menu::Folder::Quarantine) {
        // #270: a conversation was opened from the grouped list — render the
        // whole thread (Nested or Compact per the inbox setting). Resolve the
        // group by `root_id` over the same filtered population the list builds
        // so the row and the detail agree.
        if let Some(root_id) = selected_thread_root {
            let active_alias = user
                .read()
                .logged_id()
                .map(|id| id.alias.to_string())
                .unwrap_or_default();
            let pop = visible_inbox_messages(&emails, &active_alias, folder, "");
            let group = threads::group_into_threads(&pop)
                .into_iter()
                .find(|g| g.root_id == root_id);
            return match group {
                Some(group) => rsx! { ThreadDetail { group } },
                // The conversation evaporated (every member archived/deleted
                // while it was open) — fall back to the empty hint.
                None => rsx! {
                    section { class: "detail-col",
                        div { class: "empty",
                            div { class: "empty-glyph", "✉" }
                            div { class: "empty-hint", "Select a message" }
                        }
                    }
                },
            };
        }
        if let Some(msg) = selected {
            // Single message opened directly (e.g. via deep-link / search
            // result) — keep the existing single-message detail.
            rsx! { OpenMessage { msg } }
        } else {
            let hint = if matches!(folder, menu::Folder::Quarantine) {
                "Select a quarantined message"
            } else {
                "Select a message"
            };
            rsx! {
                section { class: "detail-col",
                    div { class: "empty",
                        div { class: "empty-glyph", "✉" }
                        div { class: "empty-hint", "{hint}" }
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

/// #270: the specific parent line surfaced as the reply's collapsible
/// "in reply to" chip (`ComposePrefill.quoted_excerpt`). Replaces the old
/// "> "-prefixed plain-text quote-body hack — replies now start with an
/// empty body and carry the structured excerpt instead. Returns the first
/// non-empty line of the parent body trimmed; `None` for an empty body.
fn reply_excerpt(body: &str) -> Option<String> {
    body.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(str::to_string)
}

/// #270: map a message's three-valued verification to the `.ft-pill` class
/// suffix + label used in the threaded views. Mirrors the `verif-badge`
/// mapping in `OpenMessage` but in the compact pill vocabulary the design
/// uses (`known` / `unknown` / `unsigned`).
fn thread_pill(m: &Message) -> (&'static str, &'static str) {
    use crate::inbox::VerificationState;
    match m.verification_state() {
        VerificationState::VerifiedKnown => ("ft-pill known", "verified"),
        VerificationState::VerifiedUnknown => ("ft-pill unknown", "signed"),
        VerificationState::Unverified => ("ft-pill unsigned", "unsigned"),
    }
}

/// #270: build the reply prefill for continuing a conversation from a
/// specific message in the thread. Mints a fresh `thread_id` only when the
/// parent lacks one (legacy), links `in_reply_to` to the parent, and carries
/// the parent's first body line as the structured `quoted_excerpt`.
fn thread_reply_prefill(m: &Message) -> menu::ComposePrefill {
    menu::ComposePrefill {
        to: m.from.to_string(),
        subject: format!("Re: {}", m.title),
        body: String::new(),
        draft_id: None,
        thread_id: Some(
            m.thread_id
                .clone()
                .unwrap_or_else(crate::local_state::new_thread_id),
        ),
        in_reply_to: Some(m.id.to_string()),
        quoted_excerpt: reply_excerpt(&m.content),
    }
}

/// #270: the threaded detail pane. Renders an entire `ThreadGroup` as either
/// the Nested indentation tree or the Compact accordion, chosen by the
/// Settings → Inbox `thread_view` preference. Opening a thread marks all of
/// its messages read (same persistence path as `OpenMessage`, applied to the
/// whole set). The bottom reply dock continues the conversation from the
/// newest message.
#[component]
fn ThreadDetail(group: crate::app::threads::ThreadGroup) -> Element {
    let mut menu_selection = use_context::<Signal<menu::MenuSelection>>();
    let client = crate::api::WEB_API_SENDER.get().unwrap();
    let mut inbox = use_context::<Signal<InboxView>>();
    let inbox_data = use_context::<InboxesData>();
    let user = use_context::<Signal<User>>();
    // Re-render the badges when the address book changes (#134).
    let ab_gen_ctx = use_context::<AddressBookGen>();
    let _ab_gen = ab_gen_ctx.0.read();

    let thread_view = crate::local_state::global_settings().inbox.thread_view;

    // Mark every message in the conversation read — opening a thread reads it
    // (#270). Mirrors the single-message path in `OpenMessage`: flip the
    // in-memory flag AND persist a kept snapshot + delegate write per unread
    // member.
    let unread_ids: Vec<u64> = group
        .messages
        .iter()
        .filter(|m| !m.read)
        .map(|m| m.id)
        .collect();
    if !unread_ids.is_empty() {
        let result = inbox
            .write()
            .mark_as_read(client.clone(), &unread_ids, inbox_data)
            .unwrap();
        DELAYED_ACTIONS.with(|queue| {
            queue.borrow_mut().push(result);
        });
        let alias = user
            .read()
            .logged_id()
            .map(|id| id.alias.to_string())
            .unwrap_or_default();
        if !alias.is_empty() {
            for m in group.messages.iter().filter(|m| !m.read) {
                let kept = mail_local_state::KeptMessage {
                    from: m.from.to_string(),
                    title: m.title.to_string(),
                    content: m.content.to_string(),
                    kept_at: chrono::Utc::now().timestamp_millis(),
                    sent_at: Some(m.time.timestamp_millis()),
                    sender_vk: m.sender_vk.clone(),
                    signature_valid: m.signature_valid,
                };
                crate::local_state::local_mark_read(&alias, m.id, kept.clone());
                #[cfg(feature = "use-node")]
                {
                    let mut client_clone = client.clone();
                    let alias_for_send = alias.clone();
                    let mid = m.id;
                    // spawn_forever: opening a message then immediately
                    // navigating away (archive/delete/back) unmounts this
                    // view; a bare spawn() would cancel the MarkRead delegate
                    // write, so the message resurfaced as unread on reload
                    // (#286 read-state variant).
                    let _task = dioxus_core::spawn_forever(async move {
                        if let Err(e) = crate::local_state::mark_read(
                            &mut client_clone,
                            alias_for_send,
                            mid,
                            kept,
                        )
                        .await
                        {
                            crate::log::local_state_failure("mark thread message read", e);
                        }
                    });
                }
            }
        }
    }

    // Header: normalized subject, facepile of distinct senders, meta line.
    let newest = group
        .messages
        .last()
        .cloned()
        .unwrap_or_else(|| group.messages[0].clone());
    let subject = newest.title.clone();
    let msg_count = group.count;
    let mut seen = std::collections::HashSet::new();
    let mut participants: Vec<String> = Vec::new();
    for m in &group.messages {
        let name = m.from.to_string();
        if seen.insert(name.clone()) {
            participants.push(name);
        }
    }
    let participant_count = participants.len();
    // Up to four avatars in the facepile; the rest fold into the count.
    let facepile: Vec<String> = participants
        .iter()
        .take(4)
        .map(|p| p.chars().next().unwrap_or('·').to_string())
        .collect();

    // Reply continues from the newest message in the conversation.
    let reply_prefill = thread_reply_prefill(&newest);

    rsx! {
        section { class: "detail-col",
            div {
                class: "ft-thread-container",
                "data-testid": testid::FM_THREAD_CONTAINER,
                "data-thread-view": match thread_view {
                    mail_local_state::ThreadView::Nested => "nested",
                    mail_local_state::ThreadView::Compact => "compact",
                },
                div { class: "ft-head",
                    div { class: "ft-subj", "{subject}" }
                    div { class: "ft-subj-meta",
                        span { class: "ft-facepile",
                            {facepile.into_iter().map(|initial| rsx! {
                                span { class: "ft-face sm", "{initial}" }
                            })}
                        }
                        span { "{msg_count} messages" }
                        span { "·" }
                        span { "{participant_count} participants" }
                    }
                }
                div { class: "detail-scroll",
                    match thread_view {
                        mail_local_state::ThreadView::Nested => rsx! { ThreadNested { group: group.clone() } },
                        mail_local_state::ThreadView::Compact => rsx! { ThreadCompact { group: group.clone() } },
                    }
                }
                div { class: "toolbar",
                    div { class: "spacer" }
                    button {
                        class: "btn btn-primary",
                        "data-testid": testid::FM_REPLY,
                        onclick: move |_| {
                            menu_selection.write().open_draft(reply_prefill.clone());
                        },
                        "Reply"
                    }
                }
            }
        }
    }
}

/// #270 BLOCKER-1: per-message action cluster shared by the Nested and Compact
/// threaded views. Restores the affordances the old single-message
/// `OpenMessage` carried — Reply, Archive, Delete, and (only for a
/// verified-but-unknown sender) Add-to-address-book — onto every row of a
/// thread, routing through the same shared `archive_message` /
/// `delete_message` / `add_sender_to_address_book` helpers `OpenMessage` now
/// uses so behavior can't drift.
///
/// The buttons reuse the existing `FM_REPLY` / `FM_ARCHIVE` / `FM_DELETE` /
/// `FM_ADD_TO_AB` testids; they repeat once per row, so a Playwright spec
/// targets a specific message's actions by first scoping to the row via its
/// `data-msg-id` on the enclosing `FM_THREAD_ROW`, then the action testid
/// within (e.g. `row.getByTestId(testids.fmArchive)`).
///
/// `thread_total` is the conversation's current member count; after an
/// archive/delete the helper stays in the thread while `thread_total - 1 > 0`
/// and otherwise returns to the inbox list.
#[component]
fn ThreadRowActions(msg: Message, root_id: u64, thread_total: usize) -> Element {
    let menu_selection = use_context::<Signal<menu::MenuSelection>>();
    let client = crate::api::WEB_API_SENDER.get().unwrap();
    let inbox = use_context::<Signal<InboxView>>();
    let inbox_data = use_context::<InboxesData>();
    let import_contact = use_context::<Signal<crate::app::login::ImportContact>>();
    let user = use_context::<Signal<User>>();
    let alias = user
        .read()
        .logged_id()
        .map(|id| id.alias.to_string())
        .unwrap_or_default();

    let id = msg.id;
    let reply_prefill = thread_reply_prefill(&msg);
    let show_add_to_ab = matches!(
        msg.verification_state(),
        crate::inbox::VerificationState::VerifiedUnknown
    );
    let add_to_ab_vk = msg.sender_vk.clone();
    let add_to_ab_from = msg.from.to_string(); // #289: sender display name → modal nickname default
    // After removing this row the thread keeps `thread_total - 1` members.
    let remaining = thread_total.saturating_sub(1);
    let post = PostMessageAction::LeaveThread {
        root_id,
        removed_id: id,
        remaining,
    };

    let archive_client = client.clone();
    let archive_alias = alias.clone();
    let archive_msg = msg.clone();
    let delete_client = client.clone();
    let delete_alias = alias.clone();

    let mut menu_for_reply = menu_selection;

    // Returns just the buttons (a fragment); each view wraps them in its own
    // positioning container (`.ft-nest-actions` hover cluster in Nested, the
    // `.ft-cz-actions` footer row in Compact).
    rsx! {
        button {
            class: "ft-act",
            "data-testid": testid::FM_REPLY,
            title: "Reply",
            onclick: move |_| {
                menu_for_reply.write().open_draft(reply_prefill.clone());
            },
            "Reply"
        }
        if show_add_to_ab {
            button {
                class: "ft-act",
                "data-testid": testid::FM_ADD_TO_AB,
                title: "Add sender to address book",
                onclick: move |_| {
                    add_sender_to_address_book(import_contact, &add_to_ab_vk, &add_to_ab_from);
                },
                "Add to address book"
            }
        }
        button {
            class: "ft-act",
            "data-testid": testid::FM_ARCHIVE,
            title: "Archive",
            onclick: move |_| {
                archive_message(
                    inbox,
                    menu_selection,
                    archive_client.clone(),
                    inbox_data,
                    &archive_alias,
                    &archive_msg,
                    post,
                );
            },
            "Archive"
        }
        button {
            class: "ft-act",
            "data-testid": testid::FM_DELETE,
            title: "Delete",
            onclick: move |_| {
                delete_message(
                    inbox,
                    menu_selection,
                    delete_client.clone(),
                    inbox_data,
                    &delete_alias,
                    id,
                    post,
                );
            },
            "Delete"
        }
    }
}

/// #270 Nested view: indentation tree. Depth comes from the `in_reply_to`
/// chain (`threads::depth_map`, capped at `MAX_THREAD_DEPTH`); connector
/// rails + per-depth margins are pure CSS (`.ft-nest-msg.depth-N`). Each
/// message carries a collapsible "in reply to" quote chip when it has a
/// `quoted_excerpt`. Default expansion: the leaf of each branch (a message
/// that is no one's parent) is expanded; interior nodes collapse. Any node
/// can be toggled.
#[component]
fn ThreadNested(group: crate::app::threads::ThreadGroup) -> Element {
    let depths = threads::depth_map(&group);
    // A message is a leaf if no other message replies to it. Leaves default
    // to expanded (#270).
    let has_child: std::collections::HashSet<String> = group
        .messages
        .iter()
        .filter_map(|m| m.in_reply_to.clone())
        .collect();
    let active_alias = use_context::<Signal<User>>()
        .read()
        .logged_id()
        .map(|id| id.alias.to_string())
        .unwrap_or_default();

    // Per-message body + quote expansion state, keyed by message id. Seeded so
    // leaves are expanded; interior nodes collapsed.
    let init_open: std::collections::HashMap<u64, bool> = group
        .messages
        .iter()
        .map(|m| (m.id, !has_child.contains(&m.id.to_string())))
        .collect();
    let open = use_signal(|| init_open);
    let quote_open = use_signal(std::collections::HashMap::<u64, bool>::new);

    let root_id = group.root_id;
    let thread_total = group.count;
    let messages = group.messages;
    rsx! {
        div { class: "ft-nest",
            {messages.into_iter().map(move |m| {
                let id = m.id;
                let depth = depths.get(&id).copied().unwrap_or(0);
                let is_me = m.from.as_ref() == active_alias && !active_alias.is_empty();
                let mut classes = format!("ft-nest-msg depth-{depth}");
                if is_me { classes.push_str(" is-me"); }
                let (pill_class, pill_label) = thread_pill(&m);
                let from = m.from.clone();
                let from_initial = from.chars().next().unwrap_or('·').to_string();
                let time_short = format_time_short(m.time);
                let quote = m.quoted_excerpt.clone();
                let content = m.content.clone();
                let body_open = open.read().get(&id).copied().unwrap_or(true);
                let q_open = quote_open.read().get(&id).copied().unwrap_or(false);
                let mut open_sig = open;
                let mut quote_sig = quote_open;
                let actions_msg = m.clone();
                rsx! {
                    div {
                        class: "{classes}",
                        "data-testid": testid::FM_THREAD_ROW,
                        "data-msg-id": "{id}",
                        div { class: "ft-nest-inner",
                            div { class: "ft-nest-actions",
                                ThreadRowActions {
                                    msg: actions_msg,
                                    root_id,
                                    thread_total,
                                }
                            }
                            div { class: "ft-msg-head",
                                div { class: "ft-face sm", "{from_initial}" }
                                div { class: "ft-msg-id",
                                    div { class: "ft-msg-namerow",
                                        span { class: "ft-msg-name", "{from}" }
                                        span { class: "{pill_class}", "{pill_label}" }
                                    }
                                }
                                span {
                                    class: "ft-msg-time",
                                    style: "cursor:pointer",
                                    "data-testid": testid::FM_THREAD_EXPAND,
                                    onclick: move |_| {
                                        let cur = open_sig.read().get(&id).copied().unwrap_or(true);
                                        open_sig.write().insert(id, !cur);
                                    },
                                    "{time_short}"
                                }
                            }
                            if let Some(q) = quote {
                                div { class: "ft-quote",
                                    button {
                                        class: "ft-quote-toggle",
                                        onclick: move |_| {
                                            let cur = quote_sig.read().get(&id).copied().unwrap_or(false);
                                            quote_sig.write().insert(id, !cur);
                                        },
                                        span {
                                            class: if q_open { "ft-caret open" } else { "ft-caret" },
                                            "›"
                                        }
                                        if q_open { "hide quoted" } else { "in reply to" }
                                    }
                                    if q_open {
                                        div { class: "ft-quote-text", "“{q}”" }
                                    }
                                }
                            }
                            if body_open {
                                div { class: "ft-body-text", style: "margin-top:10px",
                                    {content.split("\n\n").map(|para| rsx! { p { "{para}" } })}
                                }
                            }
                        }
                    }
                }
            })}
        }
    }
}

/// #270 Compact view: power-user accordion. One tight row per message
/// (caret, avatar, name, snippet, key-pill, time). Default expansion: the
/// newest message only. Click a row to toggle; the expanded row reveals the
/// body and a `.ft-cz-tokenline` footer (sender + signature scheme).
#[component]
fn ThreadCompact(group: crate::app::threads::ThreadGroup) -> Element {
    let newest_id = group.messages.last().map(|m| m.id).unwrap_or(0);
    let init_open: std::collections::HashMap<u64, bool> = group
        .messages
        .iter()
        .map(|m| (m.id, m.id == newest_id))
        .collect();
    let open = use_signal(|| init_open);

    let root_id = group.root_id;
    let thread_total = group.count;
    let messages = group.messages;
    rsx! {
        div { class: "ft-compact",
            {messages.into_iter().map(move |m| {
                let id = m.id;
                let is_open = open.read().get(&id).copied().unwrap_or(false);
                let (pill_class, pill_label) = thread_pill(&m);
                let from = m.from.clone();
                let from_initial = from.chars().next().unwrap_or('·').to_string();
                let time_short = format_time_short(m.time);
                let snippet = reply_excerpt(&m.content).unwrap_or_default();
                let content = m.content.clone();
                let actions_msg = m.clone();
                // Sender fingerprint short-form for the token footer line.
                let footer_id = if m.sender_vk.is_empty() {
                    "unsigned".to_string()
                } else {
                    let words = address_book::fingerprint_words(&m.sender_vk, &m.sender_vk);
                    format!("{}-{}-{}", words[0], words[1], words[2])
                };
                let mut row_classes = String::from("ft-cz-row");
                if is_open { row_classes.push_str(" is-open"); }
                if !m.read { row_classes.push_str(" unread"); }
                let mut open_sig = open;
                rsx! {
                    div {
                        class: "ft-cz-msg",
                        "data-testid": testid::FM_THREAD_ROW,
                        "data-msg-id": "{id}",
                        button {
                            class: "{row_classes}",
                            "data-testid": testid::FM_THREAD_EXPAND,
                            onclick: move |_| {
                                let cur = open_sig.read().get(&id).copied().unwrap_or(false);
                                open_sig.write().insert(id, !cur);
                            },
                            span {
                                class: if is_open { "ft-caret open" } else { "ft-caret" },
                                "›"
                            }
                            span { class: "ft-face sm", "{from_initial}" }
                            span { class: "ft-cz-name", "{from}" }
                            if !is_open {
                                span { class: "ft-cz-snippet", "{snippet}" }
                            }
                            span { class: "ft-cz-meta",
                                span { class: "{pill_class}", "{pill_label}" }
                                span { "{time_short}" }
                            }
                        }
                        if is_open {
                            div { class: "ft-cz-open",
                                div { class: "ft-body-text",
                                    {content.split("\n\n").map(|para| rsx! { p { "{para}" } })}
                                }
                                div { class: "ft-cz-tokenline",
                                    span { "{footer_id}" }
                                    span { class: "ft-dot" }
                                    span { "ml-dsa-65" }
                                }
                                div { class: "ft-cz-actions",
                                    ThreadRowActions {
                                        msg: actions_msg,
                                        root_id,
                                        thread_total,
                                    }
                                }
                            }
                        }
                    }
                }
            })}
        }
    }
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
    // #270: reply continues the thread. Carry the parent's thread_id
    // (minting a fresh one for legacy rows that predate threading), the
    // parent message id, and the parent's first body line as the excerpt.
    let reply_thread_id = Some(
        msg.thread_id
            .clone()
            .unwrap_or_else(crate::local_state::new_thread_id),
    );
    let reply_in_reply_to = Some(msg_id.to_string());
    let reply_excerpt = reply_excerpt(&content);
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
                        menu_selection.write().open_draft(menu::ComposePrefill {
                            to: reply_to.to_string(),
                            subject: reply_subj.clone(),
                            // #270: fresh body; the parent line rides along as
                            // the structured quoted_excerpt instead.
                            body: String::new(),
                            draft_id: None,
                            thread_id: reply_thread_id.clone(),
                            in_reply_to: reply_in_reply_to.clone(),
                            quoted_excerpt: reply_excerpt.clone(),
                        });
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
                                // spawn_forever: at_inbox_list() below
                                // navigates away and unmounts this view, which
                                // would cancel a bare spawn() before the
                                // DeleteMessage delegate write committed —
                                // message returns after reload (#286).
                                let _task = dioxus_core::spawn_forever(async move {
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

    // #270: reply continues the conversation this sent message belonged to,
    // minting a thread id for legacy rows that predate threading. The sent
    // row has no numeric inbox id, so `in_reply_to` stays None (it isn't a
    // node in the recipient's inbox tree); the parent's first line rides as
    // the structured excerpt and the body starts fresh.
    let reply_thread_id = Some(
        msg.thread_id
            .clone()
            .unwrap_or_else(crate::local_state::new_thread_id),
    );
    let reply_excerpt = reply_excerpt(&body);
    // Reply: same recipient, "Re: <subject>", thread continues.
    let reply_prefill = menu::ComposePrefill {
        to: to.clone(),
        subject: format!("Re: {subject}"),
        body: String::new(),
        draft_id: None,
        thread_id: reply_thread_id,
        in_reply_to: None,
        quoted_excerpt: reply_excerpt,
    };
    // Forward: blank recipient, "Fwd: <subject>". A forward starts a NEW
    // conversation (#270) — no thread_id, no in_reply_to. The original body
    // is kept verbatim so the forwarder can frame it.
    let forward_prefill = menu::ComposePrefill {
        to: String::new(),
        subject: format!("Fwd: {subject}"),
        body: body.clone(),
        draft_id: None,
        thread_id: None,
        in_reply_to: None,
        quoted_excerpt: None,
    };
    // Resend: identical fields, fresh draft id (a new send → new Sent row).
    let resend_prefill = menu::ComposePrefill {
        to: to.clone(),
        subject: subject.clone(),
        body: body.clone(),
        draft_id: None,
        thread_id: None,
        in_reply_to: None,
        quoted_excerpt: None,
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

/// Where to navigate after a per-message archive / delete (#270 BLOCKER-1).
///
/// `OpenMessage` (single-message detail) always returns to the inbox list.
/// The threaded views stay inside the open thread as long as it still has
/// members AND the removed message wasn't the thread root — `DetailPanel`
/// resolves the open thread by `root_id`, and removing the root message
/// shifts the surviving group's `root_id` to the next-oldest member, so a
/// re-open of the stale `root_id` would resolve to nothing. In that case we
/// fall back to the inbox list rather than stranding the user on an empty
/// detail pane.
#[derive(Clone, Copy)]
enum PostMessageAction {
    /// Single-message detail: always go back to the inbox list.
    ToInboxList,
    /// Thread row. `root_id` is the thread's current root, `removed_id` the
    /// message being archived/deleted, `remaining` the member count after
    /// removal. Stay in the thread only when members remain AND the root
    /// survives; otherwise return to the inbox list.
    LeaveThread {
        root_id: u64,
        removed_id: u64,
        remaining: usize,
    },
}

impl PostMessageAction {
    /// Apply the navigation to `menu_selection` after the inbox mutation.
    fn apply(self, menu_selection: &mut Signal<menu::MenuSelection>) {
        match self {
            PostMessageAction::ToInboxList => {
                menu_selection.write().at_inbox_list();
            }
            PostMessageAction::LeaveThread {
                root_id,
                removed_id,
                remaining,
            } => {
                if remaining == 0 || removed_id == root_id {
                    menu_selection.write().at_inbox_list();
                } else {
                    // Re-open the (now smaller) thread so the detail pane
                    // re-resolves the group and re-renders without the removed
                    // row. `open_thread` is idempotent on the same root_id.
                    menu_selection.write().open_thread(root_id);
                }
            }
        }
    }
}

/// Shared Archive logic (#270 BLOCKER-1): stash a local copy of the message in
/// mail-local-state (preserving threading metadata so a later Reply continues
/// the conversation), then remove it from the inbox contract. Used by both the
/// single-message `OpenMessage` toolbar and the per-message action clusters in
/// the threaded views, so the behavior can't drift between them.
#[allow(clippy::too_many_arguments)]
fn archive_message(
    mut inbox: Signal<InboxView>,
    mut menu_selection: Signal<menu::MenuSelection>,
    client: WebApiRequestClient,
    inbox_data: InboxesData,
    alias: &str,
    msg: &Message,
    post: PostMessageAction,
) {
    let id = msg.id;
    let archived = mail_local_state::ArchivedMessage {
        from: msg.from.to_string(),
        title: msg.title.to_string(),
        content: msg.content.to_string(),
        archived_at: chrono::Utc::now().timestamp_millis(),
        thread_id: msg.thread_id.clone(),
        in_reply_to: msg.in_reply_to.clone(),
        quoted_excerpt: msg.quoted_excerpt.clone(),
    };
    if !alias.is_empty() {
        crate::local_state::local_archive_message(alias, id, archived.clone());
        #[cfg(feature = "use-node")]
        {
            let mut c = client.clone();
            let a = alias.to_string();
            let ar = archived.clone();
            // spawn_forever: the caller runs post.apply() right after this,
            // navigating away and unmounting the view. A bare spawn() would
            // cancel the ArchiveMessage delegate write on unmount, so the
            // archived message bounced back to the Inbox after reload (#286).
            let _task = dioxus_core::spawn_forever(async move {
                if let Err(e) = crate::local_state::archive_message(&mut c, a, id, ar).await {
                    crate::log::local_state_failure("archive message", e);
                }
            });
        }
    }
    let result = inbox
        .write()
        .remove_messages(client, &[id], inbox_data)
        .unwrap();
    DELAYED_ACTIONS.with(|queue| {
        queue.borrow_mut().push(result);
    });
    post.apply(&mut menu_selection);
    crate::toast::push_toast("Archived", crate::toast::ToastLevel::Success);
}

/// Shared Delete logic (#270 BLOCKER-1): drop any local kept/archived copies
/// AND remove the message from the inbox contract — distinct from Archive
/// because it leaves no trace. Shared between `OpenMessage` and the threaded
/// per-message action clusters.
fn delete_message(
    mut inbox: Signal<InboxView>,
    mut menu_selection: Signal<menu::MenuSelection>,
    client: WebApiRequestClient,
    inbox_data: InboxesData,
    alias: &str,
    id: u64,
    post: PostMessageAction,
) {
    if !alias.is_empty() {
        crate::local_state::local_delete_message(alias, id);
        #[cfg(feature = "use-node")]
        {
            let mut c = client.clone();
            let a = alias.to_string();
            // spawn_forever: the caller runs post.apply() right after this,
            // which navigates away and unmounts the message view. A bare
            // spawn() would cancel the DeleteMessage delegate write on
            // unmount, so the deletion never committed to the node and the
            // message returned after reload (#286).
            let _task = dioxus_core::spawn_forever(async move {
                if let Err(e) = crate::local_state::delete_message(&mut c, a, id).await {
                    crate::log::error(format!("delete_message failed: {e}"), None);
                }
            });
        }
    }
    let result = inbox
        .write()
        .remove_messages(client, &[id], inbox_data)
        .unwrap();
    DELAYED_ACTIONS.with(|queue| {
        queue.borrow_mut().push(result);
    });
    post.apply(&mut menu_selection);
    crate::toast::push_toast("Deleted", crate::toast::ToastLevel::Success);
}

/// Shared Add-to-address-book logic (#270 BLOCKER-1): derive the sender's bs58
/// inbox address from their `sender_vk` and open the import modal pre-seeded
/// with it (#272). Shared between `OpenMessage` and the threaded per-message
/// clusters. Only meaningful when the sender is verified-but-unknown — callers
/// gate on `VerificationState::VerifiedUnknown` before exposing the affordance.
fn add_sender_to_address_book(
    mut import_contact: Signal<crate::app::login::ImportContact>,
    sender_vk: &[u8],
    sender_from: &str,
) {
    // #289: thread the sender's display name (`Message.from`) into the modal
    // so the nickname defaults to it and is persisted as `suggested_alias`.
    // Blank/whitespace-only display names contribute no suggestion.
    let alias = {
        let trimmed = sender_from.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    };
    match crate::inbox::inbox_address_bs58_from_vk_bytes(sender_vk) {
        Ok(addr) => {
            *import_contact.write() =
                crate::app::login::ImportContact::opened_with(addr, alias);
        }
        Err(e) => {
            crate::toast::push_toast(
                format!("Could not derive sender address: {e}"),
                crate::toast::ToastLevel::Error,
            );
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
    let import_contact = use_context::<Signal<crate::app::login::ImportContact>>();
    let email_id = [msg.id];

    let result = inbox
        .write()
        .mark_as_read(client.clone(), &email_id, inbox_data)
        .unwrap();
    DELAYED_ACTIONS.with(|queue| {
        queue.borrow_mut().push(result);
    });

    // Persist read flag + a local snapshot of the message in the
    // mail-local-state delegate (issue #47/47a). Read mail stays in the
    // inbox contract — `mark_as_read` only flips the in-memory flag — so
    // this is the durable record of "user has read this". The local
    // snapshot also lets the UI keep showing the message if the contract
    // ever does evict it (e.g. via an explicit Archive/Delete).
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
                // spawn_forever: same as the group-open path — navigating
                // away right after opening unmounts this view and a bare
                // spawn() would cancel the MarkRead write, resurfacing the
                // message as unread on reload (#286 read-state variant).
                let _task = dioxus_core::spawn_forever(async move {
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
    // #270: reply continues this message's thread (minting a fresh thread id
    // for legacy messages without one), links to this message via
    // `in_reply_to`, and carries the parent's first line as the structured
    // quoted_excerpt. The body starts fresh — the old "> "-prefix quote hack
    // is gone.
    let reply_thread_id = Some(
        msg.thread_id
            .clone()
            .unwrap_or_else(crate::local_state::new_thread_id),
    );
    let reply_in_reply_to = Some(id.to_string());
    let reply_excerpt = reply_excerpt(&content);
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
    let add_to_ab_vk = msg.sender_vk.clone();
    let add_to_ab_from = msg.from.to_string(); // #289: sender display name → modal nickname default

    let active_alias = user
        .read()
        .logged_id()
        .map(|id| id.alias.to_string())
        .unwrap_or_default();
    // #270 BLOCKER-1: the single-message detail's Archive / Delete reuse the
    // shared `archive_message` / `delete_message` helpers (same code the
    // threaded per-message rows call). A clone of the message carries the
    // threading metadata into the helper so a reply launched from Archive
    // continues the conversation.
    let archive_client = client.clone();
    let archive_msg = msg.clone();
    let archive_alias = active_alias.clone();
    let delete_client = client.clone();
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
                            add_sender_to_address_book(import_contact, &add_to_ab_vk, &add_to_ab_from);
                        },
                        "Add to address book"
                    }
                }
                button {
                    class: "btn btn-primary",
                    "data-testid": testid::FM_REPLY,
                    onclick: move |_| {
                        menu_selection.write().open_draft(menu::ComposePrefill {
                            to: reply_to.to_string(),
                            subject: reply_subj.clone(),
                            body: String::new(),
                            draft_id: None,
                            thread_id: reply_thread_id.clone(),
                            in_reply_to: reply_in_reply_to.clone(),
                            quoted_excerpt: reply_excerpt.clone(),
                        });
                    },
                    "Reply"
                }
                button {
                    class: "btn btn-secondary",
                    "data-testid": testid::FM_ARCHIVE,
                    onclick: move |_| {
                        archive_message(
                            inbox,
                            menu_selection,
                            archive_client.clone(),
                            inbox_data,
                            &archive_alias,
                            &archive_msg,
                            PostMessageAction::ToInboxList,
                        );
                    },
                    "Archive"
                }
                button {
                    class: "btn btn-secondary",
                    "data-testid": testid::FM_DELETE,
                    onclick: move |_| {
                        delete_message(
                            inbox,
                            menu_selection,
                            delete_client.clone(),
                            inbox_data,
                            &delete_alias,
                            id,
                            PostMessageAction::ToInboxList,
                        );
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
    // #270: threading linkage carried from the reply/forward prefill into
    // the compose form's signals so it survives onto the wire `send_message`
    // + the local Sent snapshot. None for a brand-new compose.
    let initial_thread_id = prefill.as_ref().and_then(|p| p.thread_id.clone());
    let initial_in_reply_to = prefill.as_ref().and_then(|p| p.in_reply_to.clone());
    let initial_quoted_excerpt = prefill.as_ref().and_then(|p| p.quoted_excerpt.clone());

    let mut to = use_signal(|| initial_to.clone());
    let mut title = use_signal(|| initial_subj.clone());
    let mut content = use_signal(|| initial_body.clone());
    let draft_id = use_signal(|| initial_draft_id.clone());
    let thread_id = use_signal(|| initial_thread_id.clone());
    let in_reply_to = use_signal(|| initial_in_reply_to.clone());
    let quoted_excerpt = use_signal(|| initial_quoted_excerpt.clone());
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
        // #270: persist the conversation linkage so a reply that's autosaved
        // and reopened keeps the SAME thread_id rather than minting a fresh
        // one. None for a brand-new compose.
        let draft = mail_local_state::Draft {
            to: to_v,
            subject: subj_v,
            body: body_v,
            updated_at,
            thread_id: thread_id.read().clone(),
            in_reply_to: in_reply_to.read().clone(),
            quoted_excerpt: quoted_excerpt.read().clone(),
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
        let val = to.read();
        address_book::lookup(&val).or_else(|| address_book::lookup_by_bs58(&val))
    });

    // Autocomplete suggestions: case-insensitive substring over all contacts.
    // Empty when input is blank or exactly matches a known alias / bs58 address.
    let ac_suggestions = use_memo(move || {
        let needle = to.read().clone();
        if needle.is_empty()
            || address_book::lookup(&needle).is_some()
            || address_book::lookup_by_bs58(&needle).is_some()
        {
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
            // spawn_forever: delete_draft_now fires on Send, which navigates
            // away and unmounts this component. A bare spawn() would cancel
            // the DeleteDraft delegate write on unmount, leaving the draft
            // persisted on the node — it then reappears (and the sent message
            // re-derives as a Draft) after reload (#286).
            let _task = dioxus_core::spawn_forever(async move {
                if let Err(e) = crate::local_state::delete_draft(&mut client_clone, alias, id).await
                {
                    crate::log::local_state_failure("delete draft", e);
                }
            });
        }
    });
    let send_msg = move |_| {
        let to_val = to.read().clone();
        // Try local alias first; fall back to raw bs58 inbox address so
        // a user can paste an address into the To field and reach a
        // contact without re-typing the alias.
        let recipient = match address_book::lookup(&to_val)
            .or_else(|| address_book::lookup_by_bs58(&to_val))
        {
            Some(r) => r,
            None => {
                crate::log::error(
                    format!("couldn't find key for `{to_val}`"),
                    Some(TryNodeAction::GetAlias),
                );
                crate::toast::push_toast(
                    format!(
                        "Recipient `{to_val}` is not in your address book. Import their contact before sending."
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
        // the Sent row's `SentId`. #251 improvement 4: derive against the
        // recipient's advertised WASM hash when known so the ack pairing
        // matches the actual contract id the runtime will route to.
        #[cfg(feature = "use-node")]
        let inbox_key_for_ack = crate::inbox::inbox_key_for_with_hash(
            &recipient_vk,
            recipient
                .inbox_wasm_hash
                .as_deref()
                .unwrap_or(crate::inbox::INBOX_CODE_HASH),
        );

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

        // #270: resolve the outgoing message's threading linkage. A reply
        // carries the parent's thread_id (already minted at reply time); a
        // brand-new compose mints a fresh thread_id so the conversation is
        // groupable from the first message. `in_reply_to` / `quoted_excerpt`
        // are non-None only for replies.
        let send_thread_id = Some(
            thread_id
                .read()
                .clone()
                .unwrap_or_else(crate::local_state::new_thread_id),
        );
        let send_in_reply_to = in_reply_to.read().clone();
        let send_quoted_excerpt = quoted_excerpt.read().clone();

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
            recipient.inbox_wasm_hash.clone(),
            &title_val,
            &content_val,
            send_thread_id.clone(),
            send_in_reply_to.clone(),
            send_quoted_excerpt.clone(),
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
                // #270: mirror the threading linkage onto the local Sent row
                // so the Sent folder + reply-from-Sent stay in the thread.
                thread_id: send_thread_id.clone(),
                in_reply_to: send_in_reply_to.clone(),
                quoted_excerpt: send_quoted_excerpt.clone(),
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
                // spawn_forever, not spawn: the send handler navigates away
                // (at_new_msg() below) and unmounts this compose component.
                // spawn() ties the task to this scope and cancels it on
                // unmount, so the SaveSent delegate write never reached the
                // wire — the message persisted only in the in-session
                // snapshot and re-derived as a Draft after reload (#286).
                let _task = dioxus_core::spawn_forever(async move {
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
mod folder_count_tests {
    use super::*;

    fn msg(id: u64, read: bool) -> Message {
        Message {
            id,
            from: "bob".into(),
            title: "t".into(),
            content: "c".into(),
            read,
            time: chrono::Utc::now(),
            sender_vk: Vec::new(),
            signature_valid: false,
            assignment_hash: [0u8; 32],
            thread_id: None,
            in_reply_to: None,
            quoted_excerpt: None,
        }
    }

    /// Reset the shared local-state snapshot so deleted/archived sets don't
    /// leak between tests on the same thread.
    fn reset_state() {
        crate::local_state::replace_snapshot(::mail_local_state::LocalState::default());
    }

    /// Repro for #268: the Inbox badge counted unread rows that the list
    /// hides because they're deleted. Badge then exceeds the visible row
    /// count — "folder counts don't match what's in them". After the fix the
    /// badge excludes deleted rows, matching the list.
    #[test]
    fn inbox_badge_excludes_deleted_unread() {
        reset_state();
        let emails = vec![msg(1, false), msg(2, false), msg(3, true)];
        // Two unread (1, 2), one read (3). Badge should be 2.
        assert_eq!(folder_count(&emails, menu::Folder::Inbox, "alice"), 2);

        // User deletes the unread message 2. It vanishes from the list, so
        // the badge must drop to 1 — not stay at 2.
        crate::local_state::local_delete_message("alice", 2);
        assert_eq!(
            folder_count(&emails, menu::Folder::Inbox, "alice"),
            1,
            "deleted unread row must not be counted (#268)",
        );
    }

    /// Same defect for archived rows: archiving an unread message removes it
    /// from the Inbox list, so the badge must not keep counting it.
    #[test]
    fn inbox_badge_excludes_archived_unread() {
        reset_state();
        let emails = vec![msg(10, false), msg(11, false)];
        assert_eq!(folder_count(&emails, menu::Folder::Inbox, "alice"), 2);

        crate::local_state::local_archive_message(
            "alice",
            11,
            ::mail_local_state::ArchivedMessage {
                from: "bob".into(),
                title: "t".into(),
                content: "c".into(),
                archived_at: 0,
                ..Default::default()
            },
        );
        assert_eq!(
            folder_count(&emails, menu::Folder::Inbox, "alice"),
            1,
            "archived unread row must not be counted (#268)",
        );
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
mod quarantine_tests {
    use super::{Message, is_sender_verified};
    use chrono::Utc;
    use std::borrow::Cow;

    fn msg_with_vk(vk: Vec<u8>) -> Message {
        Message {
            id: 0,
            from: Cow::Borrowed("someone"),
            title: Cow::Borrowed("hi"),
            content: Cow::Borrowed("body"),
            read: false,
            time: Utc::now(),
            sender_vk: vk,
            signature_valid: true,
            assignment_hash: [0u8; 32],
            thread_id: None,
            in_reply_to: None,
            quoted_excerpt: None,
        }
    }

    /// An empty sender-vk (legacy / unsigned) is never a known sender, so it
    /// is diverted to Quarantine when the toggle is on. This is the case the
    /// offline example messages exercise — they all carry an empty vk.
    #[test]
    fn empty_vk_is_unverified() {
        assert!(!is_sender_verified(&msg_with_vk(Vec::new())));
    }

    /// A vk that isn't in the (empty, in this test) address book is unknown,
    /// so even a cryptographically-valid signature lands in Quarantine until
    /// the user verifies the contact.
    #[test]
    fn unknown_vk_is_unverified() {
        assert!(!is_sender_verified(&msg_with_vk(vec![1, 2, 3, 4])));
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
            thread_id: None,
            in_reply_to: None,
            quoted_excerpt: None,
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
mod merge_inbox_list_tests {
    use super::{Message, merge_inbox_list};
    use chrono::{TimeZone, Utc};
    use mail_local_state::KeptMessage;
    use std::borrow::Cow;

    fn live(id: u64, from: &'static str) -> Message {
        Message {
            id,
            from: Cow::Borrowed(from),
            title: Cow::Borrowed("subject"),
            content: Cow::Borrowed("body"),
            read: false,
            time: Utc.timestamp_opt(1_000 + id as i64, 0).unwrap(),
            sender_vk: Vec::new(),
            signature_valid: false,
            assignment_hash: [0u8; 32],
            thread_id: None,
            in_reply_to: None,
            quoted_excerpt: None,
        }
    }

    fn kept(from: &str) -> KeptMessage {
        KeptMessage {
            from: from.into(),
            title: "subject".into(),
            content: "body".into(),
            kept_at: 100,
            sent_at: Some(50),
            sender_vk: Vec::new(),
            signature_valid: false,
        }
    }

    /// With the fix in place, clicking a message no longer triggers
    /// contract eviction, so the kept_for path stays empty and the
    /// merge just flips `read=true` on the live row. The latent merge
    /// dedup-by-positional-id bug is documented in
    /// `kept_collides_with_renumbered_live_is_a_latent_bug` below — it
    /// can still bite if a future change re-introduces contract
    /// eviction on read.
    #[test]
    fn read_message_stays_in_inbox_via_is_read_overlay() {
        let live_rows = vec![live(0, "alice"), live(1, "bob")];
        let merged = merge_inbox_list(live_rows, vec![], |_| false, |id| id == 0);
        assert_eq!(merged.len(), 2, "both rows must remain after click-to-read");
        assert!(merged[0].read, "clicked row must surface as read");
        assert!(!merged[1].read, "unread row must remain unread");
    }

    /// Latent bug — kept here as a tripwire. If a future change re-adds
    /// contract eviction on read, the `MessageId` written to
    /// `kept_for` (the positional id at click time) will collide with a
    /// different message after `from_state` re-enumerates the surviving
    /// rows, and the kept row gets dedup'd away. Captured as
    /// `#[should_panic]` so the test suite stays green today while
    /// documenting the constraint.
    #[test]
    #[should_panic(expected = "alice (read, kept-locally) must remain")]
    fn kept_collides_with_renumbered_live_is_a_latent_bug() {
        // Initial state: two messages at positional ids 0 and 1.
        // User clicks id=0 ("alice"), contract evicts it, local kept
        // snapshot records `kept[0] = alice`.
        let kept_entries: Vec<(u64, KeptMessage)> = vec![(0, kept("alice"))];

        // After eviction + state reload, the surviving message
        // (originally id=1) is now id=0.
        let live_after_evict = vec![live(0, "bob")];

        let merged = merge_inbox_list(live_after_evict, kept_entries, |_| false, |_| false);
        let froms: Vec<String> = merged.iter().map(|m| m.from.to_string()).collect();
        assert!(
            froms.iter().any(|f| f == "alice"),
            "alice (read, kept-locally) must remain in the inbox list after eviction + renumber; got {froms:?}"
        );
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
                ..Default::default()
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
                ..Default::default()
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
                ..Default::default()
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
