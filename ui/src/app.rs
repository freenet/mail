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

    #[cfg(all(feature = "use-node", not(feature = "no-sync")))]
    {
        let _sync: Coroutine<NodeAction> = use_coroutine(move |rx| {
            let login_controller = login_controller;
            let user = user;
            let fut = crate::api::node_comms(rx, login_controller, user, inbox_data)
                .map(|_| Ok(JsValue::NULL));
            let _ = wasm_bindgen_futures::future_to_promise(fut);
            async {}.boxed_local()
        });
    }
    #[cfg(any(not(feature = "use-node"), feature = "no-sync"))]
    {
        let _ = inbox_data;
        let mut login_ctl = login_controller;
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
                            }
                        }
                        NodeAction::DeleteContact { alias } => {
                            address_book::remove_contact(&alias);
                            login_ctl.write().updated = true;
                        }
                        NodeAction::RenameIdentity { old, new, .. } => {
                            // Offline mode: just relabel the in-memory
                            // ALIASES entries. The delegate isn't
                            // around, so there's no delete+create round
                            // trip.
                            Identity::rename_in_place(&old, &new);
                            login_ctl.write().updated = true;
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
                    .start_sending(&mut client, recipient_ek, recipient_ml_dsa_vk, &id)
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
                        crate::log::error(
                            format!("set_sent_delivery_state(Failed) failed: {e}"),
                            None,
                        );
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

    fn logged_id(&self) -> Option<&Identity> {
        self.active_id.and_then(|id| self.identities.get(id.0))
    }

    pub(crate) fn set_logged_id(&mut self, id: UserId) {
        assert!(id.0 < self.identities.len());
        self.active_id = Some(id);
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
    use_context_provider(|| Signal::new(Option::<String>::None));
    // SettingsShell.AccountIdentity reads `Signal<ImportBackup>` to drive
    // its Restore action through the same modal as the login pane. The
    // login flow also provides this; we re-provide here so Settings can
    // be opened from inside the inbox without the login pane in scope.
    use_context_provider(|| Signal::new(crate::app::login::ImportBackup(false)));

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
                let time = chrono::DateTime::from_timestamp_millis(kept.kept_at)
                    .unwrap_or_else(chrono::Utc::now);
                emails.push(Message {
                    id: mid,
                    from: kept.from.into(),
                    title: kept.title.into(),
                    content: kept.content.into(),
                    read: true,
                    time,
                    sender_vk: Vec::new(),
                    signature_valid: false,
                });
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
        v.sort_by_key(|m| std::cmp::Reverse(m.time));
        v
    } else {
        Vec::new()
    };
    let drafts: Vec<(String, mail_local_state::Draft)> = if matches!(folder, menu::Folder::Drafts)
        || (matches!(folder, menu::Folder::Inbox) && inbox_settings.drafts_in_inbox)
    {
        let mut d = crate::local_state::drafts_for(&active_alias);
        // Newest first.
        d.sort_by_key(|b| std::cmp::Reverse(b.1.updated_at));
        d
    } else {
        Vec::new()
    };
    let sent_msgs: Vec<(String, mail_local_state::SentMessage)> =
        if matches!(folder, menu::Folder::Sent) {
            let mut s = crate::local_state::sent_for(&active_alias);
            s.sort_by_key(|b| std::cmp::Reverse(b.1.sent_at));
            s
        } else {
            Vec::new()
        };
    let archived_msgs: Vec<(u64, mail_local_state::ArchivedMessage)> =
        if matches!(folder, menu::Folder::Archive) {
            let mut a = crate::local_state::archived_for(&active_alias);
            a.sort_by_key(|b| std::cmp::Reverse(b.1.archived_at));
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
    let mut toast = use_context::<Signal<Option<String>>>();
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
                        toast.set(Some("Deleted".to_string()));
                        spawn_toast_clear();
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
    let mut toast = use_context::<Signal<Option<String>>>();
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
                        crate::log::error(format!("mark_read failed: {e}"), None);
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
                            toast.set(Some(
                                "Open the address book to add this sender".into(),
                            ));
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
                                        crate::log::error(
                                            format!("archive_message failed: {e}"),
                                            None,
                                        );
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
                        toast.set(Some("Archived".to_string()));
                        spawn_toast_clear();
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
                        toast.set(Some("Deleted".to_string()));
                        spawn_toast_clear();
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

fn spawn_toast_clear() {
    let mut toast = use_context::<Signal<Option<String>>>();
    spawn(async move {
        gloo_timers::future::TimeoutFuture::new(2200).await;
        toast.set(None);
    });
}

#[allow(non_snake_case)]
fn ToastView() -> Element {
    let toast = use_context::<Signal<Option<String>>>();
    let value = toast.read().clone();
    if let Some(text) = value {
        rsx! {
            div { class: "toast", "data-testid": testid::FM_TOAST,
                span { class: "pulse-dot" }
                span { "{text}" }
            }
        }
    } else {
        rsx! {}
    }
}

#[allow(non_snake_case)]
fn ComposeSheet() -> Element {
    let mut menu_selection = use_context::<Signal<menu::MenuSelection>>();
    let mut toast = use_context::<Signal<Option<String>>>();
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
                    crate::log::error(format!("save_draft failed: {e}"), None);
                }
            });
        }
    });

    let recipient_lookup = use_memo(move || address_book::lookup(&to.read()));

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
                    crate::log::error(format!("delete_draft failed: {e}"), None);
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
            toast.set(Some(format!(
                "Recipient `{to_val}` is not verified. Verify the fingerprint in Contacts before sending."
            )));
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
                crate::log::error(format!("{e}"), Some(TryNodeAction::SendMessage));
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
                        crate::log::error(format!("save_sent failed: {e}"), None);
                    }
                });
            }
        }
        delete_draft_now(());
        menu_selection.write().at_new_msg();
        toast.set(Some("Sent".to_string()));
        spawn_toast_clear();
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
                div { class: "sheet-field",
                    span { class: "field-lbl", "To" }
                    input {
                        class: "field-input",
                        r#type: "text",
                        placeholder: "alias or address",
                        value: "{to}",
                        oninput: move |ev| { to.set(ev.value()); autosave(()); },
                    }
                }
                {
                    recipient_lookup.read().as_ref().map(|r| {
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
                    })
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
