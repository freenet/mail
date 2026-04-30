#[cfg(feature = "example-data")]
use std::collections::HashMap;
use std::fmt::Display;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::{borrow::Cow, cell::RefCell, rc::Rc};

use arc_swap::ArcSwap;
use chrono::Utc;
use dioxus::prelude::*;
use futures::FutureExt;
use futures::future::LocalBoxFuture;
use ml_dsa::{MlDsa65, SigningKey as MlDsaSigningKey};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem768};
use wasm_bindgen::JsValue;

pub(crate) use login::{Identity, LoginController};

use crate::api::{TryNodeAction, node_response_error_handling};
use crate::{
    DynError,
    api::WebApiRequestClient,
    inbox::{DecryptedMessage, InboxModel, MessageModel},
};

pub(crate) mod login;

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
    // Initialize and fetch shared state for User, InboxController, and InboxView
    use_context_provider(|| Signal::new(User::new()));
    let user = use_context::<Signal<User>>();
    use_context_provider(|| Signal::new(InboxController::new()));
    let inbox_controller = use_context::<Signal<InboxController>>();
    use_context_provider(|| Signal::new(InboxView::new()));
    let inbox = use_context::<Signal<InboxView>>();
    use_context_provider(InboxesData::new);
    let inbox_data = use_context::<InboxesData>();

    #[cfg(all(feature = "use-node", not(feature = "no-sync")))]
    {
        let _sync: Coroutine<NodeAction> = use_coroutine(move |rx| {
            let inbox_controller = inbox_controller;
            let login_controller = login_controller;
            let user = user;
            let inbox_data = inbox_data.clone();
            let fut =
                crate::api::node_comms(rx, inbox_controller, login_controller, user, inbox_data)
                    .map(|_| Ok(JsValue::NULL));
            let _ = wasm_bindgen_futures::future_to_promise(fut);
            async {}.boxed_local()
        });
    }
    #[cfg(any(not(feature = "use-node"), feature = "no-sync"))]
    {
        let _ = inbox_controller;
        let _ = login_controller;
        let _ = inbox_data;
        let _sync: Coroutine<NodeAction> =
            use_coroutine(move |_rx: UnboundedReceiver<NodeAction>| async {});
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

#[derive(Clone)]
// `Arc<ArcSwap<..>>` over `Rc<RefCell<InboxModel>>` is intentional: the UI is
// single-threaded (wasm) and `ArcSwap` requires `Arc`, so the non-Send inner
// type is load-bearing and can't be swapped for an `Rc`.
#[allow(clippy::arc_with_non_send_sync)]
pub(crate) struct InboxesData(Arc<ArcSwap<Vec<Rc<RefCell<InboxModel>>>>>);

impl InboxesData {
    #[allow(clippy::arc_with_non_send_sync)]
    pub fn new() -> Self {
        Self(Arc::new(ArcSwap::from_pointee(vec![])))
    }
}

impl std::ops::Deref for InboxesData {
    type Target = Arc<ArcSwap<Vec<Rc<RefCell<InboxModel>>>>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct InboxView {
    active_id: Rc<RefCell<UserId>>,
    /// loaded messages for the currently selected `active_id`
    messages: Rc<RefCell<Vec<Message>>>,
}

#[derive(Debug, Clone)]
pub struct InboxController {
    pub updated: bool,
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

impl InboxController {
    pub fn new() -> Self {
        Self { updated: false }
    }
}

impl InboxView {
    fn new() -> Self {
        Self {
            messages: Rc::new(RefCell::new(vec![])),
            active_id: Rc::new(RefCell::new(UserId(0))),
        }
    }

    fn set_active_id(&mut self, user: UserId) {
        let mut id = self.active_id.borrow_mut();
        *id = user;
    }

    fn send_message(
        &mut self,
        client: WebApiRequestClient,
        from: &str,
        recipient_ek: EncapsulationKey<MlKem768>,
        recipient_ml_dsa_vk: ml_dsa::VerifyingKey<MlDsa65>,
        title: &str,
        content: &str,
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
            let f = async move {
                let res = content_clone
                    .start_sending(&mut client, recipient_ek, recipient_ml_dsa_vk, &id)
                    .await;
                node_response_error_handling(client.into(), res, TryNodeAction::SendMessage).await;
            };
            futs.push(f.boxed_local());
        }
        #[cfg(all(feature = "example-data", not(feature = "use-node")))]
        {
            // In offline mode, deliver the message to an in-memory mailbox
            // keyed by recipient alias so that switching identities reveals it.
            use ml_kem::kem::KeyExport;
            if let Some(ek_key) = content.to.first() {
                if let Some(to_alias) = Identity::alias_for_encaps_key(ek_key.0.as_slice()) {
                    let msg = Message {
                        id: 0, // reassigned on load
                        from: content.from.clone().into(),
                        title: content.title.clone().into(),
                        content: content.content.clone().into(),
                        read: false,
                    };
                    MOCK_SENT_MESSAGES.with(|map| {
                        map.borrow_mut()
                            .entry(to_alias.to_string())
                            .or_default()
                            .push(msg);
                    });
                }
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
            return Ok(async {}.boxed_local());
        }
        #[cfg(not(all(feature = "example-data", not(feature = "use-node"))))]
        {
            // FIXME: indexing by id fails cause all not aliases inboxes has been loaded initially
            let inbox_data = inbox_data.load_full();
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
        let body: Cow<'static, str> = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
             Sed do eiusmod tempor incidunt ut labore et dolore magna aliqua."
            .into();
        let mut emails = if id.id == UserId(0) {
            vec![
                Message {
                    id: 0,
                    from: "Ian's Other Account".into(),
                    title: "Welcome to the offline preview".into(),
                    content: body.clone(),
                    read: false,
                },
                Message {
                    id: 1,
                    from: "Mary".into(),
                    title: "Lunch tomorrow?".into(),
                    content: body.clone(),
                    read: false,
                },
                Message {
                    id: 2,
                    from: "freenet-bot".into(),
                    title: "Your weekly digest".into(),
                    content: body,
                    read: true,
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
                },
                Message {
                    id: 1,
                    from: "Jane".into(),
                    title: "Re: design review".into(),
                    content: body,
                    read: false,
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
            Identity {
                alias: "address1".into(),
                id: UserId(0),
                description: "Mock identity (example-data)".into(),
                ml_dsa_signing_key: ml_dsa0,
                ml_kem_dk: ml_kem_dk0,
            },
            Identity {
                alias: "address2".into(),
                id: UserId(1),
                description: "Mock identity (example-data)".into(),
                ml_dsa_signing_key: ml_dsa1,
                ml_kem_dk: ml_kem_dk1,
            },
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

    fn set_logged_id(&mut self, id: UserId) {
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
}

impl From<MessageModel> for Message {
    fn from(value: MessageModel) -> Self {
        Message {
            id: value.id,
            from: value.content.from.into(),
            title: value.content.title.into(),
            content: value.content.content.into(),
            read: false,
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

mod menu {
    #[derive(Default)]
    pub(super) struct MenuSelection {
        email: Option<u64>,
        new_msg: bool,
    }

    impl MenuSelection {
        pub fn at_new_msg(&mut self) {
            if self.new_msg {
                self.new_msg = false;
            } else {
                self.new_msg = true;
                self.email = None;
            }
        }

        pub fn is_new_msg(&self) -> bool {
            self.new_msg
        }

        pub fn at_inbox_list(&mut self) {
            self.email = None;
            self.new_msg = false;
        }

        pub fn is_inbox_list(&self) -> bool {
            !self.new_msg && self.email.is_none()
        }

        pub fn open_email(&mut self, id: u64) {
            self.email = Some(id);
        }

        pub fn email(&self) -> Option<u64> {
            self.email
        }
    }
}

#[allow(non_snake_case)]
fn UserInbox() -> Element {
    use_context_provider(|| Signal::new(menu::MenuSelection::default()));
    rsx!(
        div {
            class: "columns",
            nav {
                class: "column is-one-fifth menu",
                UserMenuComponent {}
            }
            div {
                class: "column",
                InboxComponent {}
            }
        }
    )
}

#[allow(non_snake_case)]
fn UserMenuComponent() -> Element {
    let mut user = use_context::<Signal<User>>();
    let mut menu_selection = use_context::<Signal<menu::MenuSelection>>();

    let received_class =
        if menu_selection.read().is_inbox_list() || !menu_selection.read().is_new_msg() {
            "is-active"
        } else {
            ""
        };
    let write_msg_class = if menu_selection.read().is_new_msg() {
        "is-active"
    } else {
        ""
    };

    rsx!(
        div {
            class: "pl-3 pr-3 mt-3",
            ul {
                class: "menu-list",
                li {
                    a {
                        class: received_class,
                        onclick: move |_| { menu_selection.write().at_inbox_list(); },
                        "Received"
                    }
                }
                li {
                    a {
                        class: write_msg_class,
                        onclick: move |_| {
                            let mut selection = menu_selection.write();
                            selection.at_new_msg();
                        },
                        "Write message"
                    }
                }
                li {
                    a {
                        onclick: move |_| {
                            let mut logged_state = user.write();
                            logged_state.logged = false;
                            logged_state.active_id = None;
                        },
                        "Log out"
                    }
                }
            }
        }
    )
}

#[allow(non_snake_case)]
fn InboxComponent() -> Element {
    let inbox = use_context::<Signal<InboxView>>();
    let mut controller = use_context::<Signal<InboxController>>();
    let inbox_data = use_context::<InboxesData>();
    let menu_selection = use_context::<Signal<menu::MenuSelection>>();
    let user = use_context::<Signal<User>>();

    #[component]
    fn EmailLink(
        sender: Cow<'static, str>,
        title: Cow<'static, str>,
        read: bool,
        id: u64,
    ) -> Element {
        let mut open_mail = use_context::<Signal<menu::MenuSelection>>();
        let icon_style = if read {
            "fa-regular fa-envelope"
        } else {
            "fa-solid fa-envelope"
        };
        rsx!(
            a {
                class: "panel-block",
                id: "email-inbox-accessor-{id}",
                onclick: move |_| { open_mail.write().open_email(id); },
                span {
                    class: "panel-icon",
                    i { class: icon_style }
                }
                span { class: "ml-2", "{sender}" }
                span { class: "ml-5", "{title}" }
            }
        )
    }

    {
        let current_active_id: UserId = user.read().active_id.unwrap();
        // reload if there were new emails received
        let all_data = inbox_data.load_full();
        if let Some((current_model, id)) = all_data.iter().find_map(|ib| {
            crate::log::debug!("trying to get identity for {key}", key = &ib.borrow().key);
            let id = crate::inbox::InboxModel::contract_identity(&ib.borrow().key).unwrap();
            (id.id == current_active_id).then_some((ib, id))
        }) {
            let inbox = inbox.read();
            let mut emails = inbox.messages.borrow_mut();
            emails.clear();
            for msg in &current_model.borrow().messages {
                let m = Message::from(msg.clone());
                emails.push(m);
            }
            crate::log::debug!("active id: {:?}; emails number: {}", id.alias, emails.len());
        }
    }

    // Mark updated as false after after the inbox has been refreshed
    if controller.read().updated {
        controller.write().updated = false;
    }

    let inbox = inbox.read();
    let emails = inbox.messages.borrow();
    let is_email: Option<u64> = menu_selection.read().email();
    if let Some(email_id) = is_email {
        let id_p = (*emails).binary_search_by_key(&email_id, |e| e.id).unwrap();
        let email = &emails[id_p];
        rsx! {
            OpenMessage {
                msg: email.clone(),
            }
        }
    } else if menu_selection.read().is_new_msg() {
        rsx! {
            NewMessageWindow {}
        }
    } else {
        DELAYED_ACTIONS.with(|queue| {
            let mut queue = queue.borrow_mut();
            for fut in queue.drain(..) {
                let _ = spawn(fut);
            }
        });
        let links = emails.iter().enumerate().map(|(id, email)| {
            rsx!(EmailLink {
                sender: email.from.clone(),
                title: email.title.clone(),
                read: email.read,
                id: id as u64,
            })
        });
        rsx! {
            div {
                class: "panel is-link mt-3",
                p { class: "panel-heading", "Inbox" }
                p {
                    class: "panel-tabs",
                    a {
                        class: "is-active icon-text",
                        span { class: "icon", i { class: "fas fa-inbox" } }
                        span { "Primary" }
                    }
                    a {
                        class: "icon-text",
                        span { class: "icon",i { class: "fas fa-user-group" } },
                        span { "Social" }
                    }
                    a {
                        class: "icon-text",
                        span { class: "icon", i { class: "fas fa-circle-exclamation" } },
                        span { "Updates" }
                    }
                }
                div {
                    class: "panel-block",
                    p {
                        class: "control has-icons-left",
                        input { class: "input is-link", r#type: "text", placeholder: "Search" }
                        span { class: "icon is-left", i { class: "fas fa-search", aria_hidden: true } }
                    }
                }
                {links}
            }
        }
    }
}

thread_local! {
    static DELAYED_ACTIONS: RefCell<Vec<LocalBoxFuture<'static, ()>>> = RefCell::new(Vec::new());
}

#[component]
fn OpenMessage(msg: Message) -> Element {
    let mut menu_selection = use_context::<Signal<menu::MenuSelection>>();
    let client = crate::api::WEB_API_SENDER.get().unwrap();
    let mut inbox = use_context::<Signal<InboxView>>();
    let inbox_data = use_context::<InboxesData>();
    let email_id = [msg.id];

    let result = inbox
        .write()
        .mark_as_read(client.clone(), &email_id, inbox_data.clone())
        .unwrap();
    DELAYED_ACTIONS.with(|queue| {
        queue.borrow_mut().push(result);
    });

    // todo: delete this from the private delegate or send to trash category
    // let delete = move |_| {
    //     let result = inbox
    //         .write()
    //         .remove_messages(client.clone(), &email_id, inbox_data.clone())
    //         .unwrap();
    //     spawn(result);
    //     menu_selection.write().at_inbox_list();
    // };

    rsx! {
        div {
            class: "columns title mt-3",
            div {
                class: "column",
                a {
                    class: "icon is-small",
                    onclick: move |_| {
                        menu_selection.write().at_inbox_list();
                    },
                    i { class: "fa-sharp fa-solid fa-arrow-left", aria_label: "Back to Inbox", style: "color:#4a4a4a" },
                }
            }
            div { class: "column is-four-fifths", h2 { "{msg.title}" } }
            div {
                class: "column",
                a {
                    class: "icon is-small",
                    // onclick: delete,
                    onclick: move |_| {},
                    i { class: "fa-sharp fa-solid fa-trash", aria_label: "Delete", style: "color:#4a4a4a" }
                }
            }
        }
        div {
            id: "email-content-{msg.id}",
            p {
                "{msg.content}"
            }
        }
    }
}

#[allow(non_snake_case)]
fn NewMessageWindow() -> Element {
    let mut menu_selection = use_context::<Signal<menu::MenuSelection>>();
    let client = crate::api::WEB_API_SENDER.get().unwrap();
    let mut inbox = use_context::<Signal<InboxView>>();
    let user = use_context::<Signal<User>>();
    let user = user.read();
    let user_alias = &*user.logged_id().unwrap().alias;
    let mut to = use_signal(String::new);
    let mut title = use_signal(String::new);
    let mut content = use_signal(String::new);

    let alias = user_alias.to_string();
    let send_msg = move |_| {
        let to_val = to.read().clone();
        // fixme: this will have to come from the address book in the future
        let (recipient_ek, recipient_vk) = match Identity::get_alias(&to_val) {
            Some(v) => (v.ml_kem_ek(), v.ml_dsa_vk()),
            None => {
                crate::log::error(
                    format!("couldn't find key for `{to_val}`"),
                    Some(TryNodeAction::GetAlias),
                );
                return;
            }
        };
        let title_val = title.read().clone();
        let content_val = content.read().clone();
        match inbox.write().send_message(
            client.clone(),
            &alias,
            recipient_ek,
            recipient_vk,
            &title_val,
            &content_val,
        ) {
            Ok(futs) => {
                // spawn_forever, not spawn: the send future outlives the
                // NewMessageWindow component (we navigate away to inbox
                // immediately below via at_new_msg). spawn() ties the task
                // to the current component scope and cancels it on unmount,
                // which silently killed every send before the AFT request
                // hit the wire.
                futs.into_iter().for_each(|f| {
                    let _task = dioxus_core::spawn_forever(f);
                });
            }
            Err(e) => {
                crate::log::error(format!("{e}"), Some(TryNodeAction::SendMessage));
            }
        }
        menu_selection.write().at_new_msg();
    };

    rsx! {
        div {
            class: "column mt-3",
            div {
                class: "box has-background-light",
                h3 { class: "title is-3", "New message" }
                table {
                    class: "table is-narrow has-background-light",
                    tbody {
                        tr {
                            th { "From" }
                            td { style: "width: 100%", "{user_alias}" }
                        }
                        tr {
                            th { "To"}
                            td { style: "width: 100%", contenteditable: true, oninput: move |ev| { to.set(ev.value().clone()); } }
                        }
                        tr {
                            th { "Subject"}
                            td { style: "width: 100%", contenteditable: true, oninput: move |ev| { title.set(ev.value().clone()); }  }
                        }
                    }
                }
            }
            div {
                class: "box",
                div {
                    contenteditable: true,
                    oninput: move |ev| { content.set(ev.value().clone()); },
                    br {}
                }
            }
            div {
                button {
                    class: "button is-info is-outlined",
                    onclick: send_msg,
                    "Send"
                }
            }
        }
    }
}
