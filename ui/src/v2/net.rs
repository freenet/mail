//! Inbox v2 states on the network: GET, PUT and UPDATE, each awaited.
//!
//! On a node, every answer reaches the page through the one response loop
//! (`api::node_comms`), which hands answers for v2 inboxes to [`route`]
//! before anything else looks at them. A call waits in a slot keyed by the
//! inbox; no answer in time is an error (the outcome is unknown, never
//! "absent"), and only a node's `NotFound` is [`Got::Missing`].
//!
//! The offline build has no node: inboxes live in this page, merged by a
//! model of the contract's rules (`offline`), enough to show every outcome.
//! The contract itself is proven against the delegate in the delegate's
//! tests, and on real nodes by `cargo make test-e2e-inbox-v2`.

use std::cell::RefCell;
use std::collections::HashMap;

use freenet_mail_protocol::Addr;
use freenet_stdlib::prelude::ContractInstanceId;

/// What a GET found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Got {
    State(Vec<u8>),
    /// The node answered that no such contract exists.
    Missing,
}

thread_local! {
    /// The identities' own inboxes, to route a change to the drain.
    static OWN: RefCell<HashMap<ContractInstanceId, Addr>> = RefCell::new(HashMap::new());
}

pub(crate) fn note_own(addr: &Addr) {
    OWN.with(|o| o.borrow_mut().insert(super::instance_id(addr), *addr));
}

fn own(id: &ContractInstanceId) -> Option<Addr> {
    OWN.with(|o| o.borrow().get(id).copied())
}

#[cfg(feature = "use-node")]
pub(crate) use node::{get, put, route, update};
#[cfg(not(feature = "use-node"))]
pub(crate) use offline::{get, put, update};

#[cfg(feature = "use-node")]
mod node {
    use super::*;
    use freenet_stdlib::client_api::{
        ClientError, ContractError, ContractRequest, ContractResponse, ErrorKind, HostResponse,
        RequestError,
    };
    use freenet_stdlib::prelude::{ContractContainer, UpdateData};
    use futures::channel::oneshot;

    /// How long a GET, PUT or UPDATE gets to answer.
    const TIMEOUT_MS: u32 = 30_000;

    #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
    enum Kind {
        Get,
        Put,
        Update,
    }

    type Answer = Result<Got, String>;

    type Waiters = HashMap<(ContractInstanceId, Kind), Vec<oneshot::Sender<Answer>>>;

    thread_local! {
        static WAITING: RefCell<Waiters> = RefCell::new(HashMap::new());
        /// Every v2 inbox this page asked about: what the node says about
        /// them later (a notification of a followed recipient's inbox, a
        /// late answer) is this module's, and nobody else's.
        static KNOWN: RefCell<std::collections::HashSet<ContractInstanceId>> =
            RefCell::new(std::collections::HashSet::new());
    }

    fn known(id: &ContractInstanceId) -> bool {
        KNOWN.with(|k| k.borrow().contains(id))
    }

    fn answer(id: &ContractInstanceId, kind: Kind, a: Answer) -> bool {
        let waiters = WAITING.with(|w| w.borrow_mut().remove(&(*id, kind)));
        let Some(waiters) = waiters else {
            return false;
        };
        for w in waiters {
            let _ = w.send(a.clone());
        }
        true
    }

    /// Take a node answer about a v2 inbox. Returns whether it was one; the
    /// caller then handles nothing more of it.
    pub(crate) fn route(res: &Result<HostResponse, ClientError>) -> bool {
        match res {
            Ok(HostResponse::ContractResponse(r)) => match r {
                ContractResponse::GetResponse { key, state, .. } => {
                    let id = *key.id();
                    if let Some(addr) = own(&id) {
                        super::super::owner::state_seen(addr, state.as_ref().to_vec());
                    }
                    answer(&id, Kind::Get, Ok(Got::State(state.as_ref().to_vec()))) || known(&id)
                }
                ContractResponse::PutResponse { key } => {
                    answer(key.id(), Kind::Put, Ok(Got::Missing)) || known(key.id())
                }
                ContractResponse::UpdateResponse { key, .. } => {
                    answer(key.id(), Kind::Update, Ok(Got::Missing)) || known(key.id())
                }
                ContractResponse::UpdateNotification { key, .. } => {
                    if let Some(addr) = own(key.id()) {
                        super::super::owner::changed(addr);
                    }
                    known(key.id())
                }
                ContractResponse::SubscribeResponse { key, .. } => known(key.id()),
                ContractResponse::NotFound { instance_id } => {
                    answer(instance_id, Kind::Get, Ok(Got::Missing))
                }
                _ => false,
            },
            Err(e) => match e.kind() {
                ErrorKind::RequestError(RequestError::ContractError(err)) => {
                    let (key, kind, cause) = match err {
                        ContractError::Get { key, cause } => (key, Kind::Get, cause),
                        ContractError::Put { key, cause } => (key, Kind::Put, cause),
                        ContractError::Update { key, cause } => (key, Kind::Update, cause),
                        _ => return false,
                    };
                    answer(key.id(), kind, Err(cause.to_string()))
                }
                _ => false,
            },
            _ => false,
        }
    }

    async fn ask(addr: &Addr, kind: Kind, request: ContractRequest<'static>) -> Answer {
        let id = super::super::instance_id(addr);
        KNOWN.with(|k| k.borrow_mut().insert(id));
        let (tx, rx) = oneshot::channel();
        WAITING.with(|w| w.borrow_mut().entry((id, kind)).or_default().push(tx));
        let mut client = crate::api::WEB_API_SENDER
            .get()
            .ok_or("not connected to the node")?
            .clone();
        if let Err(e) = client.send(request.into()).await {
            WAITING.with(|w| w.borrow_mut().remove(&(id, kind)));
            return Err(format!("the node did not take the request: {e}"));
        }
        use futures::FutureExt;
        let mut rx = rx.fuse();
        let mut timer = gloo_timers::future::TimeoutFuture::new(TIMEOUT_MS).fuse();
        futures::select! {
            a = rx => a.unwrap_or_else(|_| Err("no answer".into())),
            _ = timer => Err("the node did not answer in time".into()),
        }
    }

    /// The inbox's state. `subscribe` also follows its changes (own inboxes).
    pub(crate) async fn get(addr: &Addr, subscribe: bool) -> Answer {
        let id = super::super::instance_id(addr);
        // The first GET of an inbox asks for its code too: a node applies an
        // UPDATE it sends only to a contract whose code it holds (#191).
        let first = !known(&id);
        let request = ContractRequest::Get {
            key: id,
            return_contract_code: first,
            subscribe,
            blocking_subscribe: false,
        };
        ask(addr, Kind::Get, request).await
    }

    /// Publish a whole state, and hold and follow the inbox.
    pub(crate) async fn put(addr: &Addr, state: Vec<u8>) -> Result<(), String> {
        let contract =
            ContractContainer::try_from((super::super::CODE.to_vec(), &super::super::params(addr)))
                .map_err(|e| e.to_string())?;
        let request = ContractRequest::Put {
            contract,
            state: state.into(),
            related_contracts: Default::default(),
            subscribe: true,
            blocking_subscribe: false,
        };
        ask(addr, Kind::Put, request).await.map(|_| ())
    }

    /// Send a delta. A delta the contract filters is not an error: read the
    /// state back to know what landed.
    pub(crate) async fn update(addr: &Addr, delta: Vec<u8>) -> Result<(), String> {
        let request = ContractRequest::Update {
            key: super::super::key(addr),
            data: UpdateData::Delta(delta.into()),
        };
        ask(addr, Kind::Update, request).await.map(|_| ())
    }
}

/// The offline build's inboxes, in this page.
#[cfg(not(feature = "use-node"))]
pub(crate) mod offline {
    use super::*;
    use freenet_mail_protocol::inbox_v2::{
        self as w, Admission, InboxDelta, InboxState, QuarantineMode,
    };

    thread_local! {
        static STATES: RefCell<HashMap<ContractInstanceId, Vec<u8>>> = RefCell::new(HashMap::new());
    }

    fn store(addr: &Addr, bytes: Vec<u8>) {
        let id = super::super::instance_id(addr);
        #[cfg(feature = "local-delegate")]
        crate::mail_delegate::local::set_contract_state(
            id.as_bytes().try_into().expect("32 bytes"),
            bytes.clone(),
        );
        STATES.with(|s| s.borrow_mut().insert(id, bytes));
        if own(&id).is_some() {
            super::super::owner::changed(*addr);
        }
    }

    pub(crate) async fn get(addr: &Addr, _subscribe: bool) -> Result<Got, String> {
        let id = super::super::instance_id(addr);
        Ok(STATES
            .with(|s| s.borrow().get(&id).cloned())
            .map_or(Got::Missing, Got::State))
    }

    pub(crate) async fn put(addr: &Addr, state: Vec<u8>) -> Result<(), String> {
        let id = super::super::instance_id(addr);
        let merged = match STATES.with(|s| s.borrow().get(&id).cloned()) {
            Some(held) => merge(&held, w::decode::<InboxState>(&state)?.into_delta())?,
            None => {
                let s: InboxState = w::decode(&state)?;
                w::encode(&filter(s))
            }
        };
        store(addr, merged);
        Ok(())
    }

    pub(crate) async fn update(addr: &Addr, delta: Vec<u8>) -> Result<(), String> {
        let id = super::super::instance_id(addr);
        let held = STATES
            .with(|s| s.borrow().get(&id).cloned())
            .ok_or("no such inbox")?;
        let merged = merge(&held, w::decode::<InboxDelta>(&delta)?)?;
        store(addr, merged);
        Ok(())
    }

    trait IntoDelta {
        fn into_delta(self) -> InboxDelta;
    }

    impl IntoDelta for InboxState {
        fn into_delta(self) -> InboxDelta {
            InboxDelta {
                owner: Some(self.owner),
                time: Some(self.time),
                revoked: self.revoked,
                usage: self.usage,
                messages: self.messages,
            }
        }
    }

    /// A model of the contract's merge, for the offline build only: the
    /// newest owner record and time, unions, then the filters a sender can
    /// see the effect of (tombstones, revocations, the Ghost Key rule and
    /// the 16 quarantine slots by their salted rank). Signatures are not
    /// checked; the delegate made every one.
    fn merge(held: &[u8], delta: InboxDelta) -> Result<Vec<u8>, String> {
        let mut s: InboxState = w::decode(held)?;
        if let Some(o) = delta.owner
            && o.version > s.owner.version
        {
            s.owner = o;
        }
        if let Some(t) = delta.time
            && t.owner_time > s.time.owner_time
        {
            s.time = t;
        }
        s.revoked.extend(delta.revoked);
        s.usage.extend(delta.usage);
        for (id, m) in delta.messages {
            s.messages.entry(id).or_insert(m);
        }
        Ok(w::encode(&filter(s)))
    }

    /// Offline builds' fixture for decision 25: publish `addr`'s owner record
    /// at a version this page's delegate never signed, as a second node
    /// signing for the same identity would.
    #[cfg(feature = "example-data")]
    pub(crate) fn publish_foreign_version(addr: &Addr) {
        let id = super::super::instance_id(addr);
        let Some(held) = STATES.with(|s| s.borrow().get(&id).cloned()) else {
            return;
        };
        let Ok(mut s) = w::decode::<InboxState>(&held) else {
            return;
        };
        s.owner.version += 1_000;
        store(addr, w::encode(&s));
    }

    pub(crate) fn filter(mut s: InboxState) -> InboxState {
        let owner = s.owner.clone();
        let revoked = s.revoked.clone();
        s.messages.retain(|id, m| {
            !owner.tombstones.contains_key(id)
                && match &m.admission {
                    Admission::Pass { cert, .. } => !revoked.contains_key(&cert.pass_id),
                    Admission::Owner { .. } => true,
                    Admission::Quarantine { ghost } => match owner.quarantine {
                        QuarantineMode::Open => ghost.is_none(),
                        QuarantineMode::RequireGhost { .. } => ghost.is_some(),
                    },
                }
        });
        let salt = blake3::hash(&w::encode(&s.time));
        let rank = |id: &[u8]| {
            *blake3::Hasher::new()
                .update(salt.as_bytes())
                .update(id)
                .finalize()
                .as_bytes()
        };
        let mut strangers: Vec<_> = s
            .messages
            .iter()
            .filter(|(_, m)| matches!(m.admission, Admission::Quarantine { .. }))
            .map(|(id, _)| (rank(id.as_slice()), *id))
            .collect();
        strangers.sort_unstable();
        for (_, id) in strangers.into_iter().skip(w::QUARANTINE_SLOTS) {
            s.messages.remove(&id);
        }
        s
    }
}
