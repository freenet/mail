//! Inbox v2 states on the network: GET, PUT and UPDATE, each awaited.
//!
//! On a node, every answer reaches the page through the one response loop
//! (`api::node_comms`), which hands answers for v2 inboxes to [`route`]
//! before anything else looks at them. Answers carry no request id, so one
//! request per inbox and kind is out at a time and the next waits its turn;
//! an answer resolves the request out, and only it. A request that gets no
//! answer in time (or whose caller stops waiting) is [`NetError::Unknown`],
//! never success, failure or "absent", and it keeps its turn until its late
//! answer comes, which is consumed as its own, or for at most `LATE_MS`: only
//! then does the next request go out. Only a node's `NotFound` is
//! [`Got::Missing`].
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

/// Why a request did not answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum NetError {
    /// The node refused it, or it never reached the node.
    Failed(String),
    /// Sent, and no answer in time: it may have taken effect or not.
    Unknown,
}

impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetError::Failed(e) => f.write_str(e),
            NetError::Unknown => f.write_str(
                "the node did not answer in time, so whether it took the request is unknown",
            ),
        }
    }
}

impl From<String> for NetError {
    fn from(e: String) -> Self {
        NetError::Failed(e)
    }
}

impl From<&str> for NetError {
    fn from(e: &str) -> Self {
        NetError::Failed(e.to_string())
    }
}

impl From<NetError> for String {
    fn from(e: NetError) -> Self {
        e.to_string()
    }
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

/// `addr` is no longer one of this page's identities: its inbox's changes
/// are not this page's to drain.
pub(crate) fn forget_own_route(addr: &Addr) {
    let id = super::instance_id(addr);
    OWN.with(|o| o.borrow_mut().remove(&id));
}

/// Whether `addr` is one of this page's identities.
pub(crate) fn is_own(addr: &Addr) -> bool {
    own(&super::instance_id(addr)).is_some()
}

#[cfg(feature = "use-node")]
pub(crate) use node::{get, get_id, put, route, update};
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
    #[cfg(not(test))]
    const TIMEOUT_MS: u32 = 30_000;

    #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
    enum Kind {
        Get,
        Put,
        Update,
    }

    type Answer = Result<Got, NetError>;

    /// How long a request that got no answer in time (or whose caller
    /// stopped waiting) keeps its turn, waiting for its late answer.
    pub(super) const LATE_MS: i64 = 5 * 60_000;

    /// One inbox and kind's turn: the request out (its token), where its
    /// answer goes once the node took it, whether it stopped waiting for a
    /// late answer, and the requests waiting, in order.
    #[derive(Default)]
    struct Slot {
        out: Option<u64>,
        tx: Option<oneshot::Sender<Answer>>,
        /// The request out was sent and stopped waiting before its answer
        /// came: until this page time the next answer is its own, and is
        /// consumed; then the turn passes on.
        late_until: Option<i64>,
        queue: std::collections::VecDeque<(u64, oneshot::Sender<()>)>,
    }

    impl Slot {
        /// The request out is done: the next still waiting goes out (a
        /// cancelled one's receiver is gone, so it is passed over).
        fn release(&mut self) {
            self.out = None;
            self.tx = None;
            self.late_until = None;
            while let Some((next, tx)) = self.queue.pop_front() {
                if tx.send(()).is_ok() {
                    self.out = Some(next);
                    break;
                }
            }
        }

        /// A late request whose wait is over gives up its turn.
        fn expire(&mut self, now: i64) {
            if self.late_until.is_some_and(|until| now >= until) {
                self.release();
            }
        }

        fn idle(&self) -> bool {
            self.out.is_none() && self.queue.is_empty()
        }
    }

    fn now_ms() -> i64 {
        crate::mail_delegate::ops::now_ms()
    }

    type Slots = HashMap<(ContractInstanceId, Kind), Slot>;

    thread_local! {
        static SLOTS: RefCell<Slots> = RefCell::new(HashMap::new());
        static NEXT_TOKEN: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
        /// Every v2 inbox this page asked about: what the node says about
        /// them later (a notification of a followed recipient's inbox, a
        /// late answer) is this module's, and nobody else's.
        static KNOWN: RefCell<std::collections::HashSet<ContractInstanceId>> =
            RefCell::new(std::collections::HashSet::new());
    }

    fn known(id: &ContractInstanceId) -> bool {
        KNOWN.with(|k| k.borrow().contains(id))
    }

    /// Tests: whether any request for `id` and `kind` is out or waiting.
    #[cfg(test)]
    fn waiting(id: &ContractInstanceId, kind: Kind) -> bool {
        SLOTS.with(|s| s.borrow().contains_key(&(*id, kind)))
    }

    /// Give `a` to the request out for `id` and `kind`, if one waits for an
    /// answer; a request out that stopped waiting takes it as its own late
    /// answer, which is dropped, and the turn passes on. Returns whether the
    /// answer was taken.
    fn answer(id: &ContractInstanceId, kind: Kind, a: Answer) -> bool {
        let key = (*id, kind);
        let taken = SLOTS.with(|s| {
            let mut s = s.borrow_mut();
            let slot = s.get_mut(&key)?;
            if let Some(tx) = slot.tx.take() {
                return Some(Some(tx));
            }
            slot.late_until?;
            slot.release();
            if slot.idle() {
                s.remove(&key);
            }
            Some(None)
        });
        match taken {
            Some(Some(tx)) => {
                let _ = tx.send(a);
                true
            }
            Some(None) => true,
            None => false,
        }
    }

    /// A request's turn in its slot. Dropped, it leaves the slot: out of the
    /// queue; or, if it was out, the turn passes to the next still waiting,
    /// unless it was sent and its answer has not come (timed out, or the
    /// call cancelled), when it keeps the turn for its late answer.
    struct Turn {
        key: (ContractInstanceId, Kind),
        token: u64,
        /// Sent, and its answer not yet received.
        owed: bool,
    }

    #[cfg(not(test))]
    fn late_timer(ms: i64) -> impl std::future::Future<Output = ()> {
        gloo_timers::future::TimeoutFuture::new(u32::try_from(ms.max(0)).unwrap_or(u32::MAX))
    }

    #[cfg(test)]
    thread_local! {
        /// Tests: the late-answer timers running, fired by the test.
        static LATE_TIMERS: RefCell<Vec<oneshot::Sender<()>>> = const { RefCell::new(Vec::new()) };
    }

    #[cfg(test)]
    fn late_timer(_ms: i64) -> impl std::future::Future<Output = ()> {
        let (tx, rx) = oneshot::channel();
        LATE_TIMERS.with(|t| t.borrow_mut().push(tx));
        async move {
            let _ = rx.await;
        }
    }

    impl Turn {
        /// Wait for the turn: at once if nothing is out, else after every
        /// request queued before this one, and after a late request out has
        /// its answer or its wait is over.
        async fn take(id: ContractInstanceId, kind: Kind) -> Turn {
            use futures::FutureExt;
            let key = (id, kind);
            let token = NEXT_TOKEN.with(|n| {
                let t = n.get();
                n.set(t + 1);
                t
            });
            // From here a cancelled call leaves its place, whichever it holds.
            let turn = Turn {
                key,
                token,
                owed: false,
            };
            let wait = SLOTS.with(|s| {
                let mut s = s.borrow_mut();
                let slot = s.entry(key).or_default();
                slot.expire(now_ms());
                if slot.out.is_none() {
                    slot.out = Some(token);
                    None
                } else {
                    let (tx, rx) = oneshot::channel();
                    slot.queue.push_back((token, tx));
                    Some(rx)
                }
            });
            let Some(rx) = wait else {
                return turn;
            };
            // Only a release hands the turn on, and it sets `out` first. A
            // late request's wait is timed here, by whoever waits behind it.
            let mut rx = rx.fuse();
            loop {
                let until = SLOTS.with(|s| s.borrow().get(&key).and_then(|sl| sl.late_until));
                let ms = until.map_or(LATE_MS, |u| u - now_ms());
                let mut timer = Box::pin(late_timer(ms)).fuse();
                futures::select! {
                    _ = rx => return turn,
                    _ = timer => SLOTS.with(|s| {
                        if let Some(slot) = s.borrow_mut().get_mut(&key) {
                            slot.expire(now_ms());
                        }
                    }),
                }
            }
        }

        /// Where this request's answer will come.
        fn expect_answer(&self) -> oneshot::Receiver<Answer> {
            let (tx, rx) = oneshot::channel();
            SLOTS.with(|s| {
                if let Some(slot) = s.borrow_mut().get_mut(&self.key)
                    && slot.out == Some(self.token)
                {
                    slot.tx = Some(tx);
                }
            });
            rx
        }
    }

    impl Drop for Turn {
        fn drop(&mut self) {
            SLOTS.with(|s| {
                let mut s = s.borrow_mut();
                let Some(slot) = s.get_mut(&self.key) else {
                    return;
                };
                if slot.out == Some(self.token) {
                    if self.owed {
                        // Its answer may still come: it is this request's.
                        slot.tx = None;
                        slot.late_until = Some(now_ms() + LATE_MS);
                    } else {
                        slot.release();
                    }
                } else {
                    slot.queue.retain(|(t, _)| *t != self.token);
                }
                if slot.idle() {
                    s.remove(&self.key);
                }
            });
        }
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
                    answer(key.id(), kind, Err(NetError::Failed(cause.to_string())))
                }
                _ => false,
            },
            _ => false,
        }
    }

    async fn ask(addr: &Addr, kind: Kind, request: ContractRequest<'static>) -> Answer {
        ask_id(super::super::instance_id(addr), kind, request).await
    }

    #[cfg(test)]
    thread_local! {
        /// Tests: the client requests go to, in place of the node's.
        static TEST_SENDER: RefCell<Option<crate::api::WebApiRequestClient>> =
            const { RefCell::new(None) };
    }

    fn sender() -> Option<crate::api::WebApiRequestClient> {
        #[cfg(test)]
        if let Some(s) = TEST_SENDER.with(|t| t.borrow().clone()) {
            return Some(s);
        }
        crate::api::WEB_API_SENDER.get().cloned()
    }

    /// Hand `request` to the node, holding `turn`. The inbox is known only
    /// once the node took it.
    async fn send_request(
        turn: &mut Turn,
        request: ContractRequest<'static>,
    ) -> Result<oneshot::Receiver<Answer>, NetError> {
        let mut client = sender().ok_or("not connected to the node")?;
        let rx = turn.expect_answer();
        if let Err(e) = client.send(request.into()).await {
            return Err(NetError::Failed(format!(
                "the node did not take the request: {e}"
            )));
        }
        // From here an answer is owed to this request.
        turn.owed = true;
        // Known only once the node took a request: until then no GET of it,
        // and so no code-bearing one, reached the node.
        KNOWN.with(|k| k.borrow_mut().insert(turn.key.0));
        Ok(rx)
    }

    #[cfg(not(test))]
    fn timeout() -> impl std::future::Future<Output = ()> {
        gloo_timers::future::TimeoutFuture::new(TIMEOUT_MS)
    }

    #[cfg(test)]
    thread_local! {
        /// Tests: the timers running, fired by the test in place of a clock.
        static TIMERS: RefCell<Vec<oneshot::Sender<()>>> = const { RefCell::new(Vec::new()) };
    }

    #[cfg(test)]
    fn timeout() -> impl std::future::Future<Output = ()> {
        let (tx, rx) = oneshot::channel();
        TIMERS.with(|t| t.borrow_mut().push(tx));
        async move {
            let _ = rx.await;
        }
    }

    async fn ask_id(
        id: ContractInstanceId,
        kind: Kind,
        request: ContractRequest<'static>,
    ) -> Answer {
        // Held until this returns or is dropped: the next request for this
        // inbox and kind goes out only then, or, if this one got no answer,
        // once its late answer came or its wait is over.
        let mut turn = Turn::take(id, kind).await;
        let rx = send_request(&mut turn, request).await?;
        use futures::FutureExt;
        let mut rx = rx.fuse();
        let mut timer = Box::pin(timeout()).fuse();
        futures::select! {
            a = rx => {
                turn.owed = false;
                a.unwrap_or(Err(NetError::Unknown))
            }
            _ = timer => Err(NetError::Unknown),
        }
    }

    /// The inbox's state. `subscribe` also follows its changes (own inboxes).
    pub(crate) async fn get(addr: &Addr, subscribe: bool) -> Answer {
        let request = get_request(super::super::instance_id(addr), subscribe);
        ask(addr, Kind::Get, request).await
    }

    fn get_request(id: ContractInstanceId, subscribe: bool) -> ContractRequest<'static> {
        // The first GET of an inbox asks for its code too: a node applies an
        // UPDATE it sends only to a contract whose code it holds (#191).
        ContractRequest::Get {
            key: id,
            return_contract_code: !known(&id),
            subscribe,
            blocking_subscribe: false,
        }
    }

    /// Another contract's state (the Ghost Key vault's pointer record),
    /// without its code and without following it.
    pub(crate) async fn get_id(id: ContractInstanceId) -> Answer {
        let request = ContractRequest::Get {
            key: id,
            return_contract_code: false,
            subscribe: false,
            blocking_subscribe: false,
        };
        ask_id(id, Kind::Get, request).await
    }

    /// Publish a whole state, and hold and follow the inbox.
    pub(crate) async fn put(addr: &Addr, state: Vec<u8>) -> Result<(), NetError> {
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
    pub(crate) async fn update(addr: &Addr, delta: Vec<u8>) -> Result<(), NetError> {
        let request = ContractRequest::Update {
            key: super::super::key(addr),
            data: UpdateData::Delta(delta.into()),
        };
        ask(addr, Kind::Update, request).await.map(|_| ())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn asks_for_code(request: &ContractRequest<'static>) -> bool {
            matches!(
                request,
                ContractRequest::Get {
                    return_contract_code: true,
                    ..
                }
            )
        }

        /// A GET the node never took did not fetch the code: the next one
        /// must still ask for it (#191). With no connection, and with one the
        /// node closed (the request is refused at the send).
        #[test]
        fn a_get_that_was_never_sent_leaves_the_code_to_fetch() {
            let addr = Addr([0x5c; 24]);
            let id = super::super::super::instance_id(&addr);
            assert!(futures::executor::block_on(get(&addr, false)).is_err());
            assert!(!known(&id), "an unsent GET marked the inbox known");

            let (tx, rx) = futures::channel::mpsc::unbounded();
            let (responses, _) = futures::channel::mpsc::unbounded();
            drop(rx);
            TEST_SENDER.with(|t| {
                *t.borrow_mut() = Some(crate::api::WebApiRequestClient::for_tests(tx, responses))
            });
            let sent = futures::executor::block_on(async {
                let mut turn = Turn::take(id, Kind::Get).await;
                send_request(&mut turn, get_request(id, false))
                    .await
                    .map(|_| ())
            });
            TEST_SENDER.with(|t| t.borrow_mut().take());
            assert!(sent.is_err(), "the closed connection took it");
            assert!(!known(&id), "a GET the node refused marked the inbox known");
            assert!(asks_for_code(&get_request(id, false)));
        }

        type Requests = futures::channel::mpsc::UnboundedReceiver<
            freenet_stdlib::client_api::ClientRequest<'static>,
        >;

        /// Requests go to a client whose other end the test reads.
        fn connect() -> Requests {
            let (tx, rx) = futures::channel::mpsc::unbounded();
            let (responses, _) = futures::channel::mpsc::unbounded();
            TEST_SENDER.with(|t| {
                *t.borrow_mut() = Some(crate::api::WebApiRequestClient::for_tests(tx, responses))
            });
            rx
        }

        fn disconnect() {
            TEST_SENDER.with(|t| t.borrow_mut().take());
            TIMERS.with(|t| t.borrow_mut().clear());
        }

        fn sent(requests: &mut Requests) -> usize {
            std::iter::from_fn(|| requests.try_recv().ok()).count()
        }

        fn update_request(addr: &Addr) -> ContractRequest<'static> {
            ContractRequest::Update {
                key: super::super::super::key(addr),
                data: UpdateData::Delta(vec![1].into()),
            }
        }

        fn updated(addr: &Addr) -> Result<HostResponse, ClientError> {
            Ok(HostResponse::ContractResponse(
                ContractResponse::UpdateResponse {
                    key: super::super::super::key(addr),
                    summary: Vec::new().into(),
                },
            ))
        }

        fn update_failed(addr: &Addr) -> Result<HostResponse, ClientError> {
            Err(ClientError::from(ErrorKind::RequestError(
                RequestError::ContractError(ContractError::Update {
                    key: super::super::super::key(addr),
                    cause: "refused".into(),
                }),
            )))
        }

        type Outcome = std::rc::Rc<RefCell<Option<Answer>>>;

        /// Start an UPDATE of `addr` on `pool`; its answer lands in the result.
        fn start_update(pool: &futures::executor::LocalPool, addr: Addr) -> Outcome {
            use futures::task::LocalSpawnExt;
            let out: Outcome = Default::default();
            let o = out.clone();
            pool.spawner()
                .spawn_local(async move {
                    let a = ask(&addr, Kind::Update, update_request(&addr)).await;
                    *o.borrow_mut() = Some(a);
                })
                .unwrap();
            out
        }

        /// Two UPDATEs of one inbox overlap and the second fails: each is
        /// told its own outcome. Answers carry no request id, so the second
        /// goes out only once the first is answered.
        #[test]
        fn overlapping_updates_are_each_told_their_own_outcome() {
            let addr = Addr([0x5e; 24]);
            let mut requests = connect();
            let mut pool = futures::executor::LocalPool::new();
            let first = start_update(&pool, addr);
            let second = start_update(&pool, addr);
            pool.run_until_stalled();
            let first_routed = route(&updated(&addr));
            pool.run_until_stalled();
            let second_routed = route(&update_failed(&addr));
            pool.run_until_stalled();
            disconnect();
            assert_eq!(*first.borrow(), Some(Ok(Got::Missing)));
            assert!(
                matches!(*second.borrow(), Some(Err(_))),
                "the second UPDATE failed but was reported {:?}",
                second.borrow()
            );
            assert!(first_routed && second_routed, "each answer was taken");
            assert_eq!(sent(&mut requests), 2);
        }

        type Timers = std::thread::LocalKey<RefCell<Vec<oneshot::Sender<()>>>>;

        fn fire(timers: &'static Timers) {
            timers.with(|t| {
                t.borrow_mut().drain(..).for_each(|t| {
                    let _ = t.send(());
                })
            });
        }

        type Response = fn(&Addr) -> Result<HostResponse, ClientError>;

        /// Class C: UPDATE A times out and is told the outcome is unknown; B
        /// waits behind it. A's late answer arrives: it is A's, consumed, and
        /// only then is B sent, to be told its own answer. Once with a late
        /// success followed by B failing, once with a late failure followed
        /// by B succeeding.
        #[test]
        fn a_late_answer_is_the_timed_out_requests_and_the_next_waits_for_it() {
            let cases: [(Response, Response, bool); 2] = [
                (updated, update_failed, false),
                (update_failed, updated, true),
            ];
            for (n, (late, own, b_ok)) in cases.into_iter().enumerate() {
                let addr = Addr([0x5f + n as u8; 24]);
                let id = super::super::super::instance_id(&addr);
                let mut requests = connect();
                let mut pool = futures::executor::LocalPool::new();
                let a = start_update(&pool, addr);
                pool.run_until_stalled();
                fire(&TIMERS);
                pool.run_until_stalled();
                assert_eq!(
                    *a.borrow(),
                    Some(Err(NetError::Unknown)),
                    "never success or failure"
                );
                let b = start_update(&pool, addr);
                pool.run_until_stalled();
                assert_eq!(sent(&mut requests), 1, "B waits for A's answer");
                assert!(route(&late(&addr)), "A's late answer is taken");
                pool.run_until_stalled();
                assert_eq!(*b.borrow(), None, "A's answer resolved B");
                assert_eq!(sent(&mut requests), 1, "B goes out after A's answer");
                assert!(route(&own(&addr)));
                pool.run_until_stalled();
                let told = b.borrow().clone();
                if b_ok {
                    assert_eq!(told, Some(Ok(Got::Missing)), "B was told {told:?}");
                } else {
                    assert!(
                        matches!(told, Some(Err(NetError::Failed(_)))),
                        "B was told {told:?}"
                    );
                }
                assert!(
                    !waiting(&id, Kind::Update),
                    "an answered request left its slot"
                );
                assert!(
                    !answer(&id, Kind::Update, Ok(Got::Missing)),
                    "a later answer found a request to resolve"
                );
                disconnect();
            }
        }

        /// A late answer that never comes holds the turn for `LATE_MS` and
        /// no longer: then the next request goes out.
        #[test]
        fn a_late_answer_is_waited_for_only_so_long() {
            let addr = Addr([0x7a; 24]);
            let mut requests = connect();
            let mut pool = futures::executor::LocalPool::new();
            let a = start_update(&pool, addr);
            pool.run_until_stalled();
            fire(&TIMERS);
            pool.run_until_stalled();
            assert_eq!(*a.borrow(), Some(Err(NetError::Unknown)));
            let b = start_update(&pool, addr);
            pool.run_until_stalled();
            // A timer that fires early lets nothing out.
            fire(&LATE_TIMERS);
            pool.run_until_stalled();
            assert_eq!(sent(&mut requests), 1, "the late answer's wait is not over");
            futures::executor::block_on(crate::mail_delegate::ops::pause_ms(LATE_MS as u32));
            fire(&LATE_TIMERS);
            pool.run_until_stalled();
            assert_eq!(sent(&mut requests), 1, "B goes out once the wait is over");
            assert!(route(&updated(&addr)));
            pool.run_until_stalled();
            disconnect();
            assert_eq!(*b.borrow(), Some(Ok(Got::Missing)));
        }

        /// A call dropped while it waits its turn leaves the queue. One
        /// dropped while out, after it was sent, keeps the turn for its
        /// answer, which is consumed as its own; the next goes out after.
        #[test]
        fn a_cancelled_request_gives_up_its_place() {
            use futures::FutureExt;
            let addr = Addr([0x60; 24]);
            let id = super::super::super::instance_id(&addr);
            let mut requests = connect();
            let mut out = Box::pin(ask(&addr, Kind::Update, update_request(&addr)));
            let mut queued = Box::pin(ask(&addr, Kind::Update, update_request(&addr)));
            assert!(
                (&mut out).now_or_never().is_none(),
                "out, waiting for its answer"
            );
            assert!((&mut queued).now_or_never().is_none(), "waiting its turn");
            drop(queued);
            drop(out);
            assert_eq!(sent(&mut requests), 1);
            let mut pool = futures::executor::LocalPool::new();
            let next = start_update(&pool, addr);
            pool.run_until_stalled();
            assert_eq!(
                sent(&mut requests),
                0,
                "the cancelled request's answer is owed"
            );
            assert!(route(&update_failed(&addr)), "its late answer is taken");
            pool.run_until_stalled();
            assert_eq!(sent(&mut requests), 1);
            assert!(route(&updated(&addr)));
            pool.run_until_stalled();
            disconnect();
            assert_eq!(*next.borrow(), Some(Ok(Got::Missing)));
            assert!(!waiting(&id, Kind::Update), "cancelled calls left waiters");
        }

        /// A GET the node took fetched the code: the next one does not.
        #[test]
        fn a_get_the_node_took_marks_the_code_fetched() {
            let id = super::super::super::instance_id(&Addr([0x5d; 24]));
            let (tx, mut rx) = futures::channel::mpsc::unbounded();
            let (responses, _) = futures::channel::mpsc::unbounded();
            TEST_SENDER.with(|t| {
                *t.borrow_mut() = Some(crate::api::WebApiRequestClient::for_tests(tx, responses))
            });
            let first = get_request(id, false);
            assert!(asks_for_code(&first));
            let sent = futures::executor::block_on(async {
                let mut turn = Turn::take(id, Kind::Get).await;
                send_request(&mut turn, first).await.map(|_| ())
            });
            TEST_SENDER.with(|t| t.borrow_mut().take());
            assert!(sent.is_ok());
            assert!(rx.try_recv().is_ok(), "the node got it");
            assert!(known(&id));
            assert!(!asks_for_code(&get_request(id, false)));
        }
    }
}

/// The offline build's inboxes, in this page.
///
/// The model checks only what the UI's outcomes need: the newest owner
/// version, unions, tombstones, revocation by pass id, the Ghost Key proof and
/// the 16 quarantine slots. It does not check pass signatures, certificate
/// expiry, epochs (`prev_epoch_until`), the send window, `per_invite`, the
/// per-Ghost-Key cap or the 88-message cap, and it keeps the first of two
/// messages with one id. Those are proven by the contract's own suite and by
/// the delegate's interop tests (`delegates/mail-delegate/src/tests/inbox_v2.rs`
/// runs everything the delegate builds through the contract's `apply` and
/// `is_valid`), so an offline test passing says nothing about them. A test
/// here must not claim to cover them.
#[cfg(not(feature = "use-node"))]
pub(crate) mod offline {
    use super::*;
    use freenet_mail_protocol::inbox_v2::{
        self as w, Admission, InboxDelta, InboxState, QuarantineMode,
    };

    thread_local! {
        static STATES: RefCell<HashMap<ContractInstanceId, Vec<u8>>> = RefCell::new(HashMap::new());
        /// Tests: updates to an inbox held back until that many more GETs
        /// of it, as on a slow network.
        #[cfg(test)]
        static SLOW: RefCell<HashMap<ContractInstanceId, Held>> = RefCell::new(HashMap::new());
    }

    /// Tests: GETs still to answer before the held updates apply, and them.
    #[cfg(test)]
    type Held = (u32, Vec<Vec<u8>>);

    /// Tests: hold every update to `addr` back, and apply them once `gets`
    /// GETs of it were answered while one waited.
    #[cfg(test)]
    pub(crate) fn slow_updates(addr: &Addr, gets: u32) {
        let id = super::super::instance_id(addr);
        SLOW.with(|s| s.borrow_mut().insert(id, (gets, Vec::new())));
    }

    thread_local! {
        /// Tests: the next PUT of an inbox never reaches the network, and
        /// the page is told this.
        #[cfg(test)]
        static LOSE_PUT: RefCell<HashMap<ContractInstanceId, Result<(), String>>> =
            RefCell::new(HashMap::new());
    }

    thread_local! {
        /// Tests: every inbox a GET asked to follow.
        #[cfg(test)]
        static SUBSCRIBED: RefCell<std::collections::HashSet<ContractInstanceId>> =
            RefCell::new(std::collections::HashSet::new());
    }

    /// Tests: whether a GET asked to follow `addr`'s inbox.
    #[cfg(test)]
    pub(crate) fn subscribed(addr: &Addr) -> bool {
        let id = super::super::instance_id(addr);
        SUBSCRIBED.with(|s| s.borrow().contains(&id))
    }

    /// Tests: `addr` is not one of this page's identities (another node's).
    #[cfg(test)]
    pub(crate) fn forget_own(addr: &Addr) {
        let id = super::super::instance_id(addr);
        OWN.with(|o| o.borrow_mut().remove(&id));
        SUBSCRIBED.with(|s| s.borrow_mut().remove(&id));
    }

    /// Tests: the next PUT of `addr` is not stored; it answers `answer`
    /// (an error for a rejected or unanswered PUT, `Ok` for one whose
    /// answer came but whose state went nowhere).
    #[cfg(test)]
    pub(crate) fn lose_next_put(addr: &Addr, answer: Result<(), String>) {
        let id = super::super::instance_id(addr);
        LOSE_PUT.with(|l| l.borrow_mut().insert(id, answer));
    }

    #[cfg(test)]
    fn held_back(addr: &Addr, delta: &[u8]) -> bool {
        let id = super::super::instance_id(addr);
        SLOW.with(|s| match s.borrow_mut().get_mut(&id) {
            Some((_, held)) => {
                held.push(delta.to_vec());
                true
            }
            None => false,
        })
    }

    /// Tests: count a GET against the held updates, and apply them once due.
    #[cfg(test)]
    fn tick(addr: &Addr) {
        let id = super::super::instance_id(addr);
        let due = SLOW.with(|s| {
            let mut s = s.borrow_mut();
            let (left, held) = s.get_mut(&id)?;
            if held.is_empty() {
                return None;
            }
            *left = left.saturating_sub(1);
            if *left > 0 {
                return None;
            }
            s.remove(&id).map(|(_, h)| h)
        });
        for delta in due.unwrap_or_default() {
            let held = STATES.with(|s| s.borrow().get(&id).cloned());
            if let Some(held) = held
                && let Ok(d) = w::decode::<InboxDelta>(&delta)
                && let Ok(merged) = merge(&held, d)
            {
                store(addr, merged);
            }
        }
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

    pub(crate) async fn get(addr: &Addr, subscribe: bool) -> Result<Got, NetError> {
        let id = super::super::instance_id(addr);
        #[cfg(test)]
        tick(addr);
        #[cfg(test)]
        if subscribe {
            SUBSCRIBED.with(|s| s.borrow_mut().insert(id));
        }
        let _ = subscribe;
        Ok(STATES
            .with(|s| s.borrow().get(&id).cloned())
            .map_or(Got::Missing, Got::State))
    }

    pub(crate) async fn put(addr: &Addr, state: Vec<u8>) -> Result<(), NetError> {
        let id = super::super::instance_id(addr);
        #[cfg(test)]
        if let Some(answer) = LOSE_PUT.with(|l| l.borrow_mut().remove(&id)) {
            return answer.map_err(NetError::Failed);
        }
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

    pub(crate) async fn update(addr: &Addr, delta: Vec<u8>) -> Result<(), NetError> {
        let id = super::super::instance_id(addr);
        let held = STATES
            .with(|s| s.borrow().get(&id).cloned())
            .ok_or("no such inbox")?;
        #[cfg(test)]
        if held_back(addr, &delta) {
            return Ok(());
        }
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

    /// The decision-25 fixture (`owner::another_node_signs`): `addr`'s inbox
    /// becomes `bytes`, as another node's update would make it, without
    /// telling this page.
    #[cfg(any(test, feature = "example-data"))]
    pub(crate) fn store_unannounced(addr: &Addr, bytes: Vec<u8>) {
        let id = super::super::instance_id(addr);
        #[cfg(feature = "local-delegate")]
        crate::mail_delegate::local::set_contract_state(
            id.as_bytes().try_into().expect("32 bytes"),
            bytes.clone(),
        );
        STATES.with(|s| s.borrow_mut().insert(id, bytes));
    }

    /// The contract's checks on a Ghost Key proof (decision 1): the pinned
    /// requestor, the payload binding this message, the signature, the chain
    /// to the inbox's master, and the tier.
    fn proven(addr: Addr, m: &w::Message, p: &w::GhostProof, min_usd: u32) -> bool {
        let Ok(cert) = ghostkey_verify::GhostkeyCertificate::from_cbor(&p.cert) else {
            return false;
        };
        let Ok(scoped) =
            ghostkey_common::from_cbor::<ghostkey_common::ScopedPayload>(&p.scoped_payload)
        else {
            return false;
        };
        let ct_hash = *blake3::hash(&m.ciphertext).as_bytes();
        let ghostkey_common::SignatureRequestor::WebApp(requestor) = scoped.requestor else {
            return false;
        };
        let pinned =
            bs58::decode(include_str!("../../../published-contract/contract-id.txt").trim())
                .into_vec()
                .unwrap_or_default();
        let master = ed25519_dalek::VerifyingKey::from_bytes(&super::super::ghost_master());
        requestor.as_bytes() == pinned.as_slice()
            && scoped.payload == w::ghost_admit_bytes(&addr.0, m.sent_time, &ct_hash)
            && ghostkey_verify::verify_payload_signature(
                cert.claimed_ghost_key(),
                &p.scoped_payload,
                p.ghost_sig.as_slice(),
            )
            .is_ok()
            && master
                .ok()
                .and_then(|master| cert.verify(&master).ok()?.notary_info().ok())
                .is_some_and(|i| i.action == "freenet-donation" && i.amount >= u64::from(min_usd))
    }

    pub(crate) fn filter(mut s: InboxState) -> InboxState {
        let addr = freenet_mail_protocol::address::address_of(&s.owner.owner_vk);
        let owner = s.owner.clone();
        let revoked = s.revoked.clone();
        s.messages.retain(|id, m| {
            !owner.tombstones.contains_key(id)
                && match &m.admission {
                    Admission::Pass { cert, .. } => !revoked.contains_key(&cert.pass_id),
                    Admission::Owner { .. } => true,
                    Admission::Quarantine { ghost } => match (owner.quarantine, ghost) {
                        (QuarantineMode::Open, ghost) => ghost.is_none(),
                        (QuarantineMode::RequireGhost { .. }, None) => false,
                        (QuarantineMode::RequireGhost { min_usd }, Some(p)) => {
                            proven(addr, m, p, min_usd.unwrap_or(0))
                        }
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
