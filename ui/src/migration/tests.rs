//! The walk, end to end: `freenet_migrate`'s real driver over a scripted
//! legacy node, importing into the real mail delegate's handlers.
//!
//! Old-format inputs come only from `wire-v1/src/golden_v1.txt`, the bytes
//! captured through the frozen crates. A test that needs a variation edits
//! that JSON as text; none builds an old reply with today's types.
//!
//! Tests named `scenario_*` go through the crate's walk, as do the silence
//! and back-off tests: replacing its entry point with a panic fails exactly
//! those (the PR records the run).

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;

use freenet_mail_protocol::address::address_of;
use freenet_mail_protocol::{
    Addr, Failure, FailureCode, IdentityInfo, Item, ItemKind, ItemRef, Op, PROTOCOL_VERSION, Reply,
    Request, RequestId, Response, from_cbor, to_cbor,
};
use freenet_mail_wire_v1::local_state::{ArchivedMessage, Draft, KeptMessage, SentMessage};
use freenet_migrate::{JournalStatus, PredecessorMigration};
use freenet_stdlib::prelude::{
    ApplicationMessage, ContractInstanceId, DelegateKey, InboundDelegateMsg, MessageOrigin,
    OutboundDelegateMsg,
};
use futures::executor::block_on;
use mail_delegate::env::Env;

use super::legacy_delegates::{
    AliasOwner, AliasTables, HOLD_BACK_LOADS, LegacyReply, LegacyTransport, MAX_LEGACY_REPLY_BYTES,
    MappingCounts, NewerAliases, PairKey, lineage_key, map_local_state,
};
use super::successor::{
    MailStore, MergedFlags, StoredMarker, V1InboxReader, adopt_legacy_markers, merge_fields,
};
use super::*;
use crate::app::identity_store::{MigrationMarkers, markers_from_body};
use crate::legacy_registry::{IDENTITY_LINEAGE, LOCAL_STATE_LINEAGE};
use crate::mail_delegate::CallError;

const ORIGIN: [u8; 32] = [0x4d; 32];

fn golden(name: &str) -> Vec<u8> {
    let hex = include_str!("../../../wire-v1/src/golden_v1.txt")
        .lines()
        .find_map(|l| l.strip_prefix(name)?.strip_prefix(' '))
        .unwrap_or_else(|| panic!("no golden sample {name}"));
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// A golden reply with `from` replaced by `to` in its text.
fn golden_edited(name: &str, from: &str, to: &str) -> Vec<u8> {
    edited(golden(name), from, to)
}

fn edited(reply: Vec<u8>, from: &str, to: &str) -> Vec<u8> {
    let text = String::from_utf8(reply).unwrap();
    assert!(text.contains(from), "{from} not in the reply");
    text.replace(from, to).into_bytes()
}

/// The golden identity, its recorded contract state replaced.
fn identity_with_markers(inbox: &str, pending: &str, aft: &str, pending_aft: &str) -> Vec<u8> {
    let reply = golden("identity_state_seeded");
    let reply = edited(reply, r#""inbox_wasm_hash":"a""#, inbox);
    let reply = edited(reply, r#""pending_migration_from":"b""#, pending);
    let reply = edited(reply, r#""aft_record_wasm_hash":"c""#, aft);
    edited(reply, r#""pending_aft_migration_from":"d""#, pending_aft)
}

#[derive(Default)]
struct TestEnv {
    secrets: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl Env for TestEnv {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.secrets.get(key).cloned()
    }
    fn set(&mut self, key: &[u8], value: &[u8]) -> bool {
        self.secrets.insert(key.to_vec(), value.to_vec());
        true
    }
    fn remove(&mut self, key: &[u8]) -> bool {
        self.secrets.remove(key).is_some()
    }
    fn host_random(&mut self) -> [u8; 32] {
        crate::rng::random_bytes()
    }
    fn now_secs(&self) -> Option<u64> {
        Some(1_761_000_000)
    }
    fn contract_state(&self, _: &[u8; 32]) -> Option<Vec<u8>> {
        None
    }
}

/// The real delegate over a store that survives "page loads". After
/// `writes_left` writes every call stops being answered, as when a tab dies.
#[derive(Clone)]
struct Delegate {
    env: Rc<RefCell<TestEnv>>,
    writes_left: Rc<RefCell<Option<usize>>>,
    writes_seen: Rc<RefCell<usize>>,
    faults: Rc<RefCell<Faults>>,
}

/// Answers the delegate is made to give.
#[derive(Default)]
struct Faults {
    /// The next create of this kind answers `Conflict` and stores nothing.
    false_conflict: Option<ItemKind>,
    /// Every create of this kind answers `CapReached`.
    capped: Option<ItemKind>,
    /// Every identity import answers this.
    import_fails: Option<FailureCode>,
    /// Every write of an identity's items answers `Refused`.
    owned_writes_refused: bool,
}

impl Delegate {
    fn new() -> Self {
        Delegate {
            env: Rc::new(RefCell::new(TestEnv::default())),
            writes_left: Rc::new(RefCell::new(None)),
            writes_seen: Rc::new(RefCell::new(0)),
            faults: Rc::new(RefCell::new(Faults::default())),
        }
    }

    /// Make the record of `item` read as absent while its index still lists
    /// it: what the delegate answers `Unreadable` for.
    fn blind(&self, item: &ItemRef) {
        let rel = mail_delegate::store::item_rel(item).into_bytes();
        let mut env = self.env.borrow_mut();
        let before = env.secrets.len();
        env.secrets.retain(|key, _| !key.ends_with(&rel));
        assert_eq!(env.secrets.len(), before - 1, "one record");
    }

    /// Make an identity's record read as absent while the index lists it, and
    /// return it. The delegate cannot tell that from a deleted record.
    fn hide_identity(&self, addr: Addr) -> (Vec<u8>, Vec<u8>) {
        let rel = mail_delegate::store::identity_rel(&addr).into_bytes();
        let mut env = self.env.borrow_mut();
        let key = env
            .secrets
            .keys()
            .find(|key| key.ends_with(&rel))
            .cloned()
            .expect("the identity is stored");
        let value = env.secrets.remove(&key).unwrap();
        (key, value)
    }

    fn restore_identity(&self, (key, value): (Vec<u8>, Vec<u8>)) {
        self.env.borrow_mut().secrets.insert(key, value);
    }

    fn fault(&self, op: &Op) -> Option<FailureCode> {
        let mut faults = self.faults.borrow_mut();
        match op {
            Op::ImportIdentity { .. } => faults.import_fails,
            Op::PutItem { item, .. } if faults.owned_writes_refused && item.owner.is_some() => {
                Some(FailureCode::Refused)
            }
            Op::PutItem {
                item,
                expected_gen: None,
                ..
            } if faults.capped == Some(item.kind) => Some(FailureCode::CapReached),
            Op::PutItem {
                item,
                expected_gen: None,
                ..
            } if faults.false_conflict == Some(item.kind) => {
                faults.false_conflict = None;
                Some(FailureCode::Conflict { current_gen: 0 })
            }
            _ => None,
        }
    }

    fn die_after(&self, writes: usize) {
        *self.writes_left.borrow_mut() = Some(writes);
    }

    fn revive(&self) {
        *self.writes_left.borrow_mut() = None;
    }

    fn send(&self, op: Op) -> Result<Reply, CallError> {
        let request = Request {
            version: PROTOCOL_VERSION,
            request_id: RequestId([1; 16]),
            op,
        };
        let inbound = InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(
            to_cbor(&request).unwrap(),
        ));
        let origin = MessageOrigin::WebApp(ContractInstanceId::new(ORIGIN));
        let mut env = self.env.borrow_mut();
        let out = mail_delegate::handlers::process(&mut *env, Some(origin), inbound)
            .map_err(|e| CallError::Unknown(e.to_string()))?;
        let Some(OutboundDelegateMsg::ApplicationMessage(app)) = out.into_iter().next() else {
            return Err(CallError::Unknown("no response".into()));
        };
        let response: Response = from_cbor(&app.payload).unwrap();
        response.result.map_err(CallError::Failed)
    }

    fn list(&self, kind: ItemKind, owner: Option<Addr>) -> Vec<Item> {
        match self.send(Op::ListItems {
            kind,
            owner,
            after: None,
            limit: 256,
        }) {
            Ok(Reply::Items { items, .. }) => items,
            other => panic!("{other:?}"),
        }
    }

    fn identities(&self) -> Vec<IdentityInfo> {
        match self.send(Op::ListIdentities) {
            Ok(Reply::Identities(list)) => list,
            other => panic!("{other:?}"),
        }
    }

    fn item(&self, kind: ItemKind, owner: Option<Addr>) -> Option<Item> {
        match self.send(Op::GetItem {
            item: ItemRef {
                kind,
                owner,
                id: Vec::new(),
            },
        }) {
            Ok(Reply::Item(item)) => item,
            other => panic!("{other:?}"),
        }
    }

    fn ledger(&self) -> super::ledger::Ledger {
        block_on(super::ledger::read_ledger(&mut self.clone())).unwrap()
    }

    fn markers_written(&self) -> Vec<StoredMarker> {
        let ledger = super::ledger::ledger_item().id;
        self.list(ItemKind::MigrationMarker, None)
            .iter()
            .filter(|i| i.item.id != ledger)
            .map(|i| serde_json::from_slice(&i.body).unwrap())
            .collect()
    }
}

impl MailStore for Delegate {
    async fn call(&mut self, op: Op) -> Result<Reply, CallError> {
        let write = matches!(op, Op::PutItem { .. } | Op::ImportIdentity { .. });
        let mut left = self.writes_left.borrow_mut();
        if let Some(n) = left.as_mut() {
            if *n == 0 {
                return Err(CallError::Unknown("the tab died".into()));
            }
            if write {
                *n -= 1;
            }
        }
        drop(left);
        if write {
            *self.writes_seen.borrow_mut() += 1;
        }
        if let Some(code) = self.fault(&op) {
            return Err(CallError::Failed(Failure {
                code,
                detail: "injected".into(),
            }));
        }
        self.send(op)
    }
}

/// A scripted node. A delegate with no script is typed "not installed".
#[derive(Clone, Default)]
struct Node {
    replies: Rc<RefCell<HashMap<[u8; 32], LegacyReply>>>,
    asked: Rc<RefCell<Vec<Asked>>>,
}

/// One request: the delegate, the parameters and the message.
type Asked = (DelegateKey, Vec<u8>, Vec<u8>);

/// One list's items, as `(id, body)`.
type Listed = Vec<(Vec<u8>, Vec<u8>)>;

impl Node {
    fn set(&self, entry: &freenet_migrate::DelegateLineageEntry, reply: LegacyReply) {
        self.replies.borrow_mut().insert(entry.delegate_key, reply);
    }
}

impl LegacyTransport for Node {
    async fn ask(
        &mut self,
        predecessor: &DelegateKey,
        params: &'static [u8],
        request: Vec<u8>,
    ) -> LegacyReply {
        self.asked
            .borrow_mut()
            .push((predecessor.clone(), params.to_vec(), request));
        self.replies
            .borrow()
            .get(&<[u8; 32]>::try_from(predecessor.bytes()).unwrap())
            .cloned()
            .unwrap_or(LegacyReply::NotInstalled)
    }
}

#[derive(Clone)]
struct Inbox(Option<Vec<Vec<u8>>>);

impl V1InboxReader for Inbox {
    async fn ciphertexts(&mut self, _: &[u8]) -> Option<Vec<Vec<u8>>> {
        self.0.clone()
    }

    async fn has_inbox(&mut self, _: &[u8], _: &str) -> bool {
        false
    }
}

fn no_inbox() -> Inbox {
    Inbox(None)
}

fn im(release: u32) -> &'static freenet_migrate::DelegateLineageEntry {
    IDENTITY_LINEAGE
        .iter()
        .find(|e| e.generation == release)
        .unwrap()
}

fn ls(release: u32) -> &'static freenet_migrate::DelegateLineageEntry {
    LOCAL_STATE_LINEAGE
        .iter()
        .find(|e| e.generation == release)
        .unwrap()
}

fn answer(bytes: Vec<u8>) -> LegacyReply {
    LegacyReply::Answer(bytes)
}

fn walk(delegate: &Delegate, node: &Node, inbox: Inbox) -> WalkOutcome {
    block_on(run(delegate.clone(), node.clone(), inbox, 0, || {}))
}

/// The address the golden `identity_state_seeded` seeds derive.
fn alice() -> Addr {
    use ml_dsa::signature::Keypair;
    let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&[9u8; 32].into());
    address_of(&sk.verifying_key().encode())
}

/// A node where a user ran v0.2.7 with one identity and one contact.
fn populated_node() -> Node {
    let node = Node::default();
    node.set(im(206), answer(golden("identity_state_seeded")));
    node.set(im(205), answer(golden("identity_state_contact")));
    node.set(ls(206), answer(golden("ls_state")));
    node
}

/// Six messages, so every position in the golden `read` and `deleted` lists
/// resolves: a deleted mark that imported would show.
fn six_messages() -> Inbox {
    Inbox(Some((0u8..6).map(|i| vec![i; 8]).collect()))
}

fn pending_count(status: &Option<JournalStatus>) -> usize {
    match status {
        Some(JournalStatus::Incomplete { pending, .. }) => pending.len(),
        other => panic!("{other:?}"),
    }
}

// ── The walk ────────────────────────────────────────────────────────────────

#[test]
fn scenario_a_populated_node_carries_everything_over() {
    let delegate = Delegate::new();
    let outcome = walk(&delegate, &populated_node(), six_messages());

    let identities = delegate.identities();
    assert_eq!(identities.len(), 1);
    let me = &identities[0];
    assert_eq!(me.addr, alice());
    assert_eq!(me.alias, "alice");
    assert_eq!(me.description, "home");
    assert!(!me.confirmed, "a migrated identity waits for confirmation");

    let owner = Some(alice());
    let drafts = delegate.list(ItemKind::Draft, owner);
    let draft: Draft = serde_json::from_slice(&drafts[0].body).unwrap();
    assert_eq!((draft.subject.as_str(), draft.body.as_str()), ("s", "b"));
    assert_eq!(drafts[0].item.id.len(), 16);
    let sent = delegate.list(ItemKind::Sent, owner);
    let sent: SentMessage = serde_json::from_slice(&sent[0].body).unwrap();
    assert!(!sent.subject.is_empty());
    let kept = delegate.list(ItemKind::Kept, owner);
    let kept: KeptMessage = serde_json::from_slice(&kept[0].body).unwrap();
    assert_eq!((kept.content.as_str(), kept.sent_at), ("c", Some(4)));
    let archived = delegate.list(ItemKind::Archived, owner);
    assert_eq!(archived.len(), 1, "the archive exists nowhere else");
    let archived: ArchivedMessage = serde_json::from_slice(&archived[0].body).unwrap();
    assert!(!archived.content.is_empty());

    let contacts = delegate.list(ItemKind::Contact, None);
    assert_eq!(contacts.len(), 1);
    let contact = crate::app::contact_store::decode(&contacts[0].item, &contacts[0].body)
        .expect("readable as a contact");
    assert_eq!(&*contact.local_alias, "bob");
    assert_eq!(contact.description, "friend");
    assert!(contact.verified, "the v0.2.x flag, for exactly this vk");

    // read [1, 2] land on those messages' hashes; deleted [5] is left out.
    assert_eq!(read_marks(&delegate), positions(&[1, 2]));

    let settings = delegate.item(ItemKind::IdentitySettings, owner).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&settings.body).unwrap();
    assert!(value.get("display_name").is_some());

    let c = outcome.counts;
    assert_eq!(
        (
            c.identities,
            c.contacts,
            c.drafts,
            c.sent,
            c.kept,
            c.archived
        ),
        (1, 1, 1, 1, 1, 1)
    );
    assert_eq!(c.flags_skipped, 0);
    assert_eq!(c.deleted_marks, 1);
    // Generation 205's local-state delegate was never installed here.
    assert_eq!(pending_count(&outcome.status), 1);
    assert_eq!(settled(outcome.status.as_ref()), Settled::Retry);
}

/// The read marks stored for alice, as message ids.
fn read_marks(delegate: &Delegate) -> Vec<Vec<u8>> {
    let mut marks: Vec<Vec<u8>> = delegate
        .list(ItemKind::Flags, Some(alice()))
        .into_iter()
        .map(|i| {
            let flags: MergedFlags = serde_json::from_slice(&i.body).unwrap();
            assert_eq!(
                flags,
                MergedFlags {
                    read: true,
                    deleted: false
                }
            );
            i.item.id
        })
        .collect();
    marks.sort();
    marks
}

/// The ids of the messages at `positions` in [`six_messages`].
fn positions(positions: &[u8]) -> Vec<Vec<u8>> {
    let mut ids: Vec<Vec<u8>> = positions
        .iter()
        .map(|p| crate::local_state::full_message_id(&[*p; 8]).to_vec())
        .collect();
    ids.sort();
    ids
}

#[test]
fn scenario_each_predecessor_gets_its_own_key_and_parameters() {
    let delegate = Delegate::new();
    let node = populated_node();
    walk(&delegate, &node, six_messages());
    let asked = node.asked.borrow();
    let (im_params, ls_params) = (
        include_bytes!("../../../published-contract/wasm/v1/identity-manager-params").as_slice(),
        include_bytes!("../../../published-contract/wasm/v1/mail-local-state-params").as_slice(),
    );
    for (key, params, request) in asked.iter() {
        let identity = IDENTITY_LINEAGE
            .iter()
            .any(|e| e.delegate_key.as_slice() == key.bytes());
        let (want_params, want_request) = if identity {
            (im_params, golden("identity_msg_get"))
        } else {
            (ls_params, golden("ls_msg_get_all"))
        };
        assert_eq!(params.as_slice(), want_params);
        assert_eq!(*request, want_request);
    }
    assert_eq!(asked.len(), 4, "one round trip per predecessor");
}

#[test]
fn scenario_identities_are_walked_before_any_local_state() {
    let delegate = Delegate::new();
    let node = populated_node();
    walk(&delegate, &node, six_messages());
    let asked: Vec<Vec<u8>> = node
        .asked
        .borrow()
        .iter()
        .map(|a| a.0.bytes().to_vec())
        .collect();
    assert_eq!(
        asked,
        vec![
            im(206).delegate_key.to_vec(),
            im(205).delegate_key.to_vec(),
            ls(206).delegate_key.to_vec(),
            ls(205).delegate_key.to_vec(),
        ]
    );
}

/// The name is the spec's (surgery plan section 11). Silence on every
/// predecessor: nothing imported, no marker, nothing sealed, and the same
/// walk recovers everything once the node answers.
#[test]
fn a_silent_get_is_unresponsive_never_absent_never_sealed() {
    let delegate = Delegate::new();
    let silent = Node::default();
    for entry in IDENTITY_LINEAGE.iter().chain(LOCAL_STATE_LINEAGE) {
        silent.set(entry, LegacyReply::NoAnswer("timed out".into()));
    }
    let outcome = walk(&delegate, &silent, no_inbox());
    let report = outcome.report.expect("it walked").report;
    assert_eq!(report.predecessors.len(), 4);
    assert!(
        report
            .predecessors
            .iter()
            .all(|p| matches!(p, PredecessorMigration::Unresponsive { .. }))
    );
    assert!(delegate.markers_written().is_empty(), "nothing sealed");
    assert_eq!(pending_count(&outcome.status), 4);
    assert!(delegate.identities().is_empty());

    walk(&delegate, &populated_node(), six_messages());
    assert_eq!(delegate.identities().len(), 1);
}

#[test]
fn scenario_a_typed_not_installed_stays_pending_and_is_never_sealed() {
    let delegate = Delegate::new();
    let outcome = walk(&delegate, &Node::default(), no_inbox());
    assert!(delegate.markers_written().is_empty());
    assert_eq!(pending_count(&outcome.status), 4);
    assert_eq!(settled(outcome.status.as_ref()), Settled::Retry);
    let streaks: Vec<u32> = match outcome.status.unwrap() {
        JournalStatus::Incomplete { pending, .. } => {
            pending.iter().map(|p| p.absent_streak).collect()
        }
        other => panic!("{other:?}"),
    };
    assert_eq!(streaks, vec![1; 4], "counted, so the walk can back off");
}

/// v0.2.x answers an empty default both when it holds nothing and when the
/// node failed to read its secret. Neither may become a permanent "empty".
#[test]
fn scenario_an_answered_empty_store_is_never_sealed() {
    let delegate = Delegate::new();
    let node = Node::default();
    node.set(im(206), answer(br#"{"identities":{}}"#.to_vec()));
    node.set(ls(206), answer(br#"{"aliases":{}}"#.to_vec()));
    let outcome = walk(&delegate, &node, no_inbox());
    assert!(delegate.markers_written().iter().all(|m| m.done.is_none()));
    assert!(outcome.report.unwrap().report.any_unresponsive());

    // The read that failed works next time, and the data arrives.
    walk(&delegate, &populated_node(), six_messages());
    assert_eq!(delegate.identities().len(), 1);
}

#[test]
fn scenario_undecodable_and_oversized_replies_are_unresponsive() {
    for reply in [
        LegacyReply::Answer(b"{not json".to_vec()),
        LegacyReply::Answer(vec![b' '; MAX_LEGACY_REPLY_BYTES + 1]),
        LegacyReply::NoAnswer("an empty reply".into()),
    ] {
        let delegate = Delegate::new();
        let node = Node::default();
        node.set(im(206), reply);
        let outcome = walk(&delegate, &node, no_inbox());
        let report = outcome.report.unwrap().report;
        assert!(matches!(
            report.predecessors[0],
            PredecessorMigration::Unresponsive { .. }
        ));
        assert!(delegate.markers_written().iter().all(|m| m.done.is_none()));
    }
}

/// How many writes an uninterrupted walk of `populated_node` makes, so the
/// kill loops cover every one however many there come to be.
fn writes_in_a_whole_walk() -> usize {
    let whole = Delegate::new();
    walk(&whole, &populated_node(), six_messages());
    let writes = *whole.writes_seen.borrow();
    assert!(writes > 10, "the walk barely wrote: {writes}");
    writes
}

/// A tab that dies at any write leaves the next load able to finish, with
/// the same result as a walk that was never interrupted.
#[test]
fn scenario_an_interrupted_migration_finishes_on_the_next_load() {
    let whole = Delegate::new();
    walk(&whole, &populated_node(), six_messages());
    let want = visible(&whole);
    for died_after in 0..writes_in_a_whole_walk() {
        let delegate = Delegate::new();
        delegate.die_after(died_after);
        walk(&delegate, &populated_node(), six_messages());
        delegate.revive();
        walk(&delegate, &populated_node(), six_messages());
        assert_eq!(visible(&delegate), want, "died after {died_after} writes");
    }
}

/// While an import is partial the journal says so, and a finished walk
/// clears it. A kill between two writes of one predecessor is what leaves it.
/// A retry offers every item again. One that arrived on the earlier attempt
/// was not written now, and the notice must not count it twice.
#[test]
fn scenario_a_retry_does_not_count_what_already_arrived() {
    let delegate = Delegate::new();
    let node = populated_node();
    delegate.faults.borrow_mut().false_conflict = Some(ItemKind::Archived);
    let first = walk(&delegate, &node, no_inbox());
    assert_eq!((first.counts.drafts, first.counts.archived), (1, 0));
    assert!(first.unfinished(), "206's local state stays started");

    let second = walk(&delegate, &node, no_inbox());
    assert_eq!((second.counts.drafts, second.counts.archived), (0, 1));
    let totals = delegate.ledger().totals;
    assert_eq!((totals.drafts, totals.sent, totals.kept), (1, 1, 1));
    assert_eq!(totals.archived, 1);
    assert!(!second.unfinished());
}

/// While the walk may be part done the notice does not say it moved anything.
#[test]
fn the_notice_says_a_move_under_way_is_still_in_progress() {
    use crate::app::migration_view::notice_summary;
    let counts = super::successor::MigrationCounts {
        archived: 5,
        ..Default::default()
    };
    let done = notice_summary(&counts, 0, false);
    assert!(done.starts_with("Moved from"), "{done}");
    let moving = notice_summary(&counts, 0, true);
    assert!(!moving.contains("Moved"), "{moving}");
    assert!(moving.contains("still in progress") && moving.contains("5 archived"));

    let no_journal = WalkOutcome {
        status: None,
        report: None,
        counts,
        silent_rows: 0,
        released_markers: false,
    };
    assert!(no_journal.unfinished());
}

#[test]
fn scenario_a_partial_import_reads_as_interrupted() {
    let mut saw_interrupted = 0;
    for died_after in 0..writes_in_a_whole_walk() {
        let delegate = Delegate::new();
        delegate.die_after(died_after);
        let dead = walk(&delegate, &populated_node(), six_messages());
        assert_ne!(settled(dead.status.as_ref()), Settled::Complete);
        delegate.revive();
        let silent = walk(&delegate, &Node::default(), no_inbox());
        if silent.status.is_some_and(|s| s.interrupted_import()) {
            saw_interrupted += 1;
        }
        let done = walk(&delegate, &populated_node(), six_messages());
        assert!(!done.status.unwrap().interrupted_import());
    }
    assert!(saw_interrupted > 0, "no kill point left a partial import");
}

/// What the user sees: every list's bodies, by id.
fn visible(delegate: &Delegate) -> BTreeMap<String, Listed> {
    let mut out = BTreeMap::new();
    for identity in delegate.identities() {
        out.insert(
            format!("identity {:?} {}", identity.addr, identity.alias),
            Vec::new(),
        );
        for kind in [
            ItemKind::Draft,
            ItemKind::Sent,
            ItemKind::Kept,
            ItemKind::Archived,
            ItemKind::Flags,
        ] {
            let mut items: Listed = delegate
                .list(kind, Some(identity.addr))
                .into_iter()
                .map(|i| (i.item.id, i.body.into_vec()))
                .collect();
            items.sort();
            out.insert(format!("{kind:?} {:?}", identity.addr), items);
        }
        out.insert(
            format!("settings {:?}", identity.addr),
            delegate
                .item(ItemKind::IdentitySettings, Some(identity.addr))
                .into_iter()
                .map(|i| (Vec::new(), i.body.into_vec()))
                .collect(),
        );
    }
    let contacts = delegate
        .list(ItemKind::Contact, None)
        .into_iter()
        .map(|i| (i.item.id, i.body.into_vec()))
        .collect();
    out.insert("contacts".to_string(), contacts);
    out
}

#[test]
fn scenario_running_again_changes_nothing() {
    let delegate = Delegate::new();
    let node = populated_node();
    walk(&delegate, &node, six_messages());
    let before = visible(&delegate);
    let again = walk(&delegate, &node, six_messages());
    assert_eq!(visible(&delegate), before);
    assert!(again.counts.is_empty(), "{:?}", again.counts);
}

#[test]
fn scenario_an_import_never_overwrites_what_the_new_delegate_holds() {
    let delegate = Delegate::new();
    // The user restored the same identity and edited on the new version
    // before the walk could run.
    let restored = delegate
        .send(Op::ImportIdentity {
            source: freenet_mail_protocol::ImportSource::Seeds {
                dsa: freenet_mail_protocol::DsaSeed([9; 32]),
                kem: freenet_mail_protocol::KemSeed([10; 64]),
            },
            kind: freenet_mail_protocol::ImportKind::UserRestore,
            alias: "renamed".into(),
            description: "mine".into(),
        })
        .unwrap();
    assert!(matches!(restored, Reply::Imported { .. }));
    walk(&delegate, &populated_node(), six_messages());
    let ids = delegate.identities();
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0].alias, "renamed");
    assert!(ids[0].confirmed, "the restore's answer stands");

    // A draft edited since keeps its edit on a re-import.
    let draft = delegate.list(ItemKind::Draft, Some(alice())).remove(0);
    let edited = br#"{"to":"bob","subject":"mine","body":"edited","updated_at":99}"#.to_vec();
    delegate
        .send(Op::PutItem {
            item: draft.item.clone(),
            body: edited.clone().into(),
            expected_gen: Some(draft.generation),
        })
        .unwrap();
    // A brand-new successor state for the journal: forget the markers so the
    // predecessors are offered again.
    for marker in delegate.list(ItemKind::MigrationMarker, None) {
        delegate
            .send(Op::DeleteItem {
                item: marker.item,
                expected_gen: marker.generation,
            })
            .unwrap();
    }
    let journal = delegate.item(ItemKind::MigrationJournal, None).unwrap();
    delegate
        .send(Op::DeleteItem {
            item: journal.item,
            expected_gen: journal.generation,
        })
        .unwrap();
    walk(&delegate, &populated_node(), six_messages());
    let draft = delegate.list(ItemKind::Draft, Some(alice())).remove(0);
    assert_eq!(draft.body.as_slice(), edited.as_slice());
}

/// Under the union policy only the writer keeps the newest value: the older
/// generation's draft with the same id is not a second draft, and does not
/// replace the newer one.
#[test]
fn scenario_the_newest_generation_wins_a_shared_item() {
    let delegate = Delegate::new();
    let node = populated_node();
    node.set(
        ls(205),
        answer(golden_edited(
            "ls_state",
            r#""subject":"s""#,
            r#""subject":"older""#,
        )),
    );
    walk(&delegate, &node, six_messages());
    let drafts = delegate.list(ItemKind::Draft, Some(alice()));
    assert_eq!(drafts.len(), 1);
    let draft: Draft = serde_json::from_slice(&drafts[0].body).unwrap();
    assert_eq!(draft.subject, "s");
}

/// The golden identity under alias alice, with the seed of a different one.
fn other_alice() -> Vec<u8> {
    let seed_nine = (0..32).map(|_| "9").collect::<Vec<_>>().join(",");
    let seed_eight = (0..32).map(|_| "8").collect::<Vec<_>>().join(",");
    let text = String::from_utf8(golden("identity_state_seeded")).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
    let key = parsed["identities"]["alice"]["key"].clone();
    let key_bytes: Vec<u8> = serde_json::from_value(key.clone()).unwrap();
    let key_text = String::from_utf8(key_bytes).unwrap();
    assert!(key_text.contains(&seed_nine));
    let other: Vec<u8> = key_text.replace(&seed_nine, &seed_eight).into_bytes();
    golden_edited(
        "identity_state_seeded",
        &key.to_string(),
        &serde_json::to_string(&other).unwrap(),
    )
}

#[test]
fn scenario_two_identities_with_one_alias_both_arrive() {
    let delegate = Delegate::new();
    let node = Node::default();
    node.set(im(206), answer(golden("identity_state_seeded")));
    // The same alias for different seeds, in an older generation.
    node.set(im(205), answer(other_alice()));
    walk(&delegate, &node, no_inbox());
    let mut aliases: Vec<String> = delegate.identities().into_iter().map(|i| i.alias).collect();
    aliases.sort();
    assert_eq!(aliases.len(), 2);
    assert_eq!(aliases[0], "alice");
    assert!(aliases[1].starts_with("alice ("), "{}", aliases[1]);
}

/// Mail for an alias with no identity is kept, and said to be unmatched, once
/// every row that could hold the alias has stood as holding nothing. Its own
/// generation's identities must have answered with something, or there is no
/// telling: see the next test.
#[test]
fn scenario_an_alias_with_no_identity_is_kept_not_lost() {
    let delegate = Delegate::new();
    let node = Node::default();
    node.set(
        im(206),
        answer(golden_edited(
            "identity_state_seeded",
            r#"{"identities":{"alice":"#,
            r#"{"identities":{"renamed":"#,
        )),
    );
    node.set(ls(206), answer(golden("ls_state")));
    for load in 0..HOLD_BACK_LOADS {
        walk(&delegate, &node, no_inbox());
        assert_eq!(orphan_count(&delegate), 0, "load {load}");
    }
    let outcome = walk(&delegate, &node, no_inbox());
    let orphans = delegate.list(ItemKind::LegacyOrphan, None);
    assert_eq!(orphans.len(), 5, "draft, sent, kept, archived, settings");
    assert_eq!(outcome.counts.orphaned, 5);
    assert_eq!(outcome.counts.flags_skipped, 2);
}

/// An identity row that answered nothing usable decides nothing about the
/// aliases of its generation. Sealing them as orphans would strand the mail,
/// because local state is not walked again once it is imported.
#[test]
fn scenario_local_state_waits_for_the_identities_of_its_generation() {
    let oversize = vec![b' '; MAX_LEGACY_REPLY_BYTES + 1];
    for identity_row in [
        LegacyReply::NoAnswer("timed out".into()),
        LegacyReply::NotInstalled,
        answer(br#"{"identities":{}}"#.to_vec()),
        answer(oversize),
        answer(b"{not json".to_vec()),
    ] {
        let delegate = Delegate::new();
        let node = Node::default();
        node.set(im(206), identity_row);
        node.set(ls(206), answer(golden("ls_state")));
        let outcome = walk(&delegate, &node, no_inbox());
        assert!(delegate.list(ItemKind::LegacyOrphan, None).is_empty());
        assert!(outcome.report.unwrap().report.any_unresponsive());
        assert_eq!(pending_count(&outcome.status), 4);

        // The identity row answers on the next load, and the mail lands
        // under the identity.
        let outcome = walk(&delegate, &populated_node(), six_messages());
        assert!(delegate.list(ItemKind::LegacyOrphan, None).is_empty());
        assert_eq!(delegate.list(ItemKind::Archived, Some(alice())).len(), 1);
        assert_eq!(delegate.list(ItemKind::Draft, Some(alice())).len(), 1);
        assert_eq!(pending_count(&outcome.status), 1, "only 205's local state");
    }
}

/// The older table's alice is another identity. Filing 206's mail under her
/// would be final, so it waits however long 206's identities stay silent.
#[test]
fn scenario_an_older_table_does_not_stand_in_for_a_silent_generation() {
    let delegate = Delegate::new();
    let node = Node::default();
    node.set(im(206), LegacyReply::NoAnswer("timed out".into()));
    node.set(im(205), answer(other_alice()));
    node.set(ls(206), answer(golden("ls_state")));
    for _ in 0..HOLD_BACK_LOADS + 2 {
        walk(&delegate, &node, no_inbox());
    }
    let identities = delegate.identities();
    assert_eq!(identities.len(), 1, "the hold has ended for the older row");
    assert_ne!(identities[0].addr, alice());
    assert!(
        delegate
            .list(ItemKind::Draft, Some(identities[0].addr))
            .is_empty()
    );

    node.set(im(206), answer(golden("identity_state_seeded")));
    walk(&delegate, &node, no_inbox());
    assert_eq!(delegate.list(ItemKind::Draft, Some(alice())).len(), 1);
}

/// While 206 is silent an older row must not land first: under never-clobber
/// its values would then stand for good.
#[test]
fn scenario_a_newer_row_that_answers_late_still_wins() {
    let delegate = Delegate::new();
    let node = populated_node();
    let older = golden_edited("ls_state", r#""subject":"s""#, r#""subject":"older""#);
    node.set(ls(205), answer(older));
    node.set(ls(206), LegacyReply::NoAnswer("timed out".into()));
    for _ in 0..HOLD_BACK_LOADS - 1 {
        walk(&delegate, &node, six_messages());
        assert!(delegate.list(ItemKind::Draft, Some(alice())).is_empty());
    }
    node.set(ls(206), answer(golden("ls_state")));
    let outcome = walk(&delegate, &node, six_messages());
    let drafts = delegate.list(ItemKind::Draft, Some(alice()));
    let draft: Draft = serde_json::from_slice(&drafts[0].body).unwrap();
    assert_eq!(draft.subject, "s", "the newest generation's copy");
    assert_eq!(settled(outcome.status.as_ref()), Settled::Complete);
}

/// A user who ran v0.2.6 and never re-added an identity: 206 answers empty for
/// good and everything is in 205. The hold ends, or they are stranded.
#[test]
fn scenario_a_newer_row_that_stays_empty_holds_older_rows_only_for_a_while() {
    let delegate = Delegate::new();
    let node = Node::default();
    node.set(im(206), answer(br#"{"identities":{}}"#.to_vec()));
    node.set(ls(206), answer(br#"{"aliases":{}}"#.to_vec()));
    node.set(im(205), answer(golden("identity_state_seeded")));
    node.set(ls(205), answer(golden("ls_state")));
    for load in 0..HOLD_BACK_LOADS {
        walk(&delegate, &node, no_inbox());
        assert!(delegate.identities().is_empty(), "held on load {load}");
    }
    let outcome = walk(&delegate, &node, no_inbox());
    assert_eq!(delegate.identities().len(), 1);
    assert_eq!(delegate.list(ItemKind::Archived, Some(alice())).len(), 1);
    assert_eq!(pending_count(&outcome.status), 2, "206 is never sealed");
}

#[test]
fn scenario_a_typed_not_installed_holds_nothing_back() {
    let delegate = Delegate::new();
    let node = Node::default();
    node.set(im(205), answer(golden("identity_state_seeded")));
    node.set(ls(205), answer(golden("ls_state")));
    walk(&delegate, &node, no_inbox());
    assert_eq!(delegate.identities().len(), 1);
    assert_eq!(delegate.list(ItemKind::Archived, Some(alice())).len(), 1);
}

/// One identity's record of where its inbox was, in two rows: v0.2.6 moved it,
/// so 205's record is history. A pending migration from it would merge the
/// old inbox back over newer state.
#[test]
fn scenario_only_the_newest_row_holding_an_identity_sets_its_markers() {
    let inbox = crate::inbox::INBOX_CODE_HASH.trim();
    let aft = crate::aft::TOKEN_RECORD_CODE_HASH.trim();
    let delegate = Delegate::new();
    let node = Node::default();
    node.set(
        im(206),
        answer(identity_with_markers(
            &format!(r#""inbox_wasm_hash":"{inbox}""#),
            r#""pending_migration_from":null"#,
            &format!(r#""aft_record_wasm_hash":"{aft}""#),
            r#""pending_aft_migration_from":null"#,
        )),
    );
    node.set(
        im(205),
        answer(identity_with_markers(
            r#""inbox_wasm_hash":"older""#,
            r#""pending_migration_from":null"#,
            r#""aft_record_wasm_hash":"older-aft""#,
            r#""pending_aft_migration_from":null"#,
        )),
    );
    walk(&delegate, &node, no_inbox());
    let settings = delegate.item(ItemKind::IdentitySettings, Some(alice()));
    let markers = markers_from_body(settings.as_ref().map(|i| i.body.as_slice()));
    assert_eq!(markers.pending_migration_from, None);
    assert_eq!(markers.pending_aft_migration_from, None);
    assert_eq!(markers.inbox_wasm_hash.as_deref(), Some(inbox));
    assert_eq!(markers.imported_generation, Some(206));
}

/// The markers of the golden identity as stored.
fn alice_markers(delegate: &Delegate) -> MigrationMarkers {
    let settings = delegate.item(ItemKind::IdentitySettings, Some(alice()));
    markers_from_body(settings.as_ref().map(|i| i.body.as_slice()))
}

/// The newest row went silent past its hold, so an older one landed. What it
/// says about contracts must not run yet: if the newer row holds the identity,
/// that would put an old inbox back over the current one, for good.
#[test]
fn scenario_silence_past_the_hold_starts_no_contract_migration() {
    use crate::app::identity_store::plan_load;
    let old_row = identity_with_markers(
        r#""inbox_wasm_hash":"older""#,
        r#""pending_migration_from":null"#,
        r#""aft_record_wasm_hash":"older-aft""#,
        r#""pending_aft_migration_from":null"#,
    );
    for (later, pending) in [
        // The newer row turns out to hold nothing: the marker takes effect.
        (LegacyReply::NotInstalled, Some("older")),
        // It holds the identity, at the current hash: the marker never did.
        (
            answer(identity_with_markers(
                &format!(
                    r#""inbox_wasm_hash":"{}""#,
                    crate::inbox::INBOX_CODE_HASH.trim()
                ),
                r#""pending_migration_from":null"#,
                &format!(
                    r#""aft_record_wasm_hash":"{}""#,
                    crate::aft::TOKEN_RECORD_CODE_HASH.trim()
                ),
                r#""pending_aft_migration_from":null"#,
            )),
            None,
        ),
    ] {
        let delegate = Delegate::new();
        let node = Node::default();
        node.set(im(206), LegacyReply::NoAnswer("timed out".into()));
        node.set(im(205), answer(old_row.clone()));
        for _ in 0..=HOLD_BACK_LOADS {
            walk(&delegate, &node, no_inbox());
        }
        let held = alice_markers(&delegate);
        assert!(held.pending_held && held.pending_migration_from.is_some());
        assert_eq!(plan_load(Some(held)), (None, None, None));

        node.set(im(206), later);
        walk(&delegate, &node, no_inbox());
        let markers = alice_markers(&delegate);
        assert!(!markers.pending_held);
        assert_eq!(markers.pending_migration_from.as_deref(), pending);
        let (inbox, _, _) = plan_load(Some(markers));
        assert_eq!(inbox.as_deref(), pending);
        assert!(!delegate.ledger().markers_held);
    }
}

/// With nothing newer unsettled, an older row's marker runs at once.
#[test]
fn a_row_with_nothing_newer_unsettled_holds_no_marker() {
    let delegate = Delegate::new();
    let node = Node::default();
    node.set(
        im(205),
        answer(identity_with_markers(
            r#""inbox_wasm_hash":"older""#,
            r#""pending_migration_from":null"#,
            r#""aft_record_wasm_hash":"older-aft""#,
            r#""pending_aft_migration_from":null"#,
        )),
    );
    walk(&delegate, &node, no_inbox());
    let markers = alice_markers(&delegate);
    assert!(!markers.pending_held);
    assert_eq!(markers.pending_migration_from.as_deref(), Some("older"));
}

/// A marker the walk wrote after `prepare` read stands: only what the plan
/// changed is applied.
#[test]
fn preparing_applies_only_what_the_plan_changed() {
    let source = include_str!("../app/identity_store.rs");
    let prepare = &source[source.find("pub(crate) async fn prepare").unwrap()..];
    assert!(prepare.contains("m.apply_changes(&before, &new)"));
    assert!(!prepare[..prepare.find("LoadedIdentity {").unwrap()].contains("*m = new"));
}

/// The list is read again once the identities are in, while the mail is still
/// to come, and only if the walk brought one in.
#[test]
fn scenario_identities_are_announced_before_the_mail() {
    let delegate = Delegate::new();
    let seen = Rc::new(RefCell::new(None));
    let (at, observer) = (seen.clone(), delegate.clone());
    block_on(run(
        delegate.clone(),
        populated_node(),
        no_inbox(),
        0,
        move || {
            *at.borrow_mut() = Some((
                observer.identities().len(),
                observer.list(ItemKind::Archived, Some(alice())).len(),
            ));
        },
    ));
    assert_eq!(*seen.borrow(), Some((1, 0)));
    assert_eq!(delegate.list(ItemKind::Archived, Some(alice())).len(), 1);

    let seen = Rc::new(RefCell::new(false));
    let at = seen.clone();
    block_on(run(
        delegate.clone(),
        populated_node(),
        no_inbox(),
        0,
        move || {
            *at.borrow_mut() = true;
        },
    ));
    assert!(!*seen.borrow(), "nothing new to list");
}

/// A row held back maps again next load: its marks are not news, and a walk
/// that did nothing must not raise a notice.
#[test]
fn scenario_a_row_held_back_counts_nothing() {
    let delegate = Delegate::new();
    let node = Node::default();
    node.set(im(206), LegacyReply::NoAnswer("timed out".into()));
    node.set(ls(206), answer(golden("ls_state")));
    let outcome = walk(&delegate, &node, no_inbox());
    assert!(outcome.counts.is_empty());
    assert!(delegate.ledger().totals.is_empty());
}

/// The silence alarm stays up on a load that does not walk, and goes when a
/// walk finds the row answering.
#[test]
fn scenario_the_silent_alarm_survives_loads_that_do_not_walk() {
    let delegate = Delegate::new();
    let node = Node::default();
    node.set(im(206), LegacyReply::NoAnswer("timed out".into()));
    for _ in 0..=SILENT_WALKS_BEFORE_SLOWING {
        assert_eq!(walk(&delegate, &node, no_inbox()).silent_rows, 1);
    }
    let skipped = block_on(run(delegate.clone(), node.clone(), no_inbox(), 1, || {}));
    assert!(skipped.report.is_none(), "this load does not walk");
    assert_eq!(skipped.silent_rows, 1);

    node.set(im(206), LegacyReply::NotInstalled);
    assert_eq!(walk(&delegate, &node, no_inbox()).silent_rows, 0);
    let skipped = block_on(run(delegate.clone(), node.clone(), no_inbox(), 1, || {}));
    assert_eq!(skipped.silent_rows, 0);
}

/// A dismissed notice comes back when there is something new to say. A tab
/// closed mid-walk still has what resolved on record.
#[test]
fn scenario_new_totals_or_rejections_bring_a_dismissed_notice_back() {
    let delegate = Delegate::new();
    let node = populated_node();
    node.set(ls(206), LegacyReply::NoAnswer("timed out".into()));
    walk(&delegate, &node, no_inbox());
    assert_eq!(
        delegate.ledger().totals.identities,
        1,
        "resolved rows count"
    );

    let mut store = delegate.clone();
    block_on(ledger::update_ledger(&mut store, |l| {
        l.notice_dismissed = true
    }))
    .unwrap();
    walk(&delegate, &node, no_inbox());
    assert!(delegate.ledger().notice_dismissed, "nothing new");

    node.set(ls(206), answer(golden("ls_state")));
    walk(&delegate, &node, no_inbox());
    assert!(!delegate.ledger().notice_dismissed, "mail arrived");
}

#[test]
fn the_notices_counts_are_recorded_as_rows_resolve() {
    let source = include_str!("successor.rs");
    let record = &source[source.find("async fn record_marker").unwrap()..];
    let flush = record.find("self.update_ledger(").unwrap();
    assert!(flush < record.find("let item = marker_item(predecessor)").unwrap());
}

/// A position means something only in the inbox of the generation that wrote
/// it, so an older row's marks would land on the wrong messages.
#[test]
fn scenario_read_marks_come_from_the_newest_row_holding_the_alias() {
    let older = || {
        answer(golden_edited(
            "ls_state",
            r#""read":[1,2]"#,
            r#""read":[3]"#,
        ))
    };
    let delegate = Delegate::new();
    let node = populated_node();
    node.set(ls(205), older());
    walk(&delegate, &node, six_messages());
    assert_eq!(read_marks(&delegate), positions(&[1, 2]));

    // No newer row holds it: these are the newest marks there are.
    let delegate = Delegate::new();
    let node = populated_node();
    node.set(ls(206), LegacyReply::NotInstalled);
    node.set(ls(205), older());
    walk(&delegate, &node, six_messages());
    assert_eq!(read_marks(&delegate), positions(&[3]));

    // A newer row silent past its hold may hold it: skipped and counted.
    let delegate = Delegate::new();
    let node = populated_node();
    node.set(ls(206), LegacyReply::NoAnswer("timed out".into()));
    node.set(ls(205), older());
    let mut skipped = 0;
    for _ in 0..=HOLD_BACK_LOADS {
        skipped += walk(&delegate, &node, six_messages()).counts.flags_skipped;
    }
    assert_eq!(delegate.list(ItemKind::Archived, Some(alice())).len(), 1);
    assert!(read_marks(&delegate).is_empty());
    assert_eq!(skipped, 1);
}

/// The delegate can answer `Conflict` about its index on a create of an item
/// it does not hold. Taking that for "already stored" would seal the
/// predecessor past an archived message with no other copy.
#[test]
fn scenario_a_false_conflict_does_not_pass_for_a_stored_item() {
    let delegate = Delegate::new();
    delegate.faults.borrow_mut().false_conflict = Some(ItemKind::Archived);
    let outcome = walk(&delegate, &populated_node(), six_messages());
    assert!(delegate.list(ItemKind::Archived, Some(alice())).is_empty());
    assert_eq!(pending_count(&outcome.status), 2, "206's local state too");

    let outcome = walk(&delegate, &populated_node(), six_messages());
    assert_eq!(delegate.list(ItemKind::Archived, Some(alice())).len(), 1);
    assert_eq!(pending_count(&outcome.status), 1);
}

/// A cap that stays reached must end the walk. If it kept the predecessor
/// pending, every load would re-offer everything, and what the user deleted to
/// make room would come straight back.
#[test]
fn scenario_a_cap_is_a_counted_rejection_and_the_walk_ends() {
    let delegate = Delegate::new();
    let node = populated_node();
    delegate.faults.borrow_mut().capped = Some(ItemKind::Archived);
    let outcome = walk(&delegate, &node, six_messages());
    assert_eq!(outcome.counts.at_cap, 1);
    let status = outcome.status.unwrap();
    assert_eq!(status.rejected_items(), 1);
    assert_eq!(pending_count(&Some(status)), 1, "206's local state ended");

    let draft = delegate.list(ItemKind::Draft, Some(alice())).remove(0);
    delegate
        .send(Op::DeleteItem {
            item: draft.item,
            expected_gen: draft.generation,
        })
        .unwrap();
    walk(&delegate, &node, six_messages());
    assert!(
        delegate.list(ItemKind::Draft, Some(alice())).is_empty(),
        "the user's deletion stands"
    );
}

/// An identity being deleted refuses its items for good.
#[test]
fn scenario_items_of_an_identity_being_deleted_are_a_counted_rejection() {
    let delegate = Delegate::new();
    delegate.faults.borrow_mut().owned_writes_refused = true;
    let outcome = walk(&delegate, &populated_node(), six_messages());
    assert!(outcome.counts.identity_gone > 0);
    let status = outcome.status.unwrap();
    assert!(status.rejected_items() > 0);
    assert_eq!(pending_count(&Some(status)), 1, "206's local state ended");
}

/// `NotFound` for an identity that is held by a resolved row means it is gone,
/// with the same result as the `Refused` it answered while being deleted.
#[test]
fn scenario_items_of_an_identity_that_is_gone_are_a_counted_rejection() {
    let delegate = Delegate::new();
    let node = populated_node();
    node.set(ls(206), LegacyReply::NoAnswer("timed out".into()));
    delegate.faults.borrow_mut().import_fails = Some(FailureCode::CapReached);
    let outcome = walk(&delegate, &node, six_messages());
    assert_eq!(pending_count(&outcome.status), 2, "only the local state");
    assert!(delegate.identities().is_empty());

    node.set(ls(206), answer(golden("ls_state")));
    let outcome = walk(&delegate, &node, six_messages());
    assert!(outcome.counts.identity_gone > 0);
    assert_eq!(pending_count(&outcome.status), 1, "206's local state ended");
}

/// `NotFound` also answers an identity record that failed to read. That
/// identity is listed, so its items are not a rejection: they wait, and arrive
/// once the record reads again.
#[test]
fn scenario_items_of_an_unreadable_identity_wait_for_it() {
    let delegate = Delegate::new();
    let node = populated_node();
    node.set(ls(206), LegacyReply::NoAnswer("timed out".into()));
    walk(&delegate, &node, no_inbox());
    node.set(ls(206), answer(golden("ls_state")));

    let record = delegate.hide_identity(alice());
    for _ in 0..3 {
        let outcome = walk(&delegate, &node, no_inbox());
        assert_eq!(outcome.counts.identity_gone, 0);
        assert_eq!(pending_count(&outcome.status), 2, "206's local state waits");
    }
    delegate.restore_identity(record);
    let outcome = walk(&delegate, &node, no_inbox());
    assert_eq!(pending_count(&outcome.status), 1);
    assert_eq!(delegate.list(ItemKind::Archived, Some(alice())).len(), 1);
}

/// `NotFound` for an identity still on its way means nothing of the kind, and
/// sealing the local state past it would strand the mail.
#[test]
fn scenario_items_wait_for_an_identity_that_has_not_arrived() {
    let delegate = Delegate::new();
    let node = populated_node();
    delegate.faults.borrow_mut().import_fails = Some(FailureCode::Busy);
    let outcome = walk(&delegate, &node, six_messages());
    assert!(delegate.identities().is_empty());
    assert_eq!(outcome.counts.identity_gone, 0);
    let JournalStatus::Incomplete { pending, .. } = outcome.status.unwrap() else {
        panic!("nothing is complete");
    };
    let key = lineage_key(ls(206));
    assert!(
        pending.iter().any(|p| p.key == key),
        "206's mail is not sealed"
    );

    delegate.faults.borrow_mut().import_fails = None;
    let outcome = walk(&delegate, &node, six_messages());
    assert_eq!(delegate.list(ItemKind::Archived, Some(alice())).len(), 1);
    assert_eq!(pending_count(&outcome.status), 1);
}

/// A journal or marker whose record keeps failing to read must not stop the
/// migration on every load: the markers rebuild the journal, and the writes
/// that follow replace what could not be read.
#[test]
fn scenario_an_unreadable_journal_and_marker_are_rebuilt() {
    let delegate = Delegate::new();
    let node = populated_node();
    node.set(ls(206), LegacyReply::NoAnswer("timed out".into()));
    walk(&delegate, &node, six_messages());
    node.set(ls(206), answer(golden("ls_state")));

    delegate.blind(
        &delegate
            .item(ItemKind::MigrationJournal, None)
            .unwrap()
            .item,
    );
    let marker = delegate.list(ItemKind::MigrationMarker, None).remove(0);
    delegate.blind(&marker.item);

    let outcome = walk(&delegate, &node, six_messages());
    assert!(outcome.report.is_some(), "it walked");
    assert_eq!(pending_count(&outcome.status), 1, "only 205's local state");
    assert_eq!(delegate.list(ItemKind::Archived, Some(alice())).len(), 1);
    assert!(delegate.item(ItemKind::MigrationJournal, None).is_some());
}

/// Two loads in one tab: the second waits for the first's walk to end.
#[test]
fn scenario_walks_in_one_tab_run_one_at_a_time() {
    use futures::FutureExt;
    use futures::channel::oneshot;

    struct Gated(Option<oneshot::Receiver<()>>, Node);
    impl LegacyTransport for Gated {
        async fn ask(
            &mut self,
            predecessor: &DelegateKey,
            params: &'static [u8],
            request: Vec<u8>,
        ) -> LegacyReply {
            if let Some(gate) = self.0.take() {
                let _ = gate.await;
            }
            self.1.ask(predecessor, params, request).await
        }
    }

    let delegate = Delegate::new();
    let (open, gate) = oneshot::channel();
    let gated = Gated(Some(gate), populated_node());
    let mut first = run(delegate.clone(), gated, six_messages(), 0, || {}).boxed_local();
    assert!((&mut first).now_or_never().is_none(), "stopped at the gate");

    let mut second =
        run(delegate.clone(), populated_node(), six_messages(), 0, || {}).boxed_local();
    assert!(
        (&mut second).now_or_never().is_none(),
        "the first is walking"
    );

    open.send(()).unwrap();
    block_on(futures::future::join(first, second));
    assert_eq!(delegate.identities().len(), 1);
}

#[test]
fn scenario_an_inbox_that_cannot_be_read_skips_the_marks_and_counts_them() {
    let delegate = Delegate::new();
    let outcome = walk(&delegate, &populated_node(), no_inbox());
    assert!(delegate.list(ItemKind::Flags, Some(alice())).is_empty());
    assert_eq!(outcome.counts.flags_skipped, 2);
    assert_eq!(delegate.list(ItemKind::Archived, Some(alice())).len(), 1);
}

#[test]
fn scenario_a_mark_past_the_end_of_the_inbox_is_skipped_and_counted() {
    let delegate = Delegate::new();
    let outcome = walk(
        &delegate,
        &populated_node(),
        Inbox(Some(vec![vec![0; 8], vec![1; 8]])),
    );
    assert_eq!(delegate.list(ItemKind::Flags, Some(alice())).len(), 1);
    assert_eq!(outcome.counts.flags_skipped, 1);
}

#[test]
fn a_journal_that_cannot_be_stored_stops_before_any_import() {
    let delegate = Delegate::new();
    delegate.die_after(0);
    let outcome = walk(&delegate, &populated_node(), six_messages());
    delegate.revive();
    assert!(outcome.report.is_none());
    assert_eq!(outcome.status, None);
    assert!(delegate.identities().is_empty());
    assert_eq!(settled(None), Settled::Retry);
}

#[test]
fn scenario_an_undecodable_entry_is_refused_and_counted_not_hidden() {
    let delegate = Delegate::new();
    let node = Node::default();
    // The golden `identity_state`'s key bytes are no key at all.
    node.set(
        im(206),
        answer(golden_edited(
            "identity_state",
            r#""contact""#,
            r#""identity""#,
        )),
    );
    let outcome = walk(&delegate, &node, no_inbox());
    assert_eq!(outcome.counts.refused, 1);
    assert_eq!(outcome.status.unwrap().rejected_items(), 1);
    assert!(delegate.identities().is_empty());
}

#[test]
fn scenario_v0_2_contract_markers_become_pending_migrations() {
    let delegate = Delegate::new();
    walk(&delegate, &populated_node(), six_messages());
    let settings = delegate.item(ItemKind::IdentitySettings, Some(alice()));
    let markers = markers_from_body(settings.as_ref().map(|i| i.body.as_slice()));
    // The golden record: recorded a, pending b, recorded c, pending d.
    assert_eq!(markers.inbox_wasm_hash.as_deref(), Some("a"));
    assert_eq!(markers.pending_migration_from.as_deref(), Some("b"));
    assert_eq!(markers.aft_record_wasm_hash.as_deref(), Some("c"));
    assert_eq!(markers.pending_aft_migration_from.as_deref(), Some("d"));
}

/// Parity with v0.2.x: a release that changed the delegate key left the data
/// behind and started empty. That transcription is the oracle, `old` below:
/// nothing arrives, in every scenario. Each row where this walk differs is a
/// divergence, accepted because moving the data is the point of it, and
/// where it matches the two must agree exactly.
#[test]
fn scenario_parity_with_the_v0_2_behaviour() {
    struct Row {
        name: &'static str,
        node: fn() -> Node,
        /// Identities this walk imports.
        identities: usize,
        /// Accepted divergence from the oracle, or `None` if they must agree.
        accepted: Option<&'static str>,
    }
    fn nothing() -> Node {
        Node::default()
    }
    fn silent() -> Node {
        let node = Node::default();
        node.set(im(206), LegacyReply::NoAnswer("timed out".into()));
        node
    }
    fn empty() -> Node {
        let node = Node::default();
        node.set(im(206), answer(br#"{"identities":{}}"#.to_vec()));
        node
    }
    let rows = [
        Row {
            name: "no predecessor on this node",
            node: nothing,
            identities: 0,
            accepted: None,
        },
        Row {
            name: "predecessor silent",
            node: silent,
            identities: 0,
            accepted: None,
        },
        Row {
            name: "predecessor answers empty",
            node: empty,
            identities: 0,
            accepted: None,
        },
        Row {
            name: "predecessor holds data",
            node: populated_node,
            identities: 1,
            accepted: Some("the migration carries the data over"),
        },
    ];
    let old = |_: &Row| 0usize;
    for row in &rows {
        let delegate = Delegate::new();
        walk(&delegate, &(row.node)(), six_messages());
        assert_eq!(delegate.identities().len(), row.identities, "{}", row.name);
        assert_eq!(
            row.identities != old(row),
            row.accepted.is_some(),
            "{}: a divergence must be named, and only a real one",
            row.name
        );
    }
}

// ── Pure parts ──────────────────────────────────────────────────────────────

#[test]
fn the_lineage_has_every_row_and_identities_rank_above_local_state() {
    let lineage = lineage();
    assert_eq!(
        lineage.len(),
        IDENTITY_LINEAGE.len() + LOCAL_STATE_LINEAGE.len()
    );
    let lowest_identity = lineage
        .iter()
        .filter(|e| {
            IDENTITY_LINEAGE
                .iter()
                .any(|i| i.delegate_key == e.delegate_key)
        })
        .map(|e| e.generation)
        .min()
        .unwrap();
    let highest_local = LOCAL_STATE_LINEAGE
        .iter()
        .map(|e| e.generation)
        .max()
        .unwrap();
    assert!(lowest_identity > highest_local);
    assert_eq!(
        lineage_key(&lineage[0]).bytes(),
        lineage[0].delegate_key.as_slice()
    );
}

#[test]
fn a_silent_identity_generation_makes_an_unknown_alias_an_error() {
    let mut tables = AliasTables::default();
    tables.add(206, HashMap::new());
    tables.incomplete = true;
    let mut counts = MappingCounts::default();
    let newer = NewerAliases::default();
    assert!(map_local_state(&golden("ls_state"), 206, &tables, &newer, &mut counts).is_err());
}

#[test]
fn an_alias_resolves_in_its_own_release_first() {
    let mut tables = AliasTables::default();
    let (old, new) = (Addr([1; 24]), Addr([2; 24]));
    tables.add(205, HashMap::from([("alice".to_string(), old)]));
    tables.add(206, HashMap::from([("alice".to_string(), new)]));
    tables.add(204, HashMap::new());
    assert_eq!(tables.resolve(205, "alice"), AliasOwner::Identity(old));
    assert_eq!(tables.resolve(206, "alice"), AliasOwner::Identity(new));
    assert_eq!(
        tables.resolve(204, "alice"),
        AliasOwner::Identity(new),
        "its own row answered, and the newest knows it"
    );
    assert_eq!(tables.resolve(206, "bob"), AliasOwner::NoIdentity);
    assert_eq!(tables.resolve(203, "alice"), AliasOwner::Unresolved);
}

/// The most the node can deliver is read, far more than the 122 contacts or
/// 1000 messages a smaller limit would have stranded, and one byte more
/// counts as no answer everywhere.
#[test]
fn a_reply_at_the_limit_is_read_and_one_past_it_is_not() {
    use freenet_stdlib::client_api::streaming::{CHUNK_SIZE, MAX_TOTAL_CHUNKS};
    assert_eq!(
        MAX_LEGACY_REPLY_BYTES,
        MAX_TOTAL_CHUNKS as usize * CHUNK_SIZE
    );
    let mut padded = golden("identity_state_seeded");
    padded.resize(MAX_LEGACY_REPLY_BYTES, b' ');
    let delegate = Delegate::new();
    let node = Node::default();
    node.set(im(206), answer(padded.clone()));
    walk(&delegate, &node, no_inbox());
    assert_eq!(delegate.identities().len(), 1);

    padded.push(b' ');
    let delegate = Delegate::new();
    let node = Node::default();
    node.set(im(206), answer(padded));
    let outcome = walk(&delegate, &node, no_inbox());
    assert!(delegate.identities().is_empty());
    assert!(outcome.report.unwrap().report.any_unresponsive());
}

#[test]
fn an_item_over_its_size_cap_is_refused_and_counted() {
    let huge = "x".repeat(freenet_mail_protocol::MAX_ITEM_BYTES);
    let reply = golden_edited("ls_state", r#""body":"b""#, &format!(r#""body":"{huge}""#));
    let mut tables = AliasTables::default();
    tables.add(206, HashMap::from([("alice".to_string(), alice())]));
    let mut counts = MappingCounts::default();
    let newer = NewerAliases::default();
    let pairs = map_local_state(&reply, 206, &tables, &newer, &mut counts).unwrap();
    // The golden draft and sent message both hold that body.
    assert_eq!(counts.oversized, 2);
    let refused = pairs
        .iter()
        .filter(|(k, _)| matches!(PairKey::decode(k), Some(PairKey::Refused(_))))
        .count();
    assert_eq!(refused, 2);
}

#[test]
fn every_pair_key_round_trips() {
    let addr = Addr([0xA1; 24]);
    for key in [
        PairKey::Identity(addr),
        PairKey::Contact(addr),
        PairKey::Message {
            kind: ItemKind::Archived,
            owner: addr,
            id: [3; 16],
        },
        PairKey::Flags(addr),
        PairKey::IdentitySettings(addr),
        PairKey::GlobalSettings,
        PairKey::Orphan([4; 16]),
        PairKey::Refused([5; 16]),
    ] {
        assert_eq!(PairKey::decode(&key.encode()), Some(key));
    }
    assert_eq!(PairKey::decode(b"xx/00"), None);
    assert_eq!(PairKey::decode(b"id/not-hex"), None);
}

#[test]
fn a_marker_follows_the_crates_contract() {
    use freenet_migrate::MigrationMarker::{Done, InProgress};
    let none = StoredMarker::default();
    assert_eq!(none.read(), None);
    let started = none.with(InProgress { saw_data: true });
    assert_eq!(started.read(), Some(InProgress { saw_data: true }));
    // Never lowered.
    let kept = started.with(InProgress { saw_data: false });
    assert_eq!(kept.read(), Some(InProgress { saw_data: true }));
    let done = started.with(Done { had_data: true });
    assert_eq!(done.read(), Some(Done { had_data: true }));
    // An import started beside an empty seal: the seal is wrong.
    let sealed = none.with(Done { had_data: false });
    assert_eq!(sealed.read(), Some(Done { had_data: false }));
    let contradicted = sealed.with(InProgress { saw_data: true });
    assert_eq!(contradicted.read(), Some(InProgress { saw_data: true }));
    // Recording in progress does not erase a done marker.
    assert_eq!(done.with(InProgress { saw_data: false }).done, Some(true));
}

#[test]
fn a_record_of_an_older_hash_becomes_a_pending_migration() {
    let legacy = MigrationMarkers {
        inbox_wasm_hash: Some("old".into()),
        ..MigrationMarkers::default()
    };
    let adopted = adopt_legacy_markers(&MigrationMarkers::default(), &legacy, 206, "cur", "aft");
    assert_eq!(adopted.pending_migration_from.as_deref(), Some("old"));
    assert_eq!(adopted.imported_generation, Some(206));
    // Stamped by the new version before the walk, with no import behind the
    // stamp: an identity restored by hand. Still pending, so it is retried.
    let stored = MigrationMarkers {
        inbox_wasm_hash: Some("cur".into()),
        ..MigrationMarkers::default()
    };
    let adopted = adopt_legacy_markers(&stored, &legacy, 205, "cur", "aft");
    assert_eq!(adopted.inbox_wasm_hash.as_deref(), Some("cur"));
    assert_eq!(adopted.pending_migration_from.as_deref(), Some("old"));
    // At the current hash there is nothing to move.
    let current = MigrationMarkers {
        inbox_wasm_hash: Some("cur".into()),
        ..MigrationMarkers::default()
    };
    let adopted = adopt_legacy_markers(&stored, &current, 206, "cur", "aft");
    assert_eq!(adopted.pending_migration_from, None);
    // The same stamp, but written by importing a newer row: an older row's
    // record is history, not a migration still to do.
    let imported = adopted;
    assert_eq!(
        adopt_legacy_markers(&imported, &legacy, 205, "cur", "aft"),
        imported
    );
    // A retry of the same row cannot put back what a landed migration cleared.
    assert_eq!(
        adopt_legacy_markers(&imported, &legacy, 206, "cur", "aft"),
        imported
    );
}

/// 205 got in first, its newer row having been silent past the hold. When 206
/// answers it replaces 205's record, so 205's pending migration goes.
#[test]
fn a_newer_row_replaces_the_markers_of_an_older_one() {
    let older = MigrationMarkers {
        inbox_wasm_hash: Some("old".into()),
        pending_migration_from: Some("old".into()),
        imported_generation: Some(205),
        ..MigrationMarkers::default()
    };
    let newer = MigrationMarkers {
        inbox_wasm_hash: Some("cur".into()),
        ..MigrationMarkers::default()
    };
    let adopted = adopt_legacy_markers(&older, &newer, 206, "cur", "aft");
    assert_eq!(adopted.inbox_wasm_hash.as_deref(), Some("cur"));
    assert_eq!(adopted.pending_migration_from, None);
    assert_eq!(adopted.imported_generation, Some(206));
}

#[test]
fn the_walk_backs_off_only_for_a_run_of_typed_not_installed() {
    fn status(streak: u32, then_silent: bool) -> JournalStatus {
        let delegate = Delegate::new();
        let mut last = None;
        for _ in 0..streak.max(1) {
            last = walk(&delegate, &Node::default(), no_inbox()).status;
        }
        if then_silent {
            let node = Node::default();
            node.set(im(206), LegacyReply::NoAnswer("timed out".into()));
            last = walk(&delegate, &node, no_inbox()).status;
        }
        last.unwrap()
    }
    let young = status(1, false);
    assert!(walk_this_load(&young, 1), "not yet");
    let settled_absent = status(ABSENT_WALKS_BEFORE_BACKING_OFF, false);
    assert!(!walk_this_load(&settled_absent, 1));
    assert!(walk_this_load(&settled_absent, 0), "still walks sometimes");
    let silent = status(ABSENT_WALKS_BEFORE_BACKING_OFF, true);
    assert!(
        walk_this_load(&silent, 1),
        "silence is asked again every load"
    );
    let complete = JournalStatus::Complete { rejected_items: 0 };
    assert!(!walk_this_load(&complete, 0));
}

/// An import under way may have left a partial copy. However long its
/// predecessor then reads as not installed, the walk does not back off.
#[test]
fn the_walk_does_not_back_off_from_an_import_under_way() {
    let delegate = Delegate::new();
    delegate.faults.borrow_mut().import_fails = Some(FailureCode::Busy);
    let node = Node::default();
    node.set(im(206), answer(golden("identity_state_seeded")));
    let outcome = walk(&delegate, &node, no_inbox());
    assert!(outcome.status.unwrap().interrupted_import());
    let mut last = None;
    for _ in 0..ABSENT_WALKS_BEFORE_BACKING_OFF {
        last = walk(&delegate, &Node::default(), no_inbox()).status;
    }
    let status = last.unwrap();
    let JournalStatus::Incomplete { pending, .. } = &status else {
        panic!("{status:?}");
    };
    assert!(
        pending
            .iter()
            .all(|p| p.absent_streak >= ABSENT_WALKS_BEFORE_BACKING_OFF)
    );
    assert!(status.interrupted_import());
    assert!(walk_this_load(&status, 1), "the Started row keeps it going");
}

#[test]
fn only_a_complete_journal_settles_the_migration() {
    assert_eq!(settled(None), Settled::Retry);
    assert_eq!(settled(Some(&JournalStatus::NotStarted)), Settled::Retry);
    assert_eq!(
        settled(Some(&JournalStatus::Incomplete {
            pending: Vec::new(),
            rejected_items: 0
        })),
        Settled::Retry
    );
    assert_eq!(
        settled(Some(&JournalStatus::Complete { rejected_items: 0 })),
        Settled::Complete
    );
}

/// A source pin, on purpose. `JournalStatus` is `#[non_exhaustive]`, so the
/// wildcard in `settled` guards a status a later crate adds. No input can
/// reach it today: `only_a_complete_journal_settles_the_migration` names
/// every variant that exists and stays green if the wildcard is inverted.
#[test]
fn the_wildcard_status_arm_retries() {
    let source = include_str!("mod.rs");
    let body = source
        .split_once("pub(crate) fn settled(")
        .expect("settled exists")
        .1;
    let arm = body.lines().find(|l| l.trim_start().starts_with("_ =>"));
    assert_eq!(arm.map(str::trim), Some("_ => Settled::Retry,"));
}

// ── Merge laws ──────────────────────────────────────────────────────────────

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// A random settings-like object in a namespace of `prefix`. Each field keeps
/// one shape, as a settings record's do: even fields are values, odd ones
/// nested records. Any field may be missing or null.
fn random_settings(rng: &mut Rng, prefix: &str) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for i in 0..6 {
        let field = format!("{prefix}{i}");
        match rng.next() % 3 {
            0 => {}
            1 => {
                map.insert(field, serde_json::Value::Null);
            }
            _ if i % 2 == 0 => {
                map.insert(field, serde_json::json!(rng.next() % 3));
            }
            _ => {
                let nested = format!("n{}", rng.next() % 2);
                map.insert(field, serde_json::json!({ nested: rng.next() % 3 }));
            }
        }
    }
    serde_json::Value::Object(map)
}

#[test]
fn the_settings_merge_is_idempotent_and_associative() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..2000 {
        let (a, b, c) = (
            random_settings(&mut rng, "f"),
            random_settings(&mut rng, "f"),
            random_settings(&mut rng, "f"),
        );
        let m = merge_fields(&a, &b);
        assert_eq!(merge_fields(&m, &b), m, "re-importing changes nothing");
        assert_eq!(merge_fields(&m, &a), m);
        assert_eq!(
            merge_fields(&merge_fields(&a, &b), &c),
            merge_fields(&a, &merge_fields(&b, &c))
        );
    }
}

/// The settings merge is not commutative when two sides set one field to
/// different values, by design: the plan says the value already present wins.
/// Over disjoint fields no value competes, and order does not matter.
#[test]
fn the_settings_merge_commutes_over_disjoint_fields() {
    let mut rng = Rng(0x1234_5678_9ABC_DEF1);
    for _ in 0..2000 {
        let a = random_settings(&mut rng, "a");
        let b = random_settings(&mut rng, "b");
        assert_eq!(merge_fields(&a, &b), merge_fields(&b, &a));
    }
    let conflict = merge_fields(&serde_json::json!({"f": 1}), &serde_json::json!({"f": 2}));
    assert_eq!(conflict, serde_json::json!({"f": 1}), "present wins");
    let filled = merge_fields(
        &serde_json::json!({"f": null}),
        &serde_json::json!({"f": 2}),
    );
    assert_eq!(filled, serde_json::json!({"f": 2}), "null is missing");
}

#[test]
fn the_flag_merge_is_commutative_idempotent_and_associative() {
    let all: Vec<MergedFlags> = (0..4)
        .map(|n| MergedFlags {
            read: n & 1 != 0,
            deleted: n & 2 != 0,
        })
        .collect();
    for a in &all {
        assert_eq!(a.merged(*a), *a);
        for b in &all {
            assert_eq!(a.merged(*b), b.merged(*a));
            for c in &all {
                assert_eq!(a.merged(*b).merged(*c), a.merged(b.merged(*c)));
            }
        }
    }
}

// ── Orphans, the confirm check, the silent cadence ─────────────────────────

fn orphan_count(delegate: &Delegate) -> usize {
    delegate.list(ItemKind::LegacyOrphan, None).len()
}

/// An alias whose own generation's identity row holds nothing (typed "not
/// installed", or empty) is orphaned after enough loads, and the rest of its
/// row imports. Nothing is orphaned earlier.
#[test]
fn scenario_aliases_of_an_absent_identity_row_become_orphans_after_enough_loads() {
    for identity_row in [
        LegacyReply::NotInstalled,
        answer(br#"{"identities":{}}"#.to_vec()),
    ] {
        let delegate = Delegate::new();
        let node = Node::default();
        node.set(im(206), identity_row);
        node.set(ls(206), answer(golden("ls_state")));
        for load in 0..HOLD_BACK_LOADS {
            walk(&delegate, &node, no_inbox());
            assert_eq!(orphan_count(&delegate), 0, "load {load}");
        }
        let outcome = walk(&delegate, &node, no_inbox());
        assert_eq!(
            orphan_count(&delegate),
            5,
            "draft, sent, kept, archived, settings"
        );
        assert_eq!(outcome.counts.orphaned, 5);
    }
}

/// The identity row imported, then its local-state row was silent for three
/// loads. One failed read of the identity row answers empty as the local
/// state finally arrives. The journal holds the identity row as resolved with
/// data, so the mail waits for it, however often that happens.
#[test]
fn scenario_a_resolved_identity_row_never_stands_as_absent() {
    let delegate = Delegate::new();
    let node = populated_node();
    node.set(ls(206), LegacyReply::NoAnswer("timed out".into()));
    for _ in 0..HOLD_BACK_LOADS {
        walk(&delegate, &node, no_inbox());
    }
    node.set(ls(206), answer(golden("ls_state")));
    for identity_row in [
        answer(br#"{"identities":{}}"#.to_vec()),
        LegacyReply::NotInstalled,
    ] {
        node.set(im(206), identity_row);
        for load in 0..HOLD_BACK_LOADS * 2 {
            walk(&delegate, &node, no_inbox());
            assert_eq!(orphan_count(&delegate), 0, "load {load}");
        }
    }
    node.set(im(206), answer(golden("identity_state_seeded")));
    walk(&delegate, &node, no_inbox());
    assert_eq!(orphan_count(&delegate), 0);
    assert_eq!(delegate.list(ItemKind::Archived, Some(alice())).len(), 1);
}

/// The identity row is silent while its local state's attempts run up. One
/// empty answer then is not three loads of them.
#[test]
fn scenario_one_empty_answer_after_a_silence_orphans_nothing() {
    let delegate = Delegate::new();
    let node = Node::default();
    node.set(im(206), LegacyReply::NoAnswer("timed out".into()));
    node.set(ls(206), answer(golden("ls_state")));
    for _ in 0..HOLD_BACK_LOADS {
        walk(&delegate, &node, no_inbox());
    }
    node.set(im(206), answer(br#"{"identities":{}}"#.to_vec()));
    walk(&delegate, &node, no_inbox());
    assert_eq!(orphan_count(&delegate), 0);
    node.set(im(206), answer(golden("identity_state_seeded")));
    walk(&delegate, &node, no_inbox());
    assert_eq!(orphan_count(&delegate), 0);
    assert_eq!(delegate.list(ItemKind::Archived, Some(alice())).len(), 1);
}

/// Absent answers count only in a row: anything else starts them over.
#[test]
fn scenario_absent_answers_count_only_in_a_row() {
    let delegate = Delegate::new();
    let node = Node::default();
    node.set(ls(206), answer(golden("ls_state")));
    for load in 0..HOLD_BACK_LOADS * 4 {
        let reply = if load % HOLD_BACK_LOADS == HOLD_BACK_LOADS - 1 {
            LegacyReply::NoAnswer("timed out".into())
        } else {
            answer(br#"{"identities":{}}"#.to_vec())
        };
        node.set(im(206), reply);
        walk(&delegate, &node, no_inbox());
        assert_eq!(orphan_count(&delegate), 0, "load {load}");
    }
    let empty = answer(br#"{"identities":{}}"#.to_vec());
    node.set(im(206), empty);
    for load in 0..HOLD_BACK_LOADS {
        walk(&delegate, &node, no_inbox());
        assert_eq!(orphan_count(&delegate), 0, "load {load}");
    }
    walk(&delegate, &node, no_inbox());
    assert_eq!(orphan_count(&delegate), 5);
}

/// An alias only the older identity row knows, as after a v0.2.7 rename. One
/// empty answer from that row on the first load does not orphan it: there is
/// no first-load path around the count.
#[test]
fn scenario_a_transient_empty_in_another_generation_orphans_nothing() {
    let delegate = Delegate::new();
    let node = Node::default();
    let own_table = golden_edited(
        "identity_state_seeded",
        r#"{"identities":{"alice":"#,
        r#"{"identities":{"renamed":"#,
    );
    node.set(im(206), answer(own_table));
    node.set(im(205), answer(br#"{"identities":{}}"#.to_vec()));
    node.set(ls(206), answer(golden("ls_state")));
    walk(&delegate, &node, no_inbox());
    assert_eq!(orphan_count(&delegate), 0);
    node.set(im(205), answer(golden("identity_state_seeded")));
    walk(&delegate, &node, no_inbox());
    assert_eq!(orphan_count(&delegate), 0);
    assert_eq!(delegate.list(ItemKind::Archived, Some(alice())).len(), 1);
}

/// A row that gave no answer holds no decision. However long it stays silent
/// or undecodable, nothing is orphaned and the local-state row stays pending.
#[test]
fn scenario_a_silent_identity_row_never_orphans_its_aliases() {
    for identity_row in [
        LegacyReply::NoAnswer("timed out".into()),
        answer(b"{not json".to_vec()),
    ] {
        let delegate = Delegate::new();
        let node = Node::default();
        node.set(im(206), identity_row);
        node.set(ls(206), answer(golden("ls_state")));
        for _ in 0..HOLD_BACK_LOADS * 3 {
            let outcome = walk(&delegate, &node, no_inbox());
            assert_eq!(orphan_count(&delegate), 0);
            assert_eq!(pending_count(&outcome.status), 4);
        }
    }
}

#[test]
fn rows_left_unresolved_slow_the_walk_to_one_load_in_four() {
    fn status_after(loads: u32) -> JournalStatus {
        let delegate = Delegate::new();
        let node = Node::default();
        node.set(im(206), LegacyReply::NoAnswer("timed out".into()));
        let mut last = None;
        for _ in 0..loads {
            last = walk(&delegate, &node, no_inbox()).status;
        }
        last.unwrap()
    }
    let young = status_after(SILENT_WALKS_BEFORE_SLOWING - 1);
    assert!(walk_this_load(&young, 1), "still every load");
    let old = status_after(SILENT_WALKS_BEFORE_SLOWING);
    assert!(!walk_this_load(&old, 1));
    assert!(walk_this_load(&old, 0), "still walks sometimes");
    assert!(walk_this_load(&old, SLOWED_ONE_LOAD_IN), "one in four");
}

/// Reports whether an inbox exists under one given code hash.
#[derive(Clone)]
struct InboxUnder(Option<String>);

impl V1InboxReader for InboxUnder {
    async fn ciphertexts(&mut self, _: &[u8]) -> Option<Vec<Vec<u8>>> {
        None
    }

    async fn has_inbox(&mut self, _: &[u8], code_hash: &str) -> bool {
        self.0.as_deref() == Some(code_hash)
    }
}

#[test]
fn the_inbox_check_covers_the_current_hash_and_every_registry_row() {
    let hashes = v1_inbox_hashes();
    // An offline build embeds no inbox contract: its current hash is empty,
    // and an empty hash derives no key to ask for.
    assert!(!hashes.iter().any(String::is_empty));
    let current = crate::inbox::INBOX_CODE_HASH.trim();
    assert_eq!(cfg!(feature = "use-node"), !current.is_empty());
    if cfg!(feature = "use-node") {
        assert!(hashes.contains(&current.to_string()));
    }
    for row in crate::legacy_registry::LEGACY_INBOX_CODE_HASHES.iter() {
        assert!(hashes.contains(&bs58::encode(row).into_string()));
    }
}

#[test]
fn an_identity_with_a_v1_inbox_under_any_hash_is_confirmed_and_the_rest_are_not() {
    let hashes = v1_inbox_hashes();
    for (reader, confirmed) in [
        (InboxUnder(Some(hashes[0].clone())), true),
        (InboxUnder(hashes.last().cloned()), true),
        (InboxUnder(Some("another".into())), false),
        (InboxUnder(None), false),
    ] {
        let delegate = Delegate::new();
        walk(&delegate, &populated_node(), no_inbox());
        let listed = delegate.identities();
        assert!(listed.iter().all(|i| !i.confirmed), "imported unconfirmed");
        let done = block_on(confirm_by_inbox(
            &mut delegate.clone(),
            &mut reader.clone(),
            &listed,
        ));
        assert_eq!(!done.is_empty(), confirmed);
        assert_eq!(delegate.identities().iter().all(|i| i.confirmed), confirmed);
    }
}

fn orphan_node() -> Delegate {
    let delegate = Delegate::new();
    let node = Node::default();
    node.set(
        im(206),
        answer(golden_edited(
            "identity_state_seeded",
            r#"{"identities":{"alice":"#,
            r#"{"identities":{"renamed":"#,
        )),
    );
    node.set(ls(206), answer(golden("ls_state")));
    for _ in 0..=HOLD_BACK_LOADS {
        walk(&delegate, &node, no_inbox());
    }
    delegate
}

#[test]
fn moving_orphans_files_them_under_the_identity_and_removes_the_orphans() {
    let delegate = orphan_node();
    assert_eq!(orphan_count(&delegate), 5);
    let owner = delegate.identities()[0].addr;
    let result = block_on(orphans::move_alias(&mut delegate.clone(), "alice", owner));
    let (moved, failure) = (result.moved, result.failure);
    assert_eq!((moved, failure), (5, None));
    assert_eq!(orphan_count(&delegate), 0);
    assert_eq!(delegate.list(ItemKind::Draft, Some(owner)).len(), 1);
    assert_eq!(delegate.list(ItemKind::Archived, Some(owner)).len(), 1);
}

/// An item already under the id wins: the orphan stays, with the reason.
/// One item that cannot move does not block the others, and is reported.
#[test]
fn a_refused_orphan_stays_and_the_rest_move() {
    let delegate = orphan_node();
    let owner = delegate.identities()[0].addr;
    delegate.faults.borrow_mut().capped = Some(ItemKind::Sent);
    let result = block_on(orphans::move_alias(&mut delegate.clone(), "alice", owner));
    assert_eq!((result.moved, result.stayed), (4, 1));
    assert!(result.failure.is_some());
    assert_eq!(orphan_count(&delegate), 1);
}

/// An orphan that does not decode is listed under the empty alias, and moving
/// that group reports it stayed rather than "moved 0".
#[test]
fn an_unreadable_orphan_is_reported_as_staying() {
    let delegate = orphan_node();
    let owner = delegate.identities()[0].addr;
    let item = delegate.list(ItemKind::LegacyOrphan, None)[0].item.clone();
    let mut store = delegate.clone();
    let stored = block_on(super::successor::get_item(&mut store, item.clone()))
        .unwrap()
        .unwrap();
    block_on(super::successor::put_item(
        &mut store,
        item,
        b"not an orphan".to_vec(),
        Some(stored.generation),
    ))
    .unwrap();
    let result = block_on(orphans::move_alias(&mut store, "", owner));
    assert_eq!((result.moved, result.stayed), (0, 1));
    assert!(result.failure.is_some());
}

#[test]
fn moving_an_orphan_never_overwrites_an_item_already_there() {
    let delegate = orphan_node();
    let owner = delegate.identities()[0].addr;
    let is_draft = |o: &Item| {
        let decoded: legacy_delegates::OrphanItem = serde_json::from_slice(&o.body).unwrap();
        decoded.what == "draft"
    };
    let orphan = delegate
        .list(ItemKind::LegacyOrphan, None)
        .into_iter()
        .find(is_draft)
        .unwrap();
    let decoded: legacy_delegates::OrphanItem = serde_json::from_slice(&orphan.body).unwrap();
    let existing = ItemRef {
        kind: ItemKind::Draft,
        owner: Some(owner),
        id: legacy_delegates::text_id(&decoded.legacy_id).to_vec(),
    };
    block_on(successor::put_item(
        &mut delegate.clone(),
        existing.clone(),
        b"mine".to_vec(),
        None,
    ))
    .unwrap();
    let result = block_on(orphans::move_one(&mut delegate.clone(), &orphan, owner));
    assert!(result.is_err());
    let kept = block_on(successor::get_item(&mut delegate.clone(), existing))
        .unwrap()
        .unwrap();
    assert_eq!(kept.body, b"mine");
    assert_eq!(orphan_count(&delegate), 5, "the orphan stays");
}

/// The page lists the identities before it walks, so a slow or silent
/// predecessor never delays the list.
#[test]
fn the_page_lists_identities_before_it_walks() {
    let source = include_str!("../app/identity_store.rs");
    let body = &source[source.find("pub(crate) async fn load_and_report").unwrap()..];
    let listed = body.find("load_identities().await").unwrap();
    let walked = body.find("after_listing(").unwrap();
    assert!(listed < walked);
}

/// The "we couldn't open your previous data" alarm comes from this count. A
/// typed "not installed" is what every new user's node says, and an empty
/// answer is what a node that never ran that version says: neither is silence.
#[test]
fn only_a_silent_or_undecodable_row_counts_as_silent() {
    for (row, silent) in [
        (LegacyReply::NotInstalled, false),
        (answer(br#"{"identities":{}}"#.to_vec()), false),
        (LegacyReply::NoAnswer("timed out".into()), true),
        (answer(b"{not json".to_vec()), true),
    ] {
        let node = Node::default();
        node.set(im(206), row);
        let outcome = walk(&Delegate::new(), &node, no_inbox());
        assert_eq!(outcome.silent_rows > 0, silent);
    }
}

/// A migrated identity is confirmed by its owner before it first sends.
/// Every place a contact card is built checks first. The prompt shows the
/// card of the identity it is asking about, and is not a share.
#[test]
fn sharing_asks_an_unconfirmed_identity_to_confirm_first() {
    let settings = include_str!("../app/settings.rs");
    let click = &settings[settings.find("let on_share = move |_|").unwrap()..];
    let asks = click.find("confirm_share.set(true)").unwrap();
    let opens = click.find("open_share.call(())").unwrap();
    assert!(asks < opens, "settings checks first");
    assert!(click[..asks].contains("if user.read().logged_id().is_some_and(|i| !i.confirmed) {"));

    let login = include_str!("../app/login.rs");
    let click = &login[login.find("testid::FM_ID_SHARE").unwrap()..];
    let asks = click.find("confirm_open.set(true)").unwrap();
    assert!(asks < click.find("open_share.call(())").unwrap());

    let sites = [
        ("settings", settings),
        ("login", login),
        ("the prompt", include_str!("../app/migration_view.rs")),
    ];
    for (name, source) in sites {
        assert_eq!(
            source.matches("ContactCard::from_identity").count(),
            1,
            "{name}: a new card site needs the check"
        );
    }
}

#[test]
fn sending_asks_an_unconfirmed_identity_to_confirm_first() {
    let source = include_str!("../app.rs");
    let send = &source[source.find("let send_now = use_callback").unwrap()..];
    let asks = send.find("confirm_sender.set(true)").unwrap();
    let reads_recipient = send.find("let to_val = to.read()").unwrap();
    assert!(
        asks < reads_recipient,
        "the check precedes everything the send does"
    );
    let check = "if user.read().logged_id().is_some_and(|i| !i.confirmed) {";
    assert!(send[..asks].trim_end().ends_with(check) || send[..asks].contains(check));
}
