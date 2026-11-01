//! The walk, end to end: `freenet_migrate`'s real driver over a scripted
//! legacy node, importing into the real mail delegate's handlers.
//!
//! Old-format inputs come only from `wire-v1/src/golden_v1.txt`, the bytes
//! captured through the frozen crates. A test that needs a variation edits
//! that JSON as text; none builds an old reply with today's types.
//!
//! Tests named `scenario_*` go through the crate's walk. Replacing its entry
//! point with a panic fails exactly those (the PR records the run).

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;

use freenet_mail_protocol::address::address_of;
use freenet_mail_protocol::{
    Addr, IdentityInfo, Item, ItemKind, ItemRef, Op, PROTOCOL_VERSION, Reply, Request, RequestId,
    Response, from_cbor, to_cbor,
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
    AliasTables, LegacyReply, LegacyTransport, MAX_LEGACY_REPLY_BYTES, MappingCounts, PairKey,
    lineage_key, map_identities, map_local_state,
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
    let text = String::from_utf8(golden(name)).unwrap();
    assert!(text.contains(from), "{from} not in {name}");
    text.replace(from, to).into_bytes()
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
}

impl Delegate {
    fn new() -> Self {
        Delegate {
            env: Rc::new(RefCell::new(TestEnv::default())),
            writes_left: Rc::new(RefCell::new(None)),
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
        let inbound =
            InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(to_cbor(&request).unwrap()));
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

    fn markers_written(&self) -> Vec<StoredMarker> {
        self.list(ItemKind::MigrationMarker, None)
            .iter()
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
        self.send(op)
    }
}

/// A scripted node. A delegate with no script is typed "not installed".
#[derive(Clone, Default)]
struct Node {
    replies: Rc<RefCell<HashMap<[u8; 32], LegacyReply>>>,
    asked: Rc<RefCell<Vec<(DelegateKey, Vec<u8>, Vec<u8>)>>>,
}

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
    block_on(run(delegate.clone(), node.clone(), inbox, 0))
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

/// Six messages, so the golden read [1, 2] and deleted [5] all resolve.
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

    // read [1, 2], deleted [5]: the marks land on those messages' hashes.
    let mut flags: Vec<(Vec<u8>, MergedFlags)> = delegate
        .list(ItemKind::Flags, owner)
        .into_iter()
        .map(|i| (i.item.id, serde_json::from_slice(&i.body).unwrap()))
        .collect();
    flags.sort_by(|a, b| a.0.cmp(&b.0));
    let mut want: Vec<(Vec<u8>, MergedFlags)> = [(1u8, true), (2, true), (5, false)]
        .iter()
        .map(|(i, read)| {
            (
                crate::local_state::full_message_id(&[*i; 8]).to_vec(),
                MergedFlags {
                    read: *read,
                    deleted: !*read,
                },
            )
        })
        .collect();
    want.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(flags, want);

    let settings = delegate.item(ItemKind::IdentitySettings, owner).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&settings.body).unwrap();
    assert!(value.get("display_name").is_some());

    let c = outcome.counts;
    assert_eq!(
        (c.identities, c.contacts, c.drafts, c.sent, c.kept, c.archived),
        (1, 1, 1, 1, 1, 1)
    );
    assert_eq!(c.flags_skipped, 0);
    // Generation 205's local-state delegate was never installed here.
    assert_eq!(pending_count(&outcome.status), 1);
    assert_eq!(settled(outcome.status.as_ref()), Settled::Retry);
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

/// A tab that dies at any write leaves the next load able to finish, with
/// the same result as a walk that was never interrupted.
#[test]
fn scenario_an_interrupted_migration_finishes_on_the_next_load() {
    let whole = Delegate::new();
    walk(&whole, &populated_node(), six_messages());
    let want = visible(&whole);
    for died_after in 0..24 {
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
#[test]
fn scenario_a_partial_import_reads_as_interrupted() {
    let mut saw_interrupted = 0;
    for died_after in 0..24 {
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
fn visible(delegate: &Delegate) -> BTreeMap<String, Vec<(Vec<u8>, Vec<u8>)>> {
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
            let mut items: Vec<(Vec<u8>, Vec<u8>)> = delegate
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
    let first = Delegate {
        env: delegate.env.clone(),
        writes_left: delegate.writes_left.clone(),
    };
    walk(&first, &populated_node(), six_messages());
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

#[test]
fn scenario_two_identities_with_one_alias_both_arrive() {
    let delegate = Delegate::new();
    let node = Node::default();
    node.set(im(206), answer(golden("identity_state_seeded")));
    // The same alias for different seeds, in an older generation.
    let seed_nine = (0..32).map(|_| "9").collect::<Vec<_>>().join(",");
    let seed_eight = (0..32).map(|_| "8").collect::<Vec<_>>().join(",");
    let text = String::from_utf8(golden("identity_state_seeded")).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
    let key = parsed["identities"]["alice"]["key"].clone();
    let key_bytes: Vec<u8> = serde_json::from_value(key.clone()).unwrap();
    let key_text = String::from_utf8(key_bytes).unwrap();
    assert!(key_text.contains(&seed_nine));
    let other: Vec<u8> = key_text.replace(&seed_nine, &seed_eight).into_bytes();
    node.set(
        im(205),
        answer(
            golden_edited(
                "identity_state_seeded",
                &key.to_string(),
                &serde_json::to_string(&other).unwrap(),
            ),
        ),
    );
    walk(&delegate, &node, no_inbox());
    let mut aliases: Vec<String> = delegate.identities().into_iter().map(|i| i.alias).collect();
    aliases.sort();
    assert_eq!(aliases.len(), 2);
    assert_eq!(aliases[0], "alice");
    assert!(aliases[1].starts_with("alice ("), "{}", aliases[1]);
}

/// Mail for an alias with no identity is kept, and said to be unmatched, but
/// only once every identity generation has answered: if one went silent it
/// may own the alias, and the local state stays pending instead.
#[test]
fn scenario_an_alias_with_no_identity_is_kept_not_lost() {
    let delegate = Delegate::new();
    let node = Node::default();
    node.set(ls(206), answer(golden("ls_state")));
    let outcome = walk(&delegate, &node, no_inbox());
    let orphans = delegate.list(ItemKind::LegacyOrphan, None);
    assert_eq!(orphans.len(), 5, "draft, sent, kept, archived, settings");
    assert!(outcome.counts.orphaned >= 5);

    let delegate = Delegate::new();
    let node = Node::default();
    node.set(im(206), LegacyReply::NoAnswer("timed out".into()));
    node.set(ls(206), answer(golden("ls_state")));
    let outcome = walk(&delegate, &node, no_inbox());
    assert!(delegate.list(ItemKind::LegacyOrphan, None).is_empty());
    assert!(outcome.report.unwrap().report.any_unresponsive());
}

#[test]
fn scenario_an_inbox_that_cannot_be_read_skips_the_marks_and_counts_them() {
    let delegate = Delegate::new();
    let outcome = walk(&delegate, &populated_node(), no_inbox());
    assert!(delegate.list(ItemKind::Flags, Some(alice())).is_empty());
    assert_eq!(outcome.counts.flags_skipped, 3);
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
    assert_eq!(outcome.counts.flags_skipped, 2);
}

#[test]
fn scenario_a_journal_that_cannot_be_stored_stops_before_any_import() {
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
        answer(golden_edited("identity_state", r#""contact""#, r#""identity""#)),
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
        .filter(|e| IDENTITY_LINEAGE.iter().any(|i| i.delegate_key == e.delegate_key))
        .map(|e| e.generation)
        .min()
        .unwrap();
    let highest_local = LOCAL_STATE_LINEAGE.iter().map(|e| e.generation).max().unwrap();
    assert!(lowest_identity > highest_local);
    assert_eq!(
        lineage_key(&lineage[0]).bytes(),
        lineage[0].delegate_key.as_slice()
    );
}

#[test]
fn a_silent_identity_generation_makes_an_unknown_alias_an_error() {
    let mut tables = AliasTables::default();
    tables.incomplete = true;
    let mut counts = MappingCounts::default();
    assert!(map_local_state(&golden("ls_state"), 206, &tables, &mut counts).is_err());
}

#[test]
fn an_alias_resolves_in_its_own_release_first() {
    let mut tables = AliasTables::default();
    let (old, new) = (Addr([1; 24]), Addr([2; 24]));
    tables.add(205, HashMap::from([("alice".to_string(), old)]));
    tables.add(206, HashMap::from([("alice".to_string(), new)]));
    assert_eq!(tables.resolve(205, "alice"), Some(old));
    assert_eq!(tables.resolve(206, "alice"), Some(new));
    assert_eq!(tables.resolve(204, "alice"), Some(new), "newest knows it");
    assert_eq!(tables.resolve(206, "bob"), None);
}

#[test]
fn a_reply_at_the_cap_is_parsed_and_one_past_it_is_not() {
    let mut counts = MappingCounts::default();
    let mut padded = golden("identity_state_seeded");
    padded.resize(MAX_LEGACY_REPLY_BYTES, b' ');
    assert!(map_identities(&padded, &mut counts).is_ok());
    padded.push(b' ');
    let err = map_identities(&padded, &mut counts).unwrap_err();
    assert!(err.contains("refused"), "{err}");
}

#[test]
fn an_item_over_its_size_cap_is_refused_and_counted() {
    let huge = "x".repeat(freenet_mail_protocol::MAX_ITEM_BYTES);
    let reply = golden_edited("ls_state", r#""body":"b""#, &format!(r#""body":"{huge}""#));
    let mut tables = AliasTables::default();
    tables.add(206, HashMap::from([("alice".to_string(), alice())]));
    let mut counts = MappingCounts::default();
    let pairs = map_local_state(&reply, 206, &tables, &mut counts).unwrap();
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
    let adopted = adopt_legacy_markers(&MigrationMarkers::default(), &legacy, "cur", "aft");
    assert_eq!(adopted.pending_migration_from.as_deref(), Some("old"));
    // Stamped already by the new version: still pending, so it is retried.
    let stored = MigrationMarkers {
        inbox_wasm_hash: Some("cur".into()),
        ..MigrationMarkers::default()
    };
    let adopted = adopt_legacy_markers(&stored, &legacy, "cur", "aft");
    assert_eq!(adopted.inbox_wasm_hash.as_deref(), Some("cur"));
    assert_eq!(adopted.pending_migration_from.as_deref(), Some("old"));
    // At the current hash there is nothing to move.
    let current = MigrationMarkers {
        inbox_wasm_hash: Some("cur".into()),
        ..MigrationMarkers::default()
    };
    let adopted = adopt_legacy_markers(&stored, &current, "cur", "aft");
    assert_eq!(adopted.pending_migration_from, None);
}

#[test]
fn the_walk_backs_off_only_for_a_run_of_typed_not_installed() {
    fn status(streak: u32, import_started: bool) -> JournalStatus {
        let delegate = Delegate::new();
        let mut last = None;
        for _ in 0..streak.max(1) {
            last = walk(&delegate, &Node::default(), no_inbox()).status;
        }
        if import_started {
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
    assert!(walk_this_load(&silent, 1), "silence is asked again every load");
    let complete = JournalStatus::Complete { rejected_items: 0 };
    assert!(!walk_this_load(&complete, 0));
}

#[test]
fn only_a_complete_journal_settles_the_migration() {
    assert_eq!(settled(None), Settled::Retry);
    assert_eq!(
        settled(Some(&JournalStatus::NotStarted)),
        Settled::Retry
    );
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
    let filled = merge_fields(&serde_json::json!({"f": null}), &serde_json::json!({"f": 2}));
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
