//! Scrub, over the same scripted node and real delegate as the walk's tests.
//! Each check has a test where it alone is false and nothing is deleted.

use std::collections::HashSet;

use freenet_mail_protocol::ItemRef;
use serde_json::json;

use super::super::ledger::ledger_item;
use super::super::scrub::{self, Blocker, clearing_order};
use super::super::successor::{merged_put, settings_item};
use super::*;

const IDENTITY_205: u32 = 205 + IDENTITY_GENERATION_OFFSET;
const IDENTITY_206: u32 = 206 + IDENTITY_GENERATION_OFFSET;

/// One generation installed, which is most users: every other row is typed
/// "not installed" for good and the journal is never `Complete`.
fn usual_node() -> Node {
    let node = Node::default();
    node.set(im(206), answer(golden("identity_state_seeded")));
    node.set(ls(206), answer(golden("ls_state")));
    node
}

/// Enough loads for the rows of the other generation to stand as absent.
fn settle(delegate: &Delegate, node: &Node) -> WalkOutcome {
    let mut last = walk(delegate, node, six_messages());
    for _ in 1..HOLD_BACK_LOADS {
        last = walk(delegate, node, six_messages());
    }
    last
}

fn scrub_now(delegate: &Delegate, node: &Node, outcome: &WalkOutcome) -> Vec<Blocker> {
    let mut store = delegate.clone();
    block_on(scrub::run(&mut store, node.clone(), outcome, || {}))
}

/// The user confirms a backup of `addr`, as `mark_backed_up` stores it.
fn back_up(delegate: &Delegate, addr: Addr) {
    let at = delegate.ledger().migration_started_ms.unwrap() + 1;
    let mut store = delegate.clone();
    block_on(merged_put(&mut store, settings_item(addr), |stored| {
        let mut settings: serde_json::Value = serde_json::from_slice(stored?).unwrap();
        settings["last_backup_at"] = json!(at);
        Some(serde_json::to_vec(&settings).unwrap())
    }))
    .unwrap();
}

/// Everything the checks want, short of the deletes: the snapshot is written
/// and the user has backed up.
fn ready(delegate: &Delegate, node: &Node) -> WalkOutcome {
    let outcome = settle(delegate, node);
    assert_eq!(
        scrub_now(delegate, node, &outcome),
        vec![Blocker::NoBackup(1)]
    );
    back_up(delegate, alice());
    outcome
}

/// The legacy deletes sent so far, as `(delegate key, message)`.
fn deletes(node: &Node) -> Vec<(DelegateKey, Vec<u8>)> {
    node.asked
        .borrow()
        .iter()
        .filter(|(_, _, request)| legacy_delete(request).is_some())
        .map(|(key, _, request)| (key.clone(), request.clone()))
        .collect()
}

fn assert_nothing_deleted(node: &Node, blockers: &[Blocker]) {
    assert!(!blockers.is_empty());
    assert_eq!(deletes(node), Vec::new(), "{blockers:?}");
}

fn row_text(node: &Node, entry: &freenet_migrate::DelegateLineageEntry) -> String {
    match node.replies.borrow().get(&entry.delegate_key) {
        Some(LegacyReply::Answer(bytes)) => String::from_utf8(bytes.clone()).unwrap(),
        other => panic!("{other:?}"),
    }
}

/// `edit` applied to the row's stored state, as a v0.2.7 tab left open writes.
fn old_tab_writes(
    node: &Node,
    entry: &freenet_migrate::DelegateLineageEntry,
    edit: impl Fn(&mut serde_json::Value),
) {
    let mut state = serde_json::from_str(&row_text(node, entry)).unwrap();
    edit(&mut state);
    node.set(entry, answer(serde_json::to_vec(&state).unwrap()));
}

/// The usual user is reached: one generation installed, a journal that never
/// completes, one backup. If scrub could not run this fails.
#[test]
fn scenario_the_usual_user_is_scrubbed() {
    let delegate = Delegate::new();
    let node = usual_node();
    let outcome = ready(&delegate, &node);
    assert!(!outcome.status.as_ref().unwrap().is_complete());
    assert_eq!(scrub_now(&delegate, &node, &outcome), Vec::new());

    let ledger = delegate.ledger();
    assert_eq!(ledger.scrubbed.get(&206), Some(&true));
    assert_eq!(ledger.scrubbed.get(&IDENTITY_206), Some(&true));
    assert_eq!(ledger.scrubbed.len(), 2, "absent rows are not touched");
    assert!(ledger.scrub_blockers.is_empty());

    assert_eq!(
        row_text(&node, im(206)),
        r#"{"identities":{}}"#,
        "the key is gone"
    );
    let left: serde_json::Value = serde_json::from_str(&row_text(&node, ls(206))).unwrap();
    for map in ["drafts", "sent", "kept", "archived"] {
        assert_eq!(left["aliases"]["alice"][map], json!({}), "{map}");
    }
    let owner = Some(alice());
    assert_eq!(delegate.identities().len(), 1, "the new delegate holds it");
    assert_eq!(delegate.list(ItemKind::Archived, owner).len(), 1);
    assert_eq!(delegate.list(ItemKind::Kept, owner).len(), 1);
    assert_eq!(delegate.list(ItemKind::Draft, owner).len(), 1);
    assert_eq!(delegate.list(ItemKind::Sent, owner).len(), 1);

    let absent = [lineage_key(im(205)), lineage_key(ls(205))];
    assert!(deletes(&node).iter().all(|(key, _)| !absent.contains(key)));
}

/// A later load neither repeats a delete nor brings anything back.
#[test]
fn scenario_a_finished_scrub_stays_finished() {
    let delegate = Delegate::new();
    let node = usual_node();
    let outcome = ready(&delegate, &node);
    scrub_now(&delegate, &node, &outcome);
    let sent = deletes(&node).len();
    let before = visible(&delegate);
    let outcome = walk(&delegate, &node, six_messages());
    assert_eq!(scrub_now(&delegate, &node, &outcome), Vec::new());
    assert_eq!(deletes(&node).len(), sent);
    assert_eq!(visible(&delegate), before);
}

/// Local state goes first and identities last, whatever the lineage's order.
#[test]
fn scenario_local_state_is_cleared_before_identities() {
    let delegate = Delegate::new();
    let node = usual_node();
    let outcome = ready(&delegate, &node);
    scrub_now(&delegate, &node, &outcome);
    let order: Vec<bool> = deletes(&node)
        .iter()
        .map(|(key, _)| *key == lineage_key(im(206)))
        .collect();
    assert_eq!(order.len(), 5, "draft, sent, kept, archived, identity");
    assert_eq!(order, [false, false, false, false, true]);
}

/// An interruption at every delete: the next load finishes the job, sends
/// nothing that already landed, and the identity outlives its mail.
#[test]
fn scenario_an_interrupted_scrub_resumes_and_does_not_repeat() {
    for answered in 0..5 {
        let delegate = Delegate::new();
        let node = usual_node();
        let outcome = ready(&delegate, &node);
        *node.writes_left.borrow_mut() = Some(answered);
        let blockers = scrub_now(&delegate, &node, &outcome);
        let generation = if answered < 4 { 206 } else { IDENTITY_206 };
        assert_eq!(blockers, vec![Blocker::RowFailed { generation }]);
        assert_eq!(delegate.ledger().scrubbed.get(&generation), Some(&false));
        assert!(row_text(&node, im(206)).contains("alice"), "{answered}");

        // The one the node went silent on reached it, or may have: a delete
        // is sent again only if the row still shows the item.
        node.asked.borrow_mut().pop();
        *node.writes_left.borrow_mut() = None;
        assert_eq!(scrub_now(&delegate, &node, &outcome), Vec::new());
        let sent = deletes(&node);
        let distinct: HashSet<_> = sent.iter().collect();
        assert_eq!(sent.len(), 5, "{answered}");
        assert_eq!(distinct.len(), 5, "{answered}");
    }
}

/// The tab can die between the row's last delete and its journal entry.
#[test]
fn scenario_a_row_emptied_before_its_journal_entry_finishes() {
    let delegate = Delegate::new();
    let node = usual_node();
    let outcome = ready(&delegate, &node);
    scrub_now(&delegate, &node, &outcome);
    let mut store = delegate.clone();
    block_on(super::super::ledger::update_ledger(&mut store, |l| {
        l.scrubbed.insert(IDENTITY_206, false);
    }))
    .unwrap();
    let sent = deletes(&node).len();
    assert_eq!(scrub_now(&delegate, &node, &outcome), Vec::new());
    assert_eq!(deletes(&node).len(), sent);
    assert_eq!(delegate.ledger().scrubbed.get(&IDENTITY_206), Some(&true));
}

/// An acknowledgement is an empty reply, which proves nothing. Only the
/// re-read does, and a row that fails it stops the run for this load.
#[test]
fn a_delete_that_did_not_take_leaves_the_row_unfinished() {
    let delegate = Delegate::new();
    let node = usual_node();
    let outcome = ready(&delegate, &node);
    *node.writes_ignored.borrow_mut() = true;
    let blockers = scrub_now(&delegate, &node, &outcome);
    assert_eq!(blockers, vec![Blocker::RowFailed { generation: 206 }]);
    assert_eq!(delegate.ledger().scrubbed.get(&206), Some(&false));
    assert!(!deletes(&node).iter().any(|d| d.0 == lineage_key(im(206))));
}

// ── Each check alone ────────────────────────────────────────────────────────

#[test]
fn nothing_is_deleted_without_a_journal() {
    let delegate = Delegate::new();
    let node = usual_node();
    let mut outcome = ready(&delegate, &node);
    outcome.status = None;
    let blockers = scrub_now(&delegate, &node, &outcome);
    assert_eq!(blockers, vec![Blocker::NoJournal]);
    assert_nothing_deleted(&node, &blockers);
}

#[test]
fn a_started_row_is_never_clear() {
    let delegate = Delegate::new();
    let node = usual_node();
    ready(&delegate, &node);
    // LS-205 begins importing and an item keeps failing, so it stays Started;
    // then it reads as not installed for longer than the count.
    node.set(im(205), answer(golden("identity_state_seeded")));
    node.set(
        ls(205),
        answer(golden_edited("ls_state", r#""d1""#, r#""d9""#)),
    );
    delegate.faults.borrow_mut().owned_creates_not_found = true;
    let mut started = walk(&delegate, &node, six_messages());
    delegate.faults.borrow_mut().owned_creates_not_found = false;
    node.set(ls(205), LegacyReply::NotInstalled);
    for _ in 0..=HOLD_BACK_LOADS {
        started = walk(&delegate, &node, six_messages());
    }
    let status = started.status.as_ref().unwrap();
    assert!(status.interrupted_import(), "{status:?}");
    let blockers = scrub_now(&delegate, &node, &started);
    assert_eq!(blockers, vec![Blocker::NotClear { generation: 205 }]);
    assert_nothing_deleted(&node, &blockers);
}

/// One load short of the count: the same answers, not yet standing.
#[test]
fn an_absence_short_of_the_count_is_not_clear() {
    let delegate = Delegate::new();
    let node = usual_node();
    let mut outcome = walk(&delegate, &node, six_messages());
    for _ in 2..HOLD_BACK_LOADS {
        outcome = walk(&delegate, &node, six_messages());
    }
    let blockers = scrub_now(&delegate, &node, &outcome);
    assert_eq!(
        blockers,
        vec![
            Blocker::NotClear { generation: 205 },
            Blocker::NotClear {
                generation: IDENTITY_205
            }
        ]
    );
    assert_nothing_deleted(&node, &blockers);
}

/// Silence is not absence, however long it has gone on.
#[test]
fn a_silent_row_is_not_clear() {
    let delegate = Delegate::new();
    let node = usual_node();
    node.set(ls(205), LegacyReply::NoAnswer("timed out".into()));
    let mut outcome = settle(&delegate, &node);
    for _ in 0..HOLD_BACK_LOADS {
        outcome = walk(&delegate, &node, six_messages());
    }
    back_up(&delegate, alice());
    let blockers = scrub_now(&delegate, &node, &outcome);
    assert_eq!(blockers, vec![Blocker::NotClear { generation: 205 }]);
    assert_nothing_deleted(&node, &blockers);
}

/// The ledger says it stands. The read made now says otherwise, whether it
/// has data or says nothing at all.
#[test]
fn a_standing_row_must_answer_the_same_way_now() {
    for now in [
        LegacyReply::NoAnswer("timed out".into()),
        answer(golden("ls_state")),
    ] {
        let delegate = Delegate::new();
        let node = usual_node();
        let outcome = ready(&delegate, &node);
        node.set(ls(205), now);
        let blockers = scrub_now(&delegate, &node, &outcome);
        assert_eq!(blockers, vec![Blocker::NotClear { generation: 205 }]);
        assert_nothing_deleted(&node, &blockers);
    }
}

/// A row that answers empty stands like one that is not installed, in both
/// families, and an empty local-state reply is read as local state.
#[test]
fn a_row_that_answers_empty_stands_as_absent() {
    let delegate = Delegate::new();
    let node = usual_node();
    node.set(im(205), answer(br#"{"identities":{}}"#.to_vec()));
    node.set(ls(205), answer(br#"{"aliases":{}}"#.to_vec()));
    let outcome = ready(&delegate, &node);
    assert_eq!(scrub_now(&delegate, &node, &outcome), Vec::new());
    assert_eq!(delegate.ledger().scrubbed.len(), 2);
}

/// Identity row clear, its local-state row pending: nothing goes from either.
#[test]
fn an_identity_row_waits_for_its_local_state_row() {
    let delegate = Delegate::new();
    let node = usual_node();
    node.set(ls(206), LegacyReply::NoAnswer("timed out".into()));
    let mut outcome = settle(&delegate, &node);
    back_up(&delegate, alice());
    for _ in 0..HOLD_BACK_LOADS {
        outcome = walk(&delegate, &node, six_messages());
    }
    let blockers = scrub_now(&delegate, &node, &outcome);
    assert_eq!(blockers, vec![Blocker::NotClear { generation: 206 }]);
    assert_nothing_deleted(&node, &blockers);
}

/// The pairing as its own rule: the rows of the other generation still go.
#[test]
fn the_order_leaves_out_an_identity_row_with_its_local_state_pending() {
    let rows = lineage();
    let row = |generation| rows.iter().find(|e| e.generation == generation).unwrap();
    let targets = [row(IDENTITY_206), row(205), row(IDENTITY_205)];
    let not_clear = HashSet::from([206]);
    let order: Vec<u32> = clearing_order(&targets, &not_clear)
        .iter()
        .map(|e| e.generation)
        .collect();
    assert_eq!(order, [205, IDENTITY_205]);
}

#[test]
fn a_rejected_item_blocks() {
    let delegate = Delegate::new();
    let node = usual_node();
    delegate.faults.borrow_mut().capped = Some(ItemKind::Kept);
    let outcome = ready_rejected(&delegate, &node);
    let blockers = scrub_now(&delegate, &node, &outcome);
    assert_eq!(blockers, vec![Blocker::Rejected(1)]);
    assert_nothing_deleted(&node, &blockers);
}

fn ready_rejected(delegate: &Delegate, node: &Node) -> WalkOutcome {
    let outcome = settle(delegate, node);
    scrub_now(delegate, node, &outcome);
    back_up(delegate, alice());
    outcome
}

/// `orphan_node`'s user, one generation installed: the alias `alice` matches
/// no identity, so the row's items are orphans.
fn orphaned() -> (Delegate, Node, WalkOutcome) {
    let delegate = Delegate::new();
    let node = usual_node();
    node.set(
        im(206),
        answer(golden_edited(
            "identity_state_seeded",
            r#"{"identities":{"alice":"#,
            r#"{"identities":{"renamed":"#,
        )),
    );
    settle(&delegate, &node);
    let outcome = walk(&delegate, &node, six_messages());
    assert_eq!(orphan_count(&delegate), 5);
    (delegate, node, outcome)
}

#[test]
fn an_orphan_blocks() {
    let (delegate, node, outcome) = orphaned();
    back_up(&delegate, alice());
    let blockers = scrub_now(&delegate, &node, &outcome);
    assert_eq!(blockers, vec![Blocker::Orphans(5)]);
    assert_nothing_deleted(&node, &blockers);
}

/// A move before the snapshot leaves the orphan's id in neither the delegate
/// nor the snapshot. The record of the move is what lets scrub run.
#[test]
fn an_orphan_moved_before_the_snapshot_does_not_block() {
    let (delegate, node, outcome) = orphaned();
    let mut store = delegate.clone();
    let moved = block_on(orphans::move_alias(&mut store, "alice", alice()));
    assert_eq!(moved.moved, 5);
    back_up(&delegate, alice());
    assert_eq!(scrub_now(&delegate, &node, &outcome), Vec::new());
    assert_eq!(delegate.ledger().scrubbed.len(), 2);
    assert!(!row_text(&node, im(206)).contains("renamed"));
}

/// Written by an old tab after the walk, with no address to import under.
#[test]
fn an_undecodable_identity_blocks() {
    let delegate = Delegate::new();
    let node = usual_node();
    let outcome = ready(&delegate, &node);
    old_tab_writes(&node, im(206), |state| {
        let mut bad = state["identities"]["alice"].clone();
        bad["key"] = json!([1, 2, 3]);
        state["identities"]["broken"] = bad;
    });
    let blockers = scrub_now(&delegate, &node, &outcome);
    assert_eq!(blockers, vec![Blocker::Unmappable(1)]);
    assert_nothing_deleted(&node, &blockers);
}

/// The imported `last_backup_at` (the golden row has one) is not a backup.
#[test]
fn an_imported_backup_time_does_not_count() {
    let delegate = Delegate::new();
    let node = usual_node();
    let outcome = settle(&delegate, &node);
    let stored = delegate.item(ItemKind::IdentitySettings, Some(alice()));
    let settings: serde_json::Value = serde_json::from_slice(&stored.unwrap().body).unwrap();
    assert_eq!(settings["last_backup_at"], json!(9), "it was imported");
    let blockers = scrub_now(&delegate, &node, &outcome);
    assert_eq!(blockers, vec![Blocker::NoBackup(1)]);
    assert_nothing_deleted(&node, &blockers);
}

/// The notice offers the key on the first load, long before the other rows
/// stand. A backup made then is the one the user will make.
#[test]
fn a_backup_on_the_first_load_counts() {
    let delegate = Delegate::new();
    let node = usual_node();
    walk(&delegate, &node, six_messages());
    back_up(&delegate, alice());
    let outcome = settle(&delegate, &node);
    assert_eq!(scrub_now(&delegate, &node, &outcome), Vec::new());
}

/// An identity already on the mail delegate, which the walk did not count as
/// brought in, is still being scrubbed and still needs its backup.
#[test]
fn an_identity_the_ledger_does_not_list_needs_a_backup_too() {
    let delegate = Delegate::new();
    let node = usual_node();
    let outcome = ready(&delegate, &node);
    let mut store = delegate.clone();
    block_on(super::super::ledger::update_ledger(&mut store, |l| {
        l.migrated.clear();
    }))
    .unwrap();
    block_on(merged_put(&mut store, settings_item(alice()), |stored| {
        let mut settings: serde_json::Value = serde_json::from_slice(stored?).unwrap();
        settings["last_backup_at"] = json!(9);
        Some(serde_json::to_vec(&settings).unwrap())
    }))
    .unwrap();
    let blockers = scrub_now(&delegate, &node, &outcome);
    assert_eq!(blockers, vec![Blocker::NoBackup(1)]);
    assert_nothing_deleted(&node, &blockers);
}

// ── The id sets ─────────────────────────────────────────────────────────────

/// A user deletion after import: not stored, in the snapshot, and no block.
#[test]
fn a_user_deletion_after_import_does_not_block() {
    let delegate = Delegate::new();
    let node = usual_node();
    let outcome = ready(&delegate, &node);
    let drafts = delegate.list(ItemKind::Draft, Some(alice()));
    delegate
        .send(Op::DeleteItem {
            item: drafts[0].item.clone(),
            expected_gen: drafts[0].generation,
        })
        .unwrap();
    assert_eq!(scrub_now(&delegate, &node, &outcome), Vec::new());
    assert!(!row_text(&node, ls(206)).contains("\"d1\":"));
}

/// An item that never arrived: an old tab saved it after the walk.
#[test]
fn an_item_that_never_arrived_blocks() {
    let delegate = Delegate::new();
    let node = usual_node();
    let outcome = ready(&delegate, &node);
    old_tab_writes(&node, ls(206), |state| {
        let drafts = &mut state["aliases"]["alice"]["drafts"];
        drafts["d2"] = drafts["d1"].clone();
    });
    let blockers = scrub_now(&delegate, &node, &outcome);
    assert_eq!(
        blockers,
        vec![Blocker::NotImported {
            generation: 206,
            ids: 1
        }]
    );
    assert_nothing_deleted(&node, &blockers);
}

/// A new item on the mail delegate cannot stand in for a missing one, as a
/// count would let it.
#[test]
fn an_extra_item_does_not_mask_a_missing_one() {
    let delegate = Delegate::new();
    let node = usual_node();
    let outcome = ready(&delegate, &node);
    let drafts = delegate.list(ItemKind::Draft, Some(alice()));
    let item = ItemRef {
        id: vec![7; 16],
        ..drafts[0].item.clone()
    };
    let body = drafts[0].body.clone();
    delegate
        .send(Op::PutItem {
            item,
            body,
            expected_gen: None,
        })
        .unwrap();
    old_tab_writes(&node, ls(206), |state| {
        let drafts = &mut state["aliases"]["alice"]["drafts"];
        drafts["d2"] = drafts["d1"].clone();
    });
    let blockers = scrub_now(&delegate, &node, &outcome);
    assert_nothing_deleted(&node, &blockers);
}

/// A record that keeps failing to read is not a deletion, and neither is an
/// identity the delegate cannot list.
#[test]
fn an_unreadable_record_is_not_a_deletion() {
    let delegate = Delegate::new();
    let node = usual_node();
    let outcome = ready(&delegate, &node);
    delegate.blind(&delegate.list(ItemKind::Archived, Some(alice()))[0].item);
    let blockers = scrub_now(&delegate, &node, &outcome);
    assert!(
        matches!(blockers[..], [Blocker::Delegate(_)]),
        "{blockers:?}"
    );
    assert_nothing_deleted(&node, &blockers);

    let delegate = Delegate::new();
    let node = usual_node();
    let outcome = ready(&delegate, &node);
    let hidden = delegate.hide_identity(alice());
    let blockers = scrub_now(&delegate, &node, &outcome);
    assert!(
        matches!(blockers[..], [Blocker::Delegate(_)]),
        "{blockers:?}"
    );
    assert_nothing_deleted(&node, &blockers);
    delegate.restore_identity(hidden);
}

/// A row that imported and now reads as nothing has failed to read.
#[test]
fn a_row_that_imported_and_reads_empty_blocks() {
    let delegate = Delegate::new();
    let node = usual_node();
    let outcome = ready(&delegate, &node);
    node.set(ls(206), answer(br#"{"aliases":{}}"#.to_vec()));
    let blockers = scrub_now(&delegate, &node, &outcome);
    assert_eq!(blockers, vec![Blocker::Unread { generation: 206 }]);
    assert_nothing_deleted(&node, &blockers);
}

/// The reasons reach the status report, and there is one snapshot.
#[test]
fn the_report_says_why_and_the_snapshot_is_written_once() {
    let delegate = Delegate::new();
    let node = usual_node();
    let outcome = settle(&delegate, &node);
    scrub_now(&delegate, &node, &outcome);
    let ledger = delegate.ledger();
    let report = status_report(outcome.status.as_ref(), &ledger);
    assert!(report.contains("NoBackup"), "{report}");
    assert_eq!(ledger.snapshot_chunks, Some(1));

    // A later read does not widen it: the old tab's draft stays unproven.
    old_tab_writes(&node, ls(206), |state| {
        let drafts = &mut state["aliases"]["alice"]["drafts"];
        drafts["d2"] = drafts["d1"].clone();
    });
    let before = delegate.list(ItemKind::MigrationMarker, None);
    scrub_now(&delegate, &node, &outcome);
    let ledger_id = ledger_item().id;
    let unchanged = |items: Vec<Item>| -> Vec<Item> {
        items
            .into_iter()
            .filter(|i| i.item.id != ledger_id)
            .collect()
    };
    assert_eq!(
        unchanged(delegate.list(ItemKind::MigrationMarker, None)),
        unchanged(before)
    );
}
