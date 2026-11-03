//! The filter, the caps and the joins, each at its boundary.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::*;
use freenet_email_inbox_v2::merge::{WINDOW_BACK, WINDOW_FORWARD, merge};
use freenet_email_inbox_v2::types::*;
use freenet_email_inbox_v2::{Inbox, Params, apply, is_valid, sync};
use freenet_stdlib::prelude::*;

const T: u64 = 1_800_000_000 / DAY * DAY;
const FAR: u64 = T + 300 * DAY;
const OPEN: QuarantineMode = QuarantineMode::Open;

fn owner(epoch: u32) -> OwnerRecord {
    world().owner(1, epoch, OPEN, BTreeMap::new())
}

fn clean(raw: InboxState) -> InboxState {
    merge(&Rules::V1, &world().params, vec![raw.into()]).unwrap()
}

/// Which of `messages` a state at `time` keeps.
fn kept(
    owner: OwnerRecord,
    time: u64,
    revoked: Vec<Revocation>,
    usage: Vec<PassUsage>,
    messages: Vec<(B32, Message)>,
) -> Vec<bool> {
    let w = world();
    let raw = w.raw(owner, w.time(time), revoked, usage, messages.clone());
    let merged = clean(raw);
    messages
        .iter()
        .map(|(id, _)| merged.messages.contains_key(id))
        .collect()
}

#[test]
fn the_window_at_its_edges() {
    let w = world();
    // owner_time on the hour, so both edges are reachable.
    let back = T - WINDOW_BACK;
    let top = T + WINDOW_FORWARD;
    let msgs = vec![
        w.owner_msg(ct(8192, 1), back - HOUR),
        w.owner_msg(ct(8192, 2), back),
        w.owner_msg(ct(8192, 3), top),
        w.owner_msg(ct(8192, 4), top + HOUR),
    ];
    assert_eq!(
        kept(owner(3), T, vec![], vec![], msgs),
        [false, true, true, false]
    );
    // Off the hour, the edge moves by less than a slot.
    let msgs = vec![
        w.owner_msg(ct(8192, 1), back),
        w.owner_msg(ct(8192, 2), back + HOUR),
    ];
    assert_eq!(kept(owner(3), T + 1, vec![], vec![], msgs), [false, true]);
}

/// Decision 14: quarantine mail may lead `owner_time` by two days, not 400.
/// Pass and owner mail keep the long window, for contacts writing to an
/// owner who is offline.
#[test]
fn quarantine_mail_leads_by_two_days_at_most() {
    let w = world();
    let pass = w.pass(1, 3, FAR + 400 * DAY, PassClass::Contact);
    let msgs = vec![
        w.quarantine_msg(ct(8192, 1), T + 2 * DAY, None),
        w.quarantine_msg(ct(8192, 2), T + 2 * DAY + HOUR, None),
        w.pass_msg(&pass, ct(8192, 3), T + 2 * DAY + HOUR),
        w.owner_msg(ct(8192, 4), T + 2 * DAY + HOUR),
        w.pass_msg(&pass, ct(8192, 5), T + WINDOW_FORWARD),
    ];
    assert_eq!(
        kept(owner(3), T, vec![], vec![], msgs),
        [true, false, true, true, true]
    );
}

/// Review r1 S4: a stranger's mail dated as far ahead as it may be leaves the
/// window four days after it was drained, so its tombstone can go then, and a
/// sender refilling quarantine with far-future mail cannot make the owner keep
/// tombstones for 400 days.
#[test]
fn a_far_future_stranger_message_needs_its_tombstone_four_days() {
    let w = world();
    let far_ahead = w.quarantine_msg(ct(8192, 1), T + 2 * DAY, None);
    let tomb = BTreeMap::from([(far_ahead.0, far_ahead.1.sent_time)]);
    let drained = w.owner(2, 3, OPEN, tomb);
    assert_eq!(
        kept(drained, T, vec![], vec![], vec![far_ahead.clone()]),
        [false]
    );
    // The tombstone pruned, four days on: redelivery does not bring it back.
    let pruned = w.owner(3, 3, OPEN, BTreeMap::new());
    let later = T + 4 * DAY + HOUR;
    assert_eq!(
        kept(pruned.clone(), later, vec![], vec![], vec![far_ahead]),
        [false]
    );
    // Further ahead than that was never admitted.
    let beyond = w.quarantine_msg(ct(8192, 2), T + 3 * DAY, None);
    assert_eq!(kept(pruned, T, vec![], vec![], vec![beyond]), [false]);
}

#[test]
fn sent_time_is_a_whole_hour_and_ciphertext_a_padded_size() {
    let w = world();
    let msgs = vec![
        w.owner_msg(ct(8192, 1), T + 1),
        w.owner_msg(ct(8192, 2), T + HOUR - 1),
        w.owner_msg(ct(8191, 3), T),
        w.owner_msg(ct(8193, 4), T),
        w.owner_msg(ct(16384, 5), T),
        w.owner_msg(ct(32768, 6), T),
        w.owner_msg(ct(65536, 7), T),
    ];
    let keep = kept(owner(3), T, vec![], vec![], msgs);
    assert_eq!(keep, [false, false, false, false, true, true, false]);
}

#[test]
fn a_pass_is_refused_from_its_expiry() {
    let w = world();
    let pass = w.pass(1, 3, T + DAY, PassClass::Contact);
    let msgs = vec![
        w.pass_msg(&pass, ct(8192, 1), T + DAY - HOUR),
        w.pass_msg(&pass, ct(8192, 2), T + DAY),
    ];
    assert_eq!(kept(owner(3), T, vec![], vec![], msgs), [true, false]);
}

/// Decision 17: a pass's expiry is a whole day, and so are a revocation's and a
/// usage entry's. To the second, an expiry minus the pass lifetime gives the
/// moment of the grant or renewal, which the pass message in the contact's own
/// inbox also shows, and links the pair.
#[test]
fn expiries_are_whole_days() {
    let w = world();
    let off_the_day = [FAR + 1, FAR + HOUR, FAR + DAY - 1, FAR + 1234];
    let mut msgs = vec![w.pass_msg(&w.pass(1, 3, FAR, PassClass::Contact), ct(8192, 1), T)];
    for (i, expiry) in off_the_day.iter().enumerate() {
        let pass = w.pass(10 + i as u64, 3, *expiry, PassClass::Contact);
        msgs.push(w.pass_msg(&pass, ct(8192, 10 + i as u64), T));
    }
    assert_eq!(
        kept(owner(3), T, vec![], vec![], msgs),
        [true, false, false, false, false]
    );

    // Off the day, a revocation does not revoke and a usage entry does not
    // count: each is dropped as it arrives.
    let pass = w.pass(2, 3, FAR, PassClass::Invite { max_messages: 1 });
    let msg = w.pass_msg(&pass, ct(8192, 2), T);
    for expiry in off_the_day {
        let revoked = vec![w.revocation(pass.cert.pass_id, expiry, 3)];
        assert_eq!(
            kept(owner(3), T, revoked, vec![], vec![msg.clone()]),
            [true]
        );
        let used = vec![w.usage(pass.cert.pass_id, 1, expiry)];
        assert_eq!(kept(owner(3), T, vec![], used, vec![msg.clone()]), [true]);
        let merged = clean(w.raw(
            owner(3),
            w.time(T),
            [
                w.revocation(id_of(8), expiry, 3),
                w.revocation(id_of(9), FAR, 3),
            ],
            [w.usage(id_of(8), 1, expiry), w.usage(id_of(9), 1, FAR)],
            [],
        ));
        assert_eq!(
            merged.revoked.keys().copied().collect::<Vec<_>>(),
            [id_of(9)]
        );
        assert_eq!(merged.usage.keys().copied().collect::<Vec<_>>(), [id_of(9)]);
    }
    // The controls: on the day, each does.
    let revoked = vec![w.revocation(pass.cert.pass_id, FAR, 3)];
    assert_eq!(
        kept(owner(3), T, revoked, vec![], vec![msg.clone()]),
        [false]
    );
    let used = vec![w.usage(pass.cert.pass_id, 1, FAR)];
    assert_eq!(kept(owner(3), T, vec![], used, vec![msg]), [false]);
}

#[test]
fn a_pass_of_another_epoch_is_refused_either_way() {
    let w = world();
    let msgs = vec![
        w.pass_msg(&w.pass(1, 2, FAR, PassClass::Contact), ct(8192, 1), T),
        w.pass_msg(&w.pass(2, 3, FAR, PassClass::Contact), ct(8192, 2), T),
        w.pass_msg(&w.pass(3, 4, FAR, PassClass::Contact), ct(8192, 3), T),
    ];
    assert_eq!(
        kept(owner(3), T, vec![], vec![], msgs),
        [false, true, false]
    );
}

/// Decision 18: while `owner_time < prev_epoch_until`, passes of the epoch
/// before `pass_epoch` are admitted too. Not two epochs back, not a later one,
/// and not once the grace has ended or when there is none.
#[test]
fn the_previous_epoch_is_admitted_until_its_grace_ends() {
    let w = world();
    let grace = T + 14 * DAY;
    let msgs: Vec<_> = (2..=5)
        // Sent a day before the grace ends, so inside the window at every time below.
        .map(|e| {
            w.pass_msg(
                &w.pass(e, e as u32, FAR, PassClass::Contact),
                ct(8192, e),
                grace - DAY,
            )
        })
        .collect();
    let bumped = |until| w.owner_grace(2, 4, until, OPEN, BTreeMap::new());
    assert_eq!(
        kept(bumped(grace), T, vec![], vec![], msgs.clone()),
        [false, true, true, false],
        "epochs 2 to 5 in its grace"
    );
    assert_eq!(
        kept(bumped(grace), grace - 1, vec![], vec![], msgs.clone()),
        [false, true, true, false],
        "a second before it ends"
    );
    assert_eq!(
        kept(bumped(grace), grace, vec![], vec![], msgs.clone()),
        [false, false, true, false],
        "when it ends"
    );
    assert_eq!(
        kept(bumped(0), T, vec![], vec![], msgs),
        [false, false, true, false],
        "an emergency bump has none"
    );
}

/// Decision 18: through the grace, the previous epoch's revocations are kept and
/// still revoke. Pruning by epoch waits for the grace to end, when the passes
/// they revoke stop being admitted too.
#[test]
fn the_previous_epochs_revocations_last_as_long_as_its_passes() {
    let w = world();
    let grace = T + 14 * DAY;
    let bumped = w.owner_grace(2, 4, grace, OPEN, BTreeMap::new());
    let (old, older) = (
        w.pass(1, 3, FAR, PassClass::Contact),
        w.pass(2, 3, FAR, PassClass::Contact),
    );
    let msgs = vec![
        w.pass_msg(&old, ct(8192, 1), T),
        w.pass_msg(&older, ct(8192, 2), T),
    ];
    let revoked = vec![
        w.revocation(old.cert.pass_id, FAR, 3),
        w.revocation(id_of(9), FAR, 2),
    ];
    assert_eq!(
        kept(bumped.clone(), T, revoked.clone(), vec![], msgs.clone()),
        [false, true],
        "the revocation of epoch 3 still revokes"
    );
    let at = |time| {
        let merged = clean(w.raw(bumped.clone(), w.time(time), revoked.clone(), [], []));
        merged.revoked.keys().copied().collect::<Vec<_>>()
    };
    assert_eq!(at(T), [id_of(1)], "epoch 3's is kept, epoch 2's is not");
    assert_eq!(at(grace - 1), [id_of(1)]);
    assert!(at(grace).is_empty(), "pruned when the grace ends");
    // Without a grace, pruned at once.
    let emergency = w.owner(2, 4, OPEN, BTreeMap::new());
    let merged = clean(w.raw(emergency, w.time(T), revoked, [], []));
    assert!(merged.revoked.is_empty());
}

/// Decision 18, the laws across the end of a grace: a peer before it and a peer
/// after it converge in either order, and redelivering either changes nothing.
#[test]
fn a_grace_ending_between_two_peers_converges() {
    let w = world();
    let params = w.params;
    let grace = T + 14 * DAY;
    let bumped = w.owner_grace(2, 4, grace, OPEN, BTreeMap::new());
    let (old, revoked_old) = (
        w.pass(1, 3, FAR, PassClass::Contact),
        w.pass(2, 3, FAR, PassClass::Contact),
    );
    let fresh = w.pass(3, 4, FAR, PassClass::Contact);
    let before = encode(&w.raw(
        bumped.clone(),
        w.time(T),
        [w.revocation(revoked_old.cert.pass_id, FAR, 3)],
        [],
        [
            w.pass_msg(&old, ct(8192, 1), grace - DAY),
            w.pass_msg(&revoked_old, ct(8192, 2), grace - DAY),
            w.pass_msg(&fresh, ct(8192, 3), grace - DAY),
        ],
    ));
    let after = encode(&w.raw(bumped, w.time(grace), [], [], []));
    let before = encode(&clean(decode(&before).unwrap()));
    assert!(is_valid(&Rules::V1, &params, &before) && is_valid(&Rules::V1, &params, &after));
    let held: InboxState = decode(&before).unwrap();
    assert_eq!(held.messages.len(), 2, "the old pass and the new one");
    let ab = apply(&Rules::V1, &params, &before, update_state(after.clone())).unwrap();
    let ba = apply(&Rules::V1, &params, &after, update_state(before.clone())).unwrap();
    assert_eq!(ab, ba);
    assert!(is_valid(&Rules::V1, &params, &ab));
    let merged: InboxState = decode(&ab).unwrap();
    assert!(merged.revoked.is_empty());
    assert_eq!(merged.messages.len(), 1, "only the new epoch's pass");
    for redelivered in [before, after] {
        assert_eq!(
            apply(&Rules::V1, &params, &ab, update_state(redelivered)).unwrap(),
            ab
        );
    }
}

#[test]
fn a_tombstoned_message_is_dropped_and_others_are_not() {
    let w = world();
    let (gone, other) = (w.owner_msg(ct(8192, 1), T), w.owner_msg(ct(8192, 2), T));
    let tombstones = BTreeMap::from([(gone.0, T)]);
    let o = w.owner(1, 3, OPEN, tombstones);
    assert_eq!(kept(o, T, vec![], vec![], vec![gone, other]), [false, true]);
}

#[test]
fn the_tombstone_count_is_capped_and_nothing_else_about_them_is() {
    let w = world();
    let full: BTreeMap<B32, u64> = (0..Rules::V1.tombstones as u64)
        .map(|i| {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&i.to_be_bytes());
            // Outside any window: pruning is the client's, not the contract's.
            (serde_bytes::ByteArray::new(id), i)
        })
        .collect();
    let at_cap = w.raw(w.owner(1, 3, OPEN, full.clone()), w.time(T), [], [], []);
    assert!(is_valid(&Rules::V1, &w.params, &encode(&at_cap)));
    let mut over = full;
    over.insert(serde_bytes::ByteArray::new([0xFF; 32]), T);
    let over = w.raw(w.owner(1, 3, OPEN, over), w.time(T), [], [], []);
    assert!(!is_valid(&Rules::V1, &w.params, &encode(&over)));
    assert_eq!(
        merge(&Rules::V1, &w.params, vec![over.into()]),
        Err(Malformed("too many tombstones"))
    );
}

#[test]
fn a_revocation_is_pruned_exactly_at_expiry_plus_the_window() {
    let w = world();
    // Expiries are whole days, so the time moves to a second before the edge.
    let keep = w.revocation(id_of(1), T - WINDOW_BACK + DAY, 3);
    let drop = w.revocation(id_of(2), T - WINDOW_BACK, 3);
    let older = w.revocation(id_of(3), FAR, 2);
    let current = w.revocation(id_of(4), FAR, 3);
    let later = w.revocation(id_of(5), FAR, 4);
    let merged = clean(w.raw(
        owner(3),
        w.time(T + DAY - 1),
        [keep, drop, older, current, later],
        [],
        [],
    ));
    let ids: BTreeSet<B16> = merged.revoked.keys().copied().collect();
    assert_eq!(ids, BTreeSet::from([id_of(1), id_of(4), id_of(5)]));
}

#[test]
fn a_usage_entry_is_pruned_exactly_at_expiry_plus_the_window() {
    let w = world();
    let keep = w.usage(id_of(1), 1, T - WINDOW_BACK + DAY);
    let drop = w.usage(id_of(2), 1, T - WINDOW_BACK);
    let merged = clean(w.raw(owner(3), w.time(T + DAY - 1), [], [keep, drop], []));
    assert_eq!(merged.usage.keys().copied().collect::<Vec<_>>(), [id_of(1)]);
}

#[test]
fn a_live_revocation_drops_its_pass_only() {
    let w = world();
    let (p1, p2) = (
        w.pass(1, 3, FAR, PassClass::Contact),
        w.pass(2, 3, FAR, PassClass::Contact),
    );
    let msgs = vec![
        w.pass_msg(&p1, ct(8192, 1), T),
        w.pass_msg(&p2, ct(8192, 2), T),
    ];
    let r = w.revocation(p1.cert.pass_id, FAR, 3);
    assert_eq!(kept(owner(3), T, vec![r], vec![], msgs), [false, true]);
}

/// Decision 10: the filter reads what pruning left. A revocation that has run
/// out does not filter, or it and the message cycle under redelivery.
#[test]
fn a_pruned_revocation_does_not_filter() {
    let w = world();
    let pass = w.pass(1, 3, FAR, PassClass::Contact);
    let msgs = vec![w.pass_msg(&pass, ct(8192, 1), T)];
    let by_expiry = w.revocation(pass.cert.pass_id, T - WINDOW_BACK, 3);
    assert_eq!(
        kept(owner(3), T, vec![by_expiry], vec![], msgs.clone()),
        [true]
    );
    let by_epoch = w.revocation(pass.cert.pass_id, FAR, 2);
    assert_eq!(kept(owner(3), T, vec![by_epoch], vec![], msgs), [true]);
}

#[test]
fn the_highest_entry_wins_on_one_id() {
    let w = world();
    let params = w.params;
    let o = owner(3);
    let state =
        |r: Vec<Revocation>, u: Vec<PassUsage>| encode(&w.raw(o.clone(), w.time(T), r, u, []));
    let (shorter, longer) = (
        w.revocation(id_of(1), FAR, 3),
        w.revocation(id_of(1), FAR + DAY, 3),
    );
    let (less, more) = (w.usage(id_of(1), 1, FAR + DAY), w.usage(id_of(1), 2, FAR));
    let a = state(vec![shorter], vec![less]);
    let b = state(vec![longer.clone()], vec![more.clone()]);
    let merged: InboxState =
        decode(&apply(&Rules::V1, &params, &a, update_state(b)).unwrap()).unwrap();
    assert_eq!(merged.revoked[&id_of(1)], longer);
    assert_eq!(merged.usage[&id_of(1)], more);
}

#[test]
fn a_contact_pass_holds_eight_earliest_first() {
    let w = world();
    let pass = w.pass(1, 3, FAR, PassClass::Contact);
    let msgs: Vec<_> = (0..10)
        .map(|i| w.pass_msg(&pass, ct(8192, i), T + i * HOUR))
        .collect();
    let keep = kept(owner(3), T, vec![], vec![], msgs);
    assert_eq!(
        keep,
        [true, true, true, true, true, true, true, true, false, false]
    );
}

#[test]
fn an_invite_holds_two_and_counts_what_was_used() {
    let w = world();
    let class = PassClass::Invite { max_messages: 3 };
    let pass = w.pass(1, 3, FAR, class);
    let msgs: Vec<_> = (0..3)
        .map(|i| w.pass_msg(&pass, ct(8192, i), T + i * HOUR))
        .collect();
    let usage = |used| vec![w.usage(pass.cert.pass_id, used, FAR)];
    assert_eq!(
        kept(owner(3), T, vec![], vec![], msgs.clone()),
        [true, true, false]
    );
    assert_eq!(
        kept(owner(3), T, vec![], usage(1), msgs.clone()),
        [true, true, false]
    );
    assert_eq!(
        kept(owner(3), T, vec![], usage(2), msgs.clone()),
        [true, false, false]
    );
    assert_eq!(
        kept(owner(3), T, vec![], usage(3), msgs.clone()),
        [false, false, false]
    );
    assert_eq!(
        kept(owner(3), T, vec![], usage(9), msgs),
        [false, false, false]
    );
}

/// Review r1 S2. The owner drains one of an invite's two messages: owner
/// version 2 tombstones it and a usage entry counts it. Whichever of the two
/// reaches a peer first, the other message stays held: the usage entry counts
/// only once the owner version it names is joined, which is when the tombstone
/// it counts is there too.
#[test]
fn a_usage_entry_ahead_of_its_tombstone_drops_nothing() {
    let w = world();
    let params = w.params;
    let pass = w.pass(1, 3, FAR, PassClass::Invite { max_messages: 2 });
    let (m1, m2) = (
        w.pass_msg(&pass, ct(8192, 1), T),
        w.pass_msg(&pass, ct(8192, 2), T + HOUR),
    );
    let start = encode(&w.raw(owner(3), w.time(T), [], [], [m1.clone(), m2.clone()]));
    let tomb = BTreeMap::from([(m1.0, m1.1.sent_time)]);
    let drained = InboxDelta {
        owner: Some(w.owner(2, 3, OPEN, tomb)),
        ..InboxDelta::default()
    };
    let counted = InboxDelta {
        usage: BTreeMap::from([(pass.cert.pass_id, w.usage_at(pass.cert.pass_id, 1, FAR, 2))]),
        ..InboxDelta::default()
    };
    let deliver = |state: &[u8], part: &InboxDelta| {
        let data = vec![UpdateData::Delta(encode(part).into())];
        apply(&Rules::V1, &params, state, data).unwrap()
    };
    let held = |state: &[u8]| {
        let s: InboxState = decode(state).unwrap();
        (
            s.messages.contains_key(&m1.0),
            s.messages.contains_key(&m2.0),
        )
    };
    for (first, second) in [(&counted, &drained), (&drained, &counted)] {
        let one = deliver(&start, first);
        assert!(held(&one).1, "the second message is held after one part");
        let both = deliver(&one, second);
        assert_eq!(held(&both), (false, true));
        // An entry that arrived first was dropped, so its redelivery adds it.
        let settled = deliver(&deliver(&both, first), second);
        assert_eq!(held(&settled), (false, true));
        let s: InboxState = decode(&settled).unwrap();
        assert_eq!(s.usage.len(), 1, "the count stands");
        for part in [first, second] {
            assert_eq!(
                deliver(&settled, part),
                settled,
                "redelivery changes nothing"
            );
        }
    }
}

#[test]
fn the_pass_pool_is_round_robin() {
    let w = world();
    // 20 passes with 8 each: 160 candidates, 64 places. Each pass sends all of
    // its mail before the next begins, so ordering by time alone would give
    // eight passes everything. Every pass keeps its first three, and four of
    // the twenty a fourth.
    let mut msgs = Vec::new();
    for p in 0..20u64 {
        let pass = w.pass(p, 3, FAR, PassClass::Contact);
        for i in 0..8u64 {
            msgs.push(w.pass_msg(&pass, ct(8192, p * 100 + i), T + (p * 10 + i) * HOUR));
        }
    }
    let merged = clean(w.raw(owner(3), w.time(T), [], [], msgs.clone()));
    assert_eq!(merged.messages.len(), 64);
    let mut per_pass: BTreeMap<B16, u32> = BTreeMap::new();
    for message in merged.messages.values() {
        let Admission::Pass { cert, .. } = &message.admission else {
            panic!()
        };
        *per_pass.entry(cert.pass_id).or_default() += 1;
    }
    assert_eq!(per_pass.len(), 20);
    assert_eq!(per_pass[&id_of(0)], 4, "the earliest sender's fourth");
    assert_eq!(per_pass[&id_of(3)], 4);
    assert_eq!(per_pass[&id_of(4)], 3, "by sent_time within k");
    assert_eq!(
        per_pass[&id_of(7)],
        3,
        "not eight, as time alone would give"
    );
    assert_eq!(per_pass[&id_of(19)], 3);
}

#[test]
fn the_owner_pool_holds_eight_earliest() {
    let w = world();
    let msgs: Vec<_> = (0..10)
        .map(|i| w.owner_msg(ct(8192, i), T + i * HOUR))
        .collect();
    let keep = kept(owner(3), T, vec![], vec![], msgs);
    assert_eq!(
        keep,
        [true, true, true, true, true, true, true, true, false, false]
    );
}

#[test]
fn quarantine_holds_sixteen_by_salted_rank() {
    let w = world();
    let msgs: Vec<_> = (0..40)
        .map(|i| w.quarantine_msg(ct(8192, i), T, None))
        .collect();
    let ranked = |time: u64| {
        let salt = blake3::hash(&encode(&w.time(time)));
        let mut order: Vec<_> = msgs
            .iter()
            .map(|(id, _)| {
                let mut h = blake3::Hasher::new();
                h.update(salt.as_bytes());
                h.update(id.as_slice());
                (*h.finalize().as_bytes(), *id)
            })
            .collect();
        order.sort();
        order.truncate(16);
        order.into_iter().map(|(_, id)| id).collect::<BTreeSet<_>>()
    };
    for time in [T, T + HOUR] {
        let merged = clean(w.raw(owner(3), w.time(time), [], [], msgs.clone()));
        assert_eq!(
            merged.messages.keys().copied().collect::<BTreeSet<_>>(),
            ranked(time)
        );
    }
    assert_ne!(
        ranked(T),
        ranked(T + HOUR),
        "the salt moves with the attestation"
    );
}

#[test]
fn the_pools_do_not_share_places() {
    let w = world();
    let pass = w.pass(1, 3, FAR, PassClass::Contact);
    let mut msgs = vec![w.pass_msg(&pass, ct(8192, 1), T)];
    msgs.extend((2..30).map(|i| w.quarantine_msg(ct(8192, i), T, None)));
    msgs.extend((30..50).map(|i| w.owner_msg(ct(8192, i), T)));
    let merged = clean(w.raw(owner(3), w.time(T), [], [], msgs));
    assert_eq!(merged.messages.len(), 1 + 8 + 16);
}

fn revocations(count: u64, start: u64) -> Vec<Revocation> {
    (0..count)
        .map(|i| world().revocation(id_of(start + i), FAR, 3))
        .collect()
}

#[test]
fn a_state_one_short_of_the_revocation_cap_holds_passes() {
    let w = world();
    let pass = w.pass(1 << 40, 3, FAR, PassClass::Contact);
    let msg = w.pass_msg(&pass, ct(8192, 1), T);
    let revoked = revocations(Rules::V1.revoked as u64 - 1, 0);
    let raw = w.raw(owner(3), w.time(T), revoked, [], [msg]);
    assert!(is_valid(&Rules::V1, &w.params, &encode(&raw)));
}

#[test]
fn at_the_revocation_cap_a_state_holds_no_pass_mail() {
    let w = world();
    let pass = w.pass(1 << 40, 3, FAR, PassClass::Contact);
    let msg = w.pass_msg(&pass, ct(8192, 1), T);
    let bare = w.quarantine_msg(ct(8192, 2), T, None);
    let revoked = revocations(Rules::V1.revoked as u64, 0);
    let raw = w.raw(owner(3), w.time(T), revoked, [], [msg, bare.clone()]);
    assert!(!is_valid(&Rules::V1, &w.params, &encode(&raw)));
    let merged = clean(raw);
    assert_eq!(merged.revoked.len(), Rules::V1.revoked);
    assert_eq!(
        merged.messages.keys().copied().collect::<Vec<_>>(),
        [bare.0]
    );
    assert!(is_valid(&Rules::V1, &w.params, &encode(&merged)));
}

/// Two valid states, each under the cap, whose union is over it: the smallest
/// ids stay, in either order, and passes are refused. A later time that prunes
/// a kept entry brings the set under the cap, and the pass mail in again.
#[test]
fn a_union_over_the_revocation_cap_keeps_the_smallest_and_recovers() {
    let w = world();
    let params = w.params;
    let cap = Rules::V1.revoked as u64;
    let pass = w.pass(1 << 40, 3, FAR, PassClass::Contact);
    let msg = w.pass_msg(&pass, ct(8192, 1), T);

    // Id 0 is the smallest and runs out first. Ids 1.. never do.
    let mut high = vec![w.revocation(id_of(0), T, 3)];
    // Together they name ids 0 to cap, one more than the cap.
    high.extend(revocations(cap - 2, 3));
    let low = encode(&w.raw(
        owner(3),
        w.time(T),
        revocations(cap - 1, 1),
        [],
        [msg.clone()],
    ));
    let high = encode(&w.raw(owner(3), w.time(T), high, [], []));
    assert!(is_valid(&Rules::V1, &params, &low) && is_valid(&Rules::V1, &params, &high));

    let ab = apply(&Rules::V1, &params, &low, update_state(high.clone())).unwrap();
    let ba = apply(&Rules::V1, &params, &high, update_state(low.clone())).unwrap();
    assert_eq!(ab, ba);
    assert!(is_valid(&Rules::V1, &params, &ab));
    let merged: InboxState = decode(&ab).unwrap();
    assert_eq!(merged.revoked.len(), cap as usize);
    assert_eq!(merged.revoked.keys().next(), Some(&id_of(0)));
    assert_eq!(merged.revoked.keys().next_back(), Some(&id_of(cap - 1)));
    assert!(merged.messages.is_empty(), "passes refused while full");

    // Redelivery changes nothing.
    assert_eq!(
        apply(&Rules::V1, &params, &ab, update_state(low.clone())).unwrap(),
        ab
    );
    assert_eq!(
        apply(&Rules::V1, &params, &ab, update_state(high)).unwrap(),
        ab
    );

    // The time that prunes id 0. The message is still inside the window.
    let later = encode(&w.raw(owner(3), w.time(T + WINDOW_BACK), [], [], []));
    let pruned = apply(&Rules::V1, &params, &ab, update_state(later)).unwrap();
    let thin: InboxState = decode(&pruned).unwrap();
    assert_eq!(thin.revoked.len(), cap as usize - 1);
    let back = apply(&Rules::V1, &params, &pruned, update_state(low)).unwrap();
    assert!(is_valid(&Rules::V1, &params, &back));
    let back: InboxState = decode(&back).unwrap();
    assert_eq!(back.messages.keys().copied().collect::<Vec<_>>(), [msg.0]);
}

/// Decision 23: a full set (4096) refuses every pass, and the way out is an
/// emergency epoch bump, grace 0, which prunes the old epoch's revocations at
/// once, so the new epoch's pass mail comes in at the same time.
#[test]
fn an_emergency_bump_empties_a_full_set() {
    let w = world();
    let params = w.params;
    let pass = w.pass(1 << 40, 4, FAR, PassClass::Contact);
    let msg = w.pass_msg(&pass, ct(8192, 1), T);
    let full = clean(w.raw(
        owner(3),
        w.time(T),
        revocations(Rules::V1.revoked as u64, 0),
        [],
        [],
    ));
    assert_eq!(full.revoked.len(), Rules::V1.revoked);
    let bump = w.raw(
        w.owner_grace(2, 4, 0, OPEN, BTreeMap::new()),
        w.time(T),
        [],
        [],
        [msg.clone()],
    );
    let merged: InboxState = decode(
        &apply(
            &Rules::V1,
            &params,
            &encode(&full),
            update_state(encode(&bump)),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        merged.revoked.is_empty(),
        "the old epoch's revocations went with it"
    );
    assert_eq!(merged.messages.keys().copied().collect::<Vec<_>>(), [msg.0]);
}

/// Decision 23: a routine bump, with a grace, out of a full set keeps the old
/// epoch's revocations through the grace, so the set stays full and refuses
/// pass mail of both epochs; at the grace's end they are pruned and the mail
/// comes in.
#[test]
fn a_routine_bump_from_a_full_set_refuses_until_the_grace_ends() {
    let w = world();
    let params = w.params;
    let grace = T + 14 * DAY;
    let new = w.pass(1 << 40, 4, FAR, PassClass::Contact);
    let old = w.pass(1 << 41, 3, FAR, PassClass::Contact);
    // Dated near the grace's end, so still inside the window then.
    let msgs = [
        w.pass_msg(&new, ct(8192, 1), grace),
        w.pass_msg(&old, ct(8192, 2), grace - DAY),
    ];
    let full = encode(&clean(w.raw(
        owner(3),
        w.time(T),
        revocations(Rules::V1.revoked as u64, 0),
        [],
        [],
    )));
    let routine = w.owner_grace(2, 4, grace, OPEN, BTreeMap::new());
    let at = |time: u64| -> InboxState {
        let bump = w.raw(routine.clone(), w.time(time), [], [], msgs.clone());
        decode(&apply(&Rules::V1, &params, &full, update_state(encode(&bump))).unwrap()).unwrap()
    };
    let during = at(grace - HOUR);
    assert_eq!(
        during.revoked.len(),
        Rules::V1.revoked,
        "full through the grace"
    );
    assert!(during.messages.is_empty(), "both epochs refused while full");
    let after = at(grace);
    assert!(after.revoked.is_empty(), "pruned at the grace's end");
    assert_eq!(
        after.messages.keys().copied().collect::<Vec<_>>(),
        [msgs[0].0],
        "the new epoch's mail, and not the old epoch's, whose grace is over"
    );
}

#[test]
fn a_summary_cut_mid_entry_is_refused() {
    use ciborium::Value;
    let w = world();
    let state = w.raw(owner(3), w.time(T), [], [], [w.owner_msg(ct(8192, 1), T)]);
    let summary = sync::summarize(&state);
    let mut value: Value = ciborium::from_reader(summary.as_slice()).unwrap();
    let Value::Map(fields) = &mut value else {
        panic!("a map")
    };
    let (_, Value::Bytes(entries)) = fields
        .iter_mut()
        .find(|(k, _)| k.as_text() == Some("messages"))
        .unwrap()
    else {
        panic!("bytes")
    };
    entries.pop();
    let mut cut = Vec::new();
    ciborium::into_writer(&value, &mut cut).unwrap();
    assert_eq!(sync::delta(&state, &cut), Err(Malformed("summary")));
}

#[test]
fn over_the_usage_cap_the_smallest_ids_stay() {
    let w = world();
    let rules = Rules {
        usage: 3,
        ..Rules::V1
    };
    let entries: Vec<_> = (0..5).map(|i| w.usage(id_of(i), 1, FAR)).collect();
    let raw = w.raw(owner(3), w.time(T), [], entries, []);
    assert!(!is_valid(&rules, &w.params, &encode(&raw)));
    let merged = merge(&rules, &w.params, vec![raw.into()]).unwrap();
    assert_eq!(
        merged.usage.keys().copied().collect::<Vec<_>>(),
        [id_of(0), id_of(1), id_of(2)]
    );
    assert!(is_valid(&rules, &w.params, &encode(&merged)));
}

#[test]
fn the_owner_and_time_joins_are_by_their_orders() {
    let w = world();
    let (v1, v2) = (
        w.owner(1, 3, OPEN, BTreeMap::new()),
        w.owner(2, 3, OPEN, BTreeMap::new()),
    );
    let a = encode(&w.raw(v2.clone(), w.time(T), [], [], []));
    let b = encode(&w.raw(v1, w.time(T + DAY), [], [], []));
    let merged: InboxState =
        decode(&apply(&Rules::V1, &w.params, &a, update_state(b)).unwrap()).unwrap();
    assert_eq!((merged.owner.version, merged.time.owner_time), (2, T + DAY));
}

#[test]
fn a_delta_merges_like_the_rest_and_zero_bytes_is_nothing() {
    let w = world();
    let params = w.params;
    let base = encode(&w.raw(owner(3), w.time(T), [], [], []));
    let unchanged = apply(
        &Rules::V1,
        &params,
        &base,
        vec![UpdateData::Delta(vec![].into())],
    );
    assert_eq!(unchanged.unwrap(), base);

    let (id, message) = w.owner_msg(ct(8192, 1), T);
    let delta = InboxDelta {
        messages: BTreeMap::from([(id, message)]),
        ..InboxDelta::default()
    };
    let merged = apply(
        &Rules::V1,
        &params,
        &base,
        vec![UpdateData::Delta(encode(&delta).into())],
    );
    let merged: InboxState = decode(&merged.unwrap()).unwrap();
    assert!(merged.messages.contains_key(&id));

    let mut bad = encode(&delta);
    bad.push(0);
    assert!(
        apply(
            &Rules::V1,
            &params,
            &base,
            vec![UpdateData::Delta(bad.into())]
        )
        .is_err()
    );
}

#[test]
fn a_delta_and_a_state_can_arrive_together() {
    let w = world();
    let base = encode(&w.raw(owner(3), w.time(T), [], [], []));
    let (id1, m1) = w.owner_msg(ct(8192, 1), T);
    let (id2, m2) = w.owner_msg(ct(8192, 2), T);
    let delta = InboxDelta {
        messages: BTreeMap::from([(id1, m1)]),
        ..InboxDelta::default()
    };
    let state = encode(&w.raw(owner(3), w.time(T), [], [], [(id2, m2)]));
    let update = UpdateData::StateAndDelta {
        state: state.into(),
        delta: encode(&delta).into(),
    };
    let merged = apply(&Rules::V1, &w.params, &base, vec![update]).unwrap();
    assert_eq!(decode::<InboxState>(&merged).unwrap().messages.len(), 2);
}

#[test]
fn related_data_is_refused() {
    let w = world();
    let base = encode(&w.raw(owner(3), w.time(T), [], [], []));
    let update = UpdateData::RelatedState {
        related_to: ContractInstanceId::new([1; 32]),
        state: vec![].into(),
    };
    assert!(apply(&Rules::V1, &w.params, &base, vec![update]).is_err());
}

#[test]
fn a_summary_digest_tells_two_encodings_of_one_id_apart() {
    let w = world();
    let params = w.params;
    let pass = w.pass(1, 3, FAR, PassClass::Contact);
    let renewed = w.pass(1, 3, FAR + DAY, PassClass::Contact);
    let older = encode(&w.raw(
        owner(3),
        w.time(T),
        [],
        [],
        [w.pass_msg(&pass, ct(8192, 1), T)],
    ));
    let newer = encode(&w.raw(
        owner(3),
        w.time(T),
        [],
        [],
        [w.pass_msg(&renewed, ct(8192, 1), T)],
    ));
    let (a, b): (InboxState, InboxState) = (decode(&older).unwrap(), decode(&newer).unwrap());
    assert_eq!(a.messages.keys().next(), b.messages.keys().next(), "one id");
    let delta = sync::delta(&b, &sync::summarize(&a)).unwrap();
    assert!(!delta.is_empty(), "the other encoding is sent");
    let via = apply(
        &Rules::V1,
        &params,
        &older,
        vec![UpdateData::Delta(delta.into())],
    )
    .unwrap();
    let whole = apply(&Rules::V1, &params, &older, update_state(newer)).unwrap();
    assert_eq!(via, whole);
}

#[test]
fn each_summary_part_shows_a_difference() {
    let w = world();
    let base = w.raw(owner(3), w.time(T), [], [], []);
    let summary = sync::summarize(&base);
    let others = [
        w.raw(w.owner(2, 3, OPEN, BTreeMap::new()), w.time(T), [], [], []),
        w.raw(owner(3), w.time(T + HOUR), [], [], []),
        w.raw(
            owner(3),
            w.time(T),
            [w.revocation(id_of(1), FAR, 3)],
            [],
            [],
        ),
        w.raw(owner(3), w.time(T), [], [w.usage(id_of(1), 1, FAR)], []),
        w.raw(owner(3), w.time(T), [], [], [w.owner_msg(ct(8192, 1), T)]),
    ];
    for other in others {
        assert!(!sync::delta(&other, &summary).unwrap().is_empty());
    }
    assert!(sync::delta(&base, b"not a summary").is_err());
}

fn params_of(p: &Params) -> Parameters<'static> {
    Parameters::from(p.to_bytes())
}

/// The trait the node calls. No path returns `RequestRelated`, and none asks
/// for a related contract.
#[test]
fn the_contract_interface_never_asks_for_related_contracts() {
    let w = world();
    let good = encode(&w.raw(owner(3), w.time(T), [], [], []));
    let validate = |state: Vec<u8>| {
        Inbox::validate_state(
            params_of(&w.params),
            State::from(state),
            RelatedContracts::new(),
        )
    };
    assert!(matches!(validate(good.clone()), Ok(ValidateResult::Valid)));
    assert!(matches!(validate(vec![]), Ok(ValidateResult::Invalid)));
    assert!(matches!(
        validate(vec![0xFF; 100]),
        Ok(ValidateResult::Invalid)
    ));

    let update = Inbox::update_state(
        params_of(&w.params),
        State::from(good.clone()),
        vec![UpdateData::State(good.clone().into())],
    )
    .unwrap();
    assert!(update.related.is_empty());
    assert_eq!(update.new_state.unwrap().as_ref(), good.as_slice());

    let summary = Inbox::summarize_state(params_of(&w.params), State::from(good.clone())).unwrap();
    let delta = Inbox::get_state_delta(params_of(&w.params), State::from(good), summary).unwrap();
    assert!(delta.as_ref().is_empty());
}

#[test]
fn parameters_must_be_the_exact_shape() {
    let w = world();
    let good = w.params.to_bytes();
    assert_eq!(Params::parse(&good), Ok(w.params));
    assert!(Params::parse(&good[..56]).is_err());
    assert!(Params::parse(&[good.clone(), vec![0]].concat()).is_err());
    let mut version = good;
    version[0] = 1;
    assert!(Params::parse(&version).is_err());
}

/// The revocation digest is not the only thing a summary says about the set:
/// it also counts it. A peer whose count differs is sent the set whatever its
/// digest says, so a digest that agrees by accident cannot hide a missing entry.
#[test]
fn a_summary_that_counts_the_revocations_differently_is_sent_them() {
    let w = world();
    let revoked = [
        w.revocation(id_of(1), FAR, 3),
        w.revocation(id_of(2), FAR, 3),
    ];
    let state = w.raw(owner(3), w.time(T), revoked, [], []);
    let summary = sync::summarize(&state);
    assert!(sync::delta(&state, &summary).unwrap().is_empty());

    let mut value: ciborium::Value = ciborium::from_reader(summary.as_slice()).unwrap();
    let ciborium::Value::Map(fields) = &mut value else {
        panic!("a summary is a map")
    };
    let count = fields
        .iter_mut()
        .find(|(k, _)| k.as_text() == Some("revoked_count"))
        .expect("a count of the revocations");
    assert_eq!(count.1, ciborium::Value::Integer(2.into()));
    count.1 = ciborium::Value::Integer(1.into());
    let mut counted_otherwise = Vec::new();
    ciborium::into_writer(&value, &mut counted_otherwise).unwrap();

    let delta = sync::delta(&state, &counted_otherwise).unwrap();
    let delta: InboxDelta = decode(&delta).unwrap();
    assert_eq!(delta.revoked.len(), 2, "the whole set is sent");
    assert!(delta.owner.is_none() && delta.time.is_none() && delta.messages.is_empty());
}

/// Decision 22. Two genuine revocations of one pass id across an epoch bump are
/// both live during the grace. The previous epoch's dies at the grace end
/// whatever its expiry, so it must not win the join: the current epoch's would
/// be dropped everywhere and, once the winner is pruned, nothing would be left
/// to revoke the pass.
#[test]
fn a_revocation_that_dies_first_does_not_win_the_join() {
    let w = world();
    let grace = T + 14 * DAY;
    let owner = w.owner_grace(2, 4, grace, OPEN, BTreeMap::new());
    let pass = w.pass(1, 4, FAR, PassClass::Contact);
    let previous = w.revocation(pass.cert.pass_id, FAR + 100 * DAY, 3);
    let current = w.revocation(pass.cert.pass_id, FAR, 4);
    let part = |r: &Revocation| -> InboxDelta {
        w.raw(
            owner.clone(),
            w.time(T),
            [r.clone()],
            Vec::<PassUsage>::new(),
            Vec::<(B32, Message)>::new(),
        )
        .into()
    };
    let (p, c) = (part(&previous), part(&current));
    let forward = merge(&Rules::V1, &w.params, vec![p.clone(), c.clone()]).unwrap();
    let backward = merge(&Rules::V1, &w.params, vec![c, p]).unwrap();
    assert_eq!(forward, backward, "order of the parts");
    assert_eq!(
        forward.revoked.get(&pass.cert.pass_id),
        Some(&current),
        "the current epoch's revocation wins during the grace"
    );
    // Past the grace the previous epoch's entry is pruned; the current one
    // still revokes, so the epoch-4 pass stays refused.
    let msg = w.pass_msg(&pass, ct(8192, 1), grace);
    let mut later: InboxDelta = forward.into();
    later.time = Some(w.time(grace));
    later.messages.insert(msg.0, msg.1);
    let after = merge(&Rules::V1, &w.params, vec![later]).unwrap();
    assert_eq!(after.revoked.get(&pass.cert.pass_id), Some(&current));
    assert!(
        !after.messages.contains_key(&msg.0),
        "a revoked pass was admitted"
    );
}
