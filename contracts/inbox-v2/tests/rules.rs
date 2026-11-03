//! The filter, the caps and the joins, each at its boundary.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::*;
use freenet_email_inbox_v2::merge::{WINDOW_BACK, WINDOW_FORWARD, merge};
use freenet_email_inbox_v2::types::*;
use freenet_email_inbox_v2::{Inbox, Params, apply, is_valid, sync};
use freenet_stdlib::prelude::*;

const T: u64 = 1_800_000_000 / HOUR * HOUR;
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
    let pass = w.pass(1, 3, T + HOUR, PassClass::Contact);
    let msgs = vec![
        w.pass_msg(&pass, ct(8192, 1), T),
        w.pass_msg(&pass, ct(8192, 2), T + HOUR),
    ];
    assert_eq!(kept(owner(3), T, vec![], vec![], msgs), [true, false]);
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
    let keep = w.revocation(id_of(1), T - WINDOW_BACK + 1, 3);
    let drop = w.revocation(id_of(2), T - WINDOW_BACK, 3);
    let older = w.revocation(id_of(3), FAR, 2);
    let current = w.revocation(id_of(4), FAR, 3);
    let later = w.revocation(id_of(5), FAR, 4);
    let merged = clean(w.raw(
        owner(3),
        w.time(T),
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
    let keep = w.usage(id_of(1), 1, T - WINDOW_BACK + 1);
    let drop = w.usage(id_of(2), 1, T - WINDOW_BACK);
    let merged = clean(w.raw(owner(3), w.time(T), [], [keep, drop], []));
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
