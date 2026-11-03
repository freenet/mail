//! Wrong-but-plausible rules, each shown to be caught.
//!
//! `src/mutant.rs` is a test-only seam: with the `plausible-mutants` feature a
//! call can run the real merge with one plausible mistake switched on. Every
//! mutant here has a scenario that checks the laws it bears on and returns each
//! one it sees broken. On the real rules that list is empty. Under the mutant it
//! must be exactly the list `fingerprint` gives, which names the law the mutant
//! is for: a mutant stopped by some other check is not credited, and a seam that
//! does something other than what its name says changes the list and fails.
//!
//! Run with `--features plausible-mutants` (`scripts/check-excluded-crates.sh
//! test` does). The cargo manifest requires the feature for this file, so
//! without it these tests are not built; `check-drift` runs it.

mod common;

use std::collections::BTreeMap;

use common::*;
use freenet_email_inbox_v2::merge::{WEBAPP_REQUESTOR, WINDOW_BACK, merge};
use freenet_email_inbox_v2::mutant::{Mutant, with};
use freenet_email_inbox_v2::signed::*;
use freenet_email_inbox_v2::sync;
use freenet_email_inbox_v2::types::*;

const T: u64 = 1_800_000_000 / DAY * DAY;
const FAR: u64 = T + 300 * DAY;
const OPEN: QuarantineMode = QuarantineMode::Open;
const REQUIRE: QuarantineMode = QuarantineMode::RequireGhost { min_usd: None };
const DOLLAR5: QuarantineMode = QuarantineMode::RequireGhost { min_usd: Some(5) };

/// The laws a scenario saw broken, in the order it checks them.
type Broken = Vec<&'static str>;

fn owner(mode: QuarantineMode) -> OwnerRecord {
    world().owner(1, 3, mode, BTreeMap::new())
}

fn run(rules: &Rules, parts: Vec<InboxDelta>) -> InboxState {
    merge(rules, &world().params, parts).unwrap()
}

fn state(
    mode: QuarantineMode,
    time: u64,
    revoked: Vec<Revocation>,
    messages: Vec<(B32, Message)>,
) -> InboxState {
    let w = world();
    w.raw(owner(mode), w.time(time), revoked, [], messages)
}

fn only_messages(messages: Vec<(B32, Message)>) -> InboxDelta {
    InboxDelta {
        messages: messages.into_iter().collect(),
        ..InboxDelta::default()
    }
}

fn holds(state: &InboxState, message: &(B32, Message)) -> bool {
    state.messages.contains_key(&message.0)
}

/// Pass mail is filtered by a live revocation, even when expired entries have
/// been taking up room in the set that holds it.
fn revocations_are_pruned_before_they_are_capped() -> Broken {
    let w = world();
    let rules = Rules {
        revoked: 4,
        ..Rules::V1
    };
    let pass = w.pass(100, 3, FAR, PassClass::Contact);
    let msg = w.pass_msg(&pass, ct(8192, 1), T);
    let mut revoked: Vec<_> = (0..3)
        .map(|i| w.revocation(id_of(i), T - WINDOW_BACK, 3))
        .collect();
    revoked.push(w.revocation(id_of(11), FAR, 3));
    revoked.push(w.revocation(pass.cert.pass_id, FAR, 3));
    let merged = run(
        &rules,
        vec![state(OPEN, T, revoked, vec![msg.clone()]).into()],
    );
    let mut broken = vec![];
    if holds(&merged, &msg) {
        broken.push("a revoked pass delivered mail");
    }
    broken
}

/// One message id holds one place, however many encodings arrive.
fn one_id_takes_one_place() -> Broken {
    let w = world();
    let rules = Rules {
        per_pass: 2,
        ..Rules::V1
    };
    let pass = w.pass(1, 3, FAR, PassClass::Contact);
    let renewed = w.pass(1, 3, FAR + DAY, PassClass::Contact);
    let (a1, a2) = (
        w.pass_msg(&pass, ct(8192, 1), T),
        w.pass_msg(&renewed, ct(8192, 1), T),
    );
    assert_eq!(a1.0, a2.0, "one id, two encodings");
    let b = w.pass_msg(&pass, ct(8192, 2), T + HOUR);
    let merged = run(
        &rules,
        vec![
            state(OPEN, T, vec![], vec![a1.clone()]).into(),
            only_messages(vec![a2]),
            only_messages(vec![b.clone()]),
        ],
    );
    let mut broken = vec![];
    if !holds(&merged, &a1) {
        broken.push("a message was lost");
    }
    if !holds(&merged, &b) {
        broken.push("a message lost its place to a second copy of another");
    }
    broken
}

/// Which of two encodings of one id is kept does not depend on arrival order.
fn the_kept_encoding_does_not_depend_on_order() -> Broken {
    let w = world();
    let pass = w.pass(1, 3, FAR, PassClass::Contact);
    let renewed = w.pass(1, 3, FAR + DAY, PassClass::Contact);
    let a = state(OPEN, T, vec![], vec![w.pass_msg(&pass, ct(8192, 1), T)]);
    let b = only_messages(vec![w.pass_msg(&renewed, ct(8192, 1), T)]);
    let forward = run(&Rules::V1, vec![a.clone().into(), b.clone()]);
    let backward = run(&Rules::V1, vec![b, a.into()]);
    let mut broken = vec![];
    if forward != backward {
        broken.push("merge is not commutative");
    }
    broken
}

/// Peers holding two encodings of one id can tell, so they converge.
fn a_summary_tells_two_encodings_apart() -> Broken {
    let w = world();
    let pass = w.pass(1, 3, FAR, PassClass::Contact);
    let renewed = w.pass(1, 3, FAR + DAY, PassClass::Contact);
    let mine = state(OPEN, T, vec![], vec![w.pass_msg(&pass, ct(8192, 1), T)]);
    let theirs = state(OPEN, T, vec![], vec![w.pass_msg(&renewed, ct(8192, 1), T)]);
    let mut broken = vec![];
    if sync::delta(&theirs, &sync::summarize(&mine))
        .unwrap()
        .is_empty()
    {
        broken.push("a peer with another encoding is sent nothing");
    }
    // The control: a peer with the same encoding is sent nothing.
    if !sync::delta(&mine, &sync::summarize(&mine))
        .unwrap()
        .is_empty()
    {
        broken.push("a peer with the same state is sent something");
    }
    broken
}

/// Quarantine keeps what the salted rank keeps: a sender cannot pick its
/// place by choosing `sent_time`.
fn quarantine_is_ranked_by_the_salted_rank() -> Broken {
    let w = world();
    let msgs: Vec<_> = (0..40)
        .map(|i| w.quarantine_msg(ct(8192, i), T + i * HOUR, None))
        .collect();
    let merged = run(
        &Rules::V1,
        vec![state(OPEN, T, vec![], msgs.clone()).into()],
    );
    let salt = blake3::hash(&encode(&merged.time));
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
    let mut want: Vec<B32> = order.into_iter().map(|(_, id)| id).collect();
    want.sort();
    let mut broken = vec![];
    if merged.messages.keys().copied().collect::<Vec<_>>() != want {
        broken.push("quarantine did not keep the salted rank's sixteen");
    }
    broken
}

/// Pruning reads the joined time, so the order of the parts changes nothing.
fn pruning_reads_the_merged_time() -> Broken {
    let w = world();
    // Live at T, pruned a day later: expiries are whole days.
    let r = w.revocation(id_of(9), T - WINDOW_BACK + DAY, 3);
    let old = state(OPEN, T, vec![r], vec![]);
    let later = InboxDelta {
        time: Some(w.time(T + DAY)),
        ..InboxDelta::default()
    };
    let forward = run(&Rules::V1, vec![old.clone().into(), later.clone()]);
    let backward = run(&Rules::V1, vec![later, old.into()]);
    let mut broken = vec![];
    if forward != backward {
        broken.push("merge is not commutative");
    }
    if !forward.revoked.is_empty() {
        broken.push("a revocation survived the joined time");
    }
    broken
}

/// A forged certificate does not ride on a genuine one with the same pass id,
/// and a genuine one does not fall with a forged one. The ids are chosen so the
/// genuine message is judged first.
fn a_certificate_is_judged_whole() -> Broken {
    let w = world();
    let pass = w.pass(1, 3, FAR, PassClass::Contact);
    let forger = ed25519_dalek::SigningKey::from_bytes(&[0x77; 32]);
    let mut fake = pass.clone();
    fake.cert.pass_vk = serde_bytes::ByteArray::new(forger.verifying_key().to_bytes());
    fake.cert.sig = sign64(&forger, &cert_bytes(&fake.cert));
    fake.sk = forger;
    let genuine = w.pass_msg(&pass, ct(8192, 1), T);
    let forged = (2..)
        .map(|tag| w.pass_msg(&fake, ct(8192, tag), T))
        .find(|forged| forged.0 > genuine.0)
        .unwrap();
    let merged = run(
        &Rules::V1,
        vec![state(OPEN, T, vec![], vec![genuine.clone(), forged.clone()]).into()],
    );
    let mut broken = vec![];
    if holds(&merged, &forged) {
        broken.push("a forged certificate was admitted");
    }
    if !holds(&merged, &genuine) {
        broken.push("a genuine certificate was refused");
    }
    broken
}

/// A pass's places are counted over everything merged, not per delta.
fn a_pass_is_ranked_over_the_union() -> Broken {
    let w = world();
    let rules = Rules {
        pass_pool: 2,
        ..Rules::V1
    };
    let pass = w.pass(1, 3, FAR, PassClass::Contact);
    let msgs: Vec<_> = (0..3)
        .map(|i| w.pass_msg(&pass, ct(8192, i), T + i * HOUR))
        .collect();
    let split = run(
        &rules,
        vec![
            state(OPEN, T, vec![], msgs[..2].to_vec()).into(),
            only_messages(msgs[2..].to_vec()),
        ],
    );
    let whole = run(&rules, vec![state(OPEN, T, vec![], msgs).into()]);
    let mut broken = vec![];
    if split != whole {
        broken.push("the result depends on how the input was split");
    }
    broken
}

/// Room in the revocation set is what is left after pruning, not what was sent.
fn overflow_reads_what_is_kept() -> Broken {
    let w = world();
    let rules = Rules {
        revoked: 4,
        ..Rules::V1
    };
    let pass = w.pass(99, 3, FAR, PassClass::Contact);
    let msg = w.pass_msg(&pass, ct(8192, 1), T);
    let mut revoked: Vec<_> = (0..3)
        .map(|i| w.revocation(id_of(i), T - WINDOW_BACK, 3))
        .collect();
    revoked.push(w.revocation(id_of(50), FAR, 3));
    let merged = run(
        &rules,
        vec![state(OPEN, T, revoked, vec![msg.clone()]).into()],
    );
    let mut broken = vec![];
    if !holds(&merged, &msg) {
        broken.push("a set with room refused pass mail");
    }
    broken
}

fn require(messages: Vec<(B32, Message)>, mode: QuarantineMode) -> InboxState {
    run(&Rules::V1, vec![state(mode, T, vec![], messages).into()])
}

/// A proof signs the layout of decision 1 and nothing else.
fn a_proof_signs_the_layout() -> Broken {
    let w = world();
    let good = w.quarantine_msg(ct(8192, 1), T, Some(0));
    let bytes = ct(8192, 2);
    let hash = *blake3::hash(&bytes).as_bytes();
    let bare = w.proof_over(0, hash.to_vec(), WEBAPP_REQUESTOR);
    let bare = w.keyed(bytes, T, Admission::Quarantine { ghost: Some(bare) });
    let merged = require(vec![good.clone(), bare.clone()], REQUIRE);
    let mut broken = vec![];
    if holds(&merged, &bare) {
        broken.push("a proof over the ciphertext digest alone was admitted");
    }
    if !holds(&merged, &good) {
        broken.push("a proof over the layout was refused");
    }
    broken
}

/// A proof is only taken from the webapp.
fn a_proof_must_come_from_the_webapp() -> Broken {
    let w = world();
    let bytes = ct(8192, 1);
    let hash = *blake3::hash(&bytes).as_bytes();
    let payload = ghost_admit_bytes(&w.params.addr, T, &hash);
    let other = w.proof_over(0, payload, [7; 32]);
    let msg = w.keyed(bytes, T, Admission::Quarantine { ghost: Some(other) });
    let good = w.quarantine_msg(ct(8192, 2), T, Some(0));
    let merged = require(vec![msg.clone(), good.clone()], REQUIRE);
    let mut broken = vec![];
    if holds(&merged, &msg) {
        broken.push("a proof for another requestor was admitted");
    }
    if !holds(&merged, &good) {
        broken.push("a proof from the webapp was refused");
    }
    broken
}

/// A Ghost Key under the inbox's tier is refused.
fn the_tier_is_checked() -> Broken {
    let w = world();
    let low = w.quarantine_msg(ct(8192, 1), T, Some(3));
    let ok = w.quarantine_msg(ct(8192, 2), T, Some(4));
    let merged = require(vec![low.clone(), ok.clone()], DOLLAR5);
    let mut broken = vec![];
    if holds(&merged, &low) {
        broken.push("a proof under the tier was admitted");
    }
    if !holds(&merged, &ok) {
        broken.push("a proof at the tier was refused");
    }
    broken
}

/// One ghost key holds two quarantine places however its mail arrives.
fn a_ghost_is_capped_over_the_union() -> Broken {
    let w = world();
    let msgs: Vec<_> = (0..4)
        .map(|i| w.quarantine_msg(ct(8192, i), T, Some(0)))
        .collect();
    let merged = run(
        &Rules::V1,
        vec![
            state(REQUIRE, T, vec![], msgs[..2].to_vec()).into(),
            only_messages(msgs[2..].to_vec()),
        ],
    );
    let mut broken = vec![];
    if merged.messages.len() > Rules::V1.per_ghost {
        broken.push("a ghost key holds more than its cap");
    }
    if merged.messages.len() < Rules::V1.per_ghost {
        broken.push("a ghost key holds less than its cap");
    }
    broken
}

/// A revocation that pruning removed does not filter (decision 10): it can be
/// redelivered forever, and so could the mail it dropped.
fn only_the_revocations_left_after_pruning_filter() -> Broken {
    let w = world();
    let pass = w.pass(1, 3, FAR, PassClass::Contact);
    let msg = w.pass_msg(&pass, ct(8192, 1), T);
    let mut broken = vec![];
    for dead in [
        w.revocation(pass.cert.pass_id, T - WINDOW_BACK, 3),
        w.revocation(pass.cert.pass_id, FAR, 2),
    ] {
        let merged = run(
            &Rules::V1,
            vec![state(OPEN, T, vec![dead], vec![msg.clone()]).into()],
        );
        if !holds(&merged, &msg) {
            broken.push("a pruned revocation dropped a message");
        }
    }
    // The control: a live one still filters.
    let live = w.revocation(pass.cert.pass_id, FAR, 3);
    let merged = run(
        &Rules::V1,
        vec![state(OPEN, T, vec![live], vec![msg.clone()]).into()],
    );
    if holds(&merged, &msg) {
        broken.push("a live revocation did not filter");
    }
    // The control: a forged one, dead or alive, never filters, so the union
    // the mutant reads holds genuine entries only.
    let mut forged = w.revocation(pass.cert.pass_id, T - WINDOW_BACK, 3);
    forged.sig[0] ^= 1;
    let merged = run(
        &Rules::V1,
        vec![state(OPEN, T, vec![forged], vec![msg.clone()]).into()],
    );
    if !holds(&merged, &msg) {
        broken.push("a forged revocation dropped a message");
    }
    broken
}

/// On one pass id, a dead entry that outranks a live one does not win the join
/// (review r1 B1): pruning it afterwards would take the live one with it.
fn a_dead_entry_never_wins_a_join() -> Broken {
    let w = world();
    let p = id_of(7);
    let living_use = w.usage(p, 1, FAR);
    let dying_use = w.usage(p, 3, T - WINDOW_BACK);
    let current = w.revocation(p, FAR, 4);
    let stale = w.revocation(p, FAR + DAY, 3);
    let merged = run(
        &Rules::V1,
        vec![
            w.raw(
                w.owner(1, 4, OPEN, BTreeMap::new()),
                w.time(T),
                [current.clone()],
                [living_use.clone()],
                [],
            )
            .into(),
            InboxDelta {
                revoked: BTreeMap::from([(p, stale)]),
                usage: BTreeMap::from([(p, dying_use)]),
                ..InboxDelta::default()
            },
        ],
    );
    let mut broken = vec![];
    if merged.usage.get(&p) != Some(&living_use) {
        broken.push("a dead usage entry took the live one with it");
    }
    if merged.revoked.get(&p) != Some(&current) {
        broken.push("a dead revocation took the live one with it");
    }
    broken
}

fn scenario(m: Mutant) -> fn() -> Broken {
    match m {
        Mutant::CapBeforeCleanup => revocations_are_pruned_before_they_are_capped,
        Mutant::NoOnePerId => one_id_takes_one_place,
        Mutant::FirstAdmitted => the_kept_encoding_does_not_depend_on_order,
        Mutant::DigestDropped => a_summary_tells_two_encodings_apart,
        Mutant::QuarantineBySentTime => quarantine_is_ranked_by_the_salted_rank,
        Mutant::PruneUnmergedTime => pruning_reads_the_merged_time,
        Mutant::CertMemoByPassId => a_certificate_is_judged_whole,
        Mutant::PassRankPerDelta => a_pass_is_ranked_over_the_union,
        Mutant::OverflowReadsUnion => overflow_reads_what_is_kept,
        Mutant::GhostPayloadIsCtHash => a_proof_signs_the_layout,
        Mutant::RequestorPinSkipped => a_proof_must_come_from_the_webapp,
        Mutant::TierCheckSkipped => the_tier_is_checked,
        Mutant::GhostCapPerDelta => a_ghost_is_capped_over_the_union,
        Mutant::FilterUnprunedRevocations => only_the_revocations_left_after_pruning_filter,
        Mutant::JoinBeforePrune => a_dead_entry_never_wins_a_join,
    }
}

/// Exactly what each mutant breaks. The first entry is the law the mutant is
/// for; any others are what it does to the control checks beside it.
fn fingerprint(m: Mutant) -> &'static [&'static str] {
    match m {
        Mutant::CapBeforeCleanup => &["a revoked pass delivered mail"],
        Mutant::NoOnePerId => &["a message lost its place to a second copy of another"],
        Mutant::FirstAdmitted => &["merge is not commutative"],
        Mutant::DigestDropped => &["a peer with another encoding is sent nothing"],
        Mutant::QuarantineBySentTime => &["quarantine did not keep the salted rank's sixteen"],
        Mutant::PruneUnmergedTime => &[
            "merge is not commutative",
            "a revocation survived the joined time",
        ],
        Mutant::CertMemoByPassId => &["a forged certificate was admitted"],
        Mutant::PassRankPerDelta => &["the result depends on how the input was split"],
        Mutant::OverflowReadsUnion => &["a set with room refused pass mail"],
        Mutant::GhostPayloadIsCtHash => &[
            "a proof over the ciphertext digest alone was admitted",
            "a proof over the layout was refused",
        ],
        Mutant::RequestorPinSkipped => &["a proof for another requestor was admitted"],
        Mutant::TierCheckSkipped => &["a proof under the tier was admitted"],
        Mutant::GhostCapPerDelta => &["a ghost key holds more than its cap"],
        Mutant::FilterUnprunedRevocations => &["a pruned revocation dropped a message"; 2],
        Mutant::JoinBeforePrune => &[
            "a dead usage entry took the live one with it",
            "a dead revocation took the live one with it",
        ],
    }
}

fn caught(m: Mutant) {
    let real = scenario(m);
    assert_eq!(
        real(),
        Broken::new(),
        "{m:?}: the real rules must keep every law"
    );
    let seen = with(m, real);
    println!("{m:?} breaks: {seen:?}");
    assert_eq!(seen, fingerprint(m), "{m:?}");
}

macro_rules! mutant_tests {
    ($($name:ident => $m:ident),* $(,)?) => {
        $(#[test] fn $name() { caught(Mutant::$m); })*
    };
}

mutant_tests! {
    cap_before_cleanup => CapBeforeCleanup,
    dedup_of_one_id_removed => NoOnePerId,
    first_admitted_instead_of_smallest => FirstAdmitted,
    encoding_digest_dropped_from_the_summary => DigestDropped,
    quarantine_ordered_by_sent_time => QuarantineBySentTime,
    pruning_against_an_unmerged_owner_time => PruneUnmergedTime,
    pass_id_compared_instead_of_the_certificate => CertMemoByPassId,
    pass_rank_computed_per_delta => PassRankPerDelta,
    overflow_reads_the_union => OverflowReadsUnion,
    ghost_payload_against_the_ciphertext_digest => GhostPayloadIsCtHash,
    requestor_pin_skipped => RequestorPinSkipped,
    tier_check_skipped => TierCheckSkipped,
    ghost_cap_computed_per_delta => GhostCapPerDelta,
    filtering_against_the_unpruned_revocations => FilterUnprunedRevocations,
    joining_before_pruning => JoinBeforePrune,
}
