//! Wrong-but-plausible rules, each shown to be caught.
//!
//! `src/mutant.rs` is a test-only seam: with the `plausible-mutants` feature a
//! call can run the real merge with one plausible mistake switched on. Every
//! mutant here has a scenario that checks one law and returns the law it saw
//! broken. The scenario must pass on the real rules and fail under its mutant,
//! and it must fail for the law it names: the message is asserted, so a mutant
//! stopped by some other check is not credited.
//!
//! Run with `--features plausible-mutants` (`scripts/check-excluded-crates.sh
//! test` does). The cargo manifest requires the feature for this file, so
//! without it these tests are not built; `scripts/check-guards-fail.sh` keeps
//! that from going unnoticed.

mod common;

use std::collections::BTreeMap;

use common::*;
use freenet_email_inbox_v2::merge::{WEBAPP_REQUESTOR, WINDOW_BACK, merge};
use freenet_email_inbox_v2::mutant::{Mutant, with};
use freenet_email_inbox_v2::signed::*;
use freenet_email_inbox_v2::sync;
use freenet_email_inbox_v2::types::*;

const T: u64 = 1_800_000_000 / HOUR * HOUR;
const FAR: u64 = T + 300 * DAY;
const OPEN: QuarantineMode = QuarantineMode::Open;
const REQUIRE: QuarantineMode = QuarantineMode::RequireGhost { min_usd: None };
const DOLLAR5: QuarantineMode = QuarantineMode::RequireGhost { min_usd: Some(5) };

type Law = Result<(), &'static str>;

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
fn revocations_are_pruned_before_they_are_capped() -> Law {
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
    if holds(&merged, &msg) {
        return Err("a revoked pass delivered mail");
    }
    Ok(())
}

/// One message id holds one place, however many encodings arrive.
fn one_id_takes_one_place() -> Law {
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
    if !holds(&merged, &a1) || !holds(&merged, &b) {
        return Err("a message lost its place to a second copy of another");
    }
    Ok(())
}

/// Which of two encodings of one id is kept does not depend on arrival order.
fn the_kept_encoding_does_not_depend_on_order() -> Law {
    let w = world();
    let pass = w.pass(1, 3, FAR, PassClass::Contact);
    let renewed = w.pass(1, 3, FAR + DAY, PassClass::Contact);
    let a = state(OPEN, T, vec![], vec![w.pass_msg(&pass, ct(8192, 1), T)]);
    let b = only_messages(vec![w.pass_msg(&renewed, ct(8192, 1), T)]);
    let forward = run(&Rules::V1, vec![a.clone().into(), b.clone()]);
    let backward = run(&Rules::V1, vec![b, a.into()]);
    if forward != backward {
        return Err("merge is not commutative");
    }
    Ok(())
}

/// Peers holding two encodings of one id can tell, so they converge.
fn a_summary_tells_two_encodings_apart() -> Law {
    let w = world();
    let pass = w.pass(1, 3, FAR, PassClass::Contact);
    let renewed = w.pass(1, 3, FAR + DAY, PassClass::Contact);
    let mine = state(OPEN, T, vec![], vec![w.pass_msg(&pass, ct(8192, 1), T)]);
    let theirs = state(OPEN, T, vec![], vec![w.pass_msg(&renewed, ct(8192, 1), T)]);
    if sync::delta(&theirs, &sync::summarize(&mine))
        .unwrap()
        .is_empty()
    {
        return Err("a peer with another encoding is sent nothing");
    }
    Ok(())
}

/// Quarantine keeps what the salted rank keeps: a sender cannot pick its
/// place by choosing `sent_time`.
fn quarantine_is_ranked_by_the_salted_rank() -> Law {
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
    let want: Vec<B32> = {
        let mut ids: Vec<_> = order.into_iter().map(|(_, id)| id).collect();
        ids.sort();
        ids
    };
    if merged.messages.keys().copied().collect::<Vec<_>>() != want {
        return Err("quarantine did not keep the salted rank's sixteen");
    }
    Ok(())
}

/// Pruning reads the joined time, so the order of the parts changes nothing.
fn pruning_reads_the_merged_time() -> Law {
    let w = world();
    let r = w.revocation(id_of(9), T - WINDOW_BACK + 1, 3);
    let old = state(OPEN, T, vec![r], vec![]);
    let later = InboxDelta {
        time: Some(w.time(T + HOUR)),
        ..InboxDelta::default()
    };
    let forward = run(&Rules::V1, vec![old.clone().into(), later.clone()]);
    let backward = run(&Rules::V1, vec![later, old.into()]);
    if forward != backward {
        return Err("merge is not commutative");
    }
    Ok(())
}

/// A forged certificate does not ride on a genuine one with the same pass id,
/// and a genuine one does not fall with a forged one.
fn a_certificate_is_judged_whole() -> Law {
    let w = world();
    let pass = w.pass(1, 3, FAR, PassClass::Contact);
    let forger = ed25519_dalek::SigningKey::from_bytes(&[0x77; 32]);
    let mut fake = pass.clone();
    fake.cert.pass_vk = serde_bytes::ByteArray::new(forger.verifying_key().to_bytes());
    fake.cert.sig = sign64(&forger, &cert_bytes(&fake.cert));
    fake.sk = forger;
    let genuine = w.pass_msg(&pass, ct(8192, 1), T);
    let forged = w.pass_msg(&fake, ct(8192, 2), T);
    let merged = run(
        &Rules::V1,
        vec![state(OPEN, T, vec![], vec![genuine.clone(), forged.clone()]).into()],
    );
    if holds(&merged, &forged) {
        return Err("a forged certificate was admitted");
    }
    if !holds(&merged, &genuine) {
        return Err("a genuine certificate was refused");
    }
    Ok(())
}

/// A pass's places are counted over everything merged, not per delta.
fn a_pass_is_ranked_over_the_union() -> Law {
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
    if split != whole {
        return Err("the result depends on how the input was split");
    }
    Ok(())
}

/// Room in the revocation set is what is left after pruning, not what was sent.
fn overflow_reads_what_is_kept() -> Law {
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
    if !holds(&merged, &msg) {
        return Err("a set with room refused pass mail");
    }
    Ok(())
}

fn require(messages: Vec<(B32, Message)>, mode: QuarantineMode) -> InboxState {
    run(&Rules::V1, vec![state(mode, T, vec![], messages).into()])
}

/// A proof signs the layout of decision 1 and nothing else.
fn a_proof_signs_the_layout() -> Law {
    let w = world();
    let good = w.quarantine_msg(ct(8192, 1), T, Some(0));
    let bytes = ct(8192, 2);
    let hash = *blake3::hash(&bytes).as_bytes();
    let bare = w.proof_over(0, hash.to_vec(), WEBAPP_REQUESTOR);
    let bare = w.keyed(bytes, T, Admission::Quarantine { ghost: Some(bare) });
    let merged = require(vec![good.clone(), bare.clone()], REQUIRE);
    if !holds(&merged, &good) {
        return Err("a proof over the layout was refused");
    }
    if holds(&merged, &bare) {
        return Err("a proof over the ciphertext digest alone was admitted");
    }
    Ok(())
}

/// A proof is only taken from the webapp.
fn a_proof_must_come_from_the_webapp() -> Law {
    let w = world();
    let bytes = ct(8192, 1);
    let hash = *blake3::hash(&bytes).as_bytes();
    let payload = ghost_admit_bytes(&w.params.addr, T, &hash);
    let other = w.proof_over(0, payload, [7; 32]);
    let msg = w.keyed(bytes, T, Admission::Quarantine { ghost: Some(other) });
    if holds(&require(vec![msg.clone()], REQUIRE), &msg) {
        return Err("a proof for another requestor was admitted");
    }
    Ok(())
}

/// A Ghost Key under the inbox's tier is refused.
fn the_tier_is_checked() -> Law {
    let w = world();
    let low = w.quarantine_msg(ct(8192, 1), T, Some(3));
    let ok = w.quarantine_msg(ct(8192, 2), T, Some(4));
    let merged = require(vec![low.clone(), ok.clone()], DOLLAR5);
    if !holds(&merged, &ok) {
        return Err("a proof at the tier was refused");
    }
    if holds(&merged, &low) {
        return Err("a proof under the tier was admitted");
    }
    Ok(())
}

/// One ghost key holds two quarantine places however its mail arrives.
fn a_ghost_is_capped_over_the_union() -> Law {
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
    if merged.messages.len() != Rules::V1.per_ghost {
        return Err("a ghost key holds more than its cap");
    }
    Ok(())
}

/// A revocation that pruning removed does not filter (decision 10): it can be
/// redelivered forever, and so could the mail it dropped.
fn only_the_revocations_left_after_pruning_filter() -> Law {
    let w = world();
    let pass = w.pass(1, 3, FAR, PassClass::Contact);
    let msg = w.pass_msg(&pass, ct(8192, 1), T);
    for dead in [
        w.revocation(pass.cert.pass_id, T - WINDOW_BACK, 3),
        w.revocation(pass.cert.pass_id, FAR, 2),
    ] {
        let merged = run(
            &Rules::V1,
            vec![state(OPEN, T, vec![dead], vec![msg.clone()]).into()],
        );
        if !holds(&merged, &msg) {
            return Err("a pruned revocation dropped a message");
        }
    }
    Ok(())
}

fn scenario(m: Mutant) -> fn() -> Law {
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
    }
}

fn law_broken(m: Mutant) -> [&'static str; 2] {
    let one = |law| [law, law];
    match m {
        Mutant::CapBeforeCleanup => one("a revoked pass delivered mail"),
        Mutant::NoOnePerId => one("a message lost its place to a second copy of another"),
        Mutant::FirstAdmitted | Mutant::PruneUnmergedTime => one("merge is not commutative"),
        Mutant::DigestDropped => one("a peer with another encoding is sent nothing"),
        Mutant::QuarantineBySentTime => one("quarantine did not keep the salted rank's sixteen"),
        // Whichever copy is judged first decides the other.
        Mutant::CertMemoByPassId => [
            "a forged certificate was admitted",
            "a genuine certificate was refused",
        ],
        Mutant::PassRankPerDelta => one("the result depends on how the input was split"),
        Mutant::OverflowReadsUnion => one("a set with room refused pass mail"),
        Mutant::GhostPayloadIsCtHash => [
            "a proof over the layout was refused",
            "a proof over the ciphertext digest alone was admitted",
        ],
        Mutant::RequestorPinSkipped => one("a proof for another requestor was admitted"),
        Mutant::TierCheckSkipped => one("a proof under the tier was admitted"),
        Mutant::GhostCapPerDelta => one("a ghost key holds more than its cap"),
        Mutant::FilterUnprunedRevocations => one("a pruned revocation dropped a message"),
    }
}

fn caught(m: Mutant) {
    let real = scenario(m);
    assert_eq!(real(), Ok(()), "{m:?}: the real rules must keep the law");
    let seen = with(m, real);
    let want = law_broken(m);
    match seen {
        Ok(()) => panic!("{m:?} was not caught"),
        Err(law) => {
            println!("{m:?} breaks: {law}");
            assert!(want.contains(&law), "{m:?}: broke `{law}`, not {want:?}");
        }
    }
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
}
