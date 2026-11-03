//! A test-only seam: the wrong-but-plausible rules `tests/plausible_mutants.rs`
//! runs to show that the tests catch each of them.
//!
//! Compiled only with the `plausible-mutants` feature. `src/lib.rs` refuses to
//! compile it for `wasm32`, so no build of the contract can carry it, and the
//! rules' call sites into it are `cfg`-gated on the same feature. A mutant is
//! switched on for one closure on the calling thread only, so tests running in
//! parallel do not see it.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

use freenet_stdlib::prelude::ContractInstanceId;

use crate::merge::WEBAPP_REQUESTOR;
use crate::signed::ghost_admit_bytes;
use crate::types::{B16, B32, InboxDelta, PassUsage, Revocation};

/// One plausible mistake in the rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mutant {
    /// The revocation cap applied before expired entries are pruned.
    CapBeforeCleanup,
    /// Every admitted copy of one message id is kept, so it counts twice.
    NoOnePerId,
    /// The first admitted encoding of one id wins, not the smallest.
    FirstAdmitted,
    /// The summary leaves out each message's encoding digest.
    DigestDropped,
    /// Quarantine ordered by `sent_time`, not the salted rank.
    QuarantineBySentTime,
    /// Pruning against the `owner_time` of the first part, not the joined one.
    PruneUnmergedTime,
    /// The certificate memo keyed by pass id, not by the whole certificate.
    CertMemoByPassId,
    /// A message's place within its pass counted per delta.
    PassRankPerDelta,
    /// The revocation overflow test reading the size of the union.
    OverflowReadsUnion,
    /// A Ghost Key payload compared against `blake3(ct)`.
    GhostPayloadIsCtHash,
    /// The webapp requestor pin skipped.
    RequestorPinSkipped,
    /// The Ghost Key tier check skipped.
    TierCheckSkipped,
    /// The per-ghost cap counted per delta.
    GhostCapPerDelta,
    /// Filtering against the revocation union before pruning.
    FilterUnprunedRevocations,
    /// A pass id's revocation and usage joins pick before pruning, so a dead
    /// entry can win and take a live one with it (review r1 B1).
    JoinBeforePrune,
    /// The previous epoch's grace read from the first part's owner record, not
    /// the joined one (decision 18).
    GraceFromUnjoinedOwner,
    /// Revocations of one pass id ranked by expiry before epoch, so the
    /// previous epoch's entry can win a grace and then be pruned (decision 22).
    RevocationExpiryFirst,
}

thread_local! {
    static ACTIVE: Cell<Option<Mutant>> = const { Cell::new(None) };
    static PART: Cell<usize> = const { Cell::new(0) };
    static ORIGIN: RefCell<BTreeMap<B32, usize>> = const { RefCell::new(BTreeMap::new()) };
}

/// Whether `m` is switched on, on this thread.
pub fn on(m: Mutant) -> bool {
    ACTIVE.with(|a| a.get() == Some(m))
}

/// Run `f` with `m` on.
pub fn with<R>(m: Mutant, f: impl FnOnce() -> R) -> R {
    struct Off;
    impl Drop for Off {
        fn drop(&mut self) {
            ACTIVE.with(|a| a.set(None));
        }
    }
    ACTIVE.with(|a| a.set(Some(m)));
    let _off = Off;
    f()
}

/// A merge is starting.
pub fn begin() {
    PART.with(|p| p.set(0));
    ORIGIN.with(|o| o.borrow_mut().clear());
}

/// The next part of the merge's input is being read.
pub fn next_part() {
    PART.with(|p| p.set(p.get() + 1));
}

/// `id` arrived in the current part; the first part to carry it is its origin.
pub fn note(id: &B32) {
    let part = PART.with(Cell::get);
    ORIGIN.with(|o| {
        o.borrow_mut().entry(*id).or_insert(part);
    });
}

/// The part `id` first arrived in.
pub fn origin(id: &B32) -> usize {
    ORIGIN.with(|o| o.borrow().get(id).copied().unwrap_or(0))
}

// What each mutant does when it is on. The rules call these at one-line sites,
// so the mutated logic is here and the rules keep nothing but the calls.

/// `GraceFromUnjoinedOwner`: the `prev_epoch_until` the rules read.
pub fn grace_until(joined: u64, first: Option<&InboxDelta>) -> u64 {
    if !on(Mutant::GraceFromUnjoinedOwner) {
        return joined;
    }
    first
        .and_then(|part| part.owner.as_ref())
        .map_or(joined, |owner| owner.prev_epoch_until)
}

/// `TierCheckSkipped`.
pub fn tier_met(real: bool) -> bool {
    real || on(Mutant::TierCheckSkipped)
}

/// The payload of a proof, as the rule reads it (`scoped.payload`).
pub struct Payload {
    pub payload: Vec<u8>,
}

/// `RequestorPinSkipped` and `GhostPayloadIsCtHash`: the inputs to hand the real
/// rule so that it reaches the mutant's verdict. With the pin skipped the
/// requestor is the webapp whoever it was. With the payload read as the
/// ciphertext digest, the rule sees the layout exactly when the proof signed the
/// digest, and sees nothing when it signed the layout.
pub fn proof_inputs(
    requestor: ContractInstanceId,
    payload: Vec<u8>,
    addr: &[u8; 24],
    sent_time: u64,
    ct_hash: &[u8; 32],
) -> (ContractInstanceId, Payload) {
    let requestor = if on(Mutant::RequestorPinSkipped) {
        ContractInstanceId::new(WEBAPP_REQUESTOR)
    } else {
        requestor
    };
    let payload = if on(Mutant::GhostPayloadIsCtHash) {
        if payload == ct_hash {
            ghost_admit_bytes(addr, sent_time, ct_hash)
        } else {
            Vec::new()
        }
    } else {
        payload
    };
    (requestor, Payload { payload })
}

/// Whether a pass id's join sees an entry, given whether it is live. Under
/// `JoinBeforePrune` and `CapBeforeCleanup` the join sees dead entries too and
/// `prune_late` removes them afterwards.
pub fn join_live(live: bool) -> bool {
    live || on(Mutant::JoinBeforePrune) || on(Mutant::CapBeforeCleanup)
}

/// `JoinBeforePrune`: pruning after the join, as review r1 B1 found it.
/// `CapBeforeCleanup`: the same, with the revocation cap applied first.
pub fn prune_late(
    revoked: &mut BTreeMap<B16, Revocation>,
    usage: &mut BTreeMap<B16, PassUsage>,
    cap: usize,
    live_revocation: impl Fn(&Revocation) -> bool,
    live_usage: impl Fn(&PassUsage) -> bool,
) {
    if on(Mutant::CapBeforeCleanup) {
        while revoked.len() > cap {
            revoked.pop_last();
        }
    }
    revoked.retain(|_, r| live_revocation(r));
    usage.retain(|_, u| live_usage(u));
}

/// Collects the pass ids of every genuine revocation, dead or alive, for the
/// two mutants that read the union before pruning.
pub fn note_revocation(
    unpruned: &mut BTreeSet<B16>,
    entry: &Revocation,
    genuine: impl Fn(&Revocation) -> bool,
) {
    if (on(Mutant::FilterUnprunedRevocations) || on(Mutant::OverflowReadsUnion)) && genuine(entry) {
        unpruned.insert(entry.pass_id);
    }
}

/// `OverflowReadsUnion`: whether the revocation set is full.
pub fn overflow(real: bool, union_len: usize, cap: usize) -> bool {
    if on(Mutant::OverflowReadsUnion) {
        union_len >= cap
    } else {
        real
    }
}

/// `PassRankPerDelta`: the key a pass's messages are ranked under.
pub fn pass_key(pass_id: B16, id: &B32) -> B16 {
    if !on(Mutant::PassRankPerDelta) {
        return pass_id;
    }
    let mut raw = *pass_id;
    raw[0] = origin(id) as u8 + 1;
    B16::new(raw)
}

/// `QuarantineBySentTime`: what quarantine messages are ordered by.
pub fn quarantine_rank(rank: [u8; 32], sent_time: u64) -> [u8; 32] {
    if !on(Mutant::QuarantineBySentTime) {
        return rank;
    }
    let mut by_time = [0u8; 32];
    by_time[..8].copy_from_slice(&sent_time.to_be_bytes());
    by_time
}

/// `GhostCapPerDelta`: the key a ghost's messages are counted under.
pub fn ghost_key(mut key: [u8; 32], id: &B32) -> [u8; 32] {
    if on(Mutant::GhostCapPerDelta) {
        key[0] = key[0].wrapping_add(origin(id) as u8 + 1);
    }
    key
}
