//! A test-only seam: the wrong-but-plausible rules `tests/plausible_mutants.rs`
//! runs to show that the tests catch each of them.
//!
//! Compiled only with the `plausible-mutants` feature, which no build of the
//! contract enables, so none of this reaches the WASM:
//! `scripts/check-inbox-candidate.sh` proves the candidate's bytes are the same
//! with and without these call sites. A mutant is switched on for one closure
//! on the calling thread only, so tests running in parallel do not see it.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use crate::types::B32;

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
