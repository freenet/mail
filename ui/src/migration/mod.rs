//! Moving a v0.2.x user's data into the mail delegate.
//!
//! A delegate's secrets belong to its key, so everything a user had under the
//! identity-management and mail-local-state delegates stays there until it is
//! read and imported. `freenet-migrate` drives that walk: it decides what to
//! import and records what happened in a journal the mail delegate stores.
//! This module supplies the two ends:
//!
//! - [`legacy_delegates`] reads a predecessor and maps what it holds into
//!   importable items, by content;
//! - [`successor`] writes them through the mail delegate's own operations,
//!   none of which overwrite.
//!
//! The rules the data rests on:
//!
//! - **Silence is never absence.** No answer, an empty answer, an undecodable
//!   answer and a typed "not installed" all leave a predecessor pending. The
//!   adapter never reports a predecessor as holding nothing, so nothing is
//!   ever sealed as empty and a later load can always ask again.
//! - **Import never overwrites.** Under `UnionAllGenerations` the newest
//!   generation wins a shared key only because the writer declines a key it
//!   already holds, and a user's own edit on the new delegate wins the same
//!   way. The documented cost: an identity deleted in a newer generation can
//!   come back from an older one.
//! - **There is no "done" marker of our own.** Completeness is the journal's
//!   status, read through [`settled`], and a predecessor that is simply not
//!   installed keeps the journal incomplete for good. That is expected: it
//!   costs one round trip per load and blocks nothing.
//!
//! The journal and the markers live in the mail delegate under the caller's
//! origin, not in the crate's reserved `\0` keys, so a staging app walks its
//! own migration and never reads production's.

use freenet_migrate::{
    DelegateLineageEntry, JournalStatus, JournaledMigrationReport, MigrationAuthorization,
    SecretSelectionPolicy, UnionAck, begin_migration_journal, migrate_delegate_secrets_journaled,
};

pub(crate) mod legacy_delegates;
#[cfg(feature = "use-node")]
pub(crate) mod node;
pub(crate) mod successor;
#[cfg(test)]
mod tests;

use legacy_delegates::{LegacyAdapter, LegacyTransport};
use successor::{MailStore, MailSuccessor, MigrationCounts, V1InboxReader};

/// Added to an identity-management row's generation in the lineage. The walk
/// goes newest generation first, and every identity generation must come
/// before any local-state one: local state is keyed by alias, and which
/// address an alias means is known only from the identities. Fixed for good:
/// a journal entry records its predecessor's generation.
pub(crate) const IDENTITY_GENERATION_OFFSET: u32 = 1_000_000;

/// The predecessors, in the crate's terms. Generations are the registries'
/// (fixed for a row by its release), so a row recovered later for an older
/// release does not renumber any other.
pub(crate) fn lineage() -> Vec<DelegateLineageEntry> {
    use crate::legacy_registry::{IDENTITY_LINEAGE, LOCAL_STATE_LINEAGE};
    let identity = IDENTITY_LINEAGE.iter().map(|e| DelegateLineageEntry {
        generation: e.generation + IDENTITY_GENERATION_OFFSET,
        ..e.clone()
    });
    LOCAL_STATE_LINEAGE.iter().cloned().chain(identity).collect()
}

fn policy() -> SecretSelectionPolicy {
    SecretSelectionPolicy::UnionAllGenerations(
        UnionAck::i_understand_union_resurrects_deleted_by_absence_secrets(),
    )
}

/// How many walks in a row every pending predecessor must have answered "not
/// installed" before the walk stops running on every load.
const ABSENT_WALKS_BEFORE_BACKING_OFF: u32 = 3;
/// Once it has, one load in this many still walks: "not installed" is not
/// proof a predecessor holds nothing, and the node can change.
const BACKED_OFF_ONE_LOAD_IN: u8 = 10;

/// Whether this load walks, given `begin`'s status and a random byte. Only
/// a complete journal or a run of typed "not installed" answers reduce it;
/// a predecessor that went silent is asked on every load.
pub(crate) fn walk_this_load(status: &JournalStatus, roll: u8) -> bool {
    if status.is_complete() {
        return false;
    }
    !status.pending_all_absent(ABSENT_WALKS_BEFORE_BACKING_OFF)
        || roll.is_multiple_of(BACKED_OFF_ONE_LOAD_IN)
}

/// Whether the walk has nothing left to do for good.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Settled {
    /// Every predecessor is resolved with the journal's say-so.
    Complete,
    /// Anything else: the walk runs again on a later load.
    Retry,
}

/// The one place "the migration is finished" is decided. Only the journal's
/// `Complete` says so. `None` is a journal this load could not establish.
/// The wildcard covers `NotStarted`, `Unreadable`, `Incomplete` and any
/// status a later crate adds (the enum is `#[non_exhaustive]`): anything this
/// build cannot name means retry, never finished.
pub(crate) fn settled(status: Option<&JournalStatus>) -> Settled {
    match status {
        Some(JournalStatus::Complete { .. }) => Settled::Complete,
        _ => Settled::Retry,
    }
}

/// What one load's migration did.
#[derive(Debug)]
pub(crate) struct WalkOutcome {
    /// The journal's status at the end, `None` if it could not be read or
    /// stored.
    pub status: Option<JournalStatus>,
    /// The walk's report, `None` if this load did not walk.
    pub report: Option<JournaledMigrationReport>,
    pub counts: MigrationCounts,
}

/// Run this load's migration: start the journal, and walk unless the journal
/// says there is no need. Writes nothing migrated unless the journal stored
/// its start first.
pub(crate) async fn run<S, T, I>(store: S, transport: T, inbox: I, roll: u8) -> WalkOutcome
where
    S: MailStore,
    T: LegacyTransport,
    I: V1InboxReader,
{
    let lineage = lineage();
    let mut successor = MailSuccessor::new(store, inbox);
    let begun = begin_migration_journal(&mut successor, &lineage, &policy()).await;
    let status = match begun {
        Ok(status) => status,
        Err(e) => {
            crate::log::error(format!("migration: no journal this load: {e}"), None);
            return WalkOutcome {
                status: None,
                report: None,
                counts: successor.into_counts(),
            };
        }
    };
    if !walk_this_load(&status, roll) {
        return WalkOutcome {
            status: Some(status),
            report: None,
            counts: successor.into_counts(),
        };
    }
    let mut predecessors = LegacyAdapter::new(transport, lineage.clone());
    let report = migrate_delegate_secrets_journaled(
        &mut successor,
        &mut predecessors,
        &lineage,
        MigrationAuthorization::app_author_ack(),
        policy(),
    )
    .await;
    let mut counts = successor.into_counts();
    counts.merge_mapping(predecessors.counts());
    WalkOutcome {
        status: report.status.clone(),
        report: Some(report),
        counts,
    }
}

/// The line a person can read about a migration, `None` when there is
/// nothing to say. The upgrade notice replaces this.
pub(crate) fn status_line(outcome: &WalkOutcome) -> Option<String> {
    let c = &outcome.counts;
    let unreachable = outcome
        .report
        .as_ref()
        .is_some_and(|r| r.report.any_unresponsive());
    if c.is_empty() && !unreachable {
        return None;
    }
    Some(format!(
        "migration: {} identities, {} contacts, {} drafts, {} sent, {} kept, {} archived, \
         {} unmatched, {} refused, {} marks skipped; retry later: {}",
        c.identities,
        c.contacts,
        c.drafts,
        c.sent,
        c.kept,
        c.archived,
        c.orphaned,
        c.refused,
        c.flags_skipped,
        settled(outcome.status.as_ref()) == Settled::Retry,
    ))
}
