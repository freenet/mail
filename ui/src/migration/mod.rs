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
//! - **Import never overwrites.** Under `UnionAllGenerations` the first copy
//!   of a shared key to land stands, and a user's own edit on the new delegate
//!   stands the same way. The newest generation is first when it answers. If
//!   it gives nothing usable, it holds the older rows of its family back for
//!   a few loads, after which they proceed and their values stand. The
//!   documented cost: an identity deleted in a newer generation can come back
//!   from an older one, and anything the user deleted can come back while a
//!   predecessor is being retried.
//! - **A refusal that retrying cannot change ends the walk.** An item a cap
//!   refuses, or one whose identity was deleted, is a counted permanent
//!   rejection and stays in the predecessor.
//! - **There is no "done" marker of our own.** Completeness is the journal's
//!   status, read through [`settled`], and a predecessor that is simply not
//!   installed keeps the journal incomplete for good. That is expected. It
//!   costs a round trip on the loads that walk. The walk runs after the first
//!   identity listing and blocks nothing: while it runs, an empty list shows
//!   "Checking for your previous Mail data", and the list is read again once
//!   the identity rows are done and when it ends, if they brought anything.
//! - **A row that stays unresolved does not hold the rest back for good, and
//!   only a standing absence orphans.** An alias that cannot be resolved keeps
//!   its local-state row pending. Once the identity row of its own release
//!   has answered absent or empty more than
//!   [`legacy_delegates::HOLD_BACK_LOADS`] loads in a row, its items go to the
//!   orphans, which the user can move to an identity ([`orphans`]). A row the
//!   journal holds as resolved had data, so it never stands as absent.
//! - **The walk never modifies a predecessor.** Only [`scrub`] deletes from
//!   them, and it has rules of its own.
//!
//! The journal and the markers live in the mail delegate under the caller's
//! origin, not in the crate's reserved `\0` keys, so a staging app walks its
//! own migration and never reads production's.

use std::collections::HashMap;
use std::rc::Rc;

use freenet_mail_protocol::{Addr, IdentityInfo, Op, Reply};
use freenet_migrate::{
    DelegateLineageEntry, ImportFlag, JournalStatus, JournaledMigrationReport,
    MigrationAuthorization, SecretSelectionPolicy, UnionAck, begin_migration_journal,
    migrate_delegate_secrets_journaled,
};

pub(crate) mod ledger;
pub(crate) mod legacy_delegates;
#[cfg(feature = "use-node")]
pub(crate) mod node;
pub(crate) mod orphans;
pub(crate) mod scrub;
pub(crate) mod successor;
#[cfg(test)]
mod tests;

use crate::app::identity_store::{body_with_markers, markers_from_body};
use legacy_delegates::{LegacyAdapter, LegacyTransport};
use successor::{ArrivedIdentities, MailStore, MailSuccessor, MigrationCounts, V1InboxReader};

/// The mail delegate, through the page's usual calls.
#[derive(Clone)]
pub(crate) struct PageStore;

impl MailStore for PageStore {
    async fn call(&mut self, op: Op) -> Result<Reply, crate::mail_delegate::CallError> {
        crate::mail_delegate::call(op).await
    }
}

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
        ..*e
    });
    LOCAL_STATE_LINEAGE
        .iter()
        .cloned()
        .chain(identity)
        .collect()
}

fn policy() -> SecretSelectionPolicy {
    SecretSelectionPolicy::UnionAllGenerations(
        UnionAck::i_understand_union_resurrects_deleted_by_absence_secrets(),
    )
}

/// How many walks in a row every pending predecessor must have answered "not
/// installed" before the walk stops running on every load.
// One past the hold: the load that releases a held marker must not be left to
// the back-off's roll.
const ABSENT_WALKS_BEFORE_BACKING_OFF: u32 = legacy_delegates::HOLD_BACK_LOADS + 1;
/// Once it has, one load in this many still walks: "not installed" is not
/// proof a predecessor holds nothing, and the node can change.
const BACKED_OFF_ONE_LOAD_IN: u8 = 10;

/// How many walks a row must have been left unresolved before silence slows
/// the walk down, and how often it then runs. Shorter than the "not installed"
/// cadence: a silent row may hold data and answer on any load.
const SILENT_WALKS_BEFORE_SLOWING: u32 = 6;
const SLOWED_ONE_LOAD_IN: u8 = 4;

/// Whether this load walks, given `begin`'s status and a random byte. A
/// complete journal never walks. Every pending row having answered "not
/// installed" a few walks in a row walks one load in ten; every pending row
/// having been left unresolved for several walks walks one load in four.
/// Anything else, an import under way included, walks every load.
pub(crate) fn walk_this_load(status: &JournalStatus, roll: u8) -> bool {
    if status.is_complete() {
        return false;
    }
    if status.pending_all_absent(ABSENT_WALKS_BEFORE_BACKING_OFF) {
        return roll.is_multiple_of(BACKED_OFF_ONE_LOAD_IN);
    }
    let JournalStatus::Incomplete { pending, .. } = status else {
        return true;
    };
    let slowed = pending.iter().all(|p| {
        p.import != ImportFlag::Started
            && (p.absent_streak >= ABSENT_WALKS_BEFORE_BACKING_OFF
                || p.attempts >= SILENT_WALKS_BEFORE_SLOWING)
    });
    !slowed || roll.is_multiple_of(SLOWED_ONE_LOAD_IN)
}

impl WalkOutcome {
    /// Whether the move may be part done: an import under way, or a journal
    /// that could not be read or stored. What arrived is then not everything
    /// the user had, and the notice must not say it moved.
    pub(crate) fn unfinished(&self) -> bool {
        self.status
            .as_ref()
            .is_none_or(JournalStatus::interrupted_import)
            || self
                .report
                .as_ref()
                .is_some_and(|r| r.journal_error.is_some())
    }
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
    /// Rows that went silent or answered with bytes that do not decode. A
    /// typed "not installed" is not among them.
    pub silent_rows: usize,
    /// Held contract migrations were let go, so the next listing plans them.
    pub released_markers: bool,
    /// What this walk read from each row, before importing it.
    pub read_rows: legacy_delegates::RowHashes,
}

thread_local! {
    /// Held for a whole `run`. A load can start while another is walking (the
    /// repair paths reload), and the journal's read-merge-write protects
    /// against another tab but not against an interleaving inside this one.
    static ONE_WALK: Rc<futures::lock::Mutex<()>> = Rc::new(futures::lock::Mutex::new(()));
}

/// What the journal holds of a pending predecessor.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PendingRow {
    /// The walks it has been through.
    pub attempts: u32,
    /// Its import began and has not finished, so it held data.
    pub started: bool,
}

/// The pending predecessors, by delegate key. A row missing here counts as
/// resolved, so a status that does not list them (the enum is
/// `#[non_exhaustive]`) reads as every row pending, unless it is `Complete`.
fn pending_walks(
    status: &JournalStatus,
    lineage: &[DelegateLineageEntry],
) -> HashMap<Vec<u8>, PendingRow> {
    match status {
        JournalStatus::Incomplete { pending, .. } => pending
            .iter()
            .map(|p| {
                let row = PendingRow {
                    attempts: p.attempts,
                    started: p.import == ImportFlag::Started,
                };
                (p.key.bytes().to_vec(), row)
            })
            .collect(),
        JournalStatus::Complete { .. } => HashMap::new(),
        _ => lineage
            .iter()
            .map(|e| {
                let row = PendingRow {
                    attempts: 0,
                    started: false,
                };
                (e.delegate_key.to_vec(), row)
            })
            .collect(),
    }
}

/// Let go of the pending contract migrations no identity row can still
/// supersede: those imported from `newest_unsettled` or newer, or all of them
/// if no row is unsettled. Returns whether any was. The decision reads each
/// identity's own marker, so nothing else has to survive for it to run.
async fn release_held_markers<S: MailStore>(store: &mut S, newest_unsettled: Option<u32>) -> bool {
    let Ok(Reply::Identities(identities)) = store.call(Op::ListIdentities).await else {
        return false;
    };
    let mut released = false;
    for identity in identities {
        let written =
            successor::merged_put(store, successor::settings_item(identity.addr), |stored| {
                let mut markers = markers_from_body(stored);
                let superseded = newest_unsettled
                    .is_some_and(|row| markers.imported_generation.is_none_or(|from| from < row));
                if !markers.pending_held || superseded {
                    return None;
                }
                markers.pending_held = false;
                Some(body_with_markers(stored, &markers))
            })
            .await;
        released |= written.as_ref().is_ok_and(|w| *w);
    }
    released
}

/// Run this load's migration: start the journal, and walk unless the journal
/// says there is no need. Writes nothing migrated unless the journal stored
/// its start first. The ledger is written here, as rows resolve and at the
/// end, so a walk that dies is counted as far as it got.
///
/// `on_identities` runs once, if the walk brought an identity in, as soon as
/// the identity rows are done: the mail can take far longer, and the list need
/// not wait for it.
pub(crate) async fn run<S, T, I>(
    store: S,
    transport: T,
    inbox: I,
    roll: u8,
    on_identities: impl FnOnce() + 'static,
) -> WalkOutcome
where
    S: MailStore,
    T: LegacyTransport,
    I: V1InboxReader,
{
    let one_walk = ONE_WALK.with(Rc::clone);
    let _this_walk = one_walk.lock().await;
    let lineage = lineage();
    let arrived = ArrivedIdentities::default();
    let mut successor = MailSuccessor::new(store, inbox, arrived.clone());
    let begun = begin_migration_journal(&mut successor, &lineage, &policy()).await;
    let status = match begun {
        Ok(status) => status,
        Err(e) => {
            crate::log::error(format!("migration: no journal this load: {e}"), None);
            return WalkOutcome {
                status: None,
                report: None,
                counts: successor.into_counts(),
                silent_rows: 0,
                released_markers: false,
                read_rows: Default::default(),
            };
        }
    };
    let stored = ledger::read_ledger(successor.store()).await.ok();
    if stored
        .as_ref()
        .is_some_and(|l| l.migration_started_ms.is_none())
    {
        let now = chrono::Utc::now().timestamp_millis();
        let stamp = |l: &mut ledger::Ledger| {
            l.migration_started_ms.get_or_insert(now);
        };
        if let Err(e) = ledger::update_ledger(successor.store(), stamp).await {
            crate::log::error(format!("recording the migration's start failed: {e}"), None);
        }
    }
    if !walk_this_load(&status, roll) {
        // A walk that resolved the last row can die before it lets go.
        let released_markers =
            status.is_complete() && release_held_markers(successor.store(), None).await;
        return WalkOutcome {
            silent_rows: stored.map_or(0, |l| usize::from(l.silent)),
            status: Some(status),
            report: None,
            counts: successor.into_counts(),
            released_markers,
            read_rows: Default::default(),
        };
    }
    let walks = pending_walks(&status, &lineage);
    let stored = stored.unwrap_or_default();
    let kept_tables = ledger::kept_alias_tables(successor.store(), &stored).await;
    let mut predecessors = LegacyAdapter::new(
        transport,
        lineage.clone(),
        walks,
        arrived,
        stored.absent_answers,
        Box::new(on_identities),
    )
    .with_kept_tables(kept_tables);
    let report = migrate_delegate_secrets_journaled(
        &mut successor,
        &mut predecessors,
        &lineage,
        MigrationAuthorization::app_author_ack(),
        policy(),
    )
    .await;
    let silent_rows = predecessors.silent_rows();
    let answers = predecessors.row_answers();
    let rejected = report.status.as_ref().map(JournalStatus::rejected_items);
    successor
        .update_ledger(predecessors.counts(), |l| {
            for (generation, absent) in &answers {
                if *absent {
                    *l.absent_answers.entry(*generation).or_default() += 1;
                } else {
                    l.absent_answers.remove(generation);
                }
            }
            l.silent = silent_rows > 0;
            if let Some(rejected) = rejected.filter(|r| *r != l.rejected) {
                l.rejected = rejected;
                l.notice_dismissed = false;
            }
        })
        .await;
    let still_pending = pending_walks(
        report.status.as_ref().unwrap_or(&JournalStatus::NotStarted),
        &lineage,
    );
    let newest_unsettled = predecessors.newest_unsettled_row(Some(&still_pending));
    let released_markers = release_held_markers(successor.store(), newest_unsettled).await;
    let mut counts = successor.into_counts();
    counts.merge_mapping(predecessors.counts());
    WalkOutcome {
        status: report.status.clone(),
        report: Some(report),
        counts,
        silent_rows,
        released_markers,
        read_rows: predecessors.into_read(),
    }
}

/// Every code hash an identity's v1 inbox can be under: the registry's rows
/// and the current hash, which is not a row.
pub(crate) fn v1_inbox_hashes() -> Vec<String> {
    let rows = crate::legacy_registry::LEGACY_INBOX_CODE_HASHES.iter();
    rows.map(|hash| bs58::encode(hash).into_string())
        .chain(std::iter::once(
            crate::inbox::INBOX_CODE_HASH.trim().to_string(),
        ))
        .filter(|hash| !hash.is_empty())
        .collect()
}

/// Confirm the unconfirmed identities that have a v1 inbox under any hash: a
/// key that really was in use has one. The rest stay for their owner to
/// confirm. Returns the addresses confirmed.
pub(crate) async fn confirm_by_inbox<S, I>(
    store: &mut S,
    inbox: &mut I,
    identities: &[IdentityInfo],
) -> Vec<Addr>
where
    S: MailStore,
    I: V1InboxReader,
{
    let mut confirmed = Vec::new();
    for identity in identities.iter().filter(|i| !i.confirmed) {
        let mut found = false;
        for hash in v1_inbox_hashes() {
            if inbox.has_inbox(&identity.vk, &hash).await {
                found = true;
                break;
            }
        }
        if !found {
            continue;
        }
        let op = Op::ConfirmIdentity {
            addr: identity.addr,
            expected_gen: identity.generation,
        };
        match store.call(op).await {
            Ok(_) => confirmed.push(identity.addr),
            Err(e) => crate::log::error(format!("confirming an identity failed: {e}"), None),
        }
    }
    confirmed
}

/// The migration's state for diagnosis: the journal, each row, the counts and
/// the notice's counts. Shown under Your identities as JSON.
pub(crate) fn status_report(status: Option<&JournalStatus>, ledger: &ledger::Ledger) -> String {
    let rows: Vec<serde_json::Value> = lineage()
        .iter()
        .map(|e| {
            let pending = match status {
                Some(JournalStatus::Incomplete { pending, .. }) => pending
                    .iter()
                    .find(|p| p.key.bytes() == e.delegate_key.as_slice()),
                _ => None,
            };
            serde_json::json!({
                "generation": e.generation,
                "outcome": match (status, pending) {
                    (_, Some(_)) => "pending",
                    (Some(JournalStatus::Complete { .. } | JournalStatus::Incomplete { .. }), _) => {
                        "resolved"
                    }
                    _ => "unknown",
                },
                "attempts": pending.map(|p| p.attempts),
                "absent_streak": pending.map(|p| p.absent_streak),
                "import_started": pending.map(|p| p.import == ImportFlag::Started),
            })
        })
        .collect();
    serde_json::json!({
        "journal": status.map(|s| format!("{s:?}")),
        "rejected_items": status.map(JournalStatus::rejected_items),
        "rows": rows,
        "counts": ledger.totals,
        "scrub_built": scrub::BUILT_IN,
        "scrubbed": ledger.scrubbed,
        "scrub_blockers": ledger.scrub_blockers,
    })
    .to_string()
}

/// The log's line about a migration, `None` when there is nothing to say.
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
         {} unmatched, {} refused, {} over a cap, {} of deleted identities, {} marks skipped, \
         {} deleted marks left out; retry later: {}",
        c.identities,
        c.contacts,
        c.drafts,
        c.sent,
        c.kept,
        c.archived,
        c.orphaned,
        c.refused,
        c.at_cap,
        c.identity_gone,
        c.flags_skipped,
        c.deleted_marks,
        settled(outcome.status.as_ref()) == Settled::Retry,
    ))
}
