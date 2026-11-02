//! Clearing superseded local stores: removing what the v0.2.x delegates hold
//! once the mail delegate provably holds it.
//!
//! This deletes the old copy of users' keys and mail, so it runs only if every
//! check passes, from reads made on this load. A check that can never pass
//! leaves the old copy in place for good: the status report says why and
//! nobody is alarmed.
//!
//! The checks:
//!
//! - every row of the lineage is clear. A row is clear if the journal holds it
//!   as resolved, or if it is pending with no import begun, its absence has
//!   stood for the count the held markers use, and it answers the same way
//!   now. Most users have one generation installed, so the journal is
//!   normally never `Complete`, and requiring that would mean scrub never
//!   runs;
//! - only rows that imported are touched. An absent row is sent nothing: if
//!   one returns, the walk picks it up and this module sees an imported row;
//! - an identity row goes only with its generation's local-state row clear.
//!   Alias tables are read live, so removing one while that row is pending
//!   would misfile its mail;
//! - nothing was rejected, no orphans are left and no entry is unmappable;
//! - every id a fresh read of a row maps to, by the walk's own mapping, is in
//!   the mail delegate, or was when the imported-ids snapshot was written (it
//!   landed and the user deleted it), or is an orphan the user moved. That
//!   also finds what an old tab wrote after the walk. Read marks are not
//!   compared: they are not the only copy of anything;
//! - every identity being scrubbed that the mail delegate still has was backed
//!   up after the migration began. One the user deleted there needs no backup.
//!
//! Local state goes first and identities last, so an interruption cannot leave
//! mail without its alias table. A row's deletes come from the read the checks
//! passed on, so an item written since is never deleted unproven. v0.2.x
//! delegates acknowledge a change with an empty reply, which proves nothing, so
//! a row is finished only once a re-read shows nothing left to delete. wire-v1
//! has no delete for settings, or for read marks outside the kept and archived
//! messages, so those stay.
//!
//! The token-generator delegates are not touched: the v1 send path uses them.

use std::collections::{BTreeSet, HashSet};
use std::rc::Rc;

use freenet_mail_protocol::{Addr, ItemKind, ItemRef, MAX_ITEM_BYTES, Op, Reply};
use freenet_mail_wire_v1::identity::{IdentityManagement, IdentityMsg};
use freenet_mail_wire_v1::local_state::{LocalState, LocalStateMsg};
use freenet_migrate::{DelegateLineageEntry, PredecessorSecretsIo};
use serde::{Deserialize, Serialize};

use super::ledger::{Ledger, list_items, read_ledger, snapshot_item, update_ledger};
use super::legacy_delegates::{
    EMPTY_REPLY, LegacyAdapter, LegacyReply, LegacyTransport, PairKey, hex, id16, lineage_key,
};
use super::successor::{ArrivedIdentities, MailStore, get_item, merged_put, settings_item};
use super::{IDENTITY_GENERATION_OFFSET, ONE_WALK, WalkOutcome, pending_walks};
use crate::mail_delegate::CallError;

const ID_BYTES: usize = 16;
const IDS_PER_CHUNK: usize = MAX_ITEM_BYTES / ID_BYTES / 2;

/// Why scrub did not run, or stopped. Stored for the status report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Blocker {
    /// The journal could not be established this load.
    NoJournal,
    /// A row is neither resolved nor standing as absent.
    NotClear {
        generation: u32,
    },
    Rejected(u32),
    Orphans(u32),
    /// Entries of the rows that cannot be mapped, ever.
    Unmappable(u32),
    /// A row to clear gave no usable answer to the fresh read.
    Unread {
        generation: u32,
    },
    /// A snapshot chunk is missing.
    NoSnapshot,
    /// Ids a row maps to that are not stored, snapshotted or moved.
    NotImported {
        generation: u32,
        ids: u32,
    },
    /// Identities with no backup made since the migration began.
    NoBackup(u32),
    /// A row's clearing failed. A later load tries again.
    RowFailed {
        generation: u32,
    },
    /// The mail delegate gave no usable answer.
    Delegate(String),
}

impl From<CallError> for Blocker {
    fn from(e: CallError) -> Self {
        Blocker::Delegate(e.to_string())
    }
}

fn is_identity_row(entry: &DelegateLineageEntry) -> bool {
    entry.generation >= IDENTITY_GENERATION_OFFSET
}

fn snapshot_id(key: &PairKey) -> [u8; ID_BYTES] {
    id16(&[&key.encode()])
}

fn unowned(kind: ItemKind, id: &[u8]) -> ItemRef {
    ItemRef {
        kind,
        owner: None,
        id: id.to_vec(),
    }
}

/// The keys a row's items are compared by: read marks are left out, and a
/// refused entry is a blocker of its own.
fn compared(keys: &[PairKey]) -> impl Iterator<Item = &PairKey> {
    keys.iter()
        .filter(|k| !matches!(k, PairKey::Flags(_) | PairKey::Refused(_)))
}

/// The identities the mail delegate lists. An identity it cannot read is not
/// listed, and must not pass for one the user deleted, so that is an error.
async fn readable_identities<S: MailStore>(store: &mut S) -> Result<HashSet<Addr>, Blocker> {
    match store.call(Op::GetStatus).await? {
        Reply::Status(status) if status.unreadable_identities == 0 => {}
        Reply::Status(_) => return Err(Blocker::Delegate("an unreadable identity".into())),
        other => return Err(crate::mail_delegate::unexpected(&other).into()),
    }
    match store.call(Op::ListIdentities).await? {
        Reply::Identities(list) => Ok(list.iter().map(|i| i.addr).collect()),
        other => Err(crate::mail_delegate::unexpected(&other).into()),
    }
}

/// Whether the mail delegate holds what `key` stands for. Each item is read,
/// not listed: a listing leaves out a record that failed to read, and this
/// call fails on one.
async fn present<S: MailStore>(
    store: &mut S,
    key: &PairKey,
    identities: &HashSet<Addr>,
) -> Result<bool, CallError> {
    let held = |owner: &Addr| identities.contains(owner);
    let item = match key {
        PairKey::Identity(addr) => return Ok(held(addr)),
        PairKey::Contact(addr) => unowned(ItemKind::Contact, &addr.0),
        PairKey::GlobalSettings => unowned(ItemKind::GlobalSettings, &[]),
        PairKey::Orphan(id) => unowned(ItemKind::LegacyOrphan, id),
        PairKey::IdentitySettings(owner) if held(owner) => settings_item(*owner),
        PairKey::Message { kind, owner, id } if held(owner) => ItemRef {
            kind: *kind,
            owner: Some(*owner),
            id: id.to_vec(),
        },
        _ => return Ok(false),
    };
    Ok(get_item(store, item).await?.is_some())
}

/// Write the one snapshot: the ids the rows map to that the mail delegate
/// holds now. The chunks go first, so a tab that dies leaves no count and the
/// next load writes them again. Returns the chunk count.
async fn write_snapshot<S: MailStore>(
    store: &mut S,
    rows: &[(u32, Vec<PairKey>)],
    identities: &HashSet<Addr>,
) -> Result<u32, CallError> {
    let mut ids = BTreeSet::new();
    for key in rows.iter().flat_map(|(_, keys)| compared(keys)) {
        if present(store, key, identities).await? {
            ids.insert(snapshot_id(key));
        }
    }
    let ids: Vec<[u8; ID_BYTES]> = ids.into_iter().collect();
    let chunks: Vec<Vec<u8>> = ids.chunks(IDS_PER_CHUNK).map(<[_]>::concat).collect();
    for (index, chunk) in chunks.iter().enumerate() {
        merged_put(store, snapshot_item(index as u32), |_| Some(chunk.clone())).await?;
    }
    let count = chunks.len() as u32;
    update_ledger(store, |l| {
        l.snapshot_chunks.get_or_insert(count);
    })
    .await?;
    Ok(count)
}

async fn read_snapshot<S: MailStore>(
    store: &mut S,
    chunks: u32,
) -> Result<HashSet<[u8; ID_BYTES]>, Blocker> {
    let mut ids = HashSet::new();
    for index in 0..chunks {
        let chunk = get_item(store, snapshot_item(index)).await?;
        let chunk = chunk.ok_or(Blocker::NoSnapshot)?;
        for id in chunk.body.chunks_exact(ID_BYTES) {
            ids.insert(<[u8; ID_BYTES]>::try_from(id).expect("exact chunks"));
        }
    }
    Ok(ids)
}

/// Whether `addr` was backed up after `since`. The value is compared with the
/// time and not just tested: it is imported with the settings.
async fn backed_up_since<S: MailStore>(
    store: &mut S,
    addr: Addr,
    since: Option<i64>,
) -> Result<bool, CallError> {
    let Some(item) = get_item(store, settings_item(addr)).await? else {
        return Ok(false);
    };
    let settings: serde_json::Value = serde_json::from_slice(&item.body).unwrap_or_default();
    let at = settings["last_backup_at"].as_i64();
    Ok(at.zip(since).is_some_and(|(at, since)| at > since))
}

/// How many of `addrs` the mail delegate holds with no backup since the
/// migration began. One it no longer holds is an identity the user deleted
/// there, which has nothing to protect.
async fn unprotected<S: MailStore>(
    store: &mut S,
    addrs: HashSet<Addr>,
    ledger: &Ledger,
    identities: &HashSet<Addr>,
) -> Result<u32, CallError> {
    let mut count = 0;
    for addr in addrs.into_iter().filter(|a| identities.contains(a)) {
        if !backed_up_since(store, addr, ledger.migration_started_ms).await? {
            count += 1;
        }
    }
    Ok(count)
}

/// The checks that need no read of a legacy row, so that a user who has not
/// backed up does not pay for those reads on every load.
async fn cheap_blockers<S: MailStore>(
    store: &mut S,
    outcome: &WalkOutcome,
    ledger: &Ledger,
    identities: &HashSet<Addr>,
) -> Result<Vec<Blocker>, Blocker> {
    let mut found = Vec::new();
    let rejected = outcome.status.as_ref().map_or(0, |s| s.rejected_items());
    if rejected > 0 {
        found.push(Blocker::Rejected(rejected));
    }
    let orphans = list_items(store, ItemKind::LegacyOrphan, None).await?;
    if !orphans.is_empty() {
        found.push(Blocker::Orphans(orphans.len() as u32));
    }
    let migrated = ledger.migrated.iter().copied().collect();
    let count = unprotected(store, migrated, ledger, identities).await?;
    if count > 0 {
        found.push(Blocker::NoBackup(count));
    }
    Ok(found)
}

/// Read and map the rows to clear, as the walk maps them. A row whose clearing
/// began can have nothing left to map.
async fn read_rows<T: LegacyTransport>(
    adapter: &mut LegacyAdapter<T>,
    targets: &[&DelegateLineageEntry],
    ledger: &Ledger,
) -> Result<Vec<(u32, Vec<PairKey>)>, Blocker> {
    let mut rows = Vec::new();
    for entry in targets {
        let generation = entry.generation;
        let keys = match adapter.fetch_secrets(&lineage_key(entry)).await {
            Ok(pairs) => pairs
                .iter()
                .map(|(key, _)| PairKey::decode(key).unwrap_or(PairKey::Refused([0; ID_BYTES])))
                .collect(),
            Err(_)
                if ledger.scrubbed.contains_key(&generation)
                    && adapter.holds_nothing(entry).await =>
            {
                Vec::new()
            }
            Err(_) => return Err(Blocker::Unread { generation }),
        };
        rows.push((generation, keys));
    }
    Ok(rows)
}

/// What the rows show against the mail delegate: entries that cannot be
/// mapped, identities with no backup, and ids that did not land.
async fn row_blockers<S: MailStore>(
    store: &mut S,
    rows: &[(u32, Vec<PairKey>)],
    ledger: &Ledger,
    chunks: u32,
    identities: &HashSet<Addr>,
) -> Result<Vec<Blocker>, Blocker> {
    let mut found = Vec::new();
    let all = || rows.iter().flat_map(|(_, keys)| keys);
    let refused = all().filter(|k| matches!(k, PairKey::Refused(_))).count();
    if refused > 0 {
        found.push(Blocker::Unmappable(refused as u32));
    }
    let scrubbed = all().filter_map(|key| match key {
        PairKey::Identity(addr) => Some(*addr),
        _ => None,
    });
    let count = unprotected(store, scrubbed.collect(), ledger, identities).await?;
    if count > 0 {
        found.push(Blocker::NoBackup(count));
    }
    let snapshot = read_snapshot(store, chunks).await?;
    for (generation, keys) in rows {
        let mut ids = 0;
        for key in compared(keys) {
            // Read first: a record that fails to read must stop this, even
            // for an id the snapshot lists.
            let stored = present(store, key, identities).await?;
            let moved = matches!(key, PairKey::Orphan(id) if ledger.moved.contains(&hex(id)));
            if !stored && !moved && !snapshot.contains(&snapshot_id(key)) {
                ids += 1;
            }
        }
        if ids > 0 {
            let generation = *generation;
            found.push(Blocker::NotImported { generation, ids });
        }
    }
    Ok(found)
}

/// The legacy messages that remove what a row holds.
fn row_deletes(entry: &DelegateLineageEntry, bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let text = |e: freenet_stdlib::prelude::DelegateError| e.to_string();
    let mut out = Vec::new();
    if is_identity_row(entry) {
        let manager = IdentityManagement::try_from(bytes).map_err(text)?;
        let aliases: BTreeSet<String> = manager.into_info().map(|(alias, _)| alias).collect();
        for alias in aliases {
            out.push(Vec::<u8>::try_from(&IdentityMsg::DeleteIdentity { alias }).map_err(text)?);
        }
        return Ok(out);
    }
    let mut state = LocalState::try_from(bytes).map_err(text)?;
    for (alias, held) in state.aliases_mut().iter() {
        let mut messages = Vec::new();
        for id in held.drafts.keys().cloned() {
            let alias = alias.clone();
            messages.push(LocalStateMsg::DeleteDraft { alias, id });
        }
        for id in held.sent.keys().cloned() {
            let alias = alias.clone();
            messages.push(LocalStateMsg::DeleteSent { alias, id });
        }
        // One message clears a position from both maps.
        let positions = held.kept.keys().chain(held.archived.keys());
        let positions: BTreeSet<u64> = positions.filter_map(|k| k.parse().ok()).collect();
        for msg_id in positions {
            let alias = alias.clone();
            messages.push(LocalStateMsg::DeleteMessage { alias, msg_id });
        }
        for message in &messages {
            out.push(Vec::<u8>::try_from(message).map_err(text)?);
        }
    }
    Ok(out)
}

/// Clear one row from the answer the checks passed on, then read it back.
async fn clear_row<T: LegacyTransport>(
    adapter: &mut LegacyAdapter<T>,
    entry: &DelegateLineageEntry,
) -> bool {
    let Some(Ok(requests)) = adapter.answer(entry).map(|bytes| row_deletes(entry, bytes)) else {
        return false;
    };
    for request in requests {
        match adapter.send(entry, request).await {
            LegacyReply::NoAnswer(why) if why == EMPTY_REPLY => {}
            _ => return false,
        }
    }
    let left = adapter.reread(entry).await.map(|b| row_deletes(entry, b));
    matches!(left, Some(Ok(requests)) if requests.is_empty())
}

/// The order rows are cleared in: local state, then the identity rows whose
/// generation's local-state row is clear.
pub(super) fn clearing_order<'a>(
    targets: &[&'a DelegateLineageEntry],
    not_clear: &HashSet<u32>,
) -> Vec<&'a DelegateLineageEntry> {
    let (identities, local): (Vec<_>, Vec<_>) =
        targets.iter().copied().partition(|e| is_identity_row(e));
    let paired = |e: &&DelegateLineageEntry| {
        !not_clear.contains(&(e.generation - IDENTITY_GENERATION_OFFSET))
    };
    local
        .into_iter()
        .chain(identities.into_iter().filter(paired))
        .collect()
}

/// Clear `order`, journaling each row. Stops at the first that fails.
async fn clear_rows<S: MailStore, T: LegacyTransport>(
    store: &mut S,
    adapter: &mut LegacyAdapter<T>,
    order: &[&DelegateLineageEntry],
) -> Result<(), Blocker> {
    for entry in order {
        let generation = entry.generation;
        update_ledger(store, |l| {
            l.scrubbed.entry(generation).or_default();
        })
        .await?;
        if !clear_row(adapter, entry).await {
            return Err(Blocker::RowFailed { generation });
        }
        update_ledger(store, |l| {
            l.scrubbed.insert(generation, true);
        })
        .await?;
    }
    Ok(())
}

async fn attempt<S: MailStore, T: LegacyTransport>(
    store: &mut S,
    transport: T,
    outcome: &WalkOutcome,
    on_clearing: impl FnOnce(),
) -> Result<Vec<Blocker>, Blocker> {
    let journal_stored = !outcome
        .report
        .as_ref()
        .is_some_and(|r| r.journal_error.is_some());
    let Some(status) = outcome.status.as_ref().filter(|_| journal_stored) else {
        return Ok(vec![Blocker::NoJournal]);
    };
    let ledger = read_ledger(store).await?;
    let lineage = super::lineage();
    let pending = pending_walks(status, &lineage);
    let targets: Vec<&DelegateLineageEntry> = lineage
        .iter()
        .filter(|e| !pending.contains_key(e.delegate_key.as_slice()))
        .filter(|e| ledger.scrubbed.get(&e.generation) != Some(&true))
        .collect();
    if targets.is_empty() {
        return Ok(Vec::new());
    }

    let mut adapter = LegacyAdapter::new(
        transport,
        lineage.clone(),
        pending.clone(),
        ArrivedIdentities::default(),
        ledger.absent_answers.clone(),
        Box::new(|| {}),
    );
    let mut not_clear = HashSet::new();
    for entry in &lineage {
        if pending.contains_key(entry.delegate_key.as_slice())
            && !(adapter.absence_stands(entry) && adapter.holds_nothing(entry).await)
        {
            not_clear.insert(entry.generation);
        }
    }
    let order = clearing_order(&targets, &not_clear);
    if !not_clear.is_empty() {
        let generations: BTreeSet<u32> = not_clear.into_iter().collect();
        let blockers = generations.into_iter();
        return Ok(blockers
            .map(|generation| Blocker::NotClear { generation })
            .collect());
    }

    let identities = readable_identities(store).await?;
    let cheap = cheap_blockers(store, outcome, &ledger, &identities).await?;
    if ledger.snapshot_chunks.is_some() && !cheap.is_empty() {
        return Ok(cheap);
    }
    let rows = read_rows(&mut adapter, &targets, &ledger).await?;
    let chunks = match ledger.snapshot_chunks {
        Some(chunks) => chunks,
        None => write_snapshot(store, &rows, &identities).await?,
    };
    if !cheap.is_empty() {
        return Ok(cheap);
    }
    let blockers = row_blockers(store, &rows, &ledger, chunks, &identities).await?;
    if !blockers.is_empty() {
        return Ok(blockers);
    }
    on_clearing();
    clear_rows(store, &mut adapter, &order).await?;
    Ok(Vec::new())
}

/// Clear what can be cleared on this load. `outcome` is this load's walk, and
/// `on_clearing` hears when deletes are about to start. Returns what stopped
/// it, also stored in the ledger.
pub(crate) async fn run<S: MailStore, T: LegacyTransport>(
    store: &mut S,
    transport: T,
    outcome: &WalkOutcome,
    on_clearing: impl FnOnce(),
) -> Vec<Blocker> {
    let one_walk = ONE_WALK.with(Rc::clone);
    let _this_walk = one_walk.lock().await;
    let found = attempt(store, transport, outcome, on_clearing).await;
    let blockers = found.unwrap_or_else(|blocker| vec![blocker]);
    if let Err(e) = update_ledger(store, |l| l.scrub_blockers = blockers.clone()).await {
        crate::log::error(format!("recording why scrub stopped failed: {e}"), None);
    }
    blockers
}
