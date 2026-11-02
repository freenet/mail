//! Clearing superseded local stores: removing what the v0.2.x delegates hold
//! once the mail delegate provably holds it.
//!
//! This deletes the old copy of users' keys and mail, so it runs only if every
//! check passes. The rows are read on this load; what the journal says of them
//! is from this load's walk, or its `begin` if it did not walk. A check that
//! can never pass leaves the old copy in place for good: the status report
//! says why and nobody is alarmed.
//!
//! It is compiled in only by a build with `FREENET_MAIL_SCRUB=1`: the journal
//! and the imported items are per origin, the v0.2.x delegates are not, so a
//! test build on a node with real data must never clear what production has
//! yet to read. Off, it does nothing at all.
//!
//! The checks:
//!
//! - every row of the lineage is clear. A row is clear if the journal holds it
//!   as resolved, or if it is pending with no import begun, its absence has
//!   stood for the count the held markers use, and it answers the same way
//!   now. Most users have one generation installed, so the journal is
//!   normally never `Complete`, and requiring that would mean scrub never
//!   runs;
//! - only rows that imported are touched. An absent row is sent nothing. If it
//!   returns the walk reads it and this module sees an imported row, and its
//!   aliases resolve against the table kept for a cleared identity row;
//! - an identity row goes only with its generation's local-state row clear.
//!   Alias tables are read live, so removing one while that row is pending
//!   would misfile its mail;
//! - nothing was rejected, no orphans are left and no entry is unmappable;
//! - every id a fresh read of a row maps to, by the walk's own mapping, with
//!   the same value, is the mail delegate's import of it now, or is in the
//!   row's snapshot (it landed then, whatever the user has done with it
//!   since), or is an orphan the user moved or discarded. That also finds what
//!   an old tab wrote or changed after the walk. Read marks are not compared:
//!   they are not the only copy of anything;
//! - every identity the rows name that the mail delegate has was backed up
//!   after the migration began, and the user deleted any it does not have.
//!
//! Each row's snapshot is written the first time it is seen resolved, from
//! what the walk read before importing, so a deletion on a later load does not
//! block and an edit made during the import is not taken for what landed. A
//! tab that dies before writing it leaves only what still equals the import.
//!
//! Local state goes first and identities last, so an interruption cannot leave
//! mail without its alias table. A row is read again just before its first
//! delete and stops unless the bytes are what the checks passed on: the frozen
//! delegates delete by name, with no compare-and-swap. v0.2.x delegates
//! acknowledge a change with an empty reply, which proves nothing, and answer
//! a failed read as empty, so a row is finished only after showing nothing
//! left to delete on [`EMPTY_LOADS`] loads, and the identity rows wait for
//! that. wire-v1 has no delete for settings, or for read marks outside the
//! kept and archived messages, so those stay.
//!
//! The token-generator delegates are not touched: the v1 send path uses them.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::rc::Rc;

use freenet_mail_protocol::{Addr, IdentityInfo, ItemKind, ItemRef, MAX_ITEM_BYTES, Op, Reply};
use freenet_mail_wire_v1::identity::{IdentityManagement, IdentityMsg};
use freenet_mail_wire_v1::local_state::{LocalState, LocalStateMsg};
use freenet_migrate::{DelegateLineageEntry, PredecessorSecretsIo};
use serde::{Deserialize, Serialize};

use super::ledger::{
    Ledger, alias_table_item, kept_alias_tables, list_items, read_ledger, snapshot_item,
    update_ledger,
};
use super::legacy_delegates::{
    EMPTY_REPLY, LegacyAdapter, LegacyReply, LegacyTransport, MappingCounts, MigratedIdentity,
    PairKey, distinct_alias, hex, id16, lineage_key, map_identities,
};
use super::successor::{ArrivedIdentities, MailStore, get_item, merged_put, settings_item};
use super::{IDENTITY_GENERATION_OFFSET, ONE_WALK, WalkOutcome, pending_walks};
use crate::mail_delegate::CallError;

const ID_BYTES: usize = 16;
/// A snapshot entry: an id, then the hash of the value mapped to it.
const ENTRY_BYTES: usize = 2 * ID_BYTES;
const ENTRIES_PER_CHUNK: usize = MAX_ITEM_BYTES / ENTRY_BYTES / 2;

/// Whether this build scrubs at all: only with `FREENET_MAIL_SCRUB=1`.
pub(crate) const BUILT_IN: bool = match option_env!("FREENET_MAIL_SCRUB") {
    Some(value) => matches!(value.as_bytes(), b"1"),
    None => false,
};
/// In a build's WASM only if [`BUILT_IN`]: `scripts/check-release-scrub.sh`
/// refuses a production build without it. The text is chosen by the flag, so
/// it is in the binary only when the flag is, wherever it is logged.
pub(super) const BUILD_MARKER: &str = if BUILT_IN {
    "freenet-mail:scrub-built-in"
} else {
    ""
};

/// How many loads a row must show nothing left to delete to be finished.
const EMPTY_LOADS: u32 = 2;

/// Why scrub did not run, or stopped. Stored for the status report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Blocker {
    /// This build has scrub off ([`BUILT_IN`]).
    NotBuilt,
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
    /// Items a row maps to whose id and value are not stored, snapshotted or
    /// handled as orphans.
    NotImported {
        generation: u32,
        ids: u32,
    },
    /// Identities with no backup made since the migration began.
    NoBackup(u32),
    /// Identities whose KEM key the mail delegate holds differently from the row.
    KeyMismatch(u32),
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

fn snapshot_entry(key: &PairKey, value_hash: &[u8; ID_BYTES]) -> [u8; ENTRY_BYTES] {
    let mut entry = [0; ENTRY_BYTES];
    entry[..ID_BYTES].copy_from_slice(&id16(&[&key.encode()]));
    entry[ID_BYTES..].copy_from_slice(value_hash);
    entry
}

fn unowned(kind: ItemKind, id: &[u8]) -> ItemRef {
    ItemRef {
        kind,
        owner: None,
        id: id.to_vec(),
    }
}

/// Whether a row's item is compared: read marks are left out, and a refused
/// entry is a blocker of its own.
fn is_compared(key: &PairKey) -> bool {
    !matches!(key, PairKey::Flags(_) | PairKey::Refused(_))
}

/// The identity an item belongs to.
fn owner(key: &PairKey) -> Option<Addr> {
    match key {
        PairKey::Identity(addr) | PairKey::Flags(addr) | PairKey::IdentitySettings(addr) => {
            Some(*addr)
        }
        PairKey::Message { owner, .. } => Some(*owner),
        _ => None,
    }
}

/// The identities the mail delegate lists. An identity it cannot read is not
/// listed, and must not pass for one the user deleted, so that is an error.
async fn readable_identities<S: MailStore>(
    store: &mut S,
) -> Result<HashMap<Addr, IdentityInfo>, Blocker> {
    match store.call(Op::GetStatus).await? {
        Reply::Status(status) if status.unreadable_identities == 0 => {}
        Reply::Status(_) => return Err(Blocker::Delegate("an unreadable identity".into())),
        other => return Err(crate::mail_delegate::unexpected(&other).into()),
    }
    match store.call(Op::ListIdentities).await? {
        Reply::Identities(list) => Ok(list.into_iter().map(|i| (i.addr, i)).collect()),
        other => Err(crate::mail_delegate::unexpected(&other).into()),
    }
}

/// The item `key` stands for in the mail delegate, if it can have one.
fn stored_item(key: &PairKey, identities: &HashMap<Addr, IdentityInfo>) -> Option<ItemRef> {
    let held = |owner: &Addr| identities.contains_key(owner);
    match key {
        PairKey::Contact(addr) => Some(unowned(ItemKind::Contact, &addr.0)),
        PairKey::GlobalSettings => Some(unowned(ItemKind::GlobalSettings, &[])),
        PairKey::Orphan(id) => Some(unowned(ItemKind::LegacyOrphan, id)),
        PairKey::IdentitySettings(owner) if held(owner) => Some(settings_item(*owner)),
        PairKey::Message { kind, owner, id } if held(owner) => Some(ItemRef {
            kind: *kind,
            owner: Some(*owner),
            id: id.to_vec(),
        }),
        _ => None,
    }
}

/// Whether the mail delegate holds what `key` stands for. Each item is read,
/// not listed: a listing leaves out a record that failed to read, and this
/// call fails on one.
async fn present<S: MailStore>(
    store: &mut S,
    key: &PairKey,
    identities: &HashMap<Addr, IdentityInfo>,
) -> Result<bool, CallError> {
    if let PairKey::Identity(addr) = key {
        return Ok(identities.contains_key(addr));
    }
    let Some(item) = stored_item(key, identities) else {
        return Ok(false);
    };
    Ok(get_item(store, item).await?.is_some())
}

/// Whether every field of `value` is in `stored` with that value. `null` is an
/// absent field, as it is to the merge that imports settings.
fn holds_fields(stored: &serde_json::Value, value: &serde_json::Value) -> bool {
    match (stored, value) {
        (serde_json::Value::Object(s), serde_json::Value::Object(v)) => v
            .iter()
            .all(|(field, v)| v.is_null() || s.get(field).is_some_and(|s| holds_fields(s, v))),
        _ => stored == value,
    }
}

/// Whether the mail delegate holds `key` as the import of `value` now: the
/// same bytes, or for settings, which merge, the same fields. An identity's
/// address fixes its signing seed, so its alias and description are compared.
async fn is_import_of<S: MailStore>(
    store: &mut S,
    key: &PairKey,
    value: &[u8],
    identities: &HashMap<Addr, IdentityInfo>,
) -> Result<bool, CallError> {
    if let PairKey::Identity(addr) = key {
        let held = identities.get(addr);
        let mapped = serde_json::from_slice::<MigratedIdentity>(value).ok();
        return Ok(held.zip(mapped).is_some_and(|(held, mapped)| {
            held.description == mapped.description
                && (held.alias == mapped.alias || held.alias == distinct_alias(&mapped.alias, addr))
        }));
    }
    let Some(item) = stored_item(key, identities) else {
        return Ok(false);
    };
    let Some(stored) = get_item(store, item).await? else {
        return Ok(false);
    };
    if !matches!(key, PairKey::IdentitySettings(_) | PairKey::GlobalSettings) {
        return Ok(stored.body.as_slice() == value);
    }
    let json = |bytes: &[u8]| serde_json::from_slice::<serde_json::Value>(bytes).ok();
    let both = json(&stored.body).zip(json(value));
    Ok(both.is_some_and(|(stored, value)| holds_fields(&stored, &value)))
}

/// Whether the mail delegate holds `key` as the import of a value read earlier,
/// known by its hash and, for settings, its value. An identity is present or
/// not: its aliases can differ for one address, and its seeds are checked by
/// [`row_blockers`].
async fn holds_now<S: MailStore>(
    store: &mut S,
    key: &PairKey,
    hash: &[u8; ID_BYTES],
    settings: Option<&[u8]>,
    identities: &HashMap<Addr, IdentityInfo>,
) -> Result<bool, CallError> {
    if matches!(key, PairKey::Identity(_)) {
        return present(store, key, identities).await;
    }
    let Some(item) = stored_item(key, identities) else {
        return Ok(false);
    };
    let Some(stored) = get_item(store, item).await? else {
        return Ok(false);
    };
    let Some(value) = settings else {
        return Ok(id16(&[&stored.body]) == *hash);
    };
    let json = |bytes: &[u8]| serde_json::from_slice::<serde_json::Value>(bytes).ok();
    let both = json(&stored.body).zip(json(value));
    Ok(both.is_some_and(|(stored, value)| holds_fields(&stored, &value)))
}

/// Write the snapshot of each of `rows`, once: what its read mapped to that
/// the mail delegate holds. The chunks go first, so a tab that dies leaves no
/// count and the next load writes them again. With no read from this load's
/// walk, what a read gives now may have changed since the import, so only what
/// still equals the import goes in. A row that gives no read waits.
async fn write_snapshots<S: MailStore, T: LegacyTransport>(
    store: &mut S,
    adapter: &mut LegacyAdapter<T>,
    rows: &[&DelegateLineageEntry],
    outcome: &WalkOutcome,
    identities: &HashMap<Addr, IdentityInfo>,
) -> Result<(), CallError> {
    for entry in rows {
        let generation = entry.generation;
        let mut entries = BTreeSet::new();
        if let Some(read) = outcome.read_rows.get(&generation) {
            for (key, hash, settings) in read {
                let Some(decoded) = PairKey::decode(key).filter(is_compared) else {
                    continue;
                };
                // A value that neither landed nor is held did not land: import
                // never overwrites, so the row may hold the only copy. What
                // this walk wrote landed, whatever the page has done to it
                // since. A newer row holding the key supersedes this copy; if
                // that one differs from the delegate it is not recorded.
                let newer = outcome.read_rows.iter().any(|(g, pairs)| {
                    *g > generation
                        && (*g >= IDENTITY_GENERATION_OFFSET) == is_identity_row(entry)
                        && pairs.iter().any(|(k, _, _)| k == key)
                });
                let landed = outcome.landed.contains(&(generation, key.clone()));
                if newer
                    || landed
                    || holds_now(store, &decoded, hash, settings.as_deref(), identities).await?
                {
                    entries.insert(snapshot_entry(&decoded, hash));
                }
            }
        } else {
            let Ok(pairs) = adapter.fetch_secrets(&lineage_key(entry)).await else {
                continue;
            };
            for (key, value) in &pairs {
                let Some(key) = PairKey::decode(key).filter(is_compared) else {
                    continue;
                };
                if is_import_of(store, &key, value, identities).await? {
                    entries.insert(snapshot_entry(&key, &id16(&[value])));
                }
            }
        }
        let entries: Vec<[u8; ENTRY_BYTES]> = entries.into_iter().collect();
        let chunks: Vec<Vec<u8>> = entries
            .chunks(ENTRIES_PER_CHUNK)
            .map(<[_]>::concat)
            .collect();
        for (index, chunk) in chunks.iter().enumerate() {
            let item = snapshot_item(generation, index as u32);
            merged_put(store, item, |_| Some(chunk.clone())).await?;
        }
        let count = chunks.len() as u32;
        update_ledger(store, |l| {
            l.snapshot_rows.entry(generation).or_insert(count);
        })
        .await?;
    }
    Ok(())
}

async fn read_snapshot<S: MailStore>(
    store: &mut S,
    rows: &[Row],
    ledger: &Ledger,
) -> Result<HashSet<[u8; ENTRY_BYTES]>, Blocker> {
    let mut entries = HashSet::new();
    for (generation, _) in rows {
        let chunks = ledger.snapshot_rows.get(generation);
        for index in 0..*chunks.ok_or(Blocker::NoSnapshot)? {
            let chunk = get_item(store, snapshot_item(*generation, index)).await?;
            let chunk = chunk.ok_or(Blocker::NoSnapshot)?;
            entries.extend(chunk.body.as_chunks::<ENTRY_BYTES>().0.iter().copied());
        }
    }
    Ok(entries)
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

/// How many of `addrs` are not protected: held by the mail delegate with no
/// backup since the migration began, or not held with no record that the user
/// deleted them. Not being listed is not that record.
async fn unprotected<S: MailStore>(
    store: &mut S,
    addrs: HashSet<Addr>,
    ledger: &Ledger,
    identities: &HashMap<Addr, IdentityInfo>,
) -> Result<u32, CallError> {
    let mut count = 0;
    for addr in addrs {
        let protected = if identities.contains_key(&addr) {
            backed_up_since(store, addr, ledger.migration_started_ms).await?
        } else {
            ledger.deleted_identities.contains(&addr)
        };
        if !protected {
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
    identities: &HashMap<Addr, IdentityInfo>,
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

/// A row's generation and what a fresh read of it maps to.
pub(super) type Row = (u32, Vec<(PairKey, Vec<u8>)>);

/// Read and map the rows to clear, as the walk maps them. A row whose clearing
/// began can have nothing left to map.
async fn read_rows<T: LegacyTransport>(
    adapter: &mut LegacyAdapter<T>,
    targets: &[&DelegateLineageEntry],
    ledger: &Ledger,
) -> Result<Vec<Row>, Blocker> {
    let mut rows = Vec::new();
    for entry in targets {
        let generation = entry.generation;
        let refused = PairKey::Refused([0; ID_BYTES]);
        let keys = match adapter.fetch_secrets(&lineage_key(entry)).await {
            Ok(pairs) => pairs
                .into_iter()
                .map(|(key, value)| (PairKey::decode(&key).unwrap_or(refused.clone()), value))
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

/// Whether the mail delegate lists the identity with a different ML-KEM
/// encapsulation key than the row's seed gives. The address comes from the
/// signing key alone, so it does not say the KEM seeds agree, and an import
/// under a held address drops the row's. An identity the delegate does not
/// list has no key to compare. The key covers the seed's first 32 bytes; the
/// rest is used only for implicit rejection of invalid ciphertexts.
fn kem_differs(key: &PairKey, value: &[u8], identities: &HashMap<Addr, IdentityInfo>) -> bool {
    use ml_kem::kem::{KeyExport, KeyInit};
    let PairKey::Identity(addr) = key else {
        return false;
    };
    let Some(held) = identities.get(addr) else {
        return false;
    };
    let derived = serde_json::from_slice::<MigratedIdentity>(value)
        .ok()
        .and_then(|i| ml_kem::Seed::try_from(i.kem.as_slice()).ok())
        .map(|seed| {
            let dk = ml_kem::DecapsulationKey::<ml_kem::MlKem768>::new(&seed);
            dk.encapsulation_key().to_bytes().to_vec()
        });
    derived.is_none_or(|ek| ek.as_slice() != held.ek.as_slice())
}

/// What the rows show against the mail delegate: entries that cannot be
/// mapped, identities with no backup, and items that did not land as they are.
pub(super) async fn row_blockers<S: MailStore>(
    store: &mut S,
    rows: &[Row],
    ledger: &Ledger,
    identities: &HashMap<Addr, IdentityInfo>,
) -> Result<Vec<Blocker>, Blocker> {
    let mut found = Vec::new();
    let all = || rows.iter().flat_map(|(_, pairs)| pairs);
    let refused = all()
        .filter(|(k, _)| matches!(k, PairKey::Refused(_)))
        .count();
    if refused > 0 {
        found.push(Blocker::Unmappable(refused as u32));
    }
    let scrubbed = all().filter_map(|(key, _)| owner(key));
    let count = unprotected(store, scrubbed.collect(), ledger, identities).await?;
    if count > 0 {
        found.push(Blocker::NoBackup(count));
    }
    let mismatched = all().filter(|(k, v)| kem_differs(k, v, identities)).count();
    if mismatched > 0 {
        found.push(Blocker::KeyMismatch(mismatched as u32));
    }
    let snapshot = read_snapshot(store, rows, ledger).await?;
    for (generation, pairs) in rows {
        let mut ids = 0;
        for (key, value) in pairs.iter().filter(|(k, _)| is_compared(k)) {
            // Read first: a record that fails to read must stop this, even
            // for an item the snapshot lists.
            let imported = is_import_of(store, key, value, identities).await?;
            let moved = matches!(key, PairKey::Orphan(id) if ledger.moved.contains(&hex(id)));
            if !imported && !moved && !snapshot.contains(&snapshot_entry(key, &id16(&[value]))) {
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
        let positions: Result<BTreeSet<u64>, _> = positions.map(|k| k.parse()).collect();
        let positions = positions.map_err(|e: std::num::ParseIntError| e.to_string())?;
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
/// `Some` is that nothing is left to delete, `true` if this call deleted any.
async fn clear_row<T: LegacyTransport>(
    adapter: &mut LegacyAdapter<T>,
    entry: &DelegateLineageEntry,
) -> Option<bool> {
    let passed = adapter.answer(entry)?.to_vec();
    let requests = row_deletes(entry, &passed).ok()?;
    if requests.is_empty() {
        return Some(false);
    }
    if adapter.reread(entry).await != Some(passed.as_slice()) {
        return None;
    }
    for request in requests {
        match adapter.send(entry, request).await {
            LegacyReply::NoAnswer(why) if why == EMPTY_REPLY => {}
            _ => return None,
        }
    }
    let left = adapter.reread(entry).await.map(|b| row_deletes(entry, b));
    matches!(left, Some(Ok(requests)) if requests.is_empty()).then_some(true)
}

/// Keep an identity row's alias table before the row is touched: a local-state
/// row that returns later needs it, and a recovery key has no alias.
async fn keep_alias_table<S: MailStore, T: LegacyTransport>(
    store: &mut S,
    adapter: &LegacyAdapter<T>,
    entry: &DelegateLineageEntry,
) -> Result<(), Blocker> {
    let generation = entry.generation;
    let answer = adapter
        .answer(entry)
        .ok_or(Blocker::Unread { generation })?;
    let mapped = map_identities(answer, &mut MappingCounts::default());
    let (_, table) = mapped.map_err(|_| Blocker::Unread { generation })?;
    let body = serde_json::to_vec(&table).expect("an alias table always encodes");
    merged_put(store, alias_table_item(generation), |_| Some(body.clone())).await?;
    Ok(())
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

/// Clear `order`, journaling each row. Stops at the first that fails, and the
/// identity rows wait until every local-state row is finished.
async fn clear_rows<S: MailStore, T: LegacyTransport>(
    store: &mut S,
    adapter: &mut LegacyAdapter<T>,
    order: &[&DelegateLineageEntry],
    ledger: &Ledger,
) -> Result<(), Blocker> {
    let mut mail_left = false;
    for entry in order {
        let generation = entry.generation;
        if is_identity_row(entry) {
            if mail_left {
                return Ok(());
            }
            if !ledger.scrubbed.contains_key(&generation) {
                keep_alias_table(store, adapter, entry).await?;
            }
        }
        update_ledger(store, |l| {
            l.scrubbed.entry(generation).or_default();
        })
        .await?;
        let Some(deleted) = clear_row(adapter, entry).await else {
            update_ledger(store, |l| {
                l.scrub_empty.remove(&generation);
            })
            .await?;
            return Err(Blocker::RowFailed { generation });
        };
        let before = ledger.scrub_empty.get(&generation).copied().unwrap_or(0);
        let answers = if deleted { 1 } else { before + 1 };
        update_ledger(store, |l| {
            if answers >= EMPTY_LOADS {
                l.scrub_empty.remove(&generation);
                l.scrubbed.insert(generation, true);
            } else {
                l.scrub_empty.insert(generation, answers);
            }
        })
        .await?;
        mail_left |= !is_identity_row(entry) && answers < EMPTY_LOADS;
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
    let resolved = || {
        lineage
            .iter()
            .filter(|e| !pending.contains_key(e.delegate_key.as_slice()))
    };
    let targets: Vec<&DelegateLineageEntry> = resolved()
        .filter(|e| ledger.scrubbed.get(&e.generation) != Some(&true))
        .collect();
    let unrecorded: Vec<&DelegateLineageEntry> = resolved()
        .filter(|e| !ledger.snapshot_rows.contains_key(&e.generation))
        .collect();
    if targets.is_empty() && unrecorded.is_empty() {
        return Ok(Vec::new());
    }

    let kept_tables = kept_alias_tables(store, &ledger).await;
    let mut adapter = LegacyAdapter::new(
        transport,
        lineage.clone(),
        pending.clone(),
        ArrivedIdentities::default(),
        ledger.absent_answers.clone(),
        Box::new(|| {}),
    )
    .with_kept_tables(kept_tables);
    let identities = readable_identities(store).await?;
    write_snapshots(store, &mut adapter, &unrecorded, outcome, &identities).await?;
    if targets.is_empty() {
        return Ok(Vec::new());
    }
    let ledger = read_ledger(store).await?;

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

    let cheap = cheap_blockers(store, outcome, &ledger, &identities).await?;
    if !cheap.is_empty() {
        return Ok(cheap);
    }
    let rows = read_rows(&mut adapter, &targets, &ledger).await?;
    let blockers = row_blockers(store, &rows, &ledger, &identities).await?;
    if !blockers.is_empty() {
        return Ok(blockers);
    }
    on_clearing();
    clear_rows(store, &mut adapter, &order, &ledger).await?;
    Ok(Vec::new())
}

/// Clear what can be cleared on this load, in a build that has scrub.
pub(crate) async fn run<S: MailStore, T: LegacyTransport>(
    store: &mut S,
    transport: T,
    outcome: &WalkOutcome,
    on_clearing: impl FnOnce(),
) -> Vec<Blocker> {
    if !BUILT_IN {
        return vec![Blocker::NotBuilt];
    }
    crate::log::info(BUILD_MARKER);
    run_built(store, transport, outcome, on_clearing).await
}

/// The body of [`run`]. `outcome` is this load's walk, and `on_clearing` hears
/// when deletes are about to start. Returns what stopped it, also stored in
/// the ledger.
pub(super) async fn run_built<S: MailStore, T: LegacyTransport>(
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
