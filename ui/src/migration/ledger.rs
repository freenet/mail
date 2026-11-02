//! The migration's own record: what the upgrade notice counts, whether it was
//! dismissed, and scrub's journal ([`super::scrub`]). `MigrationMarker` items
//! under ids no predecessor key can equal. That kind is per origin and never
//! exported.

use std::collections::{BTreeMap, HashMap};

use freenet_mail_protocol::{Addr, Item, ItemKind, ItemRef, Op, Reply};
use freenet_stdlib::prelude::blake3;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use super::scrub::Blocker;
use super::successor::{MailStore, MigrationCounts, get_item, merged_put};
use crate::mail_delegate::CallError;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct Ledger {
    pub totals: MigrationCounts,
    pub notice_dismissed: bool,
    /// Each row's absent-or-empty answers in a row, by lineage generation.
    /// Any other answer ends the run. The journal cannot give this: its
    /// streak counts typed "not installed" only.
    pub absent_answers: BTreeMap<u32, u32>,
    /// The last walk found a row silent or unreadable. Loads that do not walk
    /// show this.
    pub silent: bool,
    /// The rejected count the notice last showed.
    pub rejected: u32,
    /// The identities the walk brought in: the notice offers each one's
    /// recovery key.
    pub migrated: Vec<Addr>,
    /// Page time before the first walk imported anything. `last_backup_at`
    /// is imported with the settings, so only a later value is a backup made
    /// since the move.
    pub migration_started_ms: Option<i64>,
    /// How many chunks each row's part of the imported-ids snapshot has, by
    /// lineage generation, once it is written.
    pub snapshot_rows: BTreeMap<u32, u32>,
    /// Orphans moved to an identity or discarded, by item id in hex. The row's
    /// snapshot can be written after that, and could not then list them.
    pub moved: Vec<String>,
    /// Identities the user deleted here. Not being listed does not show that:
    /// a read that failed leaves an identity out too.
    pub deleted_identities: Vec<Addr>,
    /// Scrub's journal, by lineage generation: present once a row's clearing
    /// has begun, `true` once it is finished.
    pub scrubbed: BTreeMap<u32, bool>,
    /// Loads in a row on which a row being cleared had nothing left to delete.
    pub scrub_empty: BTreeMap<u32, u32>,
    /// What stopped scrub on the last load, for the status report.
    pub scrub_blockers: Vec<Blocker>,
}

fn reserved_item(name: &[u8], index: u32) -> ItemRef {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"freenet-mail migration record\0");
    hasher.update(name);
    hasher.update(&index.to_le_bytes());
    ItemRef {
        kind: ItemKind::MigrationMarker,
        owner: None,
        id: hasher.finalize().as_bytes().to_vec(),
    }
}

pub(crate) fn ledger_item() -> ItemRef {
    reserved_item(b"ledger", 0)
}

/// One chunk of a row's part of the imported-ids snapshot.
pub(crate) fn snapshot_item(generation: u32, index: u32) -> ItemRef {
    let name = [b"imported ids".as_slice(), &generation.to_le_bytes()].concat();
    reserved_item(&name, index)
}

/// An identity row's alias table, kept when that row is cleared. It holds
/// aliases and addresses, no key material.
pub(crate) fn alias_table_item(generation: u32) -> ItemRef {
    reserved_item(b"alias table", generation)
}

/// The kept alias tables of the rows whose clearing began, by lineage
/// generation. One that cannot be read leaves its row's aliases unresolved,
/// which keeps the mail waiting.
pub(crate) async fn kept_alias_tables<S: MailStore>(
    store: &mut S,
    ledger: &Ledger,
) -> BTreeMap<u32, HashMap<String, Addr>> {
    let mut tables = BTreeMap::new();
    for generation in ledger.scrubbed.keys().copied() {
        if let Ok(Some(item)) = get_item(store, alias_table_item(generation)).await
            && let Ok(table) = serde_json::from_slice(&item.body)
        {
            tables.insert(generation, table);
        }
    }
    tables
}

/// Record that the user deleted `addr`.
pub(crate) async fn record_identity_deleted<S: MailStore>(
    store: &mut S,
    addr: Addr,
) -> Result<(), CallError> {
    update_ledger(store, |l| {
        if !l.deleted_identities.contains(&addr) {
            l.deleted_identities.push(addr);
        }
    })
    .await
}

/// The stored ledger. One that cannot be decoded is an error, never an empty
/// ledger: the counts in it are the only record of what moved.
pub(crate) async fn read_ledger<S: MailStore>(store: &mut S) -> Result<Ledger, CallError> {
    match get_item(store, ledger_item()).await? {
        Some(item) => serde_json::from_slice(&item.body)
            .map_err(|e| CallError::Unknown(format!("the migration record cannot be read: {e}"))),
        None => Ok(Ledger::default()),
    }
}

/// Change the ledger, merged with what is stored so another tab's change
/// survives. A body that does not decode is an error, and is left alone.
pub(crate) async fn update_ledger<S: MailStore>(
    store: &mut S,
    change: impl Fn(&mut Ledger),
) -> Result<(), CallError> {
    let undecodable = std::cell::Cell::new(false);
    let written = merged_put(store, ledger_item(), |stored| {
        let mut ledger: Ledger = match stored {
            Some(body) => match serde_json::from_slice(body) {
                Ok(ledger) => ledger,
                Err(_) => {
                    undecodable.set(true);
                    return None;
                }
            },
            None => Ledger::default(),
        };
        let before = ledger.clone();
        change(&mut ledger);
        (ledger != before).then(|| serde_json::to_vec(&ledger).expect("a ledger always encodes"))
    })
    .await;
    if undecodable.get() {
        return Err(CallError::Unknown(
            "the migration record cannot be read, so it was left as it is".into(),
        ));
    }
    written.map(|_| ())
}

pub(crate) async fn list_items<S: MailStore>(
    store: &mut S,
    kind: ItemKind,
    owner: Option<Addr>,
) -> Result<Vec<Item>, CallError> {
    let mut out: Vec<Item> = Vec::new();
    let mut after = None;
    loop {
        let op = Op::ListItems {
            kind,
            owner,
            after: after.take(),
            limit: 256,
        };
        let (items, more) = match store.call(op).await? {
            Reply::Items { items, more } => (items, more),
            other => return Err(crate::mail_delegate::unexpected(&other)),
        };
        let last = items.last().map(|i| ByteBuf::from(i.item.id.clone()));
        out.extend(items);
        match (more, last) {
            (true, Some(last)) => after = Some(last),
            _ => return Ok(out),
        }
    }
}
