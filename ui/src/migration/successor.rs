//! Writing migrated items into the mail delegate, through the same operations
//! the app uses: its compare-and-swap, budget and per-kind caps all apply.
//!
//! An item already stored stays as it is. Settings and flags are the two
//! merged kinds, and a value already stored wins or is kept by the merge.
//!
//! The migration's bookkeeping lives in delegate items too. Each write here
//! returns only once the delegate acknowledged it, so markers and the journal
//! are durable when the crate is told they are, and there is nothing to flush.

use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;

use freenet_mail_protocol::{
    Addr, DsaSeed, FailureCode, IdentityInfo, ImportKind, ImportSource, Item, ItemKind, ItemRef,
    KemSeed, Op, Reply,
};
use freenet_migrate::{
    ItemWrite, JournaledSuccessorIo, MarkerQuery, MigrationMarker, RecoveredSecret,
    SuccessorSecretsIo,
};
use freenet_stdlib::prelude::DelegateKey;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use super::ledger::{self, Ledger};
use super::legacy_delegates::{
    LegacyFlags, MappingCounts, MigratedIdentity, PairKey, distinct_alias,
};
use crate::app::identity_store::{MigrationMarkers, body_with_markers, markers_from_body};
use crate::mail_delegate::CallError;

/// How many times a lost compare-and-swap is retried before the item waits
/// for the next load.
const CAS_ATTEMPTS: u32 = 4;

/// The mail delegate, as this module reaches it.
pub(crate) trait MailStore {
    async fn call(&mut self, op: Op) -> Result<Reply, CallError>;
}

/// The positions of an identity's v1 inbox: each message's ciphertext, in
/// list order, or `None` if the state could not be fetched.
pub(crate) trait V1InboxReader {
    async fn ciphertexts(&mut self, vk: &[u8]) -> Option<Vec<Vec<u8>>>;

    /// Whether the node returned an inbox for `vk` under `code_hash`. No
    /// answer is `false`, which only leaves an identity to be confirmed by
    /// its owner.
    async fn has_inbox(&mut self, vk: &[u8], code_hash: &str) -> bool;
}

/// What this walk imported, and what it could not, for the upgrade notice.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct MigrationCounts {
    pub identities: u32,
    pub contacts: u32,
    pub drafts: u32,
    pub sent: u32,
    pub kept: u32,
    pub archived: u32,
    pub orphaned: u32,
    /// Entries refused for good: undecodable or too large.
    pub refused: u32,
    /// Items a per-kind or storage cap refused. They stay in the predecessor.
    pub at_cap: u32,
    /// Items of an identity deleted on the new delegate. They stay in the
    /// predecessor.
    pub identity_gone: u32,
    /// Read marks that could not be translated.
    pub flags_skipped: u32,
    /// `deleted` marks left out, by design ([`MappingCounts::deleted_marks`]).
    pub deleted_marks: u32,
}

impl MigrationCounts {
    pub(crate) fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    pub(crate) fn merge_mapping(&mut self, mapping: MappingCounts) {
        self.flags_skipped += mapping.orphan_flags;
        self.deleted_marks += mapping.deleted_marks;
    }

    /// What is new since `earlier`: items written in between, and the highest
    /// of everything else, which is found again rather than added.
    pub(crate) fn since(&self, earlier: &Self) -> Self {
        MigrationCounts {
            identities: self.identities - earlier.identities,
            contacts: self.contacts - earlier.contacts,
            drafts: self.drafts - earlier.drafts,
            sent: self.sent - earlier.sent,
            kept: self.kept - earlier.kept,
            archived: self.archived - earlier.archived,
            orphaned: self.orphaned - earlier.orphaned,
            ..*self
        }
    }

    /// Add a later run. Items counted as written add up: a retry reads before
    /// it writes, so it does not count what an earlier attempt brought. The
    /// same bytes in two generations do count once each, so these can run
    /// high by that much. The rest are found again on every retry, so the
    /// highest count stands.
    pub(crate) fn absorb(&mut self, run: &Self) {
        self.identities += run.identities;
        self.contacts += run.contacts;
        self.drafts += run.drafts;
        self.sent += run.sent;
        self.kept += run.kept;
        self.archived += run.archived;
        self.orphaned += run.orphaned;
        self.refused = self.refused.max(run.refused);
        self.at_cap = self.at_cap.max(run.at_cap);
        self.identity_gone = self.identity_gone.max(run.identity_gone);
        self.flags_skipped = self.flags_skipped.max(run.flags_skipped);
        self.deleted_marks = self.deleted_marks.max(run.deleted_marks);
    }
}

/// Identities known to have reached the mail delegate: imported this run, or
/// held by an identity row the journal has resolved. It tells an item whose
/// owner was deleted from one whose owner has not arrived yet. The delegate
/// answers `NotFound` for both, and only the first may end the walk.
#[derive(Clone, Default)]
pub(crate) struct ArrivedIdentities(Rc<RefCell<Arrived>>);

#[derive(Default)]
struct Arrived {
    known: HashSet<Addr>,
    /// Brought in by this walk.
    imported: Vec<Addr>,
    /// The row being imported has a newer one that may still hold its
    /// identities, so what it says about contracts waits.
    hold_markers: bool,
}

impl ArrivedIdentities {
    pub(crate) fn note(&self, addr: Addr) {
        self.0.borrow_mut().known.insert(addr);
    }

    fn holds(&self, addr: &Addr) -> bool {
        self.0.borrow().known.contains(addr)
    }

    fn note_imported(&self, addr: Addr) {
        self.0.borrow_mut().imported.push(addr);
    }

    pub(crate) fn any_imported(&self) -> bool {
        !self.0.borrow().imported.is_empty()
    }

    pub(crate) fn hold_markers(&self, held: bool) {
        self.0.borrow_mut().hold_markers = held;
    }
}

/// Merge `incoming` under `stored`, field by field: a value already there
/// wins, `incoming` fills what is missing, and objects merge recursively.
/// `null` counts as missing, as an absent `Option` does.
pub(crate) fn merge_fields(
    stored: &serde_json::Value,
    incoming: &serde_json::Value,
) -> serde_json::Value {
    use serde_json::Value;
    match (stored, incoming) {
        (Value::Object(s), Value::Object(i)) => {
            let mut out = s.clone();
            for (field, value) in i {
                let merged = match s.get(field) {
                    Some(present) => merge_fields(present, value),
                    None => value.clone(),
                };
                out.insert(field.clone(), merged);
            }
            Value::Object(out)
        }
        (Value::Null, other) => other.clone(),
        (present, _) => present.clone(),
    }
}

/// Read and deleted marks for one message, as stored
/// (`local_state::items`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MergedFlags {
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub deleted: bool,
}

impl MergedFlags {
    pub(crate) fn merged(self, other: Self) -> Self {
        MergedFlags {
            read: self.read || other.read,
            deleted: self.deleted || other.deleted,
        }
    }
}

/// Carry a legacy identity's contract-migration state into stored markers. A
/// legacy record of an older code hash means the inbox or token record may
/// still be under that hash, so it becomes a pending migration; the recorded
/// hash alone would be read as a baseline.
///
/// `generation` is the release the record comes from. Only the newest one
/// holding the identity counts: an older record says where the inbox was
/// before the newer release moved it, and acting on it would merge that old
/// inbox back over newer state. Markers with no imported generation were
/// stamped by this version before the walk, and the record still applies.
pub(crate) fn adopt_legacy_markers(
    stored: &MigrationMarkers,
    legacy: &MigrationMarkers,
    generation: u32,
    current_inbox: &str,
    current_aft: &str,
) -> MigrationMarkers {
    let imported = stored.imported_generation;
    if imported.is_some_and(|from| from >= generation) {
        return stored.clone();
    }
    // An older row got in first (a newer one was silent past its hold), so
    // what it left is replaced.
    let replaces = imported.is_some();
    let recorded = |stored: &Option<String>, legacy: &Option<String>| {
        if replaces {
            legacy.clone().or_else(|| stored.clone())
        } else {
            stored.clone().or_else(|| legacy.clone())
        }
    };
    let held = |pending: &Option<String>| pending.clone().filter(|_| !replaces);
    fn pending(
        stored: &Option<String>,
        legacy_pending: &Option<String>,
        legacy_recorded: &Option<String>,
        current: &str,
    ) -> Option<String> {
        stored.clone().or_else(|| {
            legacy_pending
                .clone()
                .or_else(|| legacy_recorded.clone())
                .filter(|hash| hash != current)
        })
    }
    MigrationMarkers {
        inbox_wasm_hash: recorded(&stored.inbox_wasm_hash, &legacy.inbox_wasm_hash),
        pending_migration_from: pending(
            &held(&stored.pending_migration_from),
            &legacy.pending_migration_from,
            &legacy.inbox_wasm_hash,
            current_inbox,
        ),
        aft_record_wasm_hash: recorded(&stored.aft_record_wasm_hash, &legacy.aft_record_wasm_hash),
        pending_aft_migration_from: pending(
            &held(&stored.pending_aft_migration_from),
            &legacy.pending_aft_migration_from,
            &legacy.aft_record_wasm_hash,
            current_aft,
        ),
        imported_generation: Some(generation),
        pending_held: false,
    }
}

/// A predecessor's marker as stored. `Done` and `InProgress` are separate
/// fields, as the crate's marker contract requires.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StoredMarker {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub done: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started: Option<bool>,
}

impl StoredMarker {
    /// How the record reads back: `Done` wins, except that an import started
    /// beside an empty seal means the seal is wrong.
    pub(crate) fn read(self) -> Option<MigrationMarker> {
        match (self.done, self.started) {
            (Some(false), Some(true)) => Some(MigrationMarker::InProgress { saw_data: true }),
            (Some(had_data), _) => Some(MigrationMarker::Done { had_data }),
            (None, Some(saw_data)) => Some(MigrationMarker::InProgress { saw_data }),
            (None, None) => None,
        }
    }

    /// The record with `marker` added. Never erases `Done` and never lowers
    /// a data flag.
    pub(crate) fn with(self, marker: MigrationMarker) -> Self {
        match marker {
            MigrationMarker::InProgress { saw_data } => StoredMarker {
                started: Some(saw_data || self.started == Some(true)),
                ..self
            },
            MigrationMarker::Done { had_data } => StoredMarker {
                done: Some(had_data || self.done == Some(true)),
                ..self
            },
        }
    }
}

fn unowned(kind: ItemKind, id: Vec<u8>) -> ItemRef {
    ItemRef {
        kind,
        owner: None,
        id,
    }
}

pub(crate) fn settings_item(owner: Addr) -> ItemRef {
    ItemRef {
        kind: ItemKind::IdentitySettings,
        owner: Some(owner),
        id: Vec::new(),
    }
}

fn journal_item() -> ItemRef {
    unowned(ItemKind::MigrationJournal, Vec::new())
}

fn marker_item(predecessor: &DelegateKey) -> ItemRef {
    unowned(ItemKind::MigrationMarker, predecessor.bytes().to_vec())
}

fn is_conflict(e: &CallError) -> bool {
    matches!(e.code(), Some(FailureCode::Conflict { .. }))
}

/// A listed record that keeps failing to read. Only a create replaces it.
fn is_unreadable(e: &CallError) -> bool {
    e.code() == Some(FailureCode::Unreadable)
}

pub(crate) async fn get_item<S: MailStore>(
    store: &mut S,
    item: ItemRef,
) -> Result<Option<Item>, CallError> {
    match store.call(Op::GetItem { item }).await? {
        Reply::Item(item) => Ok(item),
        other => Err(crate::mail_delegate::unexpected(&other)),
    }
}

pub(crate) async fn put_item<S: MailStore>(
    store: &mut S,
    item: ItemRef,
    body: Vec<u8>,
    expected_gen: Option<u64>,
) -> Result<u64, CallError> {
    let op = Op::PutItem {
        item,
        body: ByteBuf::from(body),
        expected_gen,
    };
    match store.call(op).await? {
        Reply::Ack { generation } => Ok(generation),
        other => Err(crate::mail_delegate::unexpected(&other)),
    }
}

/// Read-merge-write `item`, retrying a lost compare-and-swap. `merge` gets
/// the stored body and returns the new one, `None` to leave it. Returns
/// whether anything was written.
pub(crate) async fn merged_put<S: MailStore>(
    store: &mut S,
    item: ItemRef,
    merge: impl Fn(Option<&[u8]>) -> Option<Vec<u8>>,
) -> Result<bool, CallError> {
    let mut attempt = 0;
    loop {
        let current = get_item(store, item.clone()).await?;
        let generation = current.as_ref().map_or(0, |i| i.generation);
        let Some(body) = merge(current.as_ref().map(|i| i.body.as_slice())) else {
            return Ok(false);
        };
        match put_item(store, item.clone(), body, Some(generation)).await {
            Ok(_) => return Ok(true),
            Err(e) if is_conflict(&e) && attempt + 1 < CAS_ATTEMPTS => attempt += 1,
            Err(e) => return Err(e),
        }
    }
}

pub(crate) struct MailSuccessor<S, I> {
    store: S,
    inbox: I,
    /// The journal's generation at the last load, `None` if it was unreadable.
    journal_generation: Option<u64>,
    counts: MigrationCounts,
    /// What the ledger holds of `counts`.
    recorded: MigrationCounts,
    arrived: ArrivedIdentities,
}

impl<S: MailStore, I: V1InboxReader> MailSuccessor<S, I> {
    pub(crate) fn new(store: S, inbox: I, arrived: ArrivedIdentities) -> Self {
        MailSuccessor {
            store,
            inbox,
            journal_generation: Some(0),
            counts: MigrationCounts::default(),
            recorded: MigrationCounts::default(),
            arrived,
        }
    }

    /// What a failed item write means for the walk. A refusal that retrying
    /// cannot change is permanent, so the walk ends and the item stays in the
    /// predecessor: a cap (or every later load would re-offer everything,
    /// undoing the user's deletions to make room) and an identity being or
    /// already deleted. `owner` is the identity the item belongs to.
    async fn failed(&mut self, owner: Option<Addr>, error: CallError) -> ItemWrite<String> {
        let text = error.to_string();
        match error.code() {
            Some(FailureCode::BadInput) => ItemWrite::permanent(text),
            Some(FailureCode::CapReached) => {
                self.counts.at_cap += 1;
                ItemWrite::permanent(text)
            }
            Some(FailureCode::Refused) if owner.is_some() => self.identity_gone(text),
            Some(FailureCode::NotFound) if owner.is_some() => {
                if self.is_deleted(owner).await {
                    self.identity_gone(text)
                } else {
                    ItemWrite::retryable(text)
                }
            }
            _ => ItemWrite::retryable(text),
        }
    }

    /// Whether `owner` reached the delegate and is gone. `NotFound` does not
    /// prove it: the delegate gives the same answer for a record that failed
    /// to read, so its index is asked. Listed but unreadable, or a question
    /// that gets no answer, means try again.
    async fn is_deleted(&mut self, owner: Option<Addr>) -> bool {
        let Some(owner) = owner.filter(|o| self.arrived.holds(o)) else {
            return false;
        };
        let readable = matches!(
            self.store.call(Op::GetStatus).await,
            Ok(Reply::Status(status)) if status.unreadable_identities == 0
        );
        readable
            && matches!(
                self.store.call(Op::ListIdentities).await,
                Ok(Reply::Identities(list)) if list.iter().all(|i| i.addr != owner)
            )
    }

    fn identity_gone(&mut self, text: String) -> ItemWrite<String> {
        self.counts.identity_gone += 1;
        ItemWrite::permanent(text)
    }

    pub(crate) fn into_counts(self) -> MigrationCounts {
        self.counts
    }

    pub(crate) fn store(&mut self) -> &mut S {
        &mut self.store
    }

    /// Bring the ledger up to date, with `mapping` counted and `also` applied.
    /// A change to the totals brings a dismissed notice back. A ledger that
    /// cannot be written costs the notice, never the walk: what was not
    /// recorded goes with the next write.
    pub(crate) async fn update_ledger(
        &mut self,
        mapping: MappingCounts,
        also: impl Fn(&mut Ledger),
    ) {
        let mut now = self.counts;
        now.merge_mapping(mapping);
        let new = now.since(&self.recorded);
        let arrived = self.arrived.clone();
        let updated = ledger::update_ledger(&mut self.store, |l| {
            let before = l.totals;
            l.totals.absorb(&new);
            l.notice_dismissed &= l.totals == before;
            let arrived = arrived.0.borrow();
            for addr in &arrived.imported {
                if !l.migrated.contains(addr) {
                    l.migrated.push(*addr);
                }
            }
            drop(arrived);
            also(l);
        })
        .await;
        match updated {
            Ok(()) => self.recorded = now,
            Err(e) => crate::log::error(
                format!("recording the migration's counts failed: {e}"),
                None,
            ),
        }
    }

    async fn get(&mut self, item: ItemRef) -> Result<Option<Item>, CallError> {
        get_item(&mut self.store, item).await
    }

    async fn put(
        &mut self,
        item: ItemRef,
        body: Vec<u8>,
        expected_gen: Option<u64>,
    ) -> Result<u64, CallError> {
        put_item(&mut self.store, item, body, expected_gen).await
    }

    async fn merged_put(
        &mut self,
        item: ItemRef,
        merge: impl Fn(Option<&[u8]>) -> Option<Vec<u8>>,
    ) -> Result<bool, CallError> {
        merged_put(&mut self.store, item, merge).await
    }

    /// Import an item that may not exist yet: a stored one stands. A
    /// `Conflict` alone does not prove that: it can be about the index, on a
    /// create of an item that is not there, so the item is looked at. A create
    /// over the same bytes also succeeds, so a `retry` reads first: an item
    /// from an earlier attempt is not written, and not counted, twice.
    async fn create(&mut self, item: ItemRef, body: Vec<u8>, retry: bool) -> ItemWrite<String> {
        let owner = item.owner;
        if retry {
            match self.get(item.clone()).await {
                Ok(Some(_)) => return ItemWrite::already_authoritative(),
                Err(e) if !is_unreadable(&e) => return self.failed(owner, e).await,
                _ => {}
            }
        }
        let conflict = match self.put(item.clone(), body, None).await {
            Ok(_) => return ItemWrite::written(),
            Err(e) if is_conflict(&e) => e,
            Err(e) => return self.failed(owner, e).await,
        };
        match self.get(item).await {
            Ok(Some(_)) => ItemWrite::already_authoritative(),
            Ok(None) => ItemWrite::retryable(format!("not stored after {conflict}")),
            Err(e) => self.failed(owner, e).await,
        }
    }

    async fn import_identity(
        &mut self,
        addr: Addr,
        value: &[u8],
        generation: u32,
    ) -> ItemWrite<String> {
        let Ok(identity) = serde_json::from_slice::<MigratedIdentity>(value) else {
            return ItemWrite::permanent("not an identity".to_string());
        };
        let (Ok(dsa), Ok(kem)) = (
            <[u8; 32]>::try_from(identity.dsa.as_slice()),
            <[u8; 64]>::try_from(identity.kem.as_slice()),
        ) else {
            return ItemWrite::permanent("seeds of the wrong size".to_string());
        };
        let mut alias = identity.alias.clone();
        let mut attempt = 0;
        let (info, already_present) = loop {
            let op = Op::ImportIdentity {
                source: ImportSource::Seeds {
                    dsa: DsaSeed(dsa),
                    kem: KemSeed(kem),
                },
                kind: ImportKind::Migration,
                alias: alias.clone(),
                description: identity.description.clone(),
            };
            match self.store.call(op).await {
                Ok(Reply::Imported {
                    identity,
                    already_present,
                }) => break (identity, already_present),
                Ok(other) => {
                    return self
                        .failed(None, crate::mail_delegate::unexpected(&other))
                        .await;
                }
                // Another identity holds the name: a different address, so
                // this one takes a name of its own.
                Err(e) if is_conflict(&e) && attempt == 0 => {
                    attempt += 1;
                    alias = distinct_alias(&identity.alias, &addr);
                }
                Err(e) => return self.failed(Some(addr), e).await,
            }
        };
        if info.addr != addr {
            return ItemWrite::permanent("seeds do not derive their address".to_string());
        }
        self.arrived.note(addr);
        if let Err(e) = self
            .adopt_markers(&info, &identity.markers, generation)
            .await
        {
            return self.failed(Some(addr), e).await;
        }
        if already_present {
            return ItemWrite::already_authoritative();
        }
        self.arrived.note_imported(addr);
        self.counts.identities += 1;
        ItemWrite::written()
    }

    async fn adopt_markers(
        &mut self,
        info: &IdentityInfo,
        legacy: &MigrationMarkers,
        generation: u32,
    ) -> Result<(), CallError> {
        let item = settings_item(info.addr);
        let hold = self.arrived.0.borrow().hold_markers;
        self.merged_put(item, |stored| {
            let markers = markers_from_body(stored);
            let mut adopted = adopt_legacy_markers(
                &markers,
                legacy,
                generation,
                crate::inbox::INBOX_CODE_HASH.trim(),
                crate::aft::TOKEN_RECORD_CODE_HASH.trim(),
            );
            if adopted.imported_generation == Some(generation) {
                adopted.pending_held = hold && adopted.has_pending();
            }
            (adopted != markers).then(|| body_with_markers(stored, &adopted))
        })
        .await?;
        Ok(())
    }

    async fn merge_settings(&mut self, item: ItemRef, value: &[u8]) -> ItemWrite<String> {
        let Ok(incoming) = serde_json::from_slice::<serde_json::Value>(value) else {
            return ItemWrite::permanent("not a settings record".to_string());
        };
        let owner = item.owner;
        let written = self
            .merged_put(item, |stored| {
                let present = stored
                    .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
                    .unwrap_or_else(|| serde_json::json!({}));
                let merged = merge_fields(&present, &incoming);
                (merged != present)
                    .then(|| serde_json::to_vec(&merged).expect("a JSON value always encodes"))
            })
            .await;
        match written {
            Ok(true) => ItemWrite::written(),
            Ok(false) => ItemWrite::already_authoritative(),
            Err(e) => self.failed(owner, e).await,
        }
    }

    /// Translate v1 list positions into marks on the messages at those
    /// positions now. An inbox that cannot be fetched skips them, counted.
    async fn import_flags(&mut self, owner: Addr, value: &[u8]) -> ItemWrite<String> {
        let Ok(flags) = serde_json::from_slice::<LegacyFlags>(value) else {
            return ItemWrite::permanent("not a flags record".to_string());
        };
        if flags.read.is_empty() {
            return ItemWrite::already_authoritative();
        }
        let marks = flags.read.len() as u32;
        let identities = match self.store.call(Op::ListIdentities).await {
            Ok(Reply::Identities(list)) => list,
            Ok(other) => {
                return self
                    .failed(Some(owner), crate::mail_delegate::unexpected(&other))
                    .await;
            }
            Err(e) => return self.failed(Some(owner), e).await,
        };
        let Some(vk) = identities
            .iter()
            .find(|i| i.addr == owner)
            .map(|i| i.vk.clone())
        else {
            if self.is_deleted(Some(owner)).await {
                return self.identity_gone("the identity was deleted".to_string());
            }
            return ItemWrite::retryable("the identity is not imported yet".to_string());
        };
        let Some(ciphertexts) = self.inbox.ciphertexts(&vk).await else {
            self.counts.flags_skipped += marks;
            return ItemWrite::already_authoritative();
        };
        let mut read = std::collections::BTreeSet::new();
        for position in &flags.read {
            match usize::try_from(*position)
                .ok()
                .and_then(|p| ciphertexts.get(p))
            {
                Some(ciphertext) => {
                    read.insert(crate::local_state::full_message_id(ciphertext));
                }
                None => self.counts.flags_skipped += 1,
            }
        }
        let mark = MergedFlags {
            read: true,
            deleted: false,
        };
        for id in read {
            let item = ItemRef {
                kind: ItemKind::Flags,
                owner: Some(owner),
                id: id.to_vec(),
            };
            let written = self
                .merged_put(item, |stored| {
                    let present: MergedFlags = stored
                        .and_then(|b| serde_json::from_slice(b).ok())
                        .unwrap_or_default();
                    let merged = present.merged(mark);
                    (merged != present || stored.is_none())
                        .then(|| serde_json::to_vec(&merged).expect("flags always encode"))
                })
                .await;
            if let Err(e) = written {
                return self.failed(Some(owner), e).await;
            }
        }
        ItemWrite::written()
    }

    fn count(&mut self, key: &PairKey) {
        let c = &mut self.counts;
        match key {
            PairKey::Contact(_) => c.contacts += 1,
            PairKey::Message { kind, .. } => match kind {
                ItemKind::Draft => c.drafts += 1,
                ItemKind::Sent => c.sent += 1,
                ItemKind::Kept => c.kept += 1,
                ItemKind::Archived => c.archived += 1,
                _ => {}
            },
            PairKey::Orphan(_) => c.orphaned += 1,
            _ => {}
        }
    }

    async fn apply(&mut self, key: PairKey, item: &RecoveredSecret<'_>) -> ItemWrite<String> {
        let (value, generation, retry) = (item.value, item.generation, item.retry);
        match key {
            PairKey::Identity(addr) => {
                let release = generation.saturating_sub(super::IDENTITY_GENERATION_OFFSET);
                self.import_identity(addr, value, release).await
            }
            PairKey::Contact(addr) => {
                let item = unowned(ItemKind::Contact, addr.0.to_vec());
                self.create(item, value.to_vec(), retry).await
            }
            PairKey::Message { kind, owner, id } => {
                let item = ItemRef {
                    kind,
                    owner: Some(owner),
                    id: id.to_vec(),
                };
                self.create(item, value.to_vec(), retry).await
            }
            PairKey::Flags(owner) => self.import_flags(owner, value).await,
            PairKey::IdentitySettings(owner) => {
                self.merge_settings(settings_item(owner), value).await
            }
            PairKey::GlobalSettings => {
                let item = unowned(ItemKind::GlobalSettings, Vec::new());
                self.merge_settings(item, value).await
            }
            PairKey::Orphan(id) => {
                let item = unowned(ItemKind::LegacyOrphan, id.to_vec());
                self.create(item, value.to_vec(), retry).await
            }
            PairKey::Refused(_) => {
                self.counts.refused += 1;
                ItemWrite::permanent("this entry cannot be imported".to_string())
            }
        }
    }
}

impl<S: MailStore, I: V1InboxReader> SuccessorSecretsIo for MailSuccessor<S, I> {
    type Error = String;

    async fn migration_marker(
        &mut self,
        query: &MarkerQuery<'_>,
    ) -> Result<Option<MigrationMarker>, String> {
        let stored = match self.get(marker_item(query.predecessor)).await {
            Ok(stored) => stored,
            // As good as no marker: the predecessor is asked again, and an
            // import never overwrites, so it costs a walk.
            Err(e) if is_unreadable(&e) => return Ok(None),
            Err(e) => return Err(e.to_string()),
        };
        let Some(stored) = stored else {
            return Ok(None);
        };
        let marker: StoredMarker = serde_json::from_slice(&stored.body)
            .map_err(|e| format!("an unreadable migration marker: {e}"))?;
        Ok(marker.read())
    }

    async fn record_marker(
        &mut self,
        predecessor: &DelegateKey,
        marker: MigrationMarker,
    ) -> Result<(), String> {
        // A resolved row's counts are recorded now, so a tab closed during
        // the walk loses only the row under way.
        if matches!(marker, MigrationMarker::Done { .. }) {
            self.update_ledger(MappingCounts::default(), |_| {}).await;
        }
        // A record that does not decode is an error, not an empty marker:
        // writing over it could lower a data flag.
        let item = marker_item(predecessor);
        let stored = match self.get(item.clone()).await {
            Ok(stored) => stored,
            Err(e) if is_unreadable(&e) => {
                let fresh = StoredMarker::default().with(marker);
                let body = serde_json::to_vec(&fresh).expect("a marker always encodes");
                return self
                    .put(item, body, None)
                    .await
                    .map(|_| ())
                    .map_err(|e| e.to_string());
            }
            Err(e) => return Err(e.to_string()),
        };
        if let Some(stored) = &stored {
            serde_json::from_slice::<StoredMarker>(&stored.body)
                .map_err(|e| format!("an unreadable migration marker: {e}"))?;
        }
        self.merged_put(item, |stored| {
            let current: StoredMarker = stored
                .and_then(|body| serde_json::from_slice(body).ok())
                .unwrap_or_default();
            let next = current.with(marker);
            (next != current).then(|| serde_json::to_vec(&next).expect("a marker always encodes"))
        })
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
    }

    async fn write_secret(&mut self, item: &RecoveredSecret<'_>) -> ItemWrite<String> {
        let Some(key) = PairKey::decode(item.key) else {
            return ItemWrite::permanent("an unknown item key".to_string());
        };
        let outcome = self.apply(key.clone(), item).await;
        if matches!(outcome, ItemWrite::Written) {
            self.count(&key);
        }
        outcome
    }
}

impl<S: MailStore, I: V1InboxReader> JournaledSuccessorIo for MailSuccessor<S, I> {
    /// A journal that keeps failing to read is reported as corrupt bytes, so
    /// the crate rebuilds it from the markers rather than stopping on every
    /// load. If the failure was brief, its re-read before storing finds the
    /// real journal and merges it.
    async fn load_journal(&mut self) -> Result<Option<Vec<u8>>, String> {
        match self.get(journal_item()).await {
            Ok(stored) => {
                self.journal_generation = Some(stored.as_ref().map_or(0, |i| i.generation));
                Ok(stored.map(|i| i.body.into_vec()))
            }
            Err(e) if is_unreadable(&e) => {
                self.journal_generation = None;
                Ok(Some(Vec::new()))
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// Compare-and-swap against the generation of the last load. The crate
    /// re-reads and merges right before every store, so a conflict is another
    /// tab storing in between: an error, and the next load merges it. Over an
    /// unreadable journal this is a create, the one write that replaces it,
    /// and a journal that has become readable answers it with a conflict.
    async fn store_journal(&mut self, journal: &[u8]) -> Result<(), String> {
        let generation = self
            .put(journal_item(), journal.to_vec(), self.journal_generation)
            .await
            .map_err(|e| e.to_string())?;
        self.journal_generation = Some(generation);
        Ok(())
    }
}
