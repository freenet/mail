//! Writing migrated items into the mail delegate, through the same operations
//! the app uses: its compare-and-swap, budget and per-kind caps all apply.
//!
//! An item already stored stays as it is. Settings and flags are the two
//! merged kinds, and a value already stored wins or is kept by the merge.
//!
//! The migration's bookkeeping lives in delegate items too. Each write here
//! returns only once the delegate acknowledged it, so markers and the journal
//! are durable when the crate is told they are, and there is nothing to flush.

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
}

/// What this walk imported, and what it could not, for the upgrade notice.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
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
    /// Read/deleted marks that could not be translated.
    pub flags_skipped: u32,
}

impl MigrationCounts {
    pub(crate) fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    pub(crate) fn merge_mapping(&mut self, mapping: MappingCounts) {
        self.flags_skipped += mapping.orphan_flags;
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
pub(crate) fn adopt_legacy_markers(
    stored: &MigrationMarkers,
    legacy: &MigrationMarkers,
    current_inbox: &str,
    current_aft: &str,
) -> MigrationMarkers {
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
        inbox_wasm_hash: stored
            .inbox_wasm_hash
            .clone()
            .or_else(|| legacy.inbox_wasm_hash.clone()),
        pending_migration_from: pending(
            &stored.pending_migration_from,
            &legacy.pending_migration_from,
            &legacy.inbox_wasm_hash,
            current_inbox,
        ),
        aft_record_wasm_hash: stored
            .aft_record_wasm_hash
            .clone()
            .or_else(|| legacy.aft_record_wasm_hash.clone()),
        pending_aft_migration_from: pending(
            &stored.pending_aft_migration_from,
            &legacy.pending_aft_migration_from,
            &legacy.aft_record_wasm_hash,
            current_aft,
        ),
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

fn journal_item() -> ItemRef {
    unowned(ItemKind::MigrationJournal, Vec::new())
}

fn marker_item(predecessor: &DelegateKey) -> ItemRef {
    unowned(ItemKind::MigrationMarker, predecessor.bytes().to_vec())
}

/// What a failed item write means for the walk. `CapReached` is retryable:
/// the user can make room, and a permanent verdict would let the walk resolve
/// past mail it did not import.
fn failed(error: CallError) -> ItemWrite<String> {
    let text = error.to_string();
    match error.code() {
        Some(FailureCode::BadInput) => ItemWrite::permanent(text),
        _ => ItemWrite::retryable(text),
    }
}

fn is_conflict(e: &CallError) -> bool {
    matches!(e.code(), Some(FailureCode::Conflict { .. }))
}

pub(crate) struct MailSuccessor<S, I> {
    store: S,
    inbox: I,
    journal_generation: u64,
    counts: MigrationCounts,
}

impl<S: MailStore, I: V1InboxReader> MailSuccessor<S, I> {
    pub(crate) fn new(store: S, inbox: I) -> Self {
        MailSuccessor {
            store,
            inbox,
            journal_generation: 0,
            counts: MigrationCounts::default(),
        }
    }

    pub(crate) fn into_counts(self) -> MigrationCounts {
        self.counts
    }

    async fn get(&mut self, item: ItemRef) -> Result<Option<Item>, CallError> {
        match self.store.call(Op::GetItem { item }).await? {
            Reply::Item(item) => Ok(item),
            other => Err(crate::mail_delegate::unexpected(&other)),
        }
    }

    async fn put(
        &mut self,
        item: ItemRef,
        body: Vec<u8>,
        expected_gen: Option<u64>,
    ) -> Result<u64, CallError> {
        let op = Op::PutItem {
            item,
            body: ByteBuf::from(body),
            expected_gen,
        };
        match self.store.call(op).await? {
            Reply::Ack { generation } => Ok(generation),
            other => Err(crate::mail_delegate::unexpected(&other)),
        }
    }

    /// Read-merge-write `item`, retrying a lost compare-and-swap. `merge`
    /// gets the stored body and returns the new one, `None` to leave it.
    /// Returns whether anything was written.
    async fn merged_put(
        &mut self,
        item: ItemRef,
        merge: impl Fn(Option<&[u8]>) -> Option<Vec<u8>>,
    ) -> Result<bool, CallError> {
        let mut attempt = 0;
        loop {
            let current = self.get(item.clone()).await?;
            let generation = current.as_ref().map_or(0, |i| i.generation);
            let Some(body) = merge(current.as_ref().map(|i| i.body.as_slice())) else {
                return Ok(false);
            };
            match self.put(item.clone(), body, Some(generation)).await {
                Ok(_) => return Ok(true),
                Err(e) if is_conflict(&e) && attempt + 1 < CAS_ATTEMPTS => attempt += 1,
                Err(e) => return Err(e),
            }
        }
    }

    /// Import an item that may not exist yet: a stored one stands.
    async fn create(&mut self, item: ItemRef, body: Vec<u8>) -> ItemWrite<String> {
        match self.put(item, body, None).await {
            Ok(_) => ItemWrite::written(),
            Err(e) if is_conflict(&e) => ItemWrite::already_authoritative(),
            // The identity is being deleted: the user's decision stands.
            Err(e) if e.code() == Some(FailureCode::Refused) => ItemWrite::already_authoritative(),
            Err(e) => failed(e),
        }
    }

    async fn import_identity(&mut self, addr: Addr, value: &[u8]) -> ItemWrite<String> {
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
                Ok(other) => return failed(crate::mail_delegate::unexpected(&other)),
                // Another identity holds the name: a different address, so
                // this one takes a name of its own.
                Err(e) if is_conflict(&e) && attempt == 0 => {
                    attempt += 1;
                    alias = distinct_alias(&identity.alias, &addr);
                }
                // It is being deleted: the user's decision stands.
                Err(e) if e.code() == Some(FailureCode::Refused) => {
                    return ItemWrite::already_authoritative();
                }
                Err(e) => return failed(e),
            }
        };
        if info.addr != addr {
            return ItemWrite::permanent("seeds do not derive their address".to_string());
        }
        if let Err(e) = self.adopt_markers(&info, &identity.markers).await {
            return failed(e);
        }
        if already_present {
            return ItemWrite::already_authoritative();
        }
        self.counts.identities += 1;
        ItemWrite::written()
    }

    async fn adopt_markers(
        &mut self,
        info: &IdentityInfo,
        legacy: &MigrationMarkers,
    ) -> Result<(), CallError> {
        let item = ItemRef {
            kind: ItemKind::IdentitySettings,
            owner: Some(info.addr),
            id: Vec::new(),
        };
        self.merged_put(item, |stored| {
            let markers = markers_from_body(stored);
            let adopted = adopt_legacy_markers(
                &markers,
                legacy,
                crate::inbox::INBOX_CODE_HASH.trim(),
                crate::aft::TOKEN_RECORD_CODE_HASH.trim(),
            );
            (adopted != markers).then(|| body_with_markers(stored, &adopted))
        })
        .await
        .map(|_| ())
    }

    async fn merge_settings(&mut self, item: ItemRef, value: &[u8]) -> ItemWrite<String> {
        let Ok(incoming) = serde_json::from_slice::<serde_json::Value>(value) else {
            return ItemWrite::permanent("not a settings record".to_string());
        };
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
            Err(e) => failed(e),
        }
    }

    /// Translate v1 list positions into marks on the messages at those
    /// positions now. An inbox that cannot be fetched skips them, counted.
    async fn import_flags(&mut self, owner: Addr, value: &[u8]) -> ItemWrite<String> {
        let Ok(flags) = serde_json::from_slice::<LegacyFlags>(value) else {
            return ItemWrite::permanent("not a flags record".to_string());
        };
        let marks = (flags.read.len() + flags.deleted.len()) as u32;
        let identities = match self.store.call(Op::ListIdentities).await {
            Ok(Reply::Identities(list)) => list,
            Ok(other) => return failed(crate::mail_delegate::unexpected(&other)),
            Err(e) => return failed(e),
        };
        let Some(vk) = identities
            .iter()
            .find(|i| i.addr == owner)
            .map(|i| i.vk.clone())
        else {
            return ItemWrite::retryable("the identity is not imported yet".to_string());
        };
        let Some(ciphertexts) = self.inbox.ciphertexts(&vk).await else {
            self.counts.flags_skipped += marks;
            return ItemWrite::already_authoritative();
        };
        let mut wanted: std::collections::BTreeMap<[u8; 16], MergedFlags> = Default::default();
        for (positions, read) in [(&flags.read, true), (&flags.deleted, false)] {
            for position in positions {
                let Some(ciphertext) = usize::try_from(*position)
                    .ok()
                    .and_then(|p| ciphertexts.get(p))
                else {
                    self.counts.flags_skipped += 1;
                    continue;
                };
                let mark = MergedFlags {
                    read,
                    deleted: !read,
                };
                let id = crate::local_state::full_message_id(ciphertext);
                let entry = wanted.entry(id).or_default();
                *entry = entry.merged(mark);
            }
        }
        for (id, mark) in wanted {
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
                return failed(e);
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

    async fn apply(&mut self, key: PairKey, value: &[u8]) -> ItemWrite<String> {
        match key {
            PairKey::Identity(addr) => self.import_identity(addr, value).await,
            PairKey::Contact(addr) => {
                let item = unowned(ItemKind::Contact, addr.0.to_vec());
                self.create(item, value.to_vec()).await
            }
            PairKey::Message { kind, owner, id } => {
                let item = ItemRef {
                    kind,
                    owner: Some(owner),
                    id: id.to_vec(),
                };
                self.create(item, value.to_vec()).await
            }
            PairKey::Flags(owner) => self.import_flags(owner, value).await,
            PairKey::IdentitySettings(owner) => {
                let item = ItemRef {
                    kind: ItemKind::IdentitySettings,
                    owner: Some(owner),
                    id: Vec::new(),
                };
                self.merge_settings(item, value).await
            }
            PairKey::GlobalSettings => {
                let item = unowned(ItemKind::GlobalSettings, Vec::new());
                self.merge_settings(item, value).await
            }
            PairKey::Orphan(id) => {
                let item = unowned(ItemKind::LegacyOrphan, id.to_vec());
                self.create(item, value.to_vec()).await
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
        let stored = self
            .get(marker_item(query.predecessor))
            .await
            .map_err(|e| e.to_string())?;
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
        // A record that does not decode is an error, not an empty marker:
        // writing over it could lower a data flag.
        let item = marker_item(predecessor);
        let stored = self.get(item.clone()).await.map_err(|e| e.to_string())?;
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
        let outcome = self.apply(key.clone(), item.value).await;
        if matches!(outcome, ItemWrite::Written) {
            self.count(&key);
        }
        outcome
    }
}

impl<S: MailStore, I: V1InboxReader> JournaledSuccessorIo for MailSuccessor<S, I> {
    async fn load_journal(&mut self) -> Result<Option<Vec<u8>>, String> {
        let stored = self.get(journal_item()).await.map_err(|e| e.to_string())?;
        self.journal_generation = stored.as_ref().map_or(0, |i| i.generation);
        Ok(stored.map(|i| i.body.into_vec()))
    }

    /// Compare-and-swap against the generation of the last load. The crate
    /// re-reads and merges right before every store, so a conflict is another
    /// tab storing in between: an error, and the next load merges it.
    async fn store_journal(&mut self, journal: &[u8]) -> Result<(), String> {
        self.journal_generation = self
            .put(
                journal_item(),
                journal.to_vec(),
                Some(self.journal_generation),
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}
