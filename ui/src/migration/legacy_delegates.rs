//! Reading the v0.2.x delegates, and turning what they hold into items.
//!
//! The walk deals in `(key, value)` pairs. A v0.2.x delegate holds one JSON
//! blob, so this module maps a reply into one pair per item. Mapping goes by
//! what a reply contains, never by which request it answered: an identity's
//! key is the address its seeds derive, and the same item in two generations
//! gets the same key, so the first copy written stands. Which copy of a name
//! lands is not always the same: with two aliases on one address, or one
//! contact under two labels, map order picks one. The set of keys is the same
//! either way.
//!
//! Anything that does not establish what the predecessor holds is `Err`, the
//! crate's "unresponsive": it earns no marker and the next load asks again.
//! That includes an answer with nothing in it. A v0.2.x delegate answers an
//! empty default both when it holds nothing and when the node failed to read
//! its secret, and `Ok(vec![])` would seal it for good. `fetch_secrets`
//! therefore never returns an empty list.

use std::collections::{BTreeMap, HashMap, HashSet};

use freenet_mail_protocol::address::address_of;
use freenet_mail_protocol::{Addr, ItemKind, MAX_ITEM_BYTES};
use freenet_mail_wire_v1::identity::{EntryKind, IdentityManagement, IdentityMsg};
use freenet_mail_wire_v1::local_state::{AliasState, GlobalSettings, LocalState, LocalStateMsg};
use freenet_migrate::{DelegateLineageEntry, PredecessorSecretsIo, ProbeVerdict, SecretPair};
use freenet_stdlib::prelude::{DelegateKey, blake3};
use serde::{Deserialize, Serialize};

use super::IDENTITY_GENERATION_OFFSET;
use super::successor::ArrivedIdentities;
use crate::app::address_book::StoredContactKeys;
use crate::app::contact_store;
use crate::app::identity_store::MigrationMarkers;

/// Largest reply read: stdlib's streaming limit (`MAX_TOTAL_CHUNKS *
/// CHUNK_SIZE`), the most a node can deliver in one response. It is a bound on
/// parsing and not on the data, because a v0.2.x delegate holds everything in
/// one blob and contacts are double-encoded. A larger reply is refused unread
/// and counts as no answer. The per-item caps still apply to what is in it.
pub(crate) const MAX_LEGACY_REPLY_BYTES: usize = 64 * 1024 * 1024;

/// What a reply with no application message is called: how a v0.2.x delegate
/// acknowledges a change, and no answer to a read.
pub(crate) const EMPTY_REPLY: &str = "an empty reply";

/// How many loads in a row a newer row that gave nothing usable holds the
/// older rows of its family back. Bounded because a user who ran v0.2.6 and
/// never re-added an identity has the newer row answering empty for good and
/// their data in the older one.
pub(crate) const HOLD_BACK_LOADS: u32 = 3;

const MAX_ALIAS_CHARS: usize = 64;
const MAX_DESCRIPTION_CHARS: usize = 1024;

/// What asking a v0.2.x delegate produced. Three-way so silence and absence
/// stay apart in the type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LegacyReply {
    /// It ran and answered with these bytes.
    Answer(Vec<u8>),
    /// The node said, in a typed error, that it has no such delegate. Not
    /// proof it holds nothing: a node reports a failed WASM read the same way
    /// and unregisters a delegate without deleting its secrets.
    NotInstalled,
    /// Anything else: a timeout, a transport fault, an empty reply, a
    /// delegate error.
    NoAnswer(String),
}

/// One request to one v0.2.x delegate, awaited. The legacy WASM is not
/// registered first: a node that never ran that version holds no data for it.
pub(crate) trait LegacyTransport {
    async fn ask(
        &mut self,
        predecessor: &DelegateKey,
        params: &'static [u8],
        request: Vec<u8>,
    ) -> LegacyReply;
}

const IDENTITY_PARAMS: &[u8] =
    include_bytes!("../../../published-contract/wasm/v1/identity-manager-params");
const LOCAL_STATE_PARAMS: &[u8] =
    include_bytes!("../../../published-contract/wasm/v1/mail-local-state-params");

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

/// What a pair stands for. Its bytes are the walk's key, which is what makes
/// a key withheld, or an item already imported, the same across generations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PairKey {
    Identity(Addr),
    Contact(Addr),
    /// A draft, sent, kept or archived item.
    Message {
        kind: ItemKind,
        owner: Addr,
        id: [u8; 16],
    },
    /// One identity's read marks, as v1 list positions.
    Flags(Addr),
    IdentitySettings(Addr),
    GlobalSettings,
    Orphan([u8; 16]),
    /// An entry that cannot be imported, ever (its reason is in the key's
    /// hash only). Offered so the journal counts it as refused.
    Refused([u8; 16]),
}

fn message_tag(kind: ItemKind) -> Option<&'static str> {
    match kind {
        ItemKind::Draft => Some("dr"),
        ItemKind::Sent => Some("se"),
        ItemKind::Kept => Some("kp"),
        ItemKind::Archived => Some("ar"),
        _ => None,
    }
}

impl PairKey {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let text = match self {
            PairKey::Identity(a) => format!("id/{}", hex(&a.0)),
            PairKey::Contact(a) => format!("ct/{}", hex(&a.0)),
            PairKey::Message { kind, owner, id } => format!(
                "{}/{}/{}",
                message_tag(*kind).expect("message kinds only"),
                hex(&owner.0),
                hex(id)
            ),
            PairKey::Flags(a) => format!("fl/{}", hex(&a.0)),
            PairKey::IdentitySettings(a) => format!("si/{}", hex(&a.0)),
            PairKey::GlobalSettings => "sg".to_string(),
            PairKey::Orphan(id) => format!("lo/{}", hex(id)),
            PairKey::Refused(id) => format!("rj/{}", hex(id)),
        };
        text.into_bytes()
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(bytes).ok()?;
        let addr = |t: &str| Some(Addr(<[u8; 24]>::try_from(unhex(t)?).ok()?));
        let id16 = |t: &str| <[u8; 16]>::try_from(unhex(t)?).ok();
        if text == "sg" {
            return Some(PairKey::GlobalSettings);
        }
        let (tag, rest) = text.split_once('/')?;
        let kind = match tag {
            "id" => return Some(PairKey::Identity(addr(rest)?)),
            "ct" => return Some(PairKey::Contact(addr(rest)?)),
            "fl" => return Some(PairKey::Flags(addr(rest)?)),
            "si" => return Some(PairKey::IdentitySettings(addr(rest)?)),
            "lo" => return Some(PairKey::Orphan(id16(rest)?)),
            "rj" => return Some(PairKey::Refused(id16(rest)?)),
            "dr" => ItemKind::Draft,
            "se" => ItemKind::Sent,
            "kp" => ItemKind::Kept,
            "ar" => ItemKind::Archived,
            _ => return None,
        };
        let (owner, id) = rest.split_once('/')?;
        Some(PairKey::Message {
            kind,
            owner: addr(owner)?,
            id: id16(id)?,
        })
    }
}

/// The value of a [`PairKey::Identity`] pair. Holds seeds, so it has no
/// `Debug` and is never logged; it exists only between the legacy reply and
/// the delegate import.
#[derive(Serialize, Deserialize)]
pub(crate) struct MigratedIdentity {
    pub dsa: Vec<u8>,
    pub kem: Vec<u8>,
    pub alias: String,
    pub description: String,
    pub markers: MigrationMarkers,
}

/// The value of a [`PairKey::Flags`] pair: v1 list positions, translated at
/// write time. One pair per identity whether or not the inbox can be read
/// then, because the journal holds a retry to the number of pairs it saw.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LegacyFlags {
    pub read: Vec<u64>,
}

/// The value of a [`PairKey::Orphan`] pair.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OrphanItem {
    pub alias: String,
    pub what: String,
    pub legacy_id: String,
    pub body: String,
}

/// Who an alias in a local-state row belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AliasOwner {
    Identity(Addr),
    /// The identities of the row's own generation answered and no identity
    /// anywhere has this alias: its items are kept as orphans.
    NoIdentity,
    /// Not established this load. An orphan now would be sealed out of reach
    /// of the identity, and an older table could name the wrong one.
    Unresolved,
}

/// The alias each identity had in each generation, newest first. A generation
/// has a table only if its identity row answered with something in it.
#[derive(Debug, Default)]
pub(crate) struct AliasTables {
    tables: Vec<(u32, HashMap<String, Addr>)>,
    /// A generation that gave no readable answer may hold the alias.
    pub incomplete: bool,
    /// Generations whose identity row is typed "not installed" or answered
    /// with nothing in it. Their aliases are known to have no identity there,
    /// unlike a row that went silent, which may hold any of them.
    absent: HashSet<u32>,
}

impl AliasTables {
    pub(crate) fn mark_absent(&mut self, generation: u32) {
        self.absent.insert(generation);
    }

    /// Whether the identity row of `generation` is known to hold nothing.
    pub(crate) fn own_row_absent(&self, generation: u32) -> bool {
        self.absent.contains(&generation)
    }

    pub(crate) fn add(&mut self, generation: u32, table: HashMap<String, Addr>) {
        self.tables.push((generation, table));
        self.tables.sort_by_key(|(g, _)| std::cmp::Reverse(*g));
    }

    /// `alias` as the identities of `generation` knew it, else as the newest
    /// generation that knew it. The same release's table comes first, and is
    /// required: an alias can be reused for a different identity across
    /// releases, so without it an older table proves nothing.
    pub(crate) fn resolve(&self, generation: u32, alias: &str) -> AliasOwner {
        let Some((_, own)) = self.tables.iter().find(|(g, _)| *g == generation) else {
            return AliasOwner::Unresolved;
        };
        if let Some(addr) = own.get(alias) {
            return AliasOwner::Identity(*addr);
        }
        if self.incomplete {
            return AliasOwner::Unresolved;
        }
        self.tables
            .iter()
            .find_map(|(_, t)| t.get(alias))
            .map_or(AliasOwner::NoIdentity, |addr| AliasOwner::Identity(*addr))
    }
}

/// The aliases newer local-state rows hold. A list position means something
/// only in the inbox of the generation that recorded it, so only the newest
/// generation holding an alias supplies its read marks.
#[derive(Debug, Default)]
pub(crate) struct NewerAliases {
    pub aliases: HashSet<String>,
    /// A newer row that could not be read may hold any alias.
    pub unknown: bool,
}

/// Counts of what mapping left out, for the upgrade notice.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct MappingCounts {
    pub oversized: u32,
    pub undecodable: u32,
    /// Read marks with nowhere to go: an alias with no identity, or one a
    /// newer row that could not be read may hold.
    pub orphan_flags: u32,
    /// `deleted` marks, never imported: v0.2.7's delete already removes the
    /// message from the inbox, so a surviving position usually names a
    /// different, live message.
    pub deleted_marks: u32,
}

/// A pair for an entry that can never be imported.
fn refused(what: &[u8]) -> SecretPair {
    let id = id16(&[b"refused", what]);
    (PairKey::Refused(id).encode(), Vec::new())
}

pub(crate) fn id16(parts: &[&[u8]]) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    for part in parts {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    id
}

/// The item id of a draft or sent message: its UUID, which every generation
/// keeps for it, so an older copy of a later-edited draft is not a second
/// draft. An id that is not a UUID is hashed.
pub(crate) fn text_id(id: &str) -> [u8; 16] {
    uuid::Uuid::parse_str(id).map_or_else(|_| id16(&[id.as_bytes()]), |u| *u.as_bytes())
}

/// The alias as the delegate accepts it: printable, at most 64 characters,
/// not empty. Legacy aliases had no such rule.
pub(crate) fn import_alias(alias: &str, addr: &Addr) -> String {
    let cleaned: String = alias
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_ALIAS_CHARS)
        .collect();
    if cleaned.is_empty() {
        return format!("imported-{}", hex(&addr.0[..4]));
    }
    cleaned
}

/// `alias`, made distinct by the identity's address, for when another
/// identity holds the name. Deterministic, so a retry gets the same name.
pub(crate) fn distinct_alias(alias: &str, addr: &Addr) -> String {
    let suffix = format!(" ({})", hex(&addr.0[..3]));
    let keep = MAX_ALIAS_CHARS - suffix.chars().count();
    let base: String = alias.chars().take(keep).collect();
    format!("{base}{suffix}")
}

fn dsa_vk(seed: &[u8; 32]) -> Vec<u8> {
    use ml_dsa::signature::Keypair;
    ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&(*seed).into())
        .verifying_key()
        .encode()
        .to_vec()
}

/// What v0.2.x kept in an identity's `key` field.
#[derive(Deserialize)]
struct StoredSeeds {
    ml_dsa_seed: Vec<u8>,
    ml_kem_seed: Vec<u8>,
}

/// The items in an identity-management reply, and the aliases of its
/// identities. `Err` is "this reply established nothing".
pub(crate) fn map_identities(
    reply: &[u8],
    counts: &mut MappingCounts,
) -> Result<(Vec<SecretPair>, HashMap<String, Addr>), String> {
    let manager = IdentityManagement::try_from(reply).map_err(|e| format!("undecodable: {e}"))?;
    if manager.is_empty() {
        return Err("answered with nothing, which does not prove it holds nothing".into());
    }
    let mut pairs = Vec::new();
    let mut aliases = HashMap::new();
    for (alias, info) in manager.into_info() {
        match info.kind {
            EntryKind::Identity => {
                let seeds = serde_json::from_slice::<StoredSeeds>(&info.key).ok();
                let dsa = seeds
                    .as_ref()
                    .and_then(|s| <[u8; 32]>::try_from(s.ml_dsa_seed.as_slice()).ok());
                let Some(((seeds, dsa), true)) = seeds.zip(dsa).map(|(s, d)| {
                    let good = s.ml_kem_seed.len() == 64;
                    ((s, d), good)
                }) else {
                    counts.undecodable += 1;
                    pairs.push(refused(alias.as_bytes()));
                    continue;
                };
                let addr = address_of(&dsa_vk(&dsa));
                let value = MigratedIdentity {
                    dsa: seeds.ml_dsa_seed,
                    kem: seeds.ml_kem_seed,
                    alias: import_alias(&alias, &addr),
                    description: info
                        .extra
                        .unwrap_or_default()
                        .chars()
                        .take(MAX_DESCRIPTION_CHARS)
                        .collect(),
                    markers: MigrationMarkers {
                        inbox_wasm_hash: info.inbox_wasm_hash,
                        pending_migration_from: info.pending_migration_from,
                        aft_record_wasm_hash: info.aft_record_wasm_hash,
                        pending_aft_migration_from: info.pending_aft_migration_from,
                        imported_generation: None,
                    },
                };
                aliases.insert(alias, addr);
                pairs.push((
                    PairKey::Identity(addr).encode(),
                    serde_json::to_vec(&value).map_err(|e| e.to_string())?,
                ));
            }
            EntryKind::Contact => {
                let Ok(keys) = serde_json::from_slice::<StoredContactKeys>(&info.key) else {
                    counts.undecodable += 1;
                    pairs.push(refused(alias.as_bytes()));
                    continue;
                };
                let addr = address_of(&keys.ml_dsa_vk_bytes);
                let body =
                    contact_store::encode_keys(&alias, &info.extra.unwrap_or_default(), keys);
                pairs.push((PairKey::Contact(addr).encode(), body));
            }
        }
    }
    Ok((pairs, aliases))
}

fn json<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|e| e.to_string())
}

/// Maps one alias's items to pairs. `owner` is `None` for an alias with no
/// identity: its items go to the orphan list rather than being lost.
struct AliasMapper<'a> {
    alias: &'a str,
    owner: Option<Addr>,
    pairs: Vec<SecretPair>,
    counts: &'a mut MappingCounts,
}

impl AliasMapper<'_> {
    fn message(
        &mut self,
        kind: ItemKind,
        what: &str,
        legacy_id: &str,
        id: [u8; 16],
        body: Vec<u8>,
    ) -> Result<(), String> {
        if body.len() > MAX_ITEM_BYTES {
            self.counts.oversized += 1;
            self.pairs.push(refused(&body));
            return Ok(());
        }
        match self.owner {
            Some(owner) => {
                self.pairs
                    .push((PairKey::Message { kind, owner, id }.encode(), body));
            }
            None => self.orphan(what, legacy_id, body)?,
        }
        Ok(())
    }

    fn orphan(&mut self, what: &str, legacy_id: &str, body: Vec<u8>) -> Result<(), String> {
        let id = id16(&[self.alias.as_bytes(), what.as_bytes(), &body]);
        let value = OrphanItem {
            alias: self.alias.to_string(),
            what: what.to_string(),
            legacy_id: legacy_id.to_string(),
            body: String::from_utf8_lossy(&body).into_owned(),
        };
        let value = json(&value)?;
        if value.len() > MAX_ITEM_BYTES {
            self.counts.oversized += 1;
            self.pairs.push(refused(&body));
            return Ok(());
        }
        self.pairs.push((PairKey::Orphan(id).encode(), value));
        Ok(())
    }
}

fn map_alias(
    alias: &str,
    state: AliasState,
    owner: Option<Addr>,
    newer: &NewerAliases,
    counts: &mut MappingCounts,
) -> Result<Vec<SecretPair>, String> {
    let mut m = AliasMapper {
        alias,
        owner,
        pairs: Vec::new(),
        counts,
    };
    for (id, draft) in &state.drafts {
        m.message(ItemKind::Draft, "draft", id, text_id(id), json(draft)?)?;
    }
    for (id, sent) in &state.sent {
        m.message(ItemKind::Sent, "sent", id, text_id(id), json(sent)?)?;
    }
    // A kept or archived entry is keyed by its position in an inbox it has
    // left, so its content is the only stable name it has. The whole record
    // is hashed: two different messages never share an id, and archiving is
    // the only copy of the message there is.
    for (id, kept) in &state.kept {
        let body = json(kept)?;
        m.message(ItemKind::Kept, "kept", id, id16(&[&body]), body)?;
    }
    for (id, archived) in &state.archived {
        let body = json(archived)?;
        m.message(ItemKind::Archived, "archived", id, id16(&[&body]), body)?;
    }
    m.counts.deleted_marks += state.deleted.len() as u32;
    let marks = state.read.len() as u32;
    if marks > 0 {
        match owner {
            // The pair is there even with its marks left out: the journal
            // holds a retry to the number of pairs it saw, and which newer
            // rows answer can differ between loads.
            Some(owner) => {
                let held = newer.aliases.contains(alias);
                if newer.unknown && !held {
                    m.counts.orphan_flags += marks;
                }
                let read = if held || newer.unknown {
                    Vec::new()
                } else {
                    state.read
                };
                let flags = LegacyFlags { read };
                m.pairs
                    .push((PairKey::Flags(owner).encode(), json(&flags)?));
            }
            None => m.counts.orphan_flags += marks,
        }
    }
    // A default bucket is what v0.2.x reports for "never set": as a value it
    // would mask a real one from an older generation.
    if state.settings != Default::default() {
        let body = json(&state.settings)?;
        match owner {
            Some(owner) => m
                .pairs
                .push((PairKey::IdentitySettings(owner).encode(), body)),
            None => m.orphan("settings", "", body)?,
        }
    }
    Ok(m.pairs)
}

/// The items in a mail-local-state reply. `generation` is the row's release.
/// `Err` is "this reply established nothing". An alias that cannot be resolved
/// holds the whole row back, unless `orphan_unresolved` says it has waited
/// long enough and the row's own identity row is known to hold nothing (typed
/// "not installed", or empty): its items then go to the orphans, and the rest
/// of the row imports. A silent identity row keeps waiting.
pub(crate) fn map_local_state(
    reply: &[u8],
    generation: u32,
    aliases: &AliasTables,
    newer: &NewerAliases,
    orphan_unresolved: bool,
    counts: &mut MappingCounts,
) -> Result<Vec<SecretPair>, String> {
    let mut state = LocalState::try_from(reply).map_err(|e| format!("undecodable: {e}"))?;
    let global = state.global_settings().clone();
    let by_alias: BTreeMap<String, AliasState> = state.aliases_mut().drain().collect();
    let mut pairs = Vec::new();
    for (alias, alias_state) in by_alias {
        let owner = match aliases.resolve(generation, &alias) {
            AliasOwner::Identity(addr) => Some(addr),
            AliasOwner::NoIdentity => None,
            AliasOwner::Unresolved if orphan_unresolved && aliases.own_row_absent(generation) => {
                None
            }
            AliasOwner::Unresolved => {
                return Err(format!("the identities that own `{alias}` did not answer"));
            }
        };
        pairs.extend(map_alias(&alias, alias_state, owner, newer, counts)?);
    }
    if global != GlobalSettings::default() {
        pairs.push((PairKey::GlobalSettings.encode(), json(&global)?));
    }
    if pairs.is_empty() {
        return Err("answered with nothing, which does not prove it holds nothing".into());
    }
    Ok(pairs)
}

/// The walk's reader. One round trip per predecessor per run: the preflight's
/// answer is the export.
pub(crate) struct LegacyAdapter<T> {
    transport: T,
    lineage: Vec<DelegateLineageEntry>,
    replies: HashMap<Vec<u8>, LegacyReply>,
    counts: MappingCounts,
    /// The rows the journal has pending, with the walks each has been through.
    pending_walks: HashMap<Vec<u8>, u32>,
    /// Rows whose read established nothing this run though they answered.
    unusable: HashSet<Vec<u8>>,
    arrived: ArrivedIdentities,
}

impl<T: LegacyTransport> LegacyAdapter<T> {
    pub(crate) fn new(
        transport: T,
        lineage: Vec<DelegateLineageEntry>,
        pending_walks: HashMap<Vec<u8>, u32>,
        arrived: ArrivedIdentities,
    ) -> Self {
        LegacyAdapter {
            transport,
            lineage,
            replies: HashMap::new(),
            counts: MappingCounts::default(),
            pending_walks,
            unusable: HashSet::new(),
            arrived,
        }
    }

    pub(crate) fn counts(&self) -> MappingCounts {
        self.counts
    }

    fn entry(&self, key: &DelegateKey) -> Option<DelegateLineageEntry> {
        self.lineage
            .iter()
            .find(|e| e.delegate_key.as_slice() == key.bytes())
            .cloned()
    }

    async fn reply(&mut self, predecessor: &DelegateKey) -> Result<LegacyReply, String> {
        if let Some(reply) = self.replies.get(predecessor.bytes()) {
            return Ok(reply.clone());
        }
        let entry = self
            .entry(predecessor)
            .ok_or("a predecessor outside the lineage")?;
        let (params, request) = if entry.generation >= IDENTITY_GENERATION_OFFSET {
            let msg = Vec::<u8>::try_from(&IdentityMsg::GetIdentities);
            (IDENTITY_PARAMS, msg.map_err(|e| e.to_string())?)
        } else {
            let msg = Vec::<u8>::try_from(&LocalStateMsg::GetAll);
            (LOCAL_STATE_PARAMS, msg.map_err(|e| e.to_string())?)
        };
        let reply = match self.transport.ask(predecessor, params, request).await {
            LegacyReply::Answer(bytes) if bytes.len() > MAX_LEGACY_REPLY_BYTES => {
                LegacyReply::NoAnswer(format!("reply of {} bytes refused", bytes.len()))
            }
            reply => reply,
        };
        self.replies
            .insert(predecessor.bytes().to_vec(), reply.clone());
        Ok(reply)
    }

    /// Every identity generation's aliases. A generation that is typed "not
    /// installed", or that answered with nothing in it, has no table, so its
    /// own local state stays unresolved. For other generations neither leaves
    /// the tables incomplete: a row that stays empty for good must not strand
    /// the rows beside it. One that went silent or is undecodable may hold
    /// any alias, and does.
    async fn alias_tables(&mut self) -> AliasTables {
        let mut tables = AliasTables::default();
        let identity_rows: Vec<DelegateLineageEntry> = self
            .lineage
            .iter()
            .filter(|e| e.generation >= IDENTITY_GENERATION_OFFSET)
            .cloned()
            .collect();
        for entry in identity_rows {
            let key = lineage_key(&entry);
            let resolved = !self.pending_walks.contains_key(key.bytes());
            match self.reply(&key).await {
                Ok(LegacyReply::Answer(bytes)) => {
                    let mut ignored = MappingCounts::default();
                    match map_identities(&bytes, &mut ignored) {
                        Ok((_, table)) => {
                            if resolved {
                                table.values().for_each(|a| self.arrived.note(*a));
                            }
                            tables.add(entry.generation - IDENTITY_GENERATION_OFFSET, table);
                        }
                        Err(_) if IdentityManagement::try_from(bytes.as_slice()).is_ok() => {
                            tables.mark_absent(entry.generation - IDENTITY_GENERATION_OFFSET);
                        }
                        Err(_) => tables.incomplete = true,
                    }
                }
                Ok(LegacyReply::NotInstalled) => {
                    tables.mark_absent(entry.generation - IDENTITY_GENERATION_OFFSET);
                }
                Ok(LegacyReply::NoAnswer(_)) | Err(_) => tables.incomplete = true,
            }
        }
        tables
    }

    /// The aliases held by the local-state rows newer than `generation`.
    async fn newer_aliases(&mut self, generation: u32) -> NewerAliases {
        let rows: Vec<DelegateLineageEntry> = self
            .lineage
            .iter()
            .filter(|e| e.generation < IDENTITY_GENERATION_OFFSET && e.generation > generation)
            .cloned()
            .collect();
        let mut newer = NewerAliases::default();
        for entry in rows {
            match self.reply(&lineage_key(&entry)).await {
                Ok(LegacyReply::Answer(bytes)) => match LocalState::try_from(bytes.as_slice()) {
                    Ok(mut state) => newer.aliases.extend(state.aliases_mut().keys().cloned()),
                    Err(_) => newer.unknown = true,
                },
                Ok(LegacyReply::NotInstalled) => {}
                Ok(LegacyReply::NoAnswer(_)) | Err(_) => newer.unknown = true,
            }
        }
        newer
    }

    /// The newer row of `entry`'s family that holds it back, if any: one still
    /// pending that gave nothing usable this run, for at most
    /// [`HOLD_BACK_LOADS`] walks. Under the union policy nothing else stops
    /// an older row landing first, and then the writer declines the newer
    /// values for good. A typed "not installed" never holds back.
    fn held_back_by(&self, entry: &DelegateLineageEntry) -> Option<u32> {
        let identity = entry.generation >= IDENTITY_GENERATION_OFFSET;
        self.lineage
            .iter()
            .filter(|e| e.generation > entry.generation)
            .filter(|e| (e.generation >= IDENTITY_GENERATION_OFFSET) == identity)
            .find(|e| {
                let key = e.delegate_key.as_slice();
                let silent = matches!(self.replies.get(key), Some(LegacyReply::NoAnswer(_)));
                (silent || self.unusable.contains(key))
                    && self
                        .pending_walks
                        .get(key)
                        .is_some_and(|walks| *walks < HOLD_BACK_LOADS)
            })
            .map(|e| e.generation)
    }

    async fn read_row(
        &mut self,
        entry: &DelegateLineageEntry,
        predecessor: &DelegateKey,
    ) -> Result<Vec<SecretPair>, String> {
        if let Some(newer) = self.held_back_by(entry) {
            return Err(format!("waiting for generation {newer}, which is newer"));
        }
        let LegacyReply::Answer(bytes) = self.reply(predecessor).await? else {
            return Err("no answer to read".into());
        };
        if entry.generation >= IDENTITY_GENERATION_OFFSET {
            return map_identities(&bytes, &mut self.counts).map(|(pairs, _)| pairs);
        }
        let tables = self.alias_tables().await;
        let newer = self.newer_aliases(entry.generation).await;
        let walks = self.pending_walks.get(predecessor.bytes());
        let orphan_unresolved = walks.is_some_and(|w| *w >= HOLD_BACK_LOADS);
        map_local_state(
            &bytes,
            entry.generation,
            &tables,
            &newer,
            orphan_unresolved,
            &mut self.counts,
        )
    }

    /// How many pending rows went silent or answered with bytes that do not
    /// decode this run. "Not installed" and an empty answer are not among
    /// them: both are what a node that never ran that version gives.
    pub(crate) fn silent_rows(&self) -> usize {
        self.replies
            .iter()
            .filter(|(key, _)| self.pending_walks.contains_key(*key))
            .filter(|(key, reply)| match reply {
                LegacyReply::NoAnswer(_) => true,
                LegacyReply::NotInstalled => false,
                LegacyReply::Answer(bytes) => !self.decodes(key, bytes),
            })
            .count()
    }

    fn decodes(&self, key: &[u8], bytes: &[u8]) -> bool {
        let identity = self
            .lineage
            .iter()
            .find(|e| e.delegate_key.as_slice() == key)
            .is_some_and(|e| e.generation >= IDENTITY_GENERATION_OFFSET);
        if identity {
            IdentityManagement::try_from(bytes).is_ok()
        } else {
            LocalState::try_from(bytes).is_ok()
        }
    }
}

pub(crate) fn lineage_key(entry: &DelegateLineageEntry) -> DelegateKey {
    DelegateKey::new(
        entry.delegate_key,
        freenet_stdlib::prelude::CodeHash::new(entry.code_hash),
    )
}

impl<T: LegacyTransport> PredecessorSecretsIo for LegacyAdapter<T> {
    type Error = String;

    async fn probe_executable(&mut self, predecessor: &DelegateKey) -> Result<bool, String> {
        Ok(matches!(
            self.reply(predecessor).await?,
            LegacyReply::Answer(_)
        ))
    }

    async fn probe_verdict(&mut self, predecessor: &DelegateKey) -> Result<ProbeVerdict, String> {
        Ok(match self.reply(predecessor).await? {
            LegacyReply::Answer(_) => ProbeVerdict::Executable,
            LegacyReply::NotInstalled => ProbeVerdict::NotInstalled,
            LegacyReply::NoAnswer(_) => ProbeVerdict::NoReply,
        })
    }

    async fn fetch_secrets(
        &mut self,
        predecessor: &DelegateKey,
    ) -> Result<Vec<SecretPair>, String> {
        let entry = self
            .entry(predecessor)
            .ok_or("a predecessor outside the lineage")?;
        let read = self.read_row(&entry, predecessor).await;
        if read.is_err() {
            self.unusable.insert(predecessor.bytes().to_vec());
        }
        read
    }
}
