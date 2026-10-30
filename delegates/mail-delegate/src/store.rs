//! Storage: one namespace per web-app origin, a budget over every key an
//! origin writes, the generation envelope, and self-maintained indexes.
//!
//! Every key is `o/<origin hex>/<relative key>`, built here from typed ids;
//! callers never send a raw key. A staging app using this delegate never sees
//! production data, and no app can read or exhaust another's.
//!
//! Nothing here lists the host's keys. Each set of items (an identity's
//! drafts, the contacts, the identities themselves) has an index record
//! naming its ids, protected by compare-and-swap like any other record.
//!
//! Every record is wrapped in `[ENVELOPE_TAG][generation u64 LE][body]`
//! (River's `versioning.rs` layout). Generations come from one counter per
//! origin, so a generation is never reused after a delete and re-create.
//!
//! Relative keys:
//!
//! | key | holds |
//! |---|---|
//! | `id/<addr>` | an identity record |
//! | `ix/id` | the identity index |
//! | `it/<kind>/<owner or ->/<id or ->` | an item |
//! | `ix/<kind>/<owner or ->` | the index of one kind for one owner |
//! | `ix/pg` | ids of pending prompts |
//! | `pg/<prompt id>` | a pending prompt |
//! | `gr/export` | the remembered export grant |
//! | `es/current` | the live export session |
//! | `mt/gen`, `mt/pseq`, `mt/usage` | bookkeeping |

use std::collections::BTreeSet;

use freenet_mail_protocol::{Addr, Failure, FailureCode, ItemKind, ItemRef};

use crate::env::Env;

pub const MAX_IDENTITIES: usize = 16;
pub const MAX_CONTACTS: usize = 2048;
pub const MAX_DRAFTS: usize = 256;
/// Per identity, for each of sent, kept, archived and flags.
pub const MAX_MESSAGES: usize = 4096;
/// Keys one origin may hold, every kind included. Fits the per-kind caps for
/// [`MAX_IDENTITIES`] identities (16 x (256 + 4 x 4096 + 1) + 2048 + ...).
pub const MAX_ORIGIN_KEYS: u64 = 300_000;
/// Bytes (keys plus values) one origin may hold.
pub const MAX_ORIGIN_BYTES: u64 = 512 * 1024 * 1024;
/// Headroom past the budget that only deletion bookkeeping may use: a
/// delete writes a marker before it removes anything, and a user whose
/// storage is full must still be able to delete to free space.
pub const RESERVED_KEYS: u64 = 64;
pub const RESERVED_BYTES: u64 = 64 * 1024;
/// Pending consent prompts per origin; the oldest is refused past this.
pub const MAX_PENDING_PROMPTS: usize = 4;
/// A prompt not answered within this many seconds is refused.
pub const PROMPT_TTL_SECS: u64 = 600;

const ENVELOPE_TAG: u8 = 1;
const HEADER_LEN: usize = 1 + 8;
const USAGE: &str = "mt/usage";
/// A recount of the usage record ([`Space::recount_step`]):
/// `[visited][keys][bytes]` (u64 LE each) while it is under way,
/// `[RECOUNT_DONE][keys][bytes]` once finished, the usage it found.
const RECOUNT: &str = "mt/recount";
const RECOUNT_DONE: u64 = u64::MAX;
/// Keys a recount reads per call, so one call stays well within the host's
/// time limit; a larger store is recounted over several calls.
pub const RECOUNT_STEP: usize = 2048;
/// What a key that must exist but cannot be read counts for in a recount:
/// its size is unknown, and counting it as nothing would under-count.
pub const UNREADABLE_VALUE_BYTES: u64 = 1024;
const GENERATION: &str = "mt/gen";
/// A second copy of the generation counter. The host cannot tell a failed
/// read from an absent key, and a read can keep failing (a file it cannot
/// read or decrypt), so the counter is kept twice and read as the larger.
const GENERATION_COPY: &str = "mt/gen2";
/// An index's existence marker (`xm/<index rel>`): `l` once the index has
/// been written, `p` while it is being created or removed. An index that
/// reads as absent while its marker says `l` is unreadable, not empty, and
/// is never rewritten from scratch (that would unlist everything in it).
const INDEX_MARKER_PREFIX: &str = "xm/";
const MARKER_LIVE: &[u8] = b"l";
const MARKER_PENDING: &[u8] = b"p";

pub fn index_marker_rel(index: &str) -> String {
    format!("{INDEX_MARKER_PREFIX}{index}")
}

/// The 32-byte web-app contract id a request came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Origin(pub [u8; 32]);

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0xf) as usize] as char);
    }
    s
}

pub fn namespace(origin: &Origin) -> String {
    format!("o/{}/", hex(&origin.0))
}

pub fn identity_rel(addr: &Addr) -> String {
    format!("id/{}", hex(&addr.0))
}

/// "This identity's index entry may have no record": written by a create
/// before it claims the slot and by the last deletion step before it
/// removes the record, and cleared once entry and record agree again. It is
/// the only licence to drop a recordless entry: the host cannot tell a
/// failed read from an absent key, so a missing record alone proves nothing.
pub fn deleted_rel(addr: &Addr) -> String {
    format!("dl/{}", hex(&addr.0))
}

/// The marker a create writes before claiming its index slot. It licenses
/// nothing by itself: left behind beside a record that later fails to read,
/// it must not get that record unlisted.
pub const MARKER_CREATING: &[u8] = b"c";
/// A create whose record write was refused and whose slot could not be
/// given back: the entry has no record, and a listing may drop it.
pub const MARKER_FAILED: &[u8] = b"f";
/// The marker a deletion the user approved writes: the record is being, or
/// was, removed. Only this one licenses finishing a deletion without asking.
pub const MARKER_DELETING: &[u8] = b"d";
/// A create marker whose create finished but which could not be removed:
/// it licenses nothing.
pub const MARKER_SPENT: &[u8] = b"s";

pub const IDENTITY_INDEX: &str = "ix/id";
pub const PROMPT_INDEX: &str = "ix/pg";
pub const EXPORT_GRANT: &str = "gr/export";
/// The one live export session of an origin (a successor export in pages).
pub const EXPORT_SESSION: &str = "es/current";
pub const PROMPT_SEQ: &str = "mt/pseq";

pub fn prompt_rel(prompt_id: u32) -> String {
    format!("pg/{prompt_id:08x}")
}

pub fn kind_tag(kind: ItemKind) -> &'static str {
    match kind {
        ItemKind::Contact => "ct",
        ItemKind::Draft => "dr",
        ItemKind::Sent => "se",
        ItemKind::Kept => "kp",
        ItemKind::Archived => "ar",
        ItemKind::Flags => "fl",
        ItemKind::IdentitySettings => "si",
        ItemKind::GlobalSettings => "sg",
    }
}

pub const ALL_KINDS: [ItemKind; 8] = [
    ItemKind::Contact,
    ItemKind::Draft,
    ItemKind::Sent,
    ItemKind::Kept,
    ItemKind::Archived,
    ItemKind::Flags,
    ItemKind::IdentitySettings,
    ItemKind::GlobalSettings,
];

/// Whether `kind` belongs to an identity, and the id length it takes.
pub fn shape(kind: ItemKind) -> (bool, usize) {
    match kind {
        ItemKind::Contact => (false, 24),
        ItemKind::Draft
        | ItemKind::Sent
        | ItemKind::Kept
        | ItemKind::Archived
        | ItemKind::Flags => (true, 16),
        ItemKind::IdentitySettings => (true, 0),
        ItemKind::GlobalSettings => (false, 0),
    }
}

/// Per-kind cap (per owner for identity-owned kinds).
pub fn cap(kind: ItemKind) -> usize {
    match kind {
        ItemKind::Contact => MAX_CONTACTS,
        ItemKind::Draft => MAX_DRAFTS,
        ItemKind::Sent | ItemKind::Kept | ItemKind::Archived | ItemKind::Flags => MAX_MESSAGES,
        ItemKind::IdentitySettings | ItemKind::GlobalSettings => 1,
    }
}

fn owner_part(owner: Option<&Addr>) -> String {
    owner.map_or_else(|| "-".to_string(), |a| hex(&a.0))
}

pub fn index_rel(kind: ItemKind, owner: Option<&Addr>) -> String {
    format!("ix/{}/{}", kind_tag(kind), owner_part(owner))
}

pub fn item_rel(item: &ItemRef) -> String {
    let id = if item.id.is_empty() {
        "-".to_string()
    } else {
        hex(&item.id)
    };
    format!(
        "it/{}/{}/{id}",
        kind_tag(item.kind),
        owner_part(item.owner.as_ref())
    )
}

pub fn encode_versioned(generation: u64, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + body.len());
    out.push(ENVELOPE_TAG);
    out.extend_from_slice(&generation.to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// `(generation, body)`, or `None` for bytes that are not an envelope.
pub fn decode_versioned(stored: &[u8]) -> Option<(u64, &[u8])> {
    if stored.len() < HEADER_LEN || stored[0] != ENVELOPE_TAG {
        return None;
    }
    let generation = u64::from_le_bytes(stored[1..HEADER_LEN].try_into().ok()?);
    Some((generation, &stored[HEADER_LEN..]))
}

pub fn fail(code: FailureCode, detail: impl Into<String>) -> Failure {
    Failure {
        code,
        detail: detail.into(),
    }
}

/// The pending marker of an item write (`c`: a create claimed the index
/// slot, `f`: that create failed and could not give the slot back, `d`: a
/// delete is removing the record). Like the identity markers, it is the
/// only licence for a listing to drop an index entry whose record reads as
/// absent: the host cannot tell a failed read from an absent key. Keyed by
/// a hash, so a marker left behind names no identity.
pub fn pending_item_rel(item: &ItemRef) -> String {
    let h = blake3::hash(item_rel(item).as_bytes());
    format!("pi/{}", hex(&h.as_bytes()[..16]))
}

/// Keys and bytes an origin holds (its usage record and recount record
/// excluded).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub keys: u64,
    pub bytes: u64,
}

fn encode_usage(u: Usage) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&u.keys.to_le_bytes());
    b[8..].copy_from_slice(&u.bytes.to_le_bytes());
    b
}

/// `None` for a record that does not decode: unknown, as if unreadable.
fn decode_usage(b: &[u8]) -> Option<Usage> {
    let b = <[u8; 16]>::try_from(b).ok()?;
    Some(Usage {
        keys: u64::from_le_bytes(b[..8].try_into().expect("8 bytes")),
        bytes: u64::from_le_bytes(b[8..].try_into().expect("8 bytes")),
    })
}

/// One origin's view of the store. Every write goes through here, so the
/// origin's budget covers every key it causes to exist.
pub struct Space<'a> {
    pub env: &'a mut dyn Env,
    pub origin: Origin,
    ns: String,
}

impl<'a> Space<'a> {
    pub fn new(env: &'a mut dyn Env, origin: Origin) -> Self {
        let ns = namespace(&origin);
        Space { env, origin, ns }
    }

    pub fn full_key(&self, rel: &str) -> Vec<u8> {
        format!("{}{rel}", self.ns).into_bytes()
    }

    pub fn get(&self, rel: &str) -> Option<Vec<u8>> {
        self.fetch(&self.full_key(rel))
    }

    /// Read `key`, re-reading once on a miss. The host cannot tell a failed
    /// read from an absent key, and every "absent" this delegate concludes
    /// can destroy something (a create over an existing record, an index
    /// rewritten without its entries, a reused generation), so absence is
    /// only believed when an immediate re-read agrees.
    fn fetch(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.env.get(key).or_else(|| self.env.get(key))
    }

    /// The recorded usage, for reporting; zero when the record cannot be
    /// read. Writes never use this: see [`Space::stored_usage`].
    pub fn usage(&self) -> Usage {
        self.stored_usage().unwrap_or_default()
    }

    /// The usage record, or `None` when it reads as absent. Absent means
    /// unknown, not zero: the record may be unreadable, and believing zero
    /// would let this origin write past its budget. A write that finds it
    /// unknown recounts ([`Space::recount_step`]).
    fn stored_usage(&self) -> Option<Usage> {
        self.get(USAGE).and_then(|b| decode_usage(&b))
    }

    fn set_usage(&mut self, u: Usage) -> bool {
        let key = self.full_key(USAGE);
        self.env.set(&key, &encode_usage(u))
    }

    /// Apply `f` to the recorded usage. Nothing is written while it is
    /// unknown: the next write recounts it.
    fn adjust_usage(&mut self, f: impl FnOnce(Usage) -> Usage) {
        if let Some(u) = self.stored_usage() {
            self.set_usage(f(u));
        }
    }

    #[cfg(test)]
    pub fn set_usage_for_test(&mut self, u: Usage) {
        assert!(self.set_usage(u));
    }

    /// Record `u` as both the usage and the result of a finished recount:
    /// a store that a recount found full, so the next refused write does
    /// not recount it again.
    #[cfg(test)]
    pub fn confirm_usage_for_test(&mut self, u: Usage) {
        assert!(self.set_usage(u));
        assert!(self.set_recount_state(RECOUNT_DONE, u));
    }

    #[cfg(test)]
    pub fn forget_usage_for_test(&mut self) {
        let key = self.full_key(USAGE);
        assert!(self.env.remove(&key));
    }

    /// What the store holds by [`Space::known_keys`], counted over as many
    /// calls as it takes: `Ok(usage)` once a recount has covered every key
    /// (it is also recorded), `Err(Busy)` while one is still under way.
    pub fn recount(&mut self) -> Result<Usage, Failure> {
        self.recount_step().ok_or_else(|| {
            fail(
                FailureCode::Busy,
                "this app's storage use is being recounted; retry",
            )
        })
    }

    /// Store `value` under `rel`, within the origin's budget. The usage
    /// record is written first: if the value write then fails, the record
    /// over-counts, which only ever costs capacity until a recount.
    pub fn put(&mut self, rel: &str, value: &[u8]) -> Result<(), Failure> {
        self.put_within(rel, value, 0, 0)
    }

    /// [`Space::put`] for the bookkeeping of a deletion, which may use the
    /// [`RESERVED_KEYS`]/[`RESERVED_BYTES`] headroom past the budget.
    pub fn put_for_delete(&mut self, rel: &str, value: &[u8]) -> Result<(), Failure> {
        self.put_within(rel, value, RESERVED_KEYS, RESERVED_BYTES)
    }

    fn put_within(
        &mut self,
        rel: &str,
        value: &[u8],
        extra_keys: u64,
        extra_bytes: u64,
    ) -> Result<(), Failure> {
        let key = self.full_key(rel);
        let old = self.fetch(&key);
        let old_size = old.as_ref().map_or(0, |v| (key.len() + v.len()) as u64);
        let with_write = |before: Usage| Usage {
            keys: before.keys.saturating_add(u64::from(old.is_none())),
            bytes: before
                .bytes
                .saturating_add((key.len() + value.len()) as u64)
                .saturating_sub(old_size),
        };
        // A write that does not grow the store is never refused, so a user
        // over the budget can still shrink what is stored.
        let refused = |before: Usage, after: Usage| {
            let grows = after.keys > before.keys || after.bytes > before.bytes;
            grows
                && (after.keys > MAX_ORIGIN_KEYS + extra_keys
                    || after.bytes > MAX_ORIGIN_BYTES + extra_bytes)
        };
        let mut before = match self.stored_usage() {
            Some(u) => u,
            None => self.recount()?,
        };
        let mut after = with_write(before);
        if refused(before, after) {
            // The record can run high: a write it counted that the host then
            // refused, a key that cannot be read and so cannot be measured
            // when removed. Before refusing, count what is really stored, so
            // a record that drifted never blocks this origin for good. A
            // recount that already found exactly this is not repeated.
            if self.recount_state() != Some((RECOUNT_DONE, before)) {
                before = self.recount()?;
                after = with_write(before);
            }
            if refused(before, after) {
                return Err(fail(
                    FailureCode::CapReached,
                    "this app's storage budget is full",
                ));
            }
        }
        if !self.set_usage(after) {
            return Err(fail(FailureCode::Internal, "the host refused the write"));
        }
        if !self.env.set(&key, value) {
            self.set_usage(before);
            return Err(fail(FailureCode::Internal, "the host refused the write"));
        }
        Ok(())
    }

    /// Remove `rel` if present. The usage record is updated after the
    /// removal, so a failed update over-counts rather than under-counts.
    ///
    /// `Ok` means the key is gone. A key that reads as absent is removed
    /// anyway (the read may have failed), and a refused removal is an error
    /// unless the key really is absent.
    pub fn del(&mut self, rel: &str) -> Result<(), Failure> {
        let key = self.full_key(rel);
        let Some(old) = self.fetch(&key) else {
            // The host answers "not found" both for an absent key and for a
            // removal it failed, so a refusal is retried: a key that keeps
            // failing to read may still be there. Three attempts, as for a
            // key known present (`del_written`). What remains is a limit of
            // the host API: a key that cannot be read AND whose removal is
            // refused every time is indistinguishable from an absent one.
            if self.env.remove(&key) || self.env.remove(&key) || self.env.remove(&key) {
                // It was there, unreadable: one key fewer.
                self.forget_unsized_key();
            } else if self.fetch(&key).is_some() {
                return Err(fail(FailureCode::Internal, "the host refused the delete"));
            }
            return Ok(());
        };
        if !self.env.remove(&key) {
            return Err(fail(FailureCode::Internal, "the host refused the delete"));
        }
        self.forget_key((key.len() + old.len()) as u64);
        Ok(())
    }

    /// Remove a key this operation itself wrote, so it is known present
    /// whatever a read says: `Ok` only once the host confirms a removal
    /// (a read that fails would otherwise make a refused removal look like
    /// an absent key, and the key would stay while the caller reports it
    /// gone).
    pub fn del_written(&mut self, rel: &str) -> Result<(), Failure> {
        let key = self.full_key(rel);
        let old = self.fetch(&key);
        if !(self.env.remove(&key) || self.env.remove(&key) || self.env.remove(&key)) {
            return Err(fail(FailureCode::Internal, "the host refused the delete"));
        }
        match old {
            Some(old) => self.forget_key((key.len() + old.len()) as u64),
            None => self.forget_unsized_key(),
        }
        Ok(())
    }

    /// Remove `rel` whether or not it reads; `true` only if the host removed
    /// something (the key was there, readable or not). The read is for the
    /// usage record only; the removal does not depend on it.
    pub fn remove_if_present(&mut self, rel: &str) -> bool {
        let key = self.full_key(rel);
        let old = self.fetch(&key);
        let removed = self.env.remove(&key) || self.env.remove(&key);
        if removed {
            match old {
                Some(old) => self.forget_key((key.len() + old.len()) as u64),
                None => self.forget_unsized_key(),
            }
        }
        removed
    }

    /// Account for a removed key of `size` bytes (key plus value).
    fn forget_key(&mut self, size: u64) {
        self.adjust_usage(|u| Usage {
            keys: u.keys.saturating_sub(1),
            bytes: u.bytes.saturating_sub(size),
        });
    }

    /// Account for a key removed (or about to be replaced) whose value
    /// could not be read. The key count is exact; its bytes cannot be known
    /// (the host reports an unreadable value as absent, and nothing records
    /// sizes elsewhere), so they stay counted.
    ///
    /// The usage record is therefore not exact. It runs high here and when
    /// a counted write is then refused, and it can be lost altogether (an
    /// unreadable record). Neither is allowed to stick: a write that finds
    /// the record unknown, or that would be refused against it, recounts
    /// what is stored first ([`Space::recount_step`]).
    fn forget_unsized_key(&mut self) {
        self.adjust_usage(|u| Usage {
            keys: u.keys.saturating_sub(1),
            bytes: u.bytes,
        });
    }

    /// `(visited, usage so far)` of a recount, `visited == RECOUNT_DONE`
    /// once one finished.
    fn recount_state(&self) -> Option<(u64, Usage)> {
        let b = self.get(RECOUNT)?;
        let b = <[u8; 24]>::try_from(b.as_slice()).ok()?;
        let visited = u64::from_le_bytes(b[..8].try_into().expect("8 bytes"));
        Some((visited, decode_usage(&b[8..])?))
    }

    fn set_recount_state(&mut self, visited: u64, u: Usage) -> bool {
        let mut b = [0u8; 24];
        b[..8].copy_from_slice(&visited.to_le_bytes());
        b[8..].copy_from_slice(&encode_usage(u));
        let key = self.full_key(RECOUNT);
        self.env.set(&key, &b)
    }

    /// Every key this origin can name, in a fixed order, each with whether
    /// it must exist: the bookkeeping, every index and its marker, the
    /// prompts, each identity's record and deletion marker, and every
    /// listed item with its pending marker. Keys nothing lists any more
    /// (bytes left behind by a deletion that could not read their list)
    /// cannot be named and are not counted: a recount never counts more
    /// than it can show is stored.
    fn known_keys(&self) -> Vec<(String, bool)> {
        let mut out: Vec<(String, bool)> = [
            GENERATION,
            GENERATION_COPY,
            PROMPT_SEQ,
            EXPORT_GRANT,
            EXPORT_SESSION,
        ]
        .iter()
        .map(|rel| (rel.to_string(), false))
        .collect();
        // An index's ids, recording the index and its marker. One that
        // cannot be read must exist (its marker says it was written) but
        // lists nothing countable.
        let listed = |out: &mut Vec<(String, bool)>, rel: &str| {
            out.push((index_marker_rel(rel), false));
            match self.index(rel) {
                Ok((generation, ids)) => {
                    out.push((rel.to_string(), generation != 0));
                    ids
                }
                Err(_) => {
                    out.push((rel.to_string(), true));
                    BTreeSet::new()
                }
            }
        };
        for id in listed(&mut out, PROMPT_INDEX) {
            if let Ok(b) = <[u8; 4]>::try_from(id.as_slice()) {
                out.push((prompt_rel(u32::from_be_bytes(b)), true));
            }
        }
        let mut owners = vec![None];
        for id in listed(&mut out, IDENTITY_INDEX) {
            if let Ok(a) = <[u8; 24]>::try_from(id.as_slice()) {
                let addr = Addr(a);
                out.push((identity_rel(&addr), true));
                out.push((deleted_rel(&addr), false));
                owners.push(Some(addr));
            }
        }
        for owner in owners {
            for kind in ALL_KINDS.iter().filter(|k| shape(**k).0 == owner.is_some()) {
                for id in listed(&mut out, &index_rel(*kind, owner.as_ref())) {
                    let item = ItemRef {
                        kind: *kind,
                        owner,
                        id,
                    };
                    out.push((pending_item_rel(&item), false));
                    out.push((item_rel(&item), true));
                }
            }
        }
        out
    }

    /// Count what this origin stores, [`RECOUNT_STEP`] keys per call:
    /// `Some(usage)` once every key in [`Space::known_keys`] is counted, and
    /// the usage record is then set to it. A key that must exist but cannot
    /// be read counts as [`UNREADABLE_VALUE_BYTES`]; so the result never
    /// counts less than what reads.
    ///
    /// Idempotent: a recount of an unchanged store gives the same usage. A
    /// store that changes between the calls of one recount is counted
    /// approximately, which only lasts until the next recount.
    fn recount_step(&mut self) -> Option<Usage> {
        let keys = self.known_keys();
        let (start, mut acc) = match self.recount_state() {
            Some((visited, u)) if visited != RECOUNT_DONE && visited as usize <= keys.len() => {
                (visited as usize, u)
            }
            _ => (0, Usage::default()),
        };
        let end = (start + RECOUNT_STEP).min(keys.len());
        for (rel, must_exist) in &keys[start..end] {
            let key = self.full_key(rel);
            let size = match self.fetch(&key) {
                Some(v) => (key.len() + v.len()) as u64,
                None if *must_exist => key.len() as u64 + UNREADABLE_VALUE_BYTES,
                None => continue,
            };
            acc.keys += 1;
            acc.bytes += size;
        }
        if end < keys.len() {
            self.set_recount_state(end as u64, acc);
            return None;
        }
        self.set_usage(acc);
        self.set_recount_state(RECOUNT_DONE, acc);
        Some(acc)
    }

    /// Write `body` at `rel` as a new record over a stored value that cannot
    /// be used: one the host cannot read, or one that does not decode
    /// (`usable` says which bodies decode). A usable stored value is a
    /// conflict, as [`Space::write_if`] with `expected = 0` reports it.
    ///
    /// Callers use this only where the record is the user's own and
    /// rebuildable from what they supply (an item, or an identity whose
    /// keys they are importing: same address, same seeds), so replacing an
    /// unusable value loses nothing. An unreadable value is removed first,
    /// so the key is counted once rather than as a second key.
    pub fn write_over_unusable(
        &mut self,
        rel: &str,
        body: &[u8],
        usable: impl Fn(&[u8]) -> bool,
    ) -> Result<u64, Failure> {
        let key = self.full_key(rel);
        let floor = match self.fetch(&key) {
            Some(stored) => match decode_versioned(&stored) {
                Some((g, b)) if usable(b) => {
                    return Err(fail(
                        FailureCode::Conflict { current_gen: g },
                        "stale generation",
                    ));
                }
                Some((g, _)) => g,
                None => 0,
            },
            None => {
                if self.env.remove(&key) || self.env.remove(&key) {
                    self.forget_unsized_key();
                }
                0
            }
        };
        let generation = self.next_generation(floor)?;
        self.put(rel, &encode_versioned(generation, body))?;
        Ok(generation)
    }

    /// The stored `(generation, body)` at `rel`.
    pub fn read(&self, rel: &str) -> Result<Option<(u64, Vec<u8>)>, Failure> {
        match self.get(rel) {
            None => Ok(None),
            Some(bytes) => decode_versioned(&bytes)
                .map(|(g, b)| Some((g, b.to_vec())))
                .ok_or_else(|| fail(FailureCode::Internal, "a stored record is unreadable")),
        }
    }

    /// The counter, as the larger of its two copies.
    fn counter(&self) -> u64 {
        [GENERATION, GENERATION_COPY]
            .iter()
            .filter_map(|rel| self.get(rel))
            .filter_map(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
            .map(u64::from_le_bytes)
            .max()
            .unwrap_or(0)
    }

    /// Take the next generation, above `floor` (the generation of the record
    /// about to be replaced) too, so a counter whose copies both read as
    /// absent still never hands a record a generation it has had.
    ///
    /// Fails closed unless both copies hold the new value: then whichever
    /// copy stays readable reads as the latest. (Accepting one write would
    /// leave the latest value only in a copy that may be the unreadable one,
    /// and the next call would hand out the same generation again.)
    pub fn next_generation(&mut self, floor: u64) -> Result<u64, Failure> {
        let next = self
            .counter()
            .max(floor)
            .checked_add(1)
            .ok_or_else(|| fail(FailureCode::Internal, "generation counter exhausted"))?;
        let bytes = next.to_le_bytes();
        self.put(GENERATION, &bytes)?;
        self.put(GENERATION_COPY, &bytes)?;
        Ok(next)
    }

    /// Write `body` at `rel` under a new generation, if the current
    /// generation is `expected` (0 = absent). Returns the new generation.
    pub fn write_if(&mut self, rel: &str, expected: u64, body: &[u8]) -> Result<u64, Failure> {
        let current = self.read(rel)?.map_or(0, |(g, _)| g);
        if current != expected {
            return Err(fail(
                FailureCode::Conflict {
                    current_gen: current,
                },
                "stale generation",
            ));
        }
        let generation = self.next_generation(current)?;
        self.put(rel, &encode_versioned(generation, body))?;
        Ok(generation)
    }

    /// The ids an index record lists, and its generation (0 = absent).
    ///
    /// An index that reads as absent while its marker says it was written is
    /// unreadable, not empty: `Busy`, so no caller rebuilds it from nothing.
    pub fn index(&self, rel: &str) -> Result<(u64, BTreeSet<Vec<u8>>), Failure> {
        match self.read(rel)? {
            None => {
                if self.get(&index_marker_rel(rel)).as_deref() == Some(MARKER_LIVE) {
                    return Err(fail(
                        FailureCode::Busy,
                        "an index record could not be read; retry",
                    ));
                }
                Ok((0, BTreeSet::new()))
            }
            Some((g, body)) => {
                let ids: Vec<serde_bytes::ByteBuf> = freenet_mail_protocol::from_cbor(&body)
                    .map_err(|_| fail(FailureCode::Internal, "an index record is unreadable"))?;
                Ok((g, ids.into_iter().map(|b| b.into_vec()).collect()))
            }
        }
    }

    /// Whether the index at `rel` is unreadable: written once (its marker
    /// says so) but reading as absent.
    pub fn index_unreadable(&self, rel: &str) -> bool {
        matches!(self.index(rel), Err(f) if f.code == FailureCode::Busy)
    }

    /// Forget an unreadable index, so the set it held can be built again.
    /// Refused while the index reads: this never drops a readable list.
    /// Its records stay stored; nothing here can find them again (nothing
    /// lists the host's keys), so they come back by being written again.
    pub fn reset_index(&mut self, rel: &str) -> Result<(), Failure> {
        if !self.index_unreadable(rel) {
            return Err(fail(
                FailureCode::Refused,
                "this index can be read; there is nothing to repair",
            ));
        }
        self.del(rel)?;
        self.del(&index_marker_rel(rel))
    }

    /// Write an index (generation 0 = absent: create it first), keeping its
    /// existence marker in step: `p` while a new index is being created,
    /// `l` once it was written.
    ///
    /// A record that lists anything is only ever written under `l`, and the
    /// only record written under `p` is the empty list. So whichever of the
    /// two keys fails to read, the index never lists an entry that is not
    /// live (a record under `p` is empty), and never reads a live list as
    /// empty (`l` beside an absent record is `Busy`).
    ///
    /// An emptied index keeps its record, as the empty list, rather than
    /// being removed. Removing it meant setting `p` first and `l` back if the
    /// removal was refused, and both could be refused: the old entries then
    /// stayed under `p`, read as empty while the record failed to read and as
    /// live once it read again, after their items' markers had been dropped
    /// (fault-harness seeds 765 and 934). Only an identity's deletion
    /// removes its indexes (`delete_step`), and [`Space::reset_index`].
    fn write_index(
        &mut self,
        rel: &str,
        generation: u64,
        ids: &BTreeSet<Vec<u8>>,
    ) -> Result<(), Failure> {
        let marker = index_marker_rel(rel);
        if generation == 0 && ids.is_empty() {
            return Ok(());
        }
        let list: Vec<serde_bytes::ByteBuf> = ids
            .iter()
            .map(|i| serde_bytes::ByteBuf::from(i.clone()))
            .collect();
        let body =
            freenet_mail_protocol::to_cbor(&list).map_err(|e| fail(FailureCode::Internal, e))?;
        if generation == 0 {
            // Just created under `l` by this op (delegate messages run one at
            // a time), so its generation is known and is not read back: a
            // record that fails to read straight after being written must
            // not fail the write.
            let created = self.create_index(rel, &marker)?;
            let next = self.next_generation(created)?;
            return self.put(rel, &encode_versioned(next, &body));
        }
        // It exists (it was just read), so `l` is true before and after the
        // write. Set first, so nothing can fail after the write. A record
        // that could be found under `p` is the empty list, so setting `l`
        // over it revives nothing.
        if self.get(&marker).as_deref() != Some(MARKER_LIVE) {
            self.put_for_delete(&marker, MARKER_LIVE)?;
        }
        self.write_if(rel, generation, &body).map(|_| ())
    }

    /// Create the index at `rel` as the empty list: `p`, the record, then
    /// `l`. Returns its generation. If `l` cannot be set the error stands
    /// and the empty record stays under `p`, where it reads as empty either
    /// way, so the next write finishes the job.
    fn create_index(&mut self, rel: &str, marker: &str) -> Result<u64, Failure> {
        let empty = freenet_mail_protocol::to_cbor(&Vec::<serde_bytes::ByteBuf>::new())
            .map_err(|e| fail(FailureCode::Internal, e))?;
        self.put(marker, MARKER_PENDING)?;
        let generation = self.write_if(rel, 0, &empty)?;
        let live = |sp: &mut Self| sp.put_for_delete(marker, MARKER_LIVE);
        live(self).or_else(|_| live(self))?;
        Ok(generation)
    }

    /// Add `id` to the index at `rel`, refusing past `cap` entries.
    pub fn index_add(&mut self, rel: &str, id: &[u8], cap: usize) -> Result<(), Failure> {
        let (generation, mut ids) = self.index(rel)?;
        if ids.contains(id) {
            return Ok(());
        }
        if ids.len() >= cap {
            return Err(fail(FailureCode::CapReached, "too many items of this kind"));
        }
        ids.insert(id.to_vec());
        self.write_index(rel, generation, &ids)
    }

    pub fn index_remove(&mut self, rel: &str, id: &[u8]) -> Result<(), Failure> {
        self.index_remove_many(rel, &[id.to_vec()])
    }

    /// Remove several ids with one index write.
    pub fn index_remove_many(&mut self, rel: &str, remove: &[Vec<u8>]) -> Result<(), Failure> {
        let (generation, mut ids) = self.index(rel)?;
        let before = ids.len();
        for id in remove {
            ids.remove(id);
        }
        if ids.len() != before {
            self.write_index(rel, generation, &ids)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::mem::MemEnv;

    #[test]
    fn origins_and_kinds_never_share_a_key() {
        let mut env = MemEnv::default();
        let a = Addr([3; 24]);
        let item = |kind| ItemRef {
            kind,
            owner: Some(a),
            id: vec![4; 16],
        };
        let one = Space::new(&mut env, Origin([1; 32])).full_key(&item_rel(&item(ItemKind::Draft)));
        let two = Space::new(&mut env, Origin([2; 32])).full_key(&item_rel(&item(ItemKind::Draft)));
        assert_ne!(one, two);
        let rels: BTreeSet<String> = [
            ItemKind::Draft,
            ItemKind::Sent,
            ItemKind::Kept,
            ItemKind::Archived,
            ItemKind::Flags,
        ]
        .map(|k| item_rel(&item(k)))
        .into();
        assert_eq!(rels.len(), 5);
        let contact = ItemRef {
            kind: ItemKind::Contact,
            owner: None,
            id: a.0.to_vec(),
        };
        assert_ne!(item_rel(&contact), identity_rel(&a));
    }

    #[test]
    fn generations_never_repeat_and_fail_closed() {
        let mut env = MemEnv::default();
        let mut s = Space::new(&mut env, Origin([1; 32]));
        assert_eq!(s.next_generation(0), Ok(1));
        assert_eq!(s.next_generation(0), Ok(2));
        // Never at or below the record being replaced.
        assert_eq!(s.next_generation(10), Ok(11));
        assert_eq!(s.next_generation(0), Ok(12));
        s.env.set(b"unrelated", b"");
        let mut env2 = MemEnv {
            fail_writes: true,
            ..MemEnv::default()
        };
        assert!(
            Space::new(&mut env2, Origin([1; 32]))
                .next_generation(0)
                .is_err()
        );
    }

    /// A host whose reads of `rel` (in origin `[1; 32]`) always fail, as a
    /// file it cannot read or decrypt does.
    fn blind_to(rel: &str) -> MemEnv {
        let key = format!("{}{rel}", namespace(&Origin([1; 32])));
        MemEnv {
            faults: Some(crate::env::mem::Faults::blind(&key)),
            ..MemEnv::default()
        }
    }

    /// One copy of the counter staying unreadable never makes it restart
    /// (a restarted counter hands out generations already used).
    #[test]
    fn an_unreadable_counter_copy_does_not_restart_generations() {
        let mut env = MemEnv::default();
        for _ in 0..5 {
            Space::new(&mut env, Origin([1; 32]))
                .next_generation(0)
                .unwrap();
        }
        for copy in [GENERATION, GENERATION_COPY] {
            let mut blind = blind_to(copy);
            blind.secrets = env.secrets.clone();
            let next = Space::new(&mut blind, Origin([1; 32])).next_generation(0);
            assert_eq!(next, Ok(6), "with {copy} unreadable");
        }
    }

    /// An index that stays unreadable is never rewritten from scratch: an
    /// add would otherwise write a fresh index holding only the new id and
    /// unlist everything else.
    #[test]
    fn an_unreadable_index_is_not_rebuilt_from_nothing() {
        let mut env = MemEnv::default();
        {
            let mut s = Space::new(&mut env, Origin([1; 32]));
            s.index_add("ix/t", b"a", 8).unwrap();
            s.index_add("ix/t", b"b", 8).unwrap();
        }
        let mut blind = blind_to("ix/t");
        blind.secrets = env.secrets.clone();
        let mut s = Space::new(&mut blind, Origin([1; 32]));
        let err = s.index_add("ix/t", b"c", 8).unwrap_err();
        assert_eq!(err.code, FailureCode::Busy);
        assert!(s.index("ix/t").is_err(), "an unreadable index is not empty");
        blind.faults = None;
        let (_, ids) = Space::new(&mut blind, Origin([1; 32]))
            .index("ix/t")
            .unwrap();
        assert_eq!(ids.len(), 2, "both entries are still listed");
        // Emptied and removed, it is absent again, not unreadable.
        let mut s = Space::new(&mut blind, Origin([1; 32]));
        s.index_remove_many("ix/t", &[b"a".to_vec(), b"b".to_vec()])
            .unwrap();
        assert_eq!(s.index("ix/t").unwrap().1.len(), 0);
        s.index_add("ix/t", b"d", 8).unwrap();
    }

    #[test]
    fn usage_counts_every_key_and_byte_and_shrinks_on_delete() {
        let mut env = MemEnv::default();
        let mut s = Space::new(&mut env, Origin([1; 32]));
        s.put("a", b"12345").unwrap();
        s.put("b", b"1").unwrap();
        let u = s.usage();
        assert_eq!(u.keys, 2);
        let ns = namespace(&Origin([1; 32])).len() as u64;
        assert_eq!(u.bytes, (ns + 1 + 5) + (ns + 1 + 1));
        s.put("a", b"1").unwrap();
        assert_eq!(s.usage().keys, 2);
        assert_eq!(s.usage().bytes, 2 * (ns + 2));
        s.del("a").unwrap();
        s.del("missing").unwrap();
        assert_eq!(
            s.usage(),
            Usage {
                keys: 1,
                bytes: ns + 2
            }
        );
    }

    fn blind(env: &mut MemEnv, rel: &str) {
        let key = String::from_utf8(Space::new(env, Origin([1; 32])).full_key(rel)).unwrap();
        env.faults = Some(crate::env::mem::Faults::blind(&key));
    }

    /// A removed key that could not be read leaves the key count; its bytes
    /// cannot be known and stay counted (an upper bound, never under).
    #[test]
    fn removing_an_unreadable_key_counts_one_key_fewer() {
        let mut env = MemEnv::default();
        {
            let mut s = Space::new(&mut env, Origin([1; 32]));
            s.put("a", b"12345").unwrap();
            s.put("b", b"1").unwrap();
            s.put("c", b"1").unwrap();
        }
        let before = Space::new(&mut env, Origin([1; 32])).usage();
        blind(&mut env, "a");
        Space::new(&mut env, Origin([1; 32])).del("a").unwrap();
        blind(&mut env, "c");
        assert!(Space::new(&mut env, Origin([1; 32])).remove_if_present("c"));
        env.faults = None;
        let s = Space::new(&mut env, Origin([1; 32]));
        assert!(s.get("a").is_none() && s.get("c").is_none());
        let after = s.usage();
        assert_eq!(after.keys, before.keys - 2);
        assert_eq!(after.bytes, before.bytes, "unknown sizes stay counted");
    }

    /// Writing over a value that cannot be read counts its key once, not as
    /// a second key.
    #[test]
    fn replacing_an_unreadable_value_counts_its_key_once() {
        let mut env = MemEnv::default();
        {
            let mut s = Space::new(&mut env, Origin([1; 32]));
            s.write_if("a", 0, b"12345").unwrap();
        }
        let before = Space::new(&mut env, Origin([1; 32])).usage();
        blind(&mut env, "a");
        let g = Space::new(&mut env, Origin([1; 32]))
            .write_over_unusable("a", b"x", |_| true)
            .unwrap();
        env.faults = None;
        let s = Space::new(&mut env, Origin([1; 32]));
        assert_eq!(s.read("a").unwrap(), Some((g, b"x".to_vec())));
        assert_eq!(s.usage().keys, before.keys);
    }

    /// A stored value that does not decode is replaced exactly (its size is
    /// known), and a usable one is a conflict.
    #[test]
    fn a_corrupt_value_is_replaced_and_a_usable_one_is_not() {
        let mut env = MemEnv::default();
        let mut s = Space::new(&mut env, Origin([1; 32]));
        let old = s.write_if("a", 0, b"bad").unwrap();
        let before = s.usage();
        let usable = |b: &[u8]| b == b"good";
        let g = s.write_over_unusable("a", b"good", usable).unwrap();
        assert!(g > old, "never reuses a generation");
        let after = s.usage();
        assert_eq!(after.keys, before.keys);
        assert_eq!(
            after.bytes + encode_versioned(old, b"bad").len() as u64,
            before.bytes + encode_versioned(g, b"good").len() as u64
        );
        assert_eq!(
            s.write_over_unusable("a", b"good", usable)
                .unwrap_err()
                .code,
            FailureCode::Conflict { current_gen: g }
        );
    }

    #[test]
    fn the_budget_refuses_and_leaves_the_store_unchanged() {
        let mut env = MemEnv::default();
        let mut s = Space::new(&mut env, Origin([1; 32]));
        // Full, as a finished recount found it (a record that merely says
        // full is recounted first: `a_drifted_usage_record_is_recounted`).
        s.confirm_usage_for_test(Usage {
            keys: MAX_ORIGIN_KEYS,
            bytes: 0,
        });
        assert_eq!(
            s.put("new", b"x").unwrap_err().code,
            FailureCode::CapReached
        );
        assert_eq!(s.get("new"), None);
    }

    #[test]
    fn indexes_are_sets_with_caps_and_read_empty_once_emptied() {
        let mut env = MemEnv::default();
        let mut s = Space::new(&mut env, Origin([1; 32]));
        s.index_add("ix/t", b"b", 2).unwrap();
        s.index_add("ix/t", b"a", 2).unwrap();
        s.index_add("ix/t", b"a", 2).unwrap();
        assert_eq!(
            s.index_add("ix/t", b"c", 2).unwrap_err().code,
            FailureCode::CapReached
        );
        let (_, ids) = s.index("ix/t").unwrap();
        assert_eq!(
            ids.into_iter().collect::<Vec<_>>(),
            vec![b"a".to_vec(), b"b".to_vec()]
        );
        s.index_remove("ix/t", b"a").unwrap();
        s.index_remove("ix/t", b"b").unwrap();
        // An emptied index keeps its record, as the empty list, still live:
        // it reads as empty, not as an unreadable list (`Busy`).
        let (generation, ids) = s.index("ix/t").unwrap();
        assert!(generation > 0 && ids.is_empty());
        assert_eq!(
            s.get(&index_marker_rel("ix/t")).as_deref(),
            Some(MARKER_LIVE)
        );
        // And it fills again.
        s.index_add("ix/t", b"c", 2).unwrap();
        assert_eq!(s.index("ix/t").unwrap().1.len(), 1);
    }

    /// Emptying an index under refused writes and removals never leaves a
    /// record that reads differently depending on whether it can be read:
    /// it must list the same either way, or be `Busy` while unreadable.
    /// (Removing the record, as emptying once did, could leave the old
    /// entries under `p`: listed while readable, empty while not.)
    #[test]
    fn an_emptied_index_reads_the_same_whether_its_record_reads_or_not() {
        use crate::env::mem::{FaultOp, Faults, Rule};
        let mut env = MemEnv::default();
        Space::new(&mut env, Origin([1; 32]))
            .index_add("ix/t", b"a", 4)
            .unwrap();
        // From here: the record's removal and the marker's next write but
        // one are refused (a removal sets the marker, then sets it back).
        let mut faults = Faults::rule(FaultOp::RemoveFail, "ix/t", 1);
        faults.rules.push(Rule {
            op: FaultOp::SetFail,
            key_contains: "xm/ix/t".into(),
            nth: 2,
        });
        env.faults = Some(faults);
        let _ = Space::new(&mut env, Origin([1; 32])).index_remove("ix/t", b"a");
        env.faults = None;
        let readable = Space::new(&mut env, Origin([1; 32]))
            .index("ix/t")
            .map(|(_, ids)| ids);
        let record = Space::new(&mut env, Origin([1; 32])).full_key("ix/t");
        env.faults = Some(Faults::blind(&String::from_utf8(record).unwrap()));
        let unreadable = Space::new(&mut env, Origin([1; 32]))
            .index("ix/t")
            .map(|(_, ids)| ids);
        match unreadable {
            Err(f) => assert_eq!(f.code, FailureCode::Busy),
            Ok(ids) => assert_eq!(Ok(ids), readable),
        }
    }

    /// Whichever of an index's two keys fails to read, the index never
    /// lists an entry its writer did not commit. A create whose marker
    /// cannot be set to `l` leaves only the empty list under `p`, and an
    /// index is emptied by writing the empty list, never by a removal that
    /// could be refused half-way (fault-harness seeds 765 and 934 left the
    /// old entries under `p`).
    #[test]
    fn a_record_under_a_pending_marker_never_lists_an_entry() {
        use crate::env::mem::{FaultOp, Faults, Rule};
        // The marker's writes are `p` (call 1), then `l` and its retry
        // (calls 2 and 3): refuse both `l`s.
        // (Distinct spellings of the key: each rule counts its own matches.)
        let mut faults = Faults::rule(FaultOp::SetFail, "xm/ix/t", 2);
        let rule = |op, key: &str, nth| Rule {
            op,
            key_contains: key.into(),
            nth,
        };
        faults.rules.push(rule(FaultOp::SetFail, "/xm/ix/t", 3));
        // Removals of the record are refused too: a create that undid itself
        // by removing what it wrote (as this once did) is left with it.
        for (key, nth) in [("ix/t", 1), ("/ix/t", 2), ("1/ix/t", 3)] {
            faults.rules.push(rule(FaultOp::RemoveFail, key, nth));
        }
        let mut env = MemEnv {
            faults: Some(faults),
            ..MemEnv::default()
        };
        assert!(
            Space::new(&mut env, Origin([1; 32]))
                .index_add("ix/t", b"a", 4)
                .is_err()
        );
        env.faults = None;
        let lists = |env: &mut MemEnv| {
            Space::new(env, Origin([1; 32]))
                .index("ix/t")
                .map(|(_, ids)| ids.len())
        };
        // Under `p`, with the marker read: nothing listed.
        assert_eq!(lists(&mut env), Ok(0));
        // With the marker unreadable (it reads as absent), the record is
        // read as it is: still nothing, since only the empty list was
        // written under `p`.
        let marker = Space::new(&mut env, Origin([1; 32])).full_key(&index_marker_rel("ix/t"));
        let saved = env.secrets.remove(&marker).unwrap();
        assert_eq!(lists(&mut env), Ok(0));
        // With the record unreadable instead: nothing either.
        env.secrets.insert(marker, saved);
        let record = Space::new(&mut env, Origin([1; 32])).full_key("ix/t");
        env.faults = Some(Faults::blind(&String::from_utf8(record).unwrap()));
        assert_eq!(lists(&mut env), Ok(0));
        // The next add finishes the job: listed, under `l`.
        env.faults = None;
        Space::new(&mut env, Origin([1; 32]))
            .index_add("ix/t", b"a", 4)
            .unwrap();
        assert_eq!(lists(&mut env), Ok(1));
    }

    #[test]
    fn a_stale_index_write_is_refused() {
        let mut env = MemEnv::default();
        let mut s = Space::new(&mut env, Origin([1; 32]));
        s.index_add("ix/t", b"a", 9).unwrap();
        let (g, ids) = s.index("ix/t").unwrap();
        s.index_add("ix/t", b"b", 9).unwrap();
        // A writer still holding the first generation loses.
        assert!(matches!(
            s.write_index("ix/t", g, &ids).unwrap_err().code,
            FailureCode::Conflict { .. }
        ));
    }

    #[test]
    fn envelope_round_trips_and_rejects_garbage() {
        let enc = encode_versioned(42, b"body");
        assert_eq!(decode_versioned(&enc), Some((42, &b"body"[..])));
        assert_eq!(decode_versioned(&[9; 20]), None);
        assert_eq!(decode_versioned(&[1, 2]), None);
    }

    /// A host whose reads of one key keep failing.
    struct Blind(MemEnv);

    impl Env for Blind {
        fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
            if key.ends_with(b"blind") {
                return None;
            }
            self.0.get(key)
        }
        fn set(&mut self, key: &[u8], value: &[u8]) -> bool {
            self.0.set(key, value)
        }
        fn remove(&mut self, key: &[u8]) -> bool {
            self.0.remove(key)
        }
        fn host_random(&mut self) -> [u8; 32] {
            self.0.host_random()
        }
        fn now_secs(&self) -> Option<u64> {
            None
        }
        fn contract_state(&self, _: &[u8; 32]) -> Option<Vec<u8>> {
            None
        }
    }

    /// A host whose first `misses` reads fail, then read normally.
    struct BlindAtFirst(MemEnv, std::cell::Cell<u32>);

    impl Env for BlindAtFirst {
        fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
            if self.1.get() > 0 {
                self.1.set(self.1.get() - 1);
                return None;
            }
            self.0.get(key)
        }
        fn set(&mut self, key: &[u8], value: &[u8]) -> bool {
            self.0.set(key, value)
        }
        fn remove(&mut self, key: &[u8]) -> bool {
            self.0.remove(key)
        }
        fn host_random(&mut self) -> [u8; 32] {
            self.0.host_random()
        }
        fn now_secs(&self) -> Option<u64> {
            None
        }
        fn contract_state(&self, _: &[u8; 32]) -> Option<Vec<u8>> {
            None
        }
    }

    /// `del` answering `Ok` means the key is gone, even when reads of it
    /// fail: a failed read looks like absence, so it is removed anyway.
    #[test]
    fn a_delete_removes_a_key_whose_reads_fail() {
        let mut env = Blind(MemEnv::default());
        let key = Space::new(&mut env, Origin([1; 32])).full_key("blind");
        env.0.secrets.insert(key.clone(), b"secret".to_vec());
        Space::new(&mut env, Origin([1; 32])).del("blind").unwrap();
        assert!(!env.0.secrets.contains_key(&key));
    }

    /// The read-miss path: the key reads as absent (the read and its
    /// re-read both fail), the host refuses both removals, and a later read
    /// finds the key still there. That is an error, never "already gone":
    /// answering `Ok` would report a deletion that did not happen.
    #[test]
    fn a_refused_delete_of_a_key_that_read_as_absent_is_an_error() {
        let mut env = BlindAtFirst(MemEnv::default(), std::cell::Cell::new(0));
        let key = Space::new(&mut env, Origin([1; 32])).full_key("item");
        env.0.secrets.insert(key.clone(), b"secret".to_vec());
        env.0.fail_keys_containing = Some("item".into());
        // The fetch and its confirming re-read miss; later reads see it.
        env.1.set(2);
        assert!(
            Space::new(&mut env, Origin([1; 32])).del("item").is_err(),
            "a key still there after refused removals is not deleted"
        );
        assert!(env.0.secrets.contains_key(&key));
    }
}
