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

/// Keys and bytes an origin holds (its usage record excluded).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub keys: u64,
    pub bytes: u64,
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

    pub fn usage(&self) -> Usage {
        self.get(USAGE)
            .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
            .map(|b| Usage {
                keys: u64::from_le_bytes(b[..8].try_into().expect("8 bytes")),
                bytes: u64::from_le_bytes(b[8..].try_into().expect("8 bytes")),
            })
            .unwrap_or_default()
    }

    fn set_usage(&mut self, u: Usage) -> bool {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&u.keys.to_le_bytes());
        b[8..].copy_from_slice(&u.bytes.to_le_bytes());
        let key = self.full_key(USAGE);
        self.env.set(&key, &b)
    }

    #[cfg(test)]
    pub fn set_usage_for_test(&mut self, u: Usage) {
        assert!(self.set_usage(u));
    }

    /// Store `value` under `rel`, within the origin's budget. The usage
    /// record is written first: if the value write then fails, the record
    /// over-counts, which only ever costs capacity.
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
        let before = self.usage();
        let old_size = old.as_ref().map_or(0, |v| (key.len() + v.len()) as u64);
        let after = Usage {
            keys: before.keys + u64::from(old.is_none()),
            bytes: (before.bytes + (key.len() + value.len()) as u64).saturating_sub(old_size),
        };
        // A write that does not grow the store is never refused, so a user
        // over the budget can still shrink what is stored.
        let grows = after.keys > before.keys || after.bytes > before.bytes;
        if grows
            && (after.keys > MAX_ORIGIN_KEYS + extra_keys
                || after.bytes > MAX_ORIGIN_BYTES + extra_bytes)
        {
            return Err(fail(
                FailureCode::CapReached,
                "this app's storage budget is full",
            ));
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
        let u = self.usage();
        self.set_usage(Usage {
            keys: u.keys.saturating_sub(1),
            bytes: u.bytes.saturating_sub((key.len() + old.len()) as u64),
        });
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
            Some(old) => {
                let u = self.usage();
                self.set_usage(Usage {
                    keys: u.keys.saturating_sub(1),
                    bytes: u.bytes.saturating_sub((key.len() + old.len()) as u64),
                });
            }
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
                Some(old) => {
                    let u = self.usage();
                    self.set_usage(Usage {
                        keys: u.keys.saturating_sub(1),
                        bytes: u.bytes.saturating_sub((key.len() + old.len()) as u64),
                    });
                }
                None => self.forget_unsized_key(),
            }
        }
        removed
    }

    /// Account for a key removed (or about to be replaced) whose value
    /// could not be read. The key count is exact; its bytes cannot be known
    /// (the host reports an unreadable value as absent, and nothing records
    /// sizes elsewhere), so they stay counted. The usage record is an upper
    /// bound throughout ([`Space::put`] over-counts on a failed write too):
    /// the error only ever costs this origin budget, never lets it exceed
    /// one, and arises only from values the host itself failed to read.
    fn forget_unsized_key(&mut self) {
        let u = self.usage();
        self.set_usage(Usage {
            keys: u.keys.saturating_sub(1),
            bytes: u.bytes,
        });
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

    /// Write an index (generation 0 = create it), or remove it when empty,
    /// keeping its existence marker in step. The marker says `p` whenever
    /// the index may legitimately be absent (before its first write lands,
    /// while it is removed), and `l` only once it was written.
    fn write_index(
        &mut self,
        rel: &str,
        generation: u64,
        ids: &BTreeSet<Vec<u8>>,
    ) -> Result<(), Failure> {
        let marker = index_marker_rel(rel);
        if ids.is_empty() {
            if generation == 0 {
                return Ok(());
            }
            self.put_for_delete(&marker, MARKER_PENDING)?;
            if let Err(e) = self.del(rel) {
                // Still there: say so again, or a read that fails later
                // would be taken for an empty index.
                let _ = self.put_for_delete(&marker, MARKER_LIVE);
                return Err(e);
            }
            // Left as `p` if this fails: "may be absent", which is true.
            let _ = self.del(&marker);
            return Ok(());
        }
        let list: Vec<serde_bytes::ByteBuf> = ids
            .iter()
            .map(|i| serde_bytes::ByteBuf::from(i.clone()))
            .collect();
        let body =
            freenet_mail_protocol::to_cbor(&list).map_err(|e| fail(FailureCode::Internal, e))?;
        if generation > 0 {
            // It exists (it was just read), so `l` is true before and after
            // the write. Set first, so nothing can fail after the write.
            if self.get(&marker).as_deref() != Some(MARKER_LIVE) {
                self.put_for_delete(&marker, MARKER_LIVE)?;
            }
            return self.write_if(rel, generation, &body).map(|_| ());
        }
        // Created: `p` until the index is written, then `l`. Not best
        // effort: an index whose marker still said `p` would be taken for
        // empty, and rebuilt from nothing, the first time a read of it
        // failed. If `l` cannot be set, the new index is removed again
        // (removal does not depend on reading it), so an error means
        // "not written".
        self.put(&marker, MARKER_PENDING)?;
        self.write_if(rel, 0, &body)?;
        let live = |sp: &mut Self| sp.put_for_delete(&marker, MARKER_LIVE);
        if let Err(e) = live(self).or_else(|_| live(self)) {
            // Never leave a written index under `p`: once it failed to read
            // it would be taken for empty and rebuilt from nothing. Remove
            // it (confirmed: it was just written), or else keep trying `l`.
            if self.del_written(rel).is_err() {
                let _ = live(self).or_else(|_| live(self));
            }
            return Err(e);
        }
        Ok(())
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
        s.set_usage(Usage {
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
    fn indexes_are_sets_with_caps_and_vanish_when_empty() {
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
        assert_eq!(s.get("ix/t"), None);
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
