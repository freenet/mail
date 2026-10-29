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
/// Pending consent prompts per origin; the oldest is refused past this.
pub const MAX_PENDING_PROMPTS: usize = 4;
/// A prompt not answered within this many seconds is refused.
pub const PROMPT_TTL_SECS: u64 = 600;

const ENVELOPE_TAG: u8 = 1;
const HEADER_LEN: usize = 1 + 8;
const USAGE: &str = "mt/usage";
const GENERATION: &str = "mt/gen";

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
        self.env.get(&self.full_key(rel))
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

    /// Store `value` under `rel`, within the origin's budget. The usage
    /// record is written first: if the value write then fails, the record
    /// over-counts, which only ever costs capacity.
    pub fn put(&mut self, rel: &str, value: &[u8]) -> Result<(), Failure> {
        let key = self.full_key(rel);
        let old = self.env.get(&key);
        let before = self.usage();
        let old_size = old.as_ref().map_or(0, |v| (key.len() + v.len()) as u64);
        let after = Usage {
            keys: before.keys + u64::from(old.is_none()),
            bytes: (before.bytes + (key.len() + value.len()) as u64).saturating_sub(old_size),
        };
        if after.keys > MAX_ORIGIN_KEYS || after.bytes > MAX_ORIGIN_BYTES {
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
    pub fn del(&mut self, rel: &str) -> Result<(), Failure> {
        let key = self.full_key(rel);
        let Some(old) = self.env.get(&key) else {
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

    /// The stored `(generation, body)` at `rel`.
    pub fn read(&self, rel: &str) -> Result<Option<(u64, Vec<u8>)>, Failure> {
        match self.get(rel) {
            None => Ok(None),
            Some(bytes) => decode_versioned(&bytes)
                .map(|(g, b)| Some((g, b.to_vec())))
                .ok_or_else(|| fail(FailureCode::Internal, "a stored record is unreadable")),
        }
    }

    /// Take the next generation. Fails closed: if the counter cannot be
    /// written, the next call would hand out the same generation.
    pub fn next_generation(&mut self) -> Result<u64, Failure> {
        let current = self
            .get(GENERATION)
            .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
            .map(u64::from_le_bytes)
            .unwrap_or(0);
        let next = current
            .checked_add(1)
            .ok_or_else(|| fail(FailureCode::Internal, "generation counter exhausted"))?;
        self.put(GENERATION, &next.to_le_bytes())?;
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
        let generation = self.next_generation()?;
        self.put(rel, &encode_versioned(generation, body))?;
        Ok(generation)
    }

    /// The ids an index record lists, and its generation (0 = absent).
    pub fn index(&self, rel: &str) -> Result<(u64, BTreeSet<Vec<u8>>), Failure> {
        match self.read(rel)? {
            None => Ok((0, BTreeSet::new())),
            Some((g, body)) => {
                let ids: Vec<serde_bytes::ByteBuf> = freenet_mail_protocol::from_cbor(&body)
                    .map_err(|_| fail(FailureCode::Internal, "an index record is unreadable"))?;
                Ok((g, ids.into_iter().map(|b| b.into_vec()).collect()))
            }
        }
    }

    fn write_index(
        &mut self,
        rel: &str,
        generation: u64,
        ids: &BTreeSet<Vec<u8>>,
    ) -> Result<(), Failure> {
        if ids.is_empty() {
            return self.del(rel);
        }
        let list: Vec<serde_bytes::ByteBuf> = ids
            .iter()
            .map(|i| serde_bytes::ByteBuf::from(i.clone()))
            .collect();
        let body =
            freenet_mail_protocol::to_cbor(&list).map_err(|e| fail(FailureCode::Internal, e))?;
        self.write_if(rel, generation, &body).map(|_| ())
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
        assert_eq!(s.next_generation(), Ok(1));
        assert_eq!(s.next_generation(), Ok(2));
        s.env.set(b"unrelated", b"");
        let mut env2 = MemEnv {
            fail_writes: true,
            ..MemEnv::default()
        };
        assert!(
            Space::new(&mut env2, Origin([1; 32]))
                .next_generation()
                .is_err()
        );
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
}
