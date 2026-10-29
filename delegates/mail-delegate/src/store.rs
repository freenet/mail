//! Key layout, the generation envelope, and caps.
//!
//! Every key is `o/<origin hex>/<kind>/...`, built here from typed ids;
//! callers never send a raw key. Each web-app origin gets its own namespace,
//! so a staging app using this delegate never sees production data, and no
//! app can read another's.
//!
//! Every value is wrapped in `[ENVELOPE_TAG][generation u64 LE][body]`
//! (River's `versioning.rs` layout). Generations come from one counter per
//! origin, so a generation is never reused, even after a delete and
//! re-create: a writer holding a generation from before a delete cannot match
//! the re-created item (the ABA case River documents as a known limitation).

use freenet_mail_protocol::{Addr, ItemKind, ItemRef};

use crate::env::Env;

/// The host's enumeration cap for one delegate, across every prefix
/// (freenet-core's `MAX_REGISTERED_KEYS_PER_SCOPE`). Past it `list` truncates
/// silently, so the store must never get there.
pub const HOST_ENUMERATION_CAP: usize = freenet_migrate::HOST_ENUMERATION_CAP;
/// Most keys this delegate will hold, all origins together. Leaves headroom
/// under the host cap for freenet-migrate's markers and journal.
pub const KEY_BUDGET: usize = 3584;

pub const MAX_IDENTITIES: usize = 16;
pub const MAX_CONTACTS: usize = 2048;
pub const MAX_DRAFTS: usize = 256;
/// Per identity, for each of sent, kept, archived and flags. The delegate-wide
/// [`KEY_BUDGET`] binds first for a heavy user.
pub const MAX_MESSAGES: usize = 4096;
/// Pending consent prompts kept per origin; the oldest is dropped past this.
pub const MAX_PENDING_PROMPTS: usize = 4;

const ENVELOPE_TAG: u8 = 1;
const HEADER_LEN: usize = 1 + 8;

/// The 32-byte web-app contract id a request came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Origin(pub [u8; 32]);

fn hex(bytes: &[u8]) -> String {
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

pub fn identity_prefix(origin: &Origin) -> Vec<u8> {
    format!("{}id/", namespace(origin)).into_bytes()
}

pub fn identity_key(origin: &Origin, addr: &Addr) -> Vec<u8> {
    format!("{}id/{}", namespace(origin), hex(&addr.0)).into_bytes()
}

pub fn generation_key(origin: &Origin) -> Vec<u8> {
    format!("{}mt/gen", namespace(origin)).into_bytes()
}

pub fn prompt_seq_key(origin: &Origin) -> Vec<u8> {
    format!("{}mt/pseq", namespace(origin)).into_bytes()
}

pub fn pending_prefix(origin: &Origin) -> Vec<u8> {
    format!("{}pg/", namespace(origin)).into_bytes()
}

pub fn pending_key(origin: &Origin, prompt_id: u32) -> Vec<u8> {
    format!("{}pg/{prompt_id:08x}", namespace(origin)).into_bytes()
}

pub fn export_grant_key(origin: &Origin) -> Vec<u8> {
    format!("{}gr/export", namespace(origin)).into_bytes()
}

fn kind_tag(kind: ItemKind) -> &'static str {
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

/// The prefix holding every item of `kind` for `owner`.
pub fn item_prefix(origin: &Origin, kind: ItemKind, owner: Option<&Addr>) -> Vec<u8> {
    let owner = owner.map_or_else(|| "-".to_string(), |a| hex(&a.0));
    format!("{}{}/{owner}/", namespace(origin), kind_tag(kind)).into_bytes()
}

pub fn item_key(origin: &Origin, item: &ItemRef) -> Vec<u8> {
    let mut key = item_prefix(origin, item.kind, item.owner.as_ref());
    if item.id.is_empty() {
        key.push(b'-');
    } else {
        key.extend_from_slice(hex(&item.id).as_bytes());
    }
    key
}

/// The id encoded at the end of an item key.
pub fn id_from_key(key: &[u8], prefix_len: usize) -> Option<Vec<u8>> {
    let tail = key.get(prefix_len..)?;
    if tail == b"-" {
        return Some(Vec::new());
    }
    if tail.len() % 2 != 0 {
        return None;
    }
    tail.chunks(2)
        .map(|pair| {
            let s = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(s, 16).ok()
        })
        .collect()
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

/// A stored value that is not a valid envelope.
#[derive(Debug, PartialEq, Eq)]
pub struct Corrupt;

/// The stored `(generation, body)` at `key`; `Err` if present but corrupt.
pub fn read(env: &dyn Env, key: &[u8]) -> Result<Option<(u64, Vec<u8>)>, Corrupt> {
    match env.get(key) {
        None => Ok(None),
        Some(bytes) => decode_versioned(&bytes)
            .map(|(g, b)| Some((g, b.to_vec())))
            .ok_or(Corrupt),
    }
}

/// Take the next generation for `origin`. Fails closed: if the counter
/// cannot be written, the next call would hand out the same generation.
pub fn next_generation(env: &mut dyn Env, origin: &Origin) -> Option<u64> {
    let key = generation_key(origin);
    let current = env
        .get(&key)
        .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0);
    let next = current.checked_add(1)?;
    env.set(&key, &next.to_le_bytes()).then_some(next)
}

/// Whether one more key fits the delegate-wide budget.
pub fn budget_has_room(env: &dyn Env) -> bool {
    env.list(b"").len() < KEY_BUDGET
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::mem::MemEnv;

    fn origin(b: u8) -> Origin {
        Origin([b; 32])
    }

    #[test]
    fn origins_never_share_a_key() {
        let item = ItemRef {
            kind: ItemKind::Contact,
            owner: None,
            id: vec![1; 24],
        };
        assert_ne!(item_key(&origin(1), &item), item_key(&origin(2), &item));
        assert!(item_key(&origin(1), &item).starts_with(namespace(&origin(1)).as_bytes()));
    }

    #[test]
    fn kinds_never_share_a_key() {
        let a = Addr([3; 24]);
        let mut keys = std::collections::BTreeSet::new();
        for kind in [
            ItemKind::Draft,
            ItemKind::Sent,
            ItemKind::Kept,
            ItemKind::Archived,
            ItemKind::Flags,
        ] {
            let item = ItemRef {
                kind,
                owner: Some(a),
                id: vec![4; 16],
            };
            assert!(keys.insert(item_key(&origin(1), &item)));
        }
        // A contact keyed by the same address as an identity is a different key.
        let contact = ItemRef {
            kind: ItemKind::Contact,
            owner: None,
            id: a.0.to_vec(),
        };
        assert_ne!(item_key(&origin(1), &contact), identity_key(&origin(1), &a));
    }

    #[test]
    fn ids_round_trip_through_keys() {
        let item = ItemRef {
            kind: ItemKind::Archived,
            owner: Some(Addr([5; 24])),
            id: (0..16).collect(),
        };
        let prefix = item_prefix(&origin(1), item.kind, item.owner.as_ref());
        let key = item_key(&origin(1), &item);
        assert_eq!(id_from_key(&key, prefix.len()), Some(item.id));
    }

    #[test]
    fn generations_never_repeat_and_fail_closed() {
        let mut env = MemEnv::default();
        let o = origin(1);
        assert_eq!(next_generation(&mut env, &o), Some(1));
        assert_eq!(next_generation(&mut env, &o), Some(2));
        assert_eq!(next_generation(&mut env, &origin(2)), Some(1));
        env.fail_writes = true;
        assert_eq!(next_generation(&mut env, &o), None);
        env.fail_writes = false;
        assert_eq!(next_generation(&mut env, &o), Some(3));
    }

    #[test]
    fn envelope_round_trips_and_rejects_garbage() {
        let enc = encode_versioned(42, b"body");
        assert_eq!(decode_versioned(&enc), Some((42, &b"body"[..])));
        assert_eq!(decode_versioned(&[9; 20]), None);
        assert_eq!(decode_versioned(&[1, 2]), None);
    }
}
