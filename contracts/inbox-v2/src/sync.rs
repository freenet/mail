//! Summaries and deltas.
//!
//! A summary carries digests, so a peer can tell what differs and not which
//! side is newer: a delta sends whatever differs and the merge decides. Each
//! message is listed by id and by a digest of its encoding, because two peers
//! can hold different encodings of one id (a proof, or a renewed certificate)
//! and must still converge. Equal states give equal summaries and an empty
//! delta.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_bytes::{ByteArray, ByteBuf};

use crate::types::{B16, InboxDelta, InboxState, Malformed, decode, encode};

/// One listed message: 16 bytes of its id, 8 of its encoding's digest.
const ENTRY_LEN: usize = 24;

#[derive(Serialize, Deserialize)]
struct Summary {
    owner: B16,
    time: B16,
    revoked: B16,
    revoked_count: u32,
    usage: B16,
    messages: ByteBuf,
}

fn digest16<T: Serialize>(value: &T) -> B16 {
    let hash = blake3::hash(&encode(value));
    let mut out = [0u8; 16];
    out.copy_from_slice(&hash.as_bytes()[..16]);
    ByteArray::new(out)
}

fn entries(state: &InboxState) -> impl Iterator<Item = [u8; ENTRY_LEN]> + '_ {
    state.messages.iter().map(|(id, message)| {
        let mut entry = [0u8; ENTRY_LEN];
        entry[..16].copy_from_slice(&id[..16]);
        entry[16..].copy_from_slice(&blake3::hash(&encode(message)).as_bytes()[..8]);
        entry
    })
}

pub fn summarize(state: &InboxState) -> Vec<u8> {
    let mut messages = Vec::with_capacity(state.messages.len() * ENTRY_LEN);
    for entry in entries(state) {
        messages.extend_from_slice(&entry);
    }
    encode(&Summary {
        owner: digest16(&state.owner),
        time: digest16(&state.time),
        revoked: digest16(&state.revoked),
        revoked_count: state.revoked.len() as u32,
        usage: digest16(&state.usage),
        messages: ByteBuf::from(messages),
    })
}

/// What a peer with `summary` lacks of `state`. Empty when it lacks nothing.
pub fn delta(state: &InboxState, summary: &[u8]) -> Result<Vec<u8>, Malformed> {
    let theirs = decode::<Summary>(summary)?;
    if theirs.messages.len() % ENTRY_LEN != 0 {
        return Err(Malformed("summary"));
    }
    let held: BTreeSet<&[u8]> = theirs.messages.chunks_exact(ENTRY_LEN).collect();

    let mut delta = InboxDelta::default();
    if digest16(&state.owner) != theirs.owner {
        delta.owner = Some(state.owner.clone());
    }
    if digest16(&state.time) != theirs.time {
        delta.time = Some(state.time.clone());
    }
    if digest16(&state.revoked) != theirs.revoked
        || state.revoked.len() as u32 != theirs.revoked_count
    {
        delta.revoked = state.revoked.clone();
    }
    if digest16(&state.usage) != theirs.usage {
        delta.usage = state.usage.clone();
    }
    for ((id, message), entry) in state.messages.iter().zip(entries(state)) {
        if !held.contains(entry.as_slice()) {
            delta.messages.insert(*id, message.clone());
        }
    }
    if delta == InboxDelta::default() {
        return Ok(Vec::new());
    }
    Ok(encode(&delta))
}
