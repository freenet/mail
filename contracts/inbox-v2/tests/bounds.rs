//! Counts and size, refused before any signature is checked (decision 12,
//! review r1 M2).
//!
//! A valid state holds at most 88 messages, 4096 revocations, 1024 usage
//! entries and 4096 tombstones, and fits in 4 MiB. Every part a contract call
//! decodes (a state, a delta, a summary) is held to those numbers as it is
//! decoded: a part over a count is refused at the entry that passes it, and an
//! input over the byte limit before decoding starts, so nothing is allocated or
//! verified for what is over.

mod common;

use std::collections::BTreeMap;

use common::*;
use freenet_email_inbox_v2::types::*;
use freenet_email_inbox_v2::{apply, is_valid};
use freenet_stdlib::prelude::UpdateData;
use serde_bytes::{ByteArray, ByteBuf};

const T: u64 = 1_800_000_000 / HOUR * HOUR;
const FAR: u64 = T + 300 * DAY;
/// 4 MiB, the size of the largest valid state rounded up, plus a margin.
const LIMIT: usize = 4 * 1024 * 1024 + 256 * 1024;

fn owner() -> OwnerRecord {
    world().owner(1, 3, QuarantineMode::Open, BTreeMap::new())
}

fn base() -> Vec<u8> {
    let w = world();
    encode(&w.raw(owner(), w.time(T), [], [], []))
}

/// `n` quarantine messages under ids that do not match them: cheap, and
/// dropped by the filter, so only a count bound can refuse them.
fn messages(n: u64) -> BTreeMap<B32, Message> {
    (0..n)
        .map(|i| {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&i.to_be_bytes());
            let (_, m) = world().quarantine_msg(ct(8192, i), T, None);
            (ByteArray::new(id), m)
        })
        .collect()
}

fn revocations(n: u64) -> BTreeMap<B16, Revocation> {
    (0..n)
        .map(|i| {
            let id = id_of(i);
            (
                id,
                Revocation {
                    pass_id: id,
                    expiry: FAR,
                    epoch: 3,
                    sig: ByteArray::new([1; 64]),
                },
            )
        })
        .collect()
}

fn usage(n: u64) -> BTreeMap<B16, PassUsage> {
    let w = world();
    (0..n)
        .map(|i| {
            let mut u = w.usage(id_of(i), 1, FAR);
            u.sig = ByteArray::new([1; 64]);
            (id_of(i), u)
        })
        .collect()
}

fn tombstones(n: u64) -> BTreeMap<B32, u64> {
    (0..n)
        .map(|i| {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&i.to_be_bytes());
            (ByteArray::new(id), T)
        })
        .collect()
}

fn reason<T: serde::de::DeserializeOwned + serde::Serialize>(bytes: &[u8]) -> Option<&'static str> {
    decode::<T>(bytes).err().map(|e| e.0)
}

fn refused_everywhere(delta: InboxDelta, why: &str) {
    let w = world();
    let bytes = encode(&delta);
    assert_eq!(reason::<InboxDelta>(&bytes), Some(why), "decode");
    for data in [
        UpdateData::Delta(bytes.clone().into()),
        UpdateData::StateAndDelta {
            state: base().into(),
            delta: bytes.clone().into(),
        },
    ] {
        assert!(apply(&Rules::V1, &w.params, &base(), vec![data]).is_err());
    }
    // As a whole state, with the genuine owner and time.
    let state = InboxState {
        owner: delta.owner.unwrap_or_else(owner),
        time: w.time(T),
        revoked: delta.revoked,
        usage: delta.usage,
        messages: delta.messages,
    };
    let state = encode(&state);
    assert_eq!(reason::<InboxState>(&state), Some(why), "decode as a state");
    assert!(!is_valid(&Rules::V1, &w.params, &state));
    assert!(apply(&Rules::V1, &w.params, &base(), update_state(state.clone())).is_err());
    assert!(apply(&Rules::V1, &w.params, &state, update_state(base())).is_err());
}

fn accepted(delta: InboxDelta) {
    let w = world();
    let bytes = encode(&delta);
    assert!(decode::<InboxDelta>(&bytes).is_ok());
    let data = vec![UpdateData::Delta(bytes.into())];
    assert!(apply(&Rules::V1, &w.params, &base(), data).is_ok());
}

#[test]
fn eighty_eight_messages_a_part_and_no_more() {
    accepted(InboxDelta {
        messages: messages(88),
        ..InboxDelta::default()
    });
    refused_everywhere(
        InboxDelta {
            messages: messages(89),
            ..InboxDelta::default()
        },
        "a count over its bound",
    );
}

#[test]
fn revocations_usage_and_tombstones_at_their_bounds() {
    accepted(InboxDelta {
        revoked: revocations(4096),
        usage: usage(1024),
        ..InboxDelta::default()
    });
    refused_everywhere(
        InboxDelta {
            revoked: revocations(4097),
            ..InboxDelta::default()
        },
        "a count over its bound",
    );
    refused_everywhere(
        InboxDelta {
            usage: usage(1025),
            ..InboxDelta::default()
        },
        "a count over its bound",
    );
    let w = world();
    let full = w.owner(2, 3, QuarantineMode::Open, tombstones(4096));
    let over = w.owner(2, 3, QuarantineMode::Open, tombstones(4097));
    assert!(decode::<OwnerRecord>(&encode(&full)).is_ok());
    refused_everywhere(
        InboxDelta {
            owner: Some(over),
            ..InboxDelta::default()
        },
        "a count over its bound",
    );
}

/// The count is checked entry by entry: a map that says it holds a million
/// messages and carries 89 is refused for the 89th, not for running short.
#[test]
fn a_count_is_refused_at_the_entry_that_passes_it() {
    let delta = InboxDelta {
        messages: messages(89),
        ..InboxDelta::default()
    };
    let bytes = encode(&delta);
    let key = b"\x68messages";
    let at = bytes.windows(key.len()).position(|w| w == key).unwrap() + key.len();
    assert_eq!(&bytes[at..at + 2], &[0xB8, 89], "a map of 89");
    let mut claims = bytes[..at].to_vec();
    claims.extend_from_slice(&[0xBA, 0x00, 0x10, 0x00, 0x00]);
    claims.extend_from_slice(&bytes[at + 2..]);
    assert_eq!(
        reason::<InboxDelta>(&claims),
        Some("a count over its bound")
    );
}

#[test]
fn an_input_over_the_byte_limit_is_refused_before_decoding() {
    // One message whose ciphertext makes the delta exactly `size` bytes.
    let sized = |size: usize| {
        let (id, mut m) = world().quarantine_msg(ct(8192, 1), T, None);
        let mut delta = InboxDelta {
            messages: BTreeMap::from([(id, m.clone())]),
            ..InboxDelta::default()
        };
        let over = encode(&delta).len() - 8192;
        m.ciphertext = ByteBuf::from(vec![0; size - over - 2]);
        delta.messages.insert(id, m);
        let bytes = encode(&delta);
        assert_eq!(bytes.len(), size);
        bytes
    };
    let at = sized(LIMIT);
    assert!(decode::<InboxDelta>(&at).is_ok());
    let over = sized(LIMIT + 1);
    assert_eq!(
        reason::<InboxDelta>(&over),
        Some("an input over the byte limit")
    );
    let w = world();
    let data = vec![UpdateData::Delta(over.clone().into())];
    assert!(apply(&Rules::V1, &w.params, &base(), data).is_err());
    // Not even read: garbage of that size is refused for its size.
    let mut garbage = over;
    garbage[0] = 0xFF;
    assert_eq!(
        reason::<InboxDelta>(&garbage),
        Some("an input over the byte limit")
    );
    assert_eq!(
        reason::<InboxState>(&garbage),
        Some("an input over the byte limit")
    );
}

/// The bounds are the rules' own numbers: a valid state never passes one.
#[test]
fn the_bounds_are_what_a_valid_state_can_hold() {
    let v1 = Rules::V1;
    assert_eq!(MAX_MESSAGES, v1.pass_pool + v1.owner_pool + v1.quarantine);
    assert_eq!(MAX_REVOKED, v1.revoked);
    assert_eq!(MAX_USAGE, v1.usage);
    assert_eq!(MAX_TOMBSTONES, v1.tombstones);
    assert_eq!(MAX_INPUT_BYTES, LIMIT);
}
