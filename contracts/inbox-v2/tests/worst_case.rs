//! The largest state the rules allow, with keys of their real sizes.
//!
//! `INBOX_V2_DUMP_DIR=<dir>` also writes the parameters and two such states with
//! nothing in common, for measuring a merge that must verify both sides in wasm.

mod common;

use std::collections::BTreeMap;

use common::*;
use freenet_email_inbox_v2::types::*;
use freenet_email_inbox_v2::{is_valid, sync};
use serde_bytes::ByteArray;

const T: u64 = 1_800_000_000 / HOUR * HOUR;
const FAR: u64 = T + 300 * DAY;
const LIMIT: usize = 4 * 1024 * 1024;
const REQUIRE: QuarantineMode = QuarantineMode::RequireGhost { min_usd: None };

/// Every collection at its cap, every message at its largest, every signature
/// distinct, one short of the revocation cap so pass mail may be held. `side`
/// keeps two such states from sharing anything.
fn worst(side: u64) -> InboxState {
    let w = world();
    let rules = Rules::V1;
    let key = |i: u64| (side << 32) + i;
    let id32 = |i: u64| {
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&key(i).to_be_bytes());
        ByteArray::new(id)
    };
    let tombstones: BTreeMap<B32, u64> = (0..rules.tombstones as u64)
        .map(|i| (id32(i), T + i))
        .collect();
    let owner = w.owner(1 + side, 3, REQUIRE, tombstones);
    let revoked: Vec<_> = (0..rules.revoked as u64 - 1)
        .map(|i| w.revocation(id_of(key(i)), FAR, 3))
        .collect();
    let usage: Vec<_> = (0..rules.usage as u64)
        .map(|i| w.usage(id_of(key(i)), 200, FAR))
        .collect();

    let mut messages = Vec::new();
    for i in 0..rules.pass_pool as u64 {
        let pass = w.pass(key(1 << 20) + i, 3, FAR, PassClass::Contact);
        messages.push(w.pass_msg(&pass, ct(32768, key(1 << 21) + i), T));
    }
    for i in 0..rules.owner_pool as u64 {
        messages.push(w.owner_msg(ct(32768, key(1 << 22) + i), T));
    }
    // Two each from eight donation keys: the per-ghost cap's limit.
    for i in 0..rules.quarantine as u64 {
        let ghost = (i / 2) as usize;
        messages.push(w.quarantine_msg(ct(32768, key(1 << 23) + i), T, Some(ghost)));
    }
    w.raw(owner, w.time(T + side), revoked, usage, messages)
}

#[test]
fn the_worst_case_is_valid_and_fits() {
    let w = world();
    let state = worst(0);
    let bytes = encode(&state);
    assert_eq!(state.messages.len(), 88);
    assert_eq!(state.revoked.len(), 4095);
    assert_eq!(state.usage.len(), 1024);
    assert_eq!(state.owner.tombstones.len(), 4096);
    assert_eq!(state.owner.owner_vk.len(), 1952);
    assert_eq!(state.owner.kem_ek.len(), 1184);
    assert_eq!(state.owner.sig.len(), 3309);
    assert!(
        is_valid(&Rules::V1, &w.params, &bytes),
        "nothing was dropped"
    );

    println!("worst-case state: {} bytes", bytes.len());
    assert!(bytes.len() <= LIMIT, "{} bytes", bytes.len());

    let summary = sync::summarize(&state);
    println!("its summary: {} bytes", summary.len());
    assert!(summary.len() * 4 < bytes.len());
    assert!(sync::delta(&state, &summary).unwrap().is_empty());

    if let Ok(dir) = std::env::var("INBOX_V2_DUMP_DIR") {
        std::fs::write(format!("{dir}/params.bin"), w.params.to_bytes()).unwrap();
        std::fs::write(format!("{dir}/a.bin"), &bytes).unwrap();
        std::fs::write(format!("{dir}/b.bin"), encode(&worst(1))).unwrap();
    }
}

/// The summary is smaller than a quarter of the state at the other extreme too.
#[test]
fn the_smallest_state_summarizes_small() {
    let w = world();
    let raw = w.raw(
        w.owner(1, 3, REQUIRE, BTreeMap::new()),
        w.time(T),
        [],
        [],
        [],
    );
    let (bytes, summary) = (encode(&raw), sync::summarize(&raw));
    assert!(
        summary.len() * 4 < bytes.len(),
        "{} of {}",
        summary.len(),
        bytes.len()
    );
    assert!(sync::delta(&raw, &summary).unwrap().is_empty());
}
