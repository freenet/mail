//! The largest state the rules allow, with keys of their real sizes.
//!
//! `INBOX_V2_DUMP_DIR=<dir>` also writes the inputs `scripts/check-inbox-cost.sh`
//! runs in wasm: the parameters, two such states with nothing in common, and
//! the most a peer can send in one call, built to cost the most to refuse.

mod common;

use std::collections::BTreeMap;

use common::*;
use ed25519_dalek::Signer as _;
use freenet_email_inbox_v2::signed::ghost_admit_bytes;
use freenet_email_inbox_v2::types::*;
use freenet_email_inbox_v2::{is_valid, sync};
use freenet_stdlib::prelude::ContractInstanceId;
use ghostkey_common::{ScopedPayload, SignatureRequestor};
use ghostkey_verify::GhostkeyCertificate;
use serde_bytes::{ByteArray, ByteBuf};

const T: u64 = 1_800_000_000 / DAY * DAY;
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
}

fn signing_key(seed: u64, tag: u8) -> ed25519_dalek::SigningKey {
    let mut s = [tag; 32];
    s[..8].copy_from_slice(&seed.to_be_bytes());
    ed25519_dalek::SigningKey::from_bytes(&s)
}

/// A genuine certificate with its ghost key swapped for `vk`: the master's
/// signature still verifies and the notary's RSA signature, the right length,
/// fails, so a merge pays for the whole chain before refusing it.
fn forged_cert(genuine: &[u8], vk: &[u8; 32]) -> Vec<u8> {
    use ciborium::Value;
    let mut value: Value = ciborium::from_reader(genuine).unwrap();
    let Value::Map(fields) = &mut value else {
        panic!("a map")
    };
    let (_, key) = fields
        .iter_mut()
        .find(|(k, _)| k.as_text() == Some("verifying_key"))
        .unwrap();
    *key = match key {
        Value::Bytes(_) => Value::Bytes(vk.to_vec()),
        Value::Array(_) => Value::Array(vk.iter().map(|b| Value::Integer((*b).into())).collect()),
        other => panic!("verifying_key is {other:?}"),
    };
    let mut out = Vec::new();
    ciborium::into_writer(&value, &mut out).unwrap();
    let cert = GhostkeyCertificate::from_cbor(&out).unwrap();
    assert_eq!(cert.claimed_ghost_key().to_bytes(), *vk);
    let master = ed25519_dalek::VerifyingKey::from_bytes(&world().params.ghost_master).unwrap();
    assert_eq!(
        cert.verify(&master).err(),
        Some(ghostkey_verify::Error::GhostKeySignature),
        "the RSA check is what fails"
    );
    cert.to_cbor()
}

/// The most one part may hold (decision 12), every item checked in full and
/// refused: proofs whose certificates reach the RSA check, and revocations and
/// usage entries with signatures of the right form over other bytes.
fn crafted(side: u64) -> InboxDelta {
    let w = world();
    let mut messages = BTreeMap::new();
    for i in 0..MAX_MESSAGES as u64 {
        let ghost = signing_key((side << 32) + i, 0x61);
        let cert = forged_cert(
            &w.ghosts[(i % 10) as usize].cert,
            &ghost.verifying_key().to_bytes(),
        );
        let ciphertext = ct(32768, (side << 40) + i);
        let hash = *blake3::hash(&ciphertext).as_bytes();
        let scoped = ghostkey_common::to_cbor(&ScopedPayload {
            requestor: SignatureRequestor::WebApp(ContractInstanceId::new(WEBAPP_REQUESTOR)),
            payload: ghost_admit_bytes(&w.params.addr, T, &hash),
        })
        .unwrap();
        let proof = GhostProof {
            cert: ByteBuf::from(cert),
            ghost_sig: ByteArray::new(ghost.sign(&scoped).to_bytes()),
            scoped_payload: ByteBuf::from(scoped),
        };
        let (id, m) = w.keyed(ciphertext, T, Admission::Quarantine { ghost: Some(proof) });
        messages.insert(id, m);
    }
    let signer = signing_key(side, 0x62);
    let sig = |i: u64| ByteArray::new(signer.sign(&i.to_be_bytes()).to_bytes());
    let id16 = |i: u64| {
        let mut id = [0xA0 + side as u8; 16];
        id[8..].copy_from_slice(&i.to_be_bytes());
        ByteArray::new(id)
    };
    let revoked = (0..MAX_REVOKED as u64)
        .map(|i| {
            let r = Revocation {
                pass_id: id16(i),
                expiry: FAR,
                epoch: 3,
                sig: sig(i),
            };
            (id16(i), r)
        })
        .collect();
    let usage = (0..MAX_USAGE as u64)
        .map(|i| {
            let id = id16(1 << 20 | i);
            let u = PassUsage {
                pass_id: id,
                used: 1,
                expiry: FAR,
                owner_version: 1,
                sig: sig(1 << 20 | i),
            };
            (id, u)
        })
        .collect();
    InboxDelta {
        owner: None,
        time: None,
        revoked,
        usage,
        messages,
    }
}

/// The inputs of `scripts/check-inbox-cost.sh`: `a` and `b`, two worst states
/// with nothing in common; `d1`, a crafted part as a delta; `s1`, the same as a
/// state carrying `a`'s owner and time; `h1` and `h2`, one crafted part's load
/// split over a state and a delta (decision 16). Each is checked to be within
/// the bounds, so a call carrying it is merged, not refused at decode.
#[test]
fn dump_the_cost_gate_inputs() {
    let Ok(dir) = std::env::var("INBOX_V2_DUMP_DIR") else {
        return;
    };
    let w = world();
    let write =
        |name: &str, bytes: Vec<u8>| std::fs::write(format!("{dir}/{name}"), bytes).unwrap();
    let a = worst(0);
    write("params.bin", w.params.to_bytes());
    write("a.bin", encode(&a));
    write("b.bin", encode(&worst(1)));
    let as_state = |d: InboxDelta| InboxState {
        owner: a.owner.clone(),
        time: a.time.clone(),
        revoked: d.revoked,
        usage: d.usage,
        messages: d.messages,
    };
    let d1 = crafted(1);
    assert!(
        decode::<InboxDelta>(&encode(&d1)).is_ok(),
        "within the bounds"
    );
    write("d1.bin", encode(&d1));
    let s1 = encode(&as_state(crafted(2)));
    assert!(decode::<InboxState>(&s1).is_ok(), "within the bounds");
    write("s1.bin", s1);
    let mut h = crafted(3);
    let at = |n: usize| n / 2;
    let m2 = h
        .messages
        .split_off(&h.messages.keys().nth(at(MAX_MESSAGES)).copied().unwrap());
    let r2 = h
        .revoked
        .split_off(&h.revoked.keys().nth(at(MAX_REVOKED)).copied().unwrap());
    let u2 = h
        .usage
        .split_off(&h.usage.keys().nth(at(MAX_USAGE)).copied().unwrap());
    write("h1.bin", encode(&as_state(h)));
    write(
        "h2.bin",
        encode(&InboxDelta {
            owner: None,
            time: None,
            revoked: r2,
            usage: u2,
            messages: m2,
        }),
    );
}

/// The widest encoding a valid state can take: the worst case above, with
/// every integer at its widest. Its quarantine is measured both ways: bare in
/// an Open inbox, which is checked valid, and with every message carrying a
/// proof at the size caps under the widest RequireGhost mode, which no valid
/// proof exceeds (an Open inbox refuses a proof, decision 19). Both fit in
/// 4 MiB, so `MAX_INPUT_BYTES`'s 256 KiB above that is margin no valid state or
/// delta uses.
#[test]
fn the_widest_valid_state_fits() {
    let w = world();
    let rules = Rules::V1;
    // Every time an 8-byte integer, every sent_time a whole hour.
    let t = (u64::MAX / 2) / HOUR * HOUR;
    // Expiries are whole days (decision 17).
    let never = u64::MAX / DAY * DAY;
    let id32 = |i: u64| {
        let mut id = [0xFFu8; 32];
        id[24..].copy_from_slice(&i.to_be_bytes());
        ByteArray::new(id)
    };
    let tombstones: BTreeMap<B32, u64> = (0..rules.tombstones as u64)
        .map(|i| (id32(i), never - i))
        .collect();
    let epoch = u32::MAX;
    let owner = |mode| w.owner(u64::MAX, epoch, mode, tombstones.clone());
    let revoked: Vec<_> = (0..rules.revoked as u64 - 1)
        .map(|i| w.revocation(id_of(i), never, epoch))
        .collect();
    let usage: Vec<_> = (0..rules.usage as u64)
        .map(|i| w.usage_at(id_of(i), u8::MAX, never, never))
        .collect();
    let mut messages = Vec::new();
    // Invites take more bytes than contacts: 32 of them, two messages each.
    for i in 0..rules.pass_pool as u64 {
        let class = PassClass::Invite {
            max_messages: u8::MAX,
        };
        let pass = w.pass((1 << 40) + i / 2, epoch, never, class);
        messages.push(w.pass_msg(&pass, ct(32768, (1 << 41) + i), t));
    }
    for i in 0..rules.owner_pool as u64 {
        messages.push(w.owner_msg(ct(32768, (1 << 42) + i), t));
    }
    let mut bare = messages.clone();
    for i in 0..rules.quarantine as u64 {
        bare.push(w.quarantine_msg(ct(32768, (1 << 43) + i), t, None));
        let proof = GhostProof {
            cert: serde_bytes::ByteBuf::from(vec![0xFF; ghostkey_verify::MAX_CERTIFICATE_BYTES]),
            scoped_payload: serde_bytes::ByteBuf::from(vec![
                0xFF;
                freenet_email_inbox_v2::merge::MAX_SCOPED_PAYLOAD
            ]),
            ghost_sig: ByteArray::new([0xFF; 64]),
        };
        let admission = Admission::Quarantine { ghost: Some(proof) };
        messages.push(w.keyed(ct(32768, (1 << 43) + i), t, admission));
    }
    let open = w.raw(
        owner(QuarantineMode::Open),
        w.time(t),
        revoked.clone(),
        usage.clone(),
        bare,
    );
    let bytes = encode(&open);
    assert!(is_valid(&rules, &w.params, &bytes), "nothing was dropped");
    assert_eq!(open.messages.len(), MAX_MESSAGES);
    let widest_mode = QuarantineMode::RequireGhost {
        min_usd: Some(u32::MAX),
    };
    let proven = encode(&w.raw(owner(widest_mode), w.time(t), revoked, usage, messages));
    assert!(proven.len() > bytes.len());
    println!(
        "widest valid state: {} bytes, {} under 4 MiB; with proofs at their caps {} bytes, {} under",
        bytes.len(),
        LIMIT - bytes.len(),
        proven.len(),
        LIMIT - proven.len()
    );
    assert!(proven.len() <= LIMIT);
    const { assert!(LIMIT < MAX_INPUT_BYTES) };
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
