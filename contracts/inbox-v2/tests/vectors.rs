//! Every signed layout, wire format and address against
//! tests/fixtures/vectors.txt, which a second implementation wrote from the
//! spec (tests/fixtures/vectors.py). A published contract's bytes cannot move,
//! so these are never regenerated to make a test pass.

use std::collections::BTreeMap;

use freenet_email_inbox_v2::Params;
use freenet_email_inbox_v2::signed::*;
use freenet_email_inbox_v2::sync;
use freenet_email_inbox_v2::types::*;
use serde_bytes::{ByteArray, ByteBuf};

const ADDR: [u8; 24] = [0x11; 24];
const T: u64 = 0x0102_0304_0506_0708;
const SENT: u64 = 0x6800_0000 / 3600 * 3600;

fn expected(name: &str) -> Vec<u8> {
    let line = include_str!("fixtures/vectors.txt")
        .lines()
        .find(|l| l.split(' ').next() == Some(name))
        .unwrap_or_else(|| panic!("no vector {name}"));
    let hex = line.split(' ').nth(1).unwrap();
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn check(name: &str, actual: &[u8]) {
    assert_eq!(actual, expected(name).as_slice(), "vector {name}");
}

fn pass_id() -> B16 {
    ByteArray::new([0x22; 16])
}
fn key() -> B32 {
    ByteArray::new([0x33; 32])
}
fn sig() -> B64 {
    ByteArray::new([0x44; 64])
}
const HASH: [u8; 32] = [0x55; 32];

fn owner(quarantine: QuarantineMode) -> OwnerRecord {
    OwnerRecord {
        owner_vk: ByteBuf::from(vec![0x77; 4]),
        kem_ek: ByteBuf::from(vec![0xAA, 0xBB, 0xCC, 0xDD]),
        issuer_vk: key(),
        pass_epoch: 3,
        version: 7,
        quarantine,
        tombstones: BTreeMap::from([(ByteArray::new([0x66; 32]), 0x1000)]),
        sig: ByteBuf::from(vec![0x99; 4]),
    }
}

fn cert(class: PassClass) -> PassCert {
    PassCert {
        recipient: ByteArray::new(ADDR),
        pass_id: pass_id(),
        pass_vk: key(),
        epoch: 3,
        expiry: T,
        class,
        sig: sig(),
    }
}

fn time() -> TimeAttestation {
    TimeAttestation {
        owner_time: T,
        sig: sig(),
    }
}

fn revocation() -> Revocation {
    Revocation {
        pass_id: pass_id(),
        expiry: T,
        epoch: 3,
        sig: sig(),
    }
}

fn usage() -> PassUsage {
    PassUsage {
        pass_id: pass_id(),
        used: 2,
        expiry: T,
        sig: sig(),
    }
}

fn message(admission: Admission) -> Message {
    Message {
        ciphertext: ByteBuf::from(vec![0xCC; 3]),
        sent_time: SENT,
        admission,
    }
}

fn bare() -> Admission {
    Admission::Quarantine { ghost: None }
}

#[test]
fn address_and_parameters() {
    let addr = address_of(&[0x77; 1952]);
    check("address", &addr);
    check("address_check", &address_check(&addr));
    let params = Params {
        addr: ADDR,
        ghost_master: [0x88; 32],
    };
    check("params", &params.to_bytes());
    assert_eq!(Params::parse(&expected("params")), Ok(params));
    assert_eq!(params.to_bytes().len(), 57);
}

#[test]
fn signed_layouts() {
    let mode = |min_usd| QuarantineMode::RequireGhost { min_usd };
    check(
        "owner_open",
        &owner_bytes(&ADDR, &owner(QuarantineMode::Open)),
    );
    check("owner_require", &owner_bytes(&ADDR, &owner(mode(None))));
    check("owner_require5", &owner_bytes(&ADDR, &owner(mode(Some(5)))));
    check("time", &time_bytes(&ADDR, T));
    check("cert_contact", &cert_bytes(&cert(PassClass::Contact)));
    check(
        "cert_invite",
        &cert_bytes(&cert(PassClass::Invite { max_messages: 3 })),
    );
    check("revocation", &revocation_bytes(&ADDR, &pass_id(), T, 3));
    check("usage", &usage_bytes(&ADDR, &pass_id(), 2, T));
    check("admit", &admit_bytes(&ADDR, SENT, &HASH));
    check("owner_msg", &owner_msg_bytes(&ADDR, SENT, &HASH));
    check("ghost_admit", &ghost_admit_bytes(&ADDR, SENT, &HASH));
    check(
        "sealed_pass",
        &inner_binding(&ADDR, &HASH, SENT, KIND_PASS, pass_id().as_slice()),
    );
    check(
        "sealed_owner",
        &inner_binding(&ADDR, &HASH, SENT, KIND_OWNER, &[]),
    );
    check(
        "sealed_quarantine",
        &inner_binding(&ADDR, &HASH, SENT, KIND_QUARANTINE, key().as_slice()),
    );
}

#[test]
fn message_ids() {
    let pass = Admission::Pass {
        cert: cert(PassClass::Contact),
        msg_sig: sig(),
    };
    check("id_pass", &message_id(&ADDR, &message(pass), &HASH));
    check(
        "id_owner",
        &message_id(&ADDR, &message(Admission::Owner { sig: sig() }), &HASH),
    );
    check("id_quarantine", &message_id(&ADDR, &message(bare()), &HASH));
    // With a proof, the ghost key its certificate claims is the tag
    // (decision 11). A certificate that does not decode tags all zeros.
    check(
        "id_quarantine_proven",
        &message_id_of(&ADDR, &HASH, SENT, KIND_QUARANTINE, key().as_slice()),
    );
    check(
        "id_quarantine_undecodable",
        &message_id_of(&ADDR, &HASH, SENT, KIND_QUARANTINE, &[0; 32]),
    );
    let garbage = Admission::Quarantine {
        ghost: Some(GhostProof {
            cert: ByteBuf::from(vec![1]),
            scoped_payload: ByteBuf::from(vec![2]),
            ghost_sig: sig(),
        }),
    };
    check(
        "id_quarantine_undecodable",
        &message_id(&ADDR, &message(garbage), &HASH),
    );
}

fn wire<T>(name: &str, value: &T)
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    check(name, &encode(value));
    assert_eq!(
        &decode::<T>(&expected(name)).unwrap(),
        value,
        "{name} decodes"
    );
}

#[test]
fn wire_formats() {
    let require5 = QuarantineMode::RequireGhost { min_usd: Some(5) };
    wire("cbor_owner_open_mode", &QuarantineMode::Open);
    wire("cbor_owner", &owner(require5));
    wire("cbor_time", &time());
    wire("cbor_revocation", &revocation());
    wire("cbor_usage", &usage());
    let invite = cert(PassClass::Invite { max_messages: 3 });
    wire("cbor_cert", &invite);
    wire(
        "cbor_pass_message",
        &message(Admission::Pass {
            cert: invite,
            msg_sig: sig(),
        }),
    );
    wire(
        "cbor_owner_message",
        &message(Admission::Owner { sig: sig() }),
    );
    let proof = GhostProof {
        cert: ByteBuf::from(vec![0xC1, 0xC2]),
        scoped_payload: ByteBuf::from(vec![0xD1]),
        ghost_sig: sig(),
    };
    wire(
        "cbor_quarantine_message",
        &message(Admission::Quarantine { ghost: Some(proof) }),
    );

    let state = InboxState {
        owner: owner(require5),
        time: time(),
        revoked: BTreeMap::from([(pass_id(), revocation())]),
        usage: BTreeMap::from([(pass_id(), usage())]),
        messages: BTreeMap::from([(ByteArray::new(HASH), message(bare()))]),
    };
    wire("cbor_state", &state);
    check("cbor_summary", &sync::summarize(&state));

    let delta = InboxDelta {
        owner: None,
        time: Some(time()),
        revoked: BTreeMap::new(),
        usage: BTreeMap::new(),
        messages: BTreeMap::from([(
            ByteArray::new(HASH),
            message(Admission::Owner { sig: sig() }),
        )]),
    };
    wire("cbor_delta", &delta);
}

/// The sender's signature lives inside the ciphertext, so it cannot cover it.
/// The layout's only hash input is the body's: pass a body and its ciphertext
/// and check no digest of the ciphertext appears.
#[test]
fn the_inner_binding_holds_no_ciphertext_digest() {
    let body = vec![0x42u8; 500];
    let ciphertext = vec![0x24u8; 8192];
    let (body_hash, ct_hash) = (blake3::hash(&body), blake3::hash(&ciphertext));
    let bytes = inner_binding(
        &ADDR,
        body_hash.as_bytes(),
        SENT,
        KIND_PASS,
        pass_id().as_slice(),
    );
    let contains = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
    assert!(contains(body_hash.as_bytes()), "the body digest is bound");
    assert!(!contains(&ct_hash.as_bytes()[..8]), "no ciphertext digest");
    assert_eq!(bytes.len(), "fmail/sealed/v1".len() + 24 + 32 + 8 + 1 + 16);
    // Its field map holds exactly one hash, so no room for a second digest.
    let no_tag = inner_binding(&ADDR, body_hash.as_bytes(), SENT, KIND_OWNER, &[]);
    assert_eq!(no_tag.len(), "fmail/sealed/v1".len() + 24 + 32 + 8 + 1);
}
