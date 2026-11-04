//! The contract's byte vectors the protocol crate's own tests do not reach:
//! the address, the address check, the state summary and the id of a
//! quarantine message whose proof cannot be decoded, checked here against what
//! the delegate and its protocol types produce. (`vectors.txt` comes from a
//! second implementation and is never regenerated to make a test pass.)

use std::collections::BTreeMap;

use freenet_mail_protocol::address::address_of;
use freenet_mail_protocol::inbox_v2::{self as w, InboxState};
use serde_bytes::{ByteArray, ByteBuf};

const VECTORS: &str = include_str!("../../../../contracts/inbox-v2/tests/fixtures/vectors.txt");
const ADDR: [u8; 24] = [0x11; 24];
const SENT: u64 = 0x6800_0000 / 3600 * 3600;
const EXPIRY: u64 = 0x6900_0000 / 86_400 * 86_400;
const HASH: [u8; 32] = [0x55; 32];

fn expected(name: &str) -> Vec<u8> {
    let line = VECTORS
        .lines()
        .find(|l| l.split(' ').next() == Some(name))
        .unwrap_or_else(|| panic!("no vector {name}"));
    let hex = line.split(' ').nth(1).unwrap();
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

/// The vector's key: the address the delegate derives, and the check the
/// contract's crate puts beside it, are the vectors.
#[test]
fn the_vector_key_has_the_vectors_address_and_check() {
    let addr = address_of(&[0x77; 1952]);
    assert_eq!(addr.0.to_vec(), expected("address"), "vector address");
    assert_eq!(
        freenet_email_inbox_v2::signed::address_check(&addr.0).to_vec(),
        expected("address_check"),
        "vector address_check"
    );
}

/// The vector's state, built from the delegate's own wire types: it encodes
/// to the vector, and the contract, reading those bytes, summarizes it to the
/// vector, so what the delegate writes is what a peer's summary is made of.
#[test]
fn a_state_the_delegate_encodes_has_the_vectors_summary() {
    let sig = || ByteArray::new([0x44; 64]);
    let pass_id = || ByteArray::new([0x22; 16]);
    let time = w::TimeAttestation {
        owner_time: 0x0102_0304_0506_0708,
        sig: sig(),
    };
    let revocation = w::Revocation {
        pass_id: pass_id(),
        expiry: EXPIRY,
        epoch: 3,
        sig: sig(),
    };
    let usage = w::PassUsage {
        pass_id: pass_id(),
        used: 2,
        expiry: EXPIRY,
        owner_version: 7,
        sig: sig(),
    };
    let owner = w::OwnerRecord {
        owner_vk: ByteBuf::from(vec![0x77; 4]),
        kem_ek: ByteBuf::from(vec![0xAA, 0xBB, 0xCC, 0xDD]),
        issuer_vk: ByteArray::new([0x33; 32]),
        pass_epoch: 3,
        prev_epoch_until: 0x0A0B_0C0D_0E0F_1011,
        version: 7,
        quarantine: w::QuarantineMode::RequireGhost { min_usd: Some(5) },
        tombstones: BTreeMap::from([(ByteArray::new([0x66; 32]), 0x1000)]),
        sig: ByteBuf::from(vec![0x99; 4]),
    };
    let message = w::Message {
        ciphertext: ByteBuf::from(vec![0xCC; 3]),
        sent_time: SENT,
        admission: w::Admission::Quarantine { ghost: None },
    };
    let state = InboxState {
        owner,
        time,
        revoked: BTreeMap::from([(pass_id(), revocation)]),
        usage: BTreeMap::from([(pass_id(), usage)]),
        messages: BTreeMap::from([(ByteArray::new(HASH), message)]),
    };
    let bytes = w::encode(&state);
    assert_eq!(bytes, expected("cbor_state"), "vector cbor_state");
    let theirs: freenet_email_inbox_v2::types::InboxState =
        freenet_email_inbox_v2::types::decode(&bytes).expect("the contract reads it");
    assert_eq!(
        freenet_email_inbox_v2::sync::summarize(&theirs),
        expected("cbor_summary"),
        "vector cbor_summary"
    );
}

/// A quarantine message whose proof the contract cannot decode has the zero
/// tag in its id. The delegate takes a proof's tag from the key the sender
/// bound in the envelope, so such a message is the one whose sender bound
/// zeros, and only that one has this id; one that bound any other key has
/// another, and the delegate tombstones it unread.
#[test]
fn a_quarantine_message_with_an_undecodable_proof_has_the_vectors_id() {
    let id = |tag: &[u8]| w::message_id(&ADDR, &HASH, SENT, w::KIND_QUARANTINE, tag);
    assert_eq!(
        id(&[0; 32]).to_vec(),
        expected("id_quarantine_undecodable"),
        "vector id_quarantine_undecodable"
    );
    let proof = w::Admission::Quarantine {
        ghost: Some(w::GhostProof {
            cert: ByteBuf::from(vec![1]),
            scoped_payload: ByteBuf::from(vec![2]),
            ghost_sig: ByteArray::new([0x44; 64]),
        }),
    };
    let (kind, tag) =
        crate::sealing::kind_and_tag(&proof, Some(&ByteArray::new([0; 32]))).expect("a tag");
    assert_eq!(kind, w::KIND_QUARANTINE);
    assert_eq!(
        w::message_id(&ADDR, &HASH, SENT, kind, &tag).to_vec(),
        expected("id_quarantine_undecodable")
    );
    // Any other bound key is another id.
    let (_, other) =
        crate::sealing::kind_and_tag(&proof, Some(&ByteArray::new([0x33; 32]))).expect("a tag");
    assert_ne!(
        w::message_id(&ADDR, &HASH, SENT, kind, &other).to_vec(),
        expected("id_quarantine_undecodable")
    );
}
