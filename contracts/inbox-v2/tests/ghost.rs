//! Ghost Key proofs: decisive in RequireGhost inboxes, inert in Open ones.
//! Fixture certificates: 0-3 are $1, 4-7 are $5, 8-9 are $20, 10 is a $5
//! certificate from a notary that is not a donation notary.

mod common;

use std::collections::BTreeMap;

use common::*;
use freenet_email_inbox_v2::merge::{MAX_SCOPED_PAYLOAD, merge};
use freenet_email_inbox_v2::signed::*;
use freenet_email_inbox_v2::types::*;
use freenet_email_inbox_v2::{Params, apply, is_valid};
use freenet_stdlib::prelude::ContractInstanceId;
use ghostkey_common::{ScopedPayload, SignatureRequestor};
use serde_bytes::{ByteArray, ByteBuf};

const T: u64 = 1_800_000_000 / HOUR * HOUR;
const REQUIRE: QuarantineMode = QuarantineMode::RequireGhost { min_usd: None };
const DOLLAR5: QuarantineMode = QuarantineMode::RequireGhost { min_usd: Some(5) };

fn require(mode: QuarantineMode) -> OwnerRecord {
    world().owner(1, 3, mode, BTreeMap::new())
}

fn holds_with(params: &Params, mode: QuarantineMode, message: (B32, Message)) -> bool {
    let w = world();
    let raw = w.raw(require(mode), w.time(T), [], [], [message]);
    let held = merge(&Rules::V1, params, vec![raw.clone().into()])
        .unwrap()
        .messages
        .len()
        == 1;
    assert_eq!(
        held,
        is_valid(&Rules::V1, params, &encode(&raw)),
        "validate agrees"
    );
    held
}

fn holds(mode: QuarantineMode, message: (B32, Message)) -> bool {
    holds_with(&world().params, mode, message)
}

/// A quarantine message carrying `proof`, under its ciphertext's own id.
fn carrying(bytes: Vec<u8>, proof: GhostProof) -> (B32, Message) {
    world().keyed(bytes, T, Admission::Quarantine { ghost: Some(proof) })
}

fn genuine_payload(bytes: &[u8]) -> Vec<u8> {
    ghost_admit_bytes(&world().params.addr, T, blake3::hash(bytes).as_bytes())
}

#[test]
fn the_contract_reads_what_the_vault_signs_and_pins_the_webapp() {
    let id =
        ContractInstanceId::from_base58("GeQLXXR8sfGe31BNRJoVxkvGUTnBkufJ4gTaoX5NWnU5").unwrap();
    assert_eq!(id.as_bytes(), WEBAPP_REQUESTOR.as_slice());
    assert_eq!(world().ghosts.len(), 11);
}

#[test]
fn a_valid_proof_is_admitted_and_no_proof_is_not() {
    let w = world();
    assert!(holds(REQUIRE, w.quarantine_msg(ct(8192, 1), T, Some(0))));
    assert!(!holds(REQUIRE, w.quarantine_msg(ct(8192, 1), T, None)));
}

#[test]
fn the_tier_decides_at_the_boundary() {
    let w = world();
    assert!(
        !holds(DOLLAR5, w.quarantine_msg(ct(8192, 1), T, Some(3))),
        "$1 under $5"
    );
    assert!(
        holds(DOLLAR5, w.quarantine_msg(ct(8192, 2), T, Some(4))),
        "$5 at $5"
    );
    assert!(
        holds(DOLLAR5, w.quarantine_msg(ct(8192, 3), T, Some(8))),
        "$20 over $5"
    );
    assert!(
        holds(REQUIRE, w.quarantine_msg(ct(8192, 4), T, Some(3))),
        "no tier set"
    );
}

#[test]
fn only_a_donation_notary_counts() {
    assert!(!holds(
        REQUIRE,
        world().quarantine_msg(ct(8192, 1), T, Some(10))
    ));
}

#[test]
fn the_chain_must_end_at_this_contracts_master() {
    let w = world();
    let other = Params {
        ghost_master: [0x42; 32],
        ..w.params
    };
    assert!(!holds_with(
        &other,
        REQUIRE,
        w.quarantine_msg(ct(8192, 1), T, Some(0))
    ));
    // A low-order point, which anyone can sign for.
    let weak = Params {
        ghost_master: [0; 32],
        ..w.params
    };
    assert!(!holds_with(
        &weak,
        REQUIRE,
        w.quarantine_msg(ct(8192, 1), T, Some(0))
    ));
}

#[test]
fn the_requestor_is_pinned() {
    let w = world();
    let bytes = ct(8192, 1);
    let mut other = WEBAPP_REQUESTOR;
    other[0] ^= 1;
    let proof = w.proof_over(0, genuine_payload(&bytes), other);
    assert!(!holds(REQUIRE, carrying(bytes.clone(), proof)));

    // A delegate asked for the signature. A delegate key needs a hash; the
    // contract refuses the variant, whatever it names.
    let g = &w.ghosts[0];
    let delegate = freenet_stdlib::prelude::DelegateKey::new(
        [1; 32],
        freenet_stdlib::prelude::CodeHash::new([2; 32]),
    );
    let scoped = ghostkey_common::to_cbor(&ScopedPayload {
        requestor: SignatureRequestor::Delegate(delegate),
        payload: genuine_payload(&bytes),
    })
    .unwrap();
    let proof = GhostProof {
        cert: ByteBuf::from(g.cert.clone()),
        ghost_sig: sign64(&g.sk, &scoped),
        scoped_payload: ByteBuf::from(scoped),
    };
    assert!(!holds(REQUIRE, carrying(bytes, proof)));
}

#[test]
fn the_payload_must_be_this_ciphertext_this_recipient_this_hour() {
    let w = world();
    let bytes = ct(8192, 1);
    let hash = *blake3::hash(&bytes).as_bytes();
    let addr = w.params.addr;
    let wrong = [
        ("bare digest", hash.to_vec()),
        (
            "other ciphertext",
            ghost_admit_bytes(&addr, T, blake3::hash(&ct(8192, 2)).as_bytes()),
        ),
        ("other recipient", ghost_admit_bytes(&[0xAB; 24], T, &hash)),
        ("other hour", ghost_admit_bytes(&addr, T + HOUR, &hash)),
        ("the pass domain", admit_bytes(&addr, T, &hash)),
        ("the owner domain", owner_msg_bytes(&addr, T, &hash)),
        (
            "the inner binding",
            inner_binding(&addr, &hash, T, KIND_QUARANTINE, &[0x33; 32]),
        ),
    ];
    for (name, payload) in wrong {
        let proof = w.proof_over(0, payload, WEBAPP_REQUESTOR);
        assert!(!holds(REQUIRE, carrying(bytes.clone(), proof)), "{name}");
    }
    let proof = w.proof_over(0, genuine_payload(&bytes), WEBAPP_REQUESTOR);
    assert!(holds(REQUIRE, carrying(bytes, proof)));
}

#[test]
fn a_proof_seen_in_public_cannot_admit_another_ciphertext() {
    let w = world();
    let (_, seen) = w.quarantine_msg(ct(8192, 1), T, Some(0));
    let Admission::Quarantine { ghost: Some(proof) } = seen.admission else {
        panic!()
    };
    assert!(!holds(REQUIRE, carrying(ct(8192, 2), proof.clone())));
    // Nor the same ciphertext at another hour.
    let moved = w.keyed(
        ct(8192, 1),
        T + HOUR,
        Admission::Quarantine { ghost: Some(proof) },
    );
    assert!(!holds(REQUIRE, moved));
}

#[test]
fn every_proof_field_is_checked() {
    let w = world();
    let bytes = ct(8192, 1);
    let good = w.proof(0, &bytes, T);
    assert!(holds(REQUIRE, carrying(bytes.clone(), good.clone())));

    let mut sig = good.clone();
    sig.ghost_sig[0] ^= 1;
    assert!(!holds(REQUIRE, carrying(bytes.clone(), sig)), "ghost_sig");

    let mut payload = good.clone();
    let last = payload.scoped_payload.len() - 1;
    payload.scoped_payload[last] ^= 1;
    assert!(
        !holds(REQUIRE, carrying(bytes.clone(), payload)),
        "scoped_payload"
    );

    // Another key's certificate under this key's signature.
    let other = GhostProof {
        cert: ByteBuf::from(w.ghosts[1].cert.clone()),
        ..good.clone()
    };
    assert!(!holds(REQUIRE, carrying(bytes.clone(), other)), "cert");

    // A signature bit in the certificate: the RSA or master check, not parsing.
    let mut cert = good.clone();
    let at = cert.cert.len() - 10;
    cert.cert[at] ^= 1;
    assert!(!holds(REQUIRE, carrying(bytes.clone(), cert)), "chain");

    // Bytes after the certificate parse, but are not its canonical form.
    let mut padded = good.clone();
    padded.cert.push(0);
    assert!(
        !holds(REQUIRE, carrying(bytes, padded)),
        "non-canonical cert"
    );
}

#[test]
fn at_most_two_per_ghost_key_when_required() {
    let w = world();
    let same_key = (1..=3).map(|i| w.quarantine_msg(ct(8192, i), T, Some(0)));
    let others = (4..=5).map(|i| w.quarantine_msg(ct(8192, i), T, Some(1)));
    let raw = w.raw(require(REQUIRE), w.time(T), [], [], same_key.chain(others));
    let merged = merge(&Rules::V1, &w.params, vec![raw.into()]).unwrap();
    assert_eq!(merged.messages.len(), 4, "2 of key 0 and 2 of key 1");
}

/// Two messages of one certificate reach the memo: both are decided right.
#[test]
fn a_memoed_certificate_still_needs_its_payload_signature() {
    let w = world();
    let bytes = ct(8192, 2);
    let mut forged = w.proof(0, &bytes, T);
    forged.ghost_sig[0] ^= 1;
    let raw = w.raw(
        require(REQUIRE),
        w.time(T),
        [],
        [],
        [
            w.quarantine_msg(ct(8192, 1), T, Some(0)),
            carrying(bytes, forged),
        ],
    );
    let merged = merge(&Rules::V1, &w.params, vec![raw.into()]).unwrap();
    assert_eq!(merged.messages.len(), 1);
}

#[test]
fn in_an_open_inbox_a_proof_is_ignored() {
    let w = world();
    // Garbage that no check could pass.
    let garbage = GhostProof {
        cert: ByteBuf::from(vec![0xFF; 10]),
        scoped_payload: ByteBuf::from(vec![0xFF; 10]),
        ghost_sig: ByteArray::new([0; 64]),
    };
    assert!(holds(QuarantineMode::Open, carrying(ct(8192, 1), garbage)));

    // Not counted either: three of one key all stay.
    let three = (1..=3).map(|i| w.quarantine_msg(ct(8192, i), T, Some(0)));
    let open = w.owner(1, 3, QuarantineMode::Open, BTreeMap::new());
    let raw = w.raw(open, w.time(T), [], [], three);
    assert_eq!(
        merge(&Rules::V1, &w.params, vec![raw.into()])
            .unwrap()
            .messages
            .len(),
        3
    );
}

#[test]
fn in_an_open_inbox_a_proof_is_size_capped() {
    let open = QuarantineMode::Open;
    let make = |cert: usize, payload: usize| GhostProof {
        cert: ByteBuf::from(vec![0; cert]),
        scoped_payload: ByteBuf::from(vec![0; payload]),
        ghost_sig: ByteArray::new([0; 64]),
    };
    let cert_cap = ghostkey_verify::MAX_CERTIFICATE_BYTES;
    assert!(holds(
        open,
        carrying(ct(8192, 1), make(cert_cap, MAX_SCOPED_PAYLOAD))
    ));
    assert!(!holds(open, carrying(ct(8192, 2), make(cert_cap + 1, 0))));
    assert!(!holds(
        open,
        carrying(ct(8192, 3), make(0, MAX_SCOPED_PAYLOAD + 1))
    ));
}

/// One id, with and without a proof. In Open the smaller stands; when the owner
/// turns on RequireGhost a surviving proof is checked then, which is why the
/// client drains first.
#[test]
fn one_id_keeps_the_smallest_that_passed() {
    let w = world();
    let bytes = ct(8192, 1);
    let proven = w.quarantine_msg(bytes.clone(), T, Some(0));
    let bare = w.quarantine_msg(bytes, T, None);
    assert_eq!(proven.0, bare.0, "the proof is outside the id");
    let state =
        |owner: OwnerRecord, m: (B32, Message)| encode(&w.raw(owner, w.time(T), [], [], [m]));

    let open = w.owner(1, 3, QuarantineMode::Open, BTreeMap::new());
    let a = state(open.clone(), proven.clone());
    let b = state(open, bare.clone());
    let merged = apply(&Rules::V1, &w.params, &a, update_state(b.clone())).unwrap();
    assert_eq!(merged, b, "Open: no proof is smaller");

    // RequireGhost: the bare one is filtered, so a valid proof beats none.
    let required = w.owner(2, 3, REQUIRE, BTreeMap::new());
    let c = state(required.clone(), proven.clone());
    let merged = apply(&Rules::V1, &w.params, &c, update_state(b)).unwrap();
    assert_eq!(merged, c);

    // An owner relaxing to Open leaves the proof ignored, not filtered.
    let relaxed = w.owner(3, 3, QuarantineMode::Open, BTreeMap::new());
    let d = state(relaxed, bare);
    let merged = decode::<InboxState>(&apply(&Rules::V1, &w.params, &c, update_state(d)).unwrap());
    assert_eq!(merged.unwrap().messages.len(), 1);
}
