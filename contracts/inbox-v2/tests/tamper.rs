//! A tamper test for every signed field. Each changes one field and keeps
//! everything else consistent (the message id is re-derived, the epoch or expiry
//! check is satisfied), so what stops the forgery is the signature and not a
//! neighbouring check.

mod common;

use std::collections::BTreeMap;

use common::*;
use ed25519_dalek::Signer as _;
use freenet_email_inbox_v2::merge::merge;
use freenet_email_inbox_v2::signed::*;
use freenet_email_inbox_v2::types::*;
use freenet_email_inbox_v2::{apply, is_valid};
use serde_bytes::{ByteArray, ByteBuf};

const T: u64 = 1_800_000_000 / HOUR * HOUR;
const EXPIRY: u64 = T + 100 * DAY;
const OPEN: QuarantineMode = QuarantineMode::Open;

fn owner(epoch: u32) -> OwnerRecord {
    world().owner(1, epoch, OPEN, BTreeMap::new())
}

fn contact() -> Pass {
    world().pass(1, 3, EXPIRY, PassClass::Contact)
}

/// Does `message` survive a merge, under `owner_record`, and is a state holding
/// it valid?
fn survives(owner_record: OwnerRecord, (id, message): (B32, Message)) -> bool {
    let w = world();
    let raw = w.raw(owner_record, w.time(T), [], [], [(id, message)]);
    let kept = !merge(&Rules::V1, &w.params, vec![raw.clone().into()])
        .unwrap()
        .messages
        .is_empty();
    assert_eq!(
        kept,
        is_valid(&Rules::V1, &w.params, &encode(&raw)),
        "validate agrees"
    );
    kept
}

/// `pass`'s message, with its certificate changed afterwards and its signature
/// by the pass key redone, so only the issuer's signature is wrong.
fn with_cert(pass: &Pass, change: impl Fn(&mut PassCert)) -> (B32, Message) {
    let w = world();
    let bytes = ct(8192, 1);
    let hash = *blake3::hash(&bytes).as_bytes();
    let msg_sig = sign64(&pass.sk, &admit_bytes(&w.params.addr, T, &hash));
    let mut cert = pass.cert.clone();
    change(&mut cert);
    w.keyed(bytes, T, Admission::Pass { cert, msg_sig })
}

#[test]
fn the_genuine_message_of_each_kind_survives() {
    let w = world();
    assert!(survives(owner(3), w.pass_msg(&contact(), ct(8192, 1), T)));
    assert!(survives(owner(3), w.owner_msg(ct(8192, 2), T)));
    assert!(survives(owner(3), w.quarantine_msg(ct(8192, 3), T, None)));
    assert!(survives(owner(3), with_cert(&contact(), |_| ())));
}

#[test]
fn every_certificate_field_is_signed() {
    let pass = contact();
    assert!(!survives(owner(3), with_cert(&pass, |c| c.pass_id[0] ^= 1)));
    assert!(!survives(owner(4), with_cert(&pass, |c| c.epoch = 4)));
    assert!(!survives(owner(3), with_cert(&pass, |c| c.expiry += DAY)));
    assert!(!survives(
        owner(3),
        with_cert(&pass, |c| c.class = PassClass::Invite { max_messages: 3 })
    ));
    assert!(!survives(owner(3), with_cert(&pass, |c| c.sig[0] ^= 1)));

    // Another key, certified by nobody, signing for itself.
    let thief = ed25519_dalek::SigningKey::from_bytes(&[0x66; 32]);
    let stolen = Pass {
        cert: PassCert {
            pass_vk: ByteArray::new(thief.verifying_key().to_bytes()),
            ..pass.cert.clone()
        },
        sk: thief,
    };
    assert!(!survives(owner(3), with_cert(&stolen, |_| ())));

    // A certificate for another recipient, genuinely signed.
    let w = world();
    let mut other = pass.cert.clone();
    other.recipient[0] ^= 1;
    other.sig = sign64(&w.issuer, &cert_bytes(&other));
    assert!(!survives(
        owner(3),
        with_cert(&pass, |c| *c = other.clone())
    ));
}

/// A forged certificate must not pass on a genuine one's memo entry.
#[test]
fn a_forged_certificate_does_not_ride_on_a_genuine_one_of_the_same_pass() {
    let w = world();
    let pass = contact();
    let genuine = w.pass_msg(&pass, ct(8192, 1), T);
    let forged = Pass {
        cert: PassCert {
            expiry: EXPIRY + DAY,
            ..pass.cert.clone()
        },
        sk: pass.sk.clone(),
    };
    let (forged_id, forged_msg) = w.pass_msg(&forged, ct(8192, 2), T);
    let raw = w.raw(
        owner(3),
        w.time(T),
        [],
        [],
        [genuine.clone(), (forged_id, forged_msg)],
    );
    let kept = merge(&Rules::V1, &w.params, vec![raw.into()])
        .unwrap()
        .messages;
    assert!(kept.contains_key(&genuine.0) && !kept.contains_key(&forged_id));
}

#[test]
fn every_outer_message_field_is_signed() {
    let w = world();
    let pass = contact();

    // Pass: the signature covers the ciphertext, the time and the recipient.
    let (_, signed) = w.pass_msg(&pass, ct(8192, 1), T);
    let admission = signed.admission.clone();
    assert!(!survives(
        owner(3),
        w.keyed(ct(8192, 2), T, admission.clone())
    ));
    assert!(!survives(
        owner(3),
        w.keyed(ct(8192, 1), T + HOUR, admission)
    ));
    let bytes = ct(8192, 1);
    let hash = *blake3::hash(&bytes).as_bytes();
    let elsewhere = sign64(&pass.sk, &admit_bytes(&[0xAB; 24], T, &hash));
    let cert = pass.cert.clone();
    assert!(!survives(
        owner(3),
        w.keyed(
            bytes.clone(),
            T,
            Admission::Pass {
                cert: cert.clone(),
                msg_sig: elsewhere
            }
        )
    ));
    let mut flipped = sign64(&pass.sk, &admit_bytes(&w.params.addr, T, &hash));
    flipped[0] ^= 1;
    assert!(!survives(
        owner(3),
        w.keyed(
            bytes,
            T,
            Admission::Pass {
                cert,
                msg_sig: flipped
            }
        )
    ));

    // Owner: the same, under the issuer key, in its own domain.
    let (_, signed) = w.owner_msg(ct(8192, 3), T);
    let admission = signed.admission.clone();
    assert!(!survives(
        owner(3),
        w.keyed(ct(8192, 4), T, admission.clone())
    ));
    assert!(!survives(
        owner(3),
        w.keyed(ct(8192, 3), T + HOUR, admission)
    ));
    let bytes = ct(8192, 3);
    let hash = *blake3::hash(&bytes).as_bytes();
    let admit_domain = sign64(&w.issuer, &admit_bytes(&w.params.addr, T, &hash));
    assert!(!survives(
        owner(3),
        w.keyed(bytes.clone(), T, Admission::Owner { sig: admit_domain })
    ));
    let stranger = ed25519_dalek::SigningKey::from_bytes(&[0x67; 32]);
    let unsigned = sign64(&stranger, &owner_msg_bytes(&w.params.addr, T, &hash));
    assert!(!survives(
        owner(3),
        w.keyed(bytes, T, Admission::Owner { sig: unsigned })
    ));
}

#[test]
fn a_message_filed_under_an_id_it_does_not_derive_is_dropped() {
    let w = world();
    let (_, message) = w.owner_msg(ct(8192, 1), T);
    assert!(!survives(owner(3), (ByteArray::new([0xEE; 32]), message)));
}

#[test]
fn every_revocation_field_is_signed() {
    let w = world();
    let pass = contact();
    let good = w.revocation(pass.cert.pass_id, EXPIRY, 3);
    let held = w.pass_msg(&pass, ct(8192, 1), T);
    let forged = [
        Revocation {
            pass_id: id_of(99),
            ..good.clone()
        },
        Revocation {
            expiry: EXPIRY + DAY,
            ..good.clone()
        },
        Revocation {
            epoch: 4,
            ..good.clone()
        },
        {
            let mut r = good.clone();
            r.sig[0] ^= 1;
            r
        },
    ];
    for forged in forged {
        let raw = w.raw(owner(3), w.time(T), [forged.clone()], [], [held.clone()]);
        let merged = merge(&Rules::V1, &w.params, vec![raw.clone().into()]).unwrap();
        assert!(merged.revoked.is_empty(), "{forged:?} kept");
        assert_eq!(merged.messages.len(), 1, "{forged:?} revoked a pass");
        assert!(!is_valid(&Rules::V1, &w.params, &encode(&raw)));
    }
    // And the genuine one does revoke.
    let raw = w.raw(owner(3), w.time(T), [good], [], [held]);
    let merged = merge(&Rules::V1, &w.params, vec![raw.into()]).unwrap();
    assert_eq!((merged.revoked.len(), merged.messages.len()), (1, 0));
}

#[test]
fn a_genuine_revocation_filed_under_another_id_is_dropped() {
    let w = world();
    let good = w.revocation(id_of(1), EXPIRY, 3);
    let mut raw = w.raw(owner(3), w.time(T), [], [], []);
    raw.revoked.insert(id_of(2), good);
    let merged = merge(&Rules::V1, &w.params, vec![raw.into()]).unwrap();
    assert!(merged.revoked.is_empty());
}

/// A pass certified for a small-order key can be signed for by anyone, so the
/// strict check is what refuses it, not the arithmetic.
#[test]
fn a_certificate_for_a_weak_key_is_no_use() {
    let w = world();
    let bytes = ct(8192, 1);
    // The identity point as the key; as R, with S = 0, it verifies any message.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let mut cert = contact().cert;
    cert.pass_vk = ByteArray::new(identity);
    cert.sig = sign64(&w.issuer, &cert_bytes(&cert));
    let mut any = [0u8; 64];
    any[..32].copy_from_slice(&identity);
    let admission = Admission::Pass {
        cert,
        msg_sig: ByteArray::new(any),
    };
    assert!(!survives(owner(3), w.keyed(bytes, T, admission)));
}

#[test]
fn a_genuine_usage_entry_filed_under_another_id_is_dropped() {
    let w = world();
    let mut raw = w.raw(owner(3), w.time(T), [], [], []);
    raw.usage.insert(id_of(2), w.usage(id_of(1), 2, EXPIRY));
    let merged = merge(&Rules::V1, &w.params, vec![raw.into()]).unwrap();
    assert!(merged.usage.is_empty());
}

#[test]
fn every_usage_field_is_signed() {
    let w = world();
    let good = w.usage(id_of(1), 2, EXPIRY);
    let forged = [
        PassUsage {
            pass_id: id_of(2),
            ..good.clone()
        },
        PassUsage {
            used: 3,
            ..good.clone()
        },
        PassUsage {
            expiry: EXPIRY + DAY,
            ..good.clone()
        },
        {
            let mut u = good.clone();
            u.sig[0] ^= 1;
            u
        },
    ];
    for forged in forged {
        let raw = w.raw(owner(3), w.time(T), [], [forged.clone()], []);
        let merged = merge(&Rules::V1, &w.params, vec![raw.clone().into()]).unwrap();
        assert!(merged.usage.is_empty(), "{forged:?} kept");
        assert!(!is_valid(&Rules::V1, &w.params, &encode(&raw)));
    }
    let raw = w.raw(owner(3), w.time(T), [], [good], []);
    assert!(is_valid(&Rules::V1, &w.params, &encode(&raw)));
}

#[test]
fn the_time_is_signed() {
    let w = world();
    let forged_time = TimeAttestation {
        owner_time: T + DAY,
        ..w.time(T)
    };
    let raw = w.raw(owner(3), forged_time, [], [], []);
    assert!(!is_valid(&Rules::V1, &w.params, &encode(&raw)));
    assert_eq!(
        merge(&Rules::V1, &w.params, vec![raw.clone().into()]),
        Err(Malformed("no time attestation"))
    );

    // Beside a genuine time, a forged later one loses to it rather than
    // refusing the merge.
    let good = w.raw(owner(3), w.time(T), [], [], []);
    let merged = apply(
        &Rules::V1,
        &w.params,
        &encode(&good),
        update_state(encode(&raw)),
    )
    .unwrap();
    assert_eq!(merged, encode(&good));
}

#[test]
fn every_owner_field_is_signed() {
    let w = world();
    let good = owner(3);
    assert!(is_valid(
        &Rules::V1,
        &w.params,
        &encode(&w.raw(good.clone(), w.time(T), [], [], []))
    ));
    type Change = fn(&mut OwnerRecord);
    let tamper: [(&str, Change); 7] = [
        ("version", |o| o.version += 1),
        ("pass_epoch", |o| o.pass_epoch += 1),
        ("issuer_vk", |o| o.issuer_vk[0] ^= 1),
        ("quarantine", |o| {
            o.quarantine = QuarantineMode::RequireGhost { min_usd: None }
        }),
        ("kem_ek", |o| o.kem_ek[0] ^= 1),
        ("tombstones", |o| {
            o.tombstones.insert(ByteArray::new([1; 32]), T);
        }),
        ("sig", |o| o.sig[0] ^= 1),
    ];
    for (name, change) in tamper {
        let mut forged = good.clone();
        change(&mut forged);
        let raw = w.raw(forged, w.time(T), [], [], []);
        assert!(
            !is_valid(&Rules::V1, &w.params, &encode(&raw)),
            "{name} validated"
        );
        // A forged owner is refused outright, even beside a genuine state.
        let base = encode(&w.raw(good.clone(), w.time(T), [], [], []));
        assert!(
            apply(&Rules::V1, &w.params, &base, update_state(encode(&raw))).is_err(),
            "{name}"
        );
    }
}

#[test]
fn another_keys_owner_record_is_not_this_inbox() {
    let w = world();
    let other = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&[8u8; 32].into());
    use ml_dsa::signature::{Keypair, Signer as _};
    let mut forged = owner(3);
    forged.owner_vk = ByteBuf::from(other.verifying_key().encode().to_vec());
    let sig: ml_dsa::Signature<ml_dsa::MlDsa65> = other.sign(&owner_bytes(&w.params.addr, &forged));
    forged.sig = ByteBuf::from(sig.encode().to_vec());
    let raw = w.raw(forged, w.time(T), [], [], []);
    assert_eq!(
        merge(&Rules::V1, &w.params, vec![raw.into()]),
        Err(Malformed("owner key is not this address"))
    );
}

#[test]
fn an_owner_signature_for_another_address_does_not_verify() {
    let w = world();
    let mut forged = owner(3);
    let sig: ml_dsa::Signature<ml_dsa::MlDsa65> =
        ml_dsa::signature::Signer::sign(&w.dsa, &owner_bytes(&[0xAB; 24], &forged));
    forged.sig = ByteBuf::from(sig.encode().to_vec());
    let raw = w.raw(forged, w.time(T), [], [], []);
    assert_eq!(
        merge(&Rules::V1, &w.params, vec![raw.into()]),
        Err(Malformed("owner signature"))
    );
}

#[test]
fn the_time_and_entries_are_bound_to_the_address() {
    let w = world();
    let wrong = |bytes: Vec<u8>| sign64(&w.issuer, &bytes);
    let time = TimeAttestation {
        owner_time: T,
        sig: wrong(time_bytes(&[0xAB; 24], T)),
    };
    assert_eq!(
        merge(
            &Rules::V1,
            &w.params,
            vec![w.raw(owner(3), time, [], [], []).into()]
        ),
        Err(Malformed("no time attestation"))
    );
    let revocation = Revocation {
        pass_id: id_of(1),
        expiry: EXPIRY,
        epoch: 3,
        sig: wrong(revocation_bytes(&[0xAB; 24], &id_of(1), EXPIRY, 3)),
    };
    let usage = PassUsage {
        pass_id: id_of(1),
        used: 1,
        expiry: EXPIRY,
        sig: wrong(usage_bytes(&[0xAB; 24], &id_of(1), 1, EXPIRY)),
    };
    let raw = w.raw(owner(3), w.time(T), [revocation], [usage], []);
    let merged = merge(&Rules::V1, &w.params, vec![raw.into()]).unwrap();
    assert!(merged.revoked.is_empty() && merged.usage.is_empty());
}

/// The issuer key is an Ed25519 key, so `verify_strict` must hold: a signature
/// with a non-canonical S would be a second encoding of a genuine item.
#[test]
fn a_malleated_signature_is_refused() {
    let w = world();
    let good = w.issuer.sign(&time_bytes(&w.params.addr, T)).to_bytes();
    // S + L, the classic malleation.
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    let mut sig = good;
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = u16::from(sig[32 + i]) + u16::from(L[i]) + carry;
        sig[32 + i] = sum as u8;
        carry = sum >> 8;
    }
    if carry == 0 && sig[63] < 0x20 {
        let time = TimeAttestation {
            owner_time: T,
            sig: ByteArray::new(sig),
        };
        let raw = w.raw(owner(3), time, [], [], []);
        assert!(!is_valid(&Rules::V1, &w.params, &encode(&raw)));
    } else {
        panic!("this signature's S + L does not fit: pick another fixture");
    }
}

/// Signed by the owner, and still no use to a sender.
#[test]
fn a_kem_key_of_the_wrong_size_is_refused() {
    let w = world();
    for len in [1183, 1185] {
        let mut record = owner(3);
        record.kem_ek = ByteBuf::from(vec![1; len]);
        w.sign_owner(&mut record);
        let raw = w.raw(record, w.time(T), [], [], []);
        assert_eq!(
            merge(&Rules::V1, &w.params, vec![raw.into()]),
            Err(Malformed("owner KEM key"))
        );
    }
}
