//! Byte layouts: what is signed, the message id, and the address.
//!
//! Manual layouts, never CBOR: a signature must not depend on a serializer.
//! Every layout starts with its own domain string. Integers are big-endian.
//! The fields of a layout have fixed sizes, or say their length, so no two
//! inputs of one layout share bytes.

use crate::types::{Admission, Message, OwnerRecord, PassCert, PassClass, QuarantineMode};

pub const KIND_PASS: u8 = 0;
pub const KIND_OWNER: u8 = 1;
pub const KIND_QUARANTINE: u8 = 2;

const ADDRESS_CONTEXT: &str = "freenet-mail address v1";
const ADDRESS_CHECK_CONTEXT: &str = "freenet-mail address check v1";

/// The 24-byte address of an ML-DSA verifying key.
pub fn address_of(owner_vk: &[u8]) -> [u8; 24] {
    let full = blake3::derive_key(ADDRESS_CONTEXT, owner_vk);
    let mut addr = [0u8; 24];
    addr.copy_from_slice(&full[..24]);
    addr
}

/// The address's 2-byte typing check. The contract never reads it: it is here
/// so the vector that pins it sits beside the address's.
pub fn address_check(addr: &[u8; 24]) -> [u8; 2] {
    let full = blake3::derive_key(ADDRESS_CHECK_CONTEXT, addr);
    [full[0], full[1]]
}

fn layout(domain: &str, capacity: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len() + capacity);
    out.extend_from_slice(domain.as_bytes());
    out
}

fn quarantine_bytes(out: &mut Vec<u8>, mode: QuarantineMode) {
    match mode {
        QuarantineMode::Open => out.push(0),
        QuarantineMode::RequireGhost { min_usd: None } => out.extend_from_slice(&[1, 0]),
        QuarantineMode::RequireGhost { min_usd: Some(usd) } => {
            out.extend_from_slice(&[1, 1]);
            out.extend_from_slice(&usd.to_be_bytes());
        }
    }
}

/// `"fmail/owner/v1" ‖ addr ‖ version ‖ pass_epoch ‖ issuer_vk ‖ quarantine ‖
/// len‖kem_ek ‖ count‖(id ‖ sent_time)*`. The verifying key is bound through
/// the address.
pub fn owner_bytes(addr: &[u8; 24], owner: &OwnerRecord) -> Vec<u8> {
    let mut out = layout(
        "fmail/owner/v1",
        128 + owner.kem_ek.len() + owner.tombstones.len() * 40,
    );
    out.extend_from_slice(addr);
    out.extend_from_slice(&owner.version.to_be_bytes());
    out.extend_from_slice(&owner.pass_epoch.to_be_bytes());
    out.extend_from_slice(owner.issuer_vk.as_slice());
    quarantine_bytes(&mut out, owner.quarantine);
    out.extend_from_slice(&(owner.kem_ek.len() as u32).to_be_bytes());
    out.extend_from_slice(&owner.kem_ek);
    out.extend_from_slice(&(owner.tombstones.len() as u32).to_be_bytes());
    for (id, sent_time) in &owner.tombstones {
        out.extend_from_slice(id.as_slice());
        out.extend_from_slice(&sent_time.to_be_bytes());
    }
    out
}

/// `"fmail/time/v1" ‖ addr ‖ owner_time`
pub fn time_bytes(addr: &[u8; 24], owner_time: u64) -> Vec<u8> {
    let mut out = layout("fmail/time/v1", 32);
    out.extend_from_slice(addr);
    out.extend_from_slice(&owner_time.to_be_bytes());
    out
}

/// `"fmail/pass/v1" ‖ recipient ‖ pass_id ‖ pass_vk ‖ epoch ‖ expiry ‖ class`
pub fn cert_bytes(cert: &PassCert) -> Vec<u8> {
    let mut out = layout("fmail/pass/v1", 90);
    out.extend_from_slice(cert.recipient.as_slice());
    out.extend_from_slice(cert.pass_id.as_slice());
    out.extend_from_slice(cert.pass_vk.as_slice());
    out.extend_from_slice(&cert.epoch.to_be_bytes());
    out.extend_from_slice(&cert.expiry.to_be_bytes());
    match cert.class {
        PassClass::Contact => out.push(0),
        PassClass::Invite { max_messages } => out.extend_from_slice(&[1, max_messages]),
    }
    out
}

/// `"fmail/revoke/v1" ‖ addr ‖ pass_id ‖ expiry ‖ epoch`
pub fn revocation_bytes(addr: &[u8; 24], pass_id: &[u8; 16], expiry: u64, epoch: u32) -> Vec<u8> {
    let mut out = layout("fmail/revoke/v1", 52);
    out.extend_from_slice(addr);
    out.extend_from_slice(pass_id);
    out.extend_from_slice(&expiry.to_be_bytes());
    out.extend_from_slice(&epoch.to_be_bytes());
    out
}

/// `"fmail/usage/v1" ‖ addr ‖ pass_id ‖ used ‖ expiry`
pub fn usage_bytes(addr: &[u8; 24], pass_id: &[u8; 16], used: u8, expiry: u64) -> Vec<u8> {
    let mut out = layout("fmail/usage/v1", 49);
    out.extend_from_slice(addr);
    out.extend_from_slice(pass_id);
    out.push(used);
    out.extend_from_slice(&expiry.to_be_bytes());
    out
}

fn stamped(domain: &str, recipient: &[u8; 24], sent_time: u64, ct_hash: &[u8; 32]) -> Vec<u8> {
    let mut out = layout(domain, 64);
    out.extend_from_slice(recipient);
    out.extend_from_slice(&sent_time.to_be_bytes());
    out.extend_from_slice(ct_hash);
    out
}

/// The pass key's signature: `"fmail/admit/v1" ‖ recipient ‖ sent_time ‖ blake3(ct)`
pub fn admit_bytes(recipient: &[u8; 24], sent_time: u64, ct_hash: &[u8; 32]) -> Vec<u8> {
    stamped("fmail/admit/v1", recipient, sent_time, ct_hash)
}

/// The issuer key's signature on an owner message:
/// `"fmail/owner-msg/v1" ‖ recipient ‖ sent_time ‖ blake3(ct)`
pub fn owner_msg_bytes(recipient: &[u8; 24], sent_time: u64, ct_hash: &[u8; 32]) -> Vec<u8> {
    stamped("fmail/owner-msg/v1", recipient, sent_time, ct_hash)
}

/// The Ghost Key proof's `ScopedPayload.payload`:
/// `"fmail/ghost-admit/v1" ‖ recipient ‖ sent_time ‖ blake3(ct)`. The proof
/// stays out of the ciphertext, so this is not circular.
pub fn ghost_admit_bytes(recipient: &[u8; 24], sent_time: u64, ct_hash: &[u8; 32]) -> Vec<u8> {
    stamped("fmail/ghost-admit/v1", recipient, sent_time, ct_hash)
}

/// The sender's ML-DSA signature inside the envelope:
/// `"fmail/sealed/v1" ‖ recipient ‖ blake3(body) ‖ sent_time ‖ kind ‖
/// (pass_id | ghost_vk | ∅)`. It takes the body, never the ciphertext, because
/// the signature is inside the ciphertext. The contract cannot see this; the
/// layout is here so the vector that pins it sits beside the others.
pub fn inner_binding(
    recipient: &[u8; 24],
    body_hash: &[u8; 32],
    sent_time: u64,
    kind: u8,
    tag: &[u8],
) -> Vec<u8> {
    let mut out = layout("fmail/sealed/v1", 65 + tag.len());
    out.extend_from_slice(recipient);
    out.extend_from_slice(body_hash);
    out.extend_from_slice(&sent_time.to_be_bytes());
    out.push(kind);
    out.extend_from_slice(tag);
    out
}

/// `blake3("fmail/msgid/v1" ‖ recipient ‖ blake3(ct) ‖ sent_time ‖ kind ‖ pass_id?)`
pub fn message_id(recipient: &[u8; 24], message: &Message, ct_hash: &[u8; 32]) -> [u8; 32] {
    let mut bytes = layout("fmail/msgid/v1", 81);
    bytes.extend_from_slice(recipient);
    bytes.extend_from_slice(ct_hash);
    bytes.extend_from_slice(&message.sent_time.to_be_bytes());
    match &message.admission {
        Admission::Pass { cert, .. } => {
            bytes.push(KIND_PASS);
            bytes.extend_from_slice(cert.pass_id.as_slice());
        }
        Admission::Owner { .. } => bytes.push(KIND_OWNER),
        Admission::Quarantine { .. } => bytes.push(KIND_QUARANTINE),
    }
    *blake3::hash(&bytes).as_bytes()
}
