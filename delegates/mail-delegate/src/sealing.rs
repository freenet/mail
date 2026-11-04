//! The inbox v2 ciphertext: `nonce24 ‖ ML-KEM ct ‖ XChaCha20-Poly1305` over
//! `len u32 ‖ CBOR(SealedEnvelope) ‖ zeros`, padded so the whole ciphertext
//! is one of the contract's sizes.
//!
//! The sender signs the inner binding over `blake3(body)`, where the body is
//! inside the ciphertext, so the binding can never cover the ciphertext. It
//! names the recipient, the `sent_time` and the admission's kind and tag, so
//! a copy restamped with another time, another pass or another Ghost Key
//! fails at the recipient even though the contract would hold it. The
//! signature is made under its own ML-DSA context (decision 24).

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use freenet_mail_protocol::address::address_of;
use freenet_mail_protocol::inbox_v2::{
    self as w, Admission, CIPHERTEXT_SIZES, KIND_OWNER, KIND_PASS, KIND_QUARANTINE, SealedBody,
    SealedEnvelope,
};
use freenet_mail_protocol::{Failure, FailureCode};
use ml_kem::kem::Encapsulate;
use serde_bytes::ByteBuf;

use crate::crypto::{self, Keys, MixRng};
use crate::store::fail;

const NONCE_LEN: usize = 24;
const KEM_CT_LEN: usize = 1088;
const TAG_LEN: usize = 16;
/// What a ciphertext adds to its plaintext.
pub const OVERHEAD: usize = NONCE_LEN + KEM_CT_LEN + TAG_LEN;
const LEN_PREFIX: usize = 4;
/// HKDF info for the v2 message key. Changing it breaks every v2 message.
const MESSAGE_KEY_INFO: &[u8] = b"freenet-mail v2 message key";
/// Bound into the AEAD, with the recipient's address.
const AAD_DOMAIN: &[u8] = b"fmail/ct/v2";

fn message_key(shared: &[u8]) -> [u8; 32] {
    let mut okm = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(None, shared)
        .expand(MESSAGE_KEY_INFO, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

fn aad(recipient: &[u8; 24]) -> Vec<u8> {
    [AAD_DOMAIN, recipient.as_slice()].concat()
}

/// The admission's kind and tag, as the inner binding and the id take them.
pub fn kind_and_tag(admission: &Admission, ghost_vk: Option<&w::B32>) -> Option<(u8, Vec<u8>)> {
    Some(match admission {
        Admission::Pass { cert, .. } => (KIND_PASS, cert.pass_id.to_vec()),
        Admission::Owner { .. } => (KIND_OWNER, Vec::new()),
        Admission::Quarantine { ghost: None } => (KIND_QUARANTINE, Vec::new()),
        // A proof's key comes from the envelope, where the sender bound it;
        // the id check below proves it is the key the proof claims.
        Admission::Quarantine { ghost: Some(_) } => (KIND_QUARANTINE, ghost_vk?.to_vec()),
    })
}

/// Seal `body` from `sender` to `recipient`'s KEM key.
#[allow(clippy::too_many_arguments)]
pub fn seal(
    sender: &Keys,
    recipient: &[u8; 24],
    recipient_ek: &[u8],
    sent_time: u64,
    kind: u8,
    tag: &[u8],
    body: &SealedBody,
    rng: &mut MixRng,
) -> Result<Vec<u8>, Failure> {
    let ek = crypto::decode_ek(recipient_ek).ok_or_else(|| {
        fail(
            FailureCode::BadInput,
            "the recipient's key is not ML-KEM-768",
        )
    })?;
    let body = w::encode(body);
    let body_hash = *blake3::hash(&body).as_bytes();
    let binding = w::inner_binding(recipient, &body_hash, sent_time, kind, tag);
    let envelope = w::encode(&SealedEnvelope {
        sender_vk: ByteBuf::from(sender.vk_bytes()),
        sender_sig: ByteBuf::from(sender.sign_v2(w::SEALED_SIG_CONTEXT, &binding)),
        body: ByteBuf::from(body),
    });
    let size = CIPHERTEXT_SIZES
        .into_iter()
        .find(|size| OVERHEAD + LEN_PREFIX + envelope.len() <= *size)
        .ok_or_else(|| fail(FailureCode::BadInput, "the message is too large"))?;
    let mut plaintext = Vec::with_capacity(size - OVERHEAD);
    plaintext.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
    plaintext.extend_from_slice(&envelope);
    plaintext.resize(size - OVERHEAD, 0);
    let (kem_ct, shared) = ek.encapsulate_with_rng(rng);
    let nonce: [u8; NONCE_LEN] = rng.bytes();
    let sealed = XChaCha20Poly1305::new(&message_key(shared.as_slice()).into())
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &plaintext,
                aad: &aad(recipient),
            },
        )
        .expect("XChaCha20-Poly1305 encryption of an in-memory buffer cannot fail");
    let kem_ct: &[u8] = kem_ct.as_ref();
    let out = [nonce.as_slice(), kem_ct, &sealed].concat();
    debug_assert_eq!(out.len(), size);
    Ok(out)
}

/// A message that opened and whose binding verified.
pub struct Opened {
    pub sender_vk: Vec<u8>,
    pub body: SealedBody,
}

/// Open message `id` of `recipient`'s inbox. `None` for anything that does
/// not decrypt, does not decode, or whose sender's binding does not name this
/// message: such a message can never be read, by anyone.
pub fn open(keys: &Keys, recipient: &[u8; 24], id: &[u8; 32], m: &w::Message) -> Option<Opened> {
    let ct = m.ciphertext.as_slice();
    if !CIPHERTEXT_SIZES.contains(&ct.len()) {
        return None;
    }
    let (nonce, rest) = ct.split_at(NONCE_LEN);
    let (kem_ct, sealed) = rest.split_at(KEM_CT_LEN);
    let shared = ml_kem::kem::Decapsulate::decapsulate_slice(&keys.kem, kem_ct).ok()?;
    let nonce: [u8; NONCE_LEN] = nonce.try_into().ok()?;
    let plaintext = XChaCha20Poly1305::new(&message_key(shared.as_slice()).into())
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: sealed,
                aad: &aad(recipient),
            },
        )
        .ok()?;
    let len = u32::from_be_bytes(plaintext.get(..LEN_PREFIX)?.try_into().ok()?) as usize;
    let end = LEN_PREFIX.checked_add(len)?;
    if plaintext.get(end..)?.iter().any(|b| *b != 0) {
        return None;
    }
    let envelope: SealedEnvelope = w::decode(&plaintext[LEN_PREFIX..end]).ok()?;
    let body: SealedBody = w::decode(&envelope.body).ok()?;
    let (kind, tag) = kind_and_tag(&m.admission, body.ghost_vk.as_ref())?;
    let ct_hash = *blake3::hash(ct).as_bytes();
    if w::message_id(recipient, &ct_hash, m.sent_time, kind, &tag) != *id {
        return None;
    }
    let body_hash = *blake3::hash(&envelope.body).as_bytes();
    let binding = w::inner_binding(recipient, &body_hash, m.sent_time, kind, &tag);
    if !crypto::verify_v2(
        w::SEALED_SIG_CONTEXT,
        &binding,
        &envelope.sender_vk,
        &envelope.sender_sig,
    ) {
        return None;
    }
    // The way back must lead to the sender's own inbox.
    if *body.reply_pass.cert.recipient != address_of(&envelope.sender_vk).0 {
        return None;
    }
    Some(Opened {
        sender_vk: envelope.sender_vk.into_vec(),
        body,
    })
}
