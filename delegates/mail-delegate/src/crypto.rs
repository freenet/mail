//! Identity keys and the v0.2.x (v1 inbox) message crypto.
//!
//! The layouts here must match what v0.2.x clients produce and accept; the
//! known-answer tests at the bottom reuse the vectors captured from the
//! release-candidate crates in B1 (`ui/src/inbox/*_vectors_v1.txt`).

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use freenet_mail_protocol::{DsaSeed, Entropy, KemSeed};
use ml_dsa::signature::{Keypair, Signer};
use ml_dsa::{MlDsa65, SigningKey};
use ml_kem::kem::{Decapsulate, Encapsulate, Key, KeyExport};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem768};

/// ML-KEM-768 ciphertext length.
const KEM_CT_LEN: usize = 1088;
const NONCE_LEN: usize = 24;
/// HKDF info for the v1 message key. Changing it breaks every v1 message.
const V1_MESSAGE_KEY_INFO: &[u8] = b"freenet-email-v1 message-key";

/// An identity's key pair, rebuilt from its seeds.
pub struct Keys {
    pub dsa: SigningKey<MlDsa65>,
    pub kem: DecapsulationKey<MlKem768>,
}

impl Keys {
    pub fn from_seeds(dsa: &DsaSeed, kem: &KemSeed) -> Self {
        let dsa_seed = ml_dsa::Seed::from(dsa.0);
        let kem_seed = ml_kem::Seed::from(kem.0);
        Keys {
            dsa: SigningKey::<MlDsa65>::from_seed(&dsa_seed),
            kem: DecapsulationKey::<MlKem768>::new(&kem_seed),
        }
    }

    /// FIPS 204 encoded verifying key (1952 bytes).
    pub fn vk_bytes(&self) -> Vec<u8> {
        self.dsa.verifying_key().encode().to_vec()
    }

    /// FIPS 203 encoded encapsulation key (1184 bytes).
    pub fn ek_bytes(&self) -> Vec<u8> {
        self.kem.encapsulation_key().to_bytes().to_vec()
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let sig: ml_dsa::Signature<MlDsa65> = Signer::sign(&self.dsa, msg);
        sig.encode().to_vec()
    }
}

/// A CSPRNG that is secure if EITHER input is: BLAKE3 in XOF mode over the
/// host's random bytes and the caller's entropy, domain-separated by
/// `purpose`. The host's bytes alone are not trusted (a failed host call can
/// leave a stale buffer), and the caller's alone are not either.
pub struct MixRng(blake3::OutputReader);

impl MixRng {
    pub fn new(purpose: &str, host: &[u8; 32], caller: &Entropy) -> Self {
        let mut h = blake3::Hasher::new_derive_key("freenet-mail delegate rng v1");
        h.update(&(purpose.len() as u64).to_le_bytes());
        h.update(purpose.as_bytes());
        h.update(host);
        h.update(&caller.0);
        MixRng(h.finalize_xof())
    }

    pub fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        self.0.fill(&mut out);
        out
    }
}

impl rand_core::TryRng for MixRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(u32::from_le_bytes(self.bytes()))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(u64::from_le_bytes(self.bytes()))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.0.fill(dst);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for MixRng {}

/// Fresh seeds for a new identity.
pub fn new_seeds(rng: &mut MixRng) -> (DsaSeed, KemSeed) {
    (DsaSeed(rng.bytes()), KemSeed(rng.bytes()))
}

fn hkdf_v1_message_key(shared_secret: &[u8]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(V1_MESSAGE_KEY_INFO, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

/// Decode a v1 encapsulation key.
pub fn decode_ek(bytes: &[u8]) -> Option<EncapsulationKey<MlKem768>> {
    let key = Key::<EncapsulationKey<MlKem768>>::try_from(bytes).ok()?;
    EncapsulationKey::<MlKem768>::new(&key).ok()
}

/// v1 layout: `nonce (24) | ML-KEM ciphertext (1088) | XChaCha20-Poly1305`.
pub fn encrypt_v1(ek: &EncapsulationKey<MlKem768>, plaintext: &[u8], rng: &mut MixRng) -> Vec<u8> {
    let (ct, shared) = ek.encapsulate_with_rng(rng);
    let key = hkdf_v1_message_key(shared.as_slice());
    let nonce: [u8; NONCE_LEN] = rng.bytes();
    let sealed = XChaCha20Poly1305::new(&key.into())
        .encrypt(&XNonce::from(nonce), plaintext)
        .expect("XChaCha20-Poly1305 encryption of an in-memory buffer cannot fail");
    let ct_bytes: &[u8] = ct.as_ref();
    let mut out = Vec::with_capacity(NONCE_LEN + KEM_CT_LEN + sealed.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(ct_bytes);
    out.extend_from_slice(&sealed);
    out
}

/// Inverse of [`encrypt_v1`]. `None` for anything that does not decrypt.
pub fn decrypt_v1(dk: &DecapsulationKey<MlKem768>, content: &[u8]) -> Option<Vec<u8>> {
    if content.len() < NONCE_LEN + KEM_CT_LEN {
        return None;
    }
    let (nonce, rest) = content.split_at(NONCE_LEN);
    let (kem_ct, sealed) = rest.split_at(KEM_CT_LEN);
    let shared = dk.decapsulate_slice(kem_ct).ok()?;
    let key = hkdf_v1_message_key(shared.as_slice());
    let nonce: [u8; NONCE_LEN] = nonce.try_into().ok()?;
    XChaCha20Poly1305::new(&key.into())
        .decrypt(&XNonce::from(nonce), sealed)
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `key value` lines from a B1 vector file.
    fn field(file: &str, name: &str) -> Vec<u8> {
        let hex = file
            .lines()
            .find_map(|l| l.strip_prefix(name)?.strip_prefix(' '))
            .unwrap_or_else(|| panic!("{name} missing from the vector file"));
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    const VECTORS: &str = include_str!("../../../ui/src/inbox/crypto_vectors_v1.txt");

    // The inputs B1 captured the vectors from (ui/src/inbox/crypto_vectors.rs).
    const SIGNED_MSG: &[u8] = b"freenet-mail crypto vector v1";
    const ENVELOPE_PLAINTEXT: &[u8] = b"hello from the rc crates";

    fn vector_keys() -> Keys {
        Keys::from_seeds(
            &DsaSeed([7; 32]),
            &KemSeed(std::array::from_fn(|i| i as u8)),
        )
    }

    #[test]
    fn seeds_derive_the_v0_2_x_keys() {
        let keys = vector_keys();
        assert_eq!(keys.vk_bytes(), field(VECTORS, "dsa_vk"));
        assert_eq!(keys.ek_bytes(), field(VECTORS, "kem_ek"));
    }

    #[test]
    fn a_v0_2_x_message_still_decrypts() {
        let keys = vector_keys();
        let pt = decrypt_v1(&keys.kem, &field(VECTORS, "envelope")).expect("decrypts");
        assert_eq!(pt, ENVELOPE_PLAINTEXT);
    }

    #[test]
    fn signatures_match_the_v0_2_x_bytes() {
        let keys = vector_keys();
        assert_eq!(keys.sign(SIGNED_MSG), field(VECTORS, "dsa_sig"));
    }

    #[test]
    fn sealing_round_trips_and_is_bound_to_the_entropy() {
        let keys = vector_keys();
        let ek = decode_ek(&keys.ek_bytes()).unwrap();
        let mut a = MixRng::new("seal-v1", &[1; 32], &Entropy([2; 32]));
        let mut b = MixRng::new("seal-v1", &[1; 32], &Entropy([3; 32]));
        let ct_a = encrypt_v1(&ek, b"hello", &mut a);
        let ct_b = encrypt_v1(&ek, b"hello", &mut b);
        assert_ne!(ct_a, ct_b, "different caller entropy, different ciphertext");
        assert_eq!(decrypt_v1(&keys.kem, &ct_a).unwrap(), b"hello");
        let mut tampered = ct_a.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(decrypt_v1(&keys.kem, &tampered), None);
        assert_eq!(decrypt_v1(&keys.kem, &ct_a[..100]), None);
    }

    #[test]
    fn the_mixer_depends_on_both_inputs_and_the_purpose() {
        let base = MixRng::new("p", &[1; 32], &Entropy([2; 32])).bytes::<32>();
        assert_ne!(
            base,
            MixRng::new("p", &[9; 32], &Entropy([2; 32])).bytes::<32>()
        );
        assert_ne!(
            base,
            MixRng::new("p", &[1; 32], &Entropy([9; 32])).bytes::<32>()
        );
        assert_ne!(
            base,
            MixRng::new("q", &[1; 32], &Entropy([2; 32])).bytes::<32>()
        );
    }
}
