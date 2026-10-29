//! Known-answer vectors captured with ml-dsa 0.1.0-rc.8, ml-kem 0.3.0-rc.2,
//! chacha20poly1305 0.10 and hkdf 0.12, the crates every v0.2.x identity was
//! created with. A crypto dependency bump must reproduce them: the same seed
//! has to yield the same keys (a restored backup must still own its inbox),
//! signing must stay byte-identical (the deployed inbox contract verifies
//! with rc.8), and a message encrypted by the old stack must still decrypt.

use super::*;

const VECTORS: &str = include_str!("crypto_vectors_v1.txt");
const DSA_SEED: [u8; 32] = [7; 32];
const SIGNED_MSG: &[u8] = b"freenet-mail crypto vector v1";
const ENVELOPE_PLAINTEXT: &[u8] = b"hello from the rc crates";

fn kem_seed() -> [u8; 64] {
    std::array::from_fn(|i| i as u8)
}

fn vector(name: &str) -> Vec<u8> {
    let hex = VECTORS
        .lines()
        .find_map(|l| l.strip_prefix(name)?.strip_prefix(' '))
        .unwrap_or_else(|| panic!("missing vector {name}"));
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn ml_dsa_seed_derives_the_v1_verifying_key() {
    let sk = ml_dsa::SigningKey::<MlDsa65>::from_seed(&DSA_SEED.into());
    let vk = MlDsaKeypair::verifying_key(&sk);
    assert_eq!(vk.encode().to_vec(), vector("dsa_vk"));
}

#[test]
fn ml_dsa_signature_is_byte_identical_to_v1() {
    let sk = ml_dsa::SigningKey::<MlDsa65>::from_seed(&DSA_SEED.into());
    let sig: ml_dsa::Signature<MlDsa65> = MlDsaSigner::sign(&sk, SIGNED_MSG);
    assert_eq!(sig.encode().to_vec(), vector("dsa_sig"));
}

#[test]
fn v1_signature_verifies() {
    assert!(verify_message_signature(
        SIGNED_MSG,
        &vector("dsa_vk"),
        &vector("dsa_sig")
    ));
}

#[test]
fn ml_kem_seed_derives_the_v1_encapsulation_key() {
    let dk = DecapsulationKey::<MlKem768>::from_seed(kem_seed().into());
    assert_eq!(
        dk.encapsulation_key().to_bytes().to_vec(),
        vector("kem_ek")
    );
}

#[test]
fn v1_envelope_still_decrypts() {
    let dk = DecapsulationKey::<MlKem768>::from_seed(kem_seed().into());
    let plaintext = ml_kem_decrypt(&dk, vector("envelope")).unwrap();
    assert_eq!(plaintext, ENVELOPE_PLAINTEXT);
}

#[test]
fn envelope_round_trips_under_current_crates() {
    let dk = DecapsulationKey::<MlKem768>::from_seed(kem_seed().into());
    let env = ml_kem_encrypt(dk.encapsulation_key(), b"round trip").unwrap();
    assert_eq!(ml_kem_decrypt(&dk, env).unwrap(), b"round trip");
}
