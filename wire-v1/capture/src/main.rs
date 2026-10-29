//! Captures the v0.2.x golden fixtures through the frozen crates and the
//! crypto crates every v0.2.x client shipped with (ml-dsa 0.1.0-rc.8,
//! ml-kem 0.3.0-rc.2, hkdf 0.12). From the repository root:
//!
//! ```text
//! cargo run --locked --manifest-path wire-v1/capture/Cargo.toml -- golden \
//!     > wire-v1/src/golden_v1.txt
//! cargo run --locked --manifest-path wire-v1/capture/Cargo.toml -- kem \
//!     > ui/src/inbox/kem_vectors_v1.txt
//! cargo run --locked --manifest-path wire-v1/capture/Cargo.toml -- defaults \
//!     > ui/src/register_defaults_v1.txt
//! ```
//!
//! CI runs both and fails if the output differs from the committed files.

use freenet_aft_interface as aft;
use freenet_email_inbox as inbox;
use identity_management as identity;
use mail_local_state as local_state;

fn dsa_signing_key(seed: [u8; 32]) -> ml_dsa::SigningKey<ml_dsa::MlDsa65> {
    use ml_dsa::KeyGen;
    ml_dsa::MlDsa65::from_seed(&seed.into())
}

include!("../../src/golden_samples.rs");
include!("../../../ui/src/inbox/kem_fixed_rng.rs");

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn golden() {
    for (name, bytes, codec) in golden_samples() {
        if let Some(rt) = codec {
            assert_eq!(rt(&bytes).unwrap(), bytes, "{name} does not round-trip");
        }
        println!("{name} {}", hex(&bytes));
    }
}

/// ML-KEM-768 encapsulation under a fixed RNG, the shared secret, and the
/// message key HKDF derives from it, from the KEM seed the crypto vectors
/// use. ML-KEM encapsulation is deterministic given its 32 random bytes, so
/// a later ml-kem that reproduces this ciphertext and secret from the same
/// RNG produces only ciphertexts these crates decapsulate.
fn kem() {
    use hkdf::Hkdf;
    use ml_kem::kem::{Decapsulate, Encapsulate};
    use ml_kem::{DecapsulationKey, MlKem768};
    use sha2::Sha256;

    let seed: [u8; 64] = std::array::from_fn(|i| i as u8);
    let dk = DecapsulationKey::<MlKem768>::from_seed(seed.into());
    let (ct, ss) = dk
        .encapsulation_key()
        .encapsulate_with_rng(&mut KemFixedRng::default());
    let ct_bytes: &[u8] = ct.as_ref();
    let back = dk.decapsulate_slice(ct_bytes).expect("decapsulate");
    assert_eq!(back.as_slice(), ss.as_slice());
    let mut okm = [0u8; 32];
    Hkdf::<Sha256>::new(None, ss.as_slice())
        .expand(b"freenet-email-v1 message-key", &mut okm)
        .expect("HKDF expand");
    println!("kem_ct_fixed_rng {}", hex(ct_bytes));
    println!("kem_shared_secret {}", hex(ss.as_slice()));
    println!("hkdf_message_key {}", hex(&okm));
}

/// The cipher and nonce every v0.2.x client sent with RegisterDelegate:
/// stdlib 0.3.5's defaults, which stdlib 0.12 no longer has.
fn defaults() {
    use freenet_stdlib::client_api::DelegateRequest;
    println!("register_cipher {}", hex(&DelegateRequest::DEFAULT_CIPHER));
    println!("register_nonce {}", hex(&DelegateRequest::DEFAULT_NONCE));
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("golden") => golden(),
        Some("kem") => kem(),
        Some("defaults") => defaults(),
        _ => {
            eprintln!("usage: wire-v1-capture golden|kem|defaults");
            std::process::exit(2);
        }
    }
}
