use std::str::FromStr;

use freenet_mail_wire_v1::aft::{Tier, TokenAssignment};
use freenet_stdlib::prelude::ContractInstanceId;

pub(crate) fn test_assignment() -> TokenAssignment {
    // Synthetic ML-DSA-65 placeholder values — this fixture is consumed only
    // by code paths that don't verify the signature (e.g. UI list rendering).
    TokenAssignment {
        tier: Tier::Day1,
        time_slot: Default::default(),
        generator: vec![0u8; 1952],
        signature: vec![1u8; 64],
        assignment_hash: [0; 32],
        token_record: ContractInstanceId::from_str("7MxRGrYiBBK2rHCVpP25SxqBLco2h4zpb2szsTS7XXgg")
            .unwrap(),
    }
}

/// A key from `frozen_keys_v1.txt`, in hex: what the v0.2.x client (stdlib
/// 0.3.5) derived for fixed inputs against the frozen v1 code hashes. A
/// client whose derivation drifts addresses a different contract or
/// delegate, and every stored secret and message becomes unreachable.
pub(crate) fn frozen_key(name: &str) -> String {
    include_str!("frozen_keys_v1.txt")
        .lines()
        .find_map(|l| l.strip_prefix(name)?.strip_prefix(' '))
        .unwrap_or_else(|| panic!("no frozen key {name}"))
        .to_string()
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Real ML-DSA-65 verifying-key bytes for `seed`, for tests that derive
/// inbox ids (an arbitrary byte pattern is not a verifying key).
pub(crate) fn real_vk_bytes(seed: u8) -> Vec<u8> {
    use ml_dsa::signature::Keypair;
    ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&[seed; 32].into())
        .verifying_key()
        .encode()
        .to_vec()
}

/// The signing key the frozen-key fixtures were captured with.
pub(crate) fn frozen_fixture_vk() -> ml_dsa::VerifyingKey<ml_dsa::MlDsa65> {
    use ml_dsa::signature::Keypair;
    ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&[7u8; 32].into()).verifying_key()
}
