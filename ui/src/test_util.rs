use std::str::FromStr;

use freenet_aft_interface::{Tier, TokenAssignment};
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
