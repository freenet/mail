//! Identity and contact addresses.

/// BLAKE3 key-derivation context for addresses.
pub const ADDRESS_CONTEXT: &str = "freenet-mail address v1";

/// The 24-byte address of an ML-DSA-65 verifying key (FIPS 204 encoding).
pub fn address_of(ml_dsa_vk: &[u8]) -> crate::Addr {
    let full = blake3::derive_key(ADDRESS_CONTEXT, ml_dsa_vk);
    let mut addr = [0u8; 24];
    addr.copy_from_slice(&full[..24]);
    crate::Addr(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_is_a_prefix_of_the_derived_key() {
        let vk = [9u8; 1952];
        let full = blake3::derive_key(ADDRESS_CONTEXT, &vk);
        assert_eq!(address_of(&vk).0[..], full[..24]);
        assert_ne!(address_of(&vk), address_of(&[8u8; 1952]));
    }
}
