//! Previous contract and delegate generations, generated at build time from
//! the repo-root `legacy_*.toml` registries by `freenet-migrate-build` (see
//! `build.rs`). Each list holds predecessors only, never the shipped
//! generation, so a migration walks exactly the keys data may still live
//! under.
//!
//! Not consumed at runtime yet: the delegate and inbox migrations that read
//! these lists arrive with the platform upgrade. Until then the tests below
//! keep the registries honest.
#![allow(dead_code)]

mod inbox {
    include!(concat!(env!("OUT_DIR"), "/legacy_inbox.rs"));
}
mod identity {
    include!(concat!(env!("OUT_DIR"), "/legacy_identity_delegate.rs"));
}
mod local_state {
    include!(concat!(env!("OUT_DIR"), "/legacy_local_state_delegate.rs"));
}

/// Previous inbox contract code hashes, oldest first.
pub(crate) const LEGACY_INBOX_CODE_HASHES: &[[u8; 32]] = inbox::LEGACY_INBOX_CODE_HASHES;
/// Previous identity-management delegates, oldest first, as
/// `(delegate_key, code_hash)`.
pub(crate) const LEGACY_IDENTITY_DELEGATES: &[([u8; 32], [u8; 32])] =
    identity::LEGACY_IDENTITY_DELEGATES;
/// Previous mail-local-state delegates, oldest first, as
/// `(delegate_key, code_hash)`.
pub(crate) const LEGACY_LOCAL_STATE_DELEGATES: &[([u8; 32], [u8; 32])] =
    local_state::LEGACY_LOCAL_STATE_DELEGATES;

#[cfg(test)]
mod tests {
    use super::*;

    fn b58(s: &str) -> [u8; 32] {
        bs58::decode(s.trim())
            .into_vec()
            .expect("base58")
            .try_into()
            .expect("32 bytes")
    }

    fn hex32(s: &str) -> [u8; 32] {
        let bytes: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect();
        bytes.try_into().expect("32 bytes")
    }

    /// Pins every row. Changing a registry must change this test in the same
    /// commit; a row that silently disappears or changes strands its users.
    #[test]
    fn registries_pin_exact_rows() {
        assert_eq!(
            LEGACY_INBOX_CODE_HASHES,
            &[
                b58("Ht8rcMjTpnraRNbzkmDCBFJJfmQGJ8M2iUAGaZimE9Ji"),
                b58("9Kuhod6Bfrd2uZAtVNtQKVWy4mku3tbfv2zop1u9HU98"),
            ]
        );
        assert_eq!(
            LEGACY_IDENTITY_DELEGATES,
            &[(
                hex32("6ce4197510093e1f6e035dd077830a1cc0b9772cbfc1559ffa6c0012c15359bd"),
                b58("2gFVM7AznH6gtMi2onvtKS2fosg3QFTnJSNNTYrHsrSV"),
            )]
        );
        assert_eq!(
            LEGACY_LOCAL_STATE_DELEGATES,
            &[(
                hex32("874fe75799e2684f41ce8f16bbec915b0edebe03f4540eafa6da1ec4694e4004"),
                b58("2VLTifcxLyhkw8XQEn4ZvT846UJu5jGnLaYCcaZcfYXw"),
            )]
        );
    }

    /// The shipped generation must never appear among its own predecessors:
    /// a migration would then "migrate" a user onto the key they already use.
    #[test]
    fn shipped_generation_is_not_a_predecessor() {
        let inbox = b58(include_str!(
            "../../published-contract/wasm/v1/inbox_code_hash"
        ));
        assert!(!LEGACY_INBOX_CODE_HASHES.contains(&inbox));

        let identity = b58(include_str!(
            "../../published-contract/wasm/v1/identity_management_code_hash"
        ));
        assert!(
            LEGACY_IDENTITY_DELEGATES
                .iter()
                .all(|(_, h)| *h != identity)
        );

        let local_state = b58(include_str!(
            "../../published-contract/wasm/v1/mail_local_state_code_hash"
        ));
        assert!(
            LEGACY_LOCAL_STATE_DELEGATES
                .iter()
                .all(|(_, h)| *h != local_state)
        );
    }
}
