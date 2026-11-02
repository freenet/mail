//! Previous contract and delegate generations, generated at build time from
//! the repo-root `legacy_*.toml` registries by `freenet-migrate-build` (see
//! `build.rs`). Each list holds predecessors only, so a migration walks
//! exactly the keys data may still live under.
//!
//! The delegate lists feed the walk in `crate::migration`, and end at the
//! v1 generation frozen in `published-contract/wasm/v1/`: the mail delegate
//! replaced those two delegates and must never appear here. The inbox list
//! is not read at runtime yet (the shipped inbox is still the v1 one).

#[allow(dead_code)]
mod inbox {
    include!(concat!(env!("OUT_DIR"), "/legacy_inbox.rs"));
}
#[allow(dead_code)]
mod identity {
    include!(concat!(env!("OUT_DIR"), "/legacy_identity_delegate.rs"));
}
#[allow(dead_code)]
mod local_state {
    include!(concat!(env!("OUT_DIR"), "/legacy_local_state_delegate.rs"));
}

/// Previous inbox contract code hashes, oldest first.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const LEGACY_INBOX_CODE_HASHES: &[[u8; 32]] = inbox::LEGACY_INBOX_CODE_HASHES;
/// Previous identity-management delegates, oldest first, as
/// `(delegate_key, code_hash)`.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const LEGACY_IDENTITY_DELEGATES: &[([u8; 32], [u8; 32])] =
    identity::LEGACY_IDENTITY_DELEGATES;
/// Previous mail-local-state delegates, oldest first, as
/// `(delegate_key, code_hash)`.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const LEGACY_LOCAL_STATE_DELEGATES: &[([u8; 32], [u8; 32])] =
    local_state::LEGACY_LOCAL_STATE_DELEGATES;
/// The same identity-management rows, as the walk takes them.
pub(crate) const IDENTITY_LINEAGE: &[freenet_migrate::DelegateLineageEntry] =
    identity::DELEGATE_LINEAGE;
/// The same mail-local-state rows, as the walk takes them.
pub(crate) const LOCAL_STATE_LINEAGE: &[freenet_migrate::DelegateLineageEntry] =
    local_state::DELEGATE_LINEAGE;

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
            &[
                (
                    hex32("6ce4197510093e1f6e035dd077830a1cc0b9772cbfc1559ffa6c0012c15359bd"),
                    b58("2gFVM7AznH6gtMi2onvtKS2fosg3QFTnJSNNTYrHsrSV"),
                ),
                (
                    hex32("08f93deef99256f513900e1a3cf258bd9d3f93cbef6a5b65133cceed42ac2dbc"),
                    b58("BbtKhHhRR24CZ1vdnzErMtJejWxNL3VKAisgu6Wggkht"),
                ),
            ]
        );
        assert_eq!(
            LEGACY_LOCAL_STATE_DELEGATES,
            &[
                (
                    hex32("874fe75799e2684f41ce8f16bbec915b0edebe03f4540eafa6da1ec4694e4004"),
                    b58("2VLTifcxLyhkw8XQEn4ZvT846UJu5jGnLaYCcaZcfYXw"),
                ),
                (
                    hex32("b7a6835fe68cf1544aa7060c42644296dcd2112558faf1305f4fa7e44c09f255"),
                    b58("5FGNJrAWVxvXjkZxwRm4MptGXu53XUP6epnaGAGT4wGT"),
                ),
            ]
        );
    }

    /// The newest rows are the frozen v1 artifacts, which hold the newest
    /// user data: their hashes and keys come from the committed files and the
    /// keys the v0.2.x client derived, not from a copy typed into the TOML.
    #[test]
    fn the_newest_rows_are_the_frozen_v1_delegates() {
        let identity = LEGACY_IDENTITY_DELEGATES.last().unwrap();
        assert_eq!(
            identity.1,
            b58(include_str!(
                "../../published-contract/wasm/v1/identity_management_code_hash"
            ))
        );
        assert_eq!(
            crate::test_util::hex(&identity.0),
            crate::test_util::frozen_key("identity_delegate")
        );
        let local_state = LEGACY_LOCAL_STATE_DELEGATES.last().unwrap();
        assert_eq!(
            local_state.1,
            b58(include_str!(
                "../../published-contract/wasm/v1/mail_local_state_code_hash"
            ))
        );
        assert_eq!(
            crate::test_util::hex(&local_state.0),
            crate::test_util::frozen_key("local_state_delegate")
        );
    }

    /// The generation in use must never appear among its own predecessors:
    /// a migration would then "migrate" a user onto the key they already use.
    /// For the delegates that is the mail delegate; the inbox is still v1.
    #[test]
    fn the_generation_in_use_is_not_a_predecessor() {
        let inbox = b58(include_str!(
            "../../published-contract/wasm/v1/inbox_code_hash"
        ));
        assert!(!LEGACY_INBOX_CODE_HASHES.contains(&inbox));

        let mail = b58(include_str!(
            "../../published-contract/candidate/mail_delegate_code_hash"
        ));
        for (_, code_hash) in LEGACY_IDENTITY_DELEGATES
            .iter()
            .chain(LEGACY_LOCAL_STATE_DELEGATES)
        {
            assert_ne!(*code_hash, mail);
        }
    }
}
