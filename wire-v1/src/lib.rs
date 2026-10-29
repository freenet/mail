//! The wire types of the v0.2.x generation, for the client.
//!
//! Each module is a copy of a frozen crate's types, minus its contract or
//! delegate implementation:
//!
//! | module        | frozen source                            |
//! |---------------|------------------------------------------|
//! | `aft`         | `modules/antiflood-tokens/interfaces`    |
//! | `inbox`       | `contracts/inbox`                        |
//! | `identity`    | `modules/identity-management`            |
//! | `local_state` | `modules/mail-local-state`               |
//!
//! The deployed contracts and delegates parse what these types produce, so
//! a serialized shape must never change here. `golden_v1.txt` holds bytes
//! captured through the frozen crates, and the tests below fail if any copy
//! drifts from them.

pub mod aft;
pub mod identity;
pub mod inbox;
pub mod local_state;

#[cfg(test)]
mod golden {
    use super::{aft, identity, inbox, local_state};

    fn dsa_signing_key(seed: [u8; 32]) -> ml_dsa::SigningKey<ml_dsa::MlDsa65> {
        ml_dsa::SigningKey::from_seed(&seed.into())
    }

    include!("golden_samples.rs");

    const GOLDEN: &str = include_str!("golden_v1.txt");

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    /// Compares the copies against a golden fixture in both directions: the
    /// copies must encode each sample to the fixture's bytes, and must
    /// decode the fixture's bytes and re-encode them unchanged.
    fn check(golden: &str) -> Result<(), String> {
        let expected: Vec<(&str, &str)> = golden
            .lines()
            .map(|l| l.split_once(' ').expect("name hex"))
            .collect();
        let actual = golden_samples();
        let names: Vec<&str> = actual.iter().map(|(n, ..)| *n).collect();
        let expected_names: Vec<&str> = expected.iter().map(|(n, _)| *n).collect();
        if names != expected_names {
            return Err(format!("sample set changed: {names:?}"));
        }
        for ((name, bytes, codec), (_, want)) in actual.iter().zip(&expected) {
            if hex(bytes) != *want {
                return Err(format!("{name}: copy encodes differently"));
            }
            if let Some(rt) = codec {
                check_decodes(name, *rt, &unhex(want))?;
            }
        }
        Ok(())
    }

    /// The copy must decode `golden` and re-encode it unchanged.
    fn check_decodes(name: &str, codec: Codec, golden: &[u8]) -> Result<(), String> {
        let reencoded = codec(golden).map_err(|e| format!("{name}: {e}"))?;
        if reencoded != golden {
            return Err(format!("{name}: copy re-encodes it differently"));
        }
        Ok(())
    }

    #[test]
    fn copies_reproduce_the_frozen_wire_bytes() {
        check(GOLDEN).unwrap();
    }

    #[test]
    fn undecodable_fixture_bytes_are_an_error_not_a_panic() {
        let (name, _, codec) = golden_samples()
            .into_iter()
            .find(|(n, ..)| *n == "ls_msg_mark_read")
            .unwrap();
        let err = check_decodes(name, codec.unwrap(), b"{not json").unwrap_err();
        assert!(err.starts_with("ls_msg_mark_read: decode:"), "{err}");
        let (name, _, codec) = golden_samples()
            .into_iter()
            .find(|(n, ..)| *n == "aft_msg_denied")
            .unwrap();
        let err = check_decodes(name, codec.unwrap(), &[0xff; 3]).unwrap_err();
        assert!(err.starts_with("aft_msg_denied: decode:"), "{err}");
    }

    #[test]
    fn a_flipped_byte_in_the_fixture_fails_the_check() {
        let target = GOLDEN
            .lines()
            .position(|l| l.starts_with("ls_msg_mark_read "))
            .unwrap();
        let corrupted: Vec<String> = GOLDEN
            .lines()
            .enumerate()
            .map(|(i, l)| {
                if i != target {
                    return l.to_string();
                }
                let last = l.len() - 1;
                let flipped = if &l[last..] == "0" { "1" } else { "0" };
                format!("{}{flipped}", &l[..last])
            })
            .collect();
        let err = check(&corrupted.join("\n")).unwrap_err();
        assert!(err.starts_with("ls_msg_mark_read"), "{err}");
    }
}
