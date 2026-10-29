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

    include!("golden_samples.rs");

    const GOLDEN: &str = include_str!("golden_v1.txt");

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn copies_reproduce_the_frozen_wire_bytes() {
        let expected: Vec<(&str, &str)> = GOLDEN
            .lines()
            .map(|l| l.split_once(' ').expect("name hex"))
            .collect();
        let actual = golden_samples();
        let names: Vec<&str> = actual.iter().map(|(n, _)| *n).collect();
        let expected_names: Vec<&str> = expected.iter().map(|(n, _)| *n).collect();
        assert_eq!(names, expected_names, "sample set changed");
        for ((name, bytes), (_, want)) in actual.iter().zip(&expected) {
            assert_eq!(&hex(bytes), want, "{name} drifted from the frozen crate");
        }
    }
}
