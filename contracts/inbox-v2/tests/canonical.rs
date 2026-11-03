//! The canonical-CBOR check: one value has one accepted encoding.
//!
//! A state or delta that decodes to a value but is spelled another way is
//! refused outright, by `validate_state`, `update_state` and `decode` alike.
//! Without that, two peers could hold different bytes for one state and never
//! agree on a summary. The forms are the ones `common::non_canonical_forms`
//! builds; `tests/merge_laws.rs` also runs them over the fuzzer's states.

mod common;

use std::collections::BTreeMap;

use common::*;
use freenet_email_inbox_v2::merge::merge;
use freenet_email_inbox_v2::types::*;
use freenet_email_inbox_v2::{apply, is_valid};

const T: u64 = 1_800_000_000 / DAY * DAY;
const FAR: u64 = T + 300 * DAY;

/// A small valid state with something in every collection, so every form
/// has a target.
fn state() -> Vec<u8> {
    let w = world();
    let pass = w.pass(1, 3, FAR, PassClass::Contact);
    let raw = w.raw(
        w.owner(1, 3, QuarantineMode::Open, BTreeMap::new()),
        w.time(T),
        [w.revocation(id_of(9), FAR, 3)],
        [w.usage(id_of(8), 1, FAR)],
        [
            w.pass_msg(&pass, ct(8192, 1), T),
            w.pass_msg(&pass, ct(8192, 2), T + HOUR),
        ],
    );
    encode(&merge(&Rules::V1, &w.params, vec![raw.into()]).unwrap())
}

#[test]
fn the_canonical_spelling_is_accepted() {
    let bytes = state();
    assert!(is_valid(&Rules::V1, &world().params, &bytes));
    assert_eq!(encode(&decode::<InboxState>(&bytes).unwrap()), bytes);
}

#[test]
fn every_other_spelling_is_refused_everywhere() {
    let params = world().params;
    let bytes = state();
    let forms = non_canonical_forms(&bytes);
    assert!(forms.len() >= 9, "every form had a target: {}", forms.len());
    for (name, bad) in forms {
        let refused = decode::<InboxState>(&bad).unwrap_err();
        assert!(
            ["non-canonical CBOR", "not CBOR of this type"].contains(&refused.0),
            "{name}: {refused:?}"
        );
        assert!(!is_valid(&Rules::V1, &params, &bad), "{name}: validated");
        assert!(
            apply(&Rules::V1, &params, &bytes, update_state(bad.clone())).is_err(),
            "{name}: merged as a state"
        );
        // As the current state of an update.
        assert!(
            apply(&Rules::V1, &params, &bad, update_state(bytes.clone())).is_err(),
            "{name}: accepted as the held state"
        );
    }
}

#[test]
fn a_delta_is_held_to_the_same_spelling() {
    let params = world().params;
    let bytes = state();
    let delta = encode(&InboxDelta::from(decode::<InboxState>(&bytes).unwrap()));
    let mut trailing = delta.clone();
    trailing.push(0);
    let update = |d: Vec<u8>| vec![freenet_stdlib::prelude::UpdateData::Delta(d.into())];
    assert!(apply(&Rules::V1, &params, &bytes, update(delta)).is_ok());
    assert!(apply(&Rules::V1, &params, &bytes, update(trailing)).is_err());
}
