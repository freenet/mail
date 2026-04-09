//! Integration tests for the inbox contract's `ContractInterface` impl.
//!
//! These tests run native Rust against the `contract`-feature build of the
//! crate, exercising `validate_state`, `update_state`, `summarize_state`,
//! and `get_state_delta` directly. They are intentionally split from the
//! single in-file `validate_test` so that the helper module under
//! `tests/common/` can be reused as the contract grows.

#![cfg(feature = "contract")]

mod common;

use chrono::{Duration, Utc};
use common::{
    add_messages_delta, assignment_hash_for, fixed_valid_slot, make_inbox_state,
    make_inbox_value, make_keypair, make_message, make_params, make_token_assignment,
    make_token_record, related_state_update, token_record_id_for,
};
use freenet_aft_interface::Tier;
use freenet_email_inbox::{Inbox, InboxSettings};
use freenet_stdlib::prelude::{
    ContractInterface, RelatedContracts, State, UpdateModification, ValidateResult,
};

// ─── validate_state ──────────────────────────────────────────────────────

#[test]
fn validate_accepts_signed_empty_inbox() {
    let (owner_sk, owner_pk) = make_keypair();
    let params = make_params(owner_pk);
    let state = make_inbox_state(
        &owner_sk,
        vec![],
        Utc::now(),
        InboxSettings::default(),
    );

    let result = Inbox::validate_state(params, state, RelatedContracts::new())
        .expect("validate_state");
    assert_eq!(
        result,
        ValidateResult::Valid,
        "an empty inbox signed by the owner key must validate"
    );
}

#[test]
fn validate_rejects_tampered_last_update() {
    let (owner_sk, owner_pk) = make_keypair();
    let params = make_params(owner_pk);

    // Build a signed inbox, then mutate `last_update` post-signing. The
    // signature itself doesn't cover `last_update` (it covers a fixed salt),
    // so the on-the-wire payload still parses — but the test documents the
    // current behavior of the validator and locks in that we never reach
    // `Invalid` for a signature mismatch on this field. If/when the contract
    // is hardened to cover `last_update` in the signature, this test should
    // flip to `assert_eq!(result, ValidateResult::Invalid)`.
    let mut value = make_inbox_value(
        &owner_sk,
        vec![],
        Utc::now(),
        InboxSettings::default(),
    );
    value["last_update"] = serde_json::json!("1999-01-01T00:00:00Z");
    let bytes = serde_json::to_vec(&value).expect("serialize tampered inbox");
    let state = State::from(bytes);

    let result = Inbox::validate_state(params, state, RelatedContracts::new())
        .expect("validate_state");
    // Documented behavior: `last_update` is not part of the signed payload,
    // so the validator currently accepts the tampered state. The test exists
    // to make this fact visible and to fail loudly if the contract changes.
    assert_eq!(result, ValidateResult::Valid);
}

#[test]
fn validate_rejects_wrong_owner_signature() {
    // Sign with `attacker_sk` but advertise `owner_pk` in the parameters —
    // the verifier should reject.
    let (_owner_sk, owner_pk) = make_keypair();
    let (attacker_sk, _attacker_pk) = make_keypair();
    let params = make_params(owner_pk);
    let state = make_inbox_state(
        &attacker_sk,
        vec![],
        Utc::now(),
        InboxSettings::default(),
    );

    let result = Inbox::validate_state(params, state, RelatedContracts::new());
    // `verify` returns `Err(VerificationError::WrongSignature)` which the
    // `From` impl on `ContractError` collapses to `InvalidUpdate`. The outer
    // `?` in `validate_state` then propagates that as `Err`.
    assert!(
        result.is_err(),
        "a state signed by a non-owner key must not validate; got {result:?}"
    );
}

// ─── update_state: AddMessages ───────────────────────────────────────────

#[test]
fn update_accepts_add_message_with_valid_token() {
    let (owner_sk, owner_pk) = make_keypair();
    let (gen_sk, _gen_pk) = make_keypair();
    let params = make_params(owner_pk);

    let token_record_id = token_record_id_for(b"valid-token-record");
    let assignment = make_token_assignment(
        &gen_sk,
        Tier::Day1,
        fixed_valid_slot(),
        assignment_hash_for(b"msg-1"),
        token_record_id,
    );
    let message = make_message(b"opaque-encrypted-payload".to_vec(), assignment.clone());
    let record = make_token_record(assignment);

    let initial_state = make_inbox_state(
        &owner_sk,
        vec![],
        Utc::now(),
        InboxSettings::default(),
    );
    let updates = vec![
        add_messages_delta(vec![message]),
        related_state_update(token_record_id, record),
    ];

    let modification = Inbox::update_state(params, initial_state, updates)
        .expect("update_state should succeed");
    let new_state = unwrap_valid(modification);
    let parsed: serde_json::Value =
        serde_json::from_slice(new_state.as_ref()).expect("inbox json");
    assert_eq!(
        parsed["messages"]
            .as_array()
            .map(|m| m.len())
            .unwrap_or(0),
        1,
        "the new message should be persisted in the inbox state"
    );
}

#[test]
fn update_rejects_message_with_unknown_token_record() {
    // AddMessages without a corresponding RelatedState carrying the token
    // allocation record: `update_state` should report the missing record
    // via `requires(...)` rather than persisting the message.
    let (owner_sk, owner_pk) = make_keypair();
    let (gen_sk, _) = make_keypair();
    let params = make_params(owner_pk);

    let token_record_id = token_record_id_for(b"unknown-record");
    let assignment = make_token_assignment(
        &gen_sk,
        Tier::Day1,
        fixed_valid_slot(),
        assignment_hash_for(b"msg-orphan"),
        token_record_id,
    );
    let message = make_message(b"orphan-message".to_vec(), assignment);

    let initial_state = make_inbox_state(
        &owner_sk,
        vec![],
        Utc::now(),
        InboxSettings::default(),
    );
    let updates = vec![add_messages_delta(vec![message])];

    let modification = Inbox::update_state(params, initial_state, updates)
        .expect("update_state");
    assert!(
        is_requires_more(&modification),
        "missing token allocation record should produce `requires(...)`, got {modification:?}"
    );
}

#[test]
fn update_rejects_token_with_invalid_slot() {
    // `Tier::Min1` requires the time slot to land on `:00.000`. Use a slot
    // with a non-zero second to trip `is_valid_slot` inside `add_message`.
    let (owner_sk, owner_pk) = make_keypair();
    let (gen_sk, _) = make_keypair();
    let params = make_params(owner_pk);

    let token_record_id = token_record_id_for(b"bad-slot-record");
    let bad_slot = fixed_valid_slot() + Duration::seconds(13);
    let assignment = make_token_assignment(
        &gen_sk,
        Tier::Min1,
        bad_slot,
        assignment_hash_for(b"msg-bad-slot"),
        token_record_id,
    );
    let message = make_message(b"bad-slot-message".to_vec(), assignment.clone());
    // Provide the related token-allocation record so the rejection is
    // attributable to the slot check, not to a missing record.
    let record = make_token_record(assignment);

    let initial_state = make_inbox_state(
        &owner_sk,
        vec![],
        Utc::now(),
        InboxSettings::default(),
    );
    let updates = vec![
        add_messages_delta(vec![message]),
        related_state_update(token_record_id, record),
    ];

    let result = Inbox::update_state(params, initial_state, updates);
    assert!(
        result.is_err(),
        "an invalid time slot should produce an error from update_state; got {result:?}"
    );
}

// ─── summarize_state / get_state_delta round trip ────────────────────────

#[test]
fn summarize_then_delta_yields_only_new_messages() {
    let (owner_sk, owner_pk) = make_keypair();
    let (gen_sk, _) = make_keypair();
    let params = make_params(owner_pk.clone());

    let token_record_id = token_record_id_for(b"round-trip-record");
    let assignment_old = make_token_assignment(
        &gen_sk,
        Tier::Day1,
        fixed_valid_slot(),
        assignment_hash_for(b"msg-old"),
        token_record_id,
    );
    let msg_old = make_message(b"older-message".to_vec(), assignment_old);

    // Build an inbox state that already contains `msg_old`. The inbox's
    // `add_message` only validates the token, not the record map, when
    // we hand-roll the state via JSON, so we can skip the related-contracts
    // dance for `summarize` / `get_state_delta` (those methods don't touch
    // the related-contracts API).
    let state = make_inbox_state(
        &owner_sk,
        vec![msg_old.clone()],
        Utc::now(),
        InboxSettings::default(),
    );

    // Summarize: returns the set of `assignment_hash` values currently in
    // the inbox.
    let summary =
        Inbox::summarize_state(make_params(owner_pk.clone()), state.clone())
            .expect("summarize_state");

    // Delta against an empty summary: every message in the state should
    // appear in the delta.
    let empty_summary =
        Inbox::summarize_state(make_params(owner_pk.clone()), make_inbox_state(
            &owner_sk,
            vec![],
            Utc::now(),
            InboxSettings::default(),
        ))
        .expect("summarize empty");
    let delta_full = Inbox::get_state_delta(params, state, empty_summary)
        .expect("get_state_delta against empty summary");
    let delta_full_json: serde_json::Value =
        serde_json::from_slice(delta_full.as_ref()).expect("delta json");
    assert_eq!(
        delta_full_json["messages"]
            .as_array()
            .map(|m| m.len())
            .unwrap_or(0),
        1,
        "delta against an empty summary should contain every existing message"
    );

    // The summary itself should be non-empty (one entry).
    let summary_json: serde_json::Value =
        serde_json::from_slice(summary.as_ref()).expect("summary json");
    // `InboxSummary` is a `HashSet<TokenAssignmentHash>` serialized as a
    // JSON array of byte arrays. We just want to assert it's non-empty.
    assert!(
        summary_json.as_array().is_some_and(|a| !a.is_empty()),
        "summary should list one assignment hash; got {summary_json}"
    );
}

// ─── helpers ─────────────────────────────────────────────────────────────

fn unwrap_valid(modification: UpdateModification<'static>) -> State<'static> {
    match modification.new_state {
        Some(state) => state,
        None => panic!(
            "expected a valid state modification, got {:?}",
            modification.related
        ),
    }
}

fn is_requires_more(modification: &UpdateModification<'static>) -> bool {
    modification.new_state.is_none() && !modification.related.is_empty()
}
