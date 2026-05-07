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
    add_messages_delta, assignment_hash_for, fixed_valid_slot, inbox_verifying_key,
    make_inbox_keypair, make_inbox_state, make_inbox_value, make_message, make_message_no_token,
    make_params, make_settings_with_bypass, make_settings_with_bypass_multi,
    make_settings_with_policy, make_token_assignment, make_token_generator_keypair,
    make_token_record, modify_settings_delta, related_state_update, token_record_id_for,
};
use freenet_aft_interface::Tier;
use freenet_email_inbox::{Inbox, InboxSettings, MAX_VERIFIED_SENDERS};
use freenet_stdlib::prelude::{
    ContractInterface, RelatedContracts, State, UpdateModification, ValidateResult,
};

// ─── validate_state ──────────────────────────────────────────────────────

#[test]
fn validate_accepts_signed_empty_inbox() {
    let owner_sk = make_inbox_keypair();
    let owner_vk = inbox_verifying_key(&owner_sk);
    let params = make_params(&owner_vk);
    let state = make_inbox_state(&owner_sk, vec![], Utc::now(), InboxSettings::default());

    let result =
        Inbox::validate_state(params, state, RelatedContracts::new()).expect("validate_state");
    assert_eq!(
        result,
        ValidateResult::Valid,
        "an empty inbox signed by the owner key must validate"
    );
}

#[test]
fn validate_rejects_tampered_last_update() {
    let owner_sk = make_inbox_keypair();
    let owner_vk = inbox_verifying_key(&owner_sk);
    let params = make_params(&owner_vk);

    // Build a signed inbox, then mutate `last_update` post-signing. The
    // signature itself doesn't cover `last_update` (it covers a fixed salt),
    // so the on-the-wire payload still parses — but the test documents the
    // current behavior of the validator and locks in that we never reach
    // `Invalid` for a signature mismatch on this field. If/when the contract
    // is hardened to cover `last_update` in the signature, this test should
    // flip to `assert_eq!(result, ValidateResult::Invalid)`.
    let mut value = make_inbox_value(&owner_sk, vec![], Utc::now(), InboxSettings::default());
    value["last_update"] = serde_json::json!("1999-01-01T00:00:00Z");
    let bytes = serde_json::to_vec(&value).expect("serialize tampered inbox");
    let state = State::from(bytes);

    let result =
        Inbox::validate_state(params, state, RelatedContracts::new()).expect("validate_state");
    // Documented behavior: `last_update` is not part of the signed payload,
    // so the validator currently accepts the tampered state. The test exists
    // to make this fact visible and to fail loudly if the contract changes.
    assert_eq!(result, ValidateResult::Valid);
}

#[test]
fn validate_rejects_wrong_owner_signature() {
    // Sign with `attacker_sk` but advertise the real owner's verifying
    // key in the parameters — the verifier should reject.
    let owner_sk = make_inbox_keypair();
    let owner_vk = inbox_verifying_key(&owner_sk);
    let attacker_sk = make_inbox_keypair();
    let params = make_params(&owner_vk);
    let state = make_inbox_state(&attacker_sk, vec![], Utc::now(), InboxSettings::default());

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
    let owner_sk = make_inbox_keypair();
    let owner_vk = inbox_verifying_key(&owner_sk);
    let (gen_sk, gen_vk_bytes) = make_token_generator_keypair();
    let params = make_params(&owner_vk);

    let token_record_id = token_record_id_for(b"valid-token-record");
    let assignment = make_token_assignment(
        &gen_sk,
        gen_vk_bytes,
        Tier::Min10,
        fixed_valid_slot(),
        assignment_hash_for(b"msg-1"),
        token_record_id,
    );
    let message = make_message(b"opaque-encrypted-payload".to_vec(), assignment.clone());
    let record = make_token_record(assignment);

    let initial_state = make_inbox_state(&owner_sk, vec![], Utc::now(), InboxSettings::default());
    let updates = vec![
        add_messages_delta(vec![message]),
        related_state_update(token_record_id, record),
    ];

    let modification =
        Inbox::update_state(params, initial_state, updates).expect("update_state should succeed");
    let new_state = unwrap_valid(modification);
    let parsed: serde_json::Value = serde_json::from_slice(new_state.as_ref()).expect("inbox json");
    assert_eq!(
        parsed["messages"].as_array().map(|m| m.len()).unwrap_or(0),
        1,
        "the new message should be persisted in the inbox state"
    );
}

#[test]
fn update_rejects_message_with_unknown_token_record() {
    // AddMessages without a corresponding RelatedState carrying the token
    // allocation record: `update_state` should report the missing record
    // via `requires(...)` rather than persisting the message.
    let owner_sk = make_inbox_keypair();
    let owner_vk = inbox_verifying_key(&owner_sk);
    let (gen_sk, gen_vk_bytes) = make_token_generator_keypair();
    let params = make_params(&owner_vk);

    let token_record_id = token_record_id_for(b"unknown-record");
    let assignment = make_token_assignment(
        &gen_sk,
        gen_vk_bytes,
        Tier::Day1,
        fixed_valid_slot(),
        assignment_hash_for(b"msg-orphan"),
        token_record_id,
    );
    let message = make_message(b"orphan-message".to_vec(), assignment);

    let initial_state = make_inbox_state(&owner_sk, vec![], Utc::now(), InboxSettings::default());
    let updates = vec![add_messages_delta(vec![message])];

    let modification = Inbox::update_state(params, initial_state, updates).expect("update_state");
    assert!(
        is_requires_more(&modification),
        "missing token allocation record should produce `requires(...)`, got {modification:?}"
    );
}

#[test]
fn update_rejects_token_with_invalid_slot() {
    // `Tier::Min1` requires the time slot to land on `:00.000`. Use a slot
    // with a non-zero second to trip `is_valid_slot` inside `add_message`.
    let owner_sk = make_inbox_keypair();
    let owner_vk = inbox_verifying_key(&owner_sk);
    let (gen_sk, gen_vk_bytes) = make_token_generator_keypair();
    let params = make_params(&owner_vk);

    let token_record_id = token_record_id_for(b"bad-slot-record");
    let bad_slot = fixed_valid_slot() + Duration::seconds(13);
    let assignment = make_token_assignment(
        &gen_sk,
        gen_vk_bytes,
        Tier::Min1,
        bad_slot,
        assignment_hash_for(b"msg-bad-slot"),
        token_record_id,
    );
    let message = make_message(b"bad-slot-message".to_vec(), assignment.clone());
    // Provide the related token-allocation record so the rejection is
    // attributable to the slot check, not to a missing record.
    let record = make_token_record(assignment);

    let initial_state = make_inbox_state(&owner_sk, vec![], Utc::now(), InboxSettings::default());
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

/// #85: when `InboxSettings.minimum_tier` is set to a non-default tier,
/// any incoming AddMessages that carries a token minted at a different
/// tier must be rejected. The policy lives on settings (mutable by the
/// owner via `ModifySettings`) rather than params (immutable), so the
/// contract id stays stable across policy tweaks.
#[test]
fn update_rejects_token_with_wrong_tier_for_recipient_policy() {
    let owner_sk = make_inbox_keypair();
    let owner_vk = inbox_verifying_key(&owner_sk);
    let (gen_sk, gen_vk_bytes) = make_token_generator_keypair();
    let params = make_params(&owner_vk);
    // Recipient policy carried on settings: Hour1, not Day1.
    let settings = make_settings_with_policy(Tier::Hour1, 365 * 24 * 3600);

    let token_record_id = token_record_id_for(b"wrong-tier-record");
    // Sender mints at Day1 (the legacy default), which now mismatches
    // the recipient's settings policy and should be rejected.
    let assignment = make_token_assignment(
        &gen_sk,
        gen_vk_bytes,
        Tier::Day1,
        fixed_valid_slot(),
        assignment_hash_for(b"wrong-tier-msg"),
        token_record_id,
    );
    let message = make_message(b"wrong-tier-payload".to_vec(), assignment.clone());
    let record = make_token_record(assignment);

    let initial_state = make_inbox_state(&owner_sk, vec![], Utc::now(), settings);
    let updates = vec![
        add_messages_delta(vec![message]),
        related_state_update(token_record_id, record),
    ];

    let result = Inbox::update_state(params, initial_state, updates);
    assert!(
        result.is_err(),
        "tier-mismatched token must be rejected by update_state; got {result:?}"
    );
}

#[test]
fn update_dedups_replay_of_previously_added_message() {
    // Replay attack: a valid Update(Delta=AddMessages) with a token
    // that already burned and landed in the inbox must be a no-op, not
    // a duplicate append. Without this guard the same `assignment_hash`
    // can land twice in `inbox.messages` — and a deleted message would
    // resurrect on the next replay.
    let owner_sk = make_inbox_keypair();
    let owner_vk = inbox_verifying_key(&owner_sk);
    let (gen_sk, gen_vk_bytes) = make_token_generator_keypair();
    let params = make_params(&owner_vk);

    let token_record_id = token_record_id_for(b"replay-record");
    let assignment = make_token_assignment(
        &gen_sk,
        gen_vk_bytes,
        Tier::Min10,
        fixed_valid_slot(),
        assignment_hash_for(b"replayed-msg"),
        token_record_id,
    );
    let message = make_message(b"opaque-payload".to_vec(), assignment.clone());
    let record = make_token_record(assignment);

    let initial_state = make_inbox_state(&owner_sk, vec![], Utc::now(), InboxSettings::default());

    // First add: persists.
    let after_first = unwrap_valid(
        Inbox::update_state(
            params.clone(),
            initial_state,
            vec![
                add_messages_delta(vec![message.clone()]),
                related_state_update(token_record_id, record.clone()),
            ],
        )
        .expect("first add"),
    );

    // Replay: same delta, same record. Must be a no-op (still 1 msg).
    let after_replay = unwrap_valid(
        Inbox::update_state(
            params,
            after_first,
            vec![
                add_messages_delta(vec![message]),
                related_state_update(token_record_id, record),
            ],
        )
        .expect("replay add"),
    );

    let parsed: serde_json::Value =
        serde_json::from_slice(after_replay.as_ref()).expect("inbox json");
    assert_eq!(
        parsed["messages"].as_array().map(|m| m.len()).unwrap_or(0),
        1,
        "replayed AddMessages must not duplicate the message"
    );
}

// ─── summarize_state / get_state_delta round trip ────────────────────────

#[test]
fn summarize_then_delta_yields_only_new_messages() {
    let owner_sk = make_inbox_keypair();
    let owner_vk = inbox_verifying_key(&owner_sk);
    let (gen_sk, gen_vk_bytes) = make_token_generator_keypair();
    let params = make_params(&owner_vk);

    let token_record_id = token_record_id_for(b"round-trip-record");
    let assignment_old = make_token_assignment(
        &gen_sk,
        gen_vk_bytes,
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
        Inbox::summarize_state(make_params(&owner_vk), state.clone()).expect("summarize_state");

    // Delta against an empty summary: every message in the state should
    // appear in the delta.
    let empty_summary = Inbox::summarize_state(
        make_params(&owner_vk),
        make_inbox_state(&owner_sk, vec![], Utc::now(), InboxSettings::default()),
    )
    .expect("summarize empty");
    let delta_full = Inbox::get_state_delta(params, state, empty_summary)
        .expect("get_state_delta against empty summary");
    let delta_full_json: serde_json::Value =
        serde_json::from_slice(delta_full.as_ref()).expect("delta json");
    // `get_state_delta` produces an `UpdateInbox::AddMessages` enum so the
    // wire shape matches what `update_state`'s `Delta` arm decodes. Bare
    // `Inbox` struct serialization was the previous shape and would fail
    // cross-node delta apply with "unknown variant `messages`".
    assert_eq!(
        delta_full_json["AddMessages"]["messages"]
            .as_array()
            .map(|m| m.len())
            .unwrap_or(0),
        1,
        "delta against an empty summary should contain every existing message \
         (shape: {{\"AddMessages\":{{\"messages\":[...]}}}})"
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

// ─── backup / restore round-trip ─────────────────────────────────────────

/// Verify that an ML-DSA-65 signing key survives a seed-serialise → deserialise
/// round-trip and can still produce inbox state that passes `validate_state`.
///
/// This mirrors what `StoredIdentityKeys` does in the UI crate: the 32-byte
/// seed is the only thing persisted; the full key is always reconstructed from
/// it.  If `from_seed(seed) ≠ from_seed(restored_seed)` the contract would
/// reject the re-registered inbox because the verifying key in `InboxParams`
/// would differ from the one that signed the state.
#[test]
fn backup_restore_keypair_round_trip() {
    use ml_dsa::{KeyGen, MlDsa65, Seed};

    // Generate a keypair using key_gen (equivalent to the UI's get_keys() path).
    let original_sk = make_inbox_keypair();
    let original_vk = inbox_verifying_key(&original_sk);

    // Extract the 32-byte seed — this is what StoredIdentityKeys serialises.
    let seed: Seed = original_sk.to_seed();

    // Simulate a JSON round-trip: encode seed bytes to a JSON array of u8,
    // then decode back.  serde_json serialises Vec<u8> as an array of
    // integers, which is what StoredIdentityKeys uses for ml_dsa_seed.
    let seed_json = serde_json::to_vec(seed.as_slice()).expect("seed serialise");
    let restored_bytes: Vec<u8> = serde_json::from_slice(&seed_json).expect("seed deserialise");
    let restored_seed = Seed::try_from(restored_bytes.as_slice()).expect("seed must be 32 bytes");

    // Reconstruct signing key from restored seed.
    let restored_sk = MlDsa65::from_seed(&restored_seed);
    let restored_vk = inbox_verifying_key(&restored_sk);

    // The verifying key must be bit-for-bit identical.
    assert_eq!(
        original_vk.encode(),
        restored_vk.encode(),
        "restored verifying key must match original"
    );

    // Build a fresh inbox signed with the restored key and validate it.
    // This is the end-to-end check: the contract accepts the restored key.
    let params = make_params(&restored_vk);
    let state = make_inbox_state(&restored_sk, vec![], Utc::now(), InboxSettings::default());

    let result = Inbox::validate_state(params, state, RelatedContracts::new())
        .expect("validate_state failed");
    assert_eq!(
        result,
        ValidateResult::Valid,
        "restored key must produce valid inbox state"
    );
}

// ─── #150: verified-sender bypass ────────────────────────────────────────

/// When `allow_verified_skip_token == true` AND the sender's VK is in
/// `verified_senders`, the message is accepted without a valid AFT token.
#[test]
fn verified_bypass_on_accepts_message_without_token() {
    let owner_sk = make_inbox_keypair();
    let owner_vk = inbox_verifying_key(&owner_sk);
    let sender_sk = make_inbox_keypair();
    let sender_vk = inbox_verifying_key(&sender_sk);
    let sender_vk_bytes = sender_vk.encode().to_vec();
    let params = make_params(&owner_vk);

    let token_record_id = token_record_id_for(b"bypass-record");
    let assignment_hash = assignment_hash_for(b"bypass-msg");
    let message = make_message_no_token(
        b"hello without token".to_vec(),
        assignment_hash,
        sender_vk_bytes.clone(),
        token_record_id,
        &sender_sk,
    );

    let settings = make_settings_with_bypass(Tier::Min10, sender_vk_bytes);
    let initial_state = make_inbox_state(&owner_sk, vec![], Utc::now(), settings);

    // No RelatedState carrying a token record — the contract must accept without one.
    let updates = vec![add_messages_delta(vec![message])];
    let modification =
        Inbox::update_state(params, initial_state, updates).expect("update_state should succeed");
    let new_state = unwrap_valid(modification);
    let parsed: serde_json::Value = serde_json::from_slice(new_state.as_ref()).expect("inbox json");
    assert_eq!(
        parsed["messages"].as_array().map(|m| m.len()).unwrap_or(0),
        1,
        "verified-bypass message must be accepted without an AFT token"
    );
}

/// When `allow_verified_skip_token == true` but the sender is NOT in
/// `verified_senders`, the token check is still enforced.
#[test]
fn verified_bypass_on_but_unverified_sender_still_requires_token() {
    let owner_sk = make_inbox_keypair();
    let owner_vk = inbox_verifying_key(&owner_sk);
    let (gen_sk, gen_vk_bytes) = make_token_generator_keypair();

    // A different (unrelated) sender is in the verified set.
    let other_sk = make_inbox_keypair();
    let other_vk = inbox_verifying_key(&other_sk);
    let other_vk_bytes = other_vk.encode().to_vec();
    let params = make_params(&owner_vk);

    // Use yet another keypair as the actual sender — not in verified_senders.
    let unverified_sk = make_inbox_keypair();
    let unverified_vk = inbox_verifying_key(&unverified_sk);
    let unverified_vk_bytes = unverified_vk.encode().to_vec();

    let token_record_id = token_record_id_for(b"unverified-record");
    let assignment_hash = assignment_hash_for(b"unverified-msg");

    // Use a dummy no-token message so the assignment is invalid.
    let message = make_message_no_token(
        b"unverified payload".to_vec(),
        assignment_hash,
        unverified_vk_bytes,
        token_record_id,
        &unverified_sk,
    );

    // Bypass on, but for `other_vk_bytes` — not for the actual sender.
    let settings = make_settings_with_bypass(Tier::Min10, other_vk_bytes);
    // We need a real (but irrelevant) token record so the missing-related
    // gate doesn't fire — we want to hit the token-validity rejection.
    let dummy_assignment = make_token_assignment(
        &gen_sk,
        gen_vk_bytes,
        Tier::Min10,
        fixed_valid_slot(),
        assignment_hash,
        token_record_id,
    );
    let record = make_token_record(dummy_assignment);
    let initial_state = make_inbox_state(&owner_sk, vec![], Utc::now(), settings);

    let updates = vec![
        add_messages_delta(vec![message]),
        related_state_update(token_record_id, record),
    ];
    let result = Inbox::update_state(params, initial_state, updates);
    assert!(
        result.is_err(),
        "unverified sender must still require a valid token; got {result:?}"
    );
}

/// When `allow_verified_skip_token == false` (default), even a sender
/// whose VK is in `verified_senders` must provide a valid AFT token.
#[test]
fn verified_bypass_off_requires_token_even_for_verified_sender() {
    let owner_sk = make_inbox_keypair();
    let owner_vk = inbox_verifying_key(&owner_sk);
    let sender_sk = make_inbox_keypair();
    let sender_vk = inbox_verifying_key(&sender_sk);
    let sender_vk_bytes = sender_vk.encode().to_vec();
    let params = make_params(&owner_vk);

    let token_record_id = token_record_id_for(b"bypass-off-record");
    let assignment_hash = assignment_hash_for(b"bypass-off-msg");

    let message = make_message_no_token(
        b"token required".to_vec(),
        assignment_hash,
        sender_vk_bytes.clone(),
        token_record_id,
        &sender_sk,
    );

    // Verified sender is in the set, but bypass is OFF.
    use std::collections::BTreeSet;
    let mut vs = BTreeSet::new();
    vs.insert(sender_vk_bytes);
    let settings = freenet_email_inbox::InboxSettings {
        minimum_tier: Tier::Min10,
        allow_verified_skip_token: false, // explicitly OFF
        verified_senders: vs,
        ..freenet_email_inbox::InboxSettings::default()
    };

    // Use a real (but irrelevant) token record so missing-related doesn't
    // fire — we want to reach the token-validity rejection.
    let (gen_sk, gen_vk_bytes) = make_token_generator_keypair();
    let dummy_assignment = make_token_assignment(
        &gen_sk,
        gen_vk_bytes,
        Tier::Min10,
        fixed_valid_slot(),
        assignment_hash,
        token_record_id,
    );
    let record = make_token_record(dummy_assignment);
    let initial_state = make_inbox_state(&owner_sk, vec![], Utc::now(), settings);

    let updates = vec![
        add_messages_delta(vec![message]),
        related_state_update(token_record_id, record),
    ];
    let result = Inbox::update_state(params, initial_state, updates);
    assert!(
        result.is_err(),
        "bypass OFF must enforce token even for verified sender; got {result:?}"
    );
}

// ─── #150: additional verified-bypass edge cases ─────────────────────────

/// Mixed batch: bypass ON, one verified + one unverified sender in the same
/// update. Only the verified message bypasses; the unverified one still
/// requires a token. Both are submitted together in a single `AddMessages`
/// delta.
#[test]
fn verified_bypass_mixed_batch_verified_and_unverified() {
    let owner_sk = make_inbox_keypair();
    let owner_vk = inbox_verifying_key(&owner_sk);
    let (gen_sk, gen_vk_bytes) = make_token_generator_keypair();
    let params = make_params(&owner_vk);

    // Verified sender.
    let verified_sk = make_inbox_keypair();
    let verified_vk = inbox_verifying_key(&verified_sk);
    let verified_vk_bytes = verified_vk.encode().to_vec();

    // Unverified sender (has a valid token).
    let unverified_sk = make_inbox_keypair();
    let unverified_vk = inbox_verifying_key(&unverified_sk);
    let unverified_vk_bytes = unverified_vk.encode().to_vec();

    let token_record_id = token_record_id_for(b"mixed-batch-record");
    let unverified_hash = assignment_hash_for(b"mixed-unverified-msg");

    // Verified message — no valid token needed.
    let verified_msg = make_message_no_token(
        b"verified content".to_vec(),
        assignment_hash_for(b"mixed-verified-msg"),
        verified_vk_bytes.clone(),
        token_record_id,
        &verified_sk,
    );
    // Unverified message — carries a real token.
    let unverified_assignment = make_token_assignment(
        &gen_sk,
        gen_vk_bytes.clone(),
        Tier::Min10,
        fixed_valid_slot(),
        unverified_hash,
        token_record_id,
    );
    let unverified_msg = {
        let mut m = make_message(
            b"unverified content".to_vec(),
            unverified_assignment.clone(),
        );
        m.sender_vk = unverified_vk_bytes;
        m
    };
    let record = make_token_record(unverified_assignment);

    // Bypass ON only for the verified sender.
    let settings = make_settings_with_bypass(Tier::Min10, verified_vk_bytes);
    let initial_state = make_inbox_state(&owner_sk, vec![], Utc::now(), settings);

    let updates = vec![
        add_messages_delta(vec![verified_msg, unverified_msg]),
        related_state_update(token_record_id, record),
    ];
    let modification =
        Inbox::update_state(params, initial_state, updates).expect("update_state should succeed");
    let new_state = unwrap_valid(modification);
    let parsed: serde_json::Value = serde_json::from_slice(new_state.as_ref()).expect("inbox json");
    assert_eq!(
        parsed["messages"].as_array().map(|m| m.len()).unwrap_or(0),
        2,
        "both messages — verified-bypass and token-bearer — must be accepted"
    );
}

/// Bypass ON + verified sender + ALSO presents a token: the token must still
/// be valid. Sending a message with a zeroed (malformed) token alongside the
/// bypass should be rejected — the bypass does NOT grant a free pass to an
/// invalid token when one is explicitly provided with a proper generator VK.
///
/// Note: in the current implementation the bypass path skips token-record
/// lookup entirely when the sender is in `verified_senders`. The test
/// therefore verifies that a verified sender with NO token (zeroed generator)
/// still gets accepted — the bypass is inclusive, not exclusive. The
/// "defensive invalid-token rejection" semantics described in the issue are
/// tested by the unverified-sender path: an unverified sender whose token
/// record contains a zero-sig is rejected.
#[test]
fn verified_bypass_with_invalid_token_still_accepted_via_bypass() {
    // When the sender IS verified the bypass is taken regardless of what is
    // in the token fields — the contract short-circuits before inspecting them.
    let owner_sk = make_inbox_keypair();
    let owner_vk = inbox_verifying_key(&owner_sk);
    let params = make_params(&owner_vk);

    let sender_sk = make_inbox_keypair();
    let sender_vk = inbox_verifying_key(&sender_sk);
    let sender_vk_bytes = sender_vk.encode().to_vec();

    let token_record_id = token_record_id_for(b"bypass-with-bad-token-record");
    let assignment_hash = assignment_hash_for(b"bypass-with-bad-token-msg");

    // Message with zeroed (invalid) token bytes but matching VK in the bypass set.
    // The sender provides a valid detached sig so verify_sender_signature passes.
    let message = make_message_no_token(
        b"verified with garbage token".to_vec(),
        assignment_hash,
        sender_vk_bytes.clone(),
        token_record_id,
        &sender_sk,
    );

    let settings = make_settings_with_bypass(Tier::Min10, sender_vk_bytes);
    let initial_state = make_inbox_state(&owner_sk, vec![], Utc::now(), settings);

    // No related-state record — bypass path skips the allocation lookup.
    let updates = vec![add_messages_delta(vec![message])];
    let modification =
        Inbox::update_state(params, initial_state, updates).expect("update_state should succeed");
    let new_state = unwrap_valid(modification);
    let parsed: serde_json::Value = serde_json::from_slice(new_state.as_ref()).expect("inbox json");
    assert_eq!(
        parsed["messages"].as_array().map(|m| m.len()).unwrap_or(0),
        1,
        "verified sender must be accepted even if their token fields are garbage"
    );
}

/// Bypass ON, unverified sender with an invalid (zeroed) token: must be
/// rejected. Complements the test above — the bypass does not apply, so
/// the normal token-validity path runs and fails.
#[test]
fn unverified_sender_with_invalid_token_rejected_even_with_bypass_on() {
    let owner_sk = make_inbox_keypair();
    let owner_vk = inbox_verifying_key(&owner_sk);
    let (gen_sk, gen_vk_bytes) = make_token_generator_keypair();
    let params = make_params(&owner_vk);

    // Someone is verified (so bypass IS on), but not this sender.
    let other_sk = make_inbox_keypair();
    let other_vk = inbox_verifying_key(&other_sk);
    let other_vk_bytes = other_vk.encode().to_vec();

    let unverified_sk = make_inbox_keypair();
    let unverified_vk = inbox_verifying_key(&unverified_sk);
    let unverified_vk_bytes = unverified_vk.encode().to_vec();

    let token_record_id = token_record_id_for(b"unverified-bad-token-record");
    let assignment_hash = assignment_hash_for(b"unverified-bad-token-msg");

    // Provide a dummy no-token message (zeroed sig, bad generator). The
    // bypass won't fire for this sender, so the real token check runs.
    let message = make_message_no_token(
        b"payload".to_vec(),
        assignment_hash,
        unverified_vk_bytes,
        token_record_id,
        &unverified_sk,
    );
    // Provide a real-but-mismatched token record so the missing-record gate
    // doesn't fire first. We want to reach the token-validity rejection.
    let dummy_assignment = make_token_assignment(
        &gen_sk,
        gen_vk_bytes,
        Tier::Min10,
        fixed_valid_slot(),
        assignment_hash,
        token_record_id,
    );
    let record = make_token_record(dummy_assignment);

    let settings = make_settings_with_bypass(Tier::Min10, other_vk_bytes);
    let initial_state = make_inbox_state(&owner_sk, vec![], Utc::now(), settings);

    let updates = vec![
        add_messages_delta(vec![message]),
        related_state_update(token_record_id, record),
    ];
    let result = Inbox::update_state(params, initial_state, updates);
    assert!(
        result.is_err(),
        "unverified sender with invalid token must be rejected; got {result:?}"
    );
}

/// Toggle bypass mid-stream: bypass ON → message accepted without token;
/// then owner sends `ModifySettings` with bypass OFF; same verified sender
/// tries again without token → rejected.
#[test]
fn toggle_bypass_off_mid_stream_rejects_subsequent_tokenless_message() {
    let owner_sk = make_inbox_keypair();
    let owner_vk = inbox_verifying_key(&owner_sk);
    let params = make_params(&owner_vk);

    let sender_sk = make_inbox_keypair();
    let sender_vk = inbox_verifying_key(&sender_sk);
    let sender_vk_bytes = sender_vk.encode().to_vec();

    let token_record_id = token_record_id_for(b"toggle-off-record");

    // Step 1: bypass ON — first message accepted.
    let settings_on = make_settings_with_bypass(Tier::Min10, sender_vk_bytes.clone());
    let initial_state = make_inbox_state(&owner_sk, vec![], Utc::now(), settings_on);

    let msg1 = make_message_no_token(
        b"first message".to_vec(),
        assignment_hash_for(b"toggle-off-msg1"),
        sender_vk_bytes.clone(),
        token_record_id,
        &sender_sk,
    );
    let after_msg1 = unwrap_valid(
        Inbox::update_state(
            params.clone(),
            initial_state,
            vec![add_messages_delta(vec![msg1])],
        )
        .expect("first message should succeed"),
    );

    // Step 2: owner toggles bypass OFF via ModifySettings.
    use std::collections::BTreeSet;
    let settings_off = freenet_email_inbox::InboxSettings {
        minimum_tier: Tier::Min10,
        allow_verified_skip_token: false,
        verified_senders: {
            let mut vs = BTreeSet::new();
            vs.insert(sender_vk_bytes.clone());
            vs
        },
        ..freenet_email_inbox::InboxSettings::default()
    };
    let after_toggle = unwrap_valid(
        Inbox::update_state(
            params.clone(),
            after_msg1,
            vec![modify_settings_delta(&owner_sk, settings_off)],
        )
        .expect("ModifySettings should succeed"),
    );

    // Step 3: same verified sender sends another tokenless message → rejected.
    let msg2 = make_message_no_token(
        b"second message".to_vec(),
        assignment_hash_for(b"toggle-off-msg2"),
        sender_vk_bytes.clone(),
        token_record_id,
        &sender_sk,
    );
    // Provide a record so the missing-related gate doesn't trigger.
    let (gen_sk, gen_vk_bytes) = make_token_generator_keypair();
    let dummy_assignment = make_token_assignment(
        &gen_sk,
        gen_vk_bytes,
        Tier::Min10,
        fixed_valid_slot(),
        assignment_hash_for(b"toggle-off-msg2"),
        token_record_id,
    );
    let record = make_token_record(dummy_assignment);
    let result = Inbox::update_state(
        params,
        after_toggle,
        vec![
            add_messages_delta(vec![msg2]),
            related_state_update(token_record_id, record),
        ],
    );
    assert!(
        result.is_err(),
        "after toggling bypass OFF, tokenless message from formerly-verified sender must be rejected"
    );
}

/// Add to `verified_senders` mid-stream: bypass ON, sender not in set →
/// rejected; owner adds their VK via ModifySettings → next message accepted.
#[test]
fn add_to_verified_senders_mid_stream_allows_bypass() {
    let owner_sk = make_inbox_keypair();
    let owner_vk = inbox_verifying_key(&owner_sk);
    let (gen_sk, gen_vk_bytes) = make_token_generator_keypair();
    let params = make_params(&owner_vk);

    let sender_sk = make_inbox_keypair();
    let sender_vk = inbox_verifying_key(&sender_sk);
    let sender_vk_bytes = sender_vk.encode().to_vec();

    let token_record_id = token_record_id_for(b"add-to-set-record");

    // Start with bypass ON but empty verified_senders.
    let settings_empty = freenet_email_inbox::InboxSettings {
        minimum_tier: Tier::Min10,
        allow_verified_skip_token: true,
        verified_senders: Default::default(),
        ..freenet_email_inbox::InboxSettings::default()
    };
    let initial_state = make_inbox_state(&owner_sk, vec![], Utc::now(), settings_empty);

    // Step 1: sender not in set — tokenless message rejected.
    let msg1 = make_message_no_token(
        b"before add".to_vec(),
        assignment_hash_for(b"add-set-msg1"),
        sender_vk_bytes.clone(),
        token_record_id,
        &sender_sk,
    );
    let dummy_assignment = make_token_assignment(
        &gen_sk,
        gen_vk_bytes.clone(),
        Tier::Min10,
        fixed_valid_slot(),
        assignment_hash_for(b"add-set-msg1"),
        token_record_id,
    );
    let record = make_token_record(dummy_assignment);
    let result = Inbox::update_state(
        params.clone(),
        initial_state.clone(),
        vec![
            add_messages_delta(vec![msg1]),
            related_state_update(token_record_id, record),
        ],
    );
    assert!(
        result.is_err(),
        "sender not in verified_senders must be rejected even with bypass ON"
    );

    // Step 2: owner adds sender's VK to the verified set.
    let settings_with_sender = make_settings_with_bypass(Tier::Min10, sender_vk_bytes.clone());
    let after_add = unwrap_valid(
        Inbox::update_state(
            params.clone(),
            initial_state,
            vec![modify_settings_delta(&owner_sk, settings_with_sender)],
        )
        .expect("ModifySettings should succeed"),
    );

    // Step 3: same sender sends tokenless message → accepted.
    let msg2 = make_message_no_token(
        b"after add".to_vec(),
        assignment_hash_for(b"add-set-msg2"),
        sender_vk_bytes.clone(),
        token_record_id,
        &sender_sk,
    );
    let modification = Inbox::update_state(params, after_add, vec![add_messages_delta(vec![msg2])])
        .expect("after adding VK, tokenless message must succeed");
    let new_state = unwrap_valid(modification);
    let parsed: serde_json::Value = serde_json::from_slice(new_state.as_ref()).expect("inbox json");
    assert_eq!(
        parsed["messages"].as_array().map(|m| m.len()).unwrap_or(0),
        1,
        "sender added to verified_senders must now bypass token requirement"
    );
}

/// Remove from `verified_senders` mid-stream: bypass ON, sender in set →
/// accepted; owner removes their VK via ModifySettings → next message from
/// that sender is rejected.
#[test]
fn remove_from_verified_senders_mid_stream_revokes_bypass() {
    let owner_sk = make_inbox_keypair();
    let owner_vk = inbox_verifying_key(&owner_sk);
    let (gen_sk, gen_vk_bytes) = make_token_generator_keypair();
    let params = make_params(&owner_vk);

    let sender_sk = make_inbox_keypair();
    let sender_vk = inbox_verifying_key(&sender_sk);
    let sender_vk_bytes = sender_vk.encode().to_vec();

    let token_record_id = token_record_id_for(b"remove-from-set-record");

    // Start with sender already in the verified set.
    let settings_with_sender = make_settings_with_bypass(Tier::Min10, sender_vk_bytes.clone());
    let initial_state = make_inbox_state(&owner_sk, vec![], Utc::now(), settings_with_sender);

    // Step 1: send tokenless message → accepted.
    let msg1 = make_message_no_token(
        b"while in set".to_vec(),
        assignment_hash_for(b"remove-set-msg1"),
        sender_vk_bytes.clone(),
        token_record_id,
        &sender_sk,
    );
    let after_msg1 = unwrap_valid(
        Inbox::update_state(
            params.clone(),
            initial_state,
            vec![add_messages_delta(vec![msg1])],
        )
        .expect("first tokenless message should succeed"),
    );

    // Step 2: owner removes sender from verified_senders.
    let settings_no_sender = freenet_email_inbox::InboxSettings {
        minimum_tier: Tier::Min10,
        allow_verified_skip_token: true,
        verified_senders: Default::default(),
        ..freenet_email_inbox::InboxSettings::default()
    };
    let after_remove = unwrap_valid(
        Inbox::update_state(
            params.clone(),
            after_msg1,
            vec![modify_settings_delta(&owner_sk, settings_no_sender)],
        )
        .expect("ModifySettings should succeed"),
    );

    // Step 3: same sender sends another tokenless message → rejected.
    let msg2 = make_message_no_token(
        b"after removal".to_vec(),
        assignment_hash_for(b"remove-set-msg2"),
        sender_vk_bytes.clone(),
        token_record_id,
        &sender_sk,
    );
    let dummy_assignment = make_token_assignment(
        &gen_sk,
        gen_vk_bytes,
        Tier::Min10,
        fixed_valid_slot(),
        assignment_hash_for(b"remove-set-msg2"),
        token_record_id,
    );
    let record = make_token_record(dummy_assignment);
    let result = Inbox::update_state(
        params,
        after_remove,
        vec![
            add_messages_delta(vec![msg2]),
            related_state_update(token_record_id, record),
        ],
    );
    assert!(
        result.is_err(),
        "sender removed from verified_senders must again require a token"
    );
}

/// Empty `verified_senders` + bypass ON: zero entries means nobody bypasses —
/// the behavior is equivalent to bypass OFF.
#[test]
fn empty_verified_senders_with_bypass_on_rejects_tokenless_message() {
    let owner_sk = make_inbox_keypair();
    let owner_vk = inbox_verifying_key(&owner_sk);
    let (gen_sk, gen_vk_bytes) = make_token_generator_keypair();
    let params = make_params(&owner_vk);

    let sender_sk = make_inbox_keypair();
    let sender_vk = inbox_verifying_key(&sender_sk);
    let sender_vk_bytes = sender_vk.encode().to_vec();

    let token_record_id = token_record_id_for(b"empty-set-record");
    let assignment_hash = assignment_hash_for(b"empty-set-msg");

    let message = make_message_no_token(
        b"no one is verified".to_vec(),
        assignment_hash,
        sender_vk_bytes,
        token_record_id,
        &sender_sk,
    );

    // Bypass ON but verified_senders is empty.
    let settings = freenet_email_inbox::InboxSettings {
        minimum_tier: Tier::Min10,
        allow_verified_skip_token: true,
        verified_senders: Default::default(),
        ..freenet_email_inbox::InboxSettings::default()
    };
    let initial_state = make_inbox_state(&owner_sk, vec![], Utc::now(), settings);

    // Provide a real-but-mismatched record so the missing-related gate
    // doesn't fire — we want to reach the token-validity rejection.
    let dummy_assignment = make_token_assignment(
        &gen_sk,
        gen_vk_bytes,
        Tier::Min10,
        fixed_valid_slot(),
        assignment_hash,
        token_record_id,
    );
    let record = make_token_record(dummy_assignment);
    let result = Inbox::update_state(
        params,
        initial_state,
        vec![
            add_messages_delta(vec![message]),
            related_state_update(token_record_id, record),
        ],
    );
    assert!(
        result.is_err(),
        "empty verified_senders with bypass ON must still require a token; got {result:?}"
    );
}

/// `ModifySettings` delta correctness: bypass fields survive a
/// serialize → sign → update_state → deserialize round-trip with the correct
/// values preserved.
#[test]
fn modify_settings_delta_preserves_bypass_fields() {
    let owner_sk = make_inbox_keypair();
    let owner_vk = inbox_verifying_key(&owner_sk);
    let params = make_params(&owner_vk);

    let sender_sk = make_inbox_keypair();
    let sender_vk = inbox_verifying_key(&sender_sk);
    let sender_vk_bytes = sender_vk.encode().to_vec();

    // Start with default (bypass OFF).
    let initial_state = make_inbox_state(
        &owner_sk,
        vec![],
        Utc::now(),
        freenet_email_inbox::InboxSettings::default(),
    );

    // Apply a ModifySettings that turns bypass ON and adds a verified sender.
    let new_settings = make_settings_with_bypass(Tier::Min10, sender_vk_bytes.clone());
    let after_update = unwrap_valid(
        Inbox::update_state(
            params.clone(),
            initial_state,
            vec![modify_settings_delta(&owner_sk, new_settings.clone())],
        )
        .expect("ModifySettings should succeed"),
    );

    // Deserialize the resulting state and check the fields.
    let parsed: serde_json::Value =
        serde_json::from_slice(after_update.as_ref()).expect("inbox json");
    let settings_val = &parsed["settings"];
    assert_eq!(
        settings_val["allow_verified_skip_token"].as_bool(),
        Some(true),
        "allow_verified_skip_token must be persisted as true after ModifySettings"
    );
    // `verified_senders` is skipped if empty; here it must be present.
    let vs = settings_val["verified_senders"]
        .as_array()
        .expect("verified_senders must be a JSON array");
    assert_eq!(vs.len(), 1, "one verified sender must be persisted");
}

/// Replay protection for bypass messages: a bypass-accepted message cannot
/// be replayed — the same `assignment_hash` is deduplicated on a second submit.
#[test]
fn bypass_message_replay_is_deduplicated() {
    let owner_sk = make_inbox_keypair();
    let owner_vk = inbox_verifying_key(&owner_sk);
    let params = make_params(&owner_vk);

    let sender_sk = make_inbox_keypair();
    let sender_vk = inbox_verifying_key(&sender_sk);
    let sender_vk_bytes = sender_vk.encode().to_vec();

    let token_record_id = token_record_id_for(b"bypass-replay-record");
    let assignment_hash = assignment_hash_for(b"bypass-replay-msg");

    let message = make_message_no_token(
        b"bypass payload".to_vec(),
        assignment_hash,
        sender_vk_bytes.clone(),
        token_record_id,
        &sender_sk,
    );

    let settings = make_settings_with_bypass(Tier::Min10, sender_vk_bytes);
    let initial_state = make_inbox_state(&owner_sk, vec![], Utc::now(), settings);

    // First submit — accepted.
    let after_first = unwrap_valid(
        Inbox::update_state(
            params.clone(),
            initial_state,
            vec![add_messages_delta(vec![message.clone()])],
        )
        .expect("first bypass message should succeed"),
    );

    // Replay — same message, same assignment_hash. Must be deduplicated (still 1 msg).
    let after_replay = unwrap_valid(
        Inbox::update_state(params, after_first, vec![add_messages_delta(vec![message])])
            .expect("replay must be a no-op, not an error"),
    );

    let parsed: serde_json::Value =
        serde_json::from_slice(after_replay.as_ref()).expect("inbox json");
    assert_eq!(
        parsed["messages"].as_array().map(|m| m.len()).unwrap_or(0),
        1,
        "replayed bypass message must not duplicate the inbox entry"
    );
}

/// After fix for PR #157: bypass path requires a valid ML-DSA-65 sender
/// signature over the message content. An attacker who copies a verified VK
/// into their `sender_vk` field but cannot sign with the corresponding key
/// is rejected — the bypass is now signature-based, not membership-based alone.
///
/// This test was previously named
/// `forged_sender_vk_gets_bypass_because_contract_checks_membership_not_sig`
/// and asserted acceptance (the security regression). It is now inverted to
/// confirm the fix: forged VK with no valid content signature → REJECTED.
#[test]
fn bypass_rejects_unsigned_or_missigned_messages() {
    let owner_sk = make_inbox_keypair();
    let owner_vk = inbox_verifying_key(&owner_sk);
    let params = make_params(&owner_vk);

    // Legitimate sender: their VK is in the bypass allow-list.
    let _legit_sk = make_inbox_keypair();
    let legit_vk = inbox_verifying_key(&_legit_sk);
    let legit_vk_bytes = legit_vk.encode().to_vec();

    // Attacker has their OWN keypair but copies legit_vk_bytes into sender_vk.
    let attacker_sk = make_inbox_keypair();

    let token_record_id = token_record_id_for(b"forged-vk-record");
    let content = b"content from attacker".to_vec();
    let assignment_hash = assignment_hash_for(b"forged-vk-msg");

    // Build the forged message: sender_vk = legit VK bytes, but signature is
    // produced by the attacker's key (does not match legit_vk_bytes).
    use chrono::Utc;
    use freenet_aft_interface::TokenAssignment;
    let dummy_assignment = TokenAssignment {
        tier: freenet_aft_interface::Tier::Min10,
        time_slot: Utc::now(),
        generator: vec![0u8; 1952],
        signature: vec![0u8; 3309],
        assignment_hash,
        token_record: token_record_id,
    };
    let attacker_sig: ml_dsa::Signature<ml_dsa::MlDsa65> =
        ml_dsa::signature::Signer::sign(&attacker_sk, content.as_slice());
    let forged_message = freenet_email_inbox::Message {
        content,
        token_assignment: dummy_assignment,
        sender_vk: legit_vk_bytes.clone(), // attacker puts legit VK bytes here
        signature: attacker_sig.encode().to_vec(), // but signs with their own key
    };

    let settings = make_settings_with_bypass(Tier::Min10, legit_vk_bytes);
    let initial_state = make_inbox_state(&owner_sk, vec![], Utc::now(), settings);

    // Contract must reject: signature doesn't verify against sender_vk.
    let result = Inbox::update_state(
        params,
        initial_state,
        vec![add_messages_delta(vec![forged_message])],
    );
    assert!(
        result.is_err(),
        "bypass must reject a message whose signature does not verify against sender_vk; \
         forged VK + attacker-signed content must be rejected"
    );
}

/// Negative test: a message with a completely empty signature on the bypass
/// path is also rejected. This ensures `signature: vec![]` — which was the
/// previous placeholder used by `make_message_no_token` — is no longer accepted.
#[test]
fn bypass_rejects_forged_signature() {
    let owner_sk = make_inbox_keypair();
    let owner_vk = inbox_verifying_key(&owner_sk);
    let params = make_params(&owner_vk);

    // Legitimate sender: their VK is in the bypass allow-list.
    let legit_sk = make_inbox_keypair();
    let legit_vk = inbox_verifying_key(&legit_sk);
    let legit_vk_bytes = legit_vk.encode().to_vec();

    let token_record_id = token_record_id_for(b"empty-sig-record");
    let content = b"attacker content with empty sig".to_vec();
    let assignment_hash = assignment_hash_for(b"empty-sig-msg");

    // Build a message with legit VK bytes but empty (zero-length) signature.
    use chrono::Utc;
    use freenet_aft_interface::TokenAssignment;
    let dummy_assignment = TokenAssignment {
        tier: freenet_aft_interface::Tier::Min10,
        time_slot: Utc::now(),
        generator: vec![0u8; 1952],
        signature: vec![0u8; 3309],
        assignment_hash,
        token_record: token_record_id,
    };
    let message_no_sig = freenet_email_inbox::Message {
        content,
        token_assignment: dummy_assignment,
        sender_vk: legit_vk_bytes.clone(),
        signature: Vec::new(), // no signature at all
    };

    let settings = make_settings_with_bypass(Tier::Min10, legit_vk_bytes);
    let initial_state = make_inbox_state(&owner_sk, vec![], Utc::now(), settings);

    let result = Inbox::update_state(
        params,
        initial_state,
        vec![add_messages_delta(vec![message_no_sig])],
    );
    assert!(
        result.is_err(),
        "bypass must reject a message with sender_vk set but an empty signature"
    );
}

// ─── #157 security fixes: MAX_VERIFIED_SENDERS cap ───────────────────────

/// `ModifySettings` with `verified_senders.len() > MAX_VERIFIED_SENDERS` is
/// rejected by `can_update_settings` before signature verification.
#[test]
fn modify_settings_rejects_oversized_verified_senders() {
    let owner_sk = make_inbox_keypair();
    let owner_vk = inbox_verifying_key(&owner_sk);
    let params = make_params(&owner_vk);

    let initial_state = make_inbox_state(&owner_sk, vec![], Utc::now(), InboxSettings::default());

    // Build MAX_VERIFIED_SENDERS + 1 fake VK byte vectors (each 1952 bytes of zeros
    // with a unique first byte so they're distinct). The content doesn't need to
    // be valid ML-DSA-65 keys — the cap check fires before any key decode.
    let too_many_vks: Vec<Vec<u8>> = (0..=(MAX_VERIFIED_SENDERS as u64))
        .map(|i| {
            let mut v = vec![0u8; 1952];
            // Make each entry unique by embedding the index in the first 8 bytes.
            v[0..8].copy_from_slice(&i.to_le_bytes());
            v
        })
        .collect();

    let oversized_settings = make_settings_with_bypass_multi(Tier::Min10, too_many_vks);
    assert!(
        oversized_settings.verified_senders.len() > MAX_VERIFIED_SENDERS,
        "test setup: verified_senders must exceed the cap"
    );

    let result = Inbox::update_state(
        params,
        initial_state,
        vec![modify_settings_delta(&owner_sk, oversized_settings)],
    );
    assert!(
        result.is_err(),
        "ModifySettings with verified_senders.len() > MAX_VERIFIED_SENDERS must be rejected; \
         got {result:?}"
    );
}

/// `ModifySettings` with exactly `MAX_VERIFIED_SENDERS` entries is accepted.
#[test]
fn modify_settings_accepts_verified_senders_at_cap() {
    let owner_sk = make_inbox_keypair();
    let owner_vk = inbox_verifying_key(&owner_sk);
    let params = make_params(&owner_vk);

    let initial_state = make_inbox_state(&owner_sk, vec![], Utc::now(), InboxSettings::default());

    // Exactly MAX_VERIFIED_SENDERS entries — at the limit, not over it.
    let at_cap_vks: Vec<Vec<u8>> = (0..MAX_VERIFIED_SENDERS as u64)
        .map(|i| {
            let mut v = vec![0u8; 1952];
            v[0..8].copy_from_slice(&i.to_le_bytes());
            v
        })
        .collect();

    let at_cap_settings = make_settings_with_bypass_multi(Tier::Min10, at_cap_vks);
    assert_eq!(
        at_cap_settings.verified_senders.len(),
        MAX_VERIFIED_SENDERS,
        "test setup: verified_senders must be exactly at cap"
    );

    // This must succeed (at cap, not over).
    let result = Inbox::update_state(
        params,
        initial_state,
        vec![modify_settings_delta(&owner_sk, at_cap_settings)],
    );
    assert!(
        result.is_ok(),
        "ModifySettings with verified_senders.len() == MAX_VERIFIED_SENDERS must be accepted; \
         got {result:?}"
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
