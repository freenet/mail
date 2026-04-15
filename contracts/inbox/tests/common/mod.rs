//! Reusable crypto + state-construction helpers for inbox integration tests.
//!
//! These tests run as native Rust (`--features contract`), driving the
//! `ContractInterface` impl directly without going through the WASM FFI.
//! Each test that needs a freshly-signed inbox / token / message reaches in
//! through this module so the round-trip / validation / token-gating tests
//! stay focused on the assertion they care about.
//!
//! Crypto note: as of Stage 4 of #18, this module uses ML-DSA-65 uniformly
//! for both inbox-owner signatures and AFT token-generator signatures.
#![allow(dead_code)] // helpers are picked up à la carte by individual test files

use std::collections::HashMap;

use chrono::{DateTime, TimeZone, Utc};
use freenet_aft_interface::{Tier, TokenAllocationRecord, TokenAssignment};
use freenet_email_inbox::{InboxParams, InboxSettings, Message, UpdateInbox};
use freenet_stdlib::prelude::{
    ContractInstanceId, Parameters, RelatedContracts, State, StateDelta, UpdateData,
};
use getrandom::SysRng;
use ml_dsa::{
    KeyGen, MlDsa65, SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey,
    signature::{Keypair as MlDsaKeypair, Signer as MlDsaSigner, rand_core::UnwrapErr},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The fixed 8-byte salt the inbox contract signs at construction time.
/// Must match the `STATE_UPDATE` constant in `contracts/inbox/src/lib.rs`.
const STATE_UPDATE: &[u8; 8] = &[168, 7, 13, 64, 168, 123, 142, 215];

/// Generate a fresh ML-DSA-65 keypair for use as an inbox owner. Keygen is
/// <10ms for ML-DSA-65, so tests can afford to generate one per test without
/// the wall-time pain RSA-4096 used to impose.
pub fn make_inbox_keypair() -> MlDsaSigningKey<MlDsa65> {
    let mut rng = UnwrapErr(SysRng);
    MlDsa65::key_gen(&mut rng)
}

/// Extract the verifying key from an inbox signing key. Small helper so
/// individual tests don't have to pull in the `Keypair` trait.
pub fn inbox_verifying_key(sk: &MlDsaSigningKey<MlDsa65>) -> MlDsaVerifyingKey<MlDsa65> {
    MlDsaKeypair::verifying_key(sk)
}

/// Generate a fresh ML-DSA-65 keypair for use as an AFT token generator.
/// Returns the signing key plus the FIPS 204 encoded verifying key bytes
/// (1952 bytes) that populate `TokenAssignment.generator`.
pub fn make_token_generator_keypair() -> (MlDsaSigningKey<MlDsa65>, Vec<u8>) {
    let mut rng = UnwrapErr(SysRng);
    let sk = MlDsa65::key_gen(&mut rng);
    let vk_bytes = MlDsaKeypair::verifying_key(&sk).encode().to_vec();
    (sk, vk_bytes)
}

/// Build the serialized [`InboxParams`] (a JSON-encoded `Parameters` blob)
/// for the given inbox owner's ML-DSA verifying key.
pub fn make_params(owner_vk: &MlDsaVerifyingKey<MlDsa65>) -> Parameters<'static> {
    InboxParams::from_verifying_key(owner_vk)
        .try_into()
        .expect("inbox params -> parameters")
}

/// Pick a deterministic, valid `Tier::Min1` slot well in the past so that
/// `is_valid_slot` accepts it. The chosen instant is rounded to second 0 of
/// minute 0 of hour 0, which is also valid for every coarser tier.
pub fn fixed_valid_slot() -> DateTime<Utc> {
    // 2024-01-01T00:00:00Z — round to the start of the day, which is a
    // valid slot for every Tier (Min1 through Day365 anchored from year 1).
    Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap()
}

/// Build a token assignment signed by `generator_sk` (ML-DSA-65). The signed
/// payload is `(tier_byte, time_slot.timestamp_le_bytes, assignment_hash)`
/// per the contract documented on [`TokenAssignment::signature_content`].
///
/// `generator_vk_bytes` is the caller-supplied encoded VK that gets stored
/// on-chain in `TokenAssignment.generator` — pass the second tuple element
/// of [`make_token_generator_keypair`].
///
/// `token_record` is the contract-instance ID that
/// [`TokenAllocationRecord`] entries are keyed by — pick any stable value
/// per test; the helper does not enforce uniqueness.
pub fn make_token_assignment(
    generator_sk: &MlDsaSigningKey<MlDsa65>,
    generator_vk_bytes: Vec<u8>,
    tier: Tier,
    time_slot: DateTime<Utc>,
    assignment_hash: [u8; 32],
    token_record: ContractInstanceId,
) -> TokenAssignment {
    let to_sign = TokenAssignment::signature_content(&time_slot, tier, &assignment_hash);
    let signature: ml_dsa::Signature<MlDsa65> = MlDsaSigner::sign(generator_sk, &to_sign);
    TokenAssignment {
        tier,
        time_slot,
        generator: generator_vk_bytes,
        signature: signature.encode().to_vec(),
        assignment_hash,
        token_record,
    }
}

/// Wrap an opaque encrypted blob with a token assignment. The contract does
/// not introspect `content`, so a placeholder body is fine for tests that
/// only exercise validation / merge / token gating.
pub fn make_message(content: Vec<u8>, token: TokenAssignment) -> Message {
    Message {
        content,
        token_assignment: token,
    }
}

/// Build an [`Inbox`] signed by `owner_sk` (ML-DSA-65) and serialize it as
/// a `State`.
///
/// We hand-roll the JSON wire format here because `Inbox::new` and
/// `inbox_signature` are private to the inbox crate; the integration test
/// harness lives in a sibling crate and only sees the public API. Matches
/// the format produced by `Inbox::serialize` (verified by the existing
/// `validate_test` unit test in `src/lib.rs`).
pub fn make_inbox_state(
    owner_sk: &MlDsaSigningKey<MlDsa65>,
    messages: Vec<Message>,
    last_update: DateTime<Utc>,
    settings: InboxSettings,
) -> State<'static> {
    let signature: ml_dsa::Signature<MlDsa65> = MlDsaSigner::sign(owner_sk, STATE_UPDATE);
    let signature_bytes: Vec<u8> = signature.encode().to_vec();

    let inbox_json: Value = json!({
        "messages": messages,
        "last_update": last_update,
        "settings": settings,
        "inbox_signature": signature_bytes,
    });
    let bytes = serde_json::to_vec(&inbox_json).expect("serialize inbox");
    State::from(bytes)
}

/// Same as [`make_inbox_state`] but returns the parsed JSON object so a
/// caller can flip a single field (e.g. tamper with `last_update`) before
/// re-serializing. Used by the signature-rejection test.
pub fn make_inbox_value(
    owner_sk: &MlDsaSigningKey<MlDsa65>,
    messages: Vec<Message>,
    last_update: DateTime<Utc>,
    settings: InboxSettings,
) -> Value {
    let signature: ml_dsa::Signature<MlDsa65> = MlDsaSigner::sign(owner_sk, STATE_UPDATE);
    let signature_bytes: Vec<u8> = signature.encode().to_vec();
    json!({
        "messages": messages,
        "last_update": last_update,
        "settings": settings,
        "inbox_signature": signature_bytes,
    })
}

/// Build a [`TokenAllocationRecord`] containing the supplied assignment.
/// `validate_state` / `update_state` look up records in the
/// [`RelatedContracts`] map by `token_record` instance id, so the helper
/// returns both the record and the keyed entry to plug into a `RelatedContracts`.
pub fn make_token_record(assignment: TokenAssignment) -> TokenAllocationRecord {
    let mut by_tier = HashMap::new();
    by_tier.insert(assignment.tier, vec![assignment]);
    TokenAllocationRecord::new(by_tier)
}

/// Wrap a [`TokenAllocationRecord`] in a `RelatedContracts` keyed by the
/// supplied `token_record` id. This is what `validate_state` will read.
pub fn related_contracts_with(
    token_record_id: ContractInstanceId,
    record: TokenAllocationRecord,
) -> RelatedContracts<'static> {
    let state: State<'static> = TryFrom::try_from(record).expect("record -> state");
    let mut map: HashMap<ContractInstanceId, Option<State<'static>>> = HashMap::new();
    map.insert(token_record_id, Some(state));
    RelatedContracts::from(map)
}

/// Build an `UpdateData::Delta(AddMessages)` payload for `update_state`.
pub fn add_messages_delta(messages: Vec<Message>) -> UpdateData<'static> {
    let delta = UpdateInbox::AddMessages { messages };
    let bytes = serde_json::to_vec(&delta).expect("serialize delta");
    UpdateData::Delta(StateDelta::from(bytes))
}

/// Build an `UpdateData::RelatedState` carrying a token allocation record.
pub fn related_state_update(
    token_record_id: ContractInstanceId,
    record: TokenAllocationRecord,
) -> UpdateData<'static> {
    let state: State<'static> = TryFrom::try_from(record).expect("record -> state");
    UpdateData::RelatedState {
        related_to: token_record_id,
        state,
    }
}

/// Hash an arbitrary identifier into a 32-byte assignment hash. Useful for
/// tests that need a stable hash but do not care about its semantic content.
pub fn assignment_hash_for(seed: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(seed);
    hasher.finalize().into()
}

/// Construct a `ContractInstanceId` deterministically from a seed. The
/// inbox contract treats this as an opaque key, so any 32-byte value works.
pub fn token_record_id_for(seed: &[u8]) -> ContractInstanceId {
    let bytes = assignment_hash_for(seed);
    ContractInstanceId::new(bytes)
}
