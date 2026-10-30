#[cfg(test)]
use std::io::{Cursor, Read};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
};

#[cfg(test)]
use chacha20poly1305::{XChaCha20Poly1305, aead::Aead};
use chrono::{DateTime, Utc};
use freenet_mail_wire_v1::aft::{Tier, TokenAssignment, TokenAssignmentHash};
use freenet_stdlib::{
    client_api::ContractRequest,
    prelude::{ContractKey, UpdateData, blake3},
};

use futures::FutureExt;
use futures::future::LocalBoxFuture;
use ml_dsa::{
    EncodedVerifyingKey, MlDsa65, VerifyingKey as MlDsaVerifyingKey,
    signature::Verifier as MlDsaVerifier,
};
#[cfg(test)]
use ml_dsa::{
    SigningKey as MlDsaSigningKey,
    signature::{Keypair as MlDsaKeypair, Signer as MlDsaSigner},
};
#[cfg(test)]
use ml_kem::{
    DecapsulationKey,
    kem::{Decapsulate, Encapsulate},
};
use ml_kem::{EncapsulationKey, MlKem768, kem::KeyExport};
use serde::{Deserialize, Serialize};

use freenet_mail_wire_v1::inbox::{
    Inbox as StoredInbox, InboxParams, InboxSettings as StoredSettings, Message as StoredMessage,
    UpdateInbox,
};

use crate::{
    DynError,
    aft::AftRecords,
    api::{TryNodeAction, WebApiRequestClient, node_response_error_handling},
    app::Identity,
};

type InboxContract = ContractKey;

// `inbox_code_hash` is produced by `cargo make build-inbox-contract`. Under
// `--no-default-features --features example-data,no-sync` it isn't needed
// (no contract calls happen) and the build artifact may not exist, so we
// fall back to an empty placeholder. Any attempt to use it offline would
// fail at `ContractKey::from_params` time, but those code paths are dead
// when `use-node` is disabled.
#[cfg(feature = "use-node")]
pub(crate) const INBOX_CODE_HASH: &str =
    include_str!("../../published-contract/wasm/v1/inbox_code_hash");
#[cfg(not(feature = "use-node"))]
pub(crate) const INBOX_CODE_HASH: &str = "";

/// Historical `INBOX_CODE_HASH` values, oldest → newest. Each entry is a
/// hash the inbox contract WASM previously had under a prior release.
/// Used by the migration path (#251 improvement 2) to handle multi-hop
/// version gaps: if a user comes back online after two or more deliberate
/// contract bumps, the recorded `inbox_wasm_hash` may be older than the
/// most recent prior hash. The migration walks the slice starting at the
/// recorded hash and dispatches GETs against every newer historical key
/// until one resolves. Append-only: never reorder, never delete entries.
/// The current `INBOX_CODE_HASH` must NOT appear in this list.
pub(crate) const LEGACY_INBOX_CODE_HASHES: &[&str] = &[
    // Pre-#253 inbox: signature payload was `STATE_UPDATE || owner_ek_bytes`
    // (settings + last_update unsigned). #253 widened the signed payload,
    // rotating the wasm hash. Users on this hash migrate forward via #213/#251.
    "Ht8rcMjTpnraRNbzkmDCBFJJfmQGJ8M2iUAGaZimE9Ji",
];

/// Build the ordered list of candidate code hashes to GET for a
/// migration starting from `prior_hash`. The returned vec always
/// contains `prior_hash` first, then every entry in `legacy` that
/// follows it (if `prior_hash` is present in `legacy`) — or every
/// entry in `legacy` other than `prior_hash` (if `prior_hash` is NOT
/// present, meaning the recorded hash predates the committed legacy
/// list; we walk the whole list to maximise recovery odds).
///
/// Pure function — extracted from `migrate_inbox` so the chain-build
/// logic can be unit-tested without a node round trip.
pub(crate) fn build_migration_candidates(prior_hash: &str, legacy: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = vec![prior_hash.to_string()];
    let start_idx = legacy
        .iter()
        .position(|h| *h == prior_hash)
        .map_or(0, |i| i + 1);
    for h in &legacy[start_idx..] {
        if *h != prior_hash {
            out.push((*h).to_string());
        }
    }
    out
}

/// Decide which prior hash to migrate FROM on startup, given the
/// recorded `inbox_wasm_hash` (`prior`), the persistent
/// pending-migration marker (`pending`), and the embedded
/// `current` hash.
///
/// Rules:
/// - If `prior == current`: no drift; ignore any stale marker (caller
///   is responsible for clearing it separately).
/// - Else if `pending` is set: prefer the marker (it's the source of
///   truth for in-flight retries — see #251 improvement 5).
/// - Else if `prior` is set: standard single-hop drift.
/// - Else: first observation; nothing to migrate.
///
/// Pure function — extracted so the precedence rules can be
/// table-tested without a node.
pub(crate) fn select_migrate_from(
    prior: Option<&str>,
    pending: Option<&str>,
    current: &str,
) -> Option<String> {
    match (prior, pending) {
        (Some(p), _) if p == current => None,
        (_, Some(pending)) => Some(pending.to_string()),
        (Some(p), None) => Some(p.to_string()),
        (None, None) => None,
    }
}

/// Encode the `InboxParams.pub_key` bytes for an inbox owned by this identity.
///
/// After Stage 2 the inbox contract ID is derived from the ML-DSA-65 verifying
/// key stored in the identity, not from an RSA public key. Callers that only
/// have the serialised verifying-key bytes (e.g. senders looking up a
/// recipient's inbox) pass them in directly.
pub(crate) fn inbox_params_pub_key_bytes(ml_dsa_vk: &MlDsaVerifyingKey<MlDsa65>) -> Vec<u8> {
    ml_dsa_vk.encode().to_vec()
}

/// Derive the on-chain inbox `ContractKey` for the inbox owned by
/// `ml_dsa_vk`. Same derivation as `start_sending` uses internally; exposed
/// so the compose-Send path can enqueue a pending Sent ack against the
/// recipient's inbox key without re-implementing the params encoding.
///
pub(crate) fn inbox_key_for(
    ml_dsa_vk: &MlDsaVerifyingKey<MlDsa65>,
) -> Result<ContractKey, DynError> {
    inbox_key_for_with_hash(ml_dsa_vk, INBOX_CODE_HASH)
}

/// Same as `inbox_key_for` but derives against an explicit code hash —
/// used by the send path (#251 improvement 4) so the sender can address
/// the recipient's inbox under the recipient's WASM hash rather than
/// the sender's embedded `INBOX_CODE_HASH`. A non-upgraded recipient
/// still receives messages from an upgraded sender.
///
/// Callers that hold a recipient's `Contact.inbox_wasm_hash` should
/// pass it here. `None` callers can stay on `inbox_key_for`.
pub(crate) fn inbox_key_for_with_hash(
    ml_dsa_vk: &MlDsaVerifyingKey<MlDsa65>,
    code_hash: &str,
) -> Result<ContractKey, DynError> {
    let params = InboxParams {
        pub_key: inbox_params_pub_key_bytes(ml_dsa_vk),
    }
    .try_into()
    .map_err(|e| format!("{e}"))?;
    ContractKey::from_params(code_hash, params).map_err(|e| format!("{e}").into())
}

/// Verify a detached ML-DSA-65 signature over `ciphertext` using the
/// sender's encoded verifying key. Returns `false` for empty / wrong-
/// length / cryptographically-invalid inputs (the recipient renders
/// these as "unverified" rather than rejecting; #51).
pub(crate) fn verify_message_signature(
    ciphertext: &[u8],
    sender_vk: &[u8],
    signature: &[u8],
) -> bool {
    if sender_vk.is_empty() || signature.is_empty() {
        return false;
    }
    let Ok(encoded_vk): Result<EncodedVerifyingKey<MlDsa65>, _> = sender_vk.try_into() else {
        return false;
    };
    let vk = MlDsaVerifyingKey::<MlDsa65>::decode(&encoded_vk);
    let Ok(sig) = ml_dsa::Signature::<MlDsa65>::try_from(signature) else {
        return false;
    };
    MlDsaVerifier::verify(&vk, ciphertext, &sig).is_ok()
}

/// Derive the bs58 inbox-contract address for a sender from their raw
/// ML-DSA-65 verifying-key bytes (as carried on a received message's
/// `sender_vk`). Used by the #272 "Add to address book" flow to seed the
/// import modal — the address is enough to trigger the live
/// `FetchContactKeys` Get that pulls the rest of the contact's keys.
///
/// Derives against the sender's embedded `INBOX_CODE_HASH`; a received
/// message carries no recipient-side hash, and the import fetch resolves
/// the real keys regardless.
pub(crate) fn inbox_address_bs58_from_vk_bytes(sender_vk: &[u8]) -> Result<String, DynError> {
    let encoded_vk: EncodedVerifyingKey<MlDsa65> =
        sender_vk.try_into().map_err(|_| "sender VK wrong length")?;
    let vk = MlDsaVerifyingKey::<MlDsa65>::decode(&encoded_vk);
    let key = inbox_key_for(&vk)?;
    Ok(key.id().encode())
}

thread_local! {
    static PENDING_INBOXES_UPDATE: RefCell<HashMap<InboxContract, Vec<PendingOutgoing>>> = RefCell::new(HashMap::new());
    static INBOX_TO_ID: RefCell<HashMap<InboxContract, Identity>> =
        RefCell::new(HashMap::new());
    /// Outgoing messages awaiting an `UpdateResponse` from the recipient's
    /// inbox contract. Populated by the compose-Send path with the
    /// `(sender_alias, sent_id)` the UI assigned to its local Sent stash;
    /// drained FIFO when an `UpdateResponse` arrives for that inbox key
    /// (api.rs flips the corresponding row to `Delivered`).
    ///
    /// FIFO pairing is approximate — the network doesn't promise responses
    /// for sequential sends to the same inbox land in submission order, and
    /// the stale-send sweep (#288) can drain an entry that NEVER gets a
    /// response, so the old "#responses == #entries" invariant no longer
    /// holds. A mis-paired or post-sweep-late `UpdateResponse` could pop a
    /// sibling entry and try to flip the wrong row to `Delivered`; that is
    /// made safe by the terminal-state guard in
    /// `local_state::local_set_sent_delivery_state` — once a row is
    /// `Delivered`/`Failed` it never flips again, so the worst case is a
    /// dropped (no-op) flip, not a wrong terminal state.
    pub(crate) static PENDING_SENT_ACK: RefCell<HashMap<InboxContract, std::collections::VecDeque<PendingSentEntry>>> =
        RefCell::new(HashMap::new());
}

/// A Sent row whose `UpdateResponse` hasn't arrived within this many
/// seconds of enqueue is failed by the stale-send sweep (#288, "no
/// terminal reply at all" case).
///
/// The clock starts at row construction (`sent_at_ms`), i.e. BEFORE the
/// async AFT assignment round trip, so the budget is shared: up to
/// `PENDING_ASSIGNMENT_TIMEOUT_SECS` (30s) can be spent minting the token
/// before the recipient-inbox UPDATE is even dispatched. The value is set
/// to 90s so the UPDATE round trip always gets a full ≥60s window
/// regardless of how long the AFT phase took — generous enough to avoid
/// false-failing a slow-but-healthy send while still bounding the
/// stuck-Pending UX.
///
/// This sweep is a backstop. An AFT-phase stall is failed earlier (at
/// `PENDING_ASSIGNMENT_TIMEOUT_SECS`) by `AftRecords::expire_stale`, which
/// now flips the Sent row directly; the `Failure` arm (#85) covers
/// delegate refusals. This 90s sweep only fires when the UPDATE itself got
/// neither an `UpdateResponse` nor a `ContractError::Update` — the
/// silent-drop case of freenet-core#4345.
#[cfg(feature = "use-node")]
pub(crate) const PENDING_SENT_TIMEOUT_SECS: i64 = 90;

/// One outgoing Sent row awaiting an `UpdateResponse`. Carries the
/// `(sender_alias, sent_id)` the UI assigned plus the wall-clock millis
/// when it was enqueued, so a periodic sweep can fail rows whose ack
/// never arrives at all — no error, no `UpdateResponse` (#288).
#[derive(Clone)]
pub(crate) struct PendingSentEntry {
    pub sender_alias: String,
    pub sent_id: String,
    /// `chrono::Utc::now().timestamp_millis()` at enqueue time.
    pub enqueued_at_ms: i64,
}

/// Record that a send to `inbox_key` is awaiting an UpdateResponse to flip
/// the Sent row identified by `(sender_alias, sent_id)` to Delivered.
/// `enqueued_at_ms` is the send-time wall clock (same source as the Sent
/// row's `sent_at`), used by the stale-send sweep.
pub(crate) fn enqueue_pending_sent_ack(
    inbox_key: InboxContract,
    sender_alias: String,
    sent_id: String,
    enqueued_at_ms: i64,
) {
    PENDING_SENT_ACK.with(|m| {
        m.borrow_mut()
            .entry(inbox_key)
            .or_default()
            .push_back(PendingSentEntry {
                sender_alias,
                sent_id,
                enqueued_at_ms,
            });
    });
}

/// Pop the next pending sent record for `inbox_key`, if any.
pub(crate) fn take_next_pending_sent_ack(inbox_key: &InboxContract) -> Option<(String, String)> {
    PENDING_SENT_ACK.with(|m| {
        let mut map = m.borrow_mut();
        let q = map.get_mut(inbox_key)?;
        let item = q.pop_front();
        if q.is_empty() {
            map.remove(inbox_key);
        }
        item.map(|e| (e.sender_alias, e.sent_id))
    })
}

/// Drain every pending Sent row queued against `inbox_key` and flip
/// each to `Failed` (both locally and via the local-state delegate so
/// the change persists across reload). Used when the AFT delegate
/// reports a `Failure` for a token request — the send cannot complete
/// and the user must see that, instead of a Pending spinner that never
/// resolves (#85).
#[cfg(feature = "use-node")]
pub(crate) fn fail_pending_sent_for_inbox(inbox_key: InboxContract) {
    let entries: Vec<(String, String)> = PENDING_SENT_ACK.with(|m| {
        let mut map = m.borrow_mut();
        match map.remove(&inbox_key) {
            Some(q) => q.into_iter().map(|e| (e.sender_alias, e.sent_id)).collect(),
            None => Vec::new(),
        }
    });
    for (sender_alias, sent_id) in entries {
        fail_one_sent(&sender_alias, &sent_id);
    }
    PENDING_INBOXES_UPDATE.with(|m| {
        m.borrow_mut().remove(&inbox_key);
    });
}

/// Flip a single Sent row to `Failed`, both in the in-memory local stash
/// and in the mail delegate so the change survives reload. Shared by
/// `fail_pending_sent_for_inbox` (#85/#288) and `expire_stale_pending_sent`.
///
/// Both run on the node loop, which delivers the delegate's answers, so the
/// delegate write runs in a detached task: awaiting it here would deadlock.
#[cfg(feature = "use-node")]
fn fail_one_sent(sender_alias: &str, sent_id: &str) {
    // Skip the delegate write when the row was already terminal — the local
    // guard suppressed the in-memory flip, and persisting again would let a
    // stale value clobber the true terminal state on reload (#288).
    if !crate::local_state::local_set_sent_delivery_state(
        sender_alias,
        sent_id,
        freenet_mail_wire_v1::local_state::DeliveryState::Failed,
    ) {
        return;
    }
    let (sender_alias, sent_id) = (sender_alias.to_string(), sent_id.to_string());
    wasm_bindgen_futures::spawn_local(async move {
        if let Err(e) = crate::local_state::set_sent_delivery_state(
            sender_alias.clone(),
            sent_id.clone(),
            freenet_mail_wire_v1::local_state::DeliveryState::Failed,
        )
        .await
        {
            crate::log::error(
                format!("set_sent_delivery_state(Failed) for {sender_alias}/{sent_id}: {e}"),
                None,
            );
        }
    });
}

/// Pure step of the stale-send sweep: remove every pending entry older
/// than `timeout_secs` from `PENDING_SENT_ACK` and return the drained
/// `(sender_alias, sent_id)` pairs. No I/O, no client — `now_ms` is
/// injected so the age logic is unit-testable. Empty per-inbox queues are
/// pruned so the map doesn't accumulate keys.
fn drain_stale_pending_sent(timeout_secs: i64, now_ms: i64) -> Vec<(String, String)> {
    let cutoff_ms = timeout_secs.saturating_mul(1000);
    PENDING_SENT_ACK.with(|m| {
        let mut map = m.borrow_mut();
        let mut out = Vec::new();
        for q in map.values_mut() {
            q.retain(|e| {
                let age = now_ms.saturating_sub(e.enqueued_at_ms);
                if age >= cutoff_ms {
                    out.push((e.sender_alias.clone(), e.sent_id.clone()));
                    false
                } else {
                    true
                }
            });
        }
        map.retain(|_, q| !q.is_empty());
        out
    })
}

/// Sweep every pending Sent row across all inboxes and fail those whose
/// `UpdateResponse` never arrived within `timeout_secs` of enqueue — the
/// "no terminal reply at all" case (no error, no `UpdateResponse`), the
/// last uncovered send-failure mode of #288. `now_ms` is the current wall
/// clock (`chrono::Utc::now().timestamp_millis()`), injected for testability.
/// Returns the `(sender_alias, sent_id)` pairs that were expired so the
/// caller can toast the user.
#[cfg(feature = "use-node")]
pub(crate) fn expire_stale_pending_sent(timeout_secs: i64, now_ms: i64) -> Vec<(String, String)> {
    // Drain the stale entries out of the map first (sync borrow); the
    // delegate writes run detached (`fail_one_sent`).
    let stale = drain_stale_pending_sent(timeout_secs, now_ms);
    for (sender_alias, sent_id) in &stale {
        crate::log::error(
            format!(
                "send to {sender_alias} (sent_id {sent_id}) got no UpdateResponse within {timeout_secs}s — marking Failed"
            ),
            Some(crate::api::TryNodeAction::SendMessage),
        );
        fail_one_sent(sender_alias, sent_id);
    }
    stale
}

/// Remove a specific pending sent record from the queue (e.g. on
/// `start_sending` async error so the row stops blocking later acks).
/// No-op if the entry is not in the queue.
pub(crate) fn remove_pending_sent_ack(
    inbox_key: &InboxContract,
    sender_alias: &str,
    sent_id: &str,
) {
    PENDING_SENT_ACK.with(|m| {
        let mut map = m.borrow_mut();
        let Some(q) = map.get_mut(inbox_key) else {
            return;
        };
        q.retain(|e| !(e.sender_alias == sender_alias && e.sent_id == sent_id));
        if q.is_empty() {
            map.remove(inbox_key);
        }
    });
}

/// Outgoing message awaiting an AFT token assignment. Holds the sender
/// identity so we can sign the ciphertext with the sender's ML-DSA-65
/// signing key when the assignment lands (#51).
struct PendingOutgoing {
    sealed: crate::mail_delegate::ops::SealedV1,
    sender: Identity,
}

impl PendingOutgoing {
    /// The stored message: the ciphertext and signature the delegate sealed
    /// once at send time, so the token answer (handled in the node loop)
    /// has nothing left to sign.
    fn to_stored(&self, token_assignment: TokenAssignment) -> StoredMessage {
        StoredMessage {
            content: self.sealed.content.clone(),
            token_assignment,
            sender_vk: self.sealed.sender_vk.clone(),
            signature: self.sealed.signature.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct InternalSettings {
    /// AFT tier the recipient demands from incoming senders. Mutable
    /// via the Settings UI (#85): `update_settings_at_store` signs a
    /// `ModifySettings` delta with `ml_dsa_signing_key` and pushes it
    /// to the inbox contract.
    minimum_tier: Tier,
    /// `max_age_secs` half of the recipient anti-flood policy. Sent
    /// alongside `minimum_tier` in `ModifySettings` deltas.
    max_age_secs: u64,
    /// Mirror of `InboxSettings.allow_verified_skip_token` (#150). When
    /// `true`, messages from senders in `verified_senders` bypass the AFT
    /// token requirement. Updated via `ModifySettings` deltas along with
    /// `verified_senders`.
    allow_verified_skip_token: bool,
    /// Set of ML-DSA-65 verifying key bytes (1952 bytes each) that are
    /// allowed to skip the AFT token when `allow_verified_skip_token` is
    /// `true`. Kept in sync with the contract-side `verified_senders` set.
    verified_senders: std::collections::BTreeSet<Vec<u8>>,
    /// The owner's address in the mail delegate, which signs modifications
    /// to the inbox contract state (removals, settings updates) with the key
    /// whose verifying half is in `InboxParams`.
    addr: freenet_mail_protocol::Addr,
    /// Owner's ML-KEM-768 encapsulation key bytes (1184), as stored in
    /// `Inbox.owner_ek_bytes` on-chain. The owner-authored inbox
    /// signature binds these (#253), so `settings_modify_prepare` must
    /// sign over the SAME bytes the contract holds — otherwise
    /// `can_update_settings` (which rebuilds the payload from
    /// `inbox.owner_ek_bytes`) rejects the delta.
    owner_ek_bytes: Vec<u8>,
}

#[allow(dead_code)] // TODO: placeholder for decrypted settings persistence
#[derive(Debug, Serialize, Deserialize)]
struct StoredDecryptedSettings {}

#[allow(dead_code)] // TODO: emitted by summarize_state once contract sync lands
#[derive(Serialize, Deserialize)]
struct InboxSummary(HashSet<TokenAssignmentHash>);

impl InboxSummary {
    #[allow(dead_code)]
    pub fn new(messages: HashSet<TokenAssignmentHash>) -> Self {
        Self(messages)
    }
}

impl InternalSettings {
    fn from_stored(
        stored_settings: StoredSettings,
        addr: freenet_mail_protocol::Addr,
        owner_ek_bytes: Vec<u8>,
    ) -> Result<Self, DynError> {
        Ok(Self {
            addr,
            owner_ek_bytes,
            minimum_tier: stored_settings.minimum_tier,
            max_age_secs: stored_settings.max_age_secs,
            allow_verified_skip_token: stored_settings.allow_verified_skip_token,
            verified_senders: stored_settings.verified_senders,
        })
    }

    fn to_stored(&self) -> Result<StoredSettings, DynError> {
        Ok(StoredSettings {
            minimum_tier: self.minimum_tier,
            max_age_secs: self.max_age_secs,
            allow_verified_skip_token: self.allow_verified_skip_token,
            verified_senders: self.verified_senders.clone(),
            private: vec![],
        })
    }
}

/// Per-message signature-verification state (#51). Combines a pure
/// crypto check (sig validates against `sender_vk`) with an address-book
/// lookup (does the user trust this VK).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum VerificationState {
    /// Signature verified AND `sender_vk` matches a contact the user has
    /// flagged as verified.
    VerifiedKnown,
    /// Signature verified, but the sender VK is unknown to the address
    /// book (or known-unverified).
    VerifiedUnknown,
    /// Signature missing, malformed, or fails to verify.
    #[default]
    Unverified,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct MessageModel {
    pub id: u64,
    pub content: DecryptedMessage,
    pub token_assignment: TokenAssignment,
    /// Sender's ML-DSA-65 verifying key bytes. Empty for legacy messages.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sender_vk: Vec<u8>,
    /// Pure-crypto verification: sig validates against `sender_vk` over
    /// the ciphertext blob. Address-book trust is layered on top at
    /// render time. The address-book lookup is fast (HashMap) so we
    /// don't cache a `VerificationState` here — see `verification_state`
    /// in the UI render path.
    #[serde(default)]
    pub signature_valid: bool,
}

impl MessageModel {
    pub async fn finish_sending(
        client: &mut WebApiRequestClient,
        assignment: TokenAssignment,
        inbox_contract: InboxContract,
    ) -> Result<(), DynError> {
        let pending_update = PENDING_INBOXES_UPDATE.with(|map| {
            let map = &mut *map.borrow_mut();
            let update = map.get_mut(&inbox_contract).and_then(|messages| {
                if !messages.is_empty() {
                    Some(messages.remove(0))
                } else {
                    None
                }
            });
            if let Some(messages) = map.get(&inbox_contract)
                && messages.is_empty()
            {
                map.remove(&inbox_contract);
            }
            update
        });

        if let Some(update) = pending_update {
            let token_record = assignment.token_record;
            let stored = update.to_stored(assignment);
            let delta = UpdateInbox::AddMessages {
                messages: vec![stored],
            };
            let delta_bytes = serde_json::to_vec(&delta)?;
            // Bundle the sender's AFT record state inline as
            // `RelatedStateAndDelta`. The inbox contract's
            // `update_state` reads it from the bundle (see
            // contracts/inbox/src/lib.rs:738-774, the
            // `RelatedStateAndDelta` arm) instead of asking the runtime
            // to fetch it. This works around freenet-core#4077 where
            // `fetch_related_via_network` times out against AFT
            // contracts that are far from the receiver in keyspace,
            // and the receiver's inbox state stays pinned at the
            // initial empty value via `merge_rejected_valid_local`.
            //
            // Falls back to bare `UpdateData::Delta` if the local AFT
            // record isn't cached (shouldn't happen for the sender at
            // send time — `assign_token` already required RECORDS hit
            // — but the fallback keeps us correct against future
            // refactors of that ordering).
            let data = match crate::aft::AftRecords::record_state_for(&update.sender) {
                Some(state_bytes) => UpdateData::RelatedStateAndDelta {
                    related_to: token_record,
                    state: state_bytes.into(),
                    delta: delta_bytes.into(),
                },
                None => {
                    crate::log::error(
                        format!(
                            "finish_sending: no AFT record cached for sender `{alias}`; \
                             falling back to bare Delta — receiver may stall on freenet-core#4077",
                            alias = update.sender.alias()
                        ),
                        None,
                    );
                    UpdateData::Delta(delta_bytes.into())
                }
            };
            let request = ContractRequest::Update {
                key: inbox_contract,
                data,
            };
            client.send(request.into()).await?;
            // todo: event after sending, we may fail to update, must keep this in mind in case we receive no confirmation
            // meaning that we will need to retry, and likely need an other token for now at least, so restart from 0
        }
        Ok(())
    }
}

/// ML-KEM-768 encapsulation key encoded as a byte vector.
///
/// This is the public key that recipients publish as part of their identity
/// so that senders can encrypt messages to them.  It is stored in
/// `DecryptedMessage.to` and serialised with the message; the decapsulation
/// (private) key stays in the identity delegate.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub(crate) struct MlKemEncapsKey(pub Vec<u8>);

impl MlKemEncapsKey {
    pub fn from_key(ek: &EncapsulationKey<MlKem768>) -> Self {
        Self(ek.to_bytes().to_vec())
    }

    pub fn to_key(&self) -> Result<EncapsulationKey<MlKem768>, DynError> {
        use ml_kem::kem::Key;
        let bytes: &[u8] = &self.0;
        let arr: Key<EncapsulationKey<MlKem768>> =
            Key::<EncapsulationKey<MlKem768>>::try_from(bytes)
                .map_err(|_| "ML-KEM encapsulation key wrong length")?;
        EncapsulationKey::<MlKem768>::new(&arr).map_err(|e| format!("{e:?}").into())
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub(crate) struct DecryptedMessage {
    pub title: String,
    pub content: String,
    pub from: String,
    /// ML-KEM-768 encapsulation keys for each recipient (one per inbox).
    pub to: Vec<MlKemEncapsKey>,
    pub cc: Vec<String>,
    pub time: DateTime<Utc>,
    /// Stable conversation id (#270). Shared by every message in a thread.
    /// `None` for legacy messages sent before threading shipped — those
    /// fall back to the heuristic subject+participant grouping. Minted as a
    /// UUID v4 the first time a thread is started (see
    /// `crate::local_state::new_thread_id`).
    #[serde(default)]
    pub thread_id: Option<String>,
    /// Parent message id this is a reply to (#270). Drives the nested-view
    /// depth calculation. `None` for thread roots and forwards.
    #[serde(default)]
    pub in_reply_to: Option<String>,
    /// The specific parent line being replied to (#270), surfaced as a
    /// collapsible "in reply to" chip. Replaces the old "> "-prefixed
    /// quote-body hack. `None` for fresh sends / forwards.
    #[serde(default)]
    pub quoted_excerpt: Option<String>,
}

impl DecryptedMessage {
    #[allow(clippy::too_many_arguments)]
    pub async fn start_sending(
        self,
        client: &mut WebApiRequestClient,
        recipient_ek: EncapsulationKey<MlKem768>,
        recipient_ml_dsa_vk: MlDsaVerifyingKey<MlDsa65>,
        recipient_required_tier: freenet_mail_wire_v1::aft::Tier,
        recipient_max_age_secs: u64,
        recipient_inbox_wasm_hash: Option<&str>,
        from: &Identity,
    ) -> Result<(), DynError> {
        let sealed = self.seal(from).await?;
        let hash: [u8; 32] = *blake3::hash(&sealed.content).as_bytes();
        crate::log::info(format!(
            "send.start_sending: from=`{}` assignment_hash={} (release-visible diagnostic for #174)",
            from.alias(),
            bs58::encode(hash).into_string()
        ));
        let inbox_pub_key_bytes = inbox_params_pub_key_bytes(&recipient_ml_dsa_vk);
        // #251 improvement 4: address the recipient's inbox under the
        // recipient's advertised WASM hash when known. Falls back to
        // the sender's `INBOX_CODE_HASH` for own-identity sends and
        // for contacts imported before the field shipped.
        let code_hash = recipient_inbox_wasm_hash.unwrap_or(INBOX_CODE_HASH);
        let params: freenet_stdlib::prelude::Parameters = InboxParams {
            pub_key: inbox_pub_key_bytes.clone(),
        }
        .try_into()
        .map_err(|e| format!("{e}"))?;
        let inbox_key = ContractKey::from_params(code_hash, params).map_err(|e| format!("{e}"))?;

        // #273: verified-sender bypass. When the recipient has the bypass
        // enabled on-chain AND has whitelisted our ML-DSA VK in
        // `verified_senders`, we may deliver this message without minting
        // an AFT token. We only take this path when we have *observed* the
        // recipient's live `InboxSettings` (cache hit) — a miss falls
        // through to the normal token mint so a stale/absent observation
        // can never silently drop the message at the recipient's contract.
        let sender_vk = from.ml_dsa_vk_bytes();
        let cached_policy = crate::contact_tier_cache::lookup(&inbox_key);
        let can_skip_token = cached_policy
            .as_ref()
            .is_some_and(|p| p.allows_token_skip_for(&sender_vk));
        if can_skip_token {
            crate::log::info(format!(
                "send.start_sending: verified-sender bypass active, skipping AFT token \
                 from=`{}` inbox_key={inbox_key} (#273)",
                from.alias()
            ));
            return finish_sending_bypass(client, inbox_key, hash, sealed).await;
        }
        // #266: when bypass doesn't fire, surface WHICH gate failed so a
        // tester wondering "I turned the toggle on, why am I still seeing
        // pop-ups?" can diagnose without source-diving. Three possible
        // gates: (a) cache miss (sender's `contact_tier_cache` never
        // observed the recipient's live `InboxSettings`), (b) recipient's
        // `allow_verified_skip_token` is false on-chain, (c) recipient
        // has not whitelisted the sender's ML-DSA VK in
        // `verified_senders`. Logged at info() so it shows up in release
        // builds.
        match cached_policy.as_ref() {
            None => crate::log::info(format!(
                "send.start_sending: AFT bypass NOT applied for inbox_key={inbox_key} — \
                 contact_tier_cache miss (recipient inbox settings never observed; \
                 sender's client has not done a Get on the recipient inbox yet). (#266)"
            )),
            Some(p) if !p.allow_verified_skip_token => crate::log::info(format!(
                "send.start_sending: AFT bypass NOT applied for inbox_key={inbox_key} — \
                 recipient's `allow_verified_skip_token` is OFF on-chain. The recipient \
                 must enable “Accept verified senders without tokens” in their Settings → \
                 Anti-Flood (AFT). (#266)"
            )),
            Some(p) if !p.verified_senders.contains(&sender_vk) => crate::log::info(format!(
                "send.start_sending: AFT bypass NOT applied for inbox_key={inbox_key} — \
                 sender's ML-DSA VK (len={}) is not in recipient's `verified_senders` set \
                 (size={}). The recipient must mark this sender's contact as verified, \
                 which republishes the set. (#266)",
                sender_vk.len(),
                p.verified_senders.len(),
            )),
            Some(_) => {}
        }

        let delegate_key = AftRecords::assign_token(
            client,
            inbox_pub_key_bytes,
            recipient_required_tier,
            recipient_max_age_secs,
            recipient_inbox_wasm_hash,
            from,
            hash,
        )
        .await?;
        crate::log::info(format!(
            "send.start_sending: token requested, awaiting AFT delegate response from=`{}` inbox_key={inbox_key} (release-visible diagnostic for #174)",
            from.alias()
        ));
        AftRecords::pending_assignment(delegate_key, inbox_key);

        PENDING_INBOXES_UPDATE.with(|map| {
            let map = &mut *map.borrow_mut();
            map.entry(inbox_key)
                .or_insert_with(Vec::new)
                .push(PendingOutgoing {
                    sealed,
                    sender: from.clone(),
                });
        });
        let _ = recipient_ek; // ek is used inside to_stored via pending queue
        Ok(())
    }

    /// Encrypt this message to its recipient and sign the ciphertext, in the
    /// mail delegate (the page holds no keys). Done once per send: the
    /// assignment hash is taken from this one ciphertext, which is also the
    /// one stored.
    async fn seal(&self, from: &Identity) -> Result<crate::mail_delegate::ops::SealedV1, DynError> {
        let plaintext = serde_json::to_vec(self)?;
        let recipient_ek = self.to.first().ok_or("receiver key not found")?;
        crate::mail_delegate::ops::seal_v1(from.addr, recipient_ek.0.clone(), plaintext)
            .await
            .map_err(|e| format!("could not seal the message: {e}").into())
    }

    /// Parse a decrypted plaintext. Returns `None` when it doesn't
    /// deserialise (a malformed or foreign entry in shared inbox state): such
    /// a message is skipped, never fatal (#267).
    pub(crate) fn from_plaintext(plaintext: &[u8]) -> Option<DecryptedMessage> {
        match serde_json::from_slice(plaintext) {
            Ok(msg) => Some(msg),
            Err(e) => {
                crate::log::debug!("skip inbox message with bad plaintext: {e}");
                None
            }
        }
    }

    /// Decrypt with a local key: tests only (the page holds no keys).
    #[cfg(test)]
    fn from_stored(
        dk: &DecapsulationKey<MlKem768>,
        msg_content: Vec<u8>,
    ) -> Option<DecryptedMessage> {
        Self::from_plaintext(&ml_kem_decrypt(dk, msg_content).ok()?)
    }
}

/// #273 verified-sender bypass send path. Used when `start_sending`
/// determined (from the recipient's observed `InboxSettings`) that
/// this sender may deliver without an AFT token. Builds a placeholder
/// `TokenAssignment` — the recipient's inbox contract skips all
/// token-assignment validation for verified senders
/// (`add_message`/`verify_token_policy` short-circuit on the
/// `verified_senders` allow-list, see `contracts/inbox/src/lib.rs`),
/// so only the `assignment_hash` is load-bearing: it must equal the
/// real message hash because the inbox keys + dedupes messages by it.
///
/// The delta is sent as a bare `UpdateData::Delta` — there is no AFT
/// allocation record to bundle as `RelatedStateAndDelta`, and the
/// contract never fetches one for a bypassed message.
async fn finish_sending_bypass(
    client: &mut WebApiRequestClient,
    inbox_key: ContractKey,
    hash: TokenAssignmentHash,
    sealed: crate::mail_delegate::ops::SealedV1,
) -> Result<(), DynError> {
    let placeholder = TokenAssignment {
        tier: Tier::Min1,
        time_slot: Utc::now(),
        generator: Vec::new(),
        signature: Vec::new(),
        assignment_hash: hash,
        token_record: *inbox_key.id(),
    };
    let stored = StoredMessage {
        content: sealed.content,
        token_assignment: placeholder,
        sender_vk: sealed.sender_vk,
        signature: sealed.signature,
    };
    let delta = UpdateInbox::AddMessages {
        messages: vec![stored],
    };
    let delta_bytes = serde_json::to_vec(&delta)?;
    let request = ContractRequest::Update {
        key: inbox_key,
        data: UpdateData::Delta(delta_bytes.into()),
    };
    client.send(request.into()).await?;
    Ok(())
}

/// Have the mail delegate sign a v1 inbox authority payload for `addr` with
/// a fresh `last_update`, returned with the signature. The timestamp is
/// truncated to the microseconds the payload carries.
pub(crate) async fn sign_authority(
    addr: freenet_mail_protocol::Addr,
    settings: &StoredSettings,
) -> Result<(DateTime<Utc>, Box<[u8]>), DynError> {
    let micros = Utc::now().timestamp_micros();
    let last_update = DateTime::from_timestamp_micros(micros).ok_or("clock out of range")?;
    let signature =
        crate::mail_delegate::ops::sign_v1_authority(addr, serde_json::to_vec(settings)?, micros)
            .await
            .map_err(|e| format!("could not sign the inbox settings: {e}"))?;
    Ok((last_update, signature.into_boxed_slice()))
}

/// Derive a 32-byte XChaCha20-Poly1305 key from an ML-KEM shared secret using HKDF-SHA256.
///
/// The context label `b"freenet-email-v1 message-key"` domain-separates this
/// key from any other use of the same shared secret (NIST SP 800-56C recommendation).
#[cfg(test)]
fn hkdf_derive_key(shared_secret: &[u8]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(b"freenet-email-v1 message-key", &mut okm)
        .expect("HKDF expand: output length is valid");
    okm
}

/// Encrypt `plaintext` to `ek` using ML-KEM-768 + XChaCha20-Poly1305.
///
/// Wire format: `[ 24-byte nonce | 1088-byte ML-KEM ciphertext | variable XChaCha20-Poly1305 ciphertext ]`
///
/// The symmetric key is HKDF-SHA256(ML-KEM shared secret, info="freenet-email-v1 message-key").
#[cfg(test)]
pub(crate) fn ml_kem_encrypt(
    ek: &EncapsulationKey<MlKem768>,
    plaintext: &[u8],
) -> Result<Vec<u8>, DynError> {
    use chacha20poly1305::{KeyInit, XNonce};

    let (ct, shared_secret) = ek.encapsulate_with_rng(&mut crate::rng::crypto_rng());
    let ct_bytes: &[u8] = ct.as_ref();

    let key_bytes = hkdf_derive_key(shared_secret.as_slice());

    let nonce_bytes: [u8; 24] = crate::rng::random_bytes();
    let chacha_nonce = XNonce::from(nonce_bytes);
    let cipher = XChaCha20Poly1305::new(&key_bytes.into());
    let encrypted_data = cipher
        .encrypt(&chacha_nonce, plaintext)
        .map_err(|e| format!("XChaCha20 encrypt failed: {e}"))?;

    let mut content = Vec::with_capacity(nonce_bytes.len() + ct_bytes.len() + encrypted_data.len());
    content.extend_from_slice(&nonce_bytes);
    content.extend_from_slice(ct_bytes);
    content.extend_from_slice(&encrypted_data);
    Ok(content)
}

/// Decrypt a message previously encrypted with [`ml_kem_encrypt`].
#[cfg(test)]
pub(crate) fn ml_kem_decrypt(
    dk: &DecapsulationKey<MlKem768>,
    msg_content: Vec<u8>,
) -> Result<Vec<u8>, DynError> {
    use chacha20poly1305::{KeyInit, XNonce};

    // ML-KEM-768 ciphertext is 1088 bytes.
    const KEM_CT_LEN: usize = 1088;
    const NONCE_LEN: usize = 24;

    if msg_content.len() < NONCE_LEN + KEM_CT_LEN {
        return Err("message content too short".into());
    }

    let mut cursor = Cursor::new(msg_content);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    cursor.read_exact(&mut nonce_bytes)?;
    let mut kem_ct_bytes = vec![0u8; KEM_CT_LEN];
    cursor.read_exact(&mut kem_ct_bytes)?;
    let mut encrypted_data = vec![];
    cursor.read_to_end(&mut encrypted_data)?;

    // `decapsulate_slice` accepts &[u8] and validates the length.
    let shared_secret = dk
        .decapsulate_slice(&kem_ct_bytes)
        .map_err(|_| "ML-KEM ciphertext wrong length")?;

    let key_bytes = hkdf_derive_key(shared_secret.as_slice());
    let cipher = XChaCha20Poly1305::new(&key_bytes.into());
    cipher
        .decrypt(&XNonce::from(nonce_bytes), encrypted_data.as_ref())
        .map_err(|e| format!("XChaCha20 decrypt failed: {e}").into())
}

/// Inbox state
#[derive(Debug, Clone)]
pub(crate) struct InboxModel {
    pub messages: Vec<MessageModel>,
    settings: InternalSettings,
    pub key: InboxContract,
    /// Assignment hashes removed from this inbox, so a decryption still in
    /// flight when the removal lands does not bring the message back.
    removed: HashSet<TokenAssignmentHash>,
    /// Assignment hashes the latest state holds (a whole state replaces
    /// them; deltas add and remove). A decryption started from an older
    /// state is dropped for any message no longer in it.
    known: HashSet<TokenAssignmentHash>,
    /// Messages handed to the delegate and not answered yet, so a repeated
    /// state does not decrypt them twice. Released on failure.
    in_flight: HashSet<TokenAssignmentHash>,
    /// Messages this identity can never read (not for it, corrupt, or too
    /// large to return); not asked for again.
    unreadable: HashSet<TokenAssignmentHash>,
}

/// Messages of an inbox that the mail delegate still has to decrypt. The
/// node loop must not wait for the delegate (it delivers the delegate's
/// answers), so it hands these to [`decrypt_pending`] in a spawned task and
/// adds the results with [`InboxModel::add_decrypted`].
#[derive(Debug, Default)]
pub(crate) struct PendingDecrypt {
    pub addr: Option<freenet_mail_protocol::Addr>,
    pub messages: Vec<StoredMessage>,
}

impl PendingDecrypt {
    pub(crate) fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// The assignment hashes of the messages to decrypt.
    pub(crate) fn hashes(&self) -> Vec<TokenAssignmentHash> {
        self.messages
            .iter()
            .map(|m| m.token_assignment.assignment_hash)
            .collect()
    }
}

/// What the delegate made of a [`PendingDecrypt`]: the messages to show,
/// and the hashes of those this identity can never read.
#[derive(Debug, Default)]
pub(crate) struct Decrypted {
    pub messages: Vec<(StoredMessage, DecryptedMessage)>,
    pub unreadable: Vec<TokenAssignmentHash>,
}

/// Decrypt `pending` in the mail delegate. Messages this identity cannot
/// decrypt (foreign or malformed entries in shared inbox state) are skipped,
/// never fatal (#267).
///
/// A call that fails as a whole (no answer, a busy or failing delegate) is
/// an error, and its messages are asked for again with the next state; a
/// message the delegate answers it cannot decrypt is reported unreadable.
pub(crate) async fn decrypt_pending(pending: PendingDecrypt) -> Result<Decrypted, DynError> {
    let Some(addr) = pending.addr else {
        return Ok(Decrypted::default());
    };
    let ciphertexts = pending.messages.iter().map(|m| m.content.clone()).collect();
    let plaintexts = crate::mail_delegate::ops::decrypt_v1(addr, ciphertexts)
        .await
        .map_err(|e| format!("could not decrypt inbox messages: {e}"))?;
    let mut out = Decrypted::default();
    for (stored, plaintext) in pending.messages.into_iter().zip(plaintexts) {
        match plaintext
            .ok()
            .and_then(|p| DecryptedMessage::from_plaintext(&p))
        {
            Some(content) => out.messages.push((stored, content)),
            None => out.unreadable.push(stored.token_assignment.assignment_hash),
        }
    }
    Ok(out)
}

impl InboxModel {
    pub async fn load_all(client: &mut WebApiRequestClient, contracts: &[Identity]) {
        // Register the inbox → identity routing entry. The actual network
        // subscription happens via the GET-with-subscribe in `load`
        // (`get_state`); a standalone `Subscribe` here is rejected when the
        // node doesn't already hold the contract (issue #288), so we only
        // populate the routing map synchronously and let the GET bootstrap
        // both the local copy and the subscription.
        fn register_routing(contract_key: &ContractKey, identity: &Identity) {
            let alias = identity.alias();
            INBOX_TO_ID.with(|map| {
                map.borrow_mut().insert(*contract_key, identity.clone());
            });
            crate::log::debug!(
                "registering inbox routing for `{contract_key}`, belonging to alias `{alias}`"
            );
        }

        fn get_key(identity: &Identity) -> Result<ContractKey, DynError> {
            let vk = identity.ml_dsa_vk();
            let pub_key = inbox_params_pub_key_bytes(&vk);
            let params = freenet_mail_wire_v1::inbox::InboxParams { pub_key }
                .try_into()
                .map_err(|e| format!("{e}"))?;
            ContractKey::from_params(crate::inbox::INBOX_CODE_HASH, params)
                .map_err(|e| format!("{e}").into())
        }

        for identity in contracts {
            let mut client = client.clone();
            let contract_key = match get_key(identity) {
                Ok(v) => v,
                Err(e) => {
                    node_response_error_handling(
                        client.clone().into(),
                        Err(e),
                        TryNodeAction::LoadInbox,
                    )
                    .await;
                    return;
                }
            };
            // INBOX_TO_ID is the single source of truth for routing
            // inbox UpdateNotifications back to an Identity. Populate it
            // synchronously before the network round trip so peer-side
            // state pushes that race the GetResponse can still find their
            // owner. The network subscription is established by the
            // GET-with-subscribe inside `load` below (issue #288).
            let already = INBOX_TO_ID.with(|map| map.borrow().contains_key(&contract_key));
            if !already {
                register_routing(&contract_key, identity);
            }
            let res = InboxModel::load(&mut client, identity).await;
            node_response_error_handling(client.into(), res.map(|_| ()), TryNodeAction::LoadInbox)
                .await;
        }
    }

    pub async fn load(
        client: &mut WebApiRequestClient,
        id: &Identity,
    ) -> Result<ContractKey, DynError> {
        let vk = id.ml_dsa_vk();
        let params = InboxParams {
            pub_key: inbox_params_pub_key_bytes(&vk),
        }
        .try_into()
        .map_err(|e| format!("{e}"))?;
        let contract_key =
            ContractKey::from_params(INBOX_CODE_HASH, params).map_err(|e| format!("{e}"))?;
        InboxModel::get_state(client, contract_key).await?;
        Ok(contract_key)
    }

    /// The routed identity named `alias`. Only a fallback for finding an
    /// identity's state key; sending resolves by address
    /// ([`Self::sender_identity`]). A deleted identity is not routed any more
    /// ([`Self::forget_identity`]), so its alias cannot shadow a new one's.
    pub fn id_for_alias(alias: &str) -> Option<Identity> {
        INBOX_TO_ID.with(|map| {
            map.borrow()
                .values()
                .find_map(|id| (id.alias() == alias).then(|| id.clone()))
        })
    }

    /// The routed identity at `addr`. By address, never by alias: a
    /// deleted identity's alias can be taken by a new one, and an alias
    /// scan of the routing map could pick either.
    pub fn id_for_addr(addr: &freenet_mail_protocol::Addr) -> Option<Identity> {
        INBOX_TO_ID.with(|map| map.borrow().values().find(|id| id.addr == *addr).cloned())
    }

    /// The identity to send as, or why there is none. A missing sender is
    /// an error the user sees (the draft stays), never a silent no-op that
    /// reads as a successful send.
    pub fn sender_identity(
        addr: &freenet_mail_protocol::Addr,
        alias: &str,
    ) -> Result<Identity, String> {
        Self::id_for_addr(addr).ok_or_else(|| {
            format!("your identity `{alias}` is not ready on this page; reload and try again")
        })
    }

    /// Stop routing a deleted identity's inbox: a state that still arrives
    /// for it (the node keeps the subscription) is then ignored, rather than
    /// decrypted with keys that no longer exist.
    pub fn forget_identity(addr: &freenet_mail_protocol::Addr) {
        INBOX_TO_ID.with(|map| map.borrow_mut().retain(|_, id| id.addr != *addr));
    }

    /// Relabel the identity at `addr` in the routing map after a rename.
    /// Routing is by inbox contract, which a rename does not change; this
    /// only keeps the alias shown for routed messages current.
    pub fn rename_identity(addr: &freenet_mail_protocol::Addr, new_alias: &str) {
        INBOX_TO_ID.with(|map| {
            for identity in map.borrow_mut().values_mut() {
                if identity.addr == *addr {
                    identity.alias = new_alias.into();
                }
            }
        });
    }

    pub fn contract_identity(key: &InboxContract) -> Option<Identity> {
        INBOX_TO_ID.with(|map| map.borrow().get(key).cloned())
    }

    pub fn set_contract_identity(key: InboxContract, identity: Identity) {
        crate::log::debug!(
            "adding inbox contract for `{alias}` ({key})",
            alias = identity.alias
        );
        INBOX_TO_ID.with(|map| map.borrow_mut().insert(key, identity));
    }

    pub fn remove_messages(
        &mut self,
        mut client: WebApiRequestClient,
        ids: &[u64],
    ) -> Result<LocalBoxFuture<'static, ()>, DynError> {
        let hashes: Vec<TokenAssignmentHash> = self
            .messages
            .iter()
            .filter(|m| ids.contains(&m.id))
            .map(|m| m.token_assignment.assignment_hash)
            .collect();
        self.removed.extend(hashes.iter().copied());
        self.remove_received_message(ids);
        #[cfg(feature = "use-node")]
        {
            let addr = self.settings.addr;
            let key = self.key;
            let f = async move {
                let r: Result<(), DynError> = async {
                    // The delegate signs only strictly ascending hashes, at
                    // most MAX_REMOVAL_BATCH at a time: a larger removal
                    // goes out as several, each signed on its own.
                    for ids in removal_batches(hashes) {
                        let signature =
                            crate::mail_delegate::ops::sign_v1_removal(addr, ids.clone())
                                .await
                                .map_err(|e| format!("could not sign the removal: {e}"))?;
                        let delta = UpdateInbox::RemoveMessages {
                            signature: signature.into_boxed_slice(),
                            ids,
                        };
                        let request = ContractRequest::Update {
                            key,
                            data: UpdateData::Delta(serde_json::to_vec(&delta)?.into()),
                        };
                        client.send(request.into()).await?;
                    }
                    Ok(())
                }
                .await;
                node_response_error_handling(client.into(), r, TryNodeAction::RemoveMessages).await;
            };
            Ok(f.boxed_local())
        }
        #[cfg(not(feature = "use-node"))]
        {
            let _ = (&mut client, hashes);
            Ok(async {}.boxed_local())
        }
    }
}

/// What the user sees when decrypting `count` messages kept failing: they
/// are not lost, and say how to get them back now.
pub(crate) fn decrypt_gave_up_text(count: usize) -> String {
    let what = if count == 1 {
        "1 message".to_string()
    } else {
        format!("{count} messages")
    };
    format!(
        "{what} couldn't be opened right now. Mail will try again when the inbox next \
         updates; reload the page to try again now."
    )
}

/// A removal as the delegate will sign it: strictly ascending hashes, in
/// batches of at most [`freenet_mail_protocol::MAX_REMOVAL_BATCH`]. A larger
/// single batch is refused as bad input after the page has already hidden
/// the messages, so they would come back on the next state.
pub(crate) fn removal_batches(hashes: Vec<TokenAssignmentHash>) -> Vec<Vec<TokenAssignmentHash>> {
    crate::mail_delegate::ops::removal_order(hashes)
        .chunks(freenet_mail_protocol::MAX_REMOVAL_BATCH)
        .map(<[TokenAssignmentHash]>::to_vec)
        .collect()
}

impl InboxModel {
    /// The model for an inbox state. Its messages are returned for the
    /// delegate to decrypt ([`decrypt_pending`]); the model starts without
    /// them.
    pub fn from_state(
        addr: freenet_mail_protocol::Addr,
        owner_ek_bytes: Vec<u8>,
        state: StoredInbox,
        key: ContractKey,
    ) -> Result<(Self, PendingDecrypt), DynError> {
        let model = Self {
            settings: InternalSettings::from_stored(state.settings, addr, owner_ek_bytes)?,
            key,
            messages: Vec::new(),
            removed: HashSet::new(),
            known: HashSet::new(),
            in_flight: HashSet::new(),
            unreadable: HashSet::new(),
        };
        let mut model = model;
        let pending = model.take_new(state.messages, true);
        Ok((model, pending))
    }

    /// The messages of a state (`whole`) or delta that still need
    /// decrypting, marked in flight; records which messages the inbox now
    /// holds.
    fn take_new(&mut self, messages: Vec<StoredMessage>, whole: bool) -> PendingDecrypt {
        if whole {
            self.known = messages
                .iter()
                .map(|m| m.token_assignment.assignment_hash)
                .collect();
        } else {
            self.known
                .extend(messages.iter().map(|m| m.token_assignment.assignment_hash));
        }
        let mut pending = PendingDecrypt {
            addr: Some(self.settings.addr),
            messages: Vec::new(),
        };
        for m in messages {
            let hash = m.token_assignment.assignment_hash;
            if self.has_message(&hash)
                || self.in_flight.contains(&hash)
                || self.unreadable.contains(&hash)
            {
                continue;
            }
            self.in_flight.insert(hash);
            pending.messages.push(m);
        }
        pending
    }

    /// A decryption that failed as a whole: its messages may be asked for
    /// again.
    pub fn release(&mut self, hashes: &[TokenAssignmentHash]) {
        for hash in hashes {
            self.in_flight.remove(hash);
        }
    }

    /// Of `messages` (from a decryption that failed and was released), the
    /// ones still worth retrying: still in the latest state, not decrypted
    /// or being decrypted since, and not unreadable. Marked in flight.
    pub fn retake(&mut self, messages: Vec<StoredMessage>) -> PendingDecrypt {
        let messages = messages
            .into_iter()
            .filter(|m| self.known.contains(&m.token_assignment.assignment_hash))
            .collect();
        let known = std::mem::take(&mut self.known);
        let pending = self.take_new(messages, false);
        self.known = known;
        pending
    }

    /// Replace this inbox with a whole new state: keeps the messages already
    /// decrypted that the state still holds, drops the rest, and returns the
    /// new ones to decrypt.
    pub fn replace_state(&mut self, state: StoredInbox) -> Result<PendingDecrypt, DynError> {
        self.settings = InternalSettings::from_stored(
            state.settings,
            self.settings.addr,
            self.settings.owner_ek_bytes.clone(),
        )?;
        let present: HashSet<TokenAssignmentHash> = state
            .messages
            .iter()
            .map(|m| m.token_assignment.assignment_hash)
            .collect();
        self.messages
            .retain(|m| present.contains(&m.token_assignment.assignment_hash));
        Ok(self.take_new(state.messages, true))
    }

    fn has_message(&self, hash: &TokenAssignmentHash) -> bool {
        self.messages
            .iter()
            .any(|c| &c.token_assignment.assignment_hash == hash)
    }

    /// Apply an `UpdateInbox` delta received via UpdateNotification (or
    /// the cross-node UPDATE_PROPAGATION path) to this in-memory model.
    /// Returns AddMessages entries not already present, for the delegate to
    /// decrypt; drops RemoveMessages by hash; ignores ModifySettings
    /// (sender-only).
    pub fn apply_delta(&mut self, delta: UpdateInbox) -> PendingDecrypt {
        let mut pending = PendingDecrypt {
            addr: Some(self.settings.addr),
            messages: Vec::new(),
        };
        match delta {
            UpdateInbox::AddMessages { messages } => {
                pending = self.take_new(messages, false);
            }
            UpdateInbox::RemoveMessages { ids, .. } => {
                for id in &ids {
                    self.known.remove(id);
                }
                self.removed.extend(ids.iter().copied());
                let drop: HashSet<TokenAssignmentHash> = HashSet::from_iter(ids);
                self.messages
                    .retain(|m| !drop.contains(&m.token_assignment.assignment_hash));
            }
            UpdateInbox::ModifySettings { .. } => {
                // Settings deltas come from this identity only; ignore on
                // the receive path.
            }
        }
        pending
    }

    /// Add messages the delegate decrypted, skipping any already present,
    /// removed while the decryption was in flight, or no longer in the
    /// latest state (a newer state superseded the one they came from).
    pub fn add_decrypted(&mut self, decrypted: Decrypted) {
        for hash in decrypted.unreadable {
            self.in_flight.remove(&hash);
            self.unreadable.insert(hash);
        }
        for (m, content) in decrypted.messages {
            let hash = m.token_assignment.assignment_hash;
            self.in_flight.remove(&hash);
            if self.has_message(&hash)
                || self.removed.contains(&hash)
                || !self.known.contains(&hash)
            {
                continue;
            }
            let signature_valid = verify_message_signature(&m.content, &m.sender_vk, &m.signature);
            // The id is the ciphertext's hash, not the message's position:
            // read, kept, archived and deleted marks stay attached to the
            // right message across reloads and however the inbox reorders.
            let id = crate::local_state::message_id_for(&m.content);
            self.add_received_message(
                id,
                content,
                m.token_assignment,
                m.sender_vk,
                signature_valid,
            );
        }
    }

    /// This only affects in-memory messages, changes are not persisted.
    fn add_received_message(
        &mut self,
        id: u64,
        content: DecryptedMessage,
        token_assignment: TokenAssignment,
        sender_vk: Vec<u8>,
        signature_valid: bool,
    ) {
        self.messages.push(MessageModel {
            id,
            content,
            token_assignment,
            sender_vk,
            signature_valid,
        });
    }

    /// This only affects in-memory messages, changes are not persisted.
    /// Messages are kept in arrival order and their ids are content hashes,
    /// so nothing here may assume they are sorted by id.
    fn remove_received_message(&mut self, ids: &[u64]) {
        let drop: HashSet<u64> = HashSet::from_iter(ids.iter().copied());
        self.messages.retain(|a| !drop.contains(&a.id));
    }

    /// Apply a new anti-flood policy locally and return a future yielding
    /// the signed `ModifySettings` request the caller must push to the inbox
    /// contract via `client.send`, outside any RefCell borrow (#85). Only the
    /// inbox owner can mutate policy — `can_update_settings` on the contract
    /// verifies the signature against `params.pub_key`.
    pub fn update_policy_prepare(
        &mut self,
        minimum_tier: Tier,
        max_age_secs: u64,
    ) -> LocalBoxFuture<'static, Result<ContractRequest<'static>, DynError>> {
        self.settings.minimum_tier = minimum_tier;
        self.settings.max_age_secs = max_age_secs;
        self.settings_modify_prepare()
    }

    /// Apply the verified-sender bypass flag and (optionally) mutate the
    /// `verified_senders` set, then return a future yielding the signed
    /// `ModifySettings` request for the inbox contract (#150).
    pub fn update_verified_bypass_prepare(
        &mut self,
        allow_verified_skip_token: bool,
        verified_senders: std::collections::BTreeSet<Vec<u8>>,
    ) -> LocalBoxFuture<'static, Result<ContractRequest<'static>, DynError>> {
        self.settings.allow_verified_skip_token = allow_verified_skip_token;
        self.settings.verified_senders = verified_senders;
        self.settings_modify_prepare()
    }

    /// Shared implementation: stamp a fresh owner-supplied `last_update`,
    /// have the delegate sign the FULL authority payload
    /// (`sign_payload(owner_ek_bytes, settings, last_update)`, with its own
    /// encapsulation key), wrap it in a `ModifySettings` delta, and return
    /// the `ContractRequest::Update`. The widened signature (#253) binds
    /// settings + last_update so a peer cannot rebroadcast a tampered State;
    /// the host pins `last_update` and stores this signature so the
    /// resulting state re-verifies.
    fn settings_modify_prepare(
        &self,
    ) -> LocalBoxFuture<'static, Result<ContractRequest<'static>, DynError>> {
        let settings = self.settings.to_stored();
        let addr = self.settings.addr;
        let key = self.key;
        async move {
            let settings = settings?;
            let (last_update, inbox_signature) = sign_authority(addr, &settings).await?;
            let delta = UpdateInbox::ModifySettings {
                inbox_signature,
                settings,
                last_update,
            };
            Ok(ContractRequest::Update {
                key,
                data: UpdateData::Delta(serde_json::to_vec(&delta)?.into()),
            })
        }
        .boxed_local()
    }

    pub async fn get_state(
        client: &mut WebApiRequestClient,
        key: ContractKey,
    ) -> Result<(), DynError> {
        // `subscribe: true` fetches current state AND registers this node as
        // a subscriber/holder in a single op. A standalone `Subscribe` is
        // rejected by the node when the contract isn't already cached locally
        // ("contract WASM not cached locally") — it never fetch-on-subscribes.
        // GET-with-subscribe bootstraps the local copy regardless, so the
        // inbox loads and the owner durably holds it (issue #288).
        let request = ContractRequest::Get {
            key: key.into(),
            return_contract_code: false,
            subscribe: true,
            blocking_subscribe: false,
        };
        client.send(request.into()).await?;
        Ok(())
    }
}

#[cfg(test)]
mod migration_logic_tests {
    use super::*;

    #[test]
    fn candidates_single_when_legacy_empty() {
        let out = build_migration_candidates("h0", &[]);
        assert_eq!(out, vec!["h0"]);
    }

    #[test]
    fn candidates_skip_entries_at_or_before_prior() {
        let legacy = ["h0", "h1", "h2"];
        let out = build_migration_candidates("h1", &legacy);
        assert_eq!(out, vec!["h1", "h2"]);
    }

    #[test]
    fn candidates_walk_all_when_prior_absent() {
        let legacy = ["h0", "h1"];
        let out = build_migration_candidates("unknown", &legacy);
        assert_eq!(out, vec!["unknown", "h0", "h1"]);
    }

    #[test]
    fn candidates_no_duplicate_when_prior_at_end() {
        let legacy = ["h0", "h1"];
        let out = build_migration_candidates("h1", &legacy);
        assert_eq!(out, vec!["h1"]);
    }

    #[test]
    fn select_no_drift_when_prior_matches_current() {
        assert_eq!(select_migrate_from(Some("cur"), None, "cur"), None);
    }

    #[test]
    fn select_ignores_pending_when_prior_matches_current() {
        // Stale marker case — drift logic returns None, caller clears
        // the marker separately.
        assert_eq!(select_migrate_from(Some("cur"), Some("stale"), "cur"), None);
    }

    #[test]
    fn select_prefers_pending_over_prior() {
        assert_eq!(
            select_migrate_from(Some("old"), Some("older"), "cur"),
            Some("older".to_string())
        );
    }

    #[test]
    fn select_falls_back_to_prior_when_no_pending() {
        assert_eq!(
            select_migrate_from(Some("old"), None, "cur"),
            Some("old".to_string())
        );
    }

    #[test]
    fn select_uses_pending_when_prior_absent() {
        // Indicates state corruption — prior was never stamped but a
        // marker exists. Conservative behavior: retry the migration.
        assert_eq!(
            select_migrate_from(None, Some("older"), "cur"),
            Some("older".to_string())
        );
    }

    #[test]
    fn select_none_on_first_observation() {
        assert_eq!(select_migrate_from(None, None, "cur"), None);
    }

    /// The current `INBOX_CODE_HASH` must NOT appear in
    /// `LEGACY_INBOX_CODE_HASHES`. Violating this invariant would make
    /// `migrate_inbox` GET the current key as an "old" candidate and
    /// re-PUT identical state. Only checked under `use-node` because
    /// the constant is otherwise empty.
    #[cfg(feature = "use-node")]
    #[test]
    fn current_hash_not_in_legacy() {
        let current = INBOX_CODE_HASH;
        assert!(
            !LEGACY_INBOX_CODE_HASHES.contains(&current),
            "INBOX_CODE_HASH ({current}) must not appear in LEGACY_INBOX_CODE_HASHES — \
             append it only AFTER bumping to a new hash",
        );
    }

    /// #270: a `DecryptedMessage` serialized before the threading fields
    /// (`thread_id`, `in_reply_to`, `quoted_excerpt`) existed must still
    /// deserialize, with all three defaulting to `None`. This is what
    /// `#[serde(default)]` guarantees and is the load-bearing
    /// backwards-compat claim — old inbox messages can't be lost or
    /// fail to render after the threading bump.
    #[test]
    fn decrypted_message_missing_thread_fields_defaults_none() {
        // Legacy plaintext: no thread_id / in_reply_to / quoted_excerpt.
        let json = br#"{"title":"hi","content":"yo","from":"alice","to":[],"cc":[],"time":"2024-01-01T00:00:00Z"}"#;
        let msg: DecryptedMessage =
            serde_json::from_slice(json).expect("legacy DecryptedMessage should deserialise");
        assert_eq!(msg.thread_id, None);
        assert_eq!(msg.in_reply_to, None);
        assert_eq!(msg.quoted_excerpt, None);
        assert_eq!(msg.title, "hi");
    }

    /// #270: new threading fields round-trip through serde so a reply's
    /// thread linkage survives the encrypt → store → decrypt path.
    #[test]
    fn decrypted_message_thread_fields_round_trip() {
        let msg = DecryptedMessage {
            title: "Re: hi".into(),
            content: "reply body".into(),
            from: "bob".into(),
            to: vec![],
            cc: vec![],
            time: Utc::now(),
            thread_id: Some("thread-xyz".into()),
            in_reply_to: Some("42".into()),
            quoted_excerpt: Some("the line being replied to".into()),
        };
        let bytes = serde_json::to_vec(&msg).unwrap();
        let back: DecryptedMessage = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.thread_id.as_deref(), Some("thread-xyz"));
        assert_eq!(back.in_reply_to.as_deref(), Some("42"));
        assert_eq!(
            back.quoted_excerpt.as_deref(),
            Some("the line being replied to")
        );
    }
}

#[cfg(test)]
mod tests {

    use freenet_stdlib::prelude::ContractCode;

    use super::*;

    impl InboxModel {
        fn new(
            addr: freenet_mail_protocol::Addr,
            vk_bytes: &[u8],
            owner_ek_bytes: Vec<u8>,
        ) -> Self {
            let params = InboxParams {
                pub_key: vk_bytes.to_vec(),
            };
            Self {
                messages: vec![],
                settings: InternalSettings {
                    minimum_tier: Tier::Hour1,
                    max_age_secs: freenet_mail_wire_v1::inbox::DEFAULT_MAX_AGE_SECS,
                    allow_verified_skip_token: false,
                    verified_senders: std::collections::BTreeSet::new(),
                    addr,
                    owner_ek_bytes,
                },
                key: ContractKey::from_params_and_code(
                    freenet_stdlib::prelude::Parameters::try_from(params).unwrap(),
                    ContractCode::from([].as_slice()),
                ),
                removed: HashSet::new(),
                known: HashSet::new(),
                in_flight: HashSet::new(),
                unreadable: HashSet::new(),
            }
        }
    }

    /// An identity in the in-page delegate (offline builds), so signing and
    /// decryption run through the real delegate code.
    #[cfg(feature = "local-delegate")]
    fn delegate_identity() -> freenet_mail_protocol::IdentityInfo {
        let alias = format!("t{}", u32::from_le_bytes(crate::rng::random_bytes()));
        futures::executor::block_on(crate::mail_delegate::ops::create_identity(
            alias,
            String::new(),
        ))
        .unwrap()
        .0
    }

    #[test]
    fn remove_msg() {
        let mut inbox = InboxModel::new(
            freenet_mail_protocol::Addr([1; 24]),
            &[2; 1952],
            vec![3; 1184],
        );
        for id in 0..10000 {
            inbox.messages.push(MessageModel {
                id,
                content: DecryptedMessage::default(),
                token_assignment: crate::test_util::test_assignment(),
                sender_vk: Vec::new(),
                signature_valid: false,
            });
        }
        let t0 = std::time::Instant::now();
        for id in 2500..7500 {
            inbox.remove_received_message(&[id]);
        }
        eprintln!("{}ms", t0.elapsed().as_millis());
        assert_eq!(inbox.messages.len(), 5000);
    }

    /// Ids are content hashes kept in arrival order, not sorted: removing
    /// one message must find it wherever it sits. A binary search over this
    /// order misses most of them.
    #[test]
    fn a_single_removal_finds_a_message_out_of_id_order() {
        let mut inbox = InboxModel::new(
            freenet_mail_protocol::Addr([1; 24]),
            &[2; 1952],
            vec![3; 1184],
        );
        let ids = [0x9f00_u64, 0x10, 0xffff_0000, 0x42, 0x7, 0x5555_5555];
        for id in ids {
            inbox.messages.push(MessageModel {
                id,
                content: DecryptedMessage::default(),
                token_assignment: crate::test_util::test_assignment(),
                sender_vk: Vec::new(),
                signature_valid: false,
            });
        }
        for (removed, id) in ids.iter().enumerate() {
            inbox.remove_received_message(&[*id]);
            assert!(
                !inbox.messages.iter().any(|m| m.id == *id),
                "message {id:#x} is still there"
            );
            assert_eq!(inbox.messages.len(), ids.len() - removed - 1);
        }
    }

    fn fresh_signing_key() -> MlDsaSigningKey<MlDsa65> {
        ml_dsa::SigningKey::<MlDsa65>::from_seed(&crate::rng::random_bytes::<32>().into())
    }

    #[test]
    fn verify_signature_round_trip() {
        let sk = fresh_signing_key();
        let ciphertext = b"opaque encrypted payload".to_vec();
        let sig: ml_dsa::Signature<MlDsa65> = MlDsaSigner::sign(&sk, &ciphertext);
        let sig_bytes = sig.encode().to_vec();
        let vk_bytes = MlDsaKeypair::verifying_key(&sk).encode().to_vec();
        assert!(verify_message_signature(&ciphertext, &vk_bytes, &sig_bytes));
    }

    #[test]
    fn verify_rejects_tampered_ciphertext() {
        let sk = fresh_signing_key();
        let ciphertext = b"original payload".to_vec();
        let sig: ml_dsa::Signature<MlDsa65> = MlDsaSigner::sign(&sk, &ciphertext);
        let sig_bytes = sig.encode().to_vec();
        let vk_bytes = MlDsaKeypair::verifying_key(&sk).encode().to_vec();
        let tampered = b"different payload".to_vec();
        assert!(!verify_message_signature(&tampered, &vk_bytes, &sig_bytes));
    }

    #[test]
    fn verify_rejects_wrong_vk() {
        let sk1 = fresh_signing_key();
        let sk2 = fresh_signing_key();
        let ciphertext = b"payload".to_vec();
        let sig: ml_dsa::Signature<MlDsa65> = MlDsaSigner::sign(&sk1, &ciphertext);
        let sig_bytes = sig.encode().to_vec();
        let vk2_bytes = MlDsaKeypair::verifying_key(&sk2).encode().to_vec();
        assert!(!verify_message_signature(
            &ciphertext,
            &vk2_bytes,
            &sig_bytes
        ));
    }

    #[test]
    fn verify_rejects_empty_inputs() {
        assert!(!verify_message_signature(b"x", &[], &[1, 2, 3]));
        assert!(!verify_message_signature(b"x", &[1, 2, 3], &[]));
        assert!(!verify_message_signature(b"x", &[], &[]));
    }

    #[test]
    fn verify_rejects_garbage_lengths() {
        // Wrong-length VK and signature bytes both bail out cleanly.
        assert!(!verify_message_signature(b"x", &[0u8; 5], &[0u8; 5]));
    }

    fn fresh_kem_dk() -> DecapsulationKey<MlKem768> {
        DecapsulationKey::<MlKem768>::from_seed(crate::rng::random_bytes::<64>().into())
    }

    /// Repro for #267: a stored message that this identity can't decrypt must
    /// return `None`, NOT panic. Before the fix, `from_stored` `.expect()`ed
    /// on the decrypt failure, aborting the wasm module and freezing the UI
    /// when an undecryptable (foreign / malformed) message surfaced in shared
    /// inbox state — e.g. on the UPDATE that followed a second send.
    #[test]
    fn from_stored_returns_none_on_undecryptable_content() {
        let dk = fresh_kem_dk();
        // Garbage that isn't even valid framing.
        assert!(DecryptedMessage::from_stored(&dk, vec![0u8; 16]).is_none());
        // Well-sized but undecryptable random bytes (wrong KEM ciphertext).
        assert!(DecryptedMessage::from_stored(&dk, vec![7u8; 1200]).is_none());
    }

    /// Repro for #267: a message correctly encrypted for a DIFFERENT identity
    /// (the realistic multi-node case) decrypts to `None` rather than
    /// panicking. The recipient's `from_stored` must skip it.
    #[test]
    fn from_stored_skips_message_encrypted_for_other_identity() {
        let alice_dk = fresh_kem_dk();
        let bob_dk = fresh_kem_dk();

        // Encrypt a real DecryptedMessage for alice.
        let msg = DecryptedMessage {
            title: "for alice".into(),
            content: "secret".into(),
            from: "carol".into(),
            to: vec![],
            cc: vec![],
            time: Utc::now(),
            thread_id: None,
            in_reply_to: None,
            quoted_excerpt: None,
        };
        let plaintext = serde_json::to_vec(&msg).unwrap();
        let ciphertext = ml_kem_encrypt(alice_dk.encapsulation_key(), &plaintext).unwrap();

        // Alice decrypts fine.
        assert!(DecryptedMessage::from_stored(&alice_dk, ciphertext.clone()).is_some());
        // Bob can't — must be skipped, not fatal.
        assert!(DecryptedMessage::from_stored(&bob_dk, ciphertext).is_none());
    }

    /// #270/#283: the threading fields (`thread_id`, `in_reply_to`,
    /// `quoted_excerpt`) must survive the REAL crypto path, not just bare
    /// serde. `to_stored` does `serde_json::to_vec` → `ml_kem_encrypt`, and
    /// the decrypt path does `ml_kem_decrypt` → `serde_json::from_slice`
    /// (see `DecryptedMessage::from_stored`). This drives that exact seam:
    /// `ml_kem_encrypt(ek, serde_json::to_vec(&msg))` then
    /// `from_stored(dk, …)`, asserting all three fields come back
    /// byte-for-byte. ML-KEM/ChaCha20-Poly1305 framing is opaque to the
    /// contract, so a regression here would silently strip thread linkage
    /// from every stored reply.
    #[test]
    fn thread_fields_survive_ml_kem_roundtrip() {
        let dk = fresh_kem_dk();
        let msg = DecryptedMessage {
            title: "Re: design review".into(),
            content: "agreed, ship it\n> the line being replied to".into(),
            from: "bob".into(),
            to: vec![],
            cc: vec![],
            time: Utc::now(),
            thread_id: Some("thread-abc-123".into()),
            in_reply_to: Some("7".into()),
            quoted_excerpt: Some("the line being replied to".into()),
        };

        // Encrypt exactly as `to_stored` does: serde_json → ml_kem_encrypt.
        let plaintext = serde_json::to_vec(&msg).unwrap();
        let ciphertext = ml_kem_encrypt(dk.encapsulation_key(), &plaintext).unwrap();

        // Decrypt via the real seam: ml_kem_decrypt → serde_json::from_slice.
        let back = DecryptedMessage::from_stored(&dk, ciphertext)
            .expect("ciphertext encrypted for this dk must decrypt");

        assert_eq!(back.thread_id.as_deref(), Some("thread-abc-123"));
        assert_eq!(back.in_reply_to.as_deref(), Some("7"));
        assert_eq!(
            back.quoted_excerpt.as_deref(),
            Some("the line being replied to")
        );
        // Sanity: the rest of the message survives too.
        assert_eq!(back.title, "Re: design review");
        assert_eq!(back.from, "bob");
    }

    #[test]
    fn a_failed_decryption_tells_the_user_how_to_retry() {
        assert!(decrypt_gave_up_text(1).starts_with("1 message couldn't"));
        let t = decrypt_gave_up_text(3);
        assert!(t.starts_with("3 messages") && t.contains("reload"), "{t}");
    }

    /// A removal larger than the delegate signs at once goes out as several
    /// batches, each within the limit, together strictly ascending and
    /// without duplicates, so no part is refused after the page hid it.
    #[test]
    fn a_large_removal_is_signed_in_batches_within_the_limit() {
        let max = freenet_mail_protocol::MAX_REMOVAL_BATCH;
        let mut hashes: Vec<[u8; 32]> = (0..2 * max + 7)
            .map(|i| *blake3::hash(&(i as u64).to_le_bytes()).as_bytes())
            .collect();
        hashes.push(hashes[3]);
        let batches = removal_batches(hashes);
        assert_eq!(batches.len(), 3);
        assert!(batches.iter().all(|b| !b.is_empty() && b.len() <= max));
        let all: Vec<_> = batches.concat();
        assert_eq!(all.len(), 2 * max + 7, "duplicates dropped");
        assert!(all.windows(2).all(|w| w[0] < w[1]), "strictly ascending");
    }

    /// `from_state` decrypts nothing itself: every stored message is handed
    /// to the delegate, and the model starts without them.
    #[test]
    fn from_state_hands_every_message_to_the_delegate() {
        let (model, pending) = model_with(&[1, 2]);
        assert!(model.messages.is_empty());
        assert_eq!(pending.messages.len(), 2);
        assert_eq!(pending.addr, Some(freenet_mail_protocol::Addr([1; 24])));
    }

    fn stored(n: u8) -> StoredMessage {
        let mut token_assignment = crate::test_util::test_assignment();
        token_assignment.assignment_hash = [n; 32];
        StoredMessage {
            content: vec![n; 1200],
            token_assignment,
            sender_vk: Vec::new(),
            signature: Vec::new(),
        }
    }

    fn state_of(hashes: &[u8]) -> StoredInbox {
        StoredInbox::with_signature(
            StoredSettings::default(),
            hashes.iter().map(|&n| stored(n)).collect(),
            Utc::now(),
            vec![3; 1184],
            Box::new([]),
        )
    }

    fn model_with(hashes: &[u8]) -> (InboxModel, PendingDecrypt) {
        let addr = freenet_mail_protocol::Addr([1; 24]);
        let key = InboxModel::new(addr, &[2; 1952], vec![3; 1184]).key;
        InboxModel::from_state(addr, vec![3; 1184], state_of(hashes), key).unwrap()
    }

    /// What the delegate would answer for `pending`: every message readable.
    fn all_readable(pending: &PendingDecrypt) -> Decrypted {
        Decrypted {
            messages: pending
                .messages
                .iter()
                .map(|m| (m.clone(), DecryptedMessage::default()))
                .collect(),
            unreadable: Vec::new(),
        }
    }

    /// A decryption started from an older state, answered after a newer
    /// state dropped one of its messages, must not bring that message back.
    #[test]
    fn a_decryption_from_a_superseded_state_does_not_resurrect_a_message() {
        let (mut model, pending) = model_with(&[1, 2]);
        let answer = all_readable(&pending);
        let again = model.replace_state(state_of(&[1])).unwrap();
        assert!(again.is_empty(), "message 1 is already being decrypted");
        model.add_decrypted(answer);
        let hashes: Vec<_> = model
            .messages
            .iter()
            .map(|m| m.token_assignment.assignment_hash)
            .collect();
        assert_eq!(hashes, vec![[1; 32]]);
    }

    /// A repeated state does not hand the delegate messages it is already
    /// decrypting; one it could never read is not asked for again.
    #[test]
    fn in_flight_and_unreadable_messages_are_not_asked_for_twice() {
        let (mut model, pending) = model_with(&[1, 2]);
        assert_eq!(pending.messages.len(), 2);
        assert!(model.replace_state(state_of(&[1, 2])).unwrap().is_empty());
        model.add_decrypted(Decrypted {
            messages: vec![(stored(1), DecryptedMessage::default())],
            unreadable: vec![[2; 32]],
        });
        assert!(model.replace_state(state_of(&[1, 2])).unwrap().is_empty());
        assert_eq!(model.messages.len(), 1);
    }

    /// A call that failed as a whole releases its messages: a retry takes
    /// the ones still in the inbox, and the next state may too.
    #[test]
    fn a_failed_decryption_is_released_and_retried() {
        let (mut model, pending) = model_with(&[1, 2]);
        let hashes = pending.hashes();
        let messages = pending.messages.clone();
        model.release(&hashes);
        // Meanwhile a delta removes message 2.
        let _ = model.apply_delta(UpdateInbox::RemoveMessages {
            signature: Box::new([]),
            ids: vec![[2; 32]],
        });
        let retry = model.retake(messages);
        assert_eq!(retry.hashes(), vec![[1; 32]]);
        assert!(
            model.replace_state(state_of(&[1])).unwrap().is_empty(),
            "the retry holds message 1 in flight"
        );
        model.add_decrypted(all_readable(&retry));
        assert_eq!(model.messages.len(), 1);
    }

    /// Repro for #267: an inbox whose stored messages include an entry
    /// encrypted for another identity must decode to a model that simply
    /// omits the undecryptable message, never panic. Decryption runs in the
    /// (in-page) delegate.
    #[cfg(feature = "local-delegate")]
    #[test]
    fn decrypting_an_inbox_skips_messages_for_other_identities() {
        let me = delegate_identity();
        let my_ek = MlKemEncapsKey(me.ek.to_vec()).to_key().unwrap();
        let foreign_dk = fresh_kem_dk();
        let mk_stored = |ek: &EncapsulationKey<MlKem768>, title: &str, n: u8| {
            let msg = DecryptedMessage {
                title: title.into(),
                content: "body".into(),
                from: "carol".into(),
                ..Default::default()
            };
            let mut token_assignment = crate::test_util::test_assignment();
            token_assignment.assignment_hash = [n; 32];
            StoredMessage {
                content: ml_kem_encrypt(ek, &serde_json::to_vec(&msg).unwrap()).unwrap(),
                token_assignment,
                sender_vk: Vec::new(),
                signature: Vec::new(),
            }
        };
        let state = StoredInbox::with_signature(
            StoredSettings::default(),
            vec![
                mk_stored(&my_ek, "ours", 1),
                mk_stored(foreign_dk.encapsulation_key(), "foreign", 2),
            ],
            Utc::now(),
            me.ek.to_vec(),
            Box::new([]),
        );
        let key = InboxModel::new(me.addr, &me.vk, me.ek.to_vec()).key;
        let (mut model, pending) =
            InboxModel::from_state(me.addr, me.ek.to_vec(), state, key).unwrap();
        let decrypted = futures::executor::block_on(decrypt_pending(pending))
            .expect("a foreign message must not fail the inbox (#267)");
        model.add_decrypted(decrypted);
        assert_eq!(
            model.messages.len(),
            1,
            "foreign message skipped, ours kept"
        );
        assert_eq!(model.messages[0].content.title, "ours");
    }

    /// A message removed while its decryption was in flight stays removed.
    #[test]
    fn a_removal_during_decryption_wins() {
        let addr = freenet_mail_protocol::Addr([1; 24]);
        let mut inbox = InboxModel::new(addr, &[2; 1952], vec![3; 1184]);
        let mut stored = StoredMessage {
            content: vec![1; 1200],
            token_assignment: crate::test_util::test_assignment(),
            sender_vk: Vec::new(),
            signature: Vec::new(),
        };
        stored.token_assignment.assignment_hash = [9; 32];
        let _pending = inbox.apply_delta(UpdateInbox::RemoveMessages {
            signature: Box::new([]),
            ids: vec![[9; 32]],
        });
        inbox.add_decrypted(Decrypted {
            messages: vec![(stored, DecryptedMessage::default())],
            unreadable: Vec::new(),
        });
        assert!(inbox.messages.is_empty());
    }

    /// The signed settings request, from the in-page delegate offline. On a
    /// node build there is no delegate in the test process, so only the
    /// model side is checked there.
    fn settle(
        request: LocalBoxFuture<'static, Result<ContractRequest<'static>, DynError>>,
    ) -> Option<ContractRequest<'static>> {
        if cfg!(feature = "local-delegate") {
            Some(futures::executor::block_on(request).expect("the delegate signs the change"))
        } else {
            None
        }
    }

    // ─── #150 UI-side bypass helpers ──────────────────────────────────────

    fn make_test_inbox() -> InboxModel {
        #[cfg(feature = "local-delegate")]
        {
            let me = delegate_identity();
            InboxModel::new(me.addr, &me.vk, me.ek.to_vec())
        }
        #[cfg(not(feature = "local-delegate"))]
        {
            InboxModel::new(
                freenet_mail_protocol::Addr([1; 24]),
                &[2; 1952],
                vec![3; 1184],
            )
        }
    }

    /// #256: a new inbox's state must carry the owner's ML-KEM ek, so it
    /// advertises a usable encryption key, and the delegate's authority
    /// signature over it must verify against the identity's key.
    #[cfg(feature = "local-delegate")]
    #[test]
    fn a_new_inbox_state_carries_the_owner_ek_and_verifies_256() {
        let me = delegate_identity();
        let identity = crate::app::Identity::from_info(&me, crate::app::UserId::new());
        let state = futures::executor::block_on(crate::app::identity_store::initial_inbox_state(
            &identity,
            Tier::Min10,
            3600,
        ))
        .unwrap();
        let decoded: StoredInbox = serde_json::from_slice(&state).unwrap();
        assert_eq!(decoded.owner_ek_bytes, me.ek.to_vec(), "#256");
        let raw: serde_json::Value = serde_json::from_slice(&state).unwrap();
        let sig: Vec<u8> = serde_json::from_value(raw["inbox_signature"].clone()).unwrap();
        let payload = freenet_mail_wire_v1::inbox::sign_payload(
            &decoded.owner_ek_bytes,
            &decoded.settings,
            decoded.last_update,
        );
        let sig = ml_dsa::Signature::<MlDsa65>::try_from(sig.as_slice()).unwrap();
        assert!(identity.ml_dsa_vk().verify(&payload, &sig).is_ok());
    }

    /// `update_verified_bypass_prepare` with a single verified VK must flip
    /// `allow_verified_skip_token` to `true` on the model and return a
    /// `ContractRequest::Update` wrapping a `ModifySettings` delta with the
    /// correct field values.
    #[test]
    fn update_verified_bypass_prepare_sets_flag_and_returns_request() {
        let mut inbox = make_test_inbox();
        let vk_bytes = vec![7u8; 1952];

        let mut vs = std::collections::BTreeSet::new();
        vs.insert(vk_bytes.clone());

        let request = settle(inbox.update_verified_bypass_prepare(true, vs.clone()));

        // The internal model must reflect the new state.
        assert!(
            inbox.settings.allow_verified_skip_token,
            "allow_verified_skip_token must be true after prepare"
        );
        assert!(
            inbox.settings.verified_senders.contains(&vk_bytes),
            "verified_senders must contain the supplied VK"
        );

        // The returned request must be an Update wrapping a Delta.
        let Some(request) = request else { return };
        match request {
            freenet_stdlib::client_api::ContractRequest::Update { data, .. } => {
                if let UpdateData::Delta(d) = data {
                    let decoded: freenet_mail_wire_v1::inbox::UpdateInbox =
                        serde_json::from_slice(&d).expect("delta must decode as UpdateInbox");
                    if let freenet_mail_wire_v1::inbox::UpdateInbox::ModifySettings {
                        settings,
                        ..
                    } = decoded
                    {
                        assert!(
                            settings.allow_verified_skip_token,
                            "delta must carry allow_verified_skip_token=true"
                        );
                        assert!(
                            settings.verified_senders.contains(&vk_bytes),
                            "delta must carry the verified VK"
                        );
                    } else {
                        panic!("expected ModifySettings delta variant");
                    }
                } else {
                    panic!("expected UpdateData::Delta");
                }
            }
            other => panic!("expected ContractRequest::Update, got {other:?}"),
        }
    }

    /// Toggling bypass ON with multiple contacts populates `verified_senders`
    /// with all of them in one `ModifySettings` delta.
    #[test]
    fn update_verified_bypass_populate_multiple_vks() {
        let mut inbox = make_test_inbox();

        // Simulate N address-book contacts.
        let mut vs = std::collections::BTreeSet::new();
        for i in 0u8..5 {
            let contact_sk = fresh_signing_key();
            let vk = MlDsaKeypair::verifying_key(&contact_sk);
            let mut vk_bytes = vk.encode().to_vec();
            // Ensure distinct entries (they should be by key but let's be safe).
            *vk_bytes.last_mut().unwrap() ^= i;
            vs.insert(vk_bytes);
        }

        let request = settle(inbox.update_verified_bypass_prepare(true, vs.clone()));

        assert_eq!(
            inbox.settings.verified_senders.len(),
            vs.len(),
            "model must hold all supplied VKs"
        );

        // Delta must also carry all of them.
        let Some(request) = request else { return };
        if let freenet_stdlib::client_api::ContractRequest::Update {
            data: UpdateData::Delta(d),
            ..
        } = request
        {
            let decoded: freenet_mail_wire_v1::inbox::UpdateInbox =
                serde_json::from_slice(&d).expect("delta decode");
            if let freenet_mail_wire_v1::inbox::UpdateInbox::ModifySettings { settings, .. } =
                decoded
            {
                assert_eq!(
                    settings.verified_senders.len(),
                    vs.len(),
                    "delta must carry all VKs"
                );
            } else {
                panic!("expected ModifySettings variant");
            }
        } else {
            panic!("unexpected request type");
        }
    }

    /// Toggling bypass OFF must NOT clear `verified_senders` — the set
    /// persists so it can be reused if the user toggles bypass back on.
    #[test]
    fn toggle_bypass_off_retains_verified_senders() {
        let mut inbox = make_test_inbox();

        let contact_sk = fresh_signing_key();
        let vk_bytes = MlDsaKeypair::verifying_key(&contact_sk).encode().to_vec();
        let mut vs = std::collections::BTreeSet::new();
        vs.insert(vk_bytes.clone());

        // Toggle ON — populates the set.
        settle(inbox.update_verified_bypass_prepare(true, vs.clone()));

        // Toggle OFF — sends an empty-VK set to the contract but the model
        // stores whatever the caller passes. The UI contract is: when
        // toggling OFF the caller passes the current set unchanged so that
        // re-enabling restores the same bypass list.
        //
        // Simulate the toggle-OFF flow: bypass=false but keep the same vs.
        settle(inbox.update_verified_bypass_prepare(false, vs.clone()));

        // The model retains the senders (they were passed by the caller).
        assert!(
            inbox.settings.verified_senders.contains(&vk_bytes),
            "verified_senders must be retained when toggling bypass OFF"
        );
        assert!(
            !inbox.settings.allow_verified_skip_token,
            "allow_verified_skip_token must be false after toggling OFF"
        );
    }

    /// `update_verified_bypass_prepare` with bypass ON and an empty set
    /// must produce a delta with `allow_verified_skip_token=true` and an
    /// empty `verified_senders` collection — the contract will accept it
    /// (nobody bypasses) and the model must reflect the same.
    #[test]
    fn toggle_bypass_on_empty_set_produces_correct_delta() {
        let mut inbox = make_test_inbox();

        let request = settle(inbox.update_verified_bypass_prepare(true, Default::default()));

        assert!(inbox.settings.allow_verified_skip_token);
        assert!(inbox.settings.verified_senders.is_empty());
        let Some(request) = request else { return };

        if let freenet_stdlib::client_api::ContractRequest::Update {
            data: UpdateData::Delta(d),
            ..
        } = request
        {
            let decoded: freenet_mail_wire_v1::inbox::UpdateInbox =
                serde_json::from_slice(&d).expect("delta decode");
            if let freenet_mail_wire_v1::inbox::UpdateInbox::ModifySettings { settings, .. } =
                decoded
            {
                assert!(settings.allow_verified_skip_token);
                assert!(settings.verified_senders.is_empty());
            } else {
                panic!("expected ModifySettings");
            }
        } else {
            panic!("unexpected request type");
        }
    }

    /// #251 improvement 4: `inbox_key_for_with_hash` against two
    /// different code hashes must yield two different `ContractKey`s
    /// for the same vk — the whole reason the helper exists. Also pin
    /// that `inbox_key_for` is exactly the `INBOX_CODE_HASH` instance
    /// of the helper, so the two stay in lockstep.
    #[cfg(feature = "use-node")]
    #[test]
    fn inbox_key_for_with_hash_distinguishes_code_hashes() {
        let sk = fresh_signing_key();
        let vk = MlDsaKeypair::verifying_key(&sk);
        let synthetic = bs58::encode([7u8; 32])
            .with_alphabet(bs58::Alphabet::BITCOIN)
            .into_string();
        let current = inbox_key_for_with_hash(&vk, INBOX_CODE_HASH).expect("current key");
        let other = inbox_key_for_with_hash(&vk, &synthetic).expect("other key");
        assert_ne!(
            current.id(),
            other.id(),
            "different code hashes must produce different contract instance ids — \
             otherwise the send-time switch in #251 improvement 4 is a no-op",
        );
        let default = inbox_key_for(&vk).expect("default key");
        assert_eq!(
            current.id(),
            default.id(),
            "inbox_key_for must equal inbox_key_for_with_hash(.., INBOX_CODE_HASH)",
        );
    }

    #[cfg(feature = "use-node")]
    #[test]
    fn inbox_key_matches_the_v0_2_client() {
        use crate::test_util::{frozen_fixture_vk, frozen_key, hex};
        let key = inbox_key_for(&frozen_fixture_vk()).unwrap();
        assert_eq!(hex(key.id().as_bytes()), frozen_key("inbox_contract"));
    }

    /// `bs58::encode(key.code_hash().as_ref())` must roundtrip through
    /// the same bs58 BITCOIN alphabet that `ContractKey::from_params`
    /// uses internally. `freenet_stdlib::CodeHash::encode` lowercases
    /// its output, which would break this roundtrip — pin the chosen
    /// alternative (#251 improvement 4).
    #[test]
    fn code_hash_bs58_roundtrips_byte_identical() {
        let bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0xAB, 0xCD, 0xEF, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
            0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB,
        ];
        let encoded = bs58::encode(bytes)
            .with_alphabet(bs58::Alphabet::BITCOIN)
            .into_string();
        // The encoding must contain mixed case — lowercasing it would
        // change the decoded bytes (case-sensitive bs58 alphabet).
        assert!(
            encoded.chars().any(|c| c.is_ascii_uppercase())
                && encoded.chars().any(|c| c.is_ascii_lowercase()),
            "fixture chosen to exercise mixed-case bs58 output, got {encoded}",
        );
        let mut decoded = [0u8; 32];
        bs58::decode(&encoded)
            .with_alphabet(bs58::Alphabet::BITCOIN)
            .onto(&mut decoded)
            .expect("decode");
        assert_eq!(decoded, bytes, "bs58 BITCOIN alphabet must roundtrip");

        // Decode lowercased — must yield DIFFERENT bytes, demonstrating
        // why we cannot use `CodeHash::encode` (which lowercases).
        let lowered = encoded.to_lowercase();
        let mut decoded_lower = [0u8; 32];
        let lower_ok = bs58::decode(&lowered)
            .with_alphabet(bs58::Alphabet::BITCOIN)
            .onto(&mut decoded_lower)
            .is_ok();
        if lower_ok {
            assert_ne!(
                decoded_lower, bytes,
                "lowercased bs58 must NOT roundtrip — proves the workaround is load-bearing",
            );
        }
    }

    // ----- #288: stale-send sweep (drain_stale_pending_sent) -----

    use freenet_stdlib::prelude::Parameters;

    fn pending_sent_key(n: u8) -> InboxContract {
        ContractKey::from_params_and_code(Parameters::from(vec![n]), ContractCode::from(vec![0u8]))
    }

    fn clear_pending_sent_ack() {
        PENDING_SENT_ACK.with(|m| m.borrow_mut().clear());
    }

    #[test]
    fn drain_stale_pending_sent_fails_only_aged_entries_288() {
        clear_pending_sent_ack();
        let key = pending_sent_key(1);
        // Two sends to the same inbox: one old (enqueued at t=0), one fresh
        // (enqueued at t=59_000ms). Sweep at now=60_000ms with a 60s timeout.
        enqueue_pending_sent_ack(key, "alice".into(), "old".into(), 0);
        enqueue_pending_sent_ack(key, "alice".into(), "fresh".into(), 59_000);

        let drained = drain_stale_pending_sent(60, 60_000);

        // Old (age 60s == cutoff) expires; fresh (age 1s) survives.
        assert_eq!(drained, vec![("alice".to_string(), "old".to_string())]);
        // The fresh entry is still queued (will flip Delivered when its ack lands).
        let remaining = take_next_pending_sent_ack(&key);
        assert_eq!(remaining, Some(("alice".to_string(), "fresh".to_string())));
        clear_pending_sent_ack();
    }

    #[test]
    fn drain_stale_pending_sent_prunes_empty_inbox_queues_288() {
        clear_pending_sent_ack();
        let key = pending_sent_key(2);
        enqueue_pending_sent_ack(key, "bob".into(), "s1".into(), 0);

        let drained = drain_stale_pending_sent(60, 1_000_000);
        assert_eq!(drained.len(), 1);
        // After draining the only entry, the inbox key must not linger in the map.
        let count = PENDING_SENT_ACK.with(|m| m.borrow().len());
        assert_eq!(count, 0, "empty per-inbox queue should be pruned");
        clear_pending_sent_ack();
    }

    #[test]
    fn drain_stale_pending_sent_noop_when_all_fresh_288() {
        clear_pending_sent_ack();
        let key = pending_sent_key(3);
        enqueue_pending_sent_ack(key, "carol".into(), "s1".into(), 90_000);
        // now only 10s past enqueue → under the 60s cutoff.
        let drained = drain_stale_pending_sent(60, 100_000);
        assert!(drained.is_empty(), "no entry past cutoff → nothing failed");
        assert_eq!(
            take_next_pending_sent_ack(&key),
            Some(("carol".into(), "s1".into()))
        );
        clear_pending_sent_ack();
    }
}

#[cfg(test)]
mod crypto_vectors;
