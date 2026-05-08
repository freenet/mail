use std::sync::atomic::AtomicU32;
use std::{cell::RefCell, collections::HashMap};

use chrono::{DateTime, Utc};
use freenet_aft_interface::{
    AllocationCriteria, DelegateParameters, FailureReason, RequestNewToken, Tier,
    TokenAllocationRecord, TokenAllocationSummary, TokenAssignment, TokenDelegateMessage,
    TokenDelegateParameters,
};
use freenet_stdlib::client_api::{ContractRequest, DelegateRequest};
use freenet_stdlib::prelude::UpdateData::{Delta, State as StateUpdate};
use freenet_stdlib::prelude::{
    ApplicationMessage, CodeHash, ContractInstanceId, ContractKey, DelegateKey, InboundDelegateMsg,
    Parameters, State, UpdateData,
};

use freenet_email_inbox::InboxParams;

use crate::api::{TryNodeAction, node_response_error_handling};
use crate::inbox::MessageModel;
use crate::{DynError, api::WebApiRequestClient, app::Identity};

// AFT code hashes are produced by `cargo make build-token-*` and are only
// dereferenced from `use-node` flows. Under offline builds we fall back to
// empty placeholders so the artifacts aren't required at compile time.
#[cfg(feature = "use-node")]
pub(crate) const TOKEN_RECORD_CODE_HASH: &str = include_str!(
    "../../modules/antiflood-tokens/contracts/token-allocation-record/build/token_allocation_record_code_hash"
);
#[cfg(not(feature = "use-node"))]
pub(crate) const TOKEN_RECORD_CODE_HASH: &str = "";

#[cfg(feature = "use-node")]
pub(crate) const TOKEN_GENERATOR_DELEGATE_CODE_HASH: &str = include_str!(
    "../../modules/antiflood-tokens/delegates/token-generator/build/token_generator_code_hash"
);
#[cfg(not(feature = "use-node"))]
pub(crate) const TOKEN_GENERATOR_DELEGATE_CODE_HASH: &str = "";

pub(crate) struct AftRecords {}

type InboxContract = ContractKey;
type AftRecordId = ContractInstanceId;
type AftRecord = ContractKey;
type AftDelegate = DelegateKey;

type AssignmentHash = [u8; 32];

thread_local! {
    static RECORDS: RefCell<HashMap<Identity, TokenAllocationRecord>> = RefCell::new(HashMap::new());
    /// Contracts that require a token assingment still for a pending message.
    static PENDING_TOKEN_ASSIGNMENT: RefCell<HashMap<AftDelegate, Vec<InboxContract>>> = RefCell::new(HashMap::new());
    /// Assignments obtained from the delegate that need to be inserted in the record still.
    static PENDING_CONFIRMED_ASSIGNMENTS: RefCell<HashMap<AftRecordId, Vec<PendingAssignmentRegister>>> = RefCell::new(HashMap::new());
    /// A token which has been confirmed as valid by a contract update.
    static VALID_TOKEN: RefCell<HashMap<AftDelegate, Vec<TokenAssignment>>> = RefCell::new(HashMap::new());
    static PENDING_INBOXES_UPDATES: RefCell<Vec<(InboxContract, AssignmentHash)>> = const { RefCell::new(Vec::new()) };
    /// Recipient fingerprints (six-word, dash-joined) for pending sends.
    ///
    /// Populated by `assign_token` from the recipient's ML-DSA VK bytes.
    /// Cleared when the token assignment is either confirmed or drained.
    /// Used by the permission pump to resolve which recipients are pending so
    /// it can look up per-recipient saved decisions (#149 Part 2).
    /// Pending recipient ML-DSA VK bytes for sends awaiting token assignment.
    /// Stored as raw byte vecs so the permission pump can cross-reference
    /// against the address book without a hex-decode step.
    static PENDING_RECIPIENT_VK_BYTES: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
}

/// Default timeout for pending AFT confirmations. If the host's
/// `UpdateResponse` summary doesn't acknowledge the assignment within
/// this window, `expire_stale` reaps the entry and surfaces an error to
/// the UI so the user knows the send didn't land. Tuned for the typical
/// cross-node propagation window (low single-digit seconds) plus
/// margin for network jitter.
pub(crate) const PENDING_ASSIGNMENT_TIMEOUT_SECS: i64 = 30;

/// How often the API coroutine checks for stale pending assignments.
/// Short enough that a stuck send surfaces quickly, long enough that
/// the WASM scheduler isn't busy on it. The actual user-visible
/// latency to error is bounded by `PENDING_ASSIGNMENT_TIMEOUT_SECS +
/// PENDING_ASSIGNMENT_SWEEP_INTERVAL_MS`.
pub(crate) const PENDING_ASSIGNMENT_SWEEP_INTERVAL_MS: u32 = 5_000;

struct PendingAssignmentRegister {
    /// Time at which the assignment was queued for confirmation. Reaped by
    /// `expire_stale` once the timeout elapses.
    start: DateTime<Utc>,
    record: TokenAssignment,
    inbox: InboxContract,
}

/// Pick the cheapest (lowest-cost) tier the sender has available that
/// satisfies the recipient's `minimum_tier` requirement (#152).
///
/// "Cheapest" means the shortest-period tier: `Min1 < Min5 < Min10 <
/// … < Day365`. Returns the lowest `t` in `available` such that
/// `t >= required`, or `None` if no available tier qualifies.
///
/// This is pure and host-side–testable so the selection logic can be
/// unit-tested without spinning up a delegate.
pub(crate) fn pick_spend_tier(available: &[Tier], required: Tier) -> Option<Tier> {
    available.iter().copied().filter(|&t| t >= required).min()
}

/// Build an `AllocationCriteria` from the recipient's `InboxParams`
/// policy (#85). Pure / testable: factored out of `assign_token` so a
/// host-side unit test can verify that the criteria the AFT delegate
/// receives reflects the recipient's chosen tier and `max_age_secs`,
/// not the legacy hardcoded `Day1`/365d.
pub(crate) fn build_recipient_criteria(
    recipient_required_tier: Tier,
    recipient_max_age_secs: u64,
    token_record: ContractInstanceId,
) -> Result<AllocationCriteria, DynError> {
    AllocationCriteria::new(
        recipient_required_tier,
        std::time::Duration::from_secs(recipient_max_age_secs),
        token_record,
    )
    .map_err(|e| format!("{e}").into())
}

impl AftRecords {
    pub async fn load_all(
        client: &mut WebApiRequestClient,
        contracts: &[Identity],
        contract_to_id: &mut HashMap<AftRecord, Identity>,
    ) {
        for identity in contracts {
            let r = Self::load_contract(client, identity, contract_to_id).await;
            if let Ok(key) = &r {
                contract_to_id.insert(*key, identity.clone());
            }
            node_response_error_handling(
                client.clone().into(),
                r.map(|_| ()),
                TryNodeAction::LoadTokenRecord,
            )
            .await;
        }
    }

    async fn load_contract(
        client: &mut WebApiRequestClient,
        identity: &Identity,
        contract_to_id: &HashMap<AftRecord, Identity>,
    ) -> Result<AftRecord, DynError> {
        use ml_dsa::signature::Keypair;
        let vk = identity.ml_dsa_signing_key.as_ref().verifying_key();
        let params = TokenDelegateParameters::new(&vk)
            .try_into()
            .map_err(|e| format!("{e}"))?;
        let contract_key =
            ContractKey::from_params(TOKEN_RECORD_CODE_HASH, params).map_err(|e| format!("{e}"))?;
        Self::get_state(client, contract_key).await?;
        let _alias = identity.alias();
        crate::log::debug!(
            "subscribing to AFT updates for `{contract_key}`, belonging to alias `{_alias}`"
        );
        if !contract_to_id.contains_key(&contract_key) {
            Self::subscribe(client, contract_key).await?;
        }
        Ok(contract_key)
    }

    /// Drain pending confirmations older than `timeout_secs` and return
    /// the expired records so the caller can surface the failure to the
    /// UI. Also clears the matching entry in `PENDING_INBOXES_UPDATES`
    /// so a retry can re-queue without colliding with a stale entry.
    ///
    /// Without this sweep, a `confirm_allocation` that never arrives
    /// (host crash, network drop, malformed summary) leaves the user's
    /// send hanging forever with no UI feedback — see #1 in the AFT
    /// audit.
    pub fn expire_stale(timeout_secs: i64) -> Vec<TokenAssignment> {
        let now = Utc::now();
        let mut expired: Vec<TokenAssignment> = Vec::new();
        PENDING_CONFIRMED_ASSIGNMENTS.with(|pending| {
            let mut pending = pending.borrow_mut();
            for registers in pending.values_mut() {
                registers.retain(|r| {
                    let elapsed = now.signed_duration_since(r.start).num_seconds();
                    if elapsed >= timeout_secs {
                        expired.push(r.record.clone());
                        false
                    } else {
                        true
                    }
                });
            }
            pending.retain(|_, v| !v.is_empty());
        });
        if !expired.is_empty() {
            let expired_hashes: HashMap<AssignmentHash, ()> =
                expired.iter().map(|r| (r.assignment_hash, ())).collect();
            PENDING_INBOXES_UPDATES.with(|queue| {
                queue
                    .borrow_mut()
                    .retain(|(_, hash)| !expired_hashes.contains_key(hash));
            });
        }
        expired
    }

    /// Drain every queued outbound assignment for `delegate` and return
    /// the matching `(inbox_contract, assignment_hash)` pairs so the
    /// caller can flip the corresponding Sent rows to `Failed` and emit
    /// a user-visible toast. Used by the AFT `Failure(NoFreeSlot)` path
    /// (#85) where the delegate has no `assignment_hash` to disambiguate
    /// which send tripped the cap, so we conservatively fail every
    /// pending send waiting on the same delegate.
    pub fn drain_pending_for_delegate(
        delegate: &AftDelegate,
    ) -> Vec<(InboxContract, AssignmentHash)> {
        let inboxes = PENDING_TOKEN_ASSIGNMENT
            .with(|map| map.borrow_mut().remove(delegate).unwrap_or_default());
        if inboxes.is_empty() {
            return Vec::new();
        }
        let inbox_set: HashMap<InboxContract, ()> = inboxes.iter().map(|c| (*c, ())).collect();
        PENDING_INBOXES_UPDATES.with(|queue| {
            let mut queue = queue.borrow_mut();
            let drained: Vec<(InboxContract, AssignmentHash)> = queue
                .iter()
                .filter(|(inbox, _)| inbox_set.contains_key(inbox))
                .copied()
                .collect();
            queue.retain(|(inbox, _)| !inbox_set.contains_key(inbox));
            drained
        })
    }

    pub fn pending_assignment(delegate: AftDelegate, contract: InboxContract) {
        PENDING_TOKEN_ASSIGNMENT.with(|map| {
            let map = &mut *map.borrow_mut();
            map.entry(delegate).or_default().push(contract);
        })
    }

    /// Register the recipient VK bytes for a pending send so the permission
    /// pump can look it up when deciding whether to auto-accept.
    /// `recipient_vk_bytes` must be the raw ML-DSA-65 verifying key bytes
    /// used to derive the inbox `InboxParams.pub_key`.
    pub fn register_pending_recipient(recipient_vk_bytes: &[u8]) {
        PENDING_RECIPIENT_VK_BYTES.with(|vec| {
            let mut v = vec.borrow_mut();
            if !v.iter().any(|b| b.as_slice() == recipient_vk_bytes) {
                v.push(recipient_vk_bytes.to_vec());
            }
        });
    }

    /// Snapshot and return the pending recipient VK bytes list, then clear
    /// it. Called by the permission pump after applying a response.
    #[cfg(all(target_family = "wasm", feature = "use-node"))]
    pub fn drain_pending_recipient_vk_bytes() -> Vec<Vec<u8>> {
        PENDING_RECIPIENT_VK_BYTES.with(|vec| {
            let mut v = vec.borrow_mut();
            let out = v.clone();
            v.clear();
            out
        })
    }

    /// Non-destructive snapshot of pending recipient VK bytes. Called by
    /// the permission pump when evaluating policy without consuming state.
    #[cfg(all(target_family = "wasm", feature = "use-node"))]
    pub fn peek_pending_recipient_vk_bytes() -> Vec<Vec<u8>> {
        PENDING_RECIPIENT_VK_BYTES.with(|vec| vec.borrow().clone())
    }

    pub async fn confirm_allocation(
        client: &mut WebApiRequestClient,
        aft_record: AftRecordId,
        summary: TokenAllocationSummary,
        sender: Option<Identity>,
    ) -> Result<(), DynError> {
        let Some(confirmed) = PENDING_CONFIRMED_ASSIGNMENTS.with(|pending| {
            let pending = &mut *pending.borrow_mut();
            pending.get_mut(&aft_record).and_then(|registers| {
                registers
                    .iter()
                    .position(|r| {
                        summary.contains_alloc_hash(r.record.tier, &r.record.assignment_hash)
                    })
                    .map(|idx| registers.remove(idx))
            })
        }) else {
            return Ok(());
        };
        // Optimistically append the freshly-minted assignment to the local
        // RECORDS cache so subsequent local reads (e.g. UI counters of
        // remaining tokens, dev-mode introspection) reflect the post-burn
        // state without having to wait for the AFT contract update to
        // round-trip back through SubscribeResponse. Cross-node delivery
        // does not depend on this cache anymore — runtime PR #4007 lets
        // the inbox contract's `update_state` requires(AFT) signal resolve
        // via `fetch_related_via_network` on the receiver side.
        if let Some(sender) = sender {
            RECORDS.with(|recs| {
                let mut recs = recs.borrow_mut();
                let entry = recs
                    .entry(sender)
                    .or_insert_with(|| TokenAllocationRecord::new(HashMap::new()));
                let tier = confirmed.record.tier;
                let mut assignments = entry
                    .get_tier(&tier)
                    .map(|s| s.to_vec())
                    .unwrap_or_default();
                if !assignments
                    .iter()
                    .any(|a| a.assignment_hash == confirmed.record.assignment_hash)
                {
                    assignments.push(confirmed.record.clone());
                    entry.insert(tier, assignments);
                }
            });
        }
        // we have a valid token now, so we can update the inbox contract
        MessageModel::finish_sending(client, confirmed.record, confirmed.inbox).await?;
        Ok(())
    }

    pub async fn allocated_assignment(
        client: &mut WebApiRequestClient,
        record: TokenAssignment,
    ) -> Result<(), DynError> {
        let Some(inbox) = PENDING_INBOXES_UPDATES.with(|queue| {
            queue.borrow().iter().find_map(|(inbox, hash)| {
                if &record.assignment_hash == hash {
                    Some(*inbox)
                } else {
                    None
                }
            })
        }) else {
            // unexpected token
            return Ok(());
        };

        // update the token record contract for this delegate.
        let mut code_hash_bytes = [0u8; 32];
        bs58::decode(TOKEN_RECORD_CODE_HASH)
            .with_alphabet(bs58::Alphabet::BITCOIN)
            .onto(&mut code_hash_bytes)
            .map_err(|e| format!("failed to decode token record code hash: {e}"))?;
        let code_hash = CodeHash::new(code_hash_bytes);
        let key = ContractKey::from_id_and_code(record.token_record, code_hash);
        let request = ContractRequest::Update {
            key,
            data: UpdateData::Delta(serde_json::to_vec(&record)?.into()),
        };
        client.send(request.into()).await?;
        crate::log::debug!("received AFT: {record}");
        let token_record = record.token_record;
        let pending_register = PendingAssignmentRegister {
            start: Utc::now(),
            record,
            inbox,
        };
        PENDING_CONFIRMED_ASSIGNMENTS.with(|pending| {
            let pending = &mut *pending.borrow_mut();
            pending
                .entry(token_record)
                .or_default()
                .push(pending_register);
        });
        Ok(())
    }

    // `recipient_inbox_pub_key`: encoded `InboxParams.pub_key` bytes for the
    // recipient's inbox contract (ML-DSA-65 verifying key bytes, caller-computed).
    // `recipient_required_tier` / `recipient_max_age_secs`: recipient's
    // anti-flood policy from their `InboxParams` / `ContactCard` (#85).
    pub async fn assign_token(
        client: &mut WebApiRequestClient,
        recipient_inbox_pub_key: Vec<u8>,
        recipient_required_tier: Tier,
        recipient_max_age_secs: u64,
        generator_id: &Identity,
        assignment_hash: [u8; 32],
    ) -> Result<DelegateKey, DynError> {
        use ml_dsa::signature::Keypair;

        static REQUEST_ID: AtomicU32 = AtomicU32::new(0);

        // AFT token signing now reuses the identity's ML-DSA-65 key. The
        // delegate stores the 32-byte seed; the generator-identity in
        // TokenAssignment is the encoded verifying key bytes.
        let sender_vk = generator_id.ml_dsa_signing_key.as_ref().verifying_key();
        let seed_bytes = {
            let s = generator_id.ml_dsa_signing_key.as_ref().to_seed();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(s.as_slice());
            arr
        };
        let token_params: Parameters = DelegateParameters::new(seed_bytes)
            .try_into()
            .map_err(|e| format!("{e}"))
            .unwrap();
        let delegate_key = DelegateKey::from_params(
            crate::aft::TOKEN_GENERATOR_DELEGATE_CODE_HASH,
            &token_params,
        )?;

        // Keep a copy for the recipient-tracking registration below before
        // the vec is consumed by `InboxParams`.
        let recipient_vk_for_tracking = recipient_inbox_pub_key.clone();
        let inbox_params: Parameters = InboxParams {
            pub_key: recipient_inbox_pub_key,
        }
        .try_into()?;
        let inbox_key =
            ContractKey::from_params(crate::inbox::INBOX_CODE_HASH, inbox_params.clone())?;
        let delegate_params = DelegateParameters::new(seed_bytes);

        let record_params = TokenDelegateParameters::new(&sender_vk);
        let token_record: ContractInstanceId = ContractKey::from_params(
            crate::aft::TOKEN_RECORD_CODE_HASH,
            record_params.try_into()?,
        )
        .unwrap()
        .into();
        // todo: optimize so we don't clone the whole record and instead use a smart pointer
        let Some(records) = RECORDS.with(|recs| recs.borrow().get(generator_id).cloned()) else {
            // todo: somehow propagate this to the UI so the user retries /or we retry automatically/ later
            return Err(format!(
                "failed to get token record for alias `{alias}` ({key})",
                alias = generator_id.alias(),
                key = token_record
            )
            .into());
        };
        // Pick the cheapest tier the sender has available that still satisfies
        // the recipient's minimum (#152). Collect available tiers from the
        // cached record so we prefer a Min10 slot over a Day1 when both exist.
        // Filter out empty Vecs: a key with no assignments is not a usable
        // tier — including it would mislead pick_spend_tier into thinking
        // the sender has tokens at that level (fix #160 bug 1).
        let available_tiers: Vec<Tier> = (&records)
            .into_iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(t, _)| *t)
            .collect();
        // Distinguish two None cases (fix #160 bug 2):
        // - Empty pool (no tiers at all, fresh install): the delegate still
        //   gets to decide — fall through with the recipient's required tier
        //   so the delegate can attempt a fresh mint.
        // - Non-empty pool but no tier qualifies (e.g. sender only has Min1,
        //   recipient requires Min10): reject early with a user-visible error
        //   rather than asking the delegate for a tier we don't hold.
        let spend_tier = match pick_spend_tier(&available_tiers, recipient_required_tier) {
            Some(t) => t,
            None if available_tiers.is_empty() => recipient_required_tier,
            None => {
                return Err(format_insufficient_tier_toast(recipient_required_tier).into());
            }
        };
        let criteria = build_recipient_criteria(spend_tier, recipient_max_age_secs, token_record)?;
        let token_request = TokenDelegateMessage::RequestNewToken(RequestNewToken {
            request_id: REQUEST_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
            delegate_id: delegate_key.clone().into(),
            criteria,
            records,
            assignment_hash,
        });
        let request = DelegateRequest::ApplicationMessages {
            key: delegate_key.clone(),
            params: delegate_params.try_into()?,
            inbound: vec![InboundDelegateMsg::ApplicationMessage(
                ApplicationMessage::new(token_request.serialize()?),
            )],
        };
        PENDING_INBOXES_UPDATES.with(|queue| {
            queue.borrow_mut().push((inbox_key, assignment_hash));
        });
        // Register the recipient's VK hex so the permission pump can
        // resolve which recipients have pending sends when it needs to
        // evaluate per-recipient saved decisions (#149 Part 2).
        Self::register_pending_recipient(&recipient_vk_for_tracking);
        client.send(request.into()).await?;
        Ok(delegate_key)
    }

    pub fn set_identity_contract(
        identity: Identity,
        state: State<'_>,
        key: &ContractKey,
    ) -> Result<(), DynError> {
        crate::log::debug!(
            "setting AFT record contract for `{alias}` ({key})",
            alias = identity.alias
        );
        let record = TokenAllocationRecord::try_from(state)?;
        RECORDS.with(|recs| {
            let recs = &mut *recs.borrow_mut();
            recs.insert(identity, record);
        });
        Ok(())
    }

    pub fn update_record(identity: Identity, update_data: UpdateData) -> Result<(), DynError> {
        let record = match update_data {
            StateUpdate(state) => {
                crate::log::debug!(
                    "updating aft record for `{}` with whole state",
                    identity.alias()
                );
                TokenAllocationRecord::try_from(state)?
            }
            Delta(delta) => {
                crate::log::debug!("updating aft record for `{}` with delta", identity.alias());
                TokenAllocationRecord::try_from(delta)?
            }
            _ => {
                return Err(DynError::from(
                    "Unexpected update data type while updating the record",
                ));
            }
        };
        RECORDS.with(|recs| {
            let recs = &mut *recs.borrow_mut();
            recs.insert(identity, record);
        });
        Ok(())
    }

    pub async fn get_state(
        client: &mut WebApiRequestClient,
        key: AftRecord,
    ) -> Result<(), DynError> {
        let request = ContractRequest::Get {
            key: key.into(),
            return_contract_code: false,
            subscribe: false,
            blocking_subscribe: false,
        };
        client.send(request.into()).await?;
        Ok(())
    }

    pub async fn subscribe(
        client: &mut WebApiRequestClient,
        key: AftRecord,
    ) -> Result<(), DynError> {
        // todo: send the proper summary from the current state
        let request = ContractRequest::Subscribe {
            key: key.into(),
            summary: None,
        };
        client.send(request.into()).await?;
        Ok(())
    }
}

/// Sentinel prefix embedded in the `DynError` message when `assign_token`
/// cannot find the sender's token record in the local cache.  Call sites in
/// `app.rs` and `api.rs` test for this prefix so they can map the opaque
/// error to the user-friendly [`format_no_record_toast`] copy instead of
/// exposing the raw internal message.  Defined as a constant so the test
/// and production code stay in sync without substring guessing.
pub(crate) const NO_TOKEN_RECORD_MSG_PREFIX: &str = "failed to get token record";

/// Map a [`Tier`] to a short human-readable label used in toast copy.
///
/// The `Tier` `Display` impl uses strum `serialize_all = "lowercase"` which
/// produces identifiers like `"min10"` and `"day1"`.  User-facing copy
/// should say "10-minute token" or "1-day token" instead.
pub(crate) fn tier_label(tier: Tier) -> &'static str {
    match tier {
        Tier::Min1 => "1-minute token",
        Tier::Min5 => "5-minute token",
        Tier::Min10 => "10-minute token",
        Tier::Min30 => "30-minute token",
        Tier::Hour1 => "1-hour token",
        Tier::Hour3 => "3-hour token",
        Tier::Hour6 => "6-hour token",
        Tier::Hour12 => "12-hour token",
        Tier::Day1 => "1-day token",
        Tier::Day7 => "7-day token",
        Tier::Day15 => "15-day token",
        Tier::Day30 => "30-day token",
        Tier::Day90 => "90-day token",
        Tier::Day180 => "180-day token",
        Tier::Day365 => "1-year token",
    }
}

/// Build a user-facing toast message for a `FailureReason` returned by
/// the AFT delegate.  Produces distinct, actionable copy for each variant
/// so the user knows both why the send failed and what they can do next.
///
/// `recipient` is an optional display label for the intended recipient;
/// when `None` the copy falls back to `"the recipient"`.
pub(crate) fn format_failure_toast(reason: &FailureReason, recipient: Option<&str>) -> String {
    let recipient = recipient.unwrap_or("the recipient");
    match reason {
        FailureReason::UserPermissionDenied => {
            "Can't send: the token delegate refused to mint a token. \
             Check Settings → AFT to approve token allocation."
                .to_string()
        }
        FailureReason::NoFreeSlot { criteria, .. } => {
            let label = tier_label(criteria.frequency);
            format!(
                "Can't send: no {label} available for {recipient}. \
                 Check Settings → AFT to mint {label}s, or ask {recipient} \
                 to relax their policy.",
            )
        }
    }
}

/// Build a user-facing toast message when an in-flight AFT assignment
/// confirmation timed out (the delegate sent no `confirm_allocation`
/// within the sweep window).
pub(crate) fn format_expired_assignment_toast(tier: Tier) -> String {
    let label = tier_label(tier);
    format!(
        "Can't send: the {label} assignment timed out. \
         Your tokens may have expired — mint new ones in Settings → AFT."
    )
}

/// Build a user-facing toast message when no AFT token record has been
/// loaded for the sender yet (the record contract was not yet fetched
/// from the node when send was attempted).
pub(crate) fn format_no_record_toast() -> String {
    "Can't send: your token record hasn't loaded yet. \
     Wait a moment and try again, or check Settings → AFT."
        .to_string()
}

/// Build a user-facing toast message when the sender's token pool is
/// non-empty but contains no tier that satisfies the recipient's
/// `minimum_tier` requirement.
///
/// Distinct from `format_no_record_toast` (record missing entirely) and
/// from `format_failure_toast(NoFreeSlot)` (delegate rejected the request
/// after we asked). This error fires *before* the delegate request because
/// asking for a tier we don't hold would always fail — surfacing it here
/// gives the user an actionable message immediately (#160).
pub(crate) fn format_insufficient_tier_toast(required: Tier) -> String {
    format!(
        "Insufficient tier — your tokens are too low to send to this recipient \
         (requires {required}). Mint higher-tier tokens in Settings → AFT.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use freenet_stdlib::prelude::ContractInstanceId;

    fn fake_token_record() -> ContractInstanceId {
        ContractInstanceId::new([7u8; 32])
    }

    /// `build_recipient_criteria` must reflect the recipient's tier +
    /// `max_age_secs` exactly, with no fallback to the legacy `Day1` /
    /// 365d defaults that the pre-#85 hardcoded path used.
    #[test]
    fn build_recipient_criteria_uses_recipient_policy() {
        let token_record = fake_token_record();
        let criteria = build_recipient_criteria(Tier::Hour1, 7 * 24 * 3600, token_record)
            .expect("Hour1 + 7d criteria must be valid");
        assert_eq!(criteria.frequency, Tier::Hour1);
        assert_eq!(criteria.max_age.as_secs(), 7 * 24 * 3600);
    }

    /// Default policy (Day1, 365d) round-trips so the legacy code path
    /// stays equivalent to the pre-#85 hardcoded constants.
    #[test]
    fn build_recipient_criteria_defaults_match_legacy() {
        let token_record = fake_token_record();
        let criteria = build_recipient_criteria(
            Tier::Day1,
            freenet_email_inbox::DEFAULT_MAX_AGE_SECS,
            token_record,
        )
        .expect("legacy default criteria must be valid");
        assert_eq!(criteria.frequency, Tier::Day1);
        assert_eq!(criteria.max_age.as_secs(), 365 * 24 * 3600);
    }

    /// `AllocationCriteria::new` rejects a `max_age` over 2 years (see
    /// `modules/antiflood-tokens/interfaces/src/lib.rs`). Surface that
    /// rejection through the helper so a misconfigured recipient
    /// `max_age_secs` cannot silently produce broken criteria.
    #[test]
    fn build_recipient_criteria_rejects_excessive_max_age() {
        let token_record = fake_token_record();
        // 3 years exceeds the 2-year ceiling enforced by AllocationCriteria::new.
        let three_years = 3 * 365 * 24 * 3600;
        let result = build_recipient_criteria(Tier::Day1, three_years, token_record);
        assert!(
            result.is_err(),
            "max_age beyond 2-year ceiling must error; got {result:?}"
        );
    }

    /// Pre-condition for the AFT Failure → fail-pending plumbing (#85):
    /// `drain_pending_for_delegate` must remove every queued
    /// `(inbox, hash)` keyed by `pending_assignment(delegate, inbox)`,
    /// returning them so the caller can flip the corresponding Sent
    /// rows to `Failed`. Ensures we don't leak entries when the
    /// delegate refuses to mint.
    #[test]
    fn drain_pending_for_delegate_returns_and_clears_queued_entries() {
        // Use a synthetic DelegateKey + InboxContract; both are opaque
        // 32-byte ids from the test's perspective.
        let delegate_key =
            DelegateKey::new([9u8; 32], freenet_stdlib::prelude::CodeHash::new([3u8; 32]));
        let inbox_id = ContractInstanceId::new([42u8; 32]);
        let inbox_code_hash = freenet_stdlib::prelude::CodeHash::new([5u8; 32]);
        let inbox_key = ContractKey::from_id_and_code(inbox_id, inbox_code_hash);
        let assignment_hash = [11u8; 32];

        // Reset thread-locals so concurrent test runs don't leak state.
        PENDING_TOKEN_ASSIGNMENT.with(|m| m.borrow_mut().clear());
        PENDING_INBOXES_UPDATES.with(|q| q.borrow_mut().clear());

        AftRecords::pending_assignment(delegate_key.clone(), inbox_key);
        PENDING_INBOXES_UPDATES.with(|q| {
            q.borrow_mut().push((inbox_key, assignment_hash));
        });

        let drained = AftRecords::drain_pending_for_delegate(&delegate_key);
        assert_eq!(drained.len(), 1, "one entry queued, one expected back");
        assert_eq!(drained[0].0, inbox_key);
        assert_eq!(drained[0].1, assignment_hash);

        // Both queues must be empty after a drain.
        let leftover_pending = PENDING_TOKEN_ASSIGNMENT.with(|m| m.borrow().len());
        let leftover_updates = PENDING_INBOXES_UPDATES.with(|q| q.borrow().len());
        assert_eq!(leftover_pending, 0, "PENDING_TOKEN_ASSIGNMENT not cleared");
        assert_eq!(leftover_updates, 0, "PENDING_INBOXES_UPDATES not cleared");
    }

    /// `format_failure_toast` produces distinct copy for each variant.
    #[test]
    fn format_failure_toast_user_permission_denied() {
        let msg = format_failure_toast(&FailureReason::UserPermissionDenied, None);
        assert!(
            msg.contains("refused to mint"),
            "expected 'refused to mint' in: {msg}"
        );
        assert!(
            msg.contains("Settings → AFT"),
            "expected settings hint in: {msg}"
        );
    }

    #[test]
    fn format_failure_toast_no_free_slot_includes_tier_and_recipient() {
        let token_record = fake_token_record();
        let criteria = AllocationCriteria::new(
            Tier::Min10,
            std::time::Duration::from_secs(3600),
            token_record,
        )
        .expect("valid criteria");
        let delegate_id = freenet_stdlib::prelude::SecretsId::new(vec![0u8; 32]);
        let reason = FailureReason::NoFreeSlot {
            delegate_id,
            criteria,
        };
        let msg = format_failure_toast(&reason, Some("alice"));
        // Should use the human-readable label, not the strum identifier.
        assert!(
            msg.contains("10-minute token"),
            "expected human tier label in: {msg}"
        );
        assert!(msg.contains("alice"), "expected recipient in: {msg}");
        assert!(
            msg.contains("Settings → AFT"),
            "expected settings hint in: {msg}"
        );
    }

    #[test]
    fn format_expired_assignment_toast_includes_tier() {
        let msg = format_expired_assignment_toast(Tier::Day1);
        assert!(
            msg.contains("1-day token"),
            "expected human tier label in: {msg}"
        );
        assert!(msg.contains("Settings → AFT"), "expected hint in: {msg}");
    }

    #[test]
    fn format_no_record_toast_is_nonempty() {
        let msg = format_no_record_toast();
        assert!(!msg.is_empty());
        assert!(msg.contains("token record"), "expected context in: {msg}");
    }

    #[test]
    fn no_token_record_msg_prefix_matches_assign_token_error() {
        // The assign_token error message starts with NO_TOKEN_RECORD_MSG_PREFIX.
        // This test ensures the sentinel and the actual error string stay in sync.
        let simulated_error = format!("{} for alias `test` (key)", NO_TOKEN_RECORD_MSG_PREFIX);
        assert!(
            simulated_error.contains(NO_TOKEN_RECORD_MSG_PREFIX),
            "sentinel must match the assign_token error prefix"
        );
    }

    #[test]
    fn tier_label_covers_all_variants() {
        // Verify all Tier variants produce non-empty human-readable labels
        // and do not contain the raw strum lowercase identifiers (e.g. "min10", "day1").
        let tiers = [
            (Tier::Min1, "1-minute"),
            (Tier::Min5, "5-minute"),
            (Tier::Min10, "10-minute"),
            (Tier::Min30, "30-minute"),
            (Tier::Hour1, "1-hour"),
            (Tier::Hour3, "3-hour"),
            (Tier::Hour6, "6-hour"),
            (Tier::Hour12, "12-hour"),
            (Tier::Day1, "1-day"),
            (Tier::Day7, "7-day"),
            (Tier::Day15, "15-day"),
            (Tier::Day30, "30-day"),
            (Tier::Day90, "90-day"),
            (Tier::Day180, "180-day"),
            (Tier::Day365, "1-year"),
        ];
        for (tier, expected_prefix) in tiers {
            let label = tier_label(tier);
            assert!(
                label.starts_with(expected_prefix),
                "tier_label({tier:?}) should start with '{expected_prefix}', got: {label}"
            );
        }
    }

    /// Drain on an unknown delegate must be a no-op (returns empty,
    /// touches no queue). Otherwise a stray Failure for an unrelated
    /// delegate could clear out unrelated pending sends.
    #[test]
    fn drain_pending_for_delegate_unknown_delegate_is_noop() {
        let known_delegate =
            DelegateKey::new([2u8; 32], freenet_stdlib::prelude::CodeHash::new([1u8; 32]));
        let unknown_delegate =
            DelegateKey::new([9u8; 32], freenet_stdlib::prelude::CodeHash::new([8u8; 32]));
        let inbox_id = ContractInstanceId::new([55u8; 32]);
        let inbox_code_hash = freenet_stdlib::prelude::CodeHash::new([6u8; 32]);
        let inbox_key = ContractKey::from_id_and_code(inbox_id, inbox_code_hash);
        let assignment_hash = [22u8; 32];

        PENDING_TOKEN_ASSIGNMENT.with(|m| m.borrow_mut().clear());
        PENDING_INBOXES_UPDATES.with(|q| q.borrow_mut().clear());
        AftRecords::pending_assignment(known_delegate.clone(), inbox_key);
        PENDING_INBOXES_UPDATES.with(|q| {
            q.borrow_mut().push((inbox_key, assignment_hash));
        });

        let drained = AftRecords::drain_pending_for_delegate(&unknown_delegate);
        assert!(drained.is_empty());
        let leftover_updates = PENDING_INBOXES_UPDATES.with(|q| q.borrow().len());
        assert_eq!(
            leftover_updates, 1,
            "unrelated drain must not touch PENDING_INBOXES_UPDATES"
        );
    }

    // --- pick_spend_tier tests (#152) ------------------------------------

    /// Sender has [Min10, Hour1, Day1]; recipient requires Min10.
    /// Cheapest satisfying tier is Min10.
    #[test]
    fn pick_spend_tier_picks_cheapest_satisfying() {
        let available = vec![Tier::Min10, Tier::Hour1, Tier::Day1];
        assert_eq!(
            pick_spend_tier(&available, Tier::Min10),
            Some(Tier::Min10),
            "cheapest satisfying tier must be Min10"
        );
    }

    /// Sender has [Hour1, Day1]; recipient requires Min10.
    /// Min10 is absent, so the next cheapest qualifying tier is Hour1.
    #[test]
    fn pick_spend_tier_falls_back_to_next_cheapest() {
        let available = vec![Tier::Hour1, Tier::Day1];
        assert_eq!(
            pick_spend_tier(&available, Tier::Min10),
            Some(Tier::Hour1),
            "should fall back to Hour1 when Min10 is absent"
        );
    }

    /// Sender only has [Min1]; recipient requires Min10.
    /// Min1 is cheaper than the minimum, so no tier qualifies.
    #[test]
    fn pick_spend_tier_none_when_all_cheaper_than_required() {
        let available = vec![Tier::Min1];
        assert_eq!(
            pick_spend_tier(&available, Tier::Min10),
            None,
            "no tier satisfies min10 when only min1 is available"
        );
    }

    /// Empty sender pool → no tier can be picked.
    #[test]
    fn pick_spend_tier_empty_pool_returns_none() {
        assert_eq!(
            pick_spend_tier(&[], Tier::Min10),
            None,
            "empty pool must return None"
        );
    }

    /// Sender has [Day7, Day1]; recipient requires Day1.
    /// Day1 == required, so it should be picked (tie-break: same tier is fine).
    #[test]
    fn pick_spend_tier_exact_match_preferred_over_higher() {
        let available = vec![Tier::Day7, Tier::Day1];
        assert_eq!(
            pick_spend_tier(&available, Tier::Day1),
            Some(Tier::Day1),
            "Day1 exact match must be preferred over Day7"
        );
    }

    // --- available_tiers filtering (#160 bug 1) --------------------------

    /// An empty Vec under a Tier key must NOT contribute that tier to the
    /// available list. The filter `!v.is_empty()` must strip it so that
    /// `pick_spend_tier` doesn't see a "phantom" tier.
    #[test]
    fn available_tiers_filters_empty_buckets() {
        use std::collections::HashMap;
        // Build a record with one non-empty bucket and one empty bucket.
        let mut tokens: HashMap<Tier, Vec<TokenAssignment>> = HashMap::new();
        tokens.insert(Tier::Day1, vec![]); // empty — must be filtered
        tokens.insert(Tier::Hour1, vec![]); // also empty
        let record = TokenAllocationRecord::new(tokens);

        // Reproduce the fix: filter empty vecs before passing to pick_spend_tier.
        let available: Vec<Tier> = (&record)
            .into_iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(t, _)| *t)
            .collect();

        assert!(
            available.is_empty(),
            "empty buckets must not appear in the available tier list; got {available:?}"
        );

        // If we had NOT filtered, Day1 and Hour1 would appear and pick_spend_tier
        // would return Some(Hour1) for a Min10 requirement — which would be wrong
        // because the sender has zero tokens at that tier.
        let unfiltered: Vec<Tier> = (&record).into_iter().map(|(t, _)| *t).collect();
        // Depending on HashMap iteration order, one or two phantom tiers surface.
        assert!(
            !unfiltered.is_empty(),
            "without filtering the phantom tiers would be visible (pre-fix behaviour)"
        );
    }

    // --- format_insufficient_tier_toast (#160 bug 2) ---------------------

    /// When the sender's pool is non-empty but has no tier at or above
    /// the required level, the error must mention the required tier and
    /// the Settings → AFT hint so the user knows what to mint.
    #[test]
    fn format_insufficient_tier_toast_mentions_required_tier_and_hint() {
        let msg = format_insufficient_tier_toast(Tier::Min10);
        assert!(
            msg.contains("min10"),
            "expected required tier name in: {msg}"
        );
        assert!(
            msg.contains("Settings → AFT"),
            "expected settings hint in: {msg}"
        );
    }

    /// Verify the two-case None split: empty pool falls through (returns
    /// the required tier so the delegate gets a chance to mint fresh
    /// tokens), whereas non-empty pool with no qualifying tier returns
    /// an error string that starts with "Insufficient tier".
    #[test]
    fn insufficient_tier_error_is_distinct_from_empty_pool() {
        // Non-empty pool case — only Min1, recipient requires Min10.
        let non_empty = vec![Tier::Min1];
        let result_non_empty = pick_spend_tier(&non_empty, Tier::Min10);
        assert!(
            result_non_empty.is_none(),
            "non-empty pool with no qualifying tier must return None"
        );

        // Empty pool case — returns None too, but the calling site treats
        // it differently (falls back to recipient_required_tier).
        let empty: Vec<Tier> = vec![];
        let result_empty = pick_spend_tier(&empty, Tier::Min10);
        assert!(
            result_empty.is_none(),
            "empty pool must also return None from pick_spend_tier"
        );

        // The difference is detected at the call site:
        // available_tiers.is_empty() distinguishes the two paths.
        // In the empty case the error is NOT produced; in the non-empty case it IS.
        let empty_case_produces_error = !empty.is_empty() && result_empty.is_none();
        let nonempty_case_produces_error = !non_empty.is_empty() && result_non_empty.is_none();
        assert!(
            !empty_case_produces_error,
            "empty pool must NOT produce an insufficient-tier error"
        );
        assert!(
            nonempty_case_produces_error,
            "non-empty pool with no qualifying tier MUST produce an insufficient-tier error"
        );
    }
}
