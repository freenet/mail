use std::sync::atomic::AtomicU32;
use std::{cell::RefCell, collections::HashMap};

use chrono::{DateTime, Utc};
use freenet_aft_interface::{
    AllocationCriteria, DelegateParameters, RequestNewToken, Tier, TokenAllocationRecord,
    TokenAllocationSummary, TokenAssignment, TokenDelegateMessage, TokenDelegateParameters,
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
        let alias = identity.alias();
        crate::log::debug!(
            "subscribing to AFT updates for `{contract_key}`, belonging to alias `{alias}`"
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

        let inbox_params: Parameters = InboxParams {
            pub_key: recipient_inbox_pub_key,
            required_tier: recipient_required_tier,
            max_age_secs: recipient_max_age_secs,
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
        let criteria = build_recipient_criteria(
            recipient_required_tier,
            recipient_max_age_secs,
            token_record,
        )?;
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
}
