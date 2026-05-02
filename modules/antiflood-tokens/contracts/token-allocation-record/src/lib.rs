use freenet_aft_interface::{
    AllocationError, TokenAllocationRecord, TokenAllocationSummary, TokenAssignment,
    TokenDelegateParameters,
};
use freenet_stdlib::prelude::*;
use ml_dsa::{MlDsa65, VerifyingKey as MlDsaVerifyingKey};

pub struct TokenAllocContract;

fn decode_vk(
    params: &TokenDelegateParameters,
) -> Result<MlDsaVerifyingKey<MlDsa65>, ContractError> {
    params.generator_vk().ok_or_else(|| {
        ContractError::Deser(
            "TokenDelegateParameters.generator_public_key is not a valid ML-DSA-65 verifying key"
                .into(),
        )
    })
}

#[contract]
impl ContractInterface for TokenAllocContract {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        let assigned_tokens = TokenAllocationRecord::try_from(state)?;
        let params = TokenDelegateParameters::try_from(parameters)?;
        let verifying_key = decode_vk(&params)?;
        for (_tier, assignments) in (&assigned_tokens).into_iter() {
            for assignment in assignments {
                if assignment.is_valid(&verifying_key).is_err() {
                    log_verification_err(&params.generator_public_key, "validate state");
                    return Ok(ValidateResult::Invalid);
                }
            }
        }
        Ok(ValidateResult::Valid)
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let mut assigned_tokens = TokenAllocationRecord::try_from(state)?;
        let params = TokenDelegateParameters::try_from(parameters)?;
        let verifying_key = decode_vk(&params)?;
        for update in data {
            match update {
                UpdateData::State(s) => {
                    let new_assigned_tokens = TokenAllocationRecord::try_from(s)?;
                    assigned_tokens
                        .merge(new_assigned_tokens, &verifying_key)
                        .map_err(|err| {
                            tracing::error!("{err}");
                            log_verification_err(
                                &params.generator_public_key,
                                "update state (state)",
                            );
                            ContractError::InvalidUpdateWithInfo {
                                reason: format!("{err}"),
                            }
                        })?;
                    log_succesful_ver(&params.generator_public_key, "update state (state)")
                }
                UpdateData::Delta(d) => {
                    // Cross-node propagation occasionally re-wraps a full
                    // TokenAllocationRecord (multi-assignment) as a Delta —
                    // see freenet/mail#71. Try the single-assignment shape
                    // first (the sender's intent at ui/src/aft.rs), then
                    // fall back to whole-record merge so we don't reject
                    // legitimate state under a Delta envelope.
                    match TokenAssignment::try_from(d.clone()) {
                        Ok(new_assigned_token) => {
                            assigned_tokens
                                .append(new_assigned_token, &verifying_key)
                                .map_err(|err| {
                                    tracing::error!("{err}");
                                    log_verification_err(
                                        &params.generator_public_key,
                                        "update state (delta)",
                                    );
                                    ContractError::InvalidUpdateWithInfo {
                                        reason: format!("{err}"),
                                    }
                                })?;
                            log_succesful_ver(&params.generator_public_key, "update state (delta)")
                        }
                        Err(_) => {
                            let new_assigned_tokens = TokenAllocationRecord::try_from(d)?;
                            assigned_tokens
                                .merge(new_assigned_tokens, &verifying_key)
                                .map_err(|err| {
                                    tracing::error!("{err}");
                                    log_verification_err(
                                        &params.generator_public_key,
                                        "update state (delta-as-record)",
                                    );
                                    ContractError::InvalidUpdateWithInfo {
                                        reason: format!("{err}"),
                                    }
                                })?;
                            log_succesful_ver(
                                &params.generator_public_key,
                                "update state (delta-as-record)",
                            )
                        }
                    }
                }
                UpdateData::StateAndDelta { state, delta } => {
                    let new_assigned_tokens = TokenAllocationRecord::try_from(state)?;
                    assigned_tokens
                        .merge(new_assigned_tokens, &verifying_key)
                        .map_err(|err| {
                            tracing::error!("{err}");
                            log_verification_err(
                                &params.generator_public_key,
                                "update state (state and delta)",
                            );
                            ContractError::InvalidUpdateWithInfo {
                                reason: format!("{err}"),
                            }
                        })?;
                    let new_assigned_token = TokenAssignment::try_from(delta)?;
                    assigned_tokens
                        .append(new_assigned_token, &verifying_key)
                        .map_err(|err| {
                            tracing::error!("{err}");
                            log_verification_err(
                                &params.generator_public_key,
                                "update state (state and delta)",
                            );
                            ContractError::InvalidUpdateWithInfo {
                                reason: format!("{err}"),
                            }
                        })?;
                    log_succesful_ver(
                        &params.generator_public_key,
                        "update state (state and delta)",
                    )
                }
                _ => unreachable!(),
            }
        }
        let update = assigned_tokens.try_into()?;
        Ok(UpdateModification::valid(update))
    }

    fn summarize_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        let assigned_tokens = TokenAllocationRecord::try_from(state)?;
        let summary = assigned_tokens.summarize();
        summary.try_into()
    }

    fn get_state_delta(
        _parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        let assigned_tokens = TokenAllocationRecord::try_from(state)?;
        // The previous implementation returned the whole record on every
        // request because `delta()` was disabled with a "FIXME: broken
        // because problem with node" comment. That meant cross-node
        // broadcast always sent the full record — which the receiver's
        // `update_state` Delta arm decoded via the "delta-as-record"
        // fallback, hit a slot collision on the sender's already-known
        // assignments, and forced a wasted ResyncRequest round-trip on
        // every send (#71, #72).
        //
        // Decoding the summary failure is non-fatal — we still need to
        // return *something* the caller can decode — so on a malformed
        // summary fall through to the whole record, matching the legacy
        // behavior that the ecosystem learned to accept via the
        // "delta-as-record" fallback in `update_state`.
        let delta_record = match TokenAllocationSummary::try_from(summary) {
            Ok(parsed) => assigned_tokens.delta(&parsed),
            Err(_) => assigned_tokens,
        };
        delta_record.try_into()
    }
}

#[allow(unused)]
fn log_succesful_ver(pub_key: &[u8], target: &str) {
    #[cfg(target_family = "wasm")]
    {
        let prefix_len = pub_key.len().min(16);
        let _pk_prefix = hex_prefix(&pub_key[..prefix_len]);
        // freenet_stdlib::log::info(&format!(
        //     "successful verification with key prefix: {_pk_prefix} @ {target}"
        // ));
    }
}

#[allow(unused)]
fn log_verification_err(pub_key: &[u8], target: &str) {
    #[cfg(target_family = "wasm")]
    {
        let prefix_len = pub_key.len().min(16);
        let pk_prefix = hex_prefix(&pub_key[..prefix_len]);
        freenet_stdlib::log::info(&format!(
            "erroneous verification with key prefix: {pk_prefix} @ {target}"
        ));
    }
}

#[cfg(target_family = "wasm")]
fn hex_prefix(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

trait TokenAllocationRecordExt {
    fn merge(
        &mut self,
        other: Self,
        key: &MlDsaVerifyingKey<MlDsa65>,
    ) -> Result<(), AllocationError>;
    fn append(
        &mut self,
        assignment: TokenAssignment,
        params: &MlDsaVerifyingKey<MlDsa65>,
    ) -> Result<(), AllocationError>;
}

impl TokenAllocationRecordExt for TokenAllocationRecord {
    fn merge(
        &mut self,
        other: Self,
        key: &MlDsaVerifyingKey<MlDsa65>,
    ) -> Result<(), AllocationError> {
        for (_, assignments) in other.into_iter() {
            for assignment in assignments {
                self.append(assignment, key)?;
            }
        }
        Ok(())
    }

    fn append(
        &mut self,
        assignment: TokenAssignment,
        key: &MlDsaVerifyingKey<MlDsa65>,
    ) -> Result<(), AllocationError> {
        match self.get_mut_tier(&assignment.tier) {
            Some(list) => match list.binary_search(&assignment) {
                Err(_) => match assignment.is_valid(key) {
                    Ok(_) => {
                        list.push(assignment);
                        list.sort_unstable();
                        Ok(())
                    }
                    Err(err) => Err(AllocationError::invalid_assignment(assignment, err)),
                },
                Ok(idx) => {
                    // `binary_search` matches via the `Ord` impl, which keys
                    // only on `time_slot` — two distinct assignments that
                    // happen to share a slot will both compare-equal even
                    // though `TokenAssignment` implements full structural
                    // equality on all fields. Distinguish:
                    //
                    //   * existing == incoming (byte-identical including
                    //     signature) → idempotent re-broadcast, return Ok.
                    //     This is the common case under cross-node propagation
                    //     where the sender's burn arrives both as the
                    //     originating UPDATE delta and again as part of the
                    //     full record state via ResyncResponse, see #72.
                    //   * existing != incoming → genuine slot collision; the
                    //     contract's anti-flood guarantee requires rejection.
                    if list[idx] == assignment {
                        Ok(())
                    } else {
                        Err(AllocationError::allocated_slot(&assignment))
                    }
                }
            },
            None => {
                self.insert(assignment.tier, vec![assignment]);
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use freenet_aft_interface::{DelegateParameters, Tier};

    fn signing_key(seed: u8) -> ml_dsa::SigningKey<ml_dsa::MlDsa65> {
        DelegateParameters::new([seed; 32]).signing_key()
    }

    fn verifying_key(seed: u8) -> MlDsaVerifyingKey<MlDsa65> {
        DelegateParameters::new([seed; 32]).verifying_key()
    }

    /// Build a signed `TokenAssignment` for unit-testing `append`. Only the
    /// fields participating in the slot-collision check matter; the record
    /// id, tier, and assignment_hash are stable per call so two builds with
    /// the same args produce byte-identical assignments.
    fn make_assignment(
        sk: &ml_dsa::SigningKey<ml_dsa::MlDsa65>,
        vk_seed: u8,
        tier: Tier,
        time_slot: chrono::DateTime<Utc>,
        assignment_hash: [u8; 32],
    ) -> TokenAssignment {
        use ml_dsa::signature::Signer;
        let to_sign = TokenAssignment::signature_content(&time_slot, tier, &assignment_hash);
        let signature: ml_dsa::Signature<ml_dsa::MlDsa65> = sk.sign(&to_sign);
        TokenAssignment {
            tier,
            time_slot,
            generator: verifying_key(vk_seed).encode().to_vec(),
            signature: signature.encode().to_vec(),
            assignment_hash,
            token_record: ContractInstanceId::new([7u8; 32]),
        }
    }

    /// Regression for #72: a duplicate `append` of a byte-identical
    /// assignment must succeed (idempotent), not return `allocated_slot`.
    /// Previously every cross-node delivery wasted a ResyncRequest because
    /// the sender's burn arrived twice (once via the originating UPDATE
    /// delta, once via the broadcast/ResyncResponse fan-out) and the second
    /// arrival was rejected as a slot collision.
    #[test]
    fn append_is_idempotent_for_byte_identical_assignment() {
        let sk = signing_key(0xA1);
        let vk = verifying_key(0xA1);
        let slot = Utc.with_ymd_and_hms(2026, 5, 3, 0, 0, 0).unwrap();
        let assignment = make_assignment(&sk, 0xA1, Tier::Day1, slot, [9u8; 32]);

        let mut record = TokenAllocationRecord::new(std::collections::HashMap::new());
        record
            .append(assignment.clone(), &vk)
            .expect("first append");
        record
            .append(assignment.clone(), &vk)
            .expect("second append must be idempotent (#72)");

        // Record still holds exactly one entry — idempotent, not duplicated.
        let assignments_in_tier: Vec<_> = (&record).into_iter().collect();
        assert_eq!(assignments_in_tier.len(), 1);
        assert_eq!(assignments_in_tier[0].1.len(), 1);
    }

    /// A different assignment occupying the same `time_slot` must still be
    /// rejected — the anti-flood guarantee depends on it. The idempotency
    /// fix only covers byte-identical re-broadcast.
    #[test]
    fn append_rejects_distinct_assignment_at_same_slot() {
        let sk = signing_key(0xB2);
        let vk = verifying_key(0xB2);
        let slot = Utc.with_ymd_and_hms(2026, 5, 3, 0, 0, 0).unwrap();

        let first = make_assignment(&sk, 0xB2, Tier::Day1, slot, [1u8; 32]);
        // Same slot, different assignment_hash → byte-different but
        // compares equal under the slot-only `Ord` impl.
        let second = make_assignment(&sk, 0xB2, Tier::Day1, slot, [2u8; 32]);

        let mut record = TokenAllocationRecord::new(std::collections::HashMap::new());
        record.append(first, &vk).expect("first append");
        let err = record
            .append(second, &vk)
            .expect_err("distinct assignment at same slot must be rejected");
        assert!(
            format!("{err}").contains("already been allocated"),
            "expected slot-collision error, got: {err}"
        );
    }

    /// Regression for #71: `get_state_delta` previously returned the
    /// whole record on every call (FIXME-disabled `delta()`). With a
    /// summary that already covers the existing assignments, the delta
    /// must be empty so cross-node broadcast doesn't re-send known state
    /// (which then triggered the slot-collision noise + ResyncRequest
    /// fallback round-trip on every send).
    #[test]
    fn get_state_delta_returns_only_new_assignments_vs_summary() {
        use chrono::TimeZone;
        let sk = signing_key(0xC3);
        let vk = verifying_key(0xC3);
        let params: Parameters<'static> = TokenDelegateParameters::new(&vk)
            .try_into()
            .expect("params");

        let slot = Utc.with_ymd_and_hms(2026, 5, 3, 0, 0, 0).unwrap();
        let assignment = make_assignment(&sk, 0xC3, Tier::Day1, slot, [9u8; 32]);

        let mut tokens = std::collections::HashMap::new();
        tokens.insert(Tier::Day1, vec![assignment.clone()]);
        let record = TokenAllocationRecord::new(tokens);
        let state: State<'static> = record.clone().try_into().expect("state");

        // Summary that already contains the assignment — delta must be empty.
        let summary: StateSummary<'static> = record.summarize().try_into().expect("summary");
        let delta = TokenAllocContract::get_state_delta(params.clone(), state.clone(), summary)
            .expect("get_state_delta with full summary");
        let decoded_delta = TokenAllocationRecord::try_from(delta).expect("decode delta");
        let assignments_in_delta: Vec<_> = (&decoded_delta)
            .into_iter()
            .flat_map(|(_, v)| v.iter().cloned())
            .collect();
        assert!(
            assignments_in_delta.is_empty(),
            "delta against a summary covering all assignments must be empty; \
             got {} assignments",
            assignments_in_delta.len()
        );

        // Empty summary — delta must contain the assignment so cold-cache
        // peers can still catch up. Build one via an empty record's
        // `summarize()` (no public constructor on the summary type).
        let empty_record = TokenAllocationRecord::new(std::collections::HashMap::new());
        let empty_summary: StateSummary<'static> =
            empty_record.summarize().try_into().expect("empty summary");
        let delta_full =
            TokenAllocContract::get_state_delta(params, state, empty_summary).expect("delta");
        let decoded_full = TokenAllocationRecord::try_from(delta_full).expect("decode full delta");
        let full_assignments: Vec<_> = (&decoded_full)
            .into_iter()
            .flat_map(|(_, v)| v.iter().cloned())
            .collect();
        assert_eq!(full_assignments, vec![assignment]);
    }
}
