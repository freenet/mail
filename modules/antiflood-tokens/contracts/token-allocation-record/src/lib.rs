use freenet_aft_interface::{
    AllocationError, TokenAllocationRecord, TokenAssignment, TokenDelegateParameters,
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
                            log_succesful_ver(
                                &params.generator_public_key,
                                "update state (delta)",
                            )
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
        _summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        let assigned_tokens = TokenAllocationRecord::try_from(state)?;
        // FIXME: this will be broken because problem with node
        //let delta = assigned_tokens.delta(&summary);
        assigned_tokens.try_into()
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
            Some(list) => {
                if list.binary_search(&assignment).is_err() {
                    match assignment.is_valid(key) {
                        Ok(_) => {
                            list.push(assignment);
                            list.sort_unstable();
                            Ok(())
                        }
                        Err(err) => Err(AllocationError::invalid_assignment(assignment, err)),
                    }
                } else {
                    Err(AllocationError::allocated_slot(&assignment))
                }
            }
            None => {
                self.insert(assignment.tier, vec![assignment]);
                Ok(())
            }
        }
    }
}
