//! Freenet Mail's inbox contract, second generation.
//!
//! The state is a set of mail waiting to be drained, plus the owner's record,
//! a signed clock and the pass bookkeeping. No public field names a sender.
//!
//! `merge::merge` is the contract: `update_state` calls it on the current state
//! and the update, and `validate_state` asks whether a state is a fixed point
//! of it, so there is one set of rules and no second path to keep in step.
//!
//! Contracts have no clock and this one has no related contracts: the rules are
//! a function of the inputs, and time is the owner's signed `owner_time`.

pub mod merge;
#[cfg(feature = "plausible-mutants")]
pub mod mutant;

// The test seam swaps rules on a thread-local switch. Nothing turns it on in a
// contract, but a WASM build with it would carry its code, so none may exist.
#[cfg(all(feature = "plausible-mutants", target_arch = "wasm32"))]
compile_error!("the plausible-mutants test seam is not part of the contract");
pub mod signed;
pub mod sync;
pub mod types;

use freenet_stdlib::prelude::*;

use crate::merge::{Rules, merge};
use crate::types::{CallCounts, InboxDelta, InboxState, Malformed, decode, encode};

/// Version byte of the contract parameters.
const PARAMS_VERSION: u8 = 2;
/// `0x02 ‖ addr24 ‖ ghost_master32`
const PARAMS_LEN: usize = 57;

/// The contract parameters: whose inbox, and whose Ghost Keys it accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    pub addr: [u8; 24],
    pub ghost_master: [u8; 32],
}

impl Params {
    pub fn parse(bytes: &[u8]) -> Result<Self, Malformed> {
        if bytes.len() != PARAMS_LEN || bytes[0] != PARAMS_VERSION {
            return Err(Malformed("parameters"));
        }
        let mut addr = [0u8; 24];
        let mut ghost_master = [0u8; 32];
        addr.copy_from_slice(&bytes[1..25]);
        ghost_master.copy_from_slice(&bytes[25..]);
        Ok(Self { addr, ghost_master })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PARAMS_LEN);
        out.push(PARAMS_VERSION);
        out.extend_from_slice(&self.addr);
        out.extend_from_slice(&self.ghost_master);
        out
    }
}

fn refused(reason: Malformed) -> ContractError {
    ContractError::InvalidUpdateWithInfo {
        reason: reason.0.to_string(),
    }
}

/// `validate_state` under `rules`: canonical, and a fixed point of the merge.
pub fn is_valid(rules: &Rules, params: &Params, state: &[u8]) -> bool {
    let Ok(decoded) = decode::<InboxState>(state) else {
        return false;
    };
    match merge(rules, params, vec![decoded.clone().into()]) {
        Ok(merged) => merged == decoded,
        Err(_) => false,
    }
}

/// `update_state` under `rules`: the merged state's encoding.
pub fn apply(
    rules: &Rules,
    params: &Params,
    state: &[u8],
    data: Vec<UpdateData<'_>>,
) -> Result<Vec<u8>, ContractError> {
    let current = decode::<InboxState>(state).map_err(refused)?;
    let mut parts = Parts {
        parts: vec![current.into()],
        // The held state is valid, so within the bounds alone; what the caller
        // sends is counted together (decision 16).
        sent: CallCounts::default(),
    };
    for update in data {
        match update {
            UpdateData::State(s) => parts.push_state(s.as_ref())?,
            UpdateData::Delta(d) => parts.push_delta(d.as_ref())?,
            UpdateData::StateAndDelta { state, delta } => {
                parts.push_state(state.as_ref())?;
                parts.push_delta(delta.as_ref())?;
            }
            // Refused rather than ignored: this contract never asks for one.
            _ => return Err(ContractError::InvalidUpdate),
        }
    }
    let merged = merge(rules, params, parts.parts).map_err(refused)?;
    Ok(encode(&merged))
}

struct Parts {
    parts: Vec<InboxDelta>,
    sent: CallCounts,
}

impl Parts {
    fn push(&mut self, part: InboxDelta) -> Result<(), ContractError> {
        self.sent.add(&part).map_err(refused)?;
        self.parts.push(part);
        Ok(())
    }

    fn push_state(&mut self, bytes: &[u8]) -> Result<(), ContractError> {
        self.push(decode::<InboxState>(bytes).map_err(refused)?.into())
    }

    fn push_delta(&mut self, bytes: &[u8]) -> Result<(), ContractError> {
        // Zero bytes is the protocol's "nothing to send".
        if bytes.is_empty() {
            return Ok(());
        }
        self.push(decode::<InboxDelta>(bytes).map_err(refused)?)
    }
}

pub struct Inbox;

#[cfg_attr(feature = "contract", contract)]
impl ContractInterface for Inbox {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        let params = Params::parse(parameters.as_ref())
            .map_err(|e| ContractError::Other(e.0.to_string()))?;
        Ok(if is_valid(&Rules::V1, &params, state.as_ref()) {
            ValidateResult::Valid
        } else {
            ValidateResult::Invalid
        })
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let params = Params::parse(parameters.as_ref())
            .map_err(|e| ContractError::Other(e.0.to_string()))?;
        let merged = apply(&Rules::V1, &params, state.as_ref(), data)?;
        Ok(UpdateModification::valid(State::from(merged)))
    }

    fn summarize_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        let state = decode::<InboxState>(state.as_ref())
            .map_err(|e| ContractError::Deser(e.0.to_string()))?;
        Ok(StateSummary::from(sync::summarize(&state)))
    }

    fn get_state_delta(
        _parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        let state = decode::<InboxState>(state.as_ref())
            .map_err(|e| ContractError::Deser(e.0.to_string()))?;
        let delta = sync::delta(&state, summary.as_ref())
            .map_err(|e| ContractError::Deser(e.0.to_string()))?;
        Ok(StateDelta::from(delta))
    }
}
