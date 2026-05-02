use std::collections::HashMap;
use std::fmt::Display;

use chrono::{DateTime, Datelike, Duration, NaiveDate, SubsecRound, Timelike, Utc};
use freenet_stdlib::prelude::*;
use ml_dsa::{
    EncodedVerifyingKey, MlDsa65, VerifyingKey as MlDsaVerifyingKey, signature::Verifier,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use strum::Display;

/// FIPS 204 encoded ML-DSA-65 verifying key bytes (1952 bytes). Used as the
/// generator identity in token assignments; stored as `Vec<u8>` so the type
/// participates in `Hash + Eq + Clone` natively without a custom serde impl.
pub type Assignee = Vec<u8>;

/// Decode encoded ML-DSA-65 verifying key bytes back into the typed key.
/// Returns `None` if the byte slice isn't the expected length.
pub fn decode_generator_vk(encoded: &[u8]) -> Option<MlDsaVerifyingKey<MlDsa65>> {
    let fixed: EncodedVerifyingKey<MlDsa65> = encoded.try_into().ok()?;
    Some(MlDsaVerifyingKey::<MlDsa65>::decode(&fixed))
}

pub type AssignmentHash = [u8; 32];

#[derive(Debug, Serialize, Deserialize)]
pub enum TokenDelegateMessage {
    RequestNewToken(RequestNewToken),
    AllocatedToken {
        delegate_id: SecretsId,
        assignment: TokenAssignment,
        /// An updated version of the record with the newly allocated token included
        records: TokenAllocationRecord,
    },
    Failure(FailureReason),
}

impl TryFrom<&[u8]> for TokenDelegateMessage {
    type Error = DelegateError;

    fn try_from(payload: &[u8]) -> Result<Self, Self::Error> {
        bincode::deserialize(payload).map_err(|err| DelegateError::Deser(format!("{err}")))
    }
}

impl TokenDelegateMessage {
    pub fn serialize(self) -> Result<Vec<u8>, DelegateError> {
        bincode::serialize(&self).map_err(|err| DelegateError::Deser(format!("{err}")))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub enum FailureReason {
    /// The user didn't accept to allocate the tokens.
    UserPermissionDenied,
    /// No free slot to allocate with the requested criteria
    NoFreeSlot {
        delegate_id: SecretsId,
        criteria: AllocationCriteria,
    },
}

impl Display for FailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FailureReason::UserPermissionDenied => {
                write!(f, "user disallowed token allocation for this application")
            }
            FailureReason::NoFreeSlot {
                delegate_id,
                criteria,
            } => {
                write!(
                    f,
                    "no free slot found for delegate `{delegate_id}` with criteria {criteria}"
                )
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestNewToken {
    pub request_id: u32,
    pub delegate_id: SecretsId,
    pub criteria: AllocationCriteria,
    pub records: TokenAllocationRecord,
    pub assignment_hash: AssignmentHash,
}

/// Contracts making use of the allocation must implement a type with this trait that allows
/// extracting the criteria for the given contract.
pub trait TokenAllocation: DeserializeOwned {
    fn get_criteria(&self) -> AllocationCriteria;
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Display)]
#[strum(serialize_all = "lowercase")]
#[repr(u8)]
pub enum Tier {
    Min1,
    Min5,
    Min10,
    Min30,
    Hour1,
    Hour3,
    Hour6,
    Hour12,
    Day1,
    Day7,
    Day15,
    Day30,
    Day90,
    Day180,
    Day365,
}

impl Tier {
    pub fn is_valid_slot(&self, dt: DateTime<Utc>) -> bool {
        match self {
            Tier::Min1 => {
                let vns = dt.nanosecond() == 0;
                let vs = dt.second() == 0;
                vns && vs
            }
            Tier::Min5 => Self::check_is_correct_minute(dt, 5),
            Tier::Min10 => Self::check_is_correct_minute(dt, 10),
            Tier::Min30 => Self::check_is_correct_minute(dt, 30),
            Tier::Hour1 => {
                let vns = dt.nanosecond() == 0;
                let vs = dt.second() == 0;
                let vm = dt.minute() == 0;
                vns && vs && vm
            }
            Tier::Hour3 => Self::check_is_correct_hour(dt, 3),
            Tier::Hour6 => Self::check_is_correct_hour(dt, 6),
            Tier::Hour12 => Self::check_is_correct_hour(dt, 12),
            Tier::Day1 => {
                let vns = dt.nanosecond() == 0;
                let vs = dt.second() == 0;
                let vm = dt.minute() == 0;
                let vh = dt.hour() == 0;
                vns && vs && vm && vh
            }
            Tier::Day7 => Self::check_is_correct_day(dt, 7),
            Tier::Day15 => Self::check_is_correct_day(dt, 15),
            Tier::Day30 => Self::check_is_correct_day(dt, 30),
            Tier::Day90 => Self::check_is_correct_day(dt, 90),
            Tier::Day180 => Self::check_is_correct_day(dt, 180),
            Tier::Day365 => Self::check_is_correct_day(dt, 365),
        }
    }

    fn check_is_correct_minute(dt: DateTime<Utc>, base_min: u32) -> bool {
        dt.second() == 0 && dt.nanosecond() == 0 && dt.minute().is_multiple_of(base_min)
    }

    fn check_is_correct_hour(dt: DateTime<Utc>, base_hour: u32) -> bool {
        dt.minute() == 0
            && dt.second() == 0
            && dt.nanosecond() == 0
            && dt.hour().is_multiple_of(base_hour)
    }

    fn check_is_correct_day(dt: DateTime<Utc>, base_day: i64) -> bool {
        let year = get_date(dt.year() - 1, 12, 31);
        let delta = dt - year;
        dt.hour() == 0
            && dt.minute() == 0
            && dt.second() == 0
            && dt.nanosecond() == 0
            && delta.num_days() % base_day == 0
    }

    pub fn tier_duration(&self) -> std::time::Duration {
        match self {
            Tier::Min1 => Duration::minutes(1).to_std().unwrap(),
            Tier::Min5 => Duration::minutes(5).to_std().unwrap(),
            Tier::Min10 => Duration::minutes(10).to_std().unwrap(),
            Tier::Min30 => Duration::minutes(30).to_std().unwrap(),
            Tier::Hour1 => Duration::hours(1).to_std().unwrap(),
            Tier::Hour3 => Duration::hours(3).to_std().unwrap(),
            Tier::Hour6 => Duration::hours(6).to_std().unwrap(),
            Tier::Hour12 => Duration::hours(12).to_std().unwrap(),
            Tier::Day1 => Duration::days(1).to_std().unwrap(),
            Tier::Day7 => Duration::days(7).to_std().unwrap(),
            Tier::Day15 => Duration::days(15).to_std().unwrap(),
            Tier::Day30 => Duration::days(30).to_std().unwrap(),
            Tier::Day90 => Duration::days(90).to_std().unwrap(),
            Tier::Day180 => Duration::days(180).to_std().unwrap(),
            Tier::Day365 => Duration::days(365).to_std().unwrap(),
        }
    }

    /// Normalized the datetime to be the next valid date from the provided one compatible with the tier.
    ///
    /// The base reference datetime used for normalization for day tiers, is from the first day of the year (Gregorian calendar).
    /// For the hour tiers, the first hour of the day; and for minute tiers, the first minute of the hour.
    pub fn normalize_to_next(&self, mut time: DateTime<Utc>) -> DateTime<Utc> {
        match self {
            Tier::Min1 => {
                let is_rounded = time.hour() == 0 && time.second() == 0 && time.nanosecond() == 0;
                if !is_rounded {
                    let duration = chrono::Duration::from_std(self.tier_duration()).unwrap();
                    time = time.with_second(0).unwrap();
                    time = time.trunc_subsecs(0);
                    time += duration;
                }
                time
            }
            Tier::Min5 => self.normalize_to_next_minute(time, 5),
            Tier::Min10 => self.normalize_to_next_minute(time, 10),
            Tier::Min30 => self.normalize_to_next_minute(time, 15),
            Tier::Hour1 => {
                let is_rounded = time.hour() == 0
                    && time.minute() == 0
                    && time.second() == 0
                    && time.nanosecond() == 0;
                if !is_rounded {
                    let duration = chrono::Duration::from_std(self.tier_duration()).unwrap();
                    time = time.with_second(0).unwrap().with_minute(0).unwrap();
                    time = time.trunc_subsecs(0);
                    time += duration;
                }
                time
            }
            Tier::Hour3 => self.normalize_to_next_hour(time, 3),
            Tier::Hour6 => self.normalize_to_next_hour(time, 6),
            Tier::Hour12 => self.normalize_to_next_hour(time, 12),
            Tier::Day1 => {
                let is_rounded = time.hour() == 0
                    && time.minute() == 0
                    && time.second() == 0
                    && time.nanosecond() == 0;
                if !is_rounded {
                    let duration = chrono::Duration::from_std(self.tier_duration()).unwrap();
                    time = time
                        .with_second(0)
                        .unwrap()
                        .with_minute(0)
                        .unwrap()
                        .with_hour(0)
                        .unwrap();
                    time = time.trunc_subsecs(0);
                    time += duration;
                }
                time
            }
            Tier::Day7 => self.normalize_to_next_day(time, 7),
            Tier::Day15 => self.normalize_to_next_day(time, 15),
            Tier::Day30 => self.normalize_to_next_day(time, 30),
            Tier::Day90 => self.normalize_to_next_day(time, 90),
            Tier::Day180 => self.normalize_to_next_day(time, 180),
            Tier::Day365 => self.normalize_to_next_day(time, 365),
        }
    }

    fn normalize_to_next_minute(&self, mut time: DateTime<Utc>, base_minute: u32) -> DateTime<Utc> {
        let is_rounded = time.minute().is_multiple_of(base_minute)
            && time.second() == 0
            && time.nanosecond() == 0;
        if !is_rounded {
            time = time.with_second(0).unwrap();
            time = time.trunc_subsecs(0);
            let minutes_in_time = time.minute();
            let remainder_minutes = minutes_in_time % base_minute;
            if remainder_minutes != 0 {
                let duration = chrono::Duration::from_std(self.tier_duration()).unwrap();
                time = time.with_minute(time.minute() - remainder_minutes).unwrap();
                time += duration;
            }
        }
        time
    }

    fn normalize_to_next_hour(&self, mut time: DateTime<Utc>, base_hour: u32) -> DateTime<Utc> {
        let is_rounded = time.hour().is_multiple_of(base_hour)
            && time.minute() == 0
            && time.second() == 0
            && time.nanosecond() == 0;
        if !is_rounded {
            time = time.with_second(0).unwrap().with_minute(0).unwrap();
            time = time.trunc_subsecs(0);
            let hours_in_time = time.hour();
            let remainder_hours = hours_in_time % base_hour;
            if remainder_hours != 0 {
                let duration = chrono::Duration::from_std(self.tier_duration()).unwrap();
                time = time.with_hour(time.hour() - remainder_hours).unwrap();
                time += duration;
            }
        }
        time
    }

    fn normalize_to_next_day(&self, mut time: DateTime<Utc>, base_day: i64) -> DateTime<Utc> {
        let year = get_date(time.year() - 1, 12, 31);
        let delta = time - year;
        let is_rounded = time.hour() == 0
            && time.minute() == 0
            && time.second() == 0
            && time.nanosecond() == 0
            && delta.num_days() % base_day == 0;
        if !is_rounded {
            time = time
                .with_second(0)
                .unwrap()
                .with_minute(0)
                .unwrap()
                .with_hour(0)
                .unwrap();
            time = time.trunc_subsecs(0);
            let days_in_time = delta.num_days();
            let remainder_days = (days_in_time % base_day) as u32;
            if remainder_days != 0 {
                let duration = chrono::Duration::from_std(self.tier_duration()).unwrap();
                time = time.with_day(time.day() - remainder_days).unwrap();
                time += duration;
            }
        }
        time
    }
}

fn get_date(y: i32, m: u32, d: u32) -> DateTime<Utc> {
    let naive = NaiveDate::from_ymd_opt(y, m, d)
        .unwrap()
        .and_hms_opt(0, 0, 0)
        .unwrap();
    DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc)
}

#[non_exhaustive]
#[derive(Serialize, Deserialize)]
pub struct TokenDelegateParameters {
    /// FIPS 204 encoded ML-DSA-65 verifying key bytes (1952 bytes).
    pub generator_public_key: Vec<u8>,
}

impl TokenDelegateParameters {
    pub fn new(generator_vk: &MlDsaVerifyingKey<MlDsa65>) -> Self {
        Self {
            generator_public_key: generator_vk.encode().to_vec(),
        }
    }

    /// Construct directly from encoded bytes (for test helpers and round-tripping).
    pub fn from_encoded(generator_public_key: Vec<u8>) -> Self {
        Self {
            generator_public_key,
        }
    }

    /// Decode `generator_public_key` into the typed ML-DSA verifying key.
    /// Returns `None` if the byte array isn't the right length for ML-DSA-65.
    pub fn generator_vk(&self) -> Option<MlDsaVerifyingKey<MlDsa65>> {
        decode_generator_vk(&self.generator_public_key)
    }
}

impl TryFrom<Parameters<'_>> for TokenDelegateParameters {
    type Error = ContractError;
    fn try_from(params: Parameters<'_>) -> Result<Self, Self::Error> {
        serde_json::from_slice(params.as_ref())
            .map_err(|err| ContractError::Deser(format!("{err}")))
    }
}

impl TryFrom<TokenDelegateParameters> for Parameters<'static> {
    type Error = serde_json::Error;
    fn try_from(params: TokenDelegateParameters) -> Result<Self, Self::Error> {
        serde_json::to_vec(&params).map(Into::into)
    }
}

/// Secret held by the token-generator delegate.
///
/// Under RSA this used to hold an `RsaPrivateKey`; under ML-DSA-65 we
/// store only the 32-byte seed that reconstructs the signing key, matching
/// the Stage 2 `StoredIdentityKeys::ml_dsa_seed` convention. The seed is
/// expanded into a `SigningKey<MlDsa65>` on demand via `KeyGen::key_gen_internal`.
#[non_exhaustive]
#[derive(Serialize, Deserialize)]
pub struct DelegateParameters {
    pub generator_seed: [u8; 32],
}

impl DelegateParameters {
    pub fn new(generator_seed: [u8; 32]) -> Self {
        Self { generator_seed }
    }

    /// Reconstruct the ML-DSA-65 signing key from the seed.
    pub fn signing_key(&self) -> ml_dsa::SigningKey<MlDsa65> {
        use ml_dsa::{KeyGen, Seed};
        let seed: Seed = self.generator_seed.into();
        MlDsa65::from_seed(&seed)
    }

    /// Derive the corresponding ML-DSA-65 verifying key from the seed.
    pub fn verifying_key(&self) -> MlDsaVerifyingKey<MlDsa65> {
        use ml_dsa::signature::Keypair;
        self.signing_key().verifying_key().clone()
    }
}

impl TryFrom<Parameters<'_>> for DelegateParameters {
    type Error = DelegateError;
    fn try_from(params: Parameters<'_>) -> Result<Self, Self::Error> {
        serde_json::from_slice(params.as_ref())
            .map_err(|err| DelegateError::Deser(format!("{err}")))
    }
}

impl TryFrom<DelegateParameters> for Parameters<'static> {
    type Error = serde_json::Error;
    fn try_from(params: DelegateParameters) -> Result<Self, Self::Error> {
        serde_json::to_vec(&params).map(Into::into)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidReason {
    #[error("invalid slot")]
    InvalidSlot,
    #[error("invalid signature")]
    SignatureMismatch,
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct AllocationError(Box<AllocationErrorInner>);

impl AllocationError {
    pub fn invalid_assignment(record: TokenAssignment, reason: InvalidReason) -> Self {
        Self(Box::new(AllocationErrorInner::InvalidAssignment {
            record,
            reason,
        }))
    }

    pub fn allocated_slot(assignment: &TokenAssignment) -> Self {
        Self(Box::new(AllocationErrorInner::AllocatedSlot {
            tier: assignment.tier,
            slot: assignment.time_slot,
        }))
    }
}

impl From<AllocationErrorInner> for AllocationError {
    fn from(value: AllocationErrorInner) -> Self {
        Self(Box::new(value))
    }
}

#[derive(Debug, thiserror::Error)]
#[allow(clippy::large_enum_variant)]
enum AllocationErrorInner {
    #[error("the following slot for {tier} has already been allocated: {slot}")]
    AllocatedSlot { tier: Tier, slot: DateTime<Utc> },
    #[error("the max age allowed is 730 days")]
    IncorrectMaxAge,
    #[error("the following assignment is incorrect: {record}, reason: {reason}")]
    InvalidAssignment {
        record: TokenAssignment,
        reason: InvalidReason,
    },
}

#[non_exhaustive]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocationCriteria {
    pub frequency: Tier,
    /// Maximum age of the allocated token.
    pub max_age: std::time::Duration,
    pub contract: ContractInstanceId,
}

impl AllocationCriteria {
    pub fn new(
        frequency: Tier,
        max_age: std::time::Duration,
        contract: ContractInstanceId,
    ) -> Result<Self, AllocationError> {
        if max_age <= std::time::Duration::from_secs(3600 * 24 * 365 * 2) {
            Ok(Self {
                frequency,
                max_age,
                contract,
            })
        } else {
            Err(AllocationErrorInner::IncorrectMaxAge.into())
        }
    }
}

impl Display for AllocationCriteria {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "frequency: {}; max age: {} secs",
            self.frequency,
            self.max_age.as_secs()
        )
    }
}

#[non_exhaustive]
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct TokenAllocationRecord {
    /// A list of issued tokens.
    ///
    /// This is categorized by tiers and then sorted by time slot.
    tokens_by_tier: HashMap<Tier, Vec<TokenAssignment>>,
}

impl TokenAllocationRecord {
    pub fn get_tier(&self, tier: &Tier) -> Option<&[TokenAssignment]> {
        self.tokens_by_tier.get(tier).map(|t| t.as_slice())
    }

    pub fn get_mut_tier(&mut self, tier: &Tier) -> Option<&mut Vec<TokenAssignment>> {
        self.tokens_by_tier.get_mut(tier)
    }

    pub fn new(mut tokens: HashMap<Tier, Vec<TokenAssignment>>) -> Self {
        tokens.iter_mut().for_each(|(_, assignments)| {
            assignments.sort_unstable();
        });
        Self {
            tokens_by_tier: tokens,
        }
    }

    pub fn insert(&mut self, tier: Tier, assignments: Vec<TokenAssignment>) {
        self.tokens_by_tier.insert(tier, assignments);
    }

    pub fn summarize(&self) -> TokenAllocationSummary {
        let mut by_tier = HashMap::with_capacity(self.tokens_by_tier.len());
        for (tier, assignments) in &self.tokens_by_tier {
            let mut slots = Vec::with_capacity(assignments.len());
            for a in assignments {
                slots.push(SummarySlot {
                    time_slot: a.time_slot.timestamp(),
                    assignment_hash: a.assignment_hash,
                });
            }
            by_tier.insert(*tier, slots);
        }
        TokenAllocationSummary(by_tier)
    }

    pub fn delta(&self, summary: &TokenAllocationSummary) -> TokenAllocationRecord {
        // Iterate every tier WE have, not every tier the summary lists, so a
        // cold-cache peer with an empty summary still receives every
        // assignment we hold. The previous implementation iterated
        // `summary.0` and silently produced an empty delta whenever the
        // summary had no entry for one of our tiers (or was empty entirely),
        // which contributed to the wasted cross-node round trips around
        // freenet/mail#71.
        let mut delta = HashMap::with_capacity(self.tokens_by_tier.len());
        for (tier, assigned) in &self.tokens_by_tier {
            let summary_slots = summary.0.get(tier);
            let mut missing = Vec::with_capacity(assigned.len());
            for a in assigned {
                let already_known = summary_slots
                    .map(|slots| slots.iter().any(|s| s.assignment_hash == a.assignment_hash))
                    .unwrap_or(false);
                if !already_known {
                    missing.push(a.clone());
                }
            }
            if !missing.is_empty() {
                delta.insert(*tier, missing);
            }
        }
        TokenAllocationRecord {
            tokens_by_tier: delta,
        }
    }

    pub fn assignment_exists(&self, record: &TokenAssignment) -> bool {
        let Some(assignments) = self.tokens_by_tier.get(&record.tier) else {
            return false;
        };
        let Ok(_idx) = assignments.binary_search_by(|t| t.time_slot.cmp(&record.time_slot)) else {
            return false;
        };
        true
    }

    pub fn serialized(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }
}

impl<'a> IntoIterator for &'a TokenAllocationRecord {
    type Item = (&'a Tier, &'a Vec<TokenAssignment>);

    type IntoIter = std::collections::hash_map::Iter<'a, Tier, Vec<TokenAssignment>>;

    fn into_iter(self) -> Self::IntoIter {
        self.tokens_by_tier.iter()
    }
}

impl IntoIterator for TokenAllocationRecord {
    type Item = (Tier, Vec<TokenAssignment>);

    type IntoIter = std::collections::hash_map::IntoIter<Tier, Vec<TokenAssignment>>;

    fn into_iter(self) -> Self::IntoIter {
        self.tokens_by_tier.into_iter()
    }
}

impl TryFrom<State<'_>> for TokenAllocationRecord {
    type Error = ContractError;

    fn try_from(state: State<'_>) -> Result<Self, Self::Error> {
        let this = serde_json::from_slice(state.as_ref())
            .map_err(|err| ContractError::Deser(format!("{err}")))?;
        Ok(this)
    }
}

impl TryFrom<StateDelta<'_>> for TokenAllocationRecord {
    type Error = ContractError;

    fn try_from(delta: StateDelta<'_>) -> Result<Self, Self::Error> {
        let this = serde_json::from_slice(delta.as_ref())
            .map_err(|err| ContractError::Deser(format!("{err}")))?;
        Ok(this)
    }
}

impl TryFrom<TokenAllocationRecord> for State<'static> {
    type Error = ContractError;

    fn try_from(state: TokenAllocationRecord) -> Result<Self, Self::Error> {
        let serialized = state
            .serialized()
            .map_err(|err| ContractError::Deser(format!("{err}")))?;
        Ok(State::from(serialized))
    }
}

impl TryFrom<TokenAllocationRecord> for StateDelta<'static> {
    type Error = ContractError;

    fn try_from(state: TokenAllocationRecord) -> Result<Self, Self::Error> {
        let serialized = state
            .serialized()
            .map_err(|err| ContractError::Deser(format!("{err}")))?;
        Ok(StateDelta::from(serialized))
    }
}

/// One entry of the per-tier allocation summary. Carries the slot
/// timestamp (for legacy slot-based equality) and the full
/// `assignment_hash` so callers can match a specific assignment without
/// false positives on slot collision (#3 in the AFT audit).
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SummarySlot {
    pub time_slot: i64,
    pub assignment_hash: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenAllocationSummary(HashMap<Tier, Vec<SummarySlot>>);

impl TokenAllocationSummary {
    /// True if any slot in `tier` matches `slot` by timestamp. Retained
    /// for callers that don't have an `assignment_hash` to match against.
    pub fn contains_alloc(&self, tier: Tier, slot: DateTime<Utc>) -> bool {
        self.0
            .get(&tier)
            .map(|slots| {
                let target = slot.timestamp();
                slots.iter().any(|s| s.time_slot == target)
            })
            .unwrap_or(false)
    }

    /// True if any slot in `tier` matches `assignment_hash` exactly.
    /// Prefer this over `contains_alloc` when binding the summary
    /// confirmation to a specific in-flight assignment.
    pub fn contains_alloc_hash(&self, tier: Tier, assignment_hash: &[u8; 32]) -> bool {
        self.0
            .get(&tier)
            .map(|slots| slots.iter().any(|s| &s.assignment_hash == assignment_hash))
            .unwrap_or(false)
    }
}

impl TryFrom<StateSummary<'_>> for TokenAllocationSummary {
    type Error = ContractError;

    fn try_from(state: StateSummary<'_>) -> Result<Self, Self::Error> {
        if state.as_ref().is_empty() {
            return Ok(TokenAllocationSummary(HashMap::new()));
        }
        let this = serde_json::from_slice(state.as_ref())
            .map_err(|err| ContractError::Deser(format!("{err}")))?;
        Ok(this)
    }
}

impl TryFrom<TokenAllocationSummary> for StateSummary<'static> {
    type Error = ContractError;

    fn try_from(summary: TokenAllocationSummary) -> Result<Self, Self::Error> {
        let serialized =
            serde_json::to_vec(&summary).map_err(|err| ContractError::Deser(format!("{err}")))?;
        Ok(StateSummary::from(serialized))
    }
}

pub type TokenAssignmentHash = [u8; 32];

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[must_use]
pub struct TokenAssignment {
    pub tier: Tier,
    pub time_slot: DateTime<Utc>,
    /// The public key of the generator of this token, and by extension, the one who created the signature.
    ///
    /// This field can be used to verify that the token has been indeed generated by this generator.
    /// Encoded as ML-DSA-65 verifying key bytes (1952 bytes).
    pub generator: Assignee,
    /// FIPS 204 encoded ML-DSA-65 signature (3309 bytes) over the
    /// `(tier, issue_time, assignment_hash)` tuple returned by
    /// [`TokenAssignment::signature_content`].
    pub signature: Vec<u8>,
    /// A Blake2s256 hash of the message.
    pub assignment_hash: TokenAssignmentHash,
    /// Key to the contract holding the token records of the assignee.
    pub token_record: ContractInstanceId,
}

impl TokenAssignment {
    const TIER_SIZE: usize = std::mem::size_of::<Tier>();
    const TS_SIZE: usize = std::mem::size_of::<i64>();

    pub const SIGNED_MSG_SIZE: usize = Self::TIER_SIZE + Self::TS_SIZE + 32;

    /// The `(tier, issue_time, assignee)` tuple that has to be verified as bytes.
    pub fn signature_content(
        issue_time: &DateTime<Utc>,
        tier: Tier,
        assingment_hash: &AssignmentHash,
    ) -> [u8; Self::SIGNED_MSG_SIZE] {
        let mut cursor = 0;
        let mut to_be_signed = [0; Self::SIGNED_MSG_SIZE];

        to_be_signed[..Self::TIER_SIZE].copy_from_slice(&(tier as u8).to_le_bytes());
        cursor += Self::TIER_SIZE;
        let timestamp = issue_time.timestamp();
        to_be_signed[cursor..cursor + Self::TS_SIZE].copy_from_slice(&timestamp.to_le_bytes());
        cursor += Self::TS_SIZE;
        to_be_signed[cursor..].copy_from_slice(assingment_hash);
        to_be_signed
    }

    pub fn next_slot(&self) -> DateTime<Utc> {
        self.time_slot + Duration::from_std(self.tier.tier_duration()).unwrap()
    }

    pub fn previous_slot(&self) -> DateTime<Utc> {
        self.time_slot - Duration::from_std(self.tier.tier_duration()).unwrap()
    }

    pub fn is_valid(
        &self,
        verifying_key: &MlDsaVerifyingKey<MlDsa65>,
    ) -> Result<(), InvalidReason> {
        if !self.tier.is_valid_slot(self.time_slot) {
            return Err(InvalidReason::InvalidSlot);
        }
        let msg =
            TokenAssignment::signature_content(&self.time_slot, self.tier, &self.assignment_hash);
        let sig_bytes: &[u8] = self.signature.as_slice();
        let signature = match ml_dsa::Signature::<MlDsa65>::try_from(sig_bytes) {
            Ok(s) => s,
            Err(_) => {
                #[cfg(all(target_family = "wasm", feature = "contract"))]
                {
                    freenet_stdlib::log::info(
                        "failed to decode ML-DSA-65 signature from TokenAssignment bytes",
                    );
                }
                return Err(InvalidReason::SignatureMismatch);
            }
        };
        if verifying_key.verify(&msg, &signature).is_err() {
            // not signed by the private key of this generator
            #[cfg(all(target_family = "wasm", feature = "contract"))]
            {
                freenet_stdlib::log::info(&format!(
                    "failed ML-DSA verification of message `{msg:?}` ({} signature bytes)",
                    self.signature.len()
                ));
            }
            return Err(InvalidReason::SignatureMismatch);
        }
        Ok(())
    }
}

impl PartialOrd for TokenAssignment {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TokenAssignment {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.time_slot.cmp(&other.time_slot)
    }
}

impl TryFrom<StateDelta<'_>> for TokenAssignment {
    type Error = ContractError;

    fn try_from(state: StateDelta<'_>) -> Result<Self, Self::Error> {
        let this = serde_json::from_slice(state.as_ref())
            .map_err(|err| ContractError::Deser(format!("{err}")))?;
        Ok(this)
    }
}

impl Display for TokenAssignment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let assignment = bs58::encode(self.assignment_hash).into_string();
        write!(
            f,
            "{{ {tier} @ {slot} for assignment `{assignment}`, record: {record}}}",
            tier = self.tier,
            slot = self.time_slot,
            record = self.token_record
        )
    }
}

#[cfg(test)]
mod tier_tests {
    use super::*;

    #[test]
    fn is_correct_minute() {
        let day7_tier = Tier::Day7;
        assert!(day7_tier.is_valid_slot(get_date(2023, 1, 7)));
        assert!(!day7_tier.is_valid_slot(get_date(2023, 1, 8)));

        let day30_tier = Tier::Day30;
        assert!(day30_tier.is_valid_slot(get_date(2023, 1, 30)));
        assert!(day30_tier.is_valid_slot(get_date(2023, 3, 1)));
        assert!(!day30_tier.is_valid_slot(get_date(2023, 3, 30)));
    }

    #[test]
    fn is_correct_hour() {
        let hour3_tier = Tier::Hour3;
        assert!(hour3_tier.is_valid_slot(get_date(2023, 1, 7).with_hour(6).unwrap()));
        assert!(!hour3_tier.is_valid_slot(get_date(2023, 1, 8).with_hour(7).unwrap()));

        let hour12_tier = Tier::Hour12;
        assert!(hour12_tier.is_valid_slot(get_date(2023, 1, 30).with_hour(12).unwrap()));
        assert!(hour12_tier.is_valid_slot(get_date(2023, 3, 1)));
        assert!(!hour12_tier.is_valid_slot(get_date(2023, 3, 30).with_hour(13).unwrap()));
    }

    #[test]
    fn is_correct_day() {
        let day1_tier = Tier::Day1;
        assert!(day1_tier.is_valid_slot(get_date(2023, 1, 8)));
        assert!(!day1_tier.is_valid_slot(get_date(2023, 1, 8).with_hour(12).unwrap()));

        let day7_tier = Tier::Day7;
        assert!(day7_tier.is_valid_slot(get_date(2023, 1, 7)));
        assert!(!day7_tier.is_valid_slot(get_date(2023, 1, 8)));

        let day30_tier = Tier::Day30;
        assert!(day30_tier.is_valid_slot(get_date(2023, 1, 30)));
        assert!(day30_tier.is_valid_slot(get_date(2023, 3, 1)));
        assert!(!day30_tier.is_valid_slot(get_date(2023, 3, 30)));
    }

    #[test]
    fn minute_tier_normalization() {
        let min5_tier = Tier::Min5;
        let min5_normalized =
            min5_tier.normalize_to_next(get_date(2023, 1, 1).with_minute(37).unwrap());
        assert_eq!(
            min5_normalized,
            get_date(2023, 1, 1).with_minute(40).unwrap()
        );
        let min5_normalized =
            min5_tier.normalize_to_next(get_date(2023, 1, 1).with_minute(8).unwrap());
        assert_eq!(
            min5_normalized,
            get_date(2023, 1, 1).with_minute(10).unwrap()
        );

        let min10_tier = Tier::Min10;
        let min10_normalized =
            min10_tier.normalize_to_next(get_date(2023, 1, 1).with_minute(22).unwrap());
        assert_eq!(
            min10_normalized,
            get_date(2023, 1, 1).with_minute(30).unwrap()
        );
        let min10_tier = Tier::Min10;
        let min10_normalized =
            min10_tier.normalize_to_next(get_date(2023, 1, 1).with_minute(38).unwrap());
        assert_eq!(
            min10_normalized,
            get_date(2023, 1, 1).with_minute(40).unwrap()
        );
    }

    #[test]
    fn hour_tier_normalization() {
        let hour6_tier = Tier::Hour6;
        let hour6_normalized =
            hour6_tier.normalize_to_next(get_date(2023, 1, 1).with_hour(4).unwrap());
        assert_eq!(hour6_normalized, get_date(2023, 1, 1).with_hour(6).unwrap());
        let hour6_normalized =
            hour6_tier.normalize_to_next(get_date(2023, 1, 1).with_hour(17).unwrap());
        assert_eq!(
            hour6_normalized,
            get_date(2023, 1, 1).with_hour(18).unwrap()
        );

        let hour12_tier = Tier::Hour12;
        let hour12_normalized =
            hour12_tier.normalize_to_next(get_date(2023, 1, 1).with_hour(4).unwrap());
        assert_eq!(
            hour12_normalized,
            get_date(2023, 1, 1).with_hour(12).unwrap()
        );
        let hour12_normalized =
            hour12_tier.normalize_to_next(get_date(2023, 1, 1).with_hour(17).unwrap());
        assert_eq!(hour12_normalized, get_date(2023, 1, 2));
    }

    #[test]
    fn day_tier_normalization() {
        let day7_tier = Tier::Day7;
        let day7_normalized = day7_tier.normalize_to_next(get_date(2023, 1, 17));
        assert_eq!(day7_normalized, get_date(2023, 1, 21));
        let day15_normalized = day7_tier.normalize_to_next(get_date(2023, 1, 31));
        assert_eq!(day15_normalized, get_date(2023, 2, 4));

        let day15_tier = Tier::Day15;
        let day15_normalized = day15_tier.normalize_to_next(get_date(2023, 1, 17));
        assert_eq!(day15_normalized, get_date(2023, 1, 30));
        let day15_normalized = day15_tier.normalize_to_next(get_date(2023, 1, 31));
        assert_eq!(day15_normalized, get_date(2023, 2, 14));
    }
}

#[cfg(test)]
mod boundary_tests {
    //! Regression tests for the deserialization boundaries on this crate.
    //!
    //! The Phase 1 audit (#5) initially flagged ~50 chrono `.unwrap()`
    //! calls in this file, but on inspection they all sit on hardcoded
    //! constants or post-check arithmetic — none touch network input. The
    //! only network-facing entry points are the `TryFrom<&[u8]>` /
    //! `TryFrom<Parameters>` / `TryFrom<StateDelta>` impls below, all of
    //! which already return `Result`. These tests pin that fact so any
    //! future regression that swaps a `?` for an `unwrap` trips them.

    use super::*;

    #[test]
    fn malformed_token_delegate_message_returns_err() {
        let garbage = [0xffu8; 64];
        let result = TokenDelegateMessage::try_from(&garbage[..]);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn empty_token_delegate_message_returns_err() {
        let result = TokenDelegateMessage::try_from(&[][..]);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn malformed_token_assignment_state_delta_returns_err() {
        let garbage = StateDelta::from(vec![0xffu8; 64]);
        let result = TokenAssignment::try_from(garbage);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn truncated_token_assignment_json_returns_err() {
        let truncated = StateDelta::from(br#"{"tier":"min1","#.to_vec());
        let result = TokenAssignment::try_from(truncated);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn malformed_token_delegate_parameters_returns_err() {
        let garbage = Parameters::from(vec![0xffu8; 64]);
        let result = TokenDelegateParameters::try_from(garbage).map(|_| ());
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn malformed_delegate_parameters_returns_err() {
        let garbage = Parameters::from(vec![0xffu8; 64]);
        let result = DelegateParameters::try_from(garbage).map(|_| ());
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn malformed_token_allocation_record_state_returns_err() {
        let garbage = State::from(vec![0xffu8; 64]);
        let result = TokenAllocationRecord::try_from(garbage);
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    // -- Cross-crate wire-shape round-trip tests -------------------------
    //
    // The AFT contract decodes Delta payloads as a `TokenAssignment` first
    // and falls back to a whole `TokenAllocationRecord` because cross-node
    // propagation occasionally re-wraps the latter under a Delta envelope
    // (see #71). These tests pin the wire shapes that both decoders
    // accept, so a regression that drifts the producer side (e.g. the UI
    // crate switching to a tagged-enum encoding) trips a fast unit test
    // instead of surfacing as a "missing field tier" error in production
    // logs.

    fn signing_key(seed: u8) -> ml_dsa::SigningKey<MlDsa65> {
        DelegateParameters::new([seed; 32]).signing_key()
    }

    fn make_assignment(seed: u8) -> TokenAssignment {
        use chrono::TimeZone;
        use ml_dsa::signature::Signer;
        let sk = signing_key(seed);
        let vk = DelegateParameters::new([seed; 32]).verifying_key();
        let tier = Tier::Day1;
        let time_slot = chrono::Utc.with_ymd_and_hms(2026, 5, 3, 0, 0, 0).unwrap();
        let assignment_hash = [seed; 32];
        let to_sign = TokenAssignment::signature_content(&time_slot, tier, &assignment_hash);
        let signature: ml_dsa::Signature<MlDsa65> = sk.sign(&to_sign);
        TokenAssignment {
            tier,
            time_slot,
            generator: vk.encode().to_vec(),
            signature: signature.encode().to_vec(),
            assignment_hash,
            token_record: ContractInstanceId::new([seed; 32]),
        }
    }

    /// Sender (`ui/src/aft.rs`) encodes a `TokenAssignment` via
    /// `serde_json::to_vec`. The contract must decode it via the
    /// `TryFrom<StateDelta<'_>>` impl. Pin that the round-trip preserves
    /// every field — a regression that, say, renamed `time_slot` would
    /// fail this test instead of producing "missing field tier" only at
    /// runtime under cross-node load.
    #[test]
    fn token_assignment_serde_json_round_trip_via_state_delta() {
        let original = make_assignment(0xA1);
        let bytes = serde_json::to_vec(&original).expect("serialize");
        let delta = StateDelta::from(bytes);
        let decoded = TokenAssignment::try_from(delta).expect("decode");
        assert_eq!(original, decoded);
    }

    /// `TokenAllocationRecord` also decodes from a Delta envelope (the
    /// "delta-as-record" fallback path). Pin the round-trip so the
    /// fallback decoder stays usable when cross-node propagation re-wraps
    /// the record. If this regresses, the AFT contract's defensive
    /// fallback in `update_state` becomes a silent panic.
    #[test]
    fn token_allocation_record_serde_round_trip_via_state_delta() {
        use std::collections::HashMap;

        let assignment = make_assignment(0xC3);
        let mut tokens = HashMap::new();
        tokens.insert(Tier::Day1, vec![assignment.clone()]);
        let original = TokenAllocationRecord::new(tokens);

        // Wire shape is what `TryFrom<StateDelta>` consumes — verify the
        // record's own `TryFrom<TokenAllocationRecord> for StateDelta`
        // produces bytes the decoder can parse back into a record with
        // the same assignments. (`TokenAllocationRecord` doesn't impl
        // `PartialEq` on the whole struct because of `tokens_by_assignee`,
        // but each `TokenAssignment` does — so compare via iter.)
        let delta: StateDelta<'static> = original.clone().try_into().expect("encode");
        let decoded = TokenAllocationRecord::try_from(delta).expect("decode");
        let decoded_assignments: Vec<_> = (&decoded)
            .into_iter()
            .flat_map(|(_, v)| v.iter().cloned())
            .collect();
        assert_eq!(decoded_assignments, vec![assignment.clone()]);

        // Also pin the State round-trip — full state propagation on
        // cross-node UPDATE goes through the `State` envelope.
        let state: State<'static> = original.clone().try_into().expect("encode state");
        let decoded_state = TokenAllocationRecord::try_from(state).expect("decode state");
        let decoded_state_assignments: Vec<_> = (&decoded_state)
            .into_iter()
            .flat_map(|(_, v)| v.iter().cloned())
            .collect();
        assert_eq!(decoded_state_assignments, vec![assignment]);
    }

    /// Cross-crate path: a single `TokenAssignment` encoded by the sender
    /// (UI crate) must decode via *both* the single-assignment path and
    /// the whole-record fallback only if it is in the right shape. This
    /// pins that bare `TokenAssignment` JSON does NOT accidentally parse
    /// as a `TokenAllocationRecord` (which would corrupt records by
    /// inserting an empty record) — the fallback path requires the
    /// record-shaped JSON.
    #[test]
    fn assignment_json_does_not_decode_as_allocation_record() {
        let assignment = make_assignment(0xD4);
        let bytes = serde_json::to_vec(&assignment).expect("serialize");
        let delta = StateDelta::from(bytes);

        // Single-assignment decode succeeds.
        let _: TokenAssignment = TokenAssignment::try_from(delta.clone()).expect("decode");

        // Whole-record decode must FAIL on bare-assignment JSON. If it
        // ever started succeeding we'd silently merge an empty record on
        // the contract side and the originally-burned token would
        // disappear.
        let as_record = TokenAllocationRecord::try_from(delta);
        assert!(
            as_record.is_err(),
            "bare TokenAssignment JSON must NOT decode as TokenAllocationRecord; got {as_record:?}"
        );
    }

    /// `contains_alloc_hash` must distinguish between two assignments
    /// that share the same `(tier, time_slot)` but have different
    /// `assignment_hash` — the legacy `contains_alloc` couldn't, which
    /// made `confirm_allocation` race-prone when two in-flight
    /// allocations landed in the same slot before either confirmed.
    #[test]
    fn summary_contains_alloc_hash_disambiguates_concurrent_allocs() {
        use std::collections::HashMap;

        let a = make_assignment(0xA1);
        // Force a second assignment into the same slot but with a different
        // `assignment_hash`. (In production this can only happen across
        // nodes mid-propagation; here we construct it directly.)
        let mut b = a.clone();
        b.assignment_hash = [0xB2; 32];
        assert_eq!(a.tier, b.tier);
        assert_eq!(a.time_slot, b.time_slot);
        assert_ne!(a.assignment_hash, b.assignment_hash);

        let mut tokens = HashMap::new();
        tokens.insert(a.tier, vec![a.clone()]);
        let record = TokenAllocationRecord::new(tokens);
        let summary = record.summarize();

        // hash-precise lookup: a is present, b is not.
        assert!(summary.contains_alloc_hash(a.tier, &a.assignment_hash));
        assert!(!summary.contains_alloc_hash(b.tier, &b.assignment_hash));

        // legacy slot-only lookup matches both, demonstrating the
        // false-positive that hash-precise lookup avoids.
        assert!(summary.contains_alloc(a.tier, a.time_slot));
        assert!(summary.contains_alloc(b.tier, b.time_slot));
    }

    /// Pin the wire shape of `TokenAllocationSummary` so the cross-crate
    /// confirmation path keeps decoding. The shape is
    /// `{ <Tier>: [{ "time_slot": <i64>, "assignment_hash": [u8; 32] }] }`.
    #[test]
    fn summary_wire_shape_round_trips() {
        let assignment = make_assignment(0xE5);
        let mut tokens = std::collections::HashMap::new();
        tokens.insert(assignment.tier, vec![assignment.clone()]);
        let record = TokenAllocationRecord::new(tokens);
        let summary = record.summarize();

        let state_summary: StateSummary<'static> = summary.try_into().expect("encode summary");
        let decoded = TokenAllocationSummary::try_from(state_summary).expect("decode summary");
        assert!(decoded.contains_alloc_hash(assignment.tier, &assignment.assignment_hash));
        assert!(decoded.contains_alloc(assignment.tier, assignment.time_slot));
    }
}
