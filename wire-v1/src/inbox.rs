//! State, parameters and deltas of the v0.2.x inbox contract
//! (`contracts/inbox`, code hash `Av3KF7WS…`), copied verbatim minus the
//! contract implementation and its validation logic, which only the
//! contract runs.

use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use freenet_stdlib::prelude::*;
use ml_dsa::{
    EncodedVerifyingKey, MlDsa65, SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey,
    signature::Signer as MlDsaSigner,
};
use serde::{Deserialize, Serialize};

use crate::aft::{Tier, TokenAssignment, TokenAssignmentHash};

/// Sign this byte array and include the signature in the `inbox_signature` so
/// this inbox can be verified on updates. Value is arbitrary but must stay
/// constant across versions — it's part of the signed-payload convention, so
/// changing it would invalidate every existing inbox signature.
pub const STATE_UPDATE: &[u8; 8] = &[168, 7, 13, 64, 168, 123, 142, 215];

/// The owner's ML-DSA-65 verifying key. Stored on-wire as the FIPS 204
/// encoded byte array (1952 bytes for ML-DSA-65) to avoid a custom serde
/// impl on the typed key. `pub_key_decoded()` reconstructs the typed
/// `VerifyingKey<MlDsa65>` on demand.
///
/// This field is part of the contract parameters, so it participates in
/// `hash(code, params)` and every bit change rotates the contract id.
///
/// The recipient anti-flood policy lives on `InboxSettings` (mutable via
/// `ModifySettings`) rather than here, so the inbox owner can re-tune
/// their tier / max-age cap without rotating the contract id and forcing
/// every existing sender to re-import.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InboxParams {
    pub pub_key: Vec<u8>,
}

/// Default seconds-component of `max_age` (365 days). Used by
/// callers that want the historical default without spelling out
/// the constant.
pub const DEFAULT_MAX_AGE_SECS: u64 = 365 * 24 * 3600;

/// Maximum number of entries permitted in `InboxSettings.verified_senders`.
/// ML-DSA-65 VKs are 1952 bytes each; 1024 entries ≈ 2 MiB — large enough
/// for any realistic contact list but bounded so a spammer cannot inflate
/// inbox state without limit via `ModifySettings`.
pub const MAX_VERIFIED_SENDERS: usize = 1024;

impl InboxParams {
    /// Convenience constructor from a typed ML-DSA verifying key.
    pub fn from_verifying_key(vk: &MlDsaVerifyingKey<MlDsa65>) -> Self {
        Self {
            pub_key: vk.encode().to_vec(),
        }
    }

    /// Decode `pub_key` back into the typed ML-DSA verifying key. Returns
    /// `None` if the byte array isn't the right length for ML-DSA-65.
    pub fn pub_key_decoded(&self) -> Option<MlDsaVerifyingKey<MlDsa65>> {
        let encoded: EncodedVerifyingKey<MlDsa65> = (&*self.pub_key).try_into().ok()?;
        Some(MlDsaVerifyingKey::<MlDsa65>::decode(&encoded))
    }
}

impl TryFrom<InboxParams> for Parameters<'_> {
    type Error = serde_json::Error;

    fn try_from(value: InboxParams) -> Result<Self, Self::Error> {
        serde_json::to_vec(&value).map(Into::into)
    }
}

impl TryFrom<Parameters<'static>> for InboxParams {
    type Error = ContractError;
    fn try_from(params: Parameters<'static>) -> Result<Self, Self::Error> {
        serde_json::from_slice(params.as_ref())
            .map_err(|err| ContractError::Deser(format!("{err}")))
    }
}

type Signature = Box<[u8]>;

#[derive(Serialize, Deserialize)]
pub enum UpdateInbox {
    AddMessages {
        messages: Vec<Message>,
    },
    RemoveMessages {
        signature: Signature,
        ids: Vec<TokenAssignmentHash>,
    },
    ModifySettings {
        /// Owner ML-DSA-65 signature over the FULL authority payload
        /// (`sign_payload(owner_ek_bytes, settings, last_update)`), not
        /// just `serialized(settings)`. The host pins `last_update` from
        /// this message and stores `inbox_signature` so the resulting
        /// state re-verifies under the widened payload (#253).
        inbox_signature: Signature,
        settings: InboxSettings,
        /// Owner-supplied LWW timestamp the signature commits to. The host
        /// assigns it verbatim (no host-side `+1µs` bump) so the stored
        /// `last_update` matches what was signed.
        last_update: DateTime<Utc>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InboxSettings {
    /// AFT tier the recipient requires for incoming messages. Senders
    /// must mint tokens at this exact tier; the contract rejects any
    /// `AddMessages` whose token tier mismatches. Mutable via
    /// `ModifySettings`, so the recipient can re-tune their flood cap
    /// without rotating the inbox contract id.
    pub minimum_tier: Tier,
    /// `max_age_secs` half of the recipient policy. The AFT delegate
    /// uses it sender-side when computing free slots; the contract does
    /// not enforce age (no clock available in WASM).
    #[serde(default = "default_max_age_secs")]
    pub max_age_secs: u64,
    /// When `true`, incoming messages whose sender ML-DSA-65 verifying
    /// key is listed in `verified_senders` are accepted without a valid
    /// AFT token. Default `false` — every message requires a token.
    /// Mutable via `ModifySettings`.
    #[serde(default)]
    pub allow_verified_skip_token: bool,
    /// Set of ML-DSA-65 verifying keys (FIPS 204 encoded, 1952 bytes
    /// each) whose owners are exempted from the AFT token requirement
    /// when `allow_verified_skip_token` is `true`. Populated by the
    /// recipient when they mark a contact as verified in the address
    /// book; cleared when the contact is removed or un-verified.
    /// The keys are public — stored in plaintext in the inbox state.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub verified_senders: BTreeSet<Vec<u8>>,
    #[serde(skip_serializing_if = "Vec::is_empty", default = "Vec::default")]
    pub private: EncryptedContent,
}

fn default_max_age_secs() -> u64 {
    DEFAULT_MAX_AGE_SECS
}

impl Default for InboxSettings {
    fn default() -> Self {
        Self {
            minimum_tier: Tier::Min10,
            max_age_secs: DEFAULT_MAX_AGE_SECS,
            allow_verified_skip_token: false,
            verified_senders: BTreeSet::new(),
            private: Default::default(),
        }
    }
}

impl TryFrom<StateDelta<'static>> for UpdateInbox {
    type Error = ContractError;
    fn try_from(state: StateDelta<'static>) -> Result<Self, Self::Error> {
        serde_json::from_slice(&state).map_err(|err| ContractError::Deser(format!("{err}")))
    }
}

/// Requires a shared key between both peers to decrypt the secrets.
/// The inbox contract does not need to be aware of the content.
type EncryptedContent = Vec<u8>;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Message {
    pub content: EncryptedContent,
    pub token_assignment: TokenAssignment,
    /// Sender's ML-DSA-65 verifying key (FIPS 204 encoded, 1952 bytes).
    /// Empty for legacy unsigned messages — the recipient renders those
    /// as "unverified" rather than rejecting (#51).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sender_vk: Vec<u8>,
    /// Detached ML-DSA-65 signature over `content` (the ciphertext blob).
    /// Verifies before decryption. Empty for legacy unsigned messages.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Inbox {
    pub messages: Vec<Message>,
    pub last_update: DateTime<Utc>,
    pub settings: InboxSettings,
    /// ML-KEM-768 encapsulation key (FIPS 203 encoded, 1184 bytes). Fetched
    /// by senders alongside the inbox state on import, so the recipient's
    /// inbox contract id is the only thing the sender needs to know to
    /// reach them. Bound to the owner via `inbox_signature` (the signed
    /// payload includes these bytes), so a peer rebroadcasting State
    /// cannot swap in their own ek. `#[serde(default)]` keeps the
    /// previous wire shape decodable during migration; legacy states
    /// re-PUTted under the new code hash by the UI's migration writer
    /// will carry a populated value.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owner_ek_bytes: Vec<u8>,
    inbox_signature: Signature,
}

/// Bytes the inbox owner signs for `UpdateInbox::RemoveMessages`: the
/// assignment hashes concatenated in order, as the frozen inbox contract's
/// `can_reemove_messages` rebuilds them. There is no domain tag.
pub fn removal_payload(ids: &[TokenAssignmentHash]) -> Vec<u8> {
    ids.concat()
}

/// Canonical bytes the inbox owner signs to authorize a state: the
/// `STATE_UPDATE` salt, the ML-KEM encapsulation key, the anti-flood
/// `settings`, and the LWW `last_update`. Binding all four means a peer
/// cannot rebroadcast a State with a legit `(owner_ek_bytes,
/// inbox_signature)` pair but attacker-chosen `settings` / bumped
/// `last_update` — `verify` recomputes this payload and rejects the
/// mismatch (#253).
///
/// `settings` is encoded via `serde_json::to_vec`, which is deterministic
/// for `InboxSettings` (stable struct field order; `verified_senders` is a
/// `BTreeSet` → sorted) — the same encoding `can_update_settings` already
/// signed. `last_update` is its microsecond unix timestamp, big-endian, so
/// the µs LWW granularity the host previously bumped is preserved in the
/// signed payload.
pub fn sign_payload(
    owner_ek_bytes: &[u8],
    settings: &InboxSettings,
    last_update: DateTime<Utc>,
) -> Vec<u8> {
    // Serializing a well-formed `InboxSettings` cannot fail: no map keys,
    // no floats — only enums, ints, bool, and byte-vec sets.
    let settings_bytes =
        serde_json::to_vec(settings).expect("InboxSettings is always serializable");
    let ts = last_update.timestamp_micros().to_be_bytes();
    let mut payload = Vec::with_capacity(
        STATE_UPDATE.len() + owner_ek_bytes.len() + settings_bytes.len() + ts.len(),
    );
    payload.extend_from_slice(STATE_UPDATE);
    payload.extend_from_slice(owner_ek_bytes);
    payload.extend_from_slice(&settings_bytes);
    payload.extend_from_slice(&ts);
    payload
}

impl Inbox {
    #[cfg(feature = "clock")]
    pub fn new(
        key: &MlDsaSigningKey<MlDsa65>,
        settings: InboxSettings,
        messages: Vec<Message>,
        owner_ek_bytes: Vec<u8>,
    ) -> Self {
        let last_update = Utc::now();
        let inbox_signature = Self::sign(key, &owner_ek_bytes, &settings, last_update);
        Self {
            settings,
            messages,
            last_update,
            owner_ek_bytes,
            inbox_signature,
        }
    }

    /// An inbox state whose `inbox_signature` was produced elsewhere (the
    /// mail delegate signs [`sign_payload`] for the owner). The caller must
    /// sign exactly `sign_payload(&owner_ek_bytes, &settings, last_update)`.
    pub fn with_signature(
        settings: InboxSettings,
        messages: Vec<Message>,
        last_update: DateTime<Utc>,
        owner_ek_bytes: Vec<u8>,
        inbox_signature: Signature,
    ) -> Self {
        Self {
            settings,
            messages,
            last_update,
            owner_ek_bytes,
            inbox_signature,
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, ContractError> {
        serde_json::to_vec(self).map_err(|err| ContractError::Deser(format!("{err}")))
    }

    /// Sign the full inbox-authority payload with the owner's ML-DSA-65
    /// signing key. The signature binds `owner_ek_bytes`, `settings`, and
    /// `last_update` so a peer rebroadcasting `UpdateData::State` cannot
    /// substitute their own encapsulation key OR tamper with the
    /// anti-flood policy / LWW timestamp — the contract host re-runs
    /// `verify` on every State ingest and would reject the swap (#253).
    /// The resulting signature is stored in `Inbox::inbox_signature`.
    pub fn sign(
        key: &MlDsaSigningKey<MlDsa65>,
        owner_ek_bytes: &[u8],
        settings: &InboxSettings,
        last_update: DateTime<Utc>,
    ) -> Signature {
        let payload = sign_payload(owner_ek_bytes, settings, last_update);
        let sig: ml_dsa::Signature<MlDsa65> = MlDsaSigner::sign(key, &payload);
        sig.encode().to_vec().into_boxed_slice()
    }
}

impl TryFrom<&'_ State<'static>> for Inbox {
    type Error = ContractError;
    fn try_from(state: &State<'static>) -> Result<Self, Self::Error> {
        serde_json::from_slice(state).map_err(|err| ContractError::Deser(format!("{err}")))
    }
}

impl TryFrom<Inbox> for StateDelta<'static> {
    type Error = ContractError;
    fn try_from(value: Inbox) -> Result<Self, Self::Error> {
        let serialized =
            serde_json::to_vec(&value).map_err(|err| ContractError::Deser(format!("{err}")))?;
        Ok(serialized.into())
    }
}

/// Ported from `contracts/inbox`'s tests: the serde round trips that do not
/// need the contract implementation.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_inbox_round_trips_through_state_delta() {
        let payload = UpdateInbox::AddMessages { messages: vec![] };
        let bytes = serde_json::to_vec(&payload).expect("encode");
        // Pin the wire shape — the JSON must contain the externally-tagged
        // discriminant so the decoder can route to the right variant.
        assert!(
            bytes.starts_with(br#"{"AddMessages""#),
            "UpdateInbox::AddMessages must serialize as externally-tagged enum; \
             got: {}",
            String::from_utf8_lossy(&bytes)
        );
        let delta = StateDelta::from(bytes);
        let decoded = UpdateInbox::try_from(delta).expect("decode");
        match decoded {
            UpdateInbox::AddMessages { messages } => assert!(messages.is_empty()),
            UpdateInbox::RemoveMessages { .. } => {
                panic!("expected AddMessages, got RemoveMessages")
            }
            UpdateInbox::ModifySettings { .. } => {
                panic!("expected AddMessages, got ModifySettings")
            }
        }
    }

    #[test]
    fn inbox_settings_max_age_serde_round_trips() {
        let settings = InboxSettings {
            minimum_tier: Tier::Min10,
            max_age_secs: 7 * 86_400,
            allow_verified_skip_token: false,
            verified_senders: BTreeSet::new(),
            private: Vec::new(),
        };
        let bytes = serde_json::to_vec(&settings).expect("encode");
        let decoded: InboxSettings = serde_json::from_slice(&bytes).expect("decode");
        assert_eq!(decoded.max_age_secs, 7 * 86_400);
        // Legacy on-chain states encoded before `max_age_secs` existed must
        // decode, with the field defaulted.
        let legacy_bytes = br#"{"minimum_tier":"Min10","private":[]}"#;
        let from_legacy: InboxSettings = serde_json::from_slice(legacy_bytes)
            .expect("legacy settings must decode with defaulted max_age_secs");
        assert_eq!(from_legacy.max_age_secs, DEFAULT_MAX_AGE_SECS);
    }
}
