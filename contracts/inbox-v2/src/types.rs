//! The state, its pieces and their canonical CBOR.
//!
//! Struct fields encode in declaration order and `BTreeMap` keys sort as the
//! bytes they are, so one value has one encoding. Decoding therefore checks
//! canonicity by re-encoding and comparing, which refuses non-minimal integers,
//! indefinite lengths, unsorted or duplicate keys, unknown fields and trailing
//! bytes without naming any of them. Fixed-size byte fields are CBOR byte
//! strings, not arrays of integers.

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_bytes::{ByteArray, ByteBuf};

pub type B16 = ByteArray<16>;
pub type B24 = ByteArray<24>;
pub type B32 = ByteArray<32>;
pub type B64 = ByteArray<64>;

/// Why an input was refused outright. Anything else about an input is filtered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Malformed(pub &'static str);

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct InboxState {
    pub owner: OwnerRecord,
    pub time: TimeAttestation,
    pub revoked: BTreeMap<B16, Revocation>,
    pub usage: BTreeMap<B16, PassUsage>,
    pub messages: BTreeMap<B32, Message>,
}

/// What `update_state` accepts as a delta, and what a state is merged as: any
/// subset of a state.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct InboxDelta {
    pub owner: Option<OwnerRecord>,
    pub time: Option<TimeAttestation>,
    pub revoked: BTreeMap<B16, Revocation>,
    pub usage: BTreeMap<B16, PassUsage>,
    pub messages: BTreeMap<B32, Message>,
}

impl From<InboxState> for InboxDelta {
    fn from(s: InboxState) -> Self {
        Self {
            owner: Some(s.owner),
            time: Some(s.time),
            revoked: s.revoked,
            usage: s.usage,
            messages: s.messages,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct OwnerRecord {
    pub owner_vk: ByteBuf,
    pub kem_ek: ByteBuf,
    pub issuer_vk: B32,
    pub pass_epoch: u32,
    pub version: u64,
    pub quarantine: QuarantineMode,
    /// Message id to its `sent_time`. Signed, so only the owner's client can
    /// prune it; the contract enforces the count.
    pub tombstones: BTreeMap<B32, u64>,
    /// ML-DSA-65.
    pub sig: ByteBuf,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuarantineMode {
    Open,
    RequireGhost { min_usd: Option<u32> },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TimeAttestation {
    pub owner_time: u64,
    /// Issuer key.
    pub sig: B64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Revocation {
    pub pass_id: B16,
    pub expiry: u64,
    pub epoch: u32,
    pub sig: B64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PassUsage {
    pub pass_id: B16,
    pub used: u8,
    pub expiry: u64,
    pub sig: B64,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum PassClass {
    Contact,
    Invite { max_messages: u8 },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PassCert {
    pub recipient: B24,
    pub pass_id: B16,
    pub pass_vk: B32,
    pub epoch: u32,
    pub expiry: u64,
    pub class: PassClass,
    pub sig: B64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub ciphertext: ByteBuf,
    pub sent_time: u64,
    pub admission: Admission,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum Admission {
    Pass { cert: PassCert, msg_sig: B64 },
    Owner { sig: B64 },
    Quarantine { ghost: Option<GhostProof> },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct GhostProof {
    /// A Ghost Key certificate's canonical CBOR.
    pub cert: ByteBuf,
    /// The CBOR `ScopedPayload`, exactly as the ghostkey vault signed it.
    pub scoped_payload: ByteBuf,
    pub ghost_sig: B64,
}

/// Canonical CBOR of `value`.
pub fn encode<T: Serialize>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    // Infallible: a `Vec` writer cannot fail, and these types serialize only
    // integers, bytes, unit-free maps and strings.
    ciborium::into_writer(value, &mut out).expect("CBOR into a Vec");
    out
}

/// Decode `bytes`, refusing anything but the canonical encoding.
pub fn decode<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, Malformed> {
    let value: T = ciborium::from_reader(bytes).map_err(|_| Malformed("not CBOR of this type"))?;
    if encode(&value) != bytes {
        return Err(Malformed("non-canonical CBOR"));
    }
    Ok(value)
}
