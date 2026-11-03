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

/// What one decoded part may hold (decision 12): a valid state holds no more,
/// so a part over any of these is refused as it is decoded, before anything in
/// it is verified. `tests/bounds.rs` pins them to `Rules::V1`.
pub const MAX_MESSAGES: usize = 88;
pub const MAX_REVOKED: usize = 4096;
pub const MAX_USAGE: usize = 1024;
pub const MAX_TOMBSTONES: usize = 4096;
/// The largest input `decode` reads: 4 MiB, which the largest valid state fits
/// in (`tests/worst_case.rs`), plus a 256 KiB margin so that no valid state or
/// delta comes near it.
pub const MAX_INPUT_BYTES: usize = 4 * 1024 * 1024 + 256 * 1024;

const OVER_A_BOUND: &str = "a count over its bound";

/// What the parts of one call hold between them (decision 16): the bounds above
/// apply to the sum over every part the caller sent, so splitting a load over a
/// state and a delta does not double what a call can cost.
#[derive(Default)]
pub struct CallCounts {
    messages: usize,
    revoked: usize,
    usage: usize,
    tombstones: usize,
}

impl CallCounts {
    /// Counts `part` in, refusing the call once a sum passes its bound.
    pub fn add(&mut self, part: &InboxDelta) -> Result<(), Malformed> {
        self.messages += part.messages.len();
        self.revoked += part.revoked.len();
        self.usage += part.usage.len();
        self.tombstones += part.owner.as_ref().map_or(0, |o| o.tombstones.len());
        if self.messages > MAX_MESSAGES
            || self.revoked > MAX_REVOKED
            || self.usage > MAX_USAGE
            || self.tombstones > MAX_TOMBSTONES
        {
            return Err(Malformed(OVER_A_BOUND));
        }
        Ok(())
    }
}

/// Deserializes a map, refusing it at the entry that takes it past `N`.
fn bounded<'de, D, K, V, const N: usize>(de: D) -> Result<BTreeMap<K, V>, D::Error>
where
    D: serde::Deserializer<'de>,
    K: Deserialize<'de> + Ord,
    V: Deserialize<'de>,
{
    struct Visit<K, V, const N: usize>(std::marker::PhantomData<(K, V)>);
    impl<'de, K, V, const N: usize> serde::de::Visitor<'de> for Visit<K, V, N>
    where
        K: Deserialize<'de> + Ord,
        V: Deserialize<'de>,
    {
        type Value = BTreeMap<K, V>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(f, "a map of at most {N} entries")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> Result<Self::Value, A::Error> {
            let mut out = BTreeMap::new();
            while let Some(key) = map.next_key()? {
                if out.len() == N {
                    return Err(serde::de::Error::custom(OVER_A_BOUND));
                }
                let value = map.next_value()?;
                out.insert(key, value);
            }
            Ok(out)
        }
    }
    de.deserialize_map(Visit::<K, V, N>(std::marker::PhantomData))
}

fn messages<'de, D: serde::Deserializer<'de>>(de: D) -> Result<BTreeMap<B32, Message>, D::Error> {
    bounded::<D, B32, Message, MAX_MESSAGES>(de)
}

fn revoked<'de, D: serde::Deserializer<'de>>(de: D) -> Result<BTreeMap<B16, Revocation>, D::Error> {
    bounded::<D, B16, Revocation, MAX_REVOKED>(de)
}

fn usage<'de, D: serde::Deserializer<'de>>(de: D) -> Result<BTreeMap<B16, PassUsage>, D::Error> {
    bounded::<D, B16, PassUsage, MAX_USAGE>(de)
}

fn tombstones<'de, D: serde::Deserializer<'de>>(de: D) -> Result<BTreeMap<B32, u64>, D::Error> {
    bounded::<D, B32, u64, MAX_TOMBSTONES>(de)
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct InboxState {
    pub owner: OwnerRecord,
    pub time: TimeAttestation,
    #[serde(deserialize_with = "revoked")]
    pub revoked: BTreeMap<B16, Revocation>,
    #[serde(deserialize_with = "usage")]
    pub usage: BTreeMap<B16, PassUsage>,
    #[serde(deserialize_with = "messages")]
    pub messages: BTreeMap<B32, Message>,
}

/// What `update_state` accepts as a delta, and what a state is merged as: any
/// subset of a state.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct InboxDelta {
    pub owner: Option<OwnerRecord>,
    pub time: Option<TimeAttestation>,
    #[serde(deserialize_with = "revoked")]
    pub revoked: BTreeMap<B16, Revocation>,
    #[serde(deserialize_with = "usage")]
    pub usage: BTreeMap<B16, PassUsage>,
    #[serde(deserialize_with = "messages")]
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
    /// An `owner_time`. Before it, passes of `pass_epoch - 1` are admitted and
    /// their revocations kept (decision 18): a routine bump sets it 14 days on,
    /// so contacts can be reissued passes over that time, and an emergency bump
    /// sets 0, so the old epoch ends at once.
    pub prev_epoch_until: u64,
    pub version: u64,
    pub quarantine: QuarantineMode,
    /// Message id to its `sent_time`. Signed, so only the owner's client can
    /// prune it; the contract enforces the count.
    #[serde(deserialize_with = "tombstones")]
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
    /// The owner version whose tombstones hold the messages `used` counts. The
    /// entry counts only once that version is joined, so it never cuts a
    /// message while one it counts is still held (review r1 S2).
    pub owner_version: u64,
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
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(Malformed("an input over the byte limit"));
    }
    let value: T = ciborium::from_reader(bytes).map_err(|e| match e {
        ciborium::de::Error::Semantic(_, why) if why == OVER_A_BOUND => Malformed(OVER_A_BOUND),
        _ => Malformed("not CBOR of this type"),
    })?;
    if encode(&value) != bytes {
        return Err(Malformed("non-canonical CBOR"));
    }
    Ok(value)
}
