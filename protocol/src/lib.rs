//! Messages between the Freenet Mail UI and the mail delegate.
//!
//! Every [`Request`] gets exactly one [`Response`] carrying the same
//! `request_id`, including writes (`Reply::Ack`). There is no empty reply
//! and no "silence means success": a caller that times out has an UNKNOWN
//! outcome, never an absent one.
//!
//! Encoding is CBOR (ciborium). Byte fields use `serde_bytes`, so they encode
//! as CBOR byte strings rather than arrays of integers.

pub mod address;
pub mod fixed_bytes;
pub mod recovery_key;

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

/// Version of this protocol. A request carrying another version is refused
/// with [`FailureCode::UnsupportedVersion`] rather than guessed at.
pub const PROTOCOL_VERSION: u16 = 1;

/// Largest response the delegate sends. List operations page to stay under
/// it.
pub const MAX_RESPONSE_BYTES: usize = 512 * 1024;
/// Largest body one stored item may have.
pub const MAX_ITEM_BYTES: usize = 256 * 1024;
/// Most ciphertexts one `DecryptV1` call may carry.
pub const MAX_DECRYPT_BATCH: usize = 32;
/// Most assignment hashes one `SignV1Removal` call may carry.
pub const MAX_REMOVAL_BATCH: usize = 1024;

macro_rules! fixed {
    ($(#[$m:meta])* $name:ident, $n:expr) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub struct $name(#[serde(with = "fixed_bytes")] pub [u8; $n]);
    };
}

fixed!(
    /// Random per call, chosen by the caller; echoed in the response.
    RequestId,
    16
);
fixed!(
    /// An identity's or contact's address: the first 24 bytes of
    /// `blake3::derive_key("freenet-mail address v1", ml_dsa_vk)`
    /// (see [`address::address_of`]).
    Addr,
    24
);
fixed!(
    /// 32 bytes of caller-supplied entropy, mixed with the host's.
    Entropy,
    32
);
fixed!(
    /// A 32-byte hash (a v1 token assignment hash).
    Hash32,
    32
);
fixed!(
    /// The 32-byte ML-DSA-65 seed.
    DsaSeed,
    32
);
fixed!(
    /// The 64-byte ML-KEM-768 seed.
    KemSeed,
    64
);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub version: u16,
    pub request_id: RequestId,
    pub op: Op,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    pub request_id: RequestId,
    pub result: Result<Reply, Failure>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Failure {
    pub code: FailureCode,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailureCode {
    NotFound,
    /// A compare-and-swap lost: the item is now at `current_gen` (0 = absent).
    Conflict {
        current_gen: u64,
    },
    CapReached,
    /// Not allowed: wrong origin, consent denied, or a request this delegate
    /// never serves.
    Refused,
    BadInput,
    Busy,
    Internal,
    UnsupportedVersion,
}

/// What kind of stored item. Each kind has its own key space, so an identity,
/// a contact and a message can never overwrite one another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ItemKind {
    /// Owner: none. Id: the contact's 24-byte address.
    Contact,
    /// Owner: an identity. Id: 16 bytes (a content hash).
    Draft,
    Sent,
    Kept,
    Archived,
    /// Read/deleted flags for one message. Owner: an identity. Id: 16 bytes.
    Flags,
    /// Owner: an identity. Id: empty.
    IdentitySettings,
    /// Owner: none. Id: empty.
    GlobalSettings,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ItemRef {
    pub kind: ItemKind,
    pub owner: Option<Addr>,
    #[serde(with = "serde_bytes")]
    pub id: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    pub item: ItemRef,
    pub body: ByteBuf,
    pub generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImportSource {
    /// An `fmail-key-1:` recovery key.
    RecoveryKey(String),
    /// A v2 JSON identity backup file, as exported by v0.2.x.
    LegacyJson(ByteBuf),
    Seeds {
        dsa: DsaSeed,
        kem: KemSeed,
    },
}

/// Operations. Every one is answered with exactly one [`Response`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Op {
    GetStatus,

    // ── Identities ──────────────────────────────────────────────────────
    /// Public information only; seeds never leave except through a
    /// consented export.
    ListIdentities,
    /// Refused with `Conflict` if an identity with that alias exists.
    /// `ui_entropy` must not be all zeros.
    CreateIdentity {
        alias: String,
        description: String,
        ui_entropy: Entropy,
    },
    /// Never overwrites: importing an address that is already stored
    /// returns the stored identity unchanged.
    ImportIdentity {
        source: ImportSource,
        alias: String,
        description: String,
    },
    UpdateIdentity {
        addr: Addr,
        alias: String,
        description: String,
        expected_gen: u64,
    },
    DeleteIdentity {
        addr: Addr,
        expected_gen: u64,
    },

    // ── Stored items (contacts, local state) ────────────────────────────
    /// Items of one kind (and owner), in id order, starting after `after`.
    ListItems {
        kind: ItemKind,
        owner: Option<Addr>,
        after: Option<ByteBuf>,
        limit: u16,
    },
    GetItem {
        item: ItemRef,
    },
    /// `expected_gen: None` creates only (fails if present); `Some(g)` is a
    /// compare-and-swap against generation `g` (`Some(0)` = must be absent).
    PutItem {
        item: ItemRef,
        body: ByteBuf,
        expected_gen: Option<u64>,
    },
    DeleteItem {
        item: ItemRef,
        expected_gen: u64,
    },

    // ── v0.2.x (v1 inbox) crypto, transitional ──────────────────────────
    /// Decrypt v1 message ciphertexts addressed to `addr`.
    DecryptV1 {
        addr: Addr,
        ciphertexts: Vec<ByteBuf>,
    },
    /// Encrypt `plaintext` to `recipient_ek` in the v1 layout and sign the
    /// resulting ciphertext with `addr`'s key. There is deliberately no
    /// operation that signs caller-chosen bytes.
    SealV1Message {
        addr: Addr,
        recipient_ek: ByteBuf,
        plaintext: ByteBuf,
        ui_entropy: Entropy,
    },
    /// Sign a v1 inbox authority payload (`sign_payload(own ek, settings,
    /// last_update)`) for a new inbox state or a settings change. The
    /// delegate supplies the encapsulation key itself.
    SignV1Authority {
        addr: Addr,
        settings_json: ByteBuf,
        last_update_micros: i64,
    },
    /// Sign a v1 `RemoveMessages` payload (the concatenated hashes).
    SignV1Removal {
        addr: Addr,
        assignment_hashes: Vec<Hash32>,
    },
    /// The v1 token-generator delegate's parameters for `addr`. These
    /// contain the identity's ML-DSA seed, which is why this exists only in
    /// builds with the `v1-transition` feature, until the v1 send path goes.
    V1AftParams {
        addr: Addr,
    },

    // ── Exports (ask the user) ──────────────────────────────────────────
    ExportRecoveryKey {
        addr: Addr,
    },
    /// A v2 JSON identity backup, readable by v0.2.x and later.
    ExportProfile {
        addr: Addr,
    },

    // ── Migration ───────────────────────────────────────────────────────
    /// freenet-migrate export of the caller's own namespace, for a future
    /// successor delegate.
    ExportForSuccessor {
        source_generation: u32,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityInfo {
    pub addr: Addr,
    pub vk: ByteBuf,
    pub ek: ByteBuf,
    pub alias: String,
    pub description: String,
    /// False for an identity imported from older data until the user
    /// confirms it is theirs.
    pub confirmed: bool,
    pub generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub protocol_version: u16,
    pub identities: u32,
    pub stored_keys: u32,
    pub key_budget: u32,
    pub v1_transition: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reply {
    Status(Status),
    Identities(Vec<IdentityInfo>),
    Identity(IdentityInfo),
    Imported {
        identity: IdentityInfo,
        already_present: bool,
    },
    Items {
        items: Vec<Item>,
        more: bool,
    },
    Item(Option<Item>),
    Ack {
        generation: u64,
    },
    Deleted,
    Decrypted(Vec<Result<ByteBuf, FailureCode>>),
    SealedV1 {
        content: ByteBuf,
        signature: ByteBuf,
        sender_vk: ByteBuf,
    },
    Signature(ByteBuf),
    AftParams(ByteBuf),
    RecoveryKey(String),
    Profile(ByteBuf),
    ExportedSecrets(ByteBuf),
}

/// Encode `value` as CBOR.
pub fn to_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

/// Decode CBOR into `T`.
pub fn from_cbor<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    ciborium::de::from_reader(bytes).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_and_responses_round_trip() {
        let req = Request {
            version: PROTOCOL_VERSION,
            request_id: RequestId([7; 16]),
            op: Op::PutItem {
                item: ItemRef {
                    kind: ItemKind::Draft,
                    owner: Some(Addr([1; 24])),
                    id: vec![2; 16],
                },
                body: ByteBuf::from(vec![3, 4]),
                expected_gen: Some(5),
            },
        };
        assert_eq!(from_cbor::<Request>(&to_cbor(&req).unwrap()).unwrap(), req);
        let resp = Response {
            request_id: RequestId([7; 16]),
            result: Err(Failure {
                code: FailureCode::Conflict { current_gen: 9 },
                detail: "stale".into(),
            }),
        };
        assert_eq!(
            from_cbor::<Response>(&to_cbor(&resp).unwrap()).unwrap(),
            resp
        );
    }

    #[test]
    fn fixed_byte_fields_encode_as_byte_strings() {
        // A CBOR byte string of length 16 starts with 0x50; an array of
        // integers would start with 0x90.
        let bytes = to_cbor(&RequestId([0xAA; 16])).unwrap();
        assert_eq!(bytes[0], 0x50);
        assert_eq!(bytes.len(), 17);
    }

    #[test]
    fn a_fixed_field_of_the_wrong_length_is_rejected() {
        let short = to_cbor(&ByteBuf::from(vec![0u8; 15])).unwrap();
        assert!(from_cbor::<RequestId>(&short).is_err());
        let long = to_cbor(&ByteBuf::from(vec![0u8; 17])).unwrap();
        assert!(from_cbor::<RequestId>(&long).is_err());
    }
}
