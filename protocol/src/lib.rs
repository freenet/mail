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
pub mod inbox_v2;
pub mod recovery_key;

#[cfg(test)]
mod golden;

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
    /// An inbox v2 pass id.
    PassId,
    16
);
/// Private key material: not `Copy`, redacted from `Debug`, and zeroized
/// when dropped.
macro_rules! secret {
    ($(#[$m:meta])* $name:ident, $n:expr) => {
        $(#[$m])*
        #[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub struct $name(#[serde(with = "fixed_bytes")] pub [u8; $n]);

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                zeroize::Zeroize::zeroize(&mut self.0);
            }
        }
    };
}

secret!(
    /// The 32-byte ML-DSA-65 seed.
    DsaSeed,
    32
);
secret!(
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
    /// The request's operation is not one this delegate knows (a newer UI).
    UnknownOperation,
    /// The item is listed but its stored bytes cannot be read (the host
    /// reports a file it cannot read or decrypt as absent, every time).
    /// Writing it with `expected_gen: None` replaces it.
    Unreadable,
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
    /// The freenet-migrate completeness journal. Owner: none. Id: empty.
    /// Never exported: it describes this delegate's own predecessors.
    MigrationJournal,
    /// The migration marker of one predecessor delegate. Owner: none. Id: the
    /// predecessor's 32-byte delegate key. Never exported, for the same
    /// reason: a copy in a successor would claim an import it never did.
    MigrationMarker,
    /// Local state of a v0.2.x alias that matches no identity, kept rather
    /// than lost. Owner: none. Id: 16 bytes (a content hash).
    LegacyOrphan,
    /// An identity's inbox v2 bookkeeping: the highest owner version and
    /// time it signed, its epoch and filters. Owner: an identity. Id: empty.
    /// Written only by the delegate.
    InboxV2,
    /// One pass this identity issued (pass id to contact and nonce). Owner:
    /// an identity. Id: the 16-byte pass id. Written only by the delegate.
    PassLedger,
    /// The passes this identity holds to write to someone, a few at most.
    /// Owner: an identity. Id: the recipient's 24-byte address. A page can
    /// never read it; it leaves only in the consented successor export.
    HeldPass,
    /// A message drained from this identity's v2 inbox. Owner: an identity.
    /// Id: the 32-byte message id. The page may delete it.
    Inbound,
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

/// Why an identity is being imported.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImportKind {
    /// The user restored it (recovery key, backup file): stored confirmed.
    UserRestore,
    /// Carried over from older data by a migration: stored unconfirmed until
    /// the user confirms it is theirs ([`Op::ConfirmIdentity`]).
    Migration,
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
        kind: ImportKind,
        alias: String,
        description: String,
    },
    UpdateIdentity {
        addr: Addr,
        alias: String,
        description: String,
        expected_gen: u64,
    },
    /// Deletes the identity and everything it owns. Asks the user every
    /// time (it cannot be undone), so the answer may come after a prompt.
    DeleteIdentity {
        addr: Addr,
        expected_gen: u64,
    },
    /// The user confirmed an identity carried over by a migration is theirs.
    ConfirmIdentity {
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
    /// Asks the user, like the other exports. Pages: pass the returned
    /// `next` as `after` until it is `None`.
    ExportForSuccessor {
        source_generation: u32,
        after: Option<ByteBuf>,
        /// The session token from the previous page's reply. With it, later
        /// pages of an approved export do not ask again. Omitted when absent,
        /// so requests without it encode as before.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session: Option<ByteBuf>,
    },
    /// Withdraw a remembered "Always allow for this app" for exports, and end
    /// any export session.
    RevokeExportGrant,
    /// The identities whose deletion the user approved but which are not
    /// gone yet (the deletion was interrupted). `ListIdentities` hides them;
    /// `DeleteIdentity` finishes one without asking again.
    ListDeletingIdentities,
    /// Reset an index whose stored bytes can no longer be read, so the app
    /// can be used again: the identity index (`kind: None`) or one kind's
    /// index (with its owner). Asks the user every time. Refused while the
    /// index reads fine. Records stay stored: an identity comes back by
    /// importing it again (from its recovery key).
    RepairIndex {
        kind: Option<ItemKind>,
        owner: Option<Addr>,
    },

    // ── Background jobs ─────────────────────────────────────────────────
    /// Run the delegate's jobs for the caller's own namespace now: what a
    /// node with no Background grant, or one too old for it, does not start
    /// by itself. One bounded slice per call; answers [`Reply::JobsRun`].
    RunJobs,

    // ── Inbox v2 ────────────────────────────────────────────────────────
    /// Start `addr`'s v2 inbox: the first owner record and time, as a full
    /// state to PUT under [`inbox_v2::params_bytes`]`(addr, ghost_master)`.
    /// Refused with `Conflict` once the identity has one. `existing` is the
    /// inbox's state when it is already on the network (an identity restored
    /// on this node): it is taken over, and its next version is returned.
    CreateInboxV2 {
        addr: Addr,
        ghost_master: Hash32,
        existing: Option<ByteBuf>,
    },
    /// Sign a change to `addr`'s own inbox, given its current state (a fresh
    /// GET). Every change drains first (decision 9): what the state holds is
    /// stored and tombstoned in the same update. Answers
    /// [`Reply::InboxV2Update`]; `remaining > 0` means call again.
    UpdateInboxV2 {
        addr: Addr,
        state: ByteBuf,
        change: OwnerChange,
        ui_entropy: Entropy,
    },
    /// Issue a pass to `addr`'s inbox: for a contact (reused while it is
    /// live) or an invite of `invite` messages.
    IssuePass {
        addr: Addr,
        contact: Option<Addr>,
        invite: Option<u8>,
        ui_entropy: Entropy,
    },
    /// Keep a pass someone gave `addr` out of band (an invite).
    HoldPass {
        addr: Addr,
        pass: inbox_v2::Pass,
    },
    /// Seal a message from `from` to the inbox `to`, given that inbox's
    /// current state (a fresh GET). Picks the admission (a held pass, the
    /// owner's own key, or quarantine) and the `sent_time`.
    SealV2 {
        from: Addr,
        to: Addr,
        to_state: ByteBuf,
        content: SealContent,
        /// The Ghost Key the sender will prove with, for a RequireGhost
        /// inbox: it is bound inside the envelope and names the message.
        ghost_vk: Option<Hash32>,
        ui_entropy: Entropy,
        /// How many times this message was sealed before: 0 the first time,
        /// one more at each `reseal_at`. Past [`MAX_RESEALS`] it is refused,
        /// so a message that never lands is reported rather than resealed for
        /// good.
        #[serde(default)]
        reseals: u8,
    },
    /// `addr`'s inbox signed again from the delegate's record, as a full
    /// state to PUT under [`inbox_v2::params_bytes`]: for when the network
    /// has no inbox although the identity has a record (the first PUT, or the
    /// [`Op::CreateInboxV2`] reply, was lost). The owner record is the next
    /// version over the record's tombstones and filters, and the time moves
    /// under the guard; both are recorded before the reply. Answers
    /// [`Reply::InboxV2State`], or `NotFound` with no record.
    RepublishInboxV2 {
        addr: Addr,
    },
    /// Tests only: end `addr`'s v1 transition window now, so a real-node
    /// test can see the close without waiting 90 days. Only builds with the
    /// `v1-transition` feature do it, which a release refuses; any other
    /// build answers `Refused`.
    EndV1WindowForTest {
        addr: Addr,
    },
}

/// Times one message may be sealed again ([`SealedV2::reseal_at`]).
pub const MAX_RESEALS: u8 = 4;

/// A change [`Op::UpdateInboxV2`] signs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OwnerChange {
    /// Drain only.
    Drain,
    /// Move `owner_time` towards the node's clock, under the guard.
    AdvanceTime,
    SetQuarantine(inbox_v2::QuarantineMode),
    Revoke {
        pass_id: PassId,
    },
    /// A new pass epoch: routine (a 14-day grace) or emergency (none).
    BumpEpoch {
        emergency: bool,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SealContent {
    Mail(ByteBuf),
    /// A system message carrying no mail, so the reply pass (renewed or
    /// reissued if due) reaches the recipient.
    PassUpdate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxV2Update {
    /// CBOR of an `inbox_v2::InboxDelta` to send as the update, when there
    /// is anything to send.
    pub update: Option<ByteBuf>,
    /// Messages stored by this call.
    pub drained: u32,
    /// Messages left for the next call.
    pub remaining: u32,
    /// Messages left in the inbox although they were tried: storage is full,
    /// a Ghost Key proof only this node's copy can confirm, or the tombstones
    /// are full (those are stored and leave once older tombstones expire).
    pub full: u32,
    /// Earlier stranger messages this call removed to make room: only the
    /// newest drained ones are kept (decision 21).
    pub strangers_dropped: u32,
    /// Whether the change was signed. It waits only when it would drop a
    /// message still in the inbox; the drain goes on either way.
    pub change: ChangeOutcome,
    /// Passes drained mail carried that were not kept because this
    /// identity's held passes are full. The mail itself is stored.
    pub passes_not_kept: u32,
}

/// What became of the change an [`Op::UpdateInboxV2`] asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChangeOutcome {
    /// Signed in full: it is in `update`.
    Signed,
    /// Not signed, or (for `AdvanceTime`) only part of the way: it would drop
    /// a message not drained yet. Call again.
    WaitsForDrain,
    /// Not signed, or only part of the way: it would drop a message that
    /// could not be stored (see `full`). It waits until that one is stored.
    WaitsForStorage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SendAdmission {
    Pass,
    Owner,
    Quarantine,
}

/// Why a sealed message may not land, said plainly to the user.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SendNotice {
    /// The pass we held for this inbox no longer admits mail (expired,
    /// revoked or from an old epoch): sent through quarantine instead.
    PassLapsed,
    /// The pass already has as many messages waiting as it may hold.
    PassFull,
    /// The new-contacts queue is full and this message would not get in.
    QueueFull,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedV2 {
    /// CBOR of the `inbox_v2::Message`. For a RequireGhost inbox it carries
    /// no proof yet: the page asks Ghost Key to sign `ghost_payload` and
    /// puts the proof in its admission.
    pub message: ByteBuf,
    pub id: Hash32,
    pub sent_time: u64,
    pub admission: SendAdmission,
    pub ghost_payload: Option<ByteBuf>,
    pub notice: Option<SendNotice>,
    /// Node time from which this message may have fallen out of the
    /// recipient's window: a send still queued then is sealed again, after a
    /// fresh GET (decision 9).
    pub reseal_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityInfo {
    pub addr: Addr,
    pub vk: ByteBuf,
    pub ek: ByteBuf,
    pub alias: String,
    pub description: String,
    /// False for an identity imported from older data until the user
    /// confirms it is theirs. A hint for the UI, not a security boundary:
    /// any code running under the app's origin can confirm it.
    pub confirmed: bool,
    pub generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub protocol_version: u16,
    pub identities: u32,
    /// Keys and bytes the caller's namespace holds, and its budgets.
    pub stored_keys: u64,
    pub stored_bytes: u64,
    pub key_budget: u64,
    pub byte_budget: u64,
    pub v1_transition: bool,
    /// Identities listed but whose record cannot be used (unreadable, or
    /// stored but not decodable). They are left out of `ListIdentities`;
    /// importing their keys restores them. Added later: absent when zero,
    /// so the earlier encoding is unchanged.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub unreadable_identities: u32,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
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
    /// One page of a freenet-migrate `ExportedSecrets`, and where the next
    /// page starts (`None` on the last page).
    ExportedSecrets {
        payload: ByteBuf,
        next: Option<ByteBuf>,
        /// Present when more pages follow and the host has a clock: pass it
        /// with the next page's request. Omitted when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session: Option<ByteBuf>,
    },
    /// Part of a long operation is done; send the same request again to
    /// continue. `remaining` counts what is left.
    Continue {
        remaining: u32,
    },
    /// The answer to `CreateIdentity`: the new identity and its
    /// `fmail-key-1:` recovery key. This is the one time a recovery key
    /// leaves the delegate without a prompt, so the new identity can be
    /// backed up as it is made; every later reveal is a consented
    /// `ExportRecoveryKey`.
    CreatedIdentity {
        identity: IdentityInfo,
        recovery_key: String,
    },
    /// What one [`Op::RunJobs`] did.
    JobsRun(JobsRun),
    /// A full inbox v2 state to PUT.
    InboxV2State(ByteBuf),
    InboxV2Update(InboxV2Update),
    PassIssued(inbox_v2::Pass),
    SealedV2(SealedV2),
}

/// What one run of the jobs did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobsRun {
    /// Inboxes read in this run.
    pub scanned: u32,
    /// Messages stored as kept copies.
    pub imported: u32,
    /// Inboxes whose state this run could not establish. Unknown, never
    /// absent: nothing is concluded about them.
    pub unknown: u32,
    /// Messages left for a later run: past this run's slice, or refused.
    pub remaining: u32,
}

/// Encode `value` as CBOR.
pub fn to_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

/// A request with its operation still undecoded. A delegate decodes this
/// first, so a request from a newer UI (another protocol version, or an
/// operation this build does not know) still gets a typed failure carrying
/// its id instead of an undecodable message.
#[derive(Clone, Debug, Deserialize)]
pub struct RequestEnvelope {
    pub version: u16,
    pub request_id: RequestId,
    pub op: ciborium::Value,
}

impl RequestEnvelope {
    pub fn op(&self) -> Result<Op, String> {
        self.op.deserialized().map_err(|e| e.to_string())
    }
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
