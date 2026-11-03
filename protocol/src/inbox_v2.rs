//! Inbox v2 on the client side: the contract's state types and signed byte
//! layouts, written again from the spec, and the sealed envelope that travels
//! inside a message's ciphertext.
//!
//! The contract (`contracts/inbox-v2`) is the authority. This copy is checked
//! against its byte vectors (`contracts/inbox-v2/tests/fixtures/vectors.txt`,
//! from a second implementation), and the mail delegate's tests run what it
//! builds through the contract's own `validate_state` and merge. It does not
//! link the contract: the delegate must not carry the Ghost Key chain code.

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_bytes::{ByteArray, ByteBuf};

pub type B16 = ByteArray<16>;
pub type B24 = ByteArray<24>;
pub type B32 = ByteArray<32>;
pub type B64 = ByteArray<64>;

pub const KIND_PASS: u8 = 0;
pub const KIND_OWNER: u8 = 1;
pub const KIND_QUARANTINE: u8 = 2;

/// How far `sent_time` may trail `owner_time`.
pub const WINDOW_BACK: u64 = 2 * 86_400;
/// How far pass and owner mail may lead `owner_time`.
pub const WINDOW_FORWARD: u64 = 400 * 86_400;
/// How far quarantine mail may lead `owner_time` (decision 14).
pub const QUARANTINE_FORWARD: u64 = 2 * 86_400;
pub const SENT_TIME_GRANULARITY: u64 = 3_600;
/// Pass, revocation and usage expiries are whole days (decision 17).
pub const EXPIRY_GRANULARITY: u64 = 86_400;
pub const CIPHERTEXT_SIZES: [usize; 3] = [8 * 1024, 16 * 1024, 32 * 1024];
/// The contract's caps (`merge::Rules::V1`).
pub const PER_PASS: usize = 8;
pub const PER_INVITE: usize = 2;
pub const QUARANTINE_SLOTS: usize = 16;
pub const PER_GHOST: usize = 2;
pub const MAX_REVOKED: usize = 4096;
pub const MAX_TOMBSTONES: usize = 4096;
/// The largest state the contract accepts.
pub const MAX_INPUT_BYTES: usize = 4 * 1024 * 1024 + 256 * 1024;

const PARAMS_VERSION: u8 = 2;

/// An inbox's contract parameters: `0x02 ‖ addr24 ‖ ghost_master32`.
pub fn params_bytes(addr: &[u8; 24], ghost_master: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(57);
    out.push(PARAMS_VERSION);
    out.extend_from_slice(addr);
    out.extend_from_slice(ghost_master);
    out
}

// ── State (field order is the encoding: never reorder) ──────────────────────

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct InboxState {
    pub owner: OwnerRecord,
    pub time: TimeAttestation,
    pub revoked: BTreeMap<B16, Revocation>,
    pub usage: BTreeMap<B16, PassUsage>,
    pub messages: BTreeMap<B32, Message>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct InboxDelta {
    pub owner: Option<OwnerRecord>,
    pub time: Option<TimeAttestation>,
    pub revoked: BTreeMap<B16, Revocation>,
    pub usage: BTreeMap<B16, PassUsage>,
    pub messages: BTreeMap<B32, Message>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct OwnerRecord {
    pub owner_vk: ByteBuf,
    pub kem_ek: ByteBuf,
    pub issuer_vk: B32,
    pub pass_epoch: u32,
    pub prev_epoch_until: u64,
    pub version: u64,
    pub quarantine: QuarantineMode,
    pub tombstones: BTreeMap<B32, u64>,
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
    pub cert: ByteBuf,
    pub scoped_payload: ByteBuf,
    pub ghost_sig: B64,
}

/// Canonical CBOR of `value`.
pub fn encode<T: Serialize>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).expect("CBOR into a Vec");
    out
}

/// Decode `bytes`, refusing anything over the contract's input limit and any
/// encoding but the canonical one, as the contract does.
pub fn decode<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, String> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err("over the inbox size limit".into());
    }
    let value: T = ciborium::from_reader(bytes).map_err(|e| e.to_string())?;
    if encode(&value) != bytes {
        return Err("not canonical CBOR".into());
    }
    Ok(value)
}

// ── Signed byte layouts (big-endian, each with its own domain) ──────────────

fn layout(domain: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(domain.as_bytes());
    out
}

/// `"fmail/owner/v1" ‖ addr ‖ version ‖ pass_epoch ‖ prev_epoch_until ‖
/// issuer_vk ‖ quarantine ‖ len‖kem_ek ‖ count‖(id ‖ sent_time)*`
pub fn owner_bytes(addr: &[u8; 24], owner: &OwnerRecord) -> Vec<u8> {
    let mut out = layout("fmail/owner/v1");
    out.extend_from_slice(addr);
    out.extend_from_slice(&owner.version.to_be_bytes());
    out.extend_from_slice(&owner.pass_epoch.to_be_bytes());
    out.extend_from_slice(&owner.prev_epoch_until.to_be_bytes());
    out.extend_from_slice(owner.issuer_vk.as_slice());
    match owner.quarantine {
        QuarantineMode::Open => out.push(0),
        QuarantineMode::RequireGhost { min_usd: None } => out.extend_from_slice(&[1, 0]),
        QuarantineMode::RequireGhost { min_usd: Some(usd) } => {
            out.extend_from_slice(&[1, 1]);
            out.extend_from_slice(&usd.to_be_bytes());
        }
    }
    out.extend_from_slice(&(owner.kem_ek.len() as u32).to_be_bytes());
    out.extend_from_slice(&owner.kem_ek);
    out.extend_from_slice(&(owner.tombstones.len() as u32).to_be_bytes());
    for (id, sent_time) in &owner.tombstones {
        out.extend_from_slice(id.as_slice());
        out.extend_from_slice(&sent_time.to_be_bytes());
    }
    out
}

/// `"fmail/time/v1" ‖ addr ‖ owner_time`
pub fn time_bytes(addr: &[u8; 24], owner_time: u64) -> Vec<u8> {
    let mut out = layout("fmail/time/v1");
    out.extend_from_slice(addr);
    out.extend_from_slice(&owner_time.to_be_bytes());
    out
}

/// `"fmail/pass/v1" ‖ recipient ‖ pass_id ‖ pass_vk ‖ epoch ‖ expiry ‖ class`
pub fn cert_bytes(cert: &PassCert) -> Vec<u8> {
    let mut out = layout("fmail/pass/v1");
    out.extend_from_slice(cert.recipient.as_slice());
    out.extend_from_slice(cert.pass_id.as_slice());
    out.extend_from_slice(cert.pass_vk.as_slice());
    out.extend_from_slice(&cert.epoch.to_be_bytes());
    out.extend_from_slice(&cert.expiry.to_be_bytes());
    match cert.class {
        PassClass::Contact => out.push(0),
        PassClass::Invite { max_messages } => out.extend_from_slice(&[1, max_messages]),
    }
    out
}

/// `"fmail/revoke/v1" ‖ addr ‖ pass_id ‖ expiry ‖ epoch`
pub fn revocation_bytes(addr: &[u8; 24], pass_id: &[u8; 16], expiry: u64, epoch: u32) -> Vec<u8> {
    let mut out = layout("fmail/revoke/v1");
    out.extend_from_slice(addr);
    out.extend_from_slice(pass_id);
    out.extend_from_slice(&expiry.to_be_bytes());
    out.extend_from_slice(&epoch.to_be_bytes());
    out
}

/// `"fmail/usage/v1" ‖ addr ‖ pass_id ‖ used ‖ expiry ‖ owner_version`
pub fn usage_bytes(
    addr: &[u8; 24],
    pass_id: &[u8; 16],
    used: u8,
    expiry: u64,
    version: u64,
) -> Vec<u8> {
    let mut out = layout("fmail/usage/v1");
    out.extend_from_slice(addr);
    out.extend_from_slice(pass_id);
    out.push(used);
    out.extend_from_slice(&expiry.to_be_bytes());
    out.extend_from_slice(&version.to_be_bytes());
    out
}

fn stamped(domain: &str, recipient: &[u8; 24], sent_time: u64, ct_hash: &[u8; 32]) -> Vec<u8> {
    let mut out = layout(domain);
    out.extend_from_slice(recipient);
    out.extend_from_slice(&sent_time.to_be_bytes());
    out.extend_from_slice(ct_hash);
    out
}

/// The pass key's signature on a message.
pub fn admit_bytes(recipient: &[u8; 24], sent_time: u64, ct_hash: &[u8; 32]) -> Vec<u8> {
    stamped("fmail/admit/v1", recipient, sent_time, ct_hash)
}

/// The issuer key's signature on an owner message (decision 4).
pub fn owner_msg_bytes(recipient: &[u8; 24], sent_time: u64, ct_hash: &[u8; 32]) -> Vec<u8> {
    stamped("fmail/owner-msg/v1", recipient, sent_time, ct_hash)
}

/// What a Ghost Key proof signs as its `ScopedPayload.payload` (decision 1).
pub fn ghost_admit_bytes(recipient: &[u8; 24], sent_time: u64, ct_hash: &[u8; 32]) -> Vec<u8> {
    stamped("fmail/ghost-admit/v1", recipient, sent_time, ct_hash)
}

/// The sender's ML-DSA signature inside the envelope: `"fmail/sealed/v1" ‖
/// recipient ‖ blake3(body) ‖ sent_time ‖ kind ‖ (pass_id | ghost_vk | ∅)`.
/// `body_hash` is the hash of the envelope's body, which is inside the
/// ciphertext, so it can never be the ciphertext's hash.
pub fn inner_binding(
    recipient: &[u8; 24],
    body_hash: &[u8; 32],
    sent_time: u64,
    kind: u8,
    tag: &[u8],
) -> Vec<u8> {
    let mut out = layout("fmail/sealed/v1");
    out.extend_from_slice(recipient);
    out.extend_from_slice(body_hash);
    out.extend_from_slice(&sent_time.to_be_bytes());
    out.push(kind);
    out.extend_from_slice(tag);
    out
}

/// A message id (decision 11): the tag is the pass id for pass mail and the
/// claimed ghost key for proven quarantine mail.
pub fn message_id(
    recipient: &[u8; 24],
    ct_hash: &[u8; 32],
    sent_time: u64,
    kind: u8,
    tag: &[u8],
) -> [u8; 32] {
    let mut bytes = layout("fmail/msgid/v1");
    bytes.extend_from_slice(recipient);
    bytes.extend_from_slice(ct_hash);
    bytes.extend_from_slice(&sent_time.to_be_bytes());
    bytes.push(kind);
    bytes.extend_from_slice(tag);
    *blake3::hash(&bytes).as_bytes()
}

/// Whether the message `id` reached the inbox: held, or drained (tombstoned).
/// A filtered update returns no error, so a sender reads back (decision 9).
pub fn delivered(state: &InboxState, id: &[u8; 32]) -> bool {
    let id = ByteArray::new(*id);
    state.messages.contains_key(&id) || state.owner.tombstones.contains_key(&id)
}

// ── The sealed envelope (inside the ciphertext) ─────────────────────────────

/// A bearer pass: what lets its holder write to the cert's recipient.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Pass {
    pub cert: PassCert,
    /// The pass's Ed25519 secret key.
    pub pass_sk: B32,
}

impl std::fmt::Debug for Pass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pass")
            .field("cert", &self.cert)
            .finish_non_exhaustive()
    }
}

/// What the plaintext of a ciphertext holds: `len u32 ‖ CBOR(SealedEnvelope)
/// ‖ zeros` up to the padded size.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SealedEnvelope {
    /// The sender's ML-DSA verifying key.
    pub sender_vk: ByteBuf,
    /// ML-DSA over [`inner_binding`] of `blake3(body)`.
    pub sender_sig: ByteBuf,
    /// CBOR of [`SealedBody`], signed as it is.
    pub body: ByteBuf,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SealedBody {
    pub kind: EnvelopeKind,
    /// A pass to the sender's own inbox, so every message has a way back.
    pub reply_pass: Pass,
    pub pass_grant: Option<Pass>,
    /// For quarantine mail with a Ghost Key proof, the key the proof claims:
    /// the inner binding's tag, which the recipient checks against the id.
    pub ghost_vk: Option<B32>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum EnvelopeKind {
    /// Mail, as the UI composed it.
    Mail(ByteBuf),
    /// Never shown as mail.
    System(SystemMsg),
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum SystemMsg {
    /// The reply pass is a renewed or reissued certificate of a pass the
    /// recipient already holds.
    PassUpdate,
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: &str = include_str!("../../contracts/inbox-v2/tests/fixtures/vectors.txt");
    const ADDR: [u8; 24] = [0x11; 24];
    const T: u64 = 0x0102_0304_0506_0708;
    const SENT: u64 = 0x6800_0000 / 3600 * 3600;
    const EXPIRY: u64 = 0x6900_0000 / 86_400 * 86_400;
    const GRACE: u64 = 0x0A0B_0C0D_0E0F_1011;
    const HASH: [u8; 32] = [0x55; 32];

    fn expected(name: &str) -> Vec<u8> {
        let line = VECTORS
            .lines()
            .find(|l| l.split(' ').next() == Some(name))
            .unwrap_or_else(|| panic!("no vector {name}"));
        let hex = line.split(' ').nth(1).unwrap();
        (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn check(name: &str, actual: &[u8]) {
        assert_eq!(actual, expected(name).as_slice(), "vector {name}");
    }

    fn pass_id() -> B16 {
        ByteArray::new([0x22; 16])
    }
    fn key() -> B32 {
        ByteArray::new([0x33; 32])
    }
    fn sig() -> B64 {
        ByteArray::new([0x44; 64])
    }

    fn owner(quarantine: QuarantineMode) -> OwnerRecord {
        OwnerRecord {
            owner_vk: ByteBuf::from(vec![0x77; 4]),
            kem_ek: ByteBuf::from(vec![0xAA, 0xBB, 0xCC, 0xDD]),
            issuer_vk: key(),
            pass_epoch: 3,
            prev_epoch_until: GRACE,
            version: 7,
            quarantine,
            tombstones: BTreeMap::from([(ByteArray::new([0x66; 32]), 0x1000)]),
            sig: ByteBuf::from(vec![0x99; 4]),
        }
    }

    fn cert(class: PassClass) -> PassCert {
        PassCert {
            recipient: ByteArray::new(ADDR),
            pass_id: pass_id(),
            pass_vk: key(),
            epoch: 3,
            expiry: EXPIRY,
            class,
            sig: sig(),
        }
    }

    fn message(admission: Admission) -> Message {
        Message {
            ciphertext: ByteBuf::from(vec![0xCC; 3]),
            sent_time: SENT,
            admission,
        }
    }

    #[test]
    fn params_match_the_contract_vector() {
        check("params", &params_bytes(&ADDR, &[0x88; 32]));
    }

    #[test]
    fn every_signed_layout_matches_the_contract_vectors() {
        let mode = |min_usd| QuarantineMode::RequireGhost { min_usd };
        check(
            "owner_open",
            &owner_bytes(&ADDR, &owner(QuarantineMode::Open)),
        );
        check("owner_require", &owner_bytes(&ADDR, &owner(mode(None))));
        check("owner_require5", &owner_bytes(&ADDR, &owner(mode(Some(5)))));
        check("time", &time_bytes(&ADDR, T));
        check("cert_contact", &cert_bytes(&cert(PassClass::Contact)));
        check(
            "cert_invite",
            &cert_bytes(&cert(PassClass::Invite { max_messages: 3 })),
        );
        check(
            "revocation",
            &revocation_bytes(&ADDR, &[0x22; 16], EXPIRY, 3),
        );
        check("usage", &usage_bytes(&ADDR, &[0x22; 16], 2, EXPIRY, 7));
        check("admit", &admit_bytes(&ADDR, SENT, &HASH));
        check("owner_msg", &owner_msg_bytes(&ADDR, SENT, &HASH));
        check("ghost_admit", &ghost_admit_bytes(&ADDR, SENT, &HASH));
        check(
            "sealed_pass",
            &inner_binding(&ADDR, &HASH, SENT, KIND_PASS, &[0x22; 16]),
        );
        check(
            "sealed_owner",
            &inner_binding(&ADDR, &HASH, SENT, KIND_OWNER, &[]),
        );
        check(
            "sealed_quarantine",
            &inner_binding(&ADDR, &HASH, SENT, KIND_QUARANTINE, &[0x33; 32]),
        );
        check(
            "id_pass",
            &message_id(&ADDR, &HASH, SENT, KIND_PASS, &[0x22; 16]),
        );
        check("id_owner", &message_id(&ADDR, &HASH, SENT, KIND_OWNER, &[]));
        check(
            "id_quarantine",
            &message_id(&ADDR, &HASH, SENT, KIND_QUARANTINE, &[]),
        );
        check(
            "id_quarantine_proven",
            &message_id(&ADDR, &HASH, SENT, KIND_QUARANTINE, &[0x33; 32]),
        );
    }

    fn wire<T>(name: &str, value: &T)
    where
        T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        check(name, &encode(value));
        assert_eq!(
            &decode::<T>(&expected(name)).unwrap(),
            value,
            "{name} decodes"
        );
    }

    #[test]
    fn every_wire_type_matches_the_contract_vectors() {
        let require5 = QuarantineMode::RequireGhost { min_usd: Some(5) };
        wire("cbor_owner_open_mode", &QuarantineMode::Open);
        wire("cbor_owner", &owner(require5));
        let time = TimeAttestation {
            owner_time: T,
            sig: sig(),
        };
        wire("cbor_time", &time);
        let revocation = Revocation {
            pass_id: pass_id(),
            expiry: EXPIRY,
            epoch: 3,
            sig: sig(),
        };
        wire("cbor_revocation", &revocation);
        let usage = PassUsage {
            pass_id: pass_id(),
            used: 2,
            expiry: EXPIRY,
            owner_version: 7,
            sig: sig(),
        };
        wire("cbor_usage", &usage);
        let invite = cert(PassClass::Invite { max_messages: 3 });
        wire("cbor_cert", &invite);
        wire(
            "cbor_pass_message",
            &message(Admission::Pass {
                cert: invite,
                msg_sig: sig(),
            }),
        );
        wire(
            "cbor_owner_message",
            &message(Admission::Owner { sig: sig() }),
        );
        let proof = GhostProof {
            cert: ByteBuf::from(vec![0xC1, 0xC2]),
            scoped_payload: ByteBuf::from(vec![0xD1]),
            ghost_sig: sig(),
        };
        wire(
            "cbor_quarantine_message",
            &message(Admission::Quarantine { ghost: Some(proof) }),
        );
        let bare = Admission::Quarantine { ghost: None };
        let state = InboxState {
            owner: owner(require5),
            time: time.clone(),
            revoked: BTreeMap::from([(pass_id(), revocation)]),
            usage: BTreeMap::from([(pass_id(), usage)]),
            messages: BTreeMap::from([(ByteArray::new(HASH), message(bare))]),
        };
        wire("cbor_state", &state);
        let delta = InboxDelta {
            owner: None,
            time: Some(time),
            revoked: BTreeMap::new(),
            usage: BTreeMap::new(),
            messages: BTreeMap::from([(
                ByteArray::new(HASH),
                message(Admission::Owner { sig: sig() }),
            )]),
        };
        wire("cbor_delta", &delta);
    }

    #[test]
    fn a_non_canonical_encoding_is_refused() {
        let mut bytes = encode(&TimeAttestation {
            owner_time: 5,
            sig: sig(),
        });
        // `owner_time: 5` as a two-byte integer instead of one.
        let at = bytes.iter().position(|b| *b == 0x05).unwrap();
        bytes.splice(at..=at, [0x18, 0x05]);
        assert!(decode::<TimeAttestation>(&bytes).is_err());
    }
}
