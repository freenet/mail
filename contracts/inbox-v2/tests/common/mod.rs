//! Builds genuine signed pieces, with fixed keys, for the tests.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::OnceLock;

use ed25519_dalek::Signer as _;
use freenet_email_inbox_v2::Params;
use freenet_email_inbox_v2::signed::*;
use freenet_email_inbox_v2::types::*;
use freenet_stdlib::prelude::{ContractInstanceId, UpdateData};
use ghostkey_common::{ScopedPayload, SignatureRequestor};
use ml_dsa::signature::{Keypair, Signer as _};
use serde_bytes::{ByteArray, ByteBuf};

pub use freenet_email_inbox_v2::merge::{Rules, WEBAPP_REQUESTOR};

pub const HOUR: u64 = 3600;
pub const DAY: u64 = 86400;

pub struct Ghost {
    pub amount: u64,
    pub sk: ed25519_dalek::SigningKey,
    pub cert: Vec<u8>,
}

#[derive(Clone)]
pub struct Pass {
    pub cert: PassCert,
    pub sk: ed25519_dalek::SigningKey,
}

pub struct World {
    pub params: Params,
    pub dsa: ml_dsa::SigningKey<ml_dsa::MlDsa65>,
    pub owner_vk: Vec<u8>,
    pub kem_ek: Vec<u8>,
    pub issuer: ed25519_dalek::SigningKey,
    pub ghosts: Vec<Ghost>,
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

/// tests/fixtures/ghost-keys.txt: a test master's verifying key, then
/// `cert <usd> <ghost sk> <cert cbor> <unused>` per key. Made once with
/// ghostkey_lib 0.2 (tests/fixtures/README.md).
fn fixture() -> ([u8; 32], Vec<Ghost>) {
    let text = include_str!("../fixtures/ghost-keys.txt");
    let mut master = [0u8; 32];
    let mut ghosts = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "master_vk" => master.copy_from_slice(&hex(f[1])),
            "cert" => {
                let sk: [u8; 32] = hex(f[2]).try_into().unwrap();
                ghosts.push(Ghost {
                    amount: f[1].parse().unwrap(),
                    sk: ed25519_dalek::SigningKey::from_bytes(&sk),
                    cert: hex(f[3]),
                });
            }
            other => panic!("fixture line {other}"),
        }
    }
    (master, ghosts)
}

pub fn world() -> &'static World {
    static WORLD: OnceLock<World> = OnceLock::new();
    WORLD.get_or_init(|| {
        let dsa = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&[7u8; 32].into());
        let owner_vk = dsa.verifying_key().encode().to_vec();
        let (ghost_master, ghosts) = fixture();
        World {
            params: Params {
                addr: address_of(&owner_vk),
                ghost_master,
            },
            dsa,
            owner_vk,
            kem_ek: vec![0xE1; 1184],
            issuer: ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]),
            ghosts,
        }
    })
}

pub fn sign64(key: &ed25519_dalek::SigningKey, bytes: &[u8]) -> B64 {
    ByteArray::new(key.sign(bytes).to_bytes())
}

pub fn ct(size: usize, tag: u64) -> Vec<u8> {
    let mut ct = vec![0xC7u8; size];
    ct[..8].copy_from_slice(&tag.to_be_bytes());
    ct
}

pub fn id_of(key: u64) -> B16 {
    let mut id = [0u8; 16];
    id[8..].copy_from_slice(&key.to_be_bytes());
    ByteArray::new(id)
}

impl World {
    pub fn addr(&self) -> B24 {
        ByteArray::new(self.params.addr)
    }

    /// An owner record with no previous-epoch grace.
    pub fn owner(
        &self,
        version: u64,
        pass_epoch: u32,
        quarantine: QuarantineMode,
        tombstones: BTreeMap<B32, u64>,
    ) -> OwnerRecord {
        self.owner_grace(version, pass_epoch, 0, quarantine, tombstones)
    }

    /// An owner record whose previous epoch lasts until `prev_epoch_until`.
    pub fn owner_grace(
        &self,
        version: u64,
        pass_epoch: u32,
        prev_epoch_until: u64,
        quarantine: QuarantineMode,
        tombstones: BTreeMap<B32, u64>,
    ) -> OwnerRecord {
        let mut owner = OwnerRecord {
            owner_vk: ByteBuf::from(self.owner_vk.clone()),
            kem_ek: ByteBuf::from(self.kem_ek.clone()),
            issuer_vk: ByteArray::new(self.issuer.verifying_key().to_bytes()),
            pass_epoch,
            prev_epoch_until,
            version,
            quarantine,
            tombstones,
            sig: ByteBuf::new(),
        };
        self.sign_owner(&mut owner);
        owner
    }

    pub fn sign_owner(&self, owner: &mut OwnerRecord) {
        let sig: ml_dsa::Signature<ml_dsa::MlDsa65> =
            self.dsa.sign(&owner_bytes(&self.params.addr, owner));
        owner.sig = ByteBuf::from(sig.encode().to_vec());
    }

    pub fn time(&self, owner_time: u64) -> TimeAttestation {
        TimeAttestation {
            owner_time,
            sig: sign64(&self.issuer, &time_bytes(&self.params.addr, owner_time)),
        }
    }

    pub fn revocation(&self, pass_id: B16, expiry: u64, epoch: u32) -> Revocation {
        let bytes = revocation_bytes(&self.params.addr, &pass_id, expiry, epoch);
        Revocation {
            pass_id,
            expiry,
            epoch,
            sig: sign64(&self.issuer, &bytes),
        }
    }

    /// A usage entry that counts from owner version 1.
    pub fn usage(&self, pass_id: B16, used: u8, expiry: u64) -> PassUsage {
        self.usage_at(pass_id, used, expiry, 1)
    }

    pub fn usage_at(&self, pass_id: B16, used: u8, expiry: u64, owner_version: u64) -> PassUsage {
        let bytes = usage_bytes(&self.params.addr, &pass_id, used, expiry, owner_version);
        PassUsage {
            pass_id,
            used,
            expiry,
            owner_version,
            sig: sign64(&self.issuer, &bytes),
        }
    }

    pub fn pass(&self, key: u64, epoch: u32, expiry: u64, class: PassClass) -> Pass {
        let mut seed = [0x55u8; 32];
        seed[..8].copy_from_slice(&key.to_be_bytes());
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let mut cert = PassCert {
            recipient: self.addr(),
            pass_id: id_of(key),
            pass_vk: ByteArray::new(sk.verifying_key().to_bytes()),
            epoch,
            expiry,
            class,
            sig: ByteArray::new([0; 64]),
        };
        cert.sig = sign64(&self.issuer, &cert_bytes(&cert));
        Pass { cert, sk }
    }

    pub fn pass_msg(&self, pass: &Pass, ct: Vec<u8>, sent_time: u64) -> (B32, Message) {
        let hash = *blake3::hash(&ct).as_bytes();
        let msg_sig = sign64(&pass.sk, &admit_bytes(&self.params.addr, sent_time, &hash));
        self.keyed(
            ct,
            sent_time,
            Admission::Pass {
                cert: pass.cert.clone(),
                msg_sig,
            },
        )
    }

    pub fn owner_msg(&self, ct: Vec<u8>, sent_time: u64) -> (B32, Message) {
        let hash = *blake3::hash(&ct).as_bytes();
        let sig = sign64(
            &self.issuer,
            &owner_msg_bytes(&self.params.addr, sent_time, &hash),
        );
        self.keyed(ct, sent_time, Admission::Owner { sig })
    }

    pub fn proof(&self, ghost: usize, ct: &[u8], sent_time: u64) -> GhostProof {
        let hash = *blake3::hash(ct).as_bytes();
        let payload = ghost_admit_bytes(&self.params.addr, sent_time, &hash);
        self.proof_over(ghost, payload, WEBAPP_REQUESTOR)
    }

    pub fn proof_over(&self, ghost: usize, payload: Vec<u8>, requestor: [u8; 32]) -> GhostProof {
        let g = &self.ghosts[ghost];
        let scoped = ghostkey_common::to_cbor(&ScopedPayload {
            requestor: SignatureRequestor::WebApp(ContractInstanceId::new(requestor)),
            payload,
        })
        .unwrap();
        GhostProof {
            cert: ByteBuf::from(g.cert.clone()),
            ghost_sig: sign64(&g.sk, &scoped),
            scoped_payload: ByteBuf::from(scoped),
        }
    }

    pub fn quarantine_msg(
        &self,
        ct: Vec<u8>,
        sent_time: u64,
        ghost: Option<usize>,
    ) -> (B32, Message) {
        let ghost = ghost.map(|g| self.proof(g, &ct, sent_time));
        self.keyed(ct, sent_time, Admission::Quarantine { ghost })
    }

    /// `(id, message)` with the id the message's contents derive.
    pub fn keyed(&self, ct: Vec<u8>, sent_time: u64, admission: Admission) -> (B32, Message) {
        let message = Message {
            ciphertext: ByteBuf::from(ct),
            sent_time,
            admission,
        };
        let hash = *blake3::hash(&message.ciphertext).as_bytes();
        (
            ByteArray::new(message_id(&self.params.addr, &message, &hash)),
            message,
        )
    }

    /// A raw state, valid or not, from its pieces.
    pub fn raw(
        &self,
        owner: OwnerRecord,
        time: TimeAttestation,
        revoked: impl IntoIterator<Item = Revocation>,
        usage: impl IntoIterator<Item = PassUsage>,
        messages: impl IntoIterator<Item = (B32, Message)>,
    ) -> InboxState {
        InboxState {
            owner,
            time,
            revoked: revoked.into_iter().map(|r| (r.pass_id, r)).collect(),
            usage: usage.into_iter().map(|u| (u.pass_id, u)).collect(),
            messages: messages.into_iter().collect(),
        }
    }
}

pub fn update_state(bytes: Vec<u8>) -> Vec<UpdateData<'static>> {
    vec![UpdateData::State(bytes.into())]
}

/// `state` re-spelled so it decodes to the same value, or with one thing added.
pub fn non_canonical_forms(state: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    use ciborium::Value;
    assert_eq!(state[0], 0xA5, "a five-field map");
    let mut forms = Vec::new();

    let mut trailing = state.to_vec();
    trailing.push(0x00);
    forms.push(("trailing byte", trailing));

    let mut long_len = vec![0xB8, 0x05];
    long_len.extend_from_slice(&state[1..]);
    forms.push(("non-minimal map length", long_len));

    let mut indefinite = vec![0xBF];
    indefinite.extend_from_slice(&state[1..]);
    indefinite.push(0xFF);
    forms.push(("indefinite map", indefinite));

    let reencode = |value: &Value| {
        let mut out = Vec::new();
        ciborium::into_writer(value, &mut out).unwrap();
        out
    };
    let value: Value = ciborium::from_reader(state).unwrap();
    let Value::Map(fields) = value.clone() else {
        panic!("a map")
    };

    let mut extra = fields.clone();
    extra.push((Value::Text("extra".into()), Value::Integer(1.into())));
    forms.push(("unknown field", reencode(&Value::Map(extra))));

    let mut swapped = fields.clone();
    swapped.swap(0, 1);
    forms.push(("fields out of order", reencode(&Value::Map(swapped))));

    // Keys of a collection: repeat one, and reverse them.
    for field in ["revoked", "usage", "messages"] {
        let at = fields
            .iter()
            .position(|(k, _)| k.as_text() == Some(field))
            .unwrap();
        let Value::Map(entries) = &fields[at].1 else {
            panic!("a map")
        };
        if let Some(first) = entries.first() {
            let mut dup = fields.clone();
            let mut with_dup = entries.clone();
            with_dup.insert(0, first.clone());
            dup[at].1 = Value::Map(with_dup);
            forms.push(("duplicate key", reencode(&Value::Map(dup))));
        }
        if entries.len() >= 2 {
            let mut rev = fields.clone();
            rev[at].1 = Value::Map(entries.iter().rev().cloned().collect());
            forms.push(("unsorted keys", reencode(&Value::Map(rev))));
        }
    }
    forms
}
