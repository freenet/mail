//! The merge: the contract's rules, in one function.
//!
//! `merge` takes any number of parts and is symmetric in them: it joins what
//! has an order, unions the rest, then filters and caps the union. A state is
//! valid exactly when merging it alone gives it back. Steps:
//!
//! 1. Owner record: the maximum by `(version, blake3)`.
//! 2. Time: the highest `owner_time` that verifies under the joined owner.
//! 3. Union of revocations, usage entries and messages. An item that does not
//!    verify under the joined owner is dropped here, so it can neither revoke a
//!    pass nor push a genuine item out of a cap.
//! 4. Prune, then cap, revocations and usage entries.
//! 5. Filter each message against the owner, the time and the UNPRUNED
//!    revocations. One message per id: the smallest encoding that passed.
//! 6. Cap the messages, by pool.
//!
//! Only an owner record that fails, or no time that verifies, refuses the input.
//! Anything else that fails is dropped without an error, so a sender reads back
//! to learn whether its message landed. Dropping a message is what the filter
//! does to anything the owner's later acts rule out, so a client drains before
//! it signs a change that would drop mail.
//!
//! Caps and removals make the merge heal-guarded associative, not strictly
//! associative, which is the law core checks. `tests/merge_laws.rs` holds it.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, VerifyingKey};
use freenet_stdlib::prelude::ContractInstanceId;
use ghostkey_verify::GhostkeyCertificate;
use ml_dsa::MlDsa65;
use ml_dsa::signature::Verifier as _;
use serde::Deserialize;

use crate::Params;
use crate::signed::{
    admit_bytes, cert_bytes, ghost_admit_bytes, message_id, owner_bytes, owner_msg_bytes,
    revocation_bytes, time_bytes, usage_bytes,
};
use crate::types::{
    Admission, B16, B32, GhostProof, InboxDelta, InboxState, Malformed, Message, OwnerRecord,
    PassCert, PassClass, PassUsage, QuarantineMode, Revocation, TimeAttestation, encode,
};

/// How far `sent_time` may trail `owner_time`.
pub const WINDOW_BACK: u64 = 2 * 86_400;
/// How far `sent_time` may lead `owner_time`.
pub const WINDOW_FORWARD: u64 = 400 * 86_400;
/// `sent_time` is a whole hour.
pub const SENT_TIME_GRANULARITY: u64 = 3_600;
/// Ciphertext is padded to one of these.
pub const CIPHERTEXT_SIZES: [usize; 3] = [8 * 1024, 16 * 1024, 32 * 1024];
const KEM_EK_LEN: usize = 1184;
/// A proof's signed payload. Generous: ours is about 200 bytes of CBOR.
pub const MAX_SCOPED_PAYLOAD: usize = 1024;

/// The webapp contract `GeQLXXR8sfGe31BNRJoVxkvGUTnBkufJ4gTaoX5NWnU5`, the only
/// requestor a Ghost Key proof is accepted from. Its id never changes.
pub const WEBAPP_REQUESTOR: [u8; 32] = [
    0xe8, 0x74, 0x2e, 0x40, 0xd4, 0x1f, 0x5a, 0x47, 0xf5, 0xb3, 0xda, 0x96, 0x73, 0x37, 0x33, 0xd0,
    0x39, 0x1e, 0xd9, 0xec, 0x29, 0x43, 0x1e, 0xde, 0x09, 0x71, 0x2b, 0xf9, 0x19, 0x3f, 0xbc, 0x4e,
];

/// What `NotaryInfo.action` says on a donation certificate.
const DONATION_ACTION: &str = "freenet-donation";

/// The numbers in the rules. Everything takes them as an argument, so tests
/// can run the same code with caps small enough to overflow cheaply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rules {
    /// Messages held per contact pass.
    pub per_pass: usize,
    /// Messages held per invite.
    pub per_invite: usize,
    pub pass_pool: usize,
    pub owner_pool: usize,
    pub quarantine: usize,
    /// Quarantine messages per ghost key, in RequireGhost inboxes.
    pub per_ghost: usize,
    pub revoked: usize,
    pub usage: usize,
    pub tombstones: usize,
}

impl Rules {
    pub const V1: Rules = Rules {
        per_pass: 8,
        per_invite: 2,
        pass_pool: 64,
        owner_pool: 8,
        quarantine: 16,
        per_ghost: 2,
        revoked: 4096,
        usage: 1024,
        tombstones: 4096,
    };
}

/// The vault's `ScopedPayload`, read with the shapes `ghostkey-common` writes.
#[derive(Deserialize)]
struct ScopedPayload {
    requestor: Requestor,
    payload: Vec<u8>,
}

#[derive(Deserialize)]
enum Requestor {
    WebApp(ContractInstanceId),
    Delegate(serde::de::IgnoredAny),
}

fn verify_ed25519(key: &VerifyingKey, bytes: &[u8], sig: &[u8; 64]) -> bool {
    key.verify_strict(bytes, &Signature::from_bytes(sig)).is_ok()
}

fn verify_owner(rules: &Rules, params: &Params, owner: &OwnerRecord) -> Result<(), Malformed> {
    if crate::signed::address_of(&owner.owner_vk) != params.addr {
        return Err(Malformed("owner key is not this address"));
    }
    if owner.kem_ek.len() != KEM_EK_LEN {
        return Err(Malformed("owner KEM key"));
    }
    if owner.tombstones.len() > rules.tombstones {
        return Err(Malformed("too many tombstones"));
    }
    let vk = owner
        .owner_vk
        .as_slice()
        .try_into()
        .map(ml_dsa::VerifyingKey::<MlDsa65>::decode)
        .map_err(|_| Malformed("owner key"))?;
    let sig = ml_dsa::Signature::<MlDsa65>::try_from(owner.sig.as_slice())
        .map_err(|_| Malformed("owner signature"))?;
    vk.verify(&owner_bytes(&params.addr, owner), &sig)
        .map_err(|_| Malformed("owner signature"))
}

/// Step 1. Every candidate must be genuine: a part naming a forged owner is
/// refused rather than merged around.
fn join_owner(
    rules: &Rules,
    params: &Params,
    parts: &[InboxDelta],
) -> Result<OwnerRecord, Malformed> {
    let mut best: Option<((u64, [u8; 32]), &OwnerRecord)> = None;
    let mut seen = BTreeSet::new();
    for owner in parts.iter().filter_map(|part| part.owner.as_ref()) {
        let digest = *blake3::hash(&encode(owner)).as_bytes();
        if !seen.insert(digest) {
            continue;
        }
        verify_owner(rules, params, owner)?;
        let rank = (owner.version, digest);
        if best.as_ref().is_none_or(|(b, _)| rank > *b) {
            best = Some((rank, owner));
        }
    }
    best.map(|(_, owner)| owner.clone())
        .ok_or(Malformed("no owner record"))
}

/// Step 2.
fn join_time(
    params: &Params,
    issuer: &VerifyingKey,
    parts: &[InboxDelta],
) -> Result<TimeAttestation, Malformed> {
    let mut best: Option<&TimeAttestation> = None;
    for time in parts.iter().filter_map(|part| part.time.as_ref()) {
        if best.is_some_and(|b| (b.owner_time, &b.sig) >= (time.owner_time, &time.sig)) {
            continue;
        }
        if verify_ed25519(issuer, &time_bytes(&params.addr, time.owner_time), &time.sig) {
            best = Some(time);
        }
    }
    best.cloned().ok_or(Malformed("no time attestation"))
}

/// What a message that passed the filter counts against.
enum Slot {
    Pass { pass_id: B16, limit: usize },
    Owner,
    Quarantine { ghost: Option<[u8; 32]> },
}

/// A certificate that passed: its ghost key and tier.
#[derive(Clone, Copy)]
struct Ghost {
    key: [u8; 32],
    usd: u64,
}

/// Step 5's inputs, and the memos that verify each distinct certificate once.
struct Filter<'a> {
    rules: &'a Rules,
    params: &'a Params,
    owner: &'a OwnerRecord,
    issuer: VerifyingKey,
    owner_time: u64,
    unpruned_revoked: BTreeSet<B16>,
    usage: &'a BTreeMap<B16, PassUsage>,
    /// While the kept revocations are at their cap, some may have been lost,
    /// so no pass can be trusted. The bump of `pass_epoch` is the way out.
    revocations_full: bool,
    certs: BTreeMap<Vec<u8>, bool>,
    ghosts: BTreeMap<Vec<u8>, Option<Ghost>>,
}

impl Filter<'_> {
    fn admit(&mut self, id: &B32, message: &Message) -> Option<Slot> {
        if !CIPHERTEXT_SIZES.contains(&message.ciphertext.len())
            || message.sent_time % SENT_TIME_GRANULARITY != 0
            || message.sent_time < self.owner_time.saturating_sub(WINDOW_BACK)
            || message.sent_time > self.owner_time.saturating_add(WINDOW_FORWARD)
            || self.owner.tombstones.contains_key(id)
        {
            return None;
        }
        let ct_hash = *blake3::hash(&message.ciphertext).as_bytes();
        if message_id(&self.params.addr, message, &ct_hash) != **id {
            return None;
        }
        let sent_time = message.sent_time;
        match &message.admission {
            Admission::Pass { cert, msg_sig } => {
                self.admit_pass(cert, msg_sig, sent_time, &ct_hash)
            }
            Admission::Owner { sig } => {
                let bytes = owner_msg_bytes(&self.params.addr, sent_time, &ct_hash);
                verify_ed25519(&self.issuer, &bytes, sig).then_some(Slot::Owner)
            }
            Admission::Quarantine { ghost } => {
                self.admit_quarantine(ghost.as_ref(), sent_time, &ct_hash)
            }
        }
    }

    fn admit_pass(
        &mut self,
        cert: &PassCert,
        msg_sig: &[u8; 64],
        sent_time: u64,
        ct_hash: &[u8; 32],
    ) -> Option<Slot> {
        if *cert.recipient != self.params.addr
            || cert.epoch != self.owner.pass_epoch
            || sent_time >= cert.expiry
            || self.revocations_full
            || self.unpruned_revoked.contains(&cert.pass_id)
            || !self.cert_is_genuine(cert)
        {
            return None;
        }
        let pass_key = VerifyingKey::from_bytes(&cert.pass_vk).ok()?;
        let bytes = admit_bytes(&self.params.addr, sent_time, ct_hash);
        verify_ed25519(&pass_key, &bytes, msg_sig).then(|| Slot::Pass {
            pass_id: cert.pass_id,
            limit: self.pass_limit(cert),
        })
    }

    /// The whole certificate, never its id, keys the memo: a pass id can have
    /// several certificates, and a forged one must not ride on a genuine one.
    fn cert_is_genuine(&mut self, cert: &PassCert) -> bool {
        let mut bytes = cert_bytes(cert);
        bytes.extend_from_slice(cert.sig.as_slice());
        if let Some(known) = self.certs.get(&bytes) {
            return *known;
        }
        let genuine = verify_ed25519(&self.issuer, &bytes[..bytes.len() - 64], &cert.sig);
        self.certs.insert(bytes, genuine);
        genuine
    }

    /// How many messages this certificate may have held at once.
    fn pass_limit(&self, cert: &PassCert) -> usize {
        match cert.class {
            PassClass::Contact => self.rules.per_pass,
            PassClass::Invite { max_messages } => {
                let used = self.usage.get(&cert.pass_id).map_or(0, |entry| entry.used);
                let left = usize::from(max_messages.saturating_sub(used));
                left.min(self.rules.per_invite)
            }
        }
    }

    /// In an Open inbox a proof is size-capped and otherwise ignored: nothing
    /// public may rest on it there. In a RequireGhost inbox it decides.
    fn admit_quarantine(
        &mut self,
        proof: Option<&GhostProof>,
        sent_time: u64,
        ct_hash: &[u8; 32],
    ) -> Option<Slot> {
        if proof.is_some_and(|p| {
            p.cert.len() > ghostkey_verify::MAX_CERTIFICATE_BYTES
                || p.scoped_payload.len() > MAX_SCOPED_PAYLOAD
        }) {
            return None;
        }
        let QuarantineMode::RequireGhost { min_usd } = self.owner.quarantine else {
            return Some(Slot::Quarantine { ghost: None });
        };
        let proof = proof?;
        let ghost = self.verify_proof(proof, sent_time, ct_hash)?;
        (ghost.usd >= u64::from(min_usd.unwrap_or(0))).then_some(Slot::Quarantine {
            ghost: Some(ghost.key),
        })
    }

    fn verify_proof(
        &mut self,
        proof: &GhostProof,
        sent_time: u64,
        ct_hash: &[u8; 32],
    ) -> Option<Ghost> {
        let scoped: ScopedPayload = ciborium::from_reader(proof.scoped_payload.as_slice()).ok()?;
        let Requestor::WebApp(requestor) = scoped.requestor else {
            return None;
        };
        if *requestor.as_bytes() != WEBAPP_REQUESTOR
            || scoped.payload != ghost_admit_bytes(&self.params.addr, sent_time, ct_hash)
        {
            return None;
        }
        // Cheapest first: the payload signature, before the chain's RSA.
        let cert = GhostkeyCertificate::from_cbor(&proof.cert).ok()?;
        if cert.to_cbor() != *proof.cert {
            return None;
        }
        let claimed = cert.claimed_ghost_key();
        ghostkey_verify::verify_payload_signature(
            claimed,
            &proof.scoped_payload,
            proof.ghost_sig.as_slice(),
        )
        .ok()?;
        if let Some(known) = self.ghosts.get(proof.cert.as_slice()) {
            return *known;
        }
        let ghost = verify_chain(self.params, &cert);
        self.ghosts.insert(proof.cert.to_vec(), ghost);
        ghost
    }
}

fn verify_chain(params: &Params, cert: &GhostkeyCertificate) -> Option<Ghost> {
    let master = VerifyingKey::from_bytes(&params.ghost_master).ok()?;
    let verified = cert.verify(&master).ok()?;
    let info = verified.notary_info().ok()?;
    (info.action == DONATION_ACTION).then(|| Ghost {
        key: verified.ghost_key().to_bytes(),
        usd: info.amount,
    })
}

/// Step 3 for the signed pass bookkeeping: on one pass id the entry that keeps
/// the most, with `rank` deciding, which is a join.
fn join_entry<V: Clone + PartialEq, R: Ord>(
    into: &mut BTreeMap<B16, V>,
    key: B16,
    value: V,
    rank: impl Fn(&V) -> R,
    genuine: impl Fn(&V) -> bool,
) {
    let keep = match into.get(&key) {
        Some(held) => *held != value && rank(&value) > rank(held),
        None => true,
    };
    if keep && genuine(&value) {
        into.insert(key, value);
    }
}

/// The merge. `parts` must name at least one owner and one time.
pub fn merge(
    rules: &Rules,
    params: &Params,
    parts: Vec<InboxDelta>,
) -> Result<InboxState, Malformed> {
    let owner = join_owner(rules, params, &parts)?;
    let issuer =
        VerifyingKey::from_bytes(&owner.issuer_vk).map_err(|_| Malformed("issuer key"))?;
    let time = join_time(params, &issuer, &parts)?;

    let mut revoked = BTreeMap::new();
    let mut usage = BTreeMap::new();
    let mut candidates: BTreeMap<B32, Vec<Message>> = BTreeMap::new();
    for part in parts {
        for (key, entry) in part.revoked {
            join_entry(
                &mut revoked,
                key,
                entry,
                |r: &Revocation| (r.expiry, r.epoch, r.sig),
                |r| {
                    let bytes = revocation_bytes(&params.addr, &r.pass_id, r.expiry, r.epoch);
                    r.pass_id == key && verify_ed25519(&issuer, &bytes, &r.sig)
                },
            );
        }
        for (key, entry) in part.usage {
            join_entry(
                &mut usage,
                key,
                entry,
                |u: &PassUsage| (u.used, u.expiry, u.sig),
                |u| {
                    let bytes = usage_bytes(&params.addr, &u.pass_id, u.used, u.expiry);
                    u.pass_id == key && verify_ed25519(&issuer, &bytes, &u.sig)
                },
            );
        }
        for (id, message) in part.messages {
            let at_id = candidates.entry(id).or_default();
            if !at_id.contains(&message) {
                at_id.push(message);
            }
        }
    }

    // Step 4. The filter reads the union as it was before pruning.
    let unpruned_revoked: BTreeSet<B16> = revoked.keys().copied().collect();
    let expired = |expiry: u64| expiry.saturating_add(WINDOW_BACK) <= time.owner_time;
    revoked.retain(|_, r: &mut Revocation| !expired(r.expiry) && r.epoch >= owner.pass_epoch);
    usage.retain(|_, u: &mut PassUsage| !expired(u.expiry));
    // Keeping the smallest ids absorbs redelivery: order does not matter.
    while revoked.len() > rules.revoked {
        revoked.pop_last();
    }
    while usage.len() > rules.usage {
        usage.pop_last();
    }

    // Step 5.
    let mut filter = Filter {
        rules,
        params,
        owner: &owner,
        issuer,
        owner_time: time.owner_time,
        unpruned_revoked,
        usage: &usage,
        revocations_full: revoked.len() >= rules.revoked,
        certs: BTreeMap::new(),
        ghosts: BTreeMap::new(),
    };
    let mut admitted: Vec<(B32, Message, Slot)> = Vec::new();
    for (id, at_id) in candidates {
        let mut best: Option<(Vec<u8>, Message, Slot)> = None;
        for message in at_id {
            let Some(slot) = filter.admit(&id, &message) else {
                continue;
            };
            let encoding = encode(&message);
            let smaller = |held: &(Vec<u8>, Message, Slot)| {
                (encoding.len(), &encoding) < (held.0.len(), &held.0)
            };
            if best.as_ref().is_none_or(smaller) {
                best = Some((encoding, message, slot));
            }
        }
        if let Some((_, message, slot)) = best {
            admitted.push((id, message, slot));
        }
    }

    // Step 6.
    let salt = blake3::hash(&encode(&time));
    let messages = cap_messages(rules, salt.as_bytes(), admitted);
    Ok(InboxState {
        owner,
        time,
        revoked,
        usage,
        messages,
    })
}

/// Which admitted messages stay. Each pool's order is total and each message's
/// rank within it depends only on the pool's members.
fn cap_messages(
    rules: &Rules,
    salt: &[u8; 32],
    admitted: Vec<(B32, Message, Slot)>,
) -> BTreeMap<B32, Message> {
    let mut by_pass: BTreeMap<B16, Vec<(u64, B32, usize)>> = BTreeMap::new();
    let mut owner_pool = Vec::new();
    let mut quarantine = Vec::new();
    let mut messages: BTreeMap<B32, Message> = BTreeMap::new();
    for (id, message, slot) in admitted {
        match slot {
            Slot::Pass { pass_id, limit } => {
                by_pass.entry(pass_id).or_default().push((message.sent_time, id, limit));
            }
            Slot::Owner => owner_pool.push((message.sent_time, id)),
            Slot::Quarantine { ghost } => {
                let mut ranked = blake3::Hasher::new();
                ranked.update(salt);
                ranked.update(id.as_slice());
                quarantine.push((*ranked.finalize().as_bytes(), id, ghost));
            }
        }
        messages.insert(id, message);
    }

    // Pass pool: round robin. k is a message's position within its own pass,
    // so every pass gets its first message in before any gets its second.
    let mut pool = Vec::new();
    for mut held in by_pass.into_values() {
        held.sort_unstable();
        let mut k = 0;
        for (sent_time, id, limit) in held {
            if k < limit {
                pool.push((k, sent_time, id));
                k += 1;
            }
        }
    }
    pool.sort_unstable();
    let mut keep: BTreeSet<B32> = pool
        .into_iter()
        .take(rules.pass_pool)
        .map(|(_, _, id)| id)
        .collect();

    owner_pool.sort_unstable();
    keep.extend(owner_pool.into_iter().take(rules.owner_pool).map(|(_, id)| id));

    quarantine.sort_unstable();
    let mut per_ghost: BTreeMap<[u8; 32], usize> = BTreeMap::new();
    let mut slots = 0;
    for (_, id, ghost) in quarantine {
        if slots == rules.quarantine {
            break;
        }
        if let Some(key) = ghost {
            let held = per_ghost.entry(key).or_default();
            if *held == rules.per_ghost {
                continue;
            }
            *held += 1;
        }
        keep.insert(id);
        slots += 1;
    }

    messages.retain(|id, _| keep.contains(id));
    messages
}
