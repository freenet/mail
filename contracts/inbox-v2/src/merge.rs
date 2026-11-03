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
//! 4. Prune, then cap, revocations and usage entries. Pruning happens inside
//!    step 3's join on each pass id: a dead entry never competes, so it cannot
//!    win the join and then be pruned with the live entry it beat. A
//!    revocation lives while its epoch is admitted: the current one, and the
//!    one before it while `owner_time < prev_epoch_until` (decision 18).
//! 5. Filter each message against the owner, the time and the revocations left
//!    after pruning. A pruned revocation must not filter: it can be redelivered
//!    forever, and the message it would drop can too, so the state would cycle.
//!    One message per id: the smallest encoding that passed.
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
// The test seam's call sites are all `#[cfg(feature = "plausible-mutants")]`.
#[cfg(feature = "plausible-mutants")]
use crate::mutant::{self, Mutant};
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
/// How far `sent_time` may lead `owner_time`, for pass and owner mail: long, so
/// contacts can write to an owner who is offline.
pub const WINDOW_FORWARD: u64 = 400 * 86_400;
/// How far a quarantine message's `sent_time` may lead `owner_time` (decision
/// 14). A stranger has no need of the long window, and with it far-future mail
/// would need its tombstone kept for 400 days.
pub const QUARANTINE_FORWARD: u64 = 2 * 86_400;
/// `sent_time` is a whole hour.
pub const SENT_TIME_GRANULARITY: u64 = 3_600;
/// A pass's expiry, and a revocation's or usage entry's, is a whole day
/// (decision 17). To the second, an expiry minus the pass lifetime would give
/// the moment of the grant, which the pass message in the contact's inbox shows.
pub const EXPIRY_GRANULARITY: u64 = 86_400;
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
    key.verify_strict(bytes, &Signature::from_bytes(sig))
        .is_ok()
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
        if verify_ed25519(
            issuer,
            &time_bytes(&params.addr, time.owner_time),
            &time.sig,
        ) {
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

/// How revocations of one pass id rank in the join (decision 22): the epoch
/// first, so the current epoch's entry beats the previous epoch's, which dies at
/// the end of the grace whatever its expiry. Ranking expiry first let the entry
/// that dies first win and take the other with it.
fn revocation_rank(r: &Revocation) -> (u64, u64, crate::types::B64) {
    #[cfg(feature = "plausible-mutants")]
    if mutant::on(Mutant::RevocationExpiryFirst) {
        return (r.expiry, u64::from(r.epoch), r.sig);
    }
    (u64::from(r.epoch), r.expiry, r.sig)
}

/// Step 5's inputs, and the memos that verify each distinct certificate once.
struct Filter<'a> {
    rules: &'a Rules,
    params: &'a Params,
    owner: &'a OwnerRecord,
    issuer: VerifyingKey,
    owner_time: u64,
    /// The oldest epoch whose passes are admitted (decision 18).
    oldest_epoch: u32,
    live_revoked: BTreeSet<B16>,
    usage: &'a BTreeMap<B16, PassUsage>,
    /// While the kept revocations are at their cap, some may have been lost,
    /// so no pass can be trusted. An emergency bump of `pass_epoch` (grace 0) is
    /// the way out. A routine bump from a full set is not: the grace keeps the
    /// previous epoch's revocations, so the set stays full and refuses every
    /// pass of both epochs until the grace ends. The client never gets there
    /// (decision 23): it bumps at 2048 revocations, half the cap, and a full
    /// set means a misbehaving owner, whose bump is an emergency one.
    revocations_full: bool,
    certs: BTreeMap<Vec<u8>, bool>,
    ghosts: BTreeMap<Vec<u8>, Option<Ghost>>,
}

impl Filter<'_> {
    fn admit(&mut self, id: &B32, message: &Message) -> Option<Slot> {
        let forward = match message.admission {
            Admission::Quarantine { .. } => QUARANTINE_FORWARD,
            Admission::Pass { .. } | Admission::Owner { .. } => WINDOW_FORWARD,
        };
        if !CIPHERTEXT_SIZES.contains(&message.ciphertext.len())
            || !message.sent_time.is_multiple_of(SENT_TIME_GRANULARITY)
            || message.sent_time < self.owner_time.saturating_sub(WINDOW_BACK)
            || message.sent_time > self.owner_time.saturating_add(forward)
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
            || cert.epoch > self.owner.pass_epoch
            || cert.epoch < self.oldest_epoch
            || sent_time >= cert.expiry
            || !cert.expiry.is_multiple_of(EXPIRY_GRANULARITY)
            || self.revocations_full
            || self.live_revoked.contains(&cert.pass_id)
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
        #[cfg(feature = "plausible-mutants")]
        if mutant::on(Mutant::CertMemoByPassId) {
            let known = self.certs.get(cert.pass_id.as_slice()).copied();
            return known.unwrap_or_else(|| {
                let mut bytes = cert_bytes(cert);
                bytes.extend_from_slice(cert.sig.as_slice());
                let genuine = verify_ed25519(&self.issuer, &bytes[..bytes.len() - 64], &cert.sig);
                self.certs.insert(cert.pass_id.to_vec(), genuine);
                genuine
            });
        }
        let mut bytes = cert_bytes(cert);
        bytes.extend_from_slice(cert.sig.as_slice());
        if let Some(known) = self.certs.get(&bytes) {
            return *known;
        }
        let genuine = verify_ed25519(&self.issuer, &bytes[..bytes.len() - 64], &cert.sig);
        self.certs.insert(bytes, genuine);
        genuine
    }

    /// How many messages this certificate may have held at once. An invite
    /// whose usage entry the 1024 cap cut reads as unused, so it may hold up
    /// to `per_invite` again: the cap keeps the smallest pass ids (review r1
    /// N2).
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

    /// In a RequireGhost inbox a proof decides. An Open inbox refuses a message
    /// that carries one (decision 19): it does not check a proof, and one it
    /// held would name a ghost key in public state with nothing behind it.
    fn admit_quarantine(
        &mut self,
        proof: Option<&GhostProof>,
        sent_time: u64,
        ct_hash: &[u8; 32],
    ) -> Option<Slot> {
        let QuarantineMode::RequireGhost { min_usd } = self.owner.quarantine else {
            return proof.is_none().then_some(Slot::Quarantine { ghost: None });
        };
        let proof = proof?;
        if proof.cert.len() > ghostkey_verify::MAX_CERTIFICATE_BYTES
            || proof.scoped_payload.len() > MAX_SCOPED_PAYLOAD
        {
            return None;
        }
        let ghost = self.verify_proof(proof, sent_time, ct_hash)?;
        let tier_met = ghost.usd >= u64::from(min_usd.unwrap_or(0));
        #[cfg(feature = "plausible-mutants")]
        let tier_met = mutant::tier_met(tier_met);
        tier_met.then_some(Slot::Quarantine {
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
        // The two mutants of this check hand it other inputs, so the rule below
        // is the one that runs.
        #[cfg(feature = "plausible-mutants")]
        let (requestor, scoped) = mutant::proof_inputs(
            requestor,
            scoped.payload,
            &self.params.addr,
            sent_time,
            ct_hash,
        );
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
    let issuer = VerifyingKey::from_bytes(&owner.issuer_vk).map_err(|_| Malformed("issuer key"))?;
    let time = join_time(params, &issuer, &parts)?;

    // Step 4's pruning, applied inside step 3's joins: an entry that is
    // already dead never competes, so it cannot win a pass id's join and then
    // be pruned, taking the live entry it beat with it (review r1 B1).
    let prune_time = time.owner_time;
    #[cfg(feature = "plausible-mutants")]
    let prune_time = parts
        .first()
        .and_then(|p| p.time.as_ref())
        .map(|t| t.owner_time)
        .filter(|_| mutant::on(Mutant::PruneUnmergedTime))
        .unwrap_or(prune_time);
    let expired = |expiry: u64| expiry.saturating_add(WINDOW_BACK) <= prune_time;
    // Decision 18: the previous epoch's passes are admitted, and so its
    // revocations kept, until the joined time reaches the joined owner's
    // `prev_epoch_until`. Both ends move together, so a revocation is pruned
    // by epoch exactly when the passes it could revoke stop being admitted.
    let grace_until = owner.prev_epoch_until;
    #[cfg(feature = "plausible-mutants")]
    let grace_until = mutant::grace_until(grace_until, parts.first());
    let oldest_epoch = if time.owner_time < grace_until {
        owner.pass_epoch.saturating_sub(1)
    } else {
        owner.pass_epoch
    };
    let live_revocation = |r: &Revocation| !expired(r.expiry) && r.epoch >= oldest_epoch;
    // A usage entry counts from the owner version that tombstones what it counts.
    let live_usage = |u: &PassUsage| !expired(u.expiry) && u.owner_version <= owner.version;
    #[cfg(feature = "plausible-mutants")]
    let (real_live_revocation, real_live_usage) = (live_revocation, live_usage);
    #[cfg(feature = "plausible-mutants")]
    let live_revocation = |r: &Revocation| mutant::join_live(live_revocation(r));
    #[cfg(feature = "plausible-mutants")]
    let live_usage = |u: &PassUsage| mutant::join_live(live_usage(u));

    let mut revoked = BTreeMap::new();
    let mut usage = BTreeMap::new();
    let mut candidates: BTreeMap<B32, Vec<Message>> = BTreeMap::new();
    #[cfg(feature = "plausible-mutants")]
    let mut unpruned = BTreeSet::new();
    #[cfg(feature = "plausible-mutants")]
    mutant::begin();
    for part in parts {
        #[cfg(feature = "plausible-mutants")]
        mutant::next_part();
        for (key, entry) in part.revoked {
            #[cfg(feature = "plausible-mutants")]
            mutant::note_revocation(&mut unpruned, &entry, |r| {
                let bytes = revocation_bytes(&params.addr, &r.pass_id, r.expiry, r.epoch);
                r.pass_id == key && verify_ed25519(&issuer, &bytes, &r.sig)
            });
            join_entry(&mut revoked, key, entry, revocation_rank, |r| {
                let bytes = revocation_bytes(&params.addr, &r.pass_id, r.expiry, r.epoch);
                r.pass_id == key
                    && r.expiry.is_multiple_of(EXPIRY_GRANULARITY)
                    && live_revocation(r)
                    && verify_ed25519(&issuer, &bytes, &r.sig)
            });
        }
        for (key, entry) in part.usage {
            join_entry(
                &mut usage,
                key,
                entry,
                |u: &PassUsage| (u.used, u.expiry, u.sig),
                |u| {
                    let bytes =
                        usage_bytes(&params.addr, &u.pass_id, u.used, u.expiry, u.owner_version);
                    u.pass_id == key
                        && u.expiry.is_multiple_of(EXPIRY_GRANULARITY)
                        && live_usage(u)
                        && verify_ed25519(&issuer, &bytes, &u.sig)
                },
            );
        }
        for (id, message) in part.messages {
            #[cfg(feature = "plausible-mutants")]
            mutant::note(&id);
            let at_id = candidates.entry(id).or_default();
            if !at_id.contains(&message) {
                at_id.push(message);
            }
        }
    }

    // Step 4: what is left is live, so only the caps remain.
    #[cfg(feature = "plausible-mutants")]
    let union_len = unpruned.len();
    #[cfg(feature = "plausible-mutants")]
    mutant::prune_late(
        &mut revoked,
        &mut usage,
        rules.revoked,
        real_live_revocation,
        real_live_usage,
    );
    let live_revoked: BTreeSet<B16> = revoked.keys().copied().collect();
    #[cfg(feature = "plausible-mutants")]
    let live_revoked = if mutant::on(Mutant::FilterUnprunedRevocations) {
        unpruned
    } else {
        live_revoked
    };
    // Keeping the smallest ids absorbs redelivery: order does not matter.
    while revoked.len() > rules.revoked {
        revoked.pop_last();
    }
    while usage.len() > rules.usage {
        usage.pop_last();
    }

    // Step 5. A set holding exactly the cap counts as full even when nothing
    // was cut: deterministic and on the safe side (review r1 N1).
    let revocations_full = revoked.len() >= rules.revoked;
    #[cfg(feature = "plausible-mutants")]
    let revocations_full = mutant::overflow(revocations_full, union_len, rules.revoked);
    let mut filter = Filter {
        rules,
        params,
        owner: &owner,
        issuer,
        owner_time: time.owner_time,
        oldest_epoch,
        live_revoked,
        usage: &usage,
        revocations_full,
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
            #[cfg(feature = "plausible-mutants")]
            if mutant::on(Mutant::NoOnePerId) {
                admitted.push((id, message, slot));
                continue;
            }
            let encoding = encode(&message);
            let smaller = |held: &(Vec<u8>, Message, Slot)| {
                (encoding.len(), &encoding) < (held.0.len(), &held.0)
            };
            let take = best.as_ref().is_none_or(smaller);
            #[cfg(feature = "plausible-mutants")]
            let take = if mutant::on(Mutant::FirstAdmitted) {
                best.is_none()
            } else {
                take
            };
            if take {
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
                #[cfg(feature = "plausible-mutants")]
                let pass_id = mutant::pass_key(pass_id, &id);
                by_pass
                    .entry(pass_id)
                    .or_default()
                    .push((message.sent_time, id, limit));
            }
            Slot::Owner => owner_pool.push((message.sent_time, id)),
            Slot::Quarantine { ghost } => {
                let mut ranked = blake3::Hasher::new();
                ranked.update(salt);
                ranked.update(id.as_slice());
                let rank = *ranked.finalize().as_bytes();
                #[cfg(feature = "plausible-mutants")]
                let rank = mutant::quarantine_rank(rank, message.sent_time);
                #[cfg(feature = "plausible-mutants")]
                let ghost = ghost.map(|key| mutant::ghost_key(key, &id));
                quarantine.push((rank, id, ghost));
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
    keep.extend(
        owner_pool
            .into_iter()
            .take(rules.owner_pool)
            .map(|(_, id)| id),
    );

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
