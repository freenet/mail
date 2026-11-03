//! A reference model of what one merge must keep: nothing live is lost.
//!
//! The merge laws compare merges with merges, so a rule that drops a genuine
//! item the same way every time is lawful (decision 22 was that, and so was
//! review r1 B1). This model says, from the inputs alone, which items are live
//! and which of them the caps keep, and `check` holds the merge's output to it.
//!
//! It is written from the owner's decisions and the plan, not from
//! `src/merge.rs`, and calls nothing in `merge`: only the byte layouts in
//! `signed.rs` (pinned by the independent vectors in `tests/fixtures/`), the
//! state types, and `ghostkey-verify` for a certificate's chain.
//! - Owner: the maximum by `(version, blake3)` (plan 5.4). Time: the highest
//!   `(owner_time, sig)` that verifies under the joined issuer (decision 5).
//! - An expiry is a whole day (decision 17) and lives while
//!   `expiry + WINDOW_BACK > owner_time` (plan 5.3).
//! - Epochs admitted: `pass_epoch`, and `pass_epoch - 1` while
//!   `owner_time < prev_epoch_until` (decision 18).
//! - Revocations: genuine, live, admitted epoch; per pass id the maximum by
//!   `(epoch, expiry, sig)` (decision 22); the cap keeps the smallest ids; mail
//!   is filtered by every live one, capped or not, and refused while the kept
//!   set is at the cap (decision 10, plan 5.3, review r1 N1).
//! - Usage: genuine, live, `owner_version <=` the joined version (fix round 1
//!   S2); per pass id the maximum by `(used, expiry, sig)` (decision 23); the
//!   cap keeps the smallest ids (decision 5).
//! - Messages: padded size, whole hour, the window (back 2 d, forward 400 d,
//!   or 2 d for quarantine, decision 14), not tombstoned, the id its fields
//!   give (decision 11), the admission's own checks (plan 5.3, decisions 1, 2,
//!   4, 19); one per id, the smallest encoding (decision 3).
//! - Caps (plan 5.3, 5.5, decision 2): per pass `per_pass`, an invite
//!   `min(max_messages - used, per_invite)`; the pass pool by
//!   `(k, sent_time, id)`; the owner pool by `(sent_time, id)`, earliest first;
//!   quarantine by `blake3(salt ‖ id)` with salt `blake3(time)`, at most
//!   `per_ghost` per ghost key in RequireGhost.
//!
//! For every cap the check is that the output keeps exactly the
//! `min(live, cap)` best-ranked live items: every live item a cap does not
//! displace is present, the count is right, and everything dropped ranks below
//! everything kept. Each failure starts with `ORACLE`.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Debug;

use ed25519_dalek::{Signature, VerifyingKey};
use freenet_email_inbox_v2::merge::Rules;
use freenet_email_inbox_v2::signed::*;
use freenet_email_inbox_v2::types::*;
use freenet_stdlib::prelude::ContractInstanceId;
use ghostkey_common::{ScopedPayload, SignatureRequestor};
use ghostkey_verify::GhostkeyCertificate;

use super::common::{DAY, HOUR, WEBAPP_REQUESTOR, world};

pub const ORACLE: &str = "ORACLE";

// The spec's numbers, stated here from the plan and decisions and not read
// from the crate: `the_oracles_numbers_are_the_crates` pins the crate to them,
// so a wrong constant in the crate fails there and is not shared by both sides.
pub const SIZES: [usize; 3] = [8192, 16384, 32768];
pub const FORWARD: u64 = 400 * DAY;
pub const QUARANTINE_FORWARD: u64 = 2 * DAY;
/// Plan 5.3: how far `sent_time` may trail `owner_time`.
pub const WINDOW_BACK: u64 = 2 * DAY;
/// V1's caps (plan; decision 14 for quarantine and per-ghost).
pub const SPEC_V1: Rules = Rules {
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

/// Which caps had more live items than room, in one merge.
#[derive(Default, Clone, Copy)]
pub struct Overflow {
    pub revoked: bool,
    pub usage: bool,
    pub per_pass: bool,
    pub pass_pool: bool,
    pub owner_pool: bool,
    pub per_ghost: bool,
    pub quarantine: bool,
}

/// A donation certificate's ghost key and tier.
type Donor = Option<([u8; 32], u64)>;

thread_local! {
    static VERIFIED: RefCell<HashMap<[u8; 32], bool>> = RefCell::new(HashMap::new());
    static GHOSTS: RefCell<HashMap<Vec<u8>, Donor>> = RefCell::new(HashMap::new());
}

/// Ed25519, strict, remembered: the fuzzer checks the same pieces many times.
fn verified(key: &[u8; 32], bytes: &[u8], sig: &[u8; 64]) -> bool {
    let mut h = blake3::Hasher::new();
    h.update(key);
    h.update(sig);
    h.update(bytes);
    let memo = *h.finalize().as_bytes();
    if let Some(known) = VERIFIED.with(|v| v.borrow().get(&memo).copied()) {
        return known;
    }
    let ok = VerifyingKey::from_bytes(key)
        .is_ok_and(|vk| vk.verify_strict(bytes, &Signature::from_bytes(sig)).is_ok());
    VERIFIED.with(|v| v.borrow_mut().insert(memo, ok));
    ok
}

/// A certificate that chains to the test master as a donation: its ghost key
/// and tier.
fn donor(cert: &[u8]) -> Donor {
    if let Some(known) = GHOSTS.with(|g| g.borrow().get(cert).copied()) {
        return known;
    }
    let master = VerifyingKey::from_bytes(&world().params.ghost_master).unwrap();
    let found = GhostkeyCertificate::from_cbor(cert)
        .ok()
        .filter(|c| c.to_cbor() == cert)
        .and_then(|c| c.verify(&master).ok())
        .and_then(|v| {
            let info = v.notary_info().ok()?;
            (info.action == "freenet-donation").then(|| (v.ghost_key().to_bytes(), info.amount))
        });
    GHOSTS.with(|g| g.borrow_mut().insert(cert.to_vec(), found));
    found
}

fn fail(what: String) -> String {
    format!("{ORACLE}: {what}")
}

/// `kept` must be exactly the first `min(ranked.len(), cap)` of `ranked`.
fn keeps_the_best<K: Ord + Debug + Clone>(
    what: &str,
    ranked: &[K],
    cap: usize,
    kept: &BTreeSet<K>,
) -> Result<bool, String> {
    let room = ranked.len().min(cap);
    if let Some(lost) = ranked[..room].iter().find(|k| !kept.contains(k)) {
        return Err(fail(format!(
            "a live {what} the cap keeps was lost: {lost:?} ({} live, cap {cap})",
            ranked.len()
        )));
    }
    if kept.len() != room {
        return Err(fail(format!(
            "{what}: kept {} of {} live, cap {cap}",
            kept.len(),
            ranked.len()
        )));
    }
    Ok(ranked.len() > cap)
}

/// The best live entry per pass id, by `rank`.
fn join<V: Clone, R: Ord>(
    parts: &[InboxDelta],
    entries: impl Fn(&InboxDelta) -> &BTreeMap<B16, V>,
    live: impl Fn(&B16, &V) -> bool,
    rank: impl Fn(&V) -> R,
) -> BTreeMap<B16, V> {
    let mut best: BTreeMap<B16, V> = BTreeMap::new();
    for part in parts {
        for (key, v) in entries(part) {
            if live(key, v) && best.get(key).is_none_or(|b| rank(v) > rank(b)) {
                best.insert(*key, v.clone());
            }
        }
    }
    best
}

enum Slot {
    Pass { pass_id: B16, limit: usize },
    Owner,
    Quarantine { ghost: Option<[u8; 32]> },
}

/// Holds `out`, the merge of `parts` under `rules`, to the model.
pub fn check(rules: &Rules, parts: &[InboxDelta], out: &InboxState) -> Result<Overflow, String> {
    let addr = world().params.addr;

    let owner = parts
        .iter()
        .filter_map(|p| p.owner.as_ref())
        .max_by_key(|o| (o.version, *blake3::hash(&encode(*o)).as_bytes()))
        .expect("an owner");
    if out.owner != *owner {
        return Err(fail("the owner is not the join".into()));
    }
    let issuer = *owner.issuer_vk;
    let time = parts
        .iter()
        .filter_map(|p| p.time.as_ref())
        .filter(|t| verified(&issuer, &time_bytes(&addr, t.owner_time), &t.sig))
        .max_by_key(|t| (t.owner_time, t.sig))
        .expect("a time");
    if out.time != *time {
        return Err(fail("the time is not the join".into()));
    }
    let now = time.owner_time;
    let alive =
        |expiry: u64| expiry.is_multiple_of(DAY) && expiry.saturating_add(WINDOW_BACK) > now;
    let oldest = if now < owner.prev_epoch_until {
        owner.pass_epoch.saturating_sub(1)
    } else {
        owner.pass_epoch
    };
    let mut overflow = Overflow::default();

    // Revocations.
    let revoked = join(
        parts,
        |p| &p.revoked,
        |key, r: &Revocation| {
            r.pass_id == *key
                && alive(r.expiry)
                && r.epoch >= oldest
                && verified(
                    &issuer,
                    &revocation_bytes(&addr, key, r.expiry, r.epoch),
                    &r.sig,
                )
        },
        |r| (r.epoch, r.expiry, r.sig),
    );
    let ids: Vec<B16> = revoked.keys().copied().collect();
    overflow.revoked = keeps_the_best(
        "revocation",
        &ids,
        rules.revoked,
        &out.revoked.keys().copied().collect(),
    )?;
    for (key, r) in &out.revoked {
        if revoked[key] != *r {
            return Err(fail(format!(
                "pass id {key:?} kept a revocation that is not the best live one"
            )));
        }
    }
    let full = ids.len() >= rules.revoked;

    // Usage.
    let usage = join(
        parts,
        |p| &p.usage,
        |key, u: &PassUsage| {
            u.pass_id == *key
                && alive(u.expiry)
                && u.owner_version <= owner.version
                && verified(
                    &issuer,
                    &usage_bytes(&addr, key, u.used, u.expiry, u.owner_version),
                    &u.sig,
                )
        },
        |u| (u.used, u.expiry, u.sig),
    );
    let ids: Vec<B16> = usage.keys().copied().collect();
    // An invite whose entry the cap cut reads as unused (review r1 N2).
    let counted: BTreeSet<B16> = ids.iter().take(rules.usage).copied().collect();
    overflow.usage = keeps_the_best(
        "usage entry",
        &ids,
        rules.usage,
        &out.usage.keys().copied().collect(),
    )?;
    for (key, u) in &out.usage {
        if usage[key] != *u {
            return Err(fail(format!(
                "pass id {key:?} kept a usage entry that is not the best live one"
            )));
        }
    }

    // Messages: which are live, then the smallest encoding of each id.
    let admit = |id: &B32, m: &Message| -> Option<Slot> {
        let forward = match m.admission {
            Admission::Quarantine { .. } => QUARANTINE_FORWARD,
            _ => FORWARD,
        };
        if !SIZES.contains(&m.ciphertext.len())
            || !m.sent_time.is_multiple_of(HOUR)
            || m.sent_time + WINDOW_BACK < now
            || m.sent_time > now + forward
            || owner.tombstones.contains_key(id)
        {
            return None;
        }
        let ct_hash = *blake3::hash(&m.ciphertext).as_bytes();
        let id_with =
            |kind, tag: &[u8]| message_id_of(&addr, &ct_hash, m.sent_time, kind, tag) == **id;
        match &m.admission {
            Admission::Pass { cert, msg_sig } => {
                let ok = id_with(KIND_PASS, cert.pass_id.as_slice())
                    && *cert.recipient == addr
                    && (oldest..=owner.pass_epoch).contains(&cert.epoch)
                    && cert.expiry.is_multiple_of(DAY)
                    && m.sent_time < cert.expiry
                    && !full
                    && !revoked.contains_key(&cert.pass_id)
                    && verified(&issuer, &cert_bytes(cert), &cert.sig)
                    && verified(
                        &cert.pass_vk,
                        &admit_bytes(&addr, m.sent_time, &ct_hash),
                        msg_sig,
                    );
                let limit = match cert.class {
                    PassClass::Contact => rules.per_pass,
                    PassClass::Invite { max_messages } => {
                        let used = usage
                            .get(&cert.pass_id)
                            .filter(|_| counted.contains(&cert.pass_id))
                            .map_or(0, |u| u.used);
                        usize::from(max_messages.saturating_sub(used)).min(rules.per_invite)
                    }
                };
                ok.then_some(Slot::Pass {
                    pass_id: cert.pass_id,
                    limit,
                })
            }
            Admission::Owner { sig } => (id_with(KIND_OWNER, &[])
                && verified(&issuer, &owner_msg_bytes(&addr, m.sent_time, &ct_hash), sig))
            .then_some(Slot::Owner),
            Admission::Quarantine { ghost: None } => (id_with(KIND_QUARANTINE, &[])
                && owner.quarantine == QuarantineMode::Open)
                .then_some(Slot::Quarantine { ghost: None }),
            Admission::Quarantine { ghost: Some(proof) } => {
                let QuarantineMode::RequireGhost { min_usd } = owner.quarantine else {
                    return None;
                };
                let (key, usd) = donor(&proof.cert)?;
                let scoped: ScopedPayload =
                    ghostkey_common::from_cbor(&proof.scoped_payload).ok()?;
                let ok = id_with(KIND_QUARANTINE, &key)
                    && scoped.requestor
                        == SignatureRequestor::WebApp(ContractInstanceId::new(WEBAPP_REQUESTOR))
                    && scoped.payload == ghost_admit_bytes(&addr, m.sent_time, &ct_hash)
                    && verified(&key, &proof.scoped_payload, &proof.ghost_sig)
                    && usd >= u64::from(min_usd.unwrap_or(0));
                ok.then_some(Slot::Quarantine { ghost: Some(key) })
            }
        }
    };
    let mut chosen: BTreeMap<B32, (Vec<u8>, &Message, Slot)> = BTreeMap::new();
    for part in parts {
        for (id, m) in &part.messages {
            let Some(slot) = admit(id, m) else { continue };
            let bytes = encode(m);
            let smaller =
                |held: &(Vec<u8>, &Message, Slot)| (bytes.len(), &bytes) < (held.0.len(), &held.0);
            if chosen.get(id).is_none_or(smaller) {
                chosen.insert(*id, (bytes, m, slot));
            }
        }
    }
    for (id, m) in &out.messages {
        match chosen.get(id) {
            None => return Err(fail(format!("kept message {id:?}, which is not live"))),
            Some((_, best, _)) if *best != m => {
                return Err(fail(format!(
                    "message {id:?} kept an encoding that is not the smallest live one"
                )));
            }
            Some(_) => {}
        }
    }

    // The caps.
    let mut per_pass: BTreeMap<B16, (usize, Vec<(u64, B32)>)> = BTreeMap::new();
    let mut owner_pool = Vec::new();
    let mut quarantine = Vec::new();
    let salt = blake3::hash(&encode(time));
    for (id, (_, m, slot)) in &chosen {
        match slot {
            Slot::Pass { pass_id, limit } => {
                let at = per_pass.entry(*pass_id).or_insert((*limit, Vec::new()));
                if at.0 != *limit {
                    return Err(fail(
                        "one pass id with two limits: the model does not cover it".into(),
                    ));
                }
                at.1.push((m.sent_time, *id));
            }
            Slot::Owner => owner_pool.push((m.sent_time, *id)),
            Slot::Quarantine { ghost } => {
                let mut h = blake3::Hasher::new();
                h.update(salt.as_bytes());
                h.update(id.as_slice());
                quarantine.push((*h.finalize().as_bytes(), *id, *ghost));
            }
        }
    }
    let kept: BTreeSet<B32> = out.messages.keys().copied().collect();
    let kept_of = |ids: &mut dyn Iterator<Item = B32>| -> BTreeSet<B32> {
        ids.filter(|id| kept.contains(id)).collect()
    };

    let mut pool = Vec::new();
    for (limit, mut held) in per_pass.into_values() {
        held.sort();
        overflow.per_pass |= held.len() > limit;
        pool.extend(
            held.into_iter()
                .take(limit)
                .enumerate()
                .map(|(k, (t, id))| (k, t, id)),
        );
    }
    pool.sort();
    let pass_kept = kept_of(
        &mut chosen
            .iter()
            .filter(|(_, (_, _, s))| matches!(s, Slot::Pass { .. }))
            .map(|(id, _)| *id),
    );
    let ranked: Vec<B32> = pool.iter().map(|(_, _, id)| *id).collect();
    overflow.pass_pool = keeps_the_best("pass message", &ranked, rules.pass_pool, &pass_kept)?;

    owner_pool.sort();
    let ranked: Vec<B32> = owner_pool.iter().map(|(_, id)| *id).collect();
    let owner_kept = kept_of(&mut ranked.iter().copied());
    overflow.owner_pool = keeps_the_best("owner message", &ranked, rules.owner_pool, &owner_kept)?;

    quarantine.sort();
    let mut per_ghost: BTreeMap<[u8; 32], usize> = BTreeMap::new();
    let mut eligible = Vec::new();
    for (_, id, ghost) in &quarantine {
        if let Some(key) = ghost {
            let n = per_ghost.entry(*key).or_default();
            if *n == rules.per_ghost {
                overflow.per_ghost = true;
                continue;
            }
            *n += 1;
        }
        eligible.push(*id);
    }
    let quarantine_kept = kept_of(&mut quarantine.iter().map(|(_, id, _)| *id));
    overflow.quarantine = keeps_the_best(
        "quarantine message",
        &eligible,
        rules.quarantine,
        &quarantine_kept,
    )?;
    Ok(overflow)
}
