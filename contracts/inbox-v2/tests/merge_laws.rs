//! The merge laws, over crafted states.
//!
//! The law is the one core enforces, `associativity_heals` in
//! `conformance/verifier.rs`: bounded retention and owner-driven removals cannot
//! be strictly associative, so two groupings that differ must heal. Heal means
//! both groupings are valid, one exchange agrees, and merging in L, R, A, B and C
//! reaches a fixpoint within `MAX_HEAL_PASSES` passes, with every moving step
//! absorbing a redelivery and no state repeating. Running out of passes is
//! inconclusive in core and a failure here.
//!
//! Every merge the fuzzer makes is also held to `oracle::check`, a model of
//! what the merge must keep that does not use the merge's code: the laws above
//! cannot see a rule that drops a live item the same way every time.
//!
//! `FORK_SEEDS=n` sets how many seeds run (default below), `FORK_SEED=n` runs one.

mod common;
mod oracle;

use std::cell::Cell;
use std::collections::{BTreeMap, HashSet};
use std::sync::OnceLock;

use common::*;
use freenet_email_inbox_v2::merge::{WINDOW_BACK, merge};
use freenet_email_inbox_v2::types::*;
use freenet_email_inbox_v2::{apply, is_valid, sync};
use freenet_stdlib::prelude::UpdateData;
use serde_bytes::ByteArray;

const DEFAULT_SEEDS: u64 = 48;
const TRIPLES_PER_SEED: usize = 6;
/// core's `MAX_HEAL_PASSES`.
const MAX_HEAL_PASSES: usize = 4;

/// Small enough that a few dozen pieces overflow every cap.
const TINY: Rules = Rules {
    per_pass: 3,
    per_invite: 2,
    pass_pool: 6,
    owner_pool: 2,
    quarantine: 4,
    per_ghost: 1,
    revoked: 5,
    usage: 2,
    tombstones: 4096,
};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len() as u64) as usize]
    }
    fn subset<T: Clone>(&mut self, items: &[T], percent: u64) -> Vec<T> {
        items
            .iter()
            .filter(|_| self.chance(percent))
            .cloned()
            .collect()
    }
}

/// Every piece one seed can draw on: the cases the plan lists, side by side, so
/// that a state can hold any mixture of them.
struct Universe {
    /// Revocations every peer holds: none, or V1's set filled to near its cap.
    fillers: &'static [Revocation],
    /// Usage entries every peer holds: more live ones than V1's usage cap, or
    /// none.
    usage_fillers: &'static [PassUsage],
    owners: Vec<OwnerRecord>,
    times: Vec<TimeAttestation>,
    revoked: Vec<Revocation>,
    usage: Vec<PassUsage>,
    messages: Vec<(B32, Message)>,
}

fn modes(rng: &mut Rng) -> QuarantineMode {
    *rng.pick(&[
        QuarantineMode::Open,
        QuarantineMode::Open,
        QuarantineMode::RequireGhost { min_usd: None },
        QuarantineMode::RequireGhost { min_usd: Some(1) },
        QuarantineMode::RequireGhost { min_usd: Some(5) },
        QuarantineMode::RequireGhost { min_usd: Some(20) },
    ])
}

/// The base time of the universe that runs at the revocation cap: its fillers
/// are signed once and shared, so their expiries are fixed against it.
const AT_CAP_T0: u64 = 1_800_000_000 / DAY * DAY;

/// Revocations that fill V1's set to within a few of its cap: most live past
/// every time the universe draws, a third run out at its 31st day.
fn cap_fillers() -> &'static [Revocation] {
    static FILLERS: OnceLock<Vec<Revocation>> = OnceLock::new();
    FILLERS.get_or_init(|| {
        let w = world();
        (0..Rules::V1.revoked as u64 - 6)
            .map(|i| {
                let mut id = [0xF0u8; 16];
                id[8..].copy_from_slice(&i.to_be_bytes());
                let expiry = if i % 3 == 0 {
                    AT_CAP_T0 + 31 * DAY
                } else {
                    AT_CAP_T0 + 900 * DAY
                };
                w.revocation(ByteArray::new(id), expiry, 3)
            })
            .collect()
    })
}

/// More live usage entries than V1's usage cap, on pass ids no pass uses, all
/// counting from owner version 1. Shared by every peer of the at-cap universe,
/// so the usage cap overflows in each merge there.
fn usage_fillers() -> &'static [PassUsage] {
    static FILLERS: OnceLock<Vec<PassUsage>> = OnceLock::new();
    FILLERS.get_or_init(|| {
        let w = world();
        (0..Rules::V1.usage as u64 + 6)
            .map(|i| {
                let mut id = [0xE0u8; 16];
                id[8..].copy_from_slice(&i.to_be_bytes());
                w.usage_at(
                    ByteArray::new(id),
                    1 + (i % 3) as u8,
                    AT_CAP_T0 + 900 * DAY,
                    1,
                )
            })
            .collect()
    })
}

fn universe(seed: u64, rng: &mut Rng, big: bool) -> Universe {
    let t0 = 1_800_000_000 / DAY * DAY + rng.below(1000) * DAY;
    universe_at(seed, rng, big, t0)
}

fn universe_at(seed: u64, rng: &mut Rng, big: bool, t0: u64) -> Universe {
    let w = world();
    let epoch = 3;
    let far = t0 + 300 * DAY;
    let invite_gone = t0 + 30 * DAY + WINDOW_BACK;
    // Keys differ per seed so states of different seeds never look alike.
    let key = |i: u64| seed.wrapping_mul(1_000_003).wrapping_add(i);
    let mut tag = 0u64;
    let mut ct_next = |rng: &mut Rng| {
        tag += 1;
        ct(*rng.pick(&[8192, 8192, 16384]), key(tag))
    };

    // Passes: live, wrong epoch, expired, invites, and one renewed (same id,
    // later expiry), which gives two encodings of one message id.
    let n_contacts = if big { 24 } else { 5 };
    let mut passes = Vec::new();
    for i in 0..n_contacts {
        passes.push(w.pass(key(i), epoch, far, PassClass::Contact));
    }
    for i in 0..3 {
        passes.push(w.pass(
            key(50 + i),
            epoch,
            t0 + 30 * DAY,
            PassClass::Invite { max_messages: 3 },
        ));
    }
    passes.push(w.pass(key(60), epoch + 1, far, PassClass::Contact));
    passes.push(w.pass(key(61), epoch, t0 - 3 * DAY, PassClass::Contact));
    passes.push(w.pass(key(62), epoch, t0 + DAY, PassClass::Contact));
    // The previous epoch's: admitted only in a grace (decision 18).
    let old_epoch = passes.len();
    passes.push(w.pass(key(63), epoch - 1, far, PassClass::Contact));
    passes.push(w.pass(
        key(64),
        epoch - 1,
        t0 + 30 * DAY,
        PassClass::Invite { max_messages: 3 },
    ));
    // An expiry off the day, which is never admitted (decision 17).
    passes.push(w.pass(key(65), epoch, far + HOUR, PassClass::Contact));
    let renewed = w.pass(key(0), epoch, far + 100 * DAY, PassClass::Contact);
    // The same pass id certified again in the next epoch: one message id, two
    // encodings, and which one is live depends on the joined owner.
    let next_epoch = w.pass(key(1), epoch + 1, far, PassClass::Contact);

    let mut messages = Vec::new();
    let per_pass = if big { 9 } else { 4 };
    for pass in &passes {
        for _ in 0..1 + rng.below(per_pass) {
            let sent = t0 + rng.below(96) * HOUR - 48 * HOUR;
            messages.push(w.pass_msg(pass, ct_next(rng), sent));
        }
    }
    // The same message under the renewed certificate: same id, other encoding.
    let same = ct_next(rng);
    messages.push(w.pass_msg(&passes[0], same.clone(), t0));
    messages.push(w.pass_msg(&renewed, same, t0));
    let reissued = ct_next(rng);
    messages.push(w.pass_msg(&passes[1], reissued.clone(), t0));
    messages.push(w.pass_msg(&next_epoch, reissued, t0));

    for _ in 0..if big { 12 } else { 5 } {
        let sent = t0 + rng.below(48) * HOUR;
        messages.push(w.owner_msg(ct_next(rng), sent));
    }
    for _ in 0..if big { 80 } else { 12 } {
        let sent = t0 + rng.below(48) * HOUR;
        let ghost = rng
            .chance(60)
            .then(|| rng.below(w.ghosts.len() as u64) as usize);
        messages.push(w.quarantine_msg(ct_next(rng), sent, ghost));
    }
    // One ciphertext and hour with no proof, with a proof, and re-proved under
    // another donor's key: three ids (decision 11).
    let both = ct_next(rng);
    messages.push(w.quarantine_msg(both.clone(), t0, Some(0)));
    messages.push(w.quarantine_msg(both.clone(), t0, None));
    messages.push(w.quarantine_msg(both.clone(), t0, Some(1)));
    // A restamped copy: another id, unsigned.
    messages.push(w.quarantine_msg(both.clone(), t0 + HOUR, None));
    // Cross-kind duplicates: one ciphertext as three messages.
    messages.push(w.pass_msg(&passes[1], both.clone(), t0));
    messages.push(w.owner_msg(both, t0));

    // Backdated below the window, and future past it: the top of the window
    // loosens as owner_time advances, so some of these come back in.
    for i in 0..4 {
        messages.push(w.quarantine_msg(ct_next(rng), t0 - 3 * DAY - i * HOUR, None));
        messages.push(w.pass_msg(&passes[2], ct_next(rng), t0 - 3 * DAY - i * HOUR));
        messages.push(w.quarantine_msg(ct_next(rng), t0 + 400 * DAY + i * DAY, None));
        messages.push(w.owner_msg(ct_next(rng), t0 + 400 * DAY + i * DAY));
        // Either side of a two-day top, the quarantine window's.
        messages.push(w.quarantine_msg(ct_next(rng), t0 + 2 * DAY + i * HOUR - 2 * HOUR, None));
        messages.push(w.quarantine_msg(ct_next(rng), t0 + 3 * DAY + (i + 1) * HOUR, None));
    }
    // Mail dated after the time has moved past every expiry.
    for i in 0..3 {
        messages.push(w.owner_msg(ct_next(rng), far + 101 * DAY + i * HOUR));
        messages.push(w.quarantine_msg(ct_next(rng), far + 101 * DAY + i * HOUR, None));
    }
    // Malformed in themselves: the merge must drop these wherever they land.
    {
        let (id, mut bad) = w.pass_msg(&passes[3], ct_next(rng), t0);
        if let Admission::Pass { msg_sig, .. } = &mut bad.admission {
            msg_sig[0] ^= 1;
        }
        messages.push((id, bad));
        messages.push(w.quarantine_msg(ct(9000, key(9000)), t0, None));
        messages.push(w.quarantine_msg(ct(8192, key(9001)), t0 + 1, None));
        let (_, m) = w.quarantine_msg(ct(8192, key(9002)), t0, None);
        messages.push((ByteArray::new([0xEE; 32]), m));
    }

    let mut revoked = Vec::new();
    for pass in rng.subset(&passes, 30) {
        let expiry = pass.cert.expiry;
        revoked.push(w.revocation(pass.cert.pass_id, expiry, epoch));
    }
    // Crossing pairs on one pass id: the entry that wins the join on rank is
    // the one pruned first, by an epoch bump.
    for pass in rng.subset(&passes, 30) {
        let (id, expiry) = (pass.cert.pass_id, pass.cert.expiry);
        revoked.push(w.revocation(id, expiry + 100 * DAY, epoch));
        revoked.push(w.revocation(id, expiry, epoch + 1));
    }
    revoked.push(w.revocation(next_epoch.cert.pass_id, far + 100 * DAY, epoch));
    revoked.push(w.revocation(next_epoch.cert.pass_id, far, epoch + 1));
    // The previous epoch's passes, revoked in their own epoch or crossing the
    // bump: which entry is live depends on the joined owner's grace.
    for pass in rng.subset(&passes[old_epoch..old_epoch + 2], 60) {
        let (id, expiry) = (pass.cert.pass_id, pass.cert.expiry);
        revoked.push(w.revocation(id, expiry, epoch - 1));
        if rng.chance(50) {
            revoked.push(w.revocation(id, expiry + 100 * DAY, epoch - 2));
        }
    }
    // Off the day: dropped wherever they land.
    revoked.push(w.revocation(passes[2].cert.pass_id, far + 1, epoch));
    // Fillers: enough to go over TINY's cap, some soon prunable, some not, and
    // ids on both sides of the real ones.
    for i in 0..9 {
        let expiry = if i % 3 == 0 { t0 - DAY } else { far };
        let mut id = key(100 + i).to_be_bytes().repeat(2);
        id[0] = (i as u8) << 5;
        revoked.push(w.revocation(
            ByteArray::new(id.try_into().unwrap()),
            expiry,
            epoch - (i % 2) as u32,
        ));
    }
    // Each counts from an owner version drawn from the five below, so some are
    // ahead of the owner a peer holds, and count once a later owner arrives.
    let mut usage = Vec::new();
    for pass in passes
        .iter()
        .filter(|p| matches!(p.cert.class, PassClass::Invite { .. }))
    {
        let id = pass.cert.pass_id;
        let mut at = |used, expiry| w.usage_at(id, used, expiry, 1 + rng.below(5));
        usage.push(at(1 + (id[15] % 3), pass.cert.expiry));
        usage.push(at(1, pass.cert.expiry + DAY));
        // Crossing: the higher count runs out long before the lower one.
        usage.push(at(3, pass.cert.expiry - 20 * DAY));
        usage.push(at(2, pass.cert.expiry + 100 * DAY));
    }
    usage.push(w.usage(id_of(key(77)), 1, t0 - 10 * DAY));
    // Off the day: dropped wherever it lands (decision 17).
    usage.push(w.usage(passes[n_contacts as usize].cert.pass_id, 2, far + HOUR));
    usage.push(w.usage(passes[old_epoch + 1].cert.pass_id, 2, t0 + 30 * DAY + HOUR));

    // Near times, drawn twice as often, and times past every expiry and at
    // each window edge: an invite's expiry plus the window, either side of it,
    // then past the contact passes and past the renewed one.
    let near = [0, HOUR, DAY, 3 * DAY, 5 * DAY].map(|d| t0 + d);
    let late = [
        invite_gone - HOUR,
        invite_gone,
        invite_gone + 12 * HOUR,
        invite_gone + DAY + HOUR,
        far + WINDOW_BACK,
        far + 100 * DAY + WINDOW_BACK + HOUR,
    ];
    let times: Vec<_> = near
        .iter()
        .chain(&near)
        .chain(&late)
        .map(|t| w.time(*t))
        .collect();

    // Owner versions, any of which may tighten or relax: a later version can
    // go back to Open or lower min_usd, which re-admits what was filtered.
    let ids: Vec<B32> = messages.iter().map(|(id, _)| *id).collect();
    // Tombstones: a drained set that grows with the version, so a tombstone
    // can arrive before or after its message, and that the last version drops.
    let drained = rng.subset(&ids, 8);
    // Where a grace ends: none, between the near times, on one of them, past
    // them, after a routine bump's 14 days, and past every expiry.
    let graces = [
        0,
        0,
        t0 + 2 * HOUR,
        t0 + DAY,
        t0 + 4 * DAY,
        t0 + 14 * DAY,
        invite_gone + HOUR,
        far + 100 * DAY,
    ];
    let mut owners = Vec::new();
    for version in 1..=5 {
        let e = if rng.chance(40) { epoch + 1 } else { epoch };
        let grace = *rng.pick(&graces);
        let mut tomb: BTreeMap<B32, u64> =
            rng.subset(&ids, 5).into_iter().map(|id| (id, t0)).collect();
        if version < 5 {
            let upto = drained.len() * version as usize / 4;
            tomb.extend(drained.iter().take(upto).map(|id| (*id, t0)));
        }
        owners.push(w.owner_grace(version, e, grace, modes(rng), tomb));
    }
    // A version tie: the digest decides.
    owners.push(w.owner(3, epoch, modes(rng), BTreeMap::new()));

    Universe {
        fillers: &[],
        usage_fillers: &[],
        owners,
        times,
        revoked,
        usage,
        messages,
    }
}

/// A state a peer could hold: raw pieces, cleaned by the merge, perhaps several
/// deliveries in.
fn peer_state(laws: &Laws, u: &Universe, rng: &mut Rng) -> Result<Vec<u8>, String> {
    let (rules, params, w) = (laws.rules, world().params, world());
    let mut bytes = None::<Vec<u8>>;
    // Some peers hold much and some little, so a cap can be full on one side
    // only.
    let share = *rng.pick(&[10, 45, 45, 90]);
    for _ in 0..1 + rng.below(3) {
        let mut revoked = rng.subset(&u.revoked, share);
        revoked.extend(u.fillers.iter().cloned());
        let mut usage = rng.subset(&u.usage, share);
        usage.extend(u.usage_fillers.iter().cloned());
        let raw = w.raw(
            rng.pick(&u.owners).clone(),
            rng.pick(&u.times).clone(),
            revoked,
            usage,
            rng.subset(&u.messages, share),
        );
        let part: InboxDelta = raw.into();
        let merged = merge(rules, &params, vec![part.clone()]).expect("genuine pieces");
        laws.count_at_cap(&merged);
        laws.model(&[part], &merged)?;
        let clean = encode(&merged);
        bytes = Some(match bytes {
            None => clean,
            Some(prev) => laws.merge(&prev, &clean)?,
        });
    }
    Ok(bytes.unwrap())
}

#[derive(Default)]
struct Tally {
    /// Merges under V1 whose result holds exactly its revocation cap.
    at_cap: u64,
    triples: u64,
    /// Peer states whose owner bumped with a grace, before and after its end,
    /// and messages held under a pass of the previous epoch.
    in_grace: u64,
    grace_over: u64,
    grace_held: u64,
    strict: u64,
    healed: u64,
    held: u64,
    /// Merges under V1's caps in which each cap had more live items than
    /// room, as the oracle counts them.
    v1_overflow: [u64; 7],
}

const CAPS: [&str; 7] = [
    "revocations",
    "usage",
    "per pass",
    "pass pool",
    "owner pool",
    "per ghost",
    "quarantine",
];

struct Laws<'a> {
    rules: &'a Rules,
    label: String,
    /// Hold every merge to `oracle::check`. Off only to show what the laws
    /// see without it.
    oracle: bool,
    overflow: Cell<[u64; 7]>,
    at_cap: Cell<u64>,
}

impl<'a> Laws<'a> {
    fn new(rules: &'a Rules, label: String) -> Self {
        Laws {
            rules,
            label,
            oracle: true,
            overflow: Cell::new([0; 7]),
            at_cap: Cell::new(0),
        }
    }

    fn merge(&self, a: &[u8], b: &[u8]) -> Result<Vec<u8>, String> {
        // As the node does: a state merged into an identical copy never
        // reaches the contract, but the law is checked on the call anyway.
        let out = apply(self.rules, &world().params, a, update_state(b.to_vec()))
            .map_err(|e| format!("{}: merge refused: {e}", self.label))?;
        self.count_at_cap(&decode(&out).unwrap());
        if self.oracle {
            let parts: Vec<InboxDelta> = [a, b]
                .iter()
                .map(|s| decode::<InboxState>(s).unwrap().into())
                .collect();
            self.model(&parts, &decode(&out).unwrap())?;
        }
        Ok(out)
    }

    fn count_at_cap(&self, out: &InboxState) {
        if *self.rules == Rules::V1 && out.revoked.len() == Rules::V1.revoked {
            self.at_cap.set(self.at_cap.get() + 1);
        }
    }

    /// Nothing live in `parts` is lost from `out`.
    fn model(&self, parts: &[InboxDelta], out: &InboxState) -> Result<(), String> {
        if !self.oracle {
            return Ok(());
        }
        let o =
            oracle::check(self.rules, parts, out).map_err(|e| format!("{}: {e}", self.label))?;
        if *self.rules == Rules::V1 {
            let mut n = self.overflow.get();
            let hit = [
                o.revoked,
                o.usage,
                o.per_pass,
                o.pass_pool,
                o.owner_pool,
                o.per_ghost,
                o.quarantine,
            ];
            for (n, hit) in n.iter_mut().zip(hit) {
                *n += u64::from(hit);
            }
            self.overflow.set(n);
        }
        Ok(())
    }

    fn valid(&self, name: &str, state: &[u8]) -> Result<(), String> {
        if is_valid(self.rules, &world().params, state) {
            Ok(())
        } else {
            Err(format!("{}: {name} is not valid", self.label))
        }
    }

    fn heal(&self, l: &[u8], r: &[u8], inputs: [&[u8]; 3]) -> Result<(), String> {
        let mut m = self.merge(l, r)?;
        if self.merge(r, l)? != m {
            return Err(format!("{}: groupings do not converge", self.label));
        }
        let absorbed = [l, r, inputs[0], inputs[1], inputs[2]];
        let mut seen = HashSet::new();
        seen.insert(*blake3::hash(&m).as_bytes());
        for _ in 0..MAX_HEAL_PASSES {
            let mut changed = false;
            for other in absorbed {
                let next = self.merge(&m, other)?;
                if next != m {
                    if self.merge(&next, other)? != next {
                        return Err(format!("{}: redelivery moved the state", self.label));
                    }
                    if !seen.insert(*blake3::hash(&next).as_bytes()) {
                        return Err(format!("{}: heal cycle", self.label));
                    }
                    m = next;
                    changed = true;
                }
            }
            if !changed {
                return Ok(());
            }
        }
        Err(format!("{}: out of heal passes", self.label))
    }

    fn triple(&self, a: &[u8], b: &[u8], c: &[u8], tally: &mut Tally) -> Result<(), String> {
        let (l_label, r_label) = ("left grouping", "right grouping");
        for (name, s) in [("A", a), ("B", b), ("C", c)] {
            self.valid(name, s)?;
            // Idempotence, and apply-twice of a state onto itself.
            if self.merge(s, s)? != s {
                return Err(format!("{}: merge({name},{name}) moved", self.label));
            }
        }
        let ab = self.merge(a, b)?;
        self.valid("merge(A,B)", &ab)?;
        // Commutativity.
        if ab != self.merge(b, a)? {
            return Err(format!("{}: merge is not commutative", self.label));
        }
        // Apply-twice and absorption.
        if self.merge(&ab, b)? != ab {
            return Err(format!("{}: applying B twice moved the state", self.label));
        }
        if self.merge(a, &ab)? != ab || self.merge(&ab, a)? != ab {
            return Err(format!(
                "{}: merge(A, merge(A,B)) is not absorbed",
                self.label
            ));
        }
        let l = self.merge(&ab, c)?;
        let bc = self.merge(b, c)?;
        let r = self.merge(a, &bc)?;
        self.valid(l_label, &l)?;
        self.valid(r_label, &r)?;
        tally.triples += 1;
        if l == r {
            tally.strict += 1;
        } else {
            self.heal(&l, &r, [a, b, c])?;
            tally.healed += 1;
        }
        self.delta_laws(a, b, tally)
    }

    /// The delta path reaches what the whole state reaches, and a peer that is
    /// up to date is sent nothing.
    fn delta_laws(&self, a: &[u8], b: &[u8], tally: &mut Tally) -> Result<(), String> {
        let params = world().params;
        let decoded_a: InboxState = decode(a).unwrap();
        let decoded_b: InboxState = decode(b).unwrap();
        let summary_a = sync::summarize(&decoded_a);
        if !sync::delta(&decoded_a, &summary_a).unwrap().is_empty() {
            return Err(format!("{}: delta to an up-to-date peer", self.label));
        }
        if summary_a.len() * 4 >= a.len() {
            return Err(format!(
                "{}: summary {} of state {}",
                self.label,
                summary_a.len(),
                a.len()
            ));
        }
        let delta = sync::delta(&decoded_b, &summary_a).unwrap();
        let via = apply(
            self.rules,
            &params,
            a,
            vec![UpdateData::Delta(delta.into())],
        )
        .map_err(|e| e.to_string())?;
        if via != self.merge(a, b)? {
            return Err(format!("{}: delta path differs from the merge", self.label));
        }
        tally.held += decoded_a.messages.len() as u64;
        let owner = &decoded_a.owner;
        if owner.prev_epoch_until > 0 {
            if decoded_a.time.owner_time < owner.prev_epoch_until {
                tally.in_grace += 1;
            } else {
                tally.grace_over += 1;
            }
        }
        tally.grace_held += decoded_a
            .messages
            .values()
            .filter(|m| {
                matches!(&m.admission, Admission::Pass { cert, .. } if cert.epoch < owner.pass_epoch)
            })
            .count() as u64;
        Ok(())
    }

    fn non_canonical(&self, state: &[u8]) -> Result<(), String> {
        let params = world().params;
        for (name, bad) in non_canonical_forms(state) {
            if is_valid(self.rules, &params, &bad) {
                return Err(format!("{}: {name} validated", self.label));
            }
            if apply(self.rules, &params, state, update_state(bad)).is_ok() {
                return Err(format!("{}: {name} was merged", self.label));
            }
        }
        Ok(())
    }
}

fn run_seed(seed: u64, oracle: bool, tally: &mut Tally) -> Result<(), String> {
    for (name, rules, big) in [("tiny", TINY, false), ("v1", Rules::V1, true)] {
        let mut rng = Rng(seed ^ 0xF00D);
        let u = universe(seed, &mut rng, big);
        let mut laws = Laws::new(&rules, format!("seed {seed} {name}"));
        laws.oracle = oracle;
        let result = (|| {
            for _ in 0..TRIPLES_PER_SEED {
                let (a, b, c) = (
                    peer_state(&laws, &u, &mut rng)?,
                    peer_state(&laws, &u, &mut rng)?,
                    peer_state(&laws, &u, &mut rng)?,
                );
                laws.triple(&a, &b, &c, tally)?;
            }
            laws.non_canonical(&peer_state(&laws, &u, &mut rng)?)
        })();
        tally.add_overflow(&laws);
        result?;
    }
    // V1's revocation set at its cap: each peer holds the fillers plus a few of
    // the universe's own, so unions land below, at and above 4096, and the late
    // times prune a third of the fillers. A merge here checks 4096 signatures,
    // so this runs on every 20th seed.
    if seed.is_multiple_of(20) {
        let mut rng = Rng(seed ^ 0xCA9);
        let mut u = universe_at(seed, &mut rng, false, AT_CAP_T0);
        u.fillers = cap_fillers();
        u.usage_fillers = usage_fillers();
        // The fillers are epoch 3's: keep the owners under which they live
        // (epoch 3, or epoch 4 in a grace), or the set is never full. The
        // bump out of a full set is pinned in `tests/rules.rs`.
        u.owners
            .retain(|o| o.pass_epoch == 3 || o.prev_epoch_until > AT_CAP_T0);
        let mut laws = Laws::new(&Rules::V1, format!("seed {seed} v1 at the revocation cap"));
        laws.oracle = oracle;
        let result = (|| {
            let (a, b, c) = (
                peer_state(&laws, &u, &mut rng)?,
                peer_state(&laws, &u, &mut rng)?,
                peer_state(&laws, &u, &mut rng)?,
            );
            laws.triple(&a, &b, &c, tally)
        })();
        tally.add_overflow(&laws);
        result?;
    }
    Ok(())
}

impl Tally {
    fn add_overflow(&mut self, laws: &Laws) {
        self.at_cap += laws.at_cap.get();
        for (n, m) in self.v1_overflow.iter_mut().zip(laws.overflow.get()) {
            *n += m;
        }
    }

    fn add(&mut self, other: &Tally) {
        self.triples += other.triples;
        self.strict += other.strict;
        self.healed += other.healed;
        self.held += other.held;
        self.at_cap += other.at_cap;
        self.in_grace += other.in_grace;
        self.grace_over += other.grace_over;
        self.grace_held += other.grace_held;
        for (n, m) in self.v1_overflow.iter_mut().zip(other.v1_overflow) {
            *n += m;
        }
    }
}

/// Runs `seeds` over every core, each through `run`, which runs one seed on
/// the calling thread.
fn run_seeds(
    seeds: &[u64],
    run: &(dyn Fn(u64, &mut Tally) -> Result<(), String> + Sync),
) -> (Tally, Vec<String>) {
    world();
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        for chunk in seeds.chunks(seeds.len().div_ceil(threads)) {
            let tx = tx.clone();
            scope.spawn(move || {
                for &seed in chunk {
                    let mut tally = Tally::default();
                    let result = run(seed, &mut tally);
                    tx.send((tally, result)).unwrap();
                }
            });
        }
    });
    drop(tx);
    let mut total = Tally::default();
    let mut failures = Vec::new();
    for (tally, result) in rx {
        total.add(&tally);
        if let Err(e) = result {
            failures.push(e);
        }
    }
    (total, failures)
}

/// Writes the corpus `scripts/check-fdev-verify-merge.sh` hands to `fdev
/// verify-merge`: the contract's parameters and states peers could hold, under
/// the rules the WASM runs. Does nothing unless `INBOX_CAPTURE_DIR` names a
/// directory; the script fails if the files are not there.
#[test]
fn capture_states_for_fdev() {
    let Ok(dir) = std::env::var("INBOX_CAPTURE_DIR") else {
        return;
    };
    let dir = std::path::Path::new(&dir);
    std::fs::write(dir.join("params.bin"), world().params.to_bytes()).unwrap();
    let mut n = 0;
    for seed in 0..6 {
        let mut rng = Rng(seed ^ 0xF00D);
        let u = universe(seed, &mut rng, true);
        let laws = Laws::new(&Rules::V1, format!("capture seed {seed}"));
        for _ in 0..3 {
            let state = peer_state(&laws, &u, &mut rng).unwrap();
            std::fs::write(dir.join(format!("state-{n:02}.bin")), state).unwrap();
            n += 1;
        }
    }
}

#[test]
fn the_merge_laws_hold_over_crafted_states() {
    let seeds: Vec<u64> = match std::env::var("FORK_SEED") {
        Ok(one) => vec![one.parse().unwrap()],
        Err(_) => {
            let n = std::env::var("FORK_SEEDS").map_or(DEFAULT_SEEDS, |s| s.parse().unwrap());
            (0..n).collect()
        }
    };
    let (total, failures) = run_seeds(&seeds, &|seed, tally| run_seed(seed, true, tally));
    println!(
        "{} seeds: {} triples, {} strict, {} healed, {} messages held, {} merges ending at the revocation cap",
        seeds.len(),
        total.triples,
        total.strict,
        total.healed,
        total.held,
        total.at_cap
    );
    println!(
        "grace (decision 18): {} states in one, {} past its end, {} messages held under the previous epoch",
        total.in_grace, total.grace_over, total.grace_held
    );
    let overflow: Vec<String> = CAPS
        .iter()
        .zip(total.v1_overflow)
        .map(|(cap, n)| format!("{cap} {n}"))
        .collect();
    println!(
        "V1 merges whose live items overflowed a cap: {}",
        overflow.join(", ")
    );
    assert!(
        failures.is_empty(),
        "{} failures, first: {}",
        failures.len(),
        failures[0]
    );
    assert_eq!(total.strict + total.healed, total.triples);
    // The run must reach both branches, or the heal law was never exercised.
    assert!(
        total.strict > 0 && total.healed > 0,
        "both branches of the law ran"
    );
    assert!(total.held > total.triples, "states held messages");
    if seeds.len() >= 8 {
        assert!(
            total.in_grace > 0 && total.grace_over > 0 && total.grace_held > 0,
            "the grace ran on both sides of its end and admitted mail"
        );
        let [_, _, per_pass, pass_pool, owner_pool, per_ghost, quarantine] = total.v1_overflow;
        assert!(
            per_pass > 0 && pass_pool > 0 && owner_pool > 0 && per_ghost > 0 && quarantine > 0,
            "V1's per-pass, pass pool, owner pool, per-ghost and quarantine caps overflowed"
        );
    }
    // Seeds 0, 20 and 40 of the default run: the 4096 rule was fuzzed only if
    // merges got there. One such seed alone may not.
    if seeds.iter().filter(|s| s.is_multiple_of(20)).count() >= 3 {
        assert!(
            total.at_cap > 0 && total.v1_overflow[0] > 0,
            "merges reached and went over the 4096 revocation cap"
        );
        assert!(
            total.v1_overflow[1] > 0,
            "merges went over the 1024 usage cap"
        );
    }
}

/// The oracle is what sees a rule that loses a live item the same way every
/// time: run the fuzzer under each plausible mutant that did exactly that, and
/// it must fail through the oracle. What the laws alone make of the same seed
/// is printed beside it. Seeds run in order until one fails, so this is cheap.
#[cfg(feature = "plausible-mutants")]
mod the_oracle_sees_a_silent_loss {
    use super::*;
    use freenet_email_inbox_v2::mutant::{Mutant, with};

    fn caught(m: Mutant) {
        for seed in 0..48 {
            let Err(seen) = with(m, || run_seed(seed, true, &mut Tally::default())) else {
                continue;
            };
            assert!(
                seen.contains(oracle::ORACLE),
                "{m:?}: seed {seed} failed, but not through the oracle: {seen}"
            );
            let laws_alone = with(m, || run_seed(seed, false, &mut Tally::default()));
            println!("{m:?}: {seen}");
            println!("{m:?}, the laws alone on seed {seed}: {laws_alone:?}");
            return;
        }
        panic!("{m:?}: the oracle saw nothing in 48 seeds");
    }

    /// Decision 22's bug.
    #[test]
    fn revocations_ranked_by_expiry_first() {
        caught(Mutant::RevocationExpiryFirst);
    }

    /// Review r1 B1.
    #[test]
    fn joining_before_pruning() {
        caught(Mutant::JoinBeforePrune);
    }
}

/// A pass reissued in a new epoch under an id revoked in the old one, with the
/// old revocation still being redelivered.
#[test]
fn a_dead_revocation_redelivered_does_not_move_the_state() {
    let (w, rules) = (world(), Rules::V1);
    let params = w.params;
    let t = 1_800_000_000 / DAY * DAY;
    let old = w.owner(1, 3, QuarantineMode::Open, BTreeMap::new());
    let new = w.owner(2, 4, QuarantineMode::Open, BTreeMap::new());
    let pass = w.pass(1, 4, t + 300 * DAY, PassClass::Contact);
    let revocation = w.revocation(pass.cert.pass_id, t + 300 * DAY, 3);
    let revoking = encode(&w.raw(old, w.time(t), [revocation], [], []));
    let holding = encode(&w.raw(new, w.time(t), [], [], [w.pass_msg(&pass, ct(8192, 1), t)]));
    assert!(is_valid(&rules, &params, &revoking) && is_valid(&rules, &params, &holding));

    let merged = apply(&rules, &params, &revoking, update_state(holding.clone())).unwrap();
    let again = apply(&rules, &params, &merged, update_state(holding.clone())).unwrap();
    assert_eq!(merged, again, "redelivering the holder moved the state");
    let back = apply(&rules, &params, &again, update_state(revoking)).unwrap();
    assert_eq!(
        again, back,
        "redelivering the dead revocation moved the state"
    );
}

/// Review r1 B1, usage: on one pass id, the entry that ranks highest (used 3)
/// runs out first. It must not win the join and then be pruned, taking the
/// live entry (used 1) with it, or the state cycles under redelivery.
#[test]
fn a_dead_usage_entry_never_wins_the_join() {
    let w = world();
    let t = 1_800_000_000 / DAY * DAY;
    let owner = w.owner(1, 3, QuarantineMode::Open, BTreeMap::new());
    let p = id_of(7);
    let dying = w.usage(p, 3, t);
    let living = w.usage(p, 1, t + 100 * DAY);
    let a = encode(&w.raw(owner.clone(), w.time(t), [], [dying], []));
    let b = encode(&w.raw(owner.clone(), w.time(t + 10 * DAY), [], [], []));
    let c = encode(&w.raw(owner, w.time(t), [], [living.clone()], []));
    let laws = Laws::new(&Rules::V1, "usage".into());
    laws.triple(&a, &b, &c, &mut Tally::default()).unwrap();
    for (x, y) in [(&a, &b), (&b, &a)] {
        let ab = laws.merge(x, y).unwrap();
        let abc: InboxState = decode(&laws.merge(&ab, &c).unwrap()).unwrap();
        assert_eq!(abc.usage.get(&p), Some(&living), "the live entry stays");
    }
}

/// Review r1 B1, revocations: an entry from the old epoch with a later expiry
/// ranks above the new epoch's. The epoch bump prunes it, and it must not take
/// the new epoch's revocation with it, which would admit a revoked pass again.
#[test]
fn a_dead_revocation_never_wins_the_join() {
    let w = world();
    let t = 1_800_000_000 / DAY * DAY;
    let old = w.owner(1, 3, QuarantineMode::Open, BTreeMap::new());
    let new = w.owner(2, 4, QuarantineMode::Open, BTreeMap::new());
    let far = t + 300 * DAY;
    let pass = w.pass(9, 4, far, PassClass::Contact);
    let stale = w.revocation(pass.cert.pass_id, far + 100 * DAY, 3);
    let current = w.revocation(pass.cert.pass_id, far, 4);
    let msg = w.pass_msg(&pass, ct(8192, 1), t);
    let a = encode(&w.raw(old, w.time(t), [stale], [], []));
    let b = encode(&w.raw(new.clone(), w.time(t), [], [], []));
    let c = encode(&w.raw(new.clone(), w.time(t), [current.clone()], [], []));
    let laws = Laws::new(&Rules::V1, "revocation".into());
    laws.triple(&a, &b, &c, &mut Tally::default()).unwrap();
    let ca = laws.merge(&c, &a).unwrap();
    let merged: InboxState = decode(&ca).unwrap();
    assert_eq!(merged.revoked.get(&pass.cert.pass_id), Some(&current));
    // And the pass it revokes stays refused.
    let mail = encode(&w.raw(new, w.time(t), [], [], [msg]));
    let held: InboxState = decode(&laws.merge(&ca, &mail).unwrap()).unwrap();
    assert!(held.messages.is_empty(), "a revoked pass delivered mail");
}

/// The oracle states every number it is handed as its own literal, from the
/// plan and decisions. A wrong constant in the crate then fails here: it would
/// pass the fuzzer, which holds the merge to the oracle with the same number on
/// both sides.
#[test]
fn the_oracles_numbers_are_the_crates() {
    use freenet_email_inbox_v2::merge as m;
    assert_eq!(Rules::V1, oracle::SPEC_V1, "V1's caps");
    assert_eq!(
        WINDOW_BACK,
        oracle::WINDOW_BACK,
        "how far sent_time may trail"
    );
    assert_eq!(
        m::WINDOW_FORWARD,
        oracle::FORWARD,
        "how far sent_time may lead"
    );
    assert_eq!(
        m::QUARANTINE_FORWARD,
        oracle::QUARANTINE_FORWARD,
        "how far a quarantine message may lead"
    );
    assert_eq!(m::CIPHERTEXT_SIZES, oracle::SIZES, "ciphertext sizes");
    assert_eq!(m::SENT_TIME_GRANULARITY, HOUR, "sent_time granularity");
    assert_eq!(m::EXPIRY_GRANULARITY, DAY, "expiry granularity");
}
