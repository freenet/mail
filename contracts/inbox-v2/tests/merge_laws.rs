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
//! `FORK_SEEDS=n` sets how many seeds run (default below), `FORK_SEED=n` runs one.

mod common;

use std::collections::{BTreeMap, HashSet};

use common::*;
use freenet_email_inbox_v2::merge::merge;
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
        items.iter().filter(|_| self.chance(percent)).cloned().collect()
    }
}

/// Every piece one seed can draw on: the cases the plan lists, side by side, so
/// that a state can hold any mixture of them.
struct Universe {
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

fn universe(seed: u64, rng: &mut Rng, big: bool) -> Universe {
    let w = world();
    let t0 = 1_800_000_000 / HOUR * HOUR + rng.below(1000) * DAY;
    let epoch = 3;
    let far = t0 + 300 * DAY;
    // Keys differ per seed so states of different seeds never look alike.
    let key = |i: u64| seed.wrapping_mul(1_000_003).wrapping_add(i);
    let mut tag = 0u64;
    let mut ct_next = |rng: &mut Rng| {
        tag += 1;
        ct(*rng.pick(&[8192, 8192, 16384]), key(tag))
    };

    // Passes: live, wrong epoch, expired, invites, and one renewed (same id,
    // later expiry), which gives two encodings of one message id.
    let n_contacts = if big { 14 } else { 5 };
    let mut passes = Vec::new();
    for i in 0..n_contacts {
        passes.push(w.pass(key(i), epoch, far, PassClass::Contact));
    }
    for i in 0..3 {
        passes.push(w.pass(key(50 + i), epoch, t0 + 30 * DAY, PassClass::Invite { max_messages: 3 }));
    }
    passes.push(w.pass(key(60), epoch + 1, far, PassClass::Contact));
    passes.push(w.pass(key(61), epoch, t0 - 3 * DAY, PassClass::Contact));
    passes.push(w.pass(key(62), epoch, t0 + DAY, PassClass::Contact));
    let renewed = w.pass(key(0), epoch, far + 100 * DAY, PassClass::Contact);

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

    for _ in 0..if big { 12 } else { 5 } {
        let sent = t0 + rng.below(48) * HOUR;
        messages.push(w.owner_msg(ct_next(rng), sent));
    }
    for _ in 0..if big { 28 } else { 12 } {
        let sent = t0 + rng.below(48) * HOUR;
        let ghost = rng.chance(60).then(|| rng.below(w.ghosts.len() as u64) as usize);
        messages.push(w.quarantine_msg(ct_next(rng), sent, ghost));
    }
    // The same quarantine message with and without its proof: one id.
    let both = ct_next(rng);
    messages.push(w.quarantine_msg(both.clone(), t0, Some(0)));
    messages.push(w.quarantine_msg(both.clone(), t0, None));
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
    // Fillers: enough to go over TINY's cap, some soon prunable, some not, and
    // ids on both sides of the real ones.
    for i in 0..9 {
        let expiry = if i % 3 == 0 { t0 - DAY } else { far };
        let mut id = key(100 + i).to_be_bytes().repeat(2);
        id[0] = (i as u8) << 5;
        revoked.push(w.revocation(ByteArray::new(id.try_into().unwrap()), expiry, epoch - (i % 2) as u32));
    }
    let mut usage = Vec::new();
    for pass in passes.iter().filter(|p| matches!(p.cert.class, PassClass::Invite { .. })) {
        usage.push(w.usage(pass.cert.pass_id, 1 + rng.below(3) as u8, pass.cert.expiry));
        usage.push(w.usage(pass.cert.pass_id, 1, pass.cert.expiry + DAY));
    }
    usage.push(w.usage(id_of(key(77)), 1, t0 - 10 * DAY));

    let times: Vec<_> = [0, HOUR, DAY, 3 * DAY, 5 * DAY]
        .iter()
        .map(|d| w.time(t0 + d))
        .collect();

    // Owner versions, any of which may tighten or relax: a later version can
    // go back to Open or lower min_usd, which re-admits what was filtered.
    let ids: Vec<B32> = messages.iter().map(|(id, _)| *id).collect();
    let mut owners = Vec::new();
    for version in 1..=5 {
        let e = if rng.chance(25) { epoch + 1 } else { epoch };
        let tomb: BTreeMap<B32, u64> = rng.subset(&ids, 5).into_iter().map(|id| (id, t0)).collect();
        owners.push(w.owner(version, e, modes(rng), tomb));
    }
    // A version tie: the digest decides.
    owners.push(w.owner(3, epoch, modes(rng), BTreeMap::new()));

    Universe { owners, times, revoked, usage, messages }
}

/// A state a peer could hold: raw pieces, cleaned by the merge, perhaps several
/// deliveries in.
fn peer_state(rules: &Rules, u: &Universe, rng: &mut Rng) -> Vec<u8> {
    let params = world().params;
    let w = world();
    let mut bytes = None::<Vec<u8>>;
    for _ in 0..1 + rng.below(3) {
        let raw = w.raw(
            rng.pick(&u.owners).clone(),
            rng.pick(&u.times).clone(),
            rng.subset(&u.revoked, 40),
            rng.subset(&u.usage, 40),
            rng.subset(&u.messages, 45),
        );
        let clean = encode(&merge(rules, &params, vec![raw.into()]).expect("genuine pieces"));
        bytes = Some(match bytes {
            None => clean,
            Some(prev) => apply(rules, &params, &prev, update_state(clean)).expect("merge"),
        });
    }
    bytes.unwrap()
}

#[derive(Default)]
struct Tally {
    triples: u64,
    strict: u64,
    healed: u64,
    held: u64,
}

struct Laws<'a> {
    rules: &'a Rules,
    label: String,
}

impl Laws<'_> {
    fn merge(&self, a: &[u8], b: &[u8]) -> Result<Vec<u8>, String> {
        // As the node does: a state merged into an identical copy never
        // reaches the contract, but the law is checked on the call anyway.
        apply(self.rules, &world().params, a, update_state(b.to_vec()))
            .map_err(|e| format!("{}: merge refused: {e}", self.label))
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
            return Err(format!("{}: merge(A, merge(A,B)) is not absorbed", self.label));
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
            return Err(format!("{}: summary {} of state {}", self.label, summary_a.len(), a.len()));
        }
        let delta = sync::delta(&decoded_b, &summary_a).unwrap();
        let via = apply(self.rules, &params, a, vec![UpdateData::Delta(delta.into())])
            .map_err(|e| e.to_string())?;
        if via != self.merge(a, b)? {
            return Err(format!("{}: delta path differs from the merge", self.label));
        }
        tally.held += decoded_a.messages.len() as u64;
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

/// `state` re-spelled so it decodes to the same value, or with one thing added.
fn non_canonical_forms(state: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
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
    let Value::Map(fields) = value.clone() else { panic!("a map") };

    let mut extra = fields.clone();
    extra.push((Value::Text("extra".into()), Value::Integer(1.into())));
    forms.push(("unknown field", reencode(&Value::Map(extra))));

    let mut swapped = fields.clone();
    swapped.swap(0, 1);
    forms.push(("fields out of order", reencode(&Value::Map(swapped))));

    // Keys of a collection: repeat one, and reverse them.
    for field in ["revoked", "usage", "messages"] {
        let at = fields.iter().position(|(k, _)| k.as_text() == Some(field)).unwrap();
        let Value::Map(entries) = &fields[at].1 else { panic!("a map") };
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

fn run_seed(seed: u64, tally: &mut Tally) -> Result<(), String> {
    for (name, rules, big) in [("tiny", TINY, false), ("v1", Rules::V1, true)] {
        let mut rng = Rng(seed ^ 0xF00D);
        let u = universe(seed, &mut rng, big);
        let laws = Laws { rules: &rules, label: format!("seed {seed} {name}") };
        for _ in 0..TRIPLES_PER_SEED {
            let (a, b, c) = (
                peer_state(&rules, &u, &mut rng),
                peer_state(&rules, &u, &mut rng),
                peer_state(&rules, &u, &mut rng),
            );
            laws.triple(&a, &b, &c, tally)?;
        }
        laws.non_canonical(&peer_state(&rules, &u, &mut rng))?;
    }
    Ok(())
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
    world();
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        for chunk in seeds.chunks(seeds.len().div_ceil(threads)) {
            let tx = tx.clone();
            scope.spawn(move || {
                for &seed in chunk {
                    let mut tally = Tally::default();
                    let result = run_seed(seed, &mut tally);
                    tx.send((tally, result)).unwrap();
                }
            });
        }
    });
    drop(tx);
    let mut total = Tally::default();
    let mut failures = Vec::new();
    for (tally, result) in rx {
        total.triples += tally.triples;
        total.strict += tally.strict;
        total.healed += tally.healed;
        total.held += tally.held;
        if let Err(e) = result {
            failures.push(e);
        }
    }
    println!(
        "{} seeds: {} triples, {} strict, {} healed, {} messages held",
        seeds.len(), total.triples, total.strict, total.healed, total.held
    );
    assert!(failures.is_empty(), "{} failures, first: {}", failures.len(), failures[0]);
    assert_eq!(total.strict + total.healed, total.triples);
    // The run must reach both branches, or the heal law was never exercised.
    assert!(total.strict > 0 && total.healed > 0, "both branches of the law ran");
    assert!(total.held > total.triples, "states held messages");
}
