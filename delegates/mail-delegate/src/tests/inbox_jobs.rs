//! The inbox v2 jobs, end to end through the merged contract: what a run
//! sends is applied with the contract's own merge, and the node's store (the
//! `MemEnv` contracts) holds what the network holds.

use std::collections::{BTreeMap, BTreeSet};

use freenet_email_inbox_v2::apply;
use freenet_email_inbox_v2::merge::{Rules, WEBAPP_REQUESTOR};
use freenet_mail_protocol::inbox_v2::{self as w, InboxDelta};
use freenet_mail_protocol::{
    Addr, ChangeOutcome, Hash32, ImportKind, ImportSource, JobsRun, Op, OwnerChange, Reply,
    SealContent, SendAdmission, SendNotice,
};
use freenet_stdlib::prelude::{ContractInstanceId, OutboundDelegateMsg, UpdateData, WrappedState};
use serde_bytes::{ByteArray, ByteBuf};

use super::inbox_v2::{DAY, World, env_or, inbound_stored, loaded, texts};
use super::{PROD, call};
use crate::env::mem::{Faults, MemEnv};
use crate::inbox_jobs;
use crate::inbox_v2::{self as v2, STRANGERS_KEPT};
use crate::jobs::{Tick, Trigger};
use crate::store::Origin;
use crate::watch;

const PAGE: Trigger = Trigger::RunJobs(Origin([PROD; 32]));

fn id_of(world: &World, addr: &Addr) -> [u8; 32] {
    inbox_jobs::inbox_id(addr, &world.master).unwrap()
}

/// The node holds every inbox as the network does.
fn sync(world: &mut World) {
    let ids: Vec<_> = world
        .inboxes
        .iter()
        .map(|(a, st)| (id_of(world, a), st.clone()))
        .collect();
    world.env.contracts.extend(ids);
}

/// One run of the jobs for `trigger`. Every update it sends goes through the
/// contract. Returns the run and the updates, by inbox.
fn run(world: &mut World, trigger: Trigger) -> (JobsRun, Vec<(Addr, InboxDelta)>) {
    sync(world);
    let (done, out) = watch::run(&mut world.env, trigger);
    let by_id: BTreeMap<[u8; 32], Addr> = world
        .inboxes
        .keys()
        .map(|a| (id_of(world, a), *a))
        .collect();
    let mut updates = Vec::new();
    for m in out {
        if let OutboundDelegateMsg::UpdateContractRequest(r) = m {
            let id: [u8; 32] = r.contract_id.as_bytes().try_into().unwrap();
            let UpdateData::Delta(d) = r.update else {
                panic!("a job sends deltas");
            };
            let addr = by_id[&id];
            world.publish(&addr, d.as_ref());
            updates.push((addr, w::decode(d.as_ref()).unwrap()));
        }
    }
    sync(world);
    (done, updates)
}

/// Page runs, of every origin in use, until nothing more is sent.
fn settle(world: &mut World) -> Vec<(Addr, InboxDelta)> {
    let mut origins: BTreeSet<u8> = world.origins.values().copied().collect();
    origins.insert(PROD);
    let mut all = Vec::new();
    // A clock far behind catches up a week a run (the guard).
    for _ in 0..80 {
        let mut quiet = true;
        for o in &origins {
            let (_, updates) = run(world, Trigger::RunJobs(Origin([*o; 32])));
            quiet &= updates.is_empty();
            all.extend(updates);
        }
        if quiet {
            return all;
        }
    }
    panic!("the jobs never settle");
}

fn hold(world: &mut World, addr: &Addr, pass: w::Pass) {
    let origin = world.origin(addr);
    call(&mut world.env, origin, Op::HoldPass { addr: *addr, pass }).unwrap();
}

fn admission(sealed: &freenet_mail_protocol::SealedV2) -> w::Admission {
    w::decode::<w::Message>(&sealed.message).unwrap().admission
}

/// System messages a set of updates carried to `to`.
fn messages_to(updates: &[(Addr, InboxDelta)], to: &Addr) -> usize {
    updates
        .iter()
        .filter(|(a, _)| a == to)
        .map(|(_, d)| d.messages.len())
        .sum()
}

/// Alice gave Bob a contact pass out of band and never writes to him. Bob
/// writes to her with it. The renew job keeps his pass alive through a
/// silent system message sent with the pass he gave her, so past the first
/// certificate's expiry his mail still goes by pass.
#[test]
fn a_renewal_reaches_a_contact_who_is_never_written_to() {
    let mut world = World::new();
    let a = world.identity("alice");
    let b = world.identity("bob");
    let pass = world.issue(&a, Some(b), None);
    hold(&mut world, &b, pass.clone());
    let (hello, landed) = world.send(&b, &a, "hello");
    assert!(landed);
    assert_eq!(hello.admission, SendAdmission::Pass);
    settle(&mut world);
    let pass_id = pass.cert.pass_id;
    let first = world.ledger(&a, pass_id.as_slice());
    assert_eq!(first.delivered, first.expiry, "handed over by the page");

    let mut renewals = 0;
    let mut terms = 0;
    let mut expiry = first.expiry;
    let mut day = 0;
    while world.env.now.unwrap() < first.expiry + 10 * DAY {
        world.advance(DAY);
        day += 1;
        let updates = settle(&mut world);
        renewals += messages_to(&updates, &b);
        let now_expiry = world.ledger(&a, pass_id.as_slice()).expiry;
        if now_expiry != expiry {
            terms += 1;
            expiry = now_expiry;
        }
        if day % 30 == 0 {
            let (sealed, landed) = world.send(&b, &a, &format!("day {day}"));
            assert!(landed, "day {day}");
            assert_eq!(sealed.admission, SendAdmission::Pass, "day {day}");
        }
    }
    let now = world.env.now.unwrap();
    let after = world.ledger(&a, pass_id.as_slice());
    assert!(after.expiry > now, "renewed before it lapsed");
    assert_eq!(
        after.delivered, after.expiry,
        "and read back from Bob's inbox"
    );
    assert!(terms >= 1, "renewed");
    assert_eq!(renewals, terms, "one silent message a renewal, no resend");
    // Alice never wrote: Bob's mail holds nothing.
    assert!(world.inbound(&b).is_empty());
    let (late, landed) = world.send(&b, &a, "after the first expiry");
    assert!(landed);
    let w::Admission::Pass { cert, .. } = admission(&late) else {
        panic!("Bob fell back to quarantine");
    };
    assert_eq!((cert.pass_id, cert.expiry), (pass_id, after.expiry));
    assert!(now > first.expiry);
}

/// A renewal not seen in the contact's inbox is sealed again: a lost update
/// does not leave the contact to lapse.
#[test]
fn a_renewal_that_does_not_land_is_sent_again() {
    let mut world = World::new();
    let a = world.identity("alice");
    let b = world.identity("bob");
    let pass = world.issue(&a, Some(b), None);
    hold(&mut world, &b, pass.clone());
    world.send(&b, &a, "hello");
    settle(&mut world);
    let first = world.ledger(&a, pass.cert.pass_id.as_slice());
    world.advance(first.renew_at - world.env.now.unwrap() + 1);
    // The run's update to Bob is lost.
    let bob_before = world.inboxes[&b].clone();
    let (_, updates) = run(&mut world, Trigger::Tick(Tick::Renew));
    assert_eq!(messages_to(&updates, &b), 1);
    world.inboxes.insert(b, bob_before.clone());
    let pending = world
        .ledger(&a, pass.cert.pass_id.as_slice())
        .pending
        .unwrap();
    // Not again before RESEND_AFTER.
    world.advance(v2::RESEND_AFTER - 60);
    let (_, updates) = run(&mut world, Trigger::Tick(Tick::Renew));
    assert_eq!(messages_to(&updates, &b), 0);
    world.advance(120);
    let (_, updates) = run(&mut world, Trigger::Tick(Tick::Renew));
    assert_eq!(messages_to(&updates, &b), 1, "sealed again");
    let again = world
        .ledger(&a, pass.cert.pass_id.as_slice())
        .pending
        .unwrap();
    assert_ne!(again.id, pending.id, "a fresh message");
    assert_eq!(again.expiry, pending.expiry, "of the same certificate");
    // Read back at the next look.
    world.advance(v2::RESEND_AFTER);
    settle(&mut world);
    let done = world.ledger(&a, pass.cert.pass_id.as_slice());
    assert_eq!(done.delivered, done.expiry);
    assert!(done.pending.is_none());
}

/// With no live pass to the contact, a renewal is not sent through
/// quarantine: it waits, and the next mail carries it.
#[test]
fn a_renewal_never_goes_through_quarantine() {
    let mut world = World::new();
    let a = world.identity("alice");
    let b = world.identity("bob");
    let pass = world.issue(&a, Some(b), None);
    hold(&mut world, &b, pass.clone());
    let first = world.ledger(&a, pass.cert.pass_id.as_slice());
    // Alice holds no pass of Bob's: he never wrote.
    world.advance(first.renew_at - world.env.now.unwrap() + 1);
    let (_, updates) = run(&mut world, Trigger::Tick(Tick::Renew));
    assert_eq!(messages_to(&updates, &b), 0);
    assert!(
        world
            .ledger(&a, pass.cert.pass_id.as_slice())
            .pending
            .is_none()
    );
    let due = world.record(&a).due[&ByteArray::new(b.0)];
    assert_eq!(due, world.env.now.unwrap() + v2::NO_PASS_RETRY);
    // Mail to Bob carries it and is read back like a renewal.
    let (sealed, landed) = world.send(&a, &b, "a letter");
    assert!(landed);
    assert_eq!(sealed.admission, SendAdmission::Quarantine);
    let e = world.ledger(&a, pass.cert.pass_id.as_slice());
    assert_eq!(e.pending.unwrap().id.into_array(), sealed.id.0);
    world.advance(v2::RESEND_AFTER);
    settle(&mut world);
    let e = world.ledger(&a, pass.cert.pass_id.as_slice());
    assert_eq!(e.delivered, e.expiry);
}

/// Alice seals a reply to Bob, who wrote first, and the page never sends
/// it. Nothing goes to Bob for it: composing to someone never makes the
/// node write to them. Mail she does send is then read back as before.
#[test]
fn a_sealed_message_never_sent_sends_nothing() {
    let mut world = World::new();
    let a = world.identity("alice");
    let b = world.identity("bob");
    world.send(&b, &a, "hello");
    world.change(&a, OwnerChange::Drain);
    let draft = world.seal(&a, &b, "never sent").unwrap();
    assert_eq!(
        draft.admission,
        SendAdmission::Pass,
        "Alice holds Bob's pass"
    );
    let mut sent = 0;
    for _ in 0..12 {
        world.advance(v2::RESEND_AFTER);
        let (_, updates) = run(&mut world, Trigger::Tick(Tick::Renew));
        sent += messages_to(&updates, &b);
        sent += messages_to(&settle(&mut world), &b);
    }
    assert_eq!(sent, 0);
    assert!(world.record(&a).due.is_empty(), "nothing left to look at");
    // Past the window the draft could not land; mail sealed now replaces it.
    let (letter, landed) = world.send(&a, &b, "a letter");
    assert!(landed);
    let pass_id = *world.record(&a).issued.values().next().unwrap();
    let e = world.ledger(&a, pass_id.as_slice());
    assert_eq!(e.pending.unwrap().id.into_array(), letter.id.0);
    world.advance(v2::RESEND_AFTER);
    settle(&mut world);
    let e = world.ledger(&a, pass_id.as_slice());
    assert_eq!(e.delivered, e.expiry);
}

/// The clock job drains first and signs the new time in the same update; a
/// message that cannot be stored holds the time back only as far as keeps it
/// in the window.
#[test]
fn the_clock_advances_owner_time_after_draining() {
    let mut world = World::new();
    let a = world.identity("alice");
    let b = world.identity("bob");
    let (sealed, _) = world.send(&b, &a, "before the tick");
    // Three days on, the node's time would drop it.
    world.advance(3 * DAY);
    world.env.fail_keys_containing = Some("it/in/".into());
    let (_, updates) = run(&mut world, Trigger::Tick(Tick::Clock));
    let (_, delta) = updates.iter().find(|(addr, _)| *addr == a).unwrap();
    let edge = sealed.sent_time + w::WINDOW_BACK;
    assert_eq!(delta.time.as_ref().unwrap().owner_time, edge);
    assert!(delta.owner.is_none(), "nothing tombstoned");
    assert_eq!(world.state(&a).messages.len(), 1, "the message stays");
    world.env.fail_keys_containing = None;
    // Stored now, it goes with the time that drops it: no tombstone needed.
    let (_, updates) = run(&mut world, Trigger::Tick(Tick::Clock));
    let (_, delta) = updates.iter().find(|(addr, _)| *addr == a).unwrap();
    let now = world.env.now.unwrap();
    assert_eq!(
        delta.time.as_ref().unwrap().owner_time,
        now,
        "the guard allows it"
    );
    assert!(world.state(&a).messages.is_empty());
    assert_eq!(texts(&world.inbound(&a)), ["before the tick"]);
    // Not again while it is less than CLOCK_LAG behind.
    world.advance(v2::CLOCK_LAG - 60);
    let (_, updates) = run(&mut world, Trigger::Tick(Tick::Clock));
    assert!(updates.is_empty());
    // A long gap is crossed a week at a time.
    world.advance(30 * DAY);
    let (_, updates) = run(&mut world, Trigger::Tick(Tick::Clock));
    let t = updates[0].1.time.as_ref().unwrap().owner_time;
    assert_eq!(t, now + 7 * DAY);
}

/// One drain run of the jobs over a faulty host: every tombstone an update
/// carries names a message already stored, and once the host heals
/// everything arrives.
fn job_drain_run(
    base: &World,
    a: &Addr,
    mail: &BTreeMap<[u8; 32], String>,
    faults: Faults,
) -> Result<u64, String> {
    let mut world = base.clone();
    world.env.faults = Some(faults);
    let mut injected = 0;
    for call in 0..14 {
        if call == 8 {
            injected = world.env.faults.take().map_or(0, |f| f.injected.get());
        }
        sync(&mut world);
        let (_, out) = watch::run(&mut world.env, PAGE);
        for m in out {
            let OutboundDelegateMsg::UpdateContractRequest(r) = m else {
                continue;
            };
            let UpdateData::Delta(d) = r.update else {
                return Err("not a delta".into());
            };
            let delta: InboxDelta = w::decode(d.as_ref()).unwrap();
            for id in delta.owner.iter().flat_map(|o| o.tombstones.keys()) {
                if mail.contains_key(&**id) && !inbound_stored(&world, a, id) {
                    return Err(format!("{} tombstoned before it was stored", mail[&**id]));
                }
            }
            if r.contract_id == ContractInstanceId::new(id_of(&world, a)) {
                world.publish(a, d.as_ref());
            }
        }
    }
    if !world.state(a).messages.is_empty() {
        return Err("mail left in the inbox after healing".into());
    }
    let got = texts(&world.inbound(a));
    let mut want: Vec<String> = mail.values().cloned().collect();
    want.push("first".into());
    want.sort();
    if got != want {
        return Err(format!("stored {got:?}, sent {want:?}"));
    }
    Ok(injected)
}

/// Never lose a message in a background drain: the jobs over a host that
/// misses reads and refuses writes at `JOB_DRAIN_RATE` per mille (default
/// 60), and with `JOB_DRAIN_BLIND` lets one key at a time go unreadable.
#[test]
fn a_job_drain_over_a_faulty_host_never_tombstones_what_it_did_not_store() {
    let (base, a, mail) = loaded();
    let seeds = env_or("JOB_DRAIN_SEEDS", 40);
    let rate = env_or("JOB_DRAIN_RATE", 60) as u32;
    let blind = env_or("JOB_DRAIN_BLIND", 0) as u32;
    let from = env_or("JOB_DRAIN_FROM", 1);
    let mut injected = 0;
    let mut failures = Vec::new();
    for seed in from..from + seeds {
        let faults = Faults::seeded_with_blindness(seed, rate, blind);
        match job_drain_run(&base, &a, &mail, faults) {
            Ok(n) => injected += n,
            Err(e) => failures.push(format!("seed {seed}: {e}")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(injected > seeds, "only {injected} faults injected");
}

/// What the sweep below sees of every update the jobs send to Alice: the
/// owner version, the signed time and the epoch only ever move forward.
struct Monotonic {
    version: u64,
    time: u64,
    epoch: u32,
}

impl Monotonic {
    fn of(state: &w::InboxState) -> Self {
        Monotonic {
            version: state.owner.version,
            time: state.time.owner_time,
            epoch: state.owner.pass_epoch,
        }
    }

    fn see(&mut self, updates: &[(Addr, InboxDelta)], a: &Addr) -> Result<(), String> {
        for (_, d) in updates.iter().filter(|(to, _)| to == a) {
            if let Some(o) = &d.owner {
                if o.version <= self.version {
                    return Err(format!("owner version {} after {}", o.version, self.version));
                }
                if o.pass_epoch < self.epoch {
                    return Err(format!("epoch {} after {}", o.pass_epoch, self.epoch));
                }
                self.version = o.version;
                self.epoch = o.pass_epoch;
            }
            if let Some(t) = &d.time {
                if t.owner_time < self.time {
                    return Err(format!("owner_time {} after {}", t.owner_time, self.time));
                }
                self.time = t.owner_time;
            }
        }
        Ok(())
    }
}

/// Alice with three contacts who hold her passes, one message each already
/// drained. Returns each contact with its pass id and the pass's first expiry.
fn with_contacts() -> (World, Addr, Vec<(Addr, w::B16, u64)>) {
    let mut world = World::new();
    let a = world.identity("alice");
    let mut contacts = Vec::new();
    for name in ["bob", "carol", "dave"] {
        let c = world.identity(name);
        let pass = world.issue(&a, Some(c), None);
        hold(&mut world, &c, pass.clone());
        world.send(&c, &a, "hi");
        let id = pass.cert.pass_id;
        let expiry = world.ledger(&a, id.as_slice()).expiry;
        contacts.push((c, id, expiry));
    }
    settle(&mut world);
    (world, a, contacts)
}

/// One run of the time-driven jobs over a faulty host: the clock, every
/// renewal and a routine bump with its reissues all happen under faults, over
/// the better part of a year. Mail the contacts send on the way is drained
/// under the same faults. Nothing is tombstoned before it is stored, no
/// message is lost or stored twice, no version, time or epoch goes back, and
/// once the host heals every contact holds a pass the node has seen arrive.
fn job_time_run(
    base: &World,
    a: &Addr,
    contacts: &[(Addr, w::B16, u64)],
    faults: Faults,
) -> Result<u64, String> {
    let mut world = base.clone();
    let mut seen = Monotonic::of(&world.state(a));
    let latest = contacts
        .iter()
        .map(|(_, id, _)| world.ledger(a, id.as_slice()).renew_at)
        .max()
        .unwrap();
    let mut mail: BTreeMap<[u8; 32], String> = BTreeMap::new();
    let mut ops = 0;
    world.env.faults = Some(faults);

    let step = |world: &mut World,
                seen: &mut Monotonic,
                mail: &BTreeMap<[u8; 32], String>,
                secs: u64|
     -> Result<(), String> {
        world.advance(secs);
        let (_, updates) = run(world, PAGE);
        seen.see(&updates, a)?;
        for id in updates
            .iter()
            .filter(|(to, _)| to == a)
            .flat_map(|(_, d)| d.owner.iter().flat_map(|o| o.tombstones.keys()))
        {
            if mail.contains_key(&**id) && !inbound_stored(world, a, id) {
                return Err(format!("{} tombstoned before it was stored", mail[&**id]));
            }
        }
        Ok(())
    };
    // A contact writes now and then; a refused seal is just a message not sent.
    let write = |world: &mut World, mail: &mut BTreeMap<[u8; 32], String>, n: usize| {
        let (c, _, _) = &contacts[n % contacts.len()];
        if let Ok(sealed) = world.seal(c, a, &format!("mail {n}")) {
            let message: w::Message = w::decode(&sealed.message).unwrap();
            let delta = InboxDelta {
                messages: [(ByteArray::new(sealed.id.0), message)].into(),
                ..InboxDelta::default()
            };
            world.publish(a, &w::encode(&delta));
            if w::delivered(&world.state(a), &sealed.id.0) {
                mail.insert(sealed.id.0, format!("mail {n}"));
            }
        }
    };

    // The clock, then every renewal, a few days at a time.
    let mut n = 0;
    while world.env.now.unwrap() < latest + 5 * DAY {
        step(&mut world, &mut seen, &mail, 5 * DAY)?;
        ops += 1;
        if ops % 8 == 0 {
            write(&mut world, &mut mail, n);
            n += 1;
        }
    }
    // A routine bump, tried until it is signed (a host this faulty may refuse
    // all of a few tries), then the reissues over its grace.
    let bump = |world: &mut World, seen: &mut Monotonic, tries: usize| -> Result<bool, String> {
        for _ in 0..tries {
            let Ok(u) = world.update(a, OwnerChange::BumpEpoch { emergency: false }) else {
                continue;
            };
            if let Some(delta) = &u.update {
                let decoded: InboxDelta = w::decode(delta).unwrap();
                seen.see(&[(*a, decoded)], a)?;
                world.publish(a, delta);
            }
            if u.remaining == 0 && u.change == ChangeOutcome::Signed {
                return Ok(true);
            }
        }
        Ok(false)
    };
    let bumped = bump(&mut world, &mut seen, 20)?;
    write(&mut world, &mut mail, n);
    for _ in 0..28 {
        step(&mut world, &mut seen, &mail, 12 * 3600)?;
    }
    // Healed: everything catches up, and a bump that never got through is
    // signed now, with its whole grace still to run.
    let injected = world.env.faults.take().map_or(0, |f| f.injected.get());
    if !bumped && !bump(&mut world, &mut seen, 3)? {
        return Err("the bump was never signed on a healed host".into());
    }
    for _ in 0..64 {
        step(&mut world, &mut seen, &mail, 6 * 3600)?;
    }
    settle(&mut world);

    if !world.state(a).messages.is_empty() {
        return Err("mail left in the inbox after healing".into());
    }
    let mut origin_probe = MemEnv::default();
    let space = crate::store::Space::new(&mut origin_probe, Origin([PROD; 32]));
    for (id, text) in &mail {
        let key = space.full_key(&crate::store::item_rel(&freenet_mail_protocol::ItemRef {
            kind: freenet_mail_protocol::ItemKind::Inbound,
            owner: Some(*a),
            id: id.to_vec(),
        }));
        match world.env.writes.get(&key) {
            Some(1) => {}
            other => return Err(format!("{text} was written {other:?} times")),
        }
    }
    let stored = world.inbound(a).len();
    if stored != mail.len() + contacts.len() {
        return Err(format!(
            "{stored} messages stored, {} sent",
            mail.len() + contacts.len()
        ));
    }
    let rec = world.record(a);
    for (c, id, first) in contacts {
        let e = world.ledger(a, id.as_slice());
        if e.pending.is_some() {
            return Err(format!("{c:?}: a renewal is still pending after healing"));
        }
        if e.expiry <= *first || e.epoch != rec.pass_epoch {
            return Err(format!(
                "{c:?}: pass of epoch {} expiring {} (first {first}) in epoch {}",
                e.epoch, e.expiry, rec.pass_epoch
            ));
        }
        // What matters is what the contact holds: the current certificate.
        let origin = Origin([world.origin(c); 32]);
        let space = crate::store::Space::new(&mut world.env, origin);
        let held: Vec<w::Pass> = v2::load(
            &space,
            &v2::item(freenet_mail_protocol::ItemKind::HeldPass, c, &a.0),
        )
        .ok()
        .flatten()
        .map(|(_, held)| held)
        .ok_or_else(|| format!("{c:?} holds no pass of Alice's"))?;
        if !held
            .iter()
            .any(|p| p.cert.pass_id == *id && p.cert.epoch == e.epoch && p.cert.expiry == e.expiry)
        {
            return Err(format!(
                "{c:?} holds epoch {:?} of a pass now at epoch {} expiring {} (delivered {})",
                held.iter().map(|p| (p.cert.epoch, p.cert.expiry)).collect::<Vec<_>>(),
                e.epoch,
                e.expiry,
                e.delivered
            ));
        }
    }
    if world.state(a).owner.pass_epoch != 2 {
        return Err("the bump never landed".into());
    }
    // The clock kept up through all of it.
    let lag = world
        .env
        .now
        .unwrap()
        .saturating_sub(world.state(a).time.owner_time);
    if lag > v2::CLOCK_LAG + 6 * 3600 {
        return Err(format!("owner_time {lag} s behind the node's clock"));
    }
    Ok(injected)
}

/// The time-driven jobs over a host that misses reads and refuses writes at
/// `JOB_TIME_RATE` per mille (default 60), over `JOB_TIME_SEEDS` seeds
/// (default 6; a long run uses thousands).
#[test]
fn the_clock_renewals_and_a_bump_over_a_faulty_host_lose_and_double_nothing() {
    let (base, a, contacts) = with_contacts();
    let seeds = env_or("JOB_TIME_SEEDS", 6);
    let rate = env_or("JOB_TIME_RATE", 60) as u32;
    let blind = env_or("JOB_TIME_BLIND", 0) as u32;
    let from = env_or("JOB_TIME_FROM", 1);
    let mut injected = 0;
    let mut failures = Vec::new();
    for seed in from..from + seeds {
        let faults = Faults::seeded_with_blindness(seed, rate, blind);
        match job_time_run(&base, &a, &contacts, faults) {
            Ok(n) => injected += n,
            Err(e) => failures.push(format!("seed {seed}: {e}")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(injected > seeds, "only {injected} faults injected");
}

/// A routine bump: every contact pass is reissued at its own drawn point of
/// the 14-day grace, through the contact's pass, and each contact writes
/// with the new epoch once the old one is gone.
#[test]
fn a_bump_reissues_each_pass_at_its_own_point_of_the_grace() {
    let mut world = World::new();
    let a = world.identity("alice");
    let names = ["bob", "carol", "dave", "erin", "frank"];
    let mut contacts = Vec::new();
    for name in names {
        let c = world.identity(name);
        let pass = world.issue(&a, Some(c), None);
        hold(&mut world, &c, pass.clone());
        world.send(&c, &a, "hi");
        contacts.push((c, pass.cert.pass_id));
    }
    settle(&mut world);
    world.change(&a, OwnerChange::BumpEpoch { emergency: false });
    let bumped = world.env.now.unwrap();
    let rec = world.record(&a);
    let points: BTreeSet<u64> = contacts
        .iter()
        .map(|(c, _)| rec.due[&ByteArray::new(c.0)])
        .collect();
    assert_eq!(points.len(), contacts.len(), "each its own point");
    assert!(
        points
            .iter()
            .all(|t| (bumped..bumped + v2::EPOCH_GRACE).contains(t))
    );

    let mut arrived = BTreeMap::new();
    for hour in 0..(15 * 24) {
        world.advance(3600);
        let updates = settle(&mut world);
        for (c, _) in &contacts {
            if messages_to(&updates, c) > 0 {
                arrived.entry(*c).or_insert(hour);
            }
        }
    }
    assert_eq!(arrived.len(), contacts.len(), "every contact got one");
    let hours: BTreeSet<_> = arrived.values().collect();
    assert!(hours.len() > 1, "not all at once: {arrived:?}");
    // Past the grace only epoch 2 is admitted, and every contact has it.
    assert!(world.state(&a).time.owner_time >= world.state(&a).owner.prev_epoch_until);
    for (c, pass_id) in &contacts {
        let (sealed, landed) = world.send(c, &a, "new epoch");
        assert!(landed);
        let w::Admission::Pass { cert, .. } = admission(&sealed) else {
            panic!("fell back to quarantine");
        };
        assert_eq!((cert.pass_id, cert.epoch), (*pass_id, 2));
    }
}

/// A send queued past two days falls out of the recipient's window, and the
/// contract drops it without an error. Sealed again at `reseal_at` it lands.
#[test]
fn a_send_queued_past_two_days_is_sealed_again() {
    let mut world = World::new();
    let a = world.identity("alice");
    let b = world.identity("bob");
    let queued = world.seal(&b, &a, "queued").unwrap();
    let lead = v2::TIME_LEAD_MAX + v2::RESEAL_MARGIN;
    assert_eq!(queued.reseal_at, queued.sent_time + w::WINDOW_BACK - lead);
    // Alice's node keeps her clock moving.
    for _ in 0..3 {
        world.advance(DAY);
        settle(&mut world);
    }
    assert!(world.env.now.unwrap() >= queued.reseal_at);
    let message: w::Message = w::decode(&queued.message).unwrap();
    let delta = InboxDelta {
        messages: [(ByteArray::new(queued.id.0), message)].into(),
        ..InboxDelta::default()
    };
    world.publish(&a, &w::encode(&delta));
    assert!(
        !w::delivered(&world.state(&a), &queued.id.0),
        "dropped silently"
    );
    let (_, landed) = world.send(&b, &a, "queued");
    assert!(landed, "sealed again");
}

/// Decision 21: strangers keep the newest `STRANGERS_KEPT` drained messages,
/// stored copies and tombstones both. The drain never stops on them, and a
/// contact's message is never what gives way.
#[test]
fn strangers_give_way_earliest_first_and_never_a_contact() {
    let mut world = World::new();
    let a = world.identity("alice");
    let b = world.identity("bob");
    let d = world.identity("dave");
    let pass = world.issue(&a, Some(b), None);
    hold(&mut world, &b, pass);
    world.send(&b, &a, "from a contact");
    let extra = env_or("STRANGER_EXTRA", 40) as usize;
    let total = STRANGERS_KEPT + extra;
    let contact_id = world.state(&a).messages.keys().next().unwrap().into_array();
    let mut dropped = 0;
    let mut ids = Vec::new();
    // The stranger messages each drain took, as `ids` indexes. The first
    // also holds the contact's message, so it takes one stranger fewer.
    let mut batches = Vec::new();
    let mut from = 0;
    for n in 0..total {
        let (sealed, landed) = world.send(&d, &a, &format!("s{n:05}"));
        assert!(landed, "s{n}");
        ids.push(sealed.id.0);
        if world.state(&a).messages.len() >= w::QUARANTINE_SLOTS || n + 1 == total {
            let u = world
                .update(&a, OwnerChange::Drain)
                .expect("the drain goes on");
            assert_eq!(u.full, 0);
            dropped += u.strangers_dropped as usize;
            world.publish(&a, &u.update.unwrap());
            batches.push(from..n + 1);
            from = n + 1;
        }
    }
    assert_eq!(dropped, extra);
    assert_eq!(world.record(&a).strangers_dropped, extra as u64);
    assert!(
        inbound_stored(&world, &a, &contact_id),
        "the contact's message"
    );
    // The earliest drained are the ones gone. A drain takes what one call
    // holds in id order, so the order is kept to the drain: every batch
    // drained wholly before the `extra`th message is gone, and every one
    // drained wholly after it is kept.
    let gone = ids
        .iter()
        .filter(|id| !inbound_stored(&world, &a, id))
        .count();
    assert_eq!(gone, extra);
    assert!(batches.len() > 2);
    for batch in &batches {
        for n in batch.clone() {
            if batch.end <= extra {
                assert!(!inbound_stored(&world, &a, &ids[n]), "s{n} kept");
            }
            if batch.start >= extra {
                assert!(inbound_stored(&world, &a, &ids[n]), "s{n} dropped");
            }
        }
    }
    let state = world.state(&a);
    assert!(state.messages.is_empty());
    assert!(state.owner.tombstones.len() <= STRANGERS_KEPT + 1);
}

/// The Ghost Key proof for a RequireGhost inbox, made with the contract's
/// own fixture certificates: the payload the sender gets back is what the
/// contract checks, and the recipient reads the key it names.
#[test]
fn a_ghost_key_proof_from_the_fixtures_passes_the_contract() {
    let (master, ghosts) = ghost_fixture();
    let mut world = World::with_master(master);
    let a = world.identity("alice");
    let b = world.identity("bob");
    // The same inbox before it asks for a Ghost Key, for the control below.
    let mut open = world.clone();
    world.change(
        &a,
        OwnerChange::SetQuarantine(w::QuarantineMode::RequireGhost { min_usd: Some(5) }),
    );
    let seal = |world: &mut World, ghost: &ed25519_dalek::SigningKey| {
        let ghost_vk = ghost.verifying_key().to_bytes();
        let ui_entropy = world.entropy();
        match call(
            &mut world.env,
            PROD,
            Op::SealV2 {
                from: b,
                to: a,
                to_state: ByteBuf::from(world.inboxes[&a].clone()),
                content: SealContent::Mail(ByteBuf::from(b"proven".to_vec())),
                ghost_vk: Some(Hash32(ghost_vk)),
                ui_entropy,
                reseals: 0,
            },
        ) {
            Ok(Reply::SealedV2(s)) => s,
            other => panic!("{other:?}"),
        }
    };
    let try_land = |world: &mut World, sealed: &freenet_mail_protocol::SealedV2, proof| {
        let mut message: w::Message = w::decode(&sealed.message).unwrap();
        message.admission = w::Admission::Quarantine { ghost: proof };
        let delta = InboxDelta {
            messages: [(ByteArray::new(sealed.id.0), message)].into(),
            ..InboxDelta::default()
        };
        world.publish(&a, &w::encode(&delta));
        w::delivered(&world.state(&a), &sealed.id.0)
    };
    let (usd5_sk, usd5_cert) = ghosts
        .iter()
        .find(|g| g.0 == 5)
        .map(|g| (&g.1, &g.2))
        .unwrap();
    let (usd1_sk, usd1_cert) = ghosts
        .iter()
        .find(|g| g.0 == 1)
        .map(|g| (&g.1, &g.2))
        .unwrap();

    // No proof is filtered for the missing proof, and for nothing else: the
    // message carries its own id (the contract's id of a quarantine message
    // with no proof), so only the proof differs from one an inbox that asks
    // for none accepts.
    let sealed = seal(&mut world, usd5_sk);
    let bare = {
        let m: w::Message = w::decode(&sealed.message).unwrap();
        let ct_hash = *blake3::hash(&m.ciphertext).as_bytes();
        let id = w::message_id(&a.0, &ct_hash, m.sent_time, w::KIND_QUARANTINE, &[]);
        let message = w::Message {
            admission: w::Admission::Quarantine { ghost: None },
            ..m
        };
        InboxDelta {
            messages: [(ByteArray::new(id), message)].into(),
            ..InboxDelta::default()
        }
    };
    let bare_id = *bare.messages.keys().next().unwrap();
    open.publish(&a, &w::encode(&bare));
    assert!(
        w::delivered(&open.state(&a), &bare_id),
        "control: an inbox that asks for no proof takes this message"
    );
    world.publish(&a, &w::encode(&bare));
    assert!(
        !w::delivered(&world.state(&a), &bare_id),
        "a RequireGhost inbox refuses it for the missing proof"
    );
    let wrong = ghost_proof(usd5_sk, usd5_cert, b"not the payload".to_vec());
    assert!(!try_land(&mut world, &sealed, Some(wrong)));
    // A $1 key is below this inbox's tier.
    let low = seal(&mut world, usd1_sk);
    let proof = ghost_proof(
        usd1_sk,
        usd1_cert,
        low.ghost_payload.clone().unwrap().into_vec(),
    );
    assert!(!try_land(&mut world, &low, Some(proof)));
    // The payload the delegate returned, signed by the $5 key, lands.
    let payload = sealed.ghost_payload.clone().expect("a payload to sign");
    let proof = ghost_proof(usd5_sk, usd5_cert, payload.into_vec());
    assert!(try_land(&mut world, &sealed, Some(proof)));
    // A page's state is trusted with a proof only as far as the node holds
    // the same message.
    sync(&mut world);
    world.change(&a, OwnerChange::Drain);
    let got = world.inbound(&a);
    assert_eq!(texts(&got), ["proven"]);
    assert_eq!(
        got[0].ghost_vk.unwrap().into_array(),
        usd5_sk.verifying_key().to_bytes()
    );
    assert_eq!(got[0].admission, w::KIND_QUARANTINE);
}

type Ghost = (u64, ed25519_dalek::SigningKey, Vec<u8>);

/// The contract's fixture: a test master and Ghost Key certificates under it
/// (`contracts/inbox-v2/tests/fixtures/README.md`).
fn ghost_fixture() -> ([u8; 32], Vec<Ghost>) {
    let hex = |s: &str| -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    };
    let text = include_str!("../../../../contracts/inbox-v2/tests/fixtures/ghost-keys.txt");
    let mut master = [0; 32];
    let mut ghosts = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "master_vk" => master.copy_from_slice(&hex(f[1])),
            "cert" => ghosts.push((
                f[1].parse().unwrap(),
                ed25519_dalek::SigningKey::from_bytes(&hex(f[2]).try_into().unwrap()),
                hex(f[3]),
            )),
            other => panic!("fixture line {other}"),
        }
    }
    (master, ghosts)
}

/// What the ghostkey vault returns for `payload`, scoped to the mail app.
fn ghost_proof(sk: &ed25519_dalek::SigningKey, cert: &[u8], payload: Vec<u8>) -> w::GhostProof {
    use ed25519_dalek::Signer as _;
    let scoped = ghostkey_common::to_cbor(&ghostkey_common::ScopedPayload {
        requestor: ghostkey_common::SignatureRequestor::WebApp(ContractInstanceId::new(
            WEBAPP_REQUESTOR,
        )),
        payload,
    })
    .unwrap();
    w::GhostProof {
        cert: ByteBuf::from(cert.to_vec()),
        ghost_sig: ByteArray::new(sk.sign(&scoped).to_bytes()),
        scoped_payload: ByteBuf::from(scoped),
    }
}

/// Key-only restore: on a new node with only the recovery key, the inbox is
/// taken over, its mail drains and it sends. Passes issued before the
/// restore cannot be renewed (the ledger is gone), so they lapse at expiry:
/// the contact falls back to quarantine and gets a new pass once answered.
#[test]
fn a_restored_identity_drains_and_sends_and_old_passes_lapse() {
    let mut world = World::new();
    let ui_entropy = world.entropy();
    let Ok(Reply::CreatedIdentity {
        identity,
        recovery_key,
    }) = call(
        &mut world.env,
        PROD,
        Op::CreateIdentity {
            alias: "alice".into(),
            description: String::new(),
            ui_entropy,
        },
    )
    else {
        panic!("create");
    };
    let a = identity.addr;
    let Ok(Reply::InboxV2State(state)) = call(
        &mut world.env,
        PROD,
        Op::CreateInboxV2 {
            addr: a,
            ghost_master: Hash32(world.master),
            existing: None,
        },
    ) else {
        panic!("inbox");
    };
    world.inboxes.insert(a, state.into_vec());
    // Bob on his own node, which the restore leaves alone.
    let b = world.identity_in("bob", BOB_NODE);
    let old = world.issue(&a, Some(b), None);
    hold(&mut world, &b, old.clone());
    world.send(&b, &a, "before");
    settle(&mut world);

    // A new node: the recovery key and nothing else.
    world.env = MemEnv {
        now: world.env.now,
        contracts: world.env.contracts.clone(),
        secrets: node_of(&world.env, BOB_NODE),
        ..MemEnv::default()
    };
    call(
        &mut world.env,
        PROD,
        Op::ImportIdentity {
            source: ImportSource::RecoveryKey(recovery_key),
            kind: ImportKind::UserRestore,
            alias: "alice".into(),
            description: String::new(),
        },
    )
    .unwrap();
    let Ok(Reply::InboxV2State(taken)) = call(
        &mut world.env,
        PROD,
        Op::CreateInboxV2 {
            addr: a,
            ghost_master: Hash32(world.master),
            existing: Some(ByteBuf::from(world.inboxes[&a].clone())),
        },
    ) else {
        panic!("take over");
    };
    let merged = apply(
        &Rules::V1,
        &world.params(&a),
        &world.inboxes[&a],
        vec![UpdateData::State(
            WrappedState::new(taken.into_vec()).into(),
        )],
    )
    .expect("the contract accepts the taken-over state");
    world.inboxes.insert(a, merged);

    // Bob's old pass still admits, and the restored node drains it.
    let (by_old, landed) = world.send(&b, &a, "to the restored node");
    assert!(landed);
    assert_eq!(by_old.admission, SendAdmission::Pass);
    settle(&mut world);
    assert_eq!(texts(&world.inbound(&a)), ["to the restored node"]);

    // Past the old pass's expiry: quarantine, said plainly.
    while world.env.now.unwrap() <= old.cert.expiry {
        world.advance(7 * DAY);
        settle(&mut world);
    }
    let (lapsed, landed) = world.send(&b, &a, "after expiry");
    assert!(landed);
    assert_eq!(lapsed.notice, Some(SendNotice::PassLapsed));
    assert_eq!(lapsed.admission, SendAdmission::Quarantine);
    settle(&mut world);
    // Alice answers: a new pass rides along, and Bob writes by pass again.
    let (_, landed) = world.send(&a, &b, "welcome back");
    assert!(landed);
    settle(&mut world);
    let (again, landed) = world.send(&b, &a, "by the new pass");
    assert!(landed);
    let w::Admission::Pass { cert, .. } = admission(&again) else {
        panic!("still quarantine");
    };
    assert_ne!(cert.pass_id, old.cert.pass_id);
}

/// The origin standing for Bob's node.
const BOB_NODE: u8 = 2;

/// What one origin's namespace holds: in these tests, one node's store.
fn node_of(env: &MemEnv, origin: u8) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let mut probe = MemEnv::default();
    let prefix = crate::store::Space::new(&mut probe, Origin([origin; 32])).full_key("");
    env.secrets
        .iter()
        .filter(|(k, _)| k.starts_with(&prefix))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// A run's work stays inside the budgets: at most the per-run message slice
/// and inbox count, one update per inbox, and no more than the per-minute
/// writes to one contract.
#[test]
fn a_run_drains_at_most_its_slice_and_writes_within_the_limit() {
    let (mut world, a, mail) = loaded();
    let (done, updates) = run(&mut world, Trigger::Tick(Tick::Rescan));
    let to_a = updates.iter().filter(|(x, _)| *x == a).count();
    assert_eq!(to_a, 1, "one update per inbox a run");
    assert!(done.imported as usize <= crate::jobs::MAX_MESSAGES_PER_RUN);
    settle(&mut world);
    assert_eq!(texts(&world.inbound(&a)).len(), mail.len() + 1);
}

/// No more than `MAX_WRITES_PER_MINUTE` updates to one contract a minute;
/// another contract and the next minute are not held back.
#[test]
fn updates_to_one_contract_stop_at_the_minute_limit() {
    use crate::jobs::{Budget, MAX_WRITES_PER_MINUTE};
    let now = 1_800_000_000;
    let mut b = Budget::new(now);
    for _ in 0..MAX_WRITES_PER_MINUTE {
        assert!(b.may_write(&[1; 32]));
        b.take_write([1; 32]);
    }
    assert!(!b.may_write(&[1; 32]));
    assert!(b.may_write(&[2; 32]));
    b.advance(now + 60);
    assert!(b.may_write(&[1; 32]));
}

/// Alice with `n` messages from Bob waiting in her inbox.
fn with_waiting(n: usize) -> (World, Addr) {
    let mut world = World::new();
    let a = world.identity("alice");
    let b = world.identity("bob");
    for i in 0..n {
        let (_, landed) = world.send(&b, &a, &format!("waiting {i}"));
        assert!(landed);
    }
    (world, a)
}

/// A node-started run drains the message slice less the owner update's share
/// (`OWNER_SLOTS`), and not a message more: 11 of 12 slots go to messages, and
/// what is left waits for the next run, which takes it.
#[test]
fn a_run_drains_exactly_its_slice_less_the_owner_updates_share() {
    // 12 slots to a run, one of them the owner update's.
    let cap = 11;
    for (waiting, imported, left) in [
        (cap - 1, cap - 1, 0),
        (cap, cap, 0),
        (cap + 1, cap, 1),
        (cap + 3, cap, 3),
    ] {
        let (mut world, a) = with_waiting(waiting);
        let (done, _) = run(&mut world, Trigger::Tick(Tick::Rescan));
        assert_eq!(
            (done.imported as usize, done.remaining as usize),
            (imported, left),
            "{waiting} waiting"
        );
        assert_eq!(texts(&world.inbound(&a)).len(), imported);
        let (done, _) = run(&mut world, Trigger::Tick(Tick::Rescan));
        assert_eq!(done.imported as usize, left, "the next run takes the rest");
        assert_eq!(texts(&world.inbound(&a)).len(), waiting);
    }
}

/// What `inbox_jobs::run` does for `trigger` with a budget that has already
/// written to the contracts in `spent` as often as a minute allows (and, with
/// `advance_budget`, a minute later).
fn run_with_spent(
    world: &mut World,
    trigger: Trigger,
    spent: &[[u8; 32]],
    advance_budget: bool,
) -> (JobsRun, Vec<OutboundDelegateMsg>) {
    sync(world);
    let now = world.env.now.unwrap();
    let origin = Origin([PROD; 32]);
    let owns: Vec<_> = world
        .inboxes
        .keys()
        .filter_map(|a| {
            let s = crate::store::Space::new(&mut world.env, origin);
            inbox_jobs::own(&s, a, now).unwrap()
        })
        .collect();
    let mut budget = crate::jobs::Budget::new(now);
    for id in spent {
        for _ in 0..crate::jobs::MAX_WRITES_PER_MINUTE {
            budget.take_write(*id);
        }
    }
    // A minute on, the node's clock and the budget both: the budget starts over.
    let now = if advance_budget {
        world.advance(60);
        budget.advance(now + 60);
        now + 60
    } else {
        now
    };
    let mut left = crate::jobs::MAX_MESSAGES_PER_RUN;
    let mut done = JobsRun::default();
    let d = inbox_jobs::run(&mut world.env, trigger, &owns, &mut budget, now, &mut left, &mut done);
    (done, d.out)
}

/// No more than `MAX_WRITES_PER_MINUTE` updates to one contract a minute, in
/// the jobs themselves: a drain of an inbox written to that often waits for
/// the next minute (and the message stays in the inbox), and so does a
/// renewal to a contact written to that often, which is looked at again in
/// 60 s. Another contract is not held back.
#[test]
fn the_jobs_stop_updating_a_contract_at_the_minute_limit() {
    let (mut world, a) = with_waiting(2);
    let id = id_of(&world, &a);
    let (done, out) = run_with_spent(&mut world, Trigger::Tick(Tick::Rescan), &[id], false);
    assert_eq!((done.imported, out.len()), (0, 0), "a spent contract is not written to");
    assert_eq!(world.state(&a).messages.len(), 2, "the mail waits in the inbox");
    let (done, out) = run_with_spent(&mut world, Trigger::Tick(Tick::Rescan), &[[7; 32]], false);
    assert_eq!((done.imported, out.len()), (2, 1), "another contract's budget is not Alice's");
    // The renewal: Alice reissues Bob's pass; Bob's contract is spent.
    let (mut world, a) = with_waiting(0);
    let c = world.identity_in("carol", 2);
    let pass = world.issue(&a, Some(c), None);
    hold(&mut world, &c, pass);
    world.send(&c, &a, "hi");
    settle(&mut world);
    world.change(&a, OwnerChange::BumpEpoch { emergency: true });
    let now = world.env.now.unwrap();
    let key = ByteArray::new(c.0);
    assert!(world.record(&a).due[&key] <= now, "the reissue is due");
    let spent = id_of(&world, &c);
    let (_, out) = run_with_spent(&mut world, PAGE, &[spent], false);
    assert!(out.is_empty(), "no renewal to a contract written to that often");
    assert_eq!(world.record(&a).due[&key], now + 60, "looked at again in a minute");
    let (_, out) = run_with_spent(&mut world, PAGE, &[spent], true);
    assert_eq!(out.len(), 1, "the next minute it goes");
}

/// Alice with `n` contacts, each holding her pass, after an emergency bump:
/// every reissue is due now, at the times in `due` (by contact order).
fn with_due_contacts(n: usize) -> (World, Addr, Vec<Addr>) {
    let mut world = World::new();
    let a = world.identity("alice");
    let mut contacts: Vec<Addr> = (0..n)
        .map(|i| {
            let c = world.identity_in(&format!("contact{i}"), 2);
            let pass = world.issue(&a, Some(c), None);
            hold(&mut world, &c, pass);
            // Writing once gives Alice the pass a renewal is sent through.
            world.send(&c, &a, "hi");
            c
        })
        .collect();
    contacts.sort_by_key(|c| c.0);
    settle(&mut world);
    world.change(&a, OwnerChange::BumpEpoch { emergency: true });
    (world, a, contacts)
}

/// A run sends at most `RENEW_PER_RUN` renewals however many are due, and the
/// next run sends the next ones: after k runs, 4k.
#[test]
fn a_run_sends_at_most_its_renewals_and_the_next_run_the_next() {
    const PER_RUN: usize = 4;
    let n = PER_RUN * 2 + 1;
    let (mut world, a, contacts) = with_due_contacts(n);
    let mut reached = BTreeSet::new();
    for k in 1..=3 {
        let (_, updates) = run(&mut world, PAGE);
        let sent: usize = contacts.iter().map(|c| messages_to(&updates, c)).sum();
        assert_eq!(
            sent,
            PER_RUN.min(n - reached.len()),
            "run {k}"
        );
        reached.extend(
            contacts
                .iter()
                .filter(|c| messages_to(&updates, c) > 0)
                .copied(),
        );
        assert_eq!(reached.len(), n.min(PER_RUN * k));
    }
    let _ = a;
}

/// A run looks at no more than `RENEW_LOOKS_PER_RUN` contacts, found or not:
/// contacts whose inboxes this node does not hold cost a look each, and the
/// rest wait for the next run.
#[test]
fn a_run_looks_at_no_more_contacts_than_its_looks() {
    const LOOKS: usize = 16;
    let n = LOOKS + 4;
    let mut world = World::new();
    let a = world.identity("alice");
    // Contacts whose inboxes the node does not hold.
    let contacts: Vec<Addr> = (1..=n as u8).map(|i| Addr([i; 24])).collect();
    for c in &contacts {
        world.issue(&a, Some(*c), None);
    }
    world.change(&a, OwnerChange::BumpEpoch { emergency: true });
    let now = world.env.now.unwrap();
    let looked = |world: &mut World| {
        let rec = world.record(&a);
        contacts
            .iter()
            .filter(|c| rec.due[&ByteArray::new(c.0)] > now)
            .count()
    };
    assert_eq!(looked(&mut world), 0, "all due");
    run(&mut world, Trigger::Tick(Tick::Rescan));
    assert_eq!(looked(&mut world), LOOKS, "one look each, and no more");
    run(&mut world, Trigger::Tick(Tick::Rescan));
    assert_eq!(looked(&mut world), n, "the next run looks at the rest");
}

/// Due contacts are taken oldest first, so a contact that has waited longest
/// is not passed over by newer ones however the addresses sort.
#[test]
fn due_contacts_are_served_oldest_first() {
    const PER_RUN: usize = 4;
    let n = PER_RUN + 2;
    let (mut world, a, contacts) = with_due_contacts(n);
    let now = world.env.now.unwrap();
    // The largest address has waited longest, the smallest least.
    {
        let origin = Origin([PROD; 32]);
        let mut s = crate::store::Space::new(&mut world.env, origin);
        let (generation, mut rec) = v2::record(&s, &a).unwrap();
        for (i, c) in contacts.iter().enumerate() {
            rec.due.insert(ByteArray::new(c.0), now - 10 * (i as u64 + 1));
        }
        v2::save(&mut s, v2::item(freenet_mail_protocol::ItemKind::InboxV2, &a, &[]), &rec, generation)
            .unwrap();
    }
    let (_, updates) = run(&mut world, PAGE);
    let served: BTreeSet<Addr> = contacts
        .iter()
        .filter(|c| messages_to(&updates, c) > 0)
        .copied()
        .collect();
    let oldest: BTreeSet<Addr> = contacts
        .iter()
        .rev()
        .take(PER_RUN)
        .copied()
        .collect();
    assert_eq!(served, oldest);
}

/// A host that counts writes, to compare what an import and a drain do.
struct Counting<'a> {
    inner: &'a mut MemEnv,
    writes: u64,
}

impl crate::env::Env for Counting<'_> {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.get(key)
    }
    fn set(&mut self, key: &[u8], value: &[u8]) -> bool {
        self.writes += 1;
        self.inner.set(key, value)
    }
    fn remove(&mut self, key: &[u8]) -> bool {
        self.writes += 1;
        self.inner.remove(key)
    }
    fn host_random(&mut self) -> [u8; 32] {
        self.inner.host_random()
    }
    fn now_secs(&self) -> Option<u64> {
        self.inner.now_secs()
    }
    fn contract_state(&self, id: &[u8; 32]) -> Option<Vec<u8>> {
        self.inner.contract_state(id)
    }
}

/// What a message costs a run, measured against the v1 import whose cost on
/// a real node is `MESSAGE_COST_MS` (120 ms, B4): the same run code, the same
/// host, natively. A v2 drain decrypts with ML-KEM and checks ML-DSA as the
/// import does, and writes more (the stored copy, the reply pass it keeps).
/// Printed as `COST` lines; run with `--release -- --nocapture` for numbers.
/// The test holds the write count, which is deterministic: if a drained
/// message ever writes more than twice what an import does, the per-message
/// estimate the budgets use is no longer an upper bound.
#[test]
fn a_drained_message_costs_about_what_an_import_does() {
    use std::time::Instant;
    const N: usize = 6;
    // v1: N arrivals imported by one page run.
    let mut env = MemEnv {
        now: Some(super::inbox_v2::START),
        ..MemEnv::default()
    };
    let me = super::create(&mut env, PROD, "alice");
    let messages: Vec<Vec<u8>> = (0..N)
        .map(|n| super::jobs::sealed(&me, &format!("m{n}")))
        .collect();
    super::jobs::deliver(&mut env, &me, &messages);
    let mut host = Counting {
        inner: &mut env,
        writes: 0,
    };
    let t = Instant::now();
    let (done, _) = watch::run(&mut host, PAGE);
    let v1 = t.elapsed();
    assert_eq!(done.imported as usize, N);
    let v1_writes = host.writes;
    let empty = {
        let t = Instant::now();
        watch::run(&mut host, PAGE);
        t.elapsed()
    };

    // v2: N arrivals drained by one page run, signed in one owner update.
    let mut world = World::new();
    let a = world.identity("alice");
    let b = world.identity("bob");
    for n in 0..N {
        world.send(&b, &a, &format!("m{n}"));
    }
    sync(&mut world);
    let mut host = Counting {
        inner: &mut world.env,
        writes: 0,
    };
    let t = Instant::now();
    let (done, out) = watch::run(&mut host, PAGE);
    let v2 = t.elapsed();
    assert_eq!(done.imported as usize, N);
    assert!(!out.is_empty());
    let v2_writes = host.writes;

    let per = |d: std::time::Duration| d.as_secs_f64() * 1000.0 / N as f64;
    println!(
        "COST v1 import per message {:.2} ms native, {} writes",
        per(v1),
        v1_writes as f64 / N as f64
    );
    println!(
        "COST v2 drain per message {:.2} ms native, {} writes",
        per(v2),
        v2_writes as f64 / N as f64
    );
    println!("COST an empty run {:.2} ms", empty.as_secs_f64() * 1000.0);
    // Bob's first message makes Alice keep his pass back; later ones change
    // nothing, so per message a drain writes about what an import does.
    assert!(
        v2_writes <= v1_writes,
        "a drain writes {v2_writes} for {N} messages, an import {v1_writes}"
    );

    // One renewal, alone in its run.
    out_updates(&mut world, out);
    let pass = world.issue(&a, Some(b), None);
    hold(&mut world, &b, pass.clone());
    world.send(&b, &a, "for the way back");
    settle(&mut world);
    let e = world.ledger(&a, pass.cert.pass_id.as_slice());
    world.advance(e.renew_at - world.env.now.unwrap() + 1);
    sync(&mut world);
    let mut host = Counting {
        inner: &mut world.env,
        writes: 0,
    };
    let t = Instant::now();
    let (_, out) = watch::run(&mut host, Trigger::Tick(Tick::Renew));
    let renew = t.elapsed();
    // Bob's pass back to Alice may fall due in the same run.
    let sent = out.len() as u64;
    assert!(sent >= 1, "a renewal sent");
    let renew_writes = host.writes / sent;
    println!(
        "COST a renewal {:.2} ms native, {renew_writes} writes",
        renew.as_secs_f64() * 1000.0 / sent as f64
    );
    // Two messages' worth.
    assert!(
        renew_writes * N as u64 <= 2 * v1_writes,
        "a renewal writes {renew_writes}, an import {} a message",
        v1_writes / N as u64
    );
}

/// Apply what a run sent, as `run` does.
fn out_updates(world: &mut World, out: Vec<OutboundDelegateMsg>) -> Vec<(Addr, InboxDelta)> {
    let mut updates = Vec::new();
    for m in out {
        if let OutboundDelegateMsg::UpdateContractRequest(r) = m {
            let id: [u8; 32] = r.contract_id.as_bytes().try_into().unwrap();
            let addr = *world
                .inboxes
                .keys()
                .find(|a| id_of(world, a) == id)
                .unwrap();
            let UpdateData::Delta(d) = r.update else {
                panic!("a job sends deltas");
            };
            world.publish(&addr, d.as_ref());
            updates.push((addr, w::decode(d.as_ref()).unwrap()));
        }
    }
    sync(world);
    updates
}

/// The issuer and pass keys must sign exactly as the contract verifies:
/// the delegate's own lockfile, which `build-wasm.sh` builds with
/// `--locked`, holds the contract's ed25519-dalek and no other. (The manifest
/// cannot say `=2.2.0`: the UI's workspace links this crate beside the
/// frozen container's `=2.1.1`, and two of one crate's semver-compatible
/// versions cannot be in one graph.)
#[test]
fn the_shipped_build_links_the_contracts_ed25519_dalek() {
    let lock = include_str!("../../Cargo.lock");
    let contract = include_str!("../../../../contracts/inbox-v2/Cargo.toml");
    assert!(contract.contains(r#"ed25519-dalek = { version = "=2.2.0""#));
    let versions: Vec<&str> = lock
        .split("[[package]]")
        .filter(|p| p.contains("name = \"ed25519-dalek\"\n"))
        .filter_map(|p| p.lines().find_map(|l| l.strip_prefix("version = ")))
        .collect();
    assert_eq!(versions, ["\"2.2.0\""]);
}

// ── Review round 2: drain, renewal and caps ─────────────────────────────────

/// Renewals Alice sends to `h` while contact `p` (sorting first) has revoked
/// her pass and turned on RequireGhost (`poison`), or not.
fn renewals_to_healthy(poison: bool) -> (usize, World, Addr, Addr) {
    let mut world = World::new();
    let a = world.identity("alice");
    let x = world.identity("xavier");
    let y = world.identity("yolanda");
    let (p, h) = if x.0 < y.0 { (x, y) } else { (y, x) };
    for c in [p, h] {
        let pass = world.issue(&a, Some(c), None);
        hold(&mut world, &c, pass);
        let (_, landed) = world.send(&c, &a, "hi");
        assert!(landed);
    }
    settle(&mut world);
    if poison {
        let mine = world.record(&p).issued[&ByteArray::new(a.0)];
        world.change(
            &p,
            OwnerChange::Revoke {
                pass_id: freenet_mail_protocol::PassId(mine.into_array()),
            },
        );
        world.change(
            &p,
            OwnerChange::SetQuarantine(w::QuarantineMode::RequireGhost { min_usd: None }),
        );
    }
    let rec = world.record(&a);
    let latest = rec
        .issued
        .values()
        .map(|id| world.clone().ledger(&a, id.as_slice()).renew_at)
        .max()
        .unwrap();
    world.advance(latest - world.env.now.unwrap() + 1);
    let mut to_h = 0;
    for _ in 0..8 {
        let (_, updates) = run(&mut world, Trigger::Tick(Tick::Renew));
        to_h += messages_to(&updates, &h);
        world.advance(7 * 3600);
    }
    (to_h, world, a, p)
}

/// One contact whose renewal cannot be sent (it revoked our pass and asks
/// for a Ghost Key) never stops the renewals of the contacts after it.
#[test]
fn a_contact_whose_renewal_fails_never_stops_the_others() {
    let (control, ..) = renewals_to_healthy(false);
    assert!(control >= 1, "control: the healthy contact is renewed");
    let (poisoned, mut world, a, p) = renewals_to_healthy(true);
    assert_eq!(
        poisoned, control,
        "the healthy contact is renewed all the same"
    );
    // The failing contact is looked at on the first run, and again on the
    // first run a full day later (the 5th, 28 hours on), each time asking
    // again in exactly a day: not every run, and not on the shorter backoff
    // of a contact that cannot be found.
    let due = world.record(&a).due[&ByteArray::new(p.0)];
    let started = world.env.now.unwrap() - 8 * 7 * 3600;
    assert_eq!(due, started + 4 * 7 * 3600 + DAY);
}

/// A message stored once counts as stored whatever path stored it: a page's
/// drain the node could not confirm, whose update was lost, never holds the
/// inbox for good. The stored copy is the same whichever drain stores it.
#[test]
fn a_message_stored_by_a_lost_drain_is_drained_again() {
    let (master, ghosts) = ghost_fixture();
    let mut world = World::with_master(master);
    let a = world.identity("alice");
    let b = world.identity("bob");
    world.change(
        &a,
        OwnerChange::SetQuarantine(w::QuarantineMode::RequireGhost { min_usd: Some(5) }),
    );
    let (sk, cert) = ghosts
        .iter()
        .find(|g| g.0 == 5)
        .map(|g| (&g.1, &g.2))
        .unwrap();
    let ui_entropy = world.entropy();
    let Ok(Reply::SealedV2(sealed)) = call(
        &mut world.env,
        PROD,
        Op::SealV2 {
            from: b,
            to: a,
            to_state: ByteBuf::from(world.inboxes[&a].clone()),
            content: SealContent::Mail(ByteBuf::from(b"proven".to_vec())),
            ghost_vk: Some(Hash32(sk.verifying_key().to_bytes())),
            ui_entropy,
            reseals: 0,
        },
    ) else {
        panic!()
    };
    let mut message: w::Message = w::decode(&sealed.message).unwrap();
    message.admission = w::Admission::Quarantine {
        ghost: Some(ghost_proof(
            sk,
            cert,
            sealed.ghost_payload.clone().unwrap().into_vec(),
        )),
    };
    let delta = InboxDelta {
        messages: [(ByteArray::new(sealed.id.0), message)].into(),
        ..InboxDelta::default()
    };
    world.publish(&a, &w::encode(&delta));
    // The page drains before this node holds the inbox; its update is lost.
    assert!(world.env.contracts.is_empty());
    let _lost = world.update(&a, OwnerChange::Drain).expect("page drain");
    // The node's drain stores it and tombstones it.
    let (_, updates) = run(&mut world, PAGE);
    let (_, d) = updates.iter().find(|(to, _)| *to == a).expect("an update");
    let owner = d.owner.as_ref().expect("tombstones");
    assert!(owner.tombstones.contains_key(&ByteArray::new(sealed.id.0)));
    assert!(world.state(&a).messages.is_empty());
    let got = world.inbound(&a);
    assert_eq!(texts(&got), ["proven"]);
    assert_eq!(
        got[0].ghost_vk.unwrap().into_array(),
        sk.verifying_key().to_bytes(),
        "the proof the contract checked"
    );
    world.change(&a, OwnerChange::AdvanceTime);
}

/// Mail is a contact's by its sender, whatever the admission, and a contact's
/// mail is never counted in or evicted by the stranger budget.
#[test]
fn a_contacts_quarantine_mail_is_never_evicted_as_a_strangers() {
    let mut world = World::new();
    let a = world.identity("alice");
    let b = world.identity("bob");
    let d = world.identity("dave");
    // Alice wrote to Bob (he is in her `issued`), but Bob holds no pass of
    // hers that admits: he writes by quarantine.
    world.issue(&a, Some(b), None);
    let (from_bob, landed) = world.send(&b, &a, "from a contact");
    assert!(landed);
    assert_eq!(from_bob.admission, SendAdmission::Quarantine);
    world.change(&a, OwnerChange::Drain);
    assert!(inbound_stored(&world, &a, &from_bob.id.0));
    for n in 0..STRANGERS_KEPT + 16 {
        let (_, landed) = world.send(&d, &a, &format!("s{n:05}"));
        assert!(landed);
        if world.state(&a).messages.len() >= w::QUARANTINE_SLOTS {
            world.change(&a, OwnerChange::Drain);
        }
    }
    world.change(&a, OwnerChange::Drain);
    assert!(
        inbound_stored(&world, &a, &from_bob.id.0),
        "the contact's message"
    );
}

/// Invites have their own cap, so they never fill the ledger: a new
/// correspondent still gets a pass when every invite slot is taken.
#[test]
fn invites_never_fill_the_pass_ledger() {
    let mut world = World::new();
    let a = world.identity("alice");
    let mut refused = 0;
    for _ in 0..crate::store::MAX_MESSAGES {
        let ui_entropy = world.entropy();
        match world.call_as(
            &a,
            Op::IssuePass {
                addr: a,
                contact: None,
                invite: Some(1),
                ui_entropy,
            },
        ) {
            Ok(_) => {}
            Err(freenet_mail_protocol::FailureCode::CapReached) => refused += 1,
            other => panic!("{other:?}"),
        }
    }
    assert!(refused > 0, "the invite cap is surfaced");
    let e = world.identity("erin");
    world
        .seal(&a, &e, "hello erin")
        .expect("a new correspondent");
}

/// Whether `id` counts against Alice's stranger budget.
fn in_stranger_budget(world: &mut World, a: &Addr, id: &[u8; 32]) -> bool {
    world
        .record(a)
        .strangers
        .values()
        .any(|(s, _)| s.into_array() == *id)
}

/// A contact's mail through quarantine is not stranger mail: after its pass
/// lapsed, after a revoke and re-add, and after an emergency bump. A
/// stranger's mail leaves the budget once the user writes back.
#[test]
fn contact_mail_is_never_in_the_stranger_budget() {
    let mut world = World::new();
    let a = world.identity("alice");
    let [b, c, d, e] = ["bob", "carol", "dave", "erin"].map(|n| world.identity(n));
    for x in [b, c, d] {
        let pass = world.issue(&a, Some(x), None);
        hold(&mut world, &x, pass);
    }
    // Carol's pass lapses: Alice's clock stays, the sender's runs past it.
    let mut at_carol = world.clone();
    at_carol.advance(400 * DAY);
    let (lapsed, landed) = at_carol.send(&c, &a, "lapsed");
    assert!(landed);
    assert_eq!(lapsed.admission, SendAdmission::Quarantine);
    at_carol.change(&a, OwnerChange::Drain);
    assert!(inbound_stored(&at_carol, &a, &lapsed.id.0));
    assert!(
        !in_stranger_budget(&mut at_carol, &a, &lapsed.id.0),
        "lapsed"
    );
    // Dave's pass is revoked and a new one issued he does not hold yet.
    let old = world.record(&a).issued[&ByteArray::new(d.0)];
    world.change(
        &a,
        OwnerChange::Revoke {
            pass_id: freenet_mail_protocol::PassId(old.into_array()),
        },
    );
    world.issue(&a, Some(d), None);
    let (readded, _) = world.send(&d, &a, "re-added");
    assert_eq!(readded.admission, SendAdmission::Quarantine);
    world.change(&a, OwnerChange::Drain);
    assert!(!in_stranger_budget(&mut world, &a, &readded.id.0), "re-add");
    // An emergency bump: Bob's held pass is of the old epoch.
    world.change(&a, OwnerChange::BumpEpoch { emergency: true });
    let (bumped, _) = world.send(&b, &a, "after the bump");
    assert_eq!(bumped.admission, SendAdmission::Quarantine);
    world.change(&a, OwnerChange::Drain);
    assert!(!in_stranger_budget(&mut world, &a, &bumped.id.0), "bump");
    // Erin is a stranger until Alice writes back.
    let (hello, _) = world.send(&e, &a, "hello");
    world.change(&a, OwnerChange::Drain);
    assert!(in_stranger_budget(&mut world, &a, &hello.id.0));
    world.seal(&a, &e, "hello erin").unwrap();
    assert!(!in_stranger_budget(&mut world, &a, &hello.id.0), "replied");
}

/// A page's older state never signs an owner version without the
/// tombstones a job already published, and never brings back a message the
/// user deleted after the job drained it.
#[test]
fn a_stale_page_state_keeps_what_a_job_tombstoned() {
    let mut world = World::new();
    let a = world.identity("alice");
    let b = world.identity("bob");
    let (sealed, _) = world.send(&b, &a, "drained by the node");
    let stale = world.inboxes[&a].clone();
    let (_, updates) = run(&mut world, Trigger::Tick(Tick::Rescan));
    assert!(messages_to(&updates, &a) == 0 && !updates.is_empty());
    let id = ByteArray::new(sealed.id.0);
    assert!(world.state(&a).owner.tombstones.contains_key(&id));
    // The user deletes it; the page still holds the state from before the
    // job's update.
    assert!(inbound_stored(&world, &a, &sealed.id.0));
    let item = freenet_mail_protocol::ItemRef {
        kind: freenet_mail_protocol::ItemKind::Inbound,
        owner: Some(a),
        id: sealed.id.0.to_vec(),
    };
    let Ok(Reply::Item(Some(stored))) = world.call_as(&a, Op::GetItem { item: item.clone() })
    else {
        panic!("the stored copy");
    };
    let expected_gen = stored.generation;
    world
        .call_as(&a, Op::DeleteItem { item, expected_gen })
        .unwrap();
    world.inboxes.insert(a, stale.clone());
    let u = world
        .update(
            &a,
            OwnerChange::SetQuarantine(w::QuarantineMode::RequireGhost { min_usd: None }),
        )
        .unwrap();
    assert_eq!(u.change, ChangeOutcome::Signed);
    let delta: InboxDelta = w::decode(&u.update.unwrap()).unwrap();
    assert!(delta.owner.unwrap().tombstones.contains_key(&id));
    assert!(
        !inbound_stored(&world, &a, &sealed.id.0),
        "not brought back"
    );
}

/// Full storage blocks only what would drop the mail it could not store:
/// the message stays untombstoned, a revoke of another pass is signed, and a
/// revoke of the pass that carried it waits, and says why.
#[test]
fn full_storage_blocks_only_the_changes_that_drop_unstored_mail() {
    let mut world = World::new();
    let a = world.identity("alice");
    let [b, c] = ["bob", "carol"].map(|n| world.identity(n));
    let mut passes = Vec::new();
    for x in [b, c] {
        let pass = world.issue(&a, Some(x), None);
        hold(&mut world, &x, pass.clone());
        passes.push(pass.cert.pass_id);
    }
    let (from_bob, _) = world.send(&b, &a, "unstored");
    world.env.fail_keys_containing = Some("it/in/".into());
    let revoke = |p: w::B16| OwnerChange::Revoke {
        pass_id: freenet_mail_protocol::PassId(p.into_array()),
    };
    let u = world.update(&a, revoke(passes[1])).unwrap();
    assert_eq!((u.change, u.full), (ChangeOutcome::Signed, 1));
    let delta: InboxDelta = w::decode(u.update.as_ref().unwrap()).unwrap();
    assert!(delta.revoked.contains_key(&passes[1]));
    let unstored = ByteArray::new(from_bob.id.0);
    assert!(
        delta
            .owner
            .is_none_or(|o| !o.tombstones.contains_key(&unstored))
    );
    world.publish(&a, &u.update.unwrap());
    let u = world.update(&a, revoke(passes[0])).unwrap();
    assert_eq!(u.change, ChangeOutcome::WaitsForStorage);
    assert!(u.update.is_none());
    assert!(w::delivered(&world.state(&a), &from_bob.id.0));
    world.env.fail_keys_containing = None;
    world.change(&a, revoke(passes[0]));
    assert!(inbound_stored(&world, &a, &from_bob.id.0));
    assert!(world.state(&a).revoked.contains_key(&passes[0]));
}

/// The ledger is pruned as time moves: a revoked pass goes once its
/// revocation is pruned (here by an emergency bump), and an invite past its
/// expiry and the window frees its slot.
#[test]
fn the_ledger_is_pruned_as_time_moves() {
    let mut world = World::new();
    let a = world.identity("alice");
    let b = world.identity("bob");
    let pass = world.issue(&a, Some(b), None);
    let invite = world.issue(&a, None, Some(1));
    world.change(
        &a,
        OwnerChange::Revoke {
            pass_id: freenet_mail_protocol::PassId(pass.cert.pass_id.into_array()),
        },
    );
    world.change(&a, OwnerChange::BumpEpoch { emergency: true });
    world.advance(20 * DAY);
    settle(&mut world);
    let gone = |world: &mut World, id: &w::B16| {
        world.call_as(
            &a,
            Op::GetItem {
                item: freenet_mail_protocol::ItemRef {
                    kind: freenet_mail_protocol::ItemKind::PassLedger,
                    owner: Some(a),
                    id: id.to_vec(),
                },
            },
        ) == Ok(Reply::Item(None))
    };
    assert!(
        gone(&mut world, &pass.cert.pass_id),
        "revoked, revocation pruned"
    );
    assert!(
        gone(&mut world, &invite.cert.pass_id),
        "invite past its window"
    );
    assert!(world.record(&a).invites.is_empty());
}

/// The clock moves with no message slice left and on the rescan, as far as
/// keeps every undrained message, and the rotation moves past an inbox only
/// once it is served.
#[test]
fn the_clock_runs_on_rescan_whatever_the_slice() {
    let mut world = World::new();
    let a = world.identity("alice");
    let d = world.identity("dave");
    for n in 0..w::QUARANTINE_SLOTS {
        world.send(&d, &a, &format!("flood {n}"));
    }
    world.advance(DAY);
    let before = world.state(&a).time.owner_time;
    let (_, updates) = run(&mut world, Trigger::Tick(Tick::Rescan));
    assert!(updates.iter().any(|(to, _)| *to == a));
    let after = world.state(&a).time.owner_time;
    assert!(after > before, "the clock moved with mail still pending");
    for m in world.state(&a).messages.values() {
        assert!(m.sent_time + w::WINDOW_BACK >= after, "nothing dropped");
    }
}

/// A contact whose inbox is not held here is looked at again later and
/// later, doubling to a day, rather than every hour.
#[test]
fn a_vanished_contact_backs_off() {
    let mut world = World::new();
    let a = world.identity("alice");
    let b = world.identity("bob");
    let pass = world.issue(&a, Some(b), None);
    hold(&mut world, &b, pass.clone());
    world.send(&b, &a, "hello");
    settle(&mut world);
    let e = world.ledger(&a, pass.cert.pass_id.as_slice());
    world.advance(e.renew_at - world.env.now.unwrap() + 1);
    let mut waits = Vec::new();
    for _ in 0..8 {
        world.inboxes.remove(&b);
        world.env.contracts.clear();
        sync(&mut world);
        let now = world.env.now.unwrap();
        let _ = watch::run(&mut world.env, Trigger::Tick(Tick::Renew));
        let due = world.record(&a).due[&ByteArray::new(b.0)];
        waits.push(due - now);
        world.advance(due - now);
    }
    assert_eq!(
        waits,
        [1, 2, 4, 8, 16, 24, 24, 24].map(|h| h * 3600),
        "doubling to a day"
    );
}

/// A look that finds the contact's inbox starts the backoff over: after it,
/// the contact that vanishes again is asked about in an hour, not at the
/// delay it had reached.
#[test]
fn a_contact_that_comes_back_starts_the_backoff_over() {
    let mut world = World::new();
    let a = world.identity("alice");
    let b = world.identity("bob");
    let pass = world.issue(&a, Some(b), None);
    hold(&mut world, &b, pass.clone());
    world.send(&b, &a, "hello");
    settle(&mut world);
    let id = pass.cert.pass_id;
    let e = world.ledger(&a, id.as_slice());
    world.advance(e.renew_at - world.env.now.unwrap() + 1);
    let held = world.inboxes[&b].clone();
    let key = ByteArray::new(b.0);
    for expected in 1..=3 {
        world.inboxes.remove(&b);
        world.env.contracts.clear();
        sync(&mut world);
        let _ = watch::run(&mut world.env, Trigger::Tick(Tick::Renew));
        assert_eq!(world.ledger(&a, id.as_slice()).misses, expected);
        let due = world.record(&a).due[&key];
        world.advance(due - world.env.now.unwrap());
    }
    // Back: found, and the count starts over.
    world.inboxes.insert(b, held);
    sync(&mut world);
    let _ = watch::run(&mut world.env, Trigger::Tick(Tick::Renew));
    assert_eq!(world.ledger(&a, id.as_slice()).misses, 0);
    // Gone again: the first wait, not the fourth.
    world.advance(7 * 3600);
    world.inboxes.remove(&b);
    world.env.contracts.clear();
    sync(&mut world);
    let now = world.env.now.unwrap();
    let _ = watch::run(&mut world.env, Trigger::Tick(Tick::Renew));
    assert_eq!(world.ledger(&a, id.as_slice()).misses, 1);
    assert_eq!(world.record(&a).due[&key] - now, 3600);
}

/// Renewal throughput comes from the duty budget: after an emergency bump,
/// every contact is reissued within a day of node runs.
#[test]
fn renewals_after_a_bump_keep_pace_with_the_budget() {
    let mut world = World::new();
    let a = world.identity("alice");
    let n = env_or("RENEW_CONTACTS", 24) as usize;
    let mut contacts = Vec::new();
    for i in 0..n {
        // Sixteen identities a store: the contacts live on other nodes.
        let c = world.identity_in(&format!("c{i}"), 2 + (i / 15) as u8);
        let pass = world.issue(&a, Some(c), None);
        hold(&mut world, &c, pass);
        world.send(&c, &a, "hi");
        contacts.push(c);
    }
    settle(&mut world);
    world.change(&a, OwnerChange::BumpEpoch { emergency: true });
    let mut reached = BTreeSet::new();
    // A day of rescans, the node's runs only.
    for _ in 0..96 {
        world.advance(900);
        let (_, updates) = run(&mut world, Trigger::Tick(Tick::Rescan));
        for c in &contacts {
            if messages_to(&updates, c) > 0 {
                reached.insert(*c);
            }
        }
    }
    assert_eq!(reached.len(), n, "every contact within a day");
}

/// `reseal_at` keeps a margin, is never at once for a recipient whose clock
/// trails, and a message is resealed a bounded number of times.
#[test]
fn reseal_has_a_margin_and_a_limit() {
    let mut world = World::new();
    let a = world.identity("alice");
    let b = world.identity("bob");
    // Alice's clock trails by five days.
    world.advance(5 * DAY);
    let sealed = world.seal(&b, &a, "to a stale clock").unwrap();
    let now = world.env.now.unwrap();
    assert!(sealed.reseal_at >= now + v2::RESEAL_MARGIN);
    let ui_entropy = world.entropy();
    let refused = world.call_as(
        &b,
        Op::SealV2 {
            from: b,
            to: a,
            to_state: ByteBuf::from(world.inboxes[&a].clone()),
            content: SealContent::Mail(ByteBuf::from(b"again".to_vec())),
            ghost_vk: None,
            ui_entropy,
            reseals: freenet_mail_protocol::MAX_RESEALS + 1,
        },
    );
    assert_eq!(refused, Err(freenet_mail_protocol::FailureCode::Refused));
}

/// A contact whose renewal fails on a host error, not a refusal, is caught
/// the same way: the others are renewed and it gets its own retry time.
#[test]
fn a_contact_whose_renewal_errors_never_stops_the_others() {
    let (control, ..) = renewals_to_healthy(false);
    let mut world = World::new();
    let a = world.identity("alice");
    let x = world.identity("xavier");
    let y = world.identity("yolanda");
    let (p, h) = if x.0 < y.0 { (x, y) } else { (y, x) };
    for c in [p, h] {
        let pass = world.issue(&a, Some(c), None);
        hold(&mut world, &c, pass);
        world.send(&c, &a, "hi");
    }
    settle(&mut world);
    let rec = world.record(&a);
    let latest = rec
        .issued
        .values()
        .map(|id| world.clone().ledger(&a, id.as_slice()).renew_at)
        .max()
        .unwrap();
    world.advance(latest - world.env.now.unwrap() + 1);
    // Every write of Alice's pass for P fails.
    let to_p = rec.issued[&ByteArray::new(p.0)];
    world.env.fail_keys_containing = Some(crate::store::hex(to_p.as_slice()));
    let mut to_h = 0;
    let mut unknown = 0;
    for _ in 0..8 {
        let (done, updates) = run(&mut world, Trigger::Tick(Tick::Renew));
        to_h += messages_to(&updates, &h);
        unknown += done.unknown;
        world.advance(7 * 3600);
    }
    assert_eq!(to_h, control, "the healthy contact is renewed all the same");
    assert!(unknown > 0, "the failure is counted");
}

/// A stored copy already under a message's id, whatever its bytes, counts
/// as that message stored: the drain tombstones it and goes on.
#[test]
fn a_copy_already_stored_under_the_id_counts_as_stored() {
    let mut world = World::new();
    let a = world.identity("alice");
    let b = world.identity("bob");
    let (sealed, _) = world.send(&b, &a, "the message");
    world.send(&b, &a, "another");
    let item = freenet_mail_protocol::ItemRef {
        kind: freenet_mail_protocol::ItemKind::Inbound,
        owner: Some(a),
        id: sealed.id.0.to_vec(),
    };
    let mut s = crate::store::Space::new(&mut world.env, Origin([PROD; 32]));
    crate::handlers::put_item(&mut s, item, b"an earlier copy".to_vec(), None).unwrap();
    let u = world
        .update(&a, OwnerChange::Drain)
        .expect("the drain goes on");
    assert_eq!((u.drained, u.full), (2, 0));
    world.publish(&a, &u.update.unwrap());
    assert!(world.state(&a).messages.is_empty());
}

/// The rotation moves past an inbox only once it is served: an inbox the
/// slice did not reach is the next run's first, however busy the other.
#[test]
fn an_inbox_the_slice_did_not_reach_comes_first_next_run() {
    let mut world = World::new();
    let a = world.identity("alice");
    let b = world.identity("bob");
    let d = world.identity("dave");
    for to in [a, b] {
        for n in 0..w::QUARANTINE_SLOTS {
            world.send(&d, &to, &format!("to {n}"));
        }
    }
    let left = |world: &World, x: &Addr| world.state(x).messages.len();
    run(&mut world, PAGE);
    let (first, second) = if left(&world, &a) < left(&world, &b) {
        (a, b)
    } else {
        (b, a)
    };
    assert_eq!(
        left(&world, &second),
        w::QUARANTINE_SLOTS,
        "the slice ran out"
    );
    // The first fills up again; the second still comes first.
    for n in 0..w::QUARANTINE_SLOTS {
        world.send(&d, &first, &format!("again {n}"));
    }
    run(&mut world, PAGE);
    assert!(left(&world, &second) < w::QUARANTINE_SLOTS, "reached");
}
