//! The inbox v2 jobs, end to end through the merged contract: what a run
//! sends is applied with the contract's own merge, and the node's store (the
//! `MemEnv` contracts) holds what the network holds.

use std::collections::{BTreeMap, BTreeSet};

use freenet_email_inbox_v2::apply;
use freenet_email_inbox_v2::merge::{Rules, WEBAPP_REQUESTOR};
use freenet_mail_protocol::inbox_v2::{self as w, InboxDelta};
use freenet_mail_protocol::{
    Addr, Hash32, ImportKind, ImportSource, JobsRun, Op, OwnerChange, Reply, SealContent,
    SendAdmission, SendNotice,
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

/// The clock job drains first and signs the new time in the same update; a
/// message that cannot be stored holds the time back.
#[test]
fn the_clock_advances_owner_time_after_draining() {
    let mut world = World::new();
    let a = world.identity("alice");
    let b = world.identity("bob");
    let start = world.state(&a).time.owner_time;
    let (sealed, _) = world.send(&b, &a, "before the tick");
    // Still inside the window after the new time, so it needs its tombstone.
    world.advance(DAY);

    // Storage refuses: nothing is signed, the message stays.
    world.env.fail_keys_containing = Some("it/in/".into());
    let (_, updates) = run(&mut world, Trigger::Tick(Tick::Clock));
    assert!(updates.iter().all(|(addr, _)| *addr != a));
    assert_eq!(world.state(&a).time.owner_time, start);
    assert!(world.state(&a).messages.len() == 1);
    world.env.fail_keys_containing = None;

    let (_, updates) = run(&mut world, Trigger::Tick(Tick::Clock));
    let (_, delta) = updates.iter().find(|(addr, _)| *addr == a).unwrap();
    let owner = delta.owner.as_ref().expect("the tombstone");
    assert!(owner.tombstones.contains_key(&ByteArray::new(sealed.id.0)));
    let now = world.env.now.unwrap();
    assert_eq!(
        delta.time.as_ref().unwrap().owner_time,
        now,
        "the guard allows it"
    );
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
    assert_eq!(queued.reseal_at, queued.sent_time + w::WINDOW_BACK);
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
        }
    }
    assert_eq!(dropped, extra);
    assert_eq!(world.record(&a).strangers_dropped, extra as u64);
    assert!(
        inbound_stored(&world, &a, &contact_id),
        "the contact's message"
    );
    // The earliest drained are the ones gone. A drain takes what one call
    // holds in id order, so the order is kept to the batch of 16.
    let batch = w::QUARANTINE_SLOTS;
    let gone = ids
        .iter()
        .filter(|id| !inbound_stored(&world, &a, id))
        .count();
    assert_eq!(gone, extra);
    for (n, id) in ids.iter().enumerate() {
        if n < extra / batch * batch {
            assert!(!inbound_stored(&world, &a, id), "s{n} kept");
        }
        if n >= extra.div_ceil(batch) * batch {
            assert!(inbound_stored(&world, &a, id), "s{n} dropped");
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

    // No proof, and a proof over other bytes, are filtered.
    let sealed = seal(&mut world, usd5_sk);
    assert!(!try_land(&mut world, &sealed, None));
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
    // RENEW_SLOTS messages' worth.
    assert!(
        renew_writes * N as u64 <= inbox_jobs::RENEW_SLOTS as u64 * v1_writes,
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
