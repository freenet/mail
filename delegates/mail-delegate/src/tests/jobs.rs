//! The background jobs: the pure planner, and the v1 watch through the
//! delegate's entry point.
//!
//! Offline: `MemEnv` stands in for the node's store, so these prove what the
//! delegate does with each thing the node can hand it, not that a real node
//! hands it over.

use freenet_mail_protocol::JobsRun;
use freenet_mail_wire_v1::local_state::KeptMessage;
use freenet_stdlib::prelude::{
    Capability, ContractNotification, DelegateManifest, GetContractResponse, LifecycleEvent,
    LifecycleKind, SubscribeContractResponse, WrappedState,
};

use super::*;
use crate::crypto::{self, Keys, MixRng};
use crate::env::Env;
use crate::env::mem::{FaultOp, Faults, Rule};
use crate::handlers::{load_identity, v1_inbox_id};
use crate::jobs::*;
use crate::store::{index_marker_rel, index_rel, item_rel, seen_rel};
use crate::watch::{self, GLOBAL, message_id};

const NOW: u64 = 1_800_000_000;

fn env() -> MemEnv {
    MemEnv {
        now: Some(NOW),
        ..MemEnv::default()
    }
}

/// A v1 message to `to`, signed by a sender, as v0.2.x writes it.
pub(super) fn sealed(to: &IdentityInfo, title: &str) -> Vec<u8> {
    let plaintext = serde_json::json!({
        "title": title,
        "content": format!("body of {title}"),
        "from": "bob",
        "to": [],
        "cc": [],
        "time": "2026-11-02T10:00:00Z",
    });
    sealed_plain(to, title, plaintext)
}

/// As [`sealed`], with the plaintext given.
fn sealed_plain(to: &IdentityInfo, title: &str, plaintext: serde_json::Value) -> Vec<u8> {
    let sender = Keys::from_seeds(&DsaSeed([9; 32]), &KemSeed([8; 64]));
    let entropy = Entropy(*blake3::hash(title.as_bytes()).as_bytes());
    let mut rng = MixRng::new("test", &[7; 32], &entropy);
    let ek = crypto::decode_ek(&to.ek).unwrap();
    let content = crypto::encrypt_v1(&ek, &serde_json::to_vec(&plaintext).unwrap(), &mut rng);
    let signature = sender.sign(&content);
    serde_json::to_vec(&serde_json::json!({
        "content": content,
        "sender_vk": sender.vk_bytes(),
        "signature": signature,
    }))
    .unwrap()
}

pub(super) fn inbox_of(messages: &[Vec<u8>]) -> Vec<u8> {
    let messages: Vec<serde_json::Value> = messages
        .iter()
        .map(|m| serde_json::from_slice(m).unwrap())
        .collect();
    serde_json::to_vec(&serde_json::json!({ "messages": messages })).unwrap()
}

pub(super) fn id_of(message: &[u8]) -> [u8; 16] {
    let v: serde_json::Value = serde_json::from_slice(message).unwrap();
    let content: Vec<u8> = serde_json::from_value(v["content"].clone()).unwrap();
    message_id(&content)
}

fn deliver(env: &mut MemEnv, to: &IdentityInfo, messages: &[Vec<u8>]) {
    env.contracts
        .insert(v1_inbox_id(&to.vk).unwrap(), inbox_of(messages));
}

fn wake(env: &mut MemEnv, tag: &str) -> Vec<OutboundDelegateMsg> {
    process(
        env,
        None,
        InboundDelegateMsg::WakeupFired {
            tag: tag.as_bytes().to_vec(),
        },
    )
    .unwrap()
}

fn node_started() -> InboundDelegateMsg<'static> {
    InboundDelegateMsg::Lifecycle(LifecycleEvent::NodeStarted {
        down_since_ms: None,
    })
}

fn run_jobs(env: &mut MemEnv, origin: u8) -> JobsRun {
    let out = send(env, app(origin), Op::RunJobs);
    match responses(&out).pop().expect("a response").result {
        Ok(Reply::JobsRun(run)) => run,
        other => panic!("{other:?}"),
    }
}

fn notification(id: [u8; 32], state: Vec<u8>) -> InboundDelegateMsg<'static> {
    InboundDelegateMsg::ContractNotification(ContractNotification {
        contract_id: ContractInstanceId::new(id),
        new_state: WrappedState::new(state),
        context: DelegateContext::default(),
    })
}

fn get_answer(id: [u8; 32], state: Option<Vec<u8>>) -> InboundDelegateMsg<'static> {
    InboundDelegateMsg::GetContractResponse(GetContractResponse {
        contract_id: ContractInstanceId::new(id),
        state: state.map(WrappedState::new),
        context: DelegateContext::default(),
    })
}

fn kept_ids(env: &mut MemEnv, owner: Addr) -> Vec<Vec<u8>> {
    list_ids(env, PROD, ItemKind::Kept, Some(owner))
}

fn message_item(kind: ItemKind, owner: Addr, id: [u8; 16]) -> ItemRef {
    ItemRef {
        kind,
        owner: Some(owner),
        id: id.to_vec(),
    }
}

fn kept_copy(env: &mut MemEnv, owner: Addr, id: [u8; 16]) -> (u64, Vec<u8>) {
    let item = message_item(ItemKind::Kept, owner, id);
    match call(env, PROD, Op::GetItem { item }) {
        Ok(Reply::Item(Some(i))) => (i.generation, i.body.into_vec()),
        other => panic!("{other:?}"),
    }
}

fn gets(out: &[OutboundDelegateMsg]) -> usize {
    out.iter()
        .filter(|m| matches!(m, OutboundDelegateMsg::GetContractRequest(_)))
        .count()
}

fn subscribes(out: &[OutboundDelegateMsg]) -> usize {
    out.iter()
        .filter(|m| matches!(m, OutboundDelegateMsg::SubscribeContractRequest(_)))
        .count()
}

fn prod(env: &mut MemEnv) -> Space<'_> {
    Space::new(env, Origin([PROD; 32]))
}

fn blind(env: &mut MemEnv, rel: &str) {
    let key = String::from_utf8(prod(env).full_key(rel)).unwrap();
    blind_key(env, key);
}

fn blind_key(env: &mut MemEnv, key: String) {
    let mut faults = Faults::default();
    faults.blind_keys.push(key);
    env.faults = Some(faults);
}

/// The manifest the published candidate actually carries, as the node reads
/// it. It reads the committed WASM, so a manifest that was changed and not
/// rebuilt fails here as well as in `check-delegate-candidate.sh`.
#[test]
fn the_built_delegate_declares_its_lifecycle_capability_and_wake_ups() {
    let wasm = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../published-contract/candidate/mail_delegate"
    ))
    .unwrap();
    // fdev's wrapper comes first: a version, a hash and a length.
    let module = wasm
        .windows(4)
        .position(|w| w == b"\0asm")
        .expect("a WASM module");
    let manifest = DelegateManifest::from_wasm(&wasm[module..])
        .unwrap()
        .expect("a manifest");
    assert_eq!(manifest.lifecycle, vec![LifecycleKind::NodeStarted]);
    assert_eq!(manifest.capabilities, vec![Capability::Background]);
    let wakeups: Vec<(Vec<u8>, u64)> = manifest
        .effective_wakeups()
        .into_iter()
        .map(|(tag, every)| (tag, every.as_secs()))
        .collect();
    let expected: Vec<(Vec<u8>, u64)> = [900, 3600, 21600, 86400]
        .iter()
        .zip(Tick::ALL)
        .map(|(secs, (tag, _))| (tag.as_bytes().to_vec(), *secs))
        .collect();
    assert_eq!(wakeups, expected, "as the node reads them, none clamped");
}

#[test]
fn the_import_allowlist_is_the_stdlib_host_set() {
    let allowlist = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scripts/delegate-imports-allowlist.txt"
    ))
    .unwrap();
    let listed: Vec<(String, String)> = allowlist
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| {
            let (module, name) = l.split_once(' ').unwrap();
            (module.to_string(), name.to_string())
        })
        .collect();
    let host: Vec<(String, String)> = freenet_stdlib::host_imports::DECLARED_HOST_IMPORTS
        .iter()
        .map(|i| (i.module.to_string(), i.name.to_string()))
        .collect();
    assert_eq!(listed, host);
}

#[test]
fn a_tag_this_build_does_not_know_does_nothing() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    deliver(&mut env, &me, &[sealed(&me, "one")]);
    assert!(wake(&mut env, "unknown").is_empty());
    assert!(kept_ids(&mut env, me.addr).is_empty());
}

// ── Ranking ─────────────────────────────────────────────────────────────────

fn candidate(n: u32, origin: u8, tier: Tier, activity: u64) -> Candidate {
    let mut id = [0; 32];
    id[..4].copy_from_slice(&n.to_be_bytes());
    Candidate {
        id,
        origin: Origin([origin; 32]),
        tier,
        activity,
    }
}

#[test]
fn ranking_stops_at_the_subscription_cap_exactly() {
    for (n, expected) in [(255, 255), (256, 256), (257, 256), (1000, 256)] {
        let all: Vec<Candidate> = (0..n)
            .map(|i| candidate(i, 1, Tier::Contact, u64::from(i)))
            .collect();
        assert_eq!(rank_subscriptions(&all).len(), expected, "{n} candidates");
    }
}

#[test]
fn ranking_puts_own_before_v1_before_contacts_and_recent_contacts_first() {
    let ranked = rank_subscriptions(&[
        candidate(1, 1, Tier::Contact, 5),
        candidate(2, 1, Tier::Contact, 9),
        candidate(3, 1, Tier::V1Inbox, 0),
        candidate(4, 1, Tier::Own, 0),
    ]);
    let n = |id: &ContractId| u32::from_be_bytes(id[..4].try_into().unwrap());
    assert_eq!(ranked.iter().map(n).collect::<Vec<_>>(), [4, 3, 2, 1]);
}

#[test]
fn at_the_cap_a_contact_never_displaces_an_inbox() {
    let mut all: Vec<Candidate> = (0..256)
        .map(|i| candidate(i, 1, Tier::Contact, 1000))
        .collect();
    all.push(candidate(900, 1, Tier::V1Inbox, 0));
    all.push(candidate(901, 1, Tier::V1Inbox, 0));
    all.push(candidate(902, 1, Tier::Own, 0));
    let ranked = rank_subscriptions(&all);
    assert_eq!(ranked.len(), 256);
    assert_eq!(ranked[0], candidate(902, 1, Tier::Own, 0).id);
    assert_eq!(ranked[1], candidate(900, 1, Tier::V1Inbox, 0).id);
    assert_eq!(ranked[2], candidate(901, 1, Tier::V1Inbox, 0).id);
}

#[test]
fn origins_take_turns_so_a_large_one_cannot_push_out_a_small_one() {
    let mut all: Vec<Candidate> = (0..300)
        .map(|i| candidate(i, 1, Tier::V1Inbox, 0))
        .collect();
    all.push(candidate(1000, 2, Tier::V1Inbox, 0));
    let ranked = rank_subscriptions(&all);
    assert_eq!(ranked.len(), 256);
    assert_eq!(ranked[1], candidate(1000, 2, Tier::V1Inbox, 0).id);
}

#[test]
fn one_identity_in_two_origins_takes_one_subscription() {
    let a = candidate(7, 1, Tier::V1Inbox, 0);
    let b = candidate(7, 2, Tier::V1Inbox, 0);
    assert_eq!(rank_subscriptions(&[a, b]).len(), 1);
}

// ── Budgets ─────────────────────────────────────────────────────────────────

#[test]
fn operations_stop_at_300_a_minute_and_come_back_with_the_next() {
    let start = NOW - NOW % 60;
    let mut b = Budget::new(start);
    assert_eq!(b.take_ops(299), 299);
    assert_eq!(b.take_ops(1), 1, "the 300th is allowed");
    assert_eq!(b.take_ops(1), 0, "the 301st is not");
    b.advance(start + 59);
    assert_eq!(b.take_ops(1), 0, "still the same minute");
    b.advance(start + 60);
    assert_eq!(b.take_ops(301), 300);
}

#[test]
fn duty_refills_at_one_percent_up_to_the_burst() {
    let mut b = Budget::new(NOW);
    assert!(b.take_duty(10_000), "the whole burst, 10 s");
    assert!(!b.take_duty(1), "and not a millisecond more");
    b.advance(NOW + 1);
    assert!(!b.take_duty(11));
    assert!(b.take_duty(10), "1% of one second");
    b.advance(NOW + 1_000_000);
    assert!(b.take_duty(10_000));
    assert!(!b.take_duty(1), "the burst is the ceiling");
}

#[test]
fn a_clock_stepping_back_a_little_refills_and_reopens_nothing() {
    let mut b = Budget::new(NOW);
    assert!(b.take_duty(DUTY_BURST_MS));
    assert_eq!(b.take_ops(300), 300);
    b.advance(NOW - CLOCK_RESET_SECS);
    b.advance(NOW);
    assert!(!b.take_duty(1));
    assert_eq!(b.take_ops(1), 0);
}

#[test]
fn a_clock_stepping_far_back_starts_the_budget_over() {
    let mut b = Budget::new(NOW + 10 * CLOCK_RESET_SECS);
    assert!(b.take_duty(DUTY_BURST_MS));
    assert_eq!(b.take_ops(300), 300);
    b.advance(NOW);
    assert!(b.take_duty(DUTY_BURST_MS), "a full budget again");
    assert_eq!(b.take_ops(300), 300);
    b.advance(NOW + 1);
    assert!(
        b.take_duty(DUTY_REFILL_MS_PER_SEC),
        "and it refills from here"
    );
}

#[test]
fn a_run_decrypts_at_most_a_batch_and_a_node_run_at_most_its_duty() {
    let mut b = Budget::new(NOW);
    assert_eq!(b.message_slice(true), MAX_MESSAGES_PER_RUN);
    assert!(b.take_duty(DUTY_BURST_MS - MESSAGE_COST_MS * 3));
    assert_eq!(b.message_slice(true), 3);
    assert!(b.take_duty(1));
    assert_eq!(b.message_slice(true), 2, "a part-paid message is not taken");
    assert_eq!(
        b.message_slice(false),
        MAX_MESSAGES_PER_RUN,
        "a page has no duty"
    );
    b.charge_messages(100);
    assert_eq!(b.message_slice(true), 0);
}

fn target(n: u8, origin: u8) -> Target {
    Target {
        origin: Origin([origin; 32]),
        addr: Addr([n; 24]),
        id: [n; 32],
    }
}

#[test]
fn scans_rotate_so_every_inbox_is_reached_at_the_per_run_limit() {
    let targets: Vec<Target> = (1..=10).map(|n| target(n, 1)).collect();
    let mut b = Budget::new(NOW);
    let mut reached = std::collections::BTreeSet::new();
    for _ in 0..3 {
        let p = plan(Trigger::Tick(Tick::Rescan), &targets, &mut b);
        assert_eq!(p.scan.len(), MAX_SCANS_PER_RUN);
        reached.extend(p.scan.iter().map(|t| t.id[0]));
    }
    assert_eq!(reached.len(), 10, "{reached:?}");
}

#[test]
fn a_node_run_with_no_duty_left_scans_nothing_and_a_page_still_does() {
    let targets = [target(1, 1)];
    let mut b = Budget::new(NOW);
    assert!(b.take_duty(DUTY_BURST_MS - SCAN_COST_MS + 1));
    let p = plan(Trigger::Tick(Tick::Rescan), &targets, &mut b);
    assert!(p.scan.is_empty());
    let p = plan(Trigger::RunJobs(Origin([1; 32])), &targets, &mut b);
    assert_eq!(p.scan, targets);
}

#[test]
fn a_refresh_past_the_operation_limit_subscribes_the_best_it_can() {
    let targets: Vec<Target> = (1..=10).map(|n| target(n, 1)).collect();
    let mut b = Budget::new(NOW - NOW % 60);
    assert_eq!(b.take_ops(297), 297);
    let p = plan(Trigger::Tick(Tick::V1Watch), &targets, &mut b);
    assert_eq!(p.subscribe, [[1; 32], [2; 32], [3; 32]]);
}

#[test]
fn each_trigger_does_only_its_jobs_and_a_clock_tick_drains_first() {
    let targets = [target(1, 1)];
    let local = |t| plan(t, &targets, &mut Budget::new(NOW));
    let rescan = local(Trigger::Tick(Tick::Rescan));
    assert!(rescan.subscribe.is_empty() && !rescan.fetch_missing);
    assert_eq!(rescan.scan.len(), 1);
    let watch = local(Trigger::Tick(Tick::V1Watch));
    assert_eq!(watch.subscribe.len(), 1);
    assert!(watch.fetch_missing);
    for tick in [Tick::Renew, Tick::Clock] {
        let p = local(Trigger::Tick(tick));
        assert!(p.scan.is_empty() && p.subscribe.is_empty(), "{tick:?}");
    }
    assert_eq!(
        jobs_for(Trigger::Tick(Tick::Clock)),
        [Job::DrainOwn, Job::AdvanceClock]
    );
}

#[test]
fn a_contract_trigger_scans_only_that_contract_and_keeps_the_rotation() {
    let targets: Vec<Target> = (1..=6).map(|n| target(n, 1)).collect();
    let mut b = Budget::new(NOW);
    plan(Trigger::Tick(Tick::Rescan), &targets, &mut b);
    let p = plan(Trigger::Contract([3; 32]), &targets, &mut b);
    assert_eq!(p.scan, [target(3, 1)]);
    assert_eq!(
        plan(Trigger::Tick(Tick::Rescan), &targets, &mut b).scan[0],
        target(5, 1),
        "the rotation goes on from where it was"
    );
    let none = plan(Trigger::Contract([99; 32]), &targets, &mut b);
    assert!(none.scan.is_empty());
}

// ── One path ────────────────────────────────────────────────────────────────

#[test]
fn the_page_and_the_node_store_the_same_bytes() {
    let mut page = env();
    let me = create(&mut page, PROD, "alice");
    let message = sealed(&me, "one");
    deliver(&mut page, &me, std::slice::from_ref(&message));
    let mut node = page.clone();
    assert_eq!(run_jobs(&mut page, PROD).imported, 1);
    wake(&mut node, "rescan");
    assert_eq!(ns_snapshot(&page, PROD), ns_snapshot(&node, PROD));
    assert_eq!(kept_ids(&mut node, me.addr), [id_of(&message).to_vec()]);
}

#[test]
fn every_trigger_imports_through_the_watch() {
    for trigger in ["rescan", "v1watch", "started", "notified", "got", "page"] {
        let mut env = env();
        let me = create(&mut env, PROD, "alice");
        let message = sealed(&me, "one");
        deliver(&mut env, &me, std::slice::from_ref(&message));
        let id = v1_inbox_id(&me.vk).unwrap();
        match trigger {
            "started" => drop(process(&mut env, None, node_started()).unwrap()),
            "notified" => drop(process(&mut env, None, notification(id, vec![])).unwrap()),
            "got" => drop(process(&mut env, None, get_answer(id, None)).unwrap()),
            "page" => drop(run_jobs(&mut env, PROD)),
            tag => drop(wake(&mut env, tag)),
        }
        assert_eq!(
            kept_ids(&mut env, me.addr),
            [id_of(&message).to_vec()],
            "{trigger}"
        );
    }
}

#[test]
fn a_run_tells_no_page_anything() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    deliver(&mut env, &me, &[sealed(&me, "one")]);
    for out in [wake(&mut env, "v1watch"), wake(&mut env, "rescan")] {
        assert!(responses(&out).is_empty());
    }
}

#[test]
fn a_new_identity_is_watched_with_no_page_ever_asking() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let out = wake(&mut env, "v1watch");
    assert_eq!(subscribes(&out), 1, "{out:?}");
    let OutboundDelegateMsg::SubscribeContractRequest(req) = &out[0] else {
        panic!("{out:?}");
    };
    assert_eq!(
        req.contract_id.as_bytes(),
        v1_inbox_id(&me.vk).unwrap().as_slice()
    );
}

fn subscribed(me: &IdentityInfo, result: Result<(), String>) -> InboundDelegateMsg<'static> {
    InboundDelegateMsg::SubscribeContractResponse(SubscribeContractResponse {
        contract_id: ContractInstanceId::new(v1_inbox_id(&me.vk).unwrap()),
        result,
        context: DelegateContext::default(),
    })
}

#[test]
fn a_forged_subscription_answer_does_not_stop_the_next_refresh_asking() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let before = env.secrets.clone();
    for origin in [None, app(PROD), app(OTHER)] {
        let out = process(&mut env, origin, subscribed(&me, Ok(()))).unwrap();
        assert!(out.is_empty());
    }
    assert_eq!(env.secrets, before, "nothing durable came of the answers");
    assert_eq!(subscribes(&wake(&mut env, "v1watch")), 1, "still asked");
    deliver(&mut env, &me, &[]);
    assert_eq!(subscribes(&send(&mut env, app(PROD), Op::RunJobs)), 1);
    assert_eq!(
        subscribes(&wake(&mut env, "v1watch")),
        1,
        "every refresh asks"
    );
}

/// Wakes `v1watch` at `at` and says how many GETs it sent.
fn watch_gets_at(env: &mut MemEnv, at: u64) -> usize {
    env.now = Some(at);
    gets(&wake(env, "v1watch"))
}

#[test]
fn a_page_run_never_asks_the_network_for_an_inbox_this_node_lacks() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let out = send(&mut env, app(PROD), Op::RunJobs);
    assert_eq!((gets(&out), subscribes(&out)), (0, 0), "{out:?}");
    // One the node holds is subscribed, which does not wait on the network.
    deliver(&mut env, &me, &[]);
    let out = send(&mut env, app(PROD), Op::RunJobs);
    assert_eq!((gets(&out), subscribes(&out)), (0, 1), "{out:?}");
}

#[test]
fn a_missing_inbox_is_asked_for_at_doubling_intervals_up_to_a_day() {
    let mut env = env();
    create(&mut env, PROD, "alice");
    let mut due = NOW;
    for ask in 1..=9u32 {
        assert_eq!(watch_gets_at(&mut env, due), 1, "ask {ask}");
        let wait = (MISSING_BACKOFF_FIRST_SECS << (ask - 1)).min(MISSING_BACKOFF_MAX_SECS);
        assert_eq!(watch_gets_at(&mut env, due + wait - 1), 0, "ask {ask}");
        let out = wake(&mut env, "v1watch");
        assert_eq!(subscribes(&out), 0, "a refresh waits for it too");
        due += wait;
    }
    assert_eq!(MISSING_BACKOFF_MAX_SECS, 86_400);
}

#[test]
fn a_missing_inbox_found_is_asked_for_at_once_if_it_goes_missing_again() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    assert_eq!(watch_gets_at(&mut env, NOW), 1);
    assert_eq!(watch_gets_at(&mut env, NOW + 10), 0, "backing off");
    deliver(&mut env, &me, &[]);
    wake(&mut env, "rescan");
    env.contracts.clear();
    assert_eq!(watch_gets_at(&mut env, NOW + 20), 1, "a success cleared it");
}

#[test]
fn a_node_start_still_asks_for_a_missing_inbox_the_first_time() {
    let mut env = env();
    create(&mut env, PROD, "alice");
    let out = process(&mut env, None, node_started()).unwrap();
    assert_eq!((gets(&out), subscribes(&out)), (1, 1));
}

#[test]
fn an_origin_with_no_identities_left_gives_up_its_place() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    assert_eq!(
        Space::new(&mut env, GLOBAL)
            .index("ix/bg/origins")
            .unwrap()
            .1
            .len(),
        1
    );
    let mut s = prod(&mut env);
    let (generation, _) = load_identity(&s, &me.addr).unwrap().unwrap();
    assert_eq!(
        crate::handlers::delete_identity_now(&mut s, &me.addr, generation),
        Ok(Reply::Deleted)
    );
    wake(&mut env, "rescan");
    let (_, listed) = Space::new(&mut env, GLOBAL).index("ix/bg/origins").unwrap();
    assert!(listed.is_empty());
}

#[test]
fn a_failed_subscription_is_asked_for_again_by_the_next_refresh() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let answer = subscribed(&me, Err("refused".into()));
    assert!(process(&mut env, None, answer).unwrap().is_empty());
    assert_eq!(subscribes(&wake(&mut env, "v1watch")), 1);
}

// ── Unknown is never absent ─────────────────────────────────────────────────

#[test]
fn a_refused_get_is_unknown_and_asked_again() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let id = v1_inbox_id(&me.vk).unwrap();
    assert_eq!(gets(&wake(&mut env, "v1watch")), 1, "not held: fetch it");
    // Core answers a refused or failed GET with `state: None`, the same as
    // "not found". It concludes nothing and starts no loop.
    let answered = process(&mut env, None, get_answer(id, None)).unwrap();
    assert!(answered.is_empty(), "{answered:?}");
    let run = run_jobs(&mut env, PROD);
    assert_eq!((run.unknown, run.scanned), (1, 0), "not an empty inbox");
    env.now = Some(NOW + MISSING_BACKOFF_FIRST_SECS);
    assert_eq!(gets(&wake(&mut env, "v1watch")), 1, "asked again");
    // The state turns up: nothing about it was written off.
    let message = sealed(&me, "late");
    deliver(&mut env, &me, std::slice::from_ref(&message));
    process(&mut env, None, get_answer(id, None)).unwrap();
    assert_eq!(kept_ids(&mut env, me.addr), [id_of(&message).to_vec()]);
}

#[test]
fn a_state_that_does_not_decode_is_unknown() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    env.contracts
        .insert(v1_inbox_id(&me.vk).unwrap(), b"not an inbox".to_vec());
    let run = run_jobs(&mut env, PROD);
    assert_eq!((run.unknown, run.scanned), (1, 0));
}

#[test]
fn a_state_over_the_size_limit_is_unknown() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let mut state = inbox_of(&[]);
    state.resize(watch::MAX_INBOX_BYTES, b' ');
    env.contracts
        .insert(v1_inbox_id(&me.vk).unwrap(), state.clone());
    assert_eq!(run_jobs(&mut env, PROD).unknown, 0, "at the limit");
    state.push(b' ');
    env.contracts.insert(v1_inbox_id(&me.vk).unwrap(), state);
    assert_eq!(run_jobs(&mut env, PROD).unknown, 1, "one byte past it");
}

#[test]
fn a_captured_v0_2_x_inbox_state_is_read() {
    let hex = include_str!("../../../../wire-v1/src/golden_v1.txt")
        .lines()
        .find_map(|l| l.strip_prefix("inbox_state "))
        .expect("the golden inbox state");
    let bytes: Vec<u8> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
        .collect();
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    env.contracts.insert(v1_inbox_id(&me.vk).unwrap(), bytes);
    let run = run_jobs(&mut env, PROD);
    // The sample's ciphertext is eight bytes: read, and not a message.
    assert_eq!((run.unknown, run.scanned, run.imported), (0, 1, 0));
    let id = message_id(&[1; 8]);
    let (_, seen) = prod(&mut env).index(&seen_rel(&me.addr, &id)).unwrap();
    assert!(seen.contains(&id[..]), "its one message was reached");
}

#[test]
fn an_origin_list_that_cannot_be_read_is_unknown() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    deliver(&mut env, &me, &[sealed(&me, "one")]);
    let key = Space::new(&mut env, GLOBAL).full_key("ix/bg/origins");
    blind_key(&mut env, String::from_utf8(key).unwrap());
    let (run, out) = watch::run(&mut env, Trigger::Tick(Tick::Rescan));
    assert_eq!((run.unknown, run.scanned), (1, 0));
    assert!(out.is_empty());
    env.faults = None;
    assert!(kept_ids(&mut env, me.addr).is_empty());
    wake(&mut env, "rescan");
    assert_eq!(kept_ids(&mut env, me.addr).len(), 1, "and read next time");
}

// ── Notifications ───────────────────────────────────────────────────────────

#[test]
fn what_a_notification_or_a_get_answer_carries_is_not_used() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let id = v1_inbox_id(&me.vk).unwrap();
    let planted = inbox_of(&[sealed(&me, "planted")]);
    process(&mut env, None, notification(id, planted.clone())).unwrap();
    process(&mut env, None, get_answer(id, Some(planted.clone()))).unwrap();
    process(&mut env, app(OTHER), notification(id, planted)).unwrap();
    assert!(kept_ids(&mut env, me.addr).is_empty());
}

#[test]
fn a_duplicate_notification_changes_nothing() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    deliver(&mut env, &me, &[sealed(&me, "one")]);
    let id = v1_inbox_id(&me.vk).unwrap();
    process(&mut env, None, notification(id, vec![])).unwrap();
    let before = ns_snapshot(&env, PROD);
    assert_eq!(kept_ids(&mut env, me.addr).len(), 1);
    for _ in 0..3 {
        process(&mut env, None, notification(id, vec![])).unwrap();
    }
    assert_eq!(ns_snapshot(&env, PROD), before);
}

#[test]
fn an_out_of_order_notification_reads_the_current_state() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let id = v1_inbox_id(&me.vk).unwrap();
    let (one, two) = (sealed(&me, "one"), sealed(&me, "two"));
    deliver(&mut env, &me, &[one.clone(), two.clone()]);
    // The node's store is at the newer state; the older state's notification
    // arrives last.
    process(
        &mut env,
        None,
        notification(id, inbox_of(std::slice::from_ref(&one))),
    )
    .unwrap();
    let mut got = kept_ids(&mut env, me.addr);
    got.sort();
    let mut want = vec![id_of(&one).to_vec(), id_of(&two).to_vec()];
    want.sort();
    assert_eq!(got, want);
}

#[test]
fn a_rescan_recovers_a_dropped_notification() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let message = sealed(&me, "one");
    // It arrived, and no notification was delivered.
    deliver(&mut env, &me, std::slice::from_ref(&message));
    assert!(kept_ids(&mut env, me.addr).is_empty());
    let out = wake(&mut env, "rescan");
    assert!(out.is_empty(), "a rescan reads what is here: {out:?}");
    assert_eq!(kept_ids(&mut env, me.addr), [id_of(&message).to_vec()]);
}

#[test]
fn a_notification_for_a_contract_nobody_here_watches_does_nothing() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    deliver(&mut env, &me, &[sealed(&me, "one")]);
    process(&mut env, None, notification([77; 32], vec![])).unwrap();
    assert!(kept_ids(&mut env, me.addr).is_empty());
}

// ── What an import writes ───────────────────────────────────────────────────

#[test]
fn an_import_is_the_page_s_kept_copy_with_a_checked_signature() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let message = sealed(&me, "one");
    deliver(&mut env, &me, std::slice::from_ref(&message));
    run_jobs(&mut env, PROD);
    let (_, body) = kept_copy(&mut env, me.addr, id_of(&message));
    let kept: KeptMessage = serde_json::from_slice(&body).unwrap();
    assert_eq!(kept.title, "one");
    assert_eq!(kept.content, "body of one");
    assert_eq!(kept.from, "bob");
    assert_eq!(kept.kept_at, NOW as i64 * 1000);
    assert_eq!(kept.sent_at, Some(1_793_613_600_000));
    assert!(kept.signature_valid);
    assert!(!kept.sender_vk.is_empty());
}

#[test]
fn a_forged_signature_is_recorded_as_invalid_like_the_page_records_it() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let mut v: serde_json::Value = serde_json::from_slice(&sealed(&me, "one")).unwrap();
    v["signature"][0] = serde_json::json!(v["signature"][0].as_u64().unwrap() ^ 1);
    let message = serde_json::to_vec(&v).unwrap();
    deliver(&mut env, &me, std::slice::from_ref(&message));
    run_jobs(&mut env, PROD);
    let (_, body) = kept_copy(&mut env, me.addr, id_of(&message));
    let kept: KeptMessage = serde_json::from_slice(&body).unwrap();
    assert!(!kept.signature_valid);
}

#[test]
fn an_import_never_overwrites_a_kept_copy() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let message = sealed(&me, "one");
    deliver(&mut env, &me, std::slice::from_ref(&message));
    let item = message_item(ItemKind::Kept, me.addr, id_of(&message));
    ack(put(&mut env, item, b"the page's copy", None));
    let before = ns_snapshot(&env, PROD);
    assert_eq!(run_jobs(&mut env, PROD).imported, 0);
    assert_eq!(ns_snapshot(&env, PROD), before);
}

/// The lists said nothing was stored, as they would have before a tab's
/// write landed: `put_item` itself refuses, because the import is create-only.
#[test]
fn a_copy_written_between_the_lists_and_the_write_stands() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let item = message_item(ItemKind::Kept, me.addr, [5; 16]);
    ack(put(&mut env, item.clone(), b"the page's copy", None));
    let refused =
        crate::handlers::put_item(&mut prod(&mut env), item, b"import".to_vec(), None).unwrap_err();
    assert!(matches!(refused.code, FailureCode::Conflict { .. }));
    assert_eq!(kept_copy(&mut env, me.addr, [5; 16]).1, b"the page's copy");
}

// ── Never brings back a deleted message ─────────────────────────────────────

#[test]
fn a_deleted_import_stays_deleted() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let message = sealed(&me, "one");
    deliver(&mut env, &me, std::slice::from_ref(&message));
    run_jobs(&mut env, PROD);
    let id = id_of(&message);
    let (expected_gen, _) = kept_copy(&mut env, me.addr, id);
    let item = message_item(ItemKind::Kept, me.addr, id);
    assert_eq!(
        call(&mut env, PROD, Op::DeleteItem { item, expected_gen }),
        Ok(Reply::Deleted)
    );
    // No flags at all, and the inbox still holds the message.
    for tag in ["rescan", "v1watch"] {
        wake(&mut env, tag);
    }
    assert_eq!(run_jobs(&mut env, PROD).imported, 0);
    assert!(kept_ids(&mut env, me.addr).is_empty());
}

#[test]
fn a_message_flagged_deleted_is_not_imported() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let message = sealed(&me, "one");
    deliver(&mut env, &me, std::slice::from_ref(&message));
    let flags = message_item(ItemKind::Flags, me.addr, id_of(&message));
    ack(put(
        &mut env,
        flags,
        br#"{"read":false,"deleted":true}"#,
        None,
    ));
    let run = run_jobs(&mut env, PROD);
    assert_eq!((run.imported, run.remaining), (0, 0));
    assert!(kept_ids(&mut env, me.addr).is_empty());
}

#[test]
fn a_message_flagged_read_is_imported() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let message = sealed(&me, "one");
    deliver(&mut env, &me, std::slice::from_ref(&message));
    let flags = message_item(ItemKind::Flags, me.addr, id_of(&message));
    ack(put(
        &mut env,
        flags,
        br#"{"read":true,"deleted":false}"#,
        None,
    ));
    assert_eq!(run_jobs(&mut env, PROD).imported, 1);
}

fn flags_body(env: &mut MemEnv, owner: Addr, id: [u8; 16]) -> Option<Vec<u8>> {
    let item = message_item(ItemKind::Flags, owner, id);
    match call(env, PROD, Op::GetItem { item }) {
        Ok(Reply::Item(i)) => i.map(|i| i.body.into_vec()),
        other => panic!("{other:?}"),
    }
}

/// The page shows a kept copy as read unless the message has flags that say
/// otherwise, so an import carries them.
#[test]
fn an_import_says_it_is_unread() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let message = sealed(&me, "one");
    deliver(&mut env, &me, std::slice::from_ref(&message));
    assert_eq!(run_jobs(&mut env, PROD).imported, 1);
    assert_eq!(
        flags_body(&mut env, me.addr, id_of(&message)).as_deref(),
        Some(&br#"{"read":false,"deleted":false}"#[..])
    );
}

/// Flags that are there are the user's, whatever they say.
#[test]
fn an_import_leaves_existing_flags_as_they_are() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let message = sealed(&me, "one");
    deliver(&mut env, &me, std::slice::from_ref(&message));
    let flags = message_item(ItemKind::Flags, me.addr, id_of(&message));
    let read = br#"{"read":true,"deleted":false}"#;
    ack(put(&mut env, flags, read, None));
    assert_eq!(run_jobs(&mut env, PROD).imported, 1);
    assert_eq!(
        flags_body(&mut env, me.addr, id_of(&message)).as_deref(),
        Some(&read[..])
    );
}

/// The page drops a deleted mark once the message left the inbox
/// (`reclaim_flags`). An older state of the inbox can come back, from a peer
/// or a re-fetch, still holding it.
#[test]
fn a_reclaimed_mark_does_not_let_an_older_state_bring_a_message_back() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let message = sealed(&me, "one");
    let flags = message_item(ItemKind::Flags, me.addr, id_of(&message));
    let expected_gen = ack(put(
        &mut env,
        flags.clone(),
        br#"{"read":false,"deleted":true}"#,
        None,
    ));
    assert_eq!(
        call(
            &mut env,
            PROD,
            Op::DeleteItem {
                item: flags,
                expected_gen
            }
        ),
        Ok(Reply::Deleted)
    );
    deliver(&mut env, &me, std::slice::from_ref(&message));
    wake(&mut env, "rescan");
    assert!(kept_ids(&mut env, me.addr).is_empty());
}

#[test]
fn a_mark_that_cannot_be_read_stops_the_import() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let message = sealed(&me, "one");
    deliver(&mut env, &me, std::slice::from_ref(&message));
    let flags = message_item(ItemKind::Flags, me.addr, id_of(&message));
    ack(put(
        &mut env,
        flags.clone(),
        br#"{"read":false,"deleted":true}"#,
        None,
    ));
    blind(&mut env, &item_rel(&flags));
    let run = run_jobs(&mut env, PROD);
    assert_eq!((run.imported, run.remaining), (0, 1));
    env.faults = None;
    assert!(kept_ids(&mut env, me.addr).is_empty());
}

#[test]
fn an_unreadable_list_of_tombstones_stops_the_scan() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let message = sealed(&me, "one");
    deliver(&mut env, &me, std::slice::from_ref(&message));
    let id = id_of(&message);
    watch::note_seen(&mut prod(&mut env), &me.addr, &id).unwrap();
    blind(&mut env, &seen_rel(&me.addr, &id));
    let run = run_jobs(&mut env, PROD);
    assert_eq!((run.unknown, run.scanned, run.imported), (1, 0, 0));
}

#[test]
fn an_unreadable_tombstone_list_does_not_block_a_delete() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let id = [0x50; 16];
    let item = message_item(ItemKind::Kept, me.addr, id);
    let expected_gen = ack(put(&mut env, item.clone(), b"copy", None));
    watch::note_seen(&mut prod(&mut env), &me.addr, &[0x51; 16]).unwrap();
    blind(&mut env, &seen_rel(&me.addr, &id));
    assert_eq!(
        call(&mut env, PROD, Op::DeleteItem { item, expected_gen }),
        Ok(Reply::Deleted)
    );
}

#[test]
fn an_archived_message_is_not_imported() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let message = sealed(&me, "one");
    deliver(&mut env, &me, std::slice::from_ref(&message));
    let archived = message_item(ItemKind::Archived, me.addr, id_of(&message));
    ack(put(&mut env, archived, b"archived", None));
    assert_eq!(run_jobs(&mut env, PROD).imported, 0);
    assert!(kept_ids(&mut env, me.addr).is_empty());
}

#[test]
fn a_full_shard_of_tombstones_makes_room() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let mut s = prod(&mut env);
    let rel = seen_rel(&me.addr, &[0; 16]);
    for n in 0..=watch::SEEN_PER_SHARD {
        let mut id = [0u8; 16];
        id[1..3].copy_from_slice(&(n as u16).to_be_bytes());
        watch::note_seen(&mut s, &me.addr, &id).unwrap();
        assert!(s.index(&rel).unwrap().1.contains(&id[..]), "entry {n}");
    }
    assert_eq!(s.index(&rel).unwrap().1.len(), watch::SEEN_PER_SHARD);
}

#[test]
fn a_store_at_its_budget_can_still_delete() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let item = message_item(ItemKind::Kept, me.addr, [5; 16]);
    let expected_gen = ack(put(&mut env, item.clone(), b"copy", None));
    let mut s = prod(&mut env);
    let full = store::Usage {
        keys: store::MAX_ORIGIN_KEYS,
        bytes: s.usage().bytes,
    };
    s.confirm_usage_for_test(full);
    assert_eq!(
        call(&mut env, PROD, Op::DeleteItem { item, expected_gen }),
        Ok(Reply::Deleted)
    );
}

#[test]
fn tombstones_travel_with_an_export_and_leave_with_the_identity() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let id = [0x50; 16];
    let rel = seen_rel(&me.addr, &id);
    let mut s = prod(&mut env);
    watch::note_seen(&mut s, &me.addr, &id).unwrap();
    assert!(crate::handlers::exportable_keys(&s).unwrap().contains(&rel));
    let (generation, _) = load_identity(&s, &me.addr).unwrap().unwrap();
    assert_eq!(
        crate::handlers::delete_identity_now(&mut s, &me.addr, generation),
        Ok(Reply::Deleted)
    );
    assert!(s.get(&rel).is_none());
    assert!(s.get(&index_marker_rel(&rel)).is_none());
}

/// `Busy` from a recount under way is not an unreadable shard: skipping the
/// tombstone there would let a deleted message back.
#[test]
fn a_delete_with_no_tombstone_written_is_not_a_delete() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let id = [0x50; 16];
    let item = message_item(ItemKind::Kept, me.addr, id);
    let expected_gen = ack(put(&mut env, item.clone(), b"copy", None));
    let shard = seen_rel(&me.addr, &id);
    env.fail_keys_containing = Some(shard);
    let got = call(&mut env, PROD, Op::DeleteItem { item, expected_gen });
    assert!(got.is_err(), "{got:?}");
    env.fail_keys_containing = None;
    assert_eq!(
        kept_ids(&mut env, me.addr).len(),
        1,
        "it stays until it can go"
    );
}

#[test]
fn a_recount_counts_the_tombstones() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let mut s = prod(&mut env);
    watch::note_seen(&mut s, &me.addr, &[1; 16]).unwrap();
    let recorded = s.usage();
    assert_eq!(s.recount().unwrap(), recorded);
}

// ── Slices ──────────────────────────────────────────────────────────────────

#[test]
fn a_backlog_is_taken_a_batch_at_a_time_and_resumes() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let total = 12 + 3;
    let messages: Vec<Vec<u8>> = (0..total).map(|n| sealed(&me, &format!("m{n}"))).collect();
    deliver(&mut env, &me, &messages);
    let first = run_jobs(&mut env, PROD);
    assert_eq!((first.imported as usize, first.remaining), (12, 3));
    let second = run_jobs(&mut env, PROD);
    assert_eq!((second.imported, second.remaining), (3, 0));
    assert_eq!(kept_ids(&mut env, me.addr).len(), total);
}

#[test]
fn a_node_run_spends_its_duty_and_stops() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let messages: Vec<Vec<u8>> = (0..5).map(|n| sealed(&me, &format!("m{n}"))).collect();
    deliver(&mut env, &me, &messages);
    let mut budget = Budget::new(NOW);
    assert!(budget.take_duty(DUTY_BURST_MS - SCAN_COST_MS - 2 * MESSAGE_COST_MS));
    let body = to_cbor(&budget).unwrap();
    Space::new(&mut env, GLOBAL)
        .put("bg/budget", &body)
        .unwrap();
    wake(&mut env, "rescan");
    assert_eq!(
        kept_ids(&mut env, me.addr).len(),
        2,
        "what the duty paid for"
    );
    wake(&mut env, "rescan");
    assert_eq!(
        kept_ids(&mut env, me.addr).len(),
        2,
        "nothing left to spend"
    );
    env.now = Some(NOW + 3600);
    wake(&mut env, "rescan");
    assert_eq!(kept_ids(&mut env, me.addr).len(), 5, "it refilled");
}

#[test]
fn a_message_that_never_decrypts_costs_one_slice() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let garbage = serde_json::to_vec(&serde_json::json!({"content": [1, 2, 3]})).unwrap();
    deliver(&mut env, &me, std::slice::from_ref(&garbage));
    let first = run_jobs(&mut env, PROD);
    assert_eq!((first.imported, first.remaining, first.scanned), (0, 0, 1));
    let id = id_of(&garbage);
    let (_, seen) = prod(&mut env).index(&seen_rel(&me.addr, &id)).unwrap();
    assert!(seen.contains(&id[..]));
    let before = ns_snapshot(&env, PROD);
    run_jobs(&mut env, PROD);
    assert_eq!(ns_snapshot(&env, PROD), before, "and is not tried again");
}

#[test]
fn the_kept_cap_stops_the_import_and_spends_no_more_of_the_slice() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    deliver(&mut env, &me, &[sealed(&me, "one"), sealed(&me, "two")]);
    let mut budget = Budget::new(NOW);
    let scan = SCAN_COST_MS + read_cost_ms(env.contracts.values().next().unwrap().len());
    assert!(budget.take_duty(DUTY_BURST_MS - scan - 5 * MESSAGE_COST_MS));
    let body = to_cbor(&budget).unwrap();
    Space::new(&mut env, GLOBAL)
        .put("bg/budget", &body)
        .unwrap();
    // Only the list: the cap is on its length.
    let ix = index_rel(ItemKind::Kept, Some(&me.addr));
    let list: Vec<ByteBuf> = (0..store::MAX_MESSAGES as u32)
        .map(|n| {
            let mut id = [0xee; 16];
            id[..4].copy_from_slice(&n.to_be_bytes());
            ByteBuf::from(id.to_vec())
        })
        .collect();
    let mut s = prod(&mut env);
    s.index_add(&ix, list[0].as_ref(), store::MAX_MESSAGES)
        .unwrap();
    let (generation, _) = s.index(&ix).unwrap();
    s.write_if(&ix, generation, &to_cbor(&list).unwrap())
        .unwrap();
    let (run, _) = watch::run(&mut env, Trigger::Tick(Tick::Rescan));
    assert_eq!((run.imported, run.remaining), (0, 2));
    let stored = Space::new(&mut env, GLOBAL).get("bg/budget").unwrap();
    let left: Budget = from_cbor(&stored).unwrap();
    assert_eq!(left.message_slice(true), 4, "one message found the cap");
}

// ── Gate ────────────────────────────────────────────────────────────────────

#[test]
fn a_run_for_one_origin_says_nothing_of_another() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    deliver(&mut env, &me, &[sealed(&me, "one")]);
    let before = ns_snapshot(&env, PROD);
    let run = run_jobs(&mut env, OTHER);
    assert_eq!(run, JobsRun::default());
    assert_eq!(ns_snapshot(&env, PROD), before);
}

#[test]
fn an_unattested_or_delegate_caller_still_cannot_ask() {
    let mut env = env();
    create(&mut env, PROD, "alice");
    assert!(process(&mut env, None, app_msg(Op::RunJobs)).is_err());
    assert!(process(&mut env, foreign_delegate(), app_msg(Op::RunJobs)).is_err());
}

#[test]
fn the_delegate_s_own_namespace_is_no_app_s_origin() {
    let mut env = env();
    let zero = Some(MessageOrigin::WebApp(ContractInstanceId::new([0; 32])));
    assert!(process(&mut env, zero, app_msg(Op::ListIdentities)).is_err());
}

#[test]
fn each_origin_is_reached_and_a_17th_only_by_its_own_page() {
    let mut env = env();
    for origin in 0..18 {
        create(&mut env, 100 + origin, "alice");
    }
    let out = wake(&mut env, "v1watch");
    assert_eq!(subscribes(&out), 16);
    let last = 117;
    assert_eq!(run_jobs(&mut env, last).unknown, 1, "its own page runs it");
}

#[test]
fn an_identity_being_deleted_is_not_watched() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    deliver(&mut env, &me, &[sealed(&me, "one")]);
    let mut s = prod(&mut env);
    let (generation, mut record) = load_identity(&s, &me.addr).unwrap().unwrap();
    record.deleting = true;
    let body = to_cbor(&record).unwrap();
    s.write_if(&store::identity_rel(&me.addr), generation, &body)
        .unwrap();
    assert_eq!(run_jobs(&mut env, PROD), JobsRun::default());
}

/// A host fault during a scan leaves nothing a later run does not finish.
/// Writes naming the message are its flags (the first) and its kept copy (the
/// second), so `nth` picks which one the host refuses.
fn a_refused_write_is_finished(nth: u32) {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let message = sealed(&me, "one");
    deliver(&mut env, &me, std::slice::from_ref(&message));
    let mut faults = Faults::default();
    faults.rules.push(Rule {
        op: FaultOp::SetFail,
        key_contains: store::hex(&id_of(&message)),
        nth,
    });
    env.faults = Some(faults);
    let run = run_jobs(&mut env, PROD);
    assert_eq!((run.imported, run.remaining), (0, 1));
    env.faults = None;
    assert_eq!(run_jobs(&mut env, PROD).imported, 1);
    assert_eq!(kept_ids(&mut env, me.addr), vec![id_of(&message).to_vec()]);
}

#[test]
fn a_refused_kept_write_is_finished_by_the_next_run() {
    a_refused_write_is_finished(2);
}

#[test]
fn a_refused_flags_write_is_finished_by_the_next_run() {
    a_refused_write_is_finished(1);
}

// ── Round 1 fixes ───────────────────────────────────────────────────────────

/// What a run takes at most is stated against the measured cost of an import
/// (`MESSAGE_COST_MS`, 120 ms on a real node): with the scans it stays under a
/// third of core's 5 s limit.
const _: () = assert!(
    MAX_MESSAGES_PER_RUN as u64 * MESSAGE_COST_MS + MAX_SCANS_PER_RUN as u64 * SCAN_COST_MS
        <= 5_000 / 3
);

fn duty_left(env: &mut MemEnv) -> u64 {
    let stored = Space::new(env, GLOBAL).get("bg/budget").unwrap();
    from_cbor::<Budget>(&stored).unwrap().duty_ms
}

/// A host that stops the run after `sets` writes, as core does when it stops
/// waiting at its time limit: the guest does not continue.
struct Killed<'a> {
    inner: &'a mut MemEnv,
    sets: usize,
}

impl Env for Killed<'_> {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.get(key)
    }
    fn set(&mut self, key: &[u8], value: &[u8]) -> bool {
        assert!(self.sets > 0, "the run was stopped");
        self.sets -= 1;
        self.inner.set(key, value)
    }
    fn remove(&mut self, key: &[u8]) -> bool {
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

#[test]
fn a_run_stopped_by_the_host_resumes_without_repeating_or_losing() {
    let mut env = env();
    let mut ids: Vec<IdentityInfo> = (1..=6)
        .map(|n| create(&mut env, PROD, &"a".repeat(n)))
        .collect();
    ids.sort_by_key(|i| i.addr.0);
    let mut sent = Vec::new();
    for me in &ids {
        let messages: Vec<Vec<u8>> = (0..3).map(|n| sealed(me, &format!("m{n}"))).collect();
        sent.push(
            messages
                .iter()
                .map(|m| id_of(m).to_vec())
                .collect::<Vec<_>>(),
        );
        deliver(&mut env, me, &messages);
    }
    // Four inboxes are scanned a run: the first run stops in the first of them.
    let stopped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut host = Killed {
            inner: &mut env,
            sets: 8,
        };
        let tag = b"rescan".to_vec();
        let _ = process(&mut host, None, InboundDelegateMsg::WakeupFired { tag });
    }));
    assert!(stopped.is_err(), "the run did not finish");
    let kept = |env: &mut MemEnv, i: usize| kept_ids(env, ids[i].addr).len();
    assert!(kept(&mut env, 0) < 3, "it stopped in the first inbox");
    // The rotation moved before the imports, so the next run goes on with the
    // inboxes the stopped one never reached.
    wake(&mut env, "rescan");
    assert_eq!((kept(&mut env, 4), kept(&mut env, 5)), (3, 3));
    for _ in 0..4 {
        wake(&mut env, "rescan");
    }
    for (i, want) in sent.iter().enumerate() {
        let mut got = kept_ids(&mut env, ids[i].addr);
        let mut want = want.clone();
        got.sort();
        want.sort();
        assert_eq!(got, want, "identity {i}: all of it, once");
    }
    assert_eq!(run_jobs(&mut env, PROD).imported, 0, "nothing left to take");
}

/// `n` identities of `origin`, each with one message waiting in its inbox.
fn with_mail(env: &mut MemEnv, origin: u8, n: usize) -> Vec<IdentityInfo> {
    (0..n)
        .map(|i| {
            // The alias length seeds the keys: distinct for each identity.
            let me = create(env, origin, &"a".repeat(i + 1 + 10 * origin as usize));
            deliver(env, &me, &[sealed(&me, "hello")]);
            me
        })
        .collect()
}

fn reached(env: &mut MemEnv, ids: &[IdentityInfo]) -> usize {
    ids.iter()
        .filter(|me| !kept_ids(env, me.addr).is_empty())
        .count()
}

#[test]
fn a_page_run_does_not_move_the_rotation_of_a_later_identity() {
    let mut env = env();
    let ids = with_mail(&mut env, PROD, 6);
    with_mail(&mut env, OTHER, 1);
    // Node runs with a page for another origin, with one identity, between.
    for _ in 0..2 {
        wake(&mut env, "rescan");
        assert_eq!(run_jobs(&mut env, OTHER).scanned, 1);
    }
    assert_eq!(reached(&mut env, &ids), 6, "the shared rotation was kept");
}

#[test]
fn a_node_with_no_wake_ups_still_reaches_every_identity_of_a_page() {
    let mut env = env();
    let ids = with_mail(&mut env, PROD, 6);
    run_jobs(&mut env, PROD);
    assert_eq!(reached(&mut env, &ids), MAX_SCANS_PER_RUN);
    run_jobs(&mut env, PROD);
    assert_eq!(reached(&mut env, &ids), 6, "the next run took the rest");
}

#[test]
fn a_missing_inbox_outside_the_scan_slice_waits_out_its_backoff() {
    let mut env = env();
    let n = MAX_SCANS_PER_RUN + 2;
    for i in 0..n {
        create(&mut env, PROD, &format!("id{i}"));
    }
    let out = wake(&mut env, "v1watch");
    assert_eq!(subscribes(&out), n, "every inbox is asked for once");
    assert_eq!(gets(&out), MAX_SCANS_PER_RUN);
    for later in [10, MISSING_BACKOFF_FIRST_SECS - 1] {
        env.now = Some(NOW + later);
        let out = wake(&mut env, "v1watch");
        assert_eq!((gets(&out), subscribes(&out)), (0, 0), "at +{later}");
    }
    env.now = Some(NOW + MISSING_BACKOFF_FIRST_SECS);
    assert_eq!(subscribes(&wake(&mut env, "v1watch")), n, "asked again after");
}

#[test]
fn a_missing_inbox_with_the_duty_out_waits_out_its_backoff() {
    let mut env = env();
    create(&mut env, PROD, "alice");
    let mut budget = Budget::new(NOW);
    assert!(budget.take_duty(DUTY_BURST_MS));
    let body = to_cbor(&budget).unwrap();
    Space::new(&mut env, GLOBAL).put("bg/budget", &body).unwrap();
    let out = wake(&mut env, "v1watch");
    assert_eq!((gets(&out), subscribes(&out)), (0, 1), "nothing scanned");
    env.now = Some(NOW + 10);
    let out = wake(&mut env, "v1watch");
    assert_eq!((gets(&out), subscribes(&out)), (0, 0), "{out:?}");
}

#[test]
fn a_large_inbox_state_is_charged_by_its_size() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    let mut state = inbox_of(&[]);
    state.truncate(state.len() - 1);
    state.extend_from_slice(br#","pad":""#);
    state.extend(std::iter::repeat_n(b'x', 8 << 20));
    state.extend_from_slice(br#""}"#);
    env.contracts.insert(v1_inbox_id(&me.vk).unwrap(), state);
    wake(&mut env, "rescan");
    assert_eq!(
        duty_left(&mut env),
        DUTY_BURST_MS - SCAN_COST_MS - 8 * SCAN_MS_PER_MIB,
        "the flat cost and the size"
    );
}

#[test]
fn a_duplicate_notification_decrypts_nothing_and_is_charged_only_its_scan() {
    let mut env = env();
    let me = create(&mut env, PROD, "alice");
    deliver(&mut env, &me, &[sealed(&me, "one"), sealed(&me, "two")]);
    let id = v1_inbox_id(&me.vk).unwrap();
    process(&mut env, None, notification(id, vec![])).unwrap();
    assert_eq!(kept_ids(&mut env, me.addr).len(), 2);
    let after_import = duty_left(&mut env);
    assert!(after_import <= DUTY_BURST_MS - 2 * MESSAGE_COST_MS, "paid");
    let scan = SCAN_COST_MS + read_cost_ms(env.contracts[&id].len());
    for _ in 0..3 {
        process(&mut env, None, notification(id, vec![])).unwrap();
    }
    assert_eq!(
        duty_left(&mut env),
        after_import - 3 * scan,
        "a held message is skipped before it is decrypted"
    );
}

#[test]
fn a_message_the_page_could_not_read_is_not_kept_by_the_watch() {
    // The page's `DecryptedMessage` needs both `to` and `cc`: a message
    // without either is shown as unreadable, so it is not kept here.
    for missing in ["to", "cc"] {
        let mut env = env();
        let me = create(&mut env, PROD, "alice");
        let mut plain = serde_json::json!({
            "title": "bare",
            "content": "body",
            "from": "bob",
            "to": [],
            "cc": [],
            "time": "2026-11-02T10:00:00Z",
        });
        plain.as_object_mut().unwrap().remove(missing);
        let message = sealed_plain(&me, "bare", plain);
        deliver(&mut env, &me, std::slice::from_ref(&message));
        let run = run_jobs(&mut env, PROD);
        assert_eq!((run.imported, run.remaining), (0, 0), "no {missing}");
        assert!(kept_ids(&mut env, me.addr).is_empty(), "no {missing}");
    }
}

#[test]
fn a_page_run_does_not_use_up_the_operations_of_a_later_refresh() {
    let targets: Vec<Target> = (1..=10).map(|n| target(n, 1)).collect();
    let mut b = Budget::new(NOW - NOW % 60);
    for _ in 0..40 {
        plan(Trigger::RunJobs(Origin([1; 32])), &targets, &mut b);
    }
    let p = plan(Trigger::Tick(Tick::V1Watch), &targets, &mut b);
    assert_eq!(p.subscribe.len(), 10, "all of a page's runs were free");
}
