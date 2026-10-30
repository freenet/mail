//! Host faults: seeded random runs of the delegate's operations over a host
//! that misses reads, refuses writes and removals, and loses replies, then
//! invariants checked with the faults off.
//!
//! Every review round of the delegate and its UI found another bug of one
//! class: an outcome the host cannot report (a failed read looks like an
//! absent key; a write or a reply may or may not have landed) treated as
//! success, failure or absence. These runs make that class testable.
//!
//! `FAULT_SEEDS` (default 300), `FAULT_OPS` (default 60 per seed) and
//! `FAULT_RATE` (default 60 per thousand calls, for each fault) widen
//! a run; a failing seed is printed and belongs in `PINNED_SEEDS`.

use std::collections::{BTreeMap, BTreeSet};

use freenet_mail_protocol::{Entropy, Failure, Item, Request};
use freenet_stdlib::prelude::DelegateError;

use super::*;
use crate::env::mem::{FaultOp, Faults};
use crate::handlers::DELETE_STEP;

/// Seeds that once broke an invariant, kept as regression cases.
const PINNED_SEEDS: &[u64] = &[1, 2, 3, 4, 5, 10, 29, 43, 129, 162, 203];

const KINDS: [ItemKind; 5] = [
    ItemKind::Draft,
    ItemKind::Sent,
    ItemKind::Kept,
    ItemKind::Flags,
    ItemKind::Contact,
];

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn chance(&mut self, per_mille: u64) -> bool {
        self.below(1000) < per_mille
    }
}

/// What the client can know of one stored value: every value it might
/// hold (`None` = absent), given the replies the client actually got.
type Possible = BTreeSet<Option<Vec<u8>>>;

#[derive(Default)]
struct Model {
    /// Identities the client knows: address -> (last known generation,
    /// whether a deletion may have started, whether it was confirmed deleted).
    ids: BTreeMap<Addr, IdModel>,
    seeds: Vec<(DsaSeed, KemSeed)>,
    items: BTreeMap<(ItemKind, Option<Addr>, Vec<u8>), Possible>,
    /// Every generation the delegate handed out, to catch reuse.
    generations: Vec<u64>,
    log: Vec<String>,
}

#[derive(Clone, Copy, Default)]
struct IdModel {
    generation: u64,
    deleting: bool,
    deleted: bool,
}

/// A host call's outcome as the client saw it.
enum Seen {
    Reply(Result<Reply, Failure>),
    /// The reply was lost (or the delegate errored): the op may or may not
    /// have run.
    Lost,
    Prompt(u32),
}

struct Run {
    env: MemEnv,
    rng: Rng,
    m: Model,
    lose_reply: u64,
}

impl Run {
    fn send(&mut self, op: Op) -> Seen {
        let req = Request {
            version: PROTOCOL_VERSION,
            request_id: RequestId([0x5a; 16]),
            op,
        };
        let msg =
            InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(to_cbor(&req).unwrap()));
        let out = process(&mut self.env, app(PROD), msg);
        self.seen(out)
    }

    fn answer(&mut self, prompt_id: u32, choice: &[u8]) -> Seen {
        let resp = UserInputResponse {
            request_id: prompt_id,
            response: ClientResponse::new(choice.to_vec()),
            context: DelegateContext::default(),
        };
        let out = process(
            &mut self.env,
            app(PROD),
            InboundDelegateMsg::UserResponse(resp),
        );
        self.seen(out)
    }

    fn seen(&mut self, out: Result<Vec<OutboundDelegateMsg>, DelegateError>) -> Seen {
        let Ok(out) = out else {
            return Seen::Lost;
        };
        if let Some(p) = out.iter().find_map(|m| match m {
            OutboundDelegateMsg::RequestUserInput(r) => Some(r.request_id),
            _ => None,
        }) {
            return Seen::Prompt(p);
        }
        let rs = responses(&out);
        assert!(rs.len() <= 1, "more than one response: {out:?}");
        let Some(r) = rs.into_iter().next() else {
            return Seen::Lost;
        };
        if self.rng.chance(self.lose_reply) {
            return Seen::Lost;
        }
        if let Ok(reply) = &r.result {
            self.note_generations(reply);
        }
        Seen::Reply(r.result)
    }

    fn note_generations(&mut self, reply: &Reply) {
        let gens: Vec<u64> = match reply {
            Reply::Ack { generation } => vec![*generation],
            Reply::CreatedIdentity { identity, .. } => vec![identity.generation],
            Reply::Imported {
                identity,
                already_present: false,
            } => vec![identity.generation],
            _ => vec![],
        };
        self.m.generations.extend(gens);
    }

    fn entropy(&mut self) -> Entropy {
        let mut e = [0u8; 32];
        for chunk in e.chunks_mut(8) {
            chunk.copy_from_slice(&self.rng.next().to_le_bytes());
        }
        e[0] |= 1;
        Entropy(e)
    }

    fn live_ids(&self) -> Vec<Addr> {
        self.m
            .ids
            .iter()
            .filter(|(_, i)| !i.deleting && !i.deleted)
            .map(|(a, _)| *a)
            .collect()
    }

    fn pick<T: Clone>(&mut self, v: &[T]) -> Option<T> {
        (!v.is_empty()).then(|| v[self.rng.below(v.len() as u64) as usize].clone())
    }

    fn step(&mut self) {
        match self.rng.below(100) {
            0..=5 => self.create(),
            6..=9 => self.rename(),
            10..=13 => self.delete_identity(),
            14..=17 => self.import(),
            18..=59 => self.put_item(),
            60..=74 => self.delete_item(),
            75..=89 => self.read_items(),
            _ => self.list_identities(),
        }
    }

    fn create(&mut self) {
        if self.live_ids().len() >= 4 {
            return;
        }
        let alias = format!("id{}", self.rng.below(1000));
        let ui_entropy = self.entropy();
        self.m.log.push(format!("create {alias}"));
        if let Seen::Reply(Ok(Reply::CreatedIdentity {
            identity,
            recovery_key,
        })) = self.send(Op::CreateIdentity {
            alias,
            description: String::new(),
            ui_entropy,
        }) {
            self.m
                .seeds
                .push(recovery_key::decode(&recovery_key).unwrap());
            self.m.ids.insert(
                identity.addr,
                IdModel {
                    generation: identity.generation,
                    ..IdModel::default()
                },
            );
        }
    }

    fn import(&mut self) {
        let Some((dsa, kem)) = self.pick(&self.m.seeds.clone()) else {
            return;
        };
        let addr = freenet_mail_protocol::address::address_of(
            &crate::crypto::Keys::from_seeds(&dsa, &kem).vk_bytes(),
        );
        if self
            .m
            .ids
            .get(&addr)
            .is_some_and(|i| i.deleting && !i.deleted)
        {
            return;
        }
        self.m
            .log
            .push(format!("import {}", store::hex(&addr.0[..4])));
        // Until a reply says otherwise, the import may or may not have
        // brought a deleted identity back.
        if self.m.ids.get(&addr).is_some_and(|i| i.deleted) {
            self.m.ids.remove(&addr);
        }
        let alias = format!("re{}", self.rng.below(1000));
        if let Seen::Reply(Ok(Reply::Imported { identity, .. })) = self.send(Op::ImportIdentity {
            source: ImportSource::Seeds { dsa, kem },
            kind: ImportKind::UserRestore,
            alias,
            description: String::new(),
        }) {
            self.m.ids.insert(
                identity.addr,
                IdModel {
                    generation: identity.generation,
                    ..IdModel::default()
                },
            );
        }
    }

    fn rename(&mut self) {
        let Some(addr) = self.pick(&self.live_ids()) else {
            return;
        };
        let expected_gen = self.m.ids[&addr].generation;
        let alias = format!("rn{}", self.rng.below(1000));
        self.m
            .log
            .push(format!("rename {}", store::hex(&addr.0[..4])));
        match self.send(Op::UpdateIdentity {
            addr,
            alias,
            description: String::new(),
            expected_gen,
        }) {
            Seen::Reply(Ok(Reply::Ack { generation })) => {
                self.m.ids.get_mut(&addr).unwrap().generation = generation;
            }
            _ => self.refresh_generation(addr),
        }
    }

    fn refresh_generation(&mut self, addr: Addr) {
        if let Seen::Reply(Ok(Reply::Identities(list))) = self.send(Op::ListIdentities)
            && let Some(i) = list.iter().find(|i| i.addr == addr)
        {
            self.m.ids.get_mut(&addr).unwrap().generation = i.generation;
        }
    }

    fn may_delete_items_of(&mut self, addr: Addr) {
        for ((_, owner, _), possible) in self.m.items.iter_mut() {
            if *owner == Some(addr) {
                possible.insert(None);
            }
        }
    }

    fn delete_identity(&mut self) {
        let candidates: Vec<Addr> = self
            .m
            .ids
            .iter()
            .filter(|(_, i)| !i.deleted)
            .map(|(a, _)| *a)
            .collect();
        let Some(addr) = self.pick(&candidates) else {
            return;
        };
        self.m
            .log
            .push(format!("delete {}", store::hex(&addr.0[..4])));
        let op = Op::DeleteIdentity {
            addr,
            expected_gen: self.m.ids[&addr].generation,
        };
        let mut seen = self.send(op.clone());
        if let Seen::Prompt(id) = seen {
            // Once answered, the deletion may have started.
            self.m.ids.get_mut(&addr).unwrap().deleting = true;
            self.may_delete_items_of(addr);
            seen = self.answer(id, crate::consent::DELETE);
        }
        for _ in 0..6 {
            match seen {
                Seen::Reply(Ok(Reply::Deleted)) => {
                    let i = self.m.ids.get_mut(&addr).unwrap();
                    i.deleting = true;
                    i.deleted = true;
                    for ((_, owner, _), possible) in self.m.items.iter_mut() {
                        if *owner == Some(addr) {
                            *possible = BTreeSet::from([None]);
                        }
                    }
                    return;
                }
                Seen::Reply(Ok(Reply::Continue { .. })) | Seen::Lost => {}
                Seen::Reply(Err(f))
                    if f.code == FailureCode::Internal || f.code == FailureCode::Busy => {}
                _ => return,
            }
            if !self.m.ids[&addr].deleting {
                return;
            }
            seen = self.send(op.clone());
            if let Seen::Prompt(id) = seen {
                seen = self.answer(id, crate::consent::DELETE);
            }
        }
    }

    fn owner_for(&mut self, kind: ItemKind) -> Option<Option<Addr>> {
        if store::shape(kind).0 {
            self.pick(&self.live_ids()).map(Some)
        } else {
            Some(None)
        }
    }

    fn item_ref(&mut self, kind: ItemKind, owner: Option<Addr>) -> ItemRef {
        let (_, len) = store::shape(kind);
        let n = self.rng.below(4) as u8 + 1;
        ItemRef {
            kind,
            owner,
            id: vec![n; len],
        }
    }

    fn current_gen(&mut self, item: &ItemRef) -> Option<Option<u64>> {
        match self.send(Op::GetItem { item: item.clone() }) {
            Seen::Reply(Ok(Reply::Item(found))) => Some(found.map(|i: Item| i.generation)),
            _ => None,
        }
    }

    fn put_item(&mut self) {
        let kind = KINDS[self.rng.below(KINDS.len() as u64) as usize];
        let Some(owner) = self.owner_for(kind) else {
            return;
        };
        let item = self.item_ref(kind, owner);
        let Some(current) = self.current_gen(&item) else {
            return;
        };
        let body = format!("b{}", self.rng.below(1_000_000)).into_bytes();
        self.m.log.push(format!("put {kind:?} {:?}", item.id[0]));
        let key = (kind, owner, item.id.clone());
        let seen = self.send(Op::PutItem {
            item,
            body: ByteBuf::from(body.clone()),
            expected_gen: current.or(Some(0)),
        });
        let possible = self
            .m
            .items
            .entry(key)
            .or_insert_with(|| BTreeSet::from([None]));
        match seen {
            Seen::Reply(Ok(Reply::Ack { .. })) => *possible = BTreeSet::from([Some(body)]),
            Seen::Reply(Err(f)) if f.code != FailureCode::Internal => {}
            _ => {
                possible.insert(Some(body));
            }
        }
    }

    fn delete_item(&mut self) {
        let kind = KINDS[self.rng.below(KINDS.len() as u64) as usize];
        let Some(owner) = self.owner_for(kind) else {
            return;
        };
        let item = self.item_ref(kind, owner);
        let Some(Some(expected_gen)) = self.current_gen(&item) else {
            return;
        };
        self.m
            .log
            .push(format!("delete-item {kind:?} {:?}", item.id[0]));
        let key = (kind, owner, item.id.clone());
        let seen = self.send(Op::DeleteItem { item, expected_gen });
        let possible = self
            .m
            .items
            .entry(key)
            .or_insert_with(|| BTreeSet::from([None]));
        match seen {
            Seen::Reply(Ok(Reply::Deleted)) => *possible = BTreeSet::from([None]),
            Seen::Reply(Err(f)) if f.code != FailureCode::Internal => {}
            _ => {
                possible.insert(None);
            }
        }
    }

    fn read_items(&mut self) {
        let kind = KINDS[self.rng.below(KINDS.len() as u64) as usize];
        if let Some(owner) = self.owner_for(kind) {
            self.send(Op::ListItems {
                kind,
                owner,
                after: None,
                limit: 256,
            });
        }
    }

    fn list_identities(&mut self) {
        if self.rng.chance(500) {
            self.send(Op::ListDeletingIdentities);
        } else {
            self.send(Op::ListIdentities);
        }
    }

    /// What a page does on its next load, with a working host: finish
    /// deletions it can, list everything.
    fn heal(&mut self) {
        self.env.faults = None;
        self.lose_reply = 0;
        if let Seen::Reply(Ok(Reply::Identities(deleting))) = self.send(Op::ListDeletingIdentities)
        {
            for i in deleting {
                for _ in 0..(1 + 2 * 4096 / DELETE_STEP) {
                    match self.send(Op::DeleteIdentity {
                        addr: i.addr,
                        expected_gen: i.generation,
                    }) {
                        Seen::Reply(Ok(Reply::Continue { .. })) => {}
                        Seen::Reply(Ok(Reply::Deleted)) => {
                            let m = self.m.ids.entry(i.addr).or_default();
                            m.deleting = true;
                            m.deleted = true;
                            for ((_, owner, _), possible) in self.m.items.iter_mut() {
                                if *owner == Some(i.addr) {
                                    *possible = BTreeSet::from([None]);
                                }
                            }
                            break;
                        }
                        other => panic!("finishing a deletion: {}", describe(&other)),
                    }
                }
            }
        }
        let Seen::Reply(Ok(Reply::Identities(listed))) = self.send(Op::ListIdentities) else {
            panic!("listing identities on a working host failed");
        };
        for i in &listed {
            for kind in KINDS.iter().filter(|k| store::shape(**k).0) {
                self.send(Op::ListItems {
                    kind: *kind,
                    owner: Some(i.addr),
                    after: None,
                    limit: 256,
                });
            }
        }
        self.send(Op::ListItems {
            kind: ItemKind::Contact,
            owner: None,
            after: None,
            limit: 256,
        });
    }
}

fn describe(s: &Seen) -> String {
    match s {
        Seen::Reply(r) => format!("{r:?}"),
        Seen::Lost => "lost".into(),
        Seen::Prompt(_) => "prompt".into(),
    }
}

/// The relative keys of the production namespace.
fn rel_keys(env: &MemEnv) -> BTreeMap<String, Vec<u8>> {
    let ns = store::namespace(&Origin([PROD; 32]));
    env.secrets
        .iter()
        .filter_map(|(k, v)| {
            let k = String::from_utf8_lossy(k);
            k.strip_prefix(ns.as_str())
                .map(|r| (r.to_string(), v.clone()))
        })
        .collect()
}

fn check(run: &mut Run) -> Result<(), String> {
    let env = run.env.clone();
    let keys = rel_keys(&env);
    let mut e = env.clone();
    let s = Space::new(&mut e, Origin([PROD; 32]));
    let (_, indexed) = s
        .index(store::IDENTITY_INDEX)
        .map_err(|f| format!("{f:?}"))?;
    let records: BTreeSet<Vec<u8>> = keys
        .keys()
        .filter_map(|k| k.strip_prefix("id/"))
        .map(unhex)
        .collect();
    // No private key without an index entry, no index entry without a
    // record (a slot is never leaked).
    if records != indexed {
        return Err(format!(
            "identity records {} vs index entries {}",
            records.len(),
            indexed.len()
        ));
    }
    // A marker may be left only where it licenses nothing (no entry).
    if let Some(h) = keys
        .keys()
        .filter_map(|k| k.strip_prefix("dl/"))
        .find(|h| indexed.contains(&unhex(h)))
    {
        return Err(format!("a marker outlived its create or deletion: {h}"));
    }
    let listed: BTreeSet<Addr> = match run.send(Op::ListIdentities) {
        Seen::Reply(Ok(Reply::Identities(l))) => l.into_iter().map(|i| i.addr).collect(),
        other => return Err(format!("list: {}", describe(&other))),
    };
    for (addr, i) in &run.m.ids {
        let hex = store::hex(&addr.0);
        if i.deleted {
            if let Some(k) = keys.keys().find(|k| k.contains(&hex)) {
                return Err(format!("a deleted identity left {k}"));
            }
        } else if !i.deleting && !listed.contains(addr) {
            return Err(format!("identity {} is no longer listed", &hex[..8]));
        }
    }
    // Every item is indexed under a stored owner, and every index entry
    // names a stored item.
    for kind in KINDS {
        let tag = store::kind_tag(kind);
        for (k, _) in keys
            .iter()
            .filter(|(k, _)| k.starts_with(&format!("it/{tag}/")))
        {
            let parts: Vec<&str> = k.split('/').collect();
            let owner = (parts[2] != "-").then(|| Addr(unhex(parts[2]).try_into().unwrap()));
            if let Some(o) = &owner
                && !records.contains(o.0.as_slice())
            {
                return Err(format!("{k} outlived its identity"));
            }
            let (_, ids) = s
                .index(&store::index_rel(kind, owner.as_ref()))
                .map_err(|f| format!("{f:?}"))?;
            if !ids.contains(&unhex(parts[3])) {
                return Err(format!("{k} is not in its index"));
            }
        }
        for (k, _) in keys
            .iter()
            .filter(|(k, _)| k.starts_with(&format!("ix/{tag}/")))
        {
            let owner_hex = k.rsplit('/').next().unwrap();
            let (_, ids) = s.index(k).map_err(|f| format!("{f:?}"))?;
            for id in ids {
                let item = format!("it/{tag}/{owner_hex}/{}", store::hex(&id));
                if !keys.contains_key(&item) {
                    return Err(format!("{k} names {item}, which is not stored"));
                }
            }
        }
    }
    // No acknowledged write lost, no acknowledged delete undone.
    for ((kind, owner, id), possible) in &run.m.items {
        let rel = store::item_rel(&ItemRef {
            kind: *kind,
            owner: *owner,
            id: id.clone(),
        });
        let stored = s
            .read(&rel)
            .map_err(|f| format!("{f:?}"))?
            .map(|(_, body)| body);
        if !possible.contains(&stored) {
            return Err(format!(
                "{rel} holds {:?}, which no reply allowed",
                stored.map(|b| String::from_utf8_lossy(&b).into_owned())
            ));
        }
    }
    // A generation is never handed out twice.
    let mut seen = BTreeSet::new();
    for g in &run.m.generations {
        if !seen.insert(*g) {
            return Err(format!("generation {g} was handed out twice"));
        }
    }
    Ok(())
}

fn unhex(h: &str) -> Vec<u8> {
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

fn run_seed(seed: u64, ops: usize, per_mille: u32) -> Result<u64, String> {
    let mut run = Run {
        env: MemEnv {
            faults: Some(Faults::seeded(seed, per_mille)),
            ..MemEnv::default()
        },
        rng: Rng(seed.wrapping_mul(0xD1B5_4A32_D192_ED03) | 1),
        m: Model::default(),
        lose_reply: u64::from(per_mille),
    };
    for _ in 0..ops {
        run.step();
    }
    let injected = run.env.faults.as_ref().map_or(0, |f| f.injected.get());
    run.heal();
    check(&mut run).map_err(|e| format!("seed {seed}: {e}\n  ops: {}", run.m.log.join(", ")))?;
    Ok(injected)
}

fn env_or(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[test]
fn invariants_hold_over_a_host_that_misses_reads_and_refuses_writes() {
    let seeds = env_or("FAULT_SEEDS", 300);
    let ops = env_or("FAULT_OPS", 60) as usize;
    let rate = env_or("FAULT_RATE", 60) as u32;
    let mut injected = 0;
    let mut failures = Vec::new();
    for seed in PINNED_SEEDS.iter().copied().chain(1..=seeds) {
        match run_seed(seed, ops, rate) {
            Ok(n) => injected += n,
            Err(e) => failures.push(e),
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} seeds broke an invariant:\n{}",
        failures.len(),
        seeds as usize + PINNED_SEEDS.len(),
        failures
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    // The faults really fired.
    assert!(injected > seeds, "only {injected} faults injected");
}

/// The same runs over a perfect host: the model and the checks agree with
/// the delegate when nothing fails.
#[test]
fn invariants_hold_over_a_perfect_host() {
    for seed in 1..=40 {
        run_seed(seed, 60, 0).unwrap();
    }
}

/// The checks themselves catch what they claim to: a store with a
/// recordless identity index entry fails them.
#[test]
fn the_invariant_check_fails_on_a_leaked_identity_slot() {
    let mut run = Run {
        env: MemEnv::default(),
        rng: Rng(7),
        m: Model::default(),
        lose_reply: 0,
    };
    run.create();
    let addr = *run.m.ids.keys().next().unwrap();
    let key = Space::new(&mut run.env, Origin([PROD; 32])).full_key(&store::identity_rel(&addr));
    run.env.secrets.remove(&key);
    assert!(check(&mut run).is_err());
}

#[test]
fn a_targeted_rule_fails_exactly_the_nth_matching_call() {
    let env = MemEnv {
        faults: Some(Faults::rule(FaultOp::GetMiss, "x", 2)),
        secrets: BTreeMap::from([(b"x".to_vec(), b"1".to_vec())]),
        ..MemEnv::default()
    };
    use crate::env::Env;
    assert!(env.get(b"x").is_some());
    assert!(env.get(b"x").is_none());
    // The immediate re-read of a key that just missed succeeds.
    assert!(env.get(b"x").is_some());
}
