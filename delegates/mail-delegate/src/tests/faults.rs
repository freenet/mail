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

/// Seeds that broke an invariant while a key stayed unreadable.
const PINNED_BLIND_SEEDS: &[u64] = &[19, 38, 41, 46, 51, 270];

/// The same, found at other settings: (seed, ops, fault rate, blind rate).
const PINNED_BLIND_RUNS: &[(u64, usize, u32, u32)] = &[
    (596, 80, 60, 20),
    (1855, 80, 60, 20),
    (1871, 80, 60, 20),
    (1389, 80, 200, 100),
    // A deletion marker that could not be read or removed, reported gone.
    (1072, 80, 60, 20),
    // A delete of an unreadable contact answered Deleted while its removal
    // had been refused twice; the contact came back once it read again.
    (1284, 100, 60, 60),
    // An index created but left marked "may be absent", rebuilt from
    // nothing once it failed to read.
    (339, 80, 200, 100),
];

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
    /// Index entries left naming no record after healing: a leaked slot.
    /// Always an invariant failure; counted so the test reports it.
    leaks: u64,
    /// The first reply that brought back an identity whose approved
    /// deletion had started.
    undone: Option<String>,
    log: Vec<String>,
}

#[derive(Clone, Copy, Default)]
struct IdModel {
    generation: u64,
    deleting: bool,
    /// A step of the approved deletion answered `Continue`: it has
    /// certainly started, so nothing may bring the identity back.
    started: bool,
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
    /// The key that went persistently unreadable during the run, kept
    /// past `heal` (which turns the faults off).
    blinded: Option<Vec<u8>>,
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
        let seen = self.seen(out);
        if std::env::var_os("FAULT_TRACE").is_some() {
            eprintln!("  -> {}", describe(&seen));
        }
        seen
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
        // A started deletion whose finishing reply was lost: if neither the
        // record nor the deletion marker is stored any more, it finished,
        // and an import now is a fresh restore, which is allowed.
        if self
            .m
            .ids
            .get(&addr)
            .is_some_and(|i| i.started && !i.deleted)
        {
            let stored = rel_keys(&self.env);
            if !stored.contains_key(&store::identity_rel(&addr))
                && !stored.contains_key(&store::deleted_rel(&addr))
            {
                self.m.ids.get_mut(&addr).unwrap().deleted = true;
                for ((_, owner, _), possible) in self.m.items.iter_mut() {
                    if *owner == Some(addr) {
                        *possible = BTreeSet::from([None]);
                    }
                }
            }
        }
        if self
            .m
            .ids
            .get(&addr)
            .is_some_and(|i| i.started && !i.deleted)
        {
            // A restore (or a migration import) of an identity whose
            // approved deletion has started must be refused, whichever key
            // is unreadable: it would undo the deletion.
            self.m
                .log
                .push(format!("import mid-deletion {}", store::hex(&addr.0[..4])));
            let alias = format!("mid{}", self.rng.below(1000));
            if let Seen::Reply(Ok(reply)) = self.send(Op::ImportIdentity {
                source: ImportSource::Seeds { dsa, kem },
                kind: ImportKind::Migration,
                alias,
                description: String::new(),
            }) {
                self.m.undone.get_or_insert(format!(
                    "an import mid-deletion of {} answered {reply:?}",
                    store::hex(&addr.0[..4])
                ));
            }
            return;
        }
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
                Seen::Reply(Ok(Reply::Continue { .. })) => {
                    self.m.ids.get_mut(&addr).unwrap().started = true;
                    // Sometimes leave it there: the next page may try to
                    // bring it back before it finishes.
                    if self.rng.chance(3) {
                        break;
                    }
                }
                Seen::Lost => {}
                Seen::Reply(Err(f))
                    if f.code == FailureCode::Internal || f.code == FailureCode::Busy => {}
                _ => break,
            }
            if !self.m.ids[&addr].deleting {
                return;
            }
            seen = self.send(op.clone());
            if let Seen::Prompt(id) = seen {
                seen = self.answer(id, crate::consent::DELETE);
            }
        }
        // Left unfinished. A deletion listed as in progress has certainly
        // started (its record is marked), so nothing may bring it back.
        if let Seen::Reply(Ok(Reply::Identities(deleting))) = self.send(Op::ListDeletingIdentities)
            && deleting.iter().any(|i| i.addr == addr)
        {
            self.m.ids.get_mut(&addr).unwrap().started = true;
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
        self.blinded = self.env.faults.as_ref().and_then(|f| f.blinded());
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
        let Seen::Reply(Ok(Reply::Identities(mut listed))) = self.send(Op::ListIdentities) else {
            panic!("listing identities on a working host failed");
        };
        // An identity unlisted because its record was the unreadable key (a
        // create marker beside it made it look like a create that never
        // finished): the user restores it from its recovery key.
        let unlisted: Vec<Addr> = self
            .m
            .ids
            .iter()
            .filter(|(a, i)| !i.deleting && !listed.iter().any(|l| l.addr == **a))
            .map(|(a, _)| *a)
            .collect();
        for addr in unlisted {
            let Some((dsa, kem)) = self.m.seeds.iter().find(|(d, k)| {
                freenet_mail_protocol::address::address_of(
                    &crate::crypto::Keys::from_seeds(d, k).vk_bytes(),
                ) == addr
            }) else {
                continue;
            };
            let (dsa, kem) = (dsa.clone(), kem.clone());
            let alias = format!("restored{}", self.rng.below(100_000));
            if let Seen::Reply(Ok(Reply::Imported { identity, .. })) =
                self.send(Op::ImportIdentity {
                    source: ImportSource::Seeds { dsa, kem },
                    kind: ImportKind::UserRestore,
                    alias,
                    description: String::new(),
                })
            {
                listed.push(identity);
            }
        }
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
    let marker_of = |id: &[u8]| keys.get(&format!("dl/{}", store::hex(id))).cloned();
    // The one record allowed to be stored but unlisted is the one that was
    // unreadable during the run, when nothing could restore it (its keys
    // were never handed back): unusable anyway, and restorable by import.
    let blinded = run.blinded.clone();
    let blinded_rel = |rel: &str| blinded.as_deref() == Some(s.full_key(rel).as_slice());
    if let Some(id) = records.difference(&indexed).find(|id| {
        let addr = Addr(id.as_slice().try_into().unwrap());
        !blinded_rel(&store::identity_rel(&addr))
    }) {
        return Err(format!(
            "identity {} is stored but not listed",
            &store::hex(id)[..8]
        ));
    }
    let leaked: BTreeSet<Vec<u8>> = indexed.difference(&records).cloned().collect();
    if let Some(id) = leaked.iter().next() {
        return Err(format!(
            "index entry {} has no record (marker {:?}): a leaked slot",
            &store::hex(id)[..8],
            marker_of(id).map(|m| String::from_utf8_lossy(&m).into_owned())
        ));
    }
    // A marker may be left only where it licenses nothing (no entry), or
    // beside a tolerated leak.
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
    if let Some(undone) = &run.m.undone {
        return Err(undone.clone());
    }
    for (addr, i) in &run.m.ids {
        let hex = store::hex(&addr.0);
        // An approved deletion that certainly started is finished by the
        // next page; it never comes back as a live identity.
        if i.started && listed.contains(addr) {
            return Err(format!("the approved deletion of {} was undone", &hex[..8]));
        }
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
            if !ids.contains(&unhex(parts[3])) && !blinded_rel(k) {
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
                    run.m.leaks += 1;
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

/// Run one seed over transient faults; returns (faults injected, leaks).
fn run_seed(seed: u64, ops: usize, per_mille: u32) -> Result<(u64, u64), String> {
    run_seed_with(seed, ops, Faults::seeded(seed, per_mille), per_mille).map(|(i, _, l)| (i, l))
}

/// Run one seed over `faults`; returns (faults injected, misses observed,
/// tolerated slot leaks).
fn run_seed_with(
    seed: u64,
    ops: usize,
    faults: Faults,
    per_mille: u32,
) -> Result<(u64, u64, u64), String> {
    let mut run = Run {
        env: MemEnv {
            faults: Some(faults),
            ..MemEnv::default()
        },
        rng: Rng(seed.wrapping_mul(0xD1B5_4A32_D192_ED03) | 1),
        m: Model::default(),
        lose_reply: u64::from(per_mille),
        blinded: None,
    };
    for _ in 0..ops {
        run.step();
    }
    let injected = run.env.faults.as_ref().map_or(0, |f| f.injected.get());
    let observed = run.env.faults.as_ref().map_or(0, |f| f.observed.get());
    let blinded = run
        .env
        .faults
        .as_ref()
        .and_then(|f| f.blinded())
        .map(|k| String::from_utf8_lossy(&k).into_owned());
    run.heal();
    check(&mut run).map_err(|e| {
        format!(
            "seed {seed}: {e}\n  unreadable: {blinded:?}\n  ops: {}",
            run.m.log.join(", ")
        )
    })?;
    Ok((injected, observed, run.m.leaks))
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
    let mut leaks = 0;
    let mut failures = Vec::new();
    for seed in PINNED_SEEDS.iter().copied().chain(1..=seeds) {
        match run_seed(seed, ops, rate) {
            Ok((n, l)) => {
                injected += n;
                leaks += l;
            }
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
    // A create that never finished frees its slot on the next listing, at
    // every fault rate.
    assert_eq!(leaks, 0, "{leaks} index slots leaked");
}

/// One present key at a time goes persistently unreadable (freenet-core
/// reports a file it cannot read or decrypt as "not found", every time),
/// on top of the transient faults. The delegate need not serve that key,
/// but must never overwrite, unlist, leak or reuse anything because of it.
/// Persistent misses are visible to the code (no re-read hides them), so
/// the run also checks that the code really saw them.
#[test]
fn invariants_hold_while_a_key_stays_unreadable() {
    let seeds = env_or("FAULT_SEEDS", 300);
    let ops = env_or("FAULT_OPS", 60) as usize;
    let rate = env_or("FAULT_RATE", 60) as u32;
    let blind = env_or("FAULT_BLIND_RATE", 20) as u32;
    let mut observed = 0;
    let mut failures = Vec::new();
    let runs = PINNED_BLIND_RUNS.iter().copied().chain(
        PINNED_BLIND_SEEDS
            .iter()
            .copied()
            .chain(1..=seeds)
            .map(|seed| (seed, ops, rate, blind)),
    );
    for (seed, ops, rate, blind) in runs {
        let faults = Faults::seeded_with_blindness(seed, rate, blind);
        match run_seed_with(seed, ops, faults, rate) {
            Ok((_, o, _)) => observed += o,
            Err(e) => failures.push(e),
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} seeds broke an invariant:\n{}",
        failures.len(),
        seeds as usize + PINNED_BLIND_SEEDS.len(),
        failures
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(
        observed > seeds,
        "only {observed} unreadable reads observed"
    );
}

/// A create's marker that could not be cleaned up (left `c`, or `s` once
/// spent), beside a record that keeps failing to read, licenses nothing: a
/// deletion still asks the user, and no listing unlists the identity. Only
/// an approved deletion's own marker (`d`) does either.
#[test]
fn a_create_marker_beside_an_unreadable_record_licenses_nothing() {
    for leftover in [store::MARKER_CREATING, store::MARKER_SPENT] {
        let mut run = Run {
            env: MemEnv::default(),
            rng: Rng(7),
            m: Model::default(),
            lose_reply: 0,
            blinded: None,
        };
        let ui_entropy = run.entropy();
        let Seen::Reply(Ok(Reply::CreatedIdentity {
            identity,
            recovery_key,
        })) = run.send(Op::CreateIdentity {
            alias: "x3".into(),
            description: String::new(),
            ui_entropy,
        })
        else {
            panic!("create failed on a perfect host");
        };
        let addr = identity.addr;
        let full = |rel: &str| {
            String::from_utf8(Space::new(&mut MemEnv::default(), Origin([PROD; 32])).full_key(rel))
                .unwrap()
        };
        run.env.secrets.insert(
            full(&store::deleted_rel(&addr)).into_bytes(),
            leftover.to_vec(),
        );
        run.env.faults = Some(Faults::blind(&full(&store::identity_rel(&addr))));
        // A listing prunes recordless entries: this one must stay.
        run.send(Op::ListDeletingIdentities);
        // The deletion must ask, not finish on the marker's say-so.
        let seen = run.send(Op::DeleteIdentity {
            addr,
            expected_gen: identity.generation,
        });
        assert!(
            !matches!(seen, Seen::Reply(Ok(Reply::Deleted))),
            "{leftover:?}: deleted without asking: {}",
            describe(&seen)
        );
        if leftover == store::MARKER_CREATING {
            // A create marker beside an absent record is a create that never
            // finished, and a listing frees its slot. The one case that
            // misreads (this one: the record is only unreadable) must stay
            // recoverable: importing the keys again restores it, even while
            // the record still cannot be read.
            let seen = run.send(Op::ImportIdentity {
                source: ImportSource::RecoveryKey(recovery_key.clone()),
                kind: ImportKind::UserRestore,
                alias: "x3".into(),
                description: String::new(),
            });
            assert!(
                matches!(seen, Seen::Reply(Ok(Reply::Imported { .. }))),
                "re-import while unreadable: {}",
                describe(&seen)
            );
        }
        run.env.faults = None;
        let Seen::Reply(Ok(Reply::Identities(listed))) = run.send(Op::ListIdentities) else {
            panic!("listing failed on a working host");
        };
        assert!(
            listed.iter().any(|i| i.addr == addr),
            "{leftover:?}: the identity was unlisted"
        );
    }
}

/// Re-run one seed of the unreadable-key run (`FAULT_SEED=n`, with
/// `FAULT_TRACE=1` to print every reply). Passes when no seed is given.
#[test]
fn replay_one_unreadable_key_seed() {
    let Some(seed) = std::env::var("FAULT_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
    else {
        return;
    };
    let rate = env_or("FAULT_RATE", 60) as u32;
    let blind = env_or("FAULT_BLIND_RATE", 20) as u32;
    let ops = env_or("FAULT_OPS", 60) as usize;
    run_seed_with(
        seed,
        ops,
        Faults::seeded_with_blindness(seed, rate, blind),
        rate,
    )
    .unwrap();
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
        blinded: None,
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
