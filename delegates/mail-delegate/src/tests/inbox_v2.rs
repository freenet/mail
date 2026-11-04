//! Inbox v2 interop: states, updates and messages the delegate builds, run
//! through the merged contract crate's own `validate_state` and merge, and the
//! states the contract returns read back by the delegate.

use std::collections::BTreeMap;

use freenet_email_inbox_v2::merge::Rules;
use freenet_email_inbox_v2::{Params, apply, is_valid};
use freenet_mail_protocol::inbox_v2::{self as w, InboxDelta, InboxState};
use freenet_mail_protocol::{
    Addr, Entropy, FailureCode, Hash32, InboxV2Update, ItemKind, ItemRef, Op, OwnerChange, PassId,
    Reply, SealContent, SealedV2, SendAdmission, SendNotice, from_cbor,
};
use freenet_stdlib::prelude::{StateDelta, UpdateData};
use serde_bytes::ByteBuf;

use super::{PROD, call, create};
use crate::env::mem::{Faults, MemEnv};
use crate::inbox_v2::{self, InboxRecord, LedgerEntry};
use crate::store::{Origin, Space, item_rel};

const MASTER: [u8; 32] = [0x42; 32];
pub const DAY: u64 = 86_400;
/// 2026-11-03, a little after midnight.
pub const START: u64 = 1_793_664_123;

#[derive(Clone)]
pub struct World {
    pub env: MemEnv,
    /// Each inbox's state as the network holds it.
    pub inboxes: BTreeMap<Addr, Vec<u8>>,
    entropy: u8,
    /// The Ghost Key master in every inbox's parameters.
    pub master: [u8; 32],
    /// Identities kept under another origin than `PROD`: a second node, in
    /// effect, when the store is split by origin.
    pub origins: BTreeMap<Addr, u8>,
}

impl World {
    pub fn new() -> Self {
        Self::with_master(MASTER)
    }

    pub fn with_master(master: [u8; 32]) -> Self {
        World {
            env: MemEnv {
                now: Some(START),
                ..MemEnv::default()
            },
            inboxes: BTreeMap::new(),
            entropy: 0,
            master,
            origins: BTreeMap::new(),
        }
    }

    pub fn params(&self, addr: &Addr) -> Params {
        Params {
            addr: addr.0,
            ghost_master: self.master,
        }
    }

    pub fn entropy(&mut self) -> Entropy {
        // Never all zeros, which the delegate refuses.
        self.entropy = self.entropy.checked_add(1).unwrap_or(1);
        Entropy([self.entropy; 32])
    }

    pub fn advance(&mut self, secs: u64) {
        self.env.now = Some(self.env.now.unwrap() + secs);
    }

    pub fn origin(&self, addr: &Addr) -> u8 {
        self.origins.get(addr).copied().unwrap_or(PROD)
    }

    /// `op`, as the page of `who`'s origin sends it.
    pub fn call_as(&mut self, who: &Addr, op: Op) -> Result<Reply, FailureCode> {
        let origin = self.origin(who);
        call(&mut self.env, origin, op)
    }

    /// A new identity with its inbox published.
    pub fn identity(&mut self, alias: &str) -> Addr {
        self.identity_in(alias, PROD)
    }

    pub fn identity_in(&mut self, alias: &str, origin: u8) -> Addr {
        let addr = create(&mut self.env, origin, alias).addr;
        self.origins.insert(addr, origin);
        let Ok(Reply::InboxV2State(state)) = call(
            &mut self.env,
            origin,
            Op::CreateInboxV2 {
                addr,
                ghost_master: Hash32(self.master),
                existing: None,
            },
        ) else {
            panic!("create inbox");
        };
        assert!(
            is_valid(&Rules::V1, &self.params(&addr), &state),
            "the contract refuses the first state"
        );
        self.inboxes.insert(addr, state.into_vec());
        addr
    }

    pub fn state(&self, addr: &Addr) -> InboxState {
        w::decode(&self.inboxes[addr]).unwrap()
    }

    /// The contract's merge of `delta` into `addr`'s inbox. The result must be
    /// a valid state, as the network would hold it.
    pub fn publish(&mut self, addr: &Addr, delta: &[u8]) {
        let merged = apply(
            &Rules::V1,
            &self.params(addr),
            &self.inboxes[addr],
            vec![UpdateData::Delta(StateDelta::from(delta.to_vec()))],
        )
        .expect("the contract accepts the update");
        assert!(
            is_valid(&Rules::V1, &self.params(addr), &merged),
            "merged state is invalid"
        );
        self.inboxes.insert(*addr, merged);
    }

    pub fn update(
        &mut self,
        addr: &Addr,
        change: OwnerChange,
    ) -> Result<InboxV2Update, FailureCode> {
        let ui_entropy = self.entropy();
        let state = ByteBuf::from(self.inboxes[addr].clone());
        match self.call_as(
            addr,
            Op::UpdateInboxV2 {
                addr: *addr,
                state,
                change,
                ui_entropy,
            },
        )? {
            Reply::InboxV2Update(u) => Ok(u),
            other => panic!("{other:?}"),
        }
    }

    /// Sign `change` (draining first until nothing is left) and publish it.
    pub fn change(&mut self, addr: &Addr, change: OwnerChange) {
        loop {
            let u = self.update(addr, change.clone()).expect("update");
            if let Some(delta) = &u.update {
                self.publish(addr, delta);
            }
            if u.remaining == 0 {
                return;
            }
        }
    }

    pub fn seal(&mut self, from: &Addr, to: &Addr, text: &str) -> Result<SealedV2, FailureCode> {
        let ui_entropy = self.entropy();
        match self.call_as(
            from,
            Op::SealV2 {
                from: *from,
                to: *to,
                to_state: ByteBuf::from(self.inboxes[to].clone()),
                content: SealContent::Mail(ByteBuf::from(text.as_bytes().to_vec())),
                ghost_vk: None,
                ui_entropy,
                reseals: 0,
            },
        )? {
            Reply::SealedV2(s) => Ok(s),
            other => panic!("{other:?}"),
        }
    }

    /// Seal, publish through the contract, and say whether it landed.
    pub fn send(&mut self, from: &Addr, to: &Addr, text: &str) -> (SealedV2, bool) {
        let sealed = self.seal(from, to, text).expect("seal");
        let message: w::Message = w::decode(&sealed.message).unwrap();
        let delta = InboxDelta {
            messages: BTreeMap::from([(serde_bytes::ByteArray::new(sealed.id.0), message)]),
            ..InboxDelta::default()
        };
        self.publish(to, &w::encode(&delta));
        let landed = w::delivered(&self.state(to), &sealed.id.0);
        (sealed, landed)
    }

    pub fn inbound(&mut self, owner: &Addr) -> Vec<w::InboundMessage> {
        let Ok(Reply::Items { items, .. }) = self.call_as(
            owner,
            Op::ListItems {
                kind: ItemKind::Inbound,
                owner: Some(*owner),
                after: None,
                limit: 256,
            },
        ) else {
            panic!("list inbound");
        };
        items.iter().map(|i| from_cbor(&i.body).unwrap()).collect()
    }

    pub fn issue(&mut self, addr: &Addr, contact: Option<Addr>, invite: Option<u8>) -> w::Pass {
        let ui_entropy = self.entropy();
        match self.call_as(
            addr,
            Op::IssuePass {
                addr: *addr,
                contact,
                invite,
                ui_entropy,
            },
        ) {
            Ok(Reply::PassIssued(p)) => p,
            other => panic!("{other:?}"),
        }
    }

    pub fn record(&mut self, addr: &Addr) -> InboxRecord {
        let Ok(Reply::Item(Some(item))) = self.call_as(
            addr,
            Op::GetItem {
                item: ItemRef {
                    kind: ItemKind::InboxV2,
                    owner: Some(*addr),
                    id: Vec::new(),
                },
            },
        ) else {
            panic!("record");
        };
        from_cbor(&item.body).unwrap()
    }

    pub fn ledger(&mut self, addr: &Addr, pass_id: &[u8]) -> LedgerEntry {
        let Ok(Reply::Item(Some(item))) = self.call_as(
            addr,
            Op::GetItem {
                item: ItemRef {
                    kind: ItemKind::PassLedger,
                    owner: Some(*addr),
                    id: pass_id.to_vec(),
                },
            },
        ) else {
            panic!("ledger");
        };
        from_cbor(&item.body).unwrap()
    }
}

pub fn texts(list: &[w::InboundMessage]) -> Vec<String> {
    let mut out: Vec<String> = list
        .iter()
        .map(|m| String::from_utf8(m.body.to_vec()).unwrap())
        .collect();
    out.sort();
    out
}

/// The whole round through the contract: issue a pass, send, drain,
/// tombstone, reply, renew, revoke, bump, and an invite with its usage entry.
#[test]
fn a_full_round_runs_through_the_contract() {
    let mut world = World::new();
    let a = world.identity("alice");
    let b = world.identity("bob");

    // Bob writes first, as a stranger: quarantine, with a pass back to him.
    let (first, landed) = world.send(&b, &a, "hello alice");
    assert!(landed, "quarantine mail must land in an Open inbox");
    assert_eq!(first.admission, SendAdmission::Quarantine);
    assert_eq!(first.sent_time % 3600, 0);

    // Alice drains: stored, then tombstoned, and the message leaves the state.
    world.change(&a, OwnerChange::Drain);
    assert_eq!(texts(&world.inbound(&a)), ["hello alice"]);
    let state = world.state(&a);
    assert!(state.messages.is_empty());
    assert!(
        state
            .owner
            .tombstones
            .contains_key(&serde_bytes::ByteArray::new(first.id.0))
    );
    assert_eq!(state.owner.version, 2);

    // Alice answers with the pass Bob handed her, and hands him one back.
    let (reply, landed) = world.send(&a, &b, "hi bob");
    assert!(landed);
    assert_eq!(reply.admission, SendAdmission::Pass);
    world.change(&b, OwnerChange::Drain);
    assert_eq!(texts(&world.inbound(&b)), ["hi bob"]);

    // Now Bob writes with Alice's pass.
    let (second, landed) = world.send(&b, &a, "second");
    assert!(landed);
    assert_eq!(second.admission, SendAdmission::Pass);
    world.change(&a, OwnerChange::Drain);
    assert_eq!(texts(&world.inbound(&a)), ["hello alice", "second"]);
    let pass_to_bob = *world.record(&a).issued.values().next().unwrap();
    let before = world.ledger(&a, pass_to_bob.as_slice());

    // Renewal: past the renewal point, Alice's next message to Bob carries a
    // renewed certificate of the same pass, which Bob's next send uses.
    world.advance(before.renew_at - START + 1);
    world.change(&a, OwnerChange::AdvanceTime);
    world.change(&b, OwnerChange::AdvanceTime);
    let (_, landed) = world.send(&a, &b, "renewal rides along");
    assert!(landed);
    world.change(&b, OwnerChange::Drain);
    let after = world.ledger(&a, pass_to_bob.as_slice());
    assert_eq!(after.nonce, before.nonce, "same pass key");
    assert!(after.expiry > before.expiry, "a renewed certificate");
    assert_eq!(after.expiry % DAY, 0);
    let (renewed, landed) = world.send(&b, &a, "with the renewed pass");
    assert!(landed);
    let message: w::Message = w::decode(&renewed.message).unwrap();
    let w::Admission::Pass { cert, .. } = message.admission else {
        panic!("not pass mail");
    };
    assert_eq!((cert.pass_id, cert.expiry), (pass_to_bob, after.expiry));
    world.change(&a, OwnerChange::Drain);

    // Revocation: Bob's pass stops working, his client sees it and falls back
    // to quarantine, which still lands.
    world.change(
        &a,
        OwnerChange::Revoke {
            pass_id: PassId(*pass_to_bob),
        },
    );
    let revoked = &world.state(&a).revoked[&pass_to_bob];
    assert_eq!(revoked.expiry, after.max_expiry, "the largest expiry");
    assert_eq!(revoked.epoch, 1);
    let (lapsed, landed) = world.send(&b, &a, "after revocation");
    assert!(landed);
    assert_eq!(lapsed.admission, SendAdmission::Quarantine);
    assert_eq!(lapsed.notice, Some(SendNotice::PassLapsed));
    world.change(&a, OwnerChange::Drain);

    // An invite: a stranger with it writes, and its usage entry is signed with
    // the owner version that tombstones the message.
    let c = world.identity("carol");
    let invite = world.issue(&a, None, Some(3));
    call(
        &mut world.env,
        PROD,
        Op::HoldPass {
            addr: c,
            pass: invite.clone(),
        },
    )
    .unwrap();
    let (by_invite, landed) = world.send(&c, &a, "invited");
    assert!(landed);
    assert_eq!(by_invite.admission, SendAdmission::Pass);
    world.change(&a, OwnerChange::Drain);
    let state = world.state(&a);
    let usage = &state.usage[&invite.cert.pass_id];
    assert_eq!((usage.used, usage.expiry), (1, invite.cert.expiry));
    assert_eq!(usage.owner_version, state.owner.version);

    // A routine bump: the old epoch keeps its grace, and Carol's invite of
    // the old epoch still lands during it.
    world.change(&a, OwnerChange::BumpEpoch { emergency: false });
    let state = world.state(&a);
    assert_eq!(state.owner.pass_epoch, 2);
    assert!(state.owner.prev_epoch_until > state.time.owner_time);
    let (old_epoch, landed) = world.send(&c, &a, "during the grace");
    assert!(landed);
    assert_eq!(old_epoch.admission, SendAdmission::Pass);
    world.change(&a, OwnerChange::Drain);
    assert_eq!(world.state(&a).usage[&invite.cert.pass_id].used, 2);
    assert_eq!(
        texts(&world.inbound(&a)),
        [
            "after revocation",
            "during the grace",
            "hello alice",
            "invited",
            "second",
            "with the renewed pass"
        ]
    );
}

/// The time guard: `owner_time` never moves more than 7 days in one step, nor
/// past the node's clock plus a day.
#[test]
fn owner_time_moves_under_the_guard() {
    let mut world = World::new();
    let a = world.identity("alice");
    assert_eq!(world.state(&a).time.owner_time, START);
    world.advance(30 * DAY);
    world.change(&a, OwnerChange::AdvanceTime);
    assert_eq!(world.state(&a).time.owner_time, START + 7 * DAY);
    world.change(&a, OwnerChange::AdvanceTime);
    assert_eq!(world.state(&a).time.owner_time, START + 14 * DAY);
    assert_eq!(inbox_v2::guarded_time(100, 50), 100, "never back");
    assert_eq!(inbox_v2::guarded_time(100, 120), 120);
}

/// Every owner version is recorded before it leaves: a lost answer never makes
/// the delegate sign one version twice.
#[test]
fn a_lost_update_never_reuses_a_version() {
    let mut world = World::new();
    let a = world.identity("alice");
    let first = world
        .update(
            &a,
            OwnerChange::SetQuarantine(w::QuarantineMode::RequireGhost { min_usd: None }),
        )
        .unwrap();
    let lost: InboxDelta = w::decode(&first.update.unwrap()).unwrap();
    let second = world
        .update(
            &a,
            OwnerChange::SetQuarantine(w::QuarantineMode::RequireGhost { min_usd: Some(5) }),
        )
        .unwrap();
    let kept: InboxDelta = w::decode(&second.update.unwrap()).unwrap();
    assert!(kept.owner.unwrap().version > lost.owner.unwrap().version);
}

/// A RequireGhost inbox: a stranger without a Ghost Key is told so, and
/// stranger mail bound to a key carries the payload Ghost Key must sign.
#[test]
fn require_ghost_needs_a_key_and_binds_it() {
    let mut world = World::new();
    let a = world.identity("alice");
    let b = world.identity("bob");
    world.change(
        &a,
        OwnerChange::SetQuarantine(w::QuarantineMode::RequireGhost { min_usd: Some(1) }),
    );
    assert_eq!(world.seal(&b, &a, "hi").unwrap_err(), FailureCode::Refused);
    let ui_entropy = world.entropy();
    let Ok(Reply::SealedV2(sealed)) = call(
        &mut world.env,
        PROD,
        Op::SealV2 {
            from: b,
            to: a,
            to_state: ByteBuf::from(world.inboxes[&a].clone()),
            content: SealContent::Mail(ByteBuf::from(b"hi".to_vec())),
            ghost_vk: Some(Hash32([0x33; 32])),
            ui_entropy,
            reseals: 0,
        },
    ) else {
        panic!("seal");
    };
    let message: w::Message = w::decode(&sealed.message).unwrap();
    let ct_hash = *blake3::hash(&message.ciphertext).as_bytes();
    assert_eq!(
        sealed.id.0,
        w::message_id(
            &a.0,
            &ct_hash,
            sealed.sent_time,
            w::KIND_QUARANTINE,
            &[0x33; 32]
        )
    );
    assert_eq!(
        sealed.ghost_payload.unwrap().to_vec(),
        w::ghost_admit_bytes(&a.0, sealed.sent_time, &ct_hash)
    );
}

/// The page cannot write the delegate's own inbox records, nor read a held
/// pass (a key).
#[test]
fn the_page_cannot_rewrite_inbox_records_or_read_held_passes() {
    let mut world = World::new();
    let a = world.identity("alice");
    let b = world.identity("bob");
    world.send(&b, &a, "x");
    world.change(&a, OwnerChange::Drain);
    let put = |kind, id: Vec<u8>| Op::PutItem {
        item: ItemRef {
            kind,
            owner: Some(a),
            id,
        },
        body: ByteBuf::from(vec![1]),
        expected_gen: Some(1),
    };
    for op in [
        put(ItemKind::InboxV2, Vec::new()),
        put(ItemKind::PassLedger, vec![0; 16]),
        put(ItemKind::HeldPass, b.0.to_vec()),
        put(ItemKind::Inbound, vec![0; 32]),
        Op::GetItem {
            item: ItemRef {
                kind: ItemKind::HeldPass,
                owner: Some(a),
                id: b.0.to_vec(),
            },
        },
    ] {
        assert_eq!(call(&mut world.env, PROD, op), Err(FailureCode::Refused));
    }
}

pub fn env_or(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Alice's inbox holding pass, invite and quarantine mail.
pub fn loaded() -> (World, Addr, BTreeMap<[u8; 32], String>) {
    let mut world = World::new();
    let a = world.identity("alice");
    let b = world.identity("bob");
    let c = world.identity("carol");
    let d = world.identity("dave");
    world.send(&b, &a, "first");
    world.change(&a, OwnerChange::Drain);
    world.send(&a, &b, "back");
    world.change(&b, OwnerChange::Drain);
    let invite = world.issue(&a, None, Some(3));
    call(
        &mut world.env,
        PROD,
        Op::HoldPass {
            addr: c,
            pass: invite,
        },
    )
    .unwrap();
    let mut mail = BTreeMap::new();
    for (from, text) in [
        (b, "pass 1"),
        (b, "pass 2"),
        (c, "invite 1"),
        (c, "invite 2"),
        (d, "stranger 1"),
        (d, "stranger 2"),
    ] {
        let (sealed, landed) = world.send(&from, &a, text);
        assert!(landed, "{text}");
        mail.insert(sealed.id.0, text.to_string());
    }
    (world, a, mail)
}

pub fn inbound_stored(world: &World, owner: &Addr, id: &[u8; 32]) -> bool {
    let item = ItemRef {
        kind: ItemKind::Inbound,
        owner: Some(*owner),
        id: id.to_vec(),
    };
    let mut probe = MemEnv::default();
    let origin = Origin([world.origin(owner); 32]);
    let key = Space::new(&mut probe, origin).full_key(&item_rel(&item));
    world.env.secrets.contains_key(&key)
}

/// One drain run over a faulty host: every tombstone an update carries names
/// a message already stored, and once the host heals everything arrives.
fn drain_run(
    base: &World,
    a: &Addr,
    mail: &BTreeMap<[u8; 32], String>,
    faults: Faults,
) -> Result<(u64, u64), String> {
    let mut world = base.clone();
    world.env.faults = Some(faults);
    let mut injected = (0, 0);
    // Eight calls over the faulty host, then up to four over a healed one.
    for call in 0..12 {
        if call == 8 {
            injected = world
                .env
                .faults
                .take()
                .map_or((0, 0), |f| (f.injected.get(), f.observed.get()));
        }
        let Ok(u) = world.update(a, OwnerChange::Drain) else {
            continue;
        };
        let Some(update) = u.update else { continue };
        let delta: InboxDelta = w::decode(&update).unwrap();
        for id in delta.owner.iter().flat_map(|o| o.tombstones.keys()) {
            if mail.contains_key(&**id) && !inbound_stored(&world, a, id) {
                return Err(format!("{} tombstoned before it was stored", mail[&**id]));
            }
        }
        world.publish(a, &update);
    }
    if !world.state(a).messages.is_empty() {
        return Err("mail left in the inbox after healing".into());
    }
    for (id, text) in mail {
        if !inbound_stored(&world, a, id) {
            return Err(format!("{text}: no stored record"));
        }
    }
    let got = texts(&world.inbound(a));
    let mut want: Vec<String> = mail.values().cloned().collect();
    want.push("first".into());
    want.sort();
    if got != want {
        let mut probe = MemEnv::default();
        let space = Space::new(&mut probe, Origin([PROD; 32]));
        let raw = |rel: &str| world.env.secrets.get(&space.full_key(rel)).cloned();
        let index = raw(&crate::store::index_rel(ItemKind::Inbound, Some(a)));
        let unlisted: Vec<_> = mail
            .iter()
            .filter(|(id, _)| {
                !index
                    .as_ref()
                    .is_some_and(|i| i.windows(32).any(|w| w == &id[..]))
            })
            .map(|(id, text)| {
                let item = ItemRef {
                    kind: ItemKind::Inbound,
                    owner: Some(*a),
                    id: id.to_vec(),
                };
                (text.clone(), raw(&crate::store::pending_item_rel(&item)))
            })
            .collect();
        return Err(format!(
            "stored {got:?}, sent {want:?}; unlisted (marker): {unlisted:?}"
        ));
    }
    Ok(injected)
}

/// Never lose a message: drain over a host that misses reads and refuses
/// writes at `DRAIN_RATE` per mille (default 60), and, with `DRAIN_BLIND`
/// per mille, lets one key at a time go unreadable for good.
#[test]
fn a_drain_over_a_faulty_host_never_tombstones_what_it_did_not_store() {
    let (base, a, mail) = loaded();
    let seeds = env_or("DRAIN_SEEDS", 60);
    let rate = env_or("DRAIN_RATE", 60) as u32;
    let blind = env_or("DRAIN_BLIND", 0) as u32;
    let (mut injected, mut seen) = (0u64, 0u64);
    let mut failures = Vec::new();
    let from = env_or("DRAIN_FROM", 1);
    for seed in from..from + seeds {
        let faults = Faults::seeded_with_blindness(seed, rate, blind);
        match drain_run(&base, &a, &mail, faults) {
            Ok((n, m)) => {
                injected += n;
                seen += m;
            }
            Err(e) => failures.push(format!("seed {seed}: {e}")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(injected > seeds, "only {injected} faults injected");
    // A sweep that asks for unreadable keys must have made some unreadable and
    // had the code read them: a blind rate that never hits one tests nothing.
    assert!(
        blind == 0 || seen > 0,
        "no unreadable key was ever read as missing in {seeds} seeds at blind rate {blind}"
    );
}

/// Seeds that tombstoned a message that was not stored while the inbox's
/// index of stored mail was the key that would not read: the index write's
/// `Conflict` was taken for "this message is already stored". Each is
/// (seed, fault rate, unreadable rate), per mille.
const UNREADABLE_INDEX_SEEDS: [(u64, u32, u32); 7] = [
    (33, 60, 20),
    (155, 60, 20),
    (246, 60, 20),
    (249, 60, 20),
    (159, 200, 20),
    (277, 200, 20),
    (323, 200, 20),
];

#[test]
fn a_drain_over_an_unreadable_index_never_tombstones_what_it_did_not_store() {
    let (base, a, mail) = loaded();
    for (seed, rate, blind) in UNREADABLE_INDEX_SEEDS {
        let faults = Faults::seeded_with_blindness(seed, rate, blind);
        if let Err(e) = drain_run(&base, &a, &mail, faults) {
            panic!("seed {seed} at {rate}/{blind}: {e}");
        }
    }
}

/// A refused store tombstones nothing: every message stays in the inbox,
/// counted, and the drain still answers.
#[test]
fn a_refused_store_tombstones_nothing() {
    let (base, a, mail) = loaded();
    let mut world = base.clone();
    world.env.fail_keys_containing = Some("it/in/".into());
    let u = world
        .update(&a, OwnerChange::Drain)
        .expect("the drain answers");
    assert_eq!((u.drained, u.full), (0, mail.len() as u32));
    if let Some(update) = &u.update {
        let delta: InboxDelta = w::decode(update).unwrap();
        let tombstoned = delta.owner.iter().flat_map(|o| o.tombstones.keys());
        assert!(tombstoned.filter(|id| mail.contains_key(&***id)).count() == 0);
        world.publish(&a, update);
    }
    assert_eq!(world.state(&a).messages.len(), mail.len());
}

/// A copy restamped with another time gets a new id the contract may hold,
/// but the sender's binding does not name it: it is tombstoned unread.
#[test]
fn a_restamped_copy_does_not_open() {
    let mut world = World::new();
    let a = world.identity("alice");
    let b = world.identity("bob");
    let sealed = world.seal(&b, &a, "original").unwrap();
    let message: w::Message = w::decode(&sealed.message).unwrap();
    let ct_hash = *blake3::hash(&message.ciphertext).as_bytes();
    let restamped = w::Message {
        sent_time: message.sent_time - 3600,
        ..message.clone()
    };
    let id = w::message_id(&a.0, &ct_hash, restamped.sent_time, w::KIND_QUARANTINE, &[]);
    let delta = InboxDelta {
        messages: BTreeMap::from([(serde_bytes::ByteArray::new(id), restamped)]),
        ..InboxDelta::default()
    };
    world.publish(&a, &w::encode(&delta));
    assert!(w::delivered(&world.state(&a), &id), "the contract holds it");
    let u = world.update(&a, OwnerChange::Drain).unwrap();
    assert_eq!((u.drained, u.remaining), (0, 0));
    world.publish(&a, &u.update.unwrap());
    assert!(world.state(&a).messages.is_empty(), "tombstoned unread");
    assert!(world.inbound(&a).is_empty());
}

/// The inner binding is over the envelope's body, never the ciphertext.
#[test]
fn the_inner_binding_never_covers_the_ciphertext() {
    use crate::crypto::{Keys, MixRng};
    use freenet_mail_protocol::{DsaSeed, KemSeed};
    let keys = Keys::from_seeds(&DsaSeed([1; 32]), &KemSeed([2; 64]));
    let to = freenet_mail_protocol::address::address_of(&keys.vk_bytes());
    let body = w::SealedBody {
        kind: w::EnvelopeKind::Mail(ByteBuf::from(b"x".to_vec())),
        reply_pass: w::Pass {
            cert: w::PassCert {
                recipient: serde_bytes::ByteArray::new(to.0),
                pass_id: serde_bytes::ByteArray::new([0; 16]),
                pass_vk: serde_bytes::ByteArray::new([0; 32]),
                epoch: 1,
                expiry: DAY,
                class: w::PassClass::Contact,
                sig: serde_bytes::ByteArray::new([0; 64]),
            },
            pass_sk: serde_bytes::ByteArray::new([0; 32]),
        },
        pass_grant: None,
        ghost_vk: None,
    };
    let mut rng = MixRng::new("t", &[3; 32], &Entropy([4; 32]));
    let ct = crate::sealing::seal(
        &keys,
        &to.0,
        &keys.ek_bytes(),
        7200,
        w::KIND_OWNER,
        &[],
        &body,
        &mut rng,
    )
    .unwrap();
    let ct_hash = *blake3::hash(&ct).as_bytes();
    let body_hash = *blake3::hash(&w::encode(&body)).as_bytes();
    let binding = w::inner_binding(&to.0, &body_hash, 7200, w::KIND_OWNER, &[]);
    assert!(
        !binding.windows(32).any(|win| win == ct_hash),
        "the binding holds the ciphertext's hash"
    );
    let message = w::Message {
        ciphertext: ByteBuf::from(ct),
        sent_time: 7200,
        admission: w::Admission::Owner {
            sig: serde_bytes::ByteArray::new([0; 64]),
        },
    };
    assert!(w::CIPHERTEXT_SIZES.contains(&message.ciphertext.len()));
    let id = w::message_id(&to.0, &ct_hash, 7200, w::KIND_OWNER, &[]);
    let opened = crate::sealing::open(&keys, &to.0, &id, &message).expect("opens");
    assert_eq!(opened.body, body, "the body signed is the body sealed");
}

/// Decisions 17 and 20: what a pass publishes is no more precise than a day,
/// its lifetime is drawn from 335 to 395 days, renewal falls at 40 to 60% of
/// it, and reissue after a bump at a point of the grace drawn per pass.
#[test]
fn pass_timing_is_coarse_and_spread() {
    use crate::crypto::MixRng;
    let mut rng = MixRng::new("t", &[5; 32], &Entropy([6; 32]));
    let (mut short, mut long) = (u64::MAX, 0);
    let (mut early, mut late) = (u64::MAX, 0);
    for i in 0..2000u64 {
        let now = START + i * 3_607;
        let mut e = LedgerEntry {
            v: 1,
            issued_for: None,
            contact: None,
            nonce: serde_bytes::ByteArray::new([0; 32]),
            class: w::PassClass::Contact,
            epoch: 1,
            expiry: 0,
            max_expiry: 0,
            renew_at: 0,
            revoked: false,
            drained: Default::default(),
            delivered: 0,
            pending: None,
            revoked_epoch: 0,
            misses: 0,
        };
        inbox_v2::start_term(&mut e, now, &mut rng);
        assert_eq!(e.expiry % DAY, 0, "expiry to the day");
        let lifetime = e.expiry - now;
        assert!(
            (335 * DAY..396 * DAY).contains(&lifetime),
            "lifetime {lifetime}"
        );
        short = short.min(lifetime);
        long = long.max(lifetime);
        // As a share of the drawn lifetime (the expiry adds under a day).
        let share = (e.renew_at - now) * 1000 / (lifetime - DAY / 2);
        assert!((395..=605).contains(&share), "renewal at {share} per mille");
        early = early.min(share);
        late = late.max(share);
    }
    assert!(
        short < 340 * DAY && long > 390 * DAY,
        "lifetimes {short}..{long}"
    );
    assert!(
        early < 410 && late > 590,
        "renewals {early}..{late} per mille"
    );
    let mut world = World::new();
    let a = world.identity("alice");
    let mut rec = world.record(&a);
    rec.epoch_began = START;
    rec.reissue_grace = inbox_v2::EPOCH_GRACE;
    let points: Vec<u64> = (0..500u16)
        .map(|i| {
            let mut id = [0u8; 16];
            id[..2].copy_from_slice(&i.to_le_bytes());
            inbox_v2::reissue_at(&rec, &serde_bytes::ByteArray::new(id)) - START
        })
        .collect();
    assert!(points.iter().all(|p| *p < inbox_v2::EPOCH_GRACE));
    assert!(*points.iter().min().unwrap() < DAY && *points.iter().max().unwrap() > 13 * DAY);
}

/// A stranger's reply pass that cannot be kept (its key does not match its
/// certificate) does not keep the mail in the inbox: it is stored and drained.
#[test]
fn a_bad_reply_pass_does_not_hold_mail_in_the_inbox() {
    use crate::crypto::{Keys, MixRng};
    use freenet_mail_protocol::{DsaSeed, KemSeed};
    let mut world = World::new();
    let a = world.identity("alice");
    let sender = Keys::from_seeds(&DsaSeed([9; 32]), &KemSeed([8; 64]));
    let from = freenet_mail_protocol::address::address_of(&sender.vk_bytes());
    let body = w::SealedBody {
        kind: w::EnvelopeKind::Mail(ByteBuf::from(b"odd pass".to_vec())),
        reply_pass: w::Pass {
            cert: w::PassCert {
                recipient: serde_bytes::ByteArray::new(from.0),
                pass_id: serde_bytes::ByteArray::new([1; 16]),
                pass_vk: serde_bytes::ByteArray::new([2; 32]),
                epoch: 1,
                expiry: 400 * DAY,
                class: w::PassClass::Contact,
                sig: serde_bytes::ByteArray::new([0; 64]),
            },
            pass_sk: serde_bytes::ByteArray::new([3; 32]),
        },
        pass_grant: None,
        ghost_vk: None,
    };
    let state = world.state(&a);
    let sent_time = inbox_v2::sent_time_for(START, state.time.owner_time, w::QUARANTINE_FORWARD);
    let mut rng = MixRng::new("t", &[3; 32], &Entropy([4; 32]));
    let ct = crate::sealing::seal(
        &sender,
        &a.0,
        &state.owner.kem_ek,
        sent_time,
        w::KIND_QUARANTINE,
        &[],
        &body,
        &mut rng,
    )
    .unwrap();
    let id = w::message_id(
        &a.0,
        blake3::hash(&ct).as_bytes(),
        sent_time,
        w::KIND_QUARANTINE,
        &[],
    );
    let message = w::Message {
        ciphertext: ByteBuf::from(ct),
        sent_time,
        admission: w::Admission::Quarantine { ghost: None },
    };
    let delta = InboxDelta {
        messages: BTreeMap::from([(serde_bytes::ByteArray::new(id), message)]),
        ..InboxDelta::default()
    };
    world.publish(&a, &w::encode(&delta));
    world.change(&a, OwnerChange::Drain);
    assert!(world.state(&a).messages.is_empty());
    assert_eq!(texts(&world.inbound(&a)), ["odd pass"]);
}

/// Seed 596 of the drain sweep at 20% (found on 1b9dfbb), as a script of the
/// faults that mattered: a create stores its record but cannot clear its
/// marker; a retry finds the record unreadable, creates again, and its write
/// is refused. Its undo used to remove the index entry the first create
/// added, leaving a stored message (already drained) that no listing shows.
#[test]
fn a_failed_retry_of_a_create_keeps_the_earlier_entry() {
    use crate::env::mem::{FaultOp, Rule};
    let mut env = MemEnv::default();
    let owner = create(&mut env, PROD, "alice").addr;
    let item = ItemRef {
        kind: ItemKind::Kept,
        owner: Some(owner),
        id: vec![7; 16],
    };
    let mut probe = MemEnv::default();
    let space = Space::new(&mut probe, Origin([PROD; 32]));
    let full = |rel: &str| String::from_utf8(space.full_key(rel)).unwrap();
    let record = full(&item_rel(&item));
    let marker = full(&crate::store::pending_item_rel(&item));
    let rule = |op, key: &String, nth| Rule {
        op,
        key_contains: key.clone(),
        nth,
    };
    let mut faults = Faults::default();
    faults.rules = vec![
        rule(FaultOp::RemoveFail, &marker, 1),
        rule(FaultOp::SetFail, &marker, 2),
        rule(FaultOp::GetBlindFrom, &record, 1),
        rule(FaultOp::SetFail, &record, 2),
    ];
    env.faults = Some(faults);
    let put = |env: &mut MemEnv| {
        call(
            env,
            PROD,
            Op::PutItem {
                item: item.clone(),
                body: ByteBuf::from(b"kept".to_vec()),
                expected_gen: None,
            },
        )
    };
    assert_eq!(
        put(&mut env),
        Err(FailureCode::Internal),
        "the marker is left"
    );
    assert!(put(&mut env).is_err(), "the retry's write is refused");
    env.faults = None;
    let Ok(Reply::Items { items, .. }) = call(
        &mut env,
        PROD,
        Op::ListItems {
            kind: ItemKind::Kept,
            owner: Some(owner),
            after: None,
            limit: 10,
        },
    ) else {
        panic!("list");
    };
    assert_eq!(items.len(), 1, "the stored item is no longer listed");
}

/// `addr`'s inbox signed again from the delegate's record.
fn republish(world: &mut World, addr: &Addr) -> Result<Vec<u8>, FailureCode> {
    match world.call_as(addr, Op::RepublishInboxV2 { addr: *addr })? {
        Reply::InboxV2State(s) => Ok(s.into_vec()),
        other => panic!("{other:?}"),
    }
}

/// The reply to `CreateInboxV2` was lost (or the tab closed before the page
/// kept or sent it): the delegate has the record, nobody has the state. The
/// inbox is signed again from the record, at a version above the one the
/// lost state carried, and that version is recorded as this node's own, so
/// it is neither signed twice nor taken for another node's (decision 25).
#[test]
fn an_inbox_whose_first_state_was_lost_is_signed_again_from_the_record() {
    let mut world = World::new();
    let a = create(&mut world.env, PROD, "alice").addr;
    let Ok(Reply::InboxV2State(lost)) = world.call_as(
        &a,
        Op::CreateInboxV2 {
            addr: a,
            ghost_master: Hash32(world.master),
            existing: None,
        },
    ) else {
        panic!("create inbox");
    };
    let lost: InboxState = w::decode(&lost).unwrap();
    world.advance(DAY);
    let state = republish(&mut world, &a).unwrap();
    assert!(is_valid(&Rules::V1, &world.params(&a), &state));
    let first: InboxState = w::decode(&state).unwrap();
    assert!(first.owner.version > lost.owner.version);
    assert!(first.time.owner_time > lost.time.owner_time, "time moved");
    let rec = world.record(&a);
    assert_eq!(rec.max_version, first.owner.version, "recorded");
    assert_eq!(rec.max_owner_time, first.time.owner_time, "recorded");
    world.inboxes.insert(a, state);

    // A drain of it sees this node's own record, and mail gets in and out.
    let b = world.identity("bob");
    assert!(world.send(&b, &a, "hi").1);
    world.change(&a, OwnerChange::Drain);
    assert_eq!(world.record(&a).foreign_seen, None, "its own record");
    assert_eq!(world.inbound(&a).len(), 1);

    // Again: a new version every time, never one already signed.
    let again: InboxState = w::decode(&republish(&mut world, &a).unwrap()).unwrap();
    assert!(again.owner.version > world.state(&a).owner.version);
}

/// The network lost an inbox that held drained mail: the state signed again
/// keeps the record's tombstones, so a peer still holding a drained message
/// cannot bring it back.
#[test]
fn an_inbox_signed_again_keeps_its_tombstones() {
    let mut world = World::new();
    let a = world.identity("alice");
    let b = world.identity("bob");
    let (sealed, landed) = world.send(&b, &a, "drained");
    assert!(landed);
    world.change(&a, OwnerChange::Drain);
    let held = world.inboxes[&a].clone();
    let state = republish(&mut world, &a).unwrap();
    let again: InboxState = w::decode(&state).unwrap();
    assert!(again.owner.tombstones.contains_key(&sealed.id.0));
    // A peer's older copy, with the message in it, merges in: still drained.
    let merged = apply(
        &Rules::V1,
        &world.params(&a),
        &state,
        vec![UpdateData::State(held.into())],
    )
    .expect("the contract merges the old copy");
    assert!(is_valid(&Rules::V1, &world.params(&a), &merged));
    let merged: InboxState = w::decode(&merged).unwrap();
    assert_eq!(merged.owner.version, again.owner.version);
    assert!(merged.owner.tombstones.contains_key(&sealed.id.0));
}

/// The network lost an inbox after a pass was revoked: the state signed again
/// carries the revocation, so mail sealed with that pass (a peer may still
/// hold some) is refused by the contract.
#[test]
fn an_inbox_signed_again_keeps_its_revocations() {
    let mut world = World::new();
    let a = world.identity("alice");
    let c = world.identity("carol");
    let invite = world.issue(&a, None, Some(3));
    world
        .call_as(
            &c,
            Op::HoldPass {
                addr: c,
                pass: invite.clone(),
            },
        )
        .unwrap();
    // Sealed before the revocation and held back, as a peer might.
    let held_back = world.seal(&c, &a, "held back").unwrap();
    assert_eq!(held_back.admission, SendAdmission::Pass);
    world.change(
        &a,
        OwnerChange::Revoke {
            pass_id: PassId(*invite.cert.pass_id),
        },
    );
    assert!(world.state(&a).revoked.contains_key(&invite.cert.pass_id));

    world.advance(DAY);
    let state = republish(&mut world, &a).unwrap();
    assert!(is_valid(&Rules::V1, &world.params(&a), &state));
    world.inboxes.insert(a, state);
    let again = world.state(&a);
    let r = &again.revoked[&invite.cert.pass_id];
    assert_eq!(r.epoch, again.owner.pass_epoch, "no bump was needed");
    let message: w::Message = w::decode(&held_back.message).unwrap();
    let delta = InboxDelta {
        messages: BTreeMap::from([(serde_bytes::ByteArray::new(held_back.id.0), message)]),
        ..InboxDelta::default()
    };
    world.publish(&a, &w::encode(&delta));
    assert!(
        !w::delivered(&world.state(&a), &held_back.id.0),
        "the revoked pass is refused"
    );
}

/// A revoked pass's ledger entry is listed but cannot be read: a republish
/// fails as unreadable rather than signing an inbox without that revocation,
/// and once the entry reads again it carries it. An entry whose deletion did
/// not finish (its record gone, its `d` marker left) is absent, not unreadable.
#[test]
fn a_republish_over_an_unreadable_revoked_ledger_entry_fails_closed() {
    let mut world = World::new();
    let a = world.identity("alice");
    let invite = world.issue(&a, None, Some(3));
    let pass_id = invite.cert.pass_id;
    world.change(
        &a,
        OwnerChange::Revoke {
            pass_id: PassId(*pass_id),
        },
    );
    world.advance(DAY);
    let ledger = ItemRef {
        kind: ItemKind::PassLedger,
        owner: Some(a),
        id: pass_id.to_vec(),
    };
    let mut probe = MemEnv::default();
    let space = Space::new(&mut probe, Origin([world.origin(&a); 32]));
    let key = String::from_utf8(space.full_key(&item_rel(&ledger))).unwrap();
    let pending =
        String::from_utf8(space.full_key(&crate::store::pending_item_rel(&ledger))).unwrap();
    world.env.faults = Some(Faults::blind(&key));
    assert_eq!(
        republish(&mut world, &a).unwrap_err(),
        FailureCode::Unreadable,
        "never signed without the revocation"
    );
    world.env.faults = None;
    let state: InboxState = w::decode(&republish(&mut world, &a).unwrap()).unwrap();
    assert!(state.revoked.contains_key(&pass_id), "readable again");

    // A deletion that removed the record and stopped before the index.
    let record = world.env.secrets.remove(key.as_bytes());
    assert!(record.is_some());
    world
        .env
        .secrets
        .insert(pending.into_bytes(), crate::store::MARKER_DELETING.to_vec());
    assert!(
        republish(&mut world, &a).is_ok(),
        "a deleted entry is absent"
    );
}

/// No record, no inbox to sign: an identity without one, and one the page's
/// origin does not hold, are refused.
#[test]
fn republishing_needs_the_identitys_record_in_this_origin() {
    let mut world = World::new();
    let a = create(&mut world.env, PROD, "alice").addr;
    assert_eq!(
        republish(&mut world, &a).unwrap_err(),
        FailureCode::NotFound
    );
    let b = world.identity("bob");
    assert!(
        call(&mut world.env, PROD + 1, Op::RepublishInboxV2 { addr: b }).is_err(),
        "another origin"
    );
}

/// The node-log line of a run the node started, as `ui/tests/inbox-v2-live.spec.ts`
/// reads it to tell which wake-up drained an inbox with every tab closed.
#[test]
fn a_node_started_run_logs_what_woke_it_and_what_it_did() {
    let done = freenet_mail_protocol::JobsRun {
        scanned: 2,
        imported: 1,
        unknown: 0,
        remaining: 3,
    };
    assert_eq!(
        crate::handlers::run_line("notification", &done),
        "mail delegate run: woken_by=notification scanned=2 imported=1 unknown=0 remaining=3"
    );
}

/// Decision 25's note keeps when another node was first seen and the
/// highest version seen: an older foreign record (a page's stale state) does
/// not lower it, and a newer one raises the version but not the time.
#[test]
fn a_note_of_another_node_keeps_its_first_sighting_and_highest_version() {
    let mut world = World::new();
    let a = world.identity("alice");
    let mut rec = world.record(&a);
    let owner = |v: u64| {
        let mut o = world.state(&a).owner;
        o.version = v;
        o
    };
    assert!(rec.max_version < 5);
    inbox_v2::note_foreign(&mut rec, &owner(10), 100);
    let seen = |rec: &InboxRecord| rec.foreign_seen.map(|f| (f.version, f.at));
    assert_eq!(seen(&rec), Some((10, 100)));
    inbox_v2::note_foreign(&mut rec, &owner(5), 200);
    assert_eq!(seen(&rec), Some((10, 100)), "an older one lowers nothing");
    inbox_v2::note_foreign(&mut rec, &owner(12), 300);
    assert_eq!(seen(&rec), Some((12, 100)), "first seen at 100");
}

/// A record from before the delegate kept the digest of what it signed has
/// none: its own version is then not taken for another node's, whatever the
/// bytes (only a higher version is).
#[test]
fn a_record_with_no_digest_is_not_flagged_at_its_own_version() {
    let mut world = World::new();
    let a = world.identity("alice");
    let mut rec = world.record(&a);
    rec.signed_owner = None;
    let mut other = world.state(&a).owner;
    assert_eq!(other.version, rec.max_version);
    other.quarantine = w::QuarantineMode::RequireGhost { min_usd: None };
    assert!(!inbox_v2::signed_elsewhere(&rec, &other));
    other.version += 1;
    assert!(inbox_v2::signed_elsewhere(&rec, &other));
}
