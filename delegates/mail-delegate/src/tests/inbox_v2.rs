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
const DAY: u64 = 86_400;
/// 2026-11-03, a little after midnight.
const START: u64 = 1_793_664_123;

#[derive(Clone)]
pub struct World {
    pub env: MemEnv,
    /// Each inbox's state as the network holds it.
    pub inboxes: BTreeMap<Addr, Vec<u8>>,
    entropy: u8,
}

fn params(addr: &Addr) -> Params {
    Params {
        addr: addr.0,
        ghost_master: MASTER,
    }
}

impl World {
    pub fn new() -> Self {
        World {
            env: MemEnv {
                now: Some(START),
                ..MemEnv::default()
            },
            inboxes: BTreeMap::new(),
            entropy: 0,
        }
    }

    pub fn entropy(&mut self) -> Entropy {
        self.entropy = self.entropy.wrapping_add(1);
        Entropy([self.entropy; 32])
    }

    pub fn advance(&mut self, secs: u64) {
        self.env.now = Some(self.env.now.unwrap() + secs);
    }

    /// A new identity with its inbox published.
    pub fn identity(&mut self, alias: &str) -> Addr {
        let addr = create(&mut self.env, PROD, alias).addr;
        let Ok(Reply::InboxV2State(state)) = call(
            &mut self.env,
            PROD,
            Op::CreateInboxV2 {
                addr,
                ghost_master: Hash32(MASTER),
                existing: None,
            },
        ) else {
            panic!("create inbox");
        };
        assert!(
            is_valid(&Rules::V1, &params(&addr), &state),
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
            &params(addr),
            &self.inboxes[addr],
            vec![UpdateData::Delta(StateDelta::from(delta.to_vec()))],
        )
        .expect("the contract accepts the update");
        assert!(
            is_valid(&Rules::V1, &params(addr), &merged),
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
        match call(
            &mut self.env,
            PROD,
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
        match call(
            &mut self.env,
            PROD,
            Op::SealV2 {
                from: *from,
                to: *to,
                to_state: ByteBuf::from(self.inboxes[to].clone()),
                content: SealContent::Mail(ByteBuf::from(text.as_bytes().to_vec())),
                ghost_vk: None,
                ui_entropy,
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
        let Ok(Reply::Items { items, .. }) = call(
            &mut self.env,
            PROD,
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
        match call(
            &mut self.env,
            PROD,
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
        let Ok(Reply::Item(Some(item))) = call(
            &mut self.env,
            PROD,
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
        let Ok(Reply::Item(Some(item))) = call(
            &mut self.env,
            PROD,
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

fn texts(list: &[w::InboundMessage]) -> Vec<String> {
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

fn env_or(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Alice's inbox holding pass, invite and quarantine mail.
fn loaded() -> (World, Addr, BTreeMap<[u8; 32], String>) {
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

fn inbound_stored(world: &World, owner: &Addr, id: &[u8; 32]) -> bool {
    let item = ItemRef {
        kind: ItemKind::Inbound,
        owner: Some(*owner),
        id: id.to_vec(),
    };
    let mut probe = MemEnv::default();
    let key = Space::new(&mut probe, Origin([PROD; 32])).full_key(&item_rel(&item));
    world.env.secrets.contains_key(&key)
}

/// One drain run over a faulty host: every tombstone an update carries names
/// a message already stored, and once the host heals everything arrives.
fn drain_run(
    base: &World,
    a: &Addr,
    mail: &BTreeMap<[u8; 32], String>,
    faults: Faults,
) -> Result<u64, String> {
    let mut world = base.clone();
    world.env.faults = Some(faults);
    let mut injected = 0;
    // Eight calls over the faulty host, then up to four over a healed one.
    for call in 0..12 {
        if call == 8 {
            injected = world.env.faults.take().map_or(0, |f| f.injected.get());
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
    let mut injected = 0;
    let mut failures = Vec::new();
    let from = env_or("DRAIN_FROM", 1);
    for seed in from..from + seeds {
        let faults = Faults::seeded_with_blindness(seed, rate, blind);
        match drain_run(&base, &a, &mail, faults) {
            Ok(n) => injected += n,
            Err(e) => failures.push(format!("seed {seed}: {e}")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(injected > seeds, "only {injected} faults injected");
}

/// A refused store stops the drain before anything is tombstoned.
#[test]
fn a_refused_store_stops_the_drain() {
    let (base, a, mail) = loaded();
    let mut world = base.clone();
    world.env.fail_keys_containing = Some("it/in/".into());
    assert!(world.update(&a, OwnerChange::Drain).is_err());
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
