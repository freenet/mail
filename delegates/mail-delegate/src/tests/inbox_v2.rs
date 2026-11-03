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
use crate::env::mem::MemEnv;
use crate::inbox_v2::{self, InboxRecord, LedgerEntry};

const MASTER: [u8; 32] = [0x42; 32];
const DAY: u64 = 86_400;
/// 2026-11-03, a little after midnight.
const START: u64 = 1_793_664_123;

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
