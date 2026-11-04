//! The v1 transition (decisions 26 to 28): the earlier v1 generations read
//! during the window, the close at its end, and a verified contact's pass
//! accepted from the queue.
//!
//! Offline. The v1 contract cannot be linked here (it pins stdlib 0.3.5), so
//! [`apply_v1`] models what the node does with a close: it verifies both
//! signatures and refuses a settings change whose outcome still holds a
//! message below the new tier, which is the check that makes the order
//! matter (`contracts/inbox/src/lib.rs`, `verify_token_policy`, run by
//! `validate_state` on the outcome).

use std::collections::BTreeMap;

use freenet_mail_protocol::inbox_v2 as w;
use freenet_mail_protocol::{
    Addr, IdentityInfo, ItemKind, ItemRef, Op, Reply, SealContent, SendAdmission,
};
use freenet_mail_wire_v1::aft::Tier;
use freenet_mail_wire_v1::inbox::{InboxSettings, UpdateInbox, removal_payload, sign_payload};
use freenet_stdlib::prelude::{OutboundDelegateMsg, UpdateData};
use serde_bytes::ByteBuf;

use super::PROD;
use super::inbox_v2::World;
use super::jobs::{id_of, sealed};
use crate::crypto;
use crate::env::mem::Faults;
use crate::handlers::{V1_LEGACY_INBOX_CODE_HASHES, v1_inbox_id, v1_inbox_id_at};
use crate::jobs::Trigger;
use crate::store::{Origin, Space, item_rel};
use crate::transition::{WINDOW, is_closed};
use crate::watch;

fn info(world: &mut World, addr: &Addr) -> IdentityInfo {
    match world.call_as(addr, Op::ListIdentities) {
        Ok(Reply::Identities(ids)) => ids.into_iter().find(|i| i.addr == *addr).unwrap(),
        other => panic!("{other:?}"),
    }
}

/// A v1 message as the inbox holds it: what v0.2.x sealed, with a token at
/// `Min10` whose hash is `n`.
fn held(to: &IdentityInfo, title: &str, n: u8) -> serde_json::Value {
    let mut m: serde_json::Value = serde_json::from_slice(&sealed(to, title)).unwrap();
    m["token_assignment"] =
        serde_json::json!({ "assignment_hash": (vec![n; 32]), "tier": "Min10" });
    m
}

/// A v1 inbox state of `owner` holding `messages`, at the default settings.
fn v1_state(owner: &IdentityInfo, messages: Vec<serde_json::Value>) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "messages": messages,
        "last_update": "2026-11-01T00:00:00Z",
        "settings": InboxSettings::default(),
        "owner_ek_bytes": owner.ek.to_vec(),
        "inbox_signature": [],
    }))
    .unwrap()
}

/// What the node does with one update to a v1 inbox: the model in the
/// module doc. `Err` is a refusal; the state is then unchanged.
fn apply_v1(owner: &IdentityInfo, state: &[u8], update: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut v: serde_json::Value = serde_json::from_slice(state).unwrap();
    match serde_json::from_slice::<UpdateInbox>(update).unwrap() {
        UpdateInbox::RemoveMessages { signature, ids } => {
            if !crypto::verify_v1(&removal_payload(&ids), &owner.vk, &signature) {
                return Err("bad removal signature");
            }
            let hash = |m: &serde_json::Value| -> [u8; 32] {
                serde_json::from_value(m["token_assignment"]["assignment_hash"].clone()).unwrap()
            };
            v["messages"]
                .as_array_mut()
                .unwrap()
                .retain(|m| !ids.contains(&hash(m)));
        }
        UpdateInbox::ModifySettings {
            inbox_signature,
            settings,
            last_update,
        } => {
            let payload = sign_payload(&owner.ek, &settings, last_update);
            if !crypto::verify_v1(&payload, &owner.vk, &inbox_signature) {
                return Err("bad settings signature");
            }
            let tier = |m: &serde_json::Value| -> Tier {
                serde_json::from_value(m["token_assignment"]["tier"].clone()).unwrap()
            };
            if v["messages"]
                .as_array()
                .unwrap()
                .iter()
                .any(|m| tier(m) < settings.minimum_tier)
            {
                return Err("invalid outcome state");
            }
            v["settings"] = serde_json::to_value(&settings).unwrap();
            v["last_update"] = serde_json::to_value(last_update).unwrap();
        }
        UpdateInbox::AddMessages { .. } => panic!("the close never adds"),
    }
    Ok(serde_json::to_vec(&v).unwrap())
}

/// One page run of `addr`'s origin. Returns the v1 updates, in order.
fn run_v1(world: &mut World, addr: &Addr, id: [u8; 32]) -> Vec<Vec<u8>> {
    let origin = Origin([world.origin(addr); 32]);
    let (_, out) = watch::run(&mut world.env, Trigger::RunJobs(origin));
    out.into_iter()
        .filter_map(|m| match m {
            OutboundDelegateMsg::UpdateContractRequest(r) if r.contract_id.as_bytes() == id => {
                match r.update {
                    UpdateData::Delta(d) => Some(d.as_ref().to_vec()),
                    other => panic!("{other:?}"),
                }
            }
            _ => None,
        })
        .collect()
}

/// Apply `updates` in order as the node would, keeping refused ones out.
/// Returns how many were refused.
fn land(world: &mut World, owner: &IdentityInfo, id: [u8; 32], updates: &[Vec<u8>]) -> usize {
    let mut refused = 0;
    for u in updates {
        let state = world.env.contracts[&id].clone();
        match apply_v1(owner, &state, u) {
            Ok(next) => {
                world.env.contracts.insert(id, next);
            }
            Err(_) => refused += 1,
        }
    }
    refused
}

fn settings_of(world: &World, id: [u8; 32]) -> InboxSettings {
    let v: serde_json::Value = serde_json::from_slice(&world.env.contracts[&id]).unwrap();
    serde_json::from_value(v["settings"].clone()).unwrap()
}

fn messages_in(world: &World, id: [u8; 32]) -> usize {
    let v: serde_json::Value = serde_json::from_slice(&world.env.contracts[&id]).unwrap();
    v["messages"].as_array().unwrap().len()
}

fn settings_sigs(updates: &[Vec<u8>]) -> Vec<Vec<u8>> {
    updates
        .iter()
        .filter_map(
            |u| match serde_json::from_slice::<UpdateInbox>(u).unwrap() {
                UpdateInbox::ModifySettings {
                    inbox_signature, ..
                } => Some(inbox_signature.to_vec()),
                _ => None,
            },
        )
        .collect()
}

fn kept_ids(world: &mut World, addr: &Addr) -> Vec<Vec<u8>> {
    match world.call_as(
        addr,
        Op::ListItems {
            kind: ItemKind::Kept,
            owner: Some(*addr),
            after: None,
            limit: 256,
        },
    ) {
        Ok(Reply::Items { items, .. }) => items.into_iter().map(|i| i.item.id).collect(),
        other => panic!("{other:?}"),
    }
}

/// An identity with a v2 inbox (so a window) and a v1 inbox holding two
/// messages, both imported by the first run.
fn imported_two() -> (World, Addr, IdentityInfo, [u8; 32]) {
    let mut world = World::new();
    let a = world.identity("alice");
    let me = info(&mut world, &a);
    let id = v1_inbox_id(&me.vk).unwrap();
    let state = v1_state(&me, vec![held(&me, "one", 1), held(&me, "two", 2)]);
    world.env.contracts.insert(id, state);
    assert!(
        run_v1(&mut world, &a, id).is_empty(),
        "nothing before the end"
    );
    assert_eq!(kept_ids(&mut world, &a).len(), 2);
    (world, a, me, id)
}

/// The window closes once, at its end: the imported messages go first, then
/// the closing settings, signed once and sent again unchanged until they
/// are seen in the inbox.
#[test]
fn the_close_waits_for_the_window_and_is_signed_once() {
    let (mut world, a, me, id) = imported_two();
    world.advance(WINDOW - 60);
    assert!(run_v1(&mut world, &a, id).is_empty(), "not a minute early");
    world.advance(60);
    let first = run_v1(&mut world, &a, id);
    assert_eq!(first.len(), 2, "removal, then settings");
    let UpdateInbox::RemoveMessages { ids, .. } = serde_json::from_slice(&first[0]).unwrap() else {
        panic!("the removal goes first");
    };
    assert_eq!(ids, vec![[1; 32], [2; 32]]);
    // The settings update is lost: a later run sends the same bytes.
    land(&mut world, &me, id, &first[..1]);
    world.advance(600);
    let again = run_v1(&mut world, &a, id);
    assert_eq!(settings_sigs(&again), settings_sigs(&first), "signed once");
    assert_eq!(again.last(), first.last(), "the same update, byte for byte");
    assert_eq!(land(&mut world, &me, id, &again), 0);
    assert!(is_closed(&settings_of(&world, id)));
    assert_eq!(messages_in(&world, id), 0);
    // Seen closed: nothing more, however often it runs.
    assert!(run_v1(&mut world, &a, id).is_empty());
    world.advance(86_400);
    assert!(run_v1(&mut world, &a, id).is_empty());
    assert_eq!(world.record(&a).v1_window.unwrap().closes.len(), 1);
    // The kept copies are untouched.
    assert_eq!(kept_ids(&mut world, &a).len(), 2);
}

/// A message that arrives after the last import is not removed: the
/// settings the run sent are refused by the node, and the next run imports
/// it and closes, with the same signature.
#[test]
fn a_message_arriving_before_the_close_lands_is_imported_then_closed() {
    let (mut world, a, me, id) = imported_two();
    world.advance(WINDOW);
    let first = run_v1(&mut world, &a, id);
    // It arrives at the node before the run's updates are applied.
    let mut v: serde_json::Value = serde_json::from_slice(&world.env.contracts[&id]).unwrap();
    v["messages"]
        .as_array_mut()
        .unwrap()
        .push(held(&me, "late", 3));
    world
        .env
        .contracts
        .insert(id, serde_json::to_vec(&v).unwrap());
    assert_eq!(land(&mut world, &me, id, &first), 1, "the settings refused");
    assert!(!is_closed(&settings_of(&world, id)));
    assert_eq!(messages_in(&world, id), 1, "the late one stays");
    world.advance(600);
    let next = run_v1(&mut world, &a, id);
    assert_eq!(kept_ids(&mut world, &a).len(), 3, "imported first");
    assert_eq!(settings_sigs(&next), settings_sigs(&first), "signed once");
    assert_eq!(land(&mut world, &me, id, &next), 0);
    assert!(is_closed(&settings_of(&world, id)));
}

/// Decision 28: a copy that cannot be read back is not "imported". Its
/// message stays and the settings are not sent.
#[test]
fn an_unreadable_kept_copy_blocks_the_removal_of_its_message() {
    let (mut world, a, me, id) = imported_two();
    world.advance(WINDOW);
    let one = id_of(&serde_json::to_vec(&held(&me, "one", 1)).unwrap());
    let rel = item_rel(&ItemRef {
        kind: ItemKind::Kept,
        owner: Some(a),
        id: one.to_vec(),
    });
    let key = Space::new(&mut world.env, Origin([PROD; 32])).full_key(&rel);
    world.env.faults = Some(Faults::blind(&String::from_utf8(key).unwrap()));
    let out = run_v1(&mut world, &a, id);
    assert_eq!(out.len(), 1, "no settings while a message stays");
    let UpdateInbox::RemoveMessages { ids, .. } = serde_json::from_slice(&out[0]).unwrap() else {
        panic!("a removal");
    };
    assert_eq!(ids, vec![[2; 32]], "only the message whose copy reads back");
    land(&mut world, &me, id, &out);
    assert_eq!(messages_in(&world, id), 1);
    assert!(!is_closed(&settings_of(&world, id)));
    // Readable again: the close goes on with the same signature.
    world.env.faults = None;
    let next = run_v1(&mut world, &a, id);
    assert_eq!(land(&mut world, &me, id, &next), 0);
    assert!(is_closed(&settings_of(&world, id)));
}

/// A copy that reads back but is not this message (another title) is not
/// proof of an import either.
#[test]
fn a_copy_that_is_not_the_message_does_not_count() {
    let (mut world, a, me, id) = imported_two();
    world.advance(WINDOW);
    let one = id_of(&serde_json::to_vec(&held(&me, "one", 1)).unwrap());
    let item = ItemRef {
        kind: ItemKind::Kept,
        owner: Some(a),
        id: one.to_vec(),
    };
    let generation = match world.call_as(&a, Op::GetItem { item: item.clone() }) {
        Ok(Reply::Item(Some(i))) => i.generation,
        other => panic!("{other:?}"),
    };
    let other = serde_json::json!({
        "from": "bob", "title": "something else", "content": "body of one",
        "kept_at": 0, "sent_at": null, "signature_valid": false, "sender_vk": [],
    });
    world
        .call_as(
            &a,
            Op::PutItem {
                item,
                body: ByteBuf::from(serde_json::to_vec(&other).unwrap()),
                expected_gen: Some(generation),
            },
        )
        .unwrap();
    let out = run_v1(&mut world, &a, id);
    assert!(settings_sigs(&out).is_empty());
}

/// A message the user deleted after it was imported is removed with the
/// rest: its tombstone is the user's decision.
#[test]
fn a_deleted_message_is_removed_and_the_inbox_closes() {
    let (mut world, a, me, id) = imported_two();
    let one = id_of(&serde_json::to_vec(&held(&me, "one", 1)).unwrap());
    let item = ItemRef {
        kind: ItemKind::Kept,
        owner: Some(a),
        id: one.to_vec(),
    };
    let generation = match world.call_as(&a, Op::GetItem { item: item.clone() }) {
        Ok(Reply::Item(Some(i))) => i.generation,
        other => panic!("{other:?}"),
    };
    world
        .call_as(
            &a,
            Op::DeleteItem {
                item,
                expected_gen: generation,
            },
        )
        .unwrap();
    world.advance(WINDOW);
    let out = run_v1(&mut world, &a, id);
    assert_eq!(land(&mut world, &me, id, &out), 0);
    assert!(is_closed(&settings_of(&world, id)));
}

/// A message too large to keep is tombstoned by the watch, not the user,
/// and is never removed: the inbox stays open.
#[test]
fn a_message_too_large_to_keep_stays() {
    let mut world = World::new();
    let a = world.identity("alice");
    let me = info(&mut world, &a);
    let id = v1_inbox_id(&me.vk).unwrap();
    let big = {
        let mut m: serde_json::Value =
            serde_json::from_slice(&super::jobs::sealed_big(&me)).unwrap();
        m["token_assignment"] =
            serde_json::json!({ "assignment_hash": (vec![9u8; 32]), "tier": "Min10" });
        m
    };
    world.env.contracts.insert(id, v1_state(&me, vec![big]));
    run_v1(&mut world, &a, id);
    assert!(kept_ids(&mut world, &a).is_empty(), "too large to keep");
    world.advance(WINDOW);
    assert!(run_v1(&mut world, &a, id).is_empty());
}

/// An inbox closed already (an identity restored after its close) is
/// recorded as closed, and nothing is signed.
#[test]
fn an_inbox_closed_already_is_never_signed_again() {
    let mut world = World::new();
    let a = world.identity("alice");
    let me = info(&mut world, &a);
    let id = v1_inbox_id(&me.vk).unwrap();
    let mut v: serde_json::Value = serde_json::from_slice(&v1_state(&me, vec![])).unwrap();
    v["settings"]["minimum_tier"] = serde_json::json!("Day365");
    world
        .env
        .contracts
        .insert(id, serde_json::to_vec(&v).unwrap());
    world.advance(WINDOW);
    assert!(run_v1(&mut world, &a, id).is_empty());
    let closes = world.record(&a).v1_window.unwrap().closes;
    assert!(closes.values().all(|c| c.done && c.sig.is_empty()));
}

/// The test clock (`Op::EndV1WindowForTest`) ends the window at once in a
/// `v1-transition` build, and is refused in any other.
#[test]
fn the_test_clock_ends_the_window_only_in_a_transition_build() {
    let (mut world, a, _, id) = imported_two();
    let ended = world.call_as(&a, Op::EndV1WindowForTest { addr: a });
    if cfg!(feature = "v1-transition") {
        assert!(ended.is_ok());
        assert_eq!(run_v1(&mut world, &a, id).len(), 2, "closes now");
    } else {
        assert_eq!(ended, Err(freenet_mail_protocol::FailureCode::Refused));
        assert!(run_v1(&mut world, &a, id).is_empty());
    }
}

/// An identity with no v2 inbox has no window, and nothing closes.
#[test]
fn no_window_without_a_v2_inbox() {
    let mut env = crate::env::mem::MemEnv {
        now: Some(super::inbox_v2::START),
        ..Default::default()
    };
    let me = super::create(&mut env, PROD, "alice");
    let id = v1_inbox_id(&me.vk).unwrap();
    env.contracts
        .insert(id, v1_state(&me, vec![held(&me, "one", 1)]));
    env.now = Some(super::inbox_v2::START + 10 * WINDOW);
    let (_, out) = watch::run(&mut env, Trigger::RunJobs(Origin([PROD; 32])));
    assert!(
        !out.iter()
            .any(|m| matches!(m, OutboundDelegateMsg::UpdateContractRequest(_)))
    );
}

/// An earlier v1 generation held on this node is read during the window and
/// its mail imported once, however many runs; it is never written to.
#[test]
fn an_earlier_generation_is_imported_once_and_never_closed() {
    let mut world = World::new();
    let a = world.identity("alice");
    let me = info(&mut world, &a);
    let old = v1_inbox_id_at(&me.vk, V1_LEGACY_INBOX_CODE_HASHES[1]).unwrap();
    let state = v1_state(&me, vec![held(&me, "old", 4)]);
    world.env.contracts.insert(old, state);
    run_v1(&mut world, &a, old);
    run_v1(&mut world, &a, old);
    assert_eq!(kept_ids(&mut world, &a).len(), 1);
    world.advance(WINDOW);
    assert!(run_v1(&mut world, &a, old).is_empty(), "never written");
    // Past the window it is no longer read: a new arrival stays there.
    let state = v1_state(&me, vec![held(&me, "old", 4), held(&me, "later", 5)]);
    world.env.contracts.insert(old, state);
    run_v1(&mut world, &a, old);
    assert_eq!(kept_ids(&mut world, &a).len(), 1);
}

/// The same message in the current inbox and an earlier one is one kept
/// copy: both are keyed by its ciphertext (decision 27).
#[test]
fn one_message_in_two_generations_is_kept_once() {
    let mut world = World::new();
    let a = world.identity("alice");
    let me = info(&mut world, &a);
    let m = held(&me, "both", 6);
    let cur = v1_inbox_id(&me.vk).unwrap();
    let old = v1_inbox_id_at(&me.vk, V1_LEGACY_INBOX_CODE_HASHES[0]).unwrap();
    world
        .env
        .contracts
        .insert(cur, v1_state(&me, vec![m.clone()]));
    world.env.contracts.insert(old, v1_state(&me, vec![m]));
    run_v1(&mut world, &a, cur);
    run_v1(&mut world, &a, cur);
    assert_eq!(kept_ids(&mut world, &a).len(), 1);
}

/// The earlier generations are exactly the rows of `legacy_inbox.toml`.
#[test]
fn the_earlier_generations_are_the_registry_rows() {
    let toml = include_str!("../../../../legacy_inbox.toml");
    let rows: Vec<&str> = toml
        .lines()
        .filter_map(|l| l.strip_prefix("code_hash = \""))
        .map(|l| l.trim_end_matches('"'))
        .collect();
    assert_eq!(rows, V1_LEGACY_INBOX_CODE_HASHES.to_vec());
}

// ── Decision 26: a verified contact's pass through the queue ────────────────

/// Store `who` as a contact of `owner`'s origin, the way the page stores
/// one, with `vk` as its key.
fn contact(world: &mut World, owner: &Addr, who: &Addr, vk: &[u8], verified: bool) {
    let record = serde_json::json!({
        "v": 1, "local_alias": "them", "description": "",
        "keys": {
            "ml_dsa_vk_bytes": vk, "ml_kem_ek_bytes": [],
            "suggested_alias": null, "verified": verified,
        },
    });
    world
        .call_as(
            owner,
            Op::PutItem {
                item: ItemRef {
                    kind: ItemKind::Contact,
                    owner: None,
                    id: who.0.to_vec(),
                },
                body: ByteBuf::from(serde_json::to_vec(&record).unwrap()),
                expected_gen: Some(0),
            },
        )
        .unwrap();
}

/// `from` sends `to` its pass through the queue, as a v0.3.0 client does
/// for a contact verified in v1.
fn send_pass(world: &mut World, from: &Addr, to: &Addr) {
    let ui_entropy = world.entropy();
    let Ok(Reply::SealedV2(s)) = world.call_as(
        from,
        Op::SealV2 {
            from: *from,
            to: *to,
            to_state: ByteBuf::from(world.inboxes[to].clone()),
            content: SealContent::PassUpdate,
            ghost_vk: None,
            ui_entropy,
            reseals: 0,
        },
    ) else {
        panic!("seal");
    };
    assert_eq!(s.admission, SendAdmission::Quarantine);
    let message: w::Message = w::decode(&s.message).unwrap();
    let delta = w::InboxDelta {
        messages: BTreeMap::from([(serde_bytes::ByteArray::new(s.id.0), message)]),
        ..w::InboxDelta::default()
    };
    world.publish(to, &w::encode(&delta));
}

/// Page runs of both origins until nothing more is sent.
fn settle(world: &mut World, a: &Addr, b: &Addr) {
    for _ in 0..20 {
        let mut quiet = true;
        for who in [a, b] {
            for (id, addr) in [(world_id(world, a), *a), (world_id(world, b), *b)] {
                world.env.contracts.insert(id, world.inboxes[&addr].clone());
            }
            let origin = Origin([world.origin(who); 32]);
            let (_, out) = watch::run(&mut world.env, Trigger::RunJobs(origin));
            for m in out {
                if let OutboundDelegateMsg::UpdateContractRequest(r) = m {
                    let UpdateData::Delta(d) = r.update else {
                        continue;
                    };
                    let id: [u8; 32] = r.contract_id.as_bytes().try_into().unwrap();
                    for x in [*a, *b] {
                        if world_id(world, &x) == id {
                            world.publish(&x, d.as_ref());
                            quiet = false;
                        }
                    }
                }
            }
        }
        if quiet {
            return;
        }
    }
    panic!("never settles");
}

fn world_id(world: &World, addr: &Addr) -> [u8; 32] {
    crate::inbox_jobs::inbox_id(addr, &world.master).unwrap()
}

fn admission_of(world: &mut World, from: &Addr, to: &Addr) -> SendAdmission {
    world.send(from, to, "after").0.admission
}

/// Bob, verified in Alice's v1 address book, sends his pass through her
/// queue. Her drain accepts him (his key signed the message), her renew job
/// sends him hers, and from then on both write by pass.
#[test]
fn a_verified_contacts_pass_is_accepted_and_answered() {
    let mut world = World::new();
    let a = world.identity_in("alice", 1);
    let b = world.identity_in("bob", 2);
    let bob = info(&mut world, &b);
    contact(&mut world, &a, &b, &bob.vk, true);
    send_pass(&mut world, &b, &a);
    settle(&mut world, &a, &b);
    let rec = world.record(&a);
    assert!(
        rec.auto_accepted
            .contains(&serde_bytes::ByteArray::new(b.0))
    );
    assert!(rec.issued.contains_key(&serde_bytes::ByteArray::new(b.0)));
    assert_eq!(admission_of(&mut world, &a, &b), SendAdmission::Pass);
    assert_eq!(admission_of(&mut world, &b, &a), SendAdmission::Pass);
}

/// Not verified: Bob stays in the queue for Alice to decide.
#[test]
fn an_unverified_contact_stays_in_the_queue() {
    let mut world = World::new();
    let a = world.identity_in("alice", 1);
    let b = world.identity_in("bob", 2);
    let bob = info(&mut world, &b);
    contact(&mut world, &a, &b, &bob.vk, false);
    send_pass(&mut world, &b, &a);
    settle(&mut world, &a, &b);
    let rec = world.record(&a);
    assert!(rec.auto_accepted.is_empty());
    assert!(!rec.issued.contains_key(&serde_bytes::ByteArray::new(b.0)));
    assert_eq!(admission_of(&mut world, &b, &a), SendAdmission::Quarantine);
}

/// The record under Bob's address names another key (a record a page wrote
/// from a claimed label, say): the key that signed is not the verified one,
/// so nothing is accepted. A stranger whose message names Bob in its label
/// is not Bob either.
#[test]
fn only_the_key_that_signed_is_accepted() {
    let mut world = World::new();
    let a = world.identity_in("alice", 1);
    let b = world.identity_in("bob", 2);
    let c = world.identity_in("carol", 3);
    let carol = info(&mut world, &c);
    // Under Bob's address, Carol's key, verified.
    contact(&mut world, &a, &b, &carol.vk, true);
    send_pass(&mut world, &b, &a);
    // Carol, whose own address has no record.
    send_pass(&mut world, &c, &a);
    settle(&mut world, &a, &b);
    settle(&mut world, &a, &c);
    let rec = world.record(&a);
    assert!(rec.auto_accepted.is_empty());
    assert!(rec.issued.is_empty());
}

fn env_or(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// The close over a host that misses reads, refuses writes and loses keys
/// for good (`CLOSE_SEEDS`, `CLOSE_RATE`, `CLOSE_BLIND`, per mille): however
/// the runs go, the settings are signed at most once, and every message
/// removed from the v1 inbox has a kept copy that reads back once the host is
/// healthy. A message arrives part way, while the faults are on.
#[test]
fn the_close_over_a_faulty_host_signs_once_and_removes_only_kept_mail() {
    let seeds = env_or("CLOSE_SEEDS", 40);
    let rate = env_or("CLOSE_RATE", 60) as u32;
    let blind = env_or("CLOSE_BLIND", 20) as u32;
    let mut closed = 0;
    for seed in 1..=seeds {
        let (mut world, a, me, id) = imported_two();
        world.advance(WINDOW - 600);
        world.env.faults = Some(Faults::seeded_with_blindness(seed, rate, blind));
        let mut sigs = std::collections::BTreeSet::new();
        let mut removed = std::collections::BTreeSet::new();
        for step in 0..12 {
            if step == 3 {
                let mut v: serde_json::Value =
                    serde_json::from_slice(&world.env.contracts[&id]).unwrap();
                v["messages"]
                    .as_array_mut()
                    .unwrap()
                    .push(held(&me, "late", 3));
                world
                    .env
                    .contracts
                    .insert(id, serde_json::to_vec(&v).unwrap());
            }
            world.advance(300);
            let out = run_v1(&mut world, &a, id);
            sigs.extend(settings_sigs(&out));
            for u in &out {
                if let UpdateInbox::RemoveMessages { ids, .. } = serde_json::from_slice(u).unwrap()
                {
                    removed.extend(ids);
                }
            }
            land(&mut world, &me, id, &out);
        }
        // Healthy again: the close finishes, still under the one signature.
        world.env.faults = None;
        for _ in 0..4 {
            world.advance(300);
            let out = run_v1(&mut world, &a, id);
            sigs.extend(settings_sigs(&out));
            for u in &out {
                if let UpdateInbox::RemoveMessages { ids, .. } = serde_json::from_slice(u).unwrap()
                {
                    removed.extend(ids);
                }
            }
            land(&mut world, &me, id, &out);
        }
        assert!(sigs.len() <= 1, "seed {seed}: signed {} times", sigs.len());
        let titles = [(1u8, "one"), (2, "two"), (3, "late")];
        for (n, title) in titles {
            if !removed.contains(&[n; 32]) {
                continue;
            }
            let mid = id_of(&serde_json::to_vec(&held(&me, title, n)).unwrap());
            let item = ItemRef {
                kind: ItemKind::Kept,
                owner: Some(a),
                id: mid.to_vec(),
            };
            assert!(
                matches!(
                    world.call_as(&a, Op::GetItem { item }),
                    Ok(Reply::Item(Some(_)))
                ),
                "seed {seed}: `{title}` was removed with no kept copy"
            );
        }
        if is_closed(&settings_of(&world, id)) {
            closed += 1;
        }
    }
    // A key lost for good can keep an inbox open; most close.
    assert!(closed * 2 > seeds, "only {closed} of {seeds} closed");
}
