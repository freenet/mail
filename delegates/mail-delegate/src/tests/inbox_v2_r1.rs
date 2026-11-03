//! Inbox v2 review round 1: signature domains, what a drained message may
//! claim, and which held pass a send uses.

use std::collections::BTreeMap;

use freenet_mail_protocol::inbox_v2::{self as w, EnvelopeKind, InboxDelta, Pass, SealedBody};
use freenet_mail_protocol::{
    Addr, Entropy, FailureCode, Hash32, Op, OwnerChange, PassId, Reply, SendAdmission, SendNotice,
};
use serde_bytes::{ByteArray, ByteBuf};

use super::inbox_v2::World;
use super::{PROD, call};
use crate::crypto::{self, Keys, MixRng};
use crate::store::{Origin, Space};

fn keys_of(world: &mut World, addr: &Addr) -> Keys {
    let s = Space::new(&mut world.env, Origin([PROD; 32]));
    let (_, rec) = crate::handlers::require_identity(&s, addr).unwrap();
    Keys::from_seeds(&rec.dsa, &rec.kem)
}

fn vk_of(world: &mut World, addr: &Addr) -> Vec<u8> {
    keys_of(world, addr).vk_bytes()
}

/// Put messages with these assignment hashes in `addr`'s v1 inbox on the node.
fn plant_v1(world: &mut World, addr: &Addr, payload: &[u8]) -> Vec<Hash32> {
    let vk = vk_of(world, addr);
    let msgs: Vec<_> = payload
        .chunks(32)
        .map(|c| serde_json::json!({"token_assignment": {"assignment_hash": c}}))
        .collect();
    let state = serde_json::to_vec(&serde_json::json!({ "messages": msgs })).unwrap();
    world
        .env
        .contracts
        .insert(crate::handlers::v1_inbox_id(&vk).unwrap(), state);
    payload
        .chunks(32)
        .map(|c| Hash32(c.try_into().unwrap()))
        .collect()
}

fn ascending(b: &[u8]) -> bool {
    b.len().is_multiple_of(32)
        && b.chunks(32)
            .collect::<Vec<_>>()
            .windows(2)
            .all(|p| p[0] < p[1])
}

/// A reply pass naming `addr`, with a key that matches and no genuine cert.
fn junk_pass(addr: &Addr, epoch: u32) -> Pass {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[5; 32]);
    Pass {
        cert: w::PassCert {
            recipient: ByteArray::new(addr.0),
            pass_id: ByteArray::new([1; 16]),
            pass_vk: ByteArray::new(sk.verifying_key().to_bytes()),
            epoch,
            expiry: u64::MAX,
            class: w::PassClass::Contact,
            sig: ByteArray::new([0; 64]),
        },
        pass_sk: ByteArray::new([5; 32]),
    }
}

/// Seal by hand: the envelope carries `sender_vk` and `sig` as given.
#[allow(clippy::too_many_arguments)]
fn hand_seal(
    to: &Addr,
    kem_ek: &[u8],
    sender_vk: Vec<u8>,
    sig: Vec<u8>,
    body: Vec<u8>,
    sent_time: u64,
    kind: u8,
    tag: &[u8],
    admission: w::Admission,
) -> ([u8; 32], w::Message) {
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
    use ml_kem::kem::Encapsulate;
    let env = w::encode(&w::SealedEnvelope {
        sender_vk: ByteBuf::from(sender_vk),
        sender_sig: ByteBuf::from(sig),
        body: ByteBuf::from(body),
    });
    let size = w::CIPHERTEXT_SIZES
        .into_iter()
        .find(|s| 24 + 1088 + 16 + 4 + env.len() <= *s)
        .unwrap();
    let mut pt = (env.len() as u32).to_be_bytes().to_vec();
    pt.extend_from_slice(&env);
    pt.resize(size - 24 - 1088 - 16, 0);
    let mut rng = MixRng::new("hand", &[1; 32], &Entropy([2; 32]));
    let ek = crypto::decode_ek(kem_ek).unwrap();
    let (kct, shared) = ek.encapsulate_with_rng(&mut rng);
    let mut key = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(None, shared.as_slice())
        .expand(b"freenet-mail v2 message key", &mut key)
        .unwrap();
    let nonce = [7u8; 24];
    let aad = [b"fmail/ct/v2".as_slice(), to.0.as_slice()].concat();
    let sealed = XChaCha20Poly1305::new(&key.into())
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &pt,
                aad: &aad,
            },
        )
        .unwrap();
    let kct: &[u8] = kct.as_ref();
    let ct = [nonce.as_slice(), kct, &sealed].concat();
    let id = w::message_id(&to.0, blake3::hash(&ct).as_bytes(), sent_time, kind, tag);
    let m = w::Message {
        ciphertext: ByteBuf::from(ct),
        sent_time,
        admission,
    };
    (id, m)
}

fn opens(world: &mut World, to: &Addr, id: &[u8; 32], m: &w::Message) -> bool {
    let keys = keys_of(world, to);
    crate::sealing::open(&keys, &to.0, id, m).is_some()
}

fn quarantine_body(world: &World, from: &Addr, text: &str) -> Vec<u8> {
    let _ = world;
    w::encode(&SealedBody {
        kind: EnvelopeKind::Mail(ByteBuf::from(text.as_bytes().to_vec())),
        reply_pass: junk_pass(from, 1),
        pass_grant: None,
        ghost_vk: None,
    })
}

/// The v1 removal signer does not sign a payload that is a v2 signed layout.
#[test]
fn the_v1_removal_signer_refuses_v2_layouts() {
    let mut world = World::new();
    let v = world.identity("v");
    // A 96-byte sealed binding whose chunks ascend.
    let mut n = 0u32;
    let binding = loop {
        n += 1;
        let h = *blake3::hash(&n.to_be_bytes()).as_bytes();
        let b = w::inner_binding(&[0xC0; 24], &h, 1_793_664_000, w::KIND_PASS, &[0x22; 16]);
        if ascending(&b) {
            break b;
        }
    };
    // The head of an owner record, then a chunk above it.
    let owner = w::owner_bytes(&v.0, &world.state(&v).owner);
    let owner_like = [&owner[..32], &[0xFF; 32][..]].concat();
    for (name, payload) in [("sealed", binding), ("owner", owner_like)] {
        let hashes = plant_v1(&mut world, &v, &payload);
        let got = call(
            &mut world.env,
            PROD,
            Op::SignV1Removal {
                addr: v,
                assignment_hashes: hashes,
            },
        );
        assert_eq!(got, Err(FailureCode::Refused), "{name}");
    }
}

/// A signature over a v2 inner binding without the v2 ML-DSA context, as
/// every v1 path signs, does not open as v2 mail.
#[test]
fn a_v1_signature_over_an_inner_binding_does_not_open() {
    let mut world = World::new();
    let v = world.identity("v");
    let r = world.identity("r");
    let st = world.state(&r);
    let vkeys = keys_of(&mut world, &v);
    let sent_time = crate::inbox_v2::sent_time_for(
        world.env.now.unwrap(),
        st.time.owner_time,
        w::QUARANTINE_FORWARD,
    );
    let body = quarantine_body(&world, &v, "not from v2");
    let binding = w::inner_binding(
        &r.0,
        blake3::hash(&body).as_bytes(),
        sent_time,
        w::KIND_QUARANTINE,
        &[],
    );
    let (id, m) = hand_seal(
        &r,
        &st.owner.kem_ek,
        vkeys.vk_bytes(),
        vkeys.sign(&binding),
        body,
        sent_time,
        w::KIND_QUARANTINE,
        &[],
        w::Admission::Quarantine { ghost: None },
    );
    assert!(!opens(&mut world, &r, &id, &m));
}

/// End to end: no signature the v1 removal path hands out opens as mail from
/// that identity.
#[test]
fn a_removal_signature_never_opens_as_mail() {
    let mut world = World::new();
    let v = world.identity("v");
    let mut i = 0;
    let r = loop {
        i += 1;
        let r = world.identity(&format!("r{i}"));
        if r.0[17] > b'f' {
            break r;
        }
    };
    let vvk = vk_of(&mut world, &v);
    let st = world.state(&r);
    let tag = [0x22u8; 16];
    let sent_time = crate::inbox_v2::sent_time_for(
        world.env.now.unwrap(),
        st.time.owner_time,
        w::WINDOW_FORWARD,
    );
    let mut n = 0u32;
    let (binding, body) = loop {
        n += 1;
        let body = quarantine_body(&world, &v, &format!("invoice #{n}"));
        let b = w::inner_binding(
            &r.0,
            blake3::hash(&body).as_bytes(),
            sent_time,
            w::KIND_PASS,
            &tag,
        );
        if ascending(&b) {
            break (b, body);
        }
    };
    let hashes = plant_v1(&mut world, &v, &binding);
    let got = call(
        &mut world.env,
        PROD,
        Op::SignV1Removal {
            addr: v,
            assignment_hashes: hashes,
        },
    );
    let Ok(Reply::Signature(sig)) = got else {
        assert_eq!(got, Err(FailureCode::Refused));
        return;
    };
    let cert = w::PassCert {
        recipient: ByteArray::new(r.0),
        pass_id: ByteArray::new(tag),
        pass_vk: ByteArray::new([0; 32]),
        epoch: 1,
        expiry: 0,
        class: w::PassClass::Contact,
        sig: ByteArray::new([0; 64]),
    };
    let (id, m) = hand_seal(
        &r,
        &st.owner.kem_ek,
        vvk,
        sig.into_vec(),
        body,
        sent_time,
        w::KIND_PASS,
        &tag,
        w::Admission::Pass {
            cert,
            msg_sig: ByteArray::new([0; 64]),
        },
    );
    assert!(!opens(&mut world, &r, &id, &m), "opened as the victim's");
}

/// An owner record signed without the v2 context is not a genuine inbox.
#[test]
fn an_owner_record_without_the_v2_context_is_refused() {
    let mut world = World::new();
    let a = world.identity("a");
    let b = world.identity("b");
    let mut st = world.state(&b);
    let keys = keys_of(&mut world, &b);
    st.owner.sig = ByteBuf::from(keys.sign(&w::owner_bytes(&b.0, &st.owner)));
    let got = call(
        &mut world.env,
        PROD,
        Op::SealV2 {
            from: a,
            to: b,
            to_state: ByteBuf::from(w::encode(&st)),
            content: freenet_mail_protocol::SealContent::Mail(ByteBuf::from(b"x".to_vec())),
            ghost_vk: None,
            ui_entropy: Entropy([9; 32]),
        },
    );
    assert_eq!(got, Err(FailureCode::BadInput));
}

/// A stranger in an Open inbox names a Ghost Key in the sealed body with no
/// proof: the drained copy does not carry it.
#[test]
fn an_unproven_ghost_key_is_not_kept() {
    let mut world = World::new();
    let a = world.identity("alice");
    let st = world.state(&a);
    let mal = crypto::new_seeds(&mut MixRng::new("x", &[9; 32], &Entropy([8; 32])));
    let keys = Keys::from_seeds(&mal.0, &mal.1);
    let sender = freenet_mail_protocol::address::address_of(&keys.vk_bytes());
    let body = SealedBody {
        kind: EnvelopeKind::Mail(ByteBuf::from(b"from the ghost key holder".to_vec())),
        reply_pass: junk_pass(&sender, 1),
        pass_grant: None,
        ghost_vk: Some(ByteArray::new([0xAB; 32])),
    };
    let sent_time = crate::inbox_v2::sent_time_for(
        world.env.now.unwrap(),
        st.time.owner_time,
        w::QUARANTINE_FORWARD,
    );
    let mut rng = MixRng::new("p", &[1; 32], &Entropy([2; 32]));
    let ct = crate::sealing::seal(
        &keys,
        &a.0,
        &st.owner.kem_ek,
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
    let msg = w::Message {
        ciphertext: ByteBuf::from(ct),
        sent_time,
        admission: w::Admission::Quarantine { ghost: None },
    };
    let delta = InboxDelta {
        messages: BTreeMap::from([(ByteArray::new(id), msg)]),
        ..Default::default()
    };
    world.publish(&a, &w::encode(&delta));
    assert!(w::delivered(&world.state(&a), &id), "the contract holds it");
    world.change(&a, OwnerChange::Drain);
    let got = world.inbound(&a);
    assert_eq!(got.len(), 1, "the mail itself is kept");
    assert_eq!(got[0].ghost_vk, None);
}

fn publish_sealed(world: &mut World, to: &Addr, sealed: &freenet_mail_protocol::SealedV2) {
    let message: w::Message = w::decode(&sealed.message).unwrap();
    let delta = InboxDelta {
        messages: BTreeMap::from([(ByteArray::new(sealed.id.0), message)]),
        ..InboxDelta::default()
    };
    world.publish(to, &w::encode(&delta));
}

fn only_issued(world: &mut World, a: &Addr) -> w::B16 {
    let issued = world.record(a).issued;
    assert_eq!(issued.len(), 1);
    *issued.values().next().unwrap()
}

/// After Alice revokes Bob's pass and writes to him again, Bob writes back
/// with the new pass, whichever of the two he drained last. Run over seeds
/// until the new pass's expiry is below the revoked one's, then both orders.
#[test]
fn a_reissued_pass_is_used_after_a_revoke_in_either_order() {
    let mut orders_seen = [false; 2];
    for seed in 0..80u8 {
        for (order, seen) in orders_seen.into_iter().enumerate() {
            if seen {
                continue;
            }
            let mut world = World::new();
            for _ in 0..seed {
                world.entropy();
            }
            let a = world.identity("alice");
            let b = world.identity("bob");
            world.send(&b, &a, "hi");
            world.change(&a, OwnerChange::Drain);
            // Mail carrying P1, published now (order 0) or after P2 (order 1).
            let first = world.seal(&a, &b, "first").unwrap();
            if order == 0 {
                publish_sealed(&mut world, &b, &first);
                world.change(&b, OwnerChange::Drain);
            }
            let p1 = only_issued(&mut world, &a);
            let e1 = world.ledger(&a, p1.as_slice());
            world.change(
                &a,
                OwnerChange::Revoke {
                    pass_id: PassId(*p1),
                },
            );
            world.send(&a, &b, "unblocked");
            world.change(&b, OwnerChange::Drain);
            let p2 = only_issued(&mut world, &a);
            assert_ne!(p1, p2);
            let e2 = world.ledger(&a, p2.as_slice());
            if e2.expiry >= e1.expiry {
                continue;
            }
            if order == 1 {
                publish_sealed(&mut world, &b, &first);
                world.change(&b, OwnerChange::Drain);
            }
            let (s, landed) = world.send(&b, &a, "back");
            assert!(landed);
            assert_eq!(s.notice, None, "order {order}, seed {seed}");
            let w::Admission::Pass { cert, .. } =
                w::decode::<w::Message>(&s.message).unwrap().admission
            else {
                panic!("order {order}: Bob fell back to quarantine");
            };
            assert_eq!(cert.pass_id, p2, "order {order}");
            assert_eq!(s.admission, SendAdmission::Pass);
            orders_seen[order] = true;
        }
        if orders_seen == [true; 2] {
            return;
        }
    }
    panic!("no seed gave a lower expiry: {orders_seen:?}");
}

/// Strangers writing from fresh keys never use up the held passes: a new
/// correspondent who writes after 2048 of them is still answered by pass.
#[test]
fn strangers_never_crowd_out_a_new_correspondents_pass() {
    let mut world = World::new();
    let a = world.identity("alice");
    let base = world.state(&a);
    let mut rng = MixRng::new("strangers", &[3; 32], &Entropy([4; 32]));
    let strangers = crate::store::MAX_CONTACTS + 8;
    let mut made = 0;
    while made < strangers {
        let mut st = base.clone();
        for _ in 0..crate::inbox_v2::DRAIN_BATCH.min(strangers - made) {
            made += 1;
            let seeds = crypto::new_seeds(&mut rng);
            let keys = Keys::from_seeds(&seeds.0, &seeds.1);
            let sender = freenet_mail_protocol::address::address_of(&keys.vk_bytes());
            let mut pass = junk_pass(&sender, 1);
            pass.cert.pass_id = ByteArray::new((made as u128).to_be_bytes());
            let body = SealedBody {
                kind: EnvelopeKind::Mail(ByteBuf::from(format!("stranger {made}").into_bytes())),
                reply_pass: pass,
                pass_grant: None,
                ghost_vk: None,
            };
            let sent_time = crate::inbox_v2::sent_time_for(
                world.env.now.unwrap(),
                st.time.owner_time,
                w::QUARANTINE_FORWARD,
            );
            let ct = crate::sealing::seal(
                &keys,
                &a.0,
                &st.owner.kem_ek,
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
            st.messages.insert(
                ByteArray::new(id),
                w::Message {
                    ciphertext: ByteBuf::from(ct),
                    sent_time,
                    admission: w::Admission::Quarantine { ghost: None },
                },
            );
        }
        let ui_entropy = world.entropy();
        let got = world.call_as(
            &a,
            Op::UpdateInboxV2 {
                addr: a,
                state: ByteBuf::from(w::encode(&st)),
                change: OwnerChange::Drain,
                ui_entropy,
            },
        );
        let Ok(Reply::InboxV2Update(u)) = got else {
            panic!("{got:?}");
        };
        assert_eq!((u.remaining, u.full), (0, 0), "after {made}");
    }
    let c = world.identity("carol");
    let (hello, landed) = world.send(&c, &a, "hello");
    assert!(landed);
    assert_eq!(hello.admission, SendAdmission::Quarantine);
    world.change(&a, OwnerChange::Drain);
    let (reply, landed) = world.send(&a, &c, "hello carol");
    assert!(landed);
    assert_eq!(reply.admission, SendAdmission::Pass, "{:?}", reply.notice);
    let _: Option<SendNotice> = reply.notice;
}

fn hold_pass(world: &mut World, addr: &Addr, pass: Pass) -> Result<Reply, FailureCode> {
    call(&mut world.env, PROD, Op::HoldPass { addr: *addr, pass })
}

fn node_holds(world: &mut World, addr: &Addr) {
    let id = crate::inbox_jobs::inbox_id(addr, &world.master).unwrap();
    let state = world.inboxes[addr].clone();
    world.env.contracts.insert(id, state);
}

/// Held passes full of contacts' (handed over by the page): a stranger's
/// pass finds no room, and the drain says so rather than drop it. The
/// message stays in the inbox, counted as full.
#[test]
fn a_full_set_of_held_passes_is_reported() {
    let mut world = World::new();
    let a = world.identity("alice");
    for n in 0..crate::store::MAX_CONTACTS as u32 {
        let mut addr = [0u8; 24];
        addr[..4].copy_from_slice(&n.to_be_bytes());
        hold_pass(&mut world, &a, junk_pass(&Addr(addr), 1)).unwrap();
    }
    let d = world.identity("dave");
    let (sealed, landed) = world.send(&d, &a, "hello");
    assert!(landed);
    let u = world.update(&a, OwnerChange::Drain).unwrap();
    assert_eq!((u.drained, u.full), (0, 1));
    assert!(w::delivered(&world.state(&a), &sealed.id.0));
    assert!(world.inbound(&a).is_empty());
}

/// A certificate that is not its recipient's is refused when this node holds
/// the recipient's inbox; one held unchecked never shadows a genuine pass.
#[test]
fn held_certificates_are_checked_and_never_shadow_a_genuine_pass() {
    let mut world = World::new();
    let a = world.identity("alice");
    let b = world.identity("bob");
    let mut forged = junk_pass(&a, u32::MAX);
    forged.cert.pass_id = ByteArray::new([9; 16]);
    // Alice's inbox not held here: kept, and checked at send time.
    hold_pass(&mut world, &b, forged.clone()).unwrap();
    node_holds(&mut world, &a);
    forged.cert.pass_id = ByteArray::new([8; 16]);
    assert_eq!(
        hold_pass(&mut world, &b, forged),
        Err(FailureCode::BadInput)
    );
    let genuine = world.issue(&a, Some(b), None);
    hold_pass(&mut world, &b, genuine.clone()).unwrap();
    let (s, landed) = world.send(&b, &a, "hi");
    assert!(landed);
    let w::Admission::Pass { cert, .. } = w::decode::<w::Message>(&s.message).unwrap().admission
    else {
        panic!("not by pass");
    };
    assert_eq!(cert.pass_id, genuine.cert.pass_id);
}

/// A page's state must carry a genuine owner record and time, and an owner
/// version at its limit takes no change rather than wrapping.
#[test]
fn a_page_state_must_verify_and_versions_never_wrap() {
    let mut world = World::new();
    let a = world.identity("alice");
    let update = |world: &mut World, st: &w::InboxState| {
        let ui_entropy = world.entropy();
        world.call_as(
            &a,
            Op::UpdateInboxV2 {
                addr: a,
                state: ByteBuf::from(w::encode(st)),
                change: OwnerChange::SetQuarantine(w::QuarantineMode::RequireGhost {
                    min_usd: None,
                }),
                ui_entropy,
            },
        )
    };
    let mut st = world.state(&a);
    st.time.owner_time += 400 * 86_400;
    assert_eq!(update(&mut world, &st), Err(FailureCode::BadInput), "time");
    let mut st = world.state(&a);
    st.owner.version = u64::MAX;
    assert_eq!(
        update(&mut world, &st),
        Err(FailureCode::BadInput),
        "unsigned"
    );
    let keys = keys_of(&mut world, &a);
    st.owner.sig =
        ByteBuf::from(keys.sign_v2(w::OWNER_SIG_CONTEXT, &w::owner_bytes(&a.0, &st.owner)));
    assert_eq!(
        update(&mut world, &st),
        Err(FailureCode::Refused),
        "at the limit"
    );
}

/// The page's state is checked again before the drain trusts an admission:
/// a pass admission the contract never saw counts no invite use, and a
/// Ghost Key proof the node does not hold is not the message's.
#[test]
fn a_page_state_admission_is_checked_before_it_counts() {
    let mut world = World::new();
    let a = world.identity("alice");
    let invite = world.issue(&a, None, Some(3));
    let mut st = world.state(&a);
    let mut rng = MixRng::new("s5", &[3; 32], &Entropy([4; 32]));
    let seeds = crypto::new_seeds(&mut rng);
    let keys = Keys::from_seeds(&seeds.0, &seeds.1);
    let sender = freenet_mail_protocol::address::address_of(&keys.vk_bytes());
    let mut seal_as = |kind: u8, tag: &[u8], ghost_vk: Option<w::B32>, admission: w::Admission| {
        let body = SealedBody {
            kind: EnvelopeKind::Mail(ByteBuf::from(format!("kind {kind}").into_bytes())),
            reply_pass: junk_pass(&sender, 1),
            pass_grant: None,
            ghost_vk,
        };
        let sent_time = crate::inbox_v2::sent_time_for(
            world.env.now.unwrap(),
            st.time.owner_time,
            w::QUARANTINE_FORWARD,
        );
        let ct = crate::sealing::seal(
            &keys,
            &a.0,
            &st.owner.kem_ek,
            sent_time,
            kind,
            tag,
            &body,
            &mut rng,
        )
        .unwrap();
        let id = w::message_id(&a.0, blake3::hash(&ct).as_bytes(), sent_time, kind, tag);
        st.messages.insert(
            ByteArray::new(id),
            w::Message {
                ciphertext: ByteBuf::from(ct),
                sent_time,
                admission,
            },
        );
    };
    // The invite's id and certificate, but no signature by its key.
    seal_as(
        w::KIND_PASS,
        invite.cert.pass_id.as_slice(),
        None,
        w::Admission::Pass {
            cert: invite.cert.clone(),
            msg_sig: ByteArray::new([0; 64]),
        },
    );
    let ghost = ByteArray::new([0xCD; 32]);
    seal_as(
        w::KIND_QUARANTINE,
        ghost.as_slice(),
        Some(ghost),
        w::Admission::Quarantine {
            ghost: Some(w::GhostProof {
                cert: ByteBuf::from(vec![1, 2, 3]),
                scoped_payload: ByteBuf::new(),
                ghost_sig: ByteArray::new([0; 64]),
            }),
        },
    );
    let ui_entropy = world.entropy();
    let Ok(Reply::InboxV2Update(u)) = world.call_as(
        &a,
        Op::UpdateInboxV2 {
            addr: a,
            state: ByteBuf::from(w::encode(&st)),
            change: OwnerChange::Drain,
            ui_entropy,
        },
    ) else {
        panic!("update");
    };
    assert_eq!(u.drained, 2, "both are genuine mail from their sender");
    let delta: InboxDelta = w::decode(&u.update.unwrap()).unwrap();
    assert!(delta.usage.is_empty(), "an invite use was counted");
    assert!(
        world
            .ledger(&a, invite.cert.pass_id.as_slice())
            .drained
            .is_empty()
    );
    assert!(world.inbound(&a).iter().all(|m| m.ghost_vk.is_none()));
}

/// The v2 operations refuse all-zero page entropy, as `seal_v1` does.
#[test]
fn v2_operations_refuse_zero_entropy() {
    let mut world = World::new();
    let a = world.identity("alice");
    let b = world.identity("bob");
    let zero = Entropy([0; 32]);
    let ops = [
        Op::SealV2 {
            from: a,
            to: b,
            to_state: ByteBuf::from(world.inboxes[&b].clone()),
            content: freenet_mail_protocol::SealContent::Mail(ByteBuf::from(b"x".to_vec())),
            ghost_vk: None,
            ui_entropy: zero,
        },
        Op::IssuePass {
            addr: a,
            contact: Some(b),
            invite: None,
            ui_entropy: zero,
        },
        Op::UpdateInboxV2 {
            addr: a,
            state: ByteBuf::from(world.inboxes[&a].clone()),
            change: OwnerChange::Drain,
            ui_entropy: zero,
        },
    ];
    for op in ops {
        let name = format!("{op:?}").chars().take(12).collect::<String>();
        assert_eq!(
            call(&mut world.env, PROD, op),
            Err(FailureCode::BadInput),
            "{name}"
        );
    }
    assert!(world.record(&a).issued.is_empty(), "nothing was issued");
}
