//! Behaviour through the delegate's entry point, over an in-memory host.

mod faults;
mod recovery;
mod resilience;
mod round2;
mod round3;

use freenet_mail_protocol::{
    Addr, DsaSeed, Entropy, FailureCode, Hash32, IdentityInfo, ImportKind, ImportSource, ItemKind,
    ItemRef, KemSeed, Op, PROTOCOL_VERSION, Reply, Request, RequestId, Response, from_cbor,
    recovery_key, to_cbor,
};
use freenet_stdlib::prelude::{
    ApplicationMessage, ClientResponse, CodeHash, ContractInstanceId, DelegateContext, DelegateKey,
    InboundDelegateMsg, MessageOrigin, OutboundDelegateMsg, UserInputResponse,
};
use serde_bytes::ByteBuf;

use crate::consent::{ALLOW, ALWAYS, CANCEL, DELETE, DENY};
use crate::env::mem::MemEnv;
use crate::handlers::process;
use crate::store::{self, Origin, Space};

const PROD: u8 = 1;
const OTHER: u8 = 2;

fn app(b: u8) -> Option<MessageOrigin> {
    Some(MessageOrigin::WebApp(ContractInstanceId::new([b; 32])))
}

fn foreign_delegate() -> Option<MessageOrigin> {
    Some(MessageOrigin::Delegate(DelegateKey::new(
        [3; 32],
        CodeHash::from_code(b"other"),
    )))
}

fn app_msg(op: Op) -> InboundDelegateMsg<'static> {
    let req = Request {
        version: PROTOCOL_VERSION,
        request_id: RequestId([0x5a; 16]),
        op,
    };
    InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(to_cbor(&req).unwrap()))
}

fn send(env: &mut MemEnv, origin: Option<MessageOrigin>, op: Op) -> Vec<OutboundDelegateMsg> {
    process(env, origin, app_msg(op)).expect("a web-app request is answered, not errored")
}

fn responses(out: &[OutboundDelegateMsg]) -> Vec<Response> {
    out.iter()
        .filter_map(|m| match m {
            OutboundDelegateMsg::ApplicationMessage(m) => {
                assert!(m.processed);
                Some(from_cbor(&m.payload).unwrap())
            }
            _ => None,
        })
        .collect()
}

fn response(out: &[OutboundDelegateMsg]) -> Response {
    assert_eq!(out.len(), 1, "exactly one message per request: {out:?}");
    responses(out).pop().expect("a response")
}

fn call(env: &mut MemEnv, origin: u8, op: Op) -> Result<Reply, FailureCode> {
    let r = response(&send(env, app(origin), op));
    assert_eq!(r.request_id, RequestId([0x5a; 16]));
    r.result.map_err(|f| f.code)
}

fn create(env: &mut MemEnv, origin: u8, alias: &str) -> IdentityInfo {
    match call(
        env,
        origin,
        Op::CreateIdentity {
            alias: alias.into(),
            description: String::new(),
            ui_entropy: Entropy([alias.len() as u8 + 1; 32]),
        },
    ) {
        Ok(Reply::CreatedIdentity {
            identity,
            recovery_key,
        }) => {
            // The key returned on creation is this identity's own: both
            // halves (the address depends on the signing half only).
            let (dsa, kem) = recovery_key::decode(&recovery_key).unwrap();
            let keys = crate::crypto::Keys::from_seeds(&dsa, &kem);
            assert_eq!(
                freenet_mail_protocol::address::address_of(&keys.vk_bytes()),
                identity.addr
            );
            assert_eq!(keys.ek_bytes(), identity.ek.to_vec());
            identity
        }
        other => panic!("{other:?}"),
    }
}

fn draft(owner: Addr, id: u8) -> ItemRef {
    ItemRef {
        kind: ItemKind::Draft,
        owner: Some(owner),
        id: vec![id; 16],
    }
}

fn contact(id: u8) -> ItemRef {
    ItemRef {
        kind: ItemKind::Contact,
        owner: None,
        id: vec![id; 24],
    }
}

fn put_as(
    env: &mut MemEnv,
    origin: u8,
    item: ItemRef,
    body: &[u8],
    expected_gen: Option<u64>,
) -> Result<Reply, FailureCode> {
    call(
        env,
        origin,
        Op::PutItem {
            item,
            body: ByteBuf::from(body.to_vec()),
            expected_gen,
        },
    )
}

fn put(env: &mut MemEnv, item: ItemRef, body: &[u8], g: Option<u64>) -> Result<Reply, FailureCode> {
    put_as(env, PROD, item, body, g)
}

fn ack(r: Result<Reply, FailureCode>) -> u64 {
    match r {
        Ok(Reply::Ack { generation }) => generation,
        other => panic!("expected Ack, got {other:?}"),
    }
}

fn ns_snapshot(env: &MemEnv, origin: u8) -> Vec<(Vec<u8>, Vec<u8>)> {
    let ns = store::namespace(&Origin([origin; 32])).into_bytes();
    env.secrets
        .iter()
        .filter(|(k, _)| k.starts_with(&ns))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

fn list_ids(env: &mut MemEnv, origin: u8, kind: ItemKind, owner: Option<Addr>) -> Vec<Vec<u8>> {
    match call(
        env,
        origin,
        Op::ListItems {
            kind,
            owner,
            after: None,
            limit: 256,
        },
    ) {
        Ok(Reply::Items { items, .. }) => items.into_iter().map(|i| i.item.id).collect(),
        other => panic!("{other:?}"),
    }
}

// ── Origin gate ─────────────────────────────────────────────────────────────

fn mutating_ops(a: Addr, g: u64) -> Vec<Op> {
    vec![
        Op::CreateIdentity {
            alias: "x".into(),
            description: String::new(),
            ui_entropy: Entropy([1; 32]),
        },
        Op::UpdateIdentity {
            addr: a,
            alias: "x".into(),
            description: String::new(),
            expected_gen: g,
        },
        Op::ConfirmIdentity {
            addr: a,
            expected_gen: g,
        },
        Op::DeleteIdentity {
            addr: a,
            expected_gen: g,
        },
        Op::PutItem {
            item: draft(a, 1),
            body: ByteBuf::from(b"x".to_vec()),
            expected_gen: None,
        },
        Op::PutItem {
            item: contact(9),
            body: ByteBuf::from(b"x".to_vec()),
            expected_gen: None,
        },
        Op::DeleteItem {
            item: draft(a, 1),
            expected_gen: 0,
        },
        Op::ExportRecoveryKey { addr: a },
        Op::ExportForSuccessor {
            source_generation: 1,
            after: None,
            session: None,
        },
    ]
}

#[test]
fn origin_gate_truth_table() {
    let mut env = MemEnv::default();
    assert!(process(&mut env, app(PROD), app_msg(Op::GetStatus)).is_ok());
    assert!(process(&mut env, None, app_msg(Op::GetStatus)).is_err());
    assert!(process(&mut env, foreign_delegate(), app_msg(Op::GetStatus)).is_err());
}

#[test]
fn delegate_and_unattested_callers_change_nothing() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    ack(put(&mut env, draft(me.addr, 1), b"d", None));
    let before = env.secrets.clone();
    for origin in [None, foreign_delegate()] {
        for op in mutating_ops(me.addr, me.generation) {
            assert!(process(&mut env, origin.clone(), app_msg(op)).is_err());
        }
        let answer = UserInputResponse {
            request_id: 1,
            response: ClientResponse::new(ALLOW.to_vec()),
            context: DelegateContext::default(),
        };
        assert!(process(&mut env, origin, InboundDelegateMsg::UserResponse(answer)).is_err());
    }
    assert_eq!(env.secrets, before);
}

/// Every request a foreign web app can send against a populated production
/// namespace: each answer is a refusal or empty, and production's bytes do
/// not change.
#[test]
fn a_foreign_origin_can_neither_read_nor_change_another_namespace() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    ack(put(&mut env, draft(me.addr, 1), b"secret draft", Some(0)));
    ack(put(&mut env, contact(9), b"bob", None));
    let before = ns_snapshot(&env, PROD);
    let a = me.addr;
    let mut ops = mutating_ops(a, me.generation);
    ops.extend([
        Op::ListIdentities,
        Op::ListItems {
            kind: ItemKind::Draft,
            owner: Some(a),
            after: None,
            limit: 10,
        },
        Op::ListItems {
            kind: ItemKind::Contact,
            owner: None,
            after: None,
            limit: 10,
        },
        Op::GetItem { item: draft(a, 1) },
        Op::GetItem { item: contact(9) },
        Op::PutItem {
            item: contact(9),
            body: ByteBuf::from(b"x".to_vec()),
            expected_gen: Some(3),
        },
        Op::DeleteItem {
            item: contact(9),
            expected_gen: 3,
        },
        Op::DecryptV1 {
            addr: a,
            ciphertexts: vec![],
        },
        Op::SealV1Message {
            addr: a,
            recipient_ek: me.ek.clone(),
            plaintext: ByteBuf::new(),
            ui_entropy: Entropy([1; 32]),
        },
        Op::SignV1Authority {
            addr: a,
            settings_json: ByteBuf::from(b"{}".to_vec()),
            last_update_micros: 0,
        },
        Op::SignV1Removal {
            addr: a,
            assignment_hashes: vec![Hash32([1; 32])],
        },
        Op::V1AftParams { addr: a },
        Op::ExportProfile { addr: a },
    ]);
    for op in ops {
        for m in send(&mut env, app(OTHER), op.clone()) {
            let OutboundDelegateMsg::ApplicationMessage(m) = m else {
                continue; // a prompt in OTHER's own namespace
            };
            match from_cbor::<Response>(&m.payload).unwrap().result {
                Err(_) => {}
                Ok(Reply::Identities(v)) => assert!(v.iter().all(|i| i.alias == "x"), "{op:?}"),
                Ok(Reply::Items { items, .. }) => {
                    assert!(items.iter().all(|i| i.body.as_ref() == b"x"), "{op:?}")
                }
                Ok(Reply::Item(Some(i))) => assert_eq!(i.body.as_ref(), b"x", "{op:?}"),
                Ok(Reply::Item(None) | Reply::Deleted | Reply::Ack { .. } | Reply::Identity(_)) => {
                }
                // The caller's own new identity, in its own namespace.
                Ok(Reply::CreatedIdentity { identity, .. }) => {
                    assert_eq!(identity.alias, "x", "{op:?}")
                }
                Ok(other) => panic!("{op:?} leaked {other:?}"),
            }
        }
    }
    assert_eq!(ns_snapshot(&env, PROD), before);
}

// ── Storage ─────────────────────────────────────────────────────────────────

#[test]
fn another_app_exhausting_its_budget_and_the_host_registry_does_not_touch_mail() {
    let mut env = MemEnv::default();
    // Far more foreign keys than the host's 4096-key enumeration cap.
    for i in 0..5000 {
        env.secrets
            .insert(format!("o/foreign/{i}").into_bytes(), vec![0; 8]);
    }
    // The other app has used its whole budget.
    {
        let mut other = Space::new(&mut env, Origin([OTHER; 32]));
        other.put("filler", b"x").unwrap();
        let usage_key = other.full_key("mt/usage");
        let mut full = store::MAX_ORIGIN_KEYS.to_le_bytes().to_vec();
        full.extend_from_slice(&0u64.to_le_bytes());
        env.secrets.insert(usage_key, full);
    }
    assert_eq!(
        call(
            &mut env,
            OTHER,
            Op::CreateIdentity {
                alias: "o".into(),
                description: String::new(),
                ui_entropy: Entropy([5; 32])
            }
        ),
        Err(FailureCode::CapReached)
    );
    // Mail still creates, writes, lists and exports.
    let me = create(&mut env, PROD, "alice");
    for id in 1..=3 {
        ack(put(&mut env, draft(me.addr, id), &[id], None));
    }
    assert_eq!(
        list_ids(&mut env, PROD, ItemKind::Draft, Some(me.addr)).len(),
        3
    );
    let s = Space::new(&mut env, Origin([PROD; 32]));
    let keys = crate::handlers::exportable_keys(&s).unwrap();
    assert!(keys.iter().any(|k| k.starts_with("it/dr/")));
}

#[test]
fn per_kind_caps_are_enforced_from_the_index() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    for id in 0..store::MAX_DRAFTS {
        let item = ItemRef {
            kind: ItemKind::Draft,
            owner: Some(me.addr),
            id: (id as u128).to_le_bytes().to_vec(),
        };
        ack(put(&mut env, item, b"d", None));
    }
    assert_eq!(
        put(&mut env, draft(me.addr, 0xff), b"d", None),
        Err(FailureCode::CapReached)
    );
    let settings = ItemRef {
        kind: ItemKind::GlobalSettings,
        owner: None,
        id: vec![],
    };
    ack(put(&mut env, settings, b"s", None));
    for i in 0..store::MAX_IDENTITIES - 1 {
        create(&mut env, PROD, &format!("id{i}"));
    }
    assert_eq!(
        call(
            &mut env,
            PROD,
            Op::CreateIdentity {
                alias: "extra".into(),
                description: String::new(),
                ui_entropy: Entropy([9; 32])
            }
        ),
        Err(FailureCode::CapReached)
    );
}

#[test]
fn cas_refuses_a_stale_writer_and_accepts_the_current_one() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    let item = draft(me.addr, 1);
    let g1 = ack(put(&mut env, item.clone(), b"v1", Some(0)));
    let g2 = ack(put(&mut env, item.clone(), b"v2", Some(g1)));
    assert!(g2 > g1);
    assert_eq!(
        put(&mut env, item.clone(), b"stale", Some(g1)),
        Err(FailureCode::Conflict { current_gen: g2 })
    );
    assert_eq!(
        put(&mut env, item.clone(), b"new", None),
        Err(FailureCode::Conflict { current_gen: g2 })
    );
    // A retry of a write that landed is acknowledged, not refused, whether
    // it was a CAS write or a create.
    assert_eq!(ack(put(&mut env, item.clone(), b"v2", Some(g1))), g2);
    assert_eq!(ack(put(&mut env, item.clone(), b"v2", None)), g2);
    match call(&mut env, PROD, Op::GetItem { item }) {
        Ok(Reply::Item(Some(i))) => assert_eq!((i.body.as_ref(), i.generation), (&b"v2"[..], g2)),
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_generation_from_before_a_delete_cannot_overwrite_the_recreated_item() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    let item = draft(me.addr, 1);
    let g1 = ack(put(&mut env, item.clone(), b"v1", Some(0)));
    assert_eq!(
        call(
            &mut env,
            PROD,
            Op::DeleteItem {
                item: item.clone(),
                expected_gen: g1
            }
        ),
        Ok(Reply::Deleted)
    );
    assert!(list_ids(&mut env, PROD, ItemKind::Draft, Some(me.addr)).is_empty());
    let g_new = ack(put(&mut env, item.clone(), b"recreated", None));
    assert_eq!(
        put(&mut env, item.clone(), b"stale", Some(g1)),
        Err(FailureCode::Conflict { current_gen: g_new })
    );
    assert_eq!(
        call(
            &mut env,
            PROD,
            Op::DeleteItem {
                item,
                expected_gen: g1
            }
        ),
        Err(FailureCode::Conflict { current_gen: g_new })
    );
}

#[test]
fn two_tabs_racing_on_settings_cannot_lose_an_update() {
    let mut env = MemEnv::default();
    let settings = ItemRef {
        kind: ItemKind::GlobalSettings,
        owner: None,
        id: vec![],
    };
    let g0 = ack(put(&mut env, settings.clone(), b"theme=dark", None));
    let ga = ack(put(
        &mut env,
        settings.clone(),
        b"theme=dark,density=compact",
        Some(g0),
    ));
    assert_eq!(
        put(&mut env, settings.clone(), b"theme=light", Some(g0)),
        Err(FailureCode::Conflict { current_gen: ga })
    );
    ack(put(
        &mut env,
        settings,
        b"theme=light,density=compact",
        Some(ga),
    ));
}

#[test]
fn items_need_the_right_shape_and_an_existing_owner() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    let bad_id = ItemRef {
        kind: ItemKind::Draft,
        owner: Some(me.addr),
        id: vec![1; 15],
    };
    assert_eq!(
        put(&mut env, bad_id, b"x", None),
        Err(FailureCode::BadInput)
    );
    let no_owner = ItemRef {
        kind: ItemKind::Draft,
        owner: None,
        id: vec![1; 16],
    };
    assert_eq!(
        put(&mut env, no_owner, b"x", None),
        Err(FailureCode::BadInput)
    );
    assert_eq!(
        put(&mut env, draft(Addr([7; 24]), 1), b"x", None),
        Err(FailureCode::NotFound)
    );
    let big = vec![0; freenet_mail_protocol::MAX_ITEM_BYTES + 1];
    assert_eq!(
        put(&mut env, draft(me.addr, 1), &big, None),
        Err(FailureCode::BadInput)
    );
    assert_eq!(
        call(
            &mut env,
            PROD,
            Op::ListItems {
                kind: ItemKind::Draft,
                owner: None,
                after: None,
                limit: 1
            }
        ),
        Err(FailureCode::BadInput)
    );
}

#[test]
fn listing_pages_in_id_order_and_within_the_response_budget() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    for id in [3u8, 1, 2] {
        ack(put(&mut env, draft(me.addr, id), &[id], None));
    }
    let page = |env: &mut MemEnv, after: Option<Vec<u8>>, limit| match call(
        env,
        PROD,
        Op::ListItems {
            kind: ItemKind::Draft,
            owner: Some(me.addr),
            after: after.map(ByteBuf::from),
            limit,
        },
    ) {
        Ok(Reply::Items { items, more }) => (
            items.into_iter().map(|i| i.item.id[0]).collect::<Vec<_>>(),
            more,
        ),
        other => panic!("{other:?}"),
    };
    assert_eq!(page(&mut env, None, 2), (vec![1, 2], true));
    assert_eq!(page(&mut env, Some(vec![2; 16]), 2), (vec![3], false));
    // Three 200 KiB bodies do not fit one 512 KiB response.
    let big = vec![7u8; 200 * 1024];
    for id in [1u8, 2, 3] {
        let g = match call(
            &mut env,
            PROD,
            Op::GetItem {
                item: draft(me.addr, id),
            },
        ) {
            Ok(Reply::Item(Some(i))) => i.generation,
            other => panic!("{other:?}"),
        };
        ack(put(&mut env, draft(me.addr, id), &big, Some(g)));
    }
    assert_eq!(page(&mut env, None, 10), (vec![1, 2], true));
}

#[test]
fn status_reports_only_the_callers_namespace() {
    let mut env = MemEnv::default();
    create(&mut env, PROD, "alice");
    match call(&mut env, OTHER, Op::GetStatus) {
        Ok(Reply::Status(st)) => {
            assert_eq!((st.identities, st.stored_keys, st.stored_bytes), (0, 0, 0));
            assert_eq!(st.key_budget, store::MAX_ORIGIN_KEYS);
            assert_eq!(st.v1_transition, cfg!(feature = "v1-transition"));
        }
        other => panic!("{other:?}"),
    }
    match call(&mut env, PROD, Op::GetStatus) {
        Ok(Reply::Status(st)) => {
            assert_eq!(st.identities, 1);
            assert!(st.stored_keys >= 3 && st.stored_bytes > 0);
        }
        other => panic!("{other:?}"),
    }
}

// ── Identities ──────────────────────────────────────────────────────────────

#[test]
fn the_recovery_key_comes_back_on_creation_only() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    // Re-creating under the same alias is refused: no second key.
    assert_eq!(
        call(
            &mut env,
            PROD,
            Op::CreateIdentity {
                alias: "alice".into(),
                description: String::new(),
                ui_entropy: Entropy([7; 32]),
            }
        ),
        Err(FailureCode::Conflict { current_gen: 0 })
    );
    // Importing an identity answers with its public view only, fresh or not.
    let (dsa, kem) = fixture_seeds();
    for _ in 0..2 {
        match call(
            &mut env,
            PROD,
            Op::ImportIdentity {
                source: ImportSource::Seeds {
                    dsa: dsa.clone(),
                    kem: kem.clone(),
                },
                kind: ImportKind::UserRestore,
                alias: "bob".into(),
                description: String::new(),
            },
        ) {
            Ok(Reply::Imported { .. }) => {}
            other => panic!("{other:?}"),
        }
    }
    // Listing never carries a key either.
    match call(&mut env, PROD, Op::ListIdentities) {
        Ok(Reply::Identities(ids)) => assert!(ids.iter().any(|i| i.addr == me.addr)),
        other => panic!("{other:?}"),
    }
}

#[test]
fn identities_are_created_without_exposing_seeds() {
    let mut env = MemEnv::default();
    assert_eq!(
        call(
            &mut env,
            PROD,
            Op::CreateIdentity {
                alias: "a".into(),
                description: String::new(),
                ui_entropy: Entropy([0; 32])
            }
        ),
        Err(FailureCode::BadInput)
    );
    let me = create(&mut env, PROD, "alice");
    assert!(me.confirmed);
    assert_eq!((me.vk.len(), me.ek.len()), (1952, 1184));
    assert_eq!(me.addr, freenet_mail_protocol::address::address_of(&me.vk));
    assert_eq!(
        call(
            &mut env,
            PROD,
            Op::CreateIdentity {
                alias: "alice".into(),
                description: String::new(),
                ui_entropy: Entropy([9; 32])
            }
        ),
        Err(FailureCode::Conflict { current_gen: 0 })
    );
    assert_eq!(
        call(&mut env, PROD, Op::ListIdentities),
        Ok(Reply::Identities(vec![me]))
    );
}

fn fixture_seeds() -> (DsaSeed, KemSeed) {
    (
        DsaSeed(std::array::from_fn(|i| i as u8)),
        KemSeed(std::array::from_fn(|i| 100 + i as u8)),
    )
}

fn import(
    env: &mut MemEnv,
    origin: u8,
    source: ImportSource,
    kind: ImportKind,
    alias: &str,
) -> Result<(IdentityInfo, bool), FailureCode> {
    match call(
        env,
        origin,
        Op::ImportIdentity {
            source,
            kind,
            alias: alias.into(),
            description: String::new(),
        },
    ) {
        Ok(Reply::Imported {
            identity,
            already_present,
        }) => Ok((identity, already_present)),
        Ok(other) => panic!("{other:?}"),
        Err(e) => Err(e),
    }
}

const BACKUP_JSON: &[u8] = include_bytes!("../../../ui/src/app/testdata/identity-backup-v2.json");

#[test]
fn every_backup_format_imports_fresh_and_none_overwrites() {
    let (dsa, kem) = fixture_seeds();
    let sources = || {
        vec![
            ImportSource::RecoveryKey(recovery_key::encode(&dsa, &kem)),
            ImportSource::LegacyJson(ByteBuf::from(BACKUP_JSON.to_vec())),
            ImportSource::Seeds {
                dsa: dsa.clone(),
                kem: kem.clone(),
            },
        ]
    };
    let mut addr = None;
    for source in sources() {
        let mut env = MemEnv::default();
        let (id, present) =
            import(&mut env, PROD, source, ImportKind::UserRestore, "alice").unwrap();
        assert!(!present);
        assert!(id.confirmed);
        assert_eq!(*addr.get_or_insert(id.addr), id.addr);
    }
    let mut env = MemEnv::default();
    let (first, _) = import(
        &mut env,
        PROD,
        sources().remove(0),
        ImportKind::UserRestore,
        "alice",
    )
    .unwrap();
    let before = ns_snapshot(&env, PROD);
    for source in sources() {
        let (again, present) =
            import(&mut env, PROD, source, ImportKind::Migration, "renamed").unwrap();
        assert!(present);
        assert_eq!(again, first);
    }
    assert_eq!(
        ns_snapshot(&env, PROD),
        before,
        "an import never writes over an identity"
    );
    // Another app importing the same seeds gets its own copy.
    let (theirs, present) = import(
        &mut env,
        OTHER,
        sources().remove(0),
        ImportKind::UserRestore,
        "a",
    )
    .unwrap();
    assert!(!present);
    assert_eq!(theirs.addr, first.addr);
}

#[test]
fn bad_imports_are_refused() {
    let mut env = MemEnv::default();
    let bad = |text: &[u8]| ImportSource::LegacyJson(ByteBuf::from(text.to_vec()));
    let cases = vec![
        ImportSource::RecoveryKey("fmail-key-1:nonsense".into()),
        ImportSource::RecoveryKey("hello".into()),
        bad(b"{not json"),
        bad(br#"{"version":3,"alias":"a","description":"","keys":{"ml_dsa_seed":[],"ml_kem_seed":[]}}"#),
        bad(br#"{"version":2,"alias":"a","description":"","keys":{"ml_dsa_seed":[1,2],"ml_kem_seed":[3]}}"#),
        bad(&vec![b' '; 20 * 1024]),
    ];
    for source in cases {
        assert_eq!(
            import(&mut env, PROD, source, ImportKind::UserRestore, "a").unwrap_err(),
            FailureCode::BadInput
        );
    }
    let (dsa, kem) = fixture_seeds();
    for alias in ["", "a\nb", &"x".repeat(65)] {
        assert_eq!(
            import(
                &mut env,
                PROD,
                ImportSource::Seeds {
                    dsa: dsa.clone(),
                    kem: kem.clone()
                },
                ImportKind::UserRestore,
                alias
            )
            .unwrap_err(),
            FailureCode::BadInput
        );
    }
    assert!(env.secrets.is_empty());
}

#[test]
fn migrated_identities_start_unconfirmed_until_confirmed() {
    let (dsa, kem) = fixture_seeds();
    let mut env = MemEnv::default();
    let (id, _) = import(
        &mut env,
        PROD,
        ImportSource::Seeds { dsa, kem },
        ImportKind::Migration,
        "old",
    )
    .unwrap();
    assert!(!id.confirmed);
    let g = ack(call(
        &mut env,
        PROD,
        Op::ConfirmIdentity {
            addr: id.addr,
            expected_gen: id.generation,
        },
    ));
    // Confirming again is an acknowledged retry.
    assert_eq!(
        ack(call(
            &mut env,
            PROD,
            Op::ConfirmIdentity {
                addr: id.addr,
                expected_gen: id.generation
            }
        )),
        g
    );
    match call(&mut env, PROD, Op::ListIdentities) {
        Ok(Reply::Identities(v)) => assert!(v[0].confirmed),
        other => panic!("{other:?}"),
    }
}

#[test]
fn renaming_checks_the_generation_and_alias() {
    let mut env = MemEnv::default();
    let a = create(&mut env, PROD, "alice");
    create(&mut env, PROD, "bob");
    let rename = |env: &mut MemEnv, alias: &str, g| {
        call(
            env,
            PROD,
            Op::UpdateIdentity {
                addr: a.addr,
                alias: alias.into(),
                description: "d".into(),
                expected_gen: g,
            },
        )
    };
    assert_eq!(
        rename(&mut env, "bob", a.generation),
        Err(FailureCode::Conflict {
            current_gen: a.generation
        })
    );
    let g = ack(rename(&mut env, "carol", a.generation));
    assert_eq!(
        ack(rename(&mut env, "carol", a.generation)),
        g,
        "retry is acknowledged"
    );
    assert_eq!(
        rename(&mut env, "dave", a.generation),
        Err(FailureCode::Conflict { current_gen: g })
    );
    assert_eq!(rename(&mut env, "", g), Err(FailureCode::BadInput));
    assert_eq!(
        call(
            &mut env,
            PROD,
            Op::UpdateIdentity {
                addr: Addr([9; 24]),
                alias: "x".into(),
                description: String::new(),
                expected_gen: 1
            }
        ),
        Err(FailureCode::NotFound)
    );
}

// ── v0.2.x crypto ───────────────────────────────────────────────────────────

fn vector_identity(env: &mut MemEnv) -> IdentityInfo {
    let dsa = DsaSeed([7; 32]);
    let kem = KemSeed(std::array::from_fn(|i| i as u8));
    import(
        env,
        PROD,
        ImportSource::Seeds { dsa, kem },
        ImportKind::UserRestore,
        "v",
    )
    .unwrap()
    .0
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn vector(name: &str) -> Vec<u8> {
    let file = include_str!("../../../ui/src/inbox/crypto_vectors_v1.txt");
    hex(file
        .lines()
        .find_map(|l| l.strip_prefix(name)?.strip_prefix(' '))
        .unwrap())
}

fn vector_keys() -> crate::crypto::Keys {
    crate::crypto::Keys::from_seeds(
        &DsaSeed([7; 32]),
        &KemSeed(std::array::from_fn(|i| i as u8)),
    )
}

#[test]
fn a_v0_2_x_message_decrypts_through_the_delegate() {
    let mut env = MemEnv::default();
    let me = vector_identity(&mut env);
    assert_eq!(
        call(
            &mut env,
            PROD,
            Op::DecryptV1 {
                addr: me.addr,
                ciphertexts: vec![
                    ByteBuf::from(vector("envelope")),
                    ByteBuf::from(vec![1, 2, 3])
                ]
            }
        ),
        Ok(Reply::Decrypted(vec![
            Ok(ByteBuf::from(b"hello from the rc crates".to_vec())),
            Err(FailureCode::BadInput)
        ]))
    );
    let too_many = vec![ByteBuf::new(); freenet_mail_protocol::MAX_DECRYPT_BATCH + 1];
    assert_eq!(
        call(
            &mut env,
            PROD,
            Op::DecryptV1 {
                addr: me.addr,
                ciphertexts: too_many
            }
        ),
        Err(FailureCode::BadInput)
    );
}

#[test]
fn sealing_produces_a_verifiable_message_and_refuses_bad_input() {
    use ml_dsa::signature::Verifier;
    let mut env = MemEnv::default();
    let me = vector_identity(&mut env);
    let seal = |env: &mut MemEnv, ek: ByteBuf, pt: Vec<u8>, e: u8| {
        call(
            env,
            PROD,
            Op::SealV1Message {
                addr: me.addr,
                recipient_ek: ek,
                plaintext: ByteBuf::from(pt),
                ui_entropy: Entropy([e; 32]),
            },
        )
    };
    let Ok(Reply::SealedV1 {
        content,
        signature,
        sender_vk,
    }) = seal(&mut env, me.ek.clone(), b"hi".to_vec(), 4)
    else {
        panic!("seal failed");
    };
    assert_eq!(sender_vk, me.vk);
    let vk =
        ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(sender_vk.as_slice().try_into().unwrap());
    let sig =
        ml_dsa::Signature::<ml_dsa::MlDsa65>::decode(signature.as_slice().try_into().unwrap())
            .unwrap();
    assert!(vk.verify(&content, &sig).is_ok());
    assert_eq!(
        call(
            &mut env,
            PROD,
            Op::DecryptV1 {
                addr: me.addr,
                ciphertexts: vec![content]
            }
        ),
        Ok(Reply::Decrypted(vec![Ok(ByteBuf::from(b"hi".to_vec()))]))
    );
    assert_eq!(
        seal(&mut env, me.ek.clone(), b"hi".to_vec(), 0),
        Err(FailureCode::BadInput)
    );
    assert_eq!(
        seal(&mut env, ByteBuf::from(vec![1; 10]), b"hi".to_vec(), 4),
        Err(FailureCode::BadInput)
    );
    assert_eq!(
        seal(
            &mut env,
            me.ek.clone(),
            vec![0; freenet_mail_protocol::MAX_ITEM_BYTES + 1],
            4
        ),
        Err(FailureCode::BadInput)
    );
}

#[test]
fn the_authority_signature_is_what_v0_2_x_signs() {
    use freenet_mail_wire_v1::inbox::{Inbox, InboxSettings};
    let mut env = MemEnv::default();
    let me = vector_identity(&mut env);
    let settings = InboxSettings::default();
    let micros = 1_700_000_000_000_000;
    let sign = |env: &mut MemEnv, json: &[u8], micros| {
        call(
            env,
            PROD,
            Op::SignV1Authority {
                addr: me.addr,
                settings_json: ByteBuf::from(json.to_vec()),
                last_update_micros: micros,
            },
        )
    };
    let Ok(Reply::Signature(sig)) = sign(&mut env, &serde_json::to_vec(&settings).unwrap(), micros)
    else {
        panic!("sign failed");
    };
    let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&[7u8; 32].into());
    let want = Inbox::sign(
        &sk,
        &me.ek,
        &settings,
        chrono::DateTime::from_timestamp_micros(micros).unwrap(),
    );
    assert_eq!(sig.into_vec(), want.to_vec());
    assert_eq!(
        sign(&mut env, b"{not json", micros),
        Err(FailureCode::BadInput)
    );
    assert_eq!(
        sign(&mut env, &serde_json::to_vec(&settings).unwrap(), i64::MAX),
        Err(FailureCode::BadInput)
    );
}

/// A v1 inbox state for `vk` holding messages with these assignment hashes.
fn hold_inbox(env: &mut MemEnv, vk: &[u8], messages: &[(Vec<u8>, [u8; 32])]) {
    let messages: Vec<serde_json::Value> = messages
        .iter()
        .map(|(content, h)| {
            serde_json::json!({
                "content": content,
                "token_assignment": {"assignment_hash": h.to_vec()},
            })
        })
        .collect();
    let state = serde_json::to_vec(&serde_json::json!({ "messages": messages })).unwrap();
    env.contracts
        .insert(crate::handlers::v1_inbox_id(vk).unwrap(), state);
}

/// A message stored the way v0.2.x stores it (`ui/src/inbox.rs`): the
/// assignment hash is blake3 of ONE encryption of the message, and the
/// stored content is a SECOND, different encryption of it.
fn v0_2_x_message(recipient_ek: &[u8], plaintext: &[u8], seed: u8) -> (Vec<u8>, [u8; 32]) {
    use crate::crypto::{MixRng, decode_ek, encrypt_v1};
    let ek = decode_ek(recipient_ek).unwrap();
    let hashed = encrypt_v1(
        &ek,
        plaintext,
        &mut MixRng::new("t", &[seed; 32], &Entropy([1; 32])),
    );
    let stored = encrypt_v1(
        &ek,
        plaintext,
        &mut MixRng::new("t", &[seed; 32], &Entropy([2; 32])),
    );
    assert_ne!(hashed, stored);
    (stored, *blake3::hash(&hashed).as_bytes())
}

#[test]
fn a_removal_is_signed_for_real_messages_in_ascending_order_only() {
    let mut env = MemEnv::default();
    let me = vector_identity(&mut env);
    let remove = |env: &mut MemEnv, hashes: Vec<[u8; 32]>| {
        call(
            env,
            PROD,
            Op::SignV1Removal {
                addr: me.addr,
                assignment_hashes: hashes.into_iter().map(Hash32).collect(),
            },
        )
    };
    let a = v0_2_x_message(&me.ek, b"one", 1);
    let b = v0_2_x_message(&me.ek, b"two", 2);
    assert_ne!(
        *blake3::hash(&a.0).as_bytes(),
        a.1,
        "the hash is not of the stored content"
    );
    let (lo, hi) = if a.1 < b.1 { (a.1, b.1) } else { (b.1, a.1) };
    // No inbox held on this node: refused.
    assert_eq!(remove(&mut env, vec![lo]), Err(FailureCode::Refused));

    // A planted attempt: a real v1 ciphertext's 32-byte chunks, each the
    // hash of a planted message, requested in ciphertext order.
    let forged = crate::crypto::encrypt_v1(
        &crate::crypto::decode_ek(&me.ek).unwrap(),
        b"forged",
        &mut crate::crypto::MixRng::new("t", &[9; 32], &Entropy([9; 32])),
    );
    let chunks: Vec<[u8; 32]> = forged[..96]
        .chunks(32)
        .map(|c| c.try_into().unwrap())
        .collect();
    assert!(
        chunks.windows(2).any(|w| w[0] >= w[1]),
        "ciphertext chunks do not ascend"
    );
    let mut aliasing = [0u8; 32];
    aliasing[..8].copy_from_slice(freenet_mail_wire_v1::inbox::STATE_UPDATE);
    let mut held = vec![a.clone(), b.clone(), (b"z".to_vec(), aliasing)];
    held.extend(chunks.iter().map(|c| (b"x".to_vec(), *c)));
    hold_inbox(&mut env, &me.vk, &held);

    let Ok(Reply::Signature(sig)) = remove(&mut env, vec![lo, hi]) else {
        panic!("removal of real messages refused");
    };
    let payload = freenet_mail_wire_v1::inbox::removal_payload(&[lo, hi]);
    assert_eq!(
        payload,
        [lo, hi].concat(),
        "the contract's layout: hashes concatenated"
    );
    assert_eq!(sig.into_vec(), vector_keys().sign(&payload));

    assert_eq!(remove(&mut env, vec![hi, lo]), Err(FailureCode::BadInput));
    assert_eq!(remove(&mut env, vec![lo, lo]), Err(FailureCode::BadInput));
    assert_eq!(remove(&mut env, chunks.clone()), Err(FailureCode::BadInput));
    // Sorted, the same planted chunks ARE signed (they are in the inbox and
    // ascend), but what is signed is no longer the ciphertext: ordering is
    // what keeps the signature from covering it.
    let mut sorted = chunks.clone();
    sorted.sort();
    let Ok(Reply::Signature(_)) = remove(&mut env, sorted.clone()) else {
        panic!("sorted planted chunks refused");
    };
    assert_ne!(sorted.concat(), forged[..96].to_vec());
    assert_eq!(
        remove(&mut env, vec![[0xee; 32]]),
        Err(FailureCode::Refused)
    );
    assert_eq!(remove(&mut env, vec![aliasing]), Err(FailureCode::Refused));
    assert_eq!(remove(&mut env, vec![]), Err(FailureCode::BadInput));
}

#[test]
fn aft_params_are_the_v0_2_x_token_generator_params() {
    let mut env = MemEnv::default();
    let me = vector_identity(&mut env);
    let got = call(&mut env, PROD, Op::V1AftParams { addr: me.addr });
    if cfg!(feature = "v1-transition") {
        let want = serde_json::to_vec(&freenet_mail_wire_v1::aft::DelegateParameters::new([7; 32]))
            .unwrap();
        assert_eq!(got, Ok(Reply::AftParams(ByteBuf::from(want))));
        assert_eq!(
            call(
                &mut env,
                PROD,
                Op::V1AftParams {
                    addr: Addr([1; 24])
                }
            ),
            Err(FailureCode::NotFound)
        );
    } else {
        assert_eq!(got, Err(FailureCode::Refused));
    }
}

// ── Consent ─────────────────────────────────────────────────────────────────

fn prompt(out: &[OutboundDelegateMsg]) -> (u32, Vec<Vec<u8>>, String) {
    let prompts: Vec<_> = out
        .iter()
        .filter_map(|m| match m {
            OutboundDelegateMsg::RequestUserInput(r) => Some(r),
            _ => None,
        })
        .collect();
    assert_eq!(prompts.len(), 1, "{out:?}");
    let r = prompts[0];
    let raw: Vec<u8> = serde_json::from_slice(&serde_json::to_vec(&r.message).unwrap()).unwrap();
    let text: String = serde_json::from_slice(&raw).unwrap();
    (
        r.request_id,
        r.responses.iter().map(|c| c.to_vec()).collect(),
        text,
    )
}

fn answer(env: &mut MemEnv, origin: u8, id: u32, choice: &[u8]) -> Vec<OutboundDelegateMsg> {
    let resp = UserInputResponse {
        request_id: id,
        response: ClientResponse::new(choice.to_vec()),
        context: DelegateContext::default(),
    };
    process(env, app(origin), InboundDelegateMsg::UserResponse(resp)).unwrap()
}

fn import_fixture(env: &mut MemEnv, origin: u8) -> Addr {
    let (dsa, kem) = fixture_seeds();
    import(
        env,
        origin,
        ImportSource::Seeds { dsa, kem },
        ImportKind::UserRestore,
        "a",
    )
    .unwrap()
    .0
    .addr
}

/// The node answers a prompt nobody answered (its 60 s timeout, or a
/// dismissed dialog) with an EMPTY response. That must end the waiting
/// request with a refusal, which is what keeps the UI from waiting out its
/// own much longer backstop, and the refusal must say it went unanswered.
#[test]
fn an_unanswered_prompt_ends_the_waiting_request() {
    let mut env = MemEnv::default();
    let addr = import_fixture(&mut env, PROD);
    let id = prompt(&send(&mut env, app(PROD), Op::ExportRecoveryKey { addr })).0;
    let failure = response(&answer(&mut env, PROD, id, b""))
        .result
        .unwrap_err();
    assert_eq!(failure.code, FailureCode::Refused);
    assert!(
        failure.detail.contains("not answered"),
        "{}",
        failure.detail
    );
    assert!(
        answer(&mut env, PROD, id, ALLOW).is_empty(),
        "the prompt is gone"
    );
}

#[test]
fn an_export_asks_and_only_an_allow_releases_the_key() {
    let (dsa, kem) = fixture_seeds();
    let mut env = MemEnv::default();
    let addr = import_fixture(&mut env, PROD);
    let ask = |env: &mut MemEnv, op| prompt(&send(env, app(PROD), op)).0;

    // Deny, and anything unrecognised, refuse and remember nothing.
    for choice in [DENY, b"maybe".as_slice()] {
        let id = ask(&mut env, Op::ExportRecoveryKey { addr });
        assert_eq!(
            response(&answer(&mut env, PROD, id, choice))
                .result
                .unwrap_err()
                .code,
            FailureCode::Refused
        );
        assert!(
            answer(&mut env, PROD, id, ALLOW).is_empty(),
            "an answered prompt is gone"
        );
    }
    // Another app cannot answer our prompt; we still can afterwards.
    let id = ask(&mut env, Op::ExportRecoveryKey { addr });
    assert!(answer(&mut env, OTHER, id, ALLOW).is_empty());
    assert_eq!(
        response(&answer(&mut env, PROD, id, ALLOW)).result,
        Ok(Reply::RecoveryKey(recovery_key::encode(&dsa, &kem)))
    );
    // Allow is not remembered; Always is, and only for this app.
    let id = ask(&mut env, Op::ExportProfile { addr });
    match response(&answer(&mut env, PROD, id, ALWAYS)).result {
        Ok(Reply::Profile(json)) => {
            let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
            assert_eq!(
                (v["version"].as_u64(), v["keys"]["ml_dsa_seed"][1].as_u64()),
                (Some(2), Some(1))
            );
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        response(&send(&mut env, app(PROD), Op::ExportRecoveryKey { addr })).result,
        Ok(Reply::RecoveryKey(recovery_key::encode(&dsa, &kem)))
    );
    let theirs = import_fixture(&mut env, OTHER);
    prompt(&send(
        &mut env,
        app(OTHER),
        Op::ExportRecoveryKey { addr: theirs },
    ));
}

#[test]
fn prompts_name_the_app_and_offer_the_right_choices() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    let (_, choices, text) = prompt(&send(
        &mut env,
        app(PROD),
        Op::ExportRecoveryKey { addr: me.addr },
    ));
    assert_eq!(
        choices,
        vec![ALLOW.to_vec(), ALWAYS.to_vec(), DENY.to_vec()]
    );
    let label = ContractInstanceId::new([PROD; 32]).encode();
    assert!(
        text.contains(&label[..8]) && text.contains("\"alice\""),
        "{text}"
    );
    let (_, choices, _) = prompt(&send(
        &mut env,
        app(PROD),
        Op::DeleteIdentity {
            addr: me.addr,
            expected_gen: me.generation,
        },
    ));
    assert_eq!(choices, vec![DELETE.to_vec(), CANCEL.to_vec()]);
}

#[test]
fn prompts_expire_and_an_expired_answer_is_refused() {
    let mut env = MemEnv {
        now: Some(1_000),
        ..MemEnv::default()
    };
    let me = create(&mut env, PROD, "alice");
    let (id, _, _) = prompt(&send(
        &mut env,
        app(PROD),
        Op::ExportRecoveryKey { addr: me.addr },
    ));
    env.now = Some(1_000 + store::PROMPT_TTL_SECS + 1);
    assert_eq!(
        response(&answer(&mut env, PROD, id, ALLOW))
            .result
            .unwrap_err()
            .code,
        FailureCode::Refused
    );
    // A stale stash found when raising a new prompt is answered Refused too.
    env.now = Some(5_000);
    let (old, _, _) = prompt(&send(
        &mut env,
        app(PROD),
        Op::ExportRecoveryKey { addr: me.addr },
    ));
    env.now = Some(5_000 + store::PROMPT_TTL_SECS + 1);
    let out = send(&mut env, app(PROD), Op::ExportProfile { addr: me.addr });
    let refused = responses(&out);
    assert_eq!(refused.len(), 1);
    assert_eq!(
        refused[0].result.as_ref().unwrap_err().code,
        FailureCode::Refused
    );
    assert!(answer(&mut env, PROD, old, ALLOW).is_empty());
}

#[test]
fn concurrent_prompts_are_distinct_bounded_and_every_request_is_answered() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    let mut ids = Vec::new();
    let mut refused = 0;
    for _ in 0..6 {
        let out = send(&mut env, app(PROD), Op::ExportRecoveryKey { addr: me.addr });
        refused += responses(&out).len();
        ids.push(prompt(&out).0);
    }
    assert_eq!(
        ids.iter().collect::<std::collections::BTreeSet<_>>().len(),
        6
    );
    assert_eq!(
        refused,
        6 - store::MAX_PENDING_PROMPTS,
        "each evicted prompt's request gets Refused"
    );
    assert!(answer(&mut env, PROD, ids[0], ALLOW).is_empty());
    assert!(matches!(
        response(&answer(&mut env, PROD, ids[5], ALLOW)).result,
        Ok(Reply::RecoveryKey(_))
    ));
}

#[test]
fn a_prompt_for_a_deleted_identity_answers_not_found() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    let (exp, _, _) = prompt(&send(
        &mut env,
        app(PROD),
        Op::ExportRecoveryKey { addr: me.addr },
    ));
    let (del, _, _) = prompt(&send(
        &mut env,
        app(PROD),
        Op::DeleteIdentity {
            addr: me.addr,
            expected_gen: me.generation,
        },
    ));
    assert_eq!(
        response(&answer(&mut env, PROD, del, DELETE)).result,
        Ok(Reply::Deleted)
    );
    assert_eq!(
        response(&answer(&mut env, PROD, exp, ALLOW))
            .result
            .unwrap_err()
            .code,
        FailureCode::NotFound
    );
    let r = response(&send(
        &mut env,
        app(PROD),
        Op::ExportRecoveryKey { addr: me.addr },
    ));
    assert_eq!(r.result.unwrap_err().code, FailureCode::NotFound);
}

#[test]
fn deleting_an_identity_asks_every_time_and_removes_everything_it_owns() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    let keep = create(&mut env, PROD, "bob");
    ack(put(&mut env, draft(me.addr, 1), b"d", None));
    let archived = ItemRef {
        kind: ItemKind::Archived,
        owner: Some(me.addr),
        id: vec![2; 16],
    };
    ack(put(&mut env, archived, b"a", None));
    let settings = ItemRef {
        kind: ItemKind::IdentitySettings,
        owner: Some(me.addr),
        id: vec![],
    };
    ack(put(&mut env, settings, b"s", None));
    ack(put(&mut env, draft(keep.addr, 1), b"bob's", None));
    ack(put(&mut env, contact(5), b"c", None));
    // An "Always" grant for exports does not cover deletion.
    let (x, _, _) = prompt(&send(
        &mut env,
        app(PROD),
        Op::ExportRecoveryKey { addr: keep.addr },
    ));
    answer(&mut env, PROD, x, ALWAYS);
    // A stale generation is refused before asking.
    assert!(matches!(
        response(&send(
            &mut env,
            app(PROD),
            Op::DeleteIdentity {
                addr: me.addr,
                expected_gen: me.generation + 99
            }
        ))
        .result
        .unwrap_err()
        .code,
        FailureCode::Conflict { .. }
    ));
    let del = Op::DeleteIdentity {
        addr: me.addr,
        expected_gen: me.generation,
    };
    let (id, _, _) = prompt(&send(&mut env, app(PROD), del.clone()));
    assert_eq!(
        response(&answer(&mut env, PROD, id, CANCEL))
            .result
            .unwrap_err()
            .code,
        FailureCode::Refused
    );
    let (id, _, _) = prompt(&send(&mut env, app(PROD), del.clone()));
    assert_eq!(
        response(&answer(&mut env, PROD, id, DELETE)).result,
        Ok(Reply::Deleted)
    );
    // Nothing of alice's remains; bob and the contacts are untouched.
    let me_hex = store::hex(&me.addr.0);
    assert!(
        env.secrets
            .keys()
            .all(|k| !String::from_utf8_lossy(k).contains(&me_hex))
    );
    assert_eq!(
        list_ids(&mut env, PROD, ItemKind::Draft, Some(keep.addr)).len(),
        1
    );
    assert_eq!(list_ids(&mut env, PROD, ItemKind::Contact, None).len(), 1);
    match call(&mut env, PROD, Op::ListIdentities) {
        Ok(Reply::Identities(v)) => assert_eq!(
            v.iter().map(|i| i.addr).collect::<Vec<_>>(),
            vec![keep.addr]
        ),
        other => panic!("{other:?}"),
    }
    // Deleting it again: answered without a prompt, as already gone.
    assert_eq!(
        response(&send(&mut env, app(PROD), del))
            .result
            .unwrap_err()
            .code,
        FailureCode::NotFound
    );
}

#[test]
fn the_successor_export_asks_and_holds_exactly_the_data() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    ack(put(&mut env, draft(me.addr, 1), b"d", None));
    ack(put(&mut env, contact(4), b"c", None));
    // Leave bookkeeping, a pending prompt and a grant behind.
    let (p, _, _) = prompt(&send(
        &mut env,
        app(PROD),
        Op::ExportProfile { addr: me.addr },
    ));
    let export = Op::ExportForSuccessor {
        source_generation: 3,
        after: None,
        session: None,
    };
    let (id, _, _) = prompt(&send(&mut env, app(PROD), export.clone()));
    let page = match response(&answer(&mut env, PROD, id, ALWAYS)).result {
        Ok(Reply::ExportedSecrets {
            payload,
            next,
            session,
        }) => {
            assert_eq!((next, session), (None, None));
            freenet_migrate::ExportedSecrets::from_bytes(&payload).unwrap()
        }
        other => panic!("{other:?}"),
    };
    assert_eq!(page.source_generation, 3);
    let ns = store::namespace(&Origin([PROD; 32]));
    let mut keys: Vec<String> = page
        .secrets
        .iter()
        .map(|(k, _)| String::from_utf8(k[ns.len()..].to_vec()).unwrap())
        .collect();
    keys.sort();
    let a = store::hex(&me.addr.0);
    let mut want = vec![
        format!("id/{a}"),
        "ix/id".to_string(),
        format!("ix/dr/{a}"),
        format!("it/dr/{a}/{}", store::hex(&[1; 16])),
        "ix/ct/-".to_string(),
        format!("it/ct/-/{}", store::hex(&[4; 24])),
    ];
    want.sort();
    assert_eq!(keys, want, "no mt/, pg/, ix/pg or gr/ keys");
    // The grant now covers further pages without asking.
    assert!(matches!(
        response(&send(&mut env, app(PROD), export)).result,
        Ok(Reply::ExportedSecrets { .. })
    ));
    let _ = p;
}

#[test]
fn the_successor_export_pages_within_the_response_budget() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    for id in 1..=4u8 {
        ack(put(
            &mut env,
            draft(me.addr, id),
            &vec![id; 200 * 1024],
            None,
        ));
    }
    let (g, _, _) = prompt(&send(
        &mut env,
        app(PROD),
        Op::ExportRecoveryKey { addr: me.addr },
    ));
    answer(&mut env, PROD, g, ALWAYS);
    let mut after = None;
    let mut all = Vec::new();
    loop {
        let r = response(&send(
            &mut env,
            app(PROD),
            Op::ExportForSuccessor {
                source_generation: 1,
                after: after.clone(),
                session: None,
            },
        ));
        let Ok(Reply::ExportedSecrets { payload, next, .. }) = r.result else {
            panic!()
        };
        assert!(payload.len() <= freenet_mail_protocol::MAX_RESPONSE_BYTES);
        all.extend(
            freenet_migrate::ExportedSecrets::from_bytes(&payload)
                .unwrap()
                .secrets,
        );
        match next {
            Some(n) => after = Some(n),
            None => break,
        }
    }
    let items = all
        .iter()
        .filter(|(k, _)| String::from_utf8_lossy(k).contains("/it/dr/"))
        .count();
    assert_eq!(items, 4);
}

// ── Protocol ────────────────────────────────────────────────────────────────

#[test]
fn an_unknown_protocol_version_is_refused_by_name() {
    let mut env = MemEnv::default();
    let req = Request {
        version: PROTOCOL_VERSION + 1,
        request_id: RequestId([2; 16]),
        op: Op::GetStatus,
    };
    let out = process(
        &mut env,
        app(PROD),
        InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(to_cbor(&req).unwrap())),
    )
    .unwrap();
    let r = response(&out);
    assert_eq!(r.request_id, RequestId([2; 16]));
    assert_eq!(r.result.unwrap_err().code, FailureCode::UnsupportedVersion);
}
