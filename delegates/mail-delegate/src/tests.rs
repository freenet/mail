//! Behaviour through the delegate's entry point, over an in-memory store.

use freenet_mail_protocol::{
    Addr, DsaSeed, Entropy, FailureCode, Hash32, IdentityInfo, ImportSource, ItemKind, ItemRef,
    KemSeed, Op, PROTOCOL_VERSION, Reply, Request, RequestId, Response, from_cbor, recovery_key,
    to_cbor,
};
use freenet_stdlib::prelude::{
    ApplicationMessage, ClientResponse, ContractInstanceId, DelegateContext, DelegateKey,
    InboundDelegateMsg, MessageOrigin, OutboundDelegateMsg, UserInputResponse,
};
use serde_bytes::ByteBuf;

use crate::consent::{ALLOW, ALWAYS, DENY};
use crate::env::mem::MemEnv;
use crate::handlers::process;
use crate::store;

fn app(b: u8) -> Option<MessageOrigin> {
    Some(MessageOrigin::WebApp(ContractInstanceId::new([b; 32])))
}

const PROD: u8 = 1;
const OTHER: u8 = 2;

fn send(env: &mut MemEnv, origin: Option<MessageOrigin>, op: Op) -> Vec<OutboundDelegateMsg> {
    let req = Request {
        version: PROTOCOL_VERSION,
        request_id: RequestId([0x5a; 16]),
        op,
    };
    let msg =
        InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(to_cbor(&req).unwrap()));
    process(env, origin, msg).expect("a web-app request is answered, not errored")
}

fn response(out: &[OutboundDelegateMsg]) -> Response {
    assert_eq!(out.len(), 1, "exactly one message per request");
    match &out[0] {
        OutboundDelegateMsg::ApplicationMessage(m) => {
            assert!(m.processed);
            from_cbor(&m.payload).unwrap()
        }
        other => panic!("expected a response, got {other:?}"),
    }
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
        Ok(Reply::Identity(i)) => i,
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

fn put(
    env: &mut MemEnv,
    item: ItemRef,
    body: &[u8],
    expected_gen: Option<u64>,
) -> Result<Reply, FailureCode> {
    call(
        env,
        PROD,
        Op::PutItem {
            item,
            body: ByteBuf::from(body.to_vec()),
            expected_gen,
        },
    )
}

fn ack(r: Result<Reply, FailureCode>) -> u64 {
    match r {
        Ok(Reply::Ack { generation }) => generation,
        other => panic!("expected Ack, got {other:?}"),
    }
}

// ── Origin gate ─────────────────────────────────────────────────────────────

#[test]
fn origin_gate_truth_table() {
    let req = Request {
        version: PROTOCOL_VERSION,
        request_id: RequestId([1; 16]),
        op: Op::GetStatus,
    };
    let msg =
        || InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(to_cbor(&req).unwrap()));
    let mut env = MemEnv::default();
    assert!(process(&mut env, app(PROD), msg()).is_ok());
    assert!(process(&mut env, None, msg()).is_err());
    let delegate = Some(MessageOrigin::Delegate(DelegateKey::new(
        [3; 32],
        freenet_stdlib::prelude::CodeHash::from_code(b"other"),
    )));
    assert!(process(&mut env, delegate, msg()).is_err());
}

/// Every request a foreign web app can send against a populated production
/// namespace: each answer is a refusal or empty, and production's bytes do
/// not change.
#[test]
fn a_foreign_origin_can_neither_read_nor_change_another_namespace() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    ack(put(&mut env, draft(me.addr, 1), b"secret draft", Some(0)));
    let contact = ItemRef {
        kind: ItemKind::Contact,
        owner: None,
        id: vec![9; 24],
    };
    ack(put(&mut env, contact.clone(), b"bob", None));
    let prod_ns = store::namespace(&store::Origin([PROD; 32])).into_bytes();
    let snapshot = |env: &MemEnv| -> Vec<(Vec<u8>, Vec<u8>)> {
        env.secrets
            .iter()
            .filter(|(k, _)| k.starts_with(&prod_ns))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    };
    let before = snapshot(&env);
    let a = me.addr;
    let ops = vec![
        Op::ListIdentities,
        Op::UpdateIdentity {
            addr: a,
            alias: "x".into(),
            description: String::new(),
            expected_gen: me.generation,
        },
        Op::DeleteIdentity {
            addr: a,
            expected_gen: me.generation,
        },
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
        Op::GetItem {
            item: contact.clone(),
        },
        Op::PutItem {
            item: draft(a, 1),
            body: ByteBuf::from(b"x".to_vec()),
            expected_gen: Some(1),
        },
        Op::PutItem {
            item: contact.clone(),
            body: ByteBuf::from(b"x".to_vec()),
            expected_gen: Some(3),
        },
        Op::DeleteItem {
            item: draft(a, 1),
            expected_gen: 2,
        },
        Op::DeleteItem {
            item: contact.clone(),
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
        Op::ExportRecoveryKey { addr: a },
        Op::ExportProfile { addr: a },
    ];
    for op in ops {
        let out = send(&mut env, app(OTHER), op.clone());
        let r = response(&out).result;
        match r {
            Err(_) => {}
            Ok(Reply::Identities(v)) => assert!(v.is_empty(), "{op:?}"),
            Ok(Reply::Items { items, .. }) => assert!(items.is_empty(), "{op:?}"),
            Ok(Reply::Item(None)) | Ok(Reply::Deleted) => {}
            Ok(other) => panic!("{op:?} leaked {other:?}"),
        }
    }
    // The foreign app's own export of "its" data contains nothing of ours.
    let exported = match call(
        &mut env,
        OTHER,
        Op::ExportForSuccessor {
            source_generation: 1,
        },
    ) {
        Ok(Reply::ExportedSecrets(b)) => freenet_migrate::ExportedSecrets::from_bytes(&b).unwrap(),
        other => panic!("{other:?}"),
    };
    assert!(
        exported
            .secrets
            .iter()
            .all(|(k, _)| !k.starts_with(&prod_ns))
    );
    assert_eq!(snapshot(&env), before);
    // And a delegate caller is refused before anything is read or written.
    let all = env.secrets.clone();
    let req = Request {
        version: PROTOCOL_VERSION,
        request_id: RequestId([1; 16]),
        op: Op::ListIdentities,
    };
    let delegate = Some(MessageOrigin::Delegate(DelegateKey::new(
        [3; 32],
        freenet_stdlib::prelude::CodeHash::from_code(b"other"),
    )));
    assert!(
        process(
            &mut env,
            delegate,
            InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(to_cbor(&req).unwrap()))
        )
        .is_err()
    );
    assert_eq!(env.secrets, all);
}

// ── Compare-and-swap ────────────────────────────────────────────────────────

#[test]
fn cas_refuses_a_stale_writer_and_accepts_the_current_one() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    let item = draft(me.addr, 1);
    let g1 = ack(put(&mut env, item.clone(), b"v1", Some(0)));
    let g2 = ack(put(&mut env, item.clone(), b"v2", Some(g1)));
    assert!(g2 > g1);
    // A tab still holding g1 loses, and learns the current generation.
    assert_eq!(
        put(&mut env, item.clone(), b"stale", Some(g1)),
        Err(FailureCode::Conflict { current_gen: g2 })
    );
    // Create-only on an existing item is a conflict too.
    assert_eq!(
        put(&mut env, item.clone(), b"new", None),
        Err(FailureCode::Conflict { current_gen: g2 })
    );
    // A retry of the write that landed is acknowledged, not refused.
    assert_eq!(ack(put(&mut env, item.clone(), b"v2", Some(g1))), g2);
    match call(&mut env, PROD, Op::GetItem { item: item.clone() }) {
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
    let g_new = ack(put(&mut env, item.clone(), b"recreated", None));
    assert_ne!(g_new, g1);
    assert!(put(&mut env, item.clone(), b"stale", Some(g1)).is_err());
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
    // Both tabs read g0. Tab A writes first; tab B's write must not land.
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
    // Tab B re-reads, merges and retries against the current generation.
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
}

#[test]
fn the_delegate_wide_key_budget_is_enforced() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    for i in env.secrets.len()..store::KEY_BUDGET {
        env.secrets
            .insert(format!("filler/{i}").into_bytes(), vec![]);
    }
    assert_eq!(
        put(&mut env, draft(me.addr, 1), b"x", None),
        Err(FailureCode::CapReached)
    );
}

#[test]
fn listing_pages_in_id_order() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    for id in [3u8, 1, 2] {
        ack(put(&mut env, draft(me.addr, id), &[id], None));
    }
    let page = |env: &mut MemEnv, after: Option<Vec<u8>>| match call(
        env,
        PROD,
        Op::ListItems {
            kind: ItemKind::Draft,
            owner: Some(me.addr),
            after: after.map(ByteBuf::from),
            limit: 2,
        },
    ) {
        Ok(Reply::Items { items, more }) => (
            items.into_iter().map(|i| i.item.id[0]).collect::<Vec<_>>(),
            more,
        ),
        other => panic!("{other:?}"),
    };
    assert_eq!(page(&mut env, None), (vec![1, 2], true));
    assert_eq!(page(&mut env, Some(vec![2; 16])), (vec![3], false));
}

// ── Identities ──────────────────────────────────────────────────────────────

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
    assert_eq!(me.vk.len(), 1952);
    assert_eq!(me.ek.len(), 1184);
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
    match call(&mut env, PROD, Op::ListIdentities) {
        Ok(Reply::Identities(v)) => assert_eq!(v, vec![me]),
        other => panic!("{other:?}"),
    }
}

/// The seeds of the UI's backup fixtures (#349).
fn fixture_seeds() -> (DsaSeed, KemSeed) {
    (
        DsaSeed(std::array::from_fn(|i| i as u8)),
        KemSeed(std::array::from_fn(|i| 100 + i as u8)),
    )
}

#[test]
fn imports_never_overwrite_and_accept_every_backup_format() {
    let (dsa, kem) = fixture_seeds();
    let mut env = MemEnv::default();
    let imported = |r: Result<Reply, FailureCode>| match r {
        Ok(Reply::Imported {
            identity,
            already_present,
        }) => (identity, already_present),
        other => panic!("{other:?}"),
    };
    let (first, present) = imported(call(
        &mut env,
        PROD,
        Op::ImportIdentity {
            source: ImportSource::RecoveryKey(recovery_key::encode(&dsa, &kem)),
            alias: "alice".into(),
            description: String::new(),
        },
    ));
    assert!(!present);
    let json = include_bytes!("../../../ui/src/app/testdata/identity-backup-v2.json");
    let (second, present) = imported(call(
        &mut env,
        PROD,
        Op::ImportIdentity {
            source: ImportSource::LegacyJson(ByteBuf::from(json.to_vec())),
            alias: "renamed".into(),
            description: String::new(),
        },
    ));
    assert!(present, "the JSON backup holds the same seeds");
    assert_eq!(
        second, first,
        "an import never overwrites the stored identity"
    );
    let (third, present) = imported(call(
        &mut env,
        PROD,
        Op::ImportIdentity {
            source: ImportSource::Seeds { dsa, kem },
            alias: "x".into(),
            description: String::new(),
        },
    ));
    assert!(present);
    assert_eq!(third.addr, first.addr);
}

// ── v0.2.x crypto ───────────────────────────────────────────────────────────

fn vector_identity(env: &mut MemEnv) -> IdentityInfo {
    let dsa = DsaSeed([7; 32]);
    let kem = KemSeed(std::array::from_fn(|i| i as u8));
    match call(
        env,
        PROD,
        Op::ImportIdentity {
            source: ImportSource::Seeds { dsa, kem },
            alias: "v".into(),
            description: String::new(),
        },
    ) {
        Ok(Reply::Imported { identity, .. }) => identity,
        other => panic!("{other:?}"),
    }
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

#[test]
fn a_v0_2_x_message_decrypts_through_the_delegate() {
    let mut env = MemEnv::default();
    let me = vector_identity(&mut env);
    let out = call(
        &mut env,
        PROD,
        Op::DecryptV1 {
            addr: me.addr,
            ciphertexts: vec![
                ByteBuf::from(vector("envelope")),
                ByteBuf::from(vec![1, 2, 3]),
            ],
        },
    );
    assert_eq!(
        out,
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
fn a_sealed_message_decrypts_and_its_signature_verifies() {
    use ml_dsa::signature::Verifier;
    let mut env = MemEnv::default();
    let me = vector_identity(&mut env);
    let (content, signature, sender_vk) = match call(
        &mut env,
        PROD,
        Op::SealV1Message {
            addr: me.addr,
            recipient_ek: me.ek.clone(),
            plaintext: ByteBuf::from(b"hi".to_vec()),
            ui_entropy: Entropy([4; 32]),
        },
    ) {
        Ok(Reply::SealedV1 {
            content,
            signature,
            sender_vk,
        }) => (content, signature, sender_vk),
        other => panic!("{other:?}"),
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
}

#[test]
fn the_authority_signature_is_what_v0_2_x_signs() {
    use freenet_mail_wire_v1::inbox::{Inbox, InboxSettings};
    let mut env = MemEnv::default();
    let me = vector_identity(&mut env);
    let settings = InboxSettings::default();
    let micros = 1_700_000_000_000_000;
    let sig = match call(
        &mut env,
        PROD,
        Op::SignV1Authority {
            addr: me.addr,
            settings_json: ByteBuf::from(serde_json::to_vec(&settings).unwrap()),
            last_update_micros: micros,
        },
    ) {
        Ok(Reply::Signature(s)) => s.into_vec(),
        other => panic!("{other:?}"),
    };
    let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&[7u8; 32].into());
    let want = Inbox::sign(
        &sk,
        &me.ek,
        &settings,
        chrono::DateTime::from_timestamp_micros(micros).unwrap(),
    );
    assert_eq!(sig, want.to_vec());
}

#[test]
fn a_removal_payload_that_aliases_an_authority_payload_is_refused() {
    let mut env = MemEnv::default();
    let me = vector_identity(&mut env);
    let mut first = [0u8; 32];
    first[..8].copy_from_slice(freenet_mail_wire_v1::inbox::STATE_UPDATE);
    assert_eq!(
        call(
            &mut env,
            PROD,
            Op::SignV1Removal {
                addr: me.addr,
                assignment_hashes: vec![Hash32(first)]
            }
        ),
        Err(FailureCode::Refused)
    );
    let hashes = vec![Hash32([1; 32]), Hash32([2; 32])];
    let sig = match call(
        &mut env,
        PROD,
        Op::SignV1Removal {
            addr: me.addr,
            assignment_hashes: hashes,
        },
    ) {
        Ok(Reply::Signature(s)) => s.into_vec(),
        other => panic!("{other:?}"),
    };
    let payload: Vec<u8> = [[1u8; 32], [2u8; 32]].concat();
    assert_eq!(
        sig,
        crate::crypto::Keys::from_seeds(
            &DsaSeed([7; 32]),
            &KemSeed(std::array::from_fn(|i| i as u8))
        )
        .sign(&payload)
    );
    assert_eq!(
        call(
            &mut env,
            PROD,
            Op::SignV1Removal {
                addr: me.addr,
                assignment_hashes: vec![]
            }
        ),
        Err(FailureCode::BadInput)
    );
}

#[cfg(feature = "v1-transition")]
#[test]
fn aft_params_are_the_v0_2_x_token_generator_params() {
    let mut env = MemEnv::default();
    let me = vector_identity(&mut env);
    let want =
        serde_json::to_vec(&freenet_mail_wire_v1::aft::DelegateParameters::new([7; 32])).unwrap();
    assert_eq!(
        call(&mut env, PROD, Op::V1AftParams { addr: me.addr }),
        Ok(Reply::AftParams(ByteBuf::from(want)))
    );
}

// ── Consent ─────────────────────────────────────────────────────────────────

fn prompt_id(out: &[OutboundDelegateMsg]) -> u32 {
    match out {
        [OutboundDelegateMsg::RequestUserInput(r)] => r.request_id,
        other => panic!("expected one prompt, got {other:?}"),
    }
}

fn answer(env: &mut MemEnv, origin: u8, id: u32, choice: &[u8]) -> Vec<OutboundDelegateMsg> {
    let resp = UserInputResponse {
        request_id: id,
        response: ClientResponse::new(choice.to_vec()),
        context: DelegateContext::default(),
    };
    process(env, app(origin), InboundDelegateMsg::UserResponse(resp)).unwrap()
}

#[test]
fn an_export_asks_and_only_the_allowed_answer_releases_the_key() {
    let (dsa, kem) = fixture_seeds();
    let mut env = MemEnv::default();
    call(
        &mut env,
        PROD,
        Op::ImportIdentity {
            source: ImportSource::Seeds { dsa, kem },
            alias: "a".into(),
            description: String::new(),
        },
    )
    .unwrap();
    let addr = freenet_mail_protocol::address::address_of(
        &crate::crypto::Keys::from_seeds(&dsa, &kem).vk_bytes(),
    );

    // Deny: refused.
    let id = prompt_id(&send(&mut env, app(PROD), Op::ExportRecoveryKey { addr }));
    assert_eq!(
        response(&answer(&mut env, PROD, id, DENY))
            .result
            .unwrap_err()
            .code,
        FailureCode::Refused
    );
    // The answered prompt is gone: answering it again does nothing.
    assert!(answer(&mut env, PROD, id, ALLOW).is_empty());

    // Another origin cannot answer our prompt; we still can afterwards.
    let id = prompt_id(&send(&mut env, app(PROD), Op::ExportRecoveryKey { addr }));
    assert!(answer(&mut env, OTHER, id, ALLOW).is_empty());
    assert_eq!(
        response(&answer(&mut env, PROD, id, ALLOW)).result,
        Ok(Reply::RecoveryKey(recovery_key::encode(&dsa, &kem)))
    );

    // Allow is not remembered.
    let id = prompt_id(&send(&mut env, app(PROD), Op::ExportProfile { addr }));
    match response(&answer(&mut env, PROD, id, ALWAYS)).result {
        Ok(Reply::Profile(json)) => {
            let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
            assert_eq!(v["version"], 2);
            assert_eq!(v["keys"]["ml_dsa_seed"][1], 1);
        }
        other => panic!("{other:?}"),
    }
    // "Always" is: the next export answers at once.
    assert_eq!(
        response(&send(&mut env, app(PROD), Op::ExportRecoveryKey { addr })).result,
        Ok(Reply::RecoveryKey(recovery_key::encode(&dsa, &kem)))
    );
    // An unknown prompt id is ignored.
    assert!(answer(&mut env, PROD, 12345, ALLOW).is_empty());
}

#[test]
fn concurrent_prompts_are_distinct_and_bounded() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    let ids: Vec<u32> = (0..6)
        .map(|_| {
            prompt_id(&send(
                &mut env,
                app(PROD),
                Op::ExportRecoveryKey { addr: me.addr },
            ))
        })
        .collect();
    let unique: std::collections::BTreeSet<_> = ids.iter().collect();
    assert_eq!(unique.len(), ids.len());
    let pending = env.list_count(&store::pending_prefix(&store::Origin([PROD; 32])));
    assert_eq!(pending, store::MAX_PENDING_PROMPTS);
    // The oldest were dropped; the newest still work.
    assert!(answer(&mut env, PROD, ids[0], ALLOW).is_empty());
    assert!(matches!(
        response(&answer(&mut env, PROD, ids[5], ALLOW)).result,
        Ok(Reply::RecoveryKey(_))
    ));
}

#[test]
fn an_export_for_a_missing_identity_answers_at_once() {
    let mut env = MemEnv::default();
    let r = response(&send(
        &mut env,
        app(PROD),
        Op::ExportRecoveryKey {
            addr: Addr([1; 24]),
        },
    ));
    assert_eq!(r.result.unwrap_err().code, FailureCode::NotFound);
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

#[test]
fn the_export_for_a_successor_holds_the_namespace_and_no_bookkeeping() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    ack(put(&mut env, draft(me.addr, 1), b"d", None));
    env.secrets
        .insert(b"\0freenet-migrate-journal/x".to_vec(), b"j".to_vec());
    let exported = match call(
        &mut env,
        PROD,
        Op::ExportForSuccessor {
            source_generation: 3,
        },
    ) {
        Ok(Reply::ExportedSecrets(b)) => freenet_migrate::ExportedSecrets::from_bytes(&b).unwrap(),
        other => panic!("{other:?}"),
    };
    assert_eq!(exported.source_generation, 3);
    let ns = store::namespace(&store::Origin([PROD; 32])).into_bytes();
    assert!(!exported.secrets.is_empty());
    assert!(exported.secrets.iter().all(|(k, _)| k.starts_with(&ns)));
}

impl MemEnv {
    fn list_count(&self, prefix: &[u8]) -> usize {
        self.secrets
            .keys()
            .filter(|k| k.starts_with(prefix))
            .count()
    }
}
