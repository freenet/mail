//! Export sessions in detail, deletion edge cases, and prompt bookkeeping
//! under storage failures, each written to fail against the behaviour it
//! replaced.

use super::*;
use crate::consent::{EXPORT_SESSION_SECS, set_session_pages_left};

fn send_as(env: &mut MemEnv, origin: u8, op: Op, id: u8) -> Vec<OutboundDelegateMsg> {
    let req = Request {
        version: PROTOCOL_VERSION,
        request_id: RequestId([id; 16]),
        op,
    };
    let msg =
        InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(to_cbor(&req).unwrap()));
    process(env, app(origin), msg).unwrap()
}

fn export(after: Option<ByteBuf>, session: Option<ByteBuf>) -> Op {
    Op::ExportForSuccessor {
        source_generation: 1,
        after,
        session,
    }
}

/// Approve a multi-page export for `origin`; returns (next, token).
fn approved_export(env: &mut MemEnv, origin: u8) -> (ByteBuf, ByteBuf) {
    let me = create(env, origin, "alice");
    for id in 1..=8u8 {
        ack(put_as(
            env,
            origin,
            draft(me.addr, id),
            &vec![id; 200 * 1024],
            None,
        ));
    }
    let (id, _, _) = prompt(&send(env, app(origin), export(None, None)));
    match response(&answer(env, origin, id, ALLOW)).result {
        Ok(Reply::ExportedSecrets {
            next: Some(n),
            session: Some(t),
            ..
        }) => (n, t),
        other => panic!("{other:?}"),
    }
}

fn next_page(
    env: &mut MemEnv,
    origin: u8,
    next: &ByteBuf,
    token: &ByteBuf,
) -> Result<Reply, FailureCode> {
    response(&send(
        env,
        app(origin),
        export(Some(next.clone()), Some(token.clone())),
    ))
    .result
    .map_err(|f| f.code)
}

#[test]
fn revoking_the_grant_ends_the_export_session() {
    let mut env = MemEnv {
        now: Some(1_000),
        ..MemEnv::default()
    };
    let (next, token) = approved_export(&mut env, PROD);
    assert_eq!(
        call(&mut env, PROD, Op::RevokeExportGrant),
        Ok(Reply::Deleted)
    );
    assert_eq!(
        Space::new(&mut env, Origin([PROD; 32])).get(store::EXPORT_SESSION),
        None
    );
    assert_eq!(
        next_page(&mut env, PROD, &next, &token),
        Err(FailureCode::Refused)
    );
}

#[test]
fn a_session_is_bound_to_its_own_app_even_when_the_other_has_one() {
    let mut env = MemEnv {
        now: Some(1_000),
        ..MemEnv::default()
    };
    let (p_next, p_token) = approved_export(&mut env, PROD);
    let (o_next, o_token) = approved_export(&mut env, OTHER);
    assert_eq!(
        next_page(&mut env, OTHER, &p_next, &p_token),
        Err(FailureCode::Refused)
    );
    assert_eq!(
        next_page(&mut env, PROD, &o_next, &o_token),
        Err(FailureCode::Refused)
    );
    assert!(next_page(&mut env, PROD, &p_next, &p_token).is_ok());
}

#[test]
fn a_session_slides_with_each_page_but_not_past_the_clock_skew_bound() {
    let mut env = MemEnv {
        now: Some(1_000),
        ..MemEnv::default()
    };
    let (next, token) = approved_export(&mut env, PROD);
    // 200 s later: still valid, and the expiry moves to 200 + 300.
    env.now = Some(1_200);
    let Ok(Reply::ExportedSecrets {
        next: Some(next), ..
    }) = next_page(&mut env, PROD, &next, &token)
    else {
        panic!("page refused");
    };
    // 450 s after approval, more than 300 after it: valid because it slid.
    env.now = Some(1_450);
    let Ok(Reply::ExportedSecrets {
        next: Some(next), ..
    }) = next_page(&mut env, PROD, &next, &token)
    else {
        panic!("sliding expiry not applied");
    };
    // The clock set back far enough that the expiry is implausibly far ahead.
    env.now = Some(1_450 - 61);
    assert_eq!(
        next_page(&mut env, PROD, &next, &token),
        Err(FailureCode::Refused)
    );
    let _ = EXPORT_SESSION_SECS;
}

#[test]
fn a_session_serves_no_more_pages_than_it_has_left() {
    let mut env = MemEnv {
        now: Some(1_000),
        ..MemEnv::default()
    };
    let (next, token) = approved_export(&mut env, PROD);
    set_session_pages_left(&mut Space::new(&mut env, Origin([PROD; 32])), 0);
    assert_eq!(
        next_page(&mut env, PROD, &next, &token),
        Err(FailureCode::Refused)
    );
}

fn fill(env: &mut MemEnv, owner: Addr, n: u32) {
    let mut s = Space::new(env, Origin([PROD; 32]));
    let mut ids = Vec::new();
    for i in 0..n {
        let id = (i as u128).to_be_bytes().to_vec();
        let item = ItemRef {
            kind: ItemKind::Archived,
            owner: Some(owner),
            id: id.clone(),
        };
        s.write_if(&store::item_rel(&item), 0, b"a").unwrap();
        ids.push(ByteBuf::from(id));
    }
    let ix = store::index_rel(ItemKind::Archived, Some(&owner));
    s.write_if(&ix, 0, &to_cbor(&ids).unwrap()).unwrap();
}

/// Import the fixture identity, give it 600 items and start deleting it.
fn half_deleted(env: &mut MemEnv) -> IdentityInfo {
    let (dsa, kem) = fixture_seeds();
    let (me, _) = import(
        env,
        PROD,
        ImportSource::Seeds { dsa, kem },
        ImportKind::UserRestore,
        "a",
    )
    .unwrap();
    fill(env, me.addr, 600);
    let del = Op::DeleteIdentity {
        addr: me.addr,
        expected_gen: me.generation,
    };
    let (id, _, _) = prompt(&send(env, app(PROD), del));
    assert!(matches!(
        response(&answer(env, PROD, id, DELETE)).result,
        Ok(Reply::Continue { .. })
    ));
    me
}

#[test]
fn an_identity_being_deleted_cannot_be_re_imported() {
    let mut env = MemEnv::default();
    half_deleted(&mut env);
    let (dsa, kem) = fixture_seeds();
    assert_eq!(
        import(
            &mut env,
            PROD,
            ImportSource::Seeds { dsa, kem },
            ImportKind::UserRestore,
            "a"
        )
        .unwrap_err(),
        FailureCode::Refused
    );
}

#[test]
fn the_successor_export_leaves_out_an_identity_being_deleted() {
    let mut env = MemEnv::default();
    let gone = half_deleted(&mut env);
    let keep = create(&mut env, PROD, "bob");
    let (g, _, _) = prompt(&send(&mut env, app(PROD), export(None, None)));
    let Ok(Reply::ExportedSecrets { payload, .. }) =
        response(&answer(&mut env, PROD, g, ALLOW)).result
    else {
        panic!("export refused");
    };
    let page = freenet_migrate::ExportedSecrets::from_bytes(&payload).unwrap();
    let keys: Vec<String> = page
        .secrets
        .iter()
        .map(|(k, _)| String::from_utf8_lossy(k).into_owned())
        .collect();
    assert!(keys.iter().any(|k| k.contains(&store::hex(&keep.addr.0))));
    assert!(keys.iter().all(|k| !k.contains(&store::hex(&gone.addr.0))));
}

// ── Prompt bookkeeping under storage failures ───────────────────────────────

#[test]
fn a_prompt_whose_index_slot_cannot_be_claimed_leaves_no_stash() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    // The index write fails: with the slot claimed first, nothing is stashed.
    env.fail_keys_containing = Some("/ix/pg".into());
    let r = response(&send(
        &mut env,
        app(PROD),
        Op::ExportRecoveryKey { addr: me.addr },
    ));
    assert_eq!(r.result.unwrap_err().code, FailureCode::Internal);
    assert!(
        env.secrets
            .keys()
            .all(|k| !String::from_utf8_lossy(k).contains("/pg/"))
    );
}

#[test]
fn a_failed_cleanup_of_one_expired_prompt_does_not_drop_anothers_refusal() {
    let mut env = MemEnv {
        now: Some(1_000),
        ..MemEnv::default()
    };
    let me = create(&mut env, PROD, "alice");
    let a = prompt(&send_as(
        &mut env,
        PROD,
        Op::ExportRecoveryKey { addr: me.addr },
        1,
    ))
    .0;
    let b = prompt(&send_as(
        &mut env,
        PROD,
        Op::ExportRecoveryKey { addr: me.addr },
        2,
    ))
    .0;
    let ((first, first_req), (second, _)) = if a < b {
        ((a, 1u8), (b, 2u8))
    } else {
        ((b, 2u8), (a, 1u8))
    };
    env.now = Some(1_000 + store::PROMPT_TTL_SECS + 1);
    // Pruning visits `first` then `second`; removing `second` fails.
    env.fail_keys_containing = Some(format!("pg/{second:08x}"));
    let out = send_as(&mut env, PROD, Op::ExportRecoveryKey { addr: me.addr }, 3);
    let rs = responses(&out);
    assert!(
        rs.iter()
            .any(|r| r.request_id == RequestId([first_req; 16])),
        "{rs:?}"
    );
    let _ = first;
}

#[test]
fn an_answer_whose_stash_cannot_be_cleared_is_answered_once_later() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    let (id, _, _) = prompt(&send(
        &mut env,
        app(PROD),
        Op::ExportRecoveryKey { addr: me.addr },
    ));
    env.fail_keys_containing = Some(format!("pg/{id:08x}"));
    let resp = UserInputResponse {
        request_id: id,
        response: ClientResponse::new(ALLOW.to_vec()),
        context: DelegateContext::default(),
    };
    assert!(process(&mut env, app(PROD), InboundDelegateMsg::UserResponse(resp)).is_err());
    env.fail_keys_containing = None;
    assert!(matches!(
        response(&answer(&mut env, PROD, id, ALLOW)).result,
        Ok(Reply::RecoveryKey(_))
    ));
    assert!(answer(&mut env, PROD, id, ALLOW).is_empty());
}
