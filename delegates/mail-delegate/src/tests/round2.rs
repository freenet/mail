//! Export sessions, revoking the grant, paged deletion, and exactly one
//! response when storage writes fail.

use super::*;
use crate::consent::EXPORT_SESSION_SECS;

fn send_id(env: &mut MemEnv, op: Op, id: u8) -> Vec<OutboundDelegateMsg> {
    let req = Request {
        version: PROTOCOL_VERSION,
        request_id: RequestId([id; 16]),
        op,
    };
    let msg =
        InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(to_cbor(&req).unwrap()));
    process(env, app(PROD), msg).unwrap()
}

fn export(after: Option<ByteBuf>, session: Option<ByteBuf>, generation: u32) -> Op {
    Op::ExportForSuccessor {
        source_generation: generation,
        after,
        session,
    }
}

/// An identity with four 200 KiB drafts: an export of several pages.
fn big_export_setup(env: &mut MemEnv) -> IdentityInfo {
    let me = create(env, PROD, "alice");
    for id in 1..=4u8 {
        ack(put(env, draft(me.addr, id), &vec![id; 200 * 1024], None));
    }
    me
}

fn page(r: Response) -> (Option<ByteBuf>, Option<ByteBuf>) {
    match r.result {
        Ok(Reply::ExportedSecrets { next, session, .. }) => (next, session),
        other => panic!("{other:?}"),
    }
}

#[test]
fn an_approved_export_continues_under_its_session_and_nothing_else() {
    let mut env = MemEnv {
        now: Some(1_000),
        ..MemEnv::default()
    };
    big_export_setup(&mut env);
    let (id, _, _) = prompt(&send(&mut env, app(PROD), export(None, None, 1)));
    let (next, session) = page(response(&answer(&mut env, PROD, id, ALLOW)));
    let (next, token) = (next.unwrap(), session.expect("a session token"));
    let bad = |r: Vec<OutboundDelegateMsg>| response(&r).result.unwrap_err().code;

    // Wrong token, cursor, source generation, or app: refused, no prompt.
    let wrong_token = ByteBuf::from(vec![0; 32]);
    assert_eq!(
        bad(send(
            &mut env,
            app(PROD),
            export(Some(next.clone()), Some(wrong_token), 1)
        )),
        FailureCode::Refused
    );
    assert_eq!(
        bad(send(
            &mut env,
            app(PROD),
            export(Some(ByteBuf::from(b"x".to_vec())), Some(token.clone()), 1)
        )),
        FailureCode::Refused
    );
    assert_eq!(
        bad(send(
            &mut env,
            app(PROD),
            export(Some(next.clone()), Some(token.clone()), 2)
        )),
        FailureCode::Refused
    );
    assert_eq!(
        bad(send(
            &mut env,
            app(OTHER),
            export(Some(next.clone()), Some(token.clone()), 1)
        )),
        FailureCode::Refused
    );

    // The right ones: the next page, without asking, until the last.
    let (mut after, mut tok) = (Some(next), token);
    let mut pages = 1;
    while let Some(a) = after.clone() {
        let (n, t) = page(response(&send(
            &mut env,
            app(PROD),
            export(Some(a), Some(tok.clone()), 1),
        )));
        pages += 1;
        after = n;
        if let Some(t) = t {
            tok = t;
        }
    }
    assert!(pages >= 2);
    let s = Space::new(&mut env, Origin([PROD; 32]));
    assert_eq!(
        s.get(store::EXPORT_SESSION),
        None,
        "the last page ends the session"
    );
}

#[test]
fn an_export_session_expires() {
    let mut env = MemEnv {
        now: Some(1_000),
        ..MemEnv::default()
    };
    big_export_setup(&mut env);
    let (id, _, _) = prompt(&send(&mut env, app(PROD), export(None, None, 1)));
    let (next, token) = page(response(&answer(&mut env, PROD, id, ALLOW)));
    env.now = Some(1_000 + EXPORT_SESSION_SECS + 1);
    let r = response(&send(&mut env, app(PROD), export(next, token, 1)));
    assert_eq!(r.result.unwrap_err().code, FailureCode::Refused);
}

#[test]
fn without_a_clock_every_page_asks() {
    let mut env = MemEnv::default();
    big_export_setup(&mut env);
    let (id, _, _) = prompt(&send(&mut env, app(PROD), export(None, None, 1)));
    let (next, session) = page(response(&answer(&mut env, PROD, id, ALLOW)));
    assert_eq!(session, None);
    prompt(&send(&mut env, app(PROD), export(next, None, 1)));
}

#[test]
fn a_remembered_grant_can_be_revoked() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    let (id, _, _) = prompt(&send(
        &mut env,
        app(PROD),
        Op::ExportRecoveryKey { addr: me.addr },
    ));
    answer(&mut env, PROD, id, ALWAYS);
    assert!(matches!(
        response(&send(
            &mut env,
            app(PROD),
            Op::ExportRecoveryKey { addr: me.addr }
        ))
        .result,
        Ok(Reply::RecoveryKey(_))
    ));
    assert_eq!(
        call(&mut env, PROD, Op::RevokeExportGrant),
        Ok(Reply::Deleted)
    );
    prompt(&send(
        &mut env,
        app(PROD),
        Op::ExportRecoveryKey { addr: me.addr },
    ));
}

/// Write `n` archived items for `owner` straight into the store (one index
/// write), to build a large identity quickly.
fn fill_archive(env: &mut MemEnv, owner: Addr, n: u32) {
    let mut s = Space::new(env, Origin([PROD; 32]));
    let mut ids = Vec::new();
    for i in 0..n {
        let id = (i as u128).to_be_bytes().to_vec();
        let item = ItemRef {
            kind: ItemKind::Archived,
            owner: Some(owner),
            id: id.clone(),
        };
        s.write_if(&store::item_rel(&item), 0, b"archived").unwrap();
        ids.push(ByteBuf::from(id));
    }
    let ix = store::index_rel(ItemKind::Archived, Some(&owner));
    s.write_if(&ix, 0, &to_cbor(&ids).unwrap()).unwrap();
}

#[test]
fn a_large_identity_is_deleted_in_bounded_steps_and_is_unusable_meanwhile() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    let keep = create(&mut env, PROD, "bob");
    fill_archive(&mut env, me.addr, 1000);
    let del = Op::DeleteIdentity {
        addr: me.addr,
        expected_gen: me.generation,
    };
    let (id, _, _) = prompt(&send(&mut env, app(PROD), del.clone()));
    let step = crate::handlers::DELETE_STEP as u32;
    assert_eq!(
        response(&answer(&mut env, PROD, id, DELETE)).result,
        Ok(Reply::Continue {
            remaining: 1000 - step
        })
    );

    // While deleting: hidden from the list and refusing other operations.
    match call(&mut env, PROD, Op::ListIdentities) {
        Ok(Reply::Identities(v)) => assert_eq!(
            v.iter().map(|i| i.addr).collect::<Vec<_>>(),
            vec![keep.addr]
        ),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        put(&mut env, draft(me.addr, 1), b"x", None),
        Err(FailureCode::Refused)
    );
    assert_eq!(
        response(&send(
            &mut env,
            app(PROD),
            Op::ExportRecoveryKey { addr: me.addr }
        ))
        .result
        .unwrap_err()
        .code,
        FailureCode::Refused
    );
    assert_eq!(
        call(
            &mut env,
            PROD,
            Op::DecryptV1 {
                addr: me.addr,
                ciphertexts: vec![]
            }
        ),
        Err(FailureCode::Refused)
    );

    // Each repeat continues without asking, until done.
    let mut steps = 1;
    loop {
        let out = send(&mut env, app(PROD), del.clone());
        steps += 1;
        match response(&out).result {
            Ok(Reply::Continue { .. }) => continue,
            Ok(Reply::Deleted) => break,
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(steps, 1000usize.div_ceil(crate::handlers::DELETE_STEP));
    let me_hex = store::hex(&me.addr.0);
    assert!(
        env.secrets
            .keys()
            .all(|k| !String::from_utf8_lossy(k).contains(&me_hex))
    );
    assert_eq!(
        response(&send(&mut env, app(PROD), del))
            .result
            .unwrap_err()
            .code,
        FailureCode::NotFound
    );
}

// ── Exactly one response when storage fails ─────────────────────────────────

#[test]
fn an_answer_whose_index_cleanup_fails_still_gets_its_response() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    let (id, _, _) = prompt(&send(
        &mut env,
        app(PROD),
        Op::ExportRecoveryKey { addr: me.addr },
    ));
    env.fail_keys_containing = Some("/ix/pg".into());
    assert!(matches!(
        response(&answer(&mut env, PROD, id, ALLOW)).result,
        Ok(Reply::RecoveryKey(_))
    ));
    env.fail_keys_containing = None;
    // The leftover index entry is dropped later without a second response.
    let out = send_id(&mut env, Op::ExportRecoveryKey { addr: me.addr }, 2);
    assert!(responses(&out).is_empty());
    prompt(&out);
}

#[test]
fn a_prompt_whose_stash_cannot_be_written_answers_and_leaves_nothing() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    env.fail_keys_containing = Some("/pg/".into());
    let r = response(&send(
        &mut env,
        app(PROD),
        Op::ExportRecoveryKey { addr: me.addr },
    ));
    assert_eq!(r.result.unwrap_err().code, FailureCode::Internal);
    env.fail_keys_containing = None;
    let s = Space::new(&mut env, Origin([PROD; 32]));
    assert!(s.index(store::PROMPT_INDEX).unwrap().1.is_empty());
    assert!(
        env.secrets
            .keys()
            .all(|k| !String::from_utf8_lossy(k).contains("/pg/"))
    );
}

#[test]
fn an_expired_prompt_is_refused_exactly_once_even_when_cleanup_fails() {
    let mut env = MemEnv {
        now: Some(1_000),
        ..MemEnv::default()
    };
    let me = create(&mut env, PROD, "alice");
    prompt(&send_id(
        &mut env,
        Op::ExportRecoveryKey { addr: me.addr },
        1,
    ));
    env.now = Some(1_000 + store::PROMPT_TTL_SECS + 1);
    // The expired stash cannot be removed: no response for it yet, and the
    // new request is answered (its own prompt cannot be stored either).
    env.fail_keys_containing = Some("/pg/".into());
    let out = send_id(&mut env, Op::ExportRecoveryKey { addr: me.addr }, 2);
    let rs = responses(&out);
    assert_eq!(rs.len(), 1);
    assert_eq!(rs[0].request_id, RequestId([2; 16]));
    env.fail_keys_containing = None;
    // Now the expired one is refused, once.
    let out = send_id(&mut env, Op::ExportRecoveryKey { addr: me.addr }, 3);
    let refused: Vec<_> = responses(&out)
        .into_iter()
        .filter(|r| r.request_id == RequestId([1; 16]))
        .collect();
    assert_eq!(refused.len(), 1);
    assert_eq!(
        refused[0].result.as_ref().unwrap_err().code,
        FailureCode::Refused
    );
    let out = send_id(&mut env, Op::ExportRecoveryKey { addr: me.addr }, 4);
    assert!(
        responses(&out)
            .iter()
            .all(|r| r.request_id != RequestId([1; 16]))
    );
}

#[test]
fn a_stash_dated_in_the_future_is_treated_as_expired() {
    let mut env = MemEnv {
        now: Some(10_000),
        ..MemEnv::default()
    };
    let me = create(&mut env, PROD, "alice");
    let (id, _, _) = prompt(&send(
        &mut env,
        app(PROD),
        Op::ExportRecoveryKey { addr: me.addr },
    ));
    env.now = Some(10_000 - 61 - 1);
    assert_eq!(
        response(&answer(&mut env, PROD, id, ALLOW))
            .result
            .unwrap_err()
            .code,
        FailureCode::Refused
    );
}

/// Listing unfinished deletions also prunes recordless identity index
/// entries. If that prune cannot write the index, the listing must still
/// answer with the deletions that can be finished; the prune runs again on
/// the next listing.
#[test]
fn a_failed_prune_does_not_fail_the_deletion_listing() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    let carol = create(&mut env, PROD, "carol");
    // alice: an approved deletion interrupted midway.
    fill_archive(&mut env, me.addr, 600);
    let del = Op::DeleteIdentity {
        addr: me.addr,
        expected_gen: me.generation,
    };
    let (id, _, _) = prompt(&send(&mut env, app(PROD), del));
    assert!(matches!(
        response(&answer(&mut env, PROD, id, DELETE)).result,
        Ok(Reply::Continue { .. })
    ));
    // carol: deleted, but the index update failed, leaving a recordless entry.
    let del = Op::DeleteIdentity {
        addr: carol.addr,
        expected_gen: carol.generation,
    };
    let (id, _, _) = prompt(&send(&mut env, app(PROD), del));
    env.fail_keys_containing = Some("/ix/id".into());
    assert!(
        response(&answer(&mut env, PROD, id, DELETE))
            .result
            .is_err()
    );
    let index_len = |env: &mut MemEnv| {
        let s = Space::new(env, Origin([PROD; 32]));
        s.index(crate::store::IDENTITY_INDEX).unwrap().1.len()
    };
    assert_eq!(index_len(&mut env), 2);

    // The index is still unwritable while the UI lists.
    match call(&mut env, PROD, Op::ListDeletingIdentities) {
        Ok(Reply::Identities(v)) => {
            assert_eq!(v.iter().map(|i| i.addr).collect::<Vec<_>>(), vec![me.addr]);
        }
        other => panic!("the listing failed with the prune: {other:?}"),
    }
    assert_eq!(index_len(&mut env), 2, "the prune could not run");

    // Once the index is writable again, the next listing prunes.
    env.fail_keys_containing = None;
    assert!(matches!(
        call(&mut env, PROD, Op::ListDeletingIdentities),
        Ok(Reply::Identities(v)) if v.len() == 1
    ));
    assert_eq!(index_len(&mut env), 1, "the stale entry is gone");
}

/// An approved deletion interrupted midway (the tab closed) is listed by
/// `ListDeletingIdentities`, only for the app that owns it, and finishing it
/// asks nothing.
#[test]
fn an_interrupted_deletion_is_listed_and_finishes_without_asking() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    let keep = create(&mut env, PROD, "bob");
    fill_archive(&mut env, me.addr, 600);
    let del = Op::DeleteIdentity {
        addr: me.addr,
        expected_gen: me.generation,
    };
    let (id, _, _) = prompt(&send(&mut env, app(PROD), del.clone()));
    assert!(matches!(
        response(&answer(&mut env, PROD, id, DELETE)).result,
        Ok(Reply::Continue { .. })
    ));
    // The page went away here.
    let listed = |env: &mut MemEnv, origin| match call(env, origin, Op::ListDeletingIdentities) {
        Ok(Reply::Identities(v)) => v.iter().map(|i| i.addr).collect::<Vec<_>>(),
        other => panic!("{other:?}"),
    };
    assert_eq!(listed(&mut env, PROD), vec![me.addr]);
    assert!(
        listed(&mut env, OTHER).is_empty(),
        "another app sees nothing"
    );
    assert!(!listed(&mut env, PROD).contains(&keep.addr));
    loop {
        let out = send(&mut env, app(PROD), del.clone());
        assert!(
            out.iter()
                .all(|m| !matches!(m, OutboundDelegateMsg::RequestUserInput(_))),
            "finishing an approved deletion must not ask again"
        );
        match response(&out).result {
            Ok(Reply::Continue { .. }) => continue,
            Ok(Reply::Deleted) => break,
            other => panic!("{other:?}"),
        }
    }
    assert!(listed(&mut env, PROD).is_empty(), "nothing left to finish");
}
