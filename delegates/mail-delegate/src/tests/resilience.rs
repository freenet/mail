//! Interrupted deletes, and requests from a newer UI.

use super::*;

#[test]
fn an_item_delete_interrupted_before_the_index_update_is_finished_by_its_retry() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    let g = ack(put(&mut env, draft(me.addr, 1), b"d", None));
    ack(put(&mut env, draft(me.addr, 2), b"e", None));
    env.fail_keys_containing = Some("/ix/dr/".into());
    let del = Op::DeleteItem {
        item: draft(me.addr, 1),
        expected_gen: g,
    };
    assert_eq!(
        call(&mut env, PROD, del.clone()),
        Err(FailureCode::Internal)
    );
    env.fail_keys_containing = None;
    // The stale index entry is invisible to readers...
    assert_eq!(
        list_ids(&mut env, PROD, ItemKind::Draft, Some(me.addr)),
        vec![vec![2; 16]]
    );
    // ...and the retry removes it.
    assert_eq!(call(&mut env, PROD, del), Ok(Reply::Deleted));
    let s = Space::new(&mut env, Origin([PROD; 32]));
    let (_, ids) = s
        .index(&store::index_rel(ItemKind::Draft, Some(&me.addr)))
        .unwrap();
    assert_eq!(ids.into_iter().collect::<Vec<_>>(), vec![vec![2; 16]]);
}

#[test]
fn an_identity_delete_interrupted_before_the_index_update_is_finished_without_asking_again() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    ack(put(&mut env, draft(me.addr, 1), b"d", None));
    let del = Op::DeleteIdentity {
        addr: me.addr,
        expected_gen: me.generation,
    };
    let (id, _, _) = prompt(&send(&mut env, app(PROD), del.clone()));
    env.fail_keys_containing = Some("/ix/id".into());
    assert_eq!(
        response(&answer(&mut env, PROD, id, DELETE))
            .result
            .unwrap_err()
            .code,
        FailureCode::Internal
    );
    env.fail_keys_containing = None;
    assert_eq!(
        call(&mut env, PROD, Op::ListIdentities),
        Ok(Reply::Identities(vec![]))
    );
    // The retry answers at once (no second prompt) and leaves nothing behind.
    assert_eq!(
        response(&send(&mut env, app(PROD), del.clone())).result,
        Ok(Reply::Deleted)
    );
    let me_hex = store::hex(&me.addr.0);
    assert!(
        env.secrets
            .keys()
            .all(|k| !String::from_utf8_lossy(k).contains(&me_hex))
    );
    // Further retries: the identity is simply not found.
    assert_eq!(
        response(&send(&mut env, app(PROD), del))
            .result
            .unwrap_err()
            .code,
        FailureCode::NotFound
    );
}

#[derive(serde::Serialize)]
enum FutureOp {
    Teleport { to: u8 },
}

#[derive(serde::Serialize)]
struct FutureRequest {
    version: u16,
    request_id: RequestId,
    op: FutureOp,
}

fn send_raw(env: &mut MemEnv, bytes: Vec<u8>) -> Response {
    let msg = InboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(bytes));
    response(&process(env, app(PROD), msg).unwrap())
}

#[test]
fn a_request_from_a_newer_ui_gets_a_typed_answer_with_its_id() {
    let mut env = MemEnv::default();
    let unknown = to_cbor(&FutureRequest {
        version: PROTOCOL_VERSION,
        request_id: RequestId([7; 16]),
        op: FutureOp::Teleport { to: 1 },
    })
    .unwrap();
    let r = send_raw(&mut env, unknown);
    assert_eq!(r.request_id, RequestId([7; 16]));
    assert_eq!(r.result.unwrap_err().code, FailureCode::UnknownOperation);
    let newer = to_cbor(&FutureRequest {
        version: PROTOCOL_VERSION + 1,
        request_id: RequestId([8; 16]),
        op: FutureOp::Teleport { to: 1 },
    })
    .unwrap();
    let r = send_raw(&mut env, newer);
    assert_eq!(r.request_id, RequestId([8; 16]));
    assert_eq!(r.result.unwrap_err().code, FailureCode::UnsupportedVersion);
    assert!(env.secrets.is_empty());
}
