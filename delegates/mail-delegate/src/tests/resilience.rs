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
    // The retry removes the stale index entry by itself (no listing first:
    // a listing would free it too, see the next test)...
    assert_eq!(call(&mut env, PROD, del), Ok(Reply::Deleted));
    let index = |env: &mut MemEnv| {
        let s = Space::new(env, Origin([PROD; 32]));
        let (_, ids) = s
            .index(&store::index_rel(ItemKind::Draft, Some(&me.addr)))
            .unwrap();
        ids.into_iter().collect::<Vec<_>>()
    };
    assert_eq!(index(&mut env), vec![vec![2; 16]]);
    // ...and readers never saw it.
    assert_eq!(
        list_ids(&mut env, PROD, ItemKind::Draft, Some(me.addr)),
        vec![vec![2; 16]]
    );
}

/// An index entry whose record a failed delete or rollback removed holds a
/// slot of its kind's cap. Listing the kind frees it.
#[test]
fn listing_frees_an_index_entry_whose_item_is_gone() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    let g = ack(put(&mut env, draft(me.addr, 1), b"d", None));
    ack(put(&mut env, draft(me.addr, 2), b"e", None));
    env.fail_keys_containing = Some("/ix/dr/".into());
    let _ = call(
        &mut env,
        PROD,
        Op::DeleteItem {
            item: draft(me.addr, 1),
            expected_gen: g,
        },
    );
    env.fail_keys_containing = None;
    assert_eq!(
        list_ids(&mut env, PROD, ItemKind::Draft, Some(me.addr)),
        vec![vec![2; 16]]
    );
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

/// A deletion that removed the identity's record and then failed to
/// update the index left an entry nothing lists. Listing unfinished
/// deletions (which every startup does) frees it, so it neither strands a
/// slot nor needs a deletion the UI cannot offer.
#[test]
fn a_recordless_identity_index_entry_is_pruned_when_deletions_are_listed() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    let del = Op::DeleteIdentity {
        addr: me.addr,
        expected_gen: me.generation,
    };
    let (id, _, _) = prompt(&send(&mut env, app(PROD), del));
    env.fail_keys_containing = Some("/ix/id".into());
    assert!(
        response(&answer(&mut env, PROD, id, DELETE))
            .result
            .is_err()
    );
    env.fail_keys_containing = None;
    let index_len = |env: &mut MemEnv| {
        let s = Space::new(env, Origin([PROD; 32]));
        s.index(store::IDENTITY_INDEX).unwrap().1.len()
    };
    assert_eq!(index_len(&mut env), 1, "the stale entry is there");
    assert_eq!(
        call(&mut env, PROD, Op::ListDeletingIdentities),
        Ok(Reply::Identities(vec![]))
    );
    assert_eq!(index_len(&mut env), 0, "listing pruned it");
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

fn identity_index_len(env: &mut MemEnv) -> usize {
    let s = Space::new(env, Origin([PROD; 32]));
    s.index(store::IDENTITY_INDEX).unwrap().1.len()
}

/// The host cannot tell a failed read from an absent key. A listing that
/// prunes while an identity's record fails to read must not unindex it:
/// only a finished deletion's own marker proves the record is gone.
#[test]
fn a_record_that_fails_to_read_is_never_pruned_from_the_index() {
    let mut env = MemEnv::default();
    let me = import_fixture(&mut env, PROD);
    let key = Space::new(&mut env, Origin([PROD; 32])).full_key(&store::identity_rel(&me));
    // The record "disappears" for a while (a transient read failure).
    let record = env.secrets.remove(&key).unwrap();
    assert_eq!(
        call(&mut env, PROD, Op::ListDeletingIdentities),
        Ok(Reply::Identities(vec![]))
    );
    // Nor may a deletion nobody approved finish on it.
    let del = Op::DeleteIdentity {
        addr: me,
        expected_gen: 0,
    };
    assert_ne!(call(&mut env, PROD, del), Ok(Reply::Deleted));
    env.secrets.insert(key, record);
    assert_eq!(identity_index_len(&mut env), 1, "still indexed");
    match call(&mut env, PROD, Op::ListIdentities) {
        Ok(Reply::Identities(v)) => {
            assert_eq!(v.iter().map(|i| i.addr).collect::<Vec<_>>(), vec![me]);
        }
        other => panic!("{other:?}"),
    }
}

/// An identity whose record exists but whose index entry was lost is listed
/// again by importing its keys.
#[test]
fn importing_a_present_but_unindexed_identity_indexes_it_again() {
    let mut env = MemEnv::default();
    let me = import_fixture(&mut env, PROD);
    Space::new(&mut env, Origin([PROD; 32]))
        .index_remove(store::IDENTITY_INDEX, &me.0)
        .unwrap();
    assert_eq!(identity_index_len(&mut env), 0);
    let (dsa, kem) = fixture_seeds();
    let (_, already) = import(
        &mut env,
        PROD,
        ImportSource::Seeds { dsa, kem },
        ImportKind::UserRestore,
        "a",
    )
    .unwrap();
    assert!(already);
    assert_eq!(identity_index_len(&mut env), 1, "indexed again");
}

/// Re-creating an identity whose earlier deletion left its marker clears
/// the marker, so a later failed read cannot prune the new record's entry.
#[test]
fn a_reimported_identity_clears_its_old_deletion_marker() {
    let mut env = MemEnv::default();
    let me = import_fixture(&mut env, PROD);
    {
        let mut s = Space::new(&mut env, Origin([PROD; 32]));
        s.put(&store::deleted_rel(&me), b"").unwrap();
        s.del(&store::identity_rel(&me)).unwrap();
        s.index_remove(store::IDENTITY_INDEX, &me.0).unwrap();
    }
    import_fixture(&mut env, PROD);
    let s = Space::new(&mut env, Origin([PROD; 32]));
    assert!(s.get(&store::deleted_rel(&me)).is_none());
}
