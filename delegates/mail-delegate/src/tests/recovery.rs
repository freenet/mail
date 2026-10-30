//! Recovering from a key the host can no longer read.
//!
//! freenet-core reports a file it cannot read or decrypt as "not found",
//! every time. The delegate must stay safe while that lasts (never
//! overwrite, unlist or reuse anything on its say-so) and the user must
//! still be able to get Mail working again: restore an identity, delete
//! it, replace an item, or reset a list that cannot be read.

use super::*;
use crate::env::mem::Faults;

fn full(env: &mut MemEnv, rel: &str) -> String {
    String::from_utf8(Space::new(env, Origin([PROD; 32])).full_key(rel)).unwrap()
}

fn blind(env: &mut MemEnv, rel: &str) {
    let key = full(env, rel);
    env.faults = Some(Faults::blind(&key));
}

fn identity_index_len(env: &mut MemEnv) -> usize {
    let s = Space::new(env, Origin([PROD; 32]));
    s.index(store::IDENTITY_INDEX).unwrap().1.len()
}

fn listed(env: &mut MemEnv) -> Vec<Addr> {
    match call(env, PROD, Op::ListIdentities) {
        Ok(Reply::Identities(v)) => v.into_iter().map(|i| i.addr).collect(),
        other => panic!("{other:?}"),
    }
}

/// Y1: a listed identity whose record cannot be read is restored by
/// importing its keys again, even while the record still cannot be read
/// (the same address means the same seeds, so nothing is lost).
#[test]
fn importing_keys_restores_a_listed_identity_whose_record_cannot_be_read() {
    let mut env = MemEnv::default();
    let me = import_fixture(&mut env, PROD);
    blind(&mut env, &store::identity_rel(&me));
    let (dsa, kem) = fixture_seeds();
    let (identity, already) = import(
        &mut env,
        PROD,
        ImportSource::Seeds { dsa, kem },
        ImportKind::UserRestore,
        "restored",
    )
    .expect("restoring over an unreadable record");
    assert_eq!(identity.addr, me);
    assert!(!already);
    env.faults = None;
    assert_eq!(listed(&mut env), vec![me]);
    assert_eq!(identity_index_len(&mut env), 1, "no second entry");
}

/// Y1: the user can delete a listed identity whose record cannot be read.
/// It asks first (nothing can check the record), then removes everything.
#[test]
fn an_identity_whose_record_cannot_be_read_can_be_deleted_after_asking() {
    let mut env = MemEnv::default();
    let me = import_fixture(&mut env, PROD);
    ack(put(&mut env, draft(me, 1), b"d", None));
    blind(&mut env, &store::identity_rel(&me));
    let out = send(
        &mut env,
        app(PROD),
        Op::DeleteIdentity {
            addr: me,
            expected_gen: 0,
        },
    );
    let (id, _, _) = prompt(&out);
    let out = answer(&mut env, PROD, id, crate::consent::DELETE);
    assert_eq!(response(&out).result, Ok(Reply::Deleted));
    env.faults = None;
    assert!(listed(&mut env).is_empty());
    let hex = store::hex(&me.0);
    assert!(
        !env.secrets
            .keys()
            .any(|k| String::from_utf8_lossy(k).contains(&hex)),
        "something of the identity was left"
    );
}

/// Y3: a listed item whose record cannot be read is reported as such, and
/// a create replaces it; the entry is never dropped.
#[test]
fn an_unreadable_item_is_reported_and_a_create_replaces_it() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    let settings = ItemRef {
        kind: ItemKind::IdentitySettings,
        owner: Some(me.addr),
        id: Vec::new(),
    };
    let g = ack(put(&mut env, settings.clone(), b"old", None));
    blind(&mut env, &store::item_rel(&settings));
    assert_eq!(
        call(
            &mut env,
            PROD,
            Op::GetItem {
                item: settings.clone()
            }
        ),
        Err(FailureCode::Unreadable)
    );
    // An update cannot be checked against what it replaces.
    assert_eq!(
        put(&mut env, settings.clone(), b"new", Some(g)),
        Err(FailureCode::Unreadable)
    );
    let g2 = ack(put(&mut env, settings.clone(), b"new", None));
    assert!(g2 > g, "a generation is never reused");
    env.faults = None;
    match call(&mut env, PROD, Op::GetItem { item: settings }) {
        Ok(Reply::Item(Some(item))) => assert_eq!(item.body.as_ref(), b"new"),
        other => panic!("{other:?}"),
    }
}

/// Y4: with the budget full, deleting still works (its bookkeeping uses a
/// small reserve), while anything that grows the store is refused.
#[test]
fn deleting_works_when_the_budget_is_full() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    let g = ack(put(&mut env, draft(me.addr, 1), b"d", None));
    // Fill the budget: the usage record says every key is taken.
    {
        let mut s = Space::new(&mut env, Origin([PROD; 32]));
        let used = s.usage();
        s.set_usage_for_test(store::Usage {
            keys: store::MAX_ORIGIN_KEYS,
            bytes: used.bytes,
        });
    }
    assert_eq!(
        put(&mut env, draft(me.addr, 2), b"e", None),
        Err(FailureCode::CapReached)
    );
    assert_eq!(
        call(
            &mut env,
            PROD,
            Op::DeleteItem {
                item: draft(me.addr, 1),
                expected_gen: g,
            }
        ),
        Ok(Reply::Deleted)
    );
    assert!(list_ids(&mut env, PROD, ItemKind::Draft, Some(me.addr)).is_empty());
}

/// Y2: an identity index that cannot be read stops every identity op, so
/// the user may reset it, after being asked. Records stay stored, and
/// importing an identity's keys lists it again.
#[test]
fn an_unreadable_identity_index_can_be_reset_and_identities_restored() {
    let mut env = MemEnv::default();
    let me = import_fixture(&mut env, PROD);
    blind(&mut env, store::IDENTITY_INDEX);
    assert_eq!(
        call(&mut env, PROD, Op::ListIdentities),
        Err(FailureCode::Busy)
    );
    let repair = Op::RepairIndex {
        kind: None,
        owner: None,
    };
    let (id, _, text) = prompt(&send(&mut env, app(PROD), repair.clone()));
    assert!(text.contains("recovery key"), "{text}");
    let out = answer(&mut env, PROD, id, crate::consent::REPAIR);
    assert_eq!(response(&out).result, Ok(Reply::Ack { generation: 0 }));
    // The list is usable again; the record is still stored.
    assert!(listed(&mut env).is_empty());
    env.faults = None;
    assert!(listed(&mut env).is_empty(), "the reset list stays empty");
    let (dsa, kem) = fixture_seeds();
    let (_, already) = import(
        &mut env,
        PROD,
        ImportSource::Seeds { dsa, kem },
        ImportKind::UserRestore,
        "back",
    )
    .unwrap();
    assert!(already, "the record was kept");
    assert_eq!(listed(&mut env), vec![me]);
}

/// Y2: a readable index is never reset, and asking is not even offered.
#[test]
fn a_readable_index_is_never_reset() {
    let mut env = MemEnv::default();
    let me = import_fixture(&mut env, PROD);
    for repair in [
        Op::RepairIndex {
            kind: None,
            owner: None,
        },
        Op::RepairIndex {
            kind: Some(ItemKind::Draft),
            owner: Some(me),
        },
    ] {
        assert_eq!(
            call(&mut env, PROD, repair),
            Err(FailureCode::Refused),
            "a readable index must not be reset"
        );
    }
    assert_eq!(listed(&mut env), vec![me]);
}

/// Y2: one kind's index of one identity, likewise, and only that one.
#[test]
fn an_unreadable_item_index_can_be_reset() {
    let mut env = MemEnv::default();
    let me = create(&mut env, PROD, "alice");
    ack(put(&mut env, draft(me.addr, 1), b"d", None));
    ack(put(&mut env, contact(1), b"c", None));
    blind(&mut env, &store::index_rel(ItemKind::Draft, Some(&me.addr)));
    let list = Op::ListItems {
        kind: ItemKind::Draft,
        owner: Some(me.addr),
        after: None,
        limit: 10,
    };
    assert_eq!(call(&mut env, PROD, list.clone()), Err(FailureCode::Busy));
    let (id, _, _) = prompt(&send(
        &mut env,
        app(PROD),
        Op::RepairIndex {
            kind: Some(ItemKind::Draft),
            owner: Some(me.addr),
        },
    ));
    assert_eq!(
        response(&answer(&mut env, PROD, id, crate::consent::REPAIR)).result,
        Ok(Reply::Ack { generation: 0 })
    );
    // Drafts can be saved again; other lists are untouched.
    ack(put(&mut env, draft(me.addr, 2), b"e", None));
    env.faults = None;
    assert_eq!(
        list_ids(&mut env, PROD, ItemKind::Draft, Some(me.addr)),
        vec![vec![2; 16]]
    );
    assert_eq!(list_ids(&mut env, PROD, ItemKind::Contact, None).len(), 1);
}

/// Y2: another app cannot reset this app's index (namespaced like every
/// other op), and a denied prompt changes nothing.
#[test]
fn a_repair_is_namespaced_and_a_denial_changes_nothing() {
    let mut env = MemEnv::default();
    let me = import_fixture(&mut env, PROD);
    blind(&mut env, store::IDENTITY_INDEX);
    let repair = Op::RepairIndex {
        kind: None,
        owner: None,
    };
    // In its own namespace the other app's index is readable (absent).
    assert_eq!(
        call(&mut env, OTHER, repair.clone()),
        Err(FailureCode::Refused)
    );
    let (id, _, _) = prompt(&send(&mut env, app(PROD), repair));
    assert_eq!(
        response(&answer(&mut env, PROD, id, crate::consent::CANCEL))
            .result
            .map_err(|f| f.code),
        Err(FailureCode::Refused)
    );
    env.faults = None;
    assert_eq!(listed(&mut env), vec![me]);
}

/// Y5: a create whose record write, undo and marking were all refused
/// leaves an entry with only its create marker. The next listing frees the
/// slot (absence confirmed by a re-read), so nothing leaks for good.
#[test]
fn a_create_that_never_finished_frees_its_slot_on_the_next_listing() {
    use crate::env::mem::{FaultOp, Rule};
    let mut env = MemEnv::default();
    import_fixture(&mut env, PROD);
    let rule = |op, key: &str, nth| Rule {
        op,
        key_contains: key.into(),
        nth,
    };
    // The record write; the undo of the index entry and its two retries;
    // the "failed" marking and its two retries. The index add itself and
    // the create marker (each one's first write) go through.
    // Rules count calls per key text, so each nth uses its own text for
    // the same key.
    let mut faults = Faults::default();
    faults.rules = vec![
        rule(FaultOp::SetFail, "/id/", 1),
        rule(FaultOp::SetFail, "/ix/id", 2),
        rule(FaultOp::SetFail, "ix/id", 3),
        rule(FaultOp::SetFail, "x/id", 4),
        rule(FaultOp::SetFail, "/dl/", 2),
        rule(FaultOp::SetFail, "dl/", 3),
        rule(FaultOp::SetFail, "/dl", 4),
    ];
    env.faults = Some(faults);
    let created = call(
        &mut env,
        PROD,
        Op::CreateIdentity {
            alias: "never".into(),
            description: String::new(),
            ui_entropy: Entropy([9; 32]),
        },
    );
    assert!(created.is_err(), "{created:?}");
    env.faults = None;
    assert_eq!(identity_index_len(&mut env), 2, "the slot was claimed");
    call(&mut env, PROD, Op::ListDeletingIdentities).unwrap();
    assert_eq!(identity_index_len(&mut env), 1, "the slot was freed");
}
