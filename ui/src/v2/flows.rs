//! The UI's v2 flows against the real mail delegate's code (the offline
//! build runs it in the page) and the offline inboxes: what the page does is
//! what it does on a node, minus the network. On real nodes the same flows
//! run in `ui/tests/inbox-v2-live.spec.ts`.

use freenet_mail_protocol::inbox_v2::{self as w, InboxState, QuarantineMode};
use freenet_mail_protocol::{Addr, OwnerChange, SendAdmission, SendNotice};

use super::net::{self, Got};
use super::send::{NotDelivered, Outcome};
use super::{MailBody, contacts, owner, send};
use crate::mail_delegate::ops;

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    futures::executor::block_on(f)
}

fn identity(alias: &str) -> Addr {
    let (info, _) = block_on(ops::create_identity(alias.into(), String::new())).unwrap();
    block_on(owner::ensure(info.addr)).unwrap();
    info.addr
}

fn body(title: &str) -> MailBody {
    MailBody {
        v: 1,
        label: Some("sender".into()),
        title: title.into(),
        content: "hello".into(),
        time_ms: 1,
        thread_id: None,
        in_reply_to: None,
        quoted_excerpt: None,
    }
}

fn state(addr: &Addr) -> InboxState {
    let Got::State(bytes) = block_on(net::get(addr, false)).unwrap() else {
        panic!("no inbox")
    };
    w::decode(&bytes).unwrap()
}

fn drain(addr: Addr) -> Vec<String> {
    block_on(owner::refresh(addr));
    let items = block_on(ops::list_all_items(
        freenet_mail_protocol::ItemKind::Inbound,
        Some(addr),
    ))
    .unwrap();
    items
        .iter()
        .filter_map(|i| {
            let m: w::InboundMessage = freenet_mail_protocol::from_cbor(&i.body).ok()?;
            Some(MailBody::decode(&m.body)?.title)
        })
        .collect()
}

#[test]
fn ensure_makes_one_inbox_and_finds_it_again() {
    let a = identity("v2-ensure");
    let s = state(&a);
    assert_eq!(s.owner.quarantine, QuarantineMode::Open);
    // A second load finds the record and the inbox and changes nothing.
    block_on(owner::ensure(a)).unwrap();
    assert_eq!(state(&a), s);
}

/// First contact lands in the new-contacts queue; the reply then goes by the
/// pass the first message carried, and so does the next message back.
#[test]
fn first_contact_then_passes_both_ways() {
    let (a, b) = (identity("v2-alice"), identity("v2-bob"));
    let first = block_on(send::send(a, b, &body("first")));
    assert_eq!(
        first,
        Outcome::Delivered {
            admission: SendAdmission::Quarantine,
            notice: None
        }
    );
    assert_eq!(drain(b), vec!["first".to_string()]);
    assert!(state(&b).messages.is_empty(), "drained and tombstoned");
    assert_eq!(contacts::held(b, a), contacts::PassState::Held);

    let reply = block_on(send::send(b, a, &body("reply")));
    assert!(
        matches!(
            reply,
            Outcome::Delivered {
                admission: SendAdmission::Pass,
                ..
            }
        ),
        "{reply:?}"
    );
    assert_eq!(drain(a), vec!["reply".to_string()]);
    let again = block_on(send::send(a, b, &body("again")));
    assert!(
        matches!(
            again,
            Outcome::Delivered {
                admission: SendAdmission::Pass,
                ..
            }
        ),
        "{again:?}"
    );
}

/// Revoking a contact's pass: their next message is told the pass lapsed and
/// goes to the new-contacts queue instead, and is still delivered.
#[test]
fn a_revoked_pass_falls_back_to_the_queue_and_says_so() {
    let (a, b) = (identity("v2-rev-a"), identity("v2-rev-b"));
    assert!(block_on(send::send(a, b, &body("hi"))).delivered());
    drain(b);
    // b writes back, so a holds b's pass and b issued a pass to a.
    assert!(block_on(send::send(b, a, &body("hi back"))).delivered());
    drain(a);
    assert!(matches!(
        block_on(send::send(a, b, &body("by pass"))),
        Outcome::Delivered {
            admission: SendAdmission::Pass,
            ..
        }
    ));
    drain(b);

    let ledger = block_on(contacts::ledger(b)).unwrap();
    assert!(matches!(
        contacts::issued_to(&ledger, &a),
        contacts::Issued::Live { .. }
    ));
    block_on(contacts::revoke(b, a)).unwrap();
    let ledger = block_on(contacts::ledger(b)).unwrap();
    assert_eq!(contacts::issued_to(&ledger, &a), contacts::Issued::Revoked);

    let after = block_on(send::send(a, b, &body("after revoke")));
    assert_eq!(
        after,
        Outcome::Delivered {
            admission: SendAdmission::Quarantine,
            notice: Some(SendNotice::PassLapsed)
        }
    );
    assert_eq!(contacts::held(a, b), contacts::PassState::Lapsed);
    assert!(after.text("bob").contains("lapsed"));
}

/// An invite carries a pass: the first message goes straight in.
#[test]
fn an_invite_lets_the_first_message_in_by_pass() {
    let (a, b) = (identity("v2-inv-a"), identity("v2-inv-b"));
    let invite = block_on(contacts::create_invite(b, Some("bob"), 3)).unwrap();
    assert!(invite.starts_with(crate::address::INVITE_PREFIX));
    let added = block_on(contacts::add(a, &invite, "")).unwrap();
    assert!(added.invite);
    assert_eq!(added.name, "bob");
    assert_eq!(contacts::held(a, b), contacts::PassState::Held);
    let sent = block_on(send::send(a, b, &body("invited")));
    assert!(
        matches!(
            sent,
            Outcome::Delivered {
                admission: SendAdmission::Pass,
                ..
            }
        ),
        "{sent:?}"
    );
}

/// RequireGhost: a stranger without a Ghost Key proof is told so, and
/// nothing lands.
#[test]
fn a_require_ghost_inbox_refuses_a_stranger_without_a_proof() {
    let (a, b) = (identity("v2-gk-a"), identity("v2-gk-b"));
    block_on(contacts::change_own(
        b,
        OwnerChange::SetQuarantine(QuarantineMode::RequireGhost { min_usd: Some(5) }),
    ))
    .unwrap();
    assert_eq!(
        state(&b).owner.quarantine,
        QuarantineMode::RequireGhost { min_usd: Some(5) }
    );
    assert_eq!(
        block_on(send::send(a, b, &body("no key"))),
        Outcome::NotDelivered(NotDelivered::NeedsGhostKey)
    );
    assert!(state(&b).messages.is_empty());
}

/// 17 strangers into 16 slots: a send whose message ranks outside the slots
/// is told the queue is full, and is never reported delivered.
#[test]
fn a_full_queue_is_reported_and_never_claimed_delivered() {
    let (a, b) = (identity("v2-full-a"), identity("v2-full-b"));
    let mut outcomes = Vec::new();
    // Past 16, each new message ranks last with chance 1/17 (the rank is a
    // salted hash), so keep sending until one does: 400 sends miss it with
    // chance (16/17)^384, about 1e-10.
    for i in 0..400 {
        let outcome = block_on(send::send(a, b, &body(&format!("stranger {i}"))));
        let full = outcome == Outcome::NotDelivered(NotDelivered::QueueFull);
        outcomes.push(outcome);
        if full {
            break;
        }
    }
    assert_eq!(state(&b).messages.len(), w::QUARANTINE_SLOTS);
    let (last, earlier) = outcomes.split_last().unwrap();
    assert_eq!(*last, Outcome::NotDelivered(NotDelivered::QueueFull));
    assert!(last.text("bob").contains("new-contacts queue is full"));
    // The first 16 always fit; after that a message that ranks inside
    // pushes an earlier one out and is delivered.
    assert!(earlier.len() >= 16);
    assert!(earlier.iter().all(Outcome::delivered), "{earlier:?}");
}

/// Decision 25: a version the delegate did not record is another node's.
#[test]
fn an_owner_version_this_node_did_not_sign_is_seen() {
    let (a, b) = (identity("v2-foreign"), identity("v2-foreign-b"));
    // This node's own changes are its own: a drain signs a new version.
    assert!(block_on(send::send(b, a, &body("x"))).delivered());
    drain(a);
    let rec = || block_on(owner::record(a)).unwrap().unwrap();
    assert!(state(&a).owner.version > 1);
    assert!(!owner::foreign(state(&a).owner.version, &rec()));
    // Another node signing for the same identity publishes a higher
    // version (the offline inboxes do not check signatures).
    let mut other = state(&a);
    other.owner.version = rec().max_version + 5;
    block_on(net::put(&a, w::encode(&other))).unwrap();
    assert!(owner::foreign(state(&a).owner.version, &rec()));
}

/// A message to a name or address the UI cannot reach says so, unsent.
#[test]
fn an_address_with_no_inbox_is_reported() {
    let a = identity("v2-nowhere");
    let out = block_on(send::send(a, Addr([0x77; 24]), &body("x")));
    assert!(matches!(
        out,
        Outcome::NotDelivered(NotDelivered::Unreachable(_))
    ));
}
