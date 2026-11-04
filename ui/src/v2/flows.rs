//! The UI's v2 flows against the real mail delegate's code (the offline
//! build runs it in the page) and the offline inboxes: what the page does is
//! what it does on a node, minus the network. On real nodes the same flows
//! run in `ui/tests/inbox-v2-live.spec.ts`.
//!
//! The offline inboxes are a model that checks only what the UI needs (see
//! `net::offline`): no pass signature, expiry, epoch, send window or cap is
//! checked here. Those are the contract's own suite's and the delegate's
//! interop tests'. Nothing in this module covers them.

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

/// Archive and Delete of a drained message remove the delegate's stored
/// copy; an archive whose copy was not written keeps it.
#[test]
fn archive_and_delete_remove_the_stored_copy() {
    let (a, b) = (identity("v2-rm-a"), identity("v2-rm-b"));
    assert!(block_on(send::send(a, b, &body("archive me"))).delivered());
    assert!(block_on(send::send(a, b, &body("delete me"))).delivered());
    drain(b);
    let mail = block_on(owner::read_inbound(b)).unwrap();
    let row = |t: &str| owner::row_id(b, mail.iter().find(|m| m.body.title == t).unwrap());
    let (archive, delete) = (row("archive me"), row("delete me"));
    let failed = owner::archive_row(archive, async { Err("not stored".into()) });
    assert!(block_on(failed).is_err());
    assert_eq!(block_on(owner::read_inbound(b)).unwrap().len(), 2);
    block_on(owner::archive_row(archive, async { Ok(()) })).unwrap();
    let left = block_on(owner::read_inbound(b)).unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].body.title, "delete me");
    block_on(owner::delete_row(delete)).unwrap();
    assert!(block_on(owner::read_inbound(b)).unwrap().is_empty());
    // Gone for good: the inbox tombstoned them, so a drain brings nothing back.
    assert!(drain(b).is_empty());
}

/// An archive whose copy was stored but whose drained copy the delegate
/// could not remove says so (`(true, _)`: the page tells the user it still
/// shows in the inbox), and the drained copy is still there.
#[test]
fn an_archive_that_could_not_remove_the_drained_copy_says_so() {
    let (a, b) = (identity("v2-arch-a"), identity("v2-arch-b"));
    assert!(block_on(send::send(a, b, &body("keep me"))).delivered());
    drain(b);
    let mail = block_on(owner::read_inbound(b)).unwrap();
    let id = owner::row_id(b, &mail[0]);
    crate::mail_delegate::local::fail_writes_containing(Some("/in/"));
    let out = block_on(owner::archive_row(id, async { Ok(()) }));
    crate::mail_delegate::local::fail_writes_containing(None);
    let Err((stored, e)) = out else {
        panic!("archived although the copy could not be removed")
    };
    assert!(stored, "the archived copy was stored: {e}");
    assert_eq!(block_on(owner::read_inbound(b)).unwrap().len(), 1);
}

/// S4: an invite whose certificate is not signed by the inbox it names is
/// refused before it is held, so it never shows as a pass held.
#[test]
fn an_invite_not_signed_by_its_inbox_is_refused() {
    let (a, b, c) = (
        identity("v2-forge-a"),
        identity("v2-forge-b"),
        identity("v2-forge-c"),
    );
    net::offline::forget_own(&b);
    // This node does not hold B's inbox, so the delegate cannot check the
    // certificate itself.
    crate::mail_delegate::local::forget_contract_state(
        super::instance_id(&b).as_bytes().try_into().unwrap(),
    );
    let invite = block_on(contacts::create_invite(c, Some("bob"), 3)).unwrap();
    let crate::address::Recipient::Invite(mut parsed) =
        crate::address::parse_recipient(&invite).unwrap()
    else {
        panic!("an invite")
    };
    // C's certificate, renamed to B's inbox.
    parsed.pass.cert.recipient = serde_bytes::ByteArray::new(b.0);
    let forged = crate::address::encode_invite(Some("bob"), parsed.pass);
    let out = block_on(contacts::add(a, &forged, ""));
    assert!(out.is_err(), "{out:?}");
    assert_eq!(contacts::held(a, b), contacts::PassState::None);
}

/// N3, N5, N6: an invite in the To field is no recipient; adding an address
/// already saved reports the name it has; an add the address book refuses
/// leaves nothing that marks the address a v2 contact.
#[test]
fn contact_adds_report_what_was_kept() {
    let (a, b, c) = (
        identity("v2-nits-a"),
        identity("v2-nits-b"),
        identity("v2-nits-c"),
    );
    let invite = block_on(contacts::create_invite(b, Some("bob"), 3)).unwrap();
    assert!(contacts::is_invite(&invite));
    assert_eq!(contacts::recipient_addr(&invite), None);

    let bob = crate::address::display(&b.0);
    block_on(contacts::add(a, &bob, "bob")).unwrap();
    let again = block_on(contacts::add(a, &bob, "robert")).unwrap();
    assert_eq!(again.name, "bob", "the name it is saved under");

    // "bob" is taken by another address: refused, and c is not a contact.
    let carol = crate::address::display(&c.0);
    assert!(block_on(contacts::add(a, &format!("carol@{carol}"), "bob")).is_err());
    assert!(contacts::by_addr(&c).is_none());
    let vk = block_on(contacts::resolve(c)).unwrap().vk;
    assert!(crate::app::contact_store::v2_notes(&vk).is_none());
}

/// A new or republished inbox is not subscribed by the delegate until it
/// runs its jobs, and mail that arrives first would wait for the next
/// wake-up. So after the page's PUT lands, the page sends `RunJobs` (the node
/// holds the contract by then, so the jobs subscribe it). A PUT that failed
/// sends none: there is nothing to subscribe.
#[test]
fn the_page_sends_run_jobs_after_each_publish_that_lands() {
    use crate::mail_delegate::RUN_JOBS_CALLS;
    let runs = || RUN_JOBS_CALLS.with(std::cell::Cell::get);
    // The create path.
    let (info, _) = block_on(ops::create_identity("v2-jobs-create".into(), String::new())).unwrap();
    let a = info.addr;
    let before = runs();
    block_on(owner::ensure(a)).unwrap();
    assert_eq!(runs(), before + 1, "create: RunJobs after the PUT");
    // Already published: nothing to do, nothing sent.
    block_on(owner::ensure(a)).unwrap();
    assert_eq!(runs(), before + 1, "no publish, no RunJobs");
    // The republish path, after a first PUT that failed (none sent for it).
    let (info, _) = block_on(ops::create_identity(
        "v2-jobs-republish".into(),
        String::new(),
    ))
    .unwrap();
    let b = info.addr;
    net::offline::lose_next_put(&b, Err("the contract refused it".to_string()));
    let before = runs();
    assert!(block_on(owner::ensure(b)).is_err());
    assert_eq!(runs(), before, "a PUT that failed sends no RunJobs");
    block_on(owner::ensure(b)).unwrap();
    assert_eq!(runs(), before + 1, "republish: RunJobs after the PUT");
}

/// The first PUT of a new inbox fails after the delegate stored its record:
/// rejected, or gone with no word. A later start publishes it after all.
#[test]
fn an_inbox_whose_first_put_failed_is_published_later() {
    for (alias, answer) in [
        (
            "v2-put-rejected",
            Err("the contract refused it".to_string()),
        ),
        ("v2-put-lost", Ok(())),
    ] {
        let (info, _) = block_on(ops::create_identity(alias.into(), String::new())).unwrap();
        let a = info.addr;
        net::offline::lose_next_put(&a, answer.clone());
        assert_eq!(block_on(owner::ensure(a)).is_ok(), answer.is_ok());
        assert_eq!(block_on(net::get(&a, false)), Ok(Got::Missing));
        block_on(owner::ensure(a)).unwrap();
        assert_eq!(state(&a).owner.quarantine, QuarantineMode::Open, "{alias}");
        // And it works: mail gets in and is drained.
        let b = identity(&format!("{alias}-sender"));
        assert!(block_on(send::send(b, a, &body("after"))).delivered());
        assert_eq!(drain(a), vec!["after".to_string()]);
    }
}

/// The delegate made the inbox but the page never had its first state to
/// publish: the `CreateInboxV2` reply was lost, or the tab closed after it
/// came and before the page kept or sent it. Either way the delegate holds
/// the record and the page holds nothing. A later start publishes the inbox
/// from the delegate's record.
#[test]
fn an_inbox_whose_create_reply_never_reached_a_page_is_published_later() {
    for alias in ["v2-reply-lost", "v2-tab-closed"] {
        let (info, _) = block_on(ops::create_identity(alias.into(), String::new())).unwrap();
        let a = info.addr;
        let reply = block_on(crate::mail_delegate::call(
            freenet_mail_protocol::Op::CreateInboxV2 {
                addr: a,
                ghost_master: freenet_mail_protocol::Hash32(super::ghost_master()),
                existing: None,
            },
        ));
        match alias {
            // Lost on the way: the page never saw it.
            "v2-reply-lost" => drop(reply),
            // Seen, then the tab closed: what it held went with it.
            _ => assert!(matches!(
                reply,
                Ok(freenet_mail_protocol::Reply::InboxV2State(_))
            )),
        }
        assert_eq!(block_on(net::get(&a, false)), Ok(Got::Missing));
        block_on(owner::ensure(a)).unwrap_or_else(|e| panic!("{alias}: {e}"));
        let s = state(&a);
        assert_eq!(s.owner.quarantine, QuarantineMode::Open, "{alias}");
        // And it works: mail gets in and is drained.
        let b = identity(&format!("{alias}-sender"));
        assert!(block_on(send::send(b, a, &body("after"))).delivered());
        assert_eq!(drain(a), vec!["after".to_string()], "{alias}");
    }
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
    // A higher version than this node signed: the page's own compare (the
    // record unsigned here, which the offline inboxes do not check; the
    // signed case through the delegate is the test below).
    let mut other = state(&a);
    other.owner.version = rec().max_version + 5;
    block_on(net::put(&a, w::encode(&other))).unwrap();
    assert!(owner::foreign(state(&a).owner.version, &rec()));
}

/// Decision 25 through the delegate: another node's signed record lands, the
/// delegate's drain notes it and signs past it, and a page loaded after that
/// (nothing in memory, the version compare false) still warns, from the
/// delegate's note alone.
#[test]
fn another_nodes_record_is_still_warned_about_after_this_node_signs_past_it() {
    let (a, b) = (identity("v2-d25-a"), identity("v2-d25-b"));
    owner::forget_status(a);
    block_on(owner::another_node_signs_with(a, b)).unwrap();
    let rec = block_on(owner::record(a)).unwrap().unwrap();
    let seen = rec.foreign_seen.expect("the delegate noted it");
    let now = state(&a).owner.version;
    assert!(now > seen.version, "signed past it");
    assert!(!(now > rec.max_version), "the version compare says nothing");
    assert_eq!(drain(a), vec!["while another node signed".to_string()]);
    // A reload: the page starts with nothing and reads the inbox again.
    owner::forget_status(a);
    block_on(owner::ensure(a)).unwrap();
    block_on(owner::refresh(a));
    assert!(owner::status(&a).foreign_version);
}

/// An update that shows up only after the read-backs is waited for, never
/// sealed again before its `reseal_at`: one message lands, not two.
#[test]
fn a_slow_update_is_waited_for_and_not_sealed_twice() {
    let (a, b) = (identity("v2-slow-a"), identity("v2-slow-b"));
    // Past the read-backs, and past many later looks.
    net::offline::slow_updates(&b, 40);
    let out = block_on(send::send(a, b, &body("slow")));
    assert!(out.delivered(), "{out:?}");
    assert_eq!(state(&b).messages.len(), 1, "sealed again before reseal_at");
}

/// An update that never shows up is sealed again only at its `reseal_at`
/// (two days on), and reported after the last reseal.
#[test]
fn a_send_that_never_lands_is_resealed_only_at_reseal_at() {
    let (a, b) = (identity("v2-lost-a"), identity("v2-lost-b"));
    net::offline::slow_updates(&b, u32::MAX);
    send::SEALS.with(|s| s.borrow_mut().clear());
    let out = block_on(send::send(a, b, &body("lost")));
    assert_eq!(out, Outcome::NotDelivered(NotDelivered::AfterReseals));
    let seals = send::SEALS.with(|s| s.borrow().clone());
    assert_eq!(
        seals.len(),
        usize::from(freenet_mail_protocol::MAX_RESEALS) + 1
    );
    for pair in seals.windows(2) {
        let ((_, reseal_at), (at, _)) = (pair[0], pair[1]);
        assert!(
            at >= i64::try_from(reseal_at).unwrap() * 1_000,
            "sealed again at {at} ms, before reseal_at {reseal_at} s"
        );
    }
}

/// The page reads the delegate's decision-25 note under the names the
/// delegate writes it with.
#[test]
fn the_page_reads_the_delegates_note_of_another_node() {
    let a = identity("v2-note");
    let item = freenet_mail_protocol::ItemRef {
        kind: freenet_mail_protocol::ItemKind::InboxV2,
        owner: Some(a),
        id: Vec::new(),
    };
    let body = block_on(ops::get_item(item)).unwrap().unwrap().body;
    let mut rec: mail_delegate::inbox_v2::InboxRecord =
        freenet_mail_protocol::from_cbor(&body).unwrap();
    assert_eq!(rec.foreign_seen, None);
    rec.foreign_seen = Some(mail_delegate::inbox_v2::ForeignSeen { version: 7, at: 3 });
    let view: super::InboxRecordView =
        freenet_mail_protocol::from_cbor(&freenet_mail_protocol::to_cbor(&rec).unwrap()).unwrap();
    assert_eq!(
        view.foreign_seen,
        Some(super::ForeignSeenView { version: 7, at: 3 })
    );
    assert!(owner::foreign(view.max_version, &view));
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

fn require_ghost(addr: Addr, min_usd: Option<u32>) {
    block_on(contacts::change_own(
        addr,
        OwnerChange::SetQuarantine(QuarantineMode::RequireGhost { min_usd }),
    ))
    .unwrap();
}

/// The test vault holding `keys` (fixture indices: 0 to 3 are $1, 4 to 7 $5,
/// 8 and 9 $20), and the key it lets this app use.
fn vault(keys: Vec<usize>) -> send::GhostChoice {
    set_vault(keys, false);
    let key = block_on(crate::ghostkeys::request_access())
        .unwrap()
        .pop()
        .unwrap();
    send::GhostChoice { key, default: true }
}

fn set_vault(keys: Vec<usize>, deny: bool) {
    crate::ghostkeys::mock::save(&crate::ghostkeys::mock::State {
        default: keys.first().copied(),
        keys,
        deny,
        ..Default::default()
    });
}

fn send_with(a: Addr, b: Addr, title: &str, ghost: Option<send::GhostChoice>) -> Outcome {
    let content = freenet_mail_protocol::SealContent::Mail(body(title).encode().into());
    block_on(send::send_ghost(a, b, content, ghost))
}

/// "Use Ghost Key": the proof the vault signs gets a stranger into a
/// RequireGhost inbox, and the recipient drains the message. A key below the
/// tier is told so and nothing is sent.
#[test]
fn a_ghost_key_proof_gets_a_stranger_in_and_a_low_tier_is_refused() {
    let (a, b) = (identity("v2-proof-a"), identity("v2-proof-b"));
    require_ghost(b, Some(5));
    let twenty = vault(vec![8]);
    let out = send_with(a, b, "proven", Some(twenty.clone()));
    assert_eq!(
        out,
        Outcome::Delivered {
            admission: SendAdmission::Quarantine,
            notice: None
        }
    );
    let held = state(&b);
    let (_, m) = held.messages.iter().next().unwrap();
    let w::Admission::Quarantine { ghost: Some(proof) } = &m.admission else {
        panic!("no proof: {:?}", m.admission)
    };
    assert_eq!(
        Some(
            ghostkey_verify::GhostkeyCertificate::from_cbor(&proof.cert)
                .unwrap()
                .claimed_ghost_key()
                .to_bytes()
        ),
        twenty.key.vk
    );
    assert_eq!(drain(b), vec!["proven".to_string()]);
    let got = &block_on(owner::read_inbound(b)).unwrap()[0];
    assert_eq!(got.admission, w::KIND_QUARANTINE);

    let one = vault(vec![0]);
    let low = send_with(a, b, "too low", Some(one));
    assert_eq!(
        low,
        Outcome::NotDelivered(NotDelivered::BelowTier { have: 1, need: 5 })
    );
    assert!(low.text("bob").contains("$1") && low.text("bob").contains("$5 or more"));
    assert!(state(&b).messages.is_empty());
}

/// A proof is attached only for a RequireGhost recipient (decision 19: an
/// Open inbox refuses one), and none is asked for.
#[test]
fn an_open_inbox_gets_no_proof() {
    let (a, b) = (identity("v2-open-a"), identity("v2-open-b"));
    let key = vault(vec![8]);
    assert!(send_with(a, b, "open", Some(key)).delivered());
    let held = state(&b);
    let (_, m) = held.messages.iter().next().unwrap();
    assert_eq!(m.admission, w::Admission::Quarantine { ghost: None });
}

/// The vault's two refusals are said plainly and send nothing.
#[test]
fn no_ghost_key_and_a_declined_prompt_are_told_plainly() {
    let (a, b) = (identity("v2-deny-a"), identity("v2-deny-b"));
    require_ghost(b, None);
    let key = vault(vec![4]);
    // Not granted now, and the user says no.
    set_vault(vec![4], true);
    assert_eq!(
        send_with(a, b, "declined", Some(key.clone())),
        Outcome::NotDelivered(NotDelivered::GhostDeclined)
    );
    set_vault(vec![], false);
    let none = send_with(a, b, "no key", Some(key));
    assert_eq!(none, Outcome::NotDelivered(NotDelivered::NoGhostKey));
    assert!(none.text("bob").contains("Get a Ghost Key"));
    assert!(state(&b).messages.is_empty());
}

/// The new-contacts queue view: a stranger's mail waits there; dropping
/// removes it without a word to the sender; accepting sends the sender a
/// pass, so their next message goes straight in, and the accepted one stays
/// out of the queue after a later revocation.
#[test]
fn the_queue_holds_strangers_until_accepted_or_dropped() {
    let (a, b) = (identity("v2-queue-a"), identity("v2-queue-b"));
    assert!(send_with(a, b, "drop me", None).delivered());
    assert!(send_with(a, b, "accept me", None).delivered());
    drain(b);
    let mail = block_on(owner::read_inbound(b)).unwrap();
    let queued = block_on(super::queue::queued(b, &mail)).unwrap();
    assert_eq!(queued.len(), 2);
    let by_title = |t: &str| mail.iter().find(|m| m.body.title == t).unwrap().clone();

    block_on(super::queue::drop_message(b, &by_title("drop me"))).unwrap();
    let mail = block_on(owner::read_inbound(b)).unwrap();
    assert_eq!(mail.len(), 1);

    let said = block_on(super::queue::accept(b, &by_title("accept me"), "alice")).unwrap();
    assert!(said.starts_with("Accepted"), "{said}");
    assert!(block_on(super::queue::queued(b, &mail)).unwrap().is_empty());
    // a drains the pass b sent, and writes by pass.
    drain(a);
    assert!(matches!(
        send_with(a, b, "by pass", None),
        Outcome::Delivered {
            admission: SendAdmission::Pass,
            ..
        }
    ));
    // Revoked later: a's new mail queues again, the accepted one does not.
    block_on(contacts::revoke(b, a)).unwrap();
    assert!(send_with(a, b, "after revoke", None).delivered());
    drain(b);
    let mail = block_on(owner::read_inbound(b)).unwrap();
    let queued = block_on(super::queue::queued(b, &mail)).unwrap();
    let titles: Vec<&str> = mail
        .iter()
        .filter(|m| queued.contains(&m.id))
        .map(|m| m.body.title.as_str())
        .collect();
    assert_eq!(titles, vec!["after revoke"]);
}

/// Only this node's own inboxes and saved contacts' are followed: looking up
/// or writing to anyone else is a plain GET, so neighbours are not told of
/// an ongoing interest in a stranger's inbox.
#[test]
fn writing_to_a_non_contact_follows_nothing() {
    let (a, b) = (identity("v2-sub-a"), identity("v2-sub-b"));
    net::offline::forget_own(&b);
    block_on(contacts::resolve(b)).unwrap();
    assert!(block_on(send::send(a, b, &body("hello"))).delivered());
    assert!(
        !net::offline::subscribed(&b),
        "a stranger's inbox was followed"
    );
    // Once b is a contact, its inbox is followed.
    block_on(contacts::add(a, &crate::address::display(&b.0), "bob")).unwrap();
    assert!(block_on(send::send(a, b, &body("again"))).delivered());
    assert!(net::offline::subscribed(&b));
    assert!(net::offline::subscribed(&a), "an own inbox is followed");
}

/// M2: accepting asks for a petname, so the stranger's own label is never
/// saved as one silently; a name that is, or looks like, another contact's
/// is flagged before saving; and a differing label still shows as differing.
#[test]
fn accepting_saves_the_petname_given_and_flags_lookalikes() {
    use crate::address::LabelWarning;
    let (a, b, c) = (
        identity("v2-pet-a"),
        identity("v2-pet-b"),
        identity("v2-pet-c"),
    );
    block_on(contacts::add(b, &crate::address::display(&c.0), "mary")).unwrap();
    assert!(send_with(a, b, "hello", None).delivered());
    drain(b);
    let m = block_on(owner::read_inbound(b)).unwrap().remove(0);
    assert_eq!(m.body.label.as_deref(), Some("sender"));

    for lookalike in ["mary", "rnary"] {
        let warnings = super::queue::petname_warnings(&m, lookalike);
        assert!(
            warnings
                .iter()
                .any(|w| matches!(w, LabelWarning::LooksLike { contact } if contact == "mary")),
            "{lookalike}: {warnings:?}"
        );
    }
    assert!(
        !super::queue::petname_warnings(&m, "andy")
            .iter()
            .any(|w| matches!(w, LabelWarning::LooksLike { .. }))
    );

    block_on(super::queue::accept(b, &m, "andy")).unwrap();
    let saved = contacts::by_addr(&a).expect("a contact now");
    assert_eq!(&*saved.local_alias, "andy");
    let (name, warnings) = contacts::sender_name(&a, Some("sender"));
    assert_eq!(name, "andy");
    assert!(
        warnings
            .iter()
            .any(|w| matches!(w, LabelWarning::DiffersFromPetname { .. })),
        "{warnings:?}"
    );
}

/// A v2 send passes the safeguards a v1 send does: the recorded recipient
/// binding, and "Require known key to send".
#[test]
fn a_v2_send_keeps_the_recorded_recipient_and_the_known_key_rule() {
    use crate::app::address_book;
    let (a, b, c) = (
        identity("v2-cr-a"),
        identity("v2-cr-b"),
        identity("v2-cr-c"),
    );
    net::offline::forget_own(&b);
    net::offline::forget_own(&c);
    block_on(contacts::add(a, &crate::address::display(&b.0), "crb")).unwrap();
    block_on(contacts::add(a, &crate::address::display(&c.0), "crc")).unwrap();
    let chosen_b = address_book::address_choice("crb").expect("crb is chosen");

    // Chosen and typed agree: sent.
    assert_eq!(
        send::check_recipient("crb", Some(&chosen_b), false, false, &b),
        Ok(())
    );
    // A reopened draft recorded crb, and the field now names crc: refused.
    let err = send::check_recipient("crc", Some(&chosen_b), false, false, &c).unwrap_err();
    assert!(err.contains("different key"), "{err}");
    // The recorded address is crb's, but the address to send to is another.
    assert!(send::check_recipient("crb", Some(&chosen_b), false, false, &c).is_err());
    // Require known key to send: an unverified contact, or a stranger, is refused.
    assert!(send::check_recipient("crb", Some(&chosen_b), false, true, &b).is_err());
    let stranger = Addr([77; 24]);
    assert!(
        send::check_recipient(
            &crate::address::display(&stranger.0),
            None,
            false,
            true,
            &stranger
        )
        .is_err()
    );
    // Verified: sent. An own identity needs no verification.
    let mut contact = contacts::by_addr(&b).unwrap();
    contact.verified = true;
    address_book::insert_contact(contact).unwrap();
    assert_eq!(
        send::check_recipient("crb", Some(&chosen_b), false, true, &b),
        Ok(())
    );
    net::note_own(&c);
    assert_eq!(send::check_recipient("crc", None, false, true, &c), Ok(()));
}

/// "Add to address book" on a v2 sender adds a v2 contact, so a reply by
/// that name goes to the v2 inbox, never a v1 one.
#[test]
fn adding_a_v2_sender_makes_a_v2_contact_and_the_reply_goes_by_v2() {
    let (a, b) = (identity("v2-adds-a"), identity("v2-adds-b"));
    net::offline::forget_own(&a);
    assert!(block_on(send::send(a, b, &body("hi"))).delivered());
    let vk = block_on(contacts::resolve(a)).unwrap().vk;
    assert!(contacts::by_addr(&a).is_none());

    let added = block_on(contacts::add_sender(b, &vk, "alice")).unwrap();
    assert_eq!(added.name, "alice");
    let contact = contacts::by_addr(&a).expect("a v2 contact");
    assert!(contacts::is_v2(&contact));
    // The reply goes to alice's v2 inbox.
    assert_eq!(contacts::recipient_addr("alice"), Some(a));
    assert!(block_on(send::send(b, a, &body("re: hi"))).delivered());
    assert_eq!(drain(a), vec!["re: hi".to_string()]);

    // A name that is no valid petname is not used: the address names them.
    let c = identity("v2-adds-c");
    net::offline::forget_own(&c);
    let vk_c = block_on(contacts::resolve(c)).unwrap().vk;
    let added = block_on(contacts::add_sender(b, &vk_c, "Not A Name!!\u{202e}")).unwrap();
    assert_eq!(contacts::recipient_addr(&added.name), Some(c));
}
