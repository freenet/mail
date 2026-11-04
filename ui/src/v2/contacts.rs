//! v2 contacts: added by address or invite, with their passes shown plainly,
//! revoked, and invites made.
//!
//! A contact is its address, kept in the address book with the keys its
//! inbox publishes. Which passes exist is the delegate's: the passes this
//! identity issued are in its ledger, which the page reads; the passes it
//! holds to write to others it never shows a page. What the page says about
//! those comes from what it saw: mail drained from the contact (every v2
//! message carries a pass back), an invite imported, and the delegate's
//! answer at each send.

use std::cell::RefCell;
use std::collections::HashSet;

use dioxus::prelude::*;
use freenet_mail_protocol::address::address_of;
use freenet_mail_protocol::inbox_v2::{self as w, InboxState, PassClass};
use freenet_mail_protocol::{
    Addr, ItemKind, Op, OwnerChange, PassId, Reply, SendAdmission, SendNotice, from_cbor,
};

use super::LedgerView;
use super::net::{self, Got};
use crate::address::{self, Recipient};
use crate::app::address_book::{self, Contact};
use crate::app::contact_store;
use crate::mail_delegate::{call, ops, unexpected};

/// Bumped when anything shown about v2 contacts changes.
pub(crate) static GEN: GlobalSignal<u64> = Signal::global(|| 0);

fn bump() {
    if dioxus::core::Runtime::try_current().is_some() {
        *GEN.write() += 1;
    }
}

thread_local! {
    /// (identity, contact) pairs seen to hold a pass: drained mail, an
    /// invite, or a send the delegate admitted by pass.
    static HELD: RefCell<HashSet<(Addr, Addr)>> = RefCell::new(HashSet::new());
    /// Pairs whose pass the delegate last reported lapsed.
    static LAPSED: RefCell<HashSet<(Addr, Addr)>> = RefCell::new(HashSet::new());
}

/// A recipient's inbox as read from the network.
#[derive(Clone, Debug)]
pub(crate) struct Resolved {
    pub vk: Vec<u8>,
    pub kem_ek: Vec<u8>,
    pub quarantine: w::QuarantineMode,
}

/// Read `addr`'s inbox and check it is that address's: the owner record's
/// key must hash to the address. The delegate checks the signatures again
/// before it seals anything to it.
pub(crate) async fn resolve(addr: Addr) -> Result<Resolved, String> {
    let bytes = match net::get(&addr, true).await? {
        Got::State(s) => s,
        Got::Missing => {
            return Err("there is no inbox at this address on the network (yet)".into());
        }
    };
    resolved_from(addr, bytes)
}

pub(crate) fn resolved_from(addr: Addr, bytes: Vec<u8>) -> Result<Resolved, String> {
    let state: InboxState = w::decode(&bytes).map_err(|e| format!("not an inbox: {e}"))?;
    if address_of(&state.owner.owner_vk) != addr {
        return Err("the inbox at this address belongs to another key".into());
    }
    Ok(Resolved {
        vk: state.owner.owner_vk.to_vec(),
        kem_ek: state.owner.kem_ek.to_vec(),
        quarantine: state.owner.quarantine,
    })
}

/// Whether `contact` is reached through its v2 inbox.
pub(crate) fn is_v2(contact: &Contact) -> bool {
    contact_store::v2_notes(&contact.ml_dsa_vk_bytes).is_some()
}

/// The v2 contacts, with their addresses.
pub(crate) fn all() -> Vec<(Contact, Addr)> {
    let mut out: Vec<(Contact, Addr)> = address_book::all_contacts()
        .into_iter()
        .filter(is_v2)
        .map(|c| {
            let a = address_of(&c.ml_dsa_vk_bytes);
            (c, a)
        })
        .collect();
    out.sort_by(|a, b| a.0.local_alias.cmp(&b.0.local_alias));
    out
}

pub(crate) fn by_addr(addr: &Addr) -> Option<Contact> {
    all().into_iter().find(|(_, a)| a == addr).map(|(c, _)| c)
}

/// (petname, address) of every contact, for the label checks.
pub(crate) fn petnames() -> Vec<(String, [u8; 24])> {
    all()
        .into_iter()
        .map(|(c, a)| (c.local_alias.to_string(), a.0))
        .collect()
}

/// The v2 address a To field names: an address in any accepted form, or a
/// v2 contact's name.
pub(crate) fn recipient_addr(text: &str) -> Option<Addr> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    if let Ok(r) = address::parse_recipient(text) {
        return r.addr().map(Addr);
    }
    all()
        .into_iter()
        .find(|(c, _)| &*c.local_alias == text)
        .map(|(_, a)| a)
}

/// What adding a contact did.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Added {
    pub name: String,
    pub warnings: Vec<address::LabelWarning>,
    pub invite: bool,
}

/// Add a contact from what the user pasted: an address in any form, or an
/// invite, which `identity` then holds to write to them.
pub(crate) async fn add(identity: Addr, input: &str, petname: &str) -> Result<Added, String> {
    let recipient = address::parse_recipient(input).map_err(|e| e.to_string())?;
    let addr = match &recipient {
        Recipient::Legacy { .. } => {
            return Err(
                "this is an old (v0.2) address. Old contacts move over in a later \
                        update; ask them for their new address meanwhile"
                    .into(),
            );
        }
        r => Addr(r.addr().expect("a v2 recipient")),
    };
    if addr == identity {
        return Err("that is this identity's own address".into());
    }
    let label = recipient.label().map(str::to_string);
    let petname = match petname.trim() {
        "" => None,
        p => Some(
            address::normalize_label(p, true)
                .map_err(|e| format!("the name {e}"))?
                .0,
        ),
    };
    let resolved = resolve(addr).await?;
    if let Recipient::Invite(invite) = &recipient {
        match call(Op::HoldPass {
            addr: identity,
            pass: invite.pass.clone(),
        })
        .await
        {
            Ok(Reply::Ack { .. }) => {}
            Ok(other) => return Err(unexpected(&other).to_string()),
            Err(e) => return Err(format!("the invite could not be kept: {e}")),
        }
    }
    let (name, warnings) =
        address::name_for(&addr.0, petname.as_deref(), label.as_deref(), &petnames());
    let mut notes = contact_store::v2_notes(&resolved.vk).unwrap_or_default();
    notes.label = label.or(notes.label);
    if matches!(recipient, Recipient::Invite(_)) && !notes.invited.contains(&identity.0) {
        notes.invited.push(identity.0);
    }
    contact_store::set_v2_notes(&resolved.vk, notes);
    let contact = match by_addr(&addr) {
        Some(existing) => existing,
        None => Contact {
            local_alias: name.as_str().into(),
            suggested_alias: None,
            description: String::new(),
            ml_dsa_vk_bytes: resolved.vk.clone(),
            ml_kem_ek_bytes: resolved.kem_ek.clone(),
            required_tier: freenet_mail_wire_v1::aft::Tier::Day1,
            max_age_secs: 0,
            verified: false,
            inbox_wasm_hash: Some(super::CODE_HASH.trim().to_string()),
        },
    };
    contact_store::accept(contact)?;
    if matches!(recipient, Recipient::Invite(_)) {
        HELD.with(|h| h.borrow_mut().insert((identity, addr)));
    }
    bump();
    Ok(Added {
        name,
        warnings,
        invite: matches!(recipient, Recipient::Invite(_)),
    })
}

/// Every drained message carried a pass to its sender's inbox, which the
/// delegate kept: this identity holds a pass to write to each sender.
pub(crate) fn note_drained(identity: Addr, mail: &[super::owner::Inbound]) {
    let changed = HELD.with(|h| {
        let mut h = h.borrow_mut();
        let before = h.len();
        h.extend(mail.iter().map(|m| (identity, m.from)));
        h.len() != before
    });
    if changed {
        bump();
    }
}

/// What a send told us about the pass to `to`.
pub(crate) fn note_send(
    identity: Addr,
    to: Addr,
    admission: SendAdmission,
    notice: Option<SendNotice>,
) {
    let pair = (identity, to);
    if admission == SendAdmission::Pass {
        HELD.with(|h| h.borrow_mut().insert(pair));
        LAPSED.with(|l| l.borrow_mut().remove(&pair));
    }
    if notice == Some(SendNotice::PassLapsed) {
        LAPSED.with(|l| l.borrow_mut().insert(pair));
        HELD.with(|h| h.borrow_mut().remove(&pair));
    }
    bump();
}

/// Whether `identity` holds a pass to write to `to`, as far as the page saw.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PassState {
    Held,
    Lapsed,
    /// None seen: a first message goes to their new-contacts queue.
    None,
}

pub(crate) fn held(identity: Addr, to: Addr) -> PassState {
    let pair = (identity, to);
    if LAPSED.with(|l| l.borrow().contains(&pair)) {
        return PassState::Lapsed;
    }
    let invited = by_addr(&to)
        .and_then(|c| contact_store::v2_notes(&c.ml_dsa_vk_bytes))
        .is_some_and(|n| n.invited.contains(&identity.0));
    if invited || HELD.with(|h| h.borrow().contains(&pair)) {
        PassState::Held
    } else {
        PassState::None
    }
}

/// The pass this identity issued a contact, from its ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Issued {
    /// Not yet: the first message to them carries one.
    NotYet,
    /// Live until this time (node seconds).
    Live {
        expiry: u64,
        ids: Vec<PassId>,
    },
    Revoked,
}

/// Every ledger entry of `identity`, by pass id.
pub(crate) async fn ledger(identity: Addr) -> Result<Vec<(PassId, LedgerView)>, String> {
    let items = ops::list_all_items(ItemKind::PassLedger, Some(identity))
        .await
        .map_err(|e| e.to_string())?;
    Ok(items
        .iter()
        .filter_map(|i| {
            let id: [u8; 16] = i.item.id.as_slice().try_into().ok()?;
            Some((PassId(id), from_cbor::<LedgerView>(&i.body).ok()?))
        })
        .collect())
}

pub(crate) fn issued_to(ledger: &[(PassId, LedgerView)], contact: &Addr) -> Issued {
    let mine: Vec<&(PassId, LedgerView)> = ledger
        .iter()
        .filter(|(_, e)| e.issued_for.is_some_and(|c| *c == contact.0))
        .filter(|(_, e)| e.class == PassClass::Contact)
        .collect();
    let live: Vec<&(PassId, LedgerView)> =
        mine.iter().copied().filter(|(_, e)| !e.revoked).collect();
    match (live.is_empty(), mine.is_empty()) {
        (true, true) => Issued::NotYet,
        (true, false) => Issued::Revoked,
        (false, _) => Issued::Live {
            expiry: live.iter().map(|(_, e)| e.expiry).max().unwrap_or(0),
            ids: live.iter().map(|(id, _)| *id).collect(),
        },
    }
}

/// Revoke every live pass `identity` issued `contact`. Their mail then goes
/// to the new-contacts queue. Drains first, as every owner change does.
pub(crate) async fn revoke(identity: Addr, contact: Addr) -> Result<(), String> {
    let ledger = ledger(identity).await?;
    let Issued::Live { ids, .. } = issued_to(&ledger, &contact) else {
        return Err("there is no live pass to revoke".into());
    };
    for pass_id in ids {
        change_own(identity, OwnerChange::Revoke { pass_id }).await?;
    }
    bump();
    Ok(())
}

/// Sign `change` to `identity`'s own inbox and publish it, draining as the
/// delegate asks until the change is signed.
pub(crate) async fn change_own(identity: Addr, change: OwnerChange) -> Result<(), String> {
    for _ in 0..16 {
        let state = match net::get(&identity, true).await? {
            Got::State(s) => s,
            Got::Missing => return Err("this identity's inbox is not on the network".into()),
        };
        let u = super::owner::update_inbox(identity, state, change.clone()).await?;
        if let Some(delta) = &u.update {
            net::update(&identity, delta.to_vec()).await?;
        }
        match u.change {
            freenet_mail_protocol::ChangeOutcome::Signed => return Ok(()),
            freenet_mail_protocol::ChangeOutcome::WaitsForDrain => continue,
            freenet_mail_protocol::ChangeOutcome::WaitsForStorage => {
                return Err(
                    "a message in the inbox could not be stored (storage is full); \
                            free some space and try again"
                        .into(),
                );
            }
        }
    }
    Err("the inbox is still draining; try again in a moment".into())
}

/// An invite to write to `identity`: `max_messages` messages within 14 days,
/// suggesting `label` as the name.
pub(crate) async fn create_invite(
    identity: Addr,
    label: Option<&str>,
    max_messages: u8,
) -> Result<String, String> {
    match call(Op::IssuePass {
        addr: identity,
        contact: None,
        invite: Some(max_messages),
        ui_entropy: super::entropy(),
    })
    .await
    {
        Ok(Reply::PassIssued(pass)) => {
            let label = label.and_then(|l| address::normalize_label(l, false).ok());
            Ok(address::encode_invite(
                label.as_ref().map(|l| l.0.as_str()),
                pass,
            ))
        }
        Ok(other) => Err(unexpected(&other).to_string()),
        Err(e) => Err(e.to_string()),
    }
}

/// The issuer's view of every v2 contact for `identity`: name, address,
/// what is held and what was issued. Read by the contacts screen.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Row {
    pub name: String,
    pub addr: Addr,
    pub label_warnings: Vec<address::LabelWarning>,
    pub held: PassState,
    pub issued: Issued,
}

pub(crate) async fn rows(identity: Addr) -> Result<Vec<Row>, String> {
    let ledger = ledger(identity).await?;
    let pets = petnames();
    Ok(all()
        .into_iter()
        .map(|(c, a)| {
            let label = contact_store::v2_notes(&c.ml_dsa_vk_bytes).and_then(|n| n.label);
            let (name, label_warnings) =
                address::name_for(&a.0, Some(&c.local_alias), label.as_deref(), &pets);
            Row {
                name,
                addr: a,
                label_warnings,
                held: held(identity, a),
                issued: issued_to(&ledger, &a),
            }
        })
        .collect())
}

/// The name to show for mail from `from`, and what to warn about.
pub(crate) fn sender_name(
    from: &Addr,
    label: Option<&str>,
) -> (String, Vec<address::LabelWarning>) {
    let petname = by_addr(from).map(|c| c.local_alias.to_string());
    address::name_for(&from.0, petname.as_deref(), label, &petnames())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(contact: [u8; 24], revoked: bool, expiry: u64) -> LedgerView {
        LedgerView {
            issued_for: Some(serde_bytes::ByteArray::new(contact)),
            class: PassClass::Contact,
            expiry,
            revoked,
        }
    }

    #[test]
    fn the_issued_pass_reads_plainly() {
        let bob = Addr([2; 24]);
        assert_eq!(issued_to(&[], &bob), Issued::NotYet);
        let revoked = vec![(PassId([1; 16]), entry(bob.0, true, 10))];
        assert_eq!(issued_to(&revoked, &bob), Issued::Revoked);
        let mut both = revoked.clone();
        both.push((PassId([3; 16]), entry(bob.0, false, 20)));
        assert_eq!(
            issued_to(&both, &bob),
            Issued::Live {
                expiry: 20,
                ids: vec![PassId([3; 16])]
            }
        );
        // Another contact's pass is not bob's.
        assert_eq!(issued_to(&both, &Addr([9; 24])), Issued::NotYet);
    }

    #[test]
    fn a_lapse_outranks_a_held_pass_until_a_pass_works_again() {
        let (me, bob) = (Addr([1; 24]), Addr([2; 24]));
        assert_eq!(held(me, bob), PassState::None);
        note_send(me, bob, SendAdmission::Pass, None);
        assert_eq!(held(me, bob), PassState::Held);
        note_send(
            me,
            bob,
            SendAdmission::Quarantine,
            Some(SendNotice::PassLapsed),
        );
        assert_eq!(held(me, bob), PassState::Lapsed);
        note_send(me, bob, SendAdmission::Pass, None);
        assert_eq!(held(me, bob), PassState::Held);
    }
}
