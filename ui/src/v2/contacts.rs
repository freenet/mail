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
    /// The key the inbox's passes are signed with.
    pub issuer_vk: [u8; 32],
    pub quarantine: w::QuarantineMode,
    /// Messages held in the inbox, not drained yet: public, like the queue
    /// fill.
    pub waiting: usize,
    /// Messages the owner drained and tombstoned (public too): it grows only
    /// when the owner's node signs a drain.
    pub drained: usize,
}

/// Read `addr`'s inbox and check it is that address's: the owner record's
/// key must hash to the address. The delegate checks the signatures again
/// before it seals anything to it.
pub(crate) async fn resolve(addr: Addr) -> Result<Resolved, String> {
    let bytes = match net::get(&addr, follows(&addr)).await? {
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
        issuer_vk: *state.owner.issuer_vk,
        quarantine: state.owner.quarantine,
        waiting: state
            .messages
            .keys()
            .filter(|id| !state.owner.tombstones.contains_key(*id))
            .count(),
        drained: state.owner.tombstones.len(),
    })
}

/// Whether a GET of `addr`'s inbox also follows it: only this node's own
/// inboxes and saved contacts' (as the jobs rank them). A lookup of, or a
/// send to, anyone else is a plain GET, so this node does not keep telling
/// its neighbours it is interested in a stranger's inbox.
pub(crate) fn follows(addr: &Addr) -> bool {
    net::is_own(addr) || by_addr(addr).is_some()
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

/// (petname, address) of every contact, v1 or v2, and of the user's own
/// identities, for the label checks: a name can be mistaken for any of them.
pub(crate) fn petnames() -> Vec<(String, [u8; 24])> {
    address_book::all_contacts()
        .into_iter()
        .map(|c| (c.local_alias.to_string(), c.ml_dsa_vk_bytes))
        .chain(address_book::own_names())
        .map(|(name, vk)| (name, address_of(&vk).0))
        .collect()
}

/// Whether a To field holds an invite. An invite is a bearer secret: it is
/// added as a contact (which holds it), never written to, and never stored
/// in a Sent record.
pub(crate) fn is_invite(text: &str) -> bool {
    matches!(
        address::parse_recipient(text.trim()),
        Ok(Recipient::Invite(_))
    )
}

/// The v2 address a To field names: an address in any accepted form, or a
/// v2 contact's name.
pub(crate) fn recipient_addr(text: &str) -> Option<Addr> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    if let Ok(r) = address::parse_recipient(text) {
        if matches!(r, Recipient::Invite(_)) {
            return None;
        }
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
    /// The address is one of your own identities: nothing is added to the
    /// address book, and an invite is kept for writing to it.
    pub own: bool,
}

/// Add a contact from what the user pasted: an address in any form, or an
/// invite, which `identity` then holds to write to them.
pub(crate) async fn add(identity: Addr, input: &str, petname: &str) -> Result<Added, String> {
    let recipient = address::parse_recipient(input).map_err(|e| e.to_string())?;
    let addr = match &recipient {
        Recipient::Legacy { id, label } => {
            return add_legacy(*id, label.as_deref(), petname).await;
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
        // Checked here, against the inbox just read: the delegate checks it
        // only when its node already holds that inbox.
        invite_is_theirs(&invite.pass, &resolved)?;
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
    let invite = matches!(recipient, Recipient::Invite(_));
    if address_book::is_own_fingerprint(&resolved.vk, &resolved.kem_ek) {
        if invite {
            HELD.with(|h| h.borrow_mut().insert((identity, addr)));
            bump();
        }
        return Ok(Added {
            name,
            warnings,
            invite,
            own: true,
        });
    }
    let mut notes = contact_store::v2_notes(&resolved.vk).unwrap_or_default();
    notes.label = label.or(notes.label);
    if matches!(recipient, Recipient::Invite(_)) && !notes.invited.contains(&identity.0) {
        notes.invited.push(identity.0);
    }
    // A contact already in the address book (v1 or v2: the address is the
    // key either way) is kept as it is, under the name it has, now reached
    // through its v2 inbox.
    let existing = address_book::contact_by_vk(&resolved.vk);
    let name = existing
        .as_ref()
        .map_or(name, |c| c.local_alias.to_string());
    let contact = match existing.clone() {
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
    if existing.is_none() {
        address_book::insert_contact(contact.clone())?;
    }
    // Only once it is in the address book: a refused insert leaves no notes
    // that would make it look like a v2 contact.
    contact_store::set_v2_notes(&resolved.vk, notes);
    // Stored before reporting success, so "added" means it is kept.
    contact_store::save(&contact)
        .await
        .map_err(|e| format!("it could not be saved: {e}"))?;
    if invite {
        HELD.with(|h| h.borrow_mut().insert((identity, addr)));
    }
    bump();
    Ok(Added {
        name,
        warnings,
        invite,
        own: false,
    })
}

/// Add a v0.2.x contact by its 44-character id: its key comes from the old
/// inbox's parameters (`transition::resolve_legacy`). A contact already in
/// the address book under that key is kept as it is, its verification
/// included; a new one is unverified. It is reached at the v2 address its
/// key gives, once it has a v2 inbox.
async fn add_legacy(id: [u8; 32], label: Option<&str>, petname: &str) -> Result<Added, String> {
    let legacy = super::transition::resolve_legacy(id).await?;
    let addr = address_of(&legacy.vk);
    let petname = match petname.trim() {
        "" => None,
        p => Some(
            address::normalize_label(p, true)
                .map_err(|e| format!("the name {e}"))?
                .0,
        ),
    };
    let (name, warnings) = address::name_for(&addr.0, petname.as_deref(), label, &petnames());
    if address_book::is_own_fingerprint(&legacy.vk, &legacy.ek) {
        return Err("that is one of your own identities".into());
    }
    let existing = address_book::contact_by_vk(&legacy.vk);
    let name = existing
        .as_ref()
        .map_or(name, |c| c.local_alias.to_string());
    if existing.is_none() {
        let contact = Contact {
            local_alias: name.as_str().into(),
            suggested_alias: None,
            description: String::new(),
            ml_dsa_vk_bytes: legacy.vk.clone(),
            ml_kem_ek_bytes: legacy.ek.clone(),
            required_tier: freenet_mail_wire_v1::aft::Tier::Day1,
            max_age_secs: 0,
            verified: false,
            inbox_wasm_hash: Some(legacy.code_hash.clone()),
        };
        address_book::insert_contact(contact.clone())?;
        contact_store::save(&contact)
            .await
            .map_err(|e| format!("it could not be saved: {e}"))?;
    }
    bump();
    Ok(Added {
        name,
        warnings,
        invite: false,
        own: false,
    })
}

/// "Add to address book" on a v2 message's sender: `identity` adds them as a
/// v2 contact (never a v1 one), so a reply by name goes to their v2 inbox.
/// `name` is the name the row showed; one that is not a valid petname is not
/// used, and the address names them.
pub(crate) async fn add_sender(
    identity: Addr,
    sender_vk: &[u8],
    name: &str,
) -> Result<Added, String> {
    let name = name.trim();
    let petname = if address::normalize_label(name, true).is_ok() {
        name
    } else {
        ""
    };
    let addr = address_of(sender_vk);
    add(identity, &address::display(&addr.0), petname).await
}

/// Whether `pass` is a pass into the inbox `resolved` was read from: its
/// certificate signed by that inbox's issuer key, and its secret key the one
/// the certificate names.
fn invite_is_theirs(pass: &w::Pass, resolved: &Resolved) -> Result<(), String> {
    let refuse = || Err("this invite is not from the inbox it names".to_string());
    let Ok(issuer) = ed25519_dalek::VerifyingKey::from_bytes(&resolved.issuer_vk) else {
        return refuse();
    };
    let sig = ed25519_dalek::Signature::from_bytes(&pass.cert.sig);
    if issuer
        .verify_strict(&w::cert_bytes(&pass.cert), &sig)
        .is_err()
    {
        return refuse();
    }
    let pass_vk = ed25519_dalek::SigningKey::from_bytes(&pass.pass_sk)
        .verifying_key()
        .to_bytes();
    if pass_vk != *pass.cert.pass_vk {
        return refuse();
    }
    Ok(())
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

/// A deleted identity's passes seen: none are held for it any more.
pub(crate) fn forget_identity(identity: &Addr) {
    HELD.with(|h| h.borrow_mut().retain(|(i, _)| i != identity));
    LAPSED.with(|l| l.borrow_mut().retain(|(i, _)| i != identity));
    bump();
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
    parse_ledger(&items)
}

/// The ledger entries in `items`. One that does not decode fails the whole
/// read: a live pass left out would not be revoked by "revoke every live
/// pass", and the page would say it was.
fn parse_ledger(
    items: &[freenet_mail_protocol::Item],
) -> Result<Vec<(PassId, LedgerView)>, String> {
    items
        .iter()
        .map(|i| {
            let id: [u8; 16] = i
                .item
                .id
                .as_slice()
                .try_into()
                .map_err(|_| "a pass ledger entry has a malformed id".to_string())?;
            let entry = from_cbor::<LedgerView>(&i.body)
                .map_err(|e| format!("a pass ledger entry could not be read: {e}"))?;
            Ok((PassId(id), entry))
        })
        .collect()
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

    /// Class A: a ledger entry that does not decode fails the read, so
    /// "revoke every live pass" never reports success while one it could
    /// not read stays live.
    #[test]
    fn an_undecodable_ledger_entry_fails_the_read() {
        let item = |id: Vec<u8>, body: Vec<u8>| freenet_mail_protocol::Item {
            item: freenet_mail_protocol::ItemRef {
                kind: ItemKind::PassLedger,
                owner: Some(Addr([1; 24])),
                id,
            },
            body: body.into(),
            generation: 1,
        };
        let bob = Addr([2; 24]);
        let live = freenet_mail_protocol::to_cbor(&entry(bob.0, false, 20)).unwrap();
        let ok = [item(vec![3; 16], live.clone())];
        assert_eq!(parse_ledger(&ok).unwrap().len(), 1);
        let bad_body = [
            item(vec![3; 16], live.clone()),
            item(vec![4; 16], vec![0xff]),
        ];
        assert!(parse_ledger(&bad_body).is_err());
        let bad_id = [item(vec![3; 16], live.clone()), item(vec![4; 5], live)];
        assert!(parse_ledger(&bad_id).is_err());
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
