//! The page's part of the v1 transition (decisions 26 to 28).
//!
//! - **Earlier v1 generations.** While the window is open the page asks the
//!   network for each identity's v1 inbox under every earlier code hash
//!   (`legacy_inbox.toml`), so the node holds any that exist and the
//!   delegate's watch imports their mail. Nothing is written to them.
//! - **Transition passes** (decision 26). Each contact verified in v1 that
//!   this identity wrote to or heard from (every verified contact, when the
//!   page has one identity) is sent this identity's pass through their new
//!   inbox's queue, once their v2 inbox exists. Those contacts are recorded
//!   in the identity's settings item (`V1_CONTACTS_FIELD`), and its own
//!   drain accepts through the queue only a verified contact on that list,
//!   during its window, so the page and the drain use one list. Their drain
//!   accepts the pass the same way. Sent once: the
//!   contacts done are listed in the identity's settings item. A contact
//!   with no v2 inbox yet is tried at the next load; any other outcome
//!   (their inbox requires a Ghost Key, their queue is full) is the normal
//!   one, and the contact is done.
//! - **Legacy ids** (44 characters). [`resolve_legacy`] reads the v0.2.x
//!   inbox with its code: the owner's key is in its parameters, and its
//!   encryption key counts only under the owner's signature.
//! - **The close.** [`close_pending`] says whether the window is over and
//!   the delegate has not yet closed the v0.2.x inbox (a message there is not
//!   imported yet).

use freenet_mail_protocol::{Addr, V1_CONTACTS_FIELD};
use freenet_mail_protocol::address::address_of;
use freenet_stdlib::prelude::{ContractInstanceId, ContractKey, Parameters};

use super::InboxRecordView;

/// How long the v0.2.x inbox stays open after the v2 inbox is made: the
/// delegate's `transition::WINDOW` (pinned by a test).
pub(crate) const WINDOW_SECS: u64 = 90 * 86_400;
/// Contacts sent this identity's pass, in its settings item.
pub(crate) const SENT_FIELD: &str = "v2_transition";
/// As many as there can be contacts.
const SENT_MAX: usize = 2048;

/// Whether the window of the inbox `rec` describes is over at `now`.
pub(crate) fn ended(rec: &InboxRecordView, now: u64) -> bool {
    rec.v1_window
        .as_ref()
        .is_some_and(|w| now >= w.start.saturating_add(WINDOW_SECS))
}

/// The window is over and the v0.2.x inbox is not closed yet.
pub(crate) fn close_pending(rec: &InboxRecordView, now: u64) -> bool {
    ended(rec, now)
        && !rec
            .v1_window
            .as_ref()
            .is_some_and(|w| !w.closes.is_empty() && w.closes.values().all(|c| c.done))
}

/// The id of `vk`'s v0.2.x inbox under `code_hash` (base58).
pub(crate) fn v1_id(vk: &[u8], code_hash: &str) -> Option<ContractInstanceId> {
    let params: Parameters = freenet_mail_wire_v1::inbox::InboxParams {
        pub_key: vk.to_vec(),
    }
    .try_into()
    .ok()?;
    Some(*ContractKey::from_params(code_hash, params).ok()?.id())
}

/// Every v0.2.x inbox code hash, base58: the current one first.
pub(crate) fn v1_code_hashes() -> Vec<String> {
    let current = include_str!("../../../published-contract/wasm/v1/inbox_code_hash")
        .trim()
        .to_string();
    std::iter::once(current)
        .chain(
            crate::legacy_registry::LEGACY_INBOX_CODE_HASHES
                .iter()
                .map(|h| bs58::encode(h).into_string()),
        )
        .collect()
}

/// A v0.2.x contact read from its inbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Legacy {
    pub vk: Vec<u8>,
    pub ek: Vec<u8>,
    pub code_hash: String,
}

/// Check what a GET of the legacy id `id` returned: the code is a v0.2.x
/// inbox, the parameters with it make exactly `id`, and they name the key.
pub(crate) fn legacy_from(id: &[u8; 32], got: &super::net::WithCode) -> Result<Legacy, String> {
    if !v1_code_hashes().contains(&got.code_hash) {
        return Err("that id is not an old Freenet Mail address".into());
    }
    let params: freenet_mail_wire_v1::inbox::InboxParams = serde_json::from_slice(&got.params)
        .map_err(|_| "that old address names no key".to_string())?;
    if v1_id(&params.pub_key, &got.code_hash).map(|i| i.as_bytes().to_vec()) != Some(id.to_vec()) {
        return Err("the node returned another contract than the one asked for".into());
    }
    #[derive(serde::Deserialize)]
    struct State {
        #[serde(default)]
        owner_ek_bytes: Vec<u8>,
        settings: freenet_mail_wire_v1::inbox::InboxSettings,
        last_update: chrono::DateTime<chrono::Utc>,
        #[serde(default)]
        inbox_signature: Vec<u8>,
    }
    let state: State = serde_json::from_slice(&got.state)
        .map_err(|_| "the old inbox could not be read".to_string())?;
    if state.owner_ek_bytes.is_empty() {
        return Err("the old inbox names no encryption key".into());
    }
    // The key is in the state, which any node can answer: it is the owner's
    // only under the owner's signature, which binds it (as the v1 contract
    // checks).
    let signed = freenet_mail_wire_v1::inbox::sign_payload(
        &state.owner_ek_bytes,
        &state.settings,
        state.last_update,
    );
    if !crate::inbox::verify_message_signature(&signed, &params.pub_key, &state.inbox_signature)
    {
        return Err("the old inbox's encryption key is not signed by its owner".into());
    }
    Ok(Legacy {
        vk: params.pub_key,
        ek: state.owner_ek_bytes,
        code_hash: got.code_hash.clone(),
    })
}

/// Read the v0.2.x inbox `id` and the contact it belongs to.
#[cfg(feature = "use-node")]
pub(crate) async fn resolve_legacy(id: [u8; 32]) -> Result<Legacy, String> {
    match super::net::get_with_code(ContractInstanceId::new(id)).await? {
        Some(got) => legacy_from(&id, &got),
        None => Err("there is no inbox at that old address".into()),
    }
}

#[cfg(not(feature = "use-node"))]
pub(crate) async fn resolve_legacy(_id: [u8; 32]) -> Result<Legacy, String> {
    Err("an old address can be looked up only with a node".into())
}

fn hex(addr: &Addr) -> String {
    addr.0.iter().map(|b| format!("{b:02x}")).collect()
}

/// The contacts `me` sends a transition pass to: verified, not one of the
/// page's identities, and, when the page has more than one identity, ones
/// `me` wrote to or heard from in v1 (so a contact does not learn which
/// identities are one person's).
pub(crate) fn pass_targets(
    me: &Addr,
    identities: usize,
    contacts: &[crate::app::address_book::Contact],
) -> Vec<Addr> {
    let key = crate::local_state::addr_key(me);
    let kept = crate::local_state::kept_for(&key);
    let sent = crate::local_state::sent_for(&key);
    contacts
        .iter()
        .filter(|c| c.verified)
        .filter(|c| {
            !crate::app::address_book::is_own_fingerprint(&c.ml_dsa_vk_bytes, &c.ml_kem_ek_bytes)
        })
        .filter(|c| {
            identities <= 1
                || kept.iter().any(|(_, k)| k.sender_vk == c.ml_dsa_vk_bytes)
                || sent
                    .iter()
                    .any(|(_, s)| s.recipient_fingerprint_full == c.fingerprint_full())
        })
        .map(|c| address_of(&c.ml_dsa_vk_bytes))
        .collect()
}

/// Record the contacts [`pass_targets`] names in `me`'s settings item
/// ([`V1_CONTACTS_FIELD`]), adding to what is there, and return the whole
/// list. It is the one list both sides use: the page sends its pass to the
/// contacts on it, and `me`'s drain accepts only those through the queue
/// (`mail_delegate::transition::may_accept`).
pub(crate) async fn note_v1_contacts(
    me: Addr,
    identities: usize,
    contacts: &[crate::app::address_book::Contact],
) -> Result<std::collections::HashSet<String>, String> {
    let entries: Vec<String> = pass_targets(&me, identities, contacts)
        .iter()
        .map(hex)
        .collect();
    super::queue::note_listed(me, V1_CONTACTS_FIELD, &entries, SENT_MAX).await?;
    super::queue::listed(me, V1_CONTACTS_FIELD).await
}

/// The contacts on `listed` that are still verified and not one of the
/// page's identities.
fn pass_to(
    contacts: &[crate::app::address_book::Contact],
    listed: &std::collections::HashSet<String>,
) -> Vec<Addr> {
    contacts
        .iter()
        .filter(|c| c.verified)
        .filter(|c| {
            !crate::app::address_book::is_own_fingerprint(&c.ml_dsa_vk_bytes, &c.ml_kem_ek_bytes)
        })
        .map(|c| address_of(&c.ml_dsa_vk_bytes))
        .filter(|a| listed.contains(&hex(a)))
        .collect()
}

/// Send `me`'s pass to each contact on its list ([`note_v1_contacts`]) that
/// the sent list does not name. Returns how many were sent.
pub(crate) async fn send_passes(me: Addr, identities: usize) -> usize {
    use super::send::{NotDelivered, Outcome};
    let done = match super::queue::listed(me, SENT_FIELD).await {
        Ok(d) => d,
        Err(e) => {
            crate::log::error(format!("transition passes: {e}"), None);
            return 0;
        }
    };
    // From the delegate, not the address book: this runs beside the page's
    // own contact load, which may not have landed yet.
    let items = match crate::mail_delegate::ops::list_all_items(
        freenet_mail_protocol::ItemKind::Contact,
        None,
    )
    .await
    {
        Ok(items) => items,
        Err(e) => {
            crate::log::error(format!("transition passes: {e}"), None);
            return 0;
        }
    };
    let contacts: Vec<_> = items
        .iter()
        .filter_map(|i| crate::app::contact_store::decode(&i.item, &i.body))
        .collect();
    crate::log::info(format!(
        "transition passes: {} contacts, {} done",
        contacts.len(),
        done.len()
    ));
    let listed = match note_v1_contacts(me, identities, &contacts).await {
        Ok(l) => l,
        Err(e) => {
            crate::log::error(format!("transition passes: {e}"), None);
            return 0;
        }
    };
    let mut sent = 0;
    for to in pass_to(&contacts, &listed) {
        if done.contains(&hex(&to)) {
            continue;
        }
        let outcome =
            super::send::send_content(me, to, freenet_mail_protocol::SealContent::PassUpdate).await;
        match &outcome {
            // No v2 inbox yet, or no answer: the next load tries again.
            Outcome::NotDelivered(NotDelivered::Unreachable(why)) => {
                crate::log::info(format!("transition pass waits: {why}"));
                continue;
            }
            Outcome::Delivered { .. } => {
                crate::log::info("transition pass delivered");
                sent += 1;
            }
            Outcome::NotDelivered(why) => {
                crate::log::info(format!("transition pass not delivered: {why:?}"));
            }
        }
        if let Err(e) = super::queue::note_listed(me, SENT_FIELD, &[hex(&to)], SENT_MAX).await {
            crate::log::error(format!("transition passes: {e}"), None);
        }
    }
    sent
}

/// Once per page load: for each identity whose window is open, ask the
/// network for its earlier v1 inboxes and send its transition passes.
#[cfg(feature = "use-node")]
pub(crate) async fn on_load() {
    let Ok(identities) = crate::mail_delegate::ops::list_identities().await else {
        return;
    };
    let now = u64::try_from(chrono::Utc::now().timestamp()).unwrap_or(0);
    let test_end = test_end_requested();
    for me in &identities {
        if test_end {
            let op = freenet_mail_protocol::Op::EndV1WindowForTest { addr: me.addr };
            if let Err(e) = crate::mail_delegate::call(op).await {
                crate::log::error(format!("end window for test: {e}"), None);
            }
        }
        let rec = super::owner::record(me.addr).await.ok().flatten();
        crate::log::info(format!(
            "transition: v2 inbox record {}, window ended {}",
            rec.is_some(),
            rec.as_ref().is_some_and(|r| ended(r, now))
        ));
        if rec.as_ref().is_some_and(|r| ended(r, now)) {
            continue;
        }
        for hash in v1_code_hashes().iter().skip(1) {
            if let Some(id) = v1_id(&me.vk, hash) {
                // Only so the node holds it: the watch reads it from there.
                let _ = super::net::get_id(id).await;
            }
        }
        if rec.is_some() {
            send_passes(me.addr, identities.len()).await;
        }
    }
    // The close runs in the jobs: one now, so a test sees it this load.
    if test_end {
        let _ = crate::jobs::run_once().await;
    }
}

/// Real-node tests only: the page was opened with `e2e_end_v1_window` in its
/// address, which asks a delegate built for tests to end each window now.
/// A release delegate refuses (`Op::EndV1WindowForTest`).
#[cfg(all(feature = "use-node", target_family = "wasm"))]
fn test_end_requested() -> bool {
    web_sys::window()
        .and_then(|w| w.location().search().ok())
        .is_some_and(|s| {
            s.trim_start_matches('?')
                .split('&')
                .any(|p| p == "e2e_end_v1_window")
        })
}

#[cfg(all(feature = "use-node", not(target_family = "wasm")))]
fn test_end_requested() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2::{V1ClosingView, V1WindowView};

    fn rec(start: u64, closes: &[bool]) -> InboxRecordView {
        InboxRecordView {
            v1_window: Some(V1WindowView {
                start,
                closes: closes
                    .iter()
                    .enumerate()
                    .map(|(i, done)| {
                        (
                            serde_bytes::ByteBuf::from(vec![i as u8; 32]),
                            V1ClosingView { done: *done },
                        )
                    })
                    .collect(),
            }),
            ..InboxRecordView::default()
        }
    }

    #[test]
    fn the_close_is_pending_from_the_end_until_every_inbox_is_closed() {
        let start = 1_000;
        let end = start + WINDOW_SECS;
        assert!(!close_pending(&rec(start, &[]), end - 1));
        assert!(close_pending(&rec(start, &[]), end));
        assert!(close_pending(&rec(start, &[false]), end));
        assert!(close_pending(&rec(start, &[true, false]), end));
        assert!(!close_pending(&rec(start, &[true]), end));
        assert!(!close_pending(&InboxRecordView::default(), end));
    }

    #[cfg(feature = "local-delegate")]
    #[test]
    fn the_window_is_the_delegates() {
        assert_eq!(WINDOW_SECS, mail_delegate::transition::WINDOW);
    }

    /// One identity: every verified contact. Several: only the ones it
    /// wrote to or heard from, so a contact is never told which identities
    /// are one person's. An unverified contact never.
    #[test]
    fn passes_go_to_verified_contacts_of_this_identity_only() {
        let me = Addr([0xA1; 24]);
        let mut verified = crate::app::address_book::contact_for_test("ver", 0x31);
        verified.verified = true;
        let unverified = crate::app::address_book::contact_for_test("unver", 0x32);
        let contacts = vec![verified.clone(), unverified];
        assert_eq!(
            pass_targets(&me, 1, &contacts),
            vec![address_of(&verified.ml_dsa_vk_bytes)]
        );
        assert!(pass_targets(&me, 2, &contacts).is_empty());
    }

    /// Decision 26, two identities on one page: the list each writes is
    /// the one its drain reads (`v1_contact_listed`, the drain's own
    /// reader), and the one the page sends passes from. Carol wrote to the
    /// first identity only, so only the first lists her; Dave, verified but
    /// written to by neither, is on no list.
    #[cfg(all(feature = "local-delegate", not(feature = "use-node")))]
    #[test]
    fn the_page_and_the_drain_use_one_list() {
        use crate::mail_delegate::ops;
        use futures::executor::block_on;
        use mail_delegate::transition::v1_contact_listed;
        let (a, _) = block_on(ops::create_identity("v1t-one".into(), String::new())).unwrap();
        let (b, _) = block_on(ops::create_identity("v1t-two".into(), String::new())).unwrap();
        let mut carol = crate::app::address_book::contact_for_test("carol", 0x41);
        carol.verified = true;
        let mut dave = crate::app::address_book::contact_for_test("dave", 0x42);
        dave.verified = true;
        let kept = freenet_mail_wire_v1::local_state::KeptMessage {
            sender_vk: carol.ml_dsa_vk_bytes.clone(),
            ..Default::default()
        };
        crate::local_state::local_mark_read(&crate::local_state::addr_key(&a.addr), 1, kept);
        let contacts = vec![carol.clone(), dave.clone()];
        let on_a = block_on(note_v1_contacts(a.addr, 2, &contacts)).unwrap();
        let on_b = block_on(note_v1_contacts(b.addr, 2, &contacts)).unwrap();
        let body = |addr: Addr| {
            let item = freenet_mail_protocol::ItemRef {
                kind: freenet_mail_protocol::ItemKind::IdentitySettings,
                owner: Some(addr),
                id: Vec::new(),
            };
            block_on(ops::get_item(item))
                .unwrap()
                .map(|i| i.body.to_vec())
                .unwrap_or_default()
        };
        let (c, d) = (
            address_of(&carol.ml_dsa_vk_bytes),
            address_of(&dave.ml_dsa_vk_bytes),
        );
        assert!(v1_contact_listed(&body(a.addr), &c));
        assert!(!v1_contact_listed(&body(a.addr), &d));
        assert!(!v1_contact_listed(&body(b.addr), &c));
        assert!(!v1_contact_listed(&body(b.addr), &d));
        assert_eq!(pass_to(&contacts, &on_a), vec![c]);
        assert!(pass_to(&contacts, &on_b).is_empty());
    }

    #[test]
    fn every_generation_is_listed_current_first() {
        let hashes = v1_code_hashes();
        assert_eq!(hashes.len(), 3);
        assert_eq!(hashes[0], "Av3KF7WSod8E5qkABKWDYenhPkF246rC5aUMcHZ3Frdc");
        assert_eq!(hashes[1], "Ht8rcMjTpnraRNbzkmDCBFJJfmQGJ8M2iUAGaZimE9Ji");
    }

    /// A v0.2.x inbox state: `ek` signed by `signer`, as the inbox's owner
    /// signs it.
    fn signed_state(signer: &ml_dsa::SigningKey<ml_dsa::MlDsa65>, ek: &[u8]) -> Vec<u8> {
        use freenet_mail_wire_v1::inbox::{Inbox, InboxSettings};
        let settings = InboxSettings::default();
        let last_update = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let sig = Inbox::sign(signer, ek, &settings, last_update);
        serde_json::to_vec(&serde_json::json!({
            "messages": [],
            "last_update": last_update,
            "settings": settings,
            "owner_ek_bytes": ek,
            "inbox_signature": sig.to_vec(),
        }))
        .unwrap()
    }

    fn got(vk: &[u8], hash: &str, state: Vec<u8>) -> crate::v2::net::WithCode {
        crate::v2::net::WithCode {
            code_hash: hash.to_string(),
            params: serde_json::to_vec(&serde_json::json!({ "pub_key": vk })).unwrap(),
            state,
        }
    }

    fn key(seed: u8) -> (ml_dsa::SigningKey<ml_dsa::MlDsa65>, Vec<u8>) {
        use ml_dsa::signature::Keypair;
        let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&[seed; 32].into());
        let vk = sk.verifying_key().encode().to_vec();
        (sk, vk)
    }

    /// A legacy id resolves to the key in its parameters, only if those
    /// parameters and the code make that id.
    #[test]
    fn a_legacy_id_resolves_to_the_key_that_makes_it() {
        let (sk, vk) = key(3);
        let hash = v1_code_hashes()[0].clone();
        let id: [u8; 32] = v1_id(&vk, &hash).unwrap().as_bytes().try_into().unwrap();
        let ok = legacy_from(&id, &got(&vk, &hash, signed_state(&sk, &[4; 1184]))).unwrap();
        assert_eq!((ok.vk, ok.ek), (vk.clone(), vec![4; 1184]));
        // Another key's parameters: not this id.
        let (other_sk, other_vk) = key(5);
        let other = got(&other_vk, &hash, signed_state(&other_sk, &[4; 1184]));
        assert!(legacy_from(&id, &other).is_err());
        // A contract that is not a v0.2.x inbox.
        let code = crate::v2::CODE_HASH.trim();
        assert!(legacy_from(&id, &got(&vk, code, signed_state(&sk, &[4; 1184]))).is_err());
        // No encryption key.
        assert!(legacy_from(&id, &got(&vk, &hash, signed_state(&sk, &[]))).is_err());
    }

    /// The encryption key is the owner's only if the owner signed it: a
    /// node that answers with its own key in a genuine inbox's state, or
    /// with a state another key signed, is refused.
    #[test]
    fn a_legacy_inbox_whose_key_the_owner_did_not_sign_is_refused() {
        let (sk, vk) = key(3);
        let hash = v1_code_hashes()[0].clone();
        let id: [u8; 32] = v1_id(&vk, &hash).unwrap().as_bytes().try_into().unwrap();
        let mut forged: serde_json::Value =
            serde_json::from_slice(&signed_state(&sk, &[4; 1184])).unwrap();
        forged["owner_ek_bytes"] = serde_json::json!(vec![6u8; 1184]);
        let forged = serde_json::to_vec(&forged).unwrap();
        assert!(legacy_from(&id, &got(&vk, &hash, forged)).is_err());
        let (mallory, _) = key(7);
        let theirs = signed_state(&mallory, &[6; 1184]);
        assert!(legacy_from(&id, &got(&vk, &hash, theirs)).is_err());
    }
}
