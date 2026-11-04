//! The page's part of the v1 transition (decisions 26 to 28).
//!
//! - **Earlier v1 generations.** While the window is open the page asks the
//!   network for each identity's v1 inbox under every earlier code hash
//!   (`legacy_inbox.toml`), so the node holds any that exist and the
//!   delegate's watch imports their mail. Nothing is written to them.
//! - **Transition passes** (decision 26). Each contact verified in v1 that
//!   this identity wrote to or heard from (every verified contact, when the
//!   page has one identity) is sent this identity's pass through their new
//!   inbox's queue, once their v2 inbox exists. Their drain accepts it,
//!   because the key that signed it is one they verified. Sent once: the
//!   contacts done are listed in the identity's settings item. A contact
//!   with no v2 inbox yet is tried at the next load; any other outcome
//!   (their inbox requires a Ghost Key, their queue is full) is the normal
//!   one, and the contact is done.
//! - **Legacy ids** (44 characters). [`resolve_legacy`] reads the v0.2.x
//!   inbox with its code: the owner's key is in its parameters.
//! - **The close.** [`close_pending`] says whether the window is over and
//!   the delegate has not yet closed the v0.2.x inbox (a message there is not
//!   imported yet).

use freenet_mail_protocol::Addr;
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
    }
    let state: State = serde_json::from_slice(&got.state)
        .map_err(|_| "the old inbox could not be read".to_string())?;
    if state.owner_ek_bytes.is_empty() {
        return Err("the old inbox names no encryption key".into());
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

/// Send `me`'s pass to each contact [`pass_targets`] names and the settings
/// list does not. Returns how many were sent.
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
    let mut sent = 0;
    for to in pass_targets(&me, identities, &contacts) {
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

    #[test]
    fn every_generation_is_listed_current_first() {
        let hashes = v1_code_hashes();
        assert_eq!(hashes.len(), 3);
        assert_eq!(hashes[0], "Av3KF7WSod8E5qkABKWDYenhPkF246rC5aUMcHZ3Frdc");
        assert_eq!(hashes[1], "Ht8rcMjTpnraRNbzkmDCBFJJfmQGJ8M2iUAGaZimE9Ji");
    }

    fn got(vk: &[u8], hash: &str, ek: &[u8]) -> crate::v2::net::WithCode {
        crate::v2::net::WithCode {
            code_hash: hash.to_string(),
            params: serde_json::to_vec(&serde_json::json!({ "pub_key": vk })).unwrap(),
            state: serde_json::to_vec(&serde_json::json!({ "owner_ek_bytes": ek })).unwrap(),
        }
    }

    /// A legacy id resolves to the key in its parameters, only if those
    /// parameters and the code make that id.
    #[test]
    fn a_legacy_id_resolves_to_the_key_that_makes_it() {
        let vk = vec![3u8; 1952];
        let hash = v1_code_hashes()[0].clone();
        let id: [u8; 32] = v1_id(&vk, &hash).unwrap().as_bytes().try_into().unwrap();
        let ok = legacy_from(&id, &got(&vk, &hash, &[4; 1184])).unwrap();
        assert_eq!((ok.vk, ok.ek.len()), (vk.clone(), 1184));
        // Another key's parameters: not this id.
        assert!(legacy_from(&id, &got(&[5; 1952], &hash, &[4; 1184])).is_err());
        // A contract that is not a v0.2.x inbox.
        let other = crate::v2::CODE_HASH.trim();
        assert!(legacy_from(&id, &got(&vk, other, &[4; 1184])).is_err());
        // No encryption key.
        assert!(legacy_from(&id, &got(&vk, &hash, &[])).is_err());
    }
}
