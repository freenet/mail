//! The new-contacts queue view (§5.5): mail strangers sent through the
//! queue, drained like all mail but kept out of the inbox until the owner
//! accepts the sender, which sends them a pass (a silent system message
//! carrying it), or drops the message.
//!
//! A message waits here while its sender holds no live pass from this
//! identity and the owner has not accepted it. Accepted messages are recorded
//! in the identity's settings item, so one stays in the inbox after a later
//! revocation; a revoked sender's new mail comes back here.

use std::collections::HashSet;

use freenet_mail_protocol::inbox_v2::KIND_QUARANTINE;
use freenet_mail_protocol::{Addr, ItemKind, ItemRef, SealContent};

use super::contacts::{self, Issued};
use super::owner::{self, Inbound};
use crate::mail_delegate::ops;

const ACCEPTED_FIELD: &str = "v2_accepted";
/// Accepted ids kept: as many as the delegate keeps drained strangers'
/// messages (decision 21), the oldest forgotten first.
const ACCEPTED_MAX: usize = 1024;

fn settings_item(addr: Addr) -> ItemRef {
    ItemRef {
        kind: ItemKind::IdentitySettings,
        owner: Some(addr),
        id: Vec::new(),
    }
}

fn accepted_in(body: Option<&[u8]>) -> Vec<String> {
    body.and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
        .and_then(|v| serde_json::from_value(v.get(ACCEPTED_FIELD)?.clone()).ok())
        .unwrap_or_default()
}

fn hex(id: &[u8; 32]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

async fn accepted(addr: Addr) -> Result<HashSet<String>, String> {
    let item = ops::get_item(settings_item(addr))
        .await
        .map_err(|e| e.to_string())?;
    Ok(accepted_in(item.as_ref().map(|i| i.body.as_slice()))
        .into_iter()
        .collect())
}

async fn note_accepted(addr: Addr, ids: &[[u8; 32]]) -> Result<(), String> {
    ops::put_item_merged(settings_item(addr), |stored| {
        let mut list = accepted_in(stored);
        let before = list.len();
        for id in ids.iter().map(hex) {
            if !list.contains(&id) {
                list.push(id);
            }
        }
        if list.len() == before {
            return None;
        }
        let excess = list.len().saturating_sub(ACCEPTED_MAX);
        list.drain(..excess);
        let mut value = stored
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
            .filter(serde_json::Value::is_object)
            .unwrap_or_else(|| serde_json::json!({}));
        value[ACCEPTED_FIELD] = serde_json::json!(list);
        Some(serde_json::to_vec(&value).expect("JSON encodes"))
    })
    .await
    .map(|_| ())
    .map_err(|e| e.to_string())
}

/// Which of `addr`'s drained `mail` waits in the queue view.
pub(crate) async fn queued(addr: Addr, mail: &[Inbound]) -> Result<HashSet<[u8; 32]>, String> {
    let strangers: Vec<&Inbound> = mail
        .iter()
        .filter(|m| m.admission == KIND_QUARANTINE)
        .collect();
    if strangers.is_empty() {
        return Ok(HashSet::new());
    }
    let accepted = accepted(addr).await?;
    let ledger = contacts::ledger(addr).await?;
    Ok(strangers
        .into_iter()
        .filter(|m| !accepted.contains(&hex(&m.id)))
        .filter(|m| !matches!(contacts::issued_to(&ledger, &m.from), Issued::Live { .. }))
        .map(|m| m.id)
        .collect())
}

/// Accept `m`'s sender: send them a pass, so their mail goes straight to the
/// inbox, keep them as a contact, and move every message of theirs waiting
/// here to the inbox. Returns what to tell the user.
pub(crate) async fn accept(identity: Addr, m: &Inbound) -> Result<String, String> {
    let (name, _) = contacts::sender_name(&m.from, m.body.label.as_deref());
    let outcome = super::send::send_content(identity, m.from, SealContent::PassUpdate).await;
    if !outcome.delivered() {
        return Err(outcome.text(&name));
    }
    let theirs: Vec<[u8; 32]> = owner::inbound(&identity, true)
        .iter()
        .filter(|q| q.from == m.from)
        .map(|q| q.id)
        .chain([m.id])
        .collect();
    note_accepted(identity, &theirs).await?;
    let mut said = format!("Accepted {name}: their mail now goes straight to your inbox.");
    if contacts::by_addr(&m.from).is_none() {
        let address = crate::address::display(&m.from.0);
        let labelled = m.body.label.as_ref().map(|l| format!("{l}@{address}"));
        let added = match labelled {
            Some(input) => match contacts::add(identity, &input, "").await {
                Ok(a) => Ok(a),
                Err(_) => contacts::add(identity, &address, "").await,
            },
            None => contacts::add(identity, &address, "").await,
        };
        if let Err(e) = added {
            said.push_str(&format!(" They could not be added to your contacts: {e}"));
        }
    }
    owner::load_inbound(identity).await;
    Ok(said)
}

/// Drop `m`: the stored copy is deleted (the inbox already tombstoned it),
/// and nothing is sent to its sender.
pub(crate) async fn drop_message(identity: Addr, m: &Inbound) -> Result<(), String> {
    let item = ItemRef {
        kind: ItemKind::Inbound,
        owner: Some(identity),
        id: m.item_id.clone(),
    };
    ops::delete_item(item, m.generation)
        .await
        .map_err(|e| e.to_string())?;
    owner::load_inbound(identity).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_ids_live_beside_other_settings() {
        let body = br#"{"migration":{"inbox_wasm_hash":"x"},"v2_accepted":["ab"]}"#;
        assert_eq!(accepted_in(Some(body)), vec!["ab".to_string()]);
        assert!(accepted_in(None).is_empty());
        assert!(accepted_in(Some(b"not json")).is_empty());
    }
}
