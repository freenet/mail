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

/// The accepted ids an identity settings body holds: none when there is no
/// body or no list. A body or list that does not decode is an error, never
/// "none accepted": a write built on that would replace the settings, or the
/// list, with only the new ids.
#[cfg(test)]
fn accepted_in(body: Option<&[u8]>) -> Result<Vec<String>, String> {
    listed_in(body, ACCEPTED_FIELD)
}

/// The list `field` of an identity settings body, as [`accepted_in`] reads
/// its own.
pub(crate) fn listed_in(body: Option<&[u8]>, field: &str) -> Result<Vec<String>, String> {
    let Some(body) = body else {
        return Ok(Vec::new());
    };
    let unreadable = || "this identity's settings could not be read".to_string();
    let value: serde_json::Value = serde_json::from_slice(body).map_err(|_| unreadable())?;
    if !value.is_object() {
        return Err(unreadable());
    }
    match value.get(field) {
        None => Ok(Vec::new()),
        Some(list) => serde_json::from_value(list.clone()).map_err(|_| match field {
            ACCEPTED_FIELD => "the list of accepted new contacts could not be read".to_string(),
            _ => format!("this identity's list `{field}` could not be read"),
        }),
    }
}

fn hex(id: &[u8; 32]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

async fn accepted(addr: Addr) -> Result<HashSet<String>, String> {
    listed(addr, ACCEPTED_FIELD).await
}

/// The list `field` of `addr`'s settings item.
pub(crate) async fn listed(addr: Addr, field: &str) -> Result<HashSet<String>, String> {
    let item = ops::get_item(settings_item(addr))
        .await
        .map_err(|e| e.to_string())?;
    Ok(listed_in(item.as_ref().map(|i| i.body.as_slice()), field)?
        .into_iter()
        .collect())
}

async fn note_accepted(addr: Addr, ids: &[[u8; 32]]) -> Result<(), String> {
    let ids: Vec<String> = ids.iter().map(hex).collect();
    note_listed(addr, ACCEPTED_FIELD, &ids, ACCEPTED_MAX).await
}

/// Add `entries` to the list `field` of `addr`'s settings item, keeping at
/// most `max`, the oldest forgotten first. A list that cannot be read is
/// left as it is and the call fails.
pub(crate) async fn note_listed(
    addr: Addr,
    field: &str,
    entries: &[String],
    max: usize,
) -> Result<(), String> {
    let mut unreadable = None;
    let written = ops::put_item_merged(settings_item(addr), |stored| {
        let mut list = match listed_in(stored, field) {
            Ok(list) => list,
            Err(e) => {
                unreadable = Some(e);
                return None;
            }
        };
        let before = list.len();
        for id in entries {
            if !list.contains(id) {
                list.push(id.clone());
            }
        }
        if list.len() == before {
            return None;
        }
        let excess = list.len().saturating_sub(max);
        list.drain(..excess);
        let mut value = stored
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
            .filter(serde_json::Value::is_object)
            .unwrap_or_else(|| serde_json::json!({}));
        value[field] = serde_json::json!(list);
        Some(serde_json::to_vec(&value).expect("JSON encodes"))
    })
    .await;
    match (written, unreadable) {
        (_, Some(e)) => Err(e),
        (Ok(_), None) => Ok(()),
        (Err(e), None) => Err(e.to_string()),
    }
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

/// What to flag about saving `m`'s sender as `petname` (M2): a name that is,
/// or can be mistaken for, another contact's, and their own label when it
/// differs. Shown before Accept saves anything.
pub(crate) fn petname_warnings(m: &Inbound, petname: &str) -> Vec<crate::address::LabelWarning> {
    let petname = petname.trim();
    if petname.is_empty() {
        return Vec::new();
    }
    let (_, warnings) = crate::address::name_for(
        &m.from.0,
        Some(petname),
        m.body.label.as_deref(),
        &contacts::petnames(),
    );
    warnings
}

/// Accept `m`'s sender: send them a pass, so their mail goes straight to the
/// inbox, keep them as a contact under `petname`, and move every message of
/// theirs waiting here to the inbox. Returns what to tell the user.
pub(crate) async fn accept(identity: Addr, m: &Inbound, petname: &str) -> Result<String, String> {
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
        // The petname the user gave, never their label unasked (M2): with
        // none, the start of their address. Their label is kept beside it,
        // so a label that differs keeps showing as differing.
        let petname = match petname.trim() {
            "" => address[..8].to_string(),
            p => p.to_string(),
        };
        let labelled = m.body.label.as_ref().map(|l| format!("{l}@{address}"));
        let added = match labelled {
            Some(input) => match contacts::add(identity, &input, &petname).await {
                Ok(a) => Ok(a),
                Err(_) => contacts::add(identity, &address, &petname).await,
            },
            None => contacts::add(identity, &address, &petname).await,
        };
        match added {
            Ok(a) => {
                said = format!(
                    "Accepted {}: their mail now goes straight to your inbox.",
                    a.name
                );
                for w in &a.warnings {
                    said.push_str(&format!(" Note: {} {w}.", a.name));
                }
            }
            Err(e) => said.push_str(&format!(" They could not be added to your contacts: {e}")),
        }
    }
    owner::load_inbound(identity).await;
    Ok(said)
}

/// Drop `m`: deleted like any v2 message, every copy of it (the inbox
/// already tombstoned it), and nothing is sent to its sender.
pub(crate) async fn drop_message(identity: Addr, m: &Inbound) -> Result<(), String> {
    let id = owner::row_id(identity, m);
    owner::delete_row(crate::local_state::addr_key(&identity), id).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Class A: settings that do not decode are not "nothing accepted": a
    /// write built on that would replace them.
    #[test]
    fn accepted_ids_live_beside_other_settings() {
        let body = br#"{"migration":{"inbox_wasm_hash":"x"},"v2_accepted":["ab"]}"#;
        assert_eq!(accepted_in(Some(body)), Ok(vec!["ab".to_string()]));
        assert_eq!(accepted_in(None), Ok(Vec::new()));
        assert_eq!(accepted_in(Some(br#"{"migration":{}}"#)), Ok(Vec::new()));
        assert!(accepted_in(Some(b"not json")).is_err());
        assert!(accepted_in(Some(b"[1]")).is_err());
        assert!(accepted_in(Some(br#"{"v2_accepted":7}"#)).is_err());
    }

    /// Class A: accepting over settings that do not decode refuses, and the
    /// stored settings are left as they were.
    #[cfg(all(feature = "local-delegate", not(feature = "use-node")))]
    #[test]
    fn accepting_over_unreadable_settings_changes_nothing() {
        use futures::executor::block_on;
        let (info, _) =
            block_on(ops::create_identity("v2-accept-bad".into(), String::new())).unwrap();
        let item = settings_item(info.addr);
        block_on(ops::put_item(item.clone(), b"not json".to_vec(), None)).unwrap();
        assert!(block_on(note_accepted(info.addr, &[[7; 32]])).is_err());
        let stored = block_on(ops::get_item(item)).unwrap().unwrap();
        assert_eq!(stored.body.as_slice(), b"not json");
    }
}
