//! Orphans: items of a v0.2.x alias no identity could be found for. They stay
//! here until the user says which identity they belong to. Moving never
//! overwrites: an item already under that id stays and the orphan with it. A
//! move is recorded, so scrub can tell it from an orphan that never landed.

use std::collections::BTreeMap;

use freenet_mail_protocol::{Addr, FailureCode, Item, ItemKind, ItemRef, Op, Reply};

use super::ledger::{list_items, update_ledger};
use super::legacy_delegates::{OrphanItem, hex, id16, text_id};
use super::successor::{MailStore, get_item, merge_fields, merged_put, put_item, settings_item};
use crate::mail_delegate::CallError;

/// One old alias's orphans, for the list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OrphanGroup {
    pub alias: String,
    /// `(kind, how many)`, e.g. `("archived", 2)`.
    pub kinds: BTreeMap<String, u32>,
}

pub(crate) async fn stored<S: MailStore>(store: &mut S) -> Result<Vec<Item>, CallError> {
    list_items(store, ItemKind::LegacyOrphan, None).await
}

fn decoded(item: &Item) -> Option<OrphanItem> {
    serde_json::from_slice(&item.body).ok()
}

/// Orphans by old alias. One that cannot be read is listed under its own
/// empty alias, so it is still counted.
pub(crate) fn groups(items: &[Item]) -> Vec<OrphanGroup> {
    let mut by_alias: BTreeMap<String, BTreeMap<String, u32>> = BTreeMap::new();
    for item in items {
        let (alias, what) = decoded(item).map_or_else(Default::default, |o| (o.alias, o.what));
        *by_alias.entry(alias).or_default().entry(what).or_default() += 1;
    }
    by_alias
        .into_iter()
        .map(|(alias, kinds)| OrphanGroup { alias, kinds })
        .collect()
}

/// Where a message orphan goes, by the same ids its pair would have had.
fn destination(orphan: &OrphanItem, owner: Addr) -> Option<ItemRef> {
    let body = orphan.body.as_bytes();
    let (kind, id) = match orphan.what.as_str() {
        "draft" => (ItemKind::Draft, text_id(&orphan.legacy_id)),
        "sent" => (ItemKind::Sent, text_id(&orphan.legacy_id)),
        "kept" => (ItemKind::Kept, id16(&[body])),
        "archived" => (ItemKind::Archived, id16(&[body])),
        _ => return None,
    };
    Some(ItemRef {
        kind,
        owner: Some(owner),
        id: id.to_vec(),
    })
}

/// Create `item` unless the same bytes are already there, which is a move
/// interrupted after its write.
async fn create<S: MailStore>(store: &mut S, item: ItemRef, body: Vec<u8>) -> Result<(), String> {
    let conflict = match put_item(store, item.clone(), body.clone(), None).await {
        Ok(_) => return Ok(()),
        Err(e) if matches!(e.code(), Some(FailureCode::Conflict { .. })) => e,
        Err(e) => return Err(e.to_string()),
    };
    match get_item(store, item).await.map_err(|e| e.to_string())? {
        Some(stored) if stored.body.as_slice() == body.as_slice() => Ok(()),
        Some(_) => Err("that identity already holds a different item with this id".to_string()),
        None => Err(format!("not stored after {conflict}")),
    }
}

/// Move one orphan to `owner`: the item, then the record of the move, then
/// the orphan, so an interruption leaves two copies and never none.
pub(crate) async fn move_one<S: MailStore>(
    store: &mut S,
    orphan: &Item,
    owner: Addr,
) -> Result<(), String> {
    let decoded = decoded(orphan).ok_or("this item cannot be read")?;
    if decoded.what == "settings" {
        let incoming: serde_json::Value =
            serde_json::from_str(&decoded.body).map_err(|e| e.to_string())?;
        merged_put(store, settings_item(owner), |stored| {
            let present = stored
                .and_then(|b| serde_json::from_slice(b).ok())
                .unwrap_or_else(|| serde_json::json!({}));
            let merged = merge_fields(&present, &incoming);
            (merged != present).then(|| serde_json::to_vec(&merged).expect("JSON always encodes"))
        })
        .await
        .map_err(|e| e.to_string())?;
    } else {
        let item = destination(&decoded, owner).ok_or("an item of an unknown kind")?;
        create(store, item, decoded.body.into_bytes()).await?;
    }
    let id = hex(&orphan.item.id);
    update_ledger(store, |l| {
        if !l.moved.contains(&id) {
            l.moved.push(id.clone());
        }
    })
    .await
    .map_err(|e| e.to_string())?;
    let op = Op::DeleteItem {
        item: orphan.item.clone(),
        expected_gen: orphan.generation,
    };
    match store.call(op).await.map_err(|e| e.to_string())? {
        Reply::Deleted | Reply::Ack { .. } => Ok(()),
        other => Err(crate::mail_delegate::unexpected(&other).to_string()),
    }
}

/// How moving an alias's orphans went.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct MoveResult {
    pub moved: u32,
    /// How many stayed where they are.
    pub stayed: u32,
    /// Why the last of them did.
    pub failure: Option<String>,
}

/// Move every orphan of `alias` to `owner`. One that cannot move stays, and
/// the rest still go: ids are hashes, so which one blocks is arbitrary, and
/// it would block the same ones on every try. One that cannot be read is
/// listed under the empty alias ([`groups`]) and stays there.
pub(crate) async fn move_alias<S: MailStore>(
    store: &mut S,
    alias: &str,
    owner: Addr,
) -> MoveResult {
    let items = match stored(store).await {
        Ok(items) => items,
        Err(e) => {
            return MoveResult {
                failure: Some(e.to_string()),
                ..Default::default()
            };
        }
    };
    let mut result = MoveResult::default();
    for orphan in &items {
        if decoded(orphan).map_or(alias.is_empty(), |o| o.alias == alias) {
            match move_one(store, orphan, owner).await {
                Ok(()) => result.moved += 1,
                Err(e) => {
                    result.stayed += 1;
                    result.failure = Some(e);
                }
            }
        }
    }
    result
}
