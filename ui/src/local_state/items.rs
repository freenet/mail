//! Local mail state in the mail delegate: one item per draft, sent message,
//! kept or archived message, per-message flags, and settings record.
//!
//! The in-memory [`LocalState`](super::SNAPSHOT) stays the view the UI
//! reads; [`load`] fills it once per page load and every write below
//! returns only when the delegate has acknowledged it (or failed, or never
//! answered: [`CallError::Unknown`]), so a caller can tell the user when a
//! change is safe across a reload (#286).
//!
//! Ids:
//! - drafts and sent messages: the 16 bytes of their UUID;
//! - received messages (kept, archived, flags): `blake3(ciphertext)[..16]`,
//!   stable across reloads and across the inbox's own ordering. The UI's
//!   [`MessageId`] is the first 8 of those bytes (little-endian) with the top
//!   bit cleared (see [`super::RECEIVED_ID_LIMIT`]); the full 16 are
//!   remembered per page for writes ([`message_id_for`]). Two messages of one
//!   identity share a UI id with probability about n²/2^64 for n messages.
//!   A UI id is never ordered on: it carries no time and no position.

use std::cell::RefCell;
use std::collections::HashMap;

use freenet_mail_protocol::{Addr, ItemKind, ItemRef};
use freenet_mail_wire_v1::local_state::{
    ArchivedMessage, DeliveryState, Draft, GlobalSettings, IdentitySettings, KeptMessage,
    LocalState, MessageId, SentMessage,
};
use freenet_stdlib::prelude::blake3;
use serde::{Deserialize, Serialize};

use crate::DynError;
use crate::mail_delegate::{CallError, ops};

thread_local! {
    /// The full 16-byte item id of every message id handed out this page.
    static FULL_IDS: RefCell<HashMap<MessageId, [u8; 16]>> = RefCell::new(HashMap::new());
}

fn remember(full: [u8; 16]) -> MessageId {
    let id =
        u64::from_le_bytes(full[..8].try_into().expect("8 bytes")) & (super::RECEIVED_ID_LIMIT - 1);
    FULL_IDS.with(|ids| ids.borrow_mut().insert(id, full));
    id
}

/// The id of a received message, from its ciphertext.
pub(crate) fn message_id_for(ciphertext: &[u8]) -> MessageId {
    let mut full = [0u8; 16];
    full.copy_from_slice(&blake3::hash(ciphertext).as_bytes()[..16]);
    remember(full)
}

fn full_id(id: MessageId) -> Result<[u8; 16], DynError> {
    FULL_IDS
        .with(|ids| ids.borrow().get(&id).copied())
        .ok_or_else(|| format!("message {id} is not loaded").into())
}

fn owner(alias: &str) -> Result<Addr, DynError> {
    crate::inbox::InboxModel::id_for_alias(alias)
        .map(|identity| identity.addr)
        .ok_or_else(|| format!("no identity `{alias}`").into())
}

fn uuid_id(id: &str) -> Result<Vec<u8>, DynError> {
    Ok(uuid::Uuid::parse_str(id)?.as_bytes().to_vec())
}

fn item(kind: ItemKind, owner: Option<Addr>, id: Vec<u8>) -> ItemRef {
    ItemRef { kind, owner, id }
}

fn message_item(kind: ItemKind, alias: &str, id: MessageId) -> Result<ItemRef, DynError> {
    Ok(item(kind, Some(owner(alias)?), full_id(id)?.to_vec()))
}

/// Read and deleted marks for one received message.
#[derive(Default, Serialize, Deserialize)]
struct Flags {
    read: bool,
    deleted: bool,
}

fn json<T: Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).expect("local state always encodes")
}

/// Replace an item's body whatever it holds.
async fn put(item: ItemRef, body: Vec<u8>) -> Result<(), CallError> {
    ops::put_item_merged(item, |_| Some(body.clone()))
        .await
        .map(|_| ())
}

/// Change one message's flags.
async fn set_flags(item: ItemRef, change: impl Fn(&mut Flags)) -> Result<(), CallError> {
    ops::put_item_merged(item, |stored| {
        let mut flags: Flags = stored
            .and_then(|b| serde_json::from_slice(b).ok())
            .unwrap_or_default();
        change(&mut flags);
        Some(json(&flags))
    })
    .await
    .map(|_| ())
}

/// Delete an item if it exists, retrying a lost compare-and-swap.
async fn delete(item: ItemRef) -> Result<(), CallError> {
    let mut attempt = 0;
    loop {
        let Some(current) = ops::get_item(item.clone()).await? else {
            return Ok(());
        };
        match ops::delete_item(item.clone(), current.generation).await {
            Err(e)
                if matches!(
                    e.code(),
                    Some(freenet_mail_protocol::FailureCode::Conflict { .. })
                ) && attempt < ops::MERGE_RETRIES =>
            {
                attempt += 1;
                ops::pause_ms(50 * 2u32.pow(attempt)).await;
            }
            other => return other,
        }
    }
}

fn boxed(e: CallError) -> DynError {
    e.into()
}

// ── Writes ────────────────────────────────────────────────────────────────

pub(crate) async fn save_draft(alias: String, id: String, draft: Draft) -> Result<(), DynError> {
    let item = item(ItemKind::Draft, Some(owner(&alias)?), uuid_id(&id)?);
    put(item, json(&draft)).await.map_err(boxed)
}

pub(crate) async fn delete_draft(alias: String, id: String) -> Result<(), DynError> {
    let item = item(ItemKind::Draft, Some(owner(&alias)?), uuid_id(&id)?);
    delete(item).await.map_err(boxed)
}

thread_local! {
    /// Delivery states that arrived before their Sent item was stored;
    /// `save_sent` writes the latest one with the item.
    static EARLY_DELIVERY: RefCell<HashMap<(String, String), DeliveryState>> =
        RefCell::new(HashMap::new());
}

/// The state to store with a Sent item: a delivery state that arrived
/// while it was being saved wins over the one it was saved with, unless
/// that one is already terminal.
fn sent_with_early_delivery(alias: &str, id: &str, mut sent: SentMessage) -> SentMessage {
    let early =
        EARLY_DELIVERY.with(|e| e.borrow_mut().remove(&(alias.to_string(), id.to_string())));
    if let Some(state) = early
        && !super::delivery_state_is_terminal(sent.delivery_state)
    {
        sent.delivery_state = state;
    }
    sent
}

pub(crate) async fn save_sent(
    alias: String,
    id: String,
    sent: SentMessage,
) -> Result<(), DynError> {
    let item = item(ItemKind::Sent, Some(owner(&alias)?), uuid_id(&id)?);
    let sent = sent_with_early_delivery(&alias, &id, sent);
    put(item, json(&sent)).await.map_err(boxed)?;
    // A state that arrived while that write was in flight found no item
    // yet; apply it now that the item is stored.
    let late = EARLY_DELIVERY.with(|e| e.borrow_mut().remove(&(alias.clone(), id.clone())));
    match late {
        Some(state) => Box::pin(set_sent_delivery_state(alias, id, state)).await,
        None => Ok(()),
    }
}

pub(crate) async fn delete_sent(alias: String, id: String) -> Result<(), DynError> {
    let item = item(ItemKind::Sent, Some(owner(&alias)?), uuid_id(&id)?);
    delete(item).await.map_err(boxed)
}

/// Move a sent message's delivery state on, unless it is already terminal
/// (`super::delivery_state_is_terminal`, #288).
pub(crate) async fn set_sent_delivery_state(
    alias: String,
    id: String,
    state: DeliveryState,
) -> Result<(), DynError> {
    let item = item(ItemKind::Sent, Some(owner(&alias)?), uuid_id(&id)?);
    let key = (alias.clone(), id.clone());
    ops::put_item_merged(item, |stored| {
        let Some(stored) = stored else {
            // The Sent item is not stored yet (`save_sent` still running):
            // hand the state to it rather than dropping it.
            EARLY_DELIVERY.with(|e| e.borrow_mut().insert(key.clone(), state));
            return None;
        };
        let mut sent: SentMessage = serde_json::from_slice(stored).ok()?;
        if super::delivery_state_is_terminal(sent.delivery_state) {
            return None;
        }
        sent.delivery_state = state;
        Some(json(&sent))
    })
    .await
    .map(|_| ())
    .map_err(boxed)
}

pub(crate) async fn mark_read(
    alias: String,
    msg_id: MessageId,
    kept: KeptMessage,
) -> Result<(), DynError> {
    put(message_item(ItemKind::Kept, &alias, msg_id)?, json(&kept))
        .await
        .map_err(boxed)?;
    set_flags(message_item(ItemKind::Flags, &alias, msg_id)?, |f| {
        f.read = true
    })
    .await
    .map_err(boxed)
}

/// Archiving implies read and drops any kept copy.
pub(crate) async fn archive_message(
    alias: String,
    msg_id: MessageId,
    archived: ArchivedMessage,
) -> Result<(), DynError> {
    put(
        message_item(ItemKind::Archived, &alias, msg_id)?,
        json(&archived),
    )
    .await
    .map_err(boxed)?;
    delete(message_item(ItemKind::Kept, &alias, msg_id)?)
        .await
        .map_err(boxed)?;
    set_flags(message_item(ItemKind::Flags, &alias, msg_id)?, |f| {
        f.read = true
    })
    .await
    .map_err(boxed)
}

#[allow(dead_code)] // Wired for #60 (true unarchive).
pub(crate) async fn unarchive_message(alias: String, msg_id: MessageId) -> Result<(), DynError> {
    delete(message_item(ItemKind::Archived, &alias, msg_id)?)
        .await
        .map_err(boxed)
}

/// Deleting leaves no copy, and a mark so the message stays hidden.
pub(crate) async fn delete_message(alias: String, msg_id: MessageId) -> Result<(), DynError> {
    set_flags(message_item(ItemKind::Flags, &alias, msg_id)?, |f| {
        f.deleted = true;
        f.read = false;
    })
    .await
    .map_err(boxed)?;
    delete(message_item(ItemKind::Kept, &alias, msg_id)?)
        .await
        .map_err(boxed)?;
    delete(message_item(ItemKind::Archived, &alias, msg_id)?)
        .await
        .map_err(boxed)
}

/// Set in `stored` every leaf field that differs between `before` and
/// `after` to `after`'s value, descending into nested records. Returns
/// whether anything changed.
pub(super) fn apply_changes(
    stored: &mut serde_json::Value,
    before: &serde_json::Value,
    after: &serde_json::Value,
) -> bool {
    use serde_json::Value;
    match (before, after) {
        (Value::Object(b), Value::Object(a)) => {
            if !stored.is_object() {
                *stored = before.clone();
            }
            let fields = stored.as_object_mut().expect("an object");
            let mut changed = false;
            for (field, value) in a {
                let was = b.get(field).unwrap_or(&Value::Null);
                let slot = fields.entry(field.clone()).or_insert_with(|| was.clone());
                changed |= apply_changes(slot, was, value);
            }
            changed
        }
        _ if before == after => false,
        _ => {
            *stored = after.clone();
            true
        }
    }
}

/// The stored settings with only the fields that differ between `before`
/// and `after` set to `after`'s values: another tab's change to a different
/// field, even one in the same group, survives. `None` when nothing changed.
fn merge_changed_fields<T: Serialize>(
    stored: Option<&[u8]>,
    before: &T,
    after: &T,
) -> Option<Vec<u8>> {
    let before = serde_json::to_value(before).ok()?;
    let after = serde_json::to_value(after).ok()?;
    let mut merged = stored
        .and_then(|b| serde_json::from_slice(b).ok())
        .unwrap_or_else(|| before.clone());
    apply_changes(&mut merged, &before, &after).then(|| json(&merged))
}

pub(crate) async fn set_identity_settings(
    alias: String,
    before: IdentitySettings,
    after: IdentitySettings,
) -> Result<(), DynError> {
    let item = item(ItemKind::IdentitySettings, Some(owner(&alias)?), Vec::new());
    ops::put_item_merged(item, |stored| merge_changed_fields(stored, &before, &after))
        .await
        .map(|_| ())
        .map_err(boxed)
}

pub(crate) async fn set_global_settings(
    before: GlobalSettings,
    after: GlobalSettings,
) -> Result<(), DynError> {
    let item = item(ItemKind::GlobalSettings, None, Vec::new());
    ops::put_item_merged(item, |stored| merge_changed_fields(stored, &before, &after))
        .await
        .map(|_| ())
        .map_err(boxed)
}

// ── Load ──────────────────────────────────────────────────────────────────

fn decode<T: for<'de> Deserialize<'de>>(what: &str, body: &[u8]) -> Option<T> {
    let value = serde_json::from_slice(body).ok();
    if value.is_none() {
        crate::log::error(format!("skipping an unreadable stored {what}"), None);
    }
    value
}

fn uuid_string(id: &[u8]) -> Option<String> {
    Some(uuid::Uuid::from_slice(id).ok()?.to_string())
}

fn message_id(id: &[u8]) -> Option<MessageId> {
    Some(remember(id.try_into().ok()?))
}

/// Everything stored for `identities` (alias, address), as one snapshot.
pub(crate) async fn load(identities: &[(String, Addr)]) -> Result<LocalState, CallError> {
    let mut state = LocalState::default();
    for (alias, addr) in identities {
        let owner = Some(*addr);
        let entry = state.aliases_mut().entry(alias.clone()).or_default();
        for i in ops::list_all_items(ItemKind::Draft, owner).await? {
            if let (Some(id), Some(d)) = (uuid_string(&i.item.id), decode("draft", &i.body)) {
                entry.drafts.insert(id, d);
            }
        }
        for i in ops::list_all_items(ItemKind::Sent, owner).await? {
            if let (Some(id), Some(s)) = (uuid_string(&i.item.id), decode("sent message", &i.body))
            {
                entry.sent.insert(id, s);
            }
        }
        for i in ops::list_all_items(ItemKind::Kept, owner).await? {
            if let (Some(id), Some(k)) = (message_id(&i.item.id), decode("kept message", &i.body)) {
                entry.kept.insert(id.to_string(), k);
            }
        }
        for i in ops::list_all_items(ItemKind::Archived, owner).await? {
            if let (Some(id), Some(a)) =
                (message_id(&i.item.id), decode("archived message", &i.body))
            {
                entry.archived.insert(id.to_string(), a);
            }
        }
        for i in ops::list_all_items(ItemKind::Flags, owner).await? {
            if let (Some(id), Some(f)) = (
                message_id(&i.item.id),
                decode::<Flags>("message flags", &i.body),
            ) {
                if f.read {
                    entry.read.push(id);
                }
                if f.deleted {
                    entry.deleted.push(id);
                }
            }
        }
        let settings = item(ItemKind::IdentitySettings, owner, Vec::new());
        if let Some(i) = ops::get_item(settings).await?
            && let Some(s) = decode("identity settings", &i.body)
        {
            entry.settings = s;
        }
    }
    let global = item(ItemKind::GlobalSettings, None, Vec::new());
    if let Some(i) = ops::get_item(global).await?
        && let Some(g) = decode("global settings", &i.body)
    {
        *state.global_settings_mut() = g;
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_delivery_state_that_beat_its_sent_item_is_saved_with_it() {
        EARLY_DELIVERY.with(|e| {
            e.borrow_mut()
                .insert(("ed-a".into(), "s1".into()), DeliveryState::Delivered)
        });
        let saved = sent_with_early_delivery("ed-a", "s1", SentMessage::default());
        assert_eq!(saved.delivery_state, DeliveryState::Delivered);
        // Used once.
        let again = sent_with_early_delivery("ed-a", "s1", SentMessage::default());
        assert_eq!(again.delivery_state, DeliveryState::Pending);
        // A terminal state being saved is not overridden.
        EARLY_DELIVERY.with(|e| {
            e.borrow_mut()
                .insert(("ed-a".into(), "s2".into()), DeliveryState::Delivered)
        });
        let failed = SentMessage {
            delivery_state: DeliveryState::Failed,
            ..SentMessage::default()
        };
        let kept = sent_with_early_delivery("ed-a", "s2", failed);
        assert_eq!(kept.delivery_state, DeliveryState::Failed);
    }

    #[test]
    fn a_message_id_is_its_ciphertexts_hash_and_is_remembered_in_full() {
        let id = message_id_for(b"ciphertext");
        let hash = blake3::hash(b"ciphertext");
        let prefix = u64::from_le_bytes(hash.as_bytes()[..8].try_into().unwrap());
        assert_eq!(id, prefix & (super::super::RECEIVED_ID_LIMIT - 1));
        assert_eq!(full_id(id).unwrap(), hash.as_bytes()[..16]);
        // The same ciphertext always gets the same id: ids survive reloads
        // and a reordered inbox.
        assert_eq!(message_id_for(b"ciphertext"), id);
        assert_ne!(message_id_for(b"other"), id);
    }

    /// #289: received ids are hashes, so their range must be partitioned
    /// from the folded own-Sent rows' or a received message is treated as
    /// one (its "Add to address book" vanishes). About half of all hashes
    /// have the top bit set, so 64 ciphertexts would catch a missing mask
    /// with probability 1 - 2^-64.
    #[test]
    fn received_message_ids_never_reach_the_folded_sent_range() {
        for i in 0u32..64 {
            let id = message_id_for(&i.to_le_bytes());
            assert!(
                id < super::super::RECEIVED_ID_LIMIT,
                "id {id:#x} for ciphertext {i}"
            );
        }
    }

    #[test]
    fn a_settings_change_keeps_other_tabs_changes_to_other_fields() {
        use freenet_mail_wire_v1::local_state::{Density, Theme};
        let before = GlobalSettings::default();
        let mut mine = before.clone();
        mine.appearance.theme = Theme::Light;
        // Another tab changed a different field of the same group, and
        // stored it first.
        let mut theirs = before.clone();
        theirs.appearance.density = Density::Compact;
        assert_ne!(before.appearance.theme, Theme::Light);
        assert_ne!(before.appearance.density, Density::Compact);
        let stored = json(&theirs);
        let merged: GlobalSettings =
            serde_json::from_slice(&merge_changed_fields(Some(&stored), &before, &mine).unwrap())
                .unwrap();
        assert_eq!(merged.appearance.theme, Theme::Light);
        assert_eq!(merged.appearance.density, Density::Compact);
        // No change, nothing to write.
        assert!(merge_changed_fields(Some(&stored), &before, &before).is_none());
        // Nothing stored yet: start from what this tab saw.
        let fresh: GlobalSettings =
            serde_json::from_slice(&merge_changed_fields(None, &before, &mine).unwrap()).unwrap();
        assert_eq!(fresh.appearance.theme, Theme::Light);
    }

    #[test]
    fn draft_and_sent_ids_are_their_uuid_bytes() {
        let id = uuid::Uuid::new_v4().to_string();
        let bytes = uuid_id(&id).unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(uuid_string(&bytes).unwrap(), id);
    }
}

/// The writes and the load, run against the real mail delegate in the page
/// (the offline build), so they are exercised without a node.
#[cfg(all(test, feature = "local-delegate", not(feature = "use-node")))]
mod delegate_tests {
    use super::*;
    use futures::executor::block_on;

    /// An identity in the in-page delegate, registered under `alias` as the
    /// startup load registers one, so writes for `alias` find their owner.
    fn identity(alias: &str) -> Addr {
        let (info, _) = block_on(ops::create_identity(alias.to_string(), String::new())).unwrap();
        let identity = crate::app::login::Identity::from_info(&info, crate::app::UserId::new());
        let key = crate::inbox::inbox_key_for(&identity.ml_dsa_vk()).unwrap();
        crate::inbox::InboxModel::set_contract_identity(key, identity);
        info.addr
    }

    fn loaded(alias: &str, addr: Addr) -> LocalState {
        block_on(load(&[(alias.to_string(), addr)])).unwrap()
    }

    fn draft(subject: &str) -> Draft {
        Draft {
            to: "bob".into(),
            subject: subject.into(),
            body: String::new(),
            updated_at: 0,
            thread_id: None,
            in_reply_to: None,
            quoted_excerpt: None,
        }
    }

    fn archived() -> ArchivedMessage {
        ArchivedMessage {
            from: "bob".into(),
            title: "t".into(),
            content: "c".into(),
            archived_at: 0,
            thread_id: None,
            in_reply_to: None,
            quoted_excerpt: None,
        }
    }

    #[test]
    fn drafts_are_stored_and_a_discard_removes_them() {
        let addr = identity("items-drafts");
        let id = uuid::Uuid::new_v4().to_string();
        block_on(save_draft("items-drafts".into(), id.clone(), draft("one"))).unwrap();
        // An autosave of the same draft replaces it.
        block_on(save_draft("items-drafts".into(), id.clone(), draft("two"))).unwrap();
        let state = loaded("items-drafts", addr);
        let drafts: Vec<_> = state.drafts_of("items-drafts").collect();
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].1.subject, "two");
        block_on(delete_draft("items-drafts".into(), id)).unwrap();
        assert_eq!(
            loaded("items-drafts", addr)
                .drafts_of("items-drafts")
                .count(),
            0
        );
    }

    /// Archive, then the inbox removal: the removal runs only once the
    /// delegate acknowledged the archived copy, which is then stored.
    #[test]
    fn the_inbox_removal_runs_after_the_archived_copy_is_stored() {
        let addr = identity("items-archive");
        let id = message_id_for(b"an archived ciphertext");
        let removed = std::rc::Rc::new(std::cell::Cell::new(false));
        let flag = removed.clone();
        let outcome = block_on(crate::app::store_then(
            archive_message("items-archive".into(), id, archived()),
            move || async move { flag.set(true) },
        ));
        assert_eq!(outcome, super::super::Stored::Yes);
        assert!(removed.get(), "the removal ran after the ack");
        let state = loaded("items-archive", addr);
        assert!(
            state.is_archived("items-archive", id),
            "the archived copy is stored"
        );
        assert!(
            state.is_read("items-archive", id),
            "archiving marks it read"
        );
    }

    /// When the archived copy cannot be stored, nothing is removed.
    #[test]
    fn the_inbox_removal_does_not_run_when_the_archive_is_not_stored() {
        // No identity holds this alias: the write fails.
        let id = message_id_for(b"an unstorable ciphertext");
        let removed = std::rc::Rc::new(std::cell::Cell::new(false));
        let flag = removed.clone();
        let outcome = block_on(crate::app::store_then(
            archive_message("nobody-holds-this".into(), id, archived()),
            move || async move { flag.set(true) },
        ));
        assert_ne!(outcome, super::super::Stored::Yes);
        assert!(!removed.get(), "no removal without a stored archive");
    }

    #[test]
    fn a_deleted_message_stays_deleted_and_loses_its_copies() {
        let addr = identity("items-delete");
        let id = message_id_for(b"a deleted ciphertext");
        block_on(archive_message("items-delete".into(), id, archived())).unwrap();
        block_on(delete_message("items-delete".into(), id)).unwrap();
        let state = loaded("items-delete", addr);
        assert!(state.is_deleted("items-delete", id));
        assert!(!state.is_archived("items-delete", id));
    }

    /// Two tabs change different settings fields from the same starting
    /// point; both changes are stored.
    #[test]
    fn two_tabs_changing_different_settings_keep_both() {
        let addr = identity("items-settings");
        let start = GlobalSettings::default();
        let mut tab_a = start.clone();
        tab_a.inbox.drafts_in_inbox = true;
        let mut tab_b = start.clone();
        tab_b.advanced.custom_relay_url = "ws://tab-b".into();
        block_on(set_global_settings(start.clone(), tab_a)).unwrap();
        block_on(set_global_settings(start, tab_b)).unwrap();
        let state = loaded("items-settings", addr);
        assert!(
            state.global_settings().inbox.drafts_in_inbox,
            "tab A's change kept"
        );
        assert_eq!(
            state.global_settings().advanced.custom_relay_url,
            "ws://tab-b"
        );

        let before = IdentitySettings::default();
        let mut name = before.clone();
        name.display_name = "Name".into();
        let mut sig = before.clone();
        sig.signature = "-- sig".into();
        block_on(set_identity_settings(
            "items-settings".into(),
            before.clone(),
            name,
        ))
        .unwrap();
        block_on(set_identity_settings("items-settings".into(), before, sig)).unwrap();
        let settings = loaded("items-settings", addr).identity_settings("items-settings");
        assert_eq!(settings.display_name, "Name");
        assert_eq!(settings.signature, "-- sig");
    }
}
