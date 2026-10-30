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
//!   A sender can grind two of their OWN messages to one id (2^32 work for
//!   63 bits); that only merges the marks of those two messages, both from
//!   them, so it is accepted rather than defended.
//!   A UI id is never ordered on: it carries no time and no position.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use freenet_mail_protocol::{Addr, ItemKind, ItemRef};
use freenet_mail_wire_v1::local_state::{
    ArchivedMessage, DeliveryState, Draft, GlobalSettings, IdentitySettings, KeptMessage,
    LocalState, MessageId, SentMessage,
};
use freenet_stdlib::prelude::blake3;
use serde::{Deserialize, Serialize};

use crate::DynError;
use crate::mail_delegate::{CallError, ops};

/// This page's mark-write count, and the count at each mark's last write.
type FlagWrites = (u64, HashMap<(Addr, Vec<u8>), u64>);

thread_local! {
    /// The full 16-byte item id of every message id handed out this page.
    static FULL_IDS: RefCell<HashMap<MessageId, [u8; 16]>> = RefCell::new(HashMap::new());
    /// Counts this page's mark writes; each mark remembers the count at its
    /// last write, so a reclaim leaves alone marks written after it began.
    static FLAG_WRITES: RefCell<FlagWrites> = RefCell::new((0, HashMap::new()));
}

fn note_flag_write(item: &ItemRef) {
    if let Some(owner) = item.owner {
        FLAG_WRITES.with(|w| {
            let w = &mut *w.borrow_mut();
            w.0 += 1;
            w.1.insert((owner, item.id.clone()), w.0);
        });
    }
}

fn flag_writes_so_far() -> u64 {
    FLAG_WRITES.with(|w| w.borrow().0)
}

fn flag_written_since(owner: Addr, id: &[u8], since: u64) -> bool {
    FLAG_WRITES.with(|w| {
        w.borrow()
            .1
            .get(&(owner, id.to_vec()))
            .is_some_and(|n| *n > since)
    })
}

fn remember(full: [u8; 16]) -> MessageId {
    let id =
        u64::from_le_bytes(full[..8].try_into().expect("8 bytes")) & (super::RECEIVED_ID_LIMIT - 1);
    FULL_IDS.with(|ids| ids.borrow_mut().insert(id, full));
    id
}

/// The id of a received message, from its ciphertext.
pub(crate) fn message_id_for(ciphertext: &[u8]) -> MessageId {
    remember(full_message_id(ciphertext))
}

/// The 16-byte item id of a received message, from its ciphertext.
pub(crate) fn full_message_id(ciphertext: &[u8]) -> [u8; 16] {
    let mut full = [0u8; 16];
    full.copy_from_slice(&blake3::hash(ciphertext).as_bytes()[..16]);
    full
}

fn full_id(id: MessageId) -> Result<[u8; 16], DynError> {
    FULL_IDS
        .with(|ids| ids.borrow().get(&id).copied())
        .ok_or_else(|| format!("message {id} is not loaded").into())
}

/// The identity that owns `alias`'s items: the address its state key names
/// ([`super::state_key`]), which a rename does not change.
fn owner(alias: &str) -> Result<Addr, DynError> {
    super::addr_of_key(&super::state_key(alias))
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
async fn set_flags(item: ItemRef, mut change: impl FnMut(&mut Flags)) -> Result<(), CallError> {
    // Before the write: a reclaim that lists this mark while the write is
    // in flight must already see it as new.
    note_flag_write(&item);
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
        // "Already gone" only when a second read agrees: one lost read must
        // not leave the item in place while the caller goes on as if
        // deleted. The cost is one extra delegate round trip, paid only
        // when the item reads as absent (so a delete of something already
        // deleted costs two reads; `delete_message`, deleting a message's
        // kept and archived copies, pays it for each copy that is absent).
        let current = match ops::get_item(item.clone()).await {
            Ok(Some(current)) => current,
            Ok(None) => match ops::get_item(item.clone()).await? {
                Some(current) => current,
                None => return Ok(()),
            },
            // Listed but unreadable: the delegate deletes it without
            // reading it (any generation; it cannot be compared).
            Err(e) if ops::is_unreadable(&e) => {
                return ops::delete_item(item.clone(), 0).await;
            }
            Err(e) => return Err(e),
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

/// What a draft save did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DraftSave {
    /// The draft is stored.
    Stored,
    /// This page discarded the draft; nothing was written.
    Discarded,
    /// The draft was stored once and is gone now: another tab discarded or
    /// sent it. Nothing was written, so it is not brought back (and cannot
    /// be sent twice); the compose sheet stops autosaving it.
    GoneElsewhere,
}

thread_local! {
    /// Drafts this page has seen stored, by (state key, draft id): loaded
    /// at startup or saved here. A save that finds one of them missing
    /// knows another tab removed it, which a page-local discard tombstone
    /// cannot know.
    static SEEN_DRAFTS: RefCell<HashSet<(String, String)>> = RefCell::new(HashSet::new());
}

fn seen_draft(key: String, id: String) {
    SEEN_DRAFTS.with(|s| s.borrow_mut().insert((key, id)));
}

/// Forget this page's bookkeeping for a deleted identity: its pending
/// mark writes and the delivery states waiting for its Sent items.
pub(crate) fn forget_identity_bookkeeping(addr: &Addr) {
    FLAG_WRITES.with(|w| w.borrow_mut().1.retain(|(a, _), _| a != addr));
    // Keyed by state key (the address), like everything `save_sent` and
    // `set_sent_delivery_state` write: by alias it would match nothing.
    let key = super::addr_key(addr);
    EARLY_DELIVERY.with(|e| e.borrow_mut().retain(|(a, _), _| *a != key));
}

/// Forget the drafts seen for state key `key` (its identity is gone).
pub(super) fn forget_seen_drafts(key: &str) {
    SEEN_DRAFTS.with(|s| s.borrow_mut().retain(|(k, _)| k != key));
}

/// A draft as stored: the v0.2.x draft fields plus the address of the
/// recipient chosen for it. The alias in `to` is only what the user typed;
/// `to_address` names the key, and a draft without one (carried over from
/// older data, or never addressed) is resolved when it is next opened.
#[derive(Serialize, Deserialize)]
struct StoredDraft {
    #[serde(flatten)]
    draft: Draft,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    to_address: Option<String>,
}

/// Whether a draft may be sent from this page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DraftCheck {
    /// Stored, or never stored by anyone this page knows of: send it.
    Current,
    /// This page saw it stored and it is gone now: sent or discarded in
    /// another tab. Sending it here would send it twice.
    GoneElsewhere,
}

/// Check, just before sending, that draft `id` is still current. A draft
/// this page never saw stored (a fresh compose not yet autosaved) is
/// current; one it saw stored is current only while the delegate still
/// holds it. Unanswered is an error: sending could duplicate a send made in
/// another tab, so the caller asks the user to try again.
pub(crate) async fn check_draft_before_send(
    alias: String,
    id: String,
) -> Result<DraftCheck, DynError> {
    let owner = owner(&alias)?;
    let key = super::addr_key(&owner);
    let seen = SEEN_DRAFTS.with(|s| s.borrow().contains(&(key, id.clone())));
    if !seen {
        return Ok(DraftCheck::Current);
    }
    let it = item(ItemKind::Draft, Some(owner), uuid_id(&id)?);
    // Absent twice before it counts: one lost read must not refuse a send.
    Ok(if draft_stored(&it).await? || draft_stored(&it).await? {
        DraftCheck::Current
    } else {
        DraftCheck::GoneElsewhere
    })
}

async fn draft_stored(item: &ItemRef) -> Result<bool, DynError> {
    match ops::get_item(item.clone()).await {
        Ok(found) => Ok(found.is_some()),
        // Still listed (stored), just unreadable: not gone.
        Err(e) if ops::is_unreadable(&e) => Ok(true),
        Err(e) => Err(boxed(e)),
    }
}

/// Save a draft unless it is gone. An autosave still in flight when the
/// draft is discarded here must not bring it back: the discard is checked
/// at the last moment before each write. A draft discarded or sent in
/// another tab is gone from the delegate while this page still edits it;
/// one this page has seen stored is not recreated
/// ([`DraftSave::GoneElsewhere`]).
pub(crate) async fn save_draft(
    alias: String,
    id: String,
    draft: Draft,
    to_address: Option<String>,
) -> Result<DraftSave, DynError> {
    let owner = owner(&alias)?;
    let key = super::addr_key(&owner);
    let item = item(ItemKind::Draft, Some(owner), uuid_id(&id)?);
    let seen = SEEN_DRAFTS.with(|s| s.borrow().contains(&(key.clone(), id.clone())));
    let body = json(&StoredDraft { draft, to_address });
    // "Gone elsewhere" stops this page autosaving the draft and drops it, so
    // it is believed only when a second read agrees: one lost read must not
    // cost the user their draft.
    for attempt in 0..2 {
        let mut outcome = DraftSave::Stored;
        let written = ops::put_item_merged(item.clone(), |stored| {
            if super::draft_discarded(&alias, &id) {
                outcome = DraftSave::Discarded;
                return None;
            }
            if stored.is_none() && seen {
                outcome = DraftSave::GoneElsewhere;
                return None;
            }
            Some(body.clone())
        })
        .await
        .map_err(boxed)?;
        let outcome = match (written, outcome) {
            (Some(_), _) => {
                seen_draft(key, id);
                return Ok(DraftSave::Stored);
            }
            // `put_item_merged` declines on its own when the draft existed at
            // its first read and was gone at a retry: removed by another tab.
            (None, DraftSave::Stored) => DraftSave::GoneElsewhere,
            (None, other) => other,
        };
        if outcome != DraftSave::GoneElsewhere || attempt == 1 || !draft_stored(&item).await? {
            return Ok(outcome);
        }
    }
    unreachable!("the second attempt always returns")
}

/// Whether message `msg_id` is gone, as far as anything here knows: deleted
/// or archived in this page, or marked deleted in its stored flags (which
/// a delete writes first, so this holds across tabs).
async fn message_gone(alias: &str, msg_id: MessageId) -> Result<bool, DynError> {
    if super::is_deleted(alias, msg_id) || super::is_archived(alias, msg_id) {
        return Ok(true);
    }
    let flags = match ops::get_item(message_item(ItemKind::Flags, alias, msg_id)?).await {
        Ok(flags) => flags,
        // Its marks cannot be read: nothing here knows it is gone.
        Err(e) if ops::is_unreadable(&e) => None,
        Err(e) => return Err(boxed(e)),
    };
    Ok(flags
        .and_then(|f| serde_json::from_slice::<Flags>(&f.body).ok())
        .is_some_and(|f| f.deleted))
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
    // Keyed like the rest of the local state: by address, so a rename
    // between this write and a delivery state can't split them.
    let alias = super::state_key(&alias);
    let item = item(ItemKind::Sent, Some(owner(&alias)?), uuid_id(&id)?);
    let sent = sent_with_early_delivery(&alias, &id, sent);
    put(item, json(&sent)).await.map_err(boxed)?;
    super::drain_acked_sent(&alias, &id);
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
    let alias = super::state_key(&alias);
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
    // A read mark racing a delete or an archive must not write the
    // message's content back after them.
    if message_gone(&alias, msg_id).await? {
        return Ok(());
    }
    // The read mark first: it is small and always fits, so a kept copy the
    // delegate refuses (too large) never costs the mark itself.
    let mut deleted = false;
    set_flags(message_item(ItemKind::Flags, &alias, msg_id)?, |f| {
        deleted = f.deleted;
        if !f.deleted {
            f.read = true;
        }
    })
    .await
    .map_err(boxed)?;
    let body = json(&kept);
    let kept_item = message_item(ItemKind::Kept, &alias, msg_id)?;
    if !deleted {
        ops::put_item_merged(kept_item.clone(), |_| {
            let gone = super::is_deleted(&alias, msg_id) || super::is_archived(&alias, msg_id);
            (!gone).then(|| body.clone())
        })
        .await
        .map_err(boxed)?;
    }
    // A delete landed between the check and the write: take the copy back.
    if deleted || message_gone(&alias, msg_id).await? {
        delete(kept_item).await.map_err(boxed)?;
    }
    super::drain_acked_kept(&super::state_key(&alias), msg_id);
    Ok(())
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
    super::drain_acked_archived(&super::state_key(&alias), msg_id);
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
///
/// The copies go first. A copy whose removal failed would otherwise
/// survive the deletion beside a mark saying it is deleted, holding the
/// message's content the user asked to remove, and pinning that mark
/// against reclamation (a kept copy keeps its mark). This way a failure
/// leaves the message visible and the deletion retryable.
pub(crate) async fn delete_message(alias: String, msg_id: MessageId) -> Result<(), DynError> {
    delete(message_item(ItemKind::Kept, &alias, msg_id)?)
        .await
        .map_err(boxed)?;
    delete(message_item(ItemKind::Archived, &alias, msg_id)?)
        .await
        .map_err(boxed)?;
    set_flags(message_item(ItemKind::Flags, &alias, msg_id)?, |f| {
        f.deleted = true;
        f.read = false;
    })
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
            // A key this tab removed (a forgotten map entry) is removed from
            // the stored copy too; keys only another tab added stay.
            for field in b.keys().filter(|f| !a.contains_key(*f)) {
                changed |= fields.remove(field).is_some();
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

/// Drop the read and deleted marks of messages that are gone for good: in
/// no inbox state the page has seen (`live`, asked at the moment each mark
/// would go, so a state that arrived meanwhile counts), with no kept or
/// archived copy, and not written since this reclaim began. Without this
/// every message ever received keeps a flags item, and the per-identity cap
/// eventually refuses every new mark. Returns how many were dropped.
///
/// A deleted mark is safe to drop then: it only hides a message the inbox
/// still holds, and this one is no longer there.
pub(crate) async fn reclaim_flags(
    owner: Addr,
    live: &dyn Fn(&[u8]) -> bool,
) -> Result<usize, CallError> {
    let began = flag_writes_so_far();
    let mut keep: HashSet<Vec<u8>> = HashSet::new();
    for kind in [ItemKind::Kept, ItemKind::Archived] {
        keep.extend(
            ops::list_all_items(kind, Some(owner))
                .await?
                .into_iter()
                .map(|i| i.item.id),
        );
    }
    let mut dropped = 0;
    for i in ops::list_all_items(ItemKind::Flags, Some(owner)).await? {
        if keep.contains(&i.item.id)
            || live(&i.item.id)
            || flag_written_since(owner, &i.item.id, began)
        {
            continue;
        }
        match ops::delete_item(i.item, i.generation).await {
            Ok(_) => dropped += 1,
            // Changed since it was listed: a mark is being written for a
            // message something still knows about; leave it.
            Err(e)
                if matches!(
                    e.code(),
                    Some(freenet_mail_protocol::FailureCode::Conflict { .. })
                ) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(dropped)
}

/// A stored item, or `None` (defaults) when it is listed but cannot be
/// read: the user is told once, and the next save replaces it.
fn readable_or_default(
    got: Result<Option<freenet_mail_protocol::Item>, CallError>,
) -> Result<Option<freenet_mail_protocol::Item>, CallError> {
    match got {
        Err(e) if ops::is_unreadable(&e) => {
            ops::notice_unreadable();
            Ok(None)
        }
        other => other,
    }
}

/// Everything stored for `identities` (alias, address), as one snapshot.
pub(crate) async fn load(identities: &[(String, Addr)]) -> Result<LocalState, CallError> {
    let mut state = LocalState::default();
    for (alias, addr) in identities {
        let owner = Some(*addr);
        let entry = state.aliases_mut().entry(alias.clone()).or_default();
        for i in ops::list_all_items(ItemKind::Draft, owner).await? {
            if let (Some(id), Some(d)) = (
                uuid_string(&i.item.id),
                decode::<StoredDraft>("draft", &i.body),
            ) {
                seen_draft(super::addr_key(addr), id.clone());
                super::set_draft_recipient_for_key(super::addr_key(addr), id.clone(), d.to_address);
                entry.drafts.insert(id, d.draft);
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
        if let Some(i) = readable_or_default(ops::get_item(settings).await)?
            && let Some(s) = decode("identity settings", &i.body)
        {
            entry.settings = s;
        }
    }
    let global = item(ItemKind::GlobalSettings, None, Vec::new());
    if let Some(i) = readable_or_default(ops::get_item(global).await)?
        && let Some(g) = decode("global settings", &i.body)
    {
        *state.global_settings_mut() = g;
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    /// A deleted identity's page bookkeeping goes with it: its pending mark
    /// writes and the delivery states waiting for its Sent items (round-8
    /// X12), and only its own.
    #[test]
    fn forgetting_an_identity_clears_its_bookkeeping() {
        use super::*;
        let (gone, kept) = (Addr([0x31; 24]), Addr([0x32; 24]));
        for owner in [gone, kept] {
            note_flag_write(&ItemRef {
                kind: freenet_mail_protocol::ItemKind::Flags,
                owner: Some(owner),
                id: vec![7; 16],
            });
        }
        // Delivery states are keyed by the identity's state key (its
        // address), as `save_sent` writes them.
        let (gone_key, kept_key) = (
            crate::local_state::addr_key(&gone),
            crate::local_state::addr_key(&kept),
        );
        EARLY_DELIVERY.with(|e| {
            let mut e = e.borrow_mut();
            e.insert((gone_key.clone(), "s1".into()), DeliveryState::Delivered);
            e.insert((kept_key.clone(), "s1".into()), DeliveryState::Delivered);
        });
        forget_identity_bookkeeping(&gone);
        FLAG_WRITES.with(|w| {
            let w = w.borrow();
            assert!(!w.1.keys().any(|(a, _)| *a == gone));
            assert!(w.1.keys().any(|(a, _)| *a == kept));
        });
        EARLY_DELIVERY.with(|e| {
            let e = e.borrow();
            assert!(!e.contains_key(&(gone_key.clone(), "s1".to_string())));
            assert!(e.contains_key(&(kept_key.clone(), "s1".to_string())));
        });
    }

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
    fn a_map_key_removed_by_this_tab_is_removed_from_the_stored_copy() {
        use serde_json::json as j;
        let before = j!({ "decisions": { "alice": "accept", "bob": "deny" }, "theme": "dark" });
        // This tab forgot bob's decision.
        let after = j!({ "decisions": { "alice": "accept" }, "theme": "dark" });
        // Another tab added carol's decision and stored it first.
        let mut stored = j!({ "decisions": { "alice": "accept", "bob": "deny", "carol": "accept" }, "theme": "dark" });
        assert!(apply_changes(&mut stored, &before, &after));
        assert_eq!(
            stored,
            j!({ "decisions": { "alice": "accept", "carol": "accept" }, "theme": "dark" }),
            "bob is gone, carol (another tab's addition) is kept"
        );
        // Removing a key another tab already removed changes nothing.
        let mut already = j!({ "decisions": { "alice": "accept" }, "theme": "dark" });
        assert!(!apply_changes(&mut already, &before, &after));
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

    fn kept(content: String) -> KeptMessage {
        KeptMessage {
            from: "bob".into(),
            title: "t".into(),
            content,
            kept_at: 0,
            sent_at: None,
            sender_vk: Vec::new(),
            signature_valid: true,
        }
    }

    fn flag_ids(addr: Addr) -> HashSet<Vec<u8>> {
        block_on(ops::list_all_items(ItemKind::Flags, Some(addr)))
            .unwrap()
            .into_iter()
            .map(|i| i.item.id)
            .collect()
    }

    /// Once the delegate acknowledges a sent message, a read mark's kept
    /// copy or an archive, the page drops its optimistic copy of the body
    /// (it used to hold every one for the whole session).
    #[test]
    fn acknowledged_writes_drop_their_optimistic_copies() {
        let alias = "items-drain";
        let _addr = identity(alias);
        let key = super::super::state_key(alias);
        let sent_id = uuid::Uuid::new_v4().to_string();
        let read = message_id_for(b"drain: read");
        let filed = message_id_for(b"drain: archived");
        super::super::local_save_sent(alias, &sent_id, SentMessage::default());
        super::super::local_mark_read(alias, read, kept("k".into()));
        super::super::local_archive_message(alias, filed, archived());
        let held = || {
            (
                super::super::OPTIMISTIC_SENT
                    .with(|p| p.borrow().contains_key(&(key.clone(), sent_id.clone()))),
                super::super::PENDING_KEPT
                    .with(|p| p.borrow().contains_key(&(key.clone(), read.to_string()))),
                super::super::OPTIMISTIC_ARCHIVED
                    .with(|p| p.borrow().contains_key(&(key.clone(), filed.to_string()))),
            )
        };
        assert_eq!(held(), (true, true, true));
        block_on(save_sent(
            alias.into(),
            sent_id.clone(),
            SentMessage::default(),
        ))
        .unwrap();
        block_on(mark_read(alias.into(), read, kept("k".into()))).unwrap();
        block_on(archive_message(alias.into(), filed, archived())).unwrap();
        assert_eq!(held(), (false, false, false));
    }

    /// Marks of messages that left the inbox with no kept or archived copy
    /// are dropped; marks of messages still in the inbox, kept or archived
    /// stay, so flags items cannot pile up to the per-identity cap.
    #[test]
    fn marks_of_messages_gone_for_good_are_reclaimed() {
        let alias = "items-reclaim";
        let addr = identity(alias);
        let live = message_id_for(b"still in the inbox");
        let gone = message_id_for(b"deleted and removed");
        let read_gone = message_id_for(b"read, then removed");
        let saved = message_id_for(b"archived");
        block_on(delete_message(alias.into(), live)).unwrap();
        block_on(delete_message(alias.into(), gone)).unwrap();
        block_on(mark_read(alias.into(), read_gone, kept("k".into()))).unwrap();
        block_on(delete(
            message_item(ItemKind::Kept, alias, read_gone).unwrap(),
        ))
        .unwrap();
        block_on(archive_message(alias.into(), saved, archived())).unwrap();
        assert_eq!(flag_ids(addr).len(), 4);
        let still: HashSet<[u8; 16]> = [full_message_id(b"still in the inbox")].into();
        let live = |id: &[u8]| still.iter().any(|s| s.as_slice() == id);
        assert_eq!(block_on(reclaim_flags(addr, &live)).unwrap(), 2);
        let left = flag_ids(addr);
        assert!(left.contains(full_message_id(b"still in the inbox").as_slice()));
        assert!(left.contains(full_message_id(b"archived").as_slice()));
        assert_eq!(left.len(), 2);
    }

    /// A mark written while a reclaim runs (after it listed the kept and
    /// archived copies, before it reached the mark) is not dropped, and a
    /// message that became live meanwhile keeps its mark too.
    #[test]
    fn a_reclaim_leaves_marks_written_or_made_live_while_it_runs() {
        let alias = "items-reclaim-race";
        let addr = identity(alias);
        let written = message_id_for(b"marked during the reclaim");
        let arrived = message_id_for(b"arrived during the reclaim");
        let gone = message_id_for(b"gone for good");
        for id in [written, arrived, gone] {
            block_on(delete_message(alias.into(), id)).unwrap();
        }
        let written_full = full_message_id(b"marked during the reclaim");
        let arrived_full = full_message_id(b"arrived during the reclaim");
        let item = ItemRef {
            kind: ItemKind::Flags,
            owner: Some(addr),
            id: written_full.to_vec(),
        };
        let live = |id: &[u8]| {
            // Another task writes this mark now, and a new state brings this
            // message: both happen after the reclaim began.
            note_flag_write(&item);
            id == arrived_full.as_slice()
        };
        assert_eq!(block_on(reclaim_flags(addr, &live)).unwrap(), 1);
        let left = flag_ids(addr);
        assert!(left.contains(written_full.as_slice()));
        assert!(left.contains(arrived_full.as_slice()));
        assert!(!left.contains(full_message_id(b"gone for good").as_slice()));
    }

    /// A kept copy too large for the delegate must not cost the read mark.
    #[test]
    fn a_read_mark_is_kept_when_the_kept_copy_is_refused() {
        let alias = "items-big-kept";
        let addr = identity(alias);
        let id = message_id_for(b"a very long message");
        let huge = "x".repeat(freenet_mail_protocol::MAX_ITEM_BYTES + 1);
        assert!(block_on(mark_read(alias.into(), id, kept(huge))).is_err());
        assert!(
            loaded(alias, addr).is_read(alias, id),
            "the mark was stored"
        );
    }

    /// After a rename, every write under the new alias still reaches the
    /// identity's items. The inbox routing map holds its own copy of the
    /// identity; resolving owners through it failed every write after a
    /// rename with "no identity".
    #[test]
    fn writes_under_a_renamed_alias_still_persist() {
        let addr = identity("items-rn-old");
        let (info, _) = {
            let list = block_on(ops::list_identities()).unwrap();
            let info = list.into_iter().find(|i| i.addr == addr).unwrap();
            (info, ())
        };
        crate::app::login::Identity::register_live_for_test(
            crate::app::login::Identity::from_info(&info, crate::app::UserId::new()),
        );
        // What the app does on a rename the delegate acknowledged.
        block_on(ops::update_identity(
            addr,
            "items-rn-new".into(),
            String::new(),
            info.generation,
        ))
        .unwrap();
        assert!(crate::app::login::Identity::rename_in_place(
            "items-rn-old",
            "items-rn-new"
        ));
        // The routing map is deliberately left holding the old alias:
        // persistence must not depend on it.
        let id = uuid::Uuid::new_v4().to_string();
        block_on(save_draft("items-rn-new".into(), id, draft("after"), None)).unwrap();
        let before = IdentitySettings::default();
        let mut after = before.clone();
        after.display_name = "Renamed".into();
        block_on(set_identity_settings("items-rn-new".into(), before, after)).unwrap();
        let key = super::super::addr_key(&addr);
        let state = loaded(&key, addr);
        assert_eq!(state.drafts_of(&key).count(), 1);
        assert_eq!(state.identity_settings(&key).display_name, "Renamed");
    }

    #[test]
    fn drafts_are_stored_and_a_discard_removes_them() {
        let addr = identity("items-drafts");
        let id = uuid::Uuid::new_v4().to_string();
        block_on(save_draft(
            "items-drafts".into(),
            id.clone(),
            draft("one"),
            None,
        ))
        .unwrap();
        // An autosave of the same draft replaces it.
        block_on(save_draft(
            "items-drafts".into(),
            id.clone(),
            draft("two"),
            None,
        ))
        .unwrap();
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

    /// An autosave still in flight when its draft is discarded must not
    /// bring the draft back.
    #[test]
    fn a_late_autosave_does_not_bring_back_a_discarded_draft() {
        let addr = identity("items-late-save");
        let id = uuid::Uuid::new_v4().to_string();
        block_on(save_draft(
            "items-late-save".into(),
            id.clone(),
            draft("one"),
            None,
        ))
        .unwrap();
        super::super::local_delete_draft("items-late-save", &id);
        block_on(delete_draft("items-late-save".into(), id.clone())).unwrap();
        block_on(save_draft(
            "items-late-save".into(),
            id,
            draft("late"),
            None,
        ))
        .unwrap();
        assert_eq!(
            loaded("items-late-save", addr)
                .drafts_of("items-late-save")
                .count(),
            0
        );
    }

    /// Another tab discarding or sending a draft deletes it from the
    /// delegate while this page still edits it. This page's next autosave
    /// must not bring it back (a sent draft would reappear and could be sent
    /// twice). This page is tab B; tab A is a second client on the same
    /// in-page store, writing through the protocol directly.
    #[test]
    fn a_draft_removed_in_another_tab_is_not_brought_back() {
        let addr = identity("items-other-tab");
        let draft_item = |id: &str| ItemRef {
            kind: ItemKind::Draft,
            owner: Some(addr),
            id: uuid_id(id).unwrap(),
        };
        let other_tab_deletes = |item: ItemRef| {
            let stored = block_on(ops::get_item(item.clone())).unwrap().unwrap();
            block_on(ops::delete_item(item, stored.generation)).unwrap();
        };

        // A draft this page saved.
        let id = uuid::Uuid::new_v4().to_string();
        let saved = block_on(save_draft(
            "items-other-tab".into(),
            id.clone(),
            draft("one"),
            None,
        ));
        assert_eq!(saved.unwrap(), DraftSave::Stored);
        other_tab_deletes(draft_item(&id));
        let late = block_on(save_draft(
            "items-other-tab".into(),
            id.clone(),
            draft("late"),
            None,
        ));
        assert_eq!(late.unwrap(), DraftSave::GoneElsewhere);
        assert!(block_on(ops::get_item(draft_item(&id))).unwrap().is_none());

        // A draft this page only loaded (the other tab wrote it).
        let id2 = uuid::Uuid::new_v4().to_string();
        block_on(ops::put_item(
            draft_item(&id2),
            json(&draft("from A")),
            None,
        ))
        .unwrap();
        let _ = loaded("items-other-tab", addr);
        other_tab_deletes(draft_item(&id2));
        let late2 = block_on(save_draft(
            "items-other-tab".into(),
            id2.clone(),
            draft("late"),
            None,
        ));
        assert_eq!(late2.unwrap(), DraftSave::GoneElsewhere);
        assert!(block_on(ops::get_item(draft_item(&id2))).unwrap().is_none());

        // A brand-new draft is still stored on its first save.
        let fresh = uuid::Uuid::new_v4().to_string();
        let first = block_on(save_draft(
            "items-other-tab".into(),
            fresh,
            draft("new"),
            None,
        ));
        assert_eq!(first.unwrap(), DraftSave::Stored);
    }

    /// A draft sent (or discarded) in another tab must not be sent again
    /// from this one, even if this page never autosaves it again. This page
    /// is tab B; tab A is a second client on the same in-page store.
    #[test]
    fn a_draft_sent_in_another_tab_is_refused_before_sending() {
        let addr = identity("items-send-check");
        let alias = "items-send-check";
        let id = uuid::Uuid::new_v4().to_string();
        let item = ItemRef {
            kind: ItemKind::Draft,
            owner: Some(addr),
            id: uuid_id(&id).unwrap(),
        };
        // Tab B saved the draft and still shows it.
        block_on(save_draft(alias.into(), id.clone(), draft("hi"), None)).unwrap();
        let check = || block_on(check_draft_before_send(alias.into(), id.clone())).unwrap();
        assert_eq!(check(), DraftCheck::Current);

        // Tab A sends it, which deletes the stored draft.
        let stored = block_on(ops::get_item(item.clone())).unwrap().unwrap();
        block_on(ops::delete_item(item, stored.generation)).unwrap();
        assert_eq!(check(), DraftCheck::GoneElsewhere);

        // A fresh compose this page never saved is sendable.
        let fresh = uuid::Uuid::new_v4().to_string();
        assert_eq!(
            block_on(check_draft_before_send(alias.into(), fresh)).unwrap(),
            DraftCheck::Current
        );
    }

    /// One delegate answer saying a seen draft is absent, while it is
    /// really stored (a read the host failed), neither refuses its send nor
    /// stops its autosave: "gone elsewhere" needs a second read to agree.
    #[cfg(feature = "local-delegate")]
    #[test]
    fn a_single_lost_read_never_makes_a_draft_gone_elsewhere() {
        let addr = identity("items-lost-read");
        let alias = "items-lost-read";
        let id = uuid::Uuid::new_v4().to_string();
        block_on(save_draft(alias.into(), id.clone(), draft("v1"), None)).unwrap();
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let rel = format!("it/dr/{}/{}", hex(&addr.0), hex(&uuid_id(&id).unwrap()));
        crate::mail_delegate::local::miss_next_reads(&rel, 2);
        assert_eq!(
            block_on(check_draft_before_send(alias.into(), id.clone())).unwrap(),
            DraftCheck::Current
        );
        crate::mail_delegate::local::miss_next_reads(&rel, 2);
        assert_eq!(
            block_on(save_draft(alias.into(), id.clone(), draft("v2"), None)).unwrap(),
            DraftSave::Stored
        );
        crate::mail_delegate::local::miss_next_reads("", 0);
        let item = ItemRef {
            kind: ItemKind::Draft,
            owner: Some(addr),
            id: uuid_id(&id).unwrap(),
        };
        assert!(block_on(ops::get_item(item)).unwrap().is_some());
    }

    /// A deletion whose kept copy cannot be removed fails before it marks
    /// the message deleted: no copy survives beside a "deleted" mark.
    #[cfg(feature = "local-delegate")]
    #[test]
    fn a_deletion_that_cannot_remove_a_copy_marks_nothing() {
        let alias = "items-del-order";
        let addr = identity(alias);
        let id = message_id_for(b"kept, then deleted");
        block_on(mark_read(alias.into(), id, kept("k".into()))).unwrap();
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let kept_rel = format!(
            "it/kp/{}/{}",
            hex(&addr.0),
            hex(&full_message_id(b"kept, then deleted"))
        );
        // The copy's current generation cannot be read: its delete cannot
        // go ahead (a failed read looks like "already gone" only when it
        // misses twice, then the delete is a no-op and the copy stays).
        crate::mail_delegate::local::miss_next_reads(&kept_rel, 2);
        let _ = block_on(delete_message(alias.into(), id));
        crate::mail_delegate::local::miss_next_reads("", 0);
        let flags = block_on(ops::get_item(
            message_item(ItemKind::Flags, alias, id).unwrap(),
        ))
        .unwrap()
        .map(|i| serde_json::from_slice::<Flags>(&i.body).unwrap());
        let copy = block_on(ops::get_item(
            message_item(ItemKind::Kept, alias, id).unwrap(),
        ))
        .unwrap();
        assert!(
            !(copy.is_some() && flags.is_some_and(|f| f.deleted)),
            "a kept copy survived beside a deleted mark"
        );
    }

    /// The recipient address a draft was addressed to survives a reload,
    /// and a draft stored without one (older data) loads with none.
    #[test]
    fn a_drafts_recipient_address_survives_a_reload() {
        let addr = identity("items-to-address");
        let alias = "items-to-address";
        let addressed = uuid::Uuid::new_v4().to_string();
        let bare = uuid::Uuid::new_v4().to_string();
        block_on(save_draft(
            alias.into(),
            addressed.clone(),
            draft("to bob"),
            Some("BobsInboxAddress".into()),
        ))
        .unwrap();
        block_on(ops::put_item(
            ItemRef {
                kind: ItemKind::Draft,
                owner: Some(addr),
                id: uuid_id(&bare).unwrap(),
            },
            json(&draft("old")),
            None,
        ))
        .unwrap();
        super::super::set_draft_recipient(alias, &addressed, None);
        let state = loaded(alias, addr);
        assert_eq!(state.drafts_of(alias).count(), 2);
        assert_eq!(
            super::super::draft_recipient(alias, &addressed).as_deref(),
            Some("BobsInboxAddress")
        );
        assert_eq!(super::super::draft_recipient(alias, &bare), None);
    }

    /// A read mark racing a delete, including one made in another tab
    /// (known here only from the stored flags), must not write the
    /// message's content back.
    #[test]
    fn a_read_mark_after_a_delete_stores_no_copy() {
        let addr = identity("items-read-del");
        let id = message_id_for(b"a ciphertext deleted elsewhere");
        block_on(delete_message("items-read-del".into(), id)).unwrap();
        block_on(mark_read(
            "items-read-del".into(),
            id,
            KeptMessage::default(),
        ))
        .unwrap();
        let state = loaded("items-read-del", addr);
        assert!(state.is_deleted("items-read-del", id));
        assert!(
            state
                .for_alias("items-read-del")
                .is_none_or(|s| s.kept.is_empty()),
            "no kept copy of a deleted message"
        );
        assert!(!state.is_read("items-read-del", id));
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

    /// Settings the node can no longer read (a file it cannot read or
    /// decrypt reads as absent every time) load as defaults instead of
    /// failing the whole load, and the next save replaces them.
    #[test]
    fn unreadable_settings_load_as_defaults_and_a_save_replaces_them() {
        let addr = identity("items-unreadable");
        let before = IdentitySettings::default();
        let mut name = before.clone();
        name.display_name = "Old".into();
        block_on(set_identity_settings(
            "items-unreadable".into(),
            before.clone(),
            name,
        ))
        .unwrap();
        let key_text = format!("/it/si/{}", mail_delegate::store::hex(&addr.0));
        crate::mail_delegate::local::miss_next_reads(&key_text, 10_000);
        let settings = loaded("items-unreadable", addr).identity_settings("items-unreadable");
        assert_eq!(
            settings, before,
            "defaults stand in for unreadable settings"
        );
        let mut sig = before.clone();
        sig.signature = "-- new".into();
        block_on(set_identity_settings(
            "items-unreadable".into(),
            before,
            sig,
        ))
        .unwrap();
        crate::mail_delegate::local::miss_next_reads(&key_text, 0);
        let settings = loaded("items-unreadable", addr).identity_settings("items-unreadable");
        assert_eq!(settings.signature, "-- new", "the save replaced them");
        assert_eq!(settings.display_name, "", "nothing unreadable came back");
    }
}
