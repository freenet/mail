//! The identity's own v2 inbox: made once, then drained whenever it changes,
//! and its drained mail shown.
//!
//! The delegate's background jobs drain too, with every tab closed; this
//! only makes mail appear sooner while a page is open. Both go through the
//! delegate's one owner update, which stores a message before it tombstones
//! it.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use dioxus::prelude::*;
use freenet_mail_protocol::address::address_of;
use freenet_mail_protocol::inbox_v2::{self as w, Admission, InboundMessage, InboxState};
use freenet_mail_protocol::{Addr, Hash32, ItemKind, ItemRef, Op, OwnerChange, Reply, from_cbor};

use super::net::{self, Got};
use super::{InboxRecordView, MailBody};
use crate::mail_delegate::{CallError, call, ops, unexpected};

/// One drained message, as the page shows it.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Inbound {
    pub id: [u8; 32],
    pub from: Addr,
    pub sender_vk: Vec<u8>,
    /// [`w::KIND_QUARANTINE`] for a stranger's first mail.
    pub admission: u8,
    pub body: MailBody,
    /// The stored copy: its item id and generation, to drop it.
    pub item_id: Vec<u8>,
    pub generation: u64,
}

/// What the page knows about one own inbox.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Status {
    pub ready: bool,
    pub quarantine: Option<w::QuarantineMode>,
    /// Stranger messages held in the inbox, waiting to be drained.
    pub waiting_strangers: usize,
    pub strangers_dropped: u64,
    /// Decision 25: the inbox holds an owner version this node did not sign.
    pub foreign_version: bool,
    /// The new-contacts queue was seen full (every slot taken), so a
    /// stranger's message may have been pushed out.
    pub queue_was_full: bool,
    pub error: Option<String>,
}

/// Drained mail by identity.
pub(crate) static INBOUND: GlobalSignal<HashMap<Addr, Vec<Inbound>>> = Signal::global(HashMap::new);
/// Drained mail waiting in the new-contacts queue view, by identity: kept
/// out of the inbox until accepted (see [`super::queue`]).
pub(crate) static QUEUED: GlobalSignal<HashMap<Addr, HashSet<[u8; 32]>>> =
    Signal::global(HashMap::new);
pub(crate) static STATUS: GlobalSignal<HashMap<Addr, Status>> = Signal::global(HashMap::new);

thread_local! {
    static STARTED: RefCell<HashSet<Addr>> = RefCell::new(HashSet::new());
    /// Inboxes being drained, and whether a change arrived meanwhile.
    static BUSY: RefCell<HashMap<Addr, bool>> = RefCell::new(HashMap::new());
    /// Inboxes not drained for now (the offline queue fixture).
    static HELD: RefCell<HashSet<Addr>> = RefCell::new(HashSet::new());
}

fn set_status(addr: Addr, f: impl FnOnce(&mut Status)) {
    if dioxus::core::Runtime::try_current().is_some() {
        f(STATUS.write().entry(addr).or_default());
    }
}

pub(crate) fn status(addr: &Addr) -> Status {
    STATUS.read().get(addr).cloned().unwrap_or_default()
}

/// Start `addr`'s inbox for this page: create it if it has none, then
/// drain and follow it. Once per page and identity.
pub(crate) fn start(addr: Addr) {
    if !STARTED.with(|s| s.borrow_mut().insert(addr)) {
        return;
    }
    crate::app::identity_store::spawn_detached(async move {
        // Until it works: an unanswered GET is unknown, never "no inbox", so
        // nothing is created on it, and the next try asks again.
        for attempt in 0u32.. {
            match ensure(addr).await {
                Ok(()) => {
                    set_status(addr, |s| {
                        s.ready = true;
                        s.error = None;
                    });
                    refresh(addr).await;
                    #[cfg(all(
                        feature = "example-data",
                        not(feature = "use-node"),
                        target_family = "wasm"
                    ))]
                    if fixture("v2-foreign-fixture") {
                        net::offline::publish_foreign_version(&addr);
                    }
                    #[cfg(all(
                        feature = "example-data",
                        not(feature = "use-node"),
                        target_family = "wasm"
                    ))]
                    if fixture("v2-queue-fixture") {
                        fill_queue(addr).await;
                    }
                    return;
                }
                Err(e) => {
                    crate::log::error(format!("inbox v2: starting the inbox failed: {e}"), None);
                    set_status(addr, |s| s.error = Some(e));
                    ops::pause_ms(2_000u32.saturating_mul(1 << attempt.min(5))).await;
                }
            }
        }
    });
}

/// Offline builds only, for the Playwright suite with no second node:
/// `?v2-foreign-fixture` publishes each inbox at an owner version from
/// "another node" (decision 25); `?v2-queue-fixture` fills the first
/// identity's new-contacts queue from the second while the first does not
/// drain, as when its owner is away.
#[cfg(all(
    feature = "example-data",
    not(feature = "use-node"),
    target_family = "wasm"
))]
fn fixture(name: &str) -> bool {
    web_sys::window()
        .and_then(|w| w.location().search().ok())
        .is_some_and(|s| s.trim_start_matches('?').split('&').any(|p| p == name))
}

#[cfg(all(
    feature = "example-data",
    not(feature = "use-node"),
    target_family = "wasm"
))]
async fn fill_queue(addr: Addr) {
    thread_local!(static FILLED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) });
    if FILLED.with(|f| f.replace(true)) {
        return;
    }
    HELD.with(|h| h.borrow_mut().insert(addr));
    let other = loop {
        let ready = STARTED.with(|s| s.borrow().iter().copied().find(|a| *a != addr));
        if let Some(o) = ready.filter(|o| status(o).ready) {
            break o;
        }
        ops::pause_ms(200).await;
    };
    for i in 0..w::QUARANTINE_SLOTS {
        let body = MailBody {
            v: 1,
            label: Some("stranger".into()),
            title: format!("queued {i}"),
            content: "from the queue fixture".into(),
            time_ms: chrono::Utc::now().timestamp_millis(),
            thread_id: None,
            in_reply_to: None,
            quoted_excerpt: None,
        };
        let content = freenet_mail_protocol::SealContent::Mail(body.encode().into());
        super::send::send_content(other, addr, content).await;
    }
    HELD.with(|h| h.borrow_mut().remove(&addr));
    refresh(addr).await;
}

/// Make sure `addr` has a v2 inbox on the network, held and followed.
pub(crate) async fn ensure(addr: Addr) -> Result<(), String> {
    net::note_own(&addr);
    let record = ItemRef {
        kind: ItemKind::InboxV2,
        owner: Some(addr),
        id: Vec::new(),
    };
    let has_record = ops::get_item(record)
        .await
        .map_err(|e| e.to_string())?
        .is_some();
    // Unknown is never absent: a GET with no answer stops here.
    let existing = match net::get(&addr, true).await? {
        Got::State(s) => Some(s),
        Got::Missing => None,
    };
    if has_record {
        return republish(addr, existing.is_some()).await;
    }
    let reply = call(Op::CreateInboxV2 {
        addr,
        ghost_master: Hash32(super::ghost_master()),
        existing: existing.clone().map(Into::into),
    })
    .await;
    let state = match reply {
        Ok(Reply::InboxV2State(s)) => s.into_vec(),
        Ok(other) => return Err(unexpected(&other).to_string()),
        // Made by another tab or an earlier load whose answer was lost.
        Err(CallError::Failed(f))
            if matches!(f.code, freenet_mail_protocol::FailureCode::Conflict { .. }) =>
        {
            return republish(addr, existing.is_some()).await;
        }
        Err(e) => return Err(e.to_string()),
    };
    // If this PUT never lands (or this tab closes first), the next start finds
    // the record and no inbox, and publishes it from the delegate's record.
    net::put(&addr, state).await
}

/// The identity has an inbox record. If the network has no inbox (the first
/// PUT failed or never left, or the reply that carried the first state was
/// lost), the delegate signs it again from its record and it is published.
async fn republish(addr: Addr, on_network: bool) -> Result<(), String> {
    if on_network {
        return Ok(());
    }
    match call(Op::RepublishInboxV2 { addr }).await {
        Ok(Reply::InboxV2State(s)) => net::put(&addr, s.into_vec()).await,
        Ok(other) => Err(unexpected(&other).to_string()),
        Err(e) => Err(format!(
            "this identity's inbox could not be published again: {e}"
        )),
    }
}

/// The node or the page saw `addr`'s state change: drain it again.
pub(crate) fn changed(addr: Addr) {
    if !STARTED.with(|s| s.borrow().contains(&addr)) {
        return;
    }
    crate::app::identity_store::spawn_detached(refresh(addr));
}

/// A GET answered with `addr`'s state; nothing to do here beyond what the
/// drain that asked for it does.
pub(crate) fn state_seen(_addr: Addr, _state: Vec<u8>) {}

/// Drain `addr`'s inbox and show what it holds. A change that arrives while
/// this runs makes it run once more.
pub(crate) async fn refresh(addr: Addr) {
    if HELD.with(|h| h.borrow().contains(&addr)) {
        return;
    }
    let first = BUSY.with(|b| {
        let mut b = b.borrow_mut();
        match b.get_mut(&addr) {
            Some(again) => {
                *again = true;
                false
            }
            None => {
                b.insert(addr, false);
                true
            }
        }
    });
    if !first {
        return;
    }
    loop {
        if let Err(e) = drain(addr).await {
            crate::log::error(format!("inbox v2: draining failed: {e}"), None);
        }
        load_inbound(addr).await;
        let again = BUSY.with(|b| {
            let mut b = b.borrow_mut();
            let again = b.get(&addr).copied().unwrap_or(false);
            if again {
                b.insert(addr, false);
            } else {
                b.remove(&addr);
            }
            again
        });
        if !again {
            return;
        }
    }
}

/// Whether `state` holds mail not yet drained.
fn undrained(state: &InboxState) -> bool {
    state
        .messages
        .keys()
        .any(|id| !state.owner.tombstones.contains_key(id))
}

async fn drain(addr: Addr) -> Result<(), String> {
    // A bounded number of rounds; a later change drains the rest.
    let mut republished = false;
    for _ in 0..16 {
        let bytes = match net::get(&addr, true).await? {
            Got::State(s) => s,
            // A first PUT whose answer came but whose state went nowhere.
            // Once per drain: each one signs a new owner version.
            Got::Missing if !republished => {
                republish(addr, false).await?;
                republished = true;
                continue;
            }
            Got::Missing => return Ok(()),
        };
        let state: InboxState = w::decode(&bytes)?;
        note_owner(addr, &state).await;
        if !undrained(&state) {
            return Ok(());
        }
        let update = update_inbox(addr, bytes, OwnerChange::Drain).await?;
        if let Some(delta) = &update.update {
            net::update(&addr, delta.to_vec()).await?;
        }
        if update.remaining == 0 && update.update.is_none() {
            return Ok(());
        }
    }
    Ok(())
}

/// Sign `change` to `addr`'s inbox given its state.
pub(crate) async fn update_inbox(
    addr: Addr,
    state: Vec<u8>,
    change: OwnerChange,
) -> Result<freenet_mail_protocol::InboxV2Update, String> {
    match call(Op::UpdateInboxV2 {
        addr,
        state: state.into(),
        change,
        ui_entropy: super::entropy(),
    })
    .await
    {
        Ok(Reply::InboxV2Update(u)) => Ok(u),
        Ok(other) => Err(unexpected(&other).to_string()),
        Err(e) => Err(e.to_string()),
    }
}

/// The delegate's inbox record for `addr`.
pub(crate) async fn record(addr: Addr) -> Result<Option<InboxRecordView>, String> {
    let item = ItemRef {
        kind: ItemKind::InboxV2,
        owner: Some(addr),
        id: Vec::new(),
    };
    match ops::get_item(item).await.map_err(|e| e.to_string())? {
        Some(i) => from_cbor(&i.body).map(Some),
        None => Ok(None),
    }
}

/// Whether the inbox shows an owner record this node did not sign (decision
/// 25): the delegate noted one (a higher version, or its own version with
/// other bytes; the note stays when this node signs past it), or the state
/// holds a version above any the delegate recorded, which it notes at its
/// next change.
pub(crate) fn foreign(state_version: u64, record: &InboxRecordView) -> bool {
    record.foreign_seen.is_some() || state_version > record.max_version
}

/// Note what `state` says about the inbox. The record is read AFTER the
/// state, so a version this node signed is already in it.
async fn note_owner(addr: Addr, state: &InboxState) {
    let rec = record(addr).await;
    let waiting = state
        .messages
        .iter()
        .filter(|(id, m)| {
            matches!(m.admission, Admission::Quarantine { .. })
                && !state.owner.tombstones.contains_key(*id)
        })
        .count();
    set_status(addr, |s| {
        s.quarantine = Some(state.owner.quarantine);
        s.waiting_strangers = waiting;
        s.queue_was_full |= waiting >= w::QUARANTINE_SLOTS;
        if let Ok(Some(rec)) = &rec {
            s.strangers_dropped = rec.strangers_dropped;
            if foreign(state.owner.version, rec) {
                s.foreign_version = true;
            }
        }
    });
}

/// `addr`'s drained mail, as the delegate stores it.
pub(crate) async fn read_inbound(addr: Addr) -> Result<Vec<Inbound>, String> {
    let items = ops::list_all_items(ItemKind::Inbound, Some(addr))
        .await
        .map_err(|e| e.to_string())?;
    Ok(items
        .iter()
        .filter_map(|i| {
            let m = from_cbor::<InboundMessage>(&i.body).ok()?;
            let body = MailBody::decode(&m.body)?;
            Some(Inbound {
                id: m.id.into_array(),
                from: address_of(&m.sender_vk),
                sender_vk: m.sender_vk.into_vec(),
                admission: m.admission,
                body,
                item_id: i.item.id.clone(),
                generation: i.generation,
            })
        })
        .collect())
}

/// Read `addr`'s drained mail from the delegate and show it.
pub(crate) async fn load_inbound(addr: Addr) {
    let shown = match read_inbound(addr).await {
        Ok(shown) => shown,
        Err(e) => {
            crate::log::error(format!("inbox v2: listing drained mail failed: {e}"), None);
            return;
        }
    };
    super::contacts::note_drained(addr, &shown);
    let queued = match super::queue::queued(addr, &shown).await {
        Ok(q) => q,
        Err(e) => {
            // Unknown is not "accepted": hold every stranger's mail back.
            crate::log::error(format!("inbox v2: the new-contacts queue: {e}"), None);
            shown
                .iter()
                .filter(|m| m.admission == w::KIND_QUARANTINE)
                .map(|m| m.id)
                .collect()
        }
    };
    if dioxus::core::Runtime::try_current().is_some() {
        INBOUND.write().insert(addr, shown);
        QUEUED.write().insert(addr, queued);
    }
}

/// Where an inbox row's message is stored: its identity, and the item id and
/// generation of the delegate's copy.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct RowRef {
    pub owner: Addr,
    pub item_id: Vec<u8>,
    pub generation: u64,
}

thread_local! {
    /// Every v2 row the list has shown, by its row id: a row is never
    /// forgotten, so a refresh can tell the rows it replaces.
    static ROWS: RefCell<HashMap<u64, RowRef>> = RefCell::new(HashMap::new());
}

/// The list's id for drained message `m` of `owner`, remembered with where
/// its copy is stored. The local-state id of its first 16 bytes, so its read
/// mark and an archived copy are stored like any message's.
pub(crate) fn row_id(owner: Addr, m: &Inbound) -> u64 {
    let full: [u8; 16] = m.id[..16].try_into().expect("16 bytes");
    let id = crate::local_state::message_id_of(full);
    let r = RowRef {
        owner,
        item_id: m.item_id.clone(),
        generation: m.generation,
    };
    ROWS.with(|rows| rows.borrow_mut().insert(id, r));
    id
}

/// Where row `id`'s message is stored, if it is a v2 row.
pub(crate) fn row(id: u64) -> Option<RowRef> {
    ROWS.with(|rows| rows.borrow().get(&id).cloned())
}

/// Archive row `id`: `store` writes the archived copy, and only once it is
/// stored is the delegate's drained copy deleted.
/// On failure, whether the archived copy was stored, and why.
pub(crate) async fn archive_row(
    id: u64,
    store: impl std::future::Future<Output = Result<(), crate::DynError>>,
) -> Result<(), (bool, String)> {
    let r = row(id).ok_or((false, "this message is not loaded".to_string()))?;
    store
        .await
        .map_err(|e| (false, format!("the archived copy was not stored: {e}")))?;
    remove_stored(r).await.map_err(|e| (true, e))
}

/// Delete row `id`'s drained copy. The inbox already tombstoned it.
pub(crate) async fn delete_row(id: u64) -> Result<(), String> {
    remove_stored(row(id).ok_or("this message is not loaded")?).await
}

async fn remove_stored(r: RowRef) -> Result<(), String> {
    let item = ItemRef {
        kind: ItemKind::Inbound,
        owner: Some(r.owner),
        id: r.item_id,
    };
    ops::delete_item(item, r.generation)
        .await
        .map_err(|e| e.to_string())?;
    load_inbound(r.owner).await;
    Ok(())
}

/// `addr`'s drained mail: in the inbox (`queued` false) or waiting in the
/// new-contacts queue view (`queued` true).
pub(crate) fn inbound(addr: &Addr, queued: bool) -> Vec<Inbound> {
    if dioxus::core::Runtime::try_current().is_none() {
        return Vec::new();
    }
    let held = QUEUED.read().get(addr).cloned().unwrap_or_default();
    let mail = INBOUND.read().get(addr).cloned().unwrap_or_default();
    mail.into_iter()
        .filter(|m| held.contains(&m.id) == queued)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_version_above_the_record_is_another_nodes() {
        let rec = InboxRecordView {
            max_version: 7,
            ..Default::default()
        };
        assert!(!foreign(7, &rec));
        assert!(!foreign(3, &rec));
        assert!(foreign(8, &rec));
    }

    /// Decision 25 survives this node signing past the other version: the
    /// delegate's note keeps the warning up, on every load.
    #[test]
    fn a_record_that_saw_another_node_keeps_the_warning() {
        let rec = InboxRecordView {
            max_version: 9,
            foreign_seen: Some(super::super::ForeignSeenView { version: 5, at: 1 }),
            ..Default::default()
        };
        assert!(foreign(9, &rec));
    }
}
