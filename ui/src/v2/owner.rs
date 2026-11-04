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
    pub error: Option<String>,
}

/// Drained mail by identity.
pub(crate) static INBOUND: GlobalSignal<HashMap<Addr, Vec<Inbound>>> = Signal::global(HashMap::new);
pub(crate) static STATUS: GlobalSignal<HashMap<Addr, Status>> = Signal::global(HashMap::new);

thread_local! {
    static STARTED: RefCell<HashSet<Addr>> = RefCell::new(HashSet::new());
    /// Inboxes being drained, and whether a change arrived meanwhile.
    static BUSY: RefCell<HashMap<Addr, bool>> = RefCell::new(HashMap::new());
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
        for attempt in 0..5u32 {
            match ensure(addr).await {
                Ok(()) => {
                    set_status(addr, |s| {
                        s.ready = true;
                        s.error = None;
                    });
                    refresh(addr).await;
                    return;
                }
                Err(e) => {
                    crate::log::error(format!("inbox v2: starting the inbox failed: {e}"), None);
                    set_status(addr, |s| s.error = Some(e));
                    ops::pause_ms(2_000 * 2u32.pow(attempt)).await;
                }
            }
        }
    });
}

/// Make sure `addr` has a v2 inbox on the network, held and followed.
async fn ensure(addr: Addr) -> Result<(), String> {
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
    match (has_record, existing) {
        (true, Some(_)) => Ok(()),
        (true, None) => {
            Err("this identity's inbox is not on the network; it will be looked for again".into())
        }
        (false, existing) => {
            let reply = call(Op::CreateInboxV2 {
                addr,
                ghost_master: Hash32(super::ghost_master()),
                existing: existing.map(Into::into),
            })
            .await;
            let state = match reply {
                Ok(Reply::InboxV2State(s)) => s.into_vec(),
                Ok(other) => return Err(unexpected(&other).to_string()),
                // Made by another tab or an earlier load whose answer was lost.
                Err(CallError::Failed(f))
                    if matches!(f.code, freenet_mail_protocol::FailureCode::Conflict { .. }) =>
                {
                    return Ok(());
                }
                Err(e) => return Err(e.to_string()),
            };
            net::put(&addr, state).await
        }
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
    for _ in 0..16 {
        let bytes = match net::get(&addr, true).await? {
            Got::State(s) => s,
            Got::Missing => return Err("the inbox is not on the network".into()),
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

/// Whether an owner version in a state is one this node signed: the
/// delegate records each version before the update carrying it leaves, so
/// one above its record came from somewhere else (decision 25).
pub(crate) fn foreign(state_version: u64, record: &InboxRecordView) -> bool {
    state_version > record.max_version
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
        if let Ok(Some(rec)) = &rec {
            s.strangers_dropped = rec.strangers_dropped;
            if foreign(state.owner.version, rec) {
                s.foreign_version = true;
            }
        }
    });
}

/// Read `addr`'s drained mail from the delegate and show it.
pub(crate) async fn load_inbound(addr: Addr) {
    let items = match ops::list_all_items(ItemKind::Inbound, Some(addr)).await {
        Ok(items) => items,
        Err(e) => {
            crate::log::error(format!("inbox v2: listing drained mail failed: {e}"), None);
            return;
        }
    };
    let shown: Vec<Inbound> = items
        .iter()
        .filter_map(|i| from_cbor::<InboundMessage>(&i.body).ok())
        .filter_map(|m| {
            let body = MailBody::decode(&m.body)?;
            Some(Inbound {
                id: m.id.into_array(),
                from: address_of(&m.sender_vk),
                sender_vk: m.sender_vk.into_vec(),
                admission: m.admission,
                body,
            })
        })
        .collect();
    super::contacts::note_drained(addr, &shown);
    if dioxus::core::Runtime::try_current().is_some() {
        INBOUND.write().insert(addr, shown);
    }
}

/// `addr`'s drained mail.
pub(crate) fn inbound(addr: &Addr) -> Vec<Inbound> {
    INBOUND.read().get(addr).cloned().unwrap_or_default()
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
}
