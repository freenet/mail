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
#[cfg(test)]
use freenet_mail_protocol::SendAdmission;
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
    /// Drained messages stored but not decodable, so not shown.
    pub unreadable_mail: usize,
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
    /// The identities started on this page, each with the generation of the
    /// start loop that serves it: deleting the identity removes it, and a
    /// loop whose generation is no longer here stops.
    static STARTED: RefCell<HashMap<Addr, u64>> = RefCell::new(HashMap::new());
    static NEXT_GEN: std::cell::Cell<u64> = const { std::cell::Cell::new(1) };
    /// Inboxes being drained, and whether a change arrived meanwhile.
    static BUSY: RefCell<HashMap<Addr, bool>> = RefCell::new(HashMap::new());
    /// Inboxes not drained for now (the offline queue fixture).
    static HELD: RefCell<HashSet<Addr>> = RefCell::new(HashSet::new());
}

#[cfg(test)]
thread_local! {
    /// Tests with no Dioxus runtime: the status the page would show.
    static TEST_STATUS: RefCell<HashMap<Addr, Status>> = RefCell::new(HashMap::new());
}

fn set_status(addr: Addr, f: impl FnOnce(&mut Status)) {
    if dioxus::core::Runtime::try_current().is_some() {
        f(STATUS.write().entry(addr).or_default());
    } else {
        #[cfg(test)]
        TEST_STATUS.with(|s| f(s.borrow_mut().entry(addr).or_default()));
    }
}

pub(crate) fn status(addr: &Addr) -> Status {
    #[cfg(test)]
    if dioxus::core::Runtime::try_current().is_none() {
        return TEST_STATUS.with(|s| s.borrow().get(addr).cloned().unwrap_or_default());
    }
    STATUS.read().get(addr).cloned().unwrap_or_default()
}

/// Start `addr`'s inbox for this page: create it if it has none, then
/// drain and follow it. Once per page and identity: restoring a deleted
/// identity starts one new loop, and the deleted one's loop stops.
pub(crate) fn start(addr: Addr) {
    let Some(generation) = begin(addr) else {
        return;
    };
    crate::app::identity_store::spawn_detached(run(addr, generation));
}

/// Mark `addr` started, with a new generation; `None` if it already is.
fn begin(addr: Addr) -> Option<u64> {
    STARTED.with(|s| {
        let mut s = s.borrow_mut();
        if s.contains_key(&addr) {
            return None;
        }
        let generation = NEXT_GEN.with(|n| n.replace(n.get() + 1));
        s.insert(addr, generation);
        Some(generation)
    })
}

/// What a start loop that is no longer current returns.
const STOPPED: &str = "this identity was deleted";

/// Whether the loop of `generation` still serves `addr`, after an await:
/// the identity was not deleted (nor deleted and restored) meanwhile.
fn checkpoint(addr: Addr, generation: Option<u64>, _at: &str) -> Result<(), String> {
    #[cfg(test)]
    CHECKPOINT.with(|c| {
        if let Some(f) = c.borrow_mut().as_mut() {
            f(addr, _at);
        }
    });
    match generation {
        Some(g) if STARTED.with(|s| s.borrow().get(&addr) != Some(&g)) => Err(STOPPED.into()),
        _ => Ok(()),
    }
}

#[cfg(test)]
type CheckpointHook = Box<dyn FnMut(Addr, &str)>;

#[cfg(test)]
thread_local! {
    /// Tests: called at each checkpoint of a start loop, before the check.
    static CHECKPOINT: RefCell<Option<CheckpointHook>> = RefCell::new(None);
}

/// The start loop of `addr` at `generation`.
async fn run(addr: Addr, generation: u64) {
    let current = || checkpoint(addr, Some(generation), "loop").is_ok();
    // Until it works: an unanswered GET is unknown, never "no inbox", so
    // nothing is created on it, and the next try asks again.
    for attempt in 0u32.. {
        if !current() {
            return;
        }
        match ensure_for(addr, Some(generation)).await {
            Ok(()) => {
                if !current() {
                    return;
                }
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
                    another_node_signs(addr).await;
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
                if !current() {
                    return;
                }
                crate::log::error(format!("inbox v2: starting the inbox failed: {e}"), None);
                set_status(addr, |s| s.error = Some(e));
                ops::pause_ms(2_000u32.saturating_mul(1 << attempt.min(5))).await;
            }
        }
    }
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
        let ready = STARTED.with(|s| s.borrow().keys().copied().find(|a| *a != addr));
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

/// Offline builds' decision-25 fixture: another node signs for `addr`, and
/// this node's delegate signs past it before the page reads the inbox, so
/// the warning can come only from the delegate's note (`foreign_seen`),
/// never from comparing versions. While `addr` is held, the next identity
/// started here writes to it; "another node" (the same identity's keys,
/// from its recovery key, as a restored copy would hold them) signs the
/// owner record 1000 versions on over that state; the delegate drains it,
/// noting the record, and its update signs a version past it.
#[cfg(all(
    feature = "example-data",
    not(feature = "use-node"),
    target_family = "wasm"
))]
async fn another_node_signs(addr: Addr) {
    thread_local!(static SIGNED: RefCell<HashSet<Addr>> = RefCell::new(HashSet::new()));
    if !SIGNED.with(|s| s.borrow_mut().insert(addr)) {
        return;
    }
    let other = loop {
        let ready = STARTED.with(|s| s.borrow().keys().copied().find(|a| *a != addr));
        if let Some(o) = ready.filter(|o| status(o).ready) {
            break o;
        }
        ops::pause_ms(200).await;
    };
    if let Err(e) = another_node_signs_with(addr, other).await {
        crate::log::error(
            format!("inbox v2: the foreign-node fixture failed: {e}"),
            None,
        );
    }
}

/// [`another_node_signs`], with `other` the identity that writes.
#[cfg(all(not(feature = "use-node"), any(test, feature = "example-data")))]
pub(crate) async fn another_node_signs_with(addr: Addr, other: Addr) -> Result<(), String> {
    HELD.with(|h| h.borrow_mut().insert(addr));
    let result = async {
        let body = MailBody {
            v: 1,
            label: None,
            title: "while another node signed".into(),
            content: "from the foreign-node fixture".into(),
            time_ms: chrono::Utc::now().timestamp_millis(),
            thread_id: None,
            in_reply_to: None,
            quoted_excerpt: None,
        };
        let content = freenet_mail_protocol::SealContent::Mail(body.encode().into());
        super::send::send_content(other, addr, content).await;
        let key = ops::export_recovery_key(addr)
            .await
            .map_err(|e| e.to_string())?;
        let (dsa, kem) =
            freenet_mail_protocol::recovery_key::decode(key.as_str()).map_err(|e| e.to_string())?;
        let keys = mail_delegate::crypto::Keys::from_seeds(&dsa, &kem);
        let Got::State(bytes) = net::get(&addr, false).await? else {
            return Err("no inbox".into());
        };
        let mut state: InboxState = w::decode(&bytes)?;
        state.owner.version += 1_000;
        state.owner.sig = keys
            .sign_v2(w::OWNER_SIG_CONTEXT, &w::owner_bytes(&addr.0, &state.owner))
            .into();
        let theirs = w::encode(&state);
        net::offline::store_unannounced(&addr, theirs.clone());
        let update = update_inbox(addr, theirs, OwnerChange::Drain).await?;
        let delta = update.update.ok_or("the drain signed nothing")?;
        net::update(&addr, delta.to_vec()).await.map_err(Into::into)
    }
    .await;
    HELD.with(|h| h.borrow_mut().remove(&addr));
    refresh(addr).await;
    result
}

/// Take a deleted identity out of this page's v2 state: its started mark
/// (so restoring the same key starts a fresh drain), the drain and hold
/// marks, drained mail and its queue view, status, the rows shown for it,
/// the routing of its inbox's changes, and what the page saw of its passes.
/// Without this, restoring the key without a reload would find the identity
/// "started" and show the old messages.
pub(crate) fn forget(addr: Addr) {
    STARTED.with(|s| s.borrow_mut().remove(&addr));
    BUSY.with(|b| b.borrow_mut().remove(&addr));
    HELD.with(|h| h.borrow_mut().remove(&addr));
    ROWS.with(|r| r.borrow_mut().retain(|_, row| row.owner != addr));
    net::forget_own_route(&addr);
    super::contacts::forget_identity(&addr);
    if dioxus::core::Runtime::try_current().is_some() {
        INBOUND.write().remove(&addr);
        QUEUED.write().remove(&addr);
        STATUS.write().remove(&addr);
    }
    #[cfg(test)]
    TEST_STATUS.with(|s| s.borrow_mut().remove(&addr));
}

/// Tests: what a page that has just loaded knows of `addr`'s inbox.
#[cfg(all(test, not(feature = "use-node")))]
pub(crate) fn forget_status(addr: Addr) {
    set_status(addr, |s| *s = Status::default());
}

/// Make sure `addr` has a v2 inbox on the network, held and followed, with
/// no start loop to stop (tests).
#[cfg(all(test, not(feature = "use-node")))]
pub(crate) async fn ensure(addr: Addr) -> Result<(), String> {
    ensure_for(addr, None).await
}

/// [`ensure`] for the start loop of `generation`: after each await it
/// stops if the identity was deleted meanwhile, so a deleted identity's
/// inbox is never created, published or reported on.
async fn ensure_for(addr: Addr, generation: Option<u64>) -> Result<(), String> {
    let at = |name| checkpoint(addr, generation, name);
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
    at("record read")?;
    // Unknown is never absent: a GET with no answer stops here.
    let existing = match net::get(&addr, true).await? {
        Got::State(s) => Some(s),
        Got::Missing => None,
    };
    at("inbox read")?;
    if has_record {
        return republish_for(addr, existing.is_some(), generation).await;
    }
    let reply = call(Op::CreateInboxV2 {
        addr,
        ghost_master: Hash32(super::ghost_master()),
        existing: existing.clone().map(Into::into),
    })
    .await;
    at("created")?;
    let state = match reply {
        Ok(Reply::InboxV2State(s)) => s.into_vec(),
        Ok(other) => return Err(unexpected(&other).to_string()),
        // Made by another tab or an earlier load whose answer was lost.
        Err(CallError::Failed(f))
            if matches!(f.code, freenet_mail_protocol::FailureCode::Conflict { .. }) =>
        {
            return republish_for(addr, existing.is_some(), generation).await;
        }
        Err(e) => return Err(e.to_string()),
    };
    // If this PUT never lands (or this tab closes first), the next start finds
    // the record and no inbox, and publishes it from the delegate's record.
    publish(addr, state).await
}

/// PUT a new or republished inbox, and once it lands ask the delegate to run
/// its jobs: the node holds the contract now, so they subscribe it. The
/// delegate does not subscribe on its own at create or republish (the node
/// may not hold the contract yet, and that would be a network fetch that
/// parks it), so without this, mail that arrives first waits for the next
/// wake-up. A failed `RunJobs` is only logged: the next wake-up does the same.
async fn publish(addr: Addr, state: Vec<u8>) -> Result<(), String> {
    net::put(&addr, state).await?;
    if let Err(e) = ops::run_jobs().await {
        crate::log::error(
            format!("inbox v2: the jobs run after publishing failed: {e}"),
            None,
        );
    }
    Ok(())
}

/// The identity has an inbox record. If the network has no inbox (the first
/// PUT failed or never left, or the reply that carried the first state was
/// lost), the delegate signs it again from its record and it is published.
async fn republish(addr: Addr, on_network: bool) -> Result<(), String> {
    republish_for(addr, on_network, None).await
}

/// [`republish`] for the start loop of `generation` (see [`ensure_for`]).
async fn republish_for(
    addr: Addr,
    on_network: bool,
    generation: Option<u64>,
) -> Result<(), String> {
    if on_network {
        return Ok(());
    }
    let reply = call(Op::RepublishInboxV2 { addr }).await;
    checkpoint(addr, generation, "signed again")?;
    match reply {
        Ok(Reply::InboxV2State(s)) => publish(addr, s.into_vec()).await,
        Ok(other) => Err(unexpected(&other).to_string()),
        Err(e) => Err(format!(
            "this identity's inbox could not be published again: {e}"
        )),
    }
}

/// The node or the page saw `addr`'s state change: drain it again.
pub(crate) fn changed(addr: Addr) {
    if !STARTED.with(|s| s.borrow().contains_key(&addr)) {
        return;
    }
    // Tests with no Dioxus runtime drain by calling `refresh` themselves.
    #[cfg(test)]
    if dioxus::core::Runtime::try_current().is_none() {
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
    // The identity may be deleted, or deleted and restored, while this runs:
    // after each await the start generation is checked, and a changed one
    // drops the result (`forget` already cleared the marks this run set).
    let generation = STARTED.with(|s| s.borrow().get(&addr).copied());
    loop {
        match drain(addr, generation).await {
            Err(e) if e == STOPPED => return,
            Err(e) => crate::log::error(format!("inbox v2: draining failed: {e}"), None),
            Ok(()) => {}
        }
        if !load_inbound_for(addr, generation).await {
            return;
        }
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

async fn drain(addr: Addr, generation: Option<u64>) -> Result<(), String> {
    // A bounded number of rounds; a later change drains the rest.
    let mut republished = false;
    for _ in 0..16 {
        let got = net::get(&addr, true).await;
        checkpoint(addr, generation, "refresh read")?;
        let bytes = match got? {
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
        note_owner(addr, generation, &state).await;
        checkpoint(addr, generation, "refresh noted")?;
        if !undrained(&state) {
            return Ok(());
        }
        let update = update_inbox(addr, bytes, OwnerChange::Drain).await;
        checkpoint(addr, generation, "refresh signed")?;
        let update = update?;
        if let Some(delta) = &update.update {
            let sent = net::update(&addr, delta.to_vec()).await;
            checkpoint(addr, generation, "refresh sent")?;
            sent?;
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
async fn note_owner(addr: Addr, generation: Option<u64>, state: &InboxState) {
    let rec = record(addr).await;
    if checkpoint(addr, generation, "refresh record").is_err() {
        return;
    }
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

/// `addr`'s drained mail, as the delegate stores it. A stored message that
/// does not decode is counted in the status (`unreadable_mail`), so the page
/// says mail could not be shown rather than leaving it out unsaid.
pub(crate) async fn read_inbound(addr: Addr) -> Result<Vec<Inbound>, String> {
    let items = ops::list_all_items(ItemKind::Inbound, Some(addr))
        .await
        .map_err(|e| e.to_string())?;
    let (mail, unreadable) = parse_inbound(&items);
    if unreadable > 0 {
        crate::log::error(
            format!("inbox v2: {unreadable} drained messages could not be read"),
            None,
        );
    }
    set_status(addr, |s| s.unreadable_mail = unreadable);
    Ok(mail)
}

/// The drained messages in `items`, and how many did not decode.
fn parse_inbound(items: &[freenet_mail_protocol::Item]) -> (Vec<Inbound>, usize) {
    let mut mail = Vec::with_capacity(items.len());
    for i in items {
        let Some((m, body)) = from_cbor::<InboundMessage>(&i.body)
            .ok()
            .and_then(|m| MailBody::decode(&m.body).map(|b| (m, b)))
        else {
            continue;
        };
        mail.push(Inbound {
            id: m.id.into_array(),
            from: address_of(&m.sender_vk),
            sender_vk: m.sender_vk.into_vec(),
            admission: m.admission,
            body,
            item_id: i.item.id.clone(),
            generation: i.generation,
        });
    }
    let unreadable = items.len() - mail.len();
    (mail, unreadable)
}

/// Read `addr`'s drained mail from the delegate and show it.
pub(crate) async fn load_inbound(addr: Addr) {
    let generation = STARTED.with(|s| s.borrow().get(&addr).copied());
    load_inbound_for(addr, generation).await;
}

/// [`load_inbound`] for a run of start `generation`: false if the identity
/// was deleted (or restored) meanwhile, and nothing was shown.
async fn load_inbound_for(addr: Addr, generation: Option<u64>) -> bool {
    let read = read_inbound(addr).await;
    if checkpoint(addr, generation, "inbound read").is_err() {
        return false;
    }
    let shown = match read {
        Ok(shown) => shown,
        Err(e) => {
            crate::log::error(format!("inbox v2: listing drained mail failed: {e}"), None);
            return true;
        }
    };
    let queued = super::queue::queued(addr, &shown).await;
    if checkpoint(addr, generation, "queue read").is_err() {
        return false;
    }
    super::contacts::note_drained(addr, &shown);
    let queued = match queued {
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
    true
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

/// Delete row `id` of `alias` (its name or state key) and every copy of it:
/// the kept copy its read mark wrote, an archived copy, the delegate's
/// drained copy (the inbox already tombstoned it), and last the deleted mark
/// in its flags. The copies go before the mark, so a failure leaves the
/// message showing where a retry finds it, never a stored copy hidden by a
/// mark, and never a copy a reload brings back.
pub(crate) async fn delete_row(alias: String, id: u64) -> Result<(), String> {
    let r = row(id).ok_or("this message is not loaded")?;
    crate::local_state::delete_message_after_copies(alias, id, async || {
        remove_stored(r).await.map_err(Into::into)
    })
    .await
    .map_err(|e| e.to_string())
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

    /// Deleting an identity clears its v2 page state, so restoring the same
    /// key without a reload starts cleanly and shows nothing stale.
    #[test]
    fn deleting_an_identity_clears_its_v2_page_state() {
        let (a, other) = (Addr([71; 24]), Addr([72; 24]));
        for addr in [a, other] {
            STARTED.with(|s| s.borrow_mut().insert(addr, 1));
            BUSY.with(|b| b.borrow_mut().insert(addr, true));
            HELD.with(|h| h.borrow_mut().insert(addr));
            net::note_own(&addr);
            set_status(addr, |s| {
                s.ready = true;
                s.error = Some("stale".into());
            });
            let id = 1000 + u64::from(addr.0[0]);
            ROWS.with(|r| {
                r.borrow_mut().insert(
                    id,
                    RowRef {
                        owner: addr,
                        item_id: vec![1],
                        generation: 1,
                    },
                )
            });
        }
        super::super::contacts::note_send(a, Addr([9; 24]), SendAdmission::Pass, None);

        crate::app::identity_store::forget_everywhere(&a);

        assert!(STARTED.with(|s| !s.borrow().contains_key(&a)), "STARTED");
        assert!(BUSY.with(|b| !b.borrow().contains_key(&a)), "BUSY");
        assert!(HELD.with(|h| !h.borrow().contains(&a)), "HELD");
        assert!(row(1000 + 71).is_none(), "rows");
        assert!(!net::is_own(&a), "routing");
        assert!(!status(&a).ready && status(&a).error.is_none(), "status");
        assert_eq!(
            super::super::contacts::held(a, Addr([9; 24])),
            super::super::contacts::PassState::None,
            "passes seen"
        );
        // Another identity is untouched.
        assert!(STARTED.with(|s| s.borrow().contains_key(&other)));
        assert!(row(1000 + 72).is_some());
        assert!(net::is_own(&other));
        assert!(status(&other).ready);
        // The same key restored starts a fresh drain.
        assert!(begin(a).is_some());
    }

    /// Class A: a stored message that does not decode is counted, never left
    /// out unsaid; the others are still shown.
    #[test]
    fn an_undecodable_drained_message_is_counted() {
        let item = |id: u8, body: Vec<u8>| freenet_mail_protocol::Item {
            item: ItemRef {
                kind: ItemKind::Inbound,
                owner: Some(Addr([1; 24])),
                id: vec![id; 32],
            },
            body: body.into(),
            generation: 1,
        };
        let good = InboundMessage {
            id: serde_bytes::ByteArray::new([2; 32]),
            sender_vk: vec![3; 32].into(),
            sent_time: 0,
            admission: w::KIND_PASS,
            ghost_vk: None,
            body: MailBody {
                v: 1,
                label: None,
                title: "readable".into(),
                content: String::new(),
                time_ms: 0,
                thread_id: None,
                in_reply_to: None,
                quoted_excerpt: None,
            }
            .encode()
            .into(),
        };
        let items = [
            item(2, freenet_mail_protocol::to_cbor(&good).unwrap()),
            item(4, b"not a message".to_vec()),
        ];
        let (mail, unreadable) = parse_inbound(&items);
        assert_eq!(mail.len(), 1);
        assert_eq!(mail[0].body.title, "readable");
        assert_eq!(unreadable, 1);
    }

    #[cfg(all(feature = "local-delegate", not(feature = "use-node")))]
    fn new_identity(alias: &str) -> Addr {
        let (info, _) =
            futures::executor::block_on(ops::create_identity(alias.into(), String::new())).unwrap();
        info.addr
    }

    #[cfg(all(feature = "local-delegate", not(feature = "use-node")))]
    fn has_inbox(addr: Addr) -> bool {
        let record = ItemRef {
            kind: ItemKind::InboxV2,
            owner: Some(addr),
            id: Vec::new(),
        };
        let on_network = futures::executor::block_on(net::get(&addr, false)).unwrap();
        futures::executor::block_on(ops::get_item(record))
            .unwrap()
            .is_some()
            || on_network != Got::Missing
    }

    /// P2: an identity deleted while its start loop waits stops the loop at
    /// its next await, at each of them: no inbox is created or published for
    /// it, and no status comes back for it.
    #[cfg(all(feature = "local-delegate", not(feature = "use-node")))]
    #[test]
    fn deleting_an_identity_during_startup_stops_its_loop() {
        for (n, stop_at) in ["record read", "inbox read"].into_iter().enumerate() {
            let a = new_identity(&format!("v2-stop-{n}"));
            let generation = begin(a).unwrap();
            CHECKPOINT.with(|c| {
                *c.borrow_mut() = Some(Box::new(move |addr, at| {
                    if addr == a && at == stop_at {
                        forget(a);
                    }
                }))
            });
            futures::executor::block_on(run(a, generation));
            CHECKPOINT.with(|c| c.borrow_mut().take());
            assert!(
                !has_inbox(a),
                "an inbox was made after a delete at {stop_at}"
            );
            assert_eq!(status(&a), Status::default(), "status came back");
        }
    }

    /// P2: an identity deleted and restored during startup: the old loop
    /// stops, the restore starts exactly one new one, and that one makes
    /// the inbox.
    #[cfg(all(feature = "local-delegate", not(feature = "use-node")))]
    #[test]
    fn a_restored_identity_runs_exactly_one_start_loop() {
        let a = new_identity("v2-restore");
        let old = begin(a).unwrap();
        let restored = std::rc::Rc::new(std::cell::Cell::new(None));
        let r = restored.clone();
        CHECKPOINT.with(|c| {
            *c.borrow_mut() = Some(Box::new(move |addr, at| {
                if addr == a && at == "record read" && r.get().is_none() {
                    forget(a);
                    r.set(Some(begin(a)));
                }
            }))
        });
        futures::executor::block_on(run(a, old));
        CHECKPOINT.with(|c| c.borrow_mut().take());
        assert!(!has_inbox(a), "the deleted identity's loop went on");
        let new = restored
            .get()
            .flatten()
            .expect("the restore started a loop");
        assert_eq!(begin(a), None, "a second start for the same key");
        futures::executor::block_on(run(a, new));
        assert!(has_inbox(a), "the restored identity's loop made its inbox");
        assert!(status(&a).ready);
    }

    /// A refresh running while its identity is deleted and restored drops its
    /// result: the old drain's state does not come back under the new start.
    #[cfg(all(feature = "local-delegate", not(feature = "use-node")))]
    #[test]
    fn a_refresh_across_a_delete_and_restore_leaves_no_stale_state() {
        let a = new_identity("v2-refresh-restore");
        let first = begin(a).unwrap();
        futures::executor::block_on(run(a, first));
        assert!(status(&a).ready);
        let fired = std::rc::Rc::new(std::cell::Cell::new(false));
        let f = fired.clone();
        CHECKPOINT.with(|c| {
            *c.borrow_mut() = Some(Box::new(move |addr, at| {
                if addr == a && at == "refresh read" && !f.get() {
                    f.set(true);
                    forget(a);
                    begin(a);
                }
            }))
        });
        futures::executor::block_on(refresh(a));
        CHECKPOINT.with(|c| c.borrow_mut().take());
        assert!(fired.get(), "the refresh never reached its checkpoint");
        assert_eq!(status(&a), Status::default(), "stale status came back");
    }

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
