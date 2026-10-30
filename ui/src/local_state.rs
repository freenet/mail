//! UI-side mirror of the local mail state the mail delegate stores (drafts,
//! sent, kept and archived messages, read/deleted marks, settings).
//!
//! Holds a `LocalState` snapshot, loaded once per page from the delegate's
//! items (`items::load`) and patched optimistically by every change, plus a
//! Dioxus signal generation counter that components subscribe to so they
//! re-render when drafts / read-state / kept messages change. Each change is
//! also written to the delegate as items owned by the identity's address
//! (`items`), acknowledged per request.
//!
//! Per-device only (issue #47, 47a); per-alias scoping happens inside the
//! `LocalState` value (`AliasState` keyed by alias string).

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use dioxus::prelude::*;
use freenet_mail_wire_v1::local_state::{
    ArchivedMessage, DeliveryState, Draft, GlobalSettings, IdentitySettings, KeptMessage,
    LocalState, MessageId, SentMessage,
};

thread_local! {
    /// The page's view of local mail state. Filled once per page by
    /// `items::load`; every change patches it here and is written to its
    /// item in the mail delegate, which acknowledges it.
    ///
    /// The optimistic stashes below were written for the v0.2.x delegate,
    /// which echoed whole snapshots that could predate a change. Items are
    /// not echoed any more, so the stashes now matter in one place only:
    /// the startup merge ([`merge_loaded`]), where a load that began before a
    /// change could otherwise undo it. Their "echo" wording below means that
    /// load.
    static SNAPSHOT: RefCell<LocalState> = RefCell::new(LocalState::default());

    /// Draft ids the UI has optimistically deleted. Stale `replace_snapshot`
    /// echoes — e.g. an in-flight `save_draft` whose response lands after the
    /// `delete_draft` was issued — would otherwise resurrect them. Kept until
    /// the delegate echoes a snapshot that no longer contains the id (#107).
    /// Key: (alias, draft_id).
    static DELETED_DRAFTS: RefCell<HashSet<(String, String)>> = RefCell::new(HashSet::new());

    /// Optimistic `local_mark_read` writes that haven't yet round-tripped
    /// through the delegate. A stale `GetAll` echo that lands BEFORE the
    /// `MarkRead` write was persisted would otherwise clobber them, and
    /// the inbox-list rebuild path (`kept_for`) would return empty — the
    /// row evaporates from the UI even though the contract has already
    /// evicted it (#113). Held until an echo includes the kept entry.
    /// Key: (alias, msg_id_string).
    static PENDING_KEPT: RefCell<HashMap<(String, String), KeptMessage>> =
        RefCell::new(HashMap::new());

    /// Optimistic `local_save_sent` writes that haven't round-tripped through
    /// the delegate. A stale `GetAll` echo landing before the `SaveSent` write
    /// persists would wipe the Sent stash and the message re-derives as a
    /// Draft (#265 — "Sent → Draft after reload"). Re-merged into the snapshot
    /// on every echo until the echo itself contains the entry.
    /// Key: (alias, sent_id).
    static OPTIMISTIC_SENT: RefCell<HashMap<(String, String), SentMessage>> =
        RefCell::new(HashMap::new());

    /// Optimistic `local_archive_message` writes not yet round-tripped. Without
    /// this, a stale echo bounces the archived message back to the Inbox
    /// (#265). Re-merged until the echo includes the archived entry.
    /// Key: (alias, msg_id_string).
    static OPTIMISTIC_ARCHIVED: RefCell<HashMap<(String, String), ArchivedMessage>> =
        RefCell::new(HashMap::new());

    /// Message ids the UI has optimistically deleted. A stale `GetAll` echo
    /// predating the `DeleteMessage` write would otherwise resurrect the
    /// message (#265 — "deleted messages return"). Re-applied to the snapshot's
    /// `deleted` list (and the kept/archived entries re-removed) until the echo
    /// itself records the deletion. Key: (alias, msg_id).
    static DELETED_MESSAGES: RefCell<HashSet<(String, MessageId)>> = RefCell::new(HashSet::new());

    /// Every change made in this page while a load from the delegate runs,
    /// numbered, so the load can be applied underneath them ([`merge_loaded`]).
    static JOURNAL: RefCell<Vec<(u64, Change)>> = const { RefCell::new(Vec::new()) };
    /// Number of the next journal entry.
    static NEXT_CHANGE: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// Loads in flight; the journal is kept only while there is one.
    static LOADS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// One change to the local state, as the page made it.
#[derive(Clone)]
enum Change {
    SaveDraft(String, String, Draft),
    DeleteDraft(String, String),
    SaveSent(String, String, SentMessage),
    DeleteSent(String, String),
    SentDelivery(String, String, DeliveryState),
    Archive(String, MessageId, ArchivedMessage),
    Unarchive(String, MessageId),
    DeleteMessage(String, MessageId),
    MarkRead(String, MessageId, KeptMessage),
    /// The fields that differ between the two values changed.
    IdentitySettings(String, IdentitySettings, IdentitySettings),
    GlobalSettings(GlobalSettings, GlobalSettings),
    /// Everything kept for one identity (a state key, [`addr_key`]). There
    /// is no rename change: an identity's key is its address, which a
    /// rename does not touch.
    Forget(String),
}

/// Apply `change` to `state` exactly as the page applied it to its
/// snapshot. Settings changes set only the fields the change touched.
fn apply(state: &mut LocalState, change: &Change) {
    match change {
        Change::SaveDraft(alias, id, draft) => {
            let entry = state.aliases_mut().entry(alias.clone()).or_default();
            entry.drafts.insert(id.clone(), draft.clone());
        }
        Change::DeleteDraft(alias, id) => {
            if let Some(entry) = state.aliases_mut().get_mut(alias) {
                entry.drafts.remove(id);
            }
        }
        Change::SaveSent(alias, id, sent) => {
            let entry = state.aliases_mut().entry(alias.clone()).or_default();
            entry.sent.insert(id.clone(), sent.clone());
        }
        Change::DeleteSent(alias, id) => {
            if let Some(entry) = state.aliases_mut().get_mut(alias) {
                entry.sent.remove(id);
            }
        }
        Change::SentDelivery(alias, id, delivery) => {
            if let Some(sent) = state
                .aliases_mut()
                .get_mut(alias)
                .and_then(|entry| entry.sent.get_mut(id))
                && !delivery_state_is_terminal(sent.delivery_state)
            {
                sent.delivery_state = *delivery;
            }
        }
        Change::Archive(alias, msg_id, archived) => {
            // Archiving implies read, drops any kept fallback for the same id,
            // and stashes the snapshot (the delegate's semantics).
            let entry = state.aliases_mut().entry(alias.clone()).or_default();
            entry.kept.remove(&msg_id.to_string());
            if !entry.read.contains(msg_id) {
                entry.read.push(*msg_id);
            }
            entry.archived.insert(msg_id.to_string(), archived.clone());
        }
        Change::Unarchive(alias, msg_id) => {
            if let Some(entry) = state.aliases_mut().get_mut(alias) {
                entry.archived.remove(&msg_id.to_string());
            }
        }
        Change::DeleteMessage(alias, msg_id) => {
            let entry = state.aliases_mut().entry(alias.clone()).or_default();
            entry.kept.remove(&msg_id.to_string());
            entry.archived.remove(&msg_id.to_string());
            entry.read.retain(|id| id != msg_id);
            if !entry.deleted.contains(msg_id) {
                entry.deleted.push(*msg_id);
            }
        }
        Change::MarkRead(alias, msg_id, kept) => {
            let entry = state.aliases_mut().entry(alias.clone()).or_default();
            if !entry.read.contains(msg_id) {
                entry.read.push(*msg_id);
            }
            entry.kept.insert(msg_id.to_string(), kept.clone());
        }
        Change::IdentitySettings(alias, before, after) => {
            let entry = state.aliases_mut().entry(alias.clone()).or_default();
            overlay_changed_fields(&mut entry.settings, before, after);
        }
        Change::GlobalSettings(before, after) => {
            overlay_changed_fields(state.global_settings_mut(), before, after);
        }
        Change::Forget(key) => {
            state.aliases_mut().remove(key);
        }
    }
}

/// Set in `value` the fields that differ between `before` and `after`.
fn overlay_changed_fields<T>(value: &mut T, before: &T, after: &T)
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let (Ok(mut merged), Ok(before), Ok(after)) = (
        serde_json::to_value(&*value),
        serde_json::to_value(before),
        serde_json::to_value(after),
    ) else {
        return;
    };
    if items::apply_changes(&mut merged, &before, &after)
        && let Ok(next) = serde_json::from_value(merged)
    {
        *value = next;
    }
}

/// Make `change` to the snapshot, and journal it while a load runs.
fn change(change: Change) {
    if LOADS.with(std::cell::Cell::get) > 0 {
        let n = NEXT_CHANGE.with(|n| {
            let next = n.get();
            n.set(next + 1);
            next
        });
        JOURNAL.with(|j| j.borrow_mut().push((n, change.clone())));
    }
    SNAPSHOT.with(|s| apply(&mut s.borrow_mut(), &change));
}

/// Every received message's UI id is below this, so ids at or above it are
/// free for rows that are not received messages (the folded own-Sent rows,
/// `app::SENT_FOLD_ID_BASE`). Received ids are hashes, so without the
/// partition nearly all of them would land in the folded range (#289).
pub(crate) const RECEIVED_ID_LIMIT: u64 = 1 << 63;

/// Identity-scoped state is keyed by the identity's address, never by its
/// alias: an alias is a display label that a rename changes, and an identity
/// whose deletion is unfinished may share it with a new one. Every entry
/// point below takes the alias the UI holds and turns it into this key once
/// ([`state_key`]); everything inside treats the key as opaque.
pub(crate) fn addr_key(addr: &freenet_mail_protocol::Addr) -> String {
    use std::fmt::Write as _;
    let mut key = String::with_capacity(1 + 2 * addr.0.len());
    key.push('@');
    for byte in addr.0 {
        let _ = write!(key, "{byte:02x}");
    }
    key
}

/// The address a state key names (see [`addr_key`]).
pub(crate) fn addr_of_key(key: &str) -> Option<freenet_mail_protocol::Addr> {
    let hex = key.strip_prefix('@')?;
    if hex.len() != 48 {
        return None;
    }
    let mut addr = [0u8; 24];
    for (i, byte) in addr.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(freenet_mail_protocol::Addr(addr))
}

/// The key `alias`'s state lives under: its identity's address. The live
/// identity list is renamed in place, so a renamed identity keeps its key.
/// A key passed in comes back unchanged; an alias that names no identity
/// (an identity not announced yet, or a unit test) is its own key.
pub(crate) fn state_key(alias: &str) -> String {
    if addr_of_key(alias).is_some() {
        return alias.to_string();
    }
    crate::app::login::Identity::get_alias(alias)
        .map(|identity| identity.addr)
        .or_else(|| crate::inbox::InboxModel::id_for_alias(alias).map(|identity| identity.addr))
        .map(|addr| addr_key(&addr))
        .unwrap_or_else(|| alias.to_string())
}

/// A load from the delegate in progress: from [`begin_load`] until it is
/// passed to [`merge_loaded`] or dropped (the load failed), the page's
/// changes are journaled.
pub(crate) struct LoadMark(u64);

impl Drop for LoadMark {
    fn drop(&mut self) {
        let left = LOADS.with(|l| {
            let left = l.get().saturating_sub(1);
            l.set(left);
            left
        });
        if left == 0 {
            JOURNAL.with(|j| j.borrow_mut().clear());
        }
    }
}

/// Mark the start of a load from the delegate; pass the result to
/// [`merge_loaded`].
pub(crate) fn begin_load() -> LoadMark {
    LOADS.with(|l| l.set(l.get() + 1));
    LoadMark(NEXT_CHANGE.with(std::cell::Cell::get))
}

/// Apply a load that began at `mark` ([`begin_load`]) for `owners` only.
///
/// The load is a snapshot taken while the page kept running. It replaces
/// just the identities it read (an identity created meanwhile keeps its
/// state, #286), and every change the page made since `mark` is applied
/// again on top of it: a draft saved meanwhile stays, a Sent row deleted
/// meanwhile stays deleted, and a settings change keeps the fields it
/// changed while every other field comes from the load. The optimistic
/// stashes still apply, as for any echo.
pub(crate) fn merge_loaded(mut loaded: LocalState, owners: &[String], mark: LoadMark) {
    let since: Vec<Change> = JOURNAL.with(|j| {
        j.borrow()
            .iter()
            .filter(|(n, _)| *n >= mark.0)
            .map(|(_, c)| c.clone())
            .collect()
    });
    drop(mark);
    let mut fresh = LocalState::default();
    *fresh.global_settings_mut() = loaded.global_settings().clone();
    let mut touched: HashSet<String> = HashSet::new();
    for alias in owners {
        let state = loaded.aliases_mut().remove(alias).unwrap_or_default();
        fresh.aliases_mut().insert(alias.clone(), state);
        touched.insert(alias.clone());
    }
    for change in &since {
        apply(&mut fresh, change);
    }
    // Taken out and put back by `replace_snapshot` below, with nothing in
    // between that could read it.
    let mut merged = SNAPSHOT.with(|s| std::mem::take(&mut *s.borrow_mut()));
    for alias in touched {
        match fresh.aliases_mut().remove(&alias) {
            Some(state) => {
                merged.aliases_mut().insert(alias, state);
            }
            None => {
                merged.aliases_mut().remove(&alias);
            }
        }
    }
    *merged.global_settings_mut() = fresh.global_settings().clone();
    // The load cannot confirm a discard: the journal already replayed it
    // into `merged`, so the draft is absent whether or not the delegate
    // has removed it, and a late save of a draft never stored must still
    // find its tombstone.
    install_snapshot(merged, false);
}

/// Bumped on every snapshot mutation. Components read this signal so Dioxus
/// subscribes them to changes; reading via `()` (call) registers the dep.
/// Why GlobalSignal vs AtomicUsize: an Atomic.load() from a component does not
/// register a reactive dependency, so kept/read/draft mutations did not trigger
/// re-render until something else dirtied the component (issue #106).
pub(crate) static GENERATION: GlobalSignal<usize> = Signal::global(|| 0);

fn bump() {
    // GlobalSignal::write() requires a live Dioxus runtime. The unit
    // tests in this module exercise the SNAPSHOT round-trip without
    // mounting a Dioxus app, so guard the bump and skip it when no
    // runtime is present.
    if dioxus::core::Runtime::try_current().is_some() {
        *GENERATION.write() += 1;
    }
}

/// Install a delegate echo as the snapshot (tests; the app installs only
/// the startup merge, through [`install_snapshot`]).
#[cfg(test)]
pub(crate) fn replace_snapshot(new: LocalState) {
    install_snapshot(new, true);
}

/// Install `new` as the snapshot. A draft tombstone always strips its draft
/// from it; with `confirm_discards`, a tombstone whose draft `new` lacks is
/// taken as confirmed (the delegate's echo of the delete) and dropped.
fn install_snapshot(new: LocalState, confirm_discards: bool) {
    let mut new = new;
    DELETED_DRAFTS.with(|tombs| {
        let mut tombs = tombs.borrow_mut();
        tombs.retain(|(alias, draft_id)| {
            // If incoming snapshot still contains the draft, an older
            // `save_draft` won the race; strip it and keep the tombstone.
            // If it's gone, the `delete_draft` echo has caught up — drop it.
            if let Some(state) = new.aliases_mut().get_mut(alias)
                && state.drafts.remove(draft_id).is_some()
            {
                return true;
            }
            !confirm_discards
        });
    });
    PENDING_KEPT.with(|pending| {
        let mut pending = pending.borrow_mut();
        pending.retain(|(alias, msg_id), kept| {
            let entry = new.aliases_mut().entry(alias.clone()).or_default();
            if entry.kept.contains_key(msg_id) {
                // Delegate echo includes this kept entry — `MarkRead`
                // round-tripped, drop the optimistic stash.
                return false;
            }
            // Stale echo — re-merge the optimistic write so `kept_for`
            // keeps surfacing the row. Also re-apply `read=true` so the
            // inbox list shows the row as read on the next rebuild.
            entry.kept.insert(msg_id.clone(), kept.clone());
            if let Ok(parsed) = msg_id.parse::<MessageId>()
                && !entry.read.contains(&parsed)
            {
                entry.read.push(parsed);
            }
            true
        });
    });
    OPTIMISTIC_SENT.with(|pending| {
        let mut pending = pending.borrow_mut();
        pending.retain(|(alias, sent_id), msg| {
            let entry = new.aliases_mut().entry(alias.clone()).or_default();
            if entry.sent.contains_key(sent_id) {
                // Delegate echo includes the Sent entry — `SaveSent`
                // round-tripped, drop the optimistic stash.
                return false;
            }
            // Stale echo — re-merge so the Sent folder keeps the row.
            entry.sent.insert(sent_id.clone(), msg.clone());
            true
        });
    });
    OPTIMISTIC_ARCHIVED.with(|pending| {
        let mut pending = pending.borrow_mut();
        pending.retain(|(alias, msg_id), archived| {
            let entry = new.aliases_mut().entry(alias.clone()).or_default();
            if entry.archived.contains_key(msg_id) {
                return false;
            }
            entry.archived.insert(msg_id.clone(), archived.clone());
            // Archiving implies read + drops any kept fallback (delegate
            // semantics) — re-apply so a stale echo doesn't surface the row
            // in both Inbox and Archive.
            entry.kept.remove(msg_id);
            if let Ok(parsed) = msg_id.parse::<MessageId>()
                && !entry.read.contains(&parsed)
            {
                entry.read.push(parsed);
            }
            true
        });
    });
    DELETED_MESSAGES.with(|tombs| {
        let mut tombs = tombs.borrow_mut();
        tombs.retain(|(alias, msg_id)| {
            let entry = new.aliases_mut().entry(alias.clone()).or_default();
            if entry.deleted.contains(msg_id) {
                // Echo records the deletion — `DeleteMessage` round-tripped.
                return false;
            }
            // Stale echo — re-apply the deletion so the message stays gone.
            let id_str = msg_id.to_string();
            entry.kept.remove(&id_str);
            entry.archived.remove(&id_str);
            entry.read.retain(|id| id != msg_id);
            entry.deleted.push(*msg_id);
            true
        });
    });
    SNAPSHOT.with(|s| *s.borrow_mut() = new);
    bump();
}

pub(crate) fn drafts_for(alias: &str) -> Vec<(String, Draft)> {
    let alias = &state_key(alias);
    SNAPSHOT.with(|s| {
        s.borrow()
            .drafts_of(alias)
            .map(|(id, d)| (id.clone(), d.clone()))
            .collect()
    })
}

pub(crate) fn is_read(alias: &str, id: MessageId) -> bool {
    let alias = &state_key(alias);
    SNAPSHOT.with(|s| s.borrow().is_read(alias, id))
}

pub(crate) fn archived_for(alias: &str) -> Vec<(MessageId, ArchivedMessage)> {
    let alias = &state_key(alias);
    SNAPSHOT.with(|s| match s.borrow().for_alias(alias) {
        Some(state) => state
            .archived
            .iter()
            .filter_map(|(k, v)| k.parse::<MessageId>().ok().map(|id| (id, v.clone())))
            .collect(),
        None => Vec::new(),
    })
}

pub(crate) fn is_archived(alias: &str, id: MessageId) -> bool {
    let alias = &state_key(alias);
    SNAPSHOT.with(|s| s.borrow().is_archived(alias, id))
}

pub(crate) fn is_deleted(alias: &str, id: MessageId) -> bool {
    let alias = &state_key(alias);
    SNAPSHOT.with(|s| s.borrow().is_deleted(alias, id))
}

/// Whether this page discarded draft `id` (a late autosave must not bring
/// it back).
fn draft_discarded(alias: &str, id: &str) -> bool {
    let key = state_key(alias);
    DELETED_DRAFTS.with(|t| t.borrow().contains(&(key, id.to_string())))
}

/// Drop everything cached for the identity at `addr` (it was deleted).
/// Keyed by address, so it never touches another identity that happens to
/// carry the same alias, such as a new one created while this one's
/// deletion was unfinished.
pub(crate) fn forget_identity(addr: &freenet_mail_protocol::Addr) {
    forget_key(&addr_key(addr));
}

fn forget_key(key: &str) {
    change(Change::Forget(key.to_string()));
    DELETED_DRAFTS.with(|t| t.borrow_mut().retain(|(a, _)| a != key));
    PENDING_KEPT.with(|t| t.borrow_mut().retain(|(a, _), _| a != key));
    OPTIMISTIC_SENT.with(|t| t.borrow_mut().retain(|(a, _), _| a != key));
    OPTIMISTIC_ARCHIVED.with(|t| t.borrow_mut().retain(|(a, _), _| a != key));
    DELETED_MESSAGES.with(|t| t.borrow_mut().retain(|(a, _)| a != key));
    READ_SENT.with(|t| t.borrow_mut().retain(|(a, _)| a != key));
    DRAFT_RECIPIENTS.with(|t| t.borrow_mut().retain(|(a, _), _| a != key));
    items::forget_seen_drafts(key);
    bump();
}

thread_local! {
    /// The address each draft is addressed to, by (state key, draft id): the
    /// recipient chosen when the To field was filled in. An alias can come
    /// to name someone else (an identity created later under a contact's
    /// name), an address cannot, so a draft is sent to the address it
    /// recorded.
    static DRAFT_RECIPIENTS: RefCell<HashMap<(String, String), String>> =
        RefCell::new(HashMap::new());
}

fn set_draft_recipient_for_key(key: String, id: String, address: Option<String>) {
    DRAFT_RECIPIENTS.with(|t| {
        let mut t = t.borrow_mut();
        match address {
            Some(a) => t.insert((key, id), a),
            None => t.remove(&(key, id)),
        };
    });
}

/// Record the recipient address of `alias`'s draft `id` (`None`: none chosen).
pub(crate) fn set_draft_recipient(alias: &str, id: &str, address: Option<String>) {
    set_draft_recipient_for_key(state_key(alias), id.to_string(), address);
}

/// The recipient address `alias`'s draft `id` recorded, if any.
pub(crate) fn draft_recipient(alias: &str, id: &str) -> Option<String> {
    DRAFT_RECIPIENTS.with(|t| t.borrow().get(&(state_key(alias), id.to_string())).cloned())
}

thread_local! {
    /// Messages whose read mark this page has already sent to the delegate.
    static READ_SENT: RefCell<HashSet<(String, MessageId)>> = RefCell::new(HashSet::new());
}

/// Whether opening message `id` should send its read mark to the delegate:
/// once per page, and never for a message already deleted or archived (a
/// late read mark would write its kept copy back after the delete). Views
/// render many times while open; each render used to send it again.
pub(crate) fn should_persist_read(alias: &str, id: MessageId) -> bool {
    let alias = &state_key(alias);
    if is_deleted(alias, id) || is_archived(alias, id) {
        return false;
    }
    READ_SENT.with(|sent| sent.borrow_mut().insert((alias.to_string(), id)))
}

/// How many times a read mark is tried before this page gives up on it.
#[cfg(any(test, feature = "use-node"))]
const READ_MARK_ATTEMPTS: u32 = 3;

/// Whether a failed read mark may succeed if tried again: the delegate never
/// answered, or answered that it was busy or lost a compare-and-swap. Any
/// other failure (the identity is gone or being deleted, the message is not
/// loaded) fails the same way every time.
#[cfg(any(test, feature = "use-node"))]
fn read_mark_is_transient(e: &crate::DynError) -> bool {
    use freenet_mail_protocol::FailureCode;
    match e.downcast_ref::<crate::mail_delegate::CallError>() {
        Some(crate::mail_delegate::CallError::Unknown(_)) => true,
        Some(failure) => matches!(
            failure.code(),
            Some(FailureCode::Busy | FailureCode::Conflict { .. })
        ),
        None => false,
    }
}

/// Send a read mark with `send`, retrying a transient failure
/// ([`read_mark_is_transient`]) with a growing pause, at most
/// [`READ_MARK_ATTEMPTS`] times in all. The last error comes back; the
/// caller reports it once. A render never re-sends a read mark: a mark that
/// failed for good would otherwise be retried, and reported, on every
/// render of the open message.
#[cfg(any(test, feature = "use-node"))]
async fn send_read_mark_with_retry<F, Fut>(mut send: F) -> Result<(), crate::DynError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<(), crate::DynError>>,
{
    let mut attempt = 1;
    loop {
        match send().await {
            Ok(()) => return Ok(()),
            Err(e) if attempt < READ_MARK_ATTEMPTS && read_mark_is_transient(&e) => {
                crate::mail_delegate::ops::pause_ms(500 * 2u32.pow(attempt)).await;
                attempt += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Send message `id`'s read mark (and its kept copy) to the delegate, once
/// per page: a render while one is in flight, or after it was sent or given
/// up, sends nothing. A transient failure is retried a few times inside the
/// task ([`send_read_mark_with_retry`]); a failure that remains is reported
/// once. Runs in a task that outlives the view: opening a message and
/// navigating straight away unmounts it, and a scoped task would be
/// cancelled (#286 read-state variant).
#[cfg(feature = "use-node")]
pub(crate) fn persist_read(alias: &str, id: MessageId, kept: KeptMessage, what: &'static str) {
    if !should_persist_read(alias, id) {
        return;
    }
    let key = state_key(alias);
    let _task = dioxus::core::spawn_forever(async move {
        let result =
            send_read_mark_with_retry(|| items::mark_read(key.clone(), id, kept.clone())).await;
        if let Err(e) = result {
            crate::log::local_state_failure(what, e);
        }
    });
}

pub(crate) fn sent_for(alias: &str) -> Vec<(String, SentMessage)> {
    let alias = &state_key(alias);
    SNAPSHOT.with(|s| {
        s.borrow()
            .sent_of(alias)
            .map(|(id, m)| (id.clone(), m.clone()))
            .collect()
    })
}

pub(crate) fn kept_for(alias: &str) -> Vec<(MessageId, KeptMessage)> {
    let alias = &state_key(alias);
    SNAPSHOT.with(|s| match s.borrow().for_alias(alias) {
        Some(state) => state
            .kept
            .iter()
            .filter_map(|(k, v)| k.parse::<MessageId>().ok().map(|id| (id, v.clone())))
            .collect(),
        None => Vec::new(),
    })
}

pub(crate) fn identity_settings_for(alias: &str) -> IdentitySettings {
    let alias = &state_key(alias);
    SNAPSHOT.with(|s| s.borrow().identity_settings(alias))
}

pub(crate) fn global_settings() -> GlobalSettings {
    SNAPSHOT.with(|s| s.borrow().global_settings().clone())
}

mod items;
pub(crate) use items::forget_identity_bookkeeping;
pub(crate) use items::{
    DraftCheck, DraftSave, archive_message, check_draft_before_send, delete_draft, delete_message,
    delete_sent, full_message_id, load, message_id_for, reclaim_flags, save_draft, save_sent,
    set_sent_delivery_state,
};
// Only the node build finds stranded sends to presume failed.
#[cfg_attr(not(feature = "use-node"), allow(unused_imports))]
pub(crate) use items::presume_sent_failed;
pub(crate) use items::{forget_unreadable_list, list_name, unreadable_lists};
// `unarchive_message` is wired but unused until #60 (true unarchive).
#[allow(unused_imports)]
pub(crate) use items::unarchive_message;

/// Whether a local-state write is stored: acknowledged by the mail
/// delegate (`Yes`), refused (`Failed`), or unanswered (`Unknown`, never
/// "absent": the write may still have landed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stored {
    Yes,
    Failed,
    Unknown,
}

impl Stored {
    /// The outcome of a write from its result.
    pub(crate) fn of(result: &Result<(), crate::DynError>) -> Self {
        match result {
            Ok(()) => Stored::Yes,
            Err(e) => match e.downcast_ref::<crate::mail_delegate::CallError>() {
                Some(crate::mail_delegate::CallError::Unknown(_)) => Stored::Unknown,
                _ => Stored::Failed,
            },
        }
    }
}

/// The v0.2.x local-state delegate this build no longer talks to. Its key
/// is pinned so the migration from it (B3) addresses exactly the delegate
/// v0.2.x users have.
#[cfg(all(test, feature = "use-node"))]
mod legacy {
    use freenet_stdlib::prelude::{DelegateKey, Parameters};

    const CODE_HASH: &str =
        include_str!("../../published-contract/wasm/v1/mail_local_state_code_hash");
    const CODE: &[u8] = include_bytes!("../../published-contract/wasm/v1/mail_local_state");
    const PARAMS: &[u8] =
        include_bytes!("../../published-contract/wasm/v1/mail-local-state-params");

    #[test]
    fn embedded_local_state_wasm_has_the_embedded_code_hash() {
        crate::api::embedded_artifact::assert_delegate(CODE, CODE_HASH);
    }

    #[test]
    fn delegate_key_matches_the_v0_2_client() {
        use crate::test_util::{frozen_key, hex};
        let params = Parameters::from(PARAMS.to_vec());
        let key = DelegateKey::from_params(CODE_HASH, &params).unwrap();
        assert_eq!(hex(key.bytes()), frozen_key("local_state_delegate"));
    }
}

// Optimistic local mutations: patch `SNAPSHOT` immediately so the UI
// re-renders without waiting for the delegate roundtrip.

pub(crate) fn local_save_draft(alias: &str, id: &str, draft: Draft) {
    let alias = &state_key(alias);
    change(Change::SaveDraft(alias.to_string(), id.to_string(), draft));
    bump();
}

pub(crate) fn local_delete_draft(alias: &str, id: &str) {
    let alias = &state_key(alias);
    change(Change::DeleteDraft(alias.to_string(), id.to_string()));
    set_draft_recipient_for_key(alias.to_string(), id.to_string(), None);
    // Tombstone protects against a stale `save_draft` echo that would
    // otherwise re-add this draft via `replace_snapshot` (#107).
    DELETED_DRAFTS.with(|t| {
        t.borrow_mut().insert((alias.to_string(), id.to_string()));
    });
    bump();
}

pub(crate) fn local_save_sent(alias: &str, id: &str, sent: SentMessage) {
    let alias = &state_key(alias);
    // No address or message id: this runs on every send, and the console
    // is captured in test artifacts.
    crate::log::info("Sent row kept on this page");
    change(Change::SaveSent(
        alias.to_string(),
        id.to_string(),
        sent.clone(),
    ));
    // Protect the optimistic Sent entry until `SaveSent` round-trips, so a
    // stale `GetAll` echo doesn't wipe it (#265).
    OPTIMISTIC_SENT.with(|p| {
        p.borrow_mut()
            .insert((alias.to_string(), id.to_string()), sent);
    });
    bump();
}

pub(crate) fn local_delete_sent(alias: &str, id: &str) {
    let alias = &state_key(alias);
    change(Change::DeleteSent(alias.to_string(), id.to_string()));
    // Drop any optimistic-sent protection for this id so a later stale echo
    // doesn't resurrect a sent row the user just deleted (#265).
    OPTIMISTIC_SENT.with(|p| {
        p.borrow_mut().remove(&(alias.to_string(), id.to_string()));
    });
    bump();
}

/// Returns whether the row actually transitioned. `false` means the row
/// was already terminal (or absent) and the caller should NOT issue the
/// follow-up delegate write — otherwise the persisted state could flap on
/// reload even though the in-memory render was correctly suppressed (#288).
#[must_use]
pub(crate) fn local_set_sent_delivery_state(alias: &str, id: &str, state: DeliveryState) -> bool {
    let alias = &state_key(alias);
    // Pending is the only non-terminal state. Once a row reaches Delivered
    // or Failed it must NOT flip again (#288): the stale-send timeout sweep
    // can drain a Pending entry and flip it Failed, after which a late
    // `UpdateResponse` would otherwise mis-pair (FIFO pop) and resurrect the
    // wrong row to Delivered — or flap a delivered row back to Failed.
    // Terminal states stick (`apply` holds the same guard).
    let changed = SNAPSHOT.with(|s| {
        s.borrow().sent_of(alias).any(|(sent_id, sent)| {
            sent_id == id && !delivery_state_is_terminal(sent.delivery_state)
        })
    });
    if changed {
        change(Change::SentDelivery(
            alias.to_string(),
            id.to_string(),
            state,
        ));
        bump();
    }
    changed
}

/// Sent rows of `owners` still `Pending` that no send in this page is
/// waiting on and that were sent at least `min_age_ms` before `now_ms`:
/// `in_flight` holds the `(state key, sent id)` of every send whose inbox
/// update this page has queued. Such a row was left by an earlier page
/// session that ended (reload, closed tab, crash) before the update was
/// answered; nothing in this page will ever resolve it, and re-sending would
/// seal a new ciphertext, so a message that did go out would arrive twice.
///
/// The age matters because `in_flight` only knows this page's sends:
/// another open tab's send is Pending in the shared store and in no set
/// here. Callers pass the stale-send timeout, after which the sending page
/// gives up on the row itself.
pub(crate) fn stranded_pending_sent(
    owners: &[String],
    in_flight: &HashSet<(String, String)>,
    now_ms: i64,
    min_age_ms: i64,
) -> Vec<(String, String)> {
    SNAPSHOT.with(|s| {
        let snapshot = s.borrow();
        let mut out = Vec::new();
        for owner in owners {
            for (sent_id, sent) in snapshot.sent_of(owner) {
                if !delivery_state_is_terminal(sent.delivery_state)
                    && now_ms.saturating_sub(sent.sent_at) >= min_age_ms
                    && !in_flight.contains(&(owner.clone(), sent_id.to_string()))
                {
                    out.push((owner.clone(), sent_id.to_string()));
                }
            }
        }
        out.sort();
        out
    })
}

/// `Delivered` and `Failed` are terminal; `Pending` is the only state a
/// later transition may overwrite. Centralised so the local stash and the
/// delegate writer agree on the guard.
pub(crate) fn delivery_state_is_terminal(state: DeliveryState) -> bool {
    matches!(state, DeliveryState::Delivered | DeliveryState::Failed)
}

pub(crate) fn local_archive_message(alias: &str, msg_id: MessageId, archived: ArchivedMessage) {
    let alias = &state_key(alias);
    change(Change::Archive(alias.to_string(), msg_id, archived.clone()));
    // Archive supersedes a pending kept tombstone — drop it so a stale
    // echo doesn't re-insert the kept entry under the archived row.
    PENDING_KEPT.with(|pending| {
        pending
            .borrow_mut()
            .remove(&(alias.to_string(), msg_id.to_string()));
    });
    // Protect the optimistic archive until `ArchiveMessage` round-trips (#265).
    OPTIMISTIC_ARCHIVED.with(|p| {
        p.borrow_mut()
            .insert((alias.to_string(), msg_id.to_string()), archived);
    });
    bump();
}

pub(crate) fn local_unarchive_message(alias: &str, msg_id: MessageId) {
    let alias = &state_key(alias);
    change(Change::Unarchive(alias.to_string(), msg_id));
    // Drop optimistic-archive protection so a stale echo doesn't re-archive
    // a message the user just unarchived (#265).
    OPTIMISTIC_ARCHIVED.with(|p| {
        p.borrow_mut()
            .remove(&(alias.to_string(), msg_id.to_string()));
    });
    bump();
}

pub(crate) fn local_delete_message(alias: &str, msg_id: MessageId) {
    let alias = &state_key(alias);
    change(Change::DeleteMessage(alias.to_string(), msg_id));
    // Same as archive: delete supersedes a pending kept tombstone.
    PENDING_KEPT.with(|pending| {
        pending
            .borrow_mut()
            .remove(&(alias.to_string(), msg_id.to_string()));
    });
    // A deleted message also can't be a protected sent/archived row.
    OPTIMISTIC_SENT.with(|p| {
        p.borrow_mut()
            .remove(&(alias.to_string(), msg_id.to_string()));
    });
    OPTIMISTIC_ARCHIVED.with(|p| {
        p.borrow_mut()
            .remove(&(alias.to_string(), msg_id.to_string()));
    });
    // Protect the deletion until `DeleteMessage` round-trips, so a stale echo
    // doesn't resurrect the message (#265).
    DELETED_MESSAGES.with(|t| {
        t.borrow_mut().insert((alias.to_string(), msg_id));
    });
    bump();
}

/// A sent message's write was acknowledged by the delegate: drop its
/// optimistic copy. The stashes guard against an older snapshot landing
/// over the page's own writes; the only such snapshot now is the startup
/// load, whose journal replays every change made while it ran
/// ([`begin_load`]), so an acknowledged write needs no copy, and holding
/// full message bodies for the whole session only costs memory.
fn drain_acked_sent(key: &str, id: &str) {
    OPTIMISTIC_SENT.with(|p| p.borrow_mut().remove(&(key.to_string(), id.to_string())));
}

/// A read mark's kept copy was acknowledged: see [`drain_acked_sent`].
fn drain_acked_kept(key: &str, msg_id: MessageId) {
    PENDING_KEPT.with(|p| {
        p.borrow_mut()
            .remove(&(key.to_string(), msg_id.to_string()))
    });
}

/// An archive was acknowledged: see [`drain_acked_sent`].
fn drain_acked_archived(key: &str, msg_id: MessageId) {
    OPTIMISTIC_ARCHIVED.with(|p| {
        p.borrow_mut()
            .remove(&(key.to_string(), msg_id.to_string()))
    });
}

pub(crate) fn local_mark_read(alias: &str, msg_id: MessageId, kept: KeptMessage) {
    let alias = &state_key(alias);
    change(Change::MarkRead(alias.to_string(), msg_id, kept.clone()));
    // Tombstone the optimistic write until the delegate echoes back a
    // snapshot that includes it — guards against the #113 race where a
    // stale `GetAll` reply lands before `MarkRead` persists.
    PENDING_KEPT.with(|pending| {
        pending
            .borrow_mut()
            .insert((alias.to_string(), msg_id.to_string()), kept);
    });
    bump();
}

pub(crate) fn local_set_identity_settings(alias: &str, settings: IdentitySettings) {
    let alias = &state_key(alias);
    let before = identity_settings_for(alias);
    change(Change::IdentitySettings(
        alias.to_string(),
        before,
        settings,
    ));
    bump();
}

pub(crate) fn local_set_global_settings(settings: GlobalSettings) {
    let before = global_settings();
    change(Change::GlobalSettings(before, settings));
    bump();
}

/// Apply a per-identity settings change everywhere: optimistically patch the
/// in-memory snapshot for an immediate UI re-render, then (under `use-node`)
/// persist the fields that changed. Another tab may have changed other fields
/// meanwhile; only this change's fields are written over what is stored
/// (`items::set_identity_settings`). A failed write is logged and reported.
///
/// Safe to call from outside the Dioxus runtime (the `api.rs` node loop
/// calls it when an identity is created): the snapshot bump is already
/// runtime-guarded, and the delegate write runs on
/// `wasm_bindgen_futures::spawn_local` rather than Dioxus `spawn`, which
/// needs a current scope and would also cancel the write if the calling
/// component unmounted first.
pub(crate) fn persist_identity_settings(alias: String, settings: IdentitySettings) {
    let alias = state_key(&alias);
    let before = identity_settings_for(&alias);
    local_set_identity_settings(&alias, settings.clone());
    #[cfg(feature = "use-node")]
    wasm_bindgen_futures::spawn_local(async move {
        if let Err(e) = items::set_identity_settings(alias, before, settings).await {
            crate::log::local_state_failure("save identity settings", e);
        }
    });
    #[cfg(not(feature = "use-node"))]
    {
        let _ = (alias, before, settings);
    }
}

/// Apply a global settings change everywhere; same shape as
/// [`persist_identity_settings`].
pub(crate) fn persist_global_settings(settings: GlobalSettings) {
    let before = global_settings();
    local_set_global_settings(settings.clone());
    #[cfg(feature = "use-node")]
    wasm_bindgen_futures::spawn_local(async move {
        if let Err(e) = items::set_global_settings(before, settings).await {
            crate::log::local_state_failure("save settings", e);
        }
    });
    #[cfg(not(feature = "use-node"))]
    {
        let _ = (before, settings);
    }
}

pub(crate) fn new_draft_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub(crate) fn new_sent_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Mint a fresh stable conversation id (#270). Used when a reply is the first
/// message to thread a conversation that previously had no `thread_id` (legacy
/// parent), and whenever a new outbound message starts a fresh conversation.
pub(crate) fn new_thread_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use freenet_mail_wire_v1::local_state::KeptMessage;

    fn fresh_snapshot() {
        SNAPSHOT.with(|s| *s.borrow_mut() = LocalState::default());
    }

    fn kept(from: &str, title: &str) -> KeptMessage {
        KeptMessage {
            from: from.into(),
            title: title.into(),
            content: "body".into(),
            kept_at: 0,
            sent_at: None,
            sender_vk: Vec::new(),
            signature_valid: false,
        }
    }

    /// Regression for #113: `local_mark_read` must make the row visible
    /// to the inbox-list rebuild path (`kept_for`) immediately, before
    /// any delegate echo. The UI relies on this so that clicking a
    /// message that is then evicted from the live contract still
    /// surfaces the row in the Inbox folder as `read=true`.
    #[test]
    fn local_mark_read_round_trips_via_kept_for() {
        fresh_snapshot();
        local_mark_read("alice", 42, kept("bob", "round one"));

        let entries = kept_for("alice");
        assert_eq!(entries.len(), 1, "exactly one kept entry");
        let (mid, k) = &entries[0];
        assert_eq!(*mid, 42);
        assert_eq!(k.title, "round one");
        assert!(is_read("alice", 42), "marked read");
    }

    /// `kept_for` must isolate by alias — bob's read state is NOT
    /// visible from alice's Inbox.
    #[test]
    fn kept_for_is_alias_scoped() {
        fresh_snapshot();
        local_mark_read("alice", 1, kept("bob", "for alice"));
        local_mark_read("bob", 2, kept("alice", "for bob"));

        let alice = kept_for("alice");
        let bob = kept_for("bob");
        assert_eq!(alice.len(), 1);
        assert_eq!(alice[0].0, 1);
        assert_eq!(bob.len(), 1);
        assert_eq!(bob[0].0, 2);
    }

    /// Idempotent: marking the same message read twice produces a
    /// single kept entry, not duplicates. The live UI path runs
    /// `OpenMessage` on every render, which re-fires `local_mark_read`
    /// — that must be a no-op on second call.
    /// A live identity at `[byte; 24]` named `alias`, as startup announces
    /// one.
    fn live_identity(alias: &str, byte: u8) -> freenet_mail_protocol::Addr {
        let addr = freenet_mail_protocol::Addr([byte; 24]);
        let info = freenet_mail_protocol::IdentityInfo {
            addr,
            vk: Vec::new().into(),
            ek: Vec::new().into(),
            alias: alias.to_string(),
            description: String::new(),
            confirmed: true,
            generation: 1,
        };
        crate::app::login::Identity::register_live_for_test(
            crate::app::login::Identity::from_info(&info, crate::app::UserId::new()),
        );
        addr
    }

    #[test]
    fn state_keys_round_trip_and_resolve_to_the_identitys_address() {
        let addr = live_identity("sk-alice", 0x51);
        let key = state_key("sk-alice");
        assert_eq!(key, addr_key(&addr));
        assert_eq!(addr_of_key(&key), Some(addr));
        assert_eq!(state_key(&key), key, "a key resolves to itself");
        assert_eq!(state_key("sk-nobody"), "sk-nobody");
        assert_eq!(addr_of_key("@00"), None);
    }

    #[test]
    fn a_new_identity_under_a_deleted_alias_starts_empty() {
        fresh_snapshot();
        let old = live_identity("fa-alice", 0x52);
        local_save_draft("fa-alice", "d1", Draft::default());
        assert_eq!(drafts_for("fa-alice").len(), 1);
        let old_key = addr_key(&old);
        assert_eq!(drafts_for(&old_key).len(), 1, "stored under the address");
        forget_identity(&old);
        crate::app::login::Identity::remove_in_place("fa-alice");
        // Asserted on the old identity's key: once the alias names no live
        // identity, `state_key("fa-alice")` falls back to the bare alias,
        // which holds nothing whether or not the forget worked.
        assert!(drafts_for(&old_key).is_empty());
        assert!(drafts_for("fa-alice").is_empty());
    }

    /// An identity whose deletion is unfinished is hidden, and a new one may
    /// take its alias. Finishing the old deletion forgets by the old
    /// address, so the new identity keeps its state.
    #[test]
    fn finishing_an_old_deletion_leaves_a_new_identity_with_its_alias_alone() {
        fresh_snapshot();
        let old = freenet_mail_protocol::Addr([0x53; 24]);
        let new = live_identity("fd-alice", 0x54);
        local_save_draft("fd-alice", "d1", Draft::default());
        local_mark_read("fd-alice", 7, kept("bob", "hi"));
        forget_identity(&old);
        assert_eq!(drafts_for("fd-alice").len(), 1);
        assert!(is_read("fd-alice", 7));
        forget_identity(&new);
        assert!(drafts_for("fd-alice").is_empty());
    }

    /// A rename changes the label, not the key: the state stays put, and
    /// writes for the new alias resolve to the same address.
    #[test]
    fn a_rename_keeps_the_identitys_state() {
        fresh_snapshot();
        let addr = live_identity("rn-old", 0x55);
        local_save_draft("rn-old", "d1", Draft::default());
        assert!(crate::app::login::Identity::rename_in_place(
            "rn-old", "rn-new"
        ));
        assert!(drafts_for("rn-old").is_empty());
        assert_eq!(drafts_for("rn-new").len(), 1);
        assert_eq!(addr_of_key(&state_key("rn-new")), Some(addr));
    }

    /// A read mark that keeps failing is tried a bounded number of times,
    /// once per transient failure, and never again by later renders, so an
    /// open message that cannot be marked read is reported once, not once
    /// per render (R12).
    #[test]
    fn a_failing_read_mark_is_retried_only_while_transient_and_only_a_few_times() {
        use crate::mail_delegate::CallError;
        use freenet_mail_protocol::{Failure, FailureCode};
        use futures::executor::block_on;
        use std::cell::Cell;

        let tries = Cell::new(0);
        let unknown = || -> crate::DynError { CallError::Unknown("timeout".into()).into() };
        let result = block_on(send_read_mark_with_retry(|| {
            tries.set(tries.get() + 1);
            async { Err(unknown()) }
        }));
        assert!(result.is_err());
        assert_eq!(
            tries.get(),
            READ_MARK_ATTEMPTS,
            "a timeout is retried, a bounded number of times"
        );

        tries.set(0);
        let result = block_on(send_read_mark_with_retry(|| {
            tries.set(tries.get() + 1);
            async {
                Err(CallError::Failed(Failure {
                    code: FailureCode::NotFound,
                    detail: "identity is being deleted".into(),
                })
                .into())
            }
        }));
        assert!(result.is_err());
        assert_eq!(tries.get(), 1, "a permanent failure is not retried");

        tries.set(0);
        let result = block_on(send_read_mark_with_retry(|| {
            tries.set(tries.get() + 1);
            let n = tries.get();
            async move { if n < 2 { Err(unknown()) } else { Ok(()) } }
        }));
        assert!(result.is_ok(), "a transient failure that clears succeeds");
        assert_eq!(tries.get(), 2);

        fresh_snapshot();
        assert!(should_persist_read("rf-alice", 51));
        assert!(
            !should_persist_read("rf-alice", 51),
            "a later render never re-sends a mark, failed or not"
        );
    }

    #[test]
    fn a_read_mark_is_sent_once_and_never_after_a_delete() {
        fresh_snapshot();
        assert!(should_persist_read("rs-alice", 41));
        assert!(!should_persist_read("rs-alice", 41), "once per page");
        local_delete_message("rs-alice", 42);
        assert!(!should_persist_read("rs-alice", 42), "not after a delete");
        local_archive_message("rs-alice", 43, archived_for_test());
        assert!(!should_persist_read("rs-alice", 43), "not after an archive");
    }

    fn archived_for_test() -> ArchivedMessage {
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
    fn local_mark_read_is_idempotent() {
        fresh_snapshot();
        local_mark_read("alice", 7, kept("bob", "once"));
        local_mark_read("alice", 7, kept("bob", "twice"));

        let entries = kept_for("alice");
        assert_eq!(entries.len(), 1, "single kept entry after repeat call");
        assert_eq!(entries[0].1.title, "twice", "latest kept payload wins");
    }

    /// `replace_snapshot` (delegate `GetAll` echo) must NOT clobber
    /// kept entries that the UI optimistically wrote. In the bug for
    /// #113, the local_mark_read entry only lives in SNAPSHOT until
    /// the delegate write round-trips; if the delegate's echoed
    /// snapshot omits it, the UI loses the row. This test pins the
    /// expected behavior: incoming snapshot wins, so the delegate
    /// MUST contain the persisted entry by the time it echoes back.
    /// Pure round-trip — confirms the data path, not the timing.
    #[test]
    fn replace_snapshot_preserves_kept_when_delegate_includes_it() {
        fresh_snapshot();
        local_mark_read("alice", 5, kept("bob", "kept"));

        // Simulate delegate echo with the kept entry persisted.
        let mut echoed = LocalState::default();
        let entry = echoed.aliases_mut().entry("alice".to_string()).or_default();
        entry.read.push(5);
        entry.kept.insert("5".to_string(), kept("bob", "kept"));
        replace_snapshot(echoed);

        let entries = kept_for("alice");
        assert_eq!(entries.len(), 1, "kept entry survives delegate echo");
        assert!(is_read("alice", 5));
    }

    /// #286: the startup load is a snapshot. An identity created while it
    /// ran keeps its state, and a settings change made meanwhile wins.
    #[test]
    fn a_draft_discarded_during_the_startup_load_keeps_its_tombstone() {
        fresh_snapshot();
        fresh_pending();
        let mark = begin_load();
        // A draft that was never stored is discarded while the load runs.
        local_delete_draft("alice", "late-draft");
        merge_loaded(LocalState::default(), &["alice".to_string()], mark);
        assert!(
            draft_discarded("alice", "late-draft"),
            "a late autosave of it must still be refused"
        );
    }

    #[test]
    fn a_startup_load_replaces_only_the_identities_it_read() {
        fresh_snapshot();
        fresh_pending();
        let mark = begin_load();
        // While the load runs: a new identity marks a message read, and the
        // user changes a global setting.
        local_mark_read("bob", 3, kept("alice", "hi"));
        let mut settings = global_settings();
        settings.inbox.thread_view = freenet_mail_wire_v1::local_state::ThreadView::Compact;
        local_set_global_settings(settings);
        // The load, which read only alice and the old settings.
        let mut loaded = LocalState::default();
        loaded
            .aliases_mut()
            .entry("alice".to_string())
            .or_default()
            .read
            .push(7);
        merge_loaded(loaded, &["alice".to_string()], mark);

        assert!(
            is_read("alice", 7),
            "the loaded identity's state is applied"
        );
        assert!(
            is_read("bob", 3),
            "an identity created during the load keeps its state"
        );
        assert_eq!(
            global_settings().inbox.thread_view,
            freenet_mail_wire_v1::local_state::ThreadView::Compact,
            "a settings change made during the load is not overwritten",
        );
    }

    #[test]
    fn a_startup_load_applies_stored_settings_when_none_changed() {
        fresh_snapshot();
        fresh_pending();
        let mark = begin_load();
        let mut loaded = LocalState::default();
        loaded.global_settings_mut().inbox.thread_view =
            freenet_mail_wire_v1::local_state::ThreadView::Compact;
        merge_loaded(loaded, &[], mark);
        assert_eq!(
            global_settings().inbox.thread_view,
            freenet_mail_wire_v1::local_state::ThreadView::Compact,
        );
    }

    fn loaded_alice(
        edit: impl FnOnce(&mut freenet_mail_wire_v1::local_state::AliasState),
    ) -> LocalState {
        let mut loaded = LocalState::default();
        edit(loaded.aliases_mut().entry("alice".to_string()).or_default());
        loaded
    }

    #[test]
    fn a_draft_saved_during_the_load_stays() {
        fresh_snapshot();
        fresh_pending();
        let mark = begin_load();
        local_save_draft("alice", "d-new", draft("bob", "written meanwhile"));
        let loaded = loaded_alice(|a| {
            a.drafts.insert("d-old".into(), draft("carol", "stored"));
        });
        merge_loaded(loaded, &["alice".to_string()], mark);
        let ids: HashSet<String> = drafts_for("alice").into_iter().map(|(id, _)| id).collect();
        assert!(
            ids.contains("d-new"),
            "the draft saved during the load stays"
        );
        assert!(ids.contains("d-old"), "the stored draft is loaded");
    }

    #[test]
    fn a_sent_row_deleted_during_the_load_stays_deleted() {
        fresh_snapshot();
        fresh_pending();
        local_save_sent("alice", "s1", sent_row("bob"));
        OPTIMISTIC_SENT.with(|p| p.borrow_mut().clear());
        let mark = begin_load();
        local_delete_sent("alice", "s1");
        // The load read the row before the delete reached the delegate.
        let loaded = loaded_alice(|a| {
            a.sent.insert("s1".into(), sent_row("bob"));
        });
        merge_loaded(loaded, &["alice".to_string()], mark);
        assert!(
            sent_for("alice").is_empty(),
            "a deleted Sent row must not come back"
        );
    }

    #[test]
    fn an_identity_settings_change_during_the_load_keeps_its_field_only() {
        fresh_snapshot();
        fresh_pending();
        let mark = begin_load();
        let mut settings = identity_settings_for("alice");
        settings.display_name = "Alice Changed".into();
        local_set_identity_settings("alice", settings);
        let loaded = loaded_alice(|a| {
            a.settings.display_name = "Alice Stored".into();
            a.settings.signature = "-- stored sig".into();
        });
        merge_loaded(loaded, &["alice".to_string()], mark);
        let got = identity_settings_for("alice");
        assert_eq!(got.display_name, "Alice Changed", "the page's change wins");
        assert_eq!(
            got.signature, "-- stored sig",
            "other loaded fields are kept"
        );
    }

    #[test]
    fn a_global_settings_change_keeps_the_other_loaded_fields() {
        fresh_snapshot();
        fresh_pending();
        let mark = begin_load();
        let mut settings = global_settings();
        settings.inbox.thread_view = freenet_mail_wire_v1::local_state::ThreadView::Compact;
        local_set_global_settings(settings);
        let mut loaded = LocalState::default();
        loaded.global_settings_mut().inbox.drafts_in_inbox = true;
        loaded.global_settings_mut().advanced.custom_relay_url = "ws://stored".into();
        merge_loaded(loaded, &[], mark);
        let got = global_settings();
        assert_eq!(
            got.inbox.thread_view,
            freenet_mail_wire_v1::local_state::ThreadView::Compact
        );
        assert!(
            got.inbox.drafts_in_inbox,
            "loaded settings are not dropped wholesale"
        );
        assert_eq!(got.advanced.custom_relay_url, "ws://stored");
    }

    #[test]
    fn an_identity_deleted_or_renamed_during_the_load_is_not_brought_back() {
        fresh_snapshot();
        fresh_pending();
        let alice = live_identity("ld-alice", 0x56);
        let bob = live_identity("ld-bob", 0x57);
        let mark = begin_load();
        forget_identity(&alice);
        crate::app::login::Identity::remove_in_place("ld-alice");
        assert!(crate::app::login::Identity::rename_in_place(
            "ld-bob",
            "ld-robert"
        ));
        let mut loaded = LocalState::default();
        loaded
            .aliases_mut()
            .entry(addr_key(&alice))
            .or_default()
            .read
            .push(1);
        loaded
            .aliases_mut()
            .entry(addr_key(&bob))
            .or_default()
            .read
            .push(2);
        merge_loaded(loaded, &[addr_key(&alice), addr_key(&bob)], mark);
        assert!(
            SNAPSHOT.with(|s| s.borrow().for_alias(&addr_key(&alice)).is_none()),
            "a deleted identity's loaded state is dropped"
        );
        assert!(
            is_read("ld-robert", 2),
            "a renamed identity's loaded state is still its own"
        );
    }

    #[test]
    fn the_journal_is_kept_only_while_a_load_runs() {
        fresh_snapshot();
        fresh_pending();
        local_save_draft("alice", "d0", draft("bob", "before"));
        assert!(JOURNAL.with(|j| j.borrow().is_empty()));
        let mark = begin_load();
        local_save_draft("alice", "d1", draft("bob", "during"));
        assert_eq!(JOURNAL.with(|j| j.borrow().len()), 1);
        drop(mark); // the load failed
        assert!(JOURNAL.with(|j| j.borrow().is_empty()));
        assert_eq!(LOADS.with(std::cell::Cell::get), 0);
    }

    fn fresh_pending() {
        PENDING_KEPT.with(|p| p.borrow_mut().clear());
        OPTIMISTIC_SENT.with(|p| p.borrow_mut().clear());
        OPTIMISTIC_ARCHIVED.with(|p| p.borrow_mut().clear());
        DELETED_MESSAGES.with(|p| p.borrow_mut().clear());
    }

    /// The race in #113: delegate echo arrives BEFORE `local_mark_read`
    /// has had time to dispatch + persist its write. Echoed snapshot
    /// has no kept entry → without the `PENDING_KEPT` tombstone path,
    /// `replace_snapshot` would clobber the optimistic write and
    /// `kept_for` would return empty. With the tombstone, the entry
    /// survives the stale echo and surfaces on the next inbox-list
    /// rebuild.
    #[test]
    fn replace_snapshot_does_not_clobber_optimistic_kept() {
        fresh_snapshot();
        fresh_pending();
        local_mark_read("alice", 9, kept("bob", "optimistic"));

        // Stale delegate echo — alice exists but kept is empty.
        let mut echoed = LocalState::default();
        echoed.aliases_mut().entry("alice".to_string()).or_default();
        replace_snapshot(echoed);

        let entries = kept_for("alice");
        assert_eq!(
            entries.len(),
            1,
            "optimistic kept entry must survive a stale echo (#113)",
        );
        assert_eq!(entries[0].0, 9);
        assert!(is_read("alice", 9), "read flag re-applied after merge");
    }

    /// Once the delegate echoes a snapshot that includes the kept entry,
    /// the `PENDING_KEPT` tombstone is dropped — subsequent stale echoes
    /// (e.g. an in-flight `GetAll` from before the `MarkRead` round-trip)
    /// no longer re-insert the entry. Pins the lifecycle so the
    /// tombstone doesn't leak forever and resurrect deleted entries.
    #[test]
    fn pending_kept_drops_after_delegate_echo_includes_entry() {
        fresh_snapshot();
        fresh_pending();
        local_mark_read("alice", 11, kept("bob", "transient"));

        // Authoritative echo — delegate has the kept entry.
        let mut echoed = LocalState::default();
        let entry = echoed.aliases_mut().entry("alice".to_string()).or_default();
        entry
            .kept
            .insert("11".to_string(), kept("bob", "transient"));
        entry.read.push(11);
        replace_snapshot(echoed);

        // Now a second, *older* echo arrives that lacks the entry —
        // simulating a network reorder. Without the tombstone drop,
        // we'd resurrect the kept row indefinitely.
        let mut stale = LocalState::default();
        stale.aliases_mut().entry("alice".to_string()).or_default();
        replace_snapshot(stale);

        assert!(
            kept_for("alice").is_empty(),
            "tombstone must be dropped once delegate confirms the entry",
        );
    }

    /// Archive supersedes kept — the pending tombstone for a freshly
    /// read message must drop when the user archives it, otherwise a
    /// later stale echo would re-insert the kept row alongside the
    /// archived one.
    #[test]
    fn local_archive_drops_pending_kept_tombstone() {
        fresh_snapshot();
        fresh_pending();
        local_mark_read("alice", 13, kept("bob", "read then archive"));
        local_archive_message(
            "alice",
            13,
            ArchivedMessage {
                from: "bob".into(),
                title: "read then archive".into(),
                content: "body".into(),
                archived_at: 1,
                ..Default::default()
            },
        );

        let stale = LocalState::default();
        replace_snapshot(stale);

        assert!(
            kept_for("alice").is_empty(),
            "archived message must not be re-merged as kept on stale echo",
        );
    }

    /// Same shape as the archive test but for deletion.
    #[test]
    fn local_delete_drops_pending_kept_tombstone() {
        fresh_snapshot();
        fresh_pending();
        local_mark_read("alice", 17, kept("bob", "read then delete"));
        local_delete_message("alice", 17);

        let stale = LocalState::default();
        replace_snapshot(stale);

        assert!(
            kept_for("alice").is_empty(),
            "deleted message must not be re-merged as kept on stale echo",
        );
    }

    fn sent(to: &str, subject: &str) -> SentMessage {
        SentMessage {
            to: to.into(),
            subject: subject.into(),
            body: "body".into(),
            ..Default::default()
        }
    }

    /// Repro for #265 — "Sent → Draft after reload". The UI optimistically
    /// stashes a sent message via `local_save_sent`, but the `SaveSent`
    /// delegate write hasn't round-tripped yet. A stale `GetAll` echo (issued
    /// before the write, e.g. on startup) lands and `replace_snapshot`
    /// wholesale-overwrites SNAPSHOT — wiping the optimistic Sent entry.
    /// The message then re-derives as a Draft. Unlike drafts (#107) and kept
    /// (#113), there is no tombstone protecting the Sent stash.
    #[test]
    fn replace_snapshot_does_not_clobber_optimistic_sent() {
        fresh_snapshot();
        fresh_pending();
        local_save_sent("alice", "sent-1", sent("bob", "hello"));

        // Stale delegate echo predating the SaveSent write — alice exists but
        // her sent stash is empty.
        let mut echoed = LocalState::default();
        echoed.aliases_mut().entry("alice".to_string()).or_default();
        replace_snapshot(echoed);

        let entries = sent_for("alice");
        assert_eq!(
            entries.len(),
            1,
            "optimistic Sent entry must survive a stale echo (#265)",
        );
        assert_eq!(entries[0].0, "sent-1");
    }

    /// Repro for #265 — "deleted/discarded messages return after reload".
    /// `local_delete_message` pushes the id into the `deleted` tombstone list
    /// in SNAPSHOT, but a stale `GetAll` echo overwrites SNAPSHOT before the
    /// `DeleteMessage` delegate write round-trips, dropping the deletion.
    /// The message reappears in the Inbox.
    #[test]
    fn replace_snapshot_does_not_clobber_optimistic_delete() {
        fresh_snapshot();
        fresh_pending();
        // Message lives in the snapshot (e.g. previously read → kept), then
        // the user deletes it.
        local_mark_read("alice", 21, kept("bob", "to delete"));
        local_delete_message("alice", 21);
        assert!(is_deleted("alice", 21), "delete recorded optimistically");

        // Stale echo predating the DeleteMessage write — still shows the
        // message as kept, no deletion recorded.
        let mut echoed = LocalState::default();
        let entry = echoed.aliases_mut().entry("alice".to_string()).or_default();
        entry.read.push(21);
        entry
            .kept
            .insert("21".to_string(), kept("bob", "to delete"));
        replace_snapshot(echoed);

        assert!(
            is_deleted("alice", 21),
            "deletion must survive a stale echo — message must not return (#265)",
        );
        assert!(
            kept_for("alice").is_empty(),
            "deleted message must not be re-surfaced as kept on stale echo (#265)",
        );
    }

    /// Repro for #265 — archived messages bouncing back to Inbox. Same shape:
    /// optimistic `local_archive_message`, stale echo lacking the archive
    /// overwrites SNAPSHOT, archive lost.
    #[test]
    fn replace_snapshot_does_not_clobber_optimistic_archive() {
        fresh_snapshot();
        fresh_pending();
        local_archive_message(
            "alice",
            33,
            ArchivedMessage {
                from: "bob".into(),
                title: "to archive".into(),
                content: "body".into(),
                archived_at: 1,
                ..Default::default()
            },
        );
        assert!(is_archived("alice", 33), "archive recorded optimistically");

        let mut echoed = LocalState::default();
        echoed.aliases_mut().entry("alice".to_string()).or_default();
        replace_snapshot(echoed);

        assert!(
            is_archived("alice", 33),
            "archive must survive a stale echo (#265)",
        );
    }

    /// Lifecycle: once the delegate echoes a snapshot that includes the Sent
    /// entry, the `OPTIMISTIC_SENT` protection drops. A later echo that lacks
    /// it (e.g. the user deleted the sent row) must NOT resurrect it.
    #[test]
    fn optimistic_sent_drops_after_delegate_echo_includes_entry() {
        fresh_snapshot();
        fresh_pending();
        local_save_sent("alice", "s-1", sent("bob", "hi"));

        // Authoritative echo — delegate has the sent entry.
        let mut echoed = LocalState::default();
        echoed
            .aliases_mut()
            .entry("alice".to_string())
            .or_default()
            .sent
            .insert("s-1".to_string(), sent("bob", "hi"));
        replace_snapshot(echoed);

        // A later echo without the entry must not bring it back.
        let mut later = LocalState::default();
        later.aliases_mut().entry("alice".to_string()).or_default();
        replace_snapshot(later);

        assert!(
            sent_for("alice").is_empty(),
            "sent protection must drop once delegate confirms the entry (#265)",
        );
    }

    /// Lifecycle: deletion tombstone drops once the delegate echoes the
    /// deletion, so it doesn't pin a message as deleted forever.
    #[test]
    fn deleted_message_tombstone_drops_after_delegate_confirms() {
        fresh_snapshot();
        fresh_pending();
        local_mark_read("alice", 41, kept("bob", "x"));
        local_delete_message("alice", 41);

        // Authoritative echo — delegate records the deletion.
        let mut echoed = LocalState::default();
        echoed
            .aliases_mut()
            .entry("alice".to_string())
            .or_default()
            .deleted
            .push(41);
        replace_snapshot(echoed);

        // Tombstone should be gone now — confirm by checking it isn't
        // re-applied to a fresh echo that has neither the message nor the
        // deletion (simulating the message legitimately gone from the node).
        let mut later = LocalState::default();
        later.aliases_mut().entry("alice".to_string()).or_default();
        replace_snapshot(later);

        assert!(
            !is_deleted("alice", 41),
            "deletion tombstone must drop once delegate confirms it (#265)",
        );
    }

    fn draft(to: &str, subject: &str) -> Draft {
        Draft {
            to: to.into(),
            subject: subject.into(),
            body: "body".into(),
            updated_at: 0,
            ..Default::default()
        }
    }

    /// End-to-end of the exact beta-tester flow (#265): compose a draft, send
    /// it (which saves a Sent row and deletes the draft), then a reload fires a
    /// stale `GetAll` echo that predates both writes. After the reload the Sent
    /// row must survive and the draft must stay gone — i.e. the message does
    /// NOT "move back to Draft".
    #[test]
    fn compose_send_then_reload_keeps_sent_and_drops_draft() {
        fresh_snapshot();
        fresh_pending();

        // 1. Compose: autosave stashes a draft.
        local_save_draft("alice", "draft-1", draft("bob", "hello"));
        assert_eq!(drafts_for("alice").len(), 1, "draft saved while composing");

        // 2. Send succeeds: a Sent row is stashed and the draft deleted (the
        //    real compose-send path runs both, app.rs ~2898 + delete_draft_now).
        local_save_sent("alice", "sent-1", sent("bob", "hello"));
        local_delete_draft("alice", "draft-1");
        assert_eq!(sent_for("alice").len(), 1, "sent row stashed on send");
        assert!(drafts_for("alice").is_empty(), "draft cleared on send");

        // 3. Reload: a stale delegate `GetAll` echo lands that predates the
        //    SaveSent + DeleteDraft writes — it still shows the old draft and
        //    no sent row. Before the #265 fix this clobbered the Sent stash and
        //    (combined with a failed draft-delete) surfaced the message as a
        //    Draft again.
        let mut stale = LocalState::default();
        stale
            .aliases_mut()
            .entry("alice".to_string())
            .or_default()
            .drafts
            .insert("draft-1".to_string(), draft("bob", "hello"));
        replace_snapshot(stale);

        // Post-reload invariants:
        assert_eq!(
            sent_for("alice").len(),
            1,
            "Sent row must survive the reload — message stays in Sent (#265)",
        );
        assert_eq!(sent_for("alice")[0].0, "sent-1");
        assert!(
            drafts_for("alice").is_empty(),
            "deleted draft must not resurrect — message must NOT move back to Draft (#265)",
        );
    }

    /// Regression for #137 / #141: `kept` is a `HashMap`, so iteration order
    /// is non-deterministic. After sorting the `kept_for` output with the same
    /// `(kept_at, id)` comparator used in the inbox rebuild, the result must
    /// be identical regardless of HashMap insertion order.
    ///
    /// This test builds a synthetic AliasState with 6 messages all sharing
    /// the same `kept_at` timestamp (forcing the tie-break to decide the final
    /// order), then re-inserts them in 10 different permutations and asserts
    /// that `sorted(kept_for(...))` is the same every time.
    #[test]
    fn kept_for_sort_is_stable_across_hashmap_insertion_orders() {
        const SHARED_KEPT_AT: i64 = 1_000_000;

        // Build a batch of (id, KeptMessage) with identical kept_at so the
        // tie-break by id is what determines order.
        let make_batch = |order: &[MessageId]| {
            let mut state = LocalState::default();
            let entry = state.aliases_mut().entry("alice".to_string()).or_default();
            for &id in order {
                entry.kept.insert(
                    id.to_string(),
                    KeptMessage {
                        from: "bob".into(),
                        title: format!("msg-{id}"),
                        content: "body".into(),
                        kept_at: SHARED_KEPT_AT,
                        sent_at: None,
                        sender_vk: Vec::new(),
                        signature_valid: false,
                    },
                );
            }
            state
        };

        // Sort helper: mirrors the sort_cmp_inbox tie-break logic of (time desc, id desc).
        let sort_entries = |mut v: Vec<(MessageId, KeptMessage)>| -> Vec<MessageId> {
            v.sort_by(|(a_id, a_k), (b_id, b_k)| {
                b_k.kept_at.cmp(&a_k.kept_at).then(b_id.cmp(a_id))
            });
            v.into_iter().map(|(id, _)| id).collect()
        };

        // 10 insertion orders (hand-enumerated permutations of the 6-element vec).
        let permutations: &[&[MessageId]] = &[
            &[3, 1, 5, 2, 4, 6],
            &[6, 4, 2, 5, 1, 3],
            &[1, 2, 3, 4, 5, 6],
            &[6, 5, 4, 3, 2, 1],
            &[2, 4, 6, 1, 3, 5],
            &[5, 3, 1, 6, 4, 2],
            &[1, 6, 2, 5, 3, 4],
            &[4, 2, 6, 3, 5, 1],
            &[3, 5, 1, 4, 2, 6],
            &[6, 1, 4, 2, 5, 3],
        ];

        let mut results: Vec<Vec<MessageId>> = Vec::with_capacity(permutations.len());
        for &perm in permutations {
            let snapshot = make_batch(perm);
            replace_snapshot(snapshot);
            let entries = kept_for("alice");
            results.push(sort_entries(entries));
        }

        // Every permutation must produce the same sorted order.
        let expected = results[0].clone();
        for (i, result) in results.iter().enumerate() {
            assert_eq!(
                *result, expected,
                "permutation {i} produced a different sort order: {result:?} vs {expected:?}",
            );
        }

        // Sanity: expected order is ids descending (6,5,4,3,2,1) because
        // kept_at is identical for all and we tie-break by id descending.
        assert_eq!(expected, vec![6, 5, 4, 3, 2, 1]);
    }

    // ----- #288: terminal-state guard on the Sent delivery-state setter -----

    fn sent_row(to: &str) -> SentMessage {
        SentMessage {
            to: to.into(),
            ..Default::default()
        }
    }

    fn delivery_state_of(alias: &str, id: &str) -> DeliveryState {
        sent_for(alias)
            .into_iter()
            .find(|(i, _)| i == id)
            .map(|(_, m)| m.delivery_state)
            .expect("sent row present")
    }

    /// #286: a Sent row still Pending after a reload, with no send in this
    /// page waiting on it, was left by a session that ended mid-send. It is
    /// reported as stranded; a row this page is still sending, and terminal
    /// rows, are not.
    #[test]
    fn a_pending_row_no_send_is_waiting_on_is_stranded_286() {
        fresh_snapshot();
        local_save_sent("alice", "left", sent_row("bob"));
        local_save_sent("alice", "sending", sent_row("bob"));
        local_save_sent("alice", "done", sent_row("bob"));
        let _ = local_set_sent_delivery_state("alice", "done", DeliveryState::Delivered);
        local_save_sent("carol", "elsewhere", sent_row("bob"));
        let in_flight: HashSet<(String, String)> =
            [("alice".to_string(), "sending".to_string())].into();
        // `sent_row` rows were sent at 0: long enough ago.
        assert_eq!(
            stranded_pending_sent(&["alice".to_string()], &in_flight, 1_000_000, 90_000),
            vec![("alice".to_string(), "left".to_string())]
        );
    }

    /// A Pending row sent less than the stale-send timeout ago may be
    /// another open tab's send in flight (this page's in-flight set knows
    /// only its own sends): it is not stranded, so this page never writes a
    /// Failed that the sending tab's Delivered would then be refused over.
    #[test]
    fn a_recent_pending_row_from_another_tab_is_not_stranded() {
        fresh_snapshot();
        let (now, timeout) = (1_000_000, 90_000);
        let at = |sent_at| SentMessage {
            sent_at,
            ..sent_row("bob")
        };
        local_save_sent("alice", "other-tab", at(now - 10_000));
        local_save_sent("alice", "old", at(now - timeout));
        assert_eq!(
            stranded_pending_sent(&["alice".to_string()], &HashSet::new(), now, timeout),
            vec![("alice".to_string(), "old".to_string())]
        );
    }

    #[test]
    fn pending_can_transition_to_either_terminal_288() {
        fresh_snapshot();
        local_save_sent("alice", "s1", sent_row("bob"));
        local_save_sent("alice", "s2", sent_row("carol"));
        assert_eq!(delivery_state_of("alice", "s1"), DeliveryState::Pending);

        assert!(local_set_sent_delivery_state(
            "alice",
            "s1",
            DeliveryState::Delivered
        ));
        assert!(local_set_sent_delivery_state(
            "alice",
            "s2",
            DeliveryState::Failed
        ));
        assert_eq!(delivery_state_of("alice", "s1"), DeliveryState::Delivered);
        assert_eq!(delivery_state_of("alice", "s2"), DeliveryState::Failed);
    }

    #[test]
    fn failed_row_never_resurrects_to_delivered_288() {
        // The core race the sweep introduces: timeout flips a row Failed,
        // then a late mis-paired UpdateResponse tries Delivered. Must no-op.
        fresh_snapshot();
        local_save_sent("alice", "s1", sent_row("bob"));
        assert!(local_set_sent_delivery_state(
            "alice",
            "s1",
            DeliveryState::Failed
        ));

        let changed = local_set_sent_delivery_state("alice", "s1", DeliveryState::Delivered);
        assert!(
            !changed,
            "terminal Failed must not transition; caller skips delegate write"
        );
        assert_eq!(
            delivery_state_of("alice", "s1"),
            DeliveryState::Failed,
            "row stays Failed"
        );
    }

    #[test]
    fn delivered_row_never_flaps_to_failed_288() {
        // Symmetric: a delivered send must not be flipped Failed by a late
        // stale-send sweep that mis-targets it.
        fresh_snapshot();
        local_save_sent("alice", "s1", sent_row("bob"));
        assert!(local_set_sent_delivery_state(
            "alice",
            "s1",
            DeliveryState::Delivered
        ));

        let changed = local_set_sent_delivery_state("alice", "s1", DeliveryState::Failed);
        assert!(!changed, "terminal Delivered must not transition");
        assert_eq!(delivery_state_of("alice", "s1"), DeliveryState::Delivered);
    }

    #[test]
    fn set_delivery_state_on_absent_row_is_noop_288() {
        fresh_snapshot();
        let changed = local_set_sent_delivery_state("ghost", "nope", DeliveryState::Failed);
        assert!(
            !changed,
            "absent row → false, caller must skip delegate write"
        );
    }
}
