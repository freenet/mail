//! UI-side mirror of the `mail-local-state` delegate.
//!
//! Holds the most recent `LocalState` snapshot returned by the delegate, plus
//! a Dioxus signal generation counter that components subscribe to so they
//! re-render when drafts / read-state / kept messages change.
//!
//! Per-device only (issue #47, 47a). The delegate stash is keyed by a single
//! P-384 secret committed at build time; per-alias scoping happens inside the
//! `LocalState` value (`AliasState` keyed by alias string).

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use dioxus::prelude::*;
use mail_local_state::{
    ArchivedMessage, DeliveryState, Draft, GlobalSettings, IdentitySettings, KeptMessage,
    LocalState, LocalStateMsg, MessageId, SentMessage,
};

thread_local! {
    /// Most recent snapshot returned by the delegate. Replaced wholesale on
    /// each `GetAll` response; mutations in the UI optimistically patch this
    /// copy and also send the corresponding `LocalStateMsg` to the delegate.
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

pub(crate) fn replace_snapshot(new: LocalState) {
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
            false
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
    SNAPSHOT.with(|s| *s.borrow_mut() = new);
    bump();
}

pub(crate) fn drafts_for(alias: &str) -> Vec<(String, Draft)> {
    SNAPSHOT.with(|s| {
        s.borrow()
            .drafts_of(alias)
            .map(|(id, d)| (id.clone(), d.clone()))
            .collect()
    })
}

pub(crate) fn is_read(alias: &str, id: MessageId) -> bool {
    SNAPSHOT.with(|s| s.borrow().is_read(alias, id))
}

pub(crate) fn archived_for(alias: &str) -> Vec<(MessageId, ArchivedMessage)> {
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
    SNAPSHOT.with(|s| s.borrow().is_archived(alias, id))
}

pub(crate) fn is_deleted(alias: &str, id: MessageId) -> bool {
    SNAPSHOT.with(|s| s.borrow().is_deleted(alias, id))
}

pub(crate) fn sent_for(alias: &str) -> Vec<(String, SentMessage)> {
    SNAPSHOT.with(|s| {
        s.borrow()
            .sent_of(alias)
            .map(|(id, m)| (id.clone(), m.clone()))
            .collect()
    })
}

pub(crate) fn kept_for(alias: &str) -> Vec<(MessageId, KeptMessage)> {
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
    SNAPSHOT.with(|s| s.borrow().identity_settings(alias))
}

pub(crate) fn global_settings() -> GlobalSettings {
    SNAPSHOT.with(|s| s.borrow().global_settings().clone())
}

#[cfg(feature = "use-node")]
mod wire {
    use super::*;
    use crate::DynError;
    use crate::api::WebApiRequestClient;
    use freenet_stdlib::{
        client_api::DelegateRequest,
        prelude::{ApplicationMessage, DelegateKey, InboundDelegateMsg, Parameters},
    };
    use mail_local_state::LocalStateParams;
    use std::sync::OnceLock;

    const CODE_HASH: &str =
        include_str!("../../modules/mail-local-state/build/mail_local_state_code_hash");
    const CODE: &[u8] =
        include_bytes!("../../modules/mail-local-state/build/freenet/mail_local_state");
    const PARAMS: &[u8] =
        include_bytes!("../../modules/mail-local-state/build/mail-local-state-params");

    /// Set after the delegate is registered + its initial `GetAll` is issued.
    /// Used by the response handler in `api::node_comms` to recognise replies
    /// destined for this delegate.
    pub(crate) static LOCAL_STATE_KEY: OnceLock<DelegateKey> = OnceLock::new();

    fn params() -> Result<Parameters<'static>, DynError> {
        let p = LocalStateParams::try_from(PARAMS)?;
        Ok(Parameters::try_from(p)?)
    }

    pub(crate) async fn register_and_init(
        client: &mut WebApiRequestClient,
    ) -> Result<DelegateKey, DynError> {
        let params = params()?;
        let key = crate::api::create_delegate(client, CODE_HASH, CODE, &params).await?;
        // Init is idempotent in the delegate.
        let request = DelegateRequest::ApplicationMessages {
            params: params.clone(),
            inbound: vec![InboundDelegateMsg::ApplicationMessage(
                ApplicationMessage::new(Vec::<u8>::try_from(&LocalStateMsg::Init)?),
            )],
            key: key.clone(),
        };
        client.send(request.into()).await?;
        Ok(key)
    }

    pub(crate) async fn fetch_all(
        client: &mut WebApiRequestClient,
        key: &DelegateKey,
    ) -> Result<(), DynError> {
        let params = params()?;
        let request = DelegateRequest::ApplicationMessages {
            params,
            inbound: vec![InboundDelegateMsg::ApplicationMessage(
                ApplicationMessage::new(Vec::<u8>::try_from(&LocalStateMsg::GetAll)?),
            )],
            key: key.clone(),
        };
        client.send(request.into()).await?;
        Ok(())
    }

    async fn send_msg(
        client: &mut WebApiRequestClient,
        msg: &LocalStateMsg,
    ) -> Result<(), DynError> {
        let key = match LOCAL_STATE_KEY.get() {
            Some(k) => k.clone(),
            None => return Err("local-state delegate not yet registered".into()),
        };
        let params = params()?;
        let request = DelegateRequest::ApplicationMessages {
            params,
            inbound: vec![InboundDelegateMsg::ApplicationMessage(
                ApplicationMessage::new(Vec::<u8>::try_from(msg)?),
            )],
            key,
        };
        client.send(request.into()).await?;
        Ok(())
    }

    pub(crate) async fn save_draft(
        client: &mut WebApiRequestClient,
        alias: String,
        id: String,
        draft: Draft,
    ) -> Result<(), DynError> {
        send_msg(client, &LocalStateMsg::SaveDraft { alias, id, draft }).await
    }

    pub(crate) async fn delete_draft(
        client: &mut WebApiRequestClient,
        alias: String,
        id: String,
    ) -> Result<(), DynError> {
        send_msg(client, &LocalStateMsg::DeleteDraft { alias, id }).await
    }

    pub(crate) async fn mark_read(
        client: &mut WebApiRequestClient,
        alias: String,
        msg_id: MessageId,
        kept: KeptMessage,
    ) -> Result<(), DynError> {
        send_msg(
            client,
            &LocalStateMsg::MarkRead {
                alias,
                msg_id,
                kept,
            },
        )
        .await
    }

    pub(crate) async fn archive_message(
        client: &mut WebApiRequestClient,
        alias: String,
        msg_id: MessageId,
        archived: ArchivedMessage,
    ) -> Result<(), DynError> {
        send_msg(
            client,
            &LocalStateMsg::ArchiveMessage {
                alias,
                msg_id,
                archived,
            },
        )
        .await
    }

    #[allow(dead_code)] // Wired for #60 (true unarchive); unused until then.
    pub(crate) async fn unarchive_message(
        client: &mut WebApiRequestClient,
        alias: String,
        msg_id: MessageId,
    ) -> Result<(), DynError> {
        send_msg(client, &LocalStateMsg::UnarchiveMessage { alias, msg_id }).await
    }

    pub(crate) async fn delete_message(
        client: &mut WebApiRequestClient,
        alias: String,
        msg_id: MessageId,
    ) -> Result<(), DynError> {
        send_msg(client, &LocalStateMsg::DeleteMessage { alias, msg_id }).await
    }

    pub(crate) async fn save_sent(
        client: &mut WebApiRequestClient,
        alias: String,
        id: String,
        sent: SentMessage,
    ) -> Result<(), DynError> {
        send_msg(client, &LocalStateMsg::SaveSent { alias, id, sent }).await
    }

    #[allow(dead_code)] // Wired for 47c (Archive); unused until then.
    pub(crate) async fn delete_sent(
        client: &mut WebApiRequestClient,
        alias: String,
        id: String,
    ) -> Result<(), DynError> {
        send_msg(client, &LocalStateMsg::DeleteSent { alias, id }).await
    }

    pub(crate) async fn set_sent_delivery_state(
        client: &mut WebApiRequestClient,
        alias: String,
        id: String,
        state: DeliveryState,
    ) -> Result<(), DynError> {
        send_msg(
            client,
            &LocalStateMsg::SetSentDeliveryState { alias, id, state },
        )
        .await
    }

    pub(crate) async fn set_identity_settings(
        client: &mut WebApiRequestClient,
        alias: String,
        settings: IdentitySettings,
    ) -> Result<(), DynError> {
        send_msg(
            client,
            &LocalStateMsg::SetIdentitySettings { alias, settings },
        )
        .await
    }

    pub(crate) async fn set_global_settings(
        client: &mut WebApiRequestClient,
        settings: GlobalSettings,
    ) -> Result<(), DynError> {
        send_msg(client, &LocalStateMsg::SetGlobalSettings { settings }).await
    }
}

#[cfg(feature = "use-node")]
pub(crate) use wire::{
    LOCAL_STATE_KEY, archive_message, delete_draft, delete_message, fetch_all, mark_read,
    register_and_init, save_draft, save_sent, set_sent_delivery_state,
};
// `delete_sent`, `local_delete_sent`, and `unarchive_message` are wired but
// unused until later phases.
#[cfg(feature = "use-node")]
#[allow(unused_imports)]
pub(crate) use wire::{delete_sent, unarchive_message};

// Optimistic local mutations: patch `SNAPSHOT` immediately so the UI
// re-renders without waiting for the delegate roundtrip.

pub(crate) fn local_save_draft(alias: &str, id: &str, draft: Draft) {
    SNAPSHOT.with(|s| {
        let mut state = s.borrow_mut();
        let key = alias.to_string();
        state
            .aliases_mut()
            .entry(key)
            .or_default()
            .drafts
            .insert(id.to_string(), draft);
    });
    bump();
}

pub(crate) fn local_delete_draft(alias: &str, id: &str) {
    SNAPSHOT.with(|s| {
        let mut state = s.borrow_mut();
        if let Some(entry) = state.aliases_mut().get_mut(alias) {
            entry.drafts.remove(id);
        }
    });
    // Tombstone protects against a stale `save_draft` echo that would
    // otherwise re-add this draft via `replace_snapshot` (#107).
    DELETED_DRAFTS.with(|t| {
        t.borrow_mut().insert((alias.to_string(), id.to_string()));
    });
    bump();
}

pub(crate) fn local_save_sent(alias: &str, id: &str, sent: SentMessage) {
    SNAPSHOT.with(|s| {
        let mut state = s.borrow_mut();
        state
            .aliases_mut()
            .entry(alias.to_string())
            .or_default()
            .sent
            .insert(id.to_string(), sent);
    });
    bump();
}

#[allow(dead_code)] // Wired for 47c (Archive); unused until then.
pub(crate) fn local_delete_sent(alias: &str, id: &str) {
    SNAPSHOT.with(|s| {
        let mut state = s.borrow_mut();
        if let Some(entry) = state.aliases_mut().get_mut(alias) {
            entry.sent.remove(id);
        }
    });
    bump();
}

pub(crate) fn local_set_sent_delivery_state(alias: &str, id: &str, state: DeliveryState) {
    SNAPSHOT.with(|s| {
        let mut snap = s.borrow_mut();
        if let Some(entry) = snap.aliases_mut().get_mut(alias)
            && let Some(sent) = entry.sent.get_mut(id)
        {
            sent.delivery_state = state;
        }
    });
    bump();
}

pub(crate) fn local_archive_message(alias: &str, msg_id: MessageId, archived: ArchivedMessage) {
    SNAPSHOT.with(|s| {
        let mut state = s.borrow_mut();
        let entry = state.aliases_mut().entry(alias.to_string()).or_default();
        // Mirrors the delegate semantics: archiving implies read, drops any
        // kept fallback for the same id, and stashes the snapshot.
        entry.kept.remove(&msg_id.to_string());
        if !entry.read.contains(&msg_id) {
            entry.read.push(msg_id);
        }
        entry.archived.insert(msg_id.to_string(), archived);
    });
    // Archive supersedes a pending kept tombstone — drop it so a stale
    // echo doesn't re-insert the kept entry under the archived row.
    PENDING_KEPT.with(|pending| {
        pending
            .borrow_mut()
            .remove(&(alias.to_string(), msg_id.to_string()));
    });
    bump();
}

#[allow(dead_code)] // Wired for #60 (true unarchive).
pub(crate) fn local_unarchive_message(alias: &str, msg_id: MessageId) {
    SNAPSHOT.with(|s| {
        let mut state = s.borrow_mut();
        if let Some(entry) = state.aliases_mut().get_mut(alias) {
            entry.archived.remove(&msg_id.to_string());
        }
    });
    bump();
}

pub(crate) fn local_delete_message(alias: &str, msg_id: MessageId) {
    SNAPSHOT.with(|s| {
        let mut state = s.borrow_mut();
        let entry = state.aliases_mut().entry(alias.to_string()).or_default();
        entry.kept.remove(&msg_id.to_string());
        entry.archived.remove(&msg_id.to_string());
        entry.read.retain(|id| *id != msg_id);
        if !entry.deleted.contains(&msg_id) {
            entry.deleted.push(msg_id);
        }
    });
    // Same as archive: delete supersedes a pending kept tombstone.
    PENDING_KEPT.with(|pending| {
        pending
            .borrow_mut()
            .remove(&(alias.to_string(), msg_id.to_string()));
    });
    bump();
}

pub(crate) fn local_mark_read(alias: &str, msg_id: MessageId, kept: KeptMessage) {
    SNAPSHOT.with(|s| {
        let mut state = s.borrow_mut();
        let entry = state.aliases_mut().entry(alias.to_string()).or_default();
        if !entry.read.contains(&msg_id) {
            entry.read.push(msg_id);
        }
        entry.kept.insert(msg_id.to_string(), kept.clone());
    });
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
    SNAPSHOT.with(|s| {
        let mut state = s.borrow_mut();
        state
            .aliases_mut()
            .entry(alias.to_string())
            .or_default()
            .settings = settings;
    });
    bump();
}

pub(crate) fn local_set_global_settings(settings: GlobalSettings) {
    SNAPSHOT.with(|s| {
        *s.borrow_mut().global_settings_mut() = settings;
    });
    bump();
}

/// Apply a per-identity settings change everywhere: optimistically patch the
/// in-memory snapshot for an immediate UI re-render, then (under `use-node`)
/// fire-and-forget the delegate dispatch so the value persists. Errors from
/// the dispatch are logged via `crate::log` but don't fail the call — the
/// local snapshot is the source of truth for the current session and the
/// delegate write is best-effort.
pub(crate) fn persist_identity_settings(alias: String, settings: IdentitySettings) {
    local_set_identity_settings(&alias, settings.clone());
    #[cfg(feature = "use-node")]
    {
        let Some(client) = crate::api::WEB_API_SENDER.get() else {
            return;
        };
        let mut client = client.clone();
        dioxus::prelude::spawn(async move {
            if let Err(e) = wire::set_identity_settings(&mut client, alias, settings).await {
                crate::log::error(format!("set_identity_settings failed: {e}"), None);
            }
        });
    }
    #[cfg(not(feature = "use-node"))]
    {
        let _ = (alias, settings);
    }
}

/// Apply a global settings change everywhere; same shape as
/// [`persist_identity_settings`].
pub(crate) fn persist_global_settings(settings: GlobalSettings) {
    local_set_global_settings(settings.clone());
    #[cfg(feature = "use-node")]
    {
        let Some(client) = crate::api::WEB_API_SENDER.get() else {
            return;
        };
        let mut client = client.clone();
        dioxus::prelude::spawn(async move {
            if let Err(e) = wire::set_global_settings(&mut client, settings).await {
                crate::log::error(format!("set_global_settings failed: {e}"), None);
            }
        });
    }
    #[cfg(not(feature = "use-node"))]
    {
        let _ = settings;
    }
}

pub(crate) fn new_draft_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub(crate) fn new_sent_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mail_local_state::KeptMessage;

    fn fresh_snapshot() {
        SNAPSHOT.with(|s| *s.borrow_mut() = LocalState::default());
    }

    fn kept(from: &str, title: &str) -> KeptMessage {
        KeptMessage {
            from: from.into(),
            title: title.into(),
            content: "body".into(),
            kept_at: 0,
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
        let entry = echoed
            .aliases_mut()
            .entry("alice".to_string())
            .or_default();
        entry.read.push(5);
        entry.kept.insert("5".to_string(), kept("bob", "kept"));
        replace_snapshot(echoed);

        let entries = kept_for("alice");
        assert_eq!(entries.len(), 1, "kept entry survives delegate echo");
        assert!(is_read("alice", 5));
    }

    fn fresh_pending() {
        PENDING_KEPT.with(|p| p.borrow_mut().clear());
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
        echoed
            .aliases_mut()
            .entry("alice".to_string())
            .or_default();
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
        let entry = echoed
            .aliases_mut()
            .entry("alice".to_string())
            .or_default();
        entry.kept.insert("11".to_string(), kept("bob", "transient"));
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
}
