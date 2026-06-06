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
pub(crate) use wire::delete_sent;
#[cfg(feature = "use-node")]
pub(crate) use wire::{
    LOCAL_STATE_KEY, archive_message, delete_draft, delete_message, fetch_all, mark_read,
    register_and_init, save_draft, save_sent, set_sent_delivery_state,
};
// `unarchive_message` is wired but unused until later phases.
#[cfg(feature = "use-node")]
#[allow(unused_imports)]
pub(crate) use wire::unarchive_message;

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
            .insert(id.to_string(), sent.clone());
    });
    // Protect the optimistic Sent entry until `SaveSent` round-trips, so a
    // stale `GetAll` echo doesn't wipe it (#265).
    OPTIMISTIC_SENT.with(|p| {
        p.borrow_mut()
            .insert((alias.to_string(), id.to_string()), sent);
    });
    bump();
}

pub(crate) fn local_delete_sent(alias: &str, id: &str) {
    SNAPSHOT.with(|s| {
        let mut state = s.borrow_mut();
        if let Some(entry) = state.aliases_mut().get_mut(alias) {
            entry.sent.remove(id);
        }
    });
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
    let changed = SNAPSHOT.with(|s| {
        let mut snap = s.borrow_mut();
        if let Some(entry) = snap.aliases_mut().get_mut(alias)
            && let Some(sent) = entry.sent.get_mut(id)
        {
            // Pending is the only non-terminal state. Once a row reaches
            // Delivered or Failed it must NOT flip again (#288): the
            // stale-send timeout sweep can drain a Pending entry and flip it
            // Failed, after which a late `UpdateResponse` would otherwise
            // mis-pair (FIFO pop) and resurrect the wrong row to Delivered —
            // or flap a delivered row back to Failed. Terminal states stick.
            if delivery_state_is_terminal(sent.delivery_state) {
                return false;
            }
            sent.delivery_state = state;
            true
        } else {
            false
        }
    });
    if changed {
        bump();
    }
    changed
}

/// `Delivered` and `Failed` are terminal; `Pending` is the only state a
/// later transition may overwrite. Centralised so the local stash and the
/// delegate writer agree on the guard.
pub(crate) fn delivery_state_is_terminal(state: DeliveryState) -> bool {
    matches!(state, DeliveryState::Delivered | DeliveryState::Failed)
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
        entry.archived.insert(msg_id.to_string(), archived.clone());
    });
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

#[allow(dead_code)] // Wired for #60 (true unarchive).
pub(crate) fn local_unarchive_message(alias: &str, msg_id: MessageId) {
    SNAPSHOT.with(|s| {
        let mut state = s.borrow_mut();
        if let Some(entry) = state.aliases_mut().get_mut(alias) {
            entry.archived.remove(&msg_id.to_string());
        }
    });
    // Drop optimistic-archive protection so a stale echo doesn't re-archive
    // a message the user just unarchived (#265).
    OPTIMISTIC_ARCHIVED.with(|p| {
        p.borrow_mut()
            .remove(&(alias.to_string(), msg_id.to_string()));
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

/// Mint a fresh stable conversation id (#270). Used when a reply is the first
/// message to thread a conversation that previously had no `thread_id` (legacy
/// parent), and whenever a new outbound message starts a fresh conversation.
pub(crate) fn new_thread_id() -> String {
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
