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
use std::sync::atomic::{AtomicUsize, Ordering};

use mail_local_state::{
    ArchivedMessage, DeliveryState, Draft, GlobalSettings, IdentitySettings, KeptMessage,
    LocalState, LocalStateMsg, MessageId, SentMessage,
};

thread_local! {
    /// Most recent snapshot returned by the delegate. Replaced wholesale on
    /// each `GetAll` response; mutations in the UI optimistically patch this
    /// copy and also send the corresponding `LocalStateMsg` to the delegate.
    static SNAPSHOT: RefCell<LocalState> = RefCell::new(LocalState::default());
}

/// Bumped on every snapshot mutation. Components that read drafts/read-state
/// gate a `use_memo` on this value to know when to re-pull from `SNAPSHOT`.
pub(crate) static GENERATION: AtomicUsize = AtomicUsize::new(0);

fn bump() {
    GENERATION.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn replace_snapshot(new: LocalState) {
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
    bump();
}

pub(crate) fn local_mark_read(alias: &str, msg_id: MessageId, kept: KeptMessage) {
    SNAPSHOT.with(|s| {
        let mut state = s.borrow_mut();
        let entry = state.aliases_mut().entry(alias.to_string()).or_default();
        if !entry.read.contains(&msg_id) {
            entry.read.push(msg_id);
        }
        entry.kept.insert(msg_id.to_string(), kept);
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
