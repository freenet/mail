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

use mail_local_state::{Draft, KeptMessage, LocalState, LocalStateMsg, MessageId};

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
}

#[cfg(feature = "use-node")]
pub(crate) use wire::{
    LOCAL_STATE_KEY, delete_draft, fetch_all, mark_read, register_and_init, save_draft,
};

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

pub(crate) fn new_draft_id() -> String {
    uuid::Uuid::new_v4().to_string()
}
