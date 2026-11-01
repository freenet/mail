//! The walk on a real node: requests to legacy delegates and inbox contracts,
//! each awaited with a timeout.
//!
//! Replies reach the page through one shared handler. Each request waits in a
//! slot keyed by what it asked (a delegate key, an inbox key), and the walk
//! asks one thing at a time, so a reply finds its waiter by that key. No
//! answer in time is [`LegacyReply::NoAnswer`], never "absent".

use std::cell::RefCell;
use std::collections::HashMap;

use freenet_mail_protocol::{Op, Reply};
use freenet_mail_wire_v1::inbox::{Inbox, InboxParams};
use freenet_stdlib::client_api::{ContractRequest, DelegateError, DelegateRequest};
use freenet_stdlib::prelude::{
    ApplicationMessage, ContractInstanceId, ContractKey, DelegateKey, InboundDelegateMsg,
    OutboundDelegateMsg, Parameters,
};
use futures::channel::oneshot;

use super::legacy_delegates::{LegacyReply, LegacyTransport};
use super::successor::{MailStore, V1InboxReader};
use crate::mail_delegate::CallError;

/// How long a legacy delegate or an inbox GET gets to answer.
const REPLY_TIMEOUT_MS: u32 = 15_000;

thread_local! {
    static LEGACY_WAITER: RefCell<HashMap<DelegateKey, oneshot::Sender<LegacyReply>>> =
        RefCell::new(HashMap::new());
    static INBOX_WAITER: RefCell<HashMap<ContractKey, oneshot::Sender<Option<Vec<u8>>>>> =
        RefCell::new(HashMap::new());
}

/// What a legacy delegate's response established. An empty reply and one with
/// no application message are not answers.
pub(crate) fn classify_response(values: &[OutboundDelegateMsg]) -> LegacyReply {
    values
        .iter()
        .find_map(|msg| match msg {
            OutboundDelegateMsg::ApplicationMessage(app) if !app.payload.is_empty() => {
                Some(LegacyReply::Answer(app.payload.to_vec()))
            }
            _ => None,
        })
        .unwrap_or_else(|| LegacyReply::NoAnswer("an empty reply".to_string()))
}

/// What a node delegate error means for a legacy request to `waiting`, `None`
/// if it is not about that request. An error naming another delegate is not;
/// one naming none is taken to be the request in flight's.
pub(crate) fn classify_error(error: &DelegateError, waiting: &DelegateKey) -> Option<LegacyReply> {
    match error {
        DelegateError::Missing(key) => (key == waiting).then_some(LegacyReply::NotInstalled),
        DelegateError::RegisterError(key) | DelegateError::MissingSecret { key, .. } => {
            (key == waiting).then(|| LegacyReply::NoAnswer(error.to_string()))
        }
        _ => Some(LegacyReply::NoAnswer(error.to_string())),
    }
}

/// Whether a legacy request is waiting on `key`: its response goes there.
pub(crate) fn takes_response(key: &DelegateKey) -> bool {
    LEGACY_WAITER.with(|w| w.borrow().contains_key(key))
}

/// Hand a legacy delegate's response to its waiter.
pub(crate) fn offer_response(key: &DelegateKey, values: &[OutboundDelegateMsg]) {
    if let Some(waiter) = LEGACY_WAITER.with(|w| w.borrow_mut().remove(key)) {
        let _ = waiter.send(classify_response(values));
    }
}

/// Offer a node delegate error to the waiting legacy request. Returns whether
/// it took it; if so the error is not a mail-delegate call's.
pub(crate) fn offer_error(error: &DelegateError) -> bool {
    let waiting = LEGACY_WAITER.with(|w| w.borrow().keys().next().cloned());
    let Some(key) = waiting else {
        return false;
    };
    let Some(reply) = classify_error(error, &key) else {
        return false;
    };
    if let Some(waiter) = LEGACY_WAITER.with(|w| w.borrow_mut().remove(&key)) {
        let _ = waiter.send(reply);
    }
    true
}

/// Hand a contract's state to an inbox read waiting for it. The caller goes
/// on to handle the response as usual.
pub(crate) fn offer_contract_state(key: &ContractKey, state: &[u8]) {
    if let Some(waiter) = INBOX_WAITER.with(|w| w.borrow_mut().remove(key)) {
        let _ = waiter.send(Some(state.to_vec()));
    }
}

/// A GET found nothing: an inbox read waiting on it stops waiting.
pub(crate) fn offer_contract_not_found(instance: &ContractInstanceId) {
    let waiter = INBOX_WAITER.with(|w| {
        let mut waiters = w.borrow_mut();
        let key = waiters.keys().find(|k| k.id() == instance).copied()?;
        waiters.remove(&key)
    });
    if let Some(waiter) = waiter {
        let _ = waiter.send(None);
    }
}

/// `rx`'s value, or `None` after the timeout or if its sender went away.
async fn answer_of<T>(rx: oneshot::Receiver<T>) -> Option<T> {
    #[cfg(target_family = "wasm")]
    {
        use futures::FutureExt;
        let mut rx = rx.fuse();
        let mut timer = gloo_timers::future::TimeoutFuture::new(REPLY_TIMEOUT_MS).fuse();
        futures::select! {
            answer = rx => answer.ok(),
            _ = timer => None,
        }
    }
    #[cfg(not(target_family = "wasm"))]
    {
        let _ = REPLY_TIMEOUT_MS;
        rx.await.ok()
    }
}

/// The node, as the walk's reader.
pub(crate) struct NodeLegacy;

impl LegacyTransport for NodeLegacy {
    async fn ask(
        &mut self,
        predecessor: &DelegateKey,
        params: &'static [u8],
        request: Vec<u8>,
    ) -> LegacyReply {
        let Some(client) = crate::api::WEB_API_SENDER.get() else {
            return LegacyReply::NoAnswer("not connected to the node".to_string());
        };
        let mut client = client.clone();
        let (tx, rx) = oneshot::channel();
        LEGACY_WAITER.with(|w| w.borrow_mut().insert(predecessor.clone(), tx));
        let sent = client
            .send(
                DelegateRequest::ApplicationMessages {
                    key: predecessor.clone(),
                    params: Parameters::from(params.to_vec()),
                    inbound: vec![InboundDelegateMsg::ApplicationMessage(
                        ApplicationMessage::new(request),
                    )],
                }
                .into(),
            )
            .await;
        let reply = match sent {
            Err(e) => LegacyReply::NoAnswer(format!("send: {e}")),
            Ok(()) => answer_of(rx)
                .await
                .unwrap_or_else(|| LegacyReply::NoAnswer("no reply in time".to_string())),
        };
        LEGACY_WAITER.with(|w| w.borrow_mut().remove(predecessor));
        reply
    }
}

/// The mail delegate, through the page's usual calls.
pub(crate) struct NodeStore;

impl MailStore for NodeStore {
    async fn call(&mut self, op: Op) -> Result<Reply, CallError> {
        crate::mail_delegate::call(op).await
    }
}

/// An identity's v1 inbox, read with a GET.
pub(crate) struct NodeInbox;

impl V1InboxReader for NodeInbox {
    async fn ciphertexts(&mut self, vk: &[u8]) -> Option<Vec<Vec<u8>>> {
        let params: Parameters<'_> = InboxParams {
            pub_key: vk.to_vec(),
        }
        .try_into()
        .ok()?;
        let key = ContractKey::from_params(crate::inbox::INBOX_CODE_HASH.trim(), params).ok()?;
        let mut client = crate::api::WEB_API_SENDER.get()?.clone();
        let (tx, rx) = oneshot::channel();
        INBOX_WAITER.with(|w| w.borrow_mut().insert(key, tx));
        let request = ContractRequest::Get {
            key: key.into(),
            return_contract_code: false,
            subscribe: false,
            blocking_subscribe: false,
        };
        let state = match client.send(request.into()).await {
            Ok(()) => answer_of(rx).await.flatten(),
            Err(_) => None,
        };
        INBOX_WAITER.with(|w| w.borrow_mut().remove(&key));
        let inbox: Inbox = serde_json::from_slice(&state?).ok()?;
        Some(inbox.messages.into_iter().map(|m| m.content).collect())
    }
}

/// This load's migration. Runs before the identities are listed, so what it
/// imports is what the load shows, and nothing the load writes (the contract
/// markers `identity_store::prepare` stamps) can precede it.
pub(crate) async fn run_on_load() {
    let roll = crate::rng::random_bytes::<1>()[0];
    let outcome = super::run(NodeStore, NodeLegacy, NodeInbox, roll).await;
    if let Some(line) = super::status_line(&outcome) {
        crate::log::info(line);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use freenet_stdlib::prelude::CodeHash;

    fn key(b: u8) -> DelegateKey {
        DelegateKey::new([b; 32], CodeHash::new([b; 32]))
    }

    #[test]
    fn only_an_application_message_with_bytes_is_an_answer() {
        assert!(matches!(classify_response(&[]), LegacyReply::NoAnswer(_)));
        let empty = OutboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(Vec::new()));
        assert!(matches!(
            classify_response(&[empty]),
            LegacyReply::NoAnswer(_)
        ));
        let full = OutboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(vec![1, 2]));
        assert_eq!(classify_response(&[full]), LegacyReply::Answer(vec![1, 2]));
    }

    #[test]
    fn only_a_typed_missing_for_this_delegate_is_not_installed() {
        let waiting = key(1);
        assert_eq!(
            classify_error(&DelegateError::Missing(waiting.clone()), &waiting),
            Some(LegacyReply::NotInstalled)
        );
        assert_eq!(
            classify_error(&DelegateError::Missing(key(2)), &waiting),
            None
        );
        assert!(matches!(
            classify_error(&DelegateError::ExecutionError("trap".into()), &waiting),
            Some(LegacyReply::NoAnswer(_))
        ));
    }
}
