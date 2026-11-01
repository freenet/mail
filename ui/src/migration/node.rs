//! The walk on a real node: requests to legacy delegates and inbox contracts,
//! each awaited with a timeout.
//!
//! Replies reach the page through one shared handler. Each request waits in a
//! slot keyed by what it asked (a delegate key, an inbox key), and the walk
//! asks one thing at a time, so a reply finds its waiter by that key. No
//! answer in time is [`LegacyReply::NoAnswer`], never "absent".

use std::cell::RefCell;
use std::collections::HashMap;

use freenet_mail_wire_v1::inbox::{Inbox, InboxParams};
use freenet_stdlib::client_api::{ContractRequest, DelegateError, DelegateRequest};
use freenet_stdlib::prelude::{
    ApplicationMessage, ContractInstanceId, ContractKey, DelegateKey, InboundDelegateMsg,
    OutboundDelegateMsg, Parameters,
};
use futures::channel::oneshot;

use super::legacy_delegates::{EMPTY_REPLY, LegacyReply, LegacyTransport};
use super::successor::V1InboxReader;

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
        .unwrap_or_else(|| LegacyReply::NoAnswer(EMPTY_REPLY.to_string()))
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

#[cfg(target_family = "wasm")]
fn timer(ms: u32) -> impl std::future::Future<Output = ()> + Unpin {
    gloo_timers::future::TimeoutFuture::new(ms)
}

/// A native build has no browser timer: tests are all that wait here.
#[cfg(not(target_family = "wasm"))]
fn timer(ms: u32) -> impl std::future::Future<Output = ()> + Unpin {
    use futures::FutureExt;
    let (fire, fired) = oneshot::channel();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(u64::from(ms)));
        let _ = fire.send(());
    });
    fired.map(|_| ())
}

/// `rx`'s value, or `None` after `timeout_ms` or if its sender went away.
async fn answer_of<T>(rx: oneshot::Receiver<T>, timeout_ms: u32) -> Option<T> {
    use futures::FutureExt;
    let mut rx = rx.fuse();
    let mut timer = timer(timeout_ms).fuse();
    futures::select! {
        answer = rx => answer.ok(),
        _ = timer => None,
    }
}

/// A legacy delegate's reply. No reply in time is a silence, never an absence.
async fn legacy_answer(rx: oneshot::Receiver<LegacyReply>, timeout_ms: u32) -> LegacyReply {
    answer_of(rx, timeout_ms)
        .await
        .unwrap_or_else(|| LegacyReply::NoAnswer("no reply in time".to_string()))
}

/// The node, as the walk's reader.
#[derive(Clone)]
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
            Ok(()) => legacy_answer(rx, REPLY_TIMEOUT_MS).await,
        };
        LEGACY_WAITER.with(|w| w.borrow_mut().remove(predecessor));
        reply
    }
}

/// An identity's v1 inbox, read with a GET.
#[derive(Clone)]
pub(crate) struct NodeInbox;

impl NodeInbox {
    /// The state of `vk`'s inbox under `code_hash`, if the node returns one.
    async fn state(vk: &[u8], code_hash: &str) -> Option<Vec<u8>> {
        let params: Parameters<'_> = InboxParams {
            pub_key: vk.to_vec(),
        }
        .try_into()
        .ok()?;
        let key = ContractKey::from_params(code_hash, params).ok()?;
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
            Ok(()) => answer_of(rx, REPLY_TIMEOUT_MS).await.flatten(),
            Err(_) => None,
        };
        INBOX_WAITER.with(|w| w.borrow_mut().remove(&key));
        state
    }
}

impl V1InboxReader for NodeInbox {
    async fn ciphertexts(&mut self, vk: &[u8]) -> Option<Vec<Vec<u8>>> {
        let state = Self::state(vk, crate::inbox::INBOX_CODE_HASH.trim()).await?;
        let inbox: Inbox = serde_json::from_slice(&state).ok()?;
        Some(inbox.messages.into_iter().map(|m| m.content).collect())
    }

    async fn has_inbox(&mut self, vk: &[u8], code_hash: &str) -> bool {
        Self::state(vk, code_hash).await.is_some()
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
    fn no_reply_in_time_is_a_silence_never_an_absence() {
        use futures::executor::block_on;
        let (_held, rx) = oneshot::channel();
        assert!(matches!(
            block_on(legacy_answer(rx, 5)),
            LegacyReply::NoAnswer(_)
        ));
        let (dropped, rx) = oneshot::channel();
        drop(dropped);
        assert!(matches!(
            block_on(legacy_answer(rx, 60_000)),
            LegacyReply::NoAnswer(_)
        ));
        let (tx, rx) = oneshot::channel();
        tx.send(LegacyReply::NotInstalled).unwrap();
        assert_eq!(
            block_on(legacy_answer(rx, 60_000)),
            LegacyReply::NotInstalled
        );
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
