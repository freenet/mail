//! The UI's side of the mail-delegate protocol (`freenet-mail-protocol`).
//!
//! Every call is a [`Request`] with a fresh random id, and the delegate
//! answers each with exactly one [`Response`] carrying that id. [`call`]
//! waits for it, keyed by the id, so answers can arrive in any order and a
//! response is never matched to the wrong request.
//!
//! A call that gets no answer in time has an UNKNOWN outcome
//! ([`CallError::Unknown`]): the delegate may still have done it. Callers
//! must never read that as "absent" or "not done".
//!
//! Two backends carry the bytes: a Freenet node (`use-node`), which runs the
//! published delegate WASM, and, for the offline build, the same delegate
//! code run in the page over an in-memory store (`local-delegate`).

use std::cell::RefCell;
use std::collections::HashMap;

use freenet_mail_protocol::{
    Failure, Op, PROTOCOL_VERSION, Reply, Request, RequestId, Response, from_cbor, to_cbor,
};
use futures::channel::oneshot;

#[cfg(feature = "local-delegate")]
pub(crate) mod local;
#[cfg(feature = "use-node")]
pub(crate) mod node;
pub(crate) mod ops;

/// Why a call did not produce a reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CallError {
    /// The delegate answered with a failure.
    Failed(Failure),
    /// No answer: the request could not be sent, or none arrived in time.
    /// The outcome is unknown, never "absent".
    Unknown(String),
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Failed(failure) => write!(f, "{:?}: {}", failure.code, failure.detail),
            CallError::Unknown(why) => write!(f, "no answer from the mail delegate ({why})"),
        }
    }
}

impl std::error::Error for CallError {}

impl CallError {
    /// The failure code, when the delegate answered with one.
    pub(crate) fn code(&self) -> Option<freenet_mail_protocol::FailureCode> {
        match self {
            CallError::Failed(failure) => Some(failure.code),
            CallError::Unknown(_) => None,
        }
    }
}

/// How long to wait for an answer. Operations that ask the user (exports,
/// identity deletion) wait for the prompt: the node times an unanswered
/// prompt out after about a minute.
pub(crate) fn timeout_ms(op: &Op) -> u32 {
    match op {
        Op::ExportRecoveryKey { .. }
        | Op::ExportProfile { .. }
        | Op::ExportForSuccessor { .. }
        | Op::DeleteIdentity { .. } => 150_000,
        _ => 30_000,
    }
}

type Waiter = oneshot::Sender<Result<Reply, Failure>>;

thread_local! {
    /// Calls waiting for their answer, by request id.
    static PENDING: RefCell<HashMap<RequestId, Waiter>> = RefCell::new(HashMap::new());
}

/// A request with a fresh random id.
pub(crate) fn new_request(op: Op) -> Request {
    Request {
        version: PROTOCOL_VERSION,
        request_id: RequestId(crate::rng::random_bytes()),
        op,
    }
}

/// Deliver one delegate answer to the call waiting for it. Returns whether
/// the payload was a mail-delegate response with a waiting call; an answer
/// whose caller already gave up (timed out) is dropped.
pub(crate) fn deliver(payload: &[u8]) -> bool {
    let Ok(response) = from_cbor::<Response>(payload) else {
        crate::log::error("undecodable mail-delegate response", None);
        return false;
    };
    let waiter = PENDING.with(|p| p.borrow_mut().remove(&response.request_id));
    match waiter {
        Some(waiter) => waiter.send(response.result).is_ok(),
        None => false,
    }
}

/// Send `op` to the mail delegate and wait for its answer.
pub(crate) async fn call(op: Op) -> Result<Reply, CallError> {
    let timeout = timeout_ms(&op);
    let request = new_request(op);
    let id = request.request_id;
    let bytes = to_cbor(&request).map_err(|e| CallError::Unknown(format!("encode: {e}")))?;
    let (tx, rx) = oneshot::channel();
    PENDING.with(|p| p.borrow_mut().insert(id, tx));
    if let Err(e) = send(bytes).await {
        PENDING.with(|p| p.borrow_mut().remove(&id));
        return Err(CallError::Unknown(e));
    }
    let answer = wait(rx, timeout).await;
    PENDING.with(|p| p.borrow_mut().remove(&id));
    match answer {
        Some(Ok(reply)) => Ok(reply),
        Some(Err(failure)) => Err(CallError::Failed(failure)),
        None => Err(CallError::Unknown("timed out".into())),
    }
}

/// `call`, expecting `Reply::Ack`: the new generation.
pub(crate) async fn call_ack(op: Op) -> Result<u64, CallError> {
    match call(op).await? {
        Reply::Ack { generation } => Ok(generation),
        other => Err(unexpected(&other)),
    }
}

/// A reply of a kind the operation never returns: a protocol mismatch.
pub(crate) fn unexpected(reply: &Reply) -> CallError {
    CallError::Unknown(format!("unexpected reply: {}", reply_name(reply)))
}

fn reply_name(reply: &Reply) -> &'static str {
    match reply {
        Reply::Status(_) => "Status",
        Reply::Identities(_) => "Identities",
        Reply::Identity(_) => "Identity",
        Reply::Imported { .. } => "Imported",
        Reply::Items { .. } => "Items",
        Reply::Item(_) => "Item",
        Reply::Ack { .. } => "Ack",
        Reply::Deleted => "Deleted",
        Reply::Decrypted(_) => "Decrypted",
        Reply::SealedV1 { .. } => "SealedV1",
        Reply::Signature(_) => "Signature",
        Reply::AftParams(_) => "AftParams",
        Reply::RecoveryKey(_) => "RecoveryKey",
        Reply::Profile(_) => "Profile",
        Reply::ExportedSecrets { .. } => "ExportedSecrets",
        Reply::Continue { .. } => "Continue",
        Reply::CreatedIdentity { .. } => "CreatedIdentity",
    }
}

async fn wait(
    rx: oneshot::Receiver<Result<Reply, Failure>>,
    timeout_ms: u32,
) -> Option<Result<Reply, Failure>> {
    #[cfg(target_family = "wasm")]
    {
        use futures::FutureExt;
        let mut rx = rx.fuse();
        let mut timer = gloo_timers::future::TimeoutFuture::new(timeout_ms).fuse();
        futures::select! {
            answer = rx => answer.ok(),
            _ = timer => None,
        }
    }
    #[cfg(not(target_family = "wasm"))]
    {
        let _ = timeout_ms;
        rx.await.ok()
    }
}

#[cfg(feature = "use-node")]
async fn send(bytes: Vec<u8>) -> Result<(), String> {
    node::send(bytes).await
}

#[cfg(all(not(feature = "use-node"), feature = "local-delegate"))]
async fn send(bytes: Vec<u8>) -> Result<(), String> {
    local::process(&bytes);
    Ok(())
}

#[cfg(all(not(feature = "use-node"), not(feature = "local-delegate")))]
async fn send(_bytes: Vec<u8>) -> Result<(), String> {
    Err("this build has no mail delegate".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use freenet_mail_protocol::FailureCode;

    fn response(id: RequestId, result: Result<Reply, Failure>) -> Vec<u8> {
        to_cbor(&Response {
            request_id: id,
            result,
        })
        .unwrap()
    }

    #[test]
    fn an_answer_reaches_only_the_call_with_its_id() {
        let (tx_a, mut rx_a) = oneshot::channel();
        let (tx_b, mut rx_b) = oneshot::channel();
        let (a, b) = (RequestId([1; 16]), RequestId([2; 16]));
        PENDING.with(|p| {
            p.borrow_mut().insert(a, tx_a);
            p.borrow_mut().insert(b, tx_b);
        });
        assert!(deliver(&response(b, Ok(Reply::Ack { generation: 7 }))));
        assert_eq!(rx_a.try_recv().unwrap(), None);
        assert_eq!(
            rx_b.try_recv().unwrap(),
            Some(Ok(Reply::Ack { generation: 7 }))
        );
        // A second answer for the same id has nobody waiting.
        assert!(!deliver(&response(b, Ok(Reply::Deleted))));
        PENDING.with(|p| p.borrow_mut().clear());
    }

    #[test]
    fn a_failure_is_delivered_as_a_failure() {
        let (tx, mut rx) = oneshot::channel();
        let id = RequestId([3; 16]);
        PENDING.with(|p| p.borrow_mut().insert(id, tx));
        let failure = Failure {
            code: FailureCode::Conflict { current_gen: 4 },
            detail: "stale".into(),
        };
        assert!(deliver(&response(id, Err(failure.clone()))));
        assert_eq!(rx.try_recv().unwrap(), Some(Err(failure)));
    }

    #[test]
    fn an_undecodable_payload_is_not_delivered() {
        assert!(!deliver(b"not cbor at all"));
    }

    #[test]
    fn prompting_operations_wait_longer() {
        use freenet_mail_protocol::Addr;
        let addr = Addr([0; 24]);
        assert!(timeout_ms(&Op::ExportRecoveryKey { addr }) > timeout_ms(&Op::ListIdentities));
        assert!(
            timeout_ms(&Op::DeleteIdentity {
                addr,
                expected_gen: 1
            }) > timeout_ms(&Op::GetStatus)
        );
    }

    #[test]
    fn request_ids_are_fresh() {
        assert_ne!(
            new_request(Op::GetStatus).request_id,
            new_request(Op::GetStatus).request_id
        );
    }
}
