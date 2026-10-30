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

/// How long the mail delegate keeps a prompt open for an answer
/// (`mail_delegate::store::PROMPT_TTL_SECS`; pinned by a test).
pub(crate) const DELEGATE_PROMPT_TTL_SECS: u32 = 600;

/// How long to wait for an answer. Operations that ask the user (exports,
/// identity deletion) wait as long as the delegate would still act on an
/// answer, plus a margin: giving up sooner would let a late approval carry
/// out an operation this page already reported as failed.
pub(crate) fn timeout_ms(op: &Op) -> u32 {
    match op {
        Op::ExportRecoveryKey { .. }
        | Op::ExportProfile { .. }
        | Op::ExportForSuccessor { .. }
        | Op::DeleteIdentity { .. } => (DELEGATE_PROMPT_TTL_SECS + 30) * 1000,
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
    // Read the request id alone first: a reply nobody waits for (its call
    // gave up or was dropped) is never decoded into a `Reply`, so a late
    // recovery key is not copied into a plain string. It is still in
    // `payload`, the bytes the node delivered, which this does not wipe.
    let Ok(ResponseId { request_id }) = from_cbor::<ResponseId>(payload) else {
        crate::log::error("undecodable mail-delegate response", None);
        return false;
    };
    if !PENDING.with(|p| p.borrow().contains_key(&request_id)) {
        return false;
    }
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

#[cfg(test)]
thread_local! {
    /// How many times this thread asked for the v1 token-generator
    /// parameters (which carry the signing seed); tests pin who may.
    pub(crate) static V1_AFT_PARAMS_CALLS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Just the request id of a [`Response`]; the result is skipped unread.
#[derive(serde::Deserialize)]
struct ResponseId {
    request_id: RequestId,
}

/// A call's slot in [`PENDING`], removed however the call ends, including
/// when its future is dropped before an answer arrives.
struct PendingSlot(RequestId);

impl Drop for PendingSlot {
    fn drop(&mut self) {
        PENDING.with(|p| p.borrow_mut().remove(&self.0));
    }
}

/// Send `op` to the mail delegate and wait for its answer.
pub(crate) async fn call(op: Op) -> Result<Reply, CallError> {
    #[cfg(test)]
    if matches!(op, Op::V1AftParams { .. }) {
        V1_AFT_PARAMS_CALLS.with(|c| c.set(c.get() + 1));
    }
    let timeout = timeout_ms(&op);
    let request = new_request(op);
    let id = request.request_id;
    let bytes = to_cbor(&request).map_err(|e| CallError::Unknown(format!("encode: {e}")))?;
    let (tx, rx) = oneshot::channel();
    PENDING.with(|p| p.borrow_mut().insert(id, tx));
    let _slot = PendingSlot(id);
    send(bytes).await.map_err(CallError::Unknown)?;
    let answer = wait(rx, timeout).await;
    match answer {
        Ok(Ok(reply)) => Ok(reply),
        Ok(Err(failure)) => Err(CallError::Failed(failure)),
        Err(why) => Err(CallError::Unknown(why.into())),
    }
}

/// Whether a node delegate error can belong to a mail-delegate call
/// (`mail` is the mail delegate's key): one naming another delegate (the v1
/// token generator, say) cannot, and must not end mail calls.
pub(crate) fn may_be_mail_delegate_error(
    error: &freenet_stdlib::client_api::DelegateError,
    mail: &freenet_stdlib::prelude::DelegateKey,
) -> bool {
    use freenet_stdlib::client_api::DelegateError as E;
    match error {
        E::RegisterError(key) | E::Missing(key) | E::MissingSecret { key, .. } => key == mail,
        // Execution errors and secret-access errors carry no key.
        _ => true,
    }
}

/// Why a waiting call was ended by [`fail_all_pending`].
const NODE_DELEGATE_ERROR: &str = "the node reported an error running the mail delegate";

/// End every waiting call now, as [`CallError::Unknown`]: the node reported
/// a delegate error that names no request (it carries no request id), so
/// which call it belongs to cannot be told, and the delegate may have done
/// part of the work before it failed. Without this each call would wait out
/// its whole timeout (up to the 10-minute consent window) for an answer that
/// never comes. Returns how many calls were ended.
pub(crate) fn fail_all_pending() -> usize {
    // Dropping a waiter's sender ends its call with NODE_DELEGATE_ERROR.
    PENDING.with(|p| p.borrow_mut().drain().count())
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
) -> Result<Result<Reply, Failure>, &'static str> {
    #[cfg(target_family = "wasm")]
    {
        use futures::FutureExt;
        let mut rx = rx.fuse();
        let mut timer = gloo_timers::future::TimeoutFuture::new(timeout_ms).fuse();
        futures::select! {
            answer = rx => answer.map_err(|_| NODE_DELEGATE_ERROR),
            _ = timer => Err("timed out"),
        }
    }
    #[cfg(not(target_family = "wasm"))]
    {
        let _ = timeout_ms;
        rx.await.map_err(|_| NODE_DELEGATE_ERROR)
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

    #[cfg(feature = "local-delegate")]
    #[test]
    fn the_prompt_ttl_matches_the_delegate() {
        assert_eq!(
            u64::from(DELEGATE_PROMPT_TTL_SECS),
            mail_delegate::store::PROMPT_TTL_SECS
        );
    }

    #[test]
    fn a_consented_call_outwaits_the_delegates_prompt() {
        let addr = freenet_mail_protocol::Addr([0; 24]);
        for op in [
            Op::ExportRecoveryKey { addr },
            Op::DeleteIdentity {
                addr,
                expected_gen: 0,
            },
        ] {
            assert!(
                u64::from(timeout_ms(&op)) > u64::from(DELEGATE_PROMPT_TTL_SECS) * 1000,
                "a late approval must not act after the page gave up"
            );
        }
    }

    /// A node delegate error with no request id ends the waiting calls at
    /// once, as unknown, instead of leaving them to their whole timeout.
    #[test]
    fn a_node_delegate_error_ends_waiting_calls_as_unknown() {
        let (tx, rx) = oneshot::channel();
        PENDING.with(|p| p.borrow_mut().insert(RequestId([9; 16]), tx));
        assert_eq!(fail_all_pending(), 1);
        let ended = futures::executor::block_on(wait(rx, 1_000));
        assert_eq!(ended, Err(NODE_DELEGATE_ERROR));
    }

    /// An error naming another delegate (the v1 token generator) never ends
    /// mail calls; one naming the mail delegate, or naming none, may.
    #[test]
    fn only_errors_that_may_be_the_mail_delegates_end_its_calls() {
        use freenet_stdlib::client_api::DelegateError as E;
        use freenet_stdlib::prelude::{CodeHash, DelegateKey};
        let mail = DelegateKey::new([1; 32], CodeHash::new([2; 32]));
        let other = DelegateKey::new([3; 32], CodeHash::new([4; 32]));
        assert!(!may_be_mail_delegate_error(
            &E::Missing(other.clone()),
            &mail
        ));
        assert!(!may_be_mail_delegate_error(&E::RegisterError(other), &mail));
        assert!(may_be_mail_delegate_error(&E::Missing(mail.clone()), &mail));
        assert!(may_be_mail_delegate_error(
            &E::ExecutionError("trap".into()),
            &mail
        ));
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

    /// `PendingSlot`'s drop, which `call()` holds across both its awaits,
    /// so a call future dropped mid-wait removes its slot. This drops the
    /// slot directly: dropping a real `call()` mid-wait needs a transport
    /// that pends, and the test builds have none (the node build's `send`
    /// fails at once without a node; the in-page delegate answers at once).
    #[test]
    fn a_dropped_call_leaves_no_waiter_behind() {
        let id = RequestId([5; 16]);
        let (tx, _rx) = oneshot::channel();
        PENDING.with(|p| p.borrow_mut().insert(id, tx));
        drop(PendingSlot(id));
        assert!(PENDING.with(|p| !p.borrow().contains_key(&id)));
        // Its late answer reaches nobody.
        assert!(!deliver(&response(
            id,
            Ok(Reply::RecoveryKey("fmail-key-1:late".into()))
        )));
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
