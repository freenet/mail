//! The node backend: the published mail delegate on the user's Freenet node.
//!
//! The delegate is registered once per page load before any request goes
//! out, and requests wait for the node's answer to the registration (or a
//! short timeout): a request sent before the registration has run could
//! reach a node that does not have the delegate yet.

use std::cell::RefCell;
use std::sync::OnceLock;

use freenet_stdlib::{
    client_api::{ClientRequest, DelegateRequest},
    prelude::*,
};
use futures::channel::oneshot;

/// The mail delegate's WASM. It is still a candidate: the v0.3.0 release
/// freezes it under `published-contract/wasm/v2/`.
pub(crate) const CODE: &[u8] =
    include_bytes!("../../../published-contract/candidate/mail_delegate");
pub(crate) const CODE_HASH: &str =
    include_str!("../../../published-contract/candidate/mail_delegate_code_hash");

/// How long requests wait for the node to answer the registration before
/// going out anyway.
const REGISTER_ACK_TIMEOUT_MS: u32 = 10_000;

/// The delegate takes no parameters: nothing secret or per-user is in its
/// key, which is `blake3(blake3(wasm) || [])`.
pub(crate) fn params() -> Parameters<'static> {
    Parameters::from(Vec::<u8>::new())
}

pub(crate) fn key() -> &'static DelegateKey {
    static KEY: OnceLock<DelegateKey> = OnceLock::new();
    KEY.get_or_init(|| {
        DelegateKey::from_params(CODE_HASH.trim(), &params())
            .expect("the committed mail-delegate code hash decodes")
    })
}

enum Registration {
    NotStarted,
    /// Sent; these requests wait for the node's answer.
    Waiting {
        ack: Option<oneshot::Sender<()>>,
        waiters: Vec<oneshot::Sender<()>>,
    },
    Done,
}

thread_local! {
    static REGISTRATION: RefCell<Registration> = const { RefCell::new(Registration::NotStarted) };
}

/// The node answered something for the mail delegate's key that is not a
/// request's response: the answer to the registration.
pub(crate) fn note_registration_answer() {
    REGISTRATION.with(|r| {
        if let Registration::Waiting { ack, .. } = &mut *r.borrow_mut()
            && let Some(ack) = ack.take()
        {
            let _ = ack.send(());
        }
    });
}

/// Register the delegate unless this page load already has, and wait until
/// the node answered (or the timeout passed).
async fn ensure_registered() -> Result<(), String> {
    enum Next {
        Ready,
        Wait(oneshot::Receiver<()>),
        Register(oneshot::Receiver<()>),
    }
    let next = REGISTRATION.with(|r| {
        let mut r = r.borrow_mut();
        match &mut *r {
            Registration::Done => Next::Ready,
            Registration::Waiting { waiters, .. } => {
                let (tx, rx) = oneshot::channel();
                waiters.push(tx);
                Next::Wait(rx)
            }
            Registration::NotStarted => {
                let (ack, rx) = oneshot::channel();
                *r = Registration::Waiting {
                    ack: Some(ack),
                    waiters: Vec::new(),
                };
                Next::Register(rx)
            }
        }
    });
    match next {
        Next::Ready => Ok(()),
        Next::Wait(rx) => {
            let _ = rx.await;
            Ok(())
        }
        Next::Register(ack) => {
            let sent = register().await;
            if sent.is_ok() {
                wait_for_ack(ack).await;
            }
            let waiters = REGISTRATION.with(|r| {
                match std::mem::replace(&mut *r.borrow_mut(), Registration::Done) {
                    Registration::Waiting { waiters, .. } => waiters,
                    _ => Vec::new(),
                }
            });
            for waiter in waiters {
                let _ = waiter.send(());
            }
            sent
        }
    }
}

async fn wait_for_ack(ack: oneshot::Receiver<()>) {
    #[cfg(target_family = "wasm")]
    {
        use futures::FutureExt;
        let mut ack = ack.fuse();
        let mut timer = gloo_timers::future::TimeoutFuture::new(REGISTER_ACK_TIMEOUT_MS).fuse();
        futures::select! {
            _ = ack => {}
            _ = timer => crate::log::debug!("mail delegate registration: no answer yet, continuing"),
        }
    }
    #[cfg(not(target_family = "wasm"))]
    {
        let _ = (ack, REGISTER_ACK_TIMEOUT_MS);
    }
}

pub(crate) fn register_request() -> Result<ClientRequest<'static>, String> {
    let delegate =
        DelegateContainer::try_from((CODE.to_vec(), &params())).map_err(|e| e.to_string())?;
    Ok(ClientRequest::DelegateOp(
        DelegateRequest::RegisterDelegate {
            delegate,
            cipher: crate::api::V0_2_CIPHER,
            nonce: crate::api::V0_2_NONCE,
        },
    ))
}

async fn register() -> Result<(), String> {
    let mut client = crate::api::WEB_API_SENDER
        .get()
        .ok_or("not connected to the node")?
        .clone();
    client
        .send(register_request()?)
        .await
        .map_err(|e| format!("register the mail delegate: {e}"))
}

/// Send one encoded request to the delegate.
pub(crate) async fn send(bytes: Vec<u8>) -> Result<(), String> {
    ensure_registered().await?;
    let request = DelegateRequest::ApplicationMessages {
        key: key().clone(),
        params: params(),
        inbound: vec![InboundDelegateMsg::ApplicationMessage(
            ApplicationMessage::new(bytes),
        )],
    };
    let mut client = crate::api::WEB_API_SENDER
        .get()
        .ok_or("not connected to the node")?
        .clone();
    client
        .send(request.into())
        .await
        .map_err(|e| format!("send to the mail delegate: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_wasm_has_the_embedded_code_hash() {
        crate::api::embedded_artifact::assert_delegate(CODE, CODE_HASH.trim());
    }

    #[test]
    fn the_key_has_empty_parameters() {
        let container = DelegateContainer::try_from((CODE.to_vec(), &params())).unwrap();
        assert_eq!(container.key(), key());
    }

    #[test]
    fn registration_sends_the_pinned_cipher_and_nonce() {
        let ClientRequest::DelegateOp(DelegateRequest::RegisterDelegate { cipher, nonce, .. }) =
            register_request().unwrap()
        else {
            panic!("not a RegisterDelegate");
        };
        assert_eq!(cipher, crate::api::V0_2_CIPHER);
        assert_eq!(nonce, crate::api::V0_2_NONCE);
    }
}
