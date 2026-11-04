//! Freenet Mail's delegate.
//!
//! One delegate holds everything private: identity keys, contacts, and local
//! mail state (drafts, sent, kept, archived, flags, settings). Keys never
//! leave it except through an export the user approves; it signs and
//! decrypts on the UI's behalf.
//!
//! Shape follows River's chat delegate: an origin gate before any request
//! is looked at, a namespace per web-app origin, one stored item per secret
//! with a compare-and-swap generation, and exactly one response per request.
//! The protocol is in `freenet-mail-protocol`.
//!
//! With the user's Background grant the node also runs it with no page open:
//! [`jobs`] plans those runs, [`watch`] carries them out.

// The `#[delegate]` macro emits `cfg(feature = "trace")` checks.
#![allow(unexpected_cfgs)]

pub mod consent;
pub mod crypto;
pub mod env;
pub mod handlers;
pub mod inbox_jobs;
pub mod inbox_v2;
pub mod jobs;
pub mod sealing;
pub mod store;
pub mod transition;
pub mod watch;

#[cfg(test)]
mod tests;

use freenet_stdlib::prelude::{
    DelegateCtx, DelegateError, DelegateInterface, InboundDelegateMsg, MessageOrigin,
    OutboundDelegateMsg, Parameters, delegate,
};

pub struct MailDelegate;

// `crate::jobs::Tick::ALL` names these tags.
#[delegate(manifest(
    lifecycle = [NodeStarted],
    capabilities = [Background],
    wakeups = [rescan = 900, v1watch = 3600, renew = 21600, clock = 86400]
))]
impl DelegateInterface for MailDelegate {
    fn process(
        ctx: &mut DelegateCtx,
        _parameters: Parameters<'static>,
        origin: Option<MessageOrigin>,
        message: InboundDelegateMsg,
    ) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
        handlers::process(ctx, origin, message)
    }
}
