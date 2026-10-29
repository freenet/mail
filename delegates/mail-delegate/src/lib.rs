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

// The `#[delegate]` macro emits `cfg(feature = "trace")` checks.
#![allow(unexpected_cfgs)]

pub mod consent;
pub mod crypto;
pub mod env;
pub mod handlers;
pub mod store;

#[cfg(test)]
mod tests;

use freenet_stdlib::prelude::{
    DelegateCtx, DelegateError, DelegateInterface, InboundDelegateMsg, MessageOrigin,
    OutboundDelegateMsg, Parameters, delegate,
};

pub struct MailDelegate;

#[delegate]
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
