//! Facade contract metadata.
//!
//! Issue #198 / #200. The actual types live in
//! `contracts/facade-types/` — a standalone crate outside the freenet-email
//! workspace so the on-chain facade wasm stays byte-stable across
//! workspace dep churn. This module just re-exports them so the signer,
//! integration tests, and UI keep their existing
//! `freenet_email_core::facade::*` import paths.

pub use freenet_email_facade_types::{
    FACADE_MAX_PREV_APP_IDS, FacadeMetadata, FacadePointer, signed_payload,
};
