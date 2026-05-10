//! Shared facade contract types.
//!
//! Issue #200 / #198. Lives in its own crate (outside the freenet-email
//! workspace) so the on-chain facade contract's wasm bytes don't shift
//! every time something unrelated in the workspace lockfile moves.
//!
//! Consumers:
//!  * `freenet-email-facade` (the on-chain contract, also outside the
//!    workspace) — depends on this crate by path.
//!  * `freenet-email-core` (workspace member) — re-exports this crate so
//!    the signer and integration tests keep their import surface stable.

use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};

/// Maximum number of `prev_app_ids` entries the facade contract will accept.
/// Keeps state bounded; older entries fall off the ring.
pub const FACADE_MAX_PREV_APP_IDS: usize = 3;

/// Pointer carried inside the signed facade metadata. Captured separately
/// so the signature payload is unambiguous regardless of CBOR map ordering.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct FacadePointer {
    /// Monotonic version (unix timestamp at signing).
    pub version: u64,
    /// 32-byte freenet `ContractInstanceId` of the webapp this facade
    /// currently points to.
    pub current_app_id: [u8; 32],
    /// Last N `(version, app_id)` pairs available for client-side rollback
    /// when `current_app_id` fails to load. The on-chain contract enforces
    /// strict descending order by version and disallows `current_app_id`
    /// from appearing in this list.
    pub prev_app_ids: Vec<(u64, [u8; 32])>,
}

/// Facade contract metadata. Lives in the metadata header of the state
/// blob and is verified by the contract's `validate_state`.
#[derive(Serialize, Deserialize)]
pub struct FacadeMetadata {
    pub pointer: FacadePointer,
    /// ed25519 signature over `signed_payload(&pointer, &loader_bytes)`.
    pub signature: Signature,
}

/// Build the canonical signed payload for facade state.
///
/// Layout: `version (u64 BE) || current_app_id (32) || prev_count (u32 BE)
/// || (prev_version (u64 BE) || prev_app_id (32))* || loader_bytes`.
///
/// Hand-rolled (rather than re-using CBOR) so the on-chain verifier and the
/// signer agree byte-for-byte without depending on map-ordering quirks of a
/// serializer.
pub fn signed_payload(pointer: &FacadePointer, loader_bytes: &[u8]) -> Vec<u8> {
    let mut buf =
        Vec::with_capacity(8 + 32 + 4 + pointer.prev_app_ids.len() * 40 + loader_bytes.len());
    buf.extend_from_slice(&pointer.version.to_be_bytes());
    buf.extend_from_slice(&pointer.current_app_id);
    buf.extend_from_slice(&(pointer.prev_app_ids.len() as u32).to_be_bytes());
    for (v, id) in &pointer.prev_app_ids {
        buf.extend_from_slice(&v.to_be_bytes());
        buf.extend_from_slice(id);
    }
    buf.extend_from_slice(loader_bytes);
    buf
}
