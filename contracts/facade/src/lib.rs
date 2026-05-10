//! Facade contract for stable freenet-email webapp URL.
//!
//! Issue #200 / Phase 1.
//!
//! The facade is a web-container-shaped contract whose ID is intended to
//! stay stable across releases. Its state carries:
//!
//!   * the loader webapp bytes (a tiny vanilla-JS shell that redirects the
//!     browser to the real app at `current_app_id`);
//!   * a signed pointer to the *current* webapp's contract ID, plus a
//!     small ring of previous IDs for client-side rollback.
//!
//! Per release, the loader bytes typically change (because the loader bakes
//! `current_app_id` into its HTML), and the pointer always changes. Both
//! are covered by a single ed25519 signature over the canonical payload
//! (see `freenet_email_core::facade::signed_payload`).
//!
//! State framing:
//!
//! ```text
//! [meta_len: u64 BE] [meta: CBOR(FacadeMetadata)]
//! [web_len:  u64 BE] [web:  loader_bytes]
//! ```
//!
//! `parse_state` requires the entire `state` slice to be consumed — no
//! trailing bytes — so two distinct framings cannot share a signature.
//!
//! `validate_state` runs the full verification (sig + version != 0 + caps
//! + prev_app_ids invariants).
//!
//! `update_state` runs the same full verification on the incoming state
//! in addition to the monotonic-version check, so an UPDATE cannot bypass
//! any check that PUT enforces.
//!
//! Signed payload (see `freenet_email_core::facade::signed_payload`):
//!
//! ```text
//! version (u64 BE)
//!   || current_app_id (32)
//!   || prev_count (u32 BE)
//!   || (prev_version (u64 BE) || prev_app_id (32))*
//!   || loader_bytes
//! ```

use byteorder::{BigEndian, ReadBytesExt};
use ciborium::{de::from_reader, ser::into_writer};
use ed25519_dalek::VerifyingKey;
use freenet_email_facade_types::{FACADE_MAX_PREV_APP_IDS, FacadeMetadata, signed_payload};
use freenet_stdlib::prelude::*;
use std::io::{Cursor, Read};

const MAX_METADATA_SIZE: u64 = 4 * 1024; // 4 KB — pointer + sig + small ring.
const MAX_WEB_SIZE: u64 = 256 * 1024; // 256 KB — loader is tiny vanilla JS.

pub struct FacadeContract;

#[contract]
impl ContractInterface for FacadeContract {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        verify_full(parameters.as_ref(), state.as_ref())?;
        Ok(ValidateResult::Valid)
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        // Reject batched updates we don't understand. The facade only takes
        // a single full-state replacement per UPDATE.
        if data.len() > 1 {
            return Err(ContractError::InvalidUpdate);
        }
        let Some(UpdateData::State(new_state)) = data.into_iter().next() else {
            return Err(ContractError::InvalidUpdate);
        };

        // Run the FULL verification on the new state — sig, caps, prev
        // invariants, version != 0. Without this, an attacker could push
        // a state with a valid CBOR framing and a higher version but a
        // garbage signature, and clients that don't re-verify would land
        // on an attacker-controlled `current_app_id`. validate_state must
        // succeed before we even compare versions.
        let new_meta = verify_full(parameters.as_ref(), new_state.as_ref())?;

        let current_version = if state.as_ref().is_empty() {
            0
        } else {
            // Current state was previously validated; reading the version
            // alone is enough.
            read_pointer_version(state.as_ref())?
        };

        if new_meta.pointer.version <= current_version {
            return Err(ContractError::InvalidUpdateWithInfo {
                reason: format!(
                    "New facade version {} must be higher than current version {current_version}",
                    new_meta.pointer.version
                ),
            });
        }

        Ok(UpdateModification::valid(new_state))
    }

    fn summarize_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        if state.as_ref().is_empty() {
            return Ok(StateSummary::from(Vec::new()));
        }
        let version = read_pointer_version(state.as_ref())?;
        let mut summary = Vec::new();
        into_writer(&version, &mut summary).map_err(|e| ContractError::Deser(e.to_string()))?;
        Ok(StateSummary::from(summary))
    }

    fn get_state_delta(
        _parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        if state.as_ref().is_empty() {
            return Ok(StateDelta::from(Vec::new()));
        }
        let current_version = read_pointer_version(state.as_ref())?;
        let summary_version: u64 =
            from_reader(summary.as_ref()).map_err(|e| ContractError::Deser(e.to_string()))?;
        if current_version > summary_version {
            Ok(StateDelta::from(state.as_ref().to_vec()))
        } else {
            Ok(StateDelta::from(Vec::new()))
        }
    }
}

/// Run every check `validate_state` runs and return the parsed metadata so
/// callers can re-use it (notably `update_state` reads `pointer.version`).
fn verify_full(params_bytes: &[u8], state_bytes: &[u8]) -> Result<FacadeMetadata, ContractError> {
    let verifying_key = parse_verifying_key(params_bytes)?;
    let (metadata, loader_bytes) = parse_state(state_bytes)?;

    if metadata.pointer.version == 0 {
        return Err(ContractError::InvalidState);
    }
    if metadata.pointer.prev_app_ids.len() > FACADE_MAX_PREV_APP_IDS {
        return Err(ContractError::Other(format!(
            "prev_app_ids length {} exceeds cap {}",
            metadata.pointer.prev_app_ids.len(),
            FACADE_MAX_PREV_APP_IDS
        )));
    }

    // prev_app_ids invariants: every prev version must be strictly less
    // than the current version, the list must be strictly descending (most
    // recent first), and the current_app_id must not also appear in the
    // ring (no self-loops in rollback). The signer enforces the first; the
    // contract enforces all three so a buggy/compromised signer cannot ship
    // pathological rollback hints to clients.
    let mut last: Option<u64> = None;
    for (v, id) in &metadata.pointer.prev_app_ids {
        if *v >= metadata.pointer.version {
            return Err(ContractError::Other(format!(
                "prev_app_ids version {v} must be strictly less than current version {}",
                metadata.pointer.version
            )));
        }
        if *id == metadata.pointer.current_app_id {
            return Err(ContractError::Other(
                "prev_app_ids cannot contain current_app_id".to_string(),
            ));
        }
        if let Some(prev) = last
            && *v >= prev
        {
            return Err(ContractError::Other(
                "prev_app_ids must be strictly descending by version".to_string(),
            ));
        }
        last = Some(*v);
    }

    let payload = signed_payload(&metadata.pointer, &loader_bytes);
    verifying_key
        .verify_strict(&payload, &metadata.signature)
        .map_err(|e| ContractError::Other(format!("Signature verification failed: {e}")))?;

    Ok(metadata)
}

fn parse_verifying_key(params_bytes: &[u8]) -> Result<VerifyingKey, ContractError> {
    if params_bytes.len() != 32 {
        return Err(ContractError::Other(
            "Parameters must be 32 bytes (ed25519 verifying key)".to_string(),
        ));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(params_bytes);
    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| ContractError::Other(format!("Invalid public key: {e}")))
}

fn parse_state(state: &[u8]) -> Result<(FacadeMetadata, Vec<u8>), ContractError> {
    let mut cursor = Cursor::new(state);

    let metadata_size = cursor
        .read_u64::<BigEndian>()
        .map_err(|e| ContractError::Other(format!("Failed to read metadata size: {e}")))?;
    if metadata_size > MAX_METADATA_SIZE {
        return Err(ContractError::Other(format!(
            "Metadata size {metadata_size} exceeds maximum {MAX_METADATA_SIZE} bytes"
        )));
    }
    let mut metadata_bytes = vec![0u8; metadata_size as usize];
    cursor
        .read_exact(&mut metadata_bytes)
        .map_err(|e| ContractError::Other(format!("Failed to read metadata: {e}")))?;
    let metadata: FacadeMetadata =
        from_reader(&metadata_bytes[..]).map_err(|e| ContractError::Deser(e.to_string()))?;

    let web_size = cursor
        .read_u64::<BigEndian>()
        .map_err(|e| ContractError::Other(format!("Failed to read web size: {e}")))?;
    if web_size > MAX_WEB_SIZE {
        return Err(ContractError::Other(format!(
            "Web size {web_size} exceeds maximum {MAX_WEB_SIZE} bytes"
        )));
    }
    let mut loader_bytes = vec![0u8; web_size as usize];
    cursor
        .read_exact(&mut loader_bytes)
        .map_err(|e| ContractError::Other(format!("Failed to read web bytes: {e}")))?;

    // Strict framing: refuse trailing junk so two distinct state blobs
    // cannot share a valid signature. (The signed payload covers loader
    // bytes but not the meta_len / web_len framing values themselves.)
    if (cursor.position() as usize) != state.len() {
        return Err(ContractError::Other(format!(
            "trailing bytes after framed state: {} extra",
            state.len() - cursor.position() as usize
        )));
    }

    Ok((metadata, loader_bytes))
}

fn read_pointer_version(state: &[u8]) -> Result<u64, ContractError> {
    let (metadata, _) = parse_state(state)?;
    Ok(metadata.pointer.version)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use freenet_email_facade_types::FacadePointer;
    use rand::rngs::OsRng;

    fn make_keypair() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn make_state(pointer: FacadePointer, loader_bytes: &[u8], sk: &SigningKey) -> Vec<u8> {
        let payload = signed_payload(&pointer, loader_bytes);
        let signature = sk.sign(&payload);
        let metadata = FacadeMetadata { pointer, signature };
        let mut metadata_bytes = Vec::new();
        into_writer(&metadata, &mut metadata_bytes).unwrap();

        let mut state = Vec::new();
        state.extend_from_slice(&(metadata_bytes.len() as u64).to_be_bytes());
        state.extend_from_slice(&metadata_bytes);
        state.extend_from_slice(&(loader_bytes.len() as u64).to_be_bytes());
        state.extend_from_slice(loader_bytes);
        state
    }

    fn pointer_v(version: u64, app_id_byte: u8) -> FacadePointer {
        FacadePointer {
            version,
            current_app_id: [app_id_byte; 32],
            prev_app_ids: vec![],
        }
    }

    fn params(vk: &VerifyingKey) -> Parameters<'static> {
        Parameters::from(vk.to_bytes().to_vec())
    }

    #[test]
    fn empty_parameters_rejected() {
        let (sk, _) = make_keypair();
        let state = make_state(pointer_v(1, 0xAA), b"L", &sk);
        let result = FacadeContract::validate_state(
            Parameters::from(vec![]),
            State::from(state),
            RelatedContracts::default(),
        );
        assert!(matches!(result, Err(ContractError::Other(_))));
    }

    #[test]
    fn valid_state_passes() {
        let (sk, vk) = make_keypair();
        let state = make_state(pointer_v(1, 0xAA), b"<loader/>", &sk);
        let result = FacadeContract::validate_state(
            params(&vk),
            State::from(state),
            RelatedContracts::default(),
        );
        assert!(matches!(result, Ok(ValidateResult::Valid)));
    }

    #[test]
    fn version_zero_rejected() {
        let (sk, vk) = make_keypair();
        let state = make_state(pointer_v(0, 0xAA), b"<loader/>", &sk);
        let result = FacadeContract::validate_state(
            params(&vk),
            State::from(state),
            RelatedContracts::default(),
        );
        assert!(matches!(result, Err(ContractError::InvalidState)));
    }

    #[test]
    fn wrong_signer_rejected() {
        let (_, vk_real) = make_keypair();
        let (sk_imp, _) = make_keypair();
        let state = make_state(pointer_v(1, 0xAA), b"<loader/>", &sk_imp);
        let result = FacadeContract::validate_state(
            params(&vk_real),
            State::from(state),
            RelatedContracts::default(),
        );
        assert!(matches!(result, Err(ContractError::Other(_))));
    }

    #[test]
    fn prev_app_ids_cap_enforced() {
        let (sk, vk) = make_keypair();
        let too_many: Vec<(u64, [u8; 32])> = (0..(FACADE_MAX_PREV_APP_IDS as u64 + 1))
            .rev()
            .map(|i| (i + 1, [i as u8; 32]))
            .collect();
        let pointer = FacadePointer {
            version: 100,
            current_app_id: [0xCC; 32],
            prev_app_ids: too_many,
        };
        let state = make_state(pointer, b"L", &sk);
        let result = FacadeContract::validate_state(
            params(&vk),
            State::from(state),
            RelatedContracts::default(),
        );
        assert!(matches!(result, Err(ContractError::Other(_))));
    }

    #[test]
    fn prev_versions_must_be_below_current() {
        let (sk, vk) = make_keypair();
        let pointer = FacadePointer {
            version: 5,
            current_app_id: [0xCC; 32],
            prev_app_ids: vec![(5, [0xAA; 32])],
        };
        let state = make_state(pointer, b"L", &sk);
        let result = FacadeContract::validate_state(
            params(&vk),
            State::from(state),
            RelatedContracts::default(),
        );
        assert!(matches!(result, Err(ContractError::Other(_))));
    }

    #[test]
    fn prev_must_be_strictly_descending() {
        let (sk, vk) = make_keypair();
        let pointer = FacadePointer {
            version: 10,
            current_app_id: [0xCC; 32],
            prev_app_ids: vec![(3, [0xAA; 32]), (5, [0xBB; 32])],
        };
        let state = make_state(pointer, b"L", &sk);
        let result = FacadeContract::validate_state(
            params(&vk),
            State::from(state),
            RelatedContracts::default(),
        );
        assert!(matches!(result, Err(ContractError::Other(_))));
    }

    #[test]
    fn current_app_id_cannot_appear_in_prev() {
        let (sk, vk) = make_keypair();
        let pointer = FacadePointer {
            version: 10,
            current_app_id: [0xCC; 32],
            prev_app_ids: vec![(5, [0xCC; 32])],
        };
        let state = make_state(pointer, b"L", &sk);
        let result = FacadeContract::validate_state(
            params(&vk),
            State::from(state),
            RelatedContracts::default(),
        );
        assert!(matches!(result, Err(ContractError::Other(_))));
    }

    #[test]
    fn trailing_bytes_rejected() {
        let (sk, vk) = make_keypair();
        let mut state = make_state(pointer_v(1, 0xAA), b"L", &sk);
        state.extend_from_slice(b"junk");
        let result = FacadeContract::validate_state(
            params(&vk),
            State::from(state),
            RelatedContracts::default(),
        );
        assert!(matches!(result, Err(ContractError::Other(_))));
    }

    #[test]
    fn metadata_size_cap_enforced() {
        let (_, vk) = make_keypair();
        let mut state = Vec::new();
        let oversized = MAX_METADATA_SIZE + 1;
        state.extend_from_slice(&oversized.to_be_bytes());
        // No actual bytes follow; parse should still trip the size guard.
        let result = FacadeContract::validate_state(
            params(&vk),
            State::from(state),
            RelatedContracts::default(),
        );
        assert!(matches!(result, Err(ContractError::Other(_))));
    }

    #[test]
    fn update_rejects_stale_version() {
        let (sk, vk) = make_keypair();
        let current = make_state(pointer_v(2, 0x01), b"L", &sk);
        let same = make_state(pointer_v(2, 0x02), b"L", &sk);
        let result = FacadeContract::update_state(
            params(&vk),
            State::from(current.clone()),
            vec![UpdateData::State(State::from(same))],
        );
        assert!(matches!(
            result,
            Err(ContractError::InvalidUpdateWithInfo { .. })
        ));

        let newer = make_state(pointer_v(3, 0x02), b"L", &sk);
        let result = FacadeContract::update_state(
            params(&vk),
            State::from(current),
            vec![UpdateData::State(State::from(newer))],
        );
        assert!(result.is_ok());
    }

    /// Regression for the BLOCKER review-finding: `update_state` must run
    /// the same signature/caps/version-zero verification as `validate_state`.
    /// Otherwise an attacker can push a state with a higher version and a
    /// forged or random signature, and the contract returns Valid.
    #[test]
    fn update_rejects_garbage_signature() {
        let (sk, vk) = make_keypair();
        let current = make_state(pointer_v(2, 0x01), b"L", &sk);

        // Build a "new" state whose version is strictly greater than
        // current but whose signature was made over completely different
        // bytes (so verify_strict fails).
        let pointer = pointer_v(99, 0x02);
        let bogus_payload = b"not the canonical payload";
        let bogus_sig = sk.sign(bogus_payload);
        let metadata = FacadeMetadata {
            pointer,
            signature: bogus_sig,
        };
        let mut metadata_bytes = Vec::new();
        into_writer(&metadata, &mut metadata_bytes).unwrap();
        let mut bad_state = Vec::new();
        bad_state.extend_from_slice(&(metadata_bytes.len() as u64).to_be_bytes());
        bad_state.extend_from_slice(&metadata_bytes);
        let loader = b"L";
        bad_state.extend_from_slice(&(loader.len() as u64).to_be_bytes());
        bad_state.extend_from_slice(loader);

        let result = FacadeContract::update_state(
            params(&vk),
            State::from(current),
            vec![UpdateData::State(State::from(bad_state))],
        );
        // Must error out; specifically through verify_full, not through
        // version comparison.
        assert!(result.is_err());
    }

    #[test]
    fn update_rejects_delta_only() {
        let (sk, vk) = make_keypair();
        let current = make_state(pointer_v(2, 0x01), b"L", &sk);
        let result = FacadeContract::update_state(
            params(&vk),
            State::from(current),
            vec![UpdateData::Delta(StateDelta::from(b"anything".to_vec()))],
        );
        assert!(matches!(result, Err(ContractError::InvalidUpdate)));
    }

    #[test]
    fn update_rejects_batched_data() {
        let (sk, vk) = make_keypair();
        let current = make_state(pointer_v(2, 0x01), b"L", &sk);
        let new_a = make_state(pointer_v(3, 0x02), b"L", &sk);
        let new_b = make_state(pointer_v(4, 0x03), b"L", &sk);
        let result = FacadeContract::update_state(
            params(&vk),
            State::from(current),
            vec![
                UpdateData::State(State::from(new_a)),
                UpdateData::State(State::from(new_b)),
            ],
        );
        assert!(matches!(result, Err(ContractError::InvalidUpdate)));
    }

    #[test]
    fn summarize_and_delta_round_trip() {
        let (sk, _) = make_keypair();
        let state = make_state(pointer_v(7, 0xEE), b"L", &sk);
        let summary =
            FacadeContract::summarize_state(Parameters::from(vec![]), State::from(state.clone()))
                .unwrap();
        let v: u64 = from_reader(summary.as_ref()).unwrap();
        assert_eq!(v, 7);

        let mut older_summary = Vec::new();
        into_writer(&3u64, &mut older_summary).unwrap();
        let delta = FacadeContract::get_state_delta(
            Parameters::from(vec![]),
            State::from(state.clone()),
            StateSummary::from(older_summary),
        )
        .unwrap();
        assert!(!delta.as_ref().is_empty());

        let mut same_summary = Vec::new();
        into_writer(&7u64, &mut same_summary).unwrap();
        let delta = FacadeContract::get_state_delta(
            Parameters::from(vec![]),
            State::from(state),
            StateSummary::from(same_summary),
        )
        .unwrap();
        assert!(delta.as_ref().is_empty());
    }
}
