//! Facade contract for stable freenet-email webapp URL.
//!
//! Issue #200 / Phase 1.
//!
//! The facade is a web-container-shaped contract whose ID stays stable
//! across releases. Its state carries:
//!
//!   * the loader webapp bytes (a tiny vanilla-JS shell that fetches the
//!     facade pointer from the gateway and redirects to the real app);
//!   * a signed pointer to the *current* webapp's contract ID, plus a
//!     small ring of previous IDs for client-side rollback.
//!
//! Per release, the loader bytes do not change — only the pointer does.
//! `update_state` therefore accepts a fully-formed new state whose loader
//! bytes match the prior loader bytes byte-for-byte and whose pointer has
//! a strictly higher version.
//!
//! State framing:
//!
//! ```text
//! [meta_len: u64 BE] [meta: CBOR(FacadeMetadata)]
//! [web_len:  u64 BE] [web:  loader_bytes]
//! ```
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
use freenet_email_core::facade::{FACADE_MAX_PREV_APP_IDS, FacadeMetadata, signed_payload};
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
        let verifying_key = parse_verifying_key(parameters.as_ref())?;
        let (metadata, loader_bytes) = parse_state(state.as_ref())?;

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

        let payload = signed_payload(&metadata.pointer, &loader_bytes);
        verifying_key
            .verify_strict(&payload, &metadata.signature)
            .map_err(|e| ContractError::Other(format!("Signature verification failed: {e}")))?;

        Ok(ValidateResult::Valid)
    }

    fn update_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let current_version = if state.as_ref().is_empty() {
            0
        } else {
            read_pointer_version(state.as_ref())?
        };

        let Some(UpdateData::State(new_state)) = data.into_iter().next() else {
            return Err(ContractError::InvalidUpdate);
        };
        let new_version = read_pointer_version(new_state.as_ref())?;

        if new_version <= current_version {
            return Err(ContractError::InvalidUpdateWithInfo {
                reason: format!(
                    "New facade version {new_version} must be higher than current version {current_version}"
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
    use freenet_email_core::facade::FacadePointer;
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

    #[test]
    fn empty_parameters_rejected() {
        let result = FacadeContract::validate_state(
            Parameters::from(vec![]),
            State::from(vec![]),
            RelatedContracts::default(),
        );
        assert!(matches!(result, Err(ContractError::Other(_))));
    }

    #[test]
    fn valid_state_passes() {
        let (sk, vk) = make_keypair();
        let state = make_state(pointer_v(1, 0xAA), b"<loader/>", &sk);
        let result = FacadeContract::validate_state(
            Parameters::from(vk.to_bytes().to_vec()),
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
            Parameters::from(vk.to_bytes().to_vec()),
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
            Parameters::from(vk_real.to_bytes().to_vec()),
            State::from(state),
            RelatedContracts::default(),
        );
        assert!(matches!(result, Err(ContractError::Other(_))));
    }

    #[test]
    fn prev_app_ids_cap_enforced() {
        let (sk, vk) = make_keypair();
        let too_many: Vec<(u64, [u8; 32])> = (0..(FACADE_MAX_PREV_APP_IDS as u64 + 1))
            .map(|i| (i, [i as u8; 32]))
            .collect();
        let pointer = FacadePointer {
            version: 5,
            current_app_id: [0xCC; 32],
            prev_app_ids: too_many,
        };
        let state = make_state(pointer, b"L", &sk);
        let result = FacadeContract::validate_state(
            Parameters::from(vk.to_bytes().to_vec()),
            State::from(state),
            RelatedContracts::default(),
        );
        assert!(matches!(result, Err(ContractError::Other(_))));
    }

    #[test]
    fn update_rejects_stale_version() {
        let (sk, _) = make_keypair();
        let current = make_state(pointer_v(2, 0x01), b"L", &sk);
        let same = make_state(pointer_v(2, 0x02), b"L", &sk);
        let result = FacadeContract::update_state(
            Parameters::from(vec![]),
            State::from(current.clone()),
            vec![UpdateData::State(State::from(same))],
        );
        assert!(matches!(
            result,
            Err(ContractError::InvalidUpdateWithInfo { .. })
        ));

        let newer = make_state(pointer_v(3, 0x02), b"L", &sk);
        let result = FacadeContract::update_state(
            Parameters::from(vec![]),
            State::from(current),
            vec![UpdateData::State(State::from(newer))],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn summarize_and_delta_round_trip() {
        let (sk, _) = make_keypair();
        let state = make_state(pointer_v(7, 0xEE), b"L", &sk);
        let summary = FacadeContract::summarize_state(
            Parameters::from(vec![]),
            State::from(state.clone()),
        )
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
