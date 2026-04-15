//! Web container contract for the Freenet Email webapp.
//!
//! Ported from freenet-river's `web-container-contract`. Validates that a
//! published webapp state is signed by the holder of a known ed25519 public
//! key (supplied via contract parameters) and enforces monotonically
//! increasing version numbers on updates.
//!
//! State format: `[metadata_len: u64 BE][metadata: CBOR][web_len: u64 BE][web: bytes]`
//! Signed payload: `version (u32 BE) || web_bytes`

use byteorder::{BigEndian, ReadBytesExt};
use ciborium::{de::from_reader, ser::into_writer};
use ed25519_dalek::VerifyingKey;
use freenet_email_core::web_container::WebContainerMetadata;
use freenet_stdlib::prelude::*;
use std::io::{Cursor, Read};

const MAX_METADATA_SIZE: u64 = 1024; // 1KB
const MAX_WEB_SIZE: u64 = 1024 * 1024 * 100; // 100MB

pub struct WebContainerContract;

#[contract]
impl ContractInterface for WebContainerContract {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        // Extract and deserialize verifying key from parameters
        let params_bytes: &[u8] = parameters.as_ref();
        if params_bytes.len() != 32 {
            return Err(ContractError::Other(
                "Parameters must be 32 bytes".to_string(),
            ));
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(params_bytes);

        let verifying_key = VerifyingKey::from_bytes(&key_bytes)
            .map_err(|e| ContractError::Other(format!("Invalid public key: {}", e)))?;

        let mut cursor = Cursor::new(state.as_ref());

        // Read metadata length
        let metadata_size = cursor
            .read_u64::<BigEndian>()
            .map_err(|e| ContractError::Other(format!("Failed to read metadata size: {}", e)))?;

        if metadata_size > MAX_METADATA_SIZE {
            return Err(ContractError::Other(format!(
                "Metadata size {} exceeds maximum allowed size of {} bytes",
                metadata_size, MAX_METADATA_SIZE
            )));
        }

        let mut metadata_bytes = vec![0; metadata_size as usize];
        cursor
            .read_exact(&mut metadata_bytes)
            .map_err(|e| ContractError::Other(format!("Failed to read metadata: {}", e)))?;

        let metadata: WebContainerMetadata =
            from_reader(&metadata_bytes[..]).map_err(|e| ContractError::Deser(e.to_string()))?;

        if metadata.version == 0 {
            return Err(ContractError::InvalidState);
        }

        // Read web content length
        let web_size = cursor
            .read_u64::<BigEndian>()
            .map_err(|e| ContractError::Other(format!("Failed to read web size: {}", e)))?;

        if web_size > MAX_WEB_SIZE {
            return Err(ContractError::Other(format!(
                "Web size {} exceeds maximum allowed size of {} bytes",
                web_size, MAX_WEB_SIZE
            )));
        }

        let mut webapp_bytes = vec![0; web_size as usize];
        cursor
            .read_exact(&mut webapp_bytes)
            .map_err(|e| ContractError::Other(format!("Failed to read web bytes: {}", e)))?;

        // Create signed payload: version || web
        let mut message = metadata.version.to_be_bytes().to_vec();
        message.extend_from_slice(&webapp_bytes);

        verifying_key
            .verify_strict(&message, &metadata.signature)
            .map_err(|e| ContractError::Other(format!("Signature verification failed: {}", e)))?;

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
            read_version(state.as_ref())?
        };

        if let Some(UpdateData::State(new_state)) = data.into_iter().next() {
            let new_version = read_version(new_state.as_ref())?;

            if new_version <= current_version {
                return Err(ContractError::InvalidUpdateWithInfo {
                    reason: format!(
                        "New state version {} must be higher than current version {}",
                        new_version, current_version
                    ),
                });
            }

            Ok(UpdateModification::valid(new_state))
        } else {
            Err(ContractError::InvalidUpdate)
        }
    }

    fn summarize_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        if state.as_ref().is_empty() {
            return Ok(StateSummary::from(Vec::new()));
        }

        let version = read_version(state.as_ref())?;
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

        let current_version = read_version(state.as_ref())?;
        let summary_version: u32 =
            from_reader(summary.as_ref()).map_err(|e| ContractError::Deser(e.to_string()))?;

        if current_version > summary_version {
            Ok(StateDelta::from(state.as_ref().to_vec()))
        } else {
            Ok(StateDelta::from(Vec::new()))
        }
    }
}

/// Parse a state blob and return its embedded metadata version.
fn read_version(state: &[u8]) -> Result<u32, ContractError> {
    let mut cursor = Cursor::new(state);
    let metadata_size = cursor
        .read_u64::<BigEndian>()
        .map_err(|e| ContractError::Other(format!("Failed to read metadata size: {}", e)))?;
    let mut metadata_bytes = vec![0; metadata_size as usize];
    cursor
        .read_exact(&mut metadata_bytes)
        .map_err(|e| ContractError::Other(format!("Failed to read metadata: {}", e)))?;
    let metadata: WebContainerMetadata =
        from_reader(&metadata_bytes[..]).map_err(|e| ContractError::Deser(e.to_string()))?;
    Ok(metadata.version)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn create_test_keypair() -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    fn create_test_state(
        version: u32,
        compressed_webapp: &[u8],
        signing_key: &SigningKey,
    ) -> Vec<u8> {
        let mut message = version.to_be_bytes().to_vec();
        message.extend_from_slice(compressed_webapp);
        let signature = signing_key.sign(&message);

        let metadata = WebContainerMetadata { version, signature };
        let mut metadata_bytes = Vec::new();
        into_writer(&metadata, &mut metadata_bytes).unwrap();

        let mut state = Vec::new();
        state.extend_from_slice(&(metadata_bytes.len() as u64).to_be_bytes());
        state.extend_from_slice(&metadata_bytes);
        state.extend_from_slice(&(compressed_webapp.len() as u64).to_be_bytes());
        state.extend_from_slice(compressed_webapp);
        state
    }

    #[test]
    fn empty_state_fails_validation() {
        let result = WebContainerContract::validate_state(
            Parameters::from(vec![]),
            State::from(vec![]),
            RelatedContracts::default(),
        );
        assert!(matches!(result, Err(ContractError::Other(_))));
    }

    #[test]
    fn valid_state() {
        let (signing_key, verifying_key) = create_test_keypair();
        let state = create_test_state(1, b"Hello, World!", &signing_key);

        let result = WebContainerContract::validate_state(
            Parameters::from(verifying_key.to_bytes().to_vec()),
            State::from(state),
            RelatedContracts::default(),
        );
        assert!(matches!(result, Ok(ValidateResult::Valid)));
    }

    #[test]
    fn invalid_version() {
        let (signing_key, verifying_key) = create_test_keypair();
        let state = create_test_state(0, b"Hello, World!", &signing_key);

        let result = WebContainerContract::validate_state(
            Parameters::from(verifying_key.to_bytes().to_vec()),
            State::from(state),
            RelatedContracts::default(),
        );
        assert!(matches!(result, Err(ContractError::InvalidState)));
    }

    #[test]
    fn invalid_signature() {
        let (_, verifying_key) = create_test_keypair();
        let (wrong_signing_key, _) = create_test_keypair();
        let state = create_test_state(1, b"Hello, World!", &wrong_signing_key);

        let result = WebContainerContract::validate_state(
            Parameters::from(verifying_key.to_bytes().to_vec()),
            State::from(state),
            RelatedContracts::default(),
        );
        assert!(matches!(result, Err(ContractError::Other(_))));
    }

    #[test]
    fn update_state_rejects_stale_version() {
        let (signing_key, _) = create_test_keypair();
        let current_state = create_test_state(1, b"Original", &signing_key);

        let same_version = create_test_state(1, b"New Content", &signing_key);
        let result = WebContainerContract::update_state(
            Parameters::from(vec![]),
            State::from(current_state.clone()),
            vec![UpdateData::State(State::from(same_version))],
        );
        assert!(matches!(
            result,
            Err(ContractError::InvalidUpdateWithInfo { reason: _ })
        ));

        let higher_version = create_test_state(2, b"New Content", &signing_key);
        let result = WebContainerContract::update_state(
            Parameters::from(vec![]),
            State::from(current_state),
            vec![UpdateData::State(State::from(higher_version))],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn summarize_and_delta() {
        let (signing_key, _) = create_test_keypair();
        let state = create_test_state(2, b"Content", &signing_key);

        let summary = WebContainerContract::summarize_state(
            Parameters::from(vec![]),
            State::from(state.clone()),
        )
        .unwrap();
        let summary_version: u32 = from_reader(summary.as_ref()).unwrap();
        assert_eq!(summary_version, 2);

        let mut old_summary = Vec::new();
        into_writer(&1u32, &mut old_summary).unwrap();
        let delta = WebContainerContract::get_state_delta(
            Parameters::from(vec![]),
            State::from(state.clone()),
            StateSummary::from(old_summary),
        )
        .unwrap();
        assert!(!delta.as_ref().is_empty());

        let mut same_summary = Vec::new();
        into_writer(&2u32, &mut same_summary).unwrap();
        let delta = WebContainerContract::get_state_delta(
            Parameters::from(vec![]),
            State::from(state),
            StateSummary::from(same_summary),
        )
        .unwrap();
        assert!(delta.as_ref().is_empty());
    }
}
