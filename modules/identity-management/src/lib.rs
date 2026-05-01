// The `#[delegate]` macro from freenet-stdlib expands to
// `#[cfg(feature = "trace")]` internally; this crate doesn't declare a
// `trace` feature, so rustc flags the cfg as unexpected. Silence it here.
#![allow(unexpected_cfgs)]

use std::collections::HashMap;

use freenet_stdlib::prelude::*;
use p384::{FieldBytes, Scalar, SecretKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Serialize, Deserialize)]
pub struct IdentityParams {
    #[serde(serialize_with = "IdentityParams::pk_serialize")]
    #[serde(deserialize_with = "IdentityParams::pk_deserialize")]
    pub secret_key: SecretKey,
}

impl IdentityParams {
    pub fn as_secret_id(&self) -> SecretsId {
        SecretsId::new(serde_json::to_vec(self).unwrap())
    }
}

impl IdentityParams {
    fn pk_deserialize<'de, D>(deser: D) -> Result<SecretKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let scalar = <Scalar as Deserialize>::deserialize(deser)?;
        Ok(SecretKey::from_bytes(&FieldBytes::from(scalar)).unwrap())
    }

    fn pk_serialize<S>(key: &SecretKey, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let scalar: Scalar = key.as_scalar_primitive().into();
        scalar.serialize(ser)
    }
}

impl TryFrom<Parameters<'_>> for IdentityParams {
    type Error = DelegateError;

    fn try_from(value: Parameters<'_>) -> Result<Self, Self::Error> {
        let deser: Self = Self::try_from(value.as_ref())?;
        Ok(deser)
    }
}

impl TryFrom<&[u8]> for IdentityParams {
    type Error = DelegateError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let deser: Self =
            serde_json::from_slice(value).map_err(|e| DelegateError::Deser(format!("{e}")))?;
        Ok(deser)
    }
}

impl TryFrom<IdentityParams> for Parameters<'static> {
    type Error = DelegateError;

    fn try_from(value: IdentityParams) -> Result<Self, Self::Error> {
        let ser = serde_json::to_vec(&value).map_err(|e| DelegateError::Deser(format!("{e}")))?;
        Ok(Parameters::from(ser))
    }
}

type Key = Vec<u8>;
type Alias = String;
type Extra = String;

/// Discriminates between a locally-owned identity (holds private key material)
/// and a contact (holds only public keys received via a ContactCard).
#[derive(Deserialize, Serialize, PartialEq, Eq, Debug, Clone, Copy, Default)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    #[default]
    Identity,
    Contact,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Debug)]
pub struct AliasInfo {
    pub key: Key,
    pub extra: Option<Extra>,
    /// Defaults to `Identity` when deserialising old state that lacks the field.
    #[serde(default)]
    pub kind: EntryKind,
}

#[derive(Deserialize, Serialize, Default, Debug)]
pub struct IdentityManagement {
    identities: HashMap<Alias, AliasInfo>,
}

impl IdentityManagement {
    pub fn is_empty(&self) -> bool {
        self.identities.is_empty()
    }

    pub fn get_info(&self) -> impl Iterator<Item = (&Alias, &AliasInfo)> {
        self.identities.iter()
    }

    pub fn into_info(self) -> impl Iterator<Item = (Alias, AliasInfo)> {
        self.identities.into_iter()
    }

    pub fn remove(&mut self, alias: &str) -> Option<AliasInfo> {
        self.identities.remove(alias)
    }
}

impl TryFrom<&[u8]> for IdentityManagement {
    type Error = DelegateError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(value).map_err(|e| DelegateError::Deser(format!("{e}")))
    }
}

#[delegate]
impl DelegateInterface for IdentityManagement {
    fn process(
        ctx: &mut DelegateCtx,
        params: Parameters<'static>,
        _origin: Option<MessageOrigin>,
        message: InboundDelegateMsg,
    ) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
        let params = IdentityParams::try_from(params)?;
        let secret_key =
            serde_json::to_vec(&params).map_err(|e| DelegateError::Deser(format!("{e}")))?;
        match message {
            InboundDelegateMsg::ApplicationMessage(ApplicationMessage {
                payload,
                processed: false,
                ..
            }) => {
                let msg = IdentityMsg::try_from(&*payload)?;
                match msg {
                    IdentityMsg::Init => {
                        // Idempotent: if a secret is already present for this
                        // params/secret_key, leave it alone. Without this,
                        // re-issuing Init on every page load (or via the
                        // missing-delegate recovery path) wipes previously
                        // stored aliases.
                        if ctx.get_secret(&secret_key).is_some() {
                            #[cfg(feature = "contract")]
                            {
                                freenet_stdlib::log::info(&format!(
                                    "init skipped — secret already exists {}",
                                    params.as_secret_id()
                                ));
                            }
                            return Ok(vec![]);
                        }
                        #[cfg(feature = "contract")]
                        {
                            freenet_stdlib::log::info(&format!(
                                "initialize secret {}",
                                params.as_secret_id()
                            ));
                        }
                        let default_value = serde_json::to_vec(&IdentityManagement::default())
                            .map_err(|e| DelegateError::Deser(format!("{e}")))?;
                        ctx.set_secret(&secret_key, &default_value);
                        Ok(vec![])
                    }
                    IdentityMsg::CreateIdentity {
                        alias,
                        key,
                        extra,
                        kind,
                    } => {
                        #[cfg(feature = "contract")]
                        {
                            freenet_stdlib::log::info(&format!(
                                "create alias new {alias} for {}",
                                params.as_secret_id()
                            ));
                        }
                        let value = ctx
                            .get_secret(&secret_key)
                            .ok_or_else(|| DelegateError::Other("secret not found".into()))?;
                        let mut manager = IdentityManagement::try_from(value.as_slice())?;
                        manager.identities.insert(
                            alias,
                            AliasInfo {
                                key,
                                extra,
                                kind: kind.unwrap_or_default(),
                            },
                        );
                        let updated = serde_json::to_vec(&manager)
                            .map_err(|e| DelegateError::Deser(format!("{e}")))?;
                        ctx.set_secret(&secret_key, &updated);
                        Ok(vec![])
                    }
                    IdentityMsg::DeleteIdentity { alias } => {
                        let value = ctx
                            .get_secret(&secret_key)
                            .ok_or_else(|| DelegateError::Other("secret not found".into()))?;
                        let mut manager = IdentityManagement::try_from(value.as_slice())?;
                        manager.identities.remove(alias.as_str());
                        let updated = serde_json::to_vec(&manager)
                            .map_err(|e| DelegateError::Deser(format!("{e}")))?;
                        ctx.set_secret(&secret_key, &updated);
                        Ok(vec![])
                    }
                    IdentityMsg::GetIdentities => {
                        let value = ctx
                            .get_secret(&secret_key)
                            .ok_or_else(|| DelegateError::Other("secret not found".into()))?;
                        Ok(vec![OutboundDelegateMsg::ApplicationMessage(
                            ApplicationMessage::new(value),
                        )])
                    }
                }
            }
            _ => Err(DelegateError::Other("unexpected message type".into())),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub enum IdentityMsg {
    Init,
    CreateIdentity {
        alias: String,
        key: Key,
        extra: Option<String>,
        /// Defaults to `Identity` when absent (backwards-compatible with
        /// senders that pre-date the contact-book feature).
        #[serde(default)]
        kind: Option<EntryKind>,
    },
    DeleteIdentity {
        alias: String,
    },
    /// Request the current set of identities. Returns the serialized
    /// `IdentityManagement` as an `ApplicationMessage` response.
    GetIdentities,
}

impl TryFrom<&[u8]> for IdentityMsg {
    type Error = DelegateError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(value).map_err(|e| DelegateError::Deser(format!("{e}")))
    }
}

impl TryFrom<&IdentityMsg> for Vec<u8> {
    type Error = DelegateError;

    fn try_from(value: &IdentityMsg) -> Result<Self, Self::Error> {
        let msg = serde_json::to_vec(&value).unwrap();
        Ok(msg)
    }
}

#[cfg(test)]
mod boundary_tests {
    //! Regression tests for the deserialization boundaries on this crate.
    //!
    //! `IdentityManagement` and `IdentityMsg` are reachable from network
    //! input via the `DelegateInterface::process` path. Both used to call
    //! `serde_json::from_slice(...).unwrap()`, which would panic the
    //! delegate on a malformed payload. These tests pin the
    //! `Result`-returning behavior so any future regression trips them.

    use super::*;

    #[test]
    fn malformed_identity_management_bytes_returns_err() {
        let garbage = [0xffu8; 64];
        let result = IdentityManagement::try_from(&garbage[..]);
        assert!(
            matches!(result, Err(DelegateError::Deser(_))),
            "expected Err(DelegateError::Deser), got {result:?}"
        );
    }

    #[test]
    fn truncated_identity_management_json_returns_err() {
        let truncated = br#"{"identities": {"alice":"#;
        let result = IdentityManagement::try_from(&truncated[..]);
        assert!(
            matches!(result, Err(DelegateError::Deser(_))),
            "expected Err(DelegateError::Deser), got {result:?}"
        );
    }

    #[test]
    fn malformed_identity_msg_bytes_returns_err() {
        let garbage = [0xffu8; 64];
        let result = IdentityMsg::try_from(&garbage[..]).map(|_| ());
        assert!(
            matches!(result, Err(DelegateError::Deser(_))),
            "expected Err(DelegateError::Deser), got {result:?}"
        );
    }

    #[test]
    fn empty_identity_msg_bytes_returns_err() {
        let result = IdentityMsg::try_from(&[][..]).map(|_| ());
        assert!(
            matches!(result, Err(DelegateError::Deser(_))),
            "expected Err(DelegateError::Deser), got {result:?}"
        );
    }

    /// AliasInfo without a `kind` field must deserialise as `EntryKind::Identity`
    /// (backwards-compat for state written before the contact-book feature).
    #[test]
    fn alias_info_missing_kind_defaults_to_identity() {
        let json = br#"{"key":[1,2,3],"extra":null}"#;
        let info: AliasInfo = serde_json::from_slice(json).expect("should deserialise");
        assert_eq!(info.kind, EntryKind::Identity);
    }

    /// `IdentityMsg::CreateIdentity` without a `kind` field must deserialise
    /// successfully (backwards-compat for senders that pre-date the field).
    #[test]
    fn create_identity_missing_kind_deserialises() {
        let json = br#"{"CreateIdentity":{"alias":"alice","key":[1],"extra":null}}"#;
        let msg: IdentityMsg = serde_json::from_slice(json).expect("should deserialise");
        if let IdentityMsg::CreateIdentity { kind, .. } = msg {
            assert_eq!(kind, None);
        } else {
            panic!("expected CreateIdentity variant");
        }
    }

    /// Storing both Identity and Contact entries round-trips correctly.
    #[test]
    fn mixed_entry_kinds_round_trip() {
        let mut mgr = IdentityManagement::default();
        mgr.identities.insert(
            "alice".into(),
            AliasInfo {
                key: vec![1],
                extra: None,
                kind: EntryKind::Identity,
            },
        );
        mgr.identities.insert(
            "bob".into(),
            AliasInfo {
                key: vec![2],
                extra: Some("friend".into()),
                kind: EntryKind::Contact,
            },
        );
        let json = serde_json::to_vec(&mgr).unwrap();
        let mgr2: IdentityManagement = serde_json::from_slice(&json).unwrap();
        assert_eq!(mgr2.identities["alice"].kind, EntryKind::Identity);
        assert_eq!(mgr2.identities["bob"].kind, EntryKind::Contact);
    }
}
