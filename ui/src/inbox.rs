use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    io::{Cursor, Read},
};

use chacha20poly1305::{XChaCha20Poly1305, aead::Aead};
use chrono::{DateTime, Utc};
use freenet_aft_interface::{Tier, TokenAssignment, TokenAssignmentHash};
use freenet_stdlib::prelude::StateSummary;
use freenet_stdlib::{
    client_api::ContractRequest,
    prelude::{
        ContractKey, State, UpdateData,
        blake3::{self, traits::digest::Digest},
    },
};
use std::sync::Arc;

use futures::FutureExt;
use futures::future::LocalBoxFuture;
use ml_dsa::{
    EncodedVerifyingKey, MlDsa65, SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey,
    signature::{Keypair as MlDsaKeypair, Signer as MlDsaSigner, Verifier as MlDsaVerifier},
};
use ml_kem::{
    DecapsulationKey, EncapsulationKey, MlKem768,
    kem::{Decapsulate, Encapsulate, KeyExport},
};
use serde::{Deserialize, Serialize};

use freenet_email_inbox::{
    Inbox as StoredInbox, InboxParams, InboxSettings as StoredSettings, Message as StoredMessage,
    UpdateInbox,
};

use crate::{
    DynError,
    aft::AftRecords,
    api::{TryNodeAction, WebApiRequestClient, node_response_error_handling},
    app::Identity,
};

type InboxContract = ContractKey;

// `inbox_code_hash` is produced by `cargo make build-inbox-contract`. Under
// `--no-default-features --features example-data,no-sync` it isn't needed
// (no contract calls happen) and the build artifact may not exist, so we
// fall back to an empty placeholder. Any attempt to use it offline would
// fail at `ContractKey::from_params` time, but those code paths are dead
// when `use-node` is disabled.
#[cfg(feature = "use-node")]
pub(crate) const INBOX_CODE_HASH: &str = include_str!("../../build/inbox_code_hash");
#[cfg(not(feature = "use-node"))]
pub(crate) const INBOX_CODE_HASH: &str = "";

/// Encode the `InboxParams.pub_key` bytes for an inbox owned by this identity.
///
/// After Stage 2 the inbox contract ID is derived from the ML-DSA-65 verifying
/// key stored in the identity, not from an RSA public key. Callers that only
/// have the serialised verifying-key bytes (e.g. senders looking up a
/// recipient's inbox) pass them in directly.
pub(crate) fn inbox_params_pub_key_bytes(ml_dsa_vk: &MlDsaVerifyingKey<MlDsa65>) -> Vec<u8> {
    ml_dsa_vk.encode().to_vec()
}

/// Derive the on-chain inbox `ContractKey` for the inbox owned by
/// `ml_dsa_vk`. Same derivation as `start_sending` uses internally; exposed
/// so the compose-Send path can enqueue a pending Sent ack against the
/// recipient's inbox key without re-implementing the params encoding.
pub(crate) fn inbox_key_for(
    ml_dsa_vk: &MlDsaVerifyingKey<MlDsa65>,
) -> Result<ContractKey, DynError> {
    let params = InboxParams {
        pub_key: inbox_params_pub_key_bytes(ml_dsa_vk),
    }
    .try_into()
    .map_err(|e| format!("{e}"))?;
    ContractKey::from_params(INBOX_CODE_HASH, params).map_err(|e| format!("{e}").into())
}

/// Verify a detached ML-DSA-65 signature over `ciphertext` using the
/// sender's encoded verifying key. Returns `false` for empty / wrong-
/// length / cryptographically-invalid inputs (the recipient renders
/// these as "unverified" rather than rejecting; #51).
pub(crate) fn verify_message_signature(
    ciphertext: &[u8],
    sender_vk: &[u8],
    signature: &[u8],
) -> bool {
    if sender_vk.is_empty() || signature.is_empty() {
        return false;
    }
    let Ok(encoded_vk): Result<EncodedVerifyingKey<MlDsa65>, _> = sender_vk.try_into() else {
        return false;
    };
    let vk = MlDsaVerifyingKey::<MlDsa65>::decode(&encoded_vk);
    let Ok(sig) = ml_dsa::Signature::<MlDsa65>::try_from(signature) else {
        return false;
    };
    MlDsaVerifier::verify(&vk, ciphertext, &sig).is_ok()
}

thread_local! {
    static PENDING_INBOXES_UPDATE: RefCell<HashMap<InboxContract, Vec<PendingOutgoing>>> = RefCell::new(HashMap::new());
    static INBOX_TO_ID: RefCell<HashMap<InboxContract, Identity>> =
        RefCell::new(HashMap::new());
    /// Outgoing messages awaiting an `UpdateResponse` from the recipient's
    /// inbox contract. Populated by the compose-Send path with the
    /// `(sender_alias, sent_id)` the UI assigned to its local Sent stash;
    /// drained FIFO when an `UpdateResponse` arrives for that inbox key
    /// (api.rs flips the corresponding row to `Delivered`).
    ///
    /// FIFO is "good enough" — the network does not promise that responses
    /// for sequential sends to the same inbox land in submission order, but
    /// every successful send will get acked, and a wrong pairing only
    /// affects the timing of the UI flip, not the correctness of which rows
    /// end up Delivered.
    pub(crate) static PENDING_SENT_ACK: RefCell<HashMap<InboxContract, std::collections::VecDeque<(String, String)>>> =
        RefCell::new(HashMap::new());
}

/// Record that a send to `inbox_key` is awaiting an UpdateResponse to flip
/// the Sent row identified by `(sender_alias, sent_id)` to Delivered.
pub(crate) fn enqueue_pending_sent_ack(
    inbox_key: InboxContract,
    sender_alias: String,
    sent_id: String,
) {
    PENDING_SENT_ACK.with(|m| {
        m.borrow_mut()
            .entry(inbox_key)
            .or_default()
            .push_back((sender_alias, sent_id));
    });
}

/// Pop the next pending sent record for `inbox_key`, if any.
pub(crate) fn take_next_pending_sent_ack(inbox_key: &InboxContract) -> Option<(String, String)> {
    PENDING_SENT_ACK.with(|m| {
        let mut map = m.borrow_mut();
        let q = map.get_mut(inbox_key)?;
        let item = q.pop_front();
        if q.is_empty() {
            map.remove(inbox_key);
        }
        item
    })
}

/// Remove a specific pending sent record from the queue (e.g. on
/// `start_sending` async error so the row stops blocking later acks).
/// No-op if the entry is not in the queue.
pub(crate) fn remove_pending_sent_ack(
    inbox_key: &InboxContract,
    sender_alias: &str,
    sent_id: &str,
) {
    PENDING_SENT_ACK.with(|m| {
        let mut map = m.borrow_mut();
        let Some(q) = map.get_mut(inbox_key) else {
            return;
        };
        q.retain(|(a, id)| !(a == sender_alias && id == sent_id));
        if q.is_empty() {
            map.remove(inbox_key);
        }
    });
}

/// Outgoing message awaiting an AFT token assignment. Holds the sender
/// identity so we can sign the ciphertext with the sender's ML-DSA-65
/// signing key when the assignment lands (#51).
struct PendingOutgoing {
    msg: DecryptedMessage,
    sender: Identity,
}

#[derive(Debug, Clone)]
struct InternalSettings {
    /// This id is used for internal handling of the inbox and is not persistent
    /// or unique across sessions.
    next_msg_id: u64,
    #[allow(dead_code)] // TODO: surfaced via settings UI (not yet wired)
    minimum_tier: Tier,
    /// ML-DSA-65 signing key used to authorise modifications to the inbox
    /// contract state (add/remove messages, settings updates). The corresponding
    /// verifying key is embedded in `InboxParams` and becomes part of the
    /// contract ID via `hash(wasm, params)`.
    /// Wrapped in `Arc` because `MlDsaSigningKey` is not `Clone`.
    ml_dsa_signing_key: Arc<MlDsaSigningKey<MlDsa65>>,
}

#[allow(dead_code)] // TODO: placeholder for decrypted settings persistence
#[derive(Debug, Serialize, Deserialize)]
struct StoredDecryptedSettings {}

#[allow(dead_code)] // TODO: emitted by summarize_state once contract sync lands
#[derive(Serialize, Deserialize)]
struct InboxSummary(HashSet<TokenAssignmentHash>);

impl InboxSummary {
    #[allow(dead_code)]
    pub fn new(messages: HashSet<TokenAssignmentHash>) -> Self {
        Self(messages)
    }
}

impl InternalSettings {
    fn from_stored(
        stored_settings: StoredSettings,
        next_id: u64,
        ml_dsa_signing_key: Arc<MlDsaSigningKey<MlDsa65>>,
    ) -> Result<Self, DynError> {
        Ok(Self {
            next_msg_id: next_id,
            ml_dsa_signing_key,
            minimum_tier: stored_settings.minimum_tier,
        })
    }

    #[allow(dead_code)] // TODO: invoked from update_settings_at_store
    fn to_stored(&self) -> Result<StoredSettings, DynError> {
        Ok(StoredSettings {
            minimum_tier: self.minimum_tier,
            private: vec![],
        })
    }
}

/// Per-message signature-verification state (#51). Combines a pure
/// crypto check (sig validates against `sender_vk`) with an address-book
/// lookup (does the user trust this VK).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum VerificationState {
    /// Signature verified AND `sender_vk` matches a contact the user has
    /// flagged as verified.
    VerifiedKnown,
    /// Signature verified, but the sender VK is unknown to the address
    /// book (or known-unverified).
    VerifiedUnknown,
    /// Signature missing, malformed, or fails to verify.
    #[default]
    Unverified,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct MessageModel {
    pub id: u64,
    pub content: DecryptedMessage,
    pub token_assignment: TokenAssignment,
    /// Sender's ML-DSA-65 verifying key bytes. Empty for legacy messages.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sender_vk: Vec<u8>,
    /// Pure-crypto verification: sig validates against `sender_vk` over
    /// the ciphertext blob. Address-book trust is layered on top at
    /// render time. The address-book lookup is fast (HashMap) so we
    /// don't cache a `VerificationState` here — see `verification_state`
    /// in the UI render path.
    #[serde(default)]
    pub signature_valid: bool,
}

impl MessageModel {
    #[allow(dead_code)] // used by the to_state path (not yet implemented)
    fn to_stored(&self, dk: &DecapsulationKey<MlKem768>) -> Result<StoredMessage, DynError> {
        let ek = dk.encapsulation_key();
        let decrypted_content = serde_json::to_vec(&self.content)?;
        let content = ml_kem_encrypt(ek, &decrypted_content)?;
        Ok::<_, DynError>(StoredMessage {
            content,
            token_assignment: self.token_assignment.clone(),
            // Re-encryption path doesn't have access to the original
            // sender's signing key. Empty sig = recipient renders as
            // "unverified" (#51). The to_state path isn't wired up yet.
            sender_vk: Vec::new(),
            signature: Vec::new(),
        })
    }

    pub async fn finish_sending(
        client: &mut WebApiRequestClient,
        assignment: TokenAssignment,
        inbox_contract: InboxContract,
    ) -> Result<(), DynError> {
        let pending_update = PENDING_INBOXES_UPDATE.with(|map| {
            let map = &mut *map.borrow_mut();
            let update = map.get_mut(&inbox_contract).and_then(|messages| {
                if !messages.is_empty() {
                    Some(messages.remove(0))
                } else {
                    None
                }
            });
            if let Some(messages) = map.get(&inbox_contract)
                && messages.is_empty()
            {
                map.remove(&inbox_contract);
            }
            update
        });

        if let Some(update) = pending_update {
            let stored = update.msg.to_stored(assignment, &update.sender)?;
            let delta = UpdateInbox::AddMessages {
                messages: vec![stored],
            };
            let delta_bytes = serde_json::to_vec(&delta)?;
            // Send a bare `UpdateData::Delta` and let the runtime resolve
            // the inbox contract's `update_state` requires(AFT record)
            // signal via `fetch_related_via_network`. This relies on
            // freenet-core PR #4006 (validate-side) + PR #4007
            // (update-side) — without those the receiver's
            // `update_state` errors with MissingRelated and the broadcast
            // bounces through ResyncRequest recovery, see #80.
            let request = ContractRequest::Update {
                key: inbox_contract,
                data: UpdateData::Delta(delta_bytes.into()),
            };
            client.send(request.into()).await?;
            // todo: event after sending, we may fail to update, must keep this in mind in case we receive no confirmation
            // meaning that we will need to retry, and likely need an other token for now at least, so restart from 0
        }
        Ok(())
    }
}

/// ML-KEM-768 encapsulation key encoded as a byte vector.
///
/// This is the public key that recipients publish as part of their identity
/// so that senders can encrypt messages to them.  It is stored in
/// `DecryptedMessage.to` and serialised with the message; the decapsulation
/// (private) key stays in the identity delegate.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub(crate) struct MlKemEncapsKey(pub Vec<u8>);

impl MlKemEncapsKey {
    pub fn from_key(ek: &EncapsulationKey<MlKem768>) -> Self {
        Self(ek.to_bytes().to_vec())
    }

    pub fn to_key(&self) -> Result<EncapsulationKey<MlKem768>, DynError> {
        use ml_kem::kem::Key;
        let bytes: &[u8] = &self.0;
        let arr: Key<EncapsulationKey<MlKem768>> =
            Key::<EncapsulationKey<MlKem768>>::try_from(bytes)
                .map_err(|_| "ML-KEM encapsulation key wrong length")?;
        EncapsulationKey::<MlKem768>::new(&arr).map_err(|e| format!("{e:?}").into())
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub(crate) struct DecryptedMessage {
    pub title: String,
    pub content: String,
    pub from: String,
    /// ML-KEM-768 encapsulation keys for each recipient (one per inbox).
    pub to: Vec<MlKemEncapsKey>,
    pub cc: Vec<String>,
    pub time: DateTime<Utc>,
}

impl DecryptedMessage {
    pub async fn start_sending(
        self,
        client: &mut WebApiRequestClient,
        recipient_ek: EncapsulationKey<MlKem768>,
        recipient_ml_dsa_vk: MlDsaVerifyingKey<MlDsa65>,
        from: &Identity,
    ) -> Result<(), DynError> {
        let (hash, _) = self.assignment_hash_and_signed_content()?;
        crate::log::debug!(
            "requesting token for assignment hash: {}",
            bs58::encode(hash).into_string()
        );
        let inbox_pub_key_bytes = inbox_params_pub_key_bytes(&recipient_ml_dsa_vk);
        let delegate_key =
            AftRecords::assign_token(client, inbox_pub_key_bytes.clone(), from, hash).await?;
        let params = InboxParams {
            pub_key: inbox_pub_key_bytes,
        }
        .try_into()
        .map_err(|e| format!("{e}"))?;
        let inbox_key =
            ContractKey::from_params(INBOX_CODE_HASH, params).map_err(|e| format!("{e}"))?;
        AftRecords::pending_assignment(delegate_key, inbox_key);

        PENDING_INBOXES_UPDATE.with(|map| {
            let map = &mut *map.borrow_mut();
            map.entry(inbox_key)
                .or_insert_with(Vec::new)
                .push(PendingOutgoing {
                    msg: self,
                    sender: from.clone(),
                });
        });
        let _ = recipient_ek; // ek is used inside to_stored via pending queue
        Ok(())
    }

    fn to_stored(
        &self,
        token_assignment: TokenAssignment,
        sender: &Identity,
    ) -> Result<StoredMessage, DynError> {
        use ml_dsa::signature::Keypair;
        let (_, content) = self.assignment_hash_and_signed_content()?;
        // Detached ML-DSA-65 signature over the ciphertext (#51). The
        // recipient verifies before decrypting; sender VK is sent
        // alongside so the recipient can both verify and recognise the
        // sender even if the address book has never seen this key.
        let signing_key = sender.ml_dsa_signing_key.as_ref();
        let sig: ml_dsa::Signature<MlDsa65> = MlDsaSigner::sign(signing_key, &content);
        let signature = sig.encode().to_vec();
        let sender_vk = signing_key.verifying_key().encode().to_vec();
        Ok::<_, DynError>(StoredMessage {
            content,
            token_assignment,
            sender_vk,
            signature,
        })
    }

    fn from_stored(dk: &DecapsulationKey<MlKem768>, msg_content: Vec<u8>) -> DecryptedMessage {
        let plaintext = ml_kem_decrypt(dk, msg_content).expect("failed to decrypt message content");
        serde_json::from_slice(&plaintext).expect("failed to deserialise decrypted message")
    }

    fn assignment_hash_and_signed_content(&self) -> Result<([u8; 32], Vec<u8>), DynError> {
        let decrypted_content: Vec<u8> = serde_json::to_vec(self)?;

        // The recipient's ML-KEM encapsulation key is stored in `self.to`.
        let recipient_ek_bytes = self.to.first().ok_or("receiver key not found")?;
        let recipient_ek = recipient_ek_bytes.to_key()?;

        let content = ml_kem_encrypt(&recipient_ek, &decrypted_content)?;

        let mut hasher = blake3::Hasher::new();
        hasher.update(&content);
        let assignment_hash: [u8; 32] = hasher.finalize().as_slice().try_into().unwrap();
        Ok((assignment_hash, content))
    }
}

/// Thin adapter: wraps rand 0.8's `ThreadRng` and implements rand_core 0.10's `TryRng` +
/// `TryCryptoRng` traits so we can pass it to `encapsulate_with_rng`. This avoids pulling
/// in getrandom 0.4 (which needs the separate `wasm_js` feature on WASM), relying instead
/// on rand 0.8's existing WASM support via getrandom 0.2 + `js` feature.
///
/// `Rng` and `CryptoRng` are provided automatically via blanket impls in rand_core 0.10.
struct Rand08Rng(rand::rngs::ThreadRng);

impl rand_core::TryRng for Rand08Rng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        use rand::RngCore as _;
        Ok(self.0.next_u32())
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        use rand::RngCore as _;
        Ok(self.0.next_u64())
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        use rand::RngCore as _;
        self.0.fill_bytes(dst);
        Ok(())
    }
}
impl rand_core::TryCryptoRng for Rand08Rng {}

/// Derive a 32-byte XChaCha20-Poly1305 key from an ML-KEM shared secret using HKDF-SHA256.
///
/// The context label `b"freenet-email-v1 message-key"` domain-separates this
/// key from any other use of the same shared secret (NIST SP 800-56C recommendation).
fn hkdf_derive_key(shared_secret: &[u8]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut okm = [0u8; 32];
    hk.expand(b"freenet-email-v1 message-key", &mut okm)
        .expect("HKDF expand: output length is valid");
    okm
}

/// Encrypt `plaintext` to `ek` using ML-KEM-768 + XChaCha20-Poly1305.
///
/// Wire format: `[ 24-byte nonce | 1088-byte ML-KEM ciphertext | variable XChaCha20-Poly1305 ciphertext ]`
///
/// The symmetric key is HKDF-SHA256(ML-KEM shared secret, info="freenet-email-v1 message-key").
fn ml_kem_encrypt(ek: &EncapsulationKey<MlKem768>, plaintext: &[u8]) -> Result<Vec<u8>, DynError> {
    use chacha20poly1305::aead::KeyInit;
    use chacha20poly1305::aead::generic_array::GenericArray;

    // Use Rand08Rng (rand 0.8 ThreadRng) to avoid getrandom 0.4's wasm_js requirement.
    let (ct, shared_secret) = ek.encapsulate_with_rng(&mut Rand08Rng(rand::thread_rng()));
    let ct_bytes: &[u8] = ct.as_ref();

    let key_bytes = hkdf_derive_key(shared_secret.as_slice());

    // Generate a random 192-bit nonce using rand::random (compatible with all rand versions).
    let nonce_bytes: [u8; 24] = rand::random();
    let chacha_nonce = GenericArray::from(nonce_bytes);
    let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(&key_bytes));
    let encrypted_data = cipher
        .encrypt(&chacha_nonce, plaintext)
        .map_err(|e| format!("XChaCha20 encrypt failed: {e}"))?;

    let mut content = Vec::with_capacity(nonce_bytes.len() + ct_bytes.len() + encrypted_data.len());
    content.extend_from_slice(&nonce_bytes);
    content.extend_from_slice(ct_bytes);
    content.extend_from_slice(&encrypted_data);
    Ok(content)
}

/// Decrypt a message previously encrypted with [`ml_kem_encrypt`].
fn ml_kem_decrypt(
    dk: &DecapsulationKey<MlKem768>,
    msg_content: Vec<u8>,
) -> Result<Vec<u8>, DynError> {
    use chacha20poly1305::aead::KeyInit;
    use chacha20poly1305::aead::generic_array::GenericArray;

    // ML-KEM-768 ciphertext is 1088 bytes.
    const KEM_CT_LEN: usize = 1088;
    const NONCE_LEN: usize = 24;

    if msg_content.len() < NONCE_LEN + KEM_CT_LEN {
        return Err("message content too short".into());
    }

    let mut cursor = Cursor::new(msg_content);
    let mut nonce_bytes = vec![0u8; NONCE_LEN];
    cursor.read_exact(&mut nonce_bytes)?;
    let mut kem_ct_bytes = vec![0u8; KEM_CT_LEN];
    cursor.read_exact(&mut kem_ct_bytes)?;
    let mut encrypted_data = vec![];
    cursor.read_to_end(&mut encrypted_data)?;

    // `decapsulate_slice` accepts &[u8] and validates the length.
    let shared_secret = dk
        .decapsulate_slice(&kem_ct_bytes)
        .map_err(|_| "ML-KEM ciphertext wrong length")?;

    let key_bytes = hkdf_derive_key(shared_secret.as_slice());
    let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(&key_bytes));
    let nonce = GenericArray::from_slice(&nonce_bytes);
    cipher
        .decrypt(nonce, encrypted_data.as_ref())
        .map_err(|e| format!("XChaCha20 decrypt failed: {e}").into())
}

/// Inbox state
#[derive(Debug, Clone)]
pub(crate) struct InboxModel {
    pub messages: Vec<MessageModel>,
    settings: InternalSettings,
    pub key: InboxContract,
}

impl InboxModel {
    pub async fn load_all(client: &mut WebApiRequestClient, contracts: &[Identity]) {
        async fn subscribe(
            client: &mut WebApiRequestClient,
            contract_key: &ContractKey,
            identity: &Identity,
        ) -> Result<(), DynError> {
            let alias = identity.alias();
            INBOX_TO_ID.with(|map| {
                map.borrow_mut().insert(*contract_key, identity.clone());
            });
            crate::log::debug!(
                "subscribing to inbox updates for `{contract_key}`, belonging to alias `{alias}`"
            );
            InboxModel::subscribe(client, *contract_key).await?;
            Ok(())
        }

        fn get_key(identity: &Identity) -> Result<ContractKey, DynError> {
            let vk = MlDsaKeypair::verifying_key(identity.ml_dsa_signing_key.as_ref());
            let pub_key = inbox_params_pub_key_bytes(&vk);
            let params = freenet_email_inbox::InboxParams { pub_key }
                .try_into()
                .map_err(|e| format!("{e}"))?;
            ContractKey::from_params(crate::inbox::INBOX_CODE_HASH, params)
                .map_err(|e| format!("{e}").into())
        }

        for identity in contracts {
            let mut client = client.clone();
            let contract_key = match get_key(identity) {
                Ok(v) => v,
                Err(e) => {
                    node_response_error_handling(
                        client.clone().into(),
                        Err(e),
                        TryNodeAction::LoadInbox,
                    )
                    .await;
                    return;
                }
            };
            // INBOX_TO_ID is the single source of truth for routing
            // inbox UpdateNotifications back to an Identity. Subscribe
            // populates it synchronously before the network round trip
            // so peer-side state pushes that race the GetResponse can
            // still find their owner.
            let already = INBOX_TO_ID.with(|map| map.borrow().contains_key(&contract_key));
            if !already {
                let res = subscribe(&mut client, &contract_key, identity).await;
                node_response_error_handling(client.clone().into(), res, TryNodeAction::LoadInbox)
                    .await;
            }
            let res = InboxModel::load(&mut client, identity).await;
            node_response_error_handling(client.into(), res.map(|_| ()), TryNodeAction::LoadInbox)
                .await;
        }
    }

    pub async fn load(
        client: &mut WebApiRequestClient,
        id: &Identity,
    ) -> Result<ContractKey, DynError> {
        let vk = MlDsaKeypair::verifying_key(id.ml_dsa_signing_key.as_ref());
        let params = InboxParams {
            pub_key: inbox_params_pub_key_bytes(&vk),
        }
        .try_into()
        .map_err(|e| format!("{e}"))?;
        let contract_key =
            ContractKey::from_params(INBOX_CODE_HASH, params).map_err(|e| format!("{e}"))?;
        InboxModel::get_state(client, contract_key).await?;
        Ok(contract_key)
    }

    pub fn id_for_alias(alias: &str) -> Option<Identity> {
        INBOX_TO_ID.with(|map| {
            map.borrow()
                .values()
                .find_map(|id| (id.alias() == alias).then(|| id.clone()))
        })
    }

    pub fn contract_identity(key: &InboxContract) -> Option<Identity> {
        INBOX_TO_ID.with(|map| map.borrow().get(key).cloned())
    }

    pub fn set_contract_identity(key: InboxContract, identity: Identity) {
        crate::log::debug!(
            "adding inbox contract for `{alias}` ({key})",
            alias = identity.alias
        );
        INBOX_TO_ID.with(|map| map.borrow_mut().insert(key, identity));
    }

    pub fn remove_messages(
        &mut self,
        mut client: WebApiRequestClient,
        ids: &[u64],
    ) -> Result<LocalBoxFuture<'static, ()>, DynError> {
        let mut signed: Vec<u8> = Vec::with_capacity(ids.len() * 32);
        let mut to_rm_message_id = Vec::with_capacity(ids.len() * 32);
        for m in &self.messages {
            if ids.contains(&m.id) {
                let h = &m.token_assignment.assignment_hash;
                signed.extend(h);
                to_rm_message_id.push(*h);
            }
        }
        self.remove_received_message(ids);
        #[cfg(feature = "use-node")]
        {
            let signing_key = self.settings.ml_dsa_signing_key.as_ref();
            let ml_sig: ml_dsa::Signature<MlDsa65> = MlDsaSigner::sign(signing_key, &signed);
            let signature: Box<[u8]> = ml_sig.encode().to_vec().into_boxed_slice();
            let delta: UpdateInbox = UpdateInbox::RemoveMessages {
                signature,
                ids: to_rm_message_id,
            };
            let request = ContractRequest::Update {
                key: self.key,
                data: UpdateData::Delta(serde_json::to_vec(&delta)?.into()),
            };
            let f = async move {
                let r = client.send(request.into()).await;
                node_response_error_handling(
                    client.into(),
                    r.map_err(Into::into),
                    TryNodeAction::RemoveMessages,
                )
                .await;
            };
            Ok(f.boxed_local())
        }
        #[cfg(not(feature = "use-node"))]
        {
            Ok(async {}.boxed_local())
        }
    }

    pub fn merge(&mut self, other: InboxModel) {
        for m in other.messages {
            if !self
                .messages
                .iter()
                .any(|c| c.content.time == m.content.time)
            {
                self.add_received_message(
                    m.content,
                    m.token_assignment,
                    m.sender_vk,
                    m.signature_valid,
                );
            }
        }
    }

    // TODO: only used when an inbox is created first time when putting the contract
    #[allow(dead_code)]
    fn to_state(&self) -> Result<State<'static>, DynError> {
        let settings = self.settings.to_stored()?;
        let messages = self
            .messages
            .iter()
            .map(|_m| {
                let dk = &self.settings.ml_dsa_signing_key;
                // We need the ML-KEM decapsulation key to re-encrypt stored messages.
                // During to_state the identity is available via INBOX_TO_ID; look it up.
                // For now this path is dead (TODO comment above), so just skip re-encryption.
                let _ = dk;
                Err::<StoredMessage, DynError>("to_state re-encryption not implemented".into())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let inbox = StoredInbox::new(
            self.settings.ml_dsa_signing_key.as_ref(),
            settings,
            messages,
        );
        let serialized = serde_json::to_vec(&inbox)?;
        Ok(serialized.into())
    }

    pub fn from_state(
        ml_dsa_signing_key: Arc<MlDsaSigningKey<MlDsa65>>,
        ml_kem_dk: DecapsulationKey<MlKem768>,
        state: StoredInbox,
        key: ContractKey,
    ) -> Result<Self, DynError> {
        let messages = state
            .messages
            .iter()
            .enumerate()
            .map(|(id, msg)| {
                let content = DecryptedMessage::from_stored(&ml_kem_dk, msg.content.clone());
                let signature_valid =
                    verify_message_signature(&msg.content, &msg.sender_vk, &msg.signature);
                Ok(MessageModel {
                    id: id as u64,
                    content,
                    token_assignment: msg.token_assignment.clone(),
                    sender_vk: msg.sender_vk.clone(),
                    signature_valid,
                })
            })
            .collect::<Result<Vec<_>, DynError>>()?;
        Ok(Self {
            settings: InternalSettings::from_stored(
                state.settings,
                messages.len() as u64,
                ml_dsa_signing_key,
            )?,
            key,
            messages,
        })
    }

    /// This only affects in-memory messages, changes are not persisted.
    fn add_received_message(
        &mut self,
        content: DecryptedMessage,
        token_assignment: TokenAssignment,
        sender_vk: Vec<u8>,
        signature_valid: bool,
    ) {
        self.messages.push(MessageModel {
            id: self.settings.next_msg_id,
            content,
            token_assignment,
            sender_vk,
            signature_valid,
        });
        self.settings.next_msg_id += 1;
    }

    /// This only affects in-memory messages, changes are not persisted.
    fn remove_received_message(&mut self, ids: &[u64]) {
        if ids.len() > 1 {
            let drop: HashSet<u64> = HashSet::from_iter(ids.iter().copied());
            self.messages.retain(|a| !drop.contains(&a.id));
        } else {
            for id in ids {
                if let Ok(p) = self.messages.binary_search_by_key(id, |a| a.id) {
                    self.messages.remove(p);
                }
            }
        }
    }

    #[allow(dead_code)] // TODO: wire into settings UI
    async fn update_settings_at_store(
        &mut self,
        client: &mut WebApiRequestClient,
    ) -> Result<(), DynError> {
        let settings = self.settings.to_stored()?;
        let serialized = serde_json::to_vec(&settings)?;
        let signing_key = self.settings.ml_dsa_signing_key.as_ref();
        let ml_sig: ml_dsa::Signature<MlDsa65> = MlDsaSigner::sign(signing_key, &serialized);
        let signature: Box<[u8]> = ml_sig.encode().to_vec().into_boxed_slice();
        let delta = UpdateInbox::ModifySettings {
            signature,
            settings,
        };
        let request = ContractRequest::Update {
            key: self.key,
            data: UpdateData::Delta(serde_json::to_vec(&delta)?.into()),
        };
        client.send(request.into()).await?;
        Ok(())
    }

    pub async fn get_state(
        client: &mut WebApiRequestClient,
        key: ContractKey,
    ) -> Result<(), DynError> {
        let request = ContractRequest::Get {
            key: key.into(),
            return_contract_code: false,
            subscribe: false,
            blocking_subscribe: false,
        };
        client.send(request.into()).await?;
        Ok(())
    }

    pub async fn subscribe(
        client: &mut WebApiRequestClient,
        key: ContractKey,
    ) -> Result<(), DynError> {
        // todo: send the proper summary from the current state
        let summary: StateSummary = serde_json::to_vec(&InboxSummary::new(HashSet::new()))?.into();
        let request = ContractRequest::Subscribe {
            key: key.into(),
            summary: Some(summary),
        };
        client.send(request.into()).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ml_dsa::KeyGen;

    use freenet_stdlib::prelude::ContractCode;

    use super::*;

    impl InboxModel {
        fn new(
            ml_dsa_signing_key: Arc<MlDsaSigningKey<MlDsa65>>,
            _ml_kem_dk: DecapsulationKey<MlKem768>,
        ) -> Result<Self, DynError> {
            let vk = MlDsaKeypair::verifying_key(ml_dsa_signing_key.as_ref());
            let params = InboxParams {
                pub_key: inbox_params_pub_key_bytes(&vk),
            };
            Ok(Self {
                messages: vec![],
                settings: InternalSettings {
                    next_msg_id: 0,
                    minimum_tier: Tier::Hour1,
                    ml_dsa_signing_key,
                },
                key: ContractKey::from_params_and_code(
                    &params.try_into()?,
                    ContractCode::from([].as_slice()),
                ),
            })
        }
    }

    #[test]
    fn remove_msg() {
        let ml_dsa_key = Arc::new(MlDsa65::from_seed(&rand::random::<[u8; 32]>().into()));
        let ml_kem_dk = DecapsulationKey::<MlKem768>::from_seed({
            use rand::RngCore;
            let mut seed = [0u8; 64];
            rand::thread_rng().fill_bytes(&mut seed);
            seed.into()
        });
        let mut inbox = InboxModel::new(ml_dsa_key, ml_kem_dk).unwrap();
        for id in 0..10000 {
            inbox.messages.push(MessageModel {
                id,
                content: DecryptedMessage::default(),
                token_assignment: crate::test_util::test_assignment(),
                sender_vk: Vec::new(),
                signature_valid: false,
            });
        }
        let t0 = std::time::Instant::now();
        for id in 2500..7500 {
            inbox.remove_received_message(&[id]);
        }
        eprintln!("{}ms", t0.elapsed().as_millis());
    }

    fn fresh_signing_key() -> MlDsaSigningKey<MlDsa65> {
        MlDsa65::from_seed(&rand::random::<[u8; 32]>().into())
    }

    #[test]
    fn verify_signature_round_trip() {
        let sk = fresh_signing_key();
        let ciphertext = b"opaque encrypted payload".to_vec();
        let sig: ml_dsa::Signature<MlDsa65> = MlDsaSigner::sign(&sk, &ciphertext);
        let sig_bytes = sig.encode().to_vec();
        let vk_bytes = MlDsaKeypair::verifying_key(&sk).encode().to_vec();
        assert!(verify_message_signature(&ciphertext, &vk_bytes, &sig_bytes));
    }

    #[test]
    fn verify_rejects_tampered_ciphertext() {
        let sk = fresh_signing_key();
        let ciphertext = b"original payload".to_vec();
        let sig: ml_dsa::Signature<MlDsa65> = MlDsaSigner::sign(&sk, &ciphertext);
        let sig_bytes = sig.encode().to_vec();
        let vk_bytes = MlDsaKeypair::verifying_key(&sk).encode().to_vec();
        let tampered = b"different payload".to_vec();
        assert!(!verify_message_signature(&tampered, &vk_bytes, &sig_bytes));
    }

    #[test]
    fn verify_rejects_wrong_vk() {
        let sk1 = fresh_signing_key();
        let sk2 = fresh_signing_key();
        let ciphertext = b"payload".to_vec();
        let sig: ml_dsa::Signature<MlDsa65> = MlDsaSigner::sign(&sk1, &ciphertext);
        let sig_bytes = sig.encode().to_vec();
        let vk2_bytes = MlDsaKeypair::verifying_key(&sk2).encode().to_vec();
        assert!(!verify_message_signature(
            &ciphertext,
            &vk2_bytes,
            &sig_bytes
        ));
    }

    #[test]
    fn verify_rejects_empty_inputs() {
        assert!(!verify_message_signature(b"x", &[], &[1, 2, 3]));
        assert!(!verify_message_signature(b"x", &[1, 2, 3], &[]));
        assert!(!verify_message_signature(b"x", &[], &[]));
    }

    #[test]
    fn verify_rejects_garbage_lengths() {
        // Wrong-length VK and signature bytes both bail out cleanly.
        assert!(!verify_message_signature(b"x", &[0u8; 5], &[0u8; 5]));
    }
}
