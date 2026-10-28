use std::hash::Hasher;
use std::{
    cell::{LazyCell, RefCell},
    rc::Rc,
};

use std::sync::Arc;

use dioxus::prelude::*;
use freenet_stdlib::prelude::ContractKey;
use identity_management::{EntryKind, IdentityManagement};
use ml_dsa::{KeyGen, MlDsa65, SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem768};

use crate::DynError;
use crate::app::{ContractType, User, UserId};
use crate::clipboard::{CopyOutcome, copy_text};
use crate::testid;

use super::{InboxView, NodeAction};

struct ImportId(bool);

struct CreateAlias(bool);

/// Pre-login topbar: brand block + "Private · Decentralized" tag +
/// connection-state indicator on the right (vs the avatar in the
/// post-login mailbox).
#[allow(non_snake_case)]
fn Topbar() -> Element {
    let app_name = crate::app_name();
    let app_version = crate::app_version();
    rsx! {
        header { class: "topbar",
            div { class: "brand",
                {crate::app::brand_logo()}
                div { class: "brand-text",
                    span { class: "brand-name", "{app_name}" }
                    span { class: "brand-tag", "Private · Decentralized" }
                }
            }
            div { class: "topbar-spacer" }
            div { class: "topbar-state",
                span { class: "pulse-dot" }
                span { "local · ready" }
                span { class: "topbar-version", title: "Webapp build version", "{app_version}" }
            }
        }
    }
}

thread_local! {
    static ALIASES: LazyCell<Rc<RefCell<Vec<Identity>>>> = LazyCell::new(|| {
        Default::default()
    });
}

/// A user identity holding ML-DSA-65 + ML-KEM-768 keypairs.
///
/// - `ml_dsa_signing_key`: ML-DSA-65 signing key. The verifying key is embedded
///   in `InboxParams` and determines the inbox contract ID. The same key is
///   used by the AFT token subsystem to sign token assignments (reuse
///   decision logged in Stage 4 of #18). Wrapped in `Arc` because
///   `MlDsaSigningKey` is intentionally not `Clone` (secret key hygiene);
///   `Arc` gives us cheap logical clones without copying the key material.
/// - `ml_kem_dk`: ML-KEM-768 decapsulation key. The encapsulation key is
///   published so senders can encrypt messages to this identity.
#[derive(Debug)]
pub(crate) struct Identity {
    pub alias: Rc<str>,
    pub id: UserId,
    pub description: String,
    /// AFT tier hashed into this identity's `InboxParams` — the recipient
    /// policy senders must mint at. Frozen for the inbox lifetime
    /// because changing it rotates the contract id (#85).
    pub required_tier: freenet_aft_interface::Tier,
    /// `max_age_secs` half of the recipient policy. Same lifetime
    /// constraints as `required_tier`.
    pub max_age_secs: u64,
    /// ML-DSA-65 signing key for inbox state authorisation and AFT token signing.
    pub ml_dsa_signing_key: Arc<MlDsaSigningKey<MlDsa65>>,
    /// ML-KEM-768 decapsulation key for message decryption.
    pub ml_kem_dk: DecapsulationKey<MlKem768>,
    /// Cached encoded ML-KEM-768 encapsulation key bytes (1184 bytes), computed
    /// once at construction. Avoids re-deriving from `ml_kem_dk` on every read,
    /// which surfaced as a fingerprint mismatch (#100): two reads from the same
    /// logical identity could return different bytes after `Clone`, so the
    /// share-modal six-word display and the encoded contact token disagreed.
    ek_bytes: Vec<u8>,
    /// Cached encoded ML-DSA-65 verifying key bytes (1952 bytes), computed once
    /// at construction. Same rationale as `ek_bytes` — keeps the public-key
    /// view of the identity stable across clones and call sites.
    vk_bytes: Vec<u8>,
}

impl Identity {
    fn derive_vk_bytes(ml_dsa_signing_key: &MlDsaSigningKey<MlDsa65>) -> Vec<u8> {
        use ml_dsa::signature::Keypair;
        ml_dsa_signing_key.verifying_key().encode().to_vec()
    }

    fn derive_ek_bytes(ml_kem_dk: &DecapsulationKey<MlKem768>) -> Vec<u8> {
        use ml_kem::kem::KeyExport;
        ml_kem_dk.encapsulation_key().to_bytes().to_vec()
    }

    /// Build an `Identity` with derived `vk_bytes` / `ek_bytes` cached. Use this
    /// instead of the struct literal so the public-key views are computed once
    /// and stay consistent across clones (#100).
    pub(crate) fn new(
        alias: Rc<str>,
        id: UserId,
        description: String,
        ml_dsa_signing_key: Arc<MlDsaSigningKey<MlDsa65>>,
        ml_kem_dk: DecapsulationKey<MlKem768>,
    ) -> Self {
        Self::new_with_policy(
            alias,
            id,
            description,
            ml_dsa_signing_key,
            ml_kem_dk,
            freenet_aft_interface::Tier::Min10,
            freenet_email_inbox::DEFAULT_MAX_AGE_SECS,
        )
    }

    /// Construct an `Identity` with explicit anti-flood policy. The
    /// policy is part of `InboxParams`, so picking it here determines
    /// the inbox contract id and cannot change later (#85).
    pub(crate) fn new_with_policy(
        alias: Rc<str>,
        id: UserId,
        description: String,
        ml_dsa_signing_key: Arc<MlDsaSigningKey<MlDsa65>>,
        ml_kem_dk: DecapsulationKey<MlKem768>,
        required_tier: freenet_aft_interface::Tier,
        max_age_secs: u64,
    ) -> Self {
        let vk_bytes = Self::derive_vk_bytes(ml_dsa_signing_key.as_ref());
        let ek_bytes = Self::derive_ek_bytes(&ml_kem_dk);
        Self {
            alias,
            id,
            description,
            required_tier,
            max_age_secs,
            ml_dsa_signing_key,
            ml_kem_dk,
            ek_bytes,
            vk_bytes,
        }
    }

    /// Encoded ML-DSA-65 verifying key bytes (1952 bytes). Stable, unique per
    /// identity; used as the identity correlator in `HashMap` / `PartialEq`
    /// contexts that previously keyed by RSA.
    pub(crate) fn ml_dsa_vk_bytes(&self) -> Vec<u8> {
        self.vk_bytes.clone()
    }

    /// Encoded ML-KEM-768 encapsulation key bytes (1184 bytes). Public key half
    /// of `ml_kem_dk`; senders use it to encrypt to this identity.
    pub(crate) fn ml_kem_ek_bytes(&self) -> Vec<u8> {
        self.ek_bytes.clone()
    }
}

impl Clone for Identity {
    fn clone(&self) -> Self {
        Self {
            alias: self.alias.clone(),
            id: self.id,
            description: self.description.clone(),
            required_tier: self.required_tier,
            max_age_secs: self.max_age_secs,
            ml_dsa_signing_key: Arc::clone(&self.ml_dsa_signing_key),
            ml_kem_dk: self.ml_kem_dk.clone(),
            ek_bytes: self.ek_bytes.clone(),
            vk_bytes: self.vk_bytes.clone(),
        }
    }
}

impl PartialEq for Identity {
    fn eq(&self, other: &Self) -> bool {
        // Encoded ML-DSA verifying key bytes are the stable identifier.
        self.ml_dsa_vk_bytes() == other.ml_dsa_vk_bytes()
    }
}

impl Eq for Identity {}

impl Identity {
    #[must_use]
    pub(crate) fn set_aliases(
        mut new_aliases: IdentityManagement,
        mut user: Signal<crate::app::User>,
    ) -> Vec<Self> {
        ALIASES.with(|aliases| {
            let aliases = &mut *aliases.borrow_mut();
            let mut to_add = Vec::new();
            for alias in &*aliases {
                // just modify and avoid creating a new id
                if let Some(info) = new_aliases.remove(&alias.alias)
                    && info.kind == EntryKind::Identity
                {
                    let id = alias
                        .clone()
                        .with_description(info.extra.unwrap_or_default());
                    crate::app::address_book::register_identity(&id);
                    to_add.push(id);
                }
            }
            let mut identities = Vec::new();
            new_aliases
                .into_info()
                .for_each(|(alias, info)| match info.kind {
                    EntryKind::Identity => {
                        let stored: StoredIdentityKeys = match serde_json::from_slice(&info.key) {
                            Ok(s) => s,
                            Err(e) => {
                                crate::log::error(
                                    format!("skipping identity {alias}: bad key bytes: {e}"),
                                    None,
                                );
                                return;
                            }
                        };
                        let ml_dsa_signing_key = stored.ml_dsa_signing_key();
                        let ml_kem_dk = stored.ml_kem_dk();
                        let alias: Rc<str> = alias.into();
                        // Dedup user.identities by alias name. ALIASES is
                        // rebuilt wholesale (see `*aliases = to_add` below),
                        // but user.identities is a Signal Vec that only
                        // gets appended — without this guard a delegate
                        // echo after `set_alias` doubles the row. When
                        // replacing, reuse the existing slot's UserId so
                        // it stays consistent with the slot index that
                        // `set_logged_id` asserts against. See #114.
                        let existing_id = user
                            .read()
                            .identities
                            .iter()
                            .find(|i| i.alias == alias)
                            .map(|i| i.id);
                        let id = existing_id.unwrap_or_else(UserId::new);
                        let identity = Identity::new(
                            alias.clone(),
                            id,
                            String::default(),
                            Arc::clone(&ml_dsa_signing_key),
                            ml_kem_dk.clone(),
                        );
                        {
                            let mut user_w = user.write();
                            if let Some(slot) =
                                user_w.identities.iter_mut().find(|i| i.alias == alias)
                            {
                                *slot = identity.clone();
                            } else {
                                user_w.identities.push(identity.clone());
                            }
                        }
                        let full = Identity::new(
                            alias.clone(),
                            id,
                            info.extra.unwrap_or_default(),
                            ml_dsa_signing_key,
                            ml_kem_dk,
                        );
                        crate::app::address_book::register_identity(&full);
                        to_add.push(full);
                        identities.push(identity);
                    }
                    EntryKind::Contact => {
                        let stored: crate::app::address_book::StoredContactKeys =
                            match serde_json::from_slice(&info.key) {
                                Ok(s) => s,
                                Err(e) => {
                                    crate::log::error(
                                        format!("skipping contact {alias}: bad key bytes: {e}"),
                                        None,
                                    );
                                    return;
                                }
                            };
                        let contact = stored
                            .into_contact(alias.clone().into(), info.extra.unwrap_or_default());
                        if let Err(e) = crate::app::address_book::insert_contact(contact) {
                            crate::log::error(
                                format!("address book rejected stored contact {alias}: {e}"),
                                None,
                            );
                        }
                    }
                });
            *aliases = to_add;
            identities
        })
    }

    fn with_description(mut self, desc: String) -> Self {
        self.description = desc;
        self
    }

    pub(crate) fn set_alias(
        alias: Rc<str>,
        description: String,
        ml_dsa_signing_key: Arc<MlDsaSigningKey<MlDsa65>>,
        ml_kem_dk: DecapsulationKey<MlKem768>,
        inbox_key: ContractKey,
        mut user: Signal<crate::app::User>,
    ) -> Identity {
        let vk_bytes = Identity::derive_vk_bytes(ml_dsa_signing_key.as_ref());
        let ek_bytes = Identity::derive_ek_bytes(&ml_kem_dk);
        // Dedup by alias name. If a stale GetIdentities echo (or
        // example-data seeding) already populated `alias`, replace
        // the entry in place instead of pushing a duplicate. The
        // delegate is single-valued per alias name (HashMap insert
        // overwrites), so the old VK is already gone server-side —
        // surfacing two rows in the UI is the bug. See #114.
        //
        // CRITICAL: when replacing, reuse the existing slot's UserId.
        // `User::set_logged_id` asserts `id.0 < identities.len()` and
        // `logged_id()` indexes by `id.0`, so the UserId has to match
        // the slot index. Generating a fresh `UserId::new()` and then
        // replacing slot 0 produces UserId(N) where N >= len() and
        // panics on subsequent login. See #81 followup verification.
        let existing_id = user
            .read()
            .identities
            .iter()
            .find(|i| i.alias == alias)
            .map(|i| i.id);
        let identity = Identity {
            alias: alias.clone(),
            id: existing_id.unwrap_or_else(UserId::new),
            description: description.clone(),
            required_tier: freenet_aft_interface::Tier::Min10,
            max_age_secs: freenet_email_inbox::DEFAULT_MAX_AGE_SECS,
            ml_dsa_signing_key: Arc::clone(&ml_dsa_signing_key),
            ml_kem_dk: ml_kem_dk.clone(),
            ek_bytes: ek_bytes.clone(),
            vk_bytes: vk_bytes.clone(),
        };
        crate::inbox::InboxModel::set_contract_identity(inbox_key, identity.clone());
        {
            let mut user_w = user.write();
            if let Some(slot) = user_w.identities.iter_mut().find(|i| i.alias == alias) {
                *slot = identity.clone();
            } else {
                user_w.identities.push(identity.clone());
            }
        }
        ALIASES.with(|aliases| {
            let aliases = &mut *aliases.borrow_mut();
            let full = Identity {
                alias: alias.clone(),
                id: identity.id,
                description,
                required_tier: identity.required_tier,
                max_age_secs: identity.max_age_secs,
                ml_dsa_signing_key,
                ml_kem_dk,
                ek_bytes,
                vk_bytes,
            };
            crate::app::address_book::register_identity(&full);
            if let Some(slot) = aliases.iter_mut().find(|a| a.alias == alias) {
                *slot = full;
            } else {
                aliases.push(full);
            }
        });
        identity
    }

    pub(crate) fn get_aliases() -> Rc<RefCell<Vec<Identity>>> {
        ALIASES.with(|aliases| {
            let mut sorted_aliases = (**aliases).borrow().clone();
            sorted_aliases.sort_by(|a1, a2| a1.alias.cmp(&a2.alias));
            Rc::new(RefCell::new(sorted_aliases))
        })
    }

    #[allow(dead_code)]
    pub(crate) fn get_alias(alias: impl AsRef<str>) -> Option<Identity> {
        let alias = alias.as_ref();
        ALIASES.with(|aliases: &LazyCell<Rc<RefCell<Vec<Identity>>>>| {
            let aliases = &*aliases.borrow();
            aliases.iter().find(|a| &*a.alias == alias).cloned()
        })
    }

    pub fn alias(&self) -> &str {
        &self.alias
    }

    /// Return the ML-KEM-768 encapsulation (public) key for this identity.
    /// Senders use this to encrypt messages.
    #[allow(dead_code)]
    pub(crate) fn ml_kem_ek(&self) -> EncapsulationKey<MlKem768> {
        self.ml_kem_dk.encapsulation_key().clone()
    }

    /// Return the ML-DSA-65 verifying (public) key for this identity.
    /// Used to compute the inbox contract ID.
    #[allow(dead_code)]
    pub(crate) fn ml_dsa_vk(&self) -> MlDsaVerifyingKey<MlDsa65> {
        use ml_dsa::signature::Keypair;
        self.ml_dsa_signing_key.as_ref().verifying_key()
    }

    /// Reverse-lookup: find the alias whose ML-KEM encapsulation key matches.
    #[cfg(feature = "example-data")]
    pub(crate) fn alias_for_encaps_key(ek_bytes: &[u8]) -> Option<Rc<str>> {
        ALIASES.with(|aliases| {
            let aliases = &*aliases.borrow();
            aliases
                .iter()
                .find(|a| {
                    use ml_kem::kem::KeyExport;
                    a.ml_kem_dk.encapsulation_key().to_bytes().as_slice() == ek_bytes
                })
                .map(|a| a.alias.clone())
        })
    }

    /// Register an identity in the shared `ALIASES` store.
    /// Used by `example-data` mode to seed the identity list without
    /// going through the real delegate flow.
    #[cfg(feature = "example-data")]
    pub(crate) fn register_example(identity: Identity) {
        ALIASES.with(|aliases| {
            let aliases = &mut *aliases.borrow_mut();
            if !aliases.iter().any(|a| a.alias == identity.alias) {
                crate::app::address_book::register_identity(&identity);
                aliases.push(identity);
            }
        });
    }

    /// Rewrite the entry whose alias is `old` to use `new`, in place.
    /// Returns `true` if a matching entry was found and rewritten.
    /// Refuses (returns `false`) if `new` is already taken.
    pub(crate) fn rename_in_place(old: &str, new: &str) -> bool {
        ALIASES.with(|aliases| {
            let aliases = &mut *aliases.borrow_mut();
            if aliases.iter().any(|a| &*a.alias == new) {
                return false;
            }
            if let Some(entry) = aliases.iter_mut().find(|a| &*a.alias == old) {
                entry.alias = Rc::from(new);
                true
            } else {
                false
            }
        })
    }

    /// Drop the entry whose alias matches `alias` from the shared
    /// `ALIASES` store. Returns `true` if a matching entry was found.
    /// Used by `NodeAction::DeleteIdentity`.
    pub(crate) fn remove_in_place(alias: &str) -> bool {
        ALIASES.with(|aliases| {
            let aliases = &mut *aliases.borrow_mut();
            let before = aliases.len();
            aliases.retain(|a| &*a.alias != alias);
            aliases.len() != before
        })
    }
}

impl std::hash::Hash for Identity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Hash via the encoded ML-DSA-65 verifying key bytes — stable identifier.
        self.ml_dsa_vk_bytes().hash(state)
    }
}

impl std::fmt::Display for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &*self.alias)
    }
}

/// Serialised form of an identity's keypair bundle stored in the identity-management delegate.
///
/// Layout (serde_json) — all byte fields serialise as JSON arrays of integers:
/// ```json
/// { "ml_dsa_seed": [<32 u8 values>],
///   "ml_kem_seed": [<64 u8 values>] }
/// ```
///
/// Stage 4 of #18 removed the `rsa_key_bytes` field. `StoredIdentityKeys`
/// produced by pre-Stage-4 builds are no longer readable; see
/// `IdentityBackup` for the version gate on restored backups.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct StoredIdentityKeys {
    /// 32-byte random seed for ML-DSA-65 signing key reconstruction.
    pub ml_dsa_seed: Vec<u8>,
    /// 64-byte seed for ML-KEM-768 decapsulation key reconstruction.
    pub ml_kem_seed: Vec<u8>,
}

use serde::{Deserialize, Serialize};

impl StoredIdentityKeys {
    pub(crate) fn new(
        ml_dsa_signing_key: &Arc<MlDsaSigningKey<MlDsa65>>,
        ml_kem_dk: &DecapsulationKey<MlKem768>,
    ) -> Self {
        // Store ML-DSA as the 32-byte seed via `SigningKey::to_seed()`.
        // Reconstruction: `MlDsa65::from_seed(&seed)`.
        let ml_dsa_seed = ml_dsa_signing_key.as_ref().to_seed().to_vec();
        let ml_kem_seed = ml_kem_dk
            .to_seed()
            .expect("ML-KEM DK must have been generated from seed")
            .to_vec();
        Self {
            ml_dsa_seed,
            ml_kem_seed,
        }
    }

    pub(crate) fn ml_dsa_signing_key(&self) -> Arc<MlDsaSigningKey<MlDsa65>> {
        // Reconstruct from the stored 32-byte seed.
        use ml_dsa::Seed;
        let seed = Seed::try_from(self.ml_dsa_seed.as_slice())
            .expect("ML-DSA seed wrong length (expected 32 bytes)");
        Arc::new(MlDsa65::from_seed(&seed))
    }

    pub(crate) fn ml_kem_dk(&self) -> DecapsulationKey<MlKem768> {
        use ml_kem::{Seed, kem::KeyInit};
        let arr = Seed::try_from(self.ml_kem_seed.as_slice()).expect("ML-KEM seed wrong length");
        DecapsulationKey::<MlKem768>::new(&arr)
    }
}

/// Current on-disk backup format version. v2 drops the `rsa_key_bytes`
/// field from `StoredIdentityKeys` (Stage 4 of #18). v1 backups are not
/// restorable; users on pre-release builds must re-create their identities.
pub(crate) const IDENTITY_BACKUP_VERSION: u32 = 2;

/// Legacy on-disk backup format for a single identity, and the in-memory
/// result of parsing any restore input (see `backup_token::parse_backup`).
///
/// New exports are recovery keys (`backup_token`), not this JSON. The
/// JSON shape stays readable forever because users hold files exported by
/// earlier builds. The file is plaintext JSON containing raw private key
/// material.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct IdentityBackup {
    pub version: u32,
    pub alias: String,
    pub description: String,
    pub keys: StoredIdentityKeys,
}

/// Recovery key (`fmail-key-1:...`) for an identity's private keys.
pub(crate) fn recovery_key_for(identity: &Identity) -> Result<String, String> {
    let keys = StoredIdentityKeys::new(&identity.ml_dsa_signing_key, &identity.ml_kem_dk);
    super::backup_token::encode(&keys).map_err(|e| e.to_string())
}

/// Fingerprint words of an identity as owned strings (the shape
/// `BackupKeyPanel` takes).
pub(crate) fn fingerprint_word_vec(identity: &Identity) -> Vec<String> {
    crate::app::address_book::fingerprint_words(
        &identity.ml_dsa_vk_bytes(),
        &identity.ml_kem_ek_bytes(),
    )
    .iter()
    .map(|w| w.to_string())
    .collect()
}

/// Stamp `last_backup_at` for `alias`. Called only when the user confirms
/// "I've saved it" in `BackupKeyPanel` for an identity that already exists,
/// never on copy or download alone. New identities go through
/// [`record_backup_after_create`] instead.
pub(crate) fn mark_backed_up(alias: &str) {
    let mut settings = crate::local_state::identity_settings_for(alias);
    settings.last_backup_at = Some(chrono::Utc::now().timestamp_millis());
    crate::local_state::persist_identity_settings(alias.to_string(), settings);
}

/// `last_backup_at` for an identity that was just created: stamped if (and
/// only if) a backup of THESE keys is known to exist.
pub(crate) fn backup_stamp_after_create(backed_up: bool, now_ms: i64) -> Option<i64> {
    backed_up.then_some(now_ms)
}

/// Record the backup state of a newly created or restored identity. Call
/// only once the create request has been handed to the node without error
/// (`NodeAction::CreateIdentity`), never before: a create that fails and is
/// retried under the same alias with new keys must not inherit a stamp for
/// keys that no longer exist. "Handed to the node" means the identity
/// delegate message was SENT; the delegate's own result isn't reported back
/// here, so this is the same point at which the UI shows the new identity,
/// not proof that it was stored.
/// A fresh keypair also clears any stamp left by an earlier identity that
/// used the same alias, since that backup holds different keys.
pub(crate) fn record_backup_after_create(alias: &str, backed_up: bool) {
    let mut settings = crate::local_state::identity_settings_for(alias);
    let next = backup_stamp_after_create(backed_up, chrono::Utc::now().timestamp_millis());
    if settings.last_backup_at.is_none() && next.is_none() {
        // Nothing to change; don't write an untouched settings record.
        return;
    }
    settings.last_backup_at = next;
    crate::local_state::persist_identity_settings(alias.to_string(), settings);
}

/// Sanitize an alias string into a safe download filename stem.
///
/// Keeps `[A-Za-z0-9_-]`, replaces any other character with `_`, and
/// collapses runs of underscores. If the result would be empty, returns
/// `None` so the caller can fall back to a fingerprint-based name.
pub(crate) fn sanitize_filename_stem(alias: &str) -> Option<String> {
    let sanitized: String = alias
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    // Collapse consecutive underscores and trim leading/trailing ones.
    let mut result = String::with_capacity(sanitized.len());
    let mut prev_under = false;
    for c in sanitized.chars() {
        if c == '_' {
            if !prev_under {
                result.push(c);
            }
            prev_under = true;
        } else {
            result.push(c);
            prev_under = false;
        }
    }
    let result = result.trim_matches('_').to_string();
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

/// Build a safe download filename for a recovery-key `.txt` file.
///
/// Uses the sanitized alias when possible; falls back to
/// `freenet-identity-<first-two-fingerprint-words>.txt` when the alias
/// produces an empty stem after sanitization.
pub(crate) fn backup_filename<S: AsRef<str>>(alias: &str, words: &[S]) -> String {
    match sanitize_filename_stem(alias) {
        Some(stem) => format!("freenet-identity-{stem}.txt"),
        None => match words {
            [a, b, ..] => format!("freenet-identity-{}-{}.txt", a.as_ref(), b.as_ref()),
            _ => "freenet-identity.txt".to_string(),
        },
    }
}

/// Why [`trigger_browser_download`] sent nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DownloadError {
    /// Another download went out less than [`DOWNLOAD_GAP_MS`] ago. Not a
    /// failure: the UI says to wait a moment and retry.
    #[cfg_attr(not(target_family = "wasm"), allow(dead_code))]
    TooSoon,
    /// The download couldn't be started.
    #[cfg_attr(not(target_family = "wasm"), allow(dead_code))]
    Failed(String),
}

/// How [`trigger_browser_download`] handed a download off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DownloadRoute {
    /// Saved by this page with `<a download>` (dev server, Playwright).
    Local,
    /// Posted to the gateway shell, which saves it but can't report back,
    /// so the UI must not claim the file arrived.
    #[cfg_attr(not(target_family = "wasm"), allow(dead_code))]
    Relayed,
}

/// Minimum gap between two downloads. The gateway shell silently drops a
/// download that arrives within 2s of the previous one, and that limit is
/// per shell, i.e. for the whole app, not per component: downloading A's
/// key and then B's within 2s would lose B's without any signal. So the gap
/// is enforced here, once, for every caller.
#[cfg_attr(not(target_family = "wasm"), allow(dead_code))]
pub(crate) const DOWNLOAD_GAP_MS: f64 = 2_100.0;
// Must cover the shell's 2s limit.
const _: () = assert!(DOWNLOAD_GAP_MS > 2_000.0);

thread_local! {
    /// `performance.now()` of the last download handed off, for
    /// [`DOWNLOAD_GAP_MS`]. Monotonic, so a wall-clock step backwards
    /// can't refuse downloads until the clock catches up.
    static LAST_DOWNLOAD_MS: std::cell::Cell<Option<f64>> = const { std::cell::Cell::new(None) };
}

/// Milliseconds until another download may go out, or `None` if one may go
/// now. Pure, so the gap rule is unit-testable.
#[cfg_attr(not(target_family = "wasm"), allow(dead_code))]
pub(crate) fn download_wait_ms(last_ms: Option<f64>, now_ms: f64) -> Option<f64> {
    let left = DOWNLOAD_GAP_MS - (now_ms - last_ms?);
    (left > 0.0).then_some(left)
}

/// Trigger a browser file-download of `bytes` as `filename` with MIME type
/// `mime` (the gateway shell only accepts a small allowlist, which
/// includes `text/plain` and `application/json`).
///
/// Two paths:
///   * **Inside the gateway's sandboxed iframe** (the production case):
///     postMessage the bytes to the shell page, which runs in the real
///     origin and can issue an `<a download>` against a non-opaque
///     blob URL. Reason: an `<a download>` clicked inside a
///     null-origin sandboxed iframe either silently fails (Firefox)
///     or hands the OS a file the user can't find (Chrome) — see #187.
///     The shell's `download` handler matches the existing `clipboard`
///     proxy pattern.
///   * **Standalone** (dev server, Playwright, raw `dx serve`):
///     fall back to the original local `<a download>` path. There is
///     no parent shell to delegate to and no opaque-origin restriction.
///
/// Returns how the download was handed off, or an error string describing
/// why nothing was sent (including "too soon after the last download").
#[cfg(target_family = "wasm")]
pub(crate) fn trigger_browser_download(
    filename: &str,
    bytes: &[u8],
    mime: &str,
) -> Result<DownloadRoute, DownloadError> {
    let now = web_sys::window()
        .and_then(|w| w.performance())
        .map(|p| p.now())
        .unwrap_or_else(web_sys::js_sys::Date::now);
    if download_wait_ms(LAST_DOWNLOAD_MS.with(|c| c.get()), now).is_some() {
        return Err(DownloadError::TooSoon);
    }
    let route = download_now(filename, bytes, mime).map_err(DownloadError::Failed)?;
    LAST_DOWNLOAD_MS.with(|c| c.set(Some(now)));
    Ok(route)
}

#[cfg(target_family = "wasm")]
fn download_now(filename: &str, bytes: &[u8], mime: &str) -> Result<DownloadRoute, String> {
    let window = web_sys::window().ok_or_else(|| "no browser window context".to_string())?;
    // `window.parent` always returns a window. Compare against `window`
    // itself: when they are the same object we're at the top level
    // (no shell to delegate to). Otherwise we're embedded — try the
    // shell-proxied path first.
    let parent = window.parent().ok().flatten();
    let in_iframe = parent
        .as_ref()
        .map(|p| !web_sys::js_sys::Object::is(p.as_ref(), window.as_ref()))
        .unwrap_or(false);

    if in_iframe {
        let Some(shell) = crate::clipboard::gateway_shell() else {
            // Embedded, but we can't tell which origin to address: don't
            // post the payload anywhere rather than broadcast it with "*".
            return Err("couldn't work out the Freenet gateway's address".to_string());
        };
        match shell_proxy_download(&shell, filename, bytes, mime) {
            Ok(()) => return Ok(DownloadRoute::Relayed),
            Err(e) => {
                // Don't fall through to the local `<a download>` path —
                // inside a sandboxed iframe that path is the broken one
                // we're trying to avoid. Surface the error so the user
                // sees a toast / log entry instead of silent failure.
                return Err(format!("shell download proxy failed: {e}"));
            }
        }
    }

    local_anchor_download(filename, bytes, mime).map(|()| DownloadRoute::Local)
}

/// Shell-proxied download: postMessage the payload to the parent
/// gateway shell, which performs the download from its own origin.
/// See `path_handlers.rs` for the matching `download` handler. Addressed to
/// the gateway's origin, never `"*"`: the payload is a private key.
#[cfg(target_family = "wasm")]
fn shell_proxy_download(
    shell: &crate::clipboard::GatewayShell,
    filename: &str,
    bytes: &[u8],
    mime: &str,
) -> Result<(), String> {
    use base64::Engine;
    use web_sys::js_sys;

    let payload = base64::engine::general_purpose::STANDARD.encode(bytes);

    let msg = js_sys::Object::new();
    js_sys::Reflect::set(&msg, &"__freenet_shell__".into(), &true.into())
        .map_err(|e| format!("set marker: {e:?}"))?;
    js_sys::Reflect::set(&msg, &"type".into(), &"download".into())
        .map_err(|e| format!("set type: {e:?}"))?;
    js_sys::Reflect::set(&msg, &"filename".into(), &filename.into())
        .map_err(|e| format!("set filename: {e:?}"))?;
    js_sys::Reflect::set(&msg, &"mimeType".into(), &mime.into())
        .map_err(|e| format!("set mimeType: {e:?}"))?;
    js_sys::Reflect::set(&msg, &"base64".into(), &payload.into())
        .map_err(|e| format!("set base64: {e:?}"))?;

    shell.post(&msg)
}

/// Local `<a download>` path. Used when the webapp is served outside
/// the gateway shell (dev / Playwright / `dx serve`).
#[cfg(target_family = "wasm")]
fn local_anchor_download(filename: &str, bytes: &[u8], mime: &str) -> Result<(), String> {
    use wasm_bindgen::JsCast;
    use web_sys::{Blob, BlobPropertyBag, HtmlAnchorElement, Url, js_sys};

    let window = web_sys::window().ok_or_else(|| "no browser window context".to_string())?;
    let document = window
        .document()
        .ok_or_else(|| "no document on window".to_string())?;

    let uint8 = js_sys::Uint8Array::from(bytes);
    let array = js_sys::Array::new();
    array.push(&uint8);
    let opts = BlobPropertyBag::new();
    opts.set_type(mime);
    let blob = Blob::new_with_u8_array_sequence_and_options(&array, &opts)
        .map_err(|e| format!("Blob creation failed: {e:?}"))?;
    let url = Url::create_object_url_with_blob(&blob)
        .map_err(|e| format!("URL creation failed: {e:?}"))?;
    let anchor = document
        .create_element("a")
        .ok()
        .and_then(|el| el.dyn_into::<HtmlAnchorElement>().ok())
        .ok_or_else(|| "failed to create anchor element".to_string())?;
    anchor.set_href(&url);
    anchor.set_download(filename);
    // Append to body before clicking — Safari ignores clicks on detached anchors.
    if let Some(body) = document.body() {
        let _ = body.append_child(&anchor);
        anchor.click();
        let _ = body.remove_child(&anchor);
    } else {
        anchor.click();
    }
    let _ = Url::revoke_object_url(&url);
    Ok(())
}

#[cfg(not(target_family = "wasm"))]
pub(crate) fn trigger_browser_download(
    _filename: &str,
    _bytes: &[u8],
    _mime: &str,
) -> Result<DownloadRoute, DownloadError> {
    Ok(DownloadRoute::Local)
}

pub(crate) struct ImportBackup(pub(crate) bool);

pub(crate) struct ShareContact(pub(crate) bool);

/// Pending share-card data passed from the click handler to
/// `ShareContactModal` via context.
#[derive(Default, Clone)]
pub(crate) struct SharePending {
    pub(crate) data: Option<SharePendingData>,
}

#[derive(Clone)]
pub(crate) struct SharePendingData {
    pub(crate) alias: String,
    pub(crate) share_text: String,
}

/// Controls the Import-contact modal. `open` toggles visibility;
/// `prefill` carries an inbox address (bs58) to seed the paste field
/// when the modal is opened from a known sender — e.g. "Add to address
/// book" on a received message (#272). `None` prefill = manual paste.
///
/// `prefill_alias` carries the sender's *display name* from the incoming
/// message (`Message.from`) so the modal can default the local nickname
/// AND persist it as `suggested_alias` (#289). Without it the
/// add-from-message path opens the nickname field blank, the user picks
/// an arbitrary local label, and the reply path can't resolve the
/// sender's send-alias — the exact #289 repro. `None` = no suggestion.
#[derive(Clone, Default)]
pub(crate) struct ImportContact {
    pub(crate) open: bool,
    pub(crate) prefill: Option<String>,
    pub(crate) prefill_alias: Option<String>,
}

impl ImportContact {
    pub(crate) fn opened() -> Self {
        Self {
            open: true,
            prefill: None,
            prefill_alias: None,
        }
    }

    /// Open the modal pre-seeded with a sender's inbox `address` (bs58) and,
    /// optionally, the sender's advertised display name (`alias`). The modal
    /// defaults the local nickname to `alias` (the primary #289 fix: a reply
    /// addressed to the sender's display name then matches the contact's
    /// `local_alias` exactly). It also seeds `card_suggested_alias` so that IF
    /// the user relabels the contact, the original name survives as the
    /// `suggested_alias` resolver fallback (#295).
    pub(crate) fn opened_with(address: String, alias: Option<String>) -> Self {
        Self {
            open: true,
            prefill: Some(address),
            prefill_alias: alias,
        }
    }
}

/// Compute the `suggested_alias` to persist on a contact at import time.
///
/// `card_suggested` is the sender's advertised display name (from a contact
/// card, or seeded from the incoming message on the add-from-message path);
/// `local_alias` is the nickname the user is saving the contact under.
///
/// Returns the advertised name ONLY when it is non-empty AND differs from the
/// local nickname. When the user accepts the seeded default (so the two are
/// equal) the result is `None` — storing a `suggested_alias` identical to
/// `local_alias` would be redundant, since the reply path already resolves by
/// exact `local_alias` match. The field earns its keep only as a relabel
/// fallback: user saves "alice-from-work" as local "ally" → persist
/// `Some("alice-from-work")` so a reply addressed to "alice-from-work" still
/// resolves (#289 / #295).
pub(crate) fn persisted_suggested_alias(
    card_suggested: Option<&str>,
    local_alias: &str,
) -> Option<String> {
    card_suggested
        .filter(|s| !s.is_empty() && *s != local_alias)
        .map(str::to_string)
}

/// Carries the `Contact` whose verified flag the user is about to flip.
/// `None` while the modal is closed; populated by the row-level Verify
/// button. Holding the full `Contact` here (rather than just the alias)
/// avoids a second lookup against `ADDRESS_BOOK` when we re-send it.
#[derive(Clone, Default)]
struct VerifyContactPending(Option<crate::app::address_book::Contact>);

#[derive(Debug, Clone)]
pub struct LoginController {
    pub updated: bool,
}

impl LoginController {
    pub fn new() -> Self {
        Self { updated: false }
    }
}

#[allow(non_snake_case)]
pub(super) fn IdentifiersList() -> Element {
    use_context_provider(|| Signal::new(CreateAlias(false)));
    // ImportBackup / ShareContact / SharePending / ImportContact are provided
    // by app() so that the modals are also reachable from UserInbox
    // (Settings → Contacts / Account). VerifyContactPending is
    // login-pane-only; provide it here.
    use_context_provider(|| Signal::new(VerifyContactPending::default()));
    // ImportForm is shared between the hub flow (toggled by ImportBackup
    // here) and the first-run flow (toggled by ImportId in
    // GetOrCreateIdentity). Provide both contexts so the same component
    // can clear whichever wrapper is active.
    use_context_provider(|| Signal::new(ImportId(false)));
    let create_alias_form = use_context::<Signal<CreateAlias>>();
    let import_backup_form = use_context::<Signal<ImportBackup>>();
    let verify_contact_pending = use_context::<Signal<VerifyContactPending>>();
    let import_contact = use_context::<Signal<ImportContact>>();
    let share_contact = use_context::<Signal<ShareContact>>();

    rsx! {
        div { class: "fm-pre",
            Topbar {}
            section { class: "page screen",
                div { class: "col-wide",
                    if create_alias_form.read().0 {
                        CreateAliasForm {}
                    } else if import_backup_form.read().0 {
                        ImportForm {}
                    } else {
                        Identities {}
                        ContactsSection {}
                    }
                }
            }
            if verify_contact_pending.read().0.is_some() {
                VerifyContactModal {}
            }
            // Contact modals rendered here so they are inside div.fm-pre
            // and get the correct scoped CSS (`.veil`/`.modal` in login.css
            // @scope .fm-pre). Signals are provided by app() root so
            // UserInbox (Settings → Contacts) can also trigger them; the
            // companion render site lives inside UserInbox's div.fm-app. (#158)
            if share_contact.read().0 {
                ShareContactModal {}
            }
            if import_contact.read().open {
                ImportContactForm {}
            }
        }
    }
}

#[allow(non_snake_case)]
pub(super) fn Identities() -> Element {
    let aliases = Identity::get_aliases();
    let aliases_list = aliases.borrow();
    let mut create_alias_form = use_context::<Signal<CreateAlias>>();
    let mut import_backup_form = use_context::<Signal<ImportBackup>>();
    let mut login_controller = use_context::<Signal<LoginController>>();

    if login_controller.read().updated {
        login_controller.write().updated = false;
    }

    // Identity::PartialEq compares by ML-DSA VK bytes only (the stable
    // cryptographic identifier), so a rename — same key, new alias —
    // hits the auto-memo on `#[component]` and the row keeps the old
    // alias on screen. Pass `alias_str` as a separate prop so the memo
    // sees the change and re-renders.
    #[component]
    fn IdentityEntry(identity: Identity, alias_str: String) -> Element {
        let _ = alias_str;
        let mut user = use_context::<Signal<User>>();
        let mut inbox = use_context::<Signal<InboxView>>();
        let mut share_contact_form = use_context::<Signal<ShareContact>>();
        let mut share_pending = use_context::<Signal<SharePending>>();
        let actions = use_coroutine_handle::<NodeAction>();
        let id = identity.id;
        let alias = identity.alias.clone();
        let description = identity.description.clone();
        let initial = alias.chars().next().unwrap_or('·').to_string();
        let fp_short = {
            let words = crate::app::address_book::fingerprint_words(
                &identity.ml_dsa_vk_bytes(),
                &identity.ml_kem_ek_bytes(),
            );
            format!("{} {}", words[0], words[1])
        };
        let backup_alias = identity.clone();
        let share_id = identity.clone();
        let rename_id = identity.clone();
        let delete_id = identity.clone();
        // Per-row rename state. `Some(draft)` means the inline editor is
        // open. Issue #32 — rename is delete+create with the same key.
        let mut rename_draft: Signal<Option<String>> = use_signal(|| None);
        let mut rename_error = use_signal(String::new);
        // Per-row delete-confirmation state. `true` means the modal is open;
        // user has to type the alias verbatim before the Delete button
        // arms. The keypair is destroyed locally so unconfirmed clicks must
        // not slip through.
        let mut delete_open = use_signal(|| false);
        let mut delete_input = use_signal(String::new);
        let mut delete_error = use_signal(String::new);
        // Per-row backup modal (recovery key panel). `backup_saved` mirrors
        // the user's "I've saved it" for this modal session.
        let mut backup_open = use_signal(|| false);
        let mut backup_saved = use_signal(|| false);

        let submit_rename = move |_| {
            let next = rename_draft
                .read()
                .clone()
                .unwrap_or_default()
                .trim()
                .to_string();
            if next.is_empty() {
                rename_error.set("Alias cannot be empty.".into());
                return;
            }
            if *next == *rename_id.alias {
                rename_draft.set(None);
                rename_error.set(String::new());
                return;
            }
            // Refuse collisions with any other own alias on this device.
            let collision = Identity::get_aliases()
                .borrow()
                .iter()
                .any(|a| *a.alias != *rename_id.alias && *a.alias == *next);
            if collision {
                rename_error.set(format!("`{next}` is already in use on this device."));
                return;
            }
            actions.send(NodeAction::RenameIdentity {
                old: rename_id.alias.clone(),
                new: Rc::from(next.as_str()),
                identity: Box::new(rename_id.clone()),
            });
            rename_draft.set(None);
            rename_error.set(String::new());
        };

        let submit_delete = {
            let delete_id = delete_id.clone();
            move |_| {
                let typed = delete_input.read().trim().to_string();
                if typed != *delete_id.alias {
                    delete_error.set("Type the alias exactly as shown to confirm.".into());
                    return;
                }
                actions.send(NodeAction::DeleteIdentity {
                    identity: Box::new(delete_id.clone()),
                });
                delete_open.set(false);
                delete_input.set(String::new());
                delete_error.set(String::new());
            }
        };

        rsx! {
            div { class: "id-row", "data-testid": testid::FM_ID_ROW, "data-alias": "{alias}",
                div { class: "id-orb", "{initial}" }
                div { class: "id-meta",
                    if let Some(draft) = &*rename_draft.read() {
                        // Inline rename editor.
                        input {
                            class: "input",
                            style: "max-width:240px;",
                            "data-testid": testid::FM_RENAME_INPUT,
                            value: "{draft}",
                            oninput: move |evt| { rename_draft.set(Some(evt.value())); },
                        }
                        if !rename_error.read().is_empty() {
                            span { class: "field-help", style: "color:#b91c1c;",
                                "{rename_error.read()}"
                            }
                        }
                    } else {
                        span { class: "id-name", "{alias}" }
                        if !description.is_empty() {
                            span { class: "id-desc", "{description}" }
                        }
                        span { class: "id-fp",
                            span { class: "label", "Fingerprint" }
                            "{fp_short}"
                        }
                    }
                }
                div { class: "id-actions",
                    if rename_draft.read().is_some() {
                        button {
                            class: "btn btn-ghost",
                            onclick: move |_| {
                                rename_draft.set(None);
                                rename_error.set(String::new());
                            },
                            "Cancel"
                        }
                        button {
                            class: "btn btn-primary",
                            "data-testid": testid::FM_RENAME_SUBMIT,
                            onclick: submit_rename,
                            "Save"
                        }
                    } else {
                        button {
                            class: "icon-btn",
                            title: "Rename this identity",
                            "data-testid": testid::FM_ID_RENAME,
                            onclick: {
                                let current = alias.to_string();
                                move |_| {
                                    rename_draft.set(Some(current.clone()));
                                    rename_error.set(String::new());
                                }
                            },
                            "✎"
                        }
                        button {
                            class: "icon-btn",
                            title: "Back up this identity's recovery key",
                            "data-testid": testid::FM_ID_BACKUP,
                            onclick: move |_| {
                                backup_saved.set(false);
                                backup_open.set(true);
                            },
                            "↓"
                        }
                        button {
                            class: "icon-btn",
                            title: "Share your address with someone",
                            "data-testid": testid::FM_ID_SHARE,
                            onclick: move |_| {
                                let card = crate::app::address_book::ContactCard::from_identity(&share_id);
                                let fp = crate::app::address_book::fingerprint_words(
                                    &share_id.ml_dsa_vk_bytes(),
                                    &share_id.ml_kem_ek_bytes(),
                                )
                                .join("-");
                                let share_text = format!("{}\nverify: {}", card.encode(), fp);
                                share_pending.set(SharePending {
                                    data: Some(SharePendingData {
                                        alias: share_id.alias.to_string(),
                                        share_text,
                                    }),
                                });
                                share_contact_form.write().0 = true;
                            },
                            "↗"
                        }
                        button {
                            class: "icon-btn",
                            title: "Delete this identity from this device",
                            "data-testid": testid::FM_ID_DELETE,
                            onclick: move |_| {
                                delete_open.set(true);
                                delete_input.set(String::new());
                                delete_error.set(String::new());
                            },
                            "🗑"
                        }
                        button {
                            class: "btn btn-primary",
                            "data-testid": testid::FM_ID_OPEN,
                            onclick: move |_| {
                                user.write().set_logged_id(id);
                                inbox.write().set_active_id(id);
                            },
                            "Open inbox"
                        }
                    }
                }
            }
            if *delete_open.read() {
                div { class: "veil",
                    onclick: move |_| {
                        delete_open.set(false);
                        delete_input.set(String::new());
                        delete_error.set(String::new());
                    },
                    div { class: "modal",
                        onclick: move |evt| { evt.stop_propagation(); },
                        h2 { class: "display md", "Delete identity?" }
                        p {
                            "This permanently removes “{delete_id.alias}” and its private keys from this device. "
                            "Messages already in this inbox become unreadable. "
                            "On-chain contracts stay where they are — there's no way to delete them — "
                            "but without the keypair they can't be reached again."
                        }
                        p { style: "color:#b91c1c; font-weight:600;",
                            "Only your recovery key (or an older backup file) can bring it back. Without one, this is irreversible."
                        }
                        p {
                            "Type "
                            code { "{delete_id.alias}" }
                            " below to confirm."
                        }
                        input {
                            class: "input",
                            "data-testid": testid::FM_DELETE_CONFIRM_INPUT,
                            value: "{delete_input.read()}",
                            oninput: move |evt| { delete_input.set(evt.value()); },
                        }
                        if !delete_error.read().is_empty() {
                            div { class: "field-help", style: "color:#b91c1c;",
                                "{delete_error.read()}"
                            }
                        }
                        div { style: "display:flex; gap:10px; margin-top:14px;",
                            button {
                                class: "btn btn-ghost",
                                "data-testid": testid::FM_DELETE_CONFIRM_CANCEL,
                                onclick: move |_| {
                                    delete_open.set(false);
                                    delete_input.set(String::new());
                                    delete_error.set(String::new());
                                },
                                "Cancel"
                            }
                            button {
                                class: "btn btn-danger",
                                "data-testid": testid::FM_DELETE_CONFIRM_SUBMIT,
                                onclick: submit_delete,
                                "Delete identity"
                            }
                        }
                    }
                }
            }
            if *backup_open.read() {
                BackupKeyModal {
                    identity: backup_alias.clone(),
                    alias_str: backup_alias.alias.to_string(),
                    saved: *backup_saved.read(),
                    on_saved: move |_| backup_saved.set(true),
                    on_close: move |_| backup_open.set(false),
                }
            }
        }
    }

    let identities_iter = aliases_list.iter().map(|alias| {
        rsx!(IdentityEntry {
            identity: alias.clone(),
            alias_str: alias.alias.to_string(),
        })
    });

    rsx! {
        div { style: "display:flex; align-items:baseline; justify-content:space-between; margin-bottom:18px;",
            h1 { class: "display lg italic", "Your identities" }
            span { class: "mono-tag", "{aliases_list.len()} on this device" }
        }
        div { class: "id-list",
            {identities_iter}
        }
        div { style: "display:flex; gap:10px; margin-top:18px;",
            button {
                class: "btn btn-secondary",
                "data-testid": testid::FM_ID_CREATE,
                onclick: move |_| { create_alias_form.write().0 = true; },
                "+ Create new identity"
            }
            button {
                class: "btn btn-ghost",
                "data-testid": testid::FM_ID_RESTORE,
                onclick: move |_| { import_backup_form.write().0 = true; },
                "Restore from backup"
            }
        }
        p { class: "field-help", style: "margin-top:14px;",
            "Recovery keys are private keys. Keep them in a password manager."
        }
    }
}

/// Modal wrapping `BackupKeyPanel` for an existing identity (the identity
/// row's "↓" button). Rendered inside `div.fm-pre`, so it uses the
/// login.css `.veil` / `.modal` rules.
#[component]
fn BackupKeyModal(
    identity: Identity,
    // Identity::PartialEq ignores the alias; pass it so a rename re-renders.
    alias_str: String,
    saved: bool,
    on_saved: EventHandler<()>,
    on_close: EventHandler<()>,
) -> Element {
    let token = recovery_key_for(&identity);
    let words = fingerprint_word_vec(&identity);
    // Close on a backdrop click only when the press also STARTED on the
    // backdrop. Selecting the key by hand and releasing the mouse outside
    // the dialog produces a click on the veil; that must not close it.
    let mut pressed_on_veil = use_signal(|| false);
    rsx! {
        div { class: "veil",
            onmousedown: move |_| pressed_on_veil.set(true),
            onclick: move |_| {
                if *pressed_on_veil.peek() {
                    on_close.call(());
                }
                pressed_on_veil.set(false);
            },
            div { class: "modal",
                "data-testid": testid::FM_BACKUP_MODAL,
                onmousedown: move |evt| {
                    evt.stop_propagation();
                    pressed_on_veil.set(false);
                },
                onclick: move |evt| { evt.stop_propagation(); },
                div { class: "modal-head",
                    span { class: "modal-title", "Back up {alias_str}" }
                    button { class: "modal-x", onclick: move |_| on_close.call(()), "✕" }
                }
                div { class: "modal-body",
                    match token {
                        Ok(token) => rsx! {
                            crate::app::backup_panel::BackupKeyPanel {
                                token,
                                alias: alias_str.clone(),
                                words,
                                saved,
                                on_exported: move |_| {},
                                on_saved: {
                                    let alias = alias_str.clone();
                                    move |_| {
                                        mark_backed_up(&alias);
                                        on_saved.call(());
                                    }
                                },
                            }
                        },
                        Err(e) => rsx! {
                            div { class: "info fm-error",
                                "Couldn't build a recovery key for this identity: {e}"
                            }
                        },
                    }
                }
                div { class: "modal-foot",
                    button {
                        class: "btn btn-secondary",
                        onclick: move |_| on_close.call(()),
                        "Close"
                    }
                }
            }
        }
    }
}

#[allow(non_snake_case)]
pub(super) fn CreateAliasForm() -> Element {
    let mut create_alias_form = use_context::<Signal<CreateAlias>>();
    let mut login_controller = use_context::<Signal<LoginController>>();
    let actions = use_coroutine_handle::<NodeAction>();

    if login_controller.read().updated {
        login_controller.write().updated = false;
    }

    let mut login_error = use_signal(String::new);
    let mut alias_input = use_signal(String::new);
    let mut description = use_signal(String::new);
    // Reveal stage: hold the freshly-generated keypair + its fingerprint
    // until the user explicitly continues. This gives them a beat to back
    // up before the keys are persisted via NodeAction::CreateIdentity.
    type PendingIdentity = (
        Arc<MlDsaSigningKey<MlDsa65>>,
        DecapsulationKey<MlKem768>,
        [&'static str; 6],
    );
    let mut pending: Signal<Option<PendingIdentity>> = use_signal(|| None);
    // True once the recovery key has left the browser (copied, downloaded
    // or confirmed saved) during this creation flow, so we can warn before
    // discarding.
    let mut backup_taken = use_signal(|| false);
    // True only after the user clicked "I've saved it". Drives the
    // `last_backup_at` stamp when the identity is created.
    let mut backup_confirmed = use_signal(|| false);
    // Copies of the pending key, including ones still in flight. Owned here
    // rather than in the panel because opening the discard dialog unmounts
    // the panel while its async copies keep running (see `CopyTracker`).
    let mut copy_tracker = use_signal(crate::app::backup_panel::CopyTracker::default);
    // Whether the recovery-key panel is expanded in the reveal card.
    let mut backup_panel_open = use_signal(|| false);
    // When true, show the orphan-keyfile confirmation dialog.
    let mut discard_confirm_open = use_signal(|| false);

    let submit = move |_| {
        let alias_str = alias_input.read().trim().to_string();
        if alias_str.is_empty() {
            login_error.set("Alias is required.".into());
            return;
        }
        if Identity::get_alias(&alias_str).is_some() {
            login_error.set(format!(
                "An identity named \"{alias_str}\" already exists. Choose a different name, or delete the existing one first — replacing it would make its inbox unreadable."
            ));
            return;
        }
        match get_keys() {
            Ok((ml_dsa, ml_kem)) => {
                use ml_dsa::signature::Keypair;
                use ml_kem::kem::KeyExport;
                let vk_bytes: Vec<u8> = ml_dsa.as_ref().verifying_key().encode().to_vec();
                let ek_bytes: Vec<u8> = ml_kem.encapsulation_key().to_bytes().to_vec();
                let words = crate::app::address_book::fingerprint_words(&vk_bytes, &ek_bytes);
                pending.set(Some((ml_dsa, ml_kem, words)));
                login_error.set(String::new());
                backup_taken.set(false);
                backup_confirmed.set(false);
                copy_tracker.write().reset();
                backup_panel_open.set(false);
            }
            Err(e) => {
                login_error.set(format!("Failed to generate keys: {e:?}"));
            }
        }
    };

    let confirm = move |_| {
        let alias_str = alias_input.read().trim().to_string();
        let desc_val = description.read().clone();
        let Some((ml_dsa, ml_kem, _words)) = pending.write().take() else {
            return;
        };
        // Not stamped here: the node action stamps it once the create
        // request has gone to the node (see `record_backup_after_create`).
        let backed_up = *backup_confirmed.read();
        let alias: Rc<str> = alias_str.into();
        let ek_bytes = {
            use ml_kem::kem::KeyExport;
            ml_kem.encapsulation_key().to_bytes().to_vec()
        };
        actions.send(NodeAction::CreateContract {
            alias: alias.clone(),
            ml_dsa_key: ml_dsa.clone(),
            ml_kem_ek_bytes: ek_bytes.clone(),
            contract_type: ContractType::InboxContract,
            required_tier: freenet_aft_interface::Tier::Min10,
            max_age_secs: freenet_email_inbox::DEFAULT_MAX_AGE_SECS,
        });
        actions.send(NodeAction::CreateDelegate {
            alias: alias.clone(),
            ml_dsa_key: ml_dsa.clone(),
        });
        actions.send(NodeAction::CreateContract {
            alias: alias.clone(),
            ml_dsa_key: ml_dsa.clone(),
            ml_kem_ek_bytes: ek_bytes,
            contract_type: ContractType::AFTContract,
            required_tier: freenet_aft_interface::Tier::Min10,
            max_age_secs: freenet_email_inbox::DEFAULT_MAX_AGE_SECS,
        });
        actions.send(NodeAction::CreateIdentity {
            alias,
            ml_dsa_key: ml_dsa,
            ml_kem_dk: Box::new(ml_kem),
            description: desc_val,
            backed_up,
        });
        create_alias_form.write().0 = false;
    };

    // Cancel from the form stage (before keys are generated — no orphan risk).
    let cancel = move |_| {
        pending.set(None);
        alias_input.set(String::new());
        description.set(String::new());
        create_alias_form.write().0 = false;
    };

    // Real discard: unconditionally clear state and close the form.
    let do_discard = move |_| {
        pending.set(None);
        backup_taken.set(false);
        backup_confirmed.set(false);
        copy_tracker.write().reset();
        backup_panel_open.set(false);
        discard_confirm_open.set(false);
        alias_input.set(String::new());
        description.set(String::new());
        create_alias_form.write().0 = false;
    };

    // "Discard" button handler: warn if the user already downloaded a backup
    // (orphan risk), otherwise discard immediately.
    let on_discard_click = move |_| {
        if *backup_taken.read() || copy_tracker.read().possibly_exported() {
            discard_confirm_open.set(true);
        } else {
            pending.set(None);
            alias_input.set(String::new());
            description.set(String::new());
            create_alias_form.write().0 = false;
        }
    };

    let words_opt = pending.read().as_ref().map(|(_, _, w)| *w);
    // Recovery key for the pending keypair, built only while the panel is
    // open so the secret isn't rendered into the DOM unless asked for.
    let pending_token: Option<Result<String, String>> = if *backup_panel_open.read() {
        pending.read().as_ref().map(|(ml_dsa, ml_kem, _)| {
            super::backup_token::encode(&StoredIdentityKeys::new(ml_dsa, ml_kem))
                .map_err(|e| e.to_string())
        })
    } else {
        None
    };

    rsx! {
        if *discard_confirm_open.read() {
            // ── Orphan-keyfile confirmation dialog ───────────────────
            div { class: "modal-overlay",
                div { class: "card",
                    h2 { class: "display md italic", "Discard backed-up identity?" }
                    p { class: "lede",
                        "You already copied or downloaded this identity's recovery key. If you discard it now, delete that copy too, so you don't mistake it for an identity you use."
                    }
                    div { class: "modal-foot", style: "background:transparent; border:0; padding:18px 0 0;",
                        button {
                            class: "btn btn-ghost",
                            onclick: move |_| { discard_confirm_open.set(false); },
                            "Go back"
                        }
                        button {
                            class: "btn btn-danger",
                            onclick: do_discard,
                            "Discard anyway"
                        }
                    }
                }
            }
        } else if let Some(words) = words_opt {
            // ── Reveal stage ────────────────────────────────────────
            div { class: "card",
                h2 { class: "display md italic", "Your fingerprint" }
                p { class: "lede",
                    "Six words. Same value, every time. Read these to a contact through a separate channel before they trust your address."
                }
                div { class: "verify-words",
                    div { class: "verify-words-label",
                        span { class: "pulse-dot" }
                        "Six-word fingerprint"
                    }
                    div { class: "verify-words-grid",
                        {
                            words.iter().enumerate().map(|(i, w)| rsx! {
                                div { class: "verify-word",
                                    span { class: "num", "{i + 1:02}" }
                                    span { class: "w", "{w}" }
                                }
                            })
                        }
                    }
                }
                div { class: "nudge",
                    span { class: "nudge-icon", "⚠" }
                    div { class: "nudge-text",
                        strong { "Back up the key before you continue." }
                        " Keys are stored in your local Freenet node's delegate — losing the node's data dir destroys them. Save the recovery key in a password manager to migrate or recover."
                    }
                }
                if let Some(token) = pending_token {
                    div { class: "bk-inline",
                        match token {
                            Ok(token) => rsx! {
                                crate::app::backup_panel::BackupKeyPanel {
                                    token,
                                    alias: alias_input.read().trim().to_string(),
                                    words: words.iter().map(|w| w.to_string()).collect::<Vec<_>>(),
                                    saved: *backup_confirmed.read(),
                                    on_exported: move |_| backup_taken.set(true),
                                    copy_tracker,
                                    on_saved: move |_| {
                                        backup_taken.set(true);
                                        backup_confirmed.set(true);
                                    },
                                }
                            },
                            Err(e) => rsx! {
                                div { class: "info fm-error",
                                    "Couldn't build a recovery key: {e}"
                                }
                            },
                        }
                    }
                }
                if !login_error.read().is_empty() {
                    div { class: "info fm-error",
                        "{login_error.read()}"
                    }
                }
                div { class: "modal-foot", style: "background:transparent; border:0; padding:18px 0 0;",
                    button {
                        class: "btn btn-ghost",
                        onclick: on_discard_click,
                        "Discard"
                    }
                    if !*backup_panel_open.read() {
                        button {
                            class: "btn btn-secondary",
                            "data-testid": testid::FM_CREATE_BACKUP_NOW,
                            title: "Show this identity's recovery key so you can save it",
                            onclick: move |_| backup_panel_open.set(true),
                            "Back up now"
                        }
                    }
                    button {
                        class: "btn btn-primary btn-lg",
                        "data-testid": testid::FM_CREATE_CONFIRM,
                        onclick: confirm,
                        "Continue to inbox"
                    }
                }
            }
        } else {
            // ── Form stage ──────────────────────────────────────────
            div { class: "card",
                h2 { class: "display md italic", "New identity" }
                p { class: "lede",
                    "Generated locally. No server has seen this key."
                }
                div { class: "field", style: "margin-top:24px;",
                    label { class: "field-label", "Alias" }
                    input {
                        class: "input",
                        placeholder: "e.g. mira",
                        value: "{alias_input}",
                        "data-testid": testid::FM_CREATE_ALIAS_INPUT,
                        oninput: move |evt| alias_input.set(evt.value()),
                    }
                    span { class: "field-help", "Used as your local handle. Other people see only your fingerprint." }
                }
                div { class: "field",
                    label { class: "field-label", "Description (optional)" }
                    input {
                        class: "input",
                        placeholder: "e.g. work",
                        value: "{description}",
                        oninput: move |evt| description.set(evt.value()),
                    }
                }
                if !login_error.read().is_empty() {
                    div { class: "info fm-error",
                        "{login_error.read()}"
                    }
                }
                div { class: "modal-foot", style: "background:transparent; border:0; padding:18px 0 0;",
                    button {
                        class: "btn btn-ghost",
                        onclick: cancel,
                        "Cancel"
                    }
                    button {
                        class: "btn btn-primary btn-lg",
                        "data-testid": testid::FM_CREATE_SUBMIT,
                        onclick: submit,
                        "Generate"
                    }
                }
            }
        }
    }
}

/// Bundle of keypairs generated together at identity creation time.
/// ML-DSA-65 + ML-KEM-768 are the two PQ primitives held by every identity.
type IdentityKeyBundle = (Arc<MlDsaSigningKey<MlDsa65>>, DecapsulationKey<MlKem768>);

/// Generate a fresh identity keypair bundle:
/// - ML-DSA-65 signing key (inbox contract ownership + AFT token signing)
/// - ML-KEM-768 decapsulation key (message encryption)
///
/// Importing an existing identity is handled by the separate `ImportForm`
/// (`IdentityBackup` JSON round-trip), not this function.
fn get_keys() -> Result<IdentityKeyBundle, DynError> {
    crate::log::debug!("generating identity keypair bundle");

    // ML-DSA-65: generate from random 32-byte seed.
    let ml_dsa_seed: [u8; 32] = rand::random();
    let ml_dsa_key = Arc::new(MlDsa65::from_seed(&ml_dsa_seed.into()));

    // ML-KEM-768: derive from random 64-byte seed via rand::random (getrandom 0.2 + js)
    // rather than ml-kem's generate_keypair() which needs getrandom 0.4 + wasm_js on WASM.
    let ml_kem_dk = DecapsulationKey::<MlKem768>::from_seed({
        use rand::RngCore;
        let mut seed = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut seed);
        seed.into()
    });

    Ok((ml_dsa_key, ml_kem_dk))
}

#[allow(non_snake_case)]
pub(super) fn GetOrCreateIdentity() -> Element {
    use_context_provider(|| Signal::new(ImportId(false)));
    let import_form_state = use_context::<Signal<ImportId>>();
    rsx! {
        div { class: "fm-pre",
            Topbar {}
            section { class: "page screen",
                div { class: "col",
                    if !import_form_state.read().0 {
                        FirstRunCards {}
                    } else {
                        ImportForm {}
                    }
                }
            }
        }
    }
}

#[allow(non_snake_case)]
fn FirstRunCards() -> Element {
    let mut user = use_context::<Signal<User>>();
    let mut import_form = use_context::<Signal<ImportId>>();
    rsx! {
        div { style: "display:flex; flex-direction:column; align-items:center; gap:18px; text-align:center; margin-bottom:8px;",
            div { class: "glyph", "✉" }
            h1 { class: "display lg italic", style: "max-width:32ch;",
                "A quiet inbox you keep, in the open."
            }
            p { class: "lede", style: "text-align:center;",
                "Generate or restore an identity. Your keys live in this browser; nothing leaves it until you say so."
            }
        }
        div { class: "actions",
            button {
                class: "action-card",
                "data-testid": testid::FM_ACTION_CREATE,
                onclick: move |_| {
                    import_form.write().0 = false;
                    user.write().identified = true;
                },
                span { class: "action-icon", "✚" }
                span { class: "action-title", "Create new identity" }
                span { class: "action-desc",
                    "Generate a fresh keypair locally. Pick an alias and back up the key before you go further."
                }
            }
            button {
                class: "action-card",
                "data-testid": testid::FM_ACTION_IMPORT,
                onclick: move |_| { import_form.write().0 = true; },
                span { class: "action-icon", "↥" }
                span { class: "action-title", "Restore from backup" }
                span { class: "action-desc",
                    "Paste your recovery key, or upload a backup file you exported earlier."
                }
            }
        }
        p { class: "quiet-hint", "no servers · no accounts · no recovery" }
    }
}

/// Whether an edit to the restore box is someone typing (checked leniently)
/// rather than a paste, drop or autofill (checked at once). Uses the input
/// event's `inputType` where the browser provides it, so select-all + paste
/// of a similar-length string still counts as a paste; any edit that adds
/// more than one character counts as bulk regardless.
fn is_typed_edit(evt: &Event<FormData>, prev_chars: usize, new_chars: usize) -> bool {
    #[cfg(target_family = "wasm")]
    let input_type: Option<String> = {
        use dioxus::web::WebEventExt;
        use wasm_bindgen::JsCast;
        evt.data()
            .try_as_web_event()
            .and_then(|e| e.dyn_into::<web_sys::InputEvent>().ok())
            .map(|ie| ie.input_type())
    };
    #[cfg(not(target_family = "wasm"))]
    let input_type: Option<String> = {
        let _ = evt;
        None
    };
    super::backup_token::is_typed_edit(input_type.as_deref(), prev_chars, new_chars)
}

/// Restore an identity from a pasted recovery key or an uploaded backup
/// file (`.txt` recovery key or legacy v2 `.json`). Both inputs go through
/// `backup_token::parse_backup`; any rejection is shown inline.
#[allow(non_snake_case)]
fn ImportForm() -> Element {
    let mut import_id_form = use_context::<Signal<ImportId>>();
    let mut import_backup_form = use_context::<Signal<ImportBackup>>();
    let actions = use_coroutine_handle::<NodeAction>();
    let mut parsed_backup: Signal<Option<IdentityBackup>> = use_signal(|| None);
    let mut paste_text = use_signal(String::new);
    // Name of the uploaded file the current input came from, if any.
    let mut loaded_file: Signal<Option<String>> = use_signal(|| None);
    let mut parse_error = use_signal(String::new);
    // An error held back while a key is being typed by hand (the input
    // could still become valid); shown when the box loses focus.
    let mut held_error: Signal<Option<String>> = use_signal(|| None);
    let mut address = use_signal(String::new);
    let mut description = use_signal(String::new);
    // The alias and description most recently filled in from a JSON backup.
    // When the input switches to a recovery key (which carries no name),
    // each field is cleared only if it still holds that backup's value, so
    // a stale imported name is dropped but anything the user typed stays.
    // Tracked per field: editing only the description must not stop the
    // imported alias from being cleared.
    let mut backup_names: Signal<Option<(String, String)>> = use_signal(|| None);
    let mut restore_error = use_signal(String::new);

    // Parse restore input (from either the paste box or a file) and update
    // the form. `typed` is true for single-character edits in the paste
    // box; pasted and uploaded input is always checked at once.
    let mut apply_input = move |text: String, typed: bool| {
        restore_error.set(String::new());
        held_error.set(None);
        if text.trim().is_empty() {
            parsed_backup.set(None);
            parse_error.set(String::new());
            return;
        }
        match super::backup_token::parse_backup(&text) {
            Ok(b) => {
                if !b.alias.is_empty() {
                    address.set(b.alias.clone());
                    description.set(b.description.clone());
                    backup_names.set(Some((b.alias.clone(), b.description.clone())));
                } else if let Some((old_alias, old_desc)) = backup_names.take() {
                    let (keep_alias, keep_desc) = super::backup_token::names_to_keep(
                        (&address.peek(), &description.peek()),
                        (&old_alias, &old_desc),
                    );
                    if !keep_alias {
                        address.set(String::new());
                    }
                    if !keep_desc {
                        description.set(String::new());
                    }
                }
                parse_error.set(String::new());
                parsed_backup.set(Some(b));
            }
            Err(e) => {
                parsed_backup.set(None);
                if typed && super::backup_token::may_be_incomplete(&text, &e) {
                    parse_error.set(String::new());
                    held_error.set(Some(e.to_string()));
                } else {
                    parse_error.set(e.to_string());
                }
            }
        }
    };

    // Derive the identity once per render: the fingerprint preview and the
    // already-on-this-device check both need it. `parse_backup` guarantees
    // correct seed lengths, so deriving the keys here cannot panic.
    let (preview_words, existing_alias): (Option<[&'static str; 6]>, Option<String>) =
        match parsed_backup.read().as_ref() {
            Some(b) => {
                let ml_dsa = b.keys.ml_dsa_signing_key();
                let ml_kem = b.keys.ml_kem_dk();
                use ml_dsa::signature::Keypair;
                use ml_kem::kem::KeyExport;
                let vk_bytes: Vec<u8> = ml_dsa.as_ref().verifying_key().encode().to_vec();
                let ek_bytes: Vec<u8> = ml_kem.encapsulation_key().to_bytes().to_vec();
                let words = crate::app::address_book::fingerprint_words(&vk_bytes, &ek_bytes);
                // Restoring keys that are already here would create a
                // second identity on the same inbox. Same check the
                // identity's PartialEq uses: the ML-DSA verifying key.
                let existing = Identity::get_aliases()
                    .borrow()
                    .iter()
                    .find(|i| i.ml_dsa_vk_bytes() == vk_bytes)
                    .map(|i| i.alias.to_string());
                (Some(words), existing)
            }
            None => (None, None),
        };
    let needs_alias = parsed_backup
        .read()
        .as_ref()
        .is_some_and(|b| b.alias.is_empty());
    let can_restore = parsed_backup.read().is_some() && existing_alias.is_none();

    let cancel = move |_| {
        // Both flows share this form: hub mode toggles ImportBackup;
        // first-run mode toggles ImportId.
        import_backup_form.write().0 = false;
        import_id_form.write().0 = false;
    };

    rsx! {
        div { class: "card",
            h2 { class: "display md italic", "Restore identity" }
            p { class: "lede",
                "Paste the recovery key from your password manager, or upload a backup file you exported earlier. The keys never leave this browser."
            }
            div { class: "field", style: "margin-top:24px;",
                label { class: "field-label", r#for: "restore-paste-input", "Recovery key" }
                // A secret: keep the browser and OS from learning it,
                // spell-checking it, or "fixing" its capitalisation.
                textarea {
                    class: "textarea",
                    id: "restore-paste-input",
                    rows: "3",
                    placeholder: "fmail-key-1:…",
                    spellcheck: "false",
                    autocomplete: "off",
                    autocapitalize: "off",
                    "autocorrect": "off",
                    "data-gramm": "false",
                    "data-testid": testid::FM_RESTORE_PASTE,
                    value: "{paste_text}",
                    oninput: move |evt| {
                        let v = evt.value();
                        let prev_len = paste_text.peek().chars().count();
                        let typed = is_typed_edit(&evt, prev_len, v.chars().count());
                        paste_text.set(v.clone());
                        loaded_file.set(None);
                        apply_input(v, typed);
                    },
                    onblur: move |_| {
                        if let Some(e) = held_error.write().take() {
                            parse_error.set(e);
                        }
                    },
                }
            }
            div { class: "field",
                label { class: "field-label", r#for: "restore-file-input", "or upload a file" }
                input {
                    class: "input",
                    r#type: "file",
                    accept: ".json,.txt",
                    id: "restore-file-input",
                    "data-testid": testid::FM_RESTORE_FILE,
                    onchange: move |_| {
                        #[cfg(target_family = "wasm")]
                        {
                            use wasm_bindgen::{JsCast, closure::Closure};
                            use web_sys::{FileReader, HtmlInputElement};
                            let Some(input) = web_sys::window()
                                .and_then(|w| w.document())
                                .and_then(|d| d.get_element_by_id("restore-file-input"))
                                .and_then(|el| el.dyn_into::<HtmlInputElement>().ok())
                            else {
                                return;
                            };
                            let Some(file) = input.files().and_then(|files| files.item(0)) else {
                                return;
                            };
                            let Ok(reader) = FileReader::new() else {
                                parse_error.set("Couldn't read that file in this browser.".into());
                                return;
                            };
                            let file_name = file.name();
                            let reader_c = reader.clone();
                            let input_c = input.clone();
                            let cb = Closure::once(Box::new(move || {
                                // Clear the picker so choosing the same
                                // file again (e.g. after fixing it) fires
                                // `onchange` again.
                                input_c.set_value("");
                                paste_text.set(String::new());
                                match reader_c.result().ok().and_then(|v| v.as_string()) {
                                    Some(text) => {
                                        loaded_file.set(Some(file_name));
                                        apply_input(text, false);
                                    }
                                    None => {
                                        loaded_file.set(None);
                                        parsed_backup.set(None);
                                        parse_error.set(format!(
                                            "Couldn't read {file_name}. Pick the .txt or .json file you exported."
                                        ));
                                    }
                                }
                            }) as Box<dyn FnOnce()>);
                            reader.set_onloadend(Some(cb.as_ref().unchecked_ref()));
                            if reader.read_as_text(&file).is_err() {
                                parse_error.set("Couldn't read that file in this browser.".into());
                            }
                            cb.forget();
                        }
                    },
                }
                if let Some(name) = &*loaded_file.read() {
                    span { class: "field-help", "Loaded from {name}." }
                }
            }
            if !parse_error.read().is_empty() {
                div {
                    class: "info fm-error",
                    role: "alert",
                    "data-testid": testid::FM_RESTORE_ERROR,
                    style: "margin:0 0 18px;",
                    "{parse_error.read()}"
                }
            }
            if let Some(existing) = &existing_alias {
                div {
                    class: "info",
                    role: "status",
                    "data-testid": testid::FM_RESTORE_EXISTING,
                    style: "margin:0 0 18px;",
                    "This identity is already on this device, as “{existing}”. There's nothing to restore."
                }
            }
            if let Some(words) = preview_words {
                div { class: "verify-words",
                    div { class: "verify-words-label",
                        span { class: "pulse-dot" }
                        "Recovered fingerprint"
                    }
                    div { class: "verify-words-grid",
                        {
                            words.iter().enumerate().map(|(i, w)| rsx! {
                                div { class: "verify-word",
                                    span { class: "num", "{i + 1:02}" }
                                    span { class: "w", "{w}" }
                                }
                            })
                        }
                    }
                }
            }
            div { class: "field",
                label { class: "field-label", "Alias" }
                input {
                    class: "input",
                    placeholder: "e.g. mira",
                    "data-testid": testid::FM_RESTORE_ALIAS,
                    value: "{address}",
                    oninput: move |evt| address.set(evt.value()),
                }
                if needs_alias && existing_alias.is_none() {
                    span { class: "field-help",
                        "Recovery keys don't include a name. Choose the alias to use on this device."
                    }
                }
            }
            div { class: "field",
                label { class: "field-label", "Description (optional)" }
                input {
                    class: "input",
                    placeholder: "e.g. work",
                    value: "{description}",
                    oninput: move |evt| description.set(evt.value()),
                }
            }
            div { class: "nudge",
                span { class: "nudge-icon", "⚠" }
                div { class: "nudge-text",
                    strong { "Recovery keys and backup files are private keys." }
                    " Keep yours in a password manager, and delete loose copies such as downloads once it's safely stored."
                }
            }
            if !restore_error.read().is_empty() {
                div { class: "info fm-error",
                    "{restore_error.read()}"
                }
            }
            div { class: "modal-foot", style: "background:transparent; border:0; padding:18px 0 0;",
                button {
                    class: "btn btn-ghost",
                    onclick: cancel,
                    "Cancel"
                }
                button {
                    class: "btn btn-primary btn-lg",
                    "data-testid": testid::FM_RESTORE_SUBMIT,
                    disabled: !can_restore,
                    onclick: move |_| {
                        if let Some(backup) = parsed_backup.read().clone() {
                            let alias_str = address.read().trim().to_string();
                            if alias_str.is_empty() {
                                restore_error.set("Choose an alias for this identity.".into());
                                return;
                            }
                            if Identity::get_alias(&alias_str).is_some() {
                                restore_error.set(format!(
                                    "An identity named \"{alias_str}\" already exists. Rename the import or delete the existing one first — restoring would replace it and its inbox would become unreadable."
                                ));
                                return;
                            }
                            restore_error.set(String::new());
                            let alias: Rc<str> = alias_str.into();
                            let desc_val = description.read().clone();
                            let ml_dsa = backup.keys.ml_dsa_signing_key();
                            let ml_kem = backup.keys.ml_kem_dk();
                            let ek_bytes = {
                                use ml_kem::kem::KeyExport;
                                ml_kem.encapsulation_key().to_bytes().to_vec()
                            };
                            actions.send(NodeAction::CreateContract {
                                alias: alias.clone(),
                                ml_dsa_key: ml_dsa.clone(),
                                ml_kem_ek_bytes: ek_bytes.clone(),
                                contract_type: ContractType::InboxContract,
                                required_tier: freenet_aft_interface::Tier::Min10,
                                max_age_secs: freenet_email_inbox::DEFAULT_MAX_AGE_SECS,
                            });
                            actions.send(NodeAction::CreateDelegate {
                                alias: alias.clone(),
                                ml_dsa_key: ml_dsa.clone(),
                            });
                            actions.send(NodeAction::CreateContract {
                                alias: alias.clone(),
                                ml_dsa_key: ml_dsa.clone(),
                                ml_kem_ek_bytes: ek_bytes,
                                contract_type: ContractType::AFTContract,
                                required_tier: freenet_aft_interface::Tier::Min10,
                                max_age_secs: freenet_email_inbox::DEFAULT_MAX_AGE_SECS,
                            });
                            actions.send(NodeAction::CreateIdentity {
                                alias,
                                ml_dsa_key: ml_dsa,
                                ml_kem_dk: Box::new(ml_kem),
                                description: desc_val,
                                // Restored from a recovery key or backup
                                // file, so the user demonstrably holds one.
                                backed_up: true,
                            });
                            import_backup_form.write().0 = false;
                            import_id_form.write().0 = false;
                        }
                    },
                    "Restore"
                }
            }
        }
    }
}

/// Modal that displays the shareable ContactCard text and offers a copy button.
#[allow(non_snake_case)]
pub(super) fn ShareContactModal() -> Element {
    let mut share_contact_form = use_context::<Signal<ShareContact>>();
    let share_pending = use_context::<Signal<SharePending>>();
    let (alias, share_text) = share_pending
        .read()
        .data
        .as_ref()
        .map(|d| (d.alias.clone(), d.share_text.clone()))
        .unwrap_or_default();
    let mut copied: Signal<Option<CopyOutcome>> = use_signal(|| None);

    // Pull the verify line ("verify: w-w-w-w-w-w") out of the share
    // text — line order is bs58-address then `verify:` (see `on_share`
    // serializer) but we scan all lines symmetrically with the Import
    // parser at `ImportContactForm` so swapping the order in the future
    // doesn't break either side. The remainder (non-`verify:` lines) is
    // the bs58 address token shown in the modal.
    let (verify_words, contact_token): (Vec<String>, String) = {
        let mut words = Vec::new();
        let mut token_lines: Vec<&str> = Vec::new();
        for line in share_text.lines() {
            if let Some(rest) = line.trim().strip_prefix("verify:") {
                words = rest.trim().split('-').map(|s| s.to_string()).collect();
            } else if !line.trim().is_empty() {
                token_lines.push(line);
            }
        }
        (words, token_lines.join("\n"))
    };
    let close = move |_| {
        share_contact_form.write().0 = false;
        copied.set(None);
    };

    rsx! {
        div { class: "veil",
            onclick: move |_| {
                share_contact_form.write().0 = false;
                copied.set(None);
            },
            div { class: "modal",
                "data-testid": testid::FM_SHARE_MODAL,
                "data-share-text": "{share_text}",
                onclick: move |ev| { ev.stop_propagation(); },
                div { class: "modal-head",
                    span { class: "modal-title", "Share {alias}" }
                    button { class: "modal-x", onclick: close, "✕" }
                }
                div { class: "modal-body",
                    p { class: "field-help", style: "margin: -4px 0 14px;",
                        "Read these six words to your contact through a separate channel — phone, in person, Signal. They should match what they see when they import."
                    }
                    if verify_words.len() == 6 {
                        div { class: "verify-words",
                            div { class: "verify-words-label",
                                span { class: "pulse-dot" }
                                "Six-word fingerprint"
                            }
                            div { class: "verify-words-grid",
                                {
                                    verify_words.iter().enumerate().map(|(i, w)| rsx! {
                                        div { class: "verify-word",
                                            span { class: "num", "{i + 1:02}" }
                                            span { class: "w", "{w}" }
                                        }
                                    })
                                }
                            }
                        }
                    }
                    label { class: "field-label", "Token" }
                    div { class: "token-block", "{contact_token}" }
                    match &*copied.read() {
                        Some(CopyOutcome::SentToShell) => rsx! {
                            p { class: "field-help", style: "margin-top:10px;",
                                "Sent to your clipboard through Freenet, which can't confirm it worked. Paste it to check."
                            }
                        },
                        Some(CopyOutcome::Failed(why)) => rsx! {
                            p { class: "field-help fm-error-text", style: "margin-top:10px;",
                                "Couldn't copy: {why}. Select the token above and copy it by hand."
                            }
                        },
                        _ => rsx! {},
                    }
                }
                div { class: "modal-foot",
                    button {
                        class: "btn btn-secondary",
                        "data-testid": testid::FM_SHARE_COPY,
                        onclick: {
                            let share_text = share_text.clone();
                            move |_| {
                                copied.set(None);
                                copy_text(share_text.clone(), move |outcome| {
                                    // May complete after the modal closed
                                    // (async Clipboard API path); writing a
                                    // dropped signal would panic.
                                    if let Ok(mut c) = copied.try_write() {
                                        *c = Some(outcome);
                                    }
                                });
                            }
                        },
                        if *copied.read() == Some(CopyOutcome::Copied) { "Copied" } else { "Copy" }
                    }
                    button {
                        class: "btn btn-primary",
                        onclick: close,
                        "Close"
                    }
                }
            }
        }
    }
}

/// Form to import a contact from a pasted bs58 inbox address.
///
/// The user pastes the address; we dispatch a `NodeAction::FetchContactKeys`
/// which issues a `Get` on the recipient's inbox contract. The api.rs
/// handler decodes the inbox state + params and drops the result into
/// `contact_import::RESULTS`; the modal polls that thread-local in a
/// `use_future` loop and renders the six-word fingerprint once the keys
/// land. The user confirms the fingerprint out-of-band and ticks
/// "verified" before persisting via `NodeAction::CreateContact`.
/// `(ml_dsa_vk_bytes, ml_kem_ek_bytes, required_tier, max_age_secs)`
/// — the four fields recovered from the inbox contract on a successful
/// `FetchContactKeys` round-trip, ready to flow into
/// `StoredContactKeys` on confirm.
///
/// Fields: `(ml_dsa_vk, ml_kem_ek, required_tier, max_age_secs,
/// inbox_wasm_hash)`. The last entry is `None` for offline-mode
/// fixtures (no node round-trip to capture the recipient's actual
/// inbox WASM hash) and the send path falls back to the sender's
/// embedded `INBOX_CODE_HASH` — same behaviour as pre-#251.
type FetchedKeys = (
    Vec<u8>,
    Vec<u8>,
    freenet_aft_interface::Tier,
    u64,
    Option<String>,
);

#[allow(non_snake_case)]
pub(super) fn ImportContactForm() -> Element {
    use crate::api::contact_import::{ImportFetchOutcome, ImportFetched};

    let mut import_contact_form = use_context::<Signal<ImportContact>>();
    let actions = use_coroutine_handle::<NodeAction>();

    let mut paste_text = use_signal(String::new);
    let mut local_alias = use_signal(String::new);
    // The alias the sender advertised on their card, captured at decode
    // time and preserved even if the user relabels `local_alias` before
    // import — so the To field can still resolve by the sender's name
    // (address_book::lookup suggested_alias fallback).
    let mut card_suggested_alias: Signal<Option<String>> = use_signal(|| None);
    let mut description = use_signal(String::new);
    let mut verified = use_signal(|| false);
    let mut error_msg = use_signal(String::new);
    let mut fingerprint_words: Signal<Option<[&'static str; 6]>> = use_signal(|| None);
    let mut fetched_keys: Signal<Option<FetchedKeys>> = use_signal(|| None);
    let mut fetching = use_signal(|| false);
    let mut pending_address: Signal<Option<String>> = use_signal(|| None);
    let mut verify_phrase: Signal<Option<String>> = use_signal(|| None);
    // Count of 150ms poll ticks since the current fetch began. Drives the
    // escalating "taking longer than expected" copy and a client-side
    // timeout, so a node that never replies at all (not even an error —
    // distinct from the core stream-assembly failure that does surface a
    // `ContractError::Get`) still releases the modal instead of spinning
    // forever. 0 while idle.
    let mut fetch_ticks = use_signal(|| 0u32);

    // Poll the api.rs result table for the address we asked about. Runs
    // while the modal is mounted; the fetch completes in well under a
    // second on a healthy local node, so 150ms is fast enough without
    // being a busy loop.
    use_future(move || async move {
        loop {
            #[cfg(feature = "use-node")]
            {
                let addr = pending_address.read().clone();
                if let Some(addr) = addr {
                    let result: Option<ImportFetched> =
                        crate::api::contact_import::RESULTS.with(|m| m.borrow_mut().remove(&addr));
                    if let Some(ImportFetched { outcome, .. }) = result {
                        match outcome {
                            ImportFetchOutcome::Ok {
                                ml_dsa_vk_bytes,
                                ml_kem_ek_bytes,
                                required_tier,
                                max_age_secs,
                                inbox_wasm_hash,
                            } => {
                                let fp = crate::app::address_book::fingerprint_words(
                                    &ml_dsa_vk_bytes,
                                    &ml_kem_ek_bytes,
                                );
                                fingerprint_words.set(Some(fp));
                                fetched_keys.set(Some((
                                    ml_dsa_vk_bytes,
                                    ml_kem_ek_bytes,
                                    required_tier,
                                    max_age_secs,
                                    Some(inbox_wasm_hash),
                                )));
                                error_msg.set(String::new());
                            }
                            ImportFetchOutcome::Failed(e) => {
                                error_msg.set(format!("Could not fetch inbox: {e}"));
                                fingerprint_words.set(None);
                                fetched_keys.set(None);
                            }
                        }
                        fetching.set(false);
                        pending_address.set(None);
                        fetch_ticks.set(0);
                    } else {
                        // No result yet — advance the elapsed clock. At
                        // ~30s (200 × 150ms) give up client-side; the node
                        // is unreachable or silently dropping the GET.
                        let t = fetch_ticks.read().saturating_add(1);
                        fetch_ticks.set(t);
                        if t >= 200 {
                            crate::api::contact_import::RESULTS
                                .with(|m| m.borrow_mut().remove(&addr));
                            error_msg.set(
                                "Could not fetch inbox: timed out after 30s. \
                                 The recipient's node may be offline, or their \
                                 inbox hasn't propagated to the network yet. \
                                 Ask them to open their inbox, then retry."
                                    .into(),
                            );
                            fingerprint_words.set(None);
                            fetched_keys.set(None);
                            fetching.set(false);
                            pending_address.set(None);
                            fetch_ticks.set(0);
                        }
                    }
                }
            }
            gloo_timers::future::TimeoutFuture::new(150).await;
        }
    });

    // Parse a pasted (or prefilled) inbox-address blob and kick off the
    // key fetch. Factored out of the textarea handler so the #272
    // "Add to address book" prefill path can reuse the exact same parse +
    // fetch logic without synthesising a DOM event.
    let mut apply_address = move |text: String| {
        paste_text.set(text.clone());
        error_msg.set(String::new());
        fingerprint_words.set(None);
        fetched_keys.set(None);

        // Pull the verify phrase if the sender included one
        // (`<addr>\nverify: <words>` from `ShareContactModal`).
        let mut phrase = None;
        let mut addr_line: Option<&str> = None;
        for line in text.lines() {
            let stripped = line.trim();
            if let Some(rest) = stripped.strip_prefix("verify:") {
                phrase = Some(rest.trim().to_string());
            } else if addr_line.is_none() && !stripped.is_empty() {
                addr_line = Some(stripped);
            }
        }
        verify_phrase.set(phrase);
        let Some(addr_input) = addr_line else {
            pending_address.set(None);
            return;
        };

        match crate::app::address_book::ContactCard::decode(addr_input) {
            Ok(card) => {
                // Preserve the sender's advertised alias regardless of
                // whether the user keeps or overrides it as local_alias.
                card_suggested_alias.set(card.suggested_alias.clone());
                if local_alias.read().is_empty()
                    && let Some(ref s) = card.suggested_alias
                {
                    local_alias.set(s.clone());
                }
                if description.read().is_empty()
                    && let Some(ref s) = card.suggested_description
                {
                    description.set(s.clone());
                }

                // Offline mode (`no-sync`) has no api.rs handler to issue
                // a real Get against the recipient inbox. To keep the
                // import + send UX exercisable without a node (Playwright
                // fixtures + manual offline testing), synthesize placeholder
                // pubkeys deterministically from the bs58 address. Fingerprint
                // is stable across runs for the same address; the bytes never
                // hit the wire in this build since there's no node. Seeded
                // example-data identities still resolve through
                // `lookup_by_bs58` first so their real fingerprint shows.
                #[cfg(not(feature = "use-node"))]
                {
                    use freenet_aft_interface::Tier;
                    use freenet_stdlib::prelude::blake3;
                    let (vk_bytes, ek_bytes) = if let Some(r) =
                        crate::app::address_book::lookup_by_bs58(&card.inbox_address)
                    {
                        (r.ml_dsa_vk_bytes, r.ml_kem_ek_bytes)
                    } else {
                        let seed_in = card.inbox_address.as_bytes();
                        let mut vk = vec![0u8; 1952];
                        let mut ek = vec![0u8; 1184];
                        for (i, chunk) in vk.chunks_mut(32).enumerate() {
                            let mut h = blake3::Hasher::new();
                            h.update(b"offline-vk");
                            h.update(seed_in);
                            h.update(&(i as u32).to_le_bytes());
                            chunk.copy_from_slice(&h.finalize().as_bytes()[..chunk.len()]);
                        }
                        for (i, chunk) in ek.chunks_mut(32).enumerate() {
                            let mut h = blake3::Hasher::new();
                            h.update(b"offline-ek");
                            h.update(seed_in);
                            h.update(&(i as u32).to_le_bytes());
                            chunk.copy_from_slice(&h.finalize().as_bytes()[..chunk.len()]);
                        }
                        (vk, ek)
                    };
                    let fp = crate::app::address_book::fingerprint_words(&vk_bytes, &ek_bytes);
                    fingerprint_words.set(Some(fp));
                    fetched_keys.set(Some((
                        vk_bytes,
                        ek_bytes,
                        Tier::Min10,
                        freenet_email_inbox::DEFAULT_MAX_AGE_SECS,
                        None,
                    )));
                }

                #[cfg(feature = "use-node")]
                {
                    fetching.set(true);
                    pending_address.set(Some(card.inbox_address.clone()));
                    actions.send(NodeAction::FetchContactKeys {
                        inbox_address: card.inbox_address,
                    });
                }
            }
            Err(e) => {
                if !text.trim().is_empty() {
                    error_msg.set(format!("Could not parse inbox address: {e}"));
                }
            }
        }
    };

    // #272: when the modal is opened from "Add to address book" on a
    // received message, the sender's inbox address is handed over via
    // `ImportContact.prefill`. Seed the paste field and trigger the key
    // fetch exactly once, then clear the prefill so a later manual edit
    // (or a re-render) doesn't clobber the user's typing.
    use_effect(move || {
        let (prefill, prefill_alias) = {
            let form = import_contact_form.read();
            (form.prefill.clone(), form.prefill_alias.clone())
        };
        if let Some(addr) = prefill {
            apply_address(addr);
            // #289: a bare bs58 address carries no card metadata, so
            // `apply_address` leaves `local_alias` / `card_suggested_alias`
            // empty. Default the nickname to the sender's display name handed
            // over by the add-from-message path — this is the PRIMARY fix: a
            // reply addressed to that display name then matches the contact's
            // `local_alias` exactly. Also seed `card_suggested_alias` so that
            // if the user relabels the contact, the original name survives as
            // the #295 resolver fallback (see `persisted_suggested_alias`: when
            // the user accepts this default, the two are equal and the field is
            // dropped at save — by design, not a bug). Guards never clobber a
            // real card's own metadata, which `apply_address` set first.
            if let Some(alias) = prefill_alias.filter(|a| !a.is_empty()) {
                if local_alias.read().is_empty() {
                    local_alias.set(alias.clone());
                }
                if card_suggested_alias.read().is_none() {
                    card_suggested_alias.set(Some(alias));
                }
            }
            let mut form = import_contact_form.write();
            form.prefill = None;
            form.prefill_alias = None;
        }
    });

    // Soft warning when the sender included a verify phrase but the user
    // hasn't ticked the box. Verified-only inboxes (settings.rs:1434)
    // will reject sends until the user ticks it once they've matched the
    // six words out-of-band.
    let has_verify_phrase = verify_phrase.read().is_some();
    let can_import = fetched_keys.read().is_some() && !local_alias.read().is_empty();

    let cancel = move |_| {
        // Drop any pending Get + cached result so re-opening the modal
        // for a different (or same) address starts clean. Without this
        // the thread-local PENDING / RESULTS maps grow unbounded across
        // a session.
        #[cfg(feature = "use-node")]
        if let Some(addr) = pending_address.read().clone() {
            crate::api::contact_import::cancel(&addr);
        }
        *import_contact_form.write() = ImportContact::default();
        error_msg.set(String::new());
    };
    let verify_check_class = if *verified.read() {
        "verify-check checked"
    } else {
        "verify-check"
    };

    rsx! {
        div { class: "veil",
            onclick: move |_| {
                #[cfg(feature = "use-node")]
                if let Some(addr) = pending_address.read().clone() {
                    crate::api::contact_import::cancel(&addr);
                }
                *import_contact_form.write() = ImportContact::default();
                error_msg.set(String::new());
            },
            div { class: "modal",
                "data-testid": testid::FM_IMPORT_CONTACT_MODAL,
                onclick: move |ev| { ev.stop_propagation(); },
                div { class: "modal-head",
                    span { class: "modal-title", "Import contact" }
                    button { class: "modal-x", onclick: cancel, "✕" }
                }
                div { class: "modal-body",
                    p { class: "field-help", style: "margin: -4px 0 14px;",
                        "Paste your contact's inbox address. We fetch their pubkeys from the inbox contract and show the fingerprint — confirm it through a separate channel before you tick the verify box."
                    }
                    div { class: "field",
                        label { class: "field-label", "Inbox address" }
                        textarea {
                            class: "textarea",
                            placeholder: "e.g. EqJ5YpEEV3XLqEvKWLQHFhGAac2qXzSUoE6k2zbdnXBr",
                            rows: "3",
                            value: "{paste_text}",
                            oninput: move |evt: dioxus::prelude::Event<dioxus::html::FormData>| {
                                apply_address(evt.value());
                            },
                        }
                    }
                    if *fetching.read() {
                        {
                            // ~150ms per tick. Escalate the copy so the user
                            // sees the fetch is alive and how far along it is,
                            // rather than a static line that looks hung.
                            let ticks = *fetch_ticks.read();
                            let secs = (ticks as f32 * 0.15) as u32;
                            let msg = if ticks < 33 {
                                "Fetching keys from the recipient's inbox…".to_string()
                            } else if ticks < 100 {
                                format!("Still fetching from the network… ({secs}s)")
                            } else {
                                format!(
                                    "Taking longer than usual ({secs}s). The recipient's \
                                     node may be slow to respond — will time out at 30s."
                                )
                            };
                            rsx! {
                                div { class: "field-help",
                                    style: "display:flex; align-items:center; gap:8px;",
                                    span { class: "pulse-dot" }
                                    span { "{msg}" }
                                }
                            }
                        }
                    }
                    if let Some(ref words) = *fingerprint_words.read() {
                        div { class: "verify-words",
                            "data-testid": testid::FM_IMPORT_FP,
                            div { class: "verify-words-label",
                                span { class: "pulse-dot" }
                                "Fingerprint (verify with sender)"
                            }
                            div { class: "verify-words-grid",
                                {
                                    words.iter().enumerate().map(|(i, w)| rsx! {
                                        div { class: "verify-word",
                                            span { class: "num", "{i + 1:02}" }
                                            span { class: "w", "{w}" }
                                        }
                                    })
                                }
                            }
                        }
                    }
                    div { class: "field",
                        label { class: "field-label", "Your local label (must be unique)" }
                        input {
                            class: "input",
                            placeholder: "e.g. Alice (work)",
                            value: "{local_alias}",
                            oninput: move |evt| local_alias.set(evt.value()),
                        }
                    }
                    div { class: "field",
                        label { class: "field-label", "Description (optional)" }
                        input {
                            class: "input",
                            placeholder: "",
                            value: "{description}",
                            oninput: move |evt| description.set(evt.value()),
                        }
                    }
                    if fingerprint_words.read().is_some() {
                        label {
                            class: "{verify_check_class}",
                            "data-testid": testid::FM_VERIFY_CHECK,
                            onclick: move |_| {
                                let v = *verified.read();
                                verified.set(!v);
                            },
                            div { class: "verify-box",
                                span { class: "tick", "✓" }
                            }
                            div { class: "verify-text",
                                span { class: "verify-headline",
                                    "I verified these six words with the sender"
                                }
                                span { class: "verify-sub",
                                    "Phone, in person, Signal — anything but this app. Untick if you have not."
                                }
                                if has_verify_phrase && !*verified.read() {
                                    span { class: "verify-sub",
                                        style: "color: var(--danger-ink, #991b1b);",
                                        "The sender included a verify phrase. Importing unverified is allowed, but verified-only inboxes will reject your messages until you tick this once you've matched the six words out-of-band."
                                    }
                                }
                            }
                        }
                    }
                    if !error_msg.read().is_empty() {
                        div { class: "info fm-error",
                            "{error_msg}"
                        }
                    }
                }
                div { class: "modal-foot",
                    button { class: "btn btn-ghost", onclick: cancel, "Cancel" }
                    button {
                        class: "btn btn-primary",
                        "data-testid": testid::FM_IMPORT_SUBMIT,
                        disabled: !can_import,
                        onclick: move |_| {
                            let alias_str = local_alias.read().clone();
                            if alias_str.is_empty() { return; }
                            let Some((vk, ek, tier, max_age, inbox_wasm_hash)) =
                                fetched_keys.read().clone()
                            else {
                                error_msg.set("Still fetching keys — wait a moment.".into());
                                return;
                            };
                            if crate::app::address_book::is_own_fingerprint(&vk, &ek) {
                                error_msg.set("That address belongs to one of your own identities.".into());
                                return;
                            }
                            // Persist the SENDER's advertised alias (from the
                            // card / add-from-message seed), not the
                            // possibly-relabelled local_alias — that's what
                            // makes the suggested_alias resolver fallback (#295)
                            // useful when the user relabels. See
                            // `persisted_suggested_alias` for the dedup rule.
                            let suggested = persisted_suggested_alias(
                                card_suggested_alias.read().as_deref(),
                                &alias_str,
                            );
                            let stored = crate::app::address_book::StoredContactKeys {
                                ml_dsa_vk_bytes: vk,
                                ml_kem_ek_bytes: ek,
                                suggested_alias: suggested,
                                verified: *verified.read(),
                                required_tier: tier,
                                max_age_secs: max_age,
                                inbox_wasm_hash,
                            };
                            let contact = stored.into_contact(
                                alias_str.into(),
                                description.read().clone(),
                            );
                            actions.send(NodeAction::CreateContact { contact });
                            #[cfg(feature = "use-node")]
                            if let Some(addr) = pending_address.read().clone() {
                                crate::api::contact_import::cancel(&addr);
                            }
                            *import_contact_form.write() = ImportContact::default();
                            paste_text.set(String::new());
                            local_alias.set(String::new());
                            card_suggested_alias.set(None);
                            description.set(String::new());
                            verified.set(false);
                            fingerprint_words.set(None);
                            fetched_keys.set(None);
                            verify_phrase.set(None);
                            pending_address.set(None);
                            error_msg.set(String::new());
                        },
                        "Import"
                    }
                }
            }
        }
    }
}

/// Confirm-verification modal. Re-renders the existing six-word
/// fingerprint and asks the user to tick the same checkbox the import
/// flow uses. On submit, re-creates the contact with `verified = true`,
/// reusing the delegate's overwrite-on-same-keys semantics so no new
/// op type is needed (issue #87).
#[allow(non_snake_case)]
fn VerifyContactModal() -> Element {
    let mut verify_pending = use_context::<Signal<VerifyContactPending>>();
    let actions = use_coroutine_handle::<NodeAction>();
    let mut confirmed = use_signal(|| false);

    let pending = verify_pending.read().0.clone();
    let Some(contact) = pending else {
        return rsx! {};
    };
    let alias_str = contact.local_alias.to_string();
    let words = contact.fingerprint();

    let close = move |_| {
        verify_pending.write().0 = None;
        confirmed.set(false);
    };
    let check_class = if *confirmed.read() {
        "verify-check checked"
    } else {
        "verify-check"
    };

    rsx! {
        div { class: "veil",
            onclick: close,
            div { class: "modal",
                "data-testid": testid::FM_VERIFY_CONTACT_MODAL,
                onclick: move |ev| { ev.stop_propagation(); },
                div { class: "modal-head",
                    span { class: "modal-title", "Mark contact verified" }
                    button { class: "modal-x", onclick: close, "✕" }
                }
                div { class: "modal-body",
                    p { class: "field-help", style: "margin: -4px 0 14px;",
                        "Confirm these six words with {alias_str} through a separate channel — phone, in person, Signal, anything but this app."
                    }
                    div { class: "verify-words",
                        div { class: "verify-words-label",
                            span { class: "pulse-dot" }
                            "Fingerprint"
                        }
                        div { class: "verify-words-grid",
                            {
                                words.iter().enumerate().map(|(i, w)| rsx! {
                                    div { class: "verify-word",
                                        span { class: "num", "{i + 1:02}" }
                                        span { class: "w", "{w}" }
                                    }
                                })
                            }
                        }
                    }
                    label {
                        class: "{check_class}",
                        "data-testid": testid::FM_VERIFY_CHECK,
                        onclick: move |_| {
                            let v = *confirmed.read();
                            confirmed.set(!v);
                        },
                        div { class: "verify-box",
                            span { class: "tick", "✓" }
                        }
                        div { class: "verify-text",
                            span { class: "verify-headline",
                                "I verified these six words with {alias_str}"
                            }
                        }
                    }
                }
                div { class: "modal-foot",
                    button { class: "btn btn-ghost", onclick: close, "Cancel" }
                    {
                        let submit_contact = contact.clone();
                        rsx! {
                            button {
                                class: "btn btn-primary",
                                "data-testid": testid::FM_VERIFY_CONTACT_SUBMIT,
                                disabled: !*confirmed.read(),
                                onclick: move |_| {
                                    let mut updated = submit_contact.clone();
                                    updated.verified = true;
                                    actions.send(NodeAction::CreateContact { contact: updated });
                                    verify_pending.write().0 = None;
                                    confirmed.set(false);
                                },
                                "Mark verified"
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Address book section showing all imported contacts.
#[allow(non_snake_case)]
fn ContactsSection() -> Element {
    let mut import_contact_form = use_context::<Signal<ImportContact>>();
    let mut verify_pending = use_context::<Signal<VerifyContactPending>>();
    let actions = use_coroutine_handle::<NodeAction>();
    let contacts = crate::app::address_book::all_contacts();
    let mut login_controller = use_context::<Signal<LoginController>>();

    if login_controller.read().updated {
        login_controller.write().updated = false;
    }

    rsx! {
        div { class: "section-head",
            span { class: "section-title", "Contacts" }
            button {
                class: "btn btn-secondary",
                "data-testid": testid::FM_CONTACT_IMPORT,
                onclick: move |_| { *import_contact_form.write() = ImportContact::opened(); },
                "+ Import contact"
            }
        }
        if contacts.is_empty() {
            div { class: "empty-state",
                div { class: "glyph sm", "✉" }
                p { class: "field-help", style: "text-align:center; max-width:36ch;",
                    "No contacts yet. Import one — they share a six-word fingerprint and you decide whether you trust it."
                }
            }
        } else {
            div { class: "contact-list",
                for contact in contacts {
                    {
                        let alias_str = contact.local_alias.to_string();
                        let fp_short = contact.fingerprint_short();
                        let fp_full = contact.fingerprint_full();
                        let del_alias = alias_str.clone();
                        let verified = contact.verified;
                        let description = contact.description.clone();
                        rsx! {
                            div { class: "contact-row",
                                "data-testid": "contact-row",
                                "data-alias": "{alias_str}",
                                div { class: "contact-name",
                                    span { class: "contact-label", "{alias_str}" }
                                    if !description.is_empty() {
                                        span { class: "id-desc", "{description}" }
                                    }
                                    span { class: "contact-fp",
                                        "data-testid": "contact-fingerprint",
                                        title: "{fp_full}",
                                        "{fp_short}"
                                    }
                                }
                                if verified {
                                    span { class: "badge badge-trust",
                                        "data-testid": "contact-verify-badge",
                                        "✓ verified"
                                    }
                                } else {
                                    {
                                        // Badge is itself the verify CTA so the
                                        // "⚠ unverified" affordance isn't passive
                                        // (#228 option B).
                                        let pending_badge = contact.clone();
                                        rsx! {
                                            button {
                                                class: "badge badge-warn btn-link",
                                                style: "cursor:pointer; border:0; background:transparent; padding:0; font:inherit;",
                                                title: "Verify this contact's fingerprint",
                                                "data-testid": "contact-verify-badge",
                                                onclick: move |_| {
                                                    verify_pending.write().0 = Some(pending_badge.clone());
                                                },
                                                "⚠ unverified"
                                            }
                                        }
                                    }
                                }
                                if !verified {
                                    {
                                        let pending_contact = contact.clone();
                                        rsx! {
                                            button {
                                                class: "btn btn-ghost btn-xs",
                                                title: "Confirm fingerprint with sender and mark verified",
                                                "data-testid": testid::FM_CONTACT_VERIFY,
                                                onclick: move |_| {
                                                    verify_pending.write().0 = Some(pending_contact.clone());
                                                },
                                                "Verify"
                                            }
                                        }
                                    }
                                }
                                button {
                                    class: "icon-btn danger",
                                    title: "Remove contact",
                                    "data-testid": "contact-remove",
                                    onclick: move |_| {
                                        actions.send(NodeAction::DeleteContact {
                                            alias: del_alias.clone(),
                                        });
                                    },
                                    "✕"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DOWNLOAD_GAP_MS, ImportContact, backup_filename, backup_stamp_after_create,
        download_wait_ms, persisted_suggested_alias, sanitize_filename_stem,
    };

    /// Review #349 round 2: the gateway shell drops a download within 2s of
    /// the previous one, app-wide, so the gap is one rule for every caller.
    #[test]
    fn download_gap_applies_since_the_last_download() {
        assert_eq!(download_wait_ms(None, 1_000.0), None);
        assert_eq!(
            download_wait_ms(Some(1_000.0), 1_100.0),
            Some(DOWNLOAD_GAP_MS - 100.0)
        );
        assert_eq!(
            download_wait_ms(Some(1_000.0), 1_000.0 + DOWNLOAD_GAP_MS),
            None
        );
    }

    /// Review #349 item 3: a new identity is stamped as backed up only when
    /// a backup of its keys is known to exist, and otherwise has NO stamp
    /// (clearing any left by an earlier identity under the same alias).
    #[test]
    fn backup_stamp_after_create_only_when_backed_up() {
        assert_eq!(backup_stamp_after_create(true, 1_234), Some(1_234));
        assert_eq!(backup_stamp_after_create(false, 1_234), None);
    }

    /// #289 (add-from-message half): the modal constructor must carry the
    /// sender's display name into `prefill_alias` so the prefill effect can
    /// default the nickname to it. This pins the constructor seam only — the
    /// save-time persistence rule is covered by the
    /// `persisted_suggested_alias_*` tests below.
    #[test]
    fn opened_with_carries_sender_alias_for_289() {
        let modal = ImportContact::opened_with(
            "addr-bs58".to_string(),
            Some("alice-from-work".to_string()),
        );
        assert!(modal.open);
        assert_eq!(modal.prefill.as_deref(), Some("addr-bs58"));
        assert_eq!(
            modal.prefill_alias.as_deref(),
            Some("alice-from-work"),
            "sender's advertised display name must reach the modal (#289)",
        );
    }

    /// A bare manual-paste open carries no alias suggestion.
    #[test]
    fn opened_has_no_prefill_alias() {
        let modal = ImportContact::opened();
        assert!(modal.prefill_alias.is_none());
        assert!(modal.prefill.is_none());
    }

    /// #289 / #295 save-path rule: the relabel case is the ONLY case that
    /// persists a `suggested_alias`. Accepting the seeded default (local ==
    /// advertised) drops it — the reply already resolves by exact local_alias.
    #[test]
    fn persisted_suggested_alias_kept_only_on_relabel_289() {
        // User relabels: advertised "alice-from-work" saved as local "ally"
        // → the fallback handle is persisted so a reply to "alice-from-work"
        // still resolves via #295.
        assert_eq!(
            persisted_suggested_alias(Some("alice-from-work"), "ally"),
            Some("alice-from-work".to_string()),
            "relabel must persist the advertised alias as the resolver fallback",
        );
        // User accepts the seeded default (local == advertised): redundant, so
        // dropped. The reply still resolves by exact local_alias match.
        assert_eq!(
            persisted_suggested_alias(Some("alice-from-work"), "alice-from-work"),
            None,
            "default-accepted nickname must NOT duplicate into suggested_alias",
        );
        // No advertised alias (manual paste of a bare address) → nothing.
        assert_eq!(persisted_suggested_alias(None, "ally"), None);
        // Empty advertised alias is treated as absent.
        assert_eq!(persisted_suggested_alias(Some(""), "ally"), None);
    }

    #[test]
    fn sanitize_plain_ascii() {
        assert_eq!(sanitize_filename_stem("alice"), Some("alice".to_string()));
        assert_eq!(
            sanitize_filename_stem("my-work_key"),
            Some("my-work_key".to_string())
        );
        assert_eq!(
            sanitize_filename_stem("Hello123"),
            Some("Hello123".to_string())
        );
    }

    #[test]
    fn sanitize_replaces_disallowed_chars() {
        // Path separators and unicode must be replaced with '_'.
        assert_eq!(
            sanitize_filename_stem("alice/bob"),
            Some("alice_bob".to_string())
        );
        assert_eq!(sanitize_filename_stem("../../etc"), Some("etc".to_string()));
        // Unicode collapsed to underscores, then trimmed.
        assert_eq!(sanitize_filename_stem("mira💌"), Some("mira".to_string()));
        // Spaces become underscores.
        assert_eq!(
            sanitize_filename_stem("my alias"),
            Some("my_alias".to_string())
        );
        // Multiple consecutive bad chars become a single underscore.
        assert_eq!(sanitize_filename_stem("a///b"), Some("a_b".to_string()));
    }

    #[test]
    fn sanitize_empty_returns_none() {
        assert_eq!(sanitize_filename_stem(""), None);
        // Only disallowed chars → all become underscores → trimmed → empty.
        assert_eq!(sanitize_filename_stem("///"), None);
        assert_eq!(sanitize_filename_stem("💌💌"), None);
    }

    #[test]
    fn backup_filename_uses_sanitized_alias() {
        let words = &["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"];
        assert_eq!(
            backup_filename("alice", words),
            "freenet-identity-alice.txt"
        );
        assert_eq!(
            backup_filename("my alias", words),
            "freenet-identity-my_alias.txt"
        );
    }

    #[test]
    fn backup_filename_falls_back_to_fingerprint_on_empty_stem() {
        let words = &["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"];
        // All-unicode alias → empty stem after sanitization → fingerprint fallback.
        assert_eq!(
            backup_filename("💌💌", words),
            "freenet-identity-alpha-bravo.txt"
        );
        assert_eq!(
            backup_filename("///", words),
            "freenet-identity-alpha-bravo.txt"
        );
    }
}
