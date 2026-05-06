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
    rsx! {
        header { class: "topbar",
            div { class: "brand",
                span { class: "brand-glyph", "f" }
                div { class: "brand-text",
                    span { class: "brand-name", "{app_name}" }
                    span { class: "brand-tag", "Private · Decentralized" }
                }
            }
            div { class: "topbar-spacer" }
            div { class: "topbar-state",
                span { class: "pulse-dot" }
                span { "local · ready" }
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
    /// ML-DSA-65 signing key for inbox state authorisation and AFT token signing.
    pub ml_dsa_signing_key: Arc<MlDsaSigningKey<MlDsa65>>,
    /// ML-KEM-768 decapsulation key for message decryption.
    pub ml_kem_dk: DecapsulationKey<MlKem768>,
    /// Cached encoded ML-KEM-768 encapsulation key bytes (1184 bytes), computed
    /// once at construction. Avoids re-deriving from `ml_kem_dk` on every read,
    /// which surfaced as a fingerprint mismatch (#100): two reads from the same
    /// logical identity could return different bytes after `Clone`, so the
    /// share-modal six-word display and the contact:// token disagreed.
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
        let vk_bytes = Self::derive_vk_bytes(ml_dsa_signing_key.as_ref());
        let ek_bytes = Self::derive_ek_bytes(&ml_kem_dk);
        Self {
            alias,
            id,
            description,
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

/// On-disk backup format for a single identity.
///
/// The file is plaintext JSON — the user must store it securely, as it
/// contains raw private key material.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct IdentityBackup {
    pub version: u32,
    pub alias: String,
    pub description: String,
    pub keys: StoredIdentityKeys,
}

impl IdentityBackup {
    pub(crate) fn from_identity(identity: &Identity) -> Self {
        Self {
            version: IDENTITY_BACKUP_VERSION,
            alias: identity.alias.to_string(),
            description: identity.description.clone(),
            keys: StoredIdentityKeys::new(&identity.ml_dsa_signing_key, &identity.ml_kem_dk),
        }
    }

    /// Returns `Ok(())` if this backup is the current version, otherwise an
    /// explanatory error. Call before using `self.keys`.
    pub(crate) fn check_version(&self) -> Result<(), String> {
        if self.version == IDENTITY_BACKUP_VERSION {
            Ok(())
        } else {
            Err(format!(
                "backup format v{} is from a pre-release version and is no longer supported \
                 (expected v{}); please re-create the identity",
                self.version, IDENTITY_BACKUP_VERSION
            ))
        }
    }
}

/// Trigger a browser file-download of `json_bytes` as `filename`.
///
/// Creates a `Blob`, wraps it in an object URL, synthesises a temporary
/// `<a download>` element, clicks it, then revokes the URL.
#[cfg(target_family = "wasm")]
pub(crate) fn trigger_browser_download(filename: &str, json_bytes: &[u8]) {
    use wasm_bindgen::JsCast;
    use web_sys::{Blob, BlobPropertyBag, HtmlAnchorElement, Url, js_sys};

    let window = match web_sys::window() {
        Some(w) => w,
        None => return,
    };
    let document = match window.document() {
        Some(d) => d,
        None => return,
    };

    let uint8 = js_sys::Uint8Array::from(json_bytes);
    let array = js_sys::Array::new();
    array.push(&uint8);
    let opts = BlobPropertyBag::new();
    opts.set_type("application/json");
    let blob = match Blob::new_with_u8_array_sequence_and_options(&array, &opts) {
        Ok(b) => b,
        Err(_) => return,
    };
    let url = match Url::create_object_url_with_blob(&blob) {
        Ok(u) => u,
        Err(_) => return,
    };
    if let Some(anchor) = document
        .create_element("a")
        .ok()
        .and_then(|el| el.dyn_into::<HtmlAnchorElement>().ok())
    {
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
    }
    let _ = Url::revoke_object_url(&url);
}

#[cfg(not(target_family = "wasm"))]
pub(crate) fn trigger_browser_download(_filename: &str, _json_bytes: &[u8]) {}

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

pub(crate) struct ImportContact(pub(crate) bool);

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
    use_context_provider(|| Signal::new(ImportBackup(false)));
    use_context_provider(|| Signal::new(ShareContact(false)));
    use_context_provider(|| Signal::new(SharePending::default()));
    use_context_provider(|| Signal::new(ImportContact(false)));
    use_context_provider(|| Signal::new(VerifyContactPending::default()));
    // ImportForm is shared between the hub flow (toggled by ImportBackup
    // here) and the first-run flow (toggled by ImportId in
    // GetOrCreateIdentity). Provide both contexts so the same component
    // can clear whichever wrapper is active.
    use_context_provider(|| Signal::new(ImportId(false)));
    let create_alias_form = use_context::<Signal<CreateAlias>>();
    let import_backup_form = use_context::<Signal<ImportBackup>>();
    let share_contact_form = use_context::<Signal<ShareContact>>();
    let import_contact_form = use_context::<Signal<ImportContact>>();
    let verify_contact_pending = use_context::<Signal<VerifyContactPending>>();

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
            if share_contact_form.read().0 {
                ShareContactModal {}
            }
            if import_contact_form.read().0 {
                ImportContactForm {}
            }
            if verify_contact_pending.read().0.is_some() {
                VerifyContactModal {}
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
        // Per-row rename state. `Some(draft)` means the inline editor is
        // open. Issue #32 — rename is delete+create with the same key.
        let mut rename_draft: Signal<Option<String>> = use_signal(|| None);
        let mut rename_error = use_signal(String::new);

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
                            title: "Export / backup this identity",
                            "data-testid": testid::FM_ID_BACKUP,
                            onclick: move |_| {
                                let backup = IdentityBackup::from_identity(&backup_alias);
                                if let Ok(json) = serde_json::to_vec_pretty(&backup) {
                                    let fname = format!("freenet-identity-{}.json", &*backup_alias.alias);
                                    trigger_browser_download(&fname, &json);
                                }
                            },
                            "↓"
                        }
                        button {
                            class: "icon-btn",
                            title: "Share your address with someone",
                            "data-testid": testid::FM_ID_SHARE,
                            onclick: move |_| {
                                let card = crate::app::address_book::ContactCard::from_identity(&share_id);
                                let fp = card.fingerprint().join("-");
                                let share_text = format!("verify: {}\n{}", fp, card.encode());
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
            "Backup files contain raw private keys — store them securely."
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
        let alias: Rc<str> = alias_str.into();
        actions.send(NodeAction::CreateContract {
            alias: alias.clone(),
            ml_dsa_key: ml_dsa.clone(),
            contract_type: ContractType::InboxContract,
        });
        actions.send(NodeAction::CreateDelegate {
            alias: alias.clone(),
            ml_dsa_key: ml_dsa.clone(),
        });
        actions.send(NodeAction::CreateContract {
            alias: alias.clone(),
            ml_dsa_key: ml_dsa.clone(),
            contract_type: ContractType::AFTContract,
        });
        actions.send(NodeAction::CreateIdentity {
            alias,
            ml_dsa_key: ml_dsa,
            ml_kem_dk: Box::new(ml_kem),
            description: desc_val,
        });
        create_alias_form.write().0 = false;
    };

    let cancel = move |_| {
        pending.set(None);
        alias_input.set(String::new());
        description.set(String::new());
        create_alias_form.write().0 = false;
    };

    let words_opt = pending.read().as_ref().map(|(_, _, w)| *w);

    rsx! {
        if let Some(words) = words_opt {
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
                        " It lives in this browser only. There is no recovery."
                    }
                }
                div { class: "modal-foot", style: "background:transparent; border:0; padding:18px 0 0;",
                    button {
                        class: "btn btn-ghost",
                        onclick: cancel,
                        "Discard"
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
                    div { class: "info", style: "background:#fef2f2; border-color:#fecaca; color:#991b1b;",
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
                    "Paste or upload a previously exported identity backup file."
                }
            }
        }
        p { class: "quiet-hint", "no servers · no accounts · no recovery" }
    }
}

#[allow(non_snake_case)]
fn ImportForm() -> Element {
    let mut import_id_form = use_context::<Signal<ImportId>>();
    let mut import_backup_form = use_context::<Signal<ImportBackup>>();
    let actions = use_coroutine_handle::<NodeAction>();
    let parsed_backup: Signal<Option<IdentityBackup>> = use_signal(|| None);
    let mut address = use_signal(String::new);
    let mut description = use_signal(String::new);
    let mut restore_error = use_signal(String::new);

    let preview_words: Option<[&'static str; 6]> = parsed_backup.read().as_ref().map(|b| {
        let ml_dsa = b.keys.ml_dsa_signing_key();
        let ml_kem = b.keys.ml_kem_dk();
        use ml_dsa::signature::Keypair;
        use ml_kem::kem::KeyExport;
        let vk_bytes: Vec<u8> = ml_dsa.as_ref().verifying_key().encode().to_vec();
        let ek_bytes: Vec<u8> = ml_kem.encapsulation_key().to_bytes().to_vec();
        crate::app::address_book::fingerprint_words(&vk_bytes, &ek_bytes)
    });

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
                "Pick the backup file you exported earlier. The keys never leave this browser."
            }
            div { class: "field", style: "margin-top:24px;",
                label { class: "field-label", "Backup file" }
                input {
                    class: "input",
                    r#type: "file",
                    accept: ".json",
                    id: "restore-file-input",
                    "data-testid": testid::FM_RESTORE_FILE,
                    onchange: move |_| {
                        #[cfg(target_family = "wasm")]
                        {
                            use wasm_bindgen::{JsCast, closure::Closure};
                            use web_sys::{FileReader, HtmlInputElement};
                            let document = match web_sys::window()
                                .and_then(|w| w.document())
                            {
                                Some(d) => d,
                                None => return,
                            };
                            let input = match document
                                .get_element_by_id("restore-file-input")
                                .and_then(|el| el.dyn_into::<HtmlInputElement>().ok())
                            {
                                Some(el) => el,
                                None => return,
                            };
                            let files = match input.files() {
                                Some(f) => f,
                                None => return,
                            };
                            let file = match files.item(0) {
                                Some(f) => f,
                                None => return,
                            };
                            let reader = match FileReader::new() {
                                Ok(r) => r,
                                Err(_) => return,
                            };
                            let reader_c = reader.clone();
                            let mut pb = parsed_backup;
                            let mut addr = address;
                            let mut desc = description;
                            let cb = Closure::once(Box::new(move || {
                                let result = reader_c.result().ok()
                                    .and_then(|v| v.as_string());
                                if let Some(text) = result
                                    && let Ok(b) = serde_json::from_str::<IdentityBackup>(&text)
                                {
                                    addr.set(b.alias.clone());
                                    desc.set(b.description.clone());
                                    pb.set(Some(b));
                                }
                            }) as Box<dyn FnOnce()>);
                            reader.set_onloadend(Some(cb.as_ref().unchecked_ref()));
                            let _ = reader.read_as_text(&file);
                            cb.forget();
                        }
                    },
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
                    placeholder: "pre-filled from backup file",
                    value: "{address}",
                    oninput: move |evt| address.set(evt.value()),
                }
            }
            div { class: "field",
                label { class: "field-label", "Description" }
                input {
                    class: "input",
                    placeholder: "pre-filled from backup file",
                    value: "{description}",
                    oninput: move |evt| description.set(evt.value()),
                }
            }
            div { class: "nudge",
                span { class: "nudge-icon", "⚠" }
                div { class: "nudge-text",
                    strong { "Backup files contain raw private keys." }
                    " Once restored, treat the original file like a password — store it offline or delete it."
                }
            }
            if !restore_error.read().is_empty() {
                div { class: "info", style: "background:#fef2f2; border-color:#fecaca; color:#991b1b;",
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
                    disabled: parsed_backup.read().is_none(),
                    onclick: move |_| {
                        if let Some(backup) = parsed_backup.read().clone() {
                            if let Err(_msg) = backup.check_version() {
                                crate::log::debug!("Rejected backup: {_msg}");
                                return;
                            }
                            let alias_str = address.read().trim().to_string();
                            if alias_str.is_empty() {
                                restore_error.set("Alias is required.".into());
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
                            actions.send(NodeAction::CreateContract {
                                alias: alias.clone(),
                                ml_dsa_key: ml_dsa.clone(),
                                contract_type: ContractType::InboxContract,
                            });
                            actions.send(NodeAction::CreateDelegate {
                                alias: alias.clone(),
                                ml_dsa_key: ml_dsa.clone(),
                            });
                            actions.send(NodeAction::CreateContract {
                                alias: alias.clone(),
                                ml_dsa_key: ml_dsa.clone(),
                                contract_type: ContractType::AFTContract,
                            });
                            actions.send(NodeAction::CreateIdentity {
                                alias,
                                ml_dsa_key: ml_dsa,
                                ml_kem_dk: Box::new(ml_kem),
                                description: desc_val,
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

/// Copy `text` to the system clipboard via the async Clipboard API.
/// No-op on non-WASM or when the API is unavailable (e.g. non-HTTPS).
#[cfg(target_family = "wasm")]
fn copy_to_clipboard(text: String) {
    use wasm_bindgen_futures::spawn_local;
    spawn_local(async move {
        if let Some(window) = web_sys::window() {
            let clipboard = window.navigator().clipboard();
            let _ = wasm_bindgen_futures::JsFuture::from(clipboard.write_text(&text)).await;
        }
    });
}

#[cfg(not(target_family = "wasm"))]
fn copy_to_clipboard(_text: String) {}

/// Modal that displays the shareable ContactCard text and offers a copy button.
#[allow(non_snake_case)]
fn ShareContactModal() -> Element {
    let mut share_contact_form = use_context::<Signal<ShareContact>>();
    let share_pending = use_context::<Signal<SharePending>>();
    let (alias, share_text) = share_pending
        .read()
        .data
        .as_ref()
        .map(|d| (d.alias.clone(), d.share_text.clone()))
        .unwrap_or_default();
    let mut copied = use_signal(|| false);

    // Pull the verify line ("verify: w-w-w-w-w-w") off the front of the
    // share text so we can render the six words in the trust-surface
    // verify-words block. The remainder is the contact:// token.
    let (verify_words, contact_token): (Vec<String>, String) = {
        let mut words = Vec::new();
        let mut token = share_text.clone();
        if let Some((first, rest)) = share_text.split_once('\n')
            && let Some(stripped) = first.strip_prefix("verify: ")
        {
            words = stripped.split('-').map(|s| s.to_string()).collect();
            token = rest.to_string();
        }
        (words, token)
    };
    let close = move |_| {
        share_contact_form.write().0 = false;
        copied.set(false);
    };

    rsx! {
        div { class: "veil",
            onclick: move |_| {
                share_contact_form.write().0 = false;
                copied.set(false);
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
                }
                div { class: "modal-foot",
                    button {
                        class: "btn btn-secondary",
                        "data-testid": testid::FM_SHARE_COPY,
                        onclick: {
                            let share_text = share_text.clone();
                            move |_| {
                                copy_to_clipboard(share_text.clone());
                                copied.set(true);
                            }
                        },
                        if *copied.read() { "Copied" } else { "Copy" }
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

/// Form to import a contact from a pasted ContactCard.
#[allow(non_snake_case)]
fn ImportContactForm() -> Element {
    let mut import_contact_form = use_context::<Signal<ImportContact>>();
    let actions = use_coroutine_handle::<NodeAction>();

    let mut paste_text = use_signal(String::new);
    let mut local_alias = use_signal(String::new);
    let mut description = use_signal(String::new);
    let mut verified = use_signal(|| false);
    let mut error_msg = use_signal(String::new);
    let mut fingerprint_words: Signal<Option<[&'static str; 6]>> = use_signal(|| None);

    let on_paste_change = move |evt: dioxus::prelude::Event<dioxus::html::FormData>| {
        let text = evt.value().clone();
        paste_text.set(text.clone());
        error_msg.set(String::new());
        fingerprint_words.set(None);
        match crate::app::address_book::ContactCard::decode(&text) {
            Ok(card) => {
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
                fingerprint_words.set(Some(card.fingerprint()));
            }
            Err(e) => {
                if !text.trim().is_empty() {
                    error_msg.set(format!("Could not parse contact card: {e}"));
                }
            }
        }
    };

    let can_import = fingerprint_words.read().is_some() && !local_alias.read().is_empty();

    let cancel = move |_| {
        import_contact_form.write().0 = false;
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
                import_contact_form.write().0 = false;
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
                        "Paste the contact:// token your contact gave you. The decoded fingerprint appears below — confirm it through a separate channel before you tick the verify box."
                    }
                    div { class: "field",
                        label { class: "field-label", "Contact card" }
                        textarea {
                            class: "textarea",
                            placeholder: "contact://…",
                            rows: "3",
                            value: "{paste_text}",
                            oninput: on_paste_change,
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
                            }
                        }
                    }
                    if !error_msg.read().is_empty() {
                        div { class: "info", style: "background:#fef2f2; border-color:#fecaca; color:#991b1b;",
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
                            let text = paste_text.read().clone();
                            let alias_str = local_alias.read().clone();
                            if alias_str.is_empty() { return; }
                            match crate::app::address_book::ContactCard::decode(&text) {
                                Ok(card) => {
                                    if crate::app::address_book::is_own_fingerprint(
                                        &card.ml_dsa_vk_bytes,
                                        &card.ml_kem_ek_bytes,
                                    ) {
                                        error_msg.set("That card belongs to one of your own identities.".into());
                                        return;
                                    }
                                    let stored = crate::app::address_book::StoredContactKeys::from_card(
                                        &card,
                                        *verified.read(),
                                    );
                                    let contact = stored.into_contact(
                                        alias_str.clone().into(),
                                        description.read().clone(),
                                    );
                                    actions.send(NodeAction::CreateContact { contact });
                                    import_contact_form.write().0 = false;
                                    paste_text.set(String::new());
                                    local_alias.set(String::new());
                                    description.set(String::new());
                                    verified.set(false);
                                    fingerprint_words.set(None);
                                    error_msg.set(String::new());
                                }
                                Err(e) => {
                                    error_msg.set(format!("Failed to parse: {e}"));
                                }
                            }
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
                onclick: move |_| { import_contact_form.write().0 = true; },
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
                                    span { class: "badge badge-warn",
                                        "data-testid": "contact-verify-badge",
                                        "⚠ unverified"
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
