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

use super::{InboxView, NodeAction};

const DEFAULT_ID_ICON: &str = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAQAAAD9CzEMAAAABGdBTUEAALGPC/xhBQAAACBjSFJNAAB6JgAAgIQAAPoAAACA6AAAdTAAAOpgAAA6mAAAF3CculE8AAAAAmJLR0QA/4ePzL8AAAAJcEhZcwABOvYAATr2ATqxVzoAAAAHdElNRQfkCBkKKyVsgwwYAAADtUlEQVRYw+3Xb2hVdRzH8de5d879dZtrhE7SDHQTDfoLKf4j0YglGqXhAxMt8kZ/6EkmUhmEDutJKzkG/bEoSaLQwvxHSiiCJaEYWhpoCzPNtru56ea8uz1IpXnv7r2bQk/8Pv3+zud9Pr9zvp/zO9yo/7uCXBeGRJQpRZu47tj1AzQYQJmJZrlDFc740Qa7tJAdkxUQwnivmqRAhyYMVqDDLsvtyY4IssknRB/yjlv85AvfOY4RJnvYOI2e8XU2RF42B9EJVqv2kVeCxqQYwmN2+sDLFlqt2e5rcBBSap0673pRa6xnZ5BVnvKNx5zN5CGSxcA00x1S31OeGK3qHTLNtMwCGQAhEbPl+8zxtAuOWy/fLJGw3w4q3andjnQPMgbfandXyn46QKEycSd67Z8QV6aw/4DrUJkB58VVqO61X61C3Pn+A5rsV2TqpXnuUSFMVWS/pn4CYiRs1GWeEWkXjDBPlw0S1zIHW21Ra5nSnh5CSi1Ta7ttmQWyZpFJPjXEh1Z0Hhv4b1QIJG/1kkVOmm9n7BoBzNRguMPW2uE0qtxvgVqNnvVVtrDLJa4jZmlQLanVWZQoEzjhORuyf3iyhN0QJ0eZ61E1BujUqgMFBhmoy88+tz55JMjoIcgkr9BcS43S5qBt9vpNG0oMd6/pblfiiJXWOx/rOyCk0nJPiNjqLfvyWhIWX+qtcZO/BrnH82bo9p7XnIn1DRAy2CoL/WmltekTP6TU45Ya6mMvaEqPiPYiX2CFxRo9GaxzIf2lm9RdSH4fHDLRZEV21l3clJuDEBZY42+Lgi3JjI8wlBQ84H2VFlub7pVNP8mjLRFVL4s8MQFbvC5qidHpVqQAQpijxub0d5SKwCc2qzE/XSimczDUHO0aMn/MeyDOatBupqE5OMAEYxzwQ07ql2ufA8YYnxVwKeUjtmvJXT1J3HYRU7tTNinVQbGxEvbmsv+X62nYK2FcpDj7FpUbplljnzYIGjWrVp4dEDVAh7Y+A9p0yE8d3FRAp1ZV6hSGOekSCik2W5VWnVd3Uw6/wankavXeNMPmcJ9ftfSe+SFR5Ua724Om6PB29FTiar00F+V5xBJj5Wl11GGHHfOHuLjkFd8VylUbqcYYtynRZb83fJl6AEiTRWtEJG42xUPuM0w+ki46p+0KIFCqUJ4AHRrtsdHu2Jk1VwI9I+A/ToaoNdZIRYYpVqFEgG5dump3zu3ZHHfSL070fXXL4RwsJ5MtTrAAkdWp3MXkhSOY+KzfqRvW//gEajCCgaQ1BtwAAACV0RVh0ZGF0ZTpjcmVhdGUAMjAyMC0wOC0yNVQxMDo0MzozNyswMDowMCaRJjwAAAAldEVYdGRhdGU6bW9kaWZ5ADIwMjAtMDgtMjVUMTA6NDM6MzcrMDA6MDBXzJ6AAAAAIHRFWHRzb2Z0d2FyZQBodHRwczovL2ltYWdlbWFnaWNrLm9yZ7zPHZ0AAAAYdEVYdFRodW1iOjpEb2N1bWVudDo6UGFnZXMAMaf/uy8AAAAYdEVYdFRodW1iOjpJbWFnZTo6SGVpZ2h0ADUxMo+NU4EAAAAXdEVYdFRodW1iOjpJbWFnZTo6V2lkdGgANTEyHHwD3AAAABl0RVh0VGh1bWI6Ok1pbWV0eXBlAGltYWdlL3BuZz+yVk4AAAAXdEVYdFRodW1iOjpNVGltZQAxNTk4MzUyMjE3d6RTMwAAABN0RVh0VGh1bWI6OlNpemUAMTcwNTRCQjjLDL0AAABAdEVYdFRodW1iOjpVUkkAZmlsZTovLy4vdXBsb2Fkcy81Ni9ZUmJ0ZDNpLzI0ODMvdXNlcl9pY29uXzE0OTg1MS5wbmd+0VDgAAAAAElFTkSuQmCC";

struct ImportId(bool);

struct CreateAlias(bool);

#[allow(non_snake_case)]
fn LoginHeader() -> Element {
    let app_name = crate::app_name();
    rsx! {
        div {
            class: "columns",
            div { class: "column is-4" }
            section {
                class: "section is-small",
                h1 { class: "title", "{app_name}" }
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
}

impl Identity {
    /// Encoded ML-DSA-65 verifying key bytes (1952 bytes). Stable, unique per
    /// identity, and cheap-to-compute; used as the identity correlator in
    /// `HashMap` / `PartialEq` contexts that previously keyed by RSA.
    pub(crate) fn ml_dsa_vk_bytes(&self) -> Vec<u8> {
        use ml_dsa::signature::Keypair;
        self.ml_dsa_signing_key
            .as_ref()
            .verifying_key()
            .encode()
            .to_vec()
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
                                crate::log::debug!("skipping identity {alias}: bad key bytes: {e}");
                                return;
                            }
                        };
                        let ml_dsa_signing_key = stored.ml_dsa_signing_key();
                        let ml_kem_dk = stored.ml_kem_dk();
                        let alias: Rc<str> = alias.into();
                        let id = UserId::new();
                        let identity = Identity {
                            id,
                            ml_dsa_signing_key: Arc::clone(&ml_dsa_signing_key),
                            ml_kem_dk: ml_kem_dk.clone(),
                            description: String::default(),
                            alias: alias.clone(),
                        };
                        user.write().identities.push(identity.clone());
                        let full = Identity {
                            alias: alias.clone(),
                            id,
                            description: info.extra.unwrap_or_default(),
                            ml_dsa_signing_key,
                            ml_kem_dk,
                        };
                        crate::app::address_book::register_identity(&full);
                        to_add.push(full);
                        identities.push(identity);
                    }
                    EntryKind::Contact => {
                        let stored: crate::app::address_book::StoredContactKeys =
                            match serde_json::from_slice(&info.key) {
                                Ok(s) => s,
                                Err(e) => {
                                    crate::log::debug!(
                                        "skipping contact {alias}: bad key bytes: {e}"
                                    );
                                    return;
                                }
                            };
                        let contact = stored
                            .into_contact(alias.clone().into(), info.extra.unwrap_or_default());
                        let _ = crate::app::address_book::insert_contact(contact);
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
        let identity = Identity {
            alias: alias.clone(),
            id: UserId::new(),
            description: description.clone(),
            ml_dsa_signing_key: Arc::clone(&ml_dsa_signing_key),
            ml_kem_dk: ml_kem_dk.clone(),
        };
        crate::inbox::InboxModel::set_contract_identity(inbox_key, identity.clone());
        user.write().identities.push(identity.clone());
        ALIASES.with(|aliases| {
            let aliases = &mut *aliases.borrow_mut();
            let full = Identity {
                alias,
                id: identity.id,
                description,
                ml_dsa_signing_key,
                ml_kem_dk,
            };
            crate::app::address_book::register_identity(&full);
            aliases.push(full);
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
fn trigger_browser_download(filename: &str, json_bytes: &[u8]) {
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
    let mut opts = BlobPropertyBag::new();
    opts.type_("application/json");
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
fn trigger_browser_download(_filename: &str, _json_bytes: &[u8]) {}

struct ImportBackup(bool);

struct ShareContact(bool);

struct ImportContact(bool);

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
    use_context_provider(|| Signal::new(ImportContact(false)));
    let create_alias_form = use_context::<Signal<CreateAlias>>();
    let import_backup_form = use_context::<Signal<ImportBackup>>();
    let share_contact_form = use_context::<Signal<ShareContact>>();
    let import_contact_form = use_context::<Signal<ImportContact>>();

    rsx! {
        LoginHeader {}
        div {
            class: "columns",
            div { class: "column is-3" }
            div {
                class: "column is-6",
                div {
                    class: "card has-background-light is-small mt-2",
                    Identities {}
                    if create_alias_form.read().0 {
                        CreateAliasForm {}
                    }
                    if import_backup_form.read().0 {
                        ImportForm {}
                    }
                    if share_contact_form.read().0 {
                        ShareContactModal {}
                    }
                    if import_contact_form.read().0 {
                        ImportContactForm {}
                    }
                    if !create_alias_form.read().0
                        && !import_backup_form.read().0
                        && !share_contact_form.read().0
                        && !import_contact_form.read().0
                    {
                        ContactsSection {}
                    }
                }
            }
        }
    }
}

// Pending share text for the share modal: (identity alias, card text).
thread_local! {
    static SHARE_PENDING: std::cell::RefCell<Option<(String, String)>> =
        const { std::cell::RefCell::new(None) };
}

#[allow(non_snake_case)]
pub(super) fn Identities() -> Element {
    let aliases = Identity::get_aliases();
    let aliases_list = aliases.borrow();
    let mut create_alias_form = use_context::<Signal<CreateAlias>>();
    let mut import_backup_form = use_context::<Signal<ImportBackup>>();
    let share_contact_form = use_context::<Signal<ShareContact>>();
    let mut login_controller = use_context::<Signal<LoginController>>();

    if login_controller.read().updated {
        login_controller.write().updated = false;
    }

    #[component]
    fn IdentityEntry(identity: Identity) -> Element {
        let mut user = use_context::<Signal<User>>();
        let mut inbox = use_context::<Signal<InboxView>>();
        let mut share_contact_form = use_context::<Signal<ShareContact>>();
        let id = identity.id;
        let alias = identity.alias.clone();
        let description = identity.description.clone();

        rsx! {
            div {
                class: "card-content",
                div {
                    class: "media",
                    div {
                        class: "media-left",
                        figure { class: "image is-48x48", img { src: DEFAULT_ID_ICON } }
                    }
                    div {
                        class: "media-content",
                        p {
                            class: "title is-4",
                            a {
                                style: "color: inherit",
                                onclick: move |_| {
                                    user.write().set_logged_id(id);
                                    inbox.write().set_active_id(id);
                                },
                                "{alias}"
                            }
                        },
                        p { class: "subtitle is-6", "{description}" }
                        div {
                            class: "buttons mt-1",
                            button {
                                class: "button is-small is-light",
                                title: "Export / backup this identity",
                                onclick: {
                                    let identity = identity.clone();
                                    move |_| {
                                        let backup = IdentityBackup::from_identity(&identity);
                                        if let Ok(json) = serde_json::to_vec_pretty(&backup) {
                                            let fname = format!("freenet-identity-{}.json", &*identity.alias);
                                            trigger_browser_download(&fname, &json);
                                        }
                                    }
                                },
                                span { class: "icon is-small", i { class: "fas fa-download" } }
                                span { "Backup" }
                            }
                            button {
                                class: "button is-small is-info is-light",
                                title: "Share your address with someone",
                                onclick: {
                                    let identity = identity.clone();
                                    move |_| {
                                        use ml_kem::kem::KeyExport;
                                        let vk_bytes = identity.ml_dsa_vk_bytes();
                                        let ek_bytes = identity.ml_kem_dk
                                            .encapsulation_key()
                                            .to_bytes()
                                            .to_vec();
                                        let card = crate::app::address_book::ContactCard {
                                            version: crate::app::address_book::ContactCard::VERSION,
                                            ml_dsa_vk_bytes: vk_bytes.clone(),
                                            ml_kem_ek_bytes: ek_bytes.clone(),
                                            suggested_alias: Some(identity.alias.to_string()),
                                            suggested_description: if identity.description.is_empty() {
                                                None
                                            } else {
                                                Some(identity.description.clone())
                                            },
                                        };
                                        let fp = crate::app::address_book::fingerprint_words(&vk_bytes, &ek_bytes);
                                        let fp_line = fp.join("-");
                                        let card_uri = card.encode();
                                        let share_text = format!("verify: {fp_line}\n{card_uri}");
                                        SHARE_PENDING.with(|sp| {
                                            *sp.borrow_mut() = Some((identity.alias.to_string(), share_text));
                                        });
                                        share_contact_form.write().0 = true;
                                    }
                                },
                                span { class: "icon is-small", i { class: "fas fa-share-alt" } }
                                span { "Share address" }
                            }
                        }
                        p { class: "help is-warning", "Backup files contain raw private keys — store securely." }
                    }
                }
            }
        }
    }

    let identities = aliases_list.iter().map(|alias| {
        rsx!(IdentityEntry {
            identity: alias.clone()
        })
    });

    let any_form =
        create_alias_form.read().0 || import_backup_form.read().0 || share_contact_form.read().0;

    rsx! {
        div {
            hidden: "{any_form}",
            {identities}
            div {
                class: "card-content columns",
                div { class: "column is-4" }
                a {
                    class: "column is-4 is-link",
                    onclick: move |_| {
                        create_alias_form.write().0 = true;
                    },
                    "Create new identity"
                }
            }
            div {
                class: "card-content columns",
                div { class: "column is-4" }
                a {
                    class: "column is-4 is-link",
                    onclick: move |_| {
                        import_backup_form.write().0 = true;
                    },
                    "Restore identity from backup"
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
    let mut show_error = use_signal(|| false);
    let mut generate = use_signal(|| true);
    let mut address = use_signal(String::new);
    let mut description = use_signal(String::new);
    let key_path = use_signal(|| {
        std::iter::repeat_n('\u{80}', 100)
            .chain(std::iter::repeat_n('.', 300))
            .collect::<String>()
    });

    rsx! {
        div {
            class: "box has-background-primary is-small mt-2",
            div {
                class: "field",
                label { "Name" }
                div {
                    class: "control has-icons-left",
                    input {
                        class: "input",
                        placeholder: "John Smith",
                        value: "{address}",
                        oninput: move |evt| address.set(evt.value().clone())
                    }
                    span { class: "icon is-small is-left", i { class: "fas fa-envelope" } }
                }
            }
            div {
                class: "field",
                label { "Description" }
                div {
                    class: "control has-icons-left",
                    input {
                        class: "input",
                        placeholder: "",
                        value: "{description}",
                        oninput: move |evt| description.set(evt.value().clone())
                    }
                    span { class: "icon is-small is-left", i { class: "fas fa-envelope" } }
                }
            }
            div {
                class: "columns mb-2 mt-2",
                div {
                    class: "column is-two-fifths",
                    div {
                        class: "file is-small has-name",
                        label {
                            class: "file-label",
                            input { class: "file-input", r#type: "file", name: "keypair-file" }
                            span {
                                class: "file-cta",
                                span { class: "file-icon", i { class: "fas fa-upload" } }
                                span { class: "file-label", "Import key file" }
                            }
                            span { class: "file-name has-background-white", "{key_path}" }
                        }
                    }
                }
                div {
                    class:"column is-one-fifth" ,
                    p { class: "has-text-centered", "or" }
                }
                div {
                    class: "column is-two-fifths",

                    label {
                        class: "checkbox",
                        input {
                            r#type: "checkbox",
                            checked: true,
                            onclick: move |_| {
                                let current = *generate.read();
                                generate.set(!current);
                            }
                        },
                        "  generate"
                    }
                }
            }
            a {
                class: "button",
                onclick: move |_|  {
                    let alias: Rc<str> = address.read().to_owned().into();
                    let keys = match get_keys() {
                        Ok(k) => {
                            create_alias_form.write().0 = false;
                            Some(k)
                        },
                        Err(e) => {
                            crate::log::debug!("Failed to generate keys: {:?}", e);
                            show_error.set(true);
                            login_error.set(format!("Failed to generate keys: {:?}", e));
                            None
                        }
                    };
                    if let Some((ml_dsa_key, ml_kem_dk)) = keys {
                        // - create inbox contract
                        actions.send(NodeAction::CreateContract {
                            alias: alias.clone(),
                            ml_dsa_key: ml_dsa_key.clone(),
                            contract_type: ContractType::InboxContract,
                        });
                        // - create AFT delegate && contract
                        actions.send(NodeAction::CreateDelegate {
                            alias: alias.clone(),
                            ml_dsa_key: ml_dsa_key.clone(),
                        });
                        actions.send(NodeAction::CreateContract {
                            alias: alias.clone(),
                            ml_dsa_key: ml_dsa_key.clone(),
                            contract_type: ContractType::AFTContract,
                        });

                        let description_val = description.read().clone();
                        actions.send(NodeAction::CreateIdentity {
                            alias,
                            ml_dsa_key,
                            ml_kem_dk: Box::new(ml_kem_dk),
                            description: description_val,
                        });
                    } else {
                        crate::log::debug!("Failed to create identity");
                    }
                },
                "Create"
            }
        }
        div {
            hidden: "{!*show_error.read()}",
            class: "notification is-danger",
            button {
                class: "delete",
                onclick: move |_| {
                    show_error.set(false);
                    login_error.set(String::default());
                },
            },
            {login_error.read().clone()}
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
        LoginHeader {}
        div {
            class: "columns",
            div { class: "column is-4"}
            div {
                class: "column is-4",
                if !import_form_state.read().0 {
                    CreateLinks {}
                } else {
                    ImportForm {}
                }
            }
        }
    }
}

#[allow(non_snake_case)]
fn CreateLinks() -> Element {
    let mut user = use_context::<Signal<User>>();
    let mut create_user_form = use_context::<Signal<ImportId>>();
    rsx! {
        div {
            class: "box is-small",
            a {
                class: "is-link",
                onclick: move |_| {
                    create_user_form.write().0 = false;
                    user.write().identified = true;
                },
                "Create new identity"
            }
        },
        div {
            class: "box is-small",
            a {
                class: "is-link",
                onclick: move |_| create_user_form.write().0 = true ,
                "Import existing identity"
            }
        }
    }
}

#[allow(non_snake_case)]
fn ImportForm() -> Element {
    let mut import_backup_form = use_context::<Signal<ImportBackup>>();
    let actions = use_coroutine_handle::<NodeAction>();
    let parsed_backup: Signal<Option<IdentityBackup>> = use_signal(|| None);
    let mut address = use_signal(String::new);
    let mut description = use_signal(String::new);

    rsx! {
        div {
            class: "box has-background-primary is-small mt-2",
            div {
                class: "file is-small mb-2",
                label {
                    class: "file-label",
                    input {
                        class: "file-input",
                        r#type: "file",
                        accept: ".json",
                        id: "restore-file-input",
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
                                let mut pb = parsed_backup.clone();
                                let mut addr = address.clone();
                                let mut desc = description.clone();
                                let cb = Closure::once(Box::new(move || {
                                    let result = reader_c.result().ok()
                                        .and_then(|v| v.as_string());
                                    if let Some(text) = result {
                                        if let Ok(b) = serde_json::from_str::<IdentityBackup>(&text) {
                                            addr.set(b.alias.clone());
                                            desc.set(b.description.clone());
                                            pb.set(Some(b));
                                        }
                                    }
                                }) as Box<dyn FnOnce()>);
                                reader.set_onloadend(Some(cb.as_ref().unchecked_ref()));
                                let _ = reader.read_as_text(&file);
                                cb.forget();
                            }
                        }
                    }
                    span {
                        class: "file-cta",
                        span { class: "file-icon", i { class: "fas fa-upload" } }
                        span { class: "file-label", "Choose backup file (.json)" }
                    }
                }
            }
            div {
                class: "field",
                label { "Alias" }
                div {
                    class: "control has-icons-left",
                    input {
                        class: "input",
                        placeholder: "pre-filled from backup file",
                        value: "{address}",
                        oninput: move |evt| address.set(evt.value().clone())
                    }
                    span { class: "icon is-small is-left", i { class: "fas fa-envelope" } }
                }
            }
            div {
                class: "field",
                label { "Description" }
                div {
                    class: "control",
                    input {
                        class: "input",
                        placeholder: "pre-filled from backup file",
                        value: "{description}",
                        oninput: move |evt| description.set(evt.value().clone())
                    }
                }
            }
            p { class: "help is-warning mb-2",
                "Backup files contain raw private keys — store them securely."
            }
            button {
                class: if parsed_backup.read().is_some() { "button is-primary mr-2" } else { "button is-primary mr-2 is-static" },
                disabled: parsed_backup.read().is_none(),
                onclick: move |_| {
                    if let Some(backup) = parsed_backup.read().clone() {
                        if let Err(_msg) = backup.check_version() {
                            crate::log::debug!("Rejected backup: {_msg}");
                            return;
                        }
                        let alias: Rc<str> = address.read().to_owned().into();
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
                    }
                },
                "Restore"
            }
            button {
                class: "button is-light",
                onclick: move |_| { import_backup_form.write().0 = false; },
                "Cancel"
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
    let (alias, share_text) = SHARE_PENDING.with(|sp| {
        sp.borrow()
            .clone()
            .unwrap_or_else(|| ("".into(), "".into()))
    });
    let mut copied = use_signal(|| false);

    rsx! {
        div {
            class: "box has-background-primary is-small mt-2",
            p { class: "title is-5", "Share your address ({alias})" }
            p { class: "is-size-7 mb-2",
                "Send this text to whoever needs to reach you. \
                 Ask them to confirm the verify: line matches what you see here."
            }
            textarea {
                class: "textarea is-family-monospace is-small mb-2",
                readonly: true,
                rows: "4",
                value: "{share_text}"
            }
            div {
                class: "buttons",
                button {
                    class: "button is-info",
                    onclick: {
                        let share_text = share_text.clone();
                        move |_| {
                            copy_to_clipboard(share_text.clone());
                            copied.set(true);
                        }
                    },
                    if *copied.read() { "Copied!" } else { "Copy to clipboard" }
                }
                button {
                    class: "button is-light",
                    onclick: move |_| {
                        share_contact_form.write().0 = false;
                        copied.set(false);
                    },
                    "Close"
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
    let mut fingerprint_words: Signal<Option<[String; 6]>> = use_signal(|| None);

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

    rsx! {
        div {
            class: "box has-background-primary is-small mt-2",
            p { class: "title is-5", "Import contact" }
            div {
                class: "field",
                label { "Paste contact card (contact://… or bare base64)" }
                div {
                    class: "control",
                    textarea {
                        class: "textarea is-small",
                        placeholder: "contact://…",
                        rows: "3",
                        value: "{paste_text}",
                        oninput: on_paste_change
                    }
                }
            }
            if let Some(ref words) = *fingerprint_words.read() {
                div {
                    class: "notification is-info is-light mb-2",
                    p { class: "has-text-weight-bold", "Fingerprint (verify with sender):" }
                    p { class: "is-family-monospace is-size-6",
                        "{words[0]} {words[1]} {words[2]} {words[3]} {words[4]} {words[5]}"
                    }
                    label {
                        class: "checkbox",
                        input {
                            r#type: "checkbox",
                            checked: *verified.read(),
                            onclick: move |_| {
                                let v = *verified.read();
                                verified.set(!v);
                            }
                        }
                        " I verified the fingerprint with the sender"
                    }
                }
            }
            div {
                class: "field",
                label { "Your local label (must be unique)" }
                div {
                    class: "control",
                    input {
                        class: "input",
                        placeholder: "e.g. Alice (work)",
                        value: "{local_alias}",
                        oninput: move |evt| local_alias.set(evt.value().clone())
                    }
                }
            }
            div {
                class: "field",
                label { "Description (optional)" }
                div {
                    class: "control",
                    input {
                        class: "input",
                        placeholder: "",
                        value: "{description}",
                        oninput: move |evt| description.set(evt.value().clone())
                    }
                }
            }
            if !error_msg.read().is_empty() {
                div {
                    class: "notification is-danger is-light mb-2",
                    "{error_msg}"
                }
            }
            div {
                class: "buttons",
                button {
                    class: if can_import { "button is-primary" } else { "button is-primary is-static" },
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
                button {
                    class: "button is-light",
                    onclick: move |_| {
                        import_contact_form.write().0 = false;
                        error_msg.set(String::new());
                    },
                    "Cancel"
                }
            }
        }
    }
}

/// Address book section showing all imported contacts.
#[allow(non_snake_case)]
fn ContactsSection() -> Element {
    let mut import_contact_form = use_context::<Signal<ImportContact>>();
    let actions = use_coroutine_handle::<NodeAction>();
    let contacts = crate::app::address_book::all_contacts();
    let mut login_controller = use_context::<Signal<LoginController>>();

    if login_controller.read().updated {
        login_controller.write().updated = false;
    }

    rsx! {
        div {
            class: "card-content",
            p { class: "title is-5 mb-1", "Contacts" }
            if contacts.is_empty() {
                p { class: "is-size-7 has-text-grey", "No contacts yet. Import one to send messages." }
            }
            for contact in contacts {
                {
                    let alias_str = contact.local_alias.to_string();
                    let fp = contact.fingerprint_short();
                    let badge = if contact.verified { "✓" } else { "⚠" };
                    let badge_class = if contact.verified {
                        "has-text-success"
                    } else {
                        "has-text-warning"
                    };
                    let del_alias = alias_str.clone();
                    rsx! {
                        div {
                            class: "media mb-1",
                            div {
                                class: "media-content",
                                p {
                                    class: "is-size-6",
                                    span { class: "{badge_class} mr-1", "{badge}" }
                                    strong { "{alias_str}" }
                                    span { class: "has-text-grey is-size-7 ml-2", "({fp})" }
                                }
                                if !contact.description.is_empty() {
                                    p { class: "is-size-7 has-text-grey", "{contact.description}" }
                                }
                            }
                            div {
                                class: "media-right",
                                button {
                                    class: "button is-small is-danger is-light",
                                    title: "Remove contact",
                                    onclick: move |_| {
                                        actions.send(NodeAction::DeleteContact {
                                            alias: del_alias.clone(),
                                        });
                                    },
                                    span { class: "icon is-small", i { class: "fas fa-trash" } }
                                }
                            }
                        }
                    }
                }
            }
            div {
                class: "mt-2",
                a {
                    class: "is-link is-size-7",
                    onclick: move |_| {
                        import_contact_form.write().0 = true;
                    },
                    "+ Import contact"
                }
            }
        }
    }
}
