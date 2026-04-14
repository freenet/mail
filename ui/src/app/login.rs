use std::hash::Hasher;
use std::{
    cell::{LazyCell, RefCell},
    rc::Rc,
};

use std::sync::Arc;

use dioxus::prelude::*;
use freenet_stdlib::prelude::ContractKey;
use identity_management::IdentityManagement;
use ml_dsa::{KeyGen, MlDsa65, SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey};
use ml_kem::{DecapsulationKey, EncapsulationKey, MlKem768};
use rand::rngs::OsRng;
use rsa::{pkcs1::DecodeRsaPrivateKey, RsaPrivateKey};

use crate::app::{ContractType, User, UserId};
use crate::DynError;

use super::{InboxView, NodeAction};

const DEFAULT_ID_ICON: &str = "data:image/x-icon;base64,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";

/// RSA key size for the AFT token subsystem. The AFT protocol is still RSA-bound
/// (separate epic, out of scope for Stage 2). This key is used solely for
/// `DelegateParameters` / `TokenDelegateParameters` in `aft.rs` and `api.rs`.
const AFT_RSA_KEY_SIZE: usize = 4096;

struct ImportId(bool);

struct CreateAlias(bool);

#[allow(non_snake_case)]
fn LoginHeader() -> Element {
    rsx! {
        div {
            class: "columns",
            div { class: "column is-4" }
            section {
                class: "section is-small",
                h1 { class: "title", "Freenet Email" }
            }
        }
    }
}

thread_local! {
    static ALIASES: LazyCell<Rc<RefCell<Vec<Identity>>>> = LazyCell::new(|| {
        Default::default()
    });
}

/// A user identity holding PQ keypairs for inbox operations and an RSA key
/// retained for the AFT token subsystem (which is still RSA-bound pending
/// a separate migration epic).
///
/// - `ml_dsa_signing_key`: ML-DSA-65 signing key. The verifying key is embedded
///   in `InboxParams` and determines the inbox contract ID. Wrapped in `Arc`
///   because `MlDsaSigningKey` is intentionally not `Clone` (secret key hygiene);
///   `Arc` gives us cheap logical clones without copying the key material.
/// - `ml_kem_dk`: ML-KEM-768 decapsulation key. The encapsulation key is
///   published so senders can encrypt messages to this identity.
/// - `rsa_key`: RSA-4096 key used **only** by the AFT token delegate. Removed
///   in Stage 4 when the AFT subsystem is migrated to PQ.
#[derive(Debug)]
pub(crate) struct Identity {
    pub alias: Rc<str>,
    pub id: UserId,
    pub description: String,
    /// ML-DSA-65 signing key for inbox state authorisation.
    pub ml_dsa_signing_key: Arc<MlDsaSigningKey<MlDsa65>>,
    /// ML-KEM-768 decapsulation key for message decryption.
    pub ml_kem_dk: DecapsulationKey<MlKem768>,
    /// RSA-4096 private key retained for the AFT token subsystem only.
    /// Remove in Stage 4 (#18) when AFT is migrated to PQ.
    pub rsa_key: RsaPrivateKey,
}

impl Clone for Identity {
    fn clone(&self) -> Self {
        Self {
            alias: self.alias.clone(),
            id: self.id,
            description: self.description.clone(),
            ml_dsa_signing_key: Arc::clone(&self.ml_dsa_signing_key),
            ml_kem_dk: self.ml_kem_dk.clone(),
            rsa_key: self.rsa_key.clone(),
        }
    }
}

impl PartialEq for Identity {
    fn eq(&self, other: &Self) -> bool {
        // RSA key is the stable unique identifier for an identity until Stage 4.
        self.rsa_key == other.rsa_key
    }
}

impl Eq for Identity {}

impl Identity {
    #[must_use]
    #[allow(dead_code)] // TODO: reinstate via Phase 1 identities delegate path
    pub(crate) fn set_aliases(
        mut new_aliases: IdentityManagement,
        mut user: Signal<crate::app::User>,
    ) -> Vec<Self> {
        ALIASES.with(|aliases| {
            let aliases = &mut *aliases.borrow_mut();
            let mut to_add = Vec::new();
            for alias in &*aliases {
                // just modify and avoid creating a new id
                if let Some(info) = new_aliases.remove(&alias.alias) {
                    to_add.push(alias.clone().with_description(info.extra.unwrap_or_default()));
                }
            }
            let mut identities = Vec::new();
            new_aliases.into_info().for_each(|(alias, info)| {
                let stored: StoredIdentityKeys =
                    serde_json::from_slice(&info.key).expect("failed to deserialise identity keys");
                let ml_dsa_signing_key = stored.ml_dsa_signing_key();
                let ml_kem_dk = stored.ml_kem_dk();
                let rsa_key = stored.rsa_key();
                let alias: Rc<str> = alias.into();
                let id = UserId::new();
                let identity = Identity {
                    id,
                    ml_dsa_signing_key: Arc::clone(&ml_dsa_signing_key),
                    ml_kem_dk: ml_kem_dk.clone(),
                    rsa_key: rsa_key.clone(),
                    description: String::default(),
                    alias: alias.clone(),
                };
                user.write().identities.push(identity.clone());
                to_add.push(Identity {
                    alias: alias.clone(),
                    id,
                    description: info.extra.unwrap_or_default(),
                    ml_dsa_signing_key,
                    ml_kem_dk,
                    rsa_key,
                });
                identities.push(identity);
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
        rsa_key: RsaPrivateKey,
        inbox_key: ContractKey,
        mut user: Signal<crate::app::User>,
    ) -> Identity {
        let identity = Identity {
            alias: alias.clone(),
            id: UserId::new(),
            description: description.clone(),
            ml_dsa_signing_key: Arc::clone(&ml_dsa_signing_key),
            ml_kem_dk: ml_kem_dk.clone(),
            rsa_key: rsa_key.clone(),
        };
        crate::inbox::InboxModel::set_contract_identity(inbox_key, identity.clone());
        user.write().identities.push(identity.clone());
        ALIASES.with(|aliases| {
            let aliases = &mut *aliases.borrow_mut();
            aliases.push(Identity {
                alias,
                id: identity.id,
                description,
                ml_dsa_signing_key,
                ml_kem_dk,
                rsa_key,
            });
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
    pub(crate) fn ml_kem_ek(&self) -> EncapsulationKey<MlKem768> {
        self.ml_kem_dk.encapsulation_key().clone()
    }

    /// Return the ML-DSA-65 verifying (public) key for this identity.
    /// Used to compute the inbox contract ID.
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
                aliases.push(identity);
            }
        });
    }
}

impl std::hash::Hash for Identity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Hash via the RSA key — stable unique identifier until Stage 4.
        self.rsa_key.hash(state)
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
/// { "ml_dsa_seed":  [<32 u8 values>],
///   "ml_kem_seed":  [<64 u8 values>],
///   "rsa_key_bytes": [<variable u8 values>] }
/// ```
///
/// The RSA key is retained for the AFT token subsystem only; it is removed in
/// Stage 4 (#18) when AFT is migrated to PQ primitives.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct StoredIdentityKeys {
    /// 32-byte random seed for ML-DSA-65 signing key reconstruction.
    pub ml_dsa_seed: Vec<u8>,
    /// 64-byte seed for ML-KEM-768 decapsulation key reconstruction.
    pub ml_kem_seed: Vec<u8>,
    /// RSA private key bytes for AFT token subsystem (serde_json of `RsaPrivateKey`).
    pub rsa_key_bytes: Vec<u8>,
}

use serde::{Deserialize, Serialize};

impl StoredIdentityKeys {
    pub(crate) fn new(
        ml_dsa_signing_key: &Arc<MlDsaSigningKey<MlDsa65>>,
        ml_kem_dk: &DecapsulationKey<MlKem768>,
        rsa_key: &RsaPrivateKey,
    ) -> Self {
        // Store ML-DSA as the 32-byte seed via `SigningKey::to_seed()`.
        // Reconstruction: `MlDsa65::from_seed(&seed)`.
        let ml_dsa_seed = ml_dsa_signing_key.as_ref().to_seed().to_vec();
        let ml_kem_seed = ml_kem_dk
            .to_seed()
            .expect("ML-KEM DK must have been generated from seed")
            .to_vec();
        let rsa_key_bytes = serde_json::to_vec(rsa_key).expect("RSA key serialisation");
        Self {
            ml_dsa_seed,
            ml_kem_seed,
            rsa_key_bytes,
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
        let arr = Seed::try_from(self.ml_kem_seed.as_slice())
            .expect("ML-KEM seed wrong length");
        DecapsulationKey::<MlKem768>::new(&arr)
    }

    pub(crate) fn rsa_key(&self) -> RsaPrivateKey {
        serde_json::from_slice(&self.rsa_key_bytes).expect("RSA key deserialisation")
    }
}

/// On-disk backup format for a single identity (version 1).
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
            version: 1,
            alias: identity.alias.to_string(),
            description: identity.description.clone(),
            keys: StoredIdentityKeys::new(
                &identity.ml_dsa_signing_key,
                &identity.ml_kem_dk,
                &identity.rsa_key,
            ),
        }
    }
}

/// Trigger a browser file-download of `json_bytes` as `filename`.
///
/// Creates a `Blob`, wraps it in an object URL, synthesises a temporary
/// `<a download>` element, clicks it, then revokes the URL.
#[cfg(target_family = "wasm")]
fn trigger_browser_download(filename: &str, json_bytes: &[u8]) {
    use js_sys::Uint8Array;
    use wasm_bindgen::JsCast;
    use web_sys::{Blob, BlobPropertyBag, HtmlAnchorElement, Url};

    let window = match web_sys::window() {
        Some(w) => w,
        None => return,
    };
    let document = match window.document() {
        Some(d) => d,
        None => return,
    };

    let uint8 = Uint8Array::from(json_bytes);
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
    let create_alias_form = use_context::<Signal<CreateAlias>>();
    let import_backup_form = use_context::<Signal<ImportBackup>>();

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
                }
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

    #[component]
    fn IdentityEntry(identity: Identity) -> Element {
        let mut user = use_context::<Signal<User>>();
        let mut inbox = use_context::<Signal<InboxView>>();
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
                        button {
                            class: "button is-small is-light mt-1",
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
                        p { class: "help is-warning", "Backup files contain raw private keys — store securely." }
                    }
                }
            }
        }
    }

    let identities = aliases_list.iter().map(|alias| {
        rsx!(IdentityEntry { identity: alias.clone() })
    });

    rsx! {
        div {
            hidden: "{create_alias_form.read().0 || import_backup_form.read().0}",
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
                    // Generate or import keypair bundle
                    let keys = match get_keys(&generate, &key_path) {
                        Ok(k) => {
                            create_alias_form.write().0 = false;
                            Some(k)
                        },
                        Err(e) => {
                            crate::log::debug!("Failed to generate or import keys: {:?}", e);
                            show_error.set(true);
                            login_error.set(format!("Failed to generate or import keys: {:?}", e));
                            None
                        }
                    };
                    if let Some((ml_dsa_key, ml_kem_dk, rsa_key)) = keys {
                        // - create inbox contract
                        actions.send(NodeAction::CreateContract {
                            alias: alias.clone(),
                            ml_dsa_key: ml_dsa_key.clone(),
                            rsa_key: rsa_key.clone(),
                            contract_type: ContractType::InboxContract,
                        });
                        // - create AFT delegate && contract
                        actions.send(NodeAction::CreateDelegate {
                            alias: alias.clone(),
                            rsa_key: rsa_key.clone(),
                        });
                        actions.send(NodeAction::CreateContract {
                            alias: alias.clone(),
                            ml_dsa_key: ml_dsa_key.clone(),
                            rsa_key: rsa_key.clone(),
                            contract_type: ContractType::AFTContract,
                        });

                        let description_val = description.read().clone();
                        actions.send(NodeAction::CreateIdentity {
                            alias,
                            ml_dsa_key,
                            ml_kem_dk: Box::new(ml_kem_dk),
                            rsa_key,
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
/// ML-DSA-65 + ML-KEM-768 are the PQ keys; RSA is retained for AFT (Stage 4).
type IdentityKeyBundle = (Arc<MlDsaSigningKey<MlDsa65>>, DecapsulationKey<MlKem768>, RsaPrivateKey);

/// Generate a fresh identity keypair bundle:
/// - ML-DSA-65 signing key (for inbox contract ownership)
/// - ML-KEM-768 decapsulation key (for message encryption)
/// - RSA-4096 key (for AFT token subsystem — retained until Stage 4)
///
/// Import mode reads an RSA PKCS#1 PEM file (legacy path, kept for
/// compatibility) and derives the PQ keys afresh. In Stage 4 the import
/// path will be updated to accept the full PQ bundle.
fn get_keys(
    generate: &Signal<bool>,
    key_path: &Signal<String>,
) -> Result<IdentityKeyBundle, DynError> {
    let mut rng = OsRng;

    let rsa_key = if *generate.read() {
        crate::log::debug!("generating identity keypair bundle");
        RsaPrivateKey::new(&mut rng, AFT_RSA_KEY_SIZE)
            .map_err(|e| format!("RSA key generation failed: {e}"))?
    } else {
        crate::log::debug!("importing RSA key for identity");
        let key_path = key_path.read().clone();
        let key_str =
            std::fs::read_to_string(key_path).map_err(|_| "Failed to read key file")?;
        RsaPrivateKey::from_pkcs1_pem(key_str.as_str())
            .map_err(|_| "Failed to parse PKCS#1 PEM key")?
    };

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

    Ok((ml_dsa_key, ml_kem_dk, rsa_key))
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
                                        } else {
                                            crate::log::error("backup file parse failed".into(), None);
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
                        let alias: Rc<str> = address.read().to_owned().into();
                        let desc_val = description.read().clone();
                        let ml_dsa = backup.keys.ml_dsa_signing_key();
                        let ml_kem = backup.keys.ml_kem_dk();
                        let rsa = backup.keys.rsa_key();
                        actions.send(NodeAction::CreateContract {
                            alias: alias.clone(),
                            ml_dsa_key: ml_dsa.clone(),
                            rsa_key: rsa.clone(),
                            contract_type: ContractType::InboxContract,
                        });
                        actions.send(NodeAction::CreateDelegate {
                            alias: alias.clone(),
                            rsa_key: rsa.clone(),
                        });
                        actions.send(NodeAction::CreateContract {
                            alias: alias.clone(),
                            ml_dsa_key: ml_dsa.clone(),
                            rsa_key: rsa.clone(),
                            contract_type: ContractType::AFTContract,
                        });
                        actions.send(NodeAction::CreateIdentity {
                            alias,
                            ml_dsa_key: ml_dsa,
                            ml_kem_dk: Box::new(ml_kem),
                            rsa_key: rsa,
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
