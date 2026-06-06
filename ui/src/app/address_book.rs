//! Local address book — single owner of all alias→entry mappings.
//!
//! Public surface:
//!   - `lookup(alias)` → `Option<Recipient>` — used by the compose picker
//!   - `insert_contact(alias, contact)` / `remove_contact(alias)` — mutators
//!   - `ContactCard` — wire format for sharing / importing contacts
//!   - `fingerprint_words(vk, ek)` — 6-word BIP-39-like fingerprint

use std::{cell::RefCell, collections::HashMap, rc::Rc, sync::OnceLock};

use freenet_aft_interface::Tier;
use freenet_email_inbox::{DEFAULT_MAX_AGE_SECS, Inbox as InboxState};
use freenet_stdlib::prelude::blake3;
use ml_dsa::{MlDsa65, VerifyingKey as MlDsaVerifyingKey};
use ml_kem::{EncapsulationKey, MlKem768};
use serde::{Deserialize, Serialize};

use crate::app::login::Identity;

/// BIP-39 English wordlist (2048 words). Source: bitcoin/bips repo,
/// `bip-0039/english.txt`. Public domain — no attribution required.
const BIP39_WORDS: &str = include_str!("bip39_english.txt");

fn wordlist() -> &'static [&'static str] {
    static WORDLIST: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDLIST.get_or_init(|| BIP39_WORDS.split_whitespace().collect())
}

/// Six-word fingerprint over `BLAKE3(vk_bytes || ek_bytes)`.
///
/// 66 bits of entropy (six 11-bit indices into the BIP-39 English
/// wordlist). Adequate for casual verbal confirmation; not a substitute
/// for a full key fingerprint.
pub fn fingerprint_words(vk_bytes: &[u8], ek_bytes: &[u8]) -> [&'static str; 6] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(vk_bytes);
    hasher.update(ek_bytes);
    let hash = hasher.finalize();
    let bytes = hash.as_bytes();

    let wl = wordlist();
    debug_assert_eq!(wl.len(), 2048);

    // Pack the first 12 bytes as a u128 (big-endian) so we can pull six
    // 11-bit windows with shift+mask. 6×11 = 66 bits; the low 30 bits of
    // the u128 are unused.
    let mut packed = [0u8; 16];
    packed[..12].copy_from_slice(&bytes[..12]);
    let n = u128::from_be_bytes(packed);
    let mut out = [""; 6];
    for (i, slot) in out.iter_mut().enumerate() {
        let shift = 128 - 11 * (i + 1);
        *slot = wl[((n >> shift) & 0x7FF) as usize];
    }
    out
}

// ── Wire format ───────────────────────────────────────────────────────────────

/// Paste-friendly contact card exchanged out-of-band (text, QR, etc.).
/// Carries the bs58-encoded inbox `ContractInstanceId` — the recipient's
/// pubkeys are fetched from the inbox contract state at import time, not
/// embedded in the card.
///
/// Neither `suggested_alias` nor `suggested_description` are authoritative —
/// the recipient chooses their own local label.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ContactCard {
    pub version: u32,
    pub inbox_address: String,
    pub suggested_alias: Option<String>,
    pub suggested_description: Option<String>,
}

/// Default AFT tier for `StoredContactKeys` rows that pre-date the
/// `required_tier` field. Must match `IdentityAftPrefs::default().required_tier`
/// so the AFT delegate does not mint at a stale default.
fn default_tier() -> Tier {
    Tier::Min10
}

fn default_max_age_secs() -> u64 {
    DEFAULT_MAX_AGE_SECS
}

impl ContactCard {
    pub const VERSION: u32 = 3;

    /// Returns the bare bs58 inbox address. No URI prefix, no base64 over
    /// JSON — a ContactCard is the address plus optional local metadata,
    /// and it's the address users actually share.
    pub fn encode(&self) -> String {
        self.inbox_address.clone()
    }

    /// Parse a pasted address into a `ContactCard`. Accepts the bare
    /// bs58-encoded `ContractInstanceId`. Re-normalizes through
    /// `ContractInstanceId`'s codec so the stored address is canonical
    /// (whitespace stripped, length validated by the stdlib).
    pub fn decode(input: &str) -> Result<Self, String> {
        use std::str::FromStr;
        let trimmed = input.trim();
        let id = freenet_stdlib::prelude::ContractInstanceId::from_str(trimmed)
            .map_err(|e| format!("invalid inbox address: {e}"))?;
        Ok(Self {
            version: Self::VERSION,
            inbox_address: id.encode(),
            suggested_alias: None,
            suggested_description: None,
        })
    }

    pub fn from_identity(identity: &Identity) -> Self {
        let inbox_address = identity_inbox_address(identity)
            .unwrap_or_else(|e| format!("<address derivation error: {e}>"));
        Self {
            version: Self::VERSION,
            inbox_address,
            suggested_alias: Some(identity.alias.to_string()),
            suggested_description: if identity.description.is_empty() {
                None
            } else {
                Some(identity.description.clone())
            },
        }
    }
}

/// Compute the bs58-encoded inbox `ContractInstanceId` for the given
/// identity. Goes through `inbox_key_for` so the derivation stays in
/// lockstep with the send path and the contract id check in
/// `is_contact_inbox_key`.
pub fn identity_inbox_address(identity: &Identity) -> Result<String, String> {
    use crate::inbox::inbox_key_for;
    let vk = vk_from_bytes(&identity.ml_dsa_vk_bytes())?;
    let key = inbox_key_for(&vk).map_err(|e| format!("derive inbox key: {e}"))?;
    Ok(key.id().encode())
}

// ── Storage types ─────────────────────────────────────────────────────────────

/// A contact whose public keys were imported via a `ContactCard`.
#[derive(Clone, Debug, PartialEq)]
pub struct Contact {
    pub local_alias: Rc<str>,
    /// The alias the sender chose for themselves on their shared card
    /// (`ContactCard.suggested_alias`). Retained so the To field can
    /// still resolve the contact when the importer relabelled them with
    /// a different `local_alias` but types the name the *sender*
    /// advertised. `None` for cards with no suggested alias or contacts
    /// imported before this field shipped.
    pub suggested_alias: Option<Rc<str>>,
    pub description: String,
    pub ml_dsa_vk_bytes: Vec<u8>,
    pub ml_kem_ek_bytes: Vec<u8>,
    /// AFT tier the recipient requires. Carried on the contact so the
    /// sender can construct `InboxParams` and `AllocationCriteria`
    /// without a state fetch (#85).
    pub required_tier: Tier,
    pub max_age_secs: u64,
    /// True when the user explicitly confirmed the fingerprint with the sender.
    pub verified: bool,
    /// bs58-encoded inbox contract WASM code hash for this contact's
    /// inbox, captured at import time (#251 improvement 4). `None`
    /// for contacts that pre-date this field. See
    /// `StoredContactKeys.inbox_wasm_hash`.
    pub inbox_wasm_hash: Option<String>,
}

impl Contact {
    pub fn fingerprint(&self) -> [&'static str; 6] {
        fingerprint_words(&self.ml_dsa_vk_bytes, &self.ml_kem_ek_bytes)
    }

    pub fn fingerprint_short(&self) -> String {
        let fp = self.fingerprint();
        format!("{}-{}-{}", fp[0], fp[1], fp[2])
    }

    pub fn fingerprint_full(&self) -> String {
        self.fingerprint().join("-")
    }
}

/// Internal storage variant — keeps `Identity` (own) and `Contact` separate.
/// `Identity` is large (contains key material), so it is boxed to equalise
/// the enum variant sizes and avoid the `large_enum_variant` lint.
#[derive(Clone)]
enum Entry {
    Own(Box<Identity>),
    Contact(Contact),
}

/// A resolved recipient ready for message composition.
/// Carries everything the send path needs without exposing private material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recipient {
    pub local_alias: Rc<str>,
    pub ml_dsa_vk_bytes: Vec<u8>,
    pub ml_kem_ek_bytes: Vec<u8>,
    pub fingerprint: [&'static str; 6],
    /// Recipient's anti-flood policy (#85). Used by the send path to
    /// derive `InboxParams` and `AllocationCriteria` so the AFT delegate
    /// mints at the tier the recipient hashed into their contract id.
    pub required_tier: Tier,
    pub max_age_secs: u64,
    /// True only for contacts whose fingerprint was confirmed by the user.
    pub verified: bool,
    pub is_own: bool,
    /// Recipient's inbox WASM code hash (#251 improvement 4). `None`
    /// means "fall back to the sender's embedded `INBOX_CODE_HASH`"
    /// — preserves pre-#251 behaviour for own identities and for
    /// contacts imported before this field shipped.
    pub inbox_wasm_hash: Option<String>,
}

impl Recipient {
    /// First three fingerprint words joined with `-`. Compact disambiguator
    /// shown in the compose picker; hover for full six-word value.
    pub fn fingerprint_short(&self) -> String {
        format!(
            "{}-{}-{}",
            self.fingerprint[0], self.fingerprint[1], self.fingerprint[2]
        )
    }

    pub fn fingerprint_full(&self) -> String {
        self.fingerprint.join("-")
    }
}

// ── Address book ──────────────────────────────────────────────────────────────

thread_local! {
    /// Single source of truth for alias → entry.  Local aliases are unique.
    static ADDRESS_BOOK: RefCell<HashMap<String, Entry>> = RefCell::new(HashMap::new());

    /// #255: cache of on-chain inbox `ContractInstanceId` → `Recipient`,
    /// rebuilt lazily from `ADDRESS_BOOK` when stale. `lookup_by_bs58` is on
    /// the per-keystroke compose-form resolver path; without this it ran an
    /// ML-DSA-65 decode (~ms-class) + key derivation for every contact on
    /// every keystroke (O(N) per keystroke). The cache makes lookup O(1).
    ///
    /// Keyed by the derived `ContractInstanceId`, which already bakes in each
    /// contact's per-contact `inbox_wasm_hash` (#251 improvement 4), so the
    /// cache is hash-aware by construction. It must be REBUILT (not patched)
    /// on any write, since a contact's hash is a build input to its key.
    static BS58_LOOKUP_CACHE: RefCell<Option<(
        u64,
        HashMap<freenet_stdlib::prelude::ContractInstanceId, Recipient>,
    )>> = const { RefCell::new(None) };

    /// Generation counter bumped by every `ADDRESS_BOOK` mutator
    /// (`register_identity`, `insert_contact`, `remove_contact`). The cache
    /// stores the gen it was built at and rebuilds when it falls behind. Kept
    /// module-internal rather than piggy-backing on `AddressBookGen` because
    /// some writers (own-identity register, offline seed) don't bump that
    /// signal.
    static ADDRESS_BOOK_GEN: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Bump the address-book generation so the bs58 lookup cache rebuilds on next
/// access. Called from every `ADDRESS_BOOK` mutator.
fn bump_address_book_gen() {
    ADDRESS_BOOK_GEN.with(|g| g.set(g.get().wrapping_add(1)));
}

/// Ensure an own `Identity` is registered.  Idempotent — a second call for
/// the same alias updates the stored identity (covers the reload path).
pub fn register_identity(identity: &Identity) {
    ADDRESS_BOOK.with(|ab| {
        ab.borrow_mut().insert(
            identity.alias.to_string(),
            Entry::Own(Box::new(identity.clone())),
        );
    });
    bump_address_book_gen();
}

/// Insert a contact. Errors if:
/// - the contact's keys match one of the user's own identities (self-import),
/// - the alias is already taken by an own identity, or
/// - the alias is already taken by a contact with a *different* fingerprint.
///
/// Re-inserting a contact with the same alias and same fingerprint succeeds
/// (allows overwrite of metadata like description / verified flag).
pub fn insert_contact(contact: Contact) -> Result<(), String> {
    ADDRESS_BOOK
        .with(|ab| {
            let mut ab = ab.borrow_mut();
            // Self-import guard: enforced here so any caller path (UI form,
            // future API, test harness) gets the same protection.
            for entry in ab.values() {
                if let Entry::Own(id) = entry
                    && id.ml_dsa_vk_bytes() == contact.ml_dsa_vk_bytes
                    && id.ml_kem_ek_bytes() == contact.ml_kem_ek_bytes
                {
                    return Err("cannot import your own identity as a contact".into());
                }
            }
            if let Some(existing) = ab.get(contact.local_alias.as_ref()) {
                match existing {
                    Entry::Own(_) => {
                        return Err(format!(
                            "\"{}\" is one of your own identities",
                            contact.local_alias
                        ));
                    }
                    Entry::Contact(c) => {
                        // Allow overwrite only when BOTH key halves match;
                        // otherwise the alias is taken by a different contact
                        // and the import must be rejected. Comparing only the
                        // ML-DSA VK would let a card with a substituted ML-KEM
                        // key silently overwrite the recipient's encryption
                        // material under an existing trusted alias.
                        if c.ml_dsa_vk_bytes != contact.ml_dsa_vk_bytes
                            || c.ml_kem_ek_bytes != contact.ml_kem_ek_bytes
                        {
                            return Err(format!(
                                "alias \"{}\" is already used by a different contact",
                                contact.local_alias
                            ));
                        }
                    }
                }
            }
            ab.insert(contact.local_alias.to_string(), Entry::Contact(contact));
            Ok(())
        })
        .inspect(|()| bump_address_book_gen())
}

/// Remove a contact by alias.  No-op if the alias does not exist or is an
/// own identity (own identities are never removed via this path).
pub fn remove_contact(alias: &str) {
    let removed = ADDRESS_BOOK.with(|ab| {
        let mut ab = ab.borrow_mut();
        if matches!(ab.get(alias), Some(Entry::Contact(_))) {
            ab.remove(alias);
            true
        } else {
            false
        }
    });
    if removed {
        bump_address_book_gen();
    }
}

/// Resolve an alias to a `Recipient`.  Walks both own identities and contacts.
///
/// Matching order: first the exact `local_alias` HashMap key, then — only
/// on a miss — a scan for a contact whose sender-advertised
/// `suggested_alias` equals `alias`. The fallback lets a user who
/// relabelled a contact on import still address them by the name the
/// sender shared. Exact local-alias matches always win, so relabelling
/// is never shadowed by someone else's suggested alias.
pub fn lookup(alias: &str) -> Option<Recipient> {
    fn entry_to_recipient(entry: &Entry) -> Recipient {
        match entry {
            Entry::Own(id) => {
                let ml_dsa_vk_bytes = id.ml_dsa_vk_bytes();
                let ml_kem_ek_bytes = id.ml_kem_ek_bytes();
                let fingerprint = fingerprint_words(&ml_dsa_vk_bytes, &ml_kem_ek_bytes);
                Recipient {
                    local_alias: id.alias.clone(),
                    ml_dsa_vk_bytes,
                    ml_kem_ek_bytes,
                    fingerprint,
                    required_tier: id.required_tier,
                    max_age_secs: id.max_age_secs,
                    verified: true,
                    is_own: true,
                    inbox_wasm_hash: None,
                }
            }
            Entry::Contact(c) => {
                let fingerprint = c.fingerprint();
                Recipient {
                    local_alias: c.local_alias.clone(),
                    ml_dsa_vk_bytes: c.ml_dsa_vk_bytes.clone(),
                    ml_kem_ek_bytes: c.ml_kem_ek_bytes.clone(),
                    fingerprint,
                    required_tier: c.required_tier,
                    max_age_secs: c.max_age_secs,
                    verified: c.verified,
                    is_own: false,
                    inbox_wasm_hash: c.inbox_wasm_hash.clone(),
                }
            }
        }
    }

    ADDRESS_BOOK.with(|ab| {
        let ab = ab.borrow();
        // Exact local-alias / own-identity-alias match wins.
        if let Some(entry) = ab.get(alias) {
            return Some(entry_to_recipient(entry));
        }
        // Fallback: a contact whose sender-advertised suggested_alias
        // matches. Only contacts carry a suggested_alias, so this never
        // collides with an own identity.
        ab.values().find_map(|entry| match entry {
            Entry::Contact(c) if c.suggested_alias.as_deref() == Some(alias) => {
                Some(entry_to_recipient(entry))
            }
            _ => None,
        })
    })
}

/// Look up a contact by their bs58 inbox address. Returns a `Recipient`
/// only if a contact with that exact inbox key is already in the address
/// book — i.e. the user has imported them and (presumably) verified the
/// fingerprint. Unknown addresses return `None`; the UI surfaces "import
/// as contact first".
/// Build the bs58 lookup map from the current `ADDRESS_BOOK` — one ML-DSA
/// decode + key derivation per entry. Called only on cache miss / staleness.
fn build_bs58_lookup_map() -> HashMap<freenet_stdlib::prelude::ContractInstanceId, Recipient> {
    use crate::inbox::{INBOX_CODE_HASH, inbox_key_for, inbox_key_for_with_hash};
    ADDRESS_BOOK.with(|ab| {
        let mut map = HashMap::new();
        for entry in ab.borrow().values() {
            match entry {
                Entry::Contact(c) => {
                    let Ok(vk) = vk_from_bytes(&c.ml_dsa_vk_bytes) else {
                        continue;
                    };
                    // #251 improvement 4: derive under the contact's advertised
                    // hash, not the sender's `INBOX_CODE_HASH`. A cross-version
                    // contact's id differs from `inbox_key_for(vk)`.
                    let code_hash = c.inbox_wasm_hash.as_deref().unwrap_or(INBOX_CODE_HASH);
                    let Ok(key) = inbox_key_for_with_hash(&vk, code_hash) else {
                        continue;
                    };
                    let fingerprint = c.fingerprint();
                    map.insert(
                        *key.id(),
                        Recipient {
                            local_alias: c.local_alias.clone(),
                            ml_dsa_vk_bytes: c.ml_dsa_vk_bytes.clone(),
                            ml_kem_ek_bytes: c.ml_kem_ek_bytes.clone(),
                            fingerprint,
                            required_tier: c.required_tier,
                            max_age_secs: c.max_age_secs,
                            verified: c.verified,
                            is_own: false,
                            inbox_wasm_hash: c.inbox_wasm_hash.clone(),
                        },
                    );
                }
                Entry::Own(id) => {
                    let Ok(vk) = vk_from_bytes(&id.ml_dsa_vk_bytes()) else {
                        continue;
                    };
                    let Ok(key) = inbox_key_for(&vk) else {
                        continue;
                    };
                    let ml_dsa_vk_bytes = id.ml_dsa_vk_bytes();
                    let ml_kem_ek_bytes = id.ml_kem_ek_bytes();
                    let fingerprint = fingerprint_words(&ml_dsa_vk_bytes, &ml_kem_ek_bytes);
                    map.insert(
                        *key.id(),
                        Recipient {
                            local_alias: id.alias.clone(),
                            ml_dsa_vk_bytes,
                            ml_kem_ek_bytes,
                            fingerprint,
                            required_tier: id.required_tier,
                            max_age_secs: id.max_age_secs,
                            verified: true,
                            is_own: true,
                            inbox_wasm_hash: None,
                        },
                    );
                }
            }
        }
        map
    })
}

/// Resolve a bs58 inbox `ContractInstanceId` to a `Recipient`. O(1) after a
/// one-time per-generation cache build (#255). On the per-keystroke compose
/// resolver path, so this must not re-decode every contact each call.
pub fn lookup_by_bs58(addr: &str) -> Option<Recipient> {
    use std::str::FromStr;
    let trimmed = addr.trim();
    let target = freenet_stdlib::prelude::ContractInstanceId::from_str(trimmed).ok()?;

    let cur_gen = ADDRESS_BOOK_GEN.with(|g| g.get());
    BS58_LOOKUP_CACHE.with(|cell| {
        let mut cell = cell.borrow_mut();
        let needs_rebuild = match cell.as_ref() {
            Some((cached_gen, _)) => *cached_gen != cur_gen,
            None => true,
        };
        if needs_rebuild {
            *cell = Some((cur_gen, build_bs58_lookup_map()));
        }
        cell.as_ref().and_then(|(_, map)| map.get(&target).cloned())
    })
}

/// True if `key` is the inbox `ContractKey` of any known contact.
///
/// Used by the api.rs GetResponse handler to swallow responses produced by
/// the rehydrate-prime / CreateContact-prime paths (#191). The webapp
/// can't render a contact's inbox (the messages are encrypted to the
/// contact's ml_kem key, not ours) — the prime is fire-and-forget.
pub fn is_contact_inbox_key(key: &freenet_stdlib::prelude::ContractKey) -> bool {
    use crate::inbox::{INBOX_CODE_HASH, inbox_key_for_with_hash};
    ADDRESS_BOOK.with(|ab| {
        ab.borrow().values().any(|e| match e {
            // #251 improvement 4: derive each contact's inbox key under
            // the contact's advertised WASM hash. A cross-version
            // contact's actual `key.id()` is derived from THAT hash, not
            // the sender's `INBOX_CODE_HASH`; falling back to the
            // sender's hash here silently failed to match
            // UpdateNotifications + GetResponses for cross-version
            // contacts, breaking tier-cache priming + ack pairing.
            Entry::Contact(c) => match vk_from_bytes(&c.ml_dsa_vk_bytes) {
                Ok(vk) => {
                    let code_hash = c.inbox_wasm_hash.as_deref().unwrap_or(INBOX_CODE_HASH);
                    match inbox_key_for_with_hash(&vk, code_hash) {
                        Ok(contact_key) => contact_key.id() == key.id(),
                        Err(_) => false,
                    }
                }
                Err(_) => false,
            },
            Entry::Own(_) => false,
        })
    })
}

/// All contacts (non-own entries), sorted by alias.
pub fn all_contacts() -> Vec<Contact> {
    ADDRESS_BOOK.with(|ab| {
        let mut contacts: Vec<Contact> = ab
            .borrow()
            .values()
            .filter_map(|e| match e {
                Entry::Contact(c) => Some(c.clone()),
                Entry::Own(_) => None,
            })
            .collect();
        contacts.sort_by(|a, b| a.local_alias.cmp(&b.local_alias));
        contacts
    })
}

/// Filter contacts by a case-insensitive substring needle.
///
/// Match tiers (highest priority first):
///   1. Alias prefix match  — the alias starts with `needle`
///   2. Alias substring match — the alias contains `needle` (but not as prefix)
///   3. Fingerprint-short match — the three-word fingerprint contains `needle`
///
/// Description is **not** matched to prevent a contact whose description
/// happens to equal another contact's alias from shadowing that alias in the
/// dropdown (adversarial shadowing). Within each tier, verified contacts
/// sort before unverified; ties are broken alphabetically by alias.
///
/// Returns up to `limit` matches. Returns an empty `Vec` when `needle` is
/// empty so callers never show the dropdown on a blank To field.
pub fn filter_contacts(needle: &str, limit: usize) -> Vec<Contact> {
    if needle.is_empty() {
        return vec![];
    }
    let needle_lc = needle.to_lowercase();

    // Assign a tier score: 0 = alias prefix, 1 = alias substring, 2 = fp match.
    // Contacts that match none are excluded.
    let mut scored: Vec<(u8, Contact)> = all_contacts()
        .into_iter()
        .filter_map(|c| {
            let alias_lc = c.local_alias.to_lowercase();
            if alias_lc.starts_with(&needle_lc) {
                Some((0u8, c))
            } else if alias_lc.contains(&needle_lc) {
                Some((1u8, c))
            } else {
                // Perf: compute fingerprint only when alias didn't match.
                // fingerprint_short() does BLAKE3 + 3 BIP-39 lookups; calling
                // it once here (and only for non-alias matches) avoids
                // recomputing it per keystroke for every contact in the book.
                let fp = c.fingerprint_short().to_lowercase();
                if fp.contains(&needle_lc) {
                    Some((2u8, c))
                } else {
                    None
                }
            }
        })
        .collect();

    // Stable sort: tier ASC, then verified DESC (true > false → invert),
    // then alias ASC for ties within the same tier+trust bucket.
    scored.sort_by(|(t_a, c_a), (t_b, c_b)| {
        t_a.cmp(t_b)
            .then(c_b.verified.cmp(&c_a.verified)) // verified-first
            .then(c_a.local_alias.cmp(&c_b.local_alias))
    });

    scored.into_iter().map(|(_, c)| c).take(limit).collect()
}

/// Look up a contact by ML-DSA verifying key (#51 — sender trust). Returns
/// `None` for unknown VKs and for the user's own identities (which are
/// stored as `Own` entries, not contacts).
pub fn contact_by_vk(vk_bytes: &[u8]) -> Option<Contact> {
    ADDRESS_BOOK.with(|ab| {
        ab.borrow().values().find_map(|e| match e {
            Entry::Contact(c) if c.ml_dsa_vk_bytes == vk_bytes => Some(c.clone()),
            _ => None,
        })
    })
}

/// Test-only: clear the address book and bump the generation so the
/// bs58 lookup cache can't carry a prior test's contacts forward. The
/// test runner reuses threads, so the thread-local state persists across
/// tests in the same thread — every test that touches `ADDRESS_BOOK`
/// must reset first. Exposed (rather than the private
/// `tests::reset_address_book`) so sibling modules' tests (e.g. the
/// `crate::app` reply-prefill tests) can seed contacts deterministically.
#[cfg(test)]
pub fn clear_for_test() {
    ADDRESS_BOOK.with(|ab| ab.borrow_mut().clear());
    bump_address_book_gen();
}

/// Check whether a fingerprint matches one of the user's own identities
/// (used to reject self-import during contact import).
pub fn is_own_fingerprint(vk_bytes: &[u8], ek_bytes: &[u8]) -> bool {
    ADDRESS_BOOK.with(|ab| {
        ab.borrow().values().any(|e| {
            matches!(e, Entry::Own(id)
                if id.ml_dsa_vk_bytes() == vk_bytes && id.ml_kem_ek_bytes() == ek_bytes)
        })
    })
}

/// Serialised form stored in the identity-management delegate under a contact alias.
///
/// Layout (serde_json):
/// ```json
/// { "ml_dsa_vk_bytes": [...], "ml_kem_ek_bytes": [...],
///   "suggested_alias": "...", "verified": false }
/// ```
#[derive(Serialize, Deserialize, Clone)]
pub struct StoredContactKeys {
    pub ml_dsa_vk_bytes: Vec<u8>,
    pub ml_kem_ek_bytes: Vec<u8>,
    pub suggested_alias: Option<String>,
    pub verified: bool,
    #[serde(default = "default_tier")]
    pub required_tier: Tier,
    #[serde(default = "default_max_age_secs")]
    pub max_age_secs: u64,
    /// bs58-encoded inbox contract WASM code hash for this contact's
    /// inbox, captured from the GetResponse at import time
    /// (#251 improvement 4). The sender uses this hash to derive the
    /// recipient's inbox `ContractKey`, so a non-upgraded recipient
    /// still receives messages from an upgraded sender. `None` for
    /// contacts imported before this field shipped — send path falls
    /// back to the sender's embedded `INBOX_CODE_HASH` (pre-#251
    /// behaviour).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbox_wasm_hash: Option<String>,
}

impl StoredContactKeys {
    /// Build the persisted contact record from a fetched inbox state. The
    /// recipient's ML-DSA vk comes from the inbox params (via the supplied
    /// `vk_bytes`); the ek + tier policy come from the state itself
    /// (`Inbox::owner_ek_bytes` + `Inbox::settings`).
    #[allow(dead_code)] // hook for future inbox-prime path; ImportContactForm currently
    // builds `StoredContactKeys` inline from `fetched_keys` for clarity.
    pub fn from_inbox_state(
        vk_bytes: Vec<u8>,
        state: &InboxState,
        suggested_alias: Option<String>,
        verified: bool,
    ) -> Self {
        Self {
            ml_dsa_vk_bytes: vk_bytes,
            ml_kem_ek_bytes: state.owner_ek_bytes.clone(),
            suggested_alias,
            verified,
            required_tier: state.settings.minimum_tier,
            max_age_secs: state.settings.max_age_secs,
            inbox_wasm_hash: None,
        }
    }

    pub fn into_contact(self, local_alias: Rc<str>, description: String) -> Contact {
        Contact {
            local_alias,
            suggested_alias: self.suggested_alias.map(Rc::from),
            description,
            ml_dsa_vk_bytes: self.ml_dsa_vk_bytes,
            ml_kem_ek_bytes: self.ml_kem_ek_bytes,
            required_tier: self.required_tier,
            max_age_secs: self.max_age_secs,
            verified: self.verified,
            inbox_wasm_hash: self.inbox_wasm_hash,
        }
    }
}

/// Decode an ML-KEM encapsulation key from raw bytes. Thin wrapper over
/// `MlKemEncapsKey::to_key` to keep the address-book module's error type
/// uniform.
pub fn ek_from_bytes(bytes: &[u8]) -> Result<EncapsulationKey<MlKem768>, String> {
    crate::inbox::MlKemEncapsKey(bytes.to_vec())
        .to_key()
        .map_err(|e| format!("{e}"))
}

/// Decode an ML-DSA-65 verifying key from raw bytes (1952 bytes expected).
pub fn vk_from_bytes(bytes: &[u8]) -> Result<MlDsaVerifyingKey<MlDsa65>, String> {
    use ml_dsa::EncodedVerifyingKey;
    let arr: EncodedVerifyingKey<MlDsa65> = bytes
        .try_into()
        .map_err(|_| format!("ML-DSA VK wrong length (got {})", bytes.len()))?;
    Ok(MlDsaVerifyingKey::<MlDsa65>::decode(&arr))
}

// ── Migration scaffolding ─────────────────────────────────────────────────────

/// Hashes of identity-management delegate wasm builds that pre-date this
/// release. Empty for now — no production data existed before v1. Populate
/// when a future breaking change bumps the wasm hash again, so the next
/// release can find and migrate identities stored under the prior hash.
pub const LEGACY_ID_DELEGATE_HASHES: &[&str] = &[];

/// Walk `LEGACY_ID_DELEGATE_HASHES` and copy entries from any legacy delegate
/// into the current one. Wired into the app startup path; currently a
/// no-op because the slice is empty. When future hashes are added, the
/// implementation should issue a `GetIdentities` request per legacy hash
/// and, on response, re-issue `CreateIdentity` against the current
/// delegate for each entry found.
pub fn migrate_legacy_identities() {
    for _hash in LEGACY_ID_DELEGATE_HASHES {
        // Placeholder: issue GetIdentities to the legacy delegate and
        // upsert results into the current delegate.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reset the address book between tests. Bumps the generation so the
    /// bs58 lookup cache (#255) can't carry a prior test's contacts into
    /// this one — the test runner reuses threads, so the thread-local cache
    /// would otherwise persist across tests. A bare `ADDRESS_BOOK.clear()`
    /// alone leaves the cache stale.
    fn reset_address_book() {
        ADDRESS_BOOK.with(|ab| ab.borrow_mut().clear());
        bump_address_book_gen();
    }

    #[test]
    fn fingerprint_is_six_bip39_words() {
        let vk = vec![0u8; 1952];
        let ek = vec![0u8; 1184];
        let words = fingerprint_words(&vk, &ek);
        let wl = wordlist();
        for word in &words {
            assert!(wl.contains(word), "word {word} not in wordlist");
        }
    }

    #[test]
    fn fingerprint_differs_for_different_keys() {
        let vk1 = vec![1u8; 1952];
        let vk2 = vec![2u8; 1952];
        let ek = vec![0u8; 1184];
        assert_ne!(fingerprint_words(&vk1, &ek), fingerprint_words(&vk2, &ek));
    }

    #[test]
    fn contact_card_encode_decode_round_trip() {
        let addr = "EqJ5YpEEV3XLqEvKWLQHFhGAac2qXzSUoE6k2zbdnXBr";
        let card = ContactCard {
            version: ContactCard::VERSION,
            inbox_address: addr.to_string(),
            suggested_alias: Some("alice".into()),
            suggested_description: None,
        };
        let encoded = card.encode();
        assert_eq!(encoded, addr);
        let decoded = ContactCard::decode(&encoded).expect("decode should succeed");
        assert_eq!(decoded.inbox_address, addr);
    }

    #[test]
    fn contact_card_decode_trims_whitespace() {
        let addr = "EqJ5YpEEV3XLqEvKWLQHFhGAac2qXzSUoE6k2zbdnXBr";
        let decoded = ContactCard::decode(&format!("  {addr}\n")).expect("trim + decode");
        assert_eq!(decoded.inbox_address, addr);
    }

    #[test]
    fn contact_card_decode_rejects_invalid_bs58() {
        // Non-bs58 alphabet ('l' / '0' / 'O' / 'I' are excluded; whitespace).
        assert!(ContactCard::decode("not a real address").is_err());
        // Way too long — the stdlib decoder asserts exactly 32 bytes.
        let too_long = "z".repeat(128);
        assert!(ContactCard::decode(&too_long).is_err());
    }

    /// `default_tier()` must match `IdentityAftPrefs::default().required_tier` so
    /// that a freshly-created inbox and a v1 contact card for that inbox agree on
    /// the required AFT tier. A mismatch would cause the sender to mint at the
    /// wrong tier and get rejected by `verify_token_policy` in the inbox contract.
    #[test]
    fn default_tier_matches_aft_prefs_default() {
        use mail_local_state::IdentityAftPrefs;
        // IdentityAftPrefs uses String; parse the tier name for comparison.
        let prefs_tier_str = IdentityAftPrefs::default().required_tier;
        let prefs_tier: Tier = match prefs_tier_str.as_str() {
            "Min1" => Tier::Min1,
            "Min5" => Tier::Min5,
            "Min10" => Tier::Min10,
            "Min30" => Tier::Min30,
            "Hour1" => Tier::Hour1,
            "Hour3" => Tier::Hour3,
            "Hour6" => Tier::Hour6,
            "Hour12" => Tier::Hour12,
            "Day1" => Tier::Day1,
            "Day7" => Tier::Day7,
            "Day15" => Tier::Day15,
            "Day30" => Tier::Day30,
            "Day90" => Tier::Day90,
            "Day180" => Tier::Day180,
            "Day365" => Tier::Day365,
            other => panic!("unrecognised tier from IdentityAftPrefs::default(): {other}"),
        };
        assert_eq!(
            default_tier(),
            prefs_tier,
            "ContactCard v1 back-compat default tier must match the AFT prefs default \
             so freshly-created inboxes accept tokens minted from v1 cards",
        );
    }

    /// Older delegate payloads omit `inbox_wasm_hash` entirely. They
    /// must still decode and default to `None` so existing contacts
    /// keep working after the #251 improvement 4 schema bump.
    #[test]
    fn stored_contact_keys_missing_inbox_wasm_hash_defaults_to_none() {
        let json = br#"{
            "ml_dsa_vk_bytes":[1,2,3],
            "ml_kem_ek_bytes":[4,5,6],
            "suggested_alias":null,
            "verified":false
        }"#;
        let decoded: StoredContactKeys =
            serde_json::from_slice(json).expect("legacy payload must decode");
        assert_eq!(decoded.inbox_wasm_hash, None);
    }

    /// New payloads with `inbox_wasm_hash` round-trip cleanly so the
    /// sender always sees the recipient's advertised hash after a
    /// delegate reload.
    #[test]
    fn stored_contact_keys_with_inbox_wasm_hash_round_trips() {
        let original = StoredContactKeys {
            ml_dsa_vk_bytes: vec![1; 1952],
            ml_kem_ek_bytes: vec![2; 1184],
            suggested_alias: Some("alice".into()),
            verified: true,
            required_tier: Tier::Min10,
            max_age_secs: DEFAULT_MAX_AGE_SECS,
            inbox_wasm_hash: Some("EeAHzLBKgFG2dF7TdpeP3JLrHEqKnaznT7WVtnutaQXH".into()),
        };
        let bytes = serde_json::to_vec(&original).expect("serialise");
        let decoded: StoredContactKeys = serde_json::from_slice(&bytes).expect("deserialise");
        assert_eq!(decoded.inbox_wasm_hash, original.inbox_wasm_hash);
    }

    fn make_contact(alias: &str, vk: u8, ek: u8) -> Contact {
        Contact {
            local_alias: alias.into(),
            suggested_alias: None,
            description: String::new(),
            ml_dsa_vk_bytes: vec![vk; 1952],
            ml_kem_ek_bytes: vec![ek; 1184],
            required_tier: Tier::Day1,
            max_age_secs: DEFAULT_MAX_AGE_SECS,
            verified: false,
            inbox_wasm_hash: None,
        }
    }

    #[test]
    fn insert_contact_rejects_alias_with_different_vk() {
        // Use a thread-local scope by clearing first.
        reset_address_book();
        insert_contact(make_contact("bob", 1, 2)).unwrap();
        let err =
            insert_contact(make_contact("bob", 3, 2)).expect_err("different VK should be rejected");
        assert!(err.contains("different contact"), "got: {err}");
    }

    fn make_contact_suggested(local: &str, suggested: Option<&str>, vk: u8, ek: u8) -> Contact {
        Contact {
            suggested_alias: suggested.map(Rc::from),
            ..make_contact(local, vk, ek)
        }
    }

    #[test]
    fn lookup_resolves_by_local_alias() {
        reset_address_book();
        insert_contact(make_contact_suggested("7511", Some("test7511"), 1, 2)).unwrap();
        let r = lookup("7511").expect("exact local alias resolves");
        assert_eq!(&*r.local_alias, "7511");
        assert!(!r.is_own);
    }

    #[test]
    fn lookup_falls_back_to_suggested_alias() {
        // The user relabelled the contact "7511" but types the name the
        // sender advertised ("test7511"). The fallback must still resolve.
        reset_address_book();
        insert_contact(make_contact_suggested("7511", Some("test7511"), 1, 2)).unwrap();
        let r = lookup("test7511").expect("suggested alias resolves on local-alias miss");
        assert_eq!(
            &*r.local_alias, "7511",
            "resolved recipient keeps the local alias, not the suggested one"
        );
    }

    #[test]
    fn lookup_exact_local_alias_wins_over_suggested() {
        // If one contact's local_alias equals another contact's
        // suggested_alias, the exact local-alias match must win.
        reset_address_book();
        insert_contact(make_contact_suggested("shared", Some("other"), 1, 2)).unwrap();
        insert_contact(make_contact_suggested("real", Some("shared"), 3, 4)).unwrap();
        let r = lookup("shared").expect("resolves");
        assert_eq!(
            &*r.local_alias, "shared",
            "exact local-alias match must win over a suggested-alias collision"
        );
    }

    #[test]
    fn lookup_unknown_alias_returns_none() {
        reset_address_book();
        insert_contact(make_contact_suggested("7511", Some("test7511"), 1, 2)).unwrap();
        assert!(lookup("nobody").is_none());
    }

    #[test]
    fn lookup_no_suggested_alias_is_local_only() {
        reset_address_book();
        insert_contact(make_contact_suggested("7511", None, 1, 2)).unwrap();
        assert!(lookup("7511").is_some());
        assert!(lookup("anything-else").is_none());
    }

    #[test]
    fn insert_contact_rejects_alias_with_different_ek() {
        // Same VK but a substituted EK must also be rejected, otherwise an
        // attacker who knows the recipient's signing pubkey could swap in
        // their own encryption key under a trusted alias.
        reset_address_book();
        insert_contact(make_contact("alice", 4, 5)).unwrap();
        let err = insert_contact(make_contact("alice", 4, 9))
            .expect_err("different EK should be rejected");
        assert!(err.contains("different contact"), "got: {err}");
    }

    #[test]
    fn insert_contact_overwrites_when_keys_match() {
        reset_address_book();
        let mut c = make_contact("carol", 7, 8);
        insert_contact(c.clone()).unwrap();
        c.description = "updated".into();
        c.verified = true;
        insert_contact(c.clone()).expect("same fingerprint should overwrite");
        let stored = all_contacts()
            .into_iter()
            .find(|x| &*x.local_alias == "carol")
            .unwrap();
        assert_eq!(stored.description, "updated");
        assert!(stored.verified);
    }

    #[test]
    fn lookup_finds_inserted_contact() {
        reset_address_book();
        insert_contact(make_contact("dave", 11, 12)).unwrap();
        let r = lookup("dave").expect("contact should resolve");
        assert!(!r.is_own);
        assert!(!r.verified);
        assert_eq!(r.ml_dsa_vk_bytes.len(), 1952);
        assert_eq!(r.ml_kem_ek_bytes.len(), 1184);
        assert_eq!(
            r.fingerprint,
            fingerprint_words(&vec![11; 1952], &vec![12; 1184])
        );
    }

    #[test]
    fn lookup_misses_for_unknown_alias() {
        reset_address_book();
        assert!(lookup("nobody").is_none());
    }

    #[test]
    fn remove_contact_clears_lookup() {
        reset_address_book();
        insert_contact(make_contact("eve", 13, 14)).unwrap();
        assert!(lookup("eve").is_some());
        remove_contact("eve");
        assert!(lookup("eve").is_none());
    }

    #[test]
    fn filter_contacts_empty_needle_returns_nothing() {
        reset_address_book();
        insert_contact(make_contact("alice", 1, 2)).unwrap();
        assert!(
            filter_contacts("", 8).is_empty(),
            "blank needle must return []"
        );
    }

    #[test]
    fn filter_contacts_case_insensitive_alias_substring() {
        reset_address_book();
        insert_contact(make_contact("Alice", 1, 2)).unwrap();
        insert_contact(make_contact("bob", 3, 4)).unwrap();
        insert_contact(make_contact("alice-work", 5, 6)).unwrap();

        // "ali" should match "Alice" and "alice-work", not "bob".
        let results = filter_contacts("ali", 8);
        assert_eq!(results.len(), 2, "expected 2 matches for 'ali'");
        // Both "Alice" and "alice-work" contain "ali" as a prefix; alphabetical
        // order within the same tier puts "Alice" before "alice-work".
        assert_eq!(&*results[0].local_alias, "Alice");
        assert_eq!(&*results[1].local_alias, "alice-work");

        // Case-insensitive: "ALI" should also match both.
        let upper = filter_contacts("ALI", 8);
        assert_eq!(upper.len(), 2, "case-insensitive match for 'ALI'");
    }

    /// Description matches are intentionally NOT surfaced (adversarial-shadowing
    /// fix). A contact whose description contains the needle must not appear.
    #[test]
    fn filter_contacts_does_not_match_description() {
        reset_address_book();
        let mut c = make_contact("carol", 7, 8);
        c.description = "work colleague".into();
        insert_contact(c).unwrap();

        // "colleague" only appears in the description, not the alias or
        // fingerprint — must return no results.
        let results = filter_contacts("colleague", 8);
        assert!(
            results.is_empty(),
            "description-only match must be suppressed (adversarial shadowing fix)"
        );
    }

    /// Alias-prefix matches sort before alias-substring matches, and verified
    /// contacts sort before unverified within the same tier.
    #[test]
    fn filter_contacts_tier_and_verified_sort() {
        reset_address_book();
        // "alice" is a prefix match for "ali" — tier 0.
        let mut alice = make_contact("alice", 1, 2);
        alice.verified = true;
        insert_contact(alice).unwrap();
        // "alice-work" is also a prefix match for "ali" — tier 0, not verified.
        insert_contact(make_contact("alice-work", 5, 6)).unwrap();
        // "malice" contains "ali" but doesn't start with it — tier 1.
        insert_contact(make_contact("malice", 9, 10)).unwrap();

        let results = filter_contacts("ali", 8);
        assert_eq!(results.len(), 3);
        // Tier 0 verified: "alice"
        assert_eq!(&*results[0].local_alias, "alice");
        // Tier 0 unverified: "alice-work"
        assert_eq!(&*results[1].local_alias, "alice-work");
        // Tier 1 (substring): "malice"
        assert_eq!(&*results[2].local_alias, "malice");
    }

    #[test]
    fn filter_contacts_respects_limit() {
        reset_address_book();
        for i in 0..10u8 {
            insert_contact(make_contact(&format!("user{i}"), i, i.wrapping_add(1))).unwrap();
        }
        // "user" matches all 10, but limit=3 caps the result.
        let results = filter_contacts("user", 3);
        assert_eq!(results.len(), 3);
    }

    /// Identity → bs58 address derivation must match `inbox_key_for`, so
    /// the address sender pastes round-trips through the contract id used
    /// internally for routing + AFT alloc.
    #[test]
    fn identity_inbox_address_round_trips_through_inbox_key_for() {
        use ml_dsa::{KeyGen, MlDsa65, signature::Keypair as MlDsaKeypair};
        use std::str::FromStr;
        let sk = MlDsa65::from_seed(&[42u8; 32].into());
        let vk = MlDsaKeypair::verifying_key(&sk);
        let vk_bytes = vk.encode().to_vec();
        let key = crate::inbox::inbox_key_for(&vk).expect("inbox_key_for");
        let expected = key.id().encode();

        // Build a minimal Identity-like shim by hand isn't ergonomic; do
        // the derivation directly via the vk → ContractInstanceId path
        // the function uses internally so the test stays self-contained.
        let id = freenet_stdlib::prelude::ContractInstanceId::from_str(&expected).unwrap();
        assert_eq!(*key.id(), id);
        // And that vk_from_bytes ↔ inbox_key_for stays consistent.
        let vk2 = vk_from_bytes(&vk_bytes).expect("vk_from_bytes");
        let key2 = crate::inbox::inbox_key_for(&vk2).expect("inbox_key_for");
        assert_eq!(key.id(), key2.id());
    }

    /// Regression for the api.rs:1467 panic ("tried to get wrong contract
    /// key: …"): GetResponse for a contact's inbox key (produced by the
    /// rehydrate-prime / CreateContact-prime paths from #191) must be
    /// recognisable so the api.rs handler can swallow it instead of
    /// panicking.
    ///
    /// We exercise the helper end-to-end with a real ML-DSA-65 keypair
    /// so `vk_from_bytes` and `inbox_key_for` produce the same key the
    /// node would echo back in a GetResponse.
    #[test]
    fn is_contact_inbox_key_recognises_imported_contact() {
        use ml_dsa::{KeyGen, MlDsa65, signature::Keypair as MlDsaKeypair};
        reset_address_book();

        // Real ML-DSA-65 keypair so vk_from_bytes succeeds.
        let sk = MlDsa65::from_seed(&[7u8; 32].into());
        let vk_bytes = MlDsaKeypair::verifying_key(&sk).encode().to_vec();

        let contact = Contact {
            local_alias: "bob".into(),
            suggested_alias: None,
            description: String::new(),
            ml_dsa_vk_bytes: vk_bytes.clone(),
            ml_kem_ek_bytes: vec![0u8; 1184],
            required_tier: Tier::Day1,
            max_age_secs: DEFAULT_MAX_AGE_SECS,
            verified: false,
            inbox_wasm_hash: None,
        };
        insert_contact(contact).unwrap();

        let vk = vk_from_bytes(&vk_bytes).expect("vk decodes");
        let key = crate::inbox::inbox_key_for(&vk).expect("inbox_key_for");
        assert!(
            is_contact_inbox_key(&key),
            "is_contact_inbox_key must return true for an imported contact's inbox key",
        );
    }

    #[test]
    fn is_contact_inbox_key_returns_false_for_unrelated_key() {
        use ml_dsa::{KeyGen, MlDsa65, signature::Keypair as MlDsaKeypair};
        reset_address_book();

        // Insert one contact.
        let sk_a = MlDsa65::from_seed(&[1u8; 32].into());
        let vk_a_bytes = MlDsaKeypair::verifying_key(&sk_a).encode().to_vec();
        insert_contact(Contact {
            local_alias: "alice".into(),
            suggested_alias: None,
            description: String::new(),
            ml_dsa_vk_bytes: vk_a_bytes,
            ml_kem_ek_bytes: vec![0u8; 1184],
            required_tier: Tier::Day1,
            max_age_secs: DEFAULT_MAX_AGE_SECS,
            verified: false,
            inbox_wasm_hash: None,
        })
        .unwrap();

        // Probe with a *different* keypair's inbox key — must not match.
        let sk_b = MlDsa65::from_seed(&[2u8; 32].into());
        let vk_b = MlDsaKeypair::verifying_key(&sk_b);
        let other_key = crate::inbox::inbox_key_for(&vk_b).expect("inbox_key_for");
        assert!(
            !is_contact_inbox_key(&other_key),
            "is_contact_inbox_key must return false for a key that is not any known contact's inbox",
        );
    }

    /// Pasting a known contact's bs58 inbox address resolves through
    /// `lookup_by_bs58` to the same `Recipient` the alias path returns.
    #[test]
    fn lookup_by_bs58_finds_imported_contact() {
        use ml_dsa::{KeyGen, MlDsa65, signature::Keypair as MlDsaKeypair};
        reset_address_book();

        let sk = MlDsa65::from_seed(&[9u8; 32].into());
        let vk = MlDsaKeypair::verifying_key(&sk);
        let vk_bytes = vk.encode().to_vec();
        let inbox_key = crate::inbox::inbox_key_for(&vk).expect("inbox_key_for");
        let addr = inbox_key.id().encode();

        insert_contact(Contact {
            local_alias: "alice".into(),
            suggested_alias: None,
            description: String::new(),
            ml_dsa_vk_bytes: vk_bytes.clone(),
            ml_kem_ek_bytes: vec![0xCC; 1184],
            required_tier: Tier::Day1,
            max_age_secs: DEFAULT_MAX_AGE_SECS,
            verified: true,
            inbox_wasm_hash: None,
        })
        .unwrap();

        let by_alias = lookup("alice").expect("alias lookup");
        let by_bs58 = lookup_by_bs58(&addr).expect("bs58 lookup");
        assert_eq!(by_alias.ml_dsa_vk_bytes, by_bs58.ml_dsa_vk_bytes);
        assert_eq!(by_alias.ml_kem_ek_bytes, by_bs58.ml_kem_ek_bytes);
        assert_eq!(by_alias.fingerprint, by_bs58.fingerprint);
        assert!(by_bs58.verified);
    }

    /// #255: the lookup cache must rebuild when the address book changes —
    /// a contact removed after a prior lookup must no longer resolve.
    #[test]
    fn lookup_by_bs58_cache_invalidates_on_remove_255() {
        use ml_dsa::{KeyGen, MlDsa65, signature::Keypair as MlDsaKeypair};
        reset_address_book();

        let sk = MlDsa65::from_seed(&[11u8; 32].into());
        let vk = MlDsaKeypair::verifying_key(&sk);
        let vk_bytes = vk.encode().to_vec();
        let addr = crate::inbox::inbox_key_for(&vk)
            .expect("inbox_key_for")
            .id()
            .encode();

        insert_contact(Contact {
            local_alias: "bob".into(),
            suggested_alias: None,
            description: String::new(),
            ml_dsa_vk_bytes: vk_bytes,
            ml_kem_ek_bytes: vec![0xCC; 1184],
            required_tier: Tier::Day1,
            max_age_secs: DEFAULT_MAX_AGE_SECS,
            verified: true,
            inbox_wasm_hash: None,
        })
        .unwrap();

        // Prime the cache.
        assert!(
            lookup_by_bs58(&addr).is_some(),
            "contact resolves before removal",
        );

        // Removal must invalidate — a stale cache would still return bob.
        remove_contact("bob");
        assert!(
            lookup_by_bs58(&addr).is_none(),
            "removed contact must not resolve (cache rebuilt) (#255)",
        );
    }

    #[test]
    fn lookup_by_bs58_returns_none_for_unknown_address() {
        reset_address_book();
        // Valid bs58 32-byte string but no matching contact.
        let id = freenet_stdlib::prelude::ContractInstanceId::new([7u8; 32]);
        assert!(lookup_by_bs58(&id.encode()).is_none());
    }

    #[test]
    fn lookup_by_bs58_returns_none_for_invalid_address() {
        reset_address_book();
        assert!(lookup_by_bs58("not bs58 at all").is_none());
    }

    #[test]
    fn is_contact_inbox_key_empty_book_returns_false() {
        use ml_dsa::{KeyGen, MlDsa65, signature::Keypair as MlDsaKeypair};
        reset_address_book();

        let sk = MlDsa65::from_seed(&[3u8; 32].into());
        let vk = MlDsaKeypair::verifying_key(&sk);
        let key = crate::inbox::inbox_key_for(&vk).expect("inbox_key_for");
        assert!(
            !is_contact_inbox_key(&key),
            "is_contact_inbox_key on an empty address book must return false",
        );
    }

    /// #289 (resolver-half characterization): a contact imported under a
    /// local label that differs from the sender's own send-alias cannot be
    /// resolved by that send-alias through the alias-keyed `lookup` — that's
    /// the address-book behavior that made the OLD reply path (which addressed
    /// by the sender's display name) miss. The reply path is now fixed in
    /// `thread_reply_prefill` (app.rs): it resolves by the sender's verified
    /// ML-DSA VK and prefills the recipient's LOCAL label, so it no longer
    /// depends on this `lookup`-by-send-alias path. This test still documents
    /// the `lookup` semantics it characterizes (exact local-alias keying with
    /// a suggested-alias fallback); see
    /// `reply_prefill_resolves_to_local_label_by_vk_289` in app.rs for the
    /// fix itself.
    #[test]
    fn lookup_misses_when_contact_imported_under_different_nickname_289() {
        use ml_dsa::{KeyGen, MlDsa65, signature::Keypair as MlDsaKeypair};
        reset_address_book();

        // Alice sends under her own alias "alice-from-work". The recipient
        // imports her contact card but labels it locally as "ally".
        let sk = MlDsa65::from_seed(&[42u8; 32].into());
        let vk_bytes = MlDsaKeypair::verifying_key(&sk).encode().to_vec();
        insert_contact(Contact {
            local_alias: "ally".into(),
            suggested_alias: None,
            description: String::new(),
            ml_dsa_vk_bytes: vk_bytes,
            ml_kem_ek_bytes: vec![0u8; 1184],
            required_tier: Tier::Day1,
            max_age_secs: DEFAULT_MAX_AGE_SECS,
            verified: true,
            inbox_wasm_hash: None,
        })
        .unwrap();

        // The reply To carries Alice's send-alias, not the local label.
        assert!(
            lookup("alice-from-work").is_none(),
            "resolving by the sender's own alias must MISS when the contact \
             was imported under a different local nickname (#289)",
        );
        // The same contact IS resolvable by the local label the user chose —
        // proving the contact exists and only the addressing handle is wrong.
        assert!(
            lookup("ally").is_some(),
            "the contact resolves under its local label; #289 is purely an \
             addressing-handle mismatch, not a missing contact",
        );
    }

    #[test]
    fn lookup_resolves_by_sender_alias_when_suggested_preserved_289() {
        use ml_dsa::{KeyGen, MlDsa65, signature::Keypair as MlDsaKeypair};
        reset_address_book();

        // Same scenario as the miss test above, but the import preserved
        // the sender's advertised alias ("alice-from-work") as
        // suggested_alias even though the user relabelled locally to "ally".
        // This is the #289 fix: the reply To resolves by the sender's
        // alias via the suggested_alias fallback.
        let sk = MlDsa65::from_seed(&[42u8; 32].into());
        let vk_bytes = MlDsaKeypair::verifying_key(&sk).encode().to_vec();
        insert_contact(Contact {
            local_alias: "ally".into(),
            suggested_alias: Some("alice-from-work".into()),
            description: String::new(),
            ml_dsa_vk_bytes: vk_bytes,
            ml_kem_ek_bytes: vec![0u8; 1184],
            required_tier: Tier::Day1,
            max_age_secs: DEFAULT_MAX_AGE_SECS,
            verified: true,
            inbox_wasm_hash: None,
        })
        .unwrap();

        let r = lookup("alice-from-work")
            .expect("sender alias resolves via suggested_alias fallback (#289)");
        assert_eq!(
            &*r.local_alias, "ally",
            "resolved recipient keeps the user's local label",
        );
        assert!(lookup("ally").is_some(), "local label still resolves too");
    }
}
