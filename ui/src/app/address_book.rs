//! Local address book — single owner of all alias→entry mappings.
//!
//! Public surface:
//!   - `lookup(alias)` → `Option<Recipient>` — used by the compose picker
//!   - `insert_contact(alias, contact)` / `remove_contact(alias)` — mutators
//!   - `ContactCard` — wire format for sharing / importing contacts
//!   - `fingerprint_words(vk, ek)` — 6-word BIP-39-like fingerprint

use std::{cell::RefCell, collections::HashMap, rc::Rc, sync::OnceLock};

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
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
/// Encoded as `base64(serde_json(ContactCard))`.
///
/// Neither `suggested_alias` nor `suggested_description` are authoritative —
/// the recipient chooses their own local label.
#[derive(Serialize, Deserialize, Clone)]
pub struct ContactCard {
    pub version: u32,
    pub ml_dsa_vk_bytes: Vec<u8>,
    pub ml_kem_ek_bytes: Vec<u8>,
    pub suggested_alias: Option<String>,
    pub suggested_description: Option<String>,
}

impl ContactCard {
    pub const VERSION: u32 = 1;
    /// Wire format uses standard (non-URL-safe) base64; the Playwright
    /// test (email-app.spec.ts) exchanges cards via `btoa()` and relies
    /// on the encodings matching.
    pub const URI_SCHEME: &'static str = "contact://";

    pub fn encode(&self) -> String {
        let json = serde_json::to_vec(self).expect("ContactCard serialization infallible");
        format!("{}{}", Self::URI_SCHEME, B64.encode(&json))
    }

    pub fn decode(input: &str) -> Result<Self, String> {
        // Accept three forms:
        //   1. Full share text:  "verify: word-...\ncontact://<base64>"
        //   2. URI alone:        "contact://<base64>"
        //   3. Bare base64:      "<base64>"
        // For (1) and (2) we slice from the first `contact://` to the end of
        // the line; for (3) we feed the trimmed input straight to base64.
        let trimmed = input.trim();
        let b64 = if let Some(start) = trimmed.find(Self::URI_SCHEME) {
            let rest = &trimmed[start + Self::URI_SCHEME.len()..];
            rest.split_whitespace().next().unwrap_or(rest)
        } else {
            trimmed
        };
        let json = B64.decode(b64).map_err(|e| format!("base64 decode: {e}"))?;
        serde_json::from_slice(&json).map_err(|e| format!("json decode: {e}"))
    }

    pub fn from_identity(identity: &Identity) -> Self {
        Self {
            version: Self::VERSION,
            ml_dsa_vk_bytes: identity.ml_dsa_vk_bytes(),
            ml_kem_ek_bytes: identity.ml_kem_ek_bytes(),
            suggested_alias: Some(identity.alias.to_string()),
            suggested_description: if identity.description.is_empty() {
                None
            } else {
                Some(identity.description.clone())
            },
        }
    }

    pub fn fingerprint(&self) -> [&'static str; 6] {
        fingerprint_words(&self.ml_dsa_vk_bytes, &self.ml_kem_ek_bytes)
    }

    #[allow(dead_code)]
    pub fn fingerprint_short(&self) -> String {
        let fp = self.fingerprint();
        format!("{}-{}", fp[0], fp[1])
    }
}

// ── Storage types ─────────────────────────────────────────────────────────────

/// A contact whose public keys were imported via a `ContactCard`.
#[derive(Clone, Debug)]
pub struct Contact {
    pub local_alias: Rc<str>,
    pub description: String,
    pub ml_dsa_vk_bytes: Vec<u8>,
    pub ml_kem_ek_bytes: Vec<u8>,
    /// True when the user explicitly confirmed the fingerprint with the sender.
    pub verified: bool,
}

impl Contact {
    pub fn fingerprint(&self) -> [&'static str; 6] {
        fingerprint_words(&self.ml_dsa_vk_bytes, &self.ml_kem_ek_bytes)
    }

    pub fn fingerprint_short(&self) -> String {
        let fp = self.fingerprint();
        format!("{}-{}", fp[0], fp[1])
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
    /// True only for contacts whose fingerprint was confirmed by the user.
    pub verified: bool,
    pub is_own: bool,
}

impl Recipient {
    /// First two fingerprint words joined with `-`. Cheap disambiguator
    /// shown in the compose picker.
    pub fn fingerprint_short(&self) -> String {
        format!("{}-{}", self.fingerprint[0], self.fingerprint[1])
    }
}

// ── Address book ──────────────────────────────────────────────────────────────

thread_local! {
    /// Single source of truth for alias → entry.  Local aliases are unique.
    static ADDRESS_BOOK: RefCell<HashMap<String, Entry>> = RefCell::new(HashMap::new());
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
}

/// Insert a contact. Errors if:
/// - the contact's keys match one of the user's own identities (self-import),
/// - the alias is already taken by an own identity, or
/// - the alias is already taken by a contact with a *different* fingerprint.
///
/// Re-inserting a contact with the same alias and same fingerprint succeeds
/// (allows overwrite of metadata like description / verified flag).
pub fn insert_contact(contact: Contact) -> Result<(), String> {
    ADDRESS_BOOK.with(|ab| {
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
}

/// Remove a contact by alias.  No-op if the alias does not exist or is an
/// own identity (own identities are never removed via this path).
pub fn remove_contact(alias: &str) {
    ADDRESS_BOOK.with(|ab| {
        let mut ab = ab.borrow_mut();
        if matches!(ab.get(alias), Some(Entry::Contact(_))) {
            ab.remove(alias);
        }
    });
}

/// Resolve an alias to a `Recipient`.  Walks both own identities and contacts.
pub fn lookup(alias: &str) -> Option<Recipient> {
    ADDRESS_BOOK.with(|ab| {
        ab.borrow().get(alias).map(|entry| match entry {
            Entry::Own(id) => {
                let ml_dsa_vk_bytes = id.ml_dsa_vk_bytes();
                let ml_kem_ek_bytes = id.ml_kem_ek_bytes();
                let fingerprint = fingerprint_words(&ml_dsa_vk_bytes, &ml_kem_ek_bytes);
                Recipient {
                    local_alias: id.alias.clone(),
                    ml_dsa_vk_bytes,
                    ml_kem_ek_bytes,
                    fingerprint,
                    verified: true,
                    is_own: true,
                }
            }
            Entry::Contact(c) => {
                let fingerprint = c.fingerprint();
                Recipient {
                    local_alias: c.local_alias.clone(),
                    ml_dsa_vk_bytes: c.ml_dsa_vk_bytes.clone(),
                    ml_kem_ek_bytes: c.ml_kem_ek_bytes.clone(),
                    fingerprint,
                    verified: c.verified,
                    is_own: false,
                }
            }
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
}

impl StoredContactKeys {
    pub fn from_card(card: &ContactCard, verified: bool) -> Self {
        Self {
            ml_dsa_vk_bytes: card.ml_dsa_vk_bytes.clone(),
            ml_kem_ek_bytes: card.ml_kem_ek_bytes.clone(),
            suggested_alias: card.suggested_alias.clone(),
            verified,
        }
    }

    pub fn into_contact(self, local_alias: Rc<str>, description: String) -> Contact {
        Contact {
            local_alias,
            description,
            ml_dsa_vk_bytes: self.ml_dsa_vk_bytes,
            ml_kem_ek_bytes: self.ml_kem_ek_bytes,
            verified: self.verified,
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
        let card = ContactCard {
            version: 1,
            ml_dsa_vk_bytes: vec![1u8; 10],
            ml_kem_ek_bytes: vec![2u8; 10],
            suggested_alias: Some("alice".into()),
            suggested_description: None,
        };
        let encoded = card.encode();
        assert!(encoded.starts_with("contact://"));
        let decoded = ContactCard::decode(&encoded).expect("decode should succeed");
        assert_eq!(decoded.suggested_alias.as_deref(), Some("alice"));
        assert_eq!(decoded.ml_dsa_vk_bytes, card.ml_dsa_vk_bytes);
    }

    #[test]
    fn contact_card_decode_bare_base64() {
        let card = ContactCard {
            version: 1,
            ml_dsa_vk_bytes: vec![3u8; 10],
            ml_kem_ek_bytes: vec![4u8; 10],
            suggested_alias: None,
            suggested_description: None,
        };
        let encoded = card.encode();
        let bare = encoded.strip_prefix("contact://").unwrap();
        let decoded = ContactCard::decode(bare).expect("bare base64 should decode");
        assert_eq!(decoded.ml_dsa_vk_bytes, card.ml_dsa_vk_bytes);
    }

    fn make_contact(alias: &str, vk: u8, ek: u8) -> Contact {
        Contact {
            local_alias: alias.into(),
            description: String::new(),
            ml_dsa_vk_bytes: vec![vk; 1952],
            ml_kem_ek_bytes: vec![ek; 1184],
            verified: false,
        }
    }

    #[test]
    fn insert_contact_rejects_alias_with_different_vk() {
        // Use a thread-local scope by clearing first.
        ADDRESS_BOOK.with(|ab| ab.borrow_mut().clear());
        insert_contact(make_contact("bob", 1, 2)).unwrap();
        let err =
            insert_contact(make_contact("bob", 3, 2)).expect_err("different VK should be rejected");
        assert!(err.contains("different contact"), "got: {err}");
    }

    #[test]
    fn insert_contact_rejects_alias_with_different_ek() {
        // Same VK but a substituted EK must also be rejected, otherwise an
        // attacker who knows the recipient's signing pubkey could swap in
        // their own encryption key under a trusted alias.
        ADDRESS_BOOK.with(|ab| ab.borrow_mut().clear());
        insert_contact(make_contact("alice", 4, 5)).unwrap();
        let err = insert_contact(make_contact("alice", 4, 9))
            .expect_err("different EK should be rejected");
        assert!(err.contains("different contact"), "got: {err}");
    }

    #[test]
    fn insert_contact_overwrites_when_keys_match() {
        ADDRESS_BOOK.with(|ab| ab.borrow_mut().clear());
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
        ADDRESS_BOOK.with(|ab| ab.borrow_mut().clear());
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
        ADDRESS_BOOK.with(|ab| ab.borrow_mut().clear());
        assert!(lookup("nobody").is_none());
    }

    #[test]
    fn remove_contact_clears_lookup() {
        ADDRESS_BOOK.with(|ab| ab.borrow_mut().clear());
        insert_contact(make_contact("eve", 13, 14)).unwrap();
        assert!(lookup("eve").is_some());
        remove_contact("eve");
        assert!(lookup("eve").is_none());
    }

    #[test]
    fn fingerprint_short_returns_first_two_words_joined() {
        let card = ContactCard {
            version: 1,
            ml_dsa_vk_bytes: vec![17; 1952],
            ml_kem_ek_bytes: vec![19; 1184],
            suggested_alias: None,
            suggested_description: None,
        };
        let fp = card.fingerprint();
        assert_eq!(card.fingerprint_short(), format!("{}-{}", fp[0], fp[1]));
    }

    /// Regression for #73 — fingerprint shown to receiver after import
    /// disagreed with sender's sidebar / share-modal fingerprint. Decoding
    /// a real card captured during QA must reproduce its `verify:` words
    /// byte-for-byte.
    #[test]
    fn contact_card_fixture_round_trip_fingerprint_matches_verify_line() {
        let raw = include_str!("bob_card_fixture.txt");
        let card = ContactCard::decode(raw).expect("fixture decodes");
        let computed = card.fingerprint().join("-");
        let verify_line = raw
            .lines()
            .next()
            .and_then(|l| l.strip_prefix("verify: "))
            .expect("fixture starts with `verify: …`");
        assert_eq!(
            computed, verify_line,
            "card fingerprint must match the verify line embedded in the share text",
        );
    }

    #[test]
    fn contact_card_decode_share_text_with_verify_line() {
        // The Share modal copies a multi-line blob: a `verify:` line for
        // human comparison followed by the `contact://...` URI. The import
        // form must accept the whole blob, not just the URI.
        let card = ContactCard {
            version: 1,
            ml_dsa_vk_bytes: vec![5u8; 10],
            ml_kem_ek_bytes: vec![6u8; 10],
            suggested_alias: Some("alice".into()),
            suggested_description: None,
        };
        let share_text = format!(
            "verify: {}\n{}",
            card.fingerprint().join("-"),
            card.encode()
        );
        let decoded =
            ContactCard::decode(&share_text).expect("share text with verify line should decode");
        assert_eq!(decoded.ml_dsa_vk_bytes, card.ml_dsa_vk_bytes);
    }
}
