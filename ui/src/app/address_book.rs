//! Local address book — single owner of all alias→entry mappings.
//!
//! Public surface:
//!   - `lookup(alias)` → `Option<Recipient>` — used by the compose picker
//!   - `insert_contact(alias, contact)` / `remove_contact(alias)` — mutators
//!   - `ContactCard` — wire format for sharing / importing contacts
//!   - `fingerprint_words(vk, ek)` — 6-word BIP-39-like fingerprint

use std::{cell::RefCell, collections::HashMap, rc::Rc};

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use ml_dsa::{MlDsa65, VerifyingKey as MlDsaVerifyingKey};
use ml_kem::{EncapsulationKey, MlKem768};
use serde::{Deserialize, Serialize};

use crate::app::login::Identity;

// ── BIP-39 wordlist (2048 words) ─────────────────────────────────────────────
//
// We embed only the English BIP-39 wordlist to derive a 6-word fingerprint
// from BLAKE3(vk_bytes || ek_bytes). The words are included verbatim from
// the canonical list (https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt).
// 66 bits of entropy; adequate for casual verbal confirmation.
const BIP39_WORDS: &str = include_str!("bip39_english.txt");

thread_local! {
    static WORDLIST: RefCell<Option<Vec<&'static str>>> = const { RefCell::new(None) };
}

fn wordlist() -> &'static [&'static str] {
    // SAFETY: BIP39_WORDS is 'static and we only ever return slices into it.
    // The Vec is stored in the thread-local for the lifetime of the thread.
    WORDLIST.with(|wl| {
        let mut wl = wl.borrow_mut();
        if wl.is_none() {
            let words: Vec<&'static str> = BIP39_WORDS
                .split_whitespace()
                // SAFETY: the static str lives for the program duration
                .map(|w| unsafe { std::mem::transmute::<&str, &'static str>(w) })
                .collect();
            *wl = Some(words);
        }
    });
    WORDLIST.with(|wl| {
        let wl = wl.borrow();
        let slice = wl.as_deref().unwrap();
        // Return a raw-pointer-backed slice that has the 'static lifetime of the content.
        // Safe because the Vec is never dropped while the thread is alive.
        unsafe { std::slice::from_raw_parts(slice.as_ptr(), slice.len()) }
    })
}

/// Derive a 6-word fingerprint from the concatenation of the ML-DSA verifying
/// key and ML-KEM encapsulation key bytes.  Uses BLAKE3 as the hash function
/// and the BIP-39 English wordlist to encode groups of 11 bits.
pub fn fingerprint_words(vk_bytes: &[u8], ek_bytes: &[u8]) -> [String; 6] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(vk_bytes);
    hasher.update(ek_bytes);
    let hash = hasher.finalize();
    let bytes = hash.as_bytes();

    let wl = wordlist();
    assert_eq!(
        wl.len(),
        2048,
        "BIP-39 wordlist must have exactly 2048 words"
    );

    // Extract 6 × 11-bit indices from the first 9 bytes (66 bits).
    let bits = |byte_offset: usize, bit_offset: usize| -> usize {
        let lo = bytes[byte_offset] as usize;
        let hi = if byte_offset + 1 < bytes.len() {
            bytes[byte_offset + 1] as usize
        } else {
            0
        };
        let wide = (lo << 8) | hi;
        (wide >> (5 - bit_offset)) & 0x7FF
    };

    // Unpack 11-bit windows: bits [0..11), [11..22), [22..33), [33..44), [44..55), [55..66)
    let idx0 = ((bytes[0] as usize) << 3) | ((bytes[1] as usize) >> 5);
    let idx1 = ((bytes[1] as usize & 0x1F) << 6) | ((bytes[2] as usize) >> 2);
    let idx2 =
        ((bytes[2] as usize & 0x03) << 9) | ((bytes[3] as usize) << 1) | ((bytes[4] as usize) >> 7);
    let idx3 = ((bytes[4] as usize & 0x7F) << 4) | ((bytes[5] as usize) >> 4);
    let idx4 = ((bytes[5] as usize & 0x0F) << 7) | ((bytes[6] as usize) >> 1);
    let idx5 = ((bytes[6] as usize & 0x01) << 10)
        | ((bytes[7] as usize) << 2)
        | ((bytes[8] as usize) >> 6);

    let _ = bits; // suppress unused warning
    [
        wl[idx0 & 0x7FF].to_string(),
        wl[idx1 & 0x7FF].to_string(),
        wl[idx2 & 0x7FF].to_string(),
        wl[idx3 & 0x7FF].to_string(),
        wl[idx4 & 0x7FF].to_string(),
        wl[idx5 & 0x7FF].to_string(),
    ]
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
    pub const URI_SCHEME: &'static str = "contact://";

    /// Encode as `contact://<base64(serde_json)>`.
    pub fn encode(&self) -> String {
        let json = serde_json::to_vec(self).expect("ContactCard serialization infallible");
        format!("{}{}", Self::URI_SCHEME, B64.encode(&json))
    }

    /// Parse `contact://<base64>` or a bare base64 blob.
    pub fn decode(input: &str) -> Result<Self, String> {
        let b64 = input
            .trim()
            .strip_prefix(Self::URI_SCHEME)
            .unwrap_or(input.trim());
        let json = B64.decode(b64).map_err(|e| format!("base64 decode: {e}"))?;
        serde_json::from_slice(&json).map_err(|e| format!("json decode: {e}"))
    }

    /// Derive the 6-word fingerprint for this card.
    pub fn fingerprint(&self) -> [String; 6] {
        fingerprint_words(&self.ml_dsa_vk_bytes, &self.ml_kem_ek_bytes)
    }

    /// Format the first two fingerprint words as `word-word`.
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
    pub fn fingerprint(&self) -> [String; 6] {
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
#[derive(Clone, Debug)]
pub struct Recipient {
    pub local_alias: Rc<str>,
    pub ml_dsa_vk_bytes: Vec<u8>,
    pub ml_kem_ek_bytes: Vec<u8>,
    pub fingerprint: [String; 6],
    /// True only for contacts whose fingerprint was confirmed by the user.
    #[allow(dead_code)]
    pub verified: bool,
    #[allow(dead_code)]
    pub is_own: bool,
}

impl Recipient {
    /// Display label for the compose picker: `alias (word-word)`.
    #[allow(dead_code)]
    pub fn display_label(&self) -> String {
        format!(
            "{} ({}-{})",
            self.local_alias, self.fingerprint[0], self.fingerprint[1]
        )
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

/// Insert a contact.  Returns an error string if the alias is already taken
/// by a *different* fingerprint (allows overwrite of the same fingerprint).
pub fn insert_contact(contact: Contact) -> Result<(), String> {
    ADDRESS_BOOK.with(|ab| {
        let mut ab = ab.borrow_mut();
        if let Some(existing) = ab.get(contact.local_alias.as_ref()) {
            match existing {
                Entry::Own(_) => {
                    return Err(format!(
                        "\"{}\" is one of your own identities",
                        contact.local_alias
                    ));
                }
                Entry::Contact(c) => {
                    // Allow overwrite only when fingerprint matches.
                    if c.ml_dsa_vk_bytes != contact.ml_dsa_vk_bytes {
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
                use ml_kem::kem::KeyExport;
                let ml_kem_ek_bytes = id.ml_kem_dk.encapsulation_key().to_bytes().to_vec();
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

/// Check whether a fingerprint matches one of the user's own identities
/// (used to reject self-import during contact import).
pub fn is_own_fingerprint(vk_bytes: &[u8], ek_bytes: &[u8]) -> bool {
    ADDRESS_BOOK.with(|ab| {
        ab.borrow().values().any(|e| {
            if let Entry::Own(id) = e {
                use ml_kem::kem::KeyExport;
                id.ml_dsa_vk_bytes() == vk_bytes
                    && id.ml_kem_dk.encapsulation_key().to_bytes().as_slice() == ek_bytes
            } else {
                false
            }
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

/// ML-KEM encapsulation key from raw bytes for use in the send path.
pub fn ek_from_bytes(bytes: &[u8]) -> Result<EncapsulationKey<MlKem768>, String> {
    use ml_kem::kem::Key;
    let arr: Key<EncapsulationKey<MlKem768>> =
        Key::<EncapsulationKey<MlKem768>>::try_from(bytes)
            .map_err(|_| format!("ML-KEM EK wrong length (got {})", bytes.len()))?;
    EncapsulationKey::<MlKem768>::new(&arr).map_err(|e| format!("ML-KEM EK decode: {e:?}"))
}

/// ML-DSA verifying key from raw bytes for use in the send path.
pub fn vk_from_bytes(bytes: &[u8]) -> Result<MlDsaVerifyingKey<MlDsa65>, String> {
    use ml_dsa::EncodedVerifyingKey;
    let arr: EncodedVerifyingKey<MlDsa65> = bytes
        .try_into()
        .map_err(|_| format!("ML-DSA VK wrong length (got {})", bytes.len()))?;
    Ok(MlDsaVerifyingKey::<MlDsa65>::decode(&arr))
}

// ── Migration scaffolding ─────────────────────────────────────────────────────

/// Hashes of identity-management delegate wasm builds that pre-date this
/// release.  Empty for now — no production data existed before v1.
/// Populate when future breaking changes bump the wasm hash again.
#[allow(dead_code)]
pub const LEGACY_ID_DELEGATE_HASHES: &[&str] = &[];

/// Walk `LEGACY_ID_DELEGATE_HASHES` and copy entries from any legacy delegate
/// into the current one.  Currently a no-op because the slice is empty.
///
/// Implementation note: when future hashes are added, this function should
/// issue a `GetIdentities` request per legacy hash and, on response, re-issue
/// `CreateIdentity` to the current delegate for each entry found.
#[allow(dead_code)]
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
            assert!(wl.contains(&word.as_str()), "word {word} not in wordlist");
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
}
