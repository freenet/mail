//! Copyable recovery key for an identity's private keys.
//!
//! The recovery key is a single line of text meant to be pasted into a
//! password manager:
//!
//! ```text
//! fmail-key-1:<base58 payload>
//! ```
//!
//! where the payload is
//!
//! ```text
//! [0x01 version][ml_dsa_seed: 32 B][ml_kem_seed: 64 B][checksum: 4 B]
//! ```
//!
//! and `checksum` is the first four bytes of
//! `SHA-256(b"fmail-key-1:" || version || ml_dsa_seed || ml_kem_seed)`.
//! Hashing the prefix in means a payload lifted from some other format
//! that happens to share the byte layout will not validate here.
//!
//! The token carries ONLY the two seeds. Alias and description are local
//! labels. The format is pinned by a fixed test vector below. Changing the
//! layout means a new prefix (`fmail-key-2:`), never a silent
//! reinterpretation of `fmail-key-1:`.
//!
//! Shared by the UI (restore form) and the mail delegate (import and export),
//! so there is one implementation of the format.

use sha2::{Digest, Sha256};

use crate::{DsaSeed, KemSeed};

/// Full prefix of a current recovery key, including the separator.
pub const TOKEN_PREFIX: &str = "fmail-key-1:";
/// Prefix stem shared by every recovery-key version. Used to tell "a
/// recovery key from a newer build" apart from "not a recovery key".
const PREFIX_STEM: &str = "fmail-key-";
/// Version byte inside the payload. Mirrors the `1` in the prefix.
const PAYLOAD_VERSION: u8 = 1;
pub const ML_DSA_SEED_LEN: usize = 32;
pub const ML_KEM_SEED_LEN: usize = 64;
const CHECKSUM_LEN: usize = 4;
/// Version byte + both seeds.
const BODY_LEN: usize = 1 + ML_DSA_SEED_LEN + ML_KEM_SEED_LEN;
/// Decoded payload length: body + checksum.
pub const PAYLOAD_LEN: usize = BODY_LEN + CHECKSUM_LEN;
/// Longest whitespace-stripped input `decode` will try to base58-decode. A
/// real key is ~150 characters; base58 decoding is quadratic and runs on
/// every keystroke in the restore form, so anything far longer is rejected
/// up front rather than decoded.
pub const MAX_TOKEN_CHARS: usize = 512;

/// Why a pasted recovery key was rejected. Each variant maps to a message a
/// user can act on (see the `Display` impl).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    /// Nothing but whitespace.
    Empty,
    /// Doesn't start with `fmail-key-`: some other kind of text.
    WrongPrefix,
    /// A recovery key, but from a format version this build doesn't know.
    UnknownVersion(String),
    /// A character outside the base58 alphabet (often `0`, `O`, `I`, `l`).
    BadBase58,
    /// Decoded to the wrong number of bytes: truncated or has extra text.
    WrongLength { got: usize },
    /// Far longer than any recovery key; not decoded at all.
    TooLong,
    /// Right length, wrong checksum: a character was changed.
    BadChecksum,
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenError::Empty => write!(f, "Paste your recovery key first."),
            TokenError::WrongPrefix => write!(
                f,
                "This isn't a Freenet Mail recovery key. Recovery keys start with \
                 \"{TOKEN_PREFIX}\"."
            ),
            TokenError::UnknownVersion(v) => write!(
                f,
                "This recovery key uses format version {v}, which this version of \
                 Freenet Mail can't read. Update the app and try again."
            ),
            TokenError::BadBase58 => write!(
                f,
                "This recovery key contains a character that can't appear in one. \
                 Copy it again from your password manager rather than retyping it."
            ),
            TokenError::WrongLength { got } => {
                if *got < PAYLOAD_LEN {
                    write!(
                        f,
                        "This recovery key is too short. Part of it is missing; copy \
                         the whole line again."
                    )
                } else {
                    write!(
                        f,
                        "This recovery key is too long. Extra text was pasted with it; \
                         copy just the key."
                    )
                }
            }
            TokenError::TooLong => write!(
                f,
                "This is much longer than a recovery key. Paste just the line that \
                 starts with \"{TOKEN_PREFIX}\"."
            ),
            TokenError::BadChecksum => write!(
                f,
                "This recovery key doesn't check out: at least one character is \
                 wrong. Copy it again from your password manager."
            ),
        }
    }
}

/// The 4-byte checksum over `body` (version byte and both seeds).
pub fn checksum(body: &[u8]) -> [u8; CHECKSUM_LEN] {
    let mut h = Sha256::new();
    h.update(TOKEN_PREFIX.as_bytes());
    h.update(body);
    let digest = h.finalize();
    let mut out = [0u8; CHECKSUM_LEN];
    out.copy_from_slice(&digest[..CHECKSUM_LEN]);
    out
}

/// Encode an identity's seeds as a recovery key.
pub fn encode(dsa: &DsaSeed, kem: &KemSeed) -> String {
    let mut payload = Vec::with_capacity(PAYLOAD_LEN);
    payload.push(PAYLOAD_VERSION);
    payload.extend_from_slice(&dsa.0);
    payload.extend_from_slice(&kem.0);
    let sum = checksum(&payload);
    payload.extend_from_slice(&sum);
    format!("{TOKEN_PREFIX}{}", bs58::encode(payload).into_string())
}

/// Decode a recovery key back into the identity's seeds.
///
/// Tolerates what password managers, notes apps and chat apps do to pasted
/// text: all whitespace is removed first (leading/trailing, CR/LF line
/// wrapping, spaces, tabs), wherever it appears, and the `fmail-key-1:`
/// prefix is matched case-insensitively (phones auto-capitalise it). The
/// base58 payload stays case-sensitive: case is meaningful there.
pub fn decode(text: &str) -> Result<(DsaSeed, KemSeed), TokenError> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.is_empty() {
        return Err(TokenError::Empty);
    }
    if compact.len() > MAX_TOKEN_CHARS {
        return Err(TokenError::TooLong);
    }
    let Some(encoded) = strip_prefix_ignore_case(&compact, TOKEN_PREFIX) else {
        // Distinguish a newer-format key from unrelated text.
        if let Some(rest) = strip_prefix_ignore_case(&compact, PREFIX_STEM)
            && let Some((version, _)) = rest.split_once(':')
            && !version.is_empty()
            && version.chars().all(|c| c.is_ascii_digit())
        {
            return Err(TokenError::UnknownVersion(version.to_string()));
        }
        return Err(TokenError::WrongPrefix);
    };
    let payload = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| TokenError::BadBase58)?;
    if payload.len() != PAYLOAD_LEN {
        return Err(TokenError::WrongLength { got: payload.len() });
    }
    let (body, sum) = payload.split_at(BODY_LEN);
    if checksum(body) != sum {
        return Err(TokenError::BadChecksum);
    }
    if body[0] != PAYLOAD_VERSION {
        return Err(TokenError::UnknownVersion(body[0].to_string()));
    }
    let mut dsa = [0u8; ML_DSA_SEED_LEN];
    let mut kem = [0u8; ML_KEM_SEED_LEN];
    dsa.copy_from_slice(&body[1..1 + ML_DSA_SEED_LEN]);
    kem.copy_from_slice(&body[1 + ML_DSA_SEED_LEN..]);
    Ok((DsaSeed(dsa), KemSeed(kem)))
}

/// `s` without `prefix`, comparing the prefix ASCII-case-insensitively.
fn strip_prefix_ignore_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &s[prefix.len()..])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (DsaSeed, KemSeed) {
        let mut dsa = [0u8; 32];
        let mut kem = [0u8; 64];
        for (i, b) in dsa.iter_mut().enumerate() {
            *b = i as u8;
        }
        for (i, b) in kem.iter_mut().enumerate() {
            *b = 100 + i as u8;
        }
        (DsaSeed(dsa), KemSeed(kem))
    }

    /// The same vector the UI's backup tests pin (#349): if this changes,
    /// every recovery key users have saved stops working.
    const FIXTURE_TOKEN: &str = "fmail-key-1:Ax4ijNhMohvn7t2FBdYENew4FSw2LERAQm36723fcqM8q2fzYT4re5MvYhBJjLckN1iBpybsSW4VW6UKgwBEkRspZvMH5LEzKcGe2Ag9k86C7eHeaB7UE3cVEroRp8wMbwxywGL95";

    #[test]
    fn the_fixed_vector_encodes_and_decodes() {
        let (dsa, kem) = fixture();
        assert_eq!(encode(&dsa, &kem), FIXTURE_TOKEN);
        assert_eq!(decode(FIXTURE_TOKEN).unwrap(), (dsa, kem));
    }

    #[test]
    fn a_changed_character_fails_the_checksum() {
        let mut s = FIXTURE_TOKEN.to_string();
        let last = s.pop().unwrap();
        s.push(if last == '5' { '6' } else { '5' });
        assert_eq!(decode(&s), Err(TokenError::BadChecksum));
    }

    #[test]
    fn whitespace_and_prefix_case_are_tolerated() {
        let messy = format!(
            "  FMAIL-KEY-1:{}\n{} ",
            &FIXTURE_TOKEN[12..60],
            &FIXTURE_TOKEN[60..]
        );
        assert_eq!(decode(&messy).unwrap(), fixture());
    }

    #[test]
    fn a_newer_version_is_named() {
        assert_eq!(
            decode("fmail-key-2:abc"),
            Err(TokenError::UnknownVersion("2".into()))
        );
        assert_eq!(decode("hello"), Err(TokenError::WrongPrefix));
        assert_eq!(decode("   "), Err(TokenError::Empty));
    }
}
