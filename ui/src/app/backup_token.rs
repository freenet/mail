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
//! labels; the restore form asks for them. The format is pinned by a fixed
//! test vector below. Changing the layout means a new prefix
//! (`fmail-key-2:`), never a silent reinterpretation of `fmail-key-1:`.
//!
//! [`parse_backup`] is the single entry point for restore: it accepts a
//! recovery key or the legacy v2 JSON backup file (kept readable forever).

use freenet_mail_protocol::recovery_key;
#[cfg(test)]
use freenet_mail_protocol::{DsaSeed, KemSeed};

use super::login::{IDENTITY_BACKUP_VERSION, IdentityBackup, StoredIdentityKeys};

// The format itself lives in freenet-mail-protocol, shared with the mail
// delegate, so there is exactly one implementation of `fmail-key-1:`.
#[cfg(test)]
use recovery_key::{MAX_TOKEN_CHARS, checksum};
use recovery_key::{ML_DSA_SEED_LEN, ML_KEM_SEED_LEN};
pub(crate) use recovery_key::{PAYLOAD_LEN, TOKEN_PREFIX, TokenError};

/// Encode an identity's seeds as a recovery key.
///
/// Fails only if `keys` holds seeds of the wrong length, which a
/// `StoredIdentityKeys` built from real keys never does.
#[cfg(test)]
pub(crate) fn encode(keys: &StoredIdentityKeys) -> Result<String, TokenError> {
    let wrong_length = || TokenError::WrongLength {
        got: 1 + keys.ml_dsa_seed.len() + keys.ml_kem_seed.len() + 4,
    };
    let dsa: [u8; ML_DSA_SEED_LEN] = keys
        .ml_dsa_seed
        .as_slice()
        .try_into()
        .map_err(|_| wrong_length())?;
    let kem: [u8; ML_KEM_SEED_LEN] = keys
        .ml_kem_seed
        .as_slice()
        .try_into()
        .map_err(|_| wrong_length())?;
    Ok(recovery_key::encode(&DsaSeed(dsa), &KemSeed(kem)))
}

/// Decode a recovery key back into the identity's seeds. See
/// [`recovery_key::decode`] for what it tolerates.
pub(crate) fn decode(text: &str) -> Result<StoredIdentityKeys, TokenError> {
    let (dsa, kem) = recovery_key::decode(text)?;
    Ok(StoredIdentityKeys {
        ml_dsa_seed: dsa.0.to_vec(),
        ml_kem_seed: kem.0.to_vec(),
    })
}

/// Whether restore input that failed to parse could still become valid by
/// typing more: it is empty, the start of `fmail-key-1:`, a recovery key
/// that is still too short, or the start of a JSON object. The restore form
/// uses this to hold back the error while someone types a key by hand;
/// pasted input is always checked at once.
pub(crate) fn may_be_incomplete(text: &str, err: &BackupParseError) -> bool {
    match err {
        BackupParseError::Token(TokenError::Empty) => true,
        BackupParseError::Token(TokenError::WrongPrefix) => {
            let compact: String = text
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect::<String>()
                .to_ascii_lowercase();
            TOKEN_PREFIX.starts_with(compact.as_str())
        }
        BackupParseError::Token(TokenError::WrongLength { got }) => *got < PAYLOAD_LEN,
        BackupParseError::InvalidJson => text.trim_start().starts_with('{'),
        _ => false,
    }
}

/// Whether an edit to the restore box is typing (as opposed to a paste,
/// drop or autofill). `input_type` is the DOM `InputEvent.inputType` when
/// available. Bulk insertions are recognised by type, so replacing a
/// selection with a pasted string of similar length still counts as a
/// paste; and anything that grows the text by more than one character is
/// bulk whatever its type (some automation and IMEs report `insertText`).
pub(crate) fn is_typed_edit(input_type: Option<&str>, prev_chars: usize, new_chars: usize) -> bool {
    let bulk_type = matches!(
        input_type,
        Some(
            "insertFromPaste"
                | "insertFromPasteAsQuotation"
                | "insertFromDrop"
                | "insertReplacementText"
                | "insertFromYank"
        )
    );
    !bulk_type && new_chars <= prev_chars + 1
}

/// Which of the restore form's (alias, description) fields to keep when the
/// input switches from a JSON backup to a recovery key. A field is cleared
/// only if it still holds the value the backup filled in; anything the user
/// has since typed is kept.
pub(crate) fn names_to_keep(current: (&str, &str), from_backup: (&str, &str)) -> (bool, bool) {
    (current.0 != from_backup.0, current.1 != from_backup.1)
}

/// Why restore input was rejected. `Display` gives the user-facing text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BackupParseError {
    /// The input looked like a recovery key (or wasn't JSON) and failed to
    /// decode as one.
    Token(TokenError),
    /// The input started with `{` but isn't a readable backup file.
    InvalidJson,
    /// A JSON backup from a format version we can no longer restore (v1
    /// predates the post-quantum key switch).
    UnsupportedJsonVersion(u32),
    /// A JSON backup whose key fields are the wrong size.
    BadKeyLength,
    /// Larger than any backup this app writes.
    TooLarge,
    /// A JSON backup whose alias or description is longer than the mail
    /// delegate accepts.
    NamesTooLong,
}

impl std::fmt::Display for BackupParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackupParseError::Token(e) => e.fmt(f),
            BackupParseError::InvalidJson => write!(
                f,
                "This file isn't a Freenet Mail backup. Pick the .json or .txt file \
                 you exported, or paste your recovery key."
            ),
            BackupParseError::UnsupportedJsonVersion(v) if *v < IDENTITY_BACKUP_VERSION => write!(
                f,
                "This backup (format v{v}) was made by an early pre-release and can't \
                 be restored. Its keys are no longer supported; create a new identity \
                 instead."
            ),
            BackupParseError::UnsupportedJsonVersion(v) => write!(
                f,
                "This backup uses format v{v}, which this version of Freenet Mail \
                 can't read. Update the app and try again."
            ),
            BackupParseError::BadKeyLength => write!(
                f,
                "This backup file is damaged: its key data is the wrong size."
            ),
            BackupParseError::TooLarge => write!(
                f,
                "This is far larger than a Freenet Mail backup. Pick the .json or .txt \
                 file you exported, or paste your recovery key."
            ),
            BackupParseError::NamesTooLong => write!(
                f,
                "This backup's alias or description is too long (at most \
                 {MAX_ALIAS_CHARS} and {MAX_DESCRIPTION_CHARS} characters)."
            ),
        }
    }
}

/// The most restore input (pasted or read from a file) that is parsed. A
/// recovery key is under 200 bytes and a JSON backup a few KiB.
pub(crate) const MAX_RESTORE_INPUT_BYTES: usize = 64 * 1024;
/// The mail delegate's limits on an identity's names.
pub(crate) const MAX_ALIAS_CHARS: usize = 64;
pub(crate) const MAX_DESCRIPTION_CHARS: usize = 1024;

/// Parse anything the restore form accepts: a recovery key, or a v2 JSON
/// backup file. Input whose first non-whitespace character is `{` takes
/// the JSON path; everything else is treated as a recovery key.
///
/// A recovery key yields empty `alias` / `description`; the restore form
/// asks for them. The returned backup always has seeds of the correct
/// length, so `ml_dsa_signing_key()` / `ml_kem_dk()` will not panic on it.
pub(crate) fn parse_backup(text: &str) -> Result<IdentityBackup, BackupParseError> {
    if text.len() > MAX_RESTORE_INPUT_BYTES {
        return Err(BackupParseError::TooLarge);
    }
    let trimmed = text.trim();
    if trimmed.starts_with('{') {
        let backup = parse_json_backup(trimmed)?;
        if backup.alias.chars().count() > MAX_ALIAS_CHARS
            || backup.description.chars().count() > MAX_DESCRIPTION_CHARS
        {
            return Err(BackupParseError::NamesTooLong);
        }
        return Ok(backup);
    }
    let keys = decode(trimmed).map_err(BackupParseError::Token)?;
    Ok(IdentityBackup {
        version: IDENTITY_BACKUP_VERSION,
        alias: String::new(),
        description: String::new(),
        keys,
    })
}

fn parse_json_backup(text: &str) -> Result<IdentityBackup, BackupParseError> {
    // Read the version first so an old-format file gets a version error
    // instead of a generic "not a backup" from a failed full parse.
    #[derive(serde::Deserialize)]
    struct VersionProbe {
        version: Option<u32>,
    }
    let probe: VersionProbe =
        serde_json::from_str(text).map_err(|_| BackupParseError::InvalidJson)?;
    match probe.version {
        Some(IDENTITY_BACKUP_VERSION) => {}
        Some(v) => return Err(BackupParseError::UnsupportedJsonVersion(v)),
        None => return Err(BackupParseError::InvalidJson),
    }
    let backup: IdentityBackup =
        serde_json::from_str(text).map_err(|_| BackupParseError::InvalidJson)?;
    if backup.keys.ml_dsa_seed.len() != ML_DSA_SEED_LEN
        || backup.keys.ml_kem_seed.len() != ML_KEM_SEED_LEN
    {
        return Err(BackupParseError::BadKeyLength);
    }
    Ok(backup)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Seeds used by the fixed test vector and the committed JSON fixture
    /// (`testdata/identity-backup-v2.json`).
    fn fixture_keys() -> StoredIdentityKeys {
        StoredIdentityKeys {
            ml_dsa_seed: (0u8..32).collect(),
            ml_kem_seed: (100u8..164).collect(),
        }
    }

    #[test]
    fn oversized_restore_input_is_refused_unparsed() {
        let huge = format!("{FIXTURE_TOKEN}{}", " ".repeat(MAX_RESTORE_INPUT_BYTES));
        assert!(matches!(
            parse_backup(&huge),
            Err(BackupParseError::TooLarge)
        ));
        assert!(parse_backup(FIXTURE_TOKEN).is_ok());
    }

    #[test]
    fn a_json_backup_with_overlong_names_is_refused() {
        let backup = IdentityBackup {
            version: IDENTITY_BACKUP_VERSION,
            alias: "a".repeat(MAX_ALIAS_CHARS + 1),
            description: String::new(),
            keys: fixture_keys(),
        };
        let json = serde_json::to_string(&backup).unwrap();
        assert!(matches!(
            parse_backup(&json),
            Err(BackupParseError::NamesTooLong)
        ));
    }

    #[test]
    fn identity_seeds_can_be_wiped() {
        // `Drop` runs exactly this; checked on a live value, since freed
        // memory cannot be read back.
        let mut keys = fixture_keys();
        zeroize::Zeroize::zeroize(&mut keys);
        assert!(keys.ml_dsa_seed.is_empty() && keys.ml_kem_seed.is_empty());
    }

    /// The recovery key for `fixture_keys()`. Pins the wire format: if
    /// this changes, every recovery key users have saved stops working.
    /// Cross-checked against an independent Python implementation
    /// (hashlib.sha256 + a hand-written base58 encoder) when pinned.
    const FIXTURE_TOKEN: &str = "fmail-key-1:Ax4ijNhMohvn7t2FBdYENew4FSw2LERAQm36723fcqM8q2fzYT4re5MvYhBJjLckN1iBpybsSW4VW6UKgwBEkRspZvMH5LEzKcGe2Ag9k86C7eHeaB7UE3cVEroRp8wMbwxywGL95";

    const FIXTURE_JSON_V2: &str = include_str!("testdata/identity-backup-v2.json");

    fn fingerprint(keys: &StoredIdentityKeys) -> [&'static str; 6] {
        use ml_dsa::signature::Keypair;
        use ml_kem::kem::KeyExport;
        let vk = keys
            .ml_dsa_signing_key()
            .as_ref()
            .verifying_key()
            .encode()
            .to_vec();
        let ek = keys.ml_kem_dk().encapsulation_key().to_bytes().to_vec();
        crate::app::address_book::fingerprint_words(&vk, &ek)
    }

    fn assert_same_keys(a: &StoredIdentityKeys, b: &StoredIdentityKeys) {
        assert_eq!(a.ml_dsa_seed, b.ml_dsa_seed);
        assert_eq!(a.ml_kem_seed, b.ml_kem_seed);
    }

    #[test]
    fn fixed_test_vector() {
        let token = encode(&fixture_keys()).unwrap();
        assert_eq!(token, FIXTURE_TOKEN);
        assert_same_keys(&decode(FIXTURE_TOKEN).unwrap(), &fixture_keys());
    }

    #[test]
    fn token_is_one_short_line() {
        let token = encode(&fixture_keys()).unwrap();
        assert!(token.starts_with(TOKEN_PREFIX));
        assert!(!token.chars().any(char::is_whitespace));
        assert!(
            (130..=160).contains(&token.len()),
            "unexpected length {}",
            token.len()
        );
    }

    #[test]
    fn round_trip_random_keys() {
        for _ in 0..32 {
            let keys = StoredIdentityKeys {
                ml_dsa_seed: crate::rng::random_bytes::<32>().to_vec(),
                ml_kem_seed: crate::rng::random_bytes::<64>().to_vec(),
            };
            let token = encode(&keys).unwrap();
            assert_same_keys(&decode(&token).unwrap(), &keys);
        }
    }

    #[test]
    fn truncated_by_one_char_is_a_length_error() {
        let short = &FIXTURE_TOKEN[..FIXTURE_TOKEN.len() - 1];
        assert!(matches!(
            decode(short),
            Err(TokenError::WrongLength { got }) if got < PAYLOAD_LEN
        ));
        assert!(
            decode(short)
                .err()
                .unwrap()
                .to_string()
                .contains("too short")
        );
    }

    #[test]
    fn extra_chars_are_a_length_error() {
        let long = format!("{FIXTURE_TOKEN}zz");
        assert!(matches!(
            decode(&long),
            Err(TokenError::WrongLength { got }) if got > PAYLOAD_LEN
        ));
    }

    #[test]
    fn one_char_substitution_is_a_checksum_error() {
        // Substitute a character in the middle of the payload. Checked at
        // several positions so the test doesn't hinge on one lucky spot.
        let payload_start = TOKEN_PREFIX.len();
        let n = FIXTURE_TOKEN.len();
        for pos in [payload_start + 10, payload_start + 40, n - 30, n - 2] {
            let mut chars: Vec<char> = FIXTURE_TOKEN.chars().collect();
            chars[pos] = if chars[pos] == 'x' { 'y' } else { 'x' };
            let mangled: String = chars.into_iter().collect();
            assert_eq!(
                decode(&mangled).err(),
                Some(TokenError::BadChecksum),
                "substitution at {pos} not caught"
            );
        }
    }

    #[test]
    fn invalid_base58_char_is_reported() {
        // `0` is not in the base58 alphabet.
        let bad = format!(
            "{TOKEN_PREFIX}0{}",
            &FIXTURE_TOKEN[TOKEN_PREFIX.len() + 1..]
        );
        assert_eq!(decode(&bad).err(), Some(TokenError::BadBase58));
    }

    #[test]
    fn whitespace_newlines_and_crlf_are_tolerated() {
        let (head, tail) = FIXTURE_TOKEN.split_at(60);
        let (mid, tail) = tail.split_at(40);
        for variant in [
            format!("  {FIXTURE_TOKEN}  \n"),
            format!("\t{FIXTURE_TOKEN}\r\n"),
            format!("{head}\r\n{mid}\r\n{tail}"),
            format!("{head}\n{mid} {tail}"),
            format!("{head}  \t{mid}\n\n{tail}\n"),
            // Password managers sometimes split after the prefix.
            format!("{TOKEN_PREFIX}\n{}", &FIXTURE_TOKEN[TOKEN_PREFIX.len()..]),
        ] {
            assert_same_keys(&decode(&variant).unwrap(), &fixture_keys());
            assert_same_keys(&parse_backup(&variant).unwrap().keys, &fixture_keys());
        }
    }

    #[test]
    fn empty_input_is_rejected() {
        assert_eq!(decode("").err(), Some(TokenError::Empty));
        assert_eq!(decode(" \r\n\t").err(), Some(TokenError::Empty));
    }

    #[test]
    fn prefix_is_case_insensitive_but_payload_is_not() {
        let payload = &FIXTURE_TOKEN[TOKEN_PREFIX.len()..];
        for variant in [
            format!("FMAIL-KEY-1:{payload}"),
            format!("Fmail-key-1:{payload}"),
            format!("fMaIl-KeY-1:{payload}"),
        ] {
            assert_same_keys(&decode(&variant).unwrap(), &fixture_keys());
        }
        // Base58 is case-sensitive: changing a payload letter's case is a
        // different key, caught by the checksum (or length).
        let lowered = format!("{TOKEN_PREFIX}{}", payload.to_ascii_lowercase());
        assert!(decode(&lowered).is_err());
    }

    #[test]
    fn prefix_only_input_is_too_short_not_a_crash() {
        assert!(matches!(
            decode(TOKEN_PREFIX),
            Err(TokenError::WrongLength { got: 0 })
        ));
        assert!(matches!(
            decode("FMAIL-KEY-1:"),
            Err(TokenError::WrongLength { got: 0 })
        ));
    }

    #[test]
    fn over_length_input_is_rejected_before_decoding() {
        let huge = format!("{TOKEN_PREFIX}{}", "z".repeat(MAX_TOKEN_CHARS));
        assert_eq!(decode(&huge).err(), Some(TokenError::TooLong));
        // Whitespace doesn't count towards the cap: a wrapped real key passes.
        let wrapped: String = FIXTURE_TOKEN
            .chars()
            .flat_map(|c| [c, ' ', ' ', ' '])
            .collect();
        assert!(wrapped.len() > MAX_TOKEN_CHARS);
        assert_same_keys(&decode(&wrapped).unwrap(), &fixture_keys());
        assert!(TokenError::TooLong.to_string().contains("longer"));
    }

    #[test]
    fn may_be_incomplete_only_for_inputs_typing_could_finish() {
        let check = |text: &str| {
            let err = parse_backup(text).err().expect("must not parse");
            may_be_incomplete(text, &err)
        };
        // Still being typed.
        assert!(check(""));
        assert!(check("fm"));
        assert!(check("FMAIL-"));
        assert!(check("fmail-key-1:"));
        assert!(check(&FIXTURE_TOKEN[..60]));
        assert!(check("{ \"version\": 2"));
        // Already wrong, no matter what comes next.
        assert!(!check("hello"));
        assert!(!check("fmail-key-1:0OIl"));
        assert!(!check(&format!("{FIXTURE_TOKEN}zz")));
        let i = FIXTURE_TOKEN.len() - 20;
        let swapped = format!(
            "{}{}{}",
            &FIXTURE_TOKEN[..i],
            if &FIXTURE_TOKEN[i..=i] == "x" {
                "y"
            } else {
                "x"
            },
            &FIXTURE_TOKEN[i + 1..]
        );
        assert!(!check(&swapped));
    }

    #[test]
    fn typed_edit_classification() {
        // Plain typing and deleting.
        assert!(is_typed_edit(Some("insertText"), 10, 11));
        assert!(is_typed_edit(Some("deleteContentBackward"), 10, 9));
        assert!(is_typed_edit(None, 10, 11));
        // Select-all + paste of a similar-length string is a paste.
        assert!(!is_typed_edit(Some("insertFromPaste"), 149, 149));
        assert!(!is_typed_edit(Some("insertFromDrop"), 0, 1));
        assert!(!is_typed_edit(Some("insertReplacementText"), 20, 20));
        // Any multi-character growth is bulk, whatever the reported type.
        assert!(!is_typed_edit(Some("insertText"), 0, 149));
        assert!(!is_typed_edit(None, 0, 2));
    }

    #[test]
    fn names_to_keep_tracks_each_field_separately() {
        let backup = ("alice", "work");
        // Untouched: both came from the backup, both cleared.
        assert_eq!(names_to_keep(("alice", "work"), backup), (false, false));
        // Only the description edited: the imported alias still goes.
        assert_eq!(names_to_keep(("alice", "home"), backup), (false, true));
        // Only the alias edited.
        assert_eq!(names_to_keep(("ally", "work"), backup), (true, false));
    }

    #[test]
    fn wrong_prefix_is_rejected() {
        let payload = &FIXTURE_TOKEN[TOKEN_PREFIX.len()..];
        for bad in [
            payload.to_string(),
            format!("fmail-key:{payload}"),
            format!("river-key-1:{payload}"),
            "hello".to_string(),
        ] {
            assert_eq!(decode(&bad).err(), Some(TokenError::WrongPrefix), "{bad}");
        }
    }

    #[test]
    fn future_version_prefix_is_unknown_version() {
        let payload = &FIXTURE_TOKEN[TOKEN_PREFIX.len()..];
        assert_eq!(
            decode(&format!("fmail-key-2:{payload}")).err(),
            Some(TokenError::UnknownVersion("2".into()))
        );
    }

    #[test]
    fn unknown_payload_version_byte_is_reported() {
        // A well-formed payload (valid checksum) with an unknown version byte.
        let mut body = vec![9u8];
        body.extend_from_slice(&fixture_keys().ml_dsa_seed);
        body.extend_from_slice(&fixture_keys().ml_kem_seed);
        let sum = checksum(&body);
        body.extend_from_slice(&sum);
        let token = format!("{TOKEN_PREFIX}{}", bs58::encode(body).into_string());
        assert_eq!(
            decode(&token).err(),
            Some(TokenError::UnknownVersion("9".into()))
        );
    }

    #[test]
    fn river_identity_token_is_rejected() {
        // Shape of River's exported room identity (armored bs58 CBOR).
        let river = "-----BEGIN RIVER IDENTITY-----\n\
                     2mpNsJxMjFHz6qGqWsoAPPDRBjqrA1Hhg9cNkEKHm1zkE8bnNWBsTC7RLMXk7xAp\n\
                     Tv5bS4dBaJ1n\n\
                     -----END RIVER IDENTITY-----";
        assert_eq!(decode(river).err(), Some(TokenError::WrongPrefix));
        assert!(matches!(
            parse_backup(river),
            Err(BackupParseError::Token(TokenError::WrongPrefix))
        ));
    }

    #[test]
    fn committed_v2_json_fixture_still_restores() {
        let backup = parse_backup(FIXTURE_JSON_V2).unwrap();
        assert_eq!(backup.version, IDENTITY_BACKUP_VERSION);
        assert_eq!(backup.alias, "fixture-alice");
        assert_eq!(backup.description, "committed v2 test fixture");
        assert_same_keys(&backup.keys, &fixture_keys());
    }

    #[test]
    fn json_and_token_for_same_keys_give_same_fingerprint() {
        let from_json = parse_backup(FIXTURE_JSON_V2).unwrap();
        let from_token = parse_backup(FIXTURE_TOKEN).unwrap();
        assert_eq!(fingerprint(&from_json.keys), fingerprint(&from_token.keys));
        assert!(from_token.alias.is_empty());
        assert!(from_token.description.is_empty());
    }

    #[test]
    fn newer_json_version_says_update_the_app() {
        let v3 = r#"{"version": 3, "alias": "x", "description": "", "keys": {}}"#;
        let err = parse_backup(v3).err().expect("v3 must be rejected");
        assert_eq!(err, BackupParseError::UnsupportedJsonVersion(3));
        let msg = err.to_string();
        assert!(
            msg.contains("v3") && msg.contains("Update the app"),
            "{msg}"
        );
    }

    /// A backup written exactly the way the previous exporter wrote it:
    /// `serde_json::to_vec_pretty(&IdentityBackup { .. })`, built from real
    /// keys via `StoredIdentityKeys::new`. Guards against the hand-written
    /// fixture drifting from what users actually have on disk.
    #[test]
    fn backup_from_the_old_exporter_shape_parses() {
        let keys = fixture_keys();
        let signing = keys.ml_dsa_signing_key();
        let dk = keys.ml_kem_dk();
        let old = IdentityBackup {
            version: IDENTITY_BACKUP_VERSION,
            alias: "alice".into(),
            description: "work".into(),
            keys: StoredIdentityKeys::new(&signing, &dk),
        };
        let bytes = serde_json::to_vec_pretty(&old).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        let parsed = parse_backup(&text).unwrap();
        assert_eq!(parsed.alias, "alice");
        assert_eq!(parsed.description, "work");
        assert_same_keys(&parsed.keys, &keys);
        assert_eq!(fingerprint(&parsed.keys), fingerprint(&keys));
    }

    #[test]
    fn v1_json_gives_a_visible_version_error() {
        let v1 = r#"{
          "version": 1,
          "alias": "old",
          "description": "",
          "keys": { "rsa_key_bytes": [1, 2, 3], "ml_dsa_seed": [1], "ml_kem_seed": [2] }
        }"#;
        let err = parse_backup(v1).err().expect("v1 must be rejected");
        assert_eq!(err, BackupParseError::UnsupportedJsonVersion(1));
        assert!(err.to_string().contains("pre-release"));
    }

    #[test]
    fn malformed_json_is_rejected() {
        for bad in [
            "{ not json",
            r#"{"alias": "x"}"#,
            r#"{"version": 2, "alias": "x"}"#,
        ] {
            assert_eq!(
                parse_backup(bad).err(),
                Some(BackupParseError::InvalidJson),
                "{bad}"
            );
        }
    }

    #[test]
    fn json_with_wrong_seed_length_is_rejected_not_panicking() {
        let bad = r#"{"version": 2, "alias": "x", "description": "",
                      "keys": {"ml_dsa_seed": [1, 2], "ml_kem_seed": [3]}}"#;
        assert_eq!(
            parse_backup(bad).err(),
            Some(BackupParseError::BadKeyLength)
        );
    }

    #[test]
    fn every_error_has_a_message() {
        for e in [
            TokenError::Empty,
            TokenError::WrongPrefix,
            TokenError::UnknownVersion("2".into()),
            TokenError::BadBase58,
            TokenError::WrongLength { got: 3 },
            TokenError::WrongLength { got: 300 },
            TokenError::TooLong,
            TokenError::BadChecksum,
        ] {
            assert!(!e.to_string().is_empty());
        }
    }
}
