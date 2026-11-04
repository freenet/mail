//! Addresses, recipients and labels (surgery plan §5.1).
//!
//! An address is the 24 bytes `address_of(ml_dsa_vk)` plus a 2-byte check,
//! shown as 36 base58 characters. People see it as `name@address`, where the
//! name is a label the address's owner suggests: cosmetic, never used for
//! routing or trust. A petname the user saved always wins over a label, and
//! the UI says so when they differ.

use freenet_mail_protocol::inbox_v2::Pass;
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;
use unicode_security::MixedScript;

/// BLAKE3 context of the 2-byte check.
const CHECK_CONTEXT: &str = "freenet-mail address check v1";
/// Characters an address is shown with. Base58 of 26 bytes is 35 or 36
/// characters; the shorter is padded with a leading `1` (a zero byte), which
/// decoding strips again.
pub(crate) const ADDRESS_CHARS: usize = 36;
/// What an invite starts with.
pub(crate) const INVITE_PREFIX: &str = "fmail-invite-1:";
const FMAIL_PREFIX: &str = "fmail:";
pub(crate) const LABEL_MAX_CHARS: usize = 32;

fn check2(addr: &[u8; 24]) -> [u8; 2] {
    let full = blake3::derive_key(CHECK_CONTEXT, addr);
    [full[0], full[1]]
}

/// The 36-character form of `addr`.
pub(crate) fn display(addr: &[u8; 24]) -> String {
    let mut bytes = addr.to_vec();
    bytes.extend_from_slice(&check2(addr));
    let text = bs58::encode(bytes).into_string();
    format!(
        "{}{text}",
        "1".repeat(ADDRESS_CHARS.saturating_sub(text.len()))
    )
}

/// Why a typed address or recipient was not accepted. Each says plainly what
/// to fix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AddressError {
    Empty,
    NotBase58,
    /// The right length but the check bytes do not match: a typo.
    BadCheck,
    WrongLength,
    BadInvite,
    Label(LabelError),
}

impl std::fmt::Display for AddressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("enter an address"),
            Self::NotBase58 => f.write_str("an address uses only letters and digits (base58)"),
            Self::BadCheck => {
                f.write_str("this address has a typo: its last characters do not match the rest")
            }
            Self::WrongLength => f.write_str(
                "this is not an address: an address is 36 characters (an old one is 44)",
            ),
            Self::BadInvite => f.write_str("this invite is damaged or incomplete"),
            Self::Label(e) => write!(f, "the name before @ {e}"),
        }
    }
}

/// What an address field can hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Parsed {
    /// A v2 address.
    Address([u8; 24]),
    /// A v0.2.x inbox id (44 characters, 32 bytes). Recognised here; C2c
    /// resolves it to the address of the key behind it.
    Legacy([u8; 32]),
}

/// Parse a bare address, v2 or legacy.
pub(crate) fn parse_address(text: &str) -> Result<Parsed, AddressError> {
    let text = text.trim();
    if text.is_empty() {
        return Err(AddressError::Empty);
    }
    let bytes = bs58::decode(text)
        .into_vec()
        .map_err(|_| AddressError::NotBase58)?;
    match bytes.len() {
        32 if text.len() >= 43 => Ok(Parsed::Legacy(bytes.try_into().expect("32 bytes"))),
        // Leading zero bytes beyond 26 are the padding `display` adds.
        n if n >= 26
            && (text.len() == ADDRESS_CHARS || text.len() == ADDRESS_CHARS - 1)
            && bytes[..n - 26].iter().all(|b| *b == 0) =>
        {
            let body = &bytes[n - 26..];
            let addr: [u8; 24] = body[..24].try_into().expect("24 bytes");
            if body[24..] != check2(&addr) {
                return Err(AddressError::BadCheck);
            }
            Ok(Parsed::Address(addr))
        }
        _ => Err(AddressError::WrongLength),
    }
}

/// An invite: a pass to write to its issuer's inbox, and the label the issuer
/// suggests. It is a bearer secret: whoever holds it can write to that inbox
/// until the invite is used up or expires.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Invite {
    pub v: u8,
    pub label: Option<String>,
    pub pass: Pass,
}

pub(crate) fn encode_invite(label: Option<&str>, pass: Pass) -> String {
    let invite = Invite {
        v: 1,
        label: label.map(str::to_string),
        pass,
    };
    let cbor = freenet_mail_protocol::to_cbor(&invite).expect("an invite encodes");
    format!("{INVITE_PREFIX}{}", bs58::encode(cbor).into_string())
}

fn decode_invite(body: &str) -> Result<Invite, AddressError> {
    let bytes = bs58::decode(body.trim())
        .into_vec()
        .map_err(|_| AddressError::BadInvite)?;
    let invite: Invite =
        freenet_mail_protocol::from_cbor(&bytes).map_err(|_| AddressError::BadInvite)?;
    if invite.v != 1 {
        return Err(AddressError::BadInvite);
    }
    Ok(invite)
}

/// What the user typed as a recipient or a contact to add.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Recipient {
    /// An address, with the label typed before `@`, if any.
    Address {
        label: Option<String>,
        addr: [u8; 24],
    },
    Legacy {
        label: Option<String>,
        id: [u8; 32],
    },
    Invite(Invite),
}

impl Recipient {
    /// The inviter's or addressee's address, for a v2 recipient.
    pub(crate) fn addr(&self) -> Option<[u8; 24]> {
        match self {
            Self::Address { addr, .. } => Some(*addr),
            Self::Invite(invite) => Some(*invite.pass.cert.recipient),
            Self::Legacy { .. } => None,
        }
    }

    pub(crate) fn label(&self) -> Option<&str> {
        match self {
            Self::Address { label, .. } | Self::Legacy { label, .. } => label.as_deref(),
            Self::Invite(invite) => invite.label.as_deref(),
        }
    }
}

/// Parse a recipient: a bare address, `name@address`, `fmail:name@address`,
/// a legacy 44-character id, or an `fmail-invite-1:` invite. The name is the
/// part before the LAST `@`, so a name cannot smuggle in a second address.
pub(crate) fn parse_recipient(text: &str) -> Result<Recipient, AddressError> {
    let text = text.trim();
    if let Some(body) = strip_prefix_ci(text, INVITE_PREFIX) {
        let mut invite = decode_invite(body)?;
        // A label the invite carries is checked like any incoming label;
        // one that fails is dropped, never shown.
        invite.label = invite
            .label
            .and_then(|l| normalize_label(&l, false).ok().map(|l| l.0));
        return Ok(Recipient::Invite(invite));
    }
    let text = strip_prefix_ci(text, FMAIL_PREFIX).unwrap_or(text);
    let (label, address) = match text.rfind('@') {
        Some(at) => {
            let label = normalize_label(&text[..at], false).map_err(AddressError::Label)?;
            (Some(label.0), &text[at + 1..])
        }
        None => (None, text),
    };
    Ok(match parse_address(address)? {
        Parsed::Address(addr) => Recipient::Address { label, addr },
        Parsed::Legacy(id) => Recipient::Legacy { label, id },
    })
}

fn strip_prefix_ci<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let head = text.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &text[prefix.len()..])
}

/// `name@address` for `addr`, or the bare address without a label.
pub(crate) fn full_address(label: Option<&str>, addr: &[u8; 24]) -> String {
    match label {
        Some(l) if !l.is_empty() => format!("{l}@{}", display(addr)),
        _ => display(addr),
    }
}

// ── Labels ──────────────────────────────────────────────────────────────────

/// Why a label was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LabelError {
    Empty,
    TooLong,
    /// `@`, whitespace, a control character or a bidi/format character.
    ForbiddenChar(char),
    MixedScripts,
    /// Outside ASCII, which incoming labels are limited to by default.
    NotAscii,
}

impl std::fmt::Display for LabelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("is empty"),
            Self::TooLong => write!(f, "is longer than {LABEL_MAX_CHARS} characters"),
            Self::ForbiddenChar(c) => {
                write!(f, "contains a character not allowed in a name ({c:?})")
            }
            Self::MixedScripts => f.write_str("mixes letters from different alphabets"),
            Self::NotAscii => f.write_str("uses letters outside plain ASCII"),
        }
    }
}

/// A normalized label: NFKC, case-folded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Label(pub String);

/// Bidi controls and the other format (Cf) characters, which can make a label
/// render as something else.
fn is_format(c: char) -> bool {
    matches!(c as u32,
        0x00AD | 0x0600..=0x0605 | 0x061C | 0x06DD | 0x070F | 0x0890..=0x0891 | 0x08E2
        | 0x180E | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x206F
        | 0xFEFF | 0xFFF9..=0xFFFB | 0x110BD | 0x110CD | 0x13430..=0x1343F
        | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A | 0xE0001 | 0xE0020..=0xE007F)
}

/// Normalize a label: NFKC, case-folded (lowercase, then NFKC again, which
/// is NFKC_Casefold for the labels this accepts), 1 to 32 characters, one
/// script, and none of `@`, whitespace, control or format characters.
/// `allow_non_ascii`: a petname the user types may use any one script; an
/// incoming label is ASCII by default.
pub(crate) fn normalize_label(text: &str, allow_non_ascii: bool) -> Result<Label, LabelError> {
    let folded: String = text
        .nfkc()
        .collect::<String>()
        .to_lowercase()
        .nfkc()
        .collect();
    if folded.is_empty() {
        return Err(LabelError::Empty);
    }
    if folded.chars().count() > LABEL_MAX_CHARS {
        return Err(LabelError::TooLong);
    }
    if let Some(c) = folded
        .chars()
        .find(|c| *c == '@' || c.is_whitespace() || c.is_control() || is_format(*c))
    {
        return Err(LabelError::ForbiddenChar(c));
    }
    if !folded.is_ascii() {
        if !allow_non_ascii {
            return Err(LabelError::NotAscii);
        }
        if !folded.as_str().is_single_script() {
            return Err(LabelError::MixedScripts);
        }
    }
    Ok(Label(folded))
}

/// The TR39 confusable skeleton of a normalized label: two labels that can
/// be mistaken for each other have the same one.
pub(crate) fn skeleton(label: &str) -> String {
    unicode_security::skeleton(label).collect()
}

/// Something about a sender's name the user should see.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LabelWarning {
    /// They call themselves something other than the name you saved.
    DiffersFromPetname { label: String },
    /// The name can be mistaken for a contact who is someone else.
    LooksLike { contact: String },
}

impl std::fmt::Display for LabelWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DiffersFromPetname { label } => {
                write!(f, "calls themselves \u{201c}{label}\u{201d}")
            }
            Self::LooksLike { contact } => write!(
                f,
                "looks like your contact \u{201c}{contact}\u{201d} but is a different address"
            ),
        }
    }
}

/// The name to show for `addr` and what to warn about. A saved petname
/// always wins; an incoming label is shown only without one. `contacts` are
/// the user's (petname, address) pairs.
pub(crate) fn name_for(
    addr: &[u8; 24],
    petname: Option<&str>,
    incoming: Option<&str>,
    contacts: &[(String, [u8; 24])],
) -> (String, Vec<LabelWarning>) {
    let mut warnings = Vec::new();
    let incoming = incoming.and_then(|l| normalize_label(l, false).ok());
    if let (Some(pet), Some(label)) = (petname, &incoming) {
        let pet_folded = normalize_label(pet, true).map(|l| l.0);
        if pet_folded.as_deref() != Ok(label.0.as_str()) {
            warnings.push(LabelWarning::DiffersFromPetname {
                label: label.0.clone(),
            });
        }
    }
    let shown = petname
        .map(str::to_string)
        .or_else(|| incoming.as_ref().map(|l| l.0.clone()));
    if let Some(name) = &shown {
        let mine = skeleton(&normalize_label(name, true).map(|l| l.0).unwrap_or_default());
        for (pet, other) in contacts {
            if other == addr {
                continue;
            }
            let theirs = skeleton(&normalize_label(pet, true).map(|l| l.0).unwrap_or_default());
            if !mine.is_empty() && mine == theirs {
                warnings.push(LabelWarning::LooksLike {
                    contact: pet.clone(),
                });
            }
        }
    }
    let short = display(addr)[..8].to_string();
    (shown.unwrap_or(short), warnings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use freenet_mail_protocol::inbox_v2::{PassCert, PassClass};
    use serde_bytes::ByteArray;

    #[test]
    fn an_address_is_36_characters_and_round_trips() {
        for seed in 0u8..=255 {
            let addr = [seed; 24];
            let shown = display(&addr);
            assert_eq!(shown.len(), ADDRESS_CHARS, "{shown}");
            assert_eq!(parse_address(&shown), Ok(Parsed::Address(addr)));
        }
        // A short encoding gets a padding `1`, and decodes past it.
        let low = [0x01; 24];
        assert!(display(&low).starts_with('1'));
        assert_eq!(parse_address(&display(&low)), Ok(Parsed::Address(low)));
    }

    /// The display is `base58(addr24 ‖ check2)`, check2 from its own context.
    #[test]
    fn the_address_layout_is_the_plans() {
        let addr = [0x11; 24];
        let full = blake3::derive_key("freenet-mail address check v1", &addr);
        let mut bytes = addr.to_vec();
        bytes.extend_from_slice(&full[..2]);
        let expected = bs58::encode(bytes).into_string();
        assert_eq!(
            display(&addr).trim_start_matches('1'),
            expected.trim_start_matches('1')
        );
    }

    #[test]
    fn a_typo_fails_the_check() {
        let shown = display(&[0x42; 24]);
        let mut chars: Vec<char> = shown.chars().collect();
        let i = 20;
        chars[i] = if chars[i] == 'z' { 'y' } else { 'z' };
        let typo: String = chars.into_iter().collect();
        assert_eq!(parse_address(&typo), Err(AddressError::BadCheck));
    }

    #[test]
    fn a_legacy_id_is_recognised() {
        let id = [0xEE; 32];
        let text = bs58::encode(id).into_string();
        assert_eq!(text.len(), 44);
        assert_eq!(parse_address(&text), Ok(Parsed::Legacy(id)));
        assert!(matches!(
            parse_recipient(&format!("bob@{text}")),
            Ok(Recipient::Legacy { label: Some(l), id: i }) if l == "bob" && i == id
        ));
    }

    #[test]
    fn junk_is_refused_plainly() {
        assert_eq!(parse_address(""), Err(AddressError::Empty));
        assert_eq!(parse_address("0OIl"), Err(AddressError::NotBase58));
        assert_eq!(parse_address("abc"), Err(AddressError::WrongLength));
    }

    #[test]
    fn every_accepted_form_names_the_same_address() {
        let addr = [0x5a; 24];
        let shown = display(&addr);
        for text in [
            shown.clone(),
            format!("  {shown} "),
            format!("alice@{shown}"),
            format!("fmail:alice@{shown}"),
            format!("FMAIL:Alice@{shown}"),
        ] {
            let parsed = parse_recipient(&text).unwrap();
            assert_eq!(parsed.addr(), Some(addr), "{text}");
        }
        assert_eq!(
            parse_recipient(&format!("fmail:Alice@{shown}"))
                .unwrap()
                .label(),
            Some("alice")
        );
    }

    /// The name is split off at the LAST `@`: a name holding an `@` is
    /// refused, rather than one address hiding another.
    #[test]
    fn the_split_is_at_the_last_at() {
        let shown = display(&[0x5b; 24]);
        assert_eq!(
            parse_recipient(&format!("a@b@{shown}")),
            Err(AddressError::Label(LabelError::ForbiddenChar('@')))
        );
    }

    fn pass() -> Pass {
        Pass {
            cert: PassCert {
                recipient: ByteArray::new([0x33; 24]),
                pass_id: ByteArray::new([1; 16]),
                pass_vk: ByteArray::new([2; 32]),
                epoch: 0,
                expiry: 86_400 * 20_000,
                class: PassClass::Invite { max_messages: 3 },
                sig: ByteArray::new([3; 64]),
            },
            pass_sk: ByteArray::new([4; 32]),
        }
    }

    #[test]
    fn an_invite_round_trips_and_names_its_issuer() {
        let text = encode_invite(Some("carol"), pass());
        assert!(text.starts_with(INVITE_PREFIX));
        let parsed = parse_recipient(&text).unwrap();
        assert_eq!(parsed.addr(), Some([0x33; 24]));
        assert_eq!(parsed.label(), Some("carol"));
        let Recipient::Invite(invite) = parsed else {
            panic!("an invite")
        };
        assert_eq!(invite.pass, pass());
        // Damaged: refused, not half-read.
        assert_eq!(
            parse_recipient(&text[..text.len() - 5]),
            Err(AddressError::BadInvite)
        );
    }

    /// An invite's label is an incoming label: one that fails the rules is
    /// dropped, never shown.
    #[test]
    fn an_invites_bad_label_is_dropped() {
        let text = encode_invite(Some("p\u{0430}ypal"), pass());
        assert_eq!(parse_recipient(&text).unwrap().label(), None);
    }

    #[test]
    fn labels_are_nfkc_casefolded() {
        assert_eq!(normalize_label("Alice", false), Ok(Label("alice".into())));
        // Fullwidth letters fold to ASCII under NFKC.
        assert_eq!(
            normalize_label("\u{FF21}lice", false),
            Ok(Label("alice".into()))
        );
        assert_eq!(
            normalize_label("STRASSE", false),
            Ok(Label("strasse".into()))
        );
    }

    #[test]
    fn labels_refuse_what_can_hide_or_mislead() {
        assert_eq!(normalize_label("", false), Err(LabelError::Empty));
        assert_eq!(
            normalize_label(&"a".repeat(33), false),
            Err(LabelError::TooLong)
        );
        assert!(normalize_label(&"a".repeat(32), false).is_ok());
        for bad in [
            "a b",
            "a\u{202E}b",
            "a\u{200B}b",
            "a\tb",
            "a@b",
            "a\u{0007}b",
        ] {
            assert!(
                matches!(
                    normalize_label(bad, true),
                    Err(LabelError::ForbiddenChar(_))
                ),
                "{bad:?}"
            );
        }
        // Cyrillic `а` in a Latin name: two scripts.
        assert_eq!(
            normalize_label("p\u{0430}ypal", true),
            Err(LabelError::MixedScripts)
        );
        // One non-Latin script is a fine petname, not an incoming label.
        assert!(normalize_label("\u{0430}\u{043d}\u{044f}", true).is_ok());
        assert_eq!(
            normalize_label("\u{0430}\u{043d}\u{044f}", false),
            Err(LabelError::NotAscii)
        );
    }

    #[test]
    fn a_petname_beats_an_incoming_label_and_a_mismatch_is_flagged() {
        let addr = [9; 24];
        let (shown, warnings) = name_for(&addr, Some("Bob"), Some("robert"), &[]);
        assert_eq!(shown, "Bob");
        assert_eq!(
            warnings,
            vec![LabelWarning::DiffersFromPetname {
                label: "robert".into()
            }]
        );
        // Same name in another case: no warning.
        assert!(name_for(&addr, Some("Bob"), Some("bob"), &[]).1.is_empty());
        // No petname: the label is shown.
        assert_eq!(name_for(&addr, None, Some("robert"), &[]).0, "robert");
        // Neither: the start of the address.
        assert_eq!(name_for(&addr, None, None, &[]).0, display(&addr)[..8]);
    }

    #[test]
    fn a_label_that_looks_like_another_contact_is_flagged() {
        let alice = [1; 24];
        let impostor = [2; 24];
        let contacts = vec![("alice".to_string(), alice)];
        // `1` and `l` share a skeleton.
        let (_, warnings) = name_for(&impostor, None, Some("a1ice"), &contacts);
        assert_eq!(
            warnings,
            vec![LabelWarning::LooksLike {
                contact: "alice".into()
            }]
        );
        // The real alice is not warned about herself.
        assert!(
            name_for(&alice, Some("alice"), None, &contacts)
                .1
                .is_empty()
        );
        assert_eq!(skeleton("a1ice"), skeleton("alice"));
    }
}
