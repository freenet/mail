//! The disclosure gate: what an observer of the contract's state can read.
//!
//! `docs/metadata-fields.toml` lists every plaintext field path of a fully
//! populated state, with why it is public. This walks such a state's canonical
//! CBOR and requires the two lists to be the same set: a field added to the
//! state without a line in the toml fails, and so does a line for a field that
//! is not there. The toml is what the README's "What others can see" is built
//! from, so a field cannot become public without the page that says so.
//!
//! Paths are dotted. A struct field is its name, an enum variant that carries
//! data is its name, a map keyed by bytes is `*`. A unit variant or a `None`
//! is a leaf (or nothing), so `owner.quarantine` is the leaf for `Open` and
//! `owner.quarantine.RequireGhost.min_usd` the field of the other mode.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use ciborium::Value;
use common::*;
use freenet_email_inbox_v2::is_valid;
use freenet_email_inbox_v2::merge::merge;
use freenet_email_inbox_v2::types::*;

const T: u64 = 1_800_000_000 / DAY * DAY;
const FAR: u64 = T + 300 * DAY;
/// Read when the test runs, not included: cargo-mutants builds every test of a
/// copy of this crate alone, where the file is not.
const TOML_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/metadata-fields.toml"
);

/// The classes of `docs/metadata-fields.toml`, one per row of the plan's table.
const CLASSES: [&str; 9] = [
    "recipient keys",
    "owner activity",
    "pass bookkeeping",
    "revocations and usage",
    "ghost key proof",
    "ciphertext",
    "send time",
    "queue",
    "admission",
];

/// Words that would put a sender's identity in public state.
const SENDER_WORDS: [&str; 5] = ["sender", "from", "author", "signer", "identity"];

fn populated(mode: QuarantineMode) -> InboxState {
    let w = world();
    let tombstones = BTreeMap::from([(serde_bytes::ByteArray::new([5u8; 32]), T - DAY)]);
    let owner = w.owner(1, 3, mode, tombstones);
    let contact = w.pass(1, 3, FAR, PassClass::Contact);
    let invite = w.pass(2, 3, FAR, PassClass::Invite { max_messages: 3 });
    let mut messages = vec![
        w.pass_msg(&contact, ct(8192, 1), T),
        w.pass_msg(&invite, ct(8192, 2), T),
        w.owner_msg(ct(8192, 3), T),
    ];
    // A proof is decisive in RequireGhost and refused in Open.
    messages.push(w.quarantine_msg(ct(8192, 4), T, Some(4)));
    messages.push(w.quarantine_msg(ct(8192, 5), T, None));
    let raw = w.raw(
        owner,
        w.time(T),
        [w.revocation(id_of(9), FAR, 3)],
        [w.usage(invite.cert.pass_id, 1, FAR)],
        messages,
    );
    let state = merge(&Rules::V1, &w.params, vec![raw.into()]).unwrap();
    assert!(is_valid(&Rules::V1, &w.params, &encode(&state)));
    state
}

fn walk(prefix: &str, value: &Value, out: &mut BTreeSet<String>) {
    match value {
        Value::Map(entries) => {
            for (key, inner) in entries {
                let part = match key {
                    Value::Text(name) => name.as_str(),
                    Value::Bytes(_) => "*",
                    other => panic!("a map key that is neither a name nor bytes: {other:?}"),
                };
                let path = if prefix.is_empty() {
                    part.to_string()
                } else {
                    format!("{prefix}.{part}")
                };
                walk(&path, inner, out);
            }
        }
        // `None`: the field is absent for an observer.
        Value::Null => {}
        Value::Array(_) => panic!("{prefix}: an array; the state's collections are maps"),
        _ => {
            out.insert(prefix.to_string());
        }
    }
}

/// Every plaintext path of the states a populated inbox can be in.
fn state_paths() -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    for mode in [
        QuarantineMode::RequireGhost { min_usd: Some(5) },
        QuarantineMode::Open,
    ] {
        let state = populated(mode);
        let kinds: BTreeSet<_> = state
            .messages
            .values()
            .map(|m| match &m.admission {
                Admission::Pass { cert, .. } => match cert.class {
                    PassClass::Contact => "contact",
                    PassClass::Invite { .. } => "invite",
                },
                Admission::Owner { .. } => "owner",
                Admission::Quarantine { ghost: Some(_) } => "proof",
                Admission::Quarantine { ghost: None } => "bare",
            })
            .collect();
        let want: &[&str] = if matches!(mode, QuarantineMode::Open) {
            // Open refuses a message carrying a proof (decision 19).
            &["contact", "invite", "owner", "bare"]
        } else {
            // RequireGhost filters a message with no proof.
            &["contact", "invite", "owner", "proof"]
        };
        assert_eq!(kinds, want.iter().copied().collect(), "{mode:?}: populated");
        let value: Value = ciborium::from_reader(encode(&state).as_slice()).unwrap();
        walk("", &value, &mut paths);
    }
    paths
}

struct Field {
    path: String,
    class: String,
    why: String,
}

/// The toml's subset this file uses: `[[field]]` tables of three string keys.
fn declared() -> Vec<Field> {
    let mut fields: Vec<Field> = Vec::new();
    let mut open = false;
    let toml = std::fs::read_to_string(TOML_PATH).expect("docs/metadata-fields.toml");
    for (n, line) in toml.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[field]]" {
            fields.push(Field {
                path: String::new(),
                class: String::new(),
                why: String::new(),
            });
            open = true;
            continue;
        }
        let (key, value) = line
            .split_once(" = ")
            .unwrap_or_else(|| panic!("line {}: not `key = \"value\"`", n + 1));
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or_else(|| panic!("line {}: the value is not a quoted string", n + 1));
        assert!(open, "line {}: a key outside [[field]]", n + 1);
        let field = fields.last_mut().unwrap();
        match key {
            "path" => field.path = value.to_string(),
            "class" => field.class = value.to_string(),
            "why" => field.why = value.to_string(),
            other => panic!("line {}: unknown key `{other}`", n + 1),
        }
    }
    fields
}

#[test]
fn the_toml_lists_exactly_the_plaintext_fields() {
    let paths = state_paths();
    let fields = declared();
    let listed: BTreeSet<String> = fields.iter().map(|f| f.path.clone()).collect();
    assert_eq!(listed.len(), fields.len(), "a path is listed twice");
    let undeclared: Vec<_> = paths.difference(&listed).collect();
    let stale: Vec<_> = listed.difference(&paths).collect();
    assert!(
        undeclared.is_empty() && stale.is_empty(),
        "docs/metadata-fields.toml is out of step with the state.\n  \
         public but not listed: {undeclared:?}\n  listed but not in the state: {stale:?}"
    );
}

#[test]
fn every_field_says_what_it_is_and_why_it_is_public() {
    for f in declared() {
        assert!(
            CLASSES.contains(&f.class.as_str()),
            "{}: class `{}`",
            f.path,
            f.class
        );
        assert!(f.why.len() >= 12, "{}: say why it is public", f.path);
    }
}

#[test]
fn no_plaintext_field_names_a_sender() {
    for path in state_paths() {
        for part in path.split('.') {
            assert!(
                !SENDER_WORDS.iter().any(|w| part.contains(w)),
                "{path}: `{part}` suggests a sender is named in public state"
            );
        }
    }
}

#[test]
fn a_ghost_key_proof_is_only_where_the_quarantine_is() {
    for path in state_paths() {
        assert_eq!(
            path.contains("ghost"),
            path.starts_with("messages.*.admission.Quarantine.ghost."),
            "{path}: a Ghost Key proof outside a quarantine message"
        );
    }
}
