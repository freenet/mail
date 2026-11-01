//! Offline builds only (`example-data`): `?migration-fixture=<name>` runs the
//! real walk in the page against a scripted node, so the Playwright suite can
//! reach the migration's screens with no node. The bytes are the captured
//! golden replies.

use freenet_stdlib::prelude::DelegateKey;

use crate::legacy_registry::{IDENTITY_LINEAGE, LOCAL_STATE_LINEAGE};
use crate::migration::legacy_delegates::{LegacyReply, LegacyTransport};
use crate::migration::successor::V1InboxReader;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Node {
    /// A v0.2.7 identity and its mail, plus mail under an alias no identity has.
    Data,
    Silent,
    NotInstalled,
}

impl Node {
    fn named(name: &str) -> Option<Self> {
        match name {
            "data" => Some(Node::Data),
            "silent" => Some(Node::Silent),
            "not-installed" => Some(Node::NotInstalled),
            _ => None,
        }
    }
}

fn golden(name: &str) -> Vec<u8> {
    let hex = include_str!("../../../wire-v1/src/golden_v1.txt")
        .lines()
        .find_map(|l| l.strip_prefix(name)?.strip_prefix(' '))
        .expect("a captured sample");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}

impl LegacyTransport for Node {
    async fn ask(&mut self, key: &DelegateKey, _: &'static [u8], _: Vec<u8>) -> LegacyReply {
        let is = |entry: &freenet_migrate::DelegateLineageEntry| {
            entry.delegate_key.as_slice() == key.bytes()
        };
        match self {
            Node::Silent => LegacyReply::NoAnswer("no reply in time".to_string()),
            Node::NotInstalled => LegacyReply::NotInstalled,
            Node::Data if IDENTITY_LINEAGE.iter().any(is) => {
                LegacyReply::Answer(golden("identity_state_seeded"))
            }
            Node::Data
                if LOCAL_STATE_LINEAGE
                    .iter()
                    .any(|e| is(e) && e.generation == 206) =>
            {
                LegacyReply::Answer(golden("ls_state"))
            }
            Node::Data => {
                let text = String::from_utf8(golden("ls_state")).expect("JSON");
                LegacyReply::Answer(text.replace("\"alice\"", "\"old-alias\"").into_bytes())
            }
        }
    }
}

#[derive(Clone)]
struct NoInbox;

impl V1InboxReader for NoInbox {
    async fn ciphertexts(&mut self, _: &[u8]) -> Option<Vec<Vec<u8>>> {
        None
    }

    async fn has_inbox(&mut self, _: &[u8], _: &str) -> bool {
        false
    }
}

fn fixture_param() -> Option<String> {
    let search = web_sys::window()?.location().search().ok()?;
    search
        .trim_start_matches('?')
        .split('&')
        .find_map(|pair| pair.strip_prefix("migration-fixture="))
        .map(str::to_string)
}

/// Run the named fixture, if the URL asks for one.
pub(crate) fn start() {
    let Some(node) = fixture_param().as_deref().and_then(Node::named) else {
        return;
    };
    super::migration_view::walk_starting();
    super::identity_store::spawn_detached(super::migration_view::after_listing(node, NoInbox));
}
