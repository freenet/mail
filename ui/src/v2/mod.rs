//! Inbox v2 in the UI: the owner's inbox (create, drain, show), contacts
//! and passes, and sending. The mail delegate does every signing and
//! sealing; this side moves states between it and the network and says
//! plainly what happened.

pub(crate) mod contacts;
// The flows use the page's test Ghost Key vault, so they need its feature
// (every example-data build has it; `no-sync` alone does not).
#[cfg(all(
    test,
    feature = "local-delegate",
    feature = "test-ghost-master",
    not(feature = "use-node")
))]
mod flows;
pub(crate) mod net;
pub(crate) mod owner;
pub(crate) mod queue;
pub(crate) mod send;

use freenet_mail_protocol::Addr;
use freenet_mail_protocol::inbox_v2;
use freenet_stdlib::prelude::{ContractInstanceId, ContractKey, Parameters};
use serde::{Deserialize, Serialize};

/// The inbox v2 contract. Still the candidate: v0.3.0 freezes it.
pub(crate) const CODE: &[u8] = include_bytes!("../../../published-contract/candidate/inbox_v2");
pub(crate) const CODE_HASH: &str =
    include_str!("../../../published-contract/candidate/inbox_v2_code_hash");

/// The Ghost Key master inbox parameters name. Production inboxes name the
/// Freenet master; a test network names its own, which gives it separate
/// contracts (the `test-ghost-master` feature: the fixture's master, whose
/// keys the page's test vault holds).
pub(crate) fn ghost_master() -> [u8; 32] {
    #[cfg(feature = "test-ghost-master")]
    return crate::ghostkeys::mock::master();
    #[cfg(not(feature = "test-ghost-master"))]
    ghostkey_verify::FREENET_MASTER_VERIFYING_KEY
}

pub(crate) fn params(addr: &Addr) -> Parameters<'static> {
    Parameters::from(inbox_v2::params_bytes(&addr.0, &ghost_master()))
}

pub(crate) fn key(addr: &Addr) -> ContractKey {
    ContractKey::from_params(CODE_HASH.trim(), params(addr))
        .expect("the committed inbox v2 code hash decodes")
}

pub(crate) fn instance_id(addr: &Addr) -> ContractInstanceId {
    *key(addr).id()
}

/// What a mail body holds, inside the sealed envelope. Only the recipient
/// reads it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MailBody {
    pub v: u8,
    /// The label the sender suggests for themselves: cosmetic, and a saved
    /// petname wins over it.
    pub label: Option<String>,
    pub title: String,
    pub content: String,
    /// When the sender wrote it, to the millisecond. The public `sent_time`
    /// is only the hour.
    pub time_ms: i64,
    pub thread_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub quoted_excerpt: Option<String>,
}

impl MailBody {
    pub(crate) fn encode(&self) -> Vec<u8> {
        freenet_mail_protocol::to_cbor(self).expect("a mail body encodes")
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        freenet_mail_protocol::from_cbor(bytes).ok()
    }
}

/// The delegate's inbox record, as far as the page reads it (the delegate
/// writes it; unknown fields are skipped).
#[derive(Clone, Debug, Default, Deserialize)]
pub(crate) struct InboxRecordView {
    pub max_version: u64,
    #[serde(default)]
    pub strangers_dropped: u64,
    /// Decision 25: the delegate saw an owner record it did not sign.
    #[serde(default)]
    pub foreign_seen: Option<ForeignSeenView>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
pub(crate) struct ForeignSeenView {
    pub version: u64,
    pub at: u64,
}

/// One ledger entry, as far as the page reads it.
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct LedgerView {
    pub issued_for: Option<inbox_v2::B24>,
    pub class: inbox_v2::PassClass,
    pub expiry: u64,
    pub revoked: bool,
}

pub(crate) fn entropy() -> freenet_mail_protocol::Entropy {
    freenet_mail_protocol::Entropy(crate::rng::random_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The page finds an inbox where the delegate's jobs do: the same code
    /// hash and parameters, under the same Ghost Key master.
    #[test]
    fn the_inbox_key_is_the_delegates() {
        let addr = Addr([7; 24]);
        let ours: [u8; 32] = instance_id(&addr).as_bytes().try_into().unwrap();
        #[cfg(feature = "local-delegate")]
        assert_eq!(
            Ok(ours),
            mail_delegate::inbox_jobs::inbox_id(&addr, &ghost_master())
        );
        assert_ne!(ours, [0; 32]);
    }

    #[test]
    fn inboxes_name_the_master_of_their_network() {
        let master: [u8; 32] = if cfg!(feature = "test-ghost-master") {
            // contracts/inbox-v2/tests/fixtures/ghost-keys.txt
            [
                0x84, 0x9f, 0x6f, 0x1d, 0x37, 0x98, 0x15, 0x7a, 0x25, 0x33, 0xeb, 0x1b, 0xe9, 0x99,
                0x3f, 0xef, 0x4d, 0xa3, 0xe1, 0xdb, 0xea, 0xc8, 0xd7, 0x74, 0x2b, 0xb8, 0xd7, 0x99,
                0xca, 0x8f, 0x74, 0x7c,
            ]
        } else {
            ghostkey_verify::production_master().to_bytes()
        };
        assert_eq!(ghost_master(), master);
        let p = params(&Addr([1; 24]));
        assert_eq!(&p.as_ref()[25..], &master);
    }

    #[test]
    fn a_mail_body_round_trips() {
        let body = MailBody {
            v: 1,
            label: Some("alice".into()),
            title: "hi".into(),
            content: "there".into(),
            time_ms: 5,
            thread_id: None,
            in_reply_to: None,
            quoted_excerpt: None,
        };
        assert_eq!(MailBody::decode(&body.encode()), Some(body));
    }
}
