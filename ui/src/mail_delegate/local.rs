//! The offline backend: the real mail delegate's code, run in the page over
//! an in-memory store. Used by the offline build (`example-data`,
//! `no-sync`), so the UI exercises the same protocol, origin scoping and
//! compare-and-swap rules it meets on a node. Nothing persists across a
//! reload.
//!
//! Prompts the delegate raises (exports, identity deletion) are answered
//! with their first choice, as a user clicking it would.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};

use freenet_stdlib::prelude::{
    ApplicationMessage, ClientResponse, ContractInstanceId, DelegateContext, InboundDelegateMsg,
    MessageOrigin, OutboundDelegateMsg, UserInputResponse,
};
use mail_delegate::env::Env;

/// The web-app origin the offline build presents.
pub(crate) const ORIGIN: [u8; 32] = [0x4d; 32];

#[derive(Default)]
struct PageEnv {
    secrets: BTreeMap<Vec<u8>, Vec<u8>>,
    contracts: HashMap<[u8; 32], Vec<u8>>,
}

impl Env for PageEnv {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.secrets.get(key).cloned()
    }
    fn set(&mut self, key: &[u8], value: &[u8]) -> bool {
        self.secrets.insert(key.to_vec(), value.to_vec());
        true
    }
    fn remove(&mut self, key: &[u8]) -> bool {
        self.secrets.remove(key).is_some()
    }
    fn host_random(&mut self) -> [u8; 32] {
        crate::rng::random_bytes()
    }
    fn now_secs(&self) -> Option<u64> {
        u64::try_from(chrono::Utc::now().timestamp()).ok()
    }
    fn contract_state(&self, instance_id: &[u8; 32]) -> Option<Vec<u8>> {
        self.contracts.get(instance_id).cloned()
    }
}

thread_local! {
    static ENV: RefCell<PageEnv> = RefCell::new(PageEnv::default());
}

/// Make a contract's state readable to the delegate, as a node holding it
/// would (the offline build keeps inboxes in memory).
pub(crate) fn set_contract_state(instance_id: [u8; 32], state: Vec<u8>) {
    ENV.with(|e| e.borrow_mut().contracts.insert(instance_id, state));
}

fn origin() -> Option<MessageOrigin> {
    Some(MessageOrigin::WebApp(ContractInstanceId::new(ORIGIN)))
}

/// Run one encoded request through the delegate and deliver its answers.
pub(crate) fn process(bytes: &[u8]) {
    run(InboundDelegateMsg::ApplicationMessage(
        ApplicationMessage::new(bytes.to_vec()),
    ));
}

fn run(message: InboundDelegateMsg<'static>) {
    let outbound =
        ENV.with(|e| mail_delegate::handlers::process(&mut *e.borrow_mut(), origin(), message));
    let outbound = match outbound {
        Ok(outbound) => outbound,
        Err(e) => {
            crate::log::error(format!("offline mail delegate: {e}"), None);
            return;
        }
    };
    for msg in outbound {
        match msg {
            OutboundDelegateMsg::ApplicationMessage(app) => {
                super::deliver(&app.payload);
            }
            OutboundDelegateMsg::RequestUserInput(prompt) => {
                let Some(first) = prompt.responses.first() else {
                    continue;
                };
                let answer = UserInputResponse {
                    request_id: prompt.request_id,
                    response: ClientResponse::new(first.to_vec()),
                    context: DelegateContext::default(),
                };
                run(InboundDelegateMsg::UserResponse(answer));
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use freenet_mail_protocol::{Entropy, Op, Reply};

    use super::super::call;

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        futures::executor::block_on(f)
    }

    #[test]
    fn identities_round_trip_through_the_in_page_delegate() {
        let Reply::CreatedIdentity {
            identity: created, ..
        } = block_on(call(Op::CreateIdentity {
            alias: "local-test".into(),
            description: String::new(),
            ui_entropy: Entropy([9; 32]),
        }))
        .unwrap()
        else {
            panic!("expected CreatedIdentity");
        };
        let Reply::Identities(all) = block_on(call(Op::ListIdentities)).unwrap() else {
            panic!("expected Identities");
        };
        assert!(all.iter().any(|i| i.addr == created.addr));
    }

    #[test]
    fn an_export_prompt_is_answered_and_returns_the_key() {
        let Reply::CreatedIdentity {
            identity: id,
            recovery_key,
        } = block_on(call(Op::CreateIdentity {
            alias: "export-test".into(),
            description: String::new(),
            ui_entropy: Entropy([8; 32]),
        }))
        .unwrap()
        else {
            panic!("expected CreatedIdentity");
        };
        // A later reveal is the consented export, and gives the same key.
        let reply = block_on(call(Op::ExportRecoveryKey { addr: id.addr })).unwrap();
        assert!(matches!(reply, Reply::RecoveryKey(k) if k == recovery_key));
    }

    /// The UI's delete loop against the real delegate: an identity owning
    /// more than one page of items reports what is left after each page, and
    /// is gone at the end, with its items.
    #[test]
    fn deleting_a_large_identity_reports_progress_until_it_is_gone() {
        let Reply::CreatedIdentity { identity: id, .. } = block_on(call(Op::CreateIdentity {
            alias: "delete-progress-test".into(),
            description: String::new(),
            ui_entropy: Entropy([7; 32]),
        }))
        .unwrap() else {
            panic!("expected CreatedIdentity");
        };
        for i in 0u32..300 {
            let mut item_id = [0u8; 16];
            item_id[..4].copy_from_slice(&i.to_le_bytes());
            let item = freenet_mail_protocol::ItemRef {
                kind: freenet_mail_protocol::ItemKind::Flags,
                owner: Some(id.addr),
                id: item_id.to_vec(),
            };
            block_on(super::super::ops::put_item(item, b"{}".to_vec(), None)).unwrap();
        }
        let mut reports = Vec::new();
        block_on(super::super::ops::delete_identity(
            id.addr,
            id.generation,
            |left| reports.push(left),
        ))
        .unwrap();
        assert!(!reports.is_empty(), "more than a page reports progress");
        assert!(
            reports.windows(2).all(|w| w[1] < w[0]),
            "what is left only goes down: {reports:?}"
        );
        let Reply::Identities(all) = block_on(call(Op::ListIdentities)).unwrap() else {
            panic!("expected Identities");
        };
        assert!(
            all.iter().all(|i| i.addr != id.addr),
            "the identity is gone"
        );
    }
}
