//! Put a v0.2.7 user's data on a test node.
//!
//! Registers the frozen delegates from `published-contract/wasm/v1/` and
//! fills them through their own protocol, as the v0.2.7 UI did, so the
//! real-node migration test starts from what such a user's node holds.
//! Nothing else writes to a node's delegates this way: it is for an isolated
//! test node, and it refuses to finish unless the delegates read back what it
//! wrote.
//!
//! Usage: `v1-node-seed <ws port>`

use std::path::{Path, PathBuf};
use std::time::Duration;

use freenet_mail_wire_v1::identity::{EntryKind, IdentityMsg};
use freenet_mail_wire_v1::local_state::{ArchivedMessage, LocalStateMsg};
use freenet_stdlib::client_api::{ClientRequest, DelegateRequest, HostResponse, WebApi};
use freenet_stdlib::prelude::*;

/// The cipher and nonce the v0.2.x UI registered its delegates with.
const CIPHER: [u8; 32] = [
    0, 24, 22, 150, 112, 207, 24, 65, 182, 161, 169, 227, 66, 182, 237, 215, 206, 164, 58, 161, 64,
    108, 157, 195, 0, 0, 0, 0, 0, 0, 0, 0,
];
const NONCE: [u8; 24] = [
    57, 18, 79, 116, 63, 134, 93, 39, 208, 161, 156, 229, 222, 247, 111, 79, 210, 126, 127, 55,
    224, 150, 139, 80,
];

/// What the test looks for after the migration.
const ALIAS: &str = "alice";
const ARCHIVED_TITLE: &str = "kept from v0.2.7";
const ARCHIVED_BODY: &str = "this message exists only in the old delegate";

const REPLY_TIMEOUT: Duration = Duration::from_secs(30);

struct Frozen {
    container: DelegateContainer,
    params: Parameters<'static>,
}

impl Frozen {
    fn load(dir: &Path, wasm: &str, params: &str) -> Result<Self, String> {
        let read = |name: &str| std::fs::read(dir.join(name)).map_err(|e| format!("{name}: {e}"));
        let params = Parameters::from(read(params)?);
        let container =
            DelegateContainer::try_from((read(wasm)?, &params)).map_err(|e| e.to_string())?;
        Ok(Frozen { container, params })
    }

    async fn register(&self, api: &mut WebApi) -> Result<(), String> {
        let request = DelegateRequest::RegisterDelegate {
            delegate: self.container.clone(),
            cipher: CIPHER,
            nonce: NONCE,
        };
        send(api, request).await?;
        reply(api).await.map(|_| ())
    }

    /// One message, and the delegate's answer (empty if it gives none).
    async fn ask(&self, api: &mut WebApi, message: Vec<u8>) -> Result<Vec<u8>, String> {
        let request = DelegateRequest::ApplicationMessages {
            key: self.container.key().clone(),
            params: self.params.clone(),
            inbound: vec![InboundDelegateMsg::ApplicationMessage(
                ApplicationMessage::new(message),
            )],
        };
        send(api, request).await?;
        reply(api).await
    }
}

async fn send(api: &mut WebApi, request: DelegateRequest<'static>) -> Result<(), String> {
    api.send(ClientRequest::DelegateOp(request))
        .await
        .map_err(|e| e.to_string())
}

async fn reply(api: &mut WebApi) -> Result<Vec<u8>, String> {
    let answer = tokio::time::timeout(REPLY_TIMEOUT, api.recv())
        .await
        .map_err(|_| "no reply in time".to_string())?
        .map_err(|e| e.to_string())?;
    let HostResponse::DelegateResponse { values, .. } = answer else {
        return Err(format!("not a delegate response: {answer}"));
    };
    Ok(values
        .into_iter()
        .find_map(|value| match value {
            OutboundDelegateMsg::ApplicationMessage(message) => Some(message.payload.to_vec()),
            _ => None,
        })
        .unwrap_or_default())
}

fn identity_message(message: &IdentityMsg) -> Result<Vec<u8>, String> {
    Vec::<u8>::try_from(message).map_err(|e| e.to_string())
}

fn local_state_message(message: &LocalStateMsg) -> Result<Vec<u8>, String> {
    Vec::<u8>::try_from(message).map_err(|e| e.to_string())
}

async fn seed(port: &str) -> Result<(), String> {
    let v1 = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../published-contract/wasm/v1");
    let identity = Frozen::load(&v1, "identity_management", "identity-manager-params")?;
    let local_state = Frozen::load(&v1, "mail_local_state", "mail-local-state-params")?;

    let url = format!("ws://127.0.0.1:{port}/v1/contract/command?encodingProtocol=native");
    let (connection, _) = tokio_tungstenite::connect_async(url)
        .await
        .map_err(|e| e.to_string())?;
    let mut api = WebApi::start(connection);

    identity.register(&mut api).await?;
    local_state.register(&mut api).await?;

    let seeds = serde_json::json!({ "ml_dsa_seed": vec![9u8; 32], "ml_kem_seed": vec![10u8; 64] });
    let create = IdentityMsg::CreateIdentity {
        alias: ALIAS.into(),
        key: serde_json::to_vec(&seeds).map_err(|e| e.to_string())?,
        extra: Some("seeded".into()),
        kind: Some(EntryKind::Identity),
    };
    for message in [IdentityMsg::Init, create] {
        identity.ask(&mut api, identity_message(&message)?).await?;
    }
    let archive = LocalStateMsg::ArchiveMessage {
        alias: ALIAS.into(),
        msg_id: 4,
        archived: ArchivedMessage {
            from: "bob".into(),
            title: ARCHIVED_TITLE.into(),
            content: ARCHIVED_BODY.into(),
            archived_at: 1_761_000_000_000,
            thread_id: None,
            in_reply_to: None,
            quoted_excerpt: None,
        },
    };
    for message in [LocalStateMsg::Init, archive] {
        local_state
            .ask(&mut api, local_state_message(&message)?)
            .await?;
    }

    let identities = identity
        .ask(&mut api, identity_message(&IdentityMsg::GetIdentities)?)
        .await?;
    let state = local_state
        .ask(&mut api, local_state_message(&LocalStateMsg::GetAll)?)
        .await?;
    let holds = |bytes: &[u8], text: &str| String::from_utf8_lossy(bytes).contains(text);
    if !holds(&identities, ALIAS) || !holds(&state, ARCHIVED_TITLE) {
        return Err("the delegates did not read back what was written".to_string());
    }
    println!(
        "seeded `{ALIAS}` under {} and its archive under {}",
        identity.container.key().code_hash(),
        local_state.container.key().code_hash()
    );
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let Some(port) = std::env::args().nth(1) else {
        eprintln!("usage: v1-node-seed <ws port>");
        std::process::exit(2);
    };
    if let Err(e) = seed(&port).await {
        eprintln!("v1-node-seed: {e}");
        std::process::exit(1);
    }
}
