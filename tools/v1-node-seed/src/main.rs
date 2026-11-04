//! Put a v0.2.7 user's data on a test node.
//!
//! Registers the frozen delegates from `published-contract/wasm/v1/` and
//! fills them through their own protocol, as the v0.2.7 UI did, so the
//! real-node migration test starts from what such a user's node holds.
//! Nothing else writes to a node's delegates this way: it is for an isolated
//! test node, and it refuses to finish unless the delegates read back what it
//! wrote.
//!
//! Usage: `v1-node-seed <ws port> [capture file]`
//!        `v1-node-seed <ws port> --expect-cleared`
//!
//! `--expect-cleared` fails unless the frozen delegates no longer hold what
//! was seeded: what the real-node test runs after the app has scrubbed them.
//!
//! `v1-node-seed <ws port> --transition <key file>` (the v1 transition test,
//! `cargo make test-e2e-v1-transition`) seeds as above, then adds a contact
//! `vbob`, verified, whose seeds are fixed, writes his recovery key to the key
//! file, and publishes alice's v0.2.x inbox holding one v0.2.7-format message
//! from him, admitted by the verified-sender exemption (no token).
//! `v1-node-seed <ws port> --inbox` prints that inbox's message count, tier,
//! exemption and `last_update` as one JSON line.
//!
//! With a capture file it also writes the delegates' own `GetIdentities` and
//! `GetAll` replies there, as hex lines: the bytes `ui/src/migration/
//! captured_v0_2_7.txt` holds. Regenerate that file with
//! `cargo make capture-v0-2-7-replies`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use freenet_mail_wire_v1::identity::{EntryKind, IdentityMsg};
use freenet_mail_wire_v1::local_state::{
    ArchivedMessage, Draft, KeptMessage, LocalStateMsg, SentMessage,
};
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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The key of the contact `bob` in wire-v1's golden identity state: real key
/// bytes, so the contact is one the migration can import.
fn contact_key() -> Result<Vec<u8>, String> {
    let golden = include_str!("../../../wire-v1/src/golden_v1.txt");
    let line = golden
        .lines()
        .find_map(|l| l.strip_prefix("identity_state_contact "))
        .ok_or("no contact sample")?;
    let bytes: Vec<u8> = (0..line.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&line[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect::<Result<_, _>>()?;
    let state: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    serde_json::from_value(state["identities"]["bob"]["key"].clone()).map_err(|e| e.to_string())
}

fn identity_message(message: &IdentityMsg) -> Result<Vec<u8>, String> {
    Vec::<u8>::try_from(message).map_err(|e| e.to_string())
}

fn local_state_message(message: &LocalStateMsg) -> Result<Vec<u8>, String> {
    Vec::<u8>::try_from(message).map_err(|e| e.to_string())
}

/// The frozen delegates, and a client of the node on `port`.
async fn connect(port: &str) -> Result<(Frozen, Frozen, WebApi), String> {
    let v1 = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../published-contract/wasm/v1");
    let identity = Frozen::load(&v1, "identity_management", "identity-manager-params")?;
    let local_state = Frozen::load(&v1, "mail_local_state", "mail-local-state-params")?;
    let url = format!("ws://127.0.0.1:{port}/v1/contract/command?encodingProtocol=native");
    let (connection, _) = tokio_tungstenite::connect_async(url)
        .await
        .map_err(|e| e.to_string())?;
    Ok((identity, local_state, WebApi::start(connection)))
}

/// Fail if the delegates still hold a key or a message that was seeded. An
/// empty reply is refused too: the delegates answer reads, so it would mean
/// this check saw nothing.
async fn expect_cleared(port: &str) -> Result<(), String> {
    let (identity, local_state, mut api) = connect(port).await?;
    let identities = identity
        .ask(&mut api, identity_message(&IdentityMsg::GetIdentities)?)
        .await?;
    let state = local_state
        .ask(&mut api, local_state_message(&LocalStateMsg::GetAll)?)
        .await?;
    let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
    let (identities, state) = (text(&identities), text(&state));
    if identities.is_empty() || state.is_empty() {
        return Err("a delegate gave no answer".to_string());
    }
    for (row, left) in [
        (&identities, ALIAS),
        (&identities, "bob"),
        (&state, ARCHIVED_TITLE),
    ] {
        if row.contains(left) {
            return Err(format!("`{left}` is still in a v0.2.x delegate"));
        }
    }
    for left in ["read and kept", "unsent", "a sent message"] {
        if state.contains(left) {
            return Err(format!("`{left}` is still in a v0.2.x delegate"));
        }
    }
    println!("the v0.2.x delegates no longer hold what was seeded");
    Ok(())
}

async fn seed(port: &str) -> Result<(), String> {
    let (identity, local_state, mut api) = connect(port).await?;

    identity.register(&mut api).await?;
    local_state.register(&mut api).await?;

    let seeds = serde_json::json!({ "ml_dsa_seed": vec![9u8; 32], "ml_kem_seed": vec![10u8; 64] });
    let create = IdentityMsg::CreateIdentity {
        alias: ALIAS.into(),
        key: serde_json::to_vec(&seeds).map_err(|e| e.to_string())?,
        extra: Some("seeded".into()),
        kind: Some(EntryKind::Identity),
    };
    let contact = IdentityMsg::CreateIdentity {
        alias: "bob".into(),
        key: contact_key()?,
        extra: Some("friend".into()),
        kind: Some(EntryKind::Contact),
    };
    for message in [IdentityMsg::Init, create, contact] {
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
    let alias = || ALIAS.to_string();
    let bob = || "bob".to_string();
    let kept = LocalStateMsg::MarkRead {
        alias: alias(),
        msg_id: 3,
        kept: KeptMessage {
            from: bob(),
            title: "read and kept".into(),
            content: "a message read on v0.2.7".into(),
            kept_at: 1_761_000_001_000,
            sent_at: Some(1_761_000_000_500),
            ..Default::default()
        },
    };
    let draft = LocalStateMsg::SaveDraft {
        alias: alias(),
        id: "d1".into(),
        draft: Draft {
            to: bob(),
            subject: "unsent".into(),
            body: "a draft".into(),
            updated_at: 1_761_000_002_000,
            ..Default::default()
        },
    };
    let sent = LocalStateMsg::SaveSent {
        alias: alias(),
        id: "s1".into(),
        sent: SentMessage {
            to: bob(),
            subject: "sent".into(),
            body: "a sent message".into(),
            sent_at: 1_761_000_003_000,
            ..Default::default()
        },
    };
    for message in [LocalStateMsg::Init, archive, kept, draft, sent] {
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
    if let Some(path) = std::env::args().nth(2) {
        let lines = format!(
            "identity_reply {}\nlocal_state_reply {}\n",
            hex(&identities),
            hex(&state)
        );
        std::fs::write(&path, lines).map_err(|e| format!("{path}: {e}"))?;
    }
    println!(
        "seeded `{ALIAS}` under {} and its archive under {}",
        identity.container.key().code_hash(),
        local_state.container.key().code_hash()
    );
    Ok(())
}

// ── The v1 transition fixture ───────────────────────────────────────────────

/// The verified contact's alias and fixed seeds, and the message title the
/// test looks for.
const VBOB: &str = "vbob";
const VBOB_DSA: [u8; 32] = [11; 32];
const VBOB_KEM: [u8; 64] = [12; 64];
pub const V1_MESSAGE_TITLE: &str = "sent on v0.2.7 before the move";

fn keys(dsa: [u8; 32], kem: [u8; 64]) -> mail_delegate::crypto::Keys {
    use freenet_mail_protocol::{DsaSeed, KemSeed};
    mail_delegate::crypto::Keys::from_seeds(&DsaSeed(dsa), &KemSeed(kem))
}

fn alice() -> mail_delegate::crypto::Keys {
    keys([9; 32], [10; 64])
}

fn inbox_key(vk: &[u8]) -> Result<(ContractContainer, ContractKey), String> {
    let v1 = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../published-contract/wasm/v1");
    let code = std::fs::read(v1.join("freenet_email_inbox")).map_err(|e| e.to_string())?;
    let params: Parameters = freenet_mail_wire_v1::inbox::InboxParams {
        pub_key: vk.to_vec(),
    }
    .try_into()
    .map_err(|e: serde_json::Error| e.to_string())?;
    let container = ContractContainer::try_from((code, &params)).map_err(|e| e.to_string())?;
    let key = container.key();
    Ok((container, key))
}

/// Alice's v0.2.x inbox: one message from vbob, sealed and signed as v0.2.7
/// does, admitted because vbob is a verified sender with the exemption on.
fn transition_inbox() -> Result<Vec<u8>, String> {
    use freenet_mail_wire_v1::aft::{Tier, TokenAssignment};
    use freenet_mail_wire_v1::inbox::{Inbox, InboxSettings, Message, sign_payload};
    let (me, bob) = (alice(), keys(VBOB_DSA, VBOB_KEM));
    let plaintext = serde_json::json!({
        "title": V1_MESSAGE_TITLE,
        "content": "written to the old address",
        "from": VBOB,
        "to": [],
        "cc": [],
        "time": "2026-11-01T10:00:00Z",
    });
    let ek = mail_delegate::crypto::decode_ek(&me.ek_bytes()).ok_or("alice's key")?;
    let entropy = freenet_mail_protocol::Entropy([5; 32]);
    let mut rng = mail_delegate::crypto::MixRng::new("seed", &[6; 32], &entropy);
    let plaintext = serde_json::to_vec(&plaintext).map_err(|e| e.to_string())?;
    let content = mail_delegate::crypto::encrypt_v1(&ek, &plaintext, &mut rng);
    let now = chrono::Utc::now();
    let message = Message {
        signature: bob.sign(&content),
        content,
        token_assignment: TokenAssignment {
            tier: Tier::Min10,
            time_slot: now,
            generator: Vec::new(),
            signature: Vec::new(),
            assignment_hash: [0x77; 32],
            token_record: ContractInstanceId::new([0; 32]),
        },
        sender_vk: bob.vk_bytes(),
    };
    let settings = InboxSettings {
        allow_verified_skip_token: true,
        verified_senders: [bob.vk_bytes()].into(),
        ..InboxSettings::default()
    };
    let signature = me.sign(&sign_payload(&me.ek_bytes(), &settings, now));
    Inbox::with_signature(
        settings,
        vec![message],
        now,
        me.ek_bytes(),
        signature.into_boxed_slice(),
    )
    .serialize()
    .map_err(|e| e.to_string())
}

async fn seed_transition(port: &str, key_file: &str) -> Result<(), String> {
    seed(port).await?;
    let (identity, _, mut api) = connect(port).await?;
    let bob = keys(VBOB_DSA, VBOB_KEM);
    let contact = serde_json::json!({
        "ml_dsa_vk_bytes": bob.vk_bytes(),
        "ml_kem_ek_bytes": bob.ek_bytes(),
        "suggested_alias": VBOB,
        "verified": true,
    });
    let create = IdentityMsg::CreateIdentity {
        alias: VBOB.into(),
        key: serde_json::to_vec(&contact).map_err(|e| e.to_string())?,
        extra: Some("verified in v0.2.7".into()),
        kind: Some(EntryKind::Contact),
    };
    identity.ask(&mut api, identity_message(&create)?).await?;
    let (contract, key) = inbox_key(&alice().vk_bytes())?;
    let put = freenet_stdlib::client_api::ContractRequest::Put {
        contract,
        state: WrappedState::new(transition_inbox()?),
        related_contracts: RelatedContracts::default(),
        subscribe: false,
        blocking_subscribe: false,
    };
    api.send(ClientRequest::ContractOp(put))
        .await
        .map_err(|e| e.to_string())?;
    let answer = tokio::time::timeout(REPLY_TIMEOUT, api.recv())
        .await
        .map_err(|_| "no PUT answer in time".to_string())?
        .map_err(|e| e.to_string())?;
    println!("published alice's v0.2.x inbox {}: {answer}", key.id());
    let recovery = freenet_mail_protocol::recovery_key::encode(
        &freenet_mail_protocol::DsaSeed(VBOB_DSA),
        &freenet_mail_protocol::KemSeed(VBOB_KEM),
    );
    std::fs::write(key_file, recovery).map_err(|e| format!("{key_file}: {e}"))
}

/// Alice's v0.2.x inbox as the node holds it, as one JSON line.
async fn show_inbox(port: &str) -> Result<(), String> {
    let (_, _, mut api) = connect(port).await?;
    let (_, key) = inbox_key(&alice().vk_bytes())?;
    let get = freenet_stdlib::client_api::ContractRequest::Get {
        key: *key.id(),
        return_contract_code: false,
        subscribe: false,
        blocking_subscribe: false,
    };
    api.send(ClientRequest::ContractOp(get))
        .await
        .map_err(|e| e.to_string())?;
    let answer = tokio::time::timeout(REPLY_TIMEOUT, api.recv())
        .await
        .map_err(|_| "no GET answer in time".to_string())?
        .map_err(|e| e.to_string())?;
    let HostResponse::ContractResponse(freenet_stdlib::client_api::ContractResponse::GetResponse {
        state,
        ..
    }) = answer
    else {
        return Err(format!("not a GET answer: {answer}"));
    };
    let v: serde_json::Value = serde_json::from_slice(state.as_ref()).map_err(|e| e.to_string())?;
    let line = serde_json::json!({
        "messages": v["messages"].as_array().map_or(0, Vec::len),
        "minimum_tier": v["settings"]["minimum_tier"],
        "exemption": v["settings"]["allow_verified_skip_token"],
        "last_update": v["last_update"],
    });
    println!("{line}");
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let Some(port) = std::env::args().nth(1) else {
        eprintln!("usage: v1-node-seed <ws port>");
        std::process::exit(2);
    };
    let run = match std::env::args().nth(2).as_deref() {
        Some("--expect-cleared") => expect_cleared(&port).await,
        Some("--transition") => match std::env::args().nth(3) {
            Some(file) => seed_transition(&port, &file).await,
            None => Err("--transition needs a key file".into()),
        },
        Some("--inbox") => show_inbox(&port).await,
        _ => seed(&port).await,
    };
    if let Err(e) = run {
        eprintln!("v1-node-seed: {e}");
        std::process::exit(1);
    }
}
