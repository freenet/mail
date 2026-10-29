//! Request dispatch: the origin gate, then one handler per operation.

use freenet_mail_protocol::address::address_of;
use freenet_mail_protocol::{
    Addr, DsaSeed, Entropy, Failure, FailureCode, IdentityInfo, ImportSource, Item, ItemKind,
    ItemRef, KemSeed, MAX_DECRYPT_BATCH, MAX_ITEM_BYTES, MAX_REMOVAL_BATCH, MAX_RESPONSE_BYTES, Op,
    PROTOCOL_VERSION, Reply, Request, RequestId, Response, Status, recovery_key, to_cbor,
};
use freenet_stdlib::prelude::{
    ApplicationMessage, ContractInstanceId, DelegateError, InboundDelegateMsg, MessageOrigin,
    OutboundDelegateMsg,
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::consent;
use crate::crypto::{self, Keys, MixRng};
use crate::env::{Env, MigrateView};
use crate::store::{self, Origin};

pub type OpResult = Result<Reply, Failure>;

pub fn fail(code: FailureCode, detail: impl Into<String>) -> Failure {
    Failure {
        code,
        detail: detail.into(),
    }
}

/// The single entry point.
pub fn process(
    env: &mut dyn Env,
    origin: Option<MessageOrigin>,
    message: InboundDelegateMsg,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    match message {
        InboundDelegateMsg::ApplicationMessage(app) => {
            let origin = check_origin(origin.as_ref())?;
            if app.processed {
                return Err(DelegateError::Other(
                    "cannot process an already processed message".into(),
                ));
            }
            let request: Request = freenet_mail_protocol::from_cbor(&app.payload)
                .map_err(|e| DelegateError::Deser(format!("request: {e}")))?;
            handle_request(env, &origin, request)
        }
        InboundDelegateMsg::UserResponse(answer) => {
            let origin = check_origin(origin.as_ref())?;
            consent::answer(env, &origin, &answer)
        }
        _ => Err(DelegateError::Other(
            "the mail delegate accepts only application messages and prompt answers".into(),
        )),
    }
}

/// The origin gate, run before ANY request is looked at (River's
/// `check_origin`). Only a web app's attested contract id is accepted; it
/// names the namespace every key of the request lives in. Calls from other
/// delegates, unattested calls and unknown origin kinds are refused.
pub fn check_origin(origin: Option<&MessageOrigin>) -> Result<Origin, DelegateError> {
    match origin {
        Some(MessageOrigin::WebApp(id)) => {
            let bytes: [u8; 32] = id.as_bytes().try_into().map_err(|_| {
                DelegateError::Other("web-app origin is not a 32-byte contract id".into())
            })?;
            Ok(Origin(bytes))
        }
        Some(MessageOrigin::Delegate(_)) => Err(DelegateError::Other(
            "the mail delegate does not accept calls from other delegates".into(),
        )),
        None => Err(DelegateError::Other(
            "the mail delegate requires an attested web-app origin".into(),
        )),
        _ => Err(DelegateError::Other(
            "unknown message origin: the mail delegate must be rebuilt against a newer stdlib"
                .into(),
        )),
    }
}

pub fn respond(request_id: RequestId, result: OpResult) -> Vec<OutboundDelegateMsg> {
    let response = Response { request_id, result };
    // Encoding a Response cannot fail: it holds no maps with non-string keys
    // and no floats. Should it ever, the caller still gets an answer.
    let payload = to_cbor(&response).unwrap_or_else(|e| {
        to_cbor(&Response {
            request_id,
            result: Err(fail(FailureCode::Internal, e)),
        })
        .unwrap_or_default()
    });
    vec![OutboundDelegateMsg::ApplicationMessage(
        ApplicationMessage::new(payload).processed(true),
    )]
}

fn handle_request(
    env: &mut dyn Env,
    origin: &Origin,
    request: Request,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    let id = request.request_id;
    if request.version != PROTOCOL_VERSION {
        return Ok(respond(
            id,
            Err(fail(
                FailureCode::UnsupportedVersion,
                format!(
                    "protocol {} (this delegate speaks {PROTOCOL_VERSION})",
                    request.version
                ),
            )),
        ));
    }
    let result = match request.op {
        // Exports may raise a prompt instead of answering now.
        op @ (Op::ExportRecoveryKey { .. } | Op::ExportProfile { .. }) => {
            return consent::request_export(env, origin, id, op);
        }
        Op::GetStatus => status(env, origin),
        Op::ListIdentities => list_identities(env, origin),
        Op::CreateIdentity {
            alias,
            description,
            ui_entropy,
        } => create_identity(env, origin, alias, description, &ui_entropy),
        Op::ImportIdentity {
            source,
            alias,
            description,
        } => import_identity(env, origin, source, alias, description),
        Op::UpdateIdentity {
            addr,
            alias,
            description,
            expected_gen,
        } => update_identity(env, origin, &addr, alias, description, expected_gen),
        Op::DeleteIdentity { addr, expected_gen } => {
            delete_identity(env, origin, &addr, expected_gen)
        }
        Op::ListItems {
            kind,
            owner,
            after,
            limit,
        } => list_items(
            env,
            origin,
            kind,
            owner,
            after.as_ref().map(|a| a.as_slice()),
            limit,
        ),
        Op::GetItem { item } => get_item(env, origin, item),
        Op::PutItem {
            item,
            body,
            expected_gen,
        } => put_item(env, origin, item, body.into_vec(), expected_gen),
        Op::DeleteItem { item, expected_gen } => delete_item(env, origin, item, expected_gen),
        Op::DecryptV1 { addr, ciphertexts } => decrypt_v1(env, origin, &addr, ciphertexts),
        Op::SealV1Message {
            addr,
            recipient_ek,
            plaintext,
            ui_entropy,
        } => seal_v1(env, origin, &addr, &recipient_ek, &plaintext, &ui_entropy),
        Op::SignV1Authority {
            addr,
            settings_json,
            last_update_micros,
        } => sign_v1_authority(env, origin, &addr, &settings_json, last_update_micros),
        Op::SignV1Removal {
            addr,
            assignment_hashes,
        } => sign_v1_removal(env, origin, &addr, &assignment_hashes),
        Op::V1AftParams { addr } => v1_aft_params(env, origin, &addr),
        Op::ExportForSuccessor { source_generation } => {
            export_for_successor(env, origin, source_generation)
        }
    };
    Ok(respond(id, result))
}

// ── Identities ──────────────────────────────────────────────────────────────

/// What is stored per identity. Only the delegate ever reads the seeds.
#[derive(Clone, Serialize, Deserialize)]
pub struct IdentityRecord {
    pub v: u8,
    pub dsa: DsaSeed,
    pub kem: KemSeed,
    pub vk: ByteBuf,
    pub ek: ByteBuf,
    pub alias: String,
    pub description: String,
    pub confirmed: bool,
}

const MAX_ALIAS_CHARS: usize = 64;
const MAX_DESCRIPTION_CHARS: usize = 1024;

fn check_names(alias: &str, description: &str) -> Result<(), Failure> {
    let n = alias.chars().count();
    if n == 0 || n > MAX_ALIAS_CHARS || alias.chars().any(char::is_control) {
        return Err(fail(
            FailureCode::BadInput,
            "alias must be 1-64 printable characters",
        ));
    }
    if description.chars().count() > MAX_DESCRIPTION_CHARS {
        return Err(fail(FailureCode::BadInput, "description is too long"));
    }
    Ok(())
}

fn info(addr: Addr, generation: u64, r: &IdentityRecord) -> IdentityInfo {
    IdentityInfo {
        addr,
        vk: r.vk.clone(),
        ek: r.ek.clone(),
        alias: r.alias.clone(),
        description: r.description.clone(),
        confirmed: r.confirmed,
        generation,
    }
}

fn corrupt(what: &str) -> Failure {
    fail(
        FailureCode::Internal,
        format!("stored {what} is unreadable"),
    )
}

pub fn load_identity(
    env: &dyn Env,
    origin: &Origin,
    addr: &Addr,
) -> Result<Option<(u64, IdentityRecord)>, Failure> {
    match store::read(env, &store::identity_key(origin, addr)) {
        Ok(None) => Ok(None),
        Ok(Some((generation, body))) => freenet_mail_protocol::from_cbor(&body)
            .map(|r| Some((generation, r)))
            .map_err(|_| corrupt("identity")),
        Err(store::Corrupt) => Err(corrupt("identity")),
    }
}

pub fn require_identity(
    env: &dyn Env,
    origin: &Origin,
    addr: &Addr,
) -> Result<(u64, IdentityRecord), Failure> {
    load_identity(env, origin, addr)?.ok_or_else(|| fail(FailureCode::NotFound, "no such identity"))
}

fn all_identities(
    env: &dyn Env,
    origin: &Origin,
) -> Result<Vec<(Addr, u64, IdentityRecord)>, Failure> {
    let prefix = store::identity_prefix(origin);
    let mut out = Vec::new();
    for key in env.list(&prefix) {
        let id = store::id_from_key(&key, prefix.len())
            .and_then(|b| <[u8; 24]>::try_from(b.as_slice()).ok())
            .ok_or_else(|| corrupt("identity key"))?;
        let addr = Addr(id);
        if let Some((g, r)) = load_identity(env, origin, &addr)? {
            out.push((addr, g, r));
        }
    }
    out.sort_by_key(|(addr, _, _)| *addr);
    Ok(out)
}

fn write_record(
    env: &mut dyn Env,
    origin: &Origin,
    key: &[u8],
    body: &[u8],
) -> Result<u64, Failure> {
    let generation = store::next_generation(env, origin).ok_or_else(|| {
        fail(
            FailureCode::Internal,
            "could not advance the generation counter",
        )
    })?;
    if env.set(key, &store::encode_versioned(generation, body)) {
        Ok(generation)
    } else {
        Err(fail(FailureCode::Internal, "the host refused the write"))
    }
}

fn status(env: &dyn Env, origin: &Origin) -> OpResult {
    Ok(Reply::Status(Status {
        protocol_version: PROTOCOL_VERSION,
        identities: env.list(&store::identity_prefix(origin)).len() as u32,
        stored_keys: env.list(b"").len() as u32,
        key_budget: store::KEY_BUDGET as u32,
        v1_transition: cfg!(feature = "v1-transition"),
    }))
}

fn list_identities(env: &dyn Env, origin: &Origin) -> OpResult {
    Ok(Reply::Identities(
        all_identities(env, origin)?
            .iter()
            .map(|(a, g, r)| info(*a, *g, r))
            .collect(),
    ))
}

/// Store a new identity under its address. The caller has checked it is new.
fn store_new_identity(
    env: &mut dyn Env,
    origin: &Origin,
    dsa: DsaSeed,
    kem: KemSeed,
    alias: String,
    description: String,
) -> Result<IdentityInfo, Failure> {
    let existing = all_identities(env, origin)?;
    if existing.iter().any(|(_, _, r)| r.alias == alias) {
        return Err(fail(
            FailureCode::Conflict { current_gen: 0 },
            "an identity with this alias exists",
        ));
    }
    if existing.len() >= store::MAX_IDENTITIES {
        return Err(fail(FailureCode::CapReached, "too many identities"));
    }
    if !store::budget_has_room(env) {
        return Err(fail(
            FailureCode::CapReached,
            "the delegate's storage budget is full",
        ));
    }
    let keys = Keys::from_seeds(&dsa, &kem);
    let vk = keys.vk_bytes();
    let addr = address_of(&vk);
    let record = IdentityRecord {
        v: 1,
        dsa,
        kem,
        vk: ByteBuf::from(vk),
        ek: ByteBuf::from(keys.ek_bytes()),
        alias,
        description,
        confirmed: true,
    };
    let body = to_cbor(&record).map_err(|e| fail(FailureCode::Internal, e))?;
    let generation = write_record(env, origin, &store::identity_key(origin, &addr), &body)?;
    Ok(info(addr, generation, &record))
}

fn create_identity(
    env: &mut dyn Env,
    origin: &Origin,
    alias: String,
    description: String,
    ui_entropy: &Entropy,
) -> OpResult {
    check_names(&alias, &description)?;
    if ui_entropy.0 == [0; 32] {
        return Err(fail(
            FailureCode::BadInput,
            "ui_entropy must be random bytes",
        ));
    }
    let host = env.host_random();
    let (dsa, kem) = crypto::new_seeds(&mut MixRng::new("create-identity", &host, ui_entropy));
    let addr = address_of(&Keys::from_seeds(&dsa, &kem).vk_bytes());
    if load_identity(env, origin, &addr)?.is_some() {
        // Only possible if both entropy sources repeated.
        return Err(fail(
            FailureCode::Internal,
            "generated an existing identity; retry",
        ));
    }
    store_new_identity(env, origin, dsa, kem, alias, description).map(Reply::Identity)
}

/// The v2 JSON identity backup written by v0.2.x (`IdentityBackup`).
#[derive(Serialize, Deserialize)]
pub struct LegacyBackup {
    pub version: u32,
    pub alias: String,
    pub description: String,
    pub keys: LegacyKeys,
}

#[derive(Serialize, Deserialize)]
pub struct LegacyKeys {
    pub ml_dsa_seed: Vec<u8>,
    pub ml_kem_seed: Vec<u8>,
}

fn seeds_from(source: ImportSource) -> Result<(DsaSeed, KemSeed), Failure> {
    match source {
        ImportSource::Seeds { dsa, kem } => Ok((dsa, kem)),
        ImportSource::RecoveryKey(text) => {
            recovery_key::decode(&text).map_err(|e| fail(FailureCode::BadInput, e.to_string()))
        }
        ImportSource::LegacyJson(bytes) => {
            let backup: LegacyBackup = serde_json::from_slice(&bytes)
                .map_err(|_| fail(FailureCode::BadInput, "not a Freenet Mail backup file"))?;
            if backup.version != 2 {
                return Err(fail(FailureCode::BadInput, "unsupported backup version"));
            }
            let dsa = <[u8; 32]>::try_from(backup.keys.ml_dsa_seed.as_slice());
            let kem = <[u8; 64]>::try_from(backup.keys.ml_kem_seed.as_slice());
            match (dsa, kem) {
                (Ok(d), Ok(k)) => Ok((DsaSeed(d), KemSeed(k))),
                _ => Err(fail(
                    FailureCode::BadInput,
                    "backup key data is the wrong size",
                )),
            }
        }
    }
}

fn import_identity(
    env: &mut dyn Env,
    origin: &Origin,
    source: ImportSource,
    alias: String,
    description: String,
) -> OpResult {
    let (dsa, kem) = seeds_from(source)?;
    let addr = address_of(&Keys::from_seeds(&dsa, &kem).vk_bytes());
    // Never overwrite: the same address means the same seeds.
    if let Some((generation, record)) = load_identity(env, origin, &addr)? {
        return Ok(Reply::Imported {
            identity: info(addr, generation, &record),
            already_present: true,
        });
    }
    check_names(&alias, &description)?;
    store_new_identity(env, origin, dsa, kem, alias, description).map(|identity| Reply::Imported {
        identity,
        already_present: false,
    })
}

fn update_identity(
    env: &mut dyn Env,
    origin: &Origin,
    addr: &Addr,
    alias: String,
    description: String,
    expected_gen: u64,
) -> OpResult {
    check_names(&alias, &description)?;
    let (generation, mut record) = require_identity(env, origin, addr)?;
    if generation != expected_gen {
        if record.alias == alias && record.description == description {
            return Ok(Reply::Ack { generation });
        }
        return Err(fail(
            FailureCode::Conflict {
                current_gen: generation,
            },
            "stale generation",
        ));
    }
    if all_identities(env, origin)?
        .iter()
        .any(|(a, _, r)| a != addr && r.alias == alias)
    {
        return Err(fail(
            FailureCode::Conflict {
                current_gen: generation,
            },
            "alias in use",
        ));
    }
    record.alias = alias;
    record.description = description;
    let body = to_cbor(&record).map_err(|e| fail(FailureCode::Internal, e))?;
    let generation = write_record(env, origin, &store::identity_key(origin, addr), &body)?;
    Ok(Reply::Ack { generation })
}

fn delete_identity(env: &mut dyn Env, origin: &Origin, addr: &Addr, expected_gen: u64) -> OpResult {
    let Some((generation, _)) = load_identity(env, origin, addr)? else {
        // Already gone: a retried delete whose answer was lost.
        return Ok(Reply::Deleted);
    };
    if generation != expected_gen {
        return Err(fail(
            FailureCode::Conflict {
                current_gen: generation,
            },
            "stale generation",
        ));
    }
    if env.remove(&store::identity_key(origin, addr)) {
        Ok(Reply::Deleted)
    } else {
        Err(fail(FailureCode::Internal, "the host refused the delete"))
    }
}

// ── Items ───────────────────────────────────────────────────────────────────

fn check_item(env: &dyn Env, origin: &Origin, item: &ItemRef) -> Result<(), Failure> {
    let (owned, id_len) = store::shape(item.kind);
    if owned != item.owner.is_some() {
        return Err(fail(
            FailureCode::BadInput,
            if owned {
                "this kind belongs to an identity"
            } else {
                "this kind has no owner"
            },
        ));
    }
    if item.id.len() != id_len {
        return Err(fail(
            FailureCode::BadInput,
            format!("id must be {id_len} bytes"),
        ));
    }
    if let Some(owner) = &item.owner {
        require_identity(env, origin, owner)?;
    }
    Ok(())
}

fn read_item(
    env: &dyn Env,
    origin: &Origin,
    item: &ItemRef,
) -> Result<Option<(u64, Vec<u8>)>, Failure> {
    store::read(env, &store::item_key(origin, item)).map_err(|store::Corrupt| corrupt("item"))
}

fn get_item(env: &dyn Env, origin: &Origin, item: ItemRef) -> OpResult {
    check_item(env, origin, &item)?;
    Ok(Reply::Item(read_item(env, origin, &item)?.map(
        |(generation, body)| Item {
            item,
            body: ByteBuf::from(body),
            generation,
        },
    )))
}

fn put_item(
    env: &mut dyn Env,
    origin: &Origin,
    item: ItemRef,
    body: Vec<u8>,
    expected_gen: Option<u64>,
) -> OpResult {
    check_item(env, origin, &item)?;
    if body.len() > MAX_ITEM_BYTES {
        return Err(fail(FailureCode::BadInput, "item body is too large"));
    }
    let current = read_item(env, origin, &item)?;
    let current_gen = current.as_ref().map_or(0, |(g, _)| *g);
    let matches = match expected_gen {
        None => current.is_none(),
        Some(g) => g == current_gen,
    };
    if !matches {
        // A retry of a write that landed but whose answer was lost.
        if let Some((g, stored)) = &current
            && *stored == body
        {
            return Ok(Reply::Ack { generation: *g });
        }
        return Err(fail(
            FailureCode::Conflict { current_gen },
            "stale generation",
        ));
    }
    if current.is_none() {
        let prefix = store::item_prefix(origin, item.kind, item.owner.as_ref());
        if env.list(&prefix).len() >= store::cap(item.kind) {
            return Err(fail(FailureCode::CapReached, "too many items of this kind"));
        }
        if !store::budget_has_room(env) {
            return Err(fail(
                FailureCode::CapReached,
                "the delegate's storage budget is full",
            ));
        }
    }
    let generation = write_record(env, origin, &store::item_key(origin, &item), &body)?;
    Ok(Reply::Ack { generation })
}

fn delete_item(env: &mut dyn Env, origin: &Origin, item: ItemRef, expected_gen: u64) -> OpResult {
    check_item(env, origin, &item)?;
    let Some((generation, _)) = read_item(env, origin, &item)? else {
        return Ok(Reply::Deleted);
    };
    if generation != expected_gen {
        return Err(fail(
            FailureCode::Conflict {
                current_gen: generation,
            },
            "stale generation",
        ));
    }
    if env.remove(&store::item_key(origin, &item)) {
        Ok(Reply::Deleted)
    } else {
        Err(fail(FailureCode::Internal, "the host refused the delete"))
    }
}

const MAX_PAGE: usize = 256;

fn list_items(
    env: &dyn Env,
    origin: &Origin,
    kind: ItemKind,
    owner: Option<Addr>,
    after: Option<&[u8]>,
    limit: u16,
) -> OpResult {
    let (owned, _) = store::shape(kind);
    if owned != owner.is_some() {
        return Err(fail(FailureCode::BadInput, "owner does not match the kind"));
    }
    if let Some(o) = &owner {
        require_identity(env, origin, o)?;
    }
    if env.list(b"").len() >= store::HOST_ENUMERATION_CAP {
        // The host would have truncated the listing: refuse rather than
        // present a partial list as complete.
        return Err(fail(
            FailureCode::Internal,
            "storage enumeration is truncated",
        ));
    }
    let prefix = store::item_prefix(origin, kind, owner.as_ref());
    let mut ids: Vec<Vec<u8>> = env
        .list(&prefix)
        .iter()
        .filter_map(|k| store::id_from_key(k, prefix.len()))
        .filter(|id| after.is_none_or(|a| id.as_slice() > a))
        .collect();
    ids.sort();
    let limit = (limit as usize).clamp(1, MAX_PAGE);
    // Leave room for the envelope around the items.
    let budget = MAX_RESPONSE_BYTES - 4096;
    let mut used = 0;
    let mut items = Vec::new();
    let mut more = false;
    for id in ids {
        let item = ItemRef { kind, owner, id };
        let Some((generation, body)) = read_item(env, origin, &item)? else {
            continue;
        };
        if items.len() == limit || used + body.len() + 64 > budget {
            more = true;
            break;
        }
        used += body.len() + 64;
        items.push(Item {
            item,
            body: ByteBuf::from(body),
            generation,
        });
    }
    Ok(Reply::Items { items, more })
}

// ── v0.2.x crypto ───────────────────────────────────────────────────────────

fn keys_for(env: &dyn Env, origin: &Origin, addr: &Addr) -> Result<Keys, Failure> {
    let (_, record) = require_identity(env, origin, addr)?;
    Ok(Keys::from_seeds(&record.dsa, &record.kem))
}

fn decrypt_v1(env: &dyn Env, origin: &Origin, addr: &Addr, ciphertexts: Vec<ByteBuf>) -> OpResult {
    if ciphertexts.len() > MAX_DECRYPT_BATCH {
        return Err(fail(
            FailureCode::BadInput,
            "too many ciphertexts in one call",
        ));
    }
    let keys = keys_for(env, origin, addr)?;
    let mut total = 0;
    let mut out = Vec::with_capacity(ciphertexts.len());
    for ct in ciphertexts {
        match crypto::decrypt_v1(&keys.kem, &ct) {
            Some(pt) if total + pt.len() <= MAX_RESPONSE_BYTES - 4096 => {
                total += pt.len();
                out.push(Ok(ByteBuf::from(pt)));
            }
            Some(_) => out.push(Err(FailureCode::CapReached)),
            None => out.push(Err(FailureCode::BadInput)),
        }
    }
    Ok(Reply::Decrypted(out))
}

fn seal_v1(
    env: &mut dyn Env,
    origin: &Origin,
    addr: &Addr,
    recipient_ek: &[u8],
    plaintext: &[u8],
    ui_entropy: &Entropy,
) -> OpResult {
    if ui_entropy.0 == [0; 32] {
        return Err(fail(
            FailureCode::BadInput,
            "ui_entropy must be random bytes",
        ));
    }
    if plaintext.len() > MAX_ITEM_BYTES {
        return Err(fail(FailureCode::BadInput, "message is too large"));
    }
    let keys = keys_for(env, origin, addr)?;
    let ek = crypto::decode_ek(recipient_ek).ok_or_else(|| {
        fail(
            FailureCode::BadInput,
            "recipient key is not an ML-KEM-768 key",
        )
    })?;
    let host = env.host_random();
    let content = crypto::encrypt_v1(
        &ek,
        plaintext,
        &mut MixRng::new("seal-v1", &host, ui_entropy),
    );
    // The signature covers a ciphertext the delegate just produced with fresh
    // randomness, so a caller cannot obtain a signature over bytes it chose.
    let signature = keys.sign(&content);
    Ok(Reply::SealedV1 {
        content: ByteBuf::from(content),
        signature: ByteBuf::from(signature),
        sender_vk: ByteBuf::from(keys.vk_bytes()),
    })
}

fn sign_v1_authority(
    env: &dyn Env,
    origin: &Origin,
    addr: &Addr,
    settings_json: &[u8],
    last_update_micros: i64,
) -> OpResult {
    use freenet_mail_wire_v1::inbox::{InboxSettings, sign_payload};
    let keys = keys_for(env, origin, addr)?;
    let settings: InboxSettings = serde_json::from_slice(settings_json)
        .map_err(|_| fail(FailureCode::BadInput, "settings are not v1 inbox settings"))?;
    let last_update = chrono::DateTime::from_timestamp_micros(last_update_micros)
        .ok_or_else(|| fail(FailureCode::BadInput, "timestamp out of range"))?;
    // The delegate supplies its own encapsulation key: the signature can only
    // ever authorize this identity's inbox with this identity's key.
    let payload = sign_payload(&keys.ek_bytes(), &settings, last_update);
    Ok(Reply::Signature(ByteBuf::from(keys.sign(&payload))))
}

fn sign_v1_removal(
    env: &dyn Env,
    origin: &Origin,
    addr: &Addr,
    hashes: &[freenet_mail_protocol::Hash32],
) -> OpResult {
    if hashes.is_empty() || hashes.len() > MAX_REMOVAL_BATCH {
        return Err(fail(
            FailureCode::BadInput,
            "1-1024 message hashes per removal",
        ));
    }
    let payload: Vec<u8> = hashes.iter().flat_map(|h| h.0).collect();
    // The v1 removal payload carries no domain tag, so a caller choosing the
    // hashes could otherwise make it equal an inbox authority payload, which
    // always starts with this salt, and get settings signed as a removal.
    if payload.starts_with(freenet_mail_wire_v1::inbox::STATE_UPDATE) {
        return Err(fail(
            FailureCode::Refused,
            "payload aliases an inbox authority payload",
        ));
    }
    let keys = keys_for(env, origin, addr)?;
    Ok(Reply::Signature(ByteBuf::from(keys.sign(&payload))))
}

#[cfg(feature = "v1-transition")]
fn v1_aft_params(env: &dyn Env, origin: &Origin, addr: &Addr) -> OpResult {
    let (_, record) = require_identity(env, origin, addr)?;
    let params = freenet_mail_wire_v1::aft::DelegateParameters::new(record.dsa.0);
    serde_json::to_vec(&params)
        .map(|b| Reply::AftParams(ByteBuf::from(b)))
        .map_err(|e| fail(FailureCode::Internal, e.to_string()))
}

#[cfg(not(feature = "v1-transition"))]
fn v1_aft_params(_: &dyn Env, _: &Origin, _: &Addr) -> OpResult {
    Err(fail(FailureCode::Refused, "this build has no v1 send path"))
}

// ── Migration ───────────────────────────────────────────────────────────────

fn export_for_successor(env: &dyn Env, origin: &Origin, source_generation: u32) -> OpResult {
    use freenet_migrate::{ExportRequest, ExportScope, OriginPolicy, handle_export_request};
    let contract = ContractInstanceId::new(origin.0);
    let attested = MessageOrigin::WebApp(contract);
    // Only the caller's own namespace: an app can never export another's.
    let scope = ExportScope::Prefix(store::namespace(origin).into_bytes());
    let request = ExportRequest { source_generation };
    let out = handle_export_request(
        &MigrateView(env),
        Some(&attested),
        &OriginPolicy::SameWebApp(contract),
        &scope,
        &request,
    )
    .map_err(|e| fail(FailureCode::CapReached, format!("export refused: {e}")))?;
    match out.into_iter().next() {
        Some(OutboundDelegateMsg::ApplicationMessage(m)) => {
            Ok(Reply::ExportedSecrets(ByteBuf::from(m.payload)))
        }
        _ => Err(fail(FailureCode::Internal, "export produced no payload")),
    }
}
