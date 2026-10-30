//! Request dispatch: the origin gate, then one handler per operation.

use freenet_mail_protocol::address::address_of;
use freenet_mail_protocol::{
    Addr, DsaSeed, Entropy, Failure, FailureCode, Hash32, IdentityInfo, ImportKind, ImportSource,
    Item, ItemKind, ItemRef, KemSeed, MAX_DECRYPT_BATCH, MAX_ITEM_BYTES, MAX_REMOVAL_BATCH,
    MAX_RESPONSE_BYTES, Op, PROTOCOL_VERSION, Reply, RequestEnvelope, RequestId, Response, Status,
    recovery_key, to_cbor,
};
use freenet_stdlib::prelude::{
    ApplicationMessage, ContractKey, DelegateError, InboundDelegateMsg, MessageOrigin,
    OutboundDelegateMsg, Parameters,
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::consent;
use crate::crypto::{self, Keys, MixRng};
use crate::env::Env;
use crate::store::{
    self, ALL_KINDS, IDENTITY_INDEX, MAX_IDENTITIES, Origin, Space, fail, identity_rel, index_rel,
    item_rel,
};

pub type OpResult = Result<Reply, Failure>;

/// Room left in a response for its envelope around the payload.
const RESPONSE_HEADROOM: usize = 16 * 1024;

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
            // The envelope first: a request this build cannot fully decode
            // (a newer version or operation) still has an id to answer.
            let envelope: RequestEnvelope = freenet_mail_protocol::from_cbor(&app.payload)
                .map_err(|e| DelegateError::Deser(format!("request: {e}")))?;
            handle_request(&mut Space::new(env, origin), envelope)
        }
        InboundDelegateMsg::UserResponse(answer) => {
            let origin = check_origin(origin.as_ref())?;
            consent::answer(&mut Space::new(env, origin), &answer)
        }
        _ => Err(DelegateError::Other(
            "the mail delegate accepts only application messages and prompt answers".into(),
        )),
    }
}

/// The origin gate, run before ANY request or answer is looked at (River's
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
    vec![response_msg(request_id, result)]
}

pub fn response_msg(request_id: RequestId, result: OpResult) -> OutboundDelegateMsg {
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
    OutboundDelegateMsg::ApplicationMessage(ApplicationMessage::new(payload).processed(true))
}

fn handle_request(
    s: &mut Space<'_>,
    request: RequestEnvelope,
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
    let op = match request.op() {
        Ok(op) => op,
        Err(e) => {
            return Ok(respond(
                id,
                Err(fail(
                    FailureCode::UnknownOperation,
                    format!("this delegate does not know the operation: {e}"),
                )),
            ));
        }
    };
    let result = match op {
        // These ask the user first, so the answer may come later.
        op @ (Op::ExportRecoveryKey { .. }
        | Op::ExportProfile { .. }
        | Op::ExportForSuccessor { .. }
        | Op::DeleteIdentity { .. }) => return Ok(consent::request(s, id, op)),
        Op::GetStatus => status(s),
        Op::ListIdentities => list_identities(s),
        Op::ListDeletingIdentities => list_deleting_identities(s),
        Op::CreateIdentity {
            alias,
            description,
            ui_entropy,
        } => create_identity(s, alias, description, &ui_entropy),
        Op::ImportIdentity {
            source,
            kind,
            alias,
            description,
        } => import_identity(s, source, kind, alias, description),
        Op::UpdateIdentity {
            addr,
            alias,
            description,
            expected_gen,
        } => update_identity(s, &addr, Some((alias, description)), expected_gen),
        Op::ConfirmIdentity { addr, expected_gen } => update_identity(s, &addr, None, expected_gen),
        Op::ListItems {
            kind,
            owner,
            after,
            limit,
        } => list_items(s, kind, owner, after.as_ref().map(|a| a.as_slice()), limit),
        Op::GetItem { item } => get_item(s, item),
        Op::PutItem {
            item,
            body,
            expected_gen,
        } => put_item(s, item, body.into_vec(), expected_gen),
        Op::DeleteItem { item, expected_gen } => delete_item(s, item, expected_gen),
        Op::DecryptV1 { addr, ciphertexts } => decrypt_v1(s, &addr, ciphertexts),
        Op::SealV1Message {
            addr,
            recipient_ek,
            plaintext,
            ui_entropy,
        } => seal_v1(s, &addr, &recipient_ek, &plaintext, &ui_entropy),
        Op::SignV1Authority {
            addr,
            settings_json,
            last_update_micros,
        } => sign_v1_authority(s, &addr, &settings_json, last_update_micros),
        Op::SignV1Removal {
            addr,
            assignment_hashes,
        } => sign_v1_removal(s, &addr, &assignment_hashes),
        Op::V1AftParams { addr } => v1_aft_params(s, &addr),
        Op::RevokeExportGrant => s
            .del(store::EXPORT_GRANT)
            .and_then(|()| s.del(store::EXPORT_SESSION))
            .map(|()| Reply::Deleted),
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
    /// Set for identities carried over by a migration until the user confirms
    /// them. A hint for the UI, not a security boundary: any code running
    /// under the app's origin can confirm an identity.
    pub confirmed: bool,
    /// Set once the user approved deleting it; the deletion then proceeds in
    /// bounded steps and the identity refuses every other operation.
    #[serde(default)]
    pub deleting: bool,
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

pub fn load_identity(s: &Space<'_>, addr: &Addr) -> Result<Option<(u64, IdentityRecord)>, Failure> {
    match s.read(&identity_rel(addr))? {
        None => Ok(None),
        Some((generation, body)) => freenet_mail_protocol::from_cbor(&body)
            .map(|r| Some((generation, r)))
            .map_err(|_| fail(FailureCode::Internal, "a stored identity is unreadable")),
    }
}

/// A usable identity: present and not being deleted.
pub fn require_identity(s: &Space<'_>, addr: &Addr) -> Result<(u64, IdentityRecord), Failure> {
    match load_identity(s, addr)? {
        None => Err(fail(FailureCode::NotFound, "no such identity")),
        Some((_, r)) if r.deleting => {
            Err(fail(FailureCode::Refused, "this identity is being deleted"))
        }
        Some(found) => Ok(found),
    }
}

/// Every identity, from the identity index (never from a host listing).
fn all_identities(s: &Space<'_>) -> Result<Vec<(Addr, u64, IdentityRecord)>, Failure> {
    let (_, ids) = s.index(IDENTITY_INDEX)?;
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let addr = Addr(
            id.as_slice()
                .try_into()
                .map_err(|_| fail(FailureCode::Internal, "the identity index is unreadable"))?,
        );
        if let Some((g, r)) = load_identity(s, &addr)?
            && !r.deleting
        {
            out.push((addr, g, r));
        }
    }
    Ok(out)
}

fn status(s: &Space<'_>) -> OpResult {
    let usage = s.usage();
    Ok(Reply::Status(Status {
        protocol_version: PROTOCOL_VERSION,
        identities: s.index(IDENTITY_INDEX)?.1.len() as u32,
        stored_keys: usage.keys,
        stored_bytes: usage.bytes,
        key_budget: store::MAX_ORIGIN_KEYS,
        byte_budget: store::MAX_ORIGIN_BYTES,
        v1_transition: cfg!(feature = "v1-transition"),
    }))
}

/// Drop identity index entries whose deletion finished: a deletion that
/// removed the record and then failed to update the index. The deletion
/// removes everything the identity owns before its record, so nothing is
/// left to finish, but the stale entry would hold one of the
/// `MAX_IDENTITIES` slots for good and could not be listed to clean up.
///
/// An entry is pruned only when the marker its create or deletion wrote
/// says the record may legitimately be absent, and the record is confirmed
/// absent. A record that merely fails to read (the host cannot tell a failed
/// read from an absent key) keeps its entry, so a transient miss never
/// leaves a private key unlisted. The same pass frees the slot of a create
/// that failed after claiming it.
fn prune_recordless_identities(s: &mut Space<'_>) -> Result<(), Failure> {
    let (_, ids) = s.index(IDENTITY_INDEX)?;
    let mut gone = Vec::new();
    let mut markers = Vec::new();
    for id in ids {
        let Ok(addr) = <[u8; 24]>::try_from(id.as_slice()).map(Addr) else {
            gone.push(id);
            continue;
        };
        let marker = store::deleted_rel(&addr);
        if s.get(&marker).is_none() {
            continue;
        }
        match load_identity(s, &addr)? {
            None => {
                gone.push(id);
                markers.push(marker);
            }
            // A marker beside a live record (its create or deletion ended,
            // its cleanup failed) proves nothing any more.
            Some((_, r)) if !r.deleting => markers.push(marker),
            Some(_) => {}
        }
    }
    if !gone.is_empty() {
        s.index_remove_many(IDENTITY_INDEX, &gone)?;
    }
    for marker in markers {
        // A marker left behind is harmless: it only ever allows pruning an
        // entry whose record is gone.
        let _ = s.del(&marker);
    }
    Ok(())
}

fn list_deleting_identities(s: &mut Space<'_>) -> OpResult {
    // Housekeeping, not the answer: a prune that cannot write the index
    // must not hide the deletions the user can finish. Every startup lists,
    // so a failed prune runs again on the next listing.
    let _ = prune_recordless_identities(s);
    let (_, ids) = s.index(IDENTITY_INDEX)?;
    let mut out = Vec::new();
    for id in ids {
        // An entry the prune could not drop (malformed, or with no record)
        // names no deletion to finish.
        let Ok(addr) = <[u8; 24]>::try_from(id.as_slice()).map(Addr) else {
            continue;
        };
        if let Some((g, r)) = load_identity(s, &addr)?
            && r.deleting
        {
            out.push(info(addr, g, &r));
        }
    }
    Ok(Reply::Identities(out))
}

fn list_identities(s: &Space<'_>) -> OpResult {
    Ok(Reply::Identities(
        all_identities(s)?
            .iter()
            .map(|(a, g, r)| info(*a, *g, r))
            .collect(),
    ))
}

/// Store a new identity. The caller has checked its address is new.
fn store_new_identity(
    s: &mut Space<'_>,
    dsa: DsaSeed,
    kem: KemSeed,
    alias: String,
    description: String,
    confirmed: bool,
) -> Result<IdentityInfo, Failure> {
    if all_identities(s)?.iter().any(|(_, _, r)| r.alias == alias) {
        return Err(fail(
            FailureCode::Conflict { current_gen: 0 },
            "an identity with this alias exists",
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
        confirmed,
        deleting: false,
    };
    let body = to_cbor(&record).map_err(|e| fail(FailureCode::Internal, e))?;
    // Claim the index slot first (it enforces the cap), then write; undo the
    // claim if the write fails. A slot a half-finished deletion left behind
    // is freed first.
    prune_recordless_identities(s)?;
    // The marker says "this entry may have no record". It is written before
    // the slot is claimed, so a create that fails after claiming it, and
    // whose undo fails too, leaves an entry the next listing can free.
    let marker = store::deleted_rel(&addr);
    s.put(&marker, b"")?;
    if let Err(e) = s.index_add(IDENTITY_INDEX, &addr.0, MAX_IDENTITIES) {
        let _ = s.del(&marker);
        return Err(e);
    }
    match s.write_if(&identity_rel(&addr), 0, &body) {
        Ok(generation) => {
            // A marker left beside the record licenses nothing (an entry is
            // only pruned when its record is confirmed absent), and the next
            // listing cleans it.
            let _ = s.del(&marker);
            Ok(info(addr, generation, &record))
        }
        Err(e) => {
            if s.index_remove(IDENTITY_INDEX, &addr.0).is_ok() {
                let _ = s.del(&marker);
            }
            Err(e)
        }
    }
}

fn create_identity(
    s: &mut Space<'_>,
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
    let host = s.env.host_random();
    let (dsa, kem) = crypto::new_seeds(&mut MixRng::new("create-identity", &host, ui_entropy));
    let addr = address_of(&Keys::from_seeds(&dsa, &kem).vk_bytes());
    if load_identity(s, &addr)?.is_some() {
        // Only possible if both entropy sources repeated.
        return Err(fail(
            FailureCode::Internal,
            "generated an existing identity; retry",
        ));
    }
    let recovery_key = recovery_key::encode(&dsa, &kem);
    let identity = store_new_identity(s, dsa, kem, alias, description, true)?;
    Ok(Reply::CreatedIdentity {
        identity,
        recovery_key,
    })
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

/// Largest JSON backup accepted (a real one is about 400 bytes).
const MAX_BACKUP_BYTES: usize = 16 * 1024;

fn seeds_from(source: ImportSource) -> Result<(DsaSeed, KemSeed), Failure> {
    match source {
        ImportSource::Seeds { dsa, kem } => Ok((dsa, kem)),
        ImportSource::RecoveryKey(text) => {
            recovery_key::decode(&text).map_err(|e| fail(FailureCode::BadInput, e.to_string()))
        }
        ImportSource::LegacyJson(bytes) => {
            if bytes.len() > MAX_BACKUP_BYTES {
                return Err(fail(FailureCode::BadInput, "backup file is too large"));
            }
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
    s: &mut Space<'_>,
    source: ImportSource,
    kind: ImportKind,
    alias: String,
    description: String,
) -> OpResult {
    let (dsa, kem) = seeds_from(source)?;
    let addr = address_of(&Keys::from_seeds(&dsa, &kem).vk_bytes());
    // Never overwrite: the same address means the same seeds.
    if let Some((generation, record)) = load_identity(s, &addr)? {
        if record.deleting {
            return Err(fail(FailureCode::Refused, "this identity is being deleted"));
        }
        // Present but unindexed (an index write that failed): list it again.
        if !s.index(IDENTITY_INDEX)?.1.contains(&addr.0[..]) {
            s.index_add(IDENTITY_INDEX, &addr.0, MAX_IDENTITIES)?;
        }
        return Ok(Reply::Imported {
            identity: info(addr, generation, &record),
            already_present: true,
        });
    }
    check_names(&alias, &description)?;
    let confirmed = kind == ImportKind::UserRestore;
    store_new_identity(s, dsa, kem, alias, description, confirmed).map(|identity| Reply::Imported {
        identity,
        already_present: false,
    })
}

/// Rename (`Some(names)`) or confirm (`None`) an identity.
fn update_identity(
    s: &mut Space<'_>,
    addr: &Addr,
    names: Option<(String, String)>,
    expected_gen: u64,
) -> OpResult {
    if let Some((alias, description)) = &names {
        check_names(alias, description)?;
    }
    let (generation, mut record) = require_identity(s, addr)?;
    let unchanged = match &names {
        Some((alias, description)) => record.alias == *alias && record.description == *description,
        None => record.confirmed,
    };
    if generation != expected_gen {
        // A retry of a change that landed but whose answer was lost.
        if unchanged {
            return Ok(Reply::Ack { generation });
        }
        return Err(fail(
            FailureCode::Conflict {
                current_gen: generation,
            },
            "stale generation",
        ));
    }
    match names {
        Some((alias, description)) => {
            if all_identities(s)?
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
        }
        None => record.confirmed = true,
    }
    let body = to_cbor(&record).map_err(|e| fail(FailureCode::Internal, e))?;
    let generation = s.write_if(&identity_rel(addr), generation, &body)?;
    Ok(Reply::Ack { generation })
}

/// Most item records one deletion step removes, so a call stays well inside
/// the host's time limit however large the identity.
pub const DELETE_STEP: usize = 256;

/// Delete an identity and everything it owns, after the user approved.
///
/// The first step marks the record `deleting` (the approval is then
/// remembered by the record itself); each step removes up to
/// [`DELETE_STEP`] items and answers `Continue` until none are left, then
/// removes the record and, last, its index entry. A retry after a failure
/// resumes where it stopped.
pub fn delete_identity_now(s: &mut Space<'_>, addr: &Addr, expected_gen: u64) -> OpResult {
    let Some((generation, mut record)) = load_identity(s, addr)? else {
        let marker = store::deleted_rel(addr);
        if s.get(&marker).is_none() {
            // No proof the record was deleted: a read that failed looks the
            // same as an absent key, so never unindex on it.
            return Err(fail(
                FailureCode::Busy,
                "the identity could not be read; retry",
            ));
        }
        // Record gone: only the index entry can be left.
        s.index_remove(IDENTITY_INDEX, &addr.0)?;
        // `Deleted` means nothing is left, the marker (which names the
        // address) included; a retry finishes a failed removal.
        s.del(&marker)?;
        return Ok(Reply::Deleted);
    };
    if !record.deleting {
        if generation != expected_gen {
            return Err(fail(
                FailureCode::Conflict {
                    current_gen: generation,
                },
                "stale generation",
            ));
        }
        record.deleting = true;
        let body = to_cbor(&record).map_err(|e| fail(FailureCode::Internal, e))?;
        s.write_if(&identity_rel(addr), generation, &body)?;
    }
    delete_step(s, addr)
}

/// Whether `addr` needs no approval to finish deleting: either the user
/// already approved (the record is marked) or only bookkeeping is left.
pub fn deletion_in_progress(s: &Space<'_>, addr: &Addr) -> Result<bool, Failure> {
    Ok(match load_identity(s, addr)? {
        Some((_, r)) => r.deleting,
        // No record (confirmed) and a marker: only bookkeeping is left (an
        // index entry, the marker itself), and nothing of the user's to lose.
        None => s.get(&store::deleted_rel(addr)).is_some(),
    })
}

fn delete_step(s: &mut Space<'_>, addr: &Addr) -> OpResult {
    let mut budget = DELETE_STEP;
    let mut remaining = 0usize;
    for kind in ALL_KINDS.into_iter().filter(|k| store::shape(*k).0) {
        let ix = index_rel(kind, Some(addr));
        let (_, ids) = s.index(&ix)?;
        let batch: Vec<Vec<u8>> = ids.iter().take(budget).cloned().collect();
        for id in &batch {
            s.del(&item_rel(&ItemRef {
                kind,
                owner: Some(*addr),
                id: id.clone(),
            }))?;
        }
        // Items first, then their index entries in one write.
        s.index_remove_many(&ix, &batch)?;
        budget -= batch.len();
        remaining += ids.len() - batch.len();
    }
    if remaining > 0 {
        return Ok(Reply::Continue {
            remaining: u32::try_from(remaining).unwrap_or(u32::MAX),
        });
    }
    // The marker goes first: it is what lets a later listing prune the
    // index entry if removing it below fails.
    let marker = store::deleted_rel(addr);
    s.put(&marker, b"")?;
    s.del(&identity_rel(addr))?;
    s.index_remove(IDENTITY_INDEX, &addr.0)?;
    // Only once the marker is gone too: a failure here is retried, and the
    // retry (record gone, marker present) finishes it without asking.
    s.del(&marker)?;
    Ok(Reply::Deleted)
}

// ── Items ───────────────────────────────────────────────────────────────────

fn check_item(s: &Space<'_>, item: &ItemRef) -> Result<(), Failure> {
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
        require_identity(s, owner)?;
    }
    Ok(())
}

fn get_item(s: &Space<'_>, item: ItemRef) -> OpResult {
    check_item(s, &item)?;
    Ok(Reply::Item(s.read(&item_rel(&item))?.map(
        |(generation, body)| Item {
            item,
            body: ByteBuf::from(body),
            generation,
        },
    )))
}

fn put_item(
    s: &mut Space<'_>,
    item: ItemRef,
    body: Vec<u8>,
    expected_gen: Option<u64>,
) -> OpResult {
    check_item(s, &item)?;
    if body.len() > MAX_ITEM_BYTES {
        return Err(fail(FailureCode::BadInput, "item body is too large"));
    }
    let rel = item_rel(&item);
    let current = s.read(&rel)?;
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
    let ix = index_rel(item.kind, item.owner.as_ref());
    if current.is_none() {
        // Claim the index slot first; it enforces the per-kind cap.
        s.index_add(&ix, &item.id, store::cap(item.kind))?;
    }
    match s.write_if(&rel, current_gen, &body) {
        Ok(generation) => Ok(Reply::Ack { generation }),
        Err(e) => {
            if current.is_none() {
                let _ = s.index_remove(&ix, &item.id);
            }
            Err(e)
        }
    }
}

fn delete_item(s: &mut Space<'_>, item: ItemRef, expected_gen: u64) -> OpResult {
    check_item(s, &item)?;
    let rel = item_rel(&item);
    let ix = index_rel(item.kind, item.owner.as_ref());
    let Some((generation, _)) = s.read(&rel)? else {
        // Already gone. If an earlier delete removed the record but failed
        // to update the index, finish that now.
        s.index_remove(&ix, &item.id)?;
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
    // Record first, index entry last: a failure in between leaves an index
    // entry with no record, which readers skip and a retry removes.
    s.del(&rel)?;
    s.index_remove(&ix, &item.id)?;
    Ok(Reply::Deleted)
}

const MAX_PAGE: usize = 256;

fn list_items(
    s: &mut Space<'_>,
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
        require_identity(s, o)?;
    }
    let ix = index_rel(kind, owner.as_ref());
    let (_, ids) = s.index(&ix)?;
    let limit = (limit as usize).clamp(1, MAX_PAGE);
    let budget = MAX_RESPONSE_BYTES - RESPONSE_HEADROOM;
    let mut used = 0;
    let mut items = Vec::new();
    let mut more = false;
    let mut recordless = Vec::new();
    for id in ids
        .into_iter()
        .filter(|id| after.is_none_or(|a| id.as_slice() > a))
    {
        let item = ItemRef { kind, owner, id };
        let Some((generation, body)) = s.read(&item_rel(&item))? else {
            // An entry a failed write or delete left behind (its record is
            // confirmed absent): it would hold a slot of the kind's cap.
            recordless.push(item.id);
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
    if !recordless.is_empty() {
        // Housekeeping: a failure here leaves the entries for the next list.
        let _ = s.index_remove_many(&ix, &recordless);
    }
    Ok(Reply::Items { items, more })
}

// ── v0.2.x crypto ───────────────────────────────────────────────────────────

fn keys_for(s: &Space<'_>, addr: &Addr) -> Result<(IdentityRecord, Keys), Failure> {
    let (_, record) = require_identity(s, addr)?;
    let keys = Keys::from_seeds(&record.dsa, &record.kem);
    Ok((record, keys))
}

fn decrypt_v1(s: &Space<'_>, addr: &Addr, ciphertexts: Vec<ByteBuf>) -> OpResult {
    if ciphertexts.len() > MAX_DECRYPT_BATCH {
        return Err(fail(
            FailureCode::BadInput,
            "too many ciphertexts in one call",
        ));
    }
    let (_, keys) = keys_for(s, addr)?;
    let mut total = 0;
    let mut out = Vec::with_capacity(ciphertexts.len());
    for ct in ciphertexts {
        match crypto::decrypt_v1(&keys.kem, &ct) {
            Some(pt) if total + pt.len() <= MAX_RESPONSE_BYTES - RESPONSE_HEADROOM => {
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
    s: &mut Space<'_>,
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
    let (_, keys) = keys_for(s, addr)?;
    let ek = crypto::decode_ek(recipient_ek).ok_or_else(|| {
        fail(
            FailureCode::BadInput,
            "recipient key is not an ML-KEM-768 key",
        )
    })?;
    let host = s.env.host_random();
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
    s: &Space<'_>,
    addr: &Addr,
    settings_json: &[u8],
    last_update_micros: i64,
) -> OpResult {
    use freenet_mail_wire_v1::inbox::{InboxSettings, sign_payload};
    let (_, keys) = keys_for(s, addr)?;
    let settings: InboxSettings = serde_json::from_slice(settings_json)
        .map_err(|_| fail(FailureCode::BadInput, "settings are not v1 inbox settings"))?;
    let last_update = chrono::DateTime::from_timestamp_micros(last_update_micros)
        .ok_or_else(|| fail(FailureCode::BadInput, "timestamp out of range"))?;
    // The delegate supplies its own encapsulation key: the signature can only
    // ever authorize this identity's inbox with this identity's key.
    let payload = sign_payload(&keys.ek_bytes(), &settings, last_update);
    Ok(Reply::Signature(ByteBuf::from(keys.sign(&payload))))
}

/// Code hash of the v1 inbox contract (the generation v0.2.x clients use).
pub fn v1_inbox_code_hash() -> &'static str {
    include_str!("../../../published-contract/wasm/v1/inbox_code_hash").trim()
}

/// The instance id of `vk`'s v1 inbox.
pub fn v1_inbox_id(vk: &[u8]) -> Result<[u8; 32], Failure> {
    let params: Parameters = freenet_mail_wire_v1::inbox::InboxParams {
        pub_key: vk.to_vec(),
    }
    .try_into()
    .map_err(|_| fail(FailureCode::Internal, "could not encode inbox parameters"))?;
    let key = ContractKey::from_params(v1_inbox_code_hash(), params)
        .map_err(|_| fail(FailureCode::Internal, "bad inbox code hash"))?;
    key.id()
        .as_bytes()
        .try_into()
        .map_err(|_| fail(FailureCode::Internal, "inbox id is not 32 bytes"))
}

/// The parts of a v1 inbox state a removal check needs.
#[derive(Deserialize)]
struct InboxHashes {
    messages: Vec<MessageHash>,
}

#[derive(Deserialize)]
struct MessageHash {
    token_assignment: AssignmentHash,
}

#[derive(Deserialize)]
struct AssignmentHash {
    assignment_hash: [u8; 32],
}

/// Sign a v1 `RemoveMessages` for messages in the identity's own inbox.
///
/// The payload is the concatenated hashes (the frozen contract's layout,
/// [`freenet_mail_wire_v1::inbox::removal_payload`]), which carries no domain
/// tag, and v1 message signatures use the same key over raw bytes. So the
/// delegate signs only:
///
/// - strictly ascending, distinct hashes (the contract accepts any order);
/// - hashes of messages in this identity's v1 inbox as held on this node;
/// - never a payload that could alias an authority payload.
///
/// A sender does choose its message's hash: v0.2.x hashes one encryption of
/// the message and stores another, so the hash is not bound to the stored
/// content and cannot be checked against it. Ordering is the defence
/// instead. A signature over the payload verifies as a v1 message signature
/// over the same bytes; to make that a message anyone would accept, the
/// payload must be a real ciphertext whose 32-byte chunks happen to be
/// strictly ascending. The first chunk holds the nonce, which the attacker
/// chooses, but the ML-KEM ciphertext after it spans about 34 chunks that
/// the attacker cannot steer (only re-roll), so they ascend with probability
/// about 1/34!, roughly 2^-128. Raw ascending bytes decrypt to nothing.
fn sign_v1_removal(s: &Space<'_>, addr: &Addr, hashes: &[Hash32]) -> OpResult {
    use freenet_mail_wire_v1::inbox::{STATE_UPDATE, removal_payload};
    if hashes.is_empty() || hashes.len() > MAX_REMOVAL_BATCH {
        return Err(fail(
            FailureCode::BadInput,
            "1-1024 message hashes per removal",
        ));
    }
    if hashes.windows(2).any(|w| w[0].0 >= w[1].0) {
        return Err(fail(
            FailureCode::BadInput,
            "hashes must be in strictly ascending order",
        ));
    }
    let (record, keys) = keys_for(s, addr)?;
    let state = s
        .env
        .contract_state(&v1_inbox_id(&record.vk)?)
        .ok_or_else(|| {
            fail(
                FailureCode::Refused,
                "this identity's inbox is not held on this node",
            )
        })?;
    let inbox: InboxHashes = serde_json::from_slice(&state)
        .map_err(|_| fail(FailureCode::Internal, "the inbox state is unreadable"))?;
    let present: std::collections::BTreeSet<[u8; 32]> = inbox
        .messages
        .iter()
        .map(|m| m.token_assignment.assignment_hash)
        .collect();
    if hashes.iter().any(|h| !present.contains(&h.0)) {
        return Err(fail(
            FailureCode::Refused,
            "a hash is not a message in this inbox",
        ));
    }
    let ids: Vec<[u8; 32]> = hashes.iter().map(|h| h.0).collect();
    let payload = removal_payload(&ids);
    if payload.starts_with(STATE_UPDATE) {
        return Err(fail(
            FailureCode::Refused,
            "payload aliases an inbox authority payload",
        ));
    }
    Ok(Reply::Signature(ByteBuf::from(keys.sign(&payload))))
}

/// Present in the WASM exactly when it is built with `v1-transition`, so
/// scripts/check-release-delegate.sh can prove a release build lacks it.
#[cfg(feature = "v1-transition")]
pub const V1_TRANSITION_MARKER: &str = "freenet-mail-delegate:v1-transition-enabled";

#[cfg(feature = "v1-transition")]
fn v1_aft_params(s: &Space<'_>, addr: &Addr) -> OpResult {
    core::hint::black_box(V1_TRANSITION_MARKER.as_bytes());
    let (_, record) = require_identity(s, addr)?;
    let params = freenet_mail_wire_v1::aft::DelegateParameters::new(record.dsa.0);
    serde_json::to_vec(&params)
        .map(|b| Reply::AftParams(ByteBuf::from(b)))
        .map_err(|e| fail(FailureCode::Internal, e.to_string()))
}

#[cfg(not(feature = "v1-transition"))]
fn v1_aft_params(_: &Space<'_>, _: &Addr) -> OpResult {
    Err(fail(FailureCode::Refused, "this build has no v1 send path"))
}

// ── Exports (run after the user approved) ───────────────────────────────────

pub fn export_recovery_key(s: &Space<'_>, addr: &Addr) -> OpResult {
    let (_, record) = require_identity(s, addr)?;
    Ok(Reply::RecoveryKey(recovery_key::encode(
        &record.dsa,
        &record.kem,
    )))
}

pub fn export_profile(s: &Space<'_>, addr: &Addr) -> OpResult {
    let (_, record) = require_identity(s, addr)?;
    let backup = LegacyBackup {
        version: 2,
        alias: record.alias.clone(),
        description: record.description.clone(),
        keys: LegacyKeys {
            ml_dsa_seed: record.dsa.0.to_vec(),
            ml_kem_seed: record.kem.0.to_vec(),
        },
    };
    serde_json::to_vec(&backup)
        .map(|b| Reply::Profile(ByteBuf::from(b)))
        .map_err(|e| fail(FailureCode::Internal, e.to_string()))
}

/// The relative keys a successor needs: identities, items and their indexes.
/// Bookkeeping (`mt/`), pending prompts (`pg/`, `ix/pg`) and the consent
/// grant (`gr/`) are not data and are never exported.
pub fn exportable_keys(s: &Space<'_>) -> Result<Vec<String>, Failure> {
    let mut rels = Vec::new();
    let add_kind = |s: &Space<'_>, rels: &mut Vec<String>, kind, owner: Option<Addr>| {
        let ix = index_rel(kind, owner.as_ref());
        let (_, ids) = s.index(&ix)?;
        if !ids.is_empty() {
            rels.push(ix);
        }
        for id in ids {
            rels.push(item_rel(&ItemRef { kind, owner, id }));
        }
        Ok::<_, Failure>(())
    };
    let (_, identities) = s.index(IDENTITY_INDEX)?;
    if !identities.is_empty() {
        rels.push(IDENTITY_INDEX.to_string());
    }
    for id in identities {
        let addr = Addr(
            id.as_slice()
                .try_into()
                .map_err(|_| fail(FailureCode::Internal, "the identity index is unreadable"))?,
        );
        // An identity being deleted is not data to carry forward.
        if load_identity(s, &addr)?.is_some_and(|(_, r)| r.deleting) {
            continue;
        }
        rels.push(identity_rel(&addr));
        for kind in ALL_KINDS.into_iter().filter(|k| store::shape(*k).0) {
            add_kind(s, &mut rels, kind, Some(addr))?;
        }
    }
    for kind in ALL_KINDS.into_iter().filter(|k| !store::shape(*k).0) {
        add_kind(s, &mut rels, kind, None)?;
    }
    rels.sort();
    Ok(rels)
}

/// The identity index as a successor should receive it: without identities
/// being deleted (their records and items are not exported either). `None`
/// when nothing is left.
fn exportable_identity_index(s: &Space<'_>) -> Result<Option<Vec<u8>>, Failure> {
    let Some((generation, _)) = s.read(IDENTITY_INDEX)? else {
        return Ok(None);
    };
    let (_, ids) = s.index(IDENTITY_INDEX)?;
    let mut kept = Vec::new();
    for id in ids {
        let addr = Addr(
            id.as_slice()
                .try_into()
                .map_err(|_| fail(FailureCode::Internal, "the identity index is unreadable"))?,
        );
        if load_identity(s, &addr)?.is_some_and(|(_, r)| !r.deleting) {
            kept.push(ByteBuf::from(id));
        }
    }
    if kept.is_empty() {
        return Ok(None);
    }
    let body = to_cbor(&kept).map_err(|e| fail(FailureCode::Internal, e))?;
    Ok(Some(store::encode_versioned(generation, &body)))
}

/// One page of the freenet-migrate export of the caller's namespace.
pub fn export_for_successor(
    s: &Space<'_>,
    source_generation: u32,
    after: Option<&[u8]>,
) -> OpResult {
    let budget = MAX_RESPONSE_BYTES - RESPONSE_HEADROOM;
    let mut used = 0;
    let mut secrets = Vec::new();
    let mut next = None;
    for rel in exportable_keys(s)?
        .into_iter()
        .filter(|r| after.is_none_or(|a| r.as_bytes() > a))
    {
        let value = if rel == IDENTITY_INDEX {
            exportable_identity_index(s)?
        } else {
            s.get(&rel)
        };
        let Some(value) = value else {
            continue;
        };
        let key = s.full_key(&rel);
        if !secrets.is_empty() && used + key.len() + value.len() + 32 > budget {
            next = Some(ByteBuf::from(last_rel(&secrets, s)));
            break;
        }
        used += key.len() + value.len() + 32;
        secrets.push((key, value));
    }
    let payload = freenet_migrate::ExportedSecrets {
        source_generation,
        secrets,
    }
    .to_bytes()
    .map_err(|e| fail(FailureCode::Internal, e.to_string()))?;
    Ok(Reply::ExportedSecrets {
        payload: ByteBuf::from(payload),
        next,
        session: None,
    })
}

fn last_rel(secrets: &[(Vec<u8>, Vec<u8>)], s: &Space<'_>) -> Vec<u8> {
    let prefix_len = s.full_key("").len();
    secrets
        .last()
        .map(|(k, _)| k[prefix_len..].to_vec())
        .unwrap_or_default()
}
