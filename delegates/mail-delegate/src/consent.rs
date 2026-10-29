//! Consent for exports, the only operations that hand private keys out.
//!
//! Signing, decryption and storage never prompt: the origin gate is their
//! control. An export asks the user unless they chose "Always allow for this
//! app" before, which is remembered per origin.
//!
//! The pending request is stashed in the secret store under the prompt id,
//! inside the requesting origin's namespace. The answer must arrive with the
//! same origin to find it, so one app cannot answer another's prompt. The
//! context slot is not used: the node clears it when the delegate emits an
//! application message.

use freenet_mail_protocol::{FailureCode, Op, Reply, RequestId, from_cbor, recovery_key, to_cbor};
use freenet_stdlib::prelude::{
    ClientResponse, DelegateError, NotificationMessage, OutboundDelegateMsg, UserInputRequest,
    UserInputResponse,
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::env::Env;
use crate::handlers::{LegacyBackup, LegacyKeys, OpResult, fail, require_identity, respond};
use crate::store::{self, Origin};

pub const ALLOW: &[u8] = b"Allow";
pub const ALWAYS: &[u8] = b"Always allow for this app";
pub const DENY: &[u8] = b"Deny";

#[derive(Serialize, Deserialize)]
struct Pending {
    seq: u64,
    request_id: RequestId,
    op: Op,
}

fn export_addr(op: &Op) -> Option<freenet_mail_protocol::Addr> {
    match op {
        Op::ExportRecoveryKey { addr } | Op::ExportProfile { addr } => Some(*addr),
        _ => None,
    }
}

/// Run an export the user has approved (or pre-approved).
fn perform(env: &dyn Env, origin: &Origin, op: &Op) -> OpResult {
    let addr = export_addr(op).ok_or_else(|| fail(FailureCode::Internal, "not an export"))?;
    let (_, record) = require_identity(env, origin, &addr)?;
    match op {
        Op::ExportRecoveryKey { .. } => Ok(Reply::RecoveryKey(recovery_key::encode(
            &record.dsa,
            &record.kem,
        ))),
        _ => {
            let backup = LegacyBackup {
                version: 2,
                alias: record.alias,
                description: record.description,
                keys: LegacyKeys {
                    ml_dsa_seed: record.dsa.0.to_vec(),
                    ml_kem_seed: record.kem.0.to_vec(),
                },
            };
            serde_json::to_vec(&backup)
                .map(|b| Reply::Profile(ByteBuf::from(b)))
                .map_err(|e| fail(FailureCode::Internal, e.to_string()))
        }
    }
}

pub fn request_export(
    env: &mut dyn Env,
    origin: &Origin,
    request_id: RequestId,
    op: Op,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    let Some(addr) = export_addr(&op) else {
        return Ok(respond(
            request_id,
            Err(fail(FailureCode::Internal, "not an export")),
        ));
    };
    let record = match require_identity(env, origin, &addr) {
        Ok((_, r)) => r,
        Err(f) => return Ok(respond(request_id, Err(f))),
    };
    if env.get(&store::export_grant_key(origin)).is_some() {
        return Ok(respond(request_id, perform(env, origin, &op)));
    }
    match raise_prompt(env, origin, request_id, op, &record.alias) {
        Ok(msgs) => Ok(msgs),
        Err(f) => Ok(respond(request_id, Err(f))),
    }
}

fn raise_prompt(
    env: &mut dyn Env,
    origin: &Origin,
    request_id: RequestId,
    op: Op,
    alias: &str,
) -> Result<Vec<OutboundDelegateMsg>, freenet_mail_protocol::Failure> {
    let seq_key = store::prompt_seq_key(origin);
    let seq = env
        .get(&seq_key)
        .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0)
        + 1;
    // Fail closed: a reused sequence number could pair the stash with the
    // wrong prompt id.
    if !env.set(&seq_key, &seq.to_le_bytes()) {
        return Err(fail(FailureCode::Internal, "could not record the prompt"));
    }
    let mut h = blake3::Hasher::new_derive_key("freenet-mail prompt id v1");
    h.update(&env.host_random());
    h.update(&origin.0);
    h.update(&seq.to_le_bytes());
    let prompt_id = match u32::from_le_bytes(h.finalize().as_bytes()[..4].try_into().expect("4")) {
        0 => 1,
        n => n,
    };

    // Keep at most MAX_PENDING_PROMPTS per origin: drop the oldest.
    let prefix = store::pending_prefix(origin);
    let mut pending: Vec<(u64, Vec<u8>)> = env
        .list(&prefix)
        .into_iter()
        .map(|k| {
            let seq = env
                .get(&k)
                .and_then(|b| from_cbor::<Pending>(&b).ok())
                .map_or(0, |p| p.seq);
            (seq, k)
        })
        .collect();
    pending.sort();
    while pending.len() >= store::MAX_PENDING_PROMPTS {
        let (_, k) = pending.remove(0);
        env.remove(&k);
    }

    let stash = to_cbor(&Pending {
        seq,
        request_id,
        op,
    })
    .map_err(|e| fail(FailureCode::Internal, e))?;
    if !env.set(&store::pending_key(origin, prompt_id), &stash) {
        return Err(fail(FailureCode::Internal, "could not record the prompt"));
    }

    let text = format!(
        "Freenet Mail wants to show the private recovery key for \"{alias}\".\n\n\
         Anyone who gets it can read this identity's mail and send as it, from \
         anywhere, and it cannot be revoked.\n\n\
         Expect this only if you just asked to back up or export this identity."
    );
    let message = NotificationMessage::try_from(&serde_json::Value::String(text))
        .map_err(|()| fail(FailureCode::Internal, "could not build the prompt"))?;
    Ok(vec![OutboundDelegateMsg::RequestUserInput(
        UserInputRequest {
            request_id: prompt_id,
            message,
            responses: vec![
                ClientResponse::new(ALLOW.to_vec()),
                ClientResponse::new(ALWAYS.to_vec()),
                ClientResponse::new(DENY.to_vec()),
            ],
        },
    )])
}

/// The user answered a prompt. An answer to an unknown or stale prompt (or
/// from another origin) is ignored.
pub fn answer(
    env: &mut dyn Env,
    origin: &Origin,
    answer: &UserInputResponse<'_>,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    let key = store::pending_key(origin, answer.request_id);
    let Some(stash) = env.get(&key) else {
        return Ok(vec![]);
    };
    // Consume it first, so one prompt can never authorize two exports.
    if !env.remove(&key) {
        return Err(DelegateError::Other(
            "could not clear the answered prompt".into(),
        ));
    }
    let pending: Pending =
        from_cbor(&stash).map_err(|e| DelegateError::Deser(format!("pending prompt: {e}")))?;
    let choice: &[u8] = &answer.response;
    let result = if choice == ALLOW {
        perform(env, origin, &pending.op)
    } else if choice == ALWAYS {
        if env.set(&store::export_grant_key(origin), b"1") {
            perform(env, origin, &pending.op)
        } else {
            Err(fail(FailureCode::Internal, "could not remember the choice"))
        }
    } else {
        Err(fail(FailureCode::Refused, "the user declined"))
    };
    Ok(respond(pending.request_id, result))
}
