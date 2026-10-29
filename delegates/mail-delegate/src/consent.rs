//! Consent for the operations that hand private keys out or cannot be undone.
//!
//! - Exports (recovery key, profile, successor export) ask the user unless
//!   they chose "Always allow for this app" before, remembered per origin.
//! - Deleting an identity asks every time; there is nothing to remember.
//!
//! Signing, decryption and storage never prompt: the origin gate is their
//! control.
//!
//! The pending request is stashed in the requesting origin's namespace
//! under the prompt id, so an answer arriving with another origin cannot
//! find it. The context slot is not used: the node clears it when the
//! delegate emits an application message. Every request gets exactly one
//! response: the result once answered, or `Refused` if its prompt expires,
//! is declined, or is pushed out by newer prompts.

use freenet_mail_protocol::{FailureCode, Op, RequestId, from_cbor, to_cbor};
use freenet_stdlib::prelude::{
    ClientResponse, ContractInstanceId, NotificationMessage, OutboundDelegateMsg, UserInputRequest,
    UserInputResponse,
};
use serde::{Deserialize, Serialize};

use crate::handlers::{
    OpResult, delete_identity_now, export_for_successor, export_profile, export_recovery_key,
    is_partly_deleted, require_identity, respond, response_msg,
};
use crate::store::{
    EXPORT_GRANT, MAX_PENDING_PROMPTS, PROMPT_INDEX, PROMPT_SEQ, PROMPT_TTL_SECS, Space, fail,
    prompt_rel,
};

pub const ALLOW: &[u8] = b"Allow";
pub const ALWAYS: &[u8] = b"Always allow for this app";
pub const DENY: &[u8] = b"Deny";
pub const DELETE: &[u8] = b"Delete";
pub const CANCEL: &[u8] = b"Cancel";

#[derive(Serialize, Deserialize)]
struct Pending {
    seq: u64,
    /// Host time when raised, if the host has a clock.
    created: Option<u64>,
    request_id: RequestId,
    op: Op,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Hands out private keys; "Always" may be remembered.
    Export,
    /// Cannot be undone; asks every time.
    Destructive,
}

fn kind_of(op: &Op) -> Option<Kind> {
    match op {
        Op::ExportRecoveryKey { .. } | Op::ExportProfile { .. } | Op::ExportForSuccessor { .. } => {
            Some(Kind::Export)
        }
        Op::DeleteIdentity { .. } => Some(Kind::Destructive),
        _ => None,
    }
}

/// Run an operation the user approved (or pre-approved).
fn perform(s: &mut Space<'_>, op: &Op) -> OpResult {
    match op {
        Op::ExportRecoveryKey { addr } => export_recovery_key(s, addr),
        Op::ExportProfile { addr } => export_profile(s, addr),
        Op::ExportForSuccessor {
            source_generation,
            after,
        } => export_for_successor(s, *source_generation, after.as_ref().map(|a| a.as_slice())),
        Op::DeleteIdentity { addr, expected_gen } => delete_identity_now(s, addr, *expected_gen),
        _ => Err(fail(FailureCode::Internal, "not a consented operation")),
    }
}

/// Checks that can fail before asking, so the user is never asked about a
/// request that cannot succeed.
fn precheck(s: &Space<'_>, op: &Op) -> Result<(), freenet_mail_protocol::Failure> {
    match op {
        Op::ExportRecoveryKey { addr } | Op::ExportProfile { addr } => {
            require_identity(s, addr).map(|_| ())
        }
        Op::DeleteIdentity { addr, expected_gen } => {
            let (generation, _) = require_identity(s, addr)?;
            if generation == *expected_gen {
                Ok(())
            } else {
                Err(fail(
                    FailureCode::Conflict {
                        current_gen: generation,
                    },
                    "stale generation",
                ))
            }
        }
        _ => Ok(()),
    }
}

pub fn request(s: &mut Space<'_>, request_id: RequestId, op: Op) -> Vec<OutboundDelegateMsg> {
    let Some(kind) = kind_of(&op) else {
        return respond(
            request_id,
            Err(fail(FailureCode::Internal, "not a consented operation")),
        );
    };
    // An approved deletion that removed the record and then failed: only
    // bookkeeping is left, so finish it without asking again.
    if let Op::DeleteIdentity { addr, expected_gen } = &op {
        match is_partly_deleted(s, addr) {
            Ok(true) => return respond(request_id, delete_identity_now(s, addr, *expected_gen)),
            Ok(false) => {}
            Err(f) => return respond(request_id, Err(f)),
        }
    }
    if let Err(f) = precheck(s, &op) {
        return respond(request_id, Err(f));
    }
    if kind == Kind::Export && s.get(EXPORT_GRANT).is_some() {
        return respond(request_id, perform(s, &op));
    }
    match raise_prompt(s, request_id, op, kind) {
        Ok(msgs) => msgs,
        Err(f) => respond(request_id, Err(f)),
    }
}

fn expired(now: Option<u64>, created: Option<u64>) -> bool {
    matches!((now, created), (Some(n), Some(c)) if n.saturating_sub(c) > PROMPT_TTL_SECS)
}

/// A short, recognisable name for the app asking.
fn app_label(s: &Space<'_>) -> String {
    let id = ContractInstanceId::new(s.origin.0).encode();
    format!("The app {}…", &id[..id.len().min(8)])
}

fn prompt_text(s: &Space<'_>, op: &Op) -> String {
    let app = app_label(s);
    let name = |addr| {
        require_identity(s, addr)
            .map(|(_, r)| format!("\"{}\"", r.alias))
            .unwrap_or_else(|_| "an identity".to_string())
    };
    match op {
        Op::ExportRecoveryKey { addr } | Op::ExportProfile { addr } => format!(
            "{app} wants a copy of the private key of {}.\n\n\
             Anyone who gets it can read this identity's mail and send as it, from \
             anywhere, and it cannot be revoked.\n\n\
             Expect this only if you just asked to back up or export this identity.",
            name(addr)
        ),
        Op::ExportForSuccessor { .. } => format!(
            "{app} wants a copy of all your mail identities, including their private \
             keys, contacts and stored mail.\n\n\
             Expect this only while Mail is moving your data to an updated version."
        ),
        Op::DeleteIdentity { addr, .. } => format!(
            "{app} wants to delete {} and everything stored for it: its keys, drafts \
             and saved mail.\n\n\
             This cannot be undone. Unless you have its recovery key, this identity and \
             its address are gone for good.",
            name(addr)
        ),
        _ => String::new(),
    }
}

/// Drop stashed prompts that expired (and, if `make_room`, the oldest beyond
/// the cap), answering each one's request with `Refused`.
fn prune(
    s: &mut Space<'_>,
    make_room: bool,
) -> Result<Vec<OutboundDelegateMsg>, freenet_mail_protocol::Failure> {
    let now = s.env.now_secs();
    let (_, ids) = s.index(PROMPT_INDEX)?;
    let mut live = Vec::new();
    let mut out = Vec::new();
    for id in ids {
        let prompt_id = u32::from_be_bytes(id.as_slice().try_into().unwrap_or([0; 4]));
        let rel = prompt_rel(prompt_id);
        match s.get(&rel).and_then(|b| from_cbor::<Pending>(&b).ok()) {
            Some(p) if !expired(now, p.created) => live.push((p.seq, id, p.request_id)),
            other => {
                s.del(&rel)?;
                s.index_remove(PROMPT_INDEX, &id)?;
                if let Some(p) = other {
                    out.push(response_msg(
                        p.request_id,
                        Err(fail(FailureCode::Refused, "the prompt expired")),
                    ));
                }
            }
        }
    }
    if make_room {
        live.sort();
        while live.len() >= MAX_PENDING_PROMPTS {
            let (_, id, request_id) = live.remove(0);
            let prompt_id = u32::from_be_bytes(id.as_slice().try_into().unwrap_or([0; 4]));
            s.del(&prompt_rel(prompt_id))?;
            s.index_remove(PROMPT_INDEX, &id)?;
            out.push(response_msg(
                request_id,
                Err(fail(
                    FailureCode::Refused,
                    "superseded by newer requests from this app",
                )),
            ));
        }
    }
    Ok(out)
}

fn raise_prompt(
    s: &mut Space<'_>,
    request_id: RequestId,
    op: Op,
    kind: Kind,
) -> Result<Vec<OutboundDelegateMsg>, freenet_mail_protocol::Failure> {
    let seq = s
        .get(PROMPT_SEQ)
        .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0)
        + 1;
    // Fail closed: a reused sequence number could pair a stash with the
    // wrong prompt.
    s.put(PROMPT_SEQ, &seq.to_le_bytes())?;
    let mut out = prune(s, true)?;

    // The prompt id mixes the host RNG with the caller's random request id
    // and the sequence number, so it is unpredictable even if the host RNG
    // fails. The host's prompt id is 32 bits wide; a collision with a live
    // stash is rehashed.
    let host = s.env.host_random();
    let mut attempt = 0u32;
    let prompt_id = loop {
        let mut h = blake3::Hasher::new_derive_key("freenet-mail prompt id v1");
        h.update(&host);
        h.update(&request_id.0);
        h.update(&s.origin.0);
        h.update(&seq.to_le_bytes());
        h.update(&attempt.to_le_bytes());
        let id = u32::from_le_bytes(h.finalize().as_bytes()[..4].try_into().expect("4 bytes"));
        if id != 0 && s.get(&prompt_rel(id)).is_none() {
            break id;
        }
        attempt += 1;
    };

    let message = NotificationMessage::try_from(&serde_json::Value::String(prompt_text(s, &op)))
        .map_err(|()| fail(FailureCode::Internal, "could not build the prompt"))?;
    let stash = to_cbor(&Pending {
        seq,
        created: s.env.now_secs(),
        request_id,
        op,
    })
    .map_err(|e| fail(FailureCode::Internal, e))?;
    s.put(&prompt_rel(prompt_id), &stash)?;
    s.index_add(PROMPT_INDEX, &prompt_id.to_be_bytes(), MAX_PENDING_PROMPTS)?;

    let responses = match kind {
        Kind::Export => vec![ALLOW, ALWAYS, DENY],
        Kind::Destructive => vec![DELETE, CANCEL],
    };
    out.push(OutboundDelegateMsg::RequestUserInput(UserInputRequest {
        request_id: prompt_id,
        message,
        responses: responses
            .into_iter()
            .map(|r| ClientResponse::new(r.to_vec()))
            .collect(),
    }));
    Ok(out)
}

/// The user answered a prompt. An answer to an unknown, already answered or
/// foreign prompt is ignored.
pub fn answer(
    s: &mut Space<'_>,
    answer: &UserInputResponse<'_>,
) -> Result<Vec<OutboundDelegateMsg>, freenet_stdlib::prelude::DelegateError> {
    let rel = prompt_rel(answer.request_id);
    let Some(stash) = s.get(&rel) else {
        return Ok(vec![]);
    };
    // Consume it first, so one prompt can never authorize two operations.
    let consumed = s
        .del(&rel)
        .and_then(|()| s.index_remove(PROMPT_INDEX, &answer.request_id.to_be_bytes()));
    if consumed.is_err() {
        return Err(freenet_stdlib::prelude::DelegateError::Other(
            "could not clear the answered prompt".into(),
        ));
    }
    let pending: Pending = from_cbor(&stash).map_err(|e| {
        freenet_stdlib::prelude::DelegateError::Deser(format!("pending prompt: {e}"))
    })?;
    if expired(s.env.now_secs(), pending.created) {
        return Ok(respond(
            pending.request_id,
            Err(fail(FailureCode::Refused, "the prompt expired")),
        ));
    }
    let choice: &[u8] = &answer.response;
    let result = match kind_of(&pending.op) {
        Some(Kind::Export) if choice == ALLOW => perform(s, &pending.op),
        Some(Kind::Export) if choice == ALWAYS => match s.put(EXPORT_GRANT, b"1") {
            Ok(()) => perform(s, &pending.op),
            Err(f) => Err(f),
        },
        Some(Kind::Destructive) if choice == DELETE => perform(s, &pending.op),
        // Deny, Cancel, and anything unrecognised.
        _ => Err(fail(FailureCode::Refused, "the user declined")),
    };
    Ok(respond(pending.request_id, result))
}
