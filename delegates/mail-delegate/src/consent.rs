//! Consent for the operations that hand private keys out or cannot be undone.
//!
//! - Exports (recovery key, profile, successor export) ask the user unless
//!   they chose "Always allow for this app" before, remembered per origin and
//!   withdrawn by `RevokeExportGrant`. An approved successor export continues
//!   page by page under a short-lived session token instead of asking again.
//! - Deleting an identity asks every time it is started; once approved the
//!   identity record itself remembers it, so the bounded deletion steps and
//!   any retry continue without asking.
//!
//! Signing, decryption and storage never prompt: the origin gate is their
//! control.
//!
//! The pending request is stashed in the requesting origin's namespace
//! under the prompt id, so an answer arriving with another origin cannot
//! find it. The context slot is not used: the node clears it when the
//! delegate emits an application message. Every request gets exactly one
//! response: the result once answered, or `Refused` if its prompt expires,
//! is declined, or is pushed out by newer prompts. To keep that true when
//! storage writes fail, a stash is claimed in the prompt index before it is
//! written, and is only answered once it has been removed.

use freenet_mail_protocol::{Failure, FailureCode, Op, Reply, RequestId, from_cbor, to_cbor};
use freenet_stdlib::prelude::{
    ClientResponse, ContractInstanceId, DelegateError, NotificationMessage, OutboundDelegateMsg,
    UserInputRequest, UserInputResponse,
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::handlers::{
    OpResult, delete_identity_now, deletion_in_progress, export_for_successor, export_profile,
    export_recovery_key, require_identity, respond, response_msg,
};
use crate::store::{
    EXPORT_GRANT, EXPORT_SESSION, MAX_PENDING_PROMPTS, PROMPT_INDEX, PROMPT_SEQ, PROMPT_TTL_SECS,
    Space, fail, prompt_rel,
};

pub const ALLOW: &[u8] = b"Allow";
pub const ALWAYS: &[u8] = b"Always allow for this app";
pub const DENY: &[u8] = b"Deny";
pub const DELETE: &[u8] = b"Delete";
pub const CANCEL: &[u8] = b"Cancel";

/// How long an export session lasts after its last page.
pub const EXPORT_SESSION_SECS: u64 = 300;
/// Most pages one export session serves.
pub const EXPORT_SESSION_PAGES: u32 = 10_000;
/// A stash dated further in the future than this is treated as expired
/// (the host clock was set back, or the record is not to be trusted).
const MAX_CLOCK_SKEW_SECS: u64 = 60;

#[derive(Serialize, Deserialize)]
struct Pending {
    seq: u64,
    /// Host time when raised, if the host has a clock.
    created: Option<u64>,
    request_id: RequestId,
    op: Op,
}

#[derive(Serialize, Deserialize)]
struct ExportSession {
    token_hash: [u8; 32],
    expiry: u64,
    cursor: ByteBuf,
    source_generation: u32,
    pages_left: u32,
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

/// Run an operation the user approved (or pre-approved). `request_id` seeds
/// an export session token.
fn perform(s: &mut Space<'_>, request_id: &RequestId, op: &Op) -> OpResult {
    match op {
        Op::ExportRecoveryKey { addr } => export_recovery_key(s, addr),
        Op::ExportProfile { addr } => export_profile(s, addr),
        Op::ExportForSuccessor {
            source_generation,
            after,
            ..
        } => {
            let page =
                export_for_successor(s, *source_generation, after.as_ref().map(|a| a.as_slice()))?;
            start_session(s, request_id, *source_generation, page)
        }
        Op::DeleteIdentity { addr, expected_gen } => delete_identity_now(s, addr, *expected_gen),
        _ => Err(fail(FailureCode::Internal, "not a consented operation")),
    }
}

/// After an approved page with more to come, mint a session token so later
/// pages need not ask. Without a host clock there is no session (the token
/// could not expire), and every page asks.
fn start_session(
    s: &mut Space<'_>,
    request_id: &RequestId,
    source_generation: u32,
    page: Reply,
) -> OpResult {
    let Reply::ExportedSecrets {
        payload,
        next: Some(next),
        ..
    } = page
    else {
        let _ = s.del(EXPORT_SESSION);
        return Ok(page);
    };
    let Some(now) = s.env.now_secs() else {
        return Ok(Reply::ExportedSecrets {
            payload,
            next: Some(next),
            session: None,
        });
    };
    let mut h = blake3::Hasher::new_derive_key("freenet-mail export session v1");
    h.update(&s.env.host_random());
    h.update(&request_id.0);
    h.update(&s.origin.0);
    let token = *h.finalize().as_bytes();
    let session = ExportSession {
        token_hash: *blake3::hash(&token).as_bytes(),
        expiry: now + EXPORT_SESSION_SECS,
        cursor: next.clone(),
        source_generation,
        pages_left: EXPORT_SESSION_PAGES,
    };
    s.put(
        EXPORT_SESSION,
        &to_cbor(&session).map_err(|e| fail(FailureCode::Internal, e))?,
    )?;
    Ok(Reply::ExportedSecrets {
        payload,
        next: Some(next),
        session: Some(ByteBuf::from(token.to_vec())),
    })
}

/// Serve the next page of an export under its session token, if the token,
/// origin (the session lives in its namespace), expiry, cursor and source
/// generation all match.
fn continue_session(
    s: &mut Space<'_>,
    token: &[u8],
    source_generation: u32,
    after: Option<&[u8]>,
) -> OpResult {
    let refused = || fail(FailureCode::Refused, "no valid export session");
    let mut session: ExportSession = s
        .get(EXPORT_SESSION)
        .and_then(|b| from_cbor(&b).ok())
        .ok_or_else(refused)?;
    let now = s.env.now_secs().ok_or_else(refused)?;
    let valid = *blake3::hash(token).as_bytes() == session.token_hash
        && now <= session.expiry
        && session.expiry <= now + EXPORT_SESSION_SECS + MAX_CLOCK_SKEW_SECS
        && after == Some(session.cursor.as_slice())
        && source_generation == session.source_generation
        && session.pages_left > 0;
    if !valid {
        return Err(refused());
    }
    let page = export_for_successor(s, source_generation, after)?;
    match &page {
        Reply::ExportedSecrets {
            payload,
            next: Some(next),
            ..
        } => {
            session.cursor = next.clone();
            session.expiry = now + EXPORT_SESSION_SECS;
            session.pages_left -= 1;
            s.put(
                EXPORT_SESSION,
                &to_cbor(&session).map_err(|e| fail(FailureCode::Internal, e))?,
            )?;
            Ok(Reply::ExportedSecrets {
                payload: payload.clone(),
                next: Some(next.clone()),
                session: Some(ByteBuf::from(token.to_vec())),
            })
        }
        _ => {
            s.del(EXPORT_SESSION)?;
            Ok(page)
        }
    }
}

/// Test hook: set the live export session's remaining page count.
#[cfg(test)]
pub(crate) fn set_session_pages_left(s: &mut Space<'_>, pages: u32) {
    let mut session: ExportSession = from_cbor(&s.get(EXPORT_SESSION).unwrap()).unwrap();
    session.pages_left = pages;
    s.put(EXPORT_SESSION, &to_cbor(&session).unwrap()).unwrap();
}

/// Checks that can fail before asking, so the user is never asked about a
/// request that cannot succeed.
fn precheck(s: &Space<'_>, op: &Op) -> Result<(), Failure> {
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
    // A deletion the user already approved continues without asking.
    if let Op::DeleteIdentity { addr, expected_gen } = &op {
        match deletion_in_progress(s, addr) {
            Ok(true) => return respond(request_id, delete_identity_now(s, addr, *expected_gen)),
            Ok(false) => {}
            Err(f) => return respond(request_id, Err(f)),
        }
    }
    // Later pages of an approved export.
    if let Op::ExportForSuccessor {
        source_generation,
        after,
        session: Some(token),
    } = &op
    {
        let after = after.as_ref().map(|a| a.as_slice());
        return respond(
            request_id,
            continue_session(s, token, *source_generation, after),
        );
    }
    if let Err(f) = precheck(s, &op) {
        return respond(request_id, Err(f));
    }
    if kind == Kind::Export && s.get(EXPORT_GRANT).is_some() {
        return respond(request_id, perform(s, &request_id, &op));
    }
    let mut out = prune(s, true);
    match raise_prompt(s, request_id, op, kind) {
        Ok(prompt) => out.push(prompt),
        Err(f) => out.push(response_msg(request_id, Err(f))),
    }
    out
}

fn expired(now: Option<u64>, created: Option<u64>) -> bool {
    match (now, created) {
        (Some(n), Some(c)) => n.saturating_sub(c) > PROMPT_TTL_SECS || c > n + MAX_CLOCK_SKEW_SECS,
        _ => false,
    }
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

fn prompt_id_of(id: &[u8]) -> Option<u32> {
    id.try_into().ok().map(u32::from_be_bytes)
}

/// Drop stashed prompts that expired (and, if `make_room`, the oldest
/// beyond the cap), answering each one's request with `Refused`. Never
/// fails: a stash that cannot be removed now is kept, unanswered, for a
/// later pass, and replies already built are never dropped.
fn prune(s: &mut Space<'_>, make_room: bool) -> Vec<OutboundDelegateMsg> {
    let now = s.env.now_secs();
    let Ok((_, ids)) = s.index(PROMPT_INDEX) else {
        return Vec::new();
    };
    let mut live = Vec::new();
    let mut out = Vec::new();
    let retire = |s: &mut Space<'_>, id: &[u8], reason: &str, out: &mut Vec<_>| {
        let Some(prompt_id) = prompt_id_of(id) else {
            let _ = s.index_remove(PROMPT_INDEX, id);
            return;
        };
        let rel = prompt_rel(prompt_id);
        let pending = s.get(&rel).and_then(|b| from_cbor::<Pending>(&b).ok());
        // Remove the stash first; answer only once it is gone, so the
        // request can never be answered twice.
        if s.del(&rel).is_err() {
            return;
        }
        let _ = s.index_remove(PROMPT_INDEX, id);
        if let Some(p) = pending {
            out.push(response_msg(
                p.request_id,
                Err(fail(FailureCode::Refused, reason)),
            ));
        }
    };
    for id in ids {
        let pending = prompt_id_of(&id)
            .and_then(|pid| s.get(&prompt_rel(pid)))
            .and_then(|b| from_cbor::<Pending>(&b).ok());
        match pending {
            Some(p) if !expired(now, p.created) => live.push((p.seq, id)),
            _ => retire(s, &id, "the prompt expired", &mut out),
        }
    }
    if make_room {
        live.sort();
        let excess = live.len().saturating_sub(MAX_PENDING_PROMPTS - 1);
        for (_, id) in live.into_iter().take(excess) {
            retire(
                s,
                &id,
                "superseded by newer requests from this app",
                &mut out,
            );
        }
    }
    out
}

fn raise_prompt(
    s: &mut Space<'_>,
    request_id: RequestId,
    op: Op,
    kind: Kind,
) -> Result<OutboundDelegateMsg, Failure> {
    let seq = s
        .get(PROMPT_SEQ)
        .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0)
        + 1;
    // Fail closed: a reused sequence number could pair a stash with the
    // wrong prompt.
    s.put(PROMPT_SEQ, &seq.to_le_bytes())?;

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
    // Claim the index slot first: a stash is never written that the index
    // (and so `prune`) cannot find. If the stash write then fails, the slot
    // is released; a slot left without a stash is dropped by `prune`.
    s.index_add(PROMPT_INDEX, &prompt_id.to_be_bytes(), MAX_PENDING_PROMPTS)?;
    if let Err(f) = s.put(&prompt_rel(prompt_id), &stash) {
        let _ = s.index_remove(PROMPT_INDEX, &prompt_id.to_be_bytes());
        return Err(f);
    }

    let responses = match kind {
        Kind::Export => vec![ALLOW, ALWAYS, DENY],
        Kind::Destructive => vec![DELETE, CANCEL],
    };
    Ok(OutboundDelegateMsg::RequestUserInput(UserInputRequest {
        request_id: prompt_id,
        message,
        responses: responses
            .into_iter()
            .map(|r| ClientResponse::new(r.to_vec()))
            .collect(),
    }))
}

/// The user answered a prompt. An answer to an unknown, already answered or
/// foreign prompt is ignored.
pub fn answer(
    s: &mut Space<'_>,
    answer: &UserInputResponse<'_>,
) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
    let rel = prompt_rel(answer.request_id);
    let Some(stash) = s.get(&rel) else {
        return Ok(vec![]);
    };
    // Consume the stash first, so one prompt can never authorize two
    // operations. If that fails, nothing changed: the prompt stays pending
    // and is answered later (or refused when it expires).
    if s.del(&rel).is_err() {
        return Err(DelegateError::Other(
            "could not clear the answered prompt".into(),
        ));
    }
    // The stash is gone, so this request must be answered now. Its index
    // entry is bookkeeping: if removing it fails, `prune` drops it later.
    let _ = s.index_remove(PROMPT_INDEX, &answer.request_id.to_be_bytes());
    let pending: Pending =
        from_cbor(&stash).map_err(|e| DelegateError::Deser(format!("pending prompt: {e}")))?;
    if expired(s.env.now_secs(), pending.created) {
        return Ok(respond(
            pending.request_id,
            Err(fail(FailureCode::Refused, "the prompt expired")),
        ));
    }
    let choice: &[u8] = &answer.response;
    let result = match kind_of(&pending.op) {
        Some(Kind::Export) if choice == ALLOW => perform(s, &pending.request_id, &pending.op),
        Some(Kind::Export) if choice == ALWAYS => match s.put(EXPORT_GRANT, b"1") {
            Ok(()) => perform(s, &pending.request_id, &pending.op),
            Err(f) => Err(f),
        },
        Some(Kind::Destructive) if choice == DELETE => perform(s, &pending.request_id, &pending.op),
        // Deny, Cancel, and anything unrecognised.
        _ => Err(fail(FailureCode::Refused, "the user declined")),
    };
    Ok(respond(pending.request_id, result))
}
