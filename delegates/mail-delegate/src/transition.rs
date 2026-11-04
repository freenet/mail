//! The v1 transition (decisions 26 to 28): for 90 days after an identity's
//! v2 inbox is made, mail still arriving in its v0.2.x inbox is imported by
//! the v1 watch. When the window ends, the v0.2.x inbox is closed: its
//! settings are signed to `minimum_tier = Day365` with the token exemption
//! off, so a v0.2.x sender is refused rather than writing to an inbox nobody
//! reads.
//!
//! **Signed once.** The closing settings, their `last_update` and the
//! signature are recorded in the inbox record ([`V1Window::closes`]) before
//! any update carrying them leaves, and every later attempt sends those same
//! bytes. A record that cannot be read signs nothing. An inbox whose settings
//! are already closed (an identity restored after its close) is recorded as
//! closed without signing.
//!
//! **Nothing is lost.** The v1 contract checks every message it holds
//! against the new settings, and the node refuses an update whose outcome is
//! invalid, so the messages go first, in a `RemoveMessages` signed on each
//! attempt. Only a message this identity has as mail is removed: a kept or
//! archived copy that reads back and holds the same title and text as the
//! message decrypts to, or a deletion by the user (a tombstone or a deleted
//! flag, for a message that could have been kept). A message that never
//! decrypts can never be read by anyone and goes too. Anything else stays,
//! the settings are not sent, and the close is tried again on a later run
//! (the page shows it as pending). An update the node refuses because a
//! message arrived meanwhile is the same: the next run imports it and tries
//! again.
//!
//! Earlier v1 generations (`handlers::V1_LEGACY_INBOX_CODE_HASHES`) are read
//! during the window and never written.

use std::collections::BTreeMap;

use freenet_mail_protocol::inbox_v2::B32;
use freenet_mail_protocol::{
    Addr, Failure, FailureCode, Hash32, ItemKind, ItemRef, MAX_ITEM_BYTES, MAX_REMOVAL_BATCH, Reply,
};
use freenet_mail_wire_v1::aft::Tier;
use freenet_mail_wire_v1::inbox::{InboxSettings, UpdateInbox};
use freenet_mail_wire_v1::local_state::{ArchivedMessage, KeptMessage};
use serde::{Deserialize, Serialize};
use serde_bytes::{ByteArray, ByteBuf};

use crate::crypto::{self, Keys};
use crate::handlers;
use crate::inbox_v2::{self as v2, item};
use crate::store::{self, Space, fail, item_rel};

/// How long a v0.2.x inbox stays open after the identity's v2 inbox is made.
pub const WINDOW: u64 = 90 * 86_400;

/// The transition of one identity, in its inbox record.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct V1Window {
    /// Node time the window began: when the v2 inbox was made, or when this
    /// build first saw a record made before it.
    pub start: u64,
    /// The close of each v1 inbox, by contract id.
    #[serde(default)]
    pub closes: BTreeMap<B32, V1Closing>,
}

impl V1Window {
    pub fn ends(&self) -> u64 {
        self.start.saturating_add(WINDOW)
    }
}

/// A close signed for one v1 inbox. Never signed again.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct V1Closing {
    /// The closing settings, as the JSON that was signed.
    pub settings: ByteBuf,
    pub last_update_micros: i64,
    pub sig: ByteBuf,
    /// The inbox was seen holding these settings (or settings someone signed
    /// later): nothing more to send.
    pub done: bool,
}

/// Whether `s` refuses a v0.2.x sender with no year token.
pub fn is_closed(s: &InboxSettings) -> bool {
    s.minimum_tier == Tier::Day365 && !s.allow_verified_skip_token
}

/// The parts of a v1 inbox state the close reads.
#[derive(Deserialize)]
struct Inbox {
    messages: Vec<Message>,
    last_update: chrono::DateTime<chrono::Utc>,
    settings: InboxSettings,
}

#[derive(Deserialize)]
struct Message {
    content: Vec<u8>,
    token_assignment: Assignment,
    #[serde(default)]
    sender_vk: Vec<u8>,
    #[serde(default)]
    signature: Vec<u8>,
}

#[derive(Deserialize)]
struct Assignment {
    assignment_hash: [u8; 32],
}

/// The parts of a v1 plaintext the close compares with a copy.
#[derive(Deserialize)]
struct Plain {
    title: String,
    content: String,
}

/// Slack under [`MAX_ITEM_BYTES`] for the copy's `kept_at`, which is the
/// only field that differs between the watch's attempt and this one.
const SIZE_SLACK: usize = 64;

#[derive(Deserialize)]
struct Flags {
    deleted: bool,
}

/// Start `owner`'s window if its record has none. Returns the window, `None`
/// when the identity has no v2 inbox yet (no window), and an error when the
/// record cannot be read (nothing is concluded).
fn window(s: &mut Space<'_>, owner: &Addr, now: u64) -> Result<Option<V1Window>, Failure> {
    let (generation, mut rec) = match v2::record(s, owner) {
        Ok(r) => r,
        Err(f) if f.code == FailureCode::NotFound => return Ok(None),
        Err(f) => return Err(f),
    };
    if let Some(w) = rec.v1_window.clone() {
        return Ok(Some(w));
    }
    let w = V1Window {
        start: now,
        closes: BTreeMap::new(),
    };
    rec.v1_window = Some(w.clone());
    v2::save(s, item(ItemKind::InboxV2, owner, &[]), &rec, generation)?;
    Ok(Some(w))
}

/// Tests only (`Op::EndV1WindowForTest`, `v1-transition` builds): move the
/// window's start back so it ends now. Only ever earlier, and a close
/// already signed is not touched.
#[cfg(feature = "v1-transition")]
pub fn end_window_now(s: &mut Space<'_>, owner: &Addr) -> Result<(), Failure> {
    let now = s.env.now_secs().unwrap_or(0);
    window(s, owner, now)?.ok_or_else(|| fail(FailureCode::NotFound, "no v2 inbox"))?;
    let (generation, mut rec) = v2::record(s, owner)?;
    if let Some(w) = rec.v1_window.as_mut() {
        w.start = w.start.min(now.saturating_sub(WINDOW));
    }
    v2::save(s, item(ItemKind::InboxV2, owner, &[]), &rec, generation)
}

/// Whether `owner`'s window is over, starting it if it has none. An error or
/// no v2 inbox reads as not over.
pub fn ended(s: &mut Space<'_>, owner: &Addr, now: u64) -> bool {
    matches!(window(s, owner, now), Ok(Some(w)) if now >= w.ends())
}

/// Whether every v1 inbox of `owner` that the close has looked at is closed.
pub fn all_closed(s: &Space<'_>, owner: &Addr) -> bool {
    matches!(v2::record(s, owner), Ok((_, rec)) if rec
        .v1_window
        .as_ref()
        .is_some_and(|w| !w.closes.is_empty() && w.closes.values().all(|c| c.done)))
}

fn save_closing(
    s: &mut Space<'_>,
    owner: &Addr,
    id: &[u8; 32],
    closing: V1Closing,
) -> Result<(), Failure> {
    let (generation, mut rec) = v2::record(s, owner)?;
    let w = rec
        .v1_window
        .as_mut()
        .ok_or_else(|| fail(FailureCode::Internal, "the window went missing"))?;
    w.closes.insert(ByteArray::new(*id), closing);
    v2::save(s, item(ItemKind::InboxV2, owner, &[]), &rec, generation)
}

/// The updates (v1 `UpdateInbox` JSON, in order) that move `owner`'s v1
/// inbox `id`, whose stored state is `state`, towards closed, once its window
/// is over. Nothing before then.
pub fn close(
    s: &mut Space<'_>,
    owner: &Addr,
    id: &[u8; 32],
    state: &[u8],
    now: u64,
) -> Result<Vec<Vec<u8>>, Failure> {
    let Some(w) = window(s, owner, now)? else {
        return Ok(Vec::new());
    };
    if now < w.ends() {
        return Ok(Vec::new());
    }
    let bad = |_| fail(FailureCode::Busy, "the v1 inbox state does not decode");
    let inbox: Inbox = serde_json::from_slice(state).map_err(bad)?;
    let held = serde_json::to_vec(&inbox.settings)
        .map_err(|e| fail(FailureCode::Internal, e.to_string()))?;
    let held_at = inbox.last_update.timestamp_micros();
    let closing = match w.closes.get(&ByteArray::new(*id)) {
        Some(c) if c.done => return Ok(Vec::new()),
        Some(c) => c.clone(),
        None if is_closed(&inbox.settings) => {
            // Closed already: by this identity on another node, or before a
            // restore. Nothing to sign.
            let done = V1Closing {
                settings: ByteBuf::from(held),
                last_update_micros: held_at,
                sig: ByteBuf::new(),
                done: true,
            };
            save_closing(s, owner, id, done)?;
            return Ok(Vec::new());
        }
        None => {
            let mut settings = inbox.settings.clone();
            settings.minimum_tier = Tier::Day365;
            settings.allow_verified_skip_token = false;
            let json = serde_json::to_vec(&settings)
                .map_err(|e| fail(FailureCode::Internal, e.to_string()))?;
            let micros = i64::try_from(now.saturating_mul(1_000_000))
                .unwrap_or(i64::MAX)
                .max(held_at.saturating_add(1));
            let sig = match handlers::sign_v1_authority(s, owner, &json, micros)? {
                Reply::Signature(sig) => sig,
                _ => return Err(fail(FailureCode::Internal, "no signature")),
            };
            let c = V1Closing {
                settings: ByteBuf::from(json),
                last_update_micros: micros,
                sig,
                done: false,
            };
            // Recorded before it can leave.
            save_closing(s, owner, id, c.clone())?;
            c
        }
    };
    // Landed, or the owner signed something later from another client,
    // which stands.
    if held_at >= closing.last_update_micros {
        let done = V1Closing {
            done: true,
            ..closing
        };
        save_closing(s, owner, id, done)?;
        return Ok(Vec::new());
    }
    let (_, record) = handlers::require_identity(s, owner)?;
    let keys = Keys::from_seeds(&record.dsa, &record.kem);
    let mut remove = Vec::new();
    let mut stays = 0usize;
    for m in &inbox.messages {
        if imported(s, owner, &keys, m, now) {
            remove.push(Hash32(m.token_assignment.assignment_hash));
        } else {
            stays += 1;
        }
    }
    remove.sort_by_key(|h| h.0);
    remove.dedup_by_key(|h| h.0);
    let all = stays == 0 && remove.len() <= MAX_REMOVAL_BATCH;
    remove.truncate(MAX_REMOVAL_BATCH);
    let mut out = Vec::new();
    if !remove.is_empty() {
        let signature = match handlers::sign_v1_removal(s, owner, &remove)? {
            Reply::Signature(sig) => sig,
            _ => return Err(fail(FailureCode::Internal, "no signature")),
        };
        let update = UpdateInbox::RemoveMessages {
            signature: signature.into_vec().into_boxed_slice(),
            ids: remove.iter().map(|h| h.0).collect(),
        };
        out.push(
            serde_json::to_vec(&update).map_err(|e| fail(FailureCode::Internal, e.to_string()))?,
        );
    }
    if all {
        let settings: InboxSettings = serde_json::from_slice(&closing.settings)
            .map_err(|_| fail(FailureCode::Internal, "the recorded settings do not decode"))?;
        let last_update = chrono::DateTime::from_timestamp_micros(closing.last_update_micros)
            .ok_or_else(|| fail(FailureCode::Internal, "the recorded time is out of range"))?;
        let update = UpdateInbox::ModifySettings {
            inbox_signature: closing.sig.to_vec().into_boxed_slice(),
            settings,
            last_update,
        };
        out.push(
            serde_json::to_vec(&update).map_err(|e| fail(FailureCode::Internal, e.to_string()))?,
        );
    }
    Ok(out)
}

fn kind_item(kind: ItemKind, owner: &Addr, id: [u8; 16]) -> ItemRef {
    ItemRef {
        kind,
        owner: Some(*owner),
        id: id.to_vec(),
    }
}

/// Whether `m` is this identity's mail already, so removing it from the v1
/// inbox loses nothing. Anything that cannot be read says no.
fn imported(s: &Space<'_>, owner: &Addr, keys: &Keys, m: &Message, now: u64) -> bool {
    let id = crate::watch::message_id(&m.content);
    let plain = crypto::decrypt_v1(&keys.kem, &m.content)
        .and_then(|p| serde_json::from_slice::<Plain>(&p).ok());
    let read = |kind| match s.read(&item_rel(&kind_item(kind, owner, id))) {
        Ok(Some((_, body))) => Some(Some(body)),
        Ok(None) => Some(None),
        Err(_) => None,
    };
    // A copy that reads back and is this message.
    let same = |title: &str, content: &str| {
        plain
            .as_ref()
            .is_some_and(|p| p.title == title && p.content == content)
    };
    for kind in [ItemKind::Kept, ItemKind::Archived] {
        let Some(found) = read(kind) else {
            return false;
        };
        let Some(body) = found else {
            continue;
        };
        let matches = match kind {
            ItemKind::Kept => serde_json::from_slice::<KeptMessage>(&body)
                .is_ok_and(|k| same(&k.title, &k.content)),
            _ => serde_json::from_slice::<ArchivedMessage>(&body)
                .is_ok_and(|a| same(&a.title, &a.content)),
        };
        if matches {
            return true;
        }
    }
    if plain.is_none() {
        // Never readable by anyone. The watch tombstoned it.
        return tombstoned(s, owner, &id) == Some(true);
    }
    // A copy too large to keep was tombstoned by the watch, not the user:
    // it stays.
    let size = crate::watch::kept_len(keys, &m.content, &m.sender_vk, &m.signature, now);
    if size.is_none_or(|n| n.saturating_add(SIZE_SLACK) > MAX_ITEM_BYTES) {
        return false;
    }
    let deleted_flag = match read(ItemKind::Flags) {
        Some(Some(body)) => serde_json::from_slice::<Flags>(&body).is_ok_and(|f| f.deleted),
        _ => false,
    };
    deleted_flag || tombstoned(s, owner, &id) == Some(true)
}

fn tombstoned(s: &Space<'_>, owner: &Addr, id: &[u8; 16]) -> Option<bool> {
    s.index(&store::seen_rel(owner, id))
        .ok()
        .map(|(_, ids)| ids.contains(&id[..]))
}
