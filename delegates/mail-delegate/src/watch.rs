//! The v1 watch: carries out a [`crate::jobs`] plan, importing what arrives
//! in each identity's v0.2.x inbox into its kept mail, with no page open.
//!
//! **The inbox is always read from this node's own store**
//! ([`Env::contract_state`]). A notification or a GET answer is only a reason
//! to look, and what it carries is not used. So a duplicate is a second look
//! at the same state, an out-of-order one a look at the current state, and a
//! dropped one is covered by the next wake-up. The store holds states the
//! contract validated, which a message handed to the delegate need not be.
//!
//! **No answer is Unknown.** A refused GET, a failed one and a contract that
//! is not here all read the same, and none of them says the inbox is empty:
//! nothing is concluded, and the next refresh asks again.
//!
//! **Import never overwrites and never brings back a deleted message.** An
//! arrival is written by [`crate::handlers::put_item`] as create-only, the
//! write the migration's imports use. A message is left alone if it has a kept
//! or archived copy, if its flags say deleted, or if it has a tombstone
//! ([`note_seen`]). Deleting a kept or archived copy or a flags item leaves a
//! tombstone first, so a message whose marks were reclaimed once it left the
//! inbox stays gone if an older state of the inbox comes back. Flags or lists
//! that cannot be read stop the import: a mark that may be there is treated
//! as if it is.
//!
//! Tombstones are per identity and bounded (16 shards of [`SEEN_PER_SHARD`]),
//! so past that many the protection of an old one can lapse. They travel
//! with an export.

use std::collections::BTreeSet;

use freenet_mail_protocol::{Addr, Failure, FailureCode, ItemKind, ItemRef, JobsRun};
use freenet_mail_wire_v1::local_state::KeptMessage;
use freenet_stdlib::prelude::{
    ContractInstanceId, GetContractRequest, OutboundDelegateMsg, SubscribeContractRequest,
};
use serde::Deserialize;

use crate::crypto::{self, Keys};
use crate::env::Env;
use crate::handlers;
use crate::jobs::{self, Budget, Target, Trigger};
use crate::store::{self, Origin, Space, seen_rel, seen_rels};

/// The namespace of the delegate's own records. No web app has it: a contract
/// id is a hash, and the origin gate refuses this value.
pub const GLOBAL: Origin = Origin([0; 32]);
/// The origins with identities, for runs no origin started.
const ORIGIN_INDEX: &str = "ix/bg/origins";
const BUDGET: &str = "bg/budget";
/// Origins a run the node starts works for. Past it a new origin's jobs run
/// only from its own `RunJobs`.
pub const MAX_ORIGINS: usize = 16;
/// Tombstones per shard. See the module doc.
pub const SEEN_PER_SHARD: usize = 512;
/// Largest inbox state read. A larger one stays unknown to the watch; the
/// page still reads it.
pub const MAX_INBOX_BYTES: usize = 16 * 1024 * 1024;

/// Remember that `origin` has identities, so runs with no origin reach it.
/// A failure is left for the next call: `RunJobs` and every new identity
/// record it again.
pub fn note_origin(env: &mut dyn Env, origin: Origin) {
    let _ = Space::new(env, GLOBAL).index_add(ORIGIN_INDEX, &origin.0, MAX_ORIGINS);
}

/// Record that message `id` of `owner` must not be imported again. When the
/// shard is full an entry makes room; ids are hashes, so which one is
/// arbitrary.
pub fn note_seen(s: &mut Space<'_>, owner: &Addr, id: &[u8]) -> Result<(), Failure> {
    let rel = seen_rel(owner, id);
    let (_, ids) = s.index(&rel)?;
    if ids.contains(id) {
        return Ok(());
    }
    if ids.len() >= SEEN_PER_SHARD
        && let Some(first) = ids.iter().next()
    {
        s.index_remove_many(&rel, std::slice::from_ref(first))?;
    }
    s.index_add(&rel, id, SEEN_PER_SHARD)
}

/// The node confirmed a subscription.
pub fn note_subscribed(env: &mut dyn Env, id: jobs::ContractId) {
    let now = env.now_secs().unwrap_or(0);
    let mut budget = load_budget(env, now);
    budget.note_subscribed(id);
    save_budget(env, &budget);
}

/// Every run, from every trigger: plan, then do the plan. Returns what it did
/// and the contract requests to send. Sends nothing to any page.
pub fn run(env: &mut dyn Env, trigger: Trigger) -> (JobsRun, Vec<OutboundDelegateMsg>) {
    let now = env.now_secs().unwrap_or(0);
    let mut done = JobsRun::default();
    let targets = targets(env, trigger, &mut done);
    let mut budget = load_budget(env, now);
    let before = budget.clone();
    let plan = jobs::plan(trigger, &targets, &mut budget);
    let mut out: Vec<OutboundDelegateMsg> = plan
        .subscribe
        .iter()
        .map(|id| {
            OutboundDelegateMsg::SubscribeContractRequest(SubscribeContractRequest::new(
                ContractInstanceId::new(*id),
            ))
        })
        .collect();
    let mut left = plan.messages;
    for target in &plan.scan {
        let mut s = Space::new(&mut *env, target.origin);
        if scan(&mut s, target, now, &mut left, &mut done).is_err() {
            done.unknown += 1;
            if plan.fetch_missing && budget.take_ops(1) == 1 {
                out.push(OutboundDelegateMsg::GetContractRequest(
                    GetContractRequest::new(ContractInstanceId::new(target.id)),
                ));
            }
        }
    }
    if trigger.is_unprompted() {
        budget.charge_messages(plan.messages - left);
    }
    if budget != before {
        save_budget(env, &budget);
    }
    (done, out)
}

/// The inboxes to watch: each listed origin's identities. An origin that
/// cannot be listed counts as unknown and is left for the next run.
fn targets(env: &mut dyn Env, trigger: Trigger, done: &mut JobsRun) -> Vec<Target> {
    let origins: Vec<Origin> = match trigger {
        Trigger::RunJobs(origin) => vec![origin],
        Trigger::NodeStarted | Trigger::Tick(_) | Trigger::Contract(_) => {
            let listed = Space::new(&mut *env, GLOBAL).index(ORIGIN_INDEX);
            let Ok((_, ids)) = listed else {
                done.unknown += 1;
                return Vec::new();
            };
            ids.iter()
                .filter_map(|id| Some(Origin(id.as_slice().try_into().ok()?)))
                .collect()
        }
    };
    let mut out = Vec::new();
    let mut emptied = Vec::new();
    for origin in origins {
        let s = Space::new(&mut *env, origin);
        if matches!(s.index(store::IDENTITY_INDEX), Ok((_, ids)) if ids.is_empty()) {
            emptied.push(origin.0.to_vec());
        }
        let Ok(identities) = handlers::all_identities(&s) else {
            done.unknown += 1;
            continue;
        };
        for (addr, _, record) in identities {
            match handlers::v1_inbox_id(&record.vk) {
                Ok(id) => out.push(Target { origin, addr, id }),
                Err(_) => done.unknown += 1,
            }
        }
    }
    // An origin with no identities left gives its place up: a new identity
    // or its `RunJobs` lists it again.
    if !emptied.is_empty() {
        let _ = Space::new(&mut *env, GLOBAL).index_remove_many(ORIGIN_INDEX, &emptied);
    }
    out
}

fn load_budget(env: &mut dyn Env, now: u64) -> Budget {
    let stored = Space::new(env, GLOBAL).get(BUDGET);
    let mut budget = stored
        .and_then(|b| freenet_mail_protocol::from_cbor::<Budget>(&b).ok())
        .unwrap_or_else(|| Budget::new(now));
    budget.advance(now);
    budget
}

fn save_budget(env: &mut dyn Env, budget: &Budget) {
    if let Ok(body) = freenet_mail_protocol::to_cbor(budget) {
        let _ = Space::new(env, GLOBAL).put(BUDGET, &body);
    }
}

/// The parts of a v1 inbox state the watch reads.
#[derive(Deserialize)]
struct V1Inbox {
    messages: Vec<V1Message>,
}

#[derive(Deserialize)]
struct V1Message {
    content: Vec<u8>,
    #[serde(default)]
    sender_vk: Vec<u8>,
    #[serde(default)]
    signature: Vec<u8>,
}

/// The parts of a v1 plaintext a kept copy holds.
#[derive(Deserialize)]
struct V1Plaintext {
    title: String,
    content: String,
    from: String,
    time: chrono::DateTime<chrono::Utc>,
}

/// A message's flags, as the page writes them.
#[derive(Deserialize)]
struct Flags {
    deleted: bool,
}

/// A message's id: what the page keys kept copies, archives and flags by.
pub fn message_id(ciphertext: &[u8]) -> [u8; 16] {
    let mut id = [0; 16];
    id.copy_from_slice(&blake3::hash(ciphertext).as_bytes()[..16]);
    id
}

fn unknown(detail: &str) -> Failure {
    store::fail(FailureCode::Busy, detail)
}

/// Import what is new in `target`'s inbox, up to `left` messages. `Err` means
/// the inbox or its bookkeeping could not be established: nothing about it
/// was concluded.
fn scan(
    s: &mut Space<'_>,
    target: &Target,
    now: u64,
    left: &mut usize,
    done: &mut JobsRun,
) -> Result<(), Failure> {
    let state = s
        .env
        .contract_state(&target.id)
        .filter(|state| state.len() <= MAX_INBOX_BYTES)
        .ok_or_else(|| unknown("the inbox is not held here"))?;
    let inbox: V1Inbox =
        serde_json::from_slice(&state).map_err(|_| unknown("the inbox state does not decode"))?;
    let owner = target.addr;
    let (_, record) = handlers::require_identity(s, &owner)?;
    let mut seen = BTreeSet::new();
    for rel in seen_rels(&owner) {
        seen.extend(s.index(&rel)?.1);
    }
    let mut held = s.index(&store::index_rel(ItemKind::Kept, Some(&owner)))?.1;
    held.extend(
        s.index(&store::index_rel(ItemKind::Archived, Some(&owner)))?
            .1,
    );
    let flags = s.index(&store::index_rel(ItemKind::Flags, Some(&owner)))?.1;
    done.scanned += 1;
    let mut keys = None;
    let mut full = false;
    for m in inbox.messages {
        let id = message_id(&m.content);
        if seen.contains(&id[..]) || held.contains(&id[..]) {
            continue;
        }
        if flags.contains(&id[..]) {
            match flagged_deleted(s, owner, id) {
                Some(false) => {}
                Some(true) => continue,
                None => {
                    done.remaining += 1;
                    continue;
                }
            }
        }
        if full || *left == 0 {
            done.remaining += 1;
            continue;
        }
        *left -= 1;
        let keys = keys.get_or_insert_with(|| Keys::from_seeds(&record.dsa, &record.kem));
        let Some(body) = kept_body(keys, &m, now) else {
            // It will never decrypt or parse: no slice is spent on it again.
            note_seen(s, &owner, &id)?;
            continue;
        };
        match handlers::put_item(s, item(ItemKind::Kept, owner, id), body, None) {
            Ok(_) => done.imported += 1,
            // Written since the lists were read. It stands.
            Err(f) if matches!(f.code, FailureCode::Conflict { .. }) => {}
            // Too large to keep: the inbox still holds it for the page.
            Err(f) if f.code == FailureCode::BadInput => note_seen(s, &owner, &id)?,
            Err(f) if f.code == FailureCode::CapReached => {
                full = true;
                done.remaining += 1;
            }
            Err(_) => done.remaining += 1,
        }
    }
    Ok(())
}

fn item(kind: ItemKind, owner: Addr, id: [u8; 16]) -> ItemRef {
    ItemRef {
        kind,
        owner: Some(owner),
        id: id.to_vec(),
    }
}

/// Whether a listed flags item says deleted; `None` when it cannot be told.
fn flagged_deleted(s: &Space<'_>, owner: Addr, id: [u8; 16]) -> Option<bool> {
    let (_, body) = s
        .read(&store::item_rel(&item(ItemKind::Flags, owner, id)))
        .ok()??;
    let flags: Flags = serde_json::from_slice(&body).ok()?;
    Some(flags.deleted)
}

/// A kept copy of `m`, or `None` if it does not decrypt to a message. The
/// signature is checked and recorded as the page records it: a bad one is
/// shown as unverified, not refused.
fn kept_body(keys: &Keys, m: &V1Message, now: u64) -> Option<Vec<u8>> {
    let plaintext = crypto::decrypt_v1(&keys.kem, &m.content)?;
    let message: V1Plaintext = serde_json::from_slice(&plaintext).ok()?;
    serde_json::to_vec(&KeptMessage {
        from: message.from,
        title: message.title,
        content: message.content,
        kept_at: i64::try_from(now.saturating_mul(1000)).unwrap_or(i64::MAX),
        sent_at: Some(message.time.timestamp_millis()),
        signature_valid: crypto::verify_v1(&m.content, &m.sender_vk, &m.signature),
        sender_vk: m.sender_vk.clone(),
    })
    .ok()
}
