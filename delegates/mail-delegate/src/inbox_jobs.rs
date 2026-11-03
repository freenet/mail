//! The inbox v2 jobs: drain, clock and renew, for runs the node starts and a
//! page's `RunJobs` alike (`crate::watch::run` calls [`run`]).
//!
//! **Drain** reads the identity's own inbox from this node's store, as the v1
//! watch does, and goes through the same [`inbox_v2::owner_update`] as the
//! page's operation: every message is stored before an update tombstones it,
//! and nothing is signed while a message is not stored (decision 9).
//!
//! **Clock** is a drain whose change is `AdvanceTime`, once `owner_time`
//! trails the node's clock by [`inbox_v2::CLOCK_LAG`], under the guard.
//!
//! **Renew** sends each contact pass's new certificate as a silent system
//! message through the pass the contact gave us, at the pass's drawn
//! renewal point (or its reissue point after an epoch bump), whether or not
//! the user writes to that contact. It reads back: the certificate counts as
//! delivered once its message is held or tombstoned in the contact's inbox,
//! and is sealed again (a fresh message, so a fresh `sent_time`) every
//! [`inbox_v2::RESEND_AFTER`] until it is. Mail to the contact carries the
//! same certificate and is read back the same way. It is never sent through
//! quarantine: with no live pass to the contact, the next mail carries it.
//!
//! A contact's inbox is found under our own Ghost Key master: senders use
//! the production master, and a test network its own (§5.1).

use freenet_mail_protocol::inbox_v2::{self as w, B24};
use freenet_mail_protocol::{Addr, Failure, FailureCode, JobsRun, OwnerChange, SealContent};
use freenet_mail_protocol::{ItemKind, SendAdmission};
use freenet_stdlib::prelude::{
    ContractInstanceId, ContractKey, OutboundDelegateMsg, Parameters, StateDelta,
    UpdateContractRequest, UpdateData,
};
use serde_bytes::ByteArray;

use crate::env::Env;
use crate::inbox_v2::{self as v2, LedgerEntry, Me};
use crate::jobs::{self, Budget, Candidate, ContractId, Job, Tier, Trigger};
use crate::store::{Origin, Space, fail};

/// Own inboxes one run drains. The rest wait for a later run.
pub const MAX_INBOXES_PER_RUN: usize = 4;
/// A contact whose inbox is not held here, or whose renewal failed, is
/// looked at again after this, doubling with each such look up to
/// [`MISS_RETRY_MAX`].
const FETCH_RETRY: u64 = 3600;
pub const MISS_RETRY_MAX: u64 = 86_400;
/// What an owner update takes from a run's message slice, in messages
/// ([`jobs::MESSAGE_COST_MS`] each): one ML-DSA signature and one record.
pub const OWNER_SLOTS: usize = 1;
/// Renewals one run may send. They do not share the message slice: their
/// throughput comes from the duty budget, at [`RENEW_COST_MS`] each, over
/// every run that renews (the 15-minute rescan, the 6-hour renew tick, node
/// start and a page's run). The rescan alone is 96 runs a day, so 384
/// renewals a day: every one of `MAX_CONTACTS` (2048) contacts is reissued
/// within 5.4 days of a bump, against the 14-day grace (2.6 times over), and
/// a day's renewals cost under 2% of the day's duty.
pub const RENEW_PER_RUN: usize = 4;
/// Contacts one run may look at for renewal, whether or not it sends: a look
/// reads and checks the contact's inbox ([`jobs::SCAN_COST_MS`]), so a run with
/// many contacts whose inboxes are missing stays bounded.
pub const RENEW_LOOKS_PER_RUN: usize = 16;
/// What one renewal is charged in duty, the same as a v1 import.
///
/// Measured in wasm (2026-11-03, wasmtime 47.0.4, cranelift, the delegate's
/// code built for wasm32 release behind a C ABI, with an in-memory host so
/// only the guest's own work is timed, best of three on nova under load):
/// draining a message (ML-KEM decapsulation, ML-DSA verify, the stores) takes
/// about 1.8 ms, and a renewal (reading and checking the contact's inbox,
/// ML-KEM encapsulation, the seal) about 14 ms. On the node the host's writes
/// dominate: a v1 import (35 host writes) cost 117 ms there
/// ([`jobs::MESSAGE_COST_MS`]), a drained message makes 24 and a renewal 22
/// (`tests::inbox_jobs::a_drained_message_costs_about_what_an_import_does`).
/// So a drained message is charged one slot of the message slice, and a
/// renewal one import's duty, both at or above what they cost.
pub const RENEW_COST_MS: u64 = 120;
/// A page's own rotation over its origin's inboxes, in its namespace.
const PAGE_CURSOR: &str = "bg/cursor-v2";

/// The inbox v2 contract's code hash. Until a release freezes it, the
/// candidate's: a test network runs the candidate.
pub fn code_hash() -> &'static str {
    include_str!("../../../published-contract/candidate/inbox_v2_code_hash").trim()
}

/// The instance id of `addr`'s v2 inbox under `ghost_master`.
pub fn inbox_id(addr: &Addr, ghost_master: &[u8; 32]) -> Result<ContractId, Failure> {
    let params = Parameters::from(w::params_bytes(&addr.0, ghost_master));
    let key = ContractKey::from_params(code_hash(), params)
        .map_err(|_| fail(FailureCode::Internal, "bad inbox v2 code hash"))?;
    key.id()
        .as_bytes()
        .try_into()
        .map_err(|_| fail(FailureCode::Internal, "inbox id is not 32 bytes"))
}

/// One identity with a v2 inbox, as a run sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Own {
    pub origin: Origin,
    pub addr: Addr,
    pub id: ContractId,
    /// Contacts' inboxes a renewal looks at soon.
    pub contacts: Vec<ContractId>,
}

/// `addr`'s v2 inbox, `Ok(None)` if it has none.
pub fn own(s: &Space<'_>, addr: &Addr, now: u64) -> Result<Option<Own>, Failure> {
    let rec = match v2::record(s, addr) {
        Ok((_, rec)) => rec,
        Err(f) if f.code == FailureCode::NotFound => return Ok(None),
        Err(f) => return Err(f),
    };
    let soon = now.saturating_add(v2::RESEND_AFTER);
    let contacts = rec
        .due
        .iter()
        .filter(|(_, at)| **at <= soon)
        .map(|(c, _)| inbox_id(&Addr(**c), &rec.ghost_master))
        .collect::<Result<_, _>>()?;
    Ok(Some(Own {
        origin: s.origin,
        addr: *addr,
        id: inbox_id(addr, &rec.ghost_master)?,
        contacts,
    }))
}

/// The inboxes `trigger` covers.
fn eligible(trigger: Trigger, owns: &[Own]) -> Vec<&Own> {
    owns.iter()
        .filter(|o| match trigger {
            Trigger::RunJobs(origin) => o.origin == origin,
            Trigger::Contract(id) => o.id == id || o.contacts.contains(&id),
            Trigger::NodeStarted | Trigger::Tick(_) => true,
        })
        .collect()
}

/// What a run should keep subscribed: own inboxes first, then the contacts'
/// inboxes a renewal reads back from.
pub fn candidates(trigger: Trigger, owns: &[Own]) -> Vec<Candidate> {
    let mut out = Vec::new();
    for o in eligible(trigger, owns) {
        let c = |id, tier| Candidate {
            id,
            origin: o.origin,
            tier,
            activity: 0,
        };
        out.push(c(o.id, Tier::Own));
        out.extend(o.contacts.iter().map(|id| c(*id, Tier::Contact)));
    }
    out
}

/// What a run did that `crate::watch` finishes.
#[derive(Default)]
pub struct Done {
    pub out: Vec<OutboundDelegateMsg>,
    /// Contracts found held here.
    pub held: Vec<ContractId>,
    /// Contracts that were needed and are not held here.
    pub missing: Vec<ContractId>,
}

fn update(id: ContractId, bytes: Vec<u8>) -> OutboundDelegateMsg {
    OutboundDelegateMsg::UpdateContractRequest(UpdateContractRequest::new(
        ContractInstanceId::new(id),
        UpdateData::Delta(StateDelta::from(bytes)),
    ))
}

/// Run the inbox v2 jobs of `trigger`. `left` is the run's message slice,
/// shared with the v1 watch.
pub fn run(
    env: &mut dyn Env,
    trigger: Trigger,
    owns: &[Own],
    budget: &mut Budget,
    now: u64,
    left: &mut usize,
    done: &mut JobsRun,
) -> Done {
    let jobs = jobs::jobs_for(trigger);
    let unprompted = trigger.is_unprompted();
    let mut d = Done::default();
    let list = eligible(trigger, owns);
    if list.is_empty() {
        return d;
    }
    // A rotation, so every inbox is reached however many there are. A page
    // keeps its own, as the v1 watch does. It moves past an inbox only as
    // that inbox's drain begins, and is saved then, with the budget: a run
    // core abandons does not start over on the same inbox, and an inbox the
    // slice did not reach is the next run's first.
    let page = match trigger {
        Trigger::RunJobs(origin) => Some(origin),
        _ => None,
    };
    let rotates = !matches!(trigger, Trigger::Contract(_));
    let stored = page.and_then(|o| {
        let b = Space::new(&mut *env, o).get(PAGE_CURSOR)?;
        Some(u32::from_le_bytes(b.try_into().ok()?))
    });
    let start = stored.unwrap_or(budget.cursor_v2) as usize % list.len();
    let take = list.len().min(MAX_INBOXES_PER_RUN);
    let mut advancing = rotates;
    let (mut looks, mut sends) = (RENEW_LOOKS_PER_RUN, RENEW_PER_RUN);
    for i in 0..take {
        let own = list[(start + i) % list.len()];
        let mine = !matches!(trigger, Trigger::Contract(id) if id != own.id);
        let drain = mine && jobs.contains(&Job::DrainOwn);
        let clock = mine && jobs.contains(&Job::AdvanceClock);
        if drain || clock {
            if unprompted && !budget.take_duty(jobs::SCAN_COST_MS) {
                break;
            }
            let mut s = Space::new(&mut *env, own.origin);
            let cursor = advancing.then_some((page, ((start + i + 1) % list.len()) as u32));
            let served = match v2::me(&s, &own.addr) {
                Ok(me) => {
                    let what = (drain, clock, unprompted);
                    let job = (cursor, now, &mut *left, &mut *budget);
                    drain_own(&mut s, &me, own, what, job, done, &mut d)
                }
                Err(_) => {
                    done.unknown += 1;
                    true
                }
            };
            advancing &= served;
        }
        if jobs.contains(&Job::Renew) {
            let mut s = Space::new(&mut *env, own.origin);
            let Ok(me) = v2::me(&s, &own.addr) else {
                done.unknown += 1;
                continue;
            };
            let only = match trigger {
                Trigger::Contract(id) if id != own.id => Some(id),
                _ => None,
            };
            let mut job = Renewing {
                me: &me,
                now,
                unprompted,
                budget: &mut *budget,
                done: &mut d,
                failed: 0,
            };
            if job.run(&mut s, only, (&mut looks, &mut sends)).is_err() {
                done.unknown += 1;
            }
            done.unknown += job.failed;
        }
    }
    d
}

/// Move the rotation to `next` and save it, with the budget for a run the
/// node started.
fn save_cursor(env: &mut dyn Env, page: Option<Origin>, budget: &mut Budget, next: u32) {
    match page {
        Some(o) => {
            let mut s = Space::new(&mut *env, o);
            if s.get(PAGE_CURSOR).as_deref() != Some(&next.to_le_bytes()[..]) {
                let _ = s.put(PAGE_CURSOR, &next.to_le_bytes());
            }
        }
        None => {
            budget.cursor_v2 = next;
            crate::watch::save_budget(env, budget);
        }
    }
}

/// The rotation's position past an inbox, to save once it is served.
type Cursor = Option<(Option<Origin>, u32)>;

/// Drain `own`, or move its clock. Returns whether it was served: false only
/// when the slice had no room for a drain it needed, so the rotation comes
/// back to it first. The rotation is saved before the work.
fn drain_own(
    s: &mut Space<'_>,
    me: &Me,
    own: &Own,
    (drain, clock, unprompted): (bool, bool, bool),
    (cursor, now, left, budget): (Cursor, u64, &mut usize, &mut Budget),
    done: &mut JobsRun,
    d: &mut Done,
) -> bool {
    let serve = |s: &mut Space<'_>, budget: &mut Budget| {
        if let Some((page, next)) = cursor {
            save_cursor(&mut *s.env, page, budget, next);
        }
        true
    };
    let Some(bytes) = s.env.contract_state(&own.id) else {
        done.unknown += 1;
        d.missing.push(own.id);
        return serve(s, budget);
    };
    d.held.push(own.id);
    if unprompted {
        budget.charge_bytes(bytes.len());
    }
    done.scanned += 1;
    let Ok(state) = v2::own_state(me, &bytes) else {
        done.unknown += 1;
        return serve(s, budget);
    };
    let pending = state
        .messages
        .keys()
        .any(|id| !state.owner.tombstones.contains_key(id));
    // The clock moves with what is left of the slice, none at all included:
    // it then moves only as far as keeps every message still in the inbox.
    let change = if clock && now >= state.time.owner_time.saturating_add(v2::CLOCK_LAG) {
        OwnerChange::AdvanceTime
    } else if drain && pending && *left >= OWNER_SLOTS {
        OwnerChange::Drain
    } else {
        // Nothing to do here, unless only the slice stopped it.
        return !(drain && pending) && serve(s, budget);
    };
    // The update it may sign is paid for first.
    if !budget.may_write(&own.id) {
        return false;
    }
    serve(s, budget);
    let mut rng = v2::background_rng(s, me, "drain", now, &own.id);
    let limit = left.saturating_sub(OWNER_SLOTS).min(v2::DRAIN_BATCH);
    match v2::owner_update(s, me, &state, change, now, &mut rng, limit, true) {
        Ok((u, tried)) => {
            *left = left.saturating_sub(tried + OWNER_SLOTS);
            done.imported += u.drained;
            done.remaining += u.remaining + u.full;
            if let Some(bytes) = u.update {
                budget.take_write(own.id);
                d.out.push(update(own.id, bytes.into_vec()));
            }
        }
        Err(_) => done.unknown += 1,
    }
    true
}

struct Renewing<'a> {
    me: &'a Me,
    now: u64,
    unprompted: bool,
    budget: &'a mut Budget,
    done: &'a mut Done,
    /// Contacts whose step failed this run.
    failed: u32,
}

impl Renewing<'_> {
    /// Look at every contact whose time has come, the longest waiting first,
    /// while the run's renewals last; `only` limits it to the contact whose
    /// inbox this is. Every contact looked at gets its own next time, whether
    /// its step succeeded or failed, so one never holds up another.
    fn run(
        &mut self,
        s: &mut Space<'_>,
        only: Option<ContractId>,
        renewals: (&mut usize, &mut usize),
    ) -> Result<(), Failure> {
        let (_, rec) = v2::record(s, &self.me.addr)?;
        let mut due: Vec<(u64, B24)> = rec
            .due
            .iter()
            .filter(|(_, at)| **at <= self.now)
            .map(|(c, at)| (*at, *c))
            .collect();
        due.sort_unstable();
        let (looks, sends) = renewals;
        for (_, contact) in due {
            let no_duty = self.unprompted && self.budget.duty_ms < RENEW_COST_MS;
            if *looks == 0 || *sends == 0 || no_duty {
                break;
            }
            let addr = Addr(*contact);
            let id = inbox_id(&addr, &rec.ghost_master)?;
            if only.is_some_and(|o| o != id) {
                continue;
            }
            // A look reads and checks the contact's inbox; a renewal sent
            // costs the rest.
            *looks -= 1;
            let sent = self.done.out.len();
            if self.unprompted {
                self.budget.take_duty(jobs::SCAN_COST_MS);
            }
            let next = match self.one(s, &addr, id) {
                Ok(next) => next,
                Err(_) => {
                    self.failed += 1;
                    Some(self.miss(s, &contact))
                }
            };
            if self.done.out.len() > sent {
                *sends -= 1;
                if self.unprompted {
                    self.budget.take_duty(RENEW_COST_MS);
                }
            }
            v2::set_due(s, &self.me.addr, &contact, next)?;
        }
        Ok(())
    }

    /// One more look at `contact` that found nothing to work with: the next
    /// waits twice as long as the last, from FETCH_RETRY up to a day.
    fn miss(&mut self, s: &mut Space<'_>, contact: &B24) -> u64 {
        let misses = v2::record(s, &self.me.addr)
            .ok()
            .and_then(|(_, rec)| rec.issued.get(contact).copied())
            .and_then(|pass_id| {
                let at = v2::item(ItemKind::PassLedger, &self.me.addr, pass_id.as_slice());
                let (generation, mut e) = v2::load::<LedgerEntry>(s, &at).ok()??;
                e.misses = e.misses.saturating_add(1);
                v2::save(s, at, &e, generation).ok()?;
                Some(e.misses)
            })
            .unwrap_or(1);
        self.now + backoff(misses)
    }

    /// Renew `contact`'s pass if due and deliver its certificate. Returns
    /// when to look again.
    fn one(
        &mut self,
        s: &mut Space<'_>,
        contact: &Addr,
        id: ContractId,
    ) -> Result<Option<u64>, Failure> {
        let (me, now) = (self.me, self.now);
        let (_, rec) = v2::record(s, &me.addr)?;
        let key = ByteArray::new(contact.0);
        let Some(pass_id) = rec.issued.get(&key).copied() else {
            return Ok(None);
        };
        let at = v2::item(ItemKind::PassLedger, &me.addr, pass_id.as_slice());
        let Some((generation, mut e)) = v2::load::<LedgerEntry>(s, &at)? else {
            return Ok(None);
        };
        if e.revoked {
            return Ok(None);
        }
        let held = s.env.contract_state(&id);
        if held.is_some() {
            self.done.held.push(id);
        }
        if let Some(b) = held.as_ref().filter(|_| self.unprompted) {
            self.budget.charge_bytes(b.len());
        }
        let state = held.and_then(|b| v2::their_state(contact, &b).ok());
        let mut changed = false;
        if state.is_some() && e.misses != 0 {
            e.misses = 0;
            changed = true;
        }
        // Read back what was sent.
        if let (Some(st), Some(p)) = (&state, &e.pending)
            && w::delivered(st, &p.id)
        {
            e.delivered = e.delivered.max(p.expiry);
            e.pending = None;
            changed = true;
        }
        if changed {
            v2::save(s, at, &e, generation)?;
        }
        // A pass the contact has never been seen to get came with mail the
        // page sealed, which it may never have sent: it is read back for
        // while that mail could still land, and nothing is sent for it, so
        // composing to someone never makes this node write to them.
        if e.delivered == 0 {
            if state.is_none() && e.pending.is_some() {
                self.done.missing.push(id);
            }
            return Ok(e
                .pending
                .as_ref()
                .map(|p| p.at + w::WINDOW_BACK)
                .filter(|end| now < *end)
                .map(|end| (now + v2::RESEND_AFTER).min(end)));
        }
        let renewing = now >= v2::refresh_at(&rec, &pass_id, &e) || e.expiry <= now;
        if !renewing && e.expiry <= e.delivered {
            return Ok(Some(v2::refresh_at(&rec, &pass_id, &e)));
        }
        if let Some(p) = e.pending.as_ref().filter(|p| p.expiry >= e.expiry)
            && !renewing
            && now < p.at + v2::RESEND_AFTER
        {
            return Ok(Some(p.at + v2::RESEND_AFTER));
        }
        let Some(state) = state else {
            // Not held here: asked for, and looked at again later and later
            // while it stays missing.
            self.done.missing.push(id);
            return Ok(Some(self.miss(s, &key)));
        };
        if !self.budget.may_write(&id) {
            return Ok(Some(now + 60));
        }
        let mut rng = v2::background_rng(s, me, "renew", now, &contact.0);
        let sealed = v2::seal_to(
            s,
            me,
            contact,
            &state,
            SealContent::PassUpdate,
            None,
            now,
            &mut rng,
        );
        let (sealed, pass_id) = match sealed {
            // A RequireGhost inbox with no pass of ours that admits: no pass.
            Err(f) if f.code == FailureCode::Refused => return Ok(Some(now + v2::NO_PASS_RETRY)),
            other => other?,
        };
        if sealed.admission != SendAdmission::Pass {
            return Ok(Some(now + v2::NO_PASS_RETRY));
        }
        v2::note_sent(s, me, &pass_id, &sealed.id.0, now, true)?;
        let message: w::Message =
            w::decode(&sealed.message).map_err(|e| fail(FailureCode::Internal, e))?;
        let delta = w::InboxDelta {
            messages: [(ByteArray::new(sealed.id.0), message)].into(),
            ..w::InboxDelta::default()
        };
        self.budget.take_write(id);
        self.done.out.push(update(id, w::encode(&delta)));
        Ok(Some(now + v2::RESEND_AFTER))
    }
}

/// The wait after `misses` looks in a row found nothing to work with.
pub fn backoff(misses: u32) -> u64 {
    FETCH_RETRY
        .saturating_mul(1 << misses.saturating_sub(1).min(16))
        .min(MISS_RETRY_MAX)
}
