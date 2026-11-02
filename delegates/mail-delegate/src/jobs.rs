//! The job planner: what a run of the delegate's background jobs should do.
//!
//! Everything here is a pure function of its inputs, with no host calls, so a
//! run the node starts and a [`Op::RunJobs`](freenet_mail_protocol::Op::RunJobs)
//! from a page are one code path: both reach [`plan`] with a [`Trigger`] and
//! differ only in which trigger it is. `crate::watch` carries a plan out.
//!
//! The limits mirror freenet-core's for runs it starts on its own
//! (`BudgetLimits`), and the delegate keeps them itself because they do not
//! cover everything: a page's `RunJobs` is not an unprompted run, and core
//! charges a notification run's time without refusing it.

use freenet_mail_protocol::{Addr, MAX_DECRYPT_BATCH};
use serde::{Deserialize, Serialize};

use crate::store::Origin;

pub type ContractId = [u8; 32];

/// Subscriptions core holds for one delegate.
pub const MAX_SUBSCRIPTIONS: usize = 256;
/// Contract operations per minute, for the whole delegate.
pub const MAX_OPS_PER_MINUTE: u32 = 300;
/// Contract writes per minute, per contract.
pub const MAX_WRITES_PER_MINUTE: u32 = 60;
/// Contracts [`Budget::take_write`] tracks in one minute.
const MAX_WRITE_ENTRIES: usize = 256;
/// Inbox states one run reads. The rest wait for a later run.
pub const MAX_SCANS_PER_RUN: usize = 4;
/// 1% of wall time, the share of it runs the node starts may use.
pub const DUTY_REFILL_MS_PER_SEC: u64 = 10;
pub const DUTY_BURST_MS: u64 = 10_000;
/// Estimated time to read and parse one inbox state. The delegate has only a
/// clock in seconds, so duty is charged by estimate; core measures the real
/// time of the runs it starts and defers a delegate that overspends.
///
/// Measured on a real node (`cargo make test-e2e-background`, wasmtime, two
/// inboxes of up to three messages): a run that scans and imports nothing takes
/// 5 to 8 ms for two scans, so about 3 ms each, against the 50 ms first
/// assumed. This is a few times that, for larger inboxes.
pub const SCAN_COST_MS: u64 = 10;
/// Estimated time to decrypt one message, check its signature and store its
/// flags and kept copy. Measured on the same node: a run importing three took
/// 210 ms before the flags were written and 371 ms after, against 18 and 20 ms
/// for one that imported nothing and subscribed the same two inboxes, so about
/// 65 and then about 117 ms per message, against the 40 ms first assumed.
pub const MESSAGE_COST_MS: u64 = 120;

/// The periodic wake-ups, by manifest tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tick {
    Rescan,
    V1Watch,
    Renew,
    Clock,
}

impl Tick {
    pub const ALL: [(&'static str, Tick); 4] = [
        ("rescan", Tick::Rescan),
        ("v1watch", Tick::V1Watch),
        ("renew", Tick::Renew),
        ("clock", Tick::Clock),
    ];

    pub fn from_tag(tag: &[u8]) -> Option<Tick> {
        Self::ALL
            .iter()
            .find(|(name, _)| name.as_bytes() == tag)
            .map(|(_, tick)| *tick)
    }
}

/// Why a run started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trigger {
    NodeStarted,
    Tick(Tick),
    /// A notification or a GET answer named this contract. What it carried is
    /// not used (see `crate::watch`), so this is only a reason to look.
    Contract(ContractId),
    /// A page asked, for its own namespace.
    RunJobs(Origin),
}

impl Trigger {
    /// Whether the node started this run, so it draws on the duty budget.
    pub fn is_unprompted(self) -> bool {
        !matches!(self, Trigger::RunJobs(_))
    }
}

/// What a trigger asks for, in order. Only the `V1` jobs do anything in this
/// version; the others name where inbox v2's work goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Job {
    /// Subscribe to the v1 inboxes and ask the network for any not held here.
    V1Refresh,
    /// Import arrivals from the v1 inbox states this node holds. No network.
    V1Scan,
    /// Drain the owner's inboxes.
    DrainOwn,
    /// Advance `owner_time`, after a drain.
    AdvanceClock,
    /// Renew what expires.
    Renew,
    /// Hand a page the queued work the delegate cannot do itself.
    SendQueued,
}

/// The jobs of a trigger. A dropped notification is not replayed, so every
/// periodic look includes a scan.
pub fn jobs_for(trigger: Trigger) -> &'static [Job] {
    match trigger {
        Trigger::NodeStarted => &[Job::V1Refresh, Job::V1Scan, Job::DrainOwn],
        Trigger::RunJobs(_) => &[Job::V1Refresh, Job::V1Scan, Job::DrainOwn, Job::SendQueued],
        Trigger::Tick(Tick::V1Watch) => &[Job::V1Refresh, Job::V1Scan],
        Trigger::Tick(Tick::Rescan) | Trigger::Contract(_) => &[Job::V1Scan, Job::DrainOwn],
        Trigger::Tick(Tick::Renew) => &[Job::Renew],
        Trigger::Tick(Tick::Clock) => &[Job::DrainOwn, Job::AdvanceClock],
    }
}

/// One identity's watched inbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target {
    pub origin: Origin,
    pub addr: Addr,
    pub id: ContractId,
}

/// A subscription's rank class, strongest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// The owner's own inboxes (inbox v2).
    Own,
    /// v0.2.x inboxes. Inbox v2 stops offering these when their 90-day window
    /// closes.
    V1Inbox,
    /// Contacts' inboxes, for key refresh (inbox v2).
    Contact,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub id: ContractId,
    pub origin: Origin,
    pub tier: Tier,
    /// When this contract was last active, for the contact tier: latest first.
    pub activity: u64,
}

/// The contracts worth a subscription, best first, at most
/// [`MAX_SUBSCRIPTIONS`]. What falls off is refreshed by a page's GET when it
/// composes.
///
/// Within a tier origins take turns (each origin's first, then each origin's
/// second, ...), so one app with many identities cannot push another's out.
pub fn rank_subscriptions(candidates: &[Candidate]) -> Vec<ContractId> {
    let key = |c: &Candidate| (c.tier, std::cmp::Reverse(c.activity), c.origin.0, c.id);
    let mut sorted = candidates.to_vec();
    sorted.sort_by_key(key);
    let mut turns: Vec<(Tier, Origin, usize)> = Vec::new();
    let mut ranked: Vec<(Tier, usize, ContractId)> = Vec::with_capacity(sorted.len());
    for c in sorted {
        let turn = turns
            .iter_mut()
            .find(|(tier, origin, _)| *tier == c.tier && *origin == c.origin);
        let position = match turn {
            Some((_, _, taken)) => {
                *taken += 1;
                *taken
            }
            None => {
                turns.push((c.tier, c.origin, 0));
                0
            }
        };
        ranked.push((c.tier, position, c.id));
    }
    // Stable, so one turn keeps the order of the sort above.
    ranked.sort_by_key(|(tier, position, _)| (*tier, *position));
    let mut out: Vec<ContractId> = Vec::with_capacity(ranked.len().min(MAX_SUBSCRIPTIONS));
    for (_, _, id) in ranked {
        // Two origins can hold one identity: one subscription serves both.
        if out.len() < MAX_SUBSCRIPTIONS && !out.contains(&id) {
            out.push(id);
        }
    }
    out
}

/// What the budgets have left, kept between runs. Losing it costs a reset:
/// core's own limits on the runs it starts still hold.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budget {
    minute: u64,
    ops: u32,
    writes: Vec<(ContractId, u32)>,
    duty_ms: u64,
    duty_at: u64,
    /// Where the next run's scans start.
    cursor: u32,
    /// Subscriptions the node confirmed since it started. Not asked for again:
    /// the delegate is parked while a request is out, and a page's calls wait
    /// behind it. Losing this costs one repeat, which is harmless.
    subscribed: Vec<ContractId>,
}

impl Budget {
    /// A full budget at `now` (seconds).
    pub fn new(now: u64) -> Self {
        Budget {
            minute: now / 60,
            ops: 0,
            writes: Vec::new(),
            duty_ms: DUTY_BURST_MS,
            duty_at: now,
            cursor: 0,
            subscribed: Vec::new(),
        }
    }

    /// Bring the windows up to `now`. A clock that steps back refills nothing
    /// and reopens nothing.
    pub fn advance(&mut self, now: u64) {
        if now / 60 > self.minute {
            self.minute = now / 60;
            self.ops = 0;
            self.writes.clear();
        }
        if now > self.duty_at {
            let refill = (now - self.duty_at).saturating_mul(DUTY_REFILL_MS_PER_SEC);
            self.duty_ms = self.duty_ms.saturating_add(refill).min(DUTY_BURST_MS);
            self.duty_at = now;
        }
    }

    /// The node confirmed a subscription.
    pub fn note_subscribed(&mut self, id: ContractId) {
        if !self.subscribed.contains(&id) && self.subscribed.len() < MAX_SUBSCRIPTIONS {
            self.subscribed.push(id);
        }
    }

    /// Take up to `want` operations; how many this minute still allows.
    pub fn take_ops(&mut self, want: usize) -> usize {
        let left = MAX_OPS_PER_MINUTE.saturating_sub(self.ops) as usize;
        let granted = want.min(left);
        self.ops += granted as u32;
        granted
    }

    /// Take one write to `contract`, which is also an operation.
    pub fn take_write(&mut self, contract: &ContractId) -> bool {
        let at = self.writes.iter().position(|(id, _)| id == contract);
        let room = match at {
            Some(i) => self.writes[i].1 < MAX_WRITES_PER_MINUTE,
            None => self.writes.len() < MAX_WRITE_ENTRIES,
        };
        if !room || self.take_ops(1) == 0 {
            return false;
        }
        match at {
            Some(i) => self.writes[i].1 += 1,
            None => self.writes.push((*contract, 1)),
        }
        true
    }

    /// Charge `ms` of duty, if that much is left.
    pub fn take_duty(&mut self, ms: u64) -> bool {
        if self.duty_ms < ms {
            return false;
        }
        self.duty_ms -= ms;
        true
    }

    /// The messages one run may decrypt: never past the batch limit that keeps
    /// a call within the host's time limit, and for a run the node started,
    /// never past the duty left.
    pub fn message_slice(&self, unprompted: bool) -> usize {
        if !unprompted {
            return MAX_DECRYPT_BATCH;
        }
        MAX_DECRYPT_BATCH.min((self.duty_ms / MESSAGE_COST_MS) as usize)
    }

    /// Charge the messages a run actually took.
    pub fn charge_messages(&mut self, messages: usize) {
        self.duty_ms = self
            .duty_ms
            .saturating_sub(messages as u64 * MESSAGE_COST_MS);
    }
}

/// What a run should do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    /// Inboxes to read, in order.
    pub scan: Vec<Target>,
    pub subscribe: Vec<ContractId>,
    /// Ask the network for a scanned inbox this node does not hold.
    pub fetch_missing: bool,
    /// Messages this run may decrypt.
    pub messages: usize,
}

/// Decide a run, taking what it will use from `budget`.
pub fn plan(trigger: Trigger, targets: &[Target], budget: &mut Budget) -> Plan {
    let jobs = jobs_for(trigger);
    let unprompted = trigger.is_unprompted();
    let refresh = jobs.contains(&Job::V1Refresh);
    let eligible: Vec<Target> = match trigger {
        Trigger::Contract(id) => targets.iter().filter(|t| t.id == id).copied().collect(),
        Trigger::RunJobs(origin) => targets
            .iter()
            .filter(|t| t.origin == origin)
            .copied()
            .collect(),
        Trigger::NodeStarted | Trigger::Tick(_) => targets.to_vec(),
    };
    let mut scan = Vec::new();
    if jobs.contains(&Job::V1Scan) {
        // A rotation, so a run that stops at the limit resumes where it ended
        // and every inbox is reached however many are watched.
        let start = budget.cursor as usize % eligible.len().max(1);
        for t in eligible
            .iter()
            .cycle()
            .skip(start)
            .take(eligible.len().min(MAX_SCANS_PER_RUN))
        {
            if unprompted && !budget.take_duty(SCAN_COST_MS) {
                break;
            }
            scan.push(*t);
        }
        if !matches!(trigger, Trigger::Contract(_)) {
            budget.cursor = ((start + scan.len()) % eligible.len().max(1)) as u32;
        }
    }
    if trigger == Trigger::NodeStarted {
        budget.subscribed.clear();
    }
    let mut subscribe = Vec::new();
    if refresh {
        let candidates: Vec<Candidate> = eligible
            .iter()
            .map(|t| Candidate {
                id: t.id,
                origin: t.origin,
                tier: Tier::V1Inbox,
                activity: 0,
            })
            .collect();
        subscribe = rank_subscriptions(&candidates);
        subscribe.retain(|id| !budget.subscribed.contains(id));
        subscribe.truncate(budget.take_ops(subscribe.len()));
    }
    Plan {
        scan,
        subscribe,
        fetch_missing: refresh,
        messages: budget.message_slice(unprompted),
    }
}
