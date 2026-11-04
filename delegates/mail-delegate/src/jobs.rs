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

use freenet_mail_protocol::Addr;
use serde::{Deserialize, Serialize};

use crate::store::Origin;

pub type ContractId = [u8; 32];

/// Subscriptions core holds for one delegate.
pub const MAX_SUBSCRIPTIONS: usize = 256;
/// Contract operations per minute, for the whole delegate.
pub const MAX_OPS_PER_MINUTE: u32 = 300;
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
/// Messages one run decrypts and imports, however much duty is left. Core
/// stops waiting for a call at 5 s, and an import costs about 120 ms
/// ([`MESSAGE_COST_MS`]), so 12 is 1.5 s with the four scans, about a third of
/// the limit: a machine three times slower still finishes. A backlog takes
/// more runs, which the rotation and the next wake-up supply.
pub const MAX_MESSAGES_PER_RUN: usize = 12;
/// Extra duty charged for reading an inbox state, per MiB of it, on top of
/// [`SCAN_COST_MS`]. See the measurement note in the tests: copying and
/// parsing an inbox takes about 40 ms a MiB natively, and this is several
/// times that for the guest, which is slower and was not timed on a node.
pub const SCAN_MS_PER_MIB: u64 = 150;
/// What reading `bytes` of inbox state costs, beyond [`SCAN_COST_MS`].
pub fn read_cost_ms(bytes: usize) -> u64 {
    (bytes as u64).saturating_mul(SCAN_MS_PER_MIB) >> 20
}
/// A clock this far behind the last one seen has been set back, not
/// jittered: the budget starts over (core still limits the runs it starts).
pub const CLOCK_RESET_SECS: u64 = 86_400;
/// First wait before asking again for an inbox this node does not hold. It
/// doubles on each ask that finds it still missing, up to a day.
pub const MISSING_BACKOFF_FIRST_SECS: u64 = 3_600;
pub const MISSING_BACKOFF_MAX_SECS: u64 = 86_400;
/// Inboxes whose backoff is remembered.
const MAX_MISSING: usize = 256;
/// Updates one contract may be sent a minute (owner records at most once per
/// drain, renewals one per contact).
pub const MAX_WRITES_PER_MINUTE: u32 = 60;

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

/// What a trigger asks for, in order. `crate::inbox_jobs` does the inbox v2
/// jobs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Job {
    /// Subscribe to the v1 inboxes and, in a run the node starts, ask the
    /// network for any not held here. A page's run subscribes only what is held.
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
        Trigger::NodeStarted => &[
            Job::V1Refresh,
            Job::V1Scan,
            Job::DrainOwn,
            Job::AdvanceClock,
            Job::Renew,
        ],
        // A page's run stands in for every wake-up on a node without them.
        Trigger::RunJobs(_) => &[
            Job::V1Refresh,
            Job::V1Scan,
            Job::DrainOwn,
            Job::AdvanceClock,
            Job::Renew,
            Job::SendQueued,
        ],
        Trigger::Tick(Tick::V1Watch) => &[Job::V1Refresh, Job::V1Scan],
        // The clock and renewals ride on the rescan too: the clock only acts
        // when `owner_time` lags, and renewals need the runs for throughput.
        Trigger::Tick(Tick::Rescan) => &[Job::V1Scan, Job::DrainOwn, Job::AdvanceClock, Job::Renew],
        // A contact's inbox arriving is what a waiting renewal needs.
        Trigger::Contract(_) => &[Job::V1Scan, Job::DrainOwn, Job::Renew],
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
    /// An inbox of an earlier v1 generation, probed read-only during the
    /// transition window. Ranked after every other subscription.
    pub legacy: bool,
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
    /// v1 inboxes of an earlier generation (`Target::legacy`).
    V1Legacy,
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
    pub(crate) duty_ms: u64,
    duty_at: u64,
    /// Where the next run's scans start.
    pub(crate) cursor: u32,
    /// Inboxes this node did not hold when last asked for: the number of asks
    /// that found them missing, and when to ask again. The delegate is parked
    /// while a request for a missing contract is out and a page's calls wait
    /// behind it, so a missing inbox is not asked for on every refresh. Cleared
    /// by a scan that finds the inbox.
    missing: Vec<(ContractId, u32, u64)>,
    /// Updates sent this minute, per contract.
    #[serde(default)]
    writes: Vec<(ContractId, u32)>,
    /// Where the next run's inbox v2 drains start.
    #[serde(default)]
    pub(crate) cursor_v2: u32,
}

impl Budget {
    /// A full budget at `now` (seconds).
    pub fn new(now: u64) -> Self {
        Budget {
            minute: now / 60,
            ops: 0,
            duty_ms: DUTY_BURST_MS,
            duty_at: now,
            cursor: 0,
            missing: Vec::new(),
            writes: Vec::new(),
            cursor_v2: 0,
        }
    }

    /// Bring the windows up to `now`. A clock that steps back a little
    /// refills nothing and reopens nothing; one that steps back by more than
    /// [`CLOCK_RESET_SECS`] starts the budget over, so a clock that was once
    /// far ahead does not stop the runs until real time catches up.
    pub fn advance(&mut self, now: u64) {
        if now.saturating_add(CLOCK_RESET_SECS) < self.duty_at {
            *self = Budget {
                cursor: self.cursor,
                cursor_v2: self.cursor_v2,
                ..Budget::new(now)
            };
            return;
        }
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

    /// Whether this node may ask the network for `id` now.
    pub fn may_ask(&self, id: &ContractId) -> bool {
        self.missing
            .iter()
            .find(|(m, _, _)| m == id)
            .is_none_or(|(_, _, next)| self.duty_at >= *next)
    }

    /// An ask for `id` found it still missing: wait twice as long as the last
    /// time before the next.
    pub fn note_missing(&mut self, id: ContractId) {
        let at = self.missing.iter().position(|(m, _, _)| *m == id);
        let asks = at.map_or(0, |i| self.missing[i].1).saturating_add(1);
        let wait = MISSING_BACKOFF_FIRST_SECS
            .saturating_mul(1u64 << (asks - 1).min(16))
            .min(MISSING_BACKOFF_MAX_SECS);
        let entry = (id, asks, self.duty_at.saturating_add(wait));
        match at {
            Some(i) => self.missing[i] = entry,
            None if self.missing.len() < MAX_MISSING => self.missing.push(entry),
            // Full: an entry makes room, as the tombstones do.
            None => self.missing[0] = entry,
        }
    }

    /// `id` is held: forget its backoff.
    pub fn note_held(&mut self, id: &ContractId) {
        self.missing.retain(|(m, _, _)| m != id);
    }

    /// Take up to `want` operations; how many this minute still allows.
    pub fn take_ops(&mut self, want: usize) -> usize {
        let left = MAX_OPS_PER_MINUTE.saturating_sub(self.ops) as usize;
        let granted = want.min(left);
        self.ops += granted as u32;
        granted
    }

    /// Whether an update may be sent to `id` this minute.
    pub fn may_write(&self, id: &ContractId) -> bool {
        self.writes
            .iter()
            .find(|(c, _)| c == id)
            .is_none_or(|(_, n)| *n < MAX_WRITES_PER_MINUTE)
    }

    /// Count an update sent to `id`.
    pub fn take_write(&mut self, id: ContractId) {
        match self.writes.iter_mut().find(|(c, _)| *c == id) {
            Some((_, n)) => *n += 1,
            None => self.writes.push((id, 1)),
        }
    }

    /// Charge `ms` of duty, if that much is left.
    pub fn take_duty(&mut self, ms: u64) -> bool {
        if self.duty_ms < ms {
            return false;
        }
        self.duty_ms -= ms;
        true
    }

    /// The messages one run may decrypt: never past the per-run limit that
    /// keeps a call within the host's time limit, and for a run the node
    /// started, never past the duty left.
    pub fn message_slice(&self, unprompted: bool) -> usize {
        if !unprompted {
            return MAX_MESSAGES_PER_RUN;
        }
        MAX_MESSAGES_PER_RUN.min((self.duty_ms / MESSAGE_COST_MS) as usize)
    }

    /// Charge reading `bytes` of inbox state beyond the flat scan cost.
    pub fn charge_bytes(&mut self, bytes: usize) {
        self.duty_ms = self.duty_ms.saturating_sub(read_cost_ms(bytes));
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
    /// Ask the network for a scanned inbox this node does not hold. Only a run
    /// the node starts does (`crate::watch` enforces it), whatever this says.
    pub fetch_missing: bool,
    /// Messages this run may decrypt.
    pub messages: usize,
}

/// Decide a run, taking what it will use from `budget`. `v2` are the inbox
/// v2 contracts worth a subscription (own inboxes, contacts' inboxes a
/// renewal waits on), already limited to what the trigger covers.
pub fn plan(trigger: Trigger, targets: &[Target], v2: &[Candidate], budget: &mut Budget) -> Plan {
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
        // A run for one contract moves nothing. A page's run moves the
        // cursor it was given: the caller keeps one per origin, since a page
        // counts only its own origin's inboxes and must not move the shared
        // rotation.
        if !matches!(trigger, Trigger::Contract(_)) {
            budget.cursor = ((start + scan.len()) % eligible.len().max(1)) as u32;
        }
    }
    let mut subscribe = Vec::new();
    if refresh {
        let candidates: Vec<Candidate> = eligible
            .iter()
            .map(|t| Candidate {
                id: t.id,
                origin: t.origin,
                tier: if t.legacy {
                    Tier::V1Legacy
                } else {
                    Tier::V1Inbox
                },
                activity: 0,
            })
            .chain(v2.iter().copied())
            .collect();
        subscribe = rank_subscriptions(&candidates);
        // A node run asks again for an inbox it found missing only once its
        // backoff is over. A page's run subscribes only inboxes it finds
        // held (see `crate::watch`), whatever the backoff says.
        if unprompted {
            subscribe.retain(|id| budget.may_ask(id));
        }
        // A page's run sends nothing to the network, so it spends no operations.
        if unprompted {
            subscribe.truncate(budget.take_ops(subscribe.len()));
        }
    }
    Plan {
        scan,
        subscribe,
        fetch_missing: refresh,
        messages: budget.message_slice(unprompted),
    }
}
