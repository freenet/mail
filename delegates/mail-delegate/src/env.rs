//! The delegate's view of its host: secret storage, randomness, time, and
//! read access to contract state this node holds.
//!
//! There is deliberately no listing. The host's key enumeration is capped
//! for the whole delegate (not per prefix), has no paging, and returns an
//! empty list on error, so nothing here may depend on it: the delegate keeps
//! its own index records (see [`crate::store`]).
//!
//! Handlers are written against [`Env`] rather than `DelegateCtx` because
//! the host functions are no-ops off-wasm; [`mem::MemEnv`] gives the tests a
//! real store.

use freenet_stdlib::prelude::DelegateCtx;

pub trait Env {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
    fn set(&mut self, key: &[u8], value: &[u8]) -> bool;
    fn remove(&mut self, key: &[u8]) -> bool;
    /// 32 bytes from the host RNG. Not trusted alone: on a host failure the
    /// buffer may hold stale bytes, so every use mixes in caller entropy.
    fn host_random(&mut self) -> [u8; 32];
    /// Seconds since the Unix epoch, when the host provides a clock.
    fn now_secs(&self) -> Option<u64>;
    /// The state of a contract this node holds locally (never a network
    /// fetch). `None` means "not held here", not "does not exist".
    fn contract_state(&self, instance_id: &[u8; 32]) -> Option<Vec<u8>>;
}

impl Env for DelegateCtx {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.get_secret(key)
    }
    fn set(&mut self, key: &[u8], value: &[u8]) -> bool {
        self.set_secret(key, value)
    }
    fn remove(&mut self, key: &[u8]) -> bool {
        self.remove_secret(key)
    }
    fn host_random(&mut self) -> [u8; 32] {
        let bytes = freenet_stdlib::rand::rand_bytes(32);
        let mut out = [0u8; 32];
        let n = bytes.len().min(32);
        out[..n].copy_from_slice(&bytes[..n]);
        out
    }
    fn now_secs(&self) -> Option<u64> {
        // Off-wasm the stdlib stub leaves the value uninitialised.
        #[cfg(target_family = "wasm")]
        {
            u64::try_from(freenet_stdlib::time::now().timestamp()).ok()
        }
        #[cfg(not(target_family = "wasm"))]
        {
            None
        }
    }
    fn contract_state(&self, instance_id: &[u8; 32]) -> Option<Vec<u8>> {
        self.get_contract_state(instance_id)
    }
}

#[cfg(test)]
pub mod mem {
    use std::cell::{Cell, RefCell};
    use std::collections::BTreeMap;

    use super::Env;

    /// A host call that a fault can hit.
    #[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
    pub enum FaultOp {
        /// `get` returns `None` for a key that is present.
        GetMiss,
        /// `set` is refused.
        SetFail,
        /// `remove` is refused (the key stays).
        RemoveFail,
        /// From the `nth` `get` of a matching key on, every read misses (a
        /// key that reads fine and then stops: a file the host can no
        /// longer read or decrypt). Not masked by an immediate re-read.
        GetBlindFrom,
    }

    /// Fail the `nth` (1-based) host call of `op` on a key containing
    /// `key_contains`.
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct Rule {
        pub op: FaultOp,
        pub key_contains: String,
        pub nth: u32,
    }

    /// Seeded, deterministic host faults.
    ///
    /// The host model the delegate defends against: any call may fail, and
    /// a failed read looks exactly like an absent key. Most read failures
    /// are transient (an immediate re-read succeeds), but freenet-core also
    /// reports a file it cannot read or decrypt as "not found", on every
    /// read: a *persistent* miss. The delegate must stay safe (never
    /// overwrite, unlist or reuse anything) while any one present key is
    /// persistently unreadable; it cannot be expected to serve that key.
    #[derive(Default, Clone, PartialEq, Eq, Debug)]
    pub struct Faults {
        rng: Cell<u64>,
        /// Chance per read of a present key, in thousandths, that the key
        /// becomes persistently unreadable (one key at a time).
        pub blind_rate: u32,
        /// Keys (exact full keys) that always read as absent.
        pub blind_keys: Vec<String>,
        blinded: RefCell<Option<Vec<u8>>>,
        /// Misses the code under test could see: every persistent miss
        /// (a transient one is hidden by an immediate re-read).
        pub observed: Cell<u64>,
        /// Chance per call, in thousandths.
        pub get_miss: u32,
        pub set_fail: u32,
        pub remove_fail: u32,
        pub rules: Vec<Rule>,
        counts: RefCell<BTreeMap<(FaultOp, String), u32>>,
        last_miss: RefCell<Option<Vec<u8>>>,
        /// How many faults were injected.
        pub injected: Cell<u64>,
    }

    impl Faults {
        pub fn seeded(seed: u64, per_mille: u32) -> Self {
            Faults {
                rng: Cell::new(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1),
                get_miss: per_mille,
                set_fail: per_mille,
                remove_fail: per_mille,
                ..Faults::default()
            }
        }

        /// Seeded faults, plus one present key at a time going
        /// persistently unreadable at `blind_per_mille` per read.
        pub fn seeded_with_blindness(seed: u64, per_mille: u32, blind_per_mille: u32) -> Self {
            Faults {
                blind_rate: blind_per_mille,
                ..Faults::seeded(seed, per_mille)
            }
        }

        /// Reads of the full key `key` always fail.
        pub fn blind(key: &str) -> Self {
            Faults {
                blind_keys: vec![key.into()],
                ..Faults::default()
            }
        }

        /// The key that went persistently unreadable, if any.
        pub fn blinded(&self) -> Option<Vec<u8>> {
            self.blinded.borrow().clone()
        }

        pub fn rule(op: FaultOp, key_contains: &str, nth: u32) -> Self {
            Faults {
                rules: vec![Rule {
                    op,
                    key_contains: key_contains.into(),
                    nth,
                }],
                ..Faults::default()
            }
        }

        fn roll(&self, per_mille: u32) -> bool {
            if per_mille == 0 {
                return false;
            }
            // xorshift64
            let mut x = self.rng.get();
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.rng.set(x);
            (x % 1000) < u64::from(per_mille)
        }

        fn hit(&self, op: FaultOp, key: &[u8]) -> bool {
            let text = String::from_utf8_lossy(key);
            let mut targeted = false;
            for r in self.rules.iter().filter(|r| r.op == op) {
                if text.contains(r.key_contains.as_str()) {
                    let mut counts = self.counts.borrow_mut();
                    let n = counts.entry((op, r.key_contains.clone())).or_default();
                    *n += 1;
                    targeted |= *n == r.nth;
                }
            }
            let chance = match op {
                FaultOp::GetMiss => self.get_miss,
                FaultOp::SetFail => self.set_fail,
                FaultOp::RemoveFail => self.remove_fail,
                FaultOp::GetBlindFrom => 0,
            };
            let hit = targeted || self.roll(chance);
            if hit {
                self.injected.set(self.injected.get() + 1);
            }
            hit
        }

        /// Whether a `GetBlindFrom` rule has made `key` unreadable by now
        /// (counting this read).
        fn blinded_from(&self, key: &[u8]) -> bool {
            let text = String::from_utf8_lossy(key);
            let mut blind = false;
            for r in self.rules.iter().filter(|r| r.op == FaultOp::GetBlindFrom) {
                if text.contains(r.key_contains.as_str()) {
                    let mut counts = self.counts.borrow_mut();
                    let n = counts
                        .entry((FaultOp::GetBlindFrom, r.key_contains.clone()))
                        .or_default();
                    *n += 1;
                    blind |= *n >= r.nth;
                }
            }
            blind
        }

        fn miss(&self, key: &[u8], present: bool) -> bool {
            if present && self.blinded_from(key) {
                self.observed.set(self.observed.get() + 1);
                return true;
            }
            let text = String::from_utf8_lossy(key);
            let persistent = self.blind_keys.iter().any(|b| text == b.as_str())
                || self.blinded.borrow().as_deref() == Some(key);
            if persistent && present {
                self.observed.set(self.observed.get() + 1);
                return true;
            }
            if present && self.blinded.borrow().is_none() && self.roll(self.blind_rate) {
                *self.blinded.borrow_mut() = Some(key.to_vec());
                self.injected.set(self.injected.get() + 1);
                self.observed.set(self.observed.get() + 1);
                return true;
            }
            let mut last = self.last_miss.borrow_mut();
            if last.as_deref() == Some(key) {
                // The immediate re-read of a key that just missed succeeds.
                *last = None;
                return false;
            }
            let miss = self.hit(FaultOp::GetMiss, key);
            *last = miss.then(|| key.to_vec());
            miss
        }
    }

    /// In-memory host for tests. Randomness is a counter, so runs repeat.
    #[derive(Default, Clone, PartialEq, Eq, Debug)]
    pub struct MemEnv {
        pub secrets: BTreeMap<Vec<u8>, Vec<u8>>,
        pub rng_counter: u64,
        /// When set, every write fails (a host refusing a write).
        pub fail_writes: bool,
        /// When set, writes and removals of keys containing this text fail.
        pub fail_keys_containing: Option<String>,
        pub now: Option<u64>,
        pub contracts: BTreeMap<[u8; 32], Vec<u8>>,
        /// Injected host faults (`None` = a perfect host).
        pub faults: Option<Faults>,
    }

    impl MemEnv {
        fn fails(&self, key: &[u8]) -> bool {
            self.fail_keys_containing
                .as_ref()
                .is_some_and(|t| String::from_utf8_lossy(key).contains(t.as_str()))
        }

        fn fault(&self, op: FaultOp, key: &[u8]) -> bool {
            self.faults.as_ref().is_some_and(|f| match op {
                FaultOp::GetMiss => f.miss(key, self.secrets.contains_key(key)),
                _ => f.hit(op, key),
            })
        }
    }

    impl Env for MemEnv {
        fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
            if self.fault(FaultOp::GetMiss, key) {
                return None;
            }
            self.secrets.get(key).cloned()
        }
        fn set(&mut self, key: &[u8], value: &[u8]) -> bool {
            if self.fail_writes || self.fails(key) || self.fault(FaultOp::SetFail, key) {
                return false;
            }
            self.secrets.insert(key.to_vec(), value.to_vec());
            true
        }
        fn remove(&mut self, key: &[u8]) -> bool {
            if self.fails(key) || self.fault(FaultOp::RemoveFail, key) {
                return false;
            }
            self.secrets.remove(key).is_some()
        }
        fn host_random(&mut self) -> [u8; 32] {
            self.rng_counter += 1;
            *blake3::hash(&self.rng_counter.to_le_bytes()).as_bytes()
        }
        fn now_secs(&self) -> Option<u64> {
            self.now
        }
        fn contract_state(&self, instance_id: &[u8; 32]) -> Option<Vec<u8>> {
            self.contracts.get(instance_id).cloned()
        }
    }
}
