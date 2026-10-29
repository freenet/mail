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
    use std::collections::BTreeMap;

    use super::Env;

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
    }

    impl MemEnv {
        fn fails(&self, key: &[u8]) -> bool {
            self.fail_keys_containing
                .as_ref()
                .is_some_and(|t| String::from_utf8_lossy(key).contains(t.as_str()))
        }
    }

    impl Env for MemEnv {
        fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.secrets.get(key).cloned()
        }
        fn set(&mut self, key: &[u8], value: &[u8]) -> bool {
            if self.fail_writes || self.fails(key) {
                return false;
            }
            self.secrets.insert(key.to_vec(), value.to_vec());
            true
        }
        fn remove(&mut self, key: &[u8]) -> bool {
            !self.fails(key) && self.secrets.remove(key).is_some()
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
