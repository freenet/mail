//! The delegate's view of its host: secret storage and randomness.
//!
//! Handlers are written against [`Env`] rather than `DelegateCtx`, because
//! the host functions are no-ops off-wasm; an in-memory [`mem::MemEnv`] gives
//! the tests a real store.

use freenet_stdlib::prelude::DelegateCtx;

pub trait Env {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
    fn set(&mut self, key: &[u8], value: &[u8]) -> bool;
    fn remove(&mut self, key: &[u8]) -> bool;
    /// Keys under `prefix`. The host caps enumeration for the whole delegate
    /// (see [`crate::store::HOST_ENUMERATION_CAP`]), not per prefix.
    fn list(&self, prefix: &[u8]) -> Vec<Vec<u8>>;
    /// 32 bytes from the host RNG. Not trusted alone: on a host failure the
    /// buffer may hold stale bytes, so every use mixes in caller entropy or
    /// a counter.
    fn host_random(&mut self) -> [u8; 32];
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
    fn list(&self, prefix: &[u8]) -> Vec<Vec<u8>> {
        self.list_secrets(prefix)
    }
    fn host_random(&mut self) -> [u8; 32] {
        let bytes = freenet_stdlib::rand::rand_bytes(32);
        let mut out = [0u8; 32];
        let n = bytes.len().min(32);
        out[..n].copy_from_slice(&bytes[..n]);
        out
    }
}

/// Adapter giving freenet-migrate read access to the store.
pub struct MigrateView<'a, E: Env + ?Sized>(pub &'a E);

impl<E: Env + ?Sized> freenet_migrate::SecretStore for MigrateView<'_, E> {
    fn list_secrets(&self, prefix: &[u8]) -> Vec<Vec<u8>> {
        self.0.list(prefix)
    }
    fn get_secret(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.0.get(key)
    }
    fn has_secret(&self, key: &[u8]) -> bool {
        self.0.get(key).is_some()
    }
    /// The export path only reads.
    fn set_secret(&mut self, _key: &[u8], _value: &[u8]) -> bool {
        false
    }
}

#[cfg(test)]
pub mod mem {
    use std::collections::BTreeMap;

    use super::Env;

    /// In-memory store for tests. Randomness is a counter, so runs repeat.
    #[derive(Default, Clone, PartialEq, Eq, Debug)]
    pub struct MemEnv {
        pub secrets: BTreeMap<Vec<u8>, Vec<u8>>,
        pub rng_counter: u64,
        /// When set, every write fails (a host refusing a write).
        pub fail_writes: bool,
    }

    impl Env for MemEnv {
        fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.secrets.get(key).cloned()
        }
        fn set(&mut self, key: &[u8], value: &[u8]) -> bool {
            if self.fail_writes {
                return false;
            }
            self.secrets.insert(key.to_vec(), value.to_vec());
            true
        }
        fn remove(&mut self, key: &[u8]) -> bool {
            self.secrets.remove(key).is_some()
        }
        fn list(&self, prefix: &[u8]) -> Vec<Vec<u8>> {
            self.secrets
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect()
        }
        fn host_random(&mut self) -> [u8; 32] {
            self.rng_counter += 1;
            *blake3::hash(&self.rng_counter.to_le_bytes()).as_bytes()
        }
    }
}
