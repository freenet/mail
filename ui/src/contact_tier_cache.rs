//! Recipient AFT policy cache (#221).
//!
//! Contact cards encode the recipient's AFT tier at share time, but
//! `InboxSettings.minimum_tier` is mutable post-#85. When the recipient
//! re-tunes their tier, senders trusting the stale card mint at the old
//! tier and the inbox contract rejects with `PolicyTierMismatch`.
//!
//! This cache mirrors the latest `InboxSettings { minimum_tier,
//! max_age_secs }` we have observed for each contact's inbox key, fed
//! by GetResponse + UpdateNotification on the contact's contract (the
//! rehydrate-prime path subscribes to these). Senders consult it before
//! minting; on miss the contact-card value is used as a v1 fallback.
//!
//! Cache is in-memory only: a reload re-primes via `set_aliases` →
//! Get-with-subscribe for every contact.
use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};

use chrono::{DateTime, Utc};
use freenet_aft_interface::Tier;
use freenet_email_inbox::InboxSettings;
use freenet_stdlib::prelude::ContractKey;

/// Minimum policy fields the sender needs from the recipient's live
/// `InboxSettings`. Skips `verified_senders` / `allow_verified_skip_token`
/// — those affect the bypass path which goes through the contract's own
/// state read, not the sender.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecipientPolicy {
    pub minimum_tier: Tier,
    pub max_age_secs: u64,
}

/// Internal cache entry: `RecipientPolicy` plus the `last_update`
/// stamp from the source `Inbox` state. Used to gate stale records
/// (`record_with_last_update` ignores incoming snapshots whose
/// `last_update` is older than what we already have, mirroring the
/// contract-level last-write-wins in `Inbox::merge`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CacheEntry {
    policy: RecipientPolicy,
    last_update: DateTime<Utc>,
}

static CACHE: LazyLock<RwLock<HashMap<ContractKey, CacheEntry>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Update the cached policy for `key` from a freshly received
/// `InboxSettings` and the source state's `last_update`. Called from
/// GetResponse + UpdateNotification(State) + ModifySettings-delta
/// handlers in `api.rs`. Stale snapshots (older `last_update` than
/// the one we already have for this key) are silently ignored — the
/// gateway can serve a cached older state right after we observed a
/// newer one (cross-node propagation race), and we don't want to
/// regress the cache.
pub fn record_with_last_update(
    key: ContractKey,
    settings: &InboxSettings,
    last_update: DateTime<Utc>,
) {
    let entry = CacheEntry {
        policy: RecipientPolicy {
            minimum_tier: settings.minimum_tier,
            max_age_secs: settings.max_age_secs,
        },
        last_update,
    };
    let mut guard = CACHE.write().expect("contact tier cache poisoned");
    let existing = guard.get(&key).copied();
    match existing {
        Some(prev) if prev.last_update > entry.last_update => {
            // Stale; ignore.
            return;
        }
        _ => {}
    }
    let prev_policy = existing.map(|e| e.policy);
    guard.insert(key, entry);
    if prev_policy != Some(entry.policy) {
        crate::log::info(format!(
            "contact tier cache: recorded {key} tier={:?} max_age_secs={} (#221)",
            entry.policy.minimum_tier, entry.policy.max_age_secs
        ));
    }
}

/// Convenience: record without a `last_update` (uses the current
/// epoch — caller doesn't know the source's stamp). Used by the
/// `ModifySettings`-delta arm where the delta carries the new
/// settings but not the inbox's whole state. Treats the local
/// observation as the freshest by stamping `Utc::now()`.
pub fn record(key: ContractKey, settings: &InboxSettings) {
    record_with_last_update(key, settings, Utc::now());
}

/// Look up the cached policy for `key`. Returns `None` on cache miss
/// (no GetResponse yet) — callers fall back to the contact card.
pub fn lookup(key: &ContractKey) -> Option<RecipientPolicy> {
    CACHE
        .read()
        .expect("contact tier cache poisoned")
        .get(key)
        .map(|e| e.policy)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use freenet_aft_interface::Tier;
    use freenet_email_inbox::{DEFAULT_MAX_AGE_SECS, InboxSettings};
    use freenet_stdlib::prelude::{CodeHash, ContractInstanceId, ContractKey};

    use super::*;

    fn dummy_key(seed: u8) -> ContractKey {
        // Deterministic ContractKey for tests: fixed instance-id + code-
        // hash yield a stable key without touching the network. Cache
        // keys on the full ContractKey so this is sufficient.
        let instance_id = ContractInstanceId::new([seed; 32]);
        let code_hash = CodeHash::new([seed.wrapping_add(1); 32]);
        ContractKey::from_id_and_code(instance_id, code_hash)
    }

    fn settings_with(tier: Tier, max_age: u64) -> InboxSettings {
        InboxSettings {
            minimum_tier: tier,
            max_age_secs: max_age,
            allow_verified_skip_token: false,
            verified_senders: BTreeSet::new(),
            private: Vec::new(),
        }
    }

    // NOTE: these tests share a process-global `CACHE` (LazyLock). Each
    // test uses a unique `dummy_key(seed)` so entries from parallel
    // runs don't collide. We avoid `clear()` because cargo test runs
    // tests in parallel by default and a clear from one test races a
    // record from another (CI flake on the original `clear()` pattern).

    #[test]
    fn record_then_lookup_round_trips() {
        let key = dummy_key(1);
        record(key, &settings_with(Tier::Min1, 60));
        let got = lookup(&key).expect("cache hit");
        assert_eq!(got.minimum_tier, Tier::Min1);
        assert_eq!(got.max_age_secs, 60);
    }

    #[test]
    fn record_overwrites_on_modify_settings() {
        let key = dummy_key(2);
        record(key, &settings_with(Tier::Min10, DEFAULT_MAX_AGE_SECS));
        record(key, &settings_with(Tier::Min1, 30));
        let got = lookup(&key).expect("cache hit");
        assert_eq!(got.minimum_tier, Tier::Min1);
        assert_eq!(got.max_age_secs, 30);
    }

    #[test]
    fn lookup_miss_returns_none() {
        // seed 3 only used here — entries from other tests use 1, 2.
        assert!(lookup(&dummy_key(3)).is_none());
    }
}
