//! Randomness from the platform CSPRNG: `crypto.getRandomValues` in the
//! browser (getrandom's `wasm_js` backend), the OS generator natively.

use getrandom::{SysRng, rand_core::UnwrapErr};

/// `N` random bytes. Panics if the platform generator is unavailable, as
/// rand's `thread_rng` did: nothing here can proceed without one.
pub(crate) fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).expect("platform random number generator unavailable");
    bytes
}

/// The platform generator as a `rand_core` crypto RNG, for APIs that take
/// one (ML-KEM encapsulation).
pub(crate) fn crypto_rng() -> UnwrapErr<SysRng> {
    UnwrapErr(SysRng)
}
