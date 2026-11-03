//! A thin C ABI over the contract's real functions, for timing and fuel
//! counting under wasmtime. Inputs are written into memory the host gets from
//! `alloc`; a call returns its verdict or the merged state's length.

use freenet_email_inbox_v2::merge::Rules;
use freenet_email_inbox_v2::{Params, apply, is_valid};
use freenet_stdlib::prelude::UpdateData;

static mut OUT: Vec<u8> = Vec::new();

fn slice<'a>(p: u32, l: u32) -> &'a [u8] {
    // SAFETY: the host wrote `l` bytes at `p`, which `alloc` returned.
    unsafe { core::slice::from_raw_parts(p as *const u8, l as usize) }
}

/// Keeps the merged state alive past the call, as the host's copy would be.
fn keep(v: Vec<u8>) -> u32 {
    let n = v.len() as u32;
    // SAFETY: single-threaded wasm, and nothing else touches OUT.
    unsafe {
        *core::ptr::addr_of_mut!(OUT) = v;
    }
    n
}

#[unsafe(no_mangle)]
pub extern "C" fn alloc(n: u32) -> u32 {
    let mut v = Vec::<u8>::with_capacity(n as usize);
    let p = v.as_mut_ptr() as u32;
    core::mem::forget(v);
    p
}

/// `validate_state`: 1 when valid, 0 when not.
#[unsafe(no_mangle)]
pub extern "C" fn validate(pp: u32, pl: u32, sp: u32, sl: u32) -> u32 {
    let params = Params::parse(slice(pp, pl)).unwrap();
    is_valid(&Rules::V1, &params, slice(sp, sl)) as u32
}

/// `update_state` with one update. kind 0: `Delta(a)`; 1: `State(a)`; 2:
/// `StateAndDelta { state: a, delta: b }`. Returns the merged state's length,
/// or 0 when the call is refused.
#[unsafe(no_mangle)]
pub extern "C" fn update(
    pp: u32,
    pl: u32,
    sp: u32,
    sl: u32,
    kind: u32,
    ap: u32,
    al: u32,
    bp: u32,
    bl: u32,
) -> u32 {
    let params = Params::parse(slice(pp, pl)).unwrap();
    let a = slice(ap, al).to_vec();
    let data = match kind {
        0 => UpdateData::Delta(a.into()),
        1 => UpdateData::State(a.into()),
        _ => UpdateData::StateAndDelta {
            state: a.into(),
            delta: slice(bp, bl).to_vec().into(),
        },
    };
    match apply(&Rules::V1, &params, slice(sp, sl), vec![data]) {
        Ok(v) => keep(v),
        Err(_) => 0,
    }
}
