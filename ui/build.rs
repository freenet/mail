//! Fail-fast check for WASM artifacts embedded via `include_bytes!` /
//! `include_str!` in `src/aft.rs` and `src/api.rs`.
//!
//! These files are produced by `fdev build` + `fdev inspect` on the
//! contract/delegate crates and the `identity-management` tool. Running
//! `cargo build -p freenet-email-ui` without first producing them yields a
//! cryptic "couldn't read" error from rustc pointing at the `include_*!`
//! invocation. This build script catches the missing files early and emits
//! a clearer message pointing the developer at the right cargo-make target.

use std::path::{Path, PathBuf};

fn main() {
    // Re-run if features change.
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_USE_NODE");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_NO_SYNC");

    // The artifact checks below only matter for builds that actually embed
    // contract WASM via `include_bytes!` (i.e. `use-node` is on and `no-sync`
    // is off). Offline builds — `--no-default-features --features
    // example-data,no-sync` — must work on a clean clone with no `build/`
    // directories present, so we skip the check entirely there.
    let use_node = std::env::var_os("CARGO_FEATURE_USE_NODE").is_some();
    let no_sync = std::env::var_os("CARGO_FEATURE_NO_SYNC").is_some();
    if !use_node || no_sync {
        return;
    }

    let ui_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = ui_dir.parent().expect("workspace root");

    // (path relative to workspace root, human-readable description,
    //  suggested cargo-make target to produce it)
    let required: &[(&str, &str, &str)] = &[
        (
            "contracts/inbox/build/freenet/freenet_email_inbox",
            "inbox contract WASM",
            "cargo make build-inbox-contract",
        ),
        (
            "modules/antiflood-tokens/contracts/token-allocation-record/build/freenet/freenet_token_allocation_record",
            "token-allocation-record contract WASM",
            "cargo make build-token-allocation-record",
        ),
        (
            "modules/antiflood-tokens/contracts/token-allocation-record/build/token_allocation_record_code_hash",
            "token-allocation-record code hash",
            "cargo make build-token-allocation-record",
        ),
        (
            "modules/antiflood-tokens/delegates/token-generator/build/freenet/freenet_token_generator",
            "token-generator delegate WASM",
            "cargo make build-token-generator",
        ),
        (
            "modules/antiflood-tokens/delegates/token-generator/build/token_generator_code_hash",
            "token-generator code hash",
            "cargo make build-token-generator",
        ),
        (
            "modules/identity-management/build/freenet/identity_management",
            "identity-management delegate WASM",
            "cargo make build-identity-management-delegate",
        ),
        (
            "modules/identity-management/build/identity_management_code_hash",
            "identity-management code hash",
            "cargo make build-identity-management-delegate",
        ),
        (
            "modules/identity-management/build/identity-manager-params",
            "identity-manager parameters (serialized)",
            "cargo make generate-identity-params",
        ),
    ];

    let mut missing: Vec<(&str, &str, &str)> = Vec::new();
    for entry in required {
        let full: PathBuf = root.join(entry.0);
        println!("cargo:rerun-if-changed={}", full.display());
        if !is_present(&full) {
            missing.push(*entry);
        }
    }

    if !missing.is_empty() {
        eprintln!();
        eprintln!("error: freenet-email-ui cannot be built because the following");
        eprintln!("       contract/delegate artifacts are missing or empty:");
        eprintln!();
        for (path, desc, how) in &missing {
            eprintln!("  - {desc}");
            eprintln!("      file: {path}");
            eprintln!("      produce with: {how}");
            eprintln!();
        }
        eprintln!("Run `cargo make build-contracts` to produce all of them in one step,");
        eprintln!("then re-run the UI build.");
        eprintln!();
        std::process::exit(1);
    }
}

fn is_present(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(md) => md.is_file() && md.len() > 0,
        Err(_) => false,
    }
}
