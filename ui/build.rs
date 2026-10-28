//! Build-time checks and codegen for the UI crate.
//!
//! 1. **Legacy registries.** `legacy_inbox.toml`, `legacy_identity_delegate.toml`
//!    and `legacy_local_state_delegate.toml` at the repo root list every
//!    previous contract/delegate generation. `freenet-migrate-build` validates
//!    each row (hash encodings, `delegate_key == blake3(code_hash ‖ params)`)
//!    and emits byte-array consts into `$OUT_DIR`, included by
//!    `src/legacy_registry.rs`. A missing or empty registry fails the build:
//!    an empty list would silently disable migration from every older
//!    generation.
//! 2. **Frozen artifacts.** The contract/delegate WASM the UI embeds via
//!    `include_bytes!` / `include_str!` is committed under
//!    `published-contract/wasm/v1/` (the exact bytes that shipped). Builds
//!    never regenerate them; a missing file means a broken checkout, not a
//!    missing build step.

use std::path::{Path, PathBuf};

use freenet_migrate_build::Registry;

fn main() {
    // Re-run if features change.
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_USE_NODE");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_NO_SYNC");

    let ui_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = ui_dir.parent().expect("workspace root").to_path_buf();

    emit_legacy_registries(&root);

    // The artifact checks below only matter for builds that actually embed
    // contract WASM via `include_bytes!` (i.e. `use-node` is on and `no-sync`
    // is off). Offline builds — `--no-default-features --features
    // example-data,no-sync` — don't reference the artifacts.
    let use_node = std::env::var_os("CARGO_FEATURE_USE_NODE").is_some();
    let no_sync = std::env::var_os("CARGO_FEATURE_NO_SYNC").is_some();
    if !use_node || no_sync {
        return;
    }

    // Optional artifact — present once the container contract was published.
    // Missing is fine; we emit an empty id. Listing it here makes cargo
    // rebuild when the file appears/changes.
    let container_id_path = root.join("published-contract/facade-id.txt");
    println!("cargo:rerun-if-changed={}", container_id_path.display());
    let container_id = std::fs::read_to_string(&container_id_path)
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    println!("cargo:rustc-env=FREENET_EMAIL_FACADE_ID={container_id}");

    let frozen = "published-contract/wasm/v1";
    let required: &[(&str, &str)] = &[
        ("freenet_email_inbox", "inbox contract WASM"),
        ("inbox_code_hash", "inbox contract code hash"),
        (
            "freenet_token_allocation_record",
            "token-allocation-record contract WASM",
        ),
        (
            "token_allocation_record_code_hash",
            "token-allocation-record code hash",
        ),
        ("freenet_token_generator", "token-generator delegate WASM"),
        ("token_generator_code_hash", "token-generator code hash"),
        ("identity_management", "identity-management delegate WASM"),
        (
            "identity_management_code_hash",
            "identity-management code hash",
        ),
        ("identity-manager-params", "identity-management parameters"),
        ("mail_local_state", "mail-local-state delegate WASM"),
        ("mail_local_state_code_hash", "mail-local-state code hash"),
        ("mail-local-state-params", "mail-local-state parameters"),
    ];

    let mut missing: Vec<(String, &str)> = Vec::new();
    for (name, desc) in required {
        let rel = format!("{frozen}/{name}");
        let full = root.join(&rel);
        println!("cargo:rerun-if-changed={}", full.display());
        if !is_present(&full) {
            missing.push((rel, desc));
        }
    }
    let contract_id = "published-contract/contract-id.txt";
    println!(
        "cargo:rerun-if-changed={}",
        root.join(contract_id).display()
    );
    if !is_present(&root.join(contract_id)) {
        missing.push((contract_id.to_string(), "committed webapp contract id"));
    }

    if !missing.is_empty() {
        eprintln!();
        eprintln!("error: freenet-email-ui cannot be built because these committed");
        eprintln!("       artifacts are missing or empty:");
        eprintln!();
        for (path, desc) in &missing {
            eprintln!("  - {desc}: {path}");
        }
        eprintln!();
        eprintln!("They are frozen release artifacts tracked in git, not build outputs.");
        eprintln!("Restore them with `git checkout -- published-contract/`.");
        eprintln!();
        std::process::exit(1);
    }
}

/// Validate each legacy registry, refuse an empty one, and emit its consts.
fn emit_legacy_registries(root: &Path) {
    let inbox = root.join("legacy_inbox.toml");
    let identity = root.join("legacy_identity_delegate.toml");
    let local_state = root.join("legacy_local_state_delegate.toml");

    for path in [&inbox, &identity, &local_state] {
        println!("cargo:rerun-if-changed={}", path.display());
        let registry = Registry::from_path(path)
            .unwrap_or_else(|e| panic!("legacy registry {}: {e}", path.display()));
        if registry.contract.is_empty() && registry.delegate.is_empty() {
            panic!(
                "legacy registry {} is empty: an empty list would silently disable \
                 migration from every older generation",
                path.display()
            );
        }
    }

    freenet_migrate_build::codegen()
        .registry(&inbox)
        .canonical_consts(false)
        .contract_hash_view("LEGACY_INBOX_CODE_HASHES")
        .out_file("legacy_inbox.rs")
        .emit()
        .expect("freenet-migrate-build: legacy inbox registry");
    freenet_migrate_build::codegen()
        .registry(&identity)
        .canonical_consts(false)
        .delegate_pair_view("LEGACY_IDENTITY_DELEGATES")
        .out_file("legacy_identity_delegate.rs")
        .emit()
        .expect("freenet-migrate-build: legacy identity delegate registry");
    freenet_migrate_build::codegen()
        .registry(&local_state)
        .canonical_consts(false)
        .delegate_pair_view("LEGACY_LOCAL_STATE_DELEGATES")
        .out_file("legacy_local_state_delegate.rs")
        .emit()
        .expect("freenet-migrate-build: legacy local-state delegate registry");
}

fn is_present(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(md) => md.is_file() && md.len() > 0,
        Err(_) => false,
    }
}
