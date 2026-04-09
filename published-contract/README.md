# `published-contract/`

This directory contains a **committed snapshot** of the artifacts that
the `cargo make publish-email-test` flow uploads to Freenet, together
with the contract ID those artifacts derive. Committing the snapshot
guarantees that:

1. Two developers building from the same commit agree on which
   contract ID the UI should target.
2. The UI can `include_str!` the contract ID at compile time
   (see `ui/src/lib.rs`'s `WEB_CONTAINER_CONTRACT_ID` constant)
   without a runtime config file or network lookup.
3. Bit-rot is visible in a `git diff`: if `update-published-contract`
   produces a new ID after a contract-code change, the diff lands in
   this directory rather than being silently forgotten.

## Contents

| File                          | What it is                                                           |
| ----------------------------- | -------------------------------------------------------------------- |
| `contract-id.txt`             | Base58-encoded `ContractInstanceId` of the signed webapp contract    |
| `web_container_contract.wasm` | The release build of `freenet-email-app-web`                         |
| `webapp.parameters`           | 32 raw bytes: the ed25519 verifying key from `test-contract/web-container-keys.toml` |

## Regenerating

```bash
cargo make update-published-contract
git add published-contract/
git commit -m "chore: refresh published-contract snapshot"
```

This target chains:

  `build-ui` →  `compress-webapp`  →  `sign-webapp-test`  →
  `build-web-container`  →  `fdev get-contract-id`  →  copy into this
  directory.

## Reproducibility across machines

A few things must match between two machines for `update-published-contract`
to produce a byte-identical `contract-id.txt`:

- **Same rustc version.** The release-profile WASM output is not bit-for-bit
  stable across rustc versions. Use the same toolchain (pin via
  `rust-toolchain.toml` if this matters in CI).
- **Same cargo profile settings.** Already pinned in the workspace
  `Cargo.toml` release profile (`lto=true`, `codegen-units=1`, `strip=true`).
- **GNU tar.** `compress-webapp` uses `tar --sort=name --mtime=... --owner=0`
  to produce a reproducible archive. macOS ships BSD tar which lacks these
  flags; install `gnu-tar` (`brew install gnu-tar`, aliased as `gtar`) for
  byte-identical archives. Without it, the archive differs per-machine
  but still signs and publishes correctly — you just can't commit the
  resulting snapshot as a cross-machine source of truth.

See `AGENTS.md` §Publishing for the full bootstrap and release flow.

## Security

These artifacts are signed with the **committed test keypair** at
`test-contract/web-container-keys.toml`. That key is public (it lives
in the repo) so this `contract-id.txt` should be treated as a
**sandbox** ID only — good enough for local E2E testing, **not** a
production release. Production publishes (`cargo make publish-email`)
use an uncommitted key and produce a different contract ID.
