# Freenet Email – Agent Guide

## Overview

Decentralized email application built on Freenet. Uses Dioxus for the web UI,
WASM contracts for inbox storage, and Anti-Flood Tokens (AFT) for rate limiting.

## Quick Reference

### Commands

```bash
cargo make build                 # Full release build (UI + contracts)
cargo make dev                   # Local Dioxus dev server
cargo make dev-example           # Offline dev server (mock data, no node)
cargo make test                  # Run all tests
cargo make test-inbox            # Run inbox contract integration tests
cargo make clippy                # Lint
cargo make run-node              # Start local Freenet node

# Publishing pipeline (see "Publishing" section below)
cargo make publish-email-test    # Sandbox publish with committed test key
cargo make publish-email         # Production publish with uncommitted key
cargo make update-published-contract  # Refresh published-contract/ snapshot
cargo make publish-all           # End-to-end test publish (build → sign → publish)
cargo make publish               # Alias for publish-email-test
```

### Repository Structure

```
freenet-email/
├── common/                  # Shared types (freenet-email-core)
├── contracts/
│   ├── inbox/               # Email inbox contract (WASM)
│   └── web-container/       # Web container contract (WASM)
├── ui/                      # Dioxus web UI
│   └── src/
│       ├── lib.rs           # Entry point, WEB_CONTAINER_CONTRACT_ID embed
│       ├── app.rs           # Main component, inbox UI
│       ├── app/login.rs     # Identity management UI
│       ├── api.rs           # WebSocket communication with Freenet node
│       ├── aft.rs           # Anti-Flood Token management
│       ├── inbox.rs         # Inbox state & message encryption
│       ├── log.rs           # Logging abstraction
│       └── test_util.rs     # Test helpers
├── modules/                 # Vendored dependencies
│   ├── antiflood-tokens/
│   │   └── interfaces/      # freenet-aft-interface
│   └── identity-management/ # Identity delegate
├── tools/
│   └── web-container-sign/  # ed25519 signer binary (our web-container-tool)
├── test-contract/           # Committed test keys (identity + web-container)
├── published-contract/      # Committed signed-webapp snapshot
├── Cargo.toml               # Workspace root
└── Makefile.toml            # cargo-make build system
```

### Key Dependencies

| Dependency | Purpose |
|-----------|---------|
| `freenet-stdlib` | Freenet contract/delegate SDK |
| `dioxus` | Web UI framework (WASM) |
| `rsa` | RSA encryption for message security |
| `chacha20poly1305` | Symmetric encryption for message content |
| `freenet-aft-interface` | Anti-Flood Token protocol |
| `identity-management` | Identity delegate for alias management |

### Architecture

- **Inbox Contract**: Stores encrypted messages on Freenet. Uses RSA signatures
  to verify ownership. Messages are gated by AFT tokens to prevent spam.
- **Web Container**: Minimal contract that hosts the compiled Dioxus UI as a
  Freenet webapp.
- **UI**: Dioxus WASM app communicating with a local Freenet node via WebSocket.
  Handles identity creation, message composition, encryption, and inbox display.
- **AFT Integration**: Each sent message requires a token from the Anti-Flood
  Token system, preventing spam while preserving sender privacy.

### Testing

```bash
cargo test --workspace              # All tests
cargo test -p freenet-email-inbox   # Inbox contract tests only
cargo make test-ui-playwright       # Playwright E2E tests (build + serve + test)
cargo make test-ui-playwright-setup # One-time: install Playwright browsers
```

### Build Targets

- `wasm32-unknown-unknown`: Contracts (inbox, web-container) and UI
- Native: Development tools (`identity-management` key generator,
  `web-container-sign` signer)

## Publishing

Freenet-email follows `freenet-river`'s signed-and-committed publishing
pattern: every release is a pair of `(ed25519 signature, webapp bytes)`
under a contract ID that is deterministic given the committed source.

### Directory layout

```
freenet-email/
├── published-contract/          # ← committed snapshot (W4 of #6)
│   ├── contract-id.txt          # base58 ContractInstanceId
│   ├── web_container_contract.wasm
│   ├── webapp.parameters        # 32 bytes: ed25519 verifying key
│   └── README.md
├── test-contract/
│   ├── README.md                # security notes on committed test keys
│   ├── web-container-keys.toml  # committed ed25519 test keypair
│   └── identity/                # (pre-existing) P-384 delegate test key
└── tools/
    └── web-container-sign/      # the signer binary (our web-container-tool)
```

### Sandbox publish (test)

1. Start a local Freenet node in another shell:
   ```bash
   cargo make run-node
   ```
2. From a fresh checkout, run the end-to-end flow:
   ```bash
   cargo make publish-all
   ```
   This chains `build` → `update-published-contract` →
   `publish-email-test`. The committed test key at
   `test-contract/web-container-keys.toml` is used for signing, and the
   derived contract ID must match
   `published-contract/contract-id.txt` — if it doesn't, the
   committed snapshot has drifted and you should commit the diff.

3. To refresh the committed snapshot without publishing:
   ```bash
   cargo make update-published-contract
   git add published-contract/ && git commit -m "chore: refresh published-contract snapshot"
   ```

### Production publish

Production uses an **uncommitted** ed25519 keypair at
`~/.config/freenet-email/web-container-keys.toml` (override with
`WEB_CONTAINER_KEY_FILE=/path/to/keys.toml`). Generate it out of band
on the release manager's machine:

```bash
mkdir -p ~/.config/freenet-email
cargo run -p web-container-sign -- generate \
  --output ~/.config/freenet-email/web-container-keys.toml
```

**Never commit this file.** Back it up offline; losing it means
rotating the production contract ID.

Then:

```bash
cargo make build
cargo make publish-email
```

The production key produces a **different** contract ID than the test
key, because the ID is `hash(wasm, parameters)` and the 32-byte
`webapp.parameters` blob is the verifying key itself. Keep production
`published-contract/` snapshots on a separate branch or tag if you
need them reproducible.

### Reproducibility caveats

Two developers building from the same commit will produce the
**same** `published-contract/contract-id.txt` only when all of these
match:

- **rustc version.** The release-profile WASM is not bit-for-bit
  stable across rustc versions. Pin via `rust-toolchain.toml` if this
  matters in your CI.
- **Cargo release profile.** Already pinned in the workspace
  `Cargo.toml` (`lto=true, codegen-units=1, strip=true, panic=abort`).
- **GNU tar.** `compress-webapp` uses
  `tar --sort=name --mtime='2024-01-01 00:00:00 UTC' --owner=0 --group=0`
  for a reproducible archive. BSD tar (macOS default) **does not**
  support these flags. Install `gnu-tar`:
  ```bash
  brew install gnu-tar   # provides `gtar`
  ```
  Without GNU tar the pipeline still works — the archive signs and
  publishes correctly — but the resulting contract ID will not match
  across machines and cannot be committed to
  `published-contract/contract-id.txt` as a source of truth.

The `cargo make compress-webapp` target detects `gtar` / GNU `tar`
automatically and emits a loud warning when falling back to BSD tar.

### Security — committed test key

The ed25519 keypair at `test-contract/web-container-keys.toml` is
**committed on purpose** so the test contract ID is reproducible
across clones. Anyone with read access to this repository can sign
webapps under the test contract ID, but the key grants no access to
any user data and must never be reused for production. See
`test-contract/README.md` for the full threat model.

## End-to-end testing

### Automated (Playwright)

The Playwright suite at `ui/tests/` tests the UI in offline mode
(`--features example-data,no-sync`) across 5 browser/viewport
profiles: Desktop Chrome, Firefox, Safari, Pixel 5, iPhone 13.

One-time setup:

```bash
cargo make test-ui-playwright-setup
```

Run the full suite (builds UI, starts dev server, runs tests, tears down):

```bash
cargo make test-ui-playwright
```

Or manually:

```bash
# Terminal 1: start the dev server
cd ui && dx serve --port 8082 --features example-data,no-sync --no-default-features

# Terminal 2: run tests
cd ui/tests && npx playwright test
```

The `example-data` feature seeds two identities (`address1`,
`address2`) with mock inboxes and supports in-memory message delivery
between them — no Freenet node required. The Playwright tests
exercise multi-turn cross-inbox messaging (compose → send → switch
identity → verify delivery → reply).

### Manual E2E checklist (against a local node)

This checklist validates the pieces that unit tests and Playwright
can't cover: real WebSocket framing, real AFT token mint/burn, real
RSA encrypt/decrypt round trip through the inbox contract state.

1. `cargo make run-node` in one terminal
2. `cargo make publish-email-test` in another
3. Open the published webapp URL in the browser
4. Create identity A and identity B
5. A sends a message to B (burns an AFT token)
6. B receives, decrypts, and reads the message
7. Token accounting check: A's remaining tokens decremented
