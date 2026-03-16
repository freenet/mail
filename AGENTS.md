# Freenet Email – Agent Guide

## Overview

Decentralized email application built on Freenet. Uses Dioxus for the web UI,
WASM contracts for inbox storage, and Anti-Flood Tokens (AFT) for rate limiting.

## Quick Reference

### Commands

```bash
cargo make build          # Full release build (UI + contracts)
cargo make dev            # Local Dioxus dev server
cargo make test           # Run all tests
cargo make clippy         # Lint
cargo make publish        # Publish webapp to Freenet
cargo make run-node       # Start local Freenet node
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
│       ├── lib.rs           # Entry point
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
```

### Build Targets

- `wasm32-unknown-unknown`: Contracts (inbox, web-container) and UI
- Native: Development tools (identity-management key generator)
