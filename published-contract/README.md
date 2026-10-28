# `published-contract/`

The exact bytes freenet-email ships on Freenet, committed and frozen.

A Freenet contract's id is `hash(wasm, parameters)` and a delegate's key is
`blake3(blake3(wasm) ‖ params)`. Users' inboxes, token records, identities
and local state live under those keys, and their bookmarks point at the
contract ids. So these files are not build outputs to refresh: they are the
keys themselves. Builds never regenerate them, and nothing in the release
flow writes to this directory.

Rebuilding from source does not reproduce them. Each build embeds the
absolute paths of the machine that ran it (panic locations name source files
under `$CARGO_HOME` and the checkout), so the same commit built in two places
gives two different keys (#348).

## Contents

| File | What it is |
| ---- | ---------- |
| `web_container_contract.wasm` | The webapp contract: serves the signed UI archive |
| `webapp.parameters` | 32 bytes: the production ed25519 verifying key that signs each release |
| `contract-id.txt` | The webapp contract id, `GeQLXXR8sfGe31BNRJoVxkvGUTnBkufJ4gTaoX5NWnU5` |
| `container.wasm` | The container contract: the stable entry point that points at the current webapp |
| `container.parameters` | The same production verifying key |
| `container-id.txt` | The container contract id, `122f6AR7PyF8d8mhczuNQM4xrLtBf5t8g2iB7PEVT7KC` |
| `wasm/v1/` | Contract and delegate WASM the UI embeds, with code hashes and delegate parameters |
| `frozen.sha256` | A sha256 pin for every file above |

`wasm/v1/` holds:

| WASM | Kind | Code hash file | Parameters |
| ---- | ---- | -------------- | ---------- |
| `freenet_email_inbox` | contract | `inbox_code_hash` | per user |
| `freenet_token_allocation_record` | contract | `token_allocation_record_code_hash` | per user |
| `freenet_token_generator` | delegate | `token_generator_code_hash` | per user |
| `identity_management` | delegate | `identity_management_code_hash` | `identity-manager-params` |
| `mail_local_state` | delegate | `mail_local_state_code_hash` | `mail-local-state-params` |

The UI pulls these in with `include_bytes!` / `include_str!`
(`ui/src/api.rs`, `inbox.rs`, `aft.rs`, `local_state.rs`), and `ui/build.rs`
refuses to build if one is missing.

## What changes per release

Only the webapp contract's **state**: the UI archive and its signed
metadata, whose version is the signing timestamp. The webapp contract id
stays `GeQLXXR8…` because neither its WASM nor its parameters change, and the
container contract keeps pointing at it.

`cargo make publish-production` checks that the signing key matches
`webapp.parameters` and that the committed files still derive
`contract-id.txt` (`verify-published-contract`), then publishes under that
id. The test flow (`publish-email-test`, `publish-all`) derives its own id
from the frozen WASM and the committed test key's parameters into
`target/webapp/contract-id.txt`; it never touches this directory.

## Checks

```bash
scripts/check-frozen-artifacts.sh     # byte pins, code hashes, derived ids
scripts/check-container-byte-equal.sh # container rebuild == container.wasm (linux/amd64)
```

CI runs both (`check-contract-wasm.yml`). The pre-commit hook
(`.githooks/pre-commit`) also refuses a commit that modifies or deletes a
file under `wasm/`.

## Adding a generation

A contract or delegate fix that must change its WASM moves its users' data
to a new key, so it ships as a new generation beside the old one, never in
place of it:

1. Record the outgoing generation in the matching registry at the repo
   root: `legacy_inbox.toml`, `legacy_identity_delegate.toml` or
   `legacy_local_state_delegate.toml`. `ui/build.rs` validates every row and
   refuses an empty registry; `ui/src/legacy_registry.rs` pins the rows.
2. Build the new WASM reproducibly:
   ```bash
   scripts/build-wasm.sh <crate-dir> <contract|delegate> <features> \
       published-contract/wasm/v2/<name>
   ```
   It remaps build-machine paths to fixed prefixes and refuses an artifact
   that still contains one (`scripts/check-wasm-paths.sh`), so any machine
   reproduces the bytes.
3. Commit the new `wasm/v2/` files with their code hashes, add their rows to
   `frozen.sha256`, and point the UI's includes at `v2`.
4. Ship the migration that moves users' data from the old key to the new one
   in the same release.

The webapp and container contracts are never re-keyed: a new id is a new URL.
