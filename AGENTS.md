# Freenet Email – Agent Guide

## Overview

Decentralized email application built on Freenet. Uses Dioxus for the web UI,
WASM contracts for inbox storage, and Anti-Flood Tokens (AFT) for rate limiting.

## One-time setup

```bash
git config core.hooksPath .githooks   # Enable repo-local git hooks
```

The pre-commit hook blocks stray `.wasm` commits outside
`published-contract/`, refuses any change to a frozen artifact under
`published-contract/wasm/`, and requires each committed contract WASM to be
staged with its id file.

## Frozen artifacts (read before touching contract or delegate code)

A contract's id is `hash(wasm, parameters)` and a delegate's key is
`blake3(blake3(wasm) ‖ params)`. Every user's inbox, token record, identity
and local state lives under one of those keys, so the shipped WASM bytes are
the keys. They are committed under `published-contract/` and never rebuilt:
a rebuild embeds the build machine's absolute paths and gives different
bytes on every machine (#348). `published-contract/README.md` lists the
files and the procedure for adding a generation.

- The UI embeds `published-contract/wasm/v1/*`; `cargo make build` builds
  only the UI.
- The webapp contract (`web_container_contract.wasm`, id
  `GeQLXXR8sfGe31BNRJoVxkvGUTnBkufJ4gTaoX5NWnU5`) and the container contract
  (`container.wasm`, id `122f6AR7PyF8d8mhczuNQM4xrLtBf5t8g2iB7PEVT7KC`) are
  published from the committed WASM. A release changes only the webapp's
  signed state.
- `scripts/check-frozen-artifacts.sh` (CI `check-drift`) pins every byte,
  checks each WASM's code hash, and re-derives both contract ids.
- A change that must alter a contract or delegate WASM is a new
  generation: record the outgoing one in the registry
  (`legacy_inbox.toml`, `legacy_identity_delegate.toml`,
  `legacy_local_state_delegate.toml`), build with `scripts/build-wasm.sh`
  (path-remapped, reproducible), commit it as `published-contract/wasm/v<N>/`,
  and ship the data migration with it.
- Changing anything under `contracts/`, `modules/` or `common/` does not
  change what ships until the UI's includes point at a new generation.
  Clippy and tests still cover that source.

The `legacy_*.toml` registries are validated by `ui/build.rs`
(`freenet-migrate-build`; an empty registry fails the build) and pinned by
`ui/src/legacy_registry.rs`. They are not read at runtime yet: the inbox and
AFT migrations still walk the in-source `LEGACY_*_CODE_HASHES` slices
described below.

## Quick Reference

### Commands

```bash
cargo make build                 # Release build of the UI (contract WASM is frozen)
cargo make dev                   # Local Dioxus dev server
cargo make dev-example           # Offline dev server (mock data, no node)
cargo make test                  # Run all tests
cargo make test-inbox            # Run inbox contract integration tests
cargo make clippy                # Lint
cargo make run-node              # Start local Freenet node

# Publishing pipeline (see "Publishing" section below)
cargo make publish-email-test    # Sandbox publish with committed test key
cargo make publish-email         # Production publish with uncommitted key
cargo make derive-test-contract-id    # Test id → target/webapp/contract-id.txt
cargo make verify-published-contract  # Prod key + committed snapshot agree
cargo make publish-all           # End-to-end test publish (build → sign → publish)
cargo make publish-production    # End-to-end production publish
cargo make publish               # Alias for publish-email-test

# Frozen artifacts
scripts/check-frozen-artifacts.sh        # Byte pins, code hashes, derived ids
scripts/build-wasm.sh <crate> <kind> <features> <out>  # Reproducible WASM for a new generation

# Release automation (see RELEASING.md)
scripts/generate-production-key.sh       # One-time: generate prod ed25519 key
scripts/release.sh <version>             # Release: build → sign → publish → container pointer flip
scripts/release-tag.sh <version>         # Tag the release commit, push tag
scripts/smoke-test-production.sh <url>   # Playwright suite against deployed webapp
```

`update-published-contract` and `update-published-contract-prod` remain as
aliases of `derive-test-contract-id` and `verify-published-contract`; neither
writes `published-contract/` any more.

`example-data + use-node` is buildable but has no user — the app always
reaches for the node when `use-node` is set. For offline dev builds use
`cargo make dev-example` (`--no-default-features --features
example-data,no-sync`); see `ui/Cargo.toml` for the full feature list.

### Toolchains

The repo root pins the latest stable rustc in `rust-toolchain.toml`. The
container contract keeps its own pin in `contracts/facade/rust-toolchain.toml`
(rustc 1.95.0), because its bytes are its stable URL and they depend on the
compiler; rustup applies it to every cargo command run in that directory.
Bump the root pin and the `dtolnay/rust-toolchain@` refs in
`.github/workflows/` together. Bump the container pin only to deliberately
re-key the container contract.

### Running a Freenet node

Two node modes: `freenet local` / `cargo make run-node` (local sandbox, no
peers; used by `publish-email-test`/`publish-all`/tests) vs. `freenet network`
(joins the real network; used by `publish-email`/`publish-production`/
`scripts/release.sh`; first publish takes ~30s to propagate).

> **⚠️ Port collision — never test-publish onto a running `freenet network` node.**
> `freenet local`/`fdev` both default to **port 7509**. If a long-running
> `freenet network` node already owns 7509 (some dev machines run one under
> launchd), then `cargo make publish-email-test` / `publish-all` will publish
> the **test-key contract onto the real network** and drive your manual QA
> against the wrong node. Before any test publish:
> 1. `ps aux | grep "[f]reenet network"` — if one is up, 7509 is the real net.
> 2. Start a dedicated sandbox on a free port and target it, e.g.
>    `freenet local --ws-api-port 7600`, then publish/QA against 7600
>    (`FREENET_LOCAL_PORT=7600 cargo make publish-email-test`).
>
> (`WEB_CONTAINER_CONTRACT_ID` is embedded from `contract-id.txt` at build
> time but is **diagnostic-only** — logged in `ui/src/lib.rs`, never used for a
> contract op — so a test build logging the production id is expected.)

### Testing

```bash
cargo test --workspace              # All tests
cargo make test-inbox               # Inbox contract tests (outside the workspace, needs --features contract)
cargo make test-ui-playwright       # Playwright E2E tests (build + serve + test)
cargo make test-ui-playwright-setup # One-time: install Playwright browsers
```

## Publishing

Every release publishes the same webapp contract (frozen WASM + the
production verifying key as parameters) with a new state: the UI archive and
its ed25519-signed metadata. The contract id never changes.

### Sandbox publish (test)

1. Start a local Freenet node in another shell:
   ```bash
   cargo make run-node
   ```
2. From a fresh checkout, run the end-to-end flow:
   ```bash
   cargo make publish-all
   ```
   This chains `build` → `sign-webapp-test` → `derive-test-contract-id` →
   `publish-email-test`. The committed test key at
   `test-contract/web-container-keys.toml` signs the webapp, and the test
   contract id (the frozen WASM with the test key's parameters) is written to
   `target/webapp/contract-id.txt`. Nothing under `published-contract/`
   changes.

### Production publish

Production uses an **uncommitted** ed25519 keypair at
`~/.config/freenet-email/web-container-keys.toml` (override with
`WEB_CONTAINER_KEY_FILE=/path/to/keys.toml`).

**One-time setup** — generate the key via the release script:

```bash
scripts/generate-production-key.sh
```

This writes the keypair with `chmod 600` and prints a reminder to back
it up offline. **Never commit this file.** Losing it means no further
release can be signed for the production contract id, and every user would
have to move to a new URL.

**End-to-end release** — use the release driver:

```bash
scripts/release.sh 0.3.0
```

See `RELEASING.md` for the full runbook, preconditions, and recovery
procedures. Under the hood this runs `cargo make publish-production`,
which chains `build` → `sign-webapp` → `verify-published-contract` →
`publish-email`. The verify step refuses to publish unless the signing key's
parameters equal `published-contract/webapp.parameters` and the committed
WASM and parameters still derive `published-contract/contract-id.txt`.

The production key and the test key give **different** contract ids,
because the id is `hash(wasm, parameters)` and the 32-byte parameters are
the verifying key itself. Only the production id is committed.

### Container contract — the stable entry point (issue #200)

The container contract is a small contract whose state points at the current
webapp. Its id, `published-contract/container-id.txt`
(`122f6AR7PyF8d8mhczuNQM4xrLtBf5t8g2iB7PEVT7KC`), is the bookmarkable URL.
Its source is `contracts/facade/` (the crate keeps its original name) and the
static HTML+JS loader it serves is `contracts/facade-loader/`. The committed
snapshot is `published-contract/container{.wasm,.parameters,-id.txt}`; CI
enforces byte-equality on the wasm, and `container.parameters` is the same
production ed25519 key the webapp contract uses (the "publisher identity").

Since the webapp contract's WASM is frozen too, the webapp id no longer
moves between releases either, so the pointer normally names the same app
id release after release. The container contract stays the documented entry
point: it is what lets the app move to a new webapp contract, should one ever
be needed, without breaking a bookmark.

Per release the container WASM is unchanged. Only the container contract's
state changes — its `current_app_id` pointer is re-signed and pushed via
`fdev execute update`, with the same production key. The loader HTML is
rendered with the app id baked in by `scripts/build-loader.sh` and embedded
in the new state. `prev_app_ids` keeps a small ring of previous pointers for
client-side rollback.

State framing matches the webapp contract's `[meta_len][meta][web_len][web]`,
but `meta` carries `FacadePointer { version, current_app_id, prev_app_ids }`
instead of just a webapp signature. Signature payload is canonicalized
hand-rolled bytes (see `freenet_email_core::facade::signed_payload`) to
sidestep CBOR map-ordering concerns.

`scripts/release.sh` renders, signs and UPDATEs the container pointer on
every release (#200); the UI's `lib.rs` logs both `WEB_CONTAINER_CONTRACT_ID`
and `FACADE_CONTRACT_ID` on startup.

#### Pointer lifecycle — how the container contract serves a release

1. `cargo make build` builds the UI. The webapp contract id stays
   `published-contract/contract-id.txt`.
2. `scripts/build-loader.sh <app_id>` substitutes the app id into
   `contracts/facade-loader/src/index.html.tmpl` → writes
   `contracts/facade-loader/dist/index.html`. This loader is the file
   the container contract serves; it's a static HTML+JS page that
   redirects the browser to the webapp url.
3. `cargo make pack-container-loader` tars + xzs the loader into
   `target/container/loader.tar.xz`. The gateway's `WebApp::try_from`
   pipeline (XzDecoder → tar.unpack) requires this exact framing.
4. `cargo make sign-container-state` signs a fresh `FacadePointer { version=now, current_app_id=<app>, prev_app_ids=[...] }`
   with the production key from `~/.config/freenet-email/web-container-keys.toml`.
   Output: `target/container/container.state` (signed `[meta_len][meta][web_len][web]`).
5. `fdev execute update --as-state <container_id> target/container/container.state`
   pushes the new state to the network. **`--as-state` is required** —
   default is `UpdateData::Delta`, which the container contract rejects
   silently as `InvalidUpdate`.
6. `scripts/release.sh` commits a `published-contract/` change on
   `release/v<version>` and opens a PR only if something there changed
   (normally nothing does); `scripts/release-tag.sh` tags the release commit.

The container contract id never changes across any of this. Users
bookmark `/v1/contract/web/<container_id>/` once and that URL keeps
working release after release.

#### Loader must postMessage, not location.replace (v0.1.8)

The gateway wraps every contract URL response in a shell page with a
sandboxed iframe and `X-Frame-Options: DENY` on the shell. Inside the
sandbox, the loader cannot `window.location.replace(<new_app_url>)` —
the new app's gateway response would have to render inside our iframe,
and XFO DENY blocks that (Firefox: "Firefox Can't Open This Page").

The fix: the loader posts `{__freenet_shell__: true, type: 'navigate', href: <new_app_url>}`
to `window.parent`. The freenet-core shell already implements
cross-contract navigation for that message — it does a top-level
`window.location.assign` outside our iframe, which loads a fresh
shell for the new contract id. See `path_handlers.rs:836` in
freenet-core for the handler.

Fallback path: if the loader is opened standalone (e.g. `?__sandbox=1`
or a dev fetch with no parent frame), it uses `window.location.replace`
so the dev UX still works.

#### Manual pointer flip / recovery

If `scripts/release.sh` aborts after publish-webapp (e.g. fdev's
300s timeout — see freenet-core#4102 — fires even though the publish
landed), resume the pointer flip manually:

```bash
# 1. Confirm the new webapp actually published.
curl -sI "http://127.0.0.1:7509/v1/contract/web/$(cat published-contract/contract-id.txt)/" \
  | head -1   # expect HTTP/1.1 200

# 2. Rebuild loader + repack + re-sign state with the production key.
cargo make sign-container-state
# (chains build-container-loader → pack-container-loader → sign)

# 3. Push the pointer update.
fdev execute update --as-state \
  "$(cat published-contract/container-id.txt)" \
  target/container/container.state
# expect "Contract updated successfully" + StateSummary

# 4. Verify the container contract now serves the new loader.
curl -s "http://127.0.0.1:7509/v1/contract/web/$(cat published-contract/container-id.txt)/?__sandbox=1" \
  | grep CURRENT_APP_ID
# expect the new app id baked in

# 5. Open the container URL in a browser. The loader should postMessage
# the shell and the shell should navigate to the webapp url.
```

If step 4 returns the old app id, the gateway likely served a stale
extracted webapp from its on-disk cache. The gateway extracts the
webapp tar.xz on GetResponse and writes the extracted files to its
webapp_cache directory; UPDATEs that change the `web` slot don't
invalidate that cache until the next contract get. Bust the cache by
hand:

```bash
# macOS:
CACHE_DIR="$HOME/Library/Caches/The-Freenet-Project-Inc.freenet/webapp_cache"
# Linux:
# CACHE_DIR="$HOME/.cache/freenet/webapp_cache"
FACADE_ID=$(cat published-contract/container-id.txt)
rm -rf "${CACHE_DIR}/${FACADE_ID}" "${CACHE_DIR}/${FACADE_ID}.hash"

# Trigger a GetResponse by hitting the MAIN URL (not ?__sandbox=1).
# The sandbox endpoint short-circuits on cache miss with a 500.
curl -s -o /dev/null "http://127.0.0.1:7509/v1/contract/web/${FACADE_ID}/"
```

This is a freenet-core gateway issue. The pointer is correct on-chain
(verified by `fdev execute get`); the staleness is local to the
gateway's extracted-webapp cache. Track downstream as a freenet-core
issue when you next encounter it.

#### What NOT to commit per release

- `target/container/container.state` is signed with the production key and
  carries a per-build timestamp version. **Do not commit it** — every
  release re-signs. Only the WASM/parameters/id snapshot
  `published-contract/container{.wasm,.parameters,-id.txt}` is checked into
  git, and it stays byte-stable across releases by design.
- `contracts/facade-loader/dist/index.html` is regenerated from
  `src/index.html.tmpl` at every release. Don't hand-edit dist; edit
  the tmpl and let `build-loader.sh` re-render.

**Inbox + AFT lockfile isolation (issue #199 Phase A)**: same pattern
extended to every other on-chain contract:

- `contracts/inbox/` — the inbox contract.
- `modules/antiflood-tokens/contracts/token-allocation-record/` — the
  AFT token-allocation-record contract.
- `modules/antiflood-tokens/delegates/token-generator/` — the AFT
  token-generator delegate.
- `modules/antiflood-tokens/interfaces/` — shared aft-interface types
  crate (analog of facade-types). Path-dep'd by all three contracts AND
  by the workspace UI.

All four are listed in `[workspace.exclude]`. Each has its own
`Cargo.lock` and =x.y.z pins on every dep that influences wasm output
(chrono, ml-dsa, freenet-stdlib, etc.). Each also has a one-line
`[workspace]` stanza so `fdev`'s `get_workspace_target_dir()` walk
doesn't panic.

Net effect: bumping a workspace dep (dioxus, ml-kem) cannot reach the
inbox or AFT build graphs. That does not make a rebuild reproducible
(embedded build paths, #348), which is why the shipped bytes are frozen
under `published-contract/wasm/v1/` and the UI embeds those, never a fresh
build. A deliberate rotation (e.g. a contract bugfix that needs a data
migration) is a new generation: see "Frozen artifacts" above and
`published-contract/README.md`.

**Inbox migration (#213/#223, shipped; #251 hardening)**: on UI
startup the `set_aliases` callback in `ui/src/api.rs` compares the
embedded `INBOX_CODE_HASH` against the `inbox_wasm_hash` recorded on
each identity in the identity-management delegate. On drift it
dispatches GETs for the old inbox keys (chained over every plausible
historical hash — see below), and the GetResponse arm decodes the
old state, re-signs via `Inbox::new`, and PUTs it under the current
inbox key. Toast surfaces the migration to the user. On first
observation (`inbox_wasm_hash = None`) the UI stamps the current
hash as a baseline so the next bump is detectable. The schema bump
on the delegate is backwards-compatible (`#[serde(default)]` on
`AliasInfo.inbox_wasm_hash`).

**AFT contract migration (#251 improvement 3)**: same shape applied
to the AFT token-allocation-record contract. `AliasInfo` carries
`aft_record_wasm_hash` + `pending_aft_migration_from`;
`LEGACY_TOKEN_RECORD_CODE_HASHES` in `ui/src/aft.rs` is the
append-only oldest→newest list (parallel to
`LEGACY_INBOX_CODE_HASHES`). On startup, after the inbox loop, the
UI runs the same drift / chained-migration / persistent-retry loop
against `TOKEN_RECORD_CODE_HASH`, dispatching GETs for each prior
AFT-record key and re-PUTing the decoded `TokenAllocationRecord`
under the current key. Re-validation works because the contract's
`TokenDelegateParameters.generator_public_key` is the identity's
ML-DSA verifying key, which is unchanged across an AFT contract
bump. The token-generator delegate is not migrated (its key derives
from the identity's ML-DSA seed, not from the WASM, so it rotates
only when the seed changes — i.e. never under a deliberate
contract bump). The `current_aft_hash_not_in_legacy` test
enforces the same append-only invariant as the inbox slice.
`token_delegate_parameters_are_deterministic_per_vk` pins the
load-bearing claim that `TokenDelegateParameters::new(&vk)` encodes
byte-identically across calls.

Deliberate AFT-record rotation recipe: change the contract source (or
a `=x.y.z` pin in its `Cargo.toml`), build the new generation with
`scripts/build-wasm.sh` into `published-contract/wasm/v<N>/`, append the
prior `TOKEN_RECORD_CODE_HASH` to `LEGACY_TOKEN_RECORD_CODE_HASHES` in
`ui/src/aft.rs`, point the UI's includes at the new generation, ship. Schema
of `TokenAllocationRecord` itself must stay compatible — appending
to the legacy slice migrates state byte-for-byte; a JSON-schema
change in the same release would silently fail `validate_state`
per user and needs a dedicated re-shape pass in
`put_migrated_aft_record`.

**Chained migration (#251 improvement 2)**: `LEGACY_INBOX_CODE_HASHES`
in `ui/src/inbox.rs` is an append-only oldest→newest list of every
prior `INBOX_CODE_HASH`. `build_migration_candidates` walks from the
recorded hash forward and `migrate_inbox` dispatches a GET per
candidate; the first GetResponse to resolve wins, suppressed by
`MIGRATED_IDENTITIES` (keyed by ML-DSA verifying-key bytes, not the
mutable alias). Append the previous hash to the slice (and to
`legacy_inbox.toml`) as part of any deliberate inbox-contract bump so users
skipping releases still recover. The current `INBOX_CODE_HASH` must never appear in the slice
— enforced by the `current_hash_not_in_legacy` test.

**Sender-side recipient hash (#251 improvement 4)**: the inbox WASM
hash a recipient was running at import time is captured on the
contact (`StoredContactKeys.inbox_wasm_hash`,
`Contact.inbox_wasm_hash`) from the import-fetch `GetResponse`'s
`key.code_hash()`. The send path
(`inbox.rs::start_sending`, `aft.rs::assign_token`,
`inbox.rs::inbox_key_for_with_hash`) addresses the recipient's
inbox under THAT hash, falling back to the sender's embedded
`INBOX_CODE_HASH` when the field is absent (own-identity sends,
contacts imported before this shipped). This decouples sender and
recipient upgrade schedules — an upgraded sender can still deliver
to a non-upgraded recipient. Stored as a bs58 string (encoded via
plain `bs58::encode`, NOT `CodeHash::encode` whose `to_lowercase`
breaks the roundtrip with `ContractKey::from_params`). Migration
to a fresher hash on the recipient's side is out of scope — the
hash sticks until the user re-imports the contact card; the
in-protocol upgrade pointer (#251 improvement 1) is the longer-
term fix for that.

Every helper that derives a contact's on-chain inbox key from its
ML-DSA VK MUST go through `inbox_key_for_with_hash` with the
contact's `inbox_wasm_hash` (fallback to `INBOX_CODE_HASH`) — using
`inbox_key_for` (sender's hash) silently breaks contact recognition
for cross-version contacts. Currently:
`ui/src/app/address_book.rs::is_contact_inbox_key`,
`::lookup_by_bs58`, and the rehydrate + CreateContact prime GETs in
`ui/src/api.rs` (~1442 and ~2540). `inbox_key_for` is still correct
for OWN-identity derivations (own inbox is at the sender's embedded
hash by construction).

**Persistent migration retry (#251 improvement 5)**:
`AliasInfo.pending_migration_from: Option<String>` is stamped on the
identity-management delegate via `IdentityMsg::SetPendingMigrationFrom`
BEFORE dispatching the migration GETs, and cleared (set to `None`)
only when the PUT under the current inbox key succeeds. On startup
`select_migrate_from` (in `ui/src/inbox.rs`) prefers a non-None
pending marker over the recorded hash, so a session whose GET never
resolved (node offline, contract expired) re-attempts on the next
session. Stale markers (`prior == current` with a leftover pending
value) are cleared in the no-drift branch.

**Container contract lockfile isolation (issue #198)**: the container
contract and its shared types crate live OUTSIDE the freenet-email workspace:

- `contracts/facade-types/` — tiny crate with `FacadePointer`,
  `FacadeMetadata`, `signed_payload()`, `FACADE_MAX_PREV_APP_IDS`. Its
  only deps are `ed25519-dalek` and `serde`.
- `contracts/facade/` — the on-chain contract crate. Path-deps on
  `freenet-email-facade-types`. Has its own `Cargo.lock` with `=x.y.z`
  pins on `byteorder`, `ciborium`, `ed25519-dalek`, `freenet-stdlib`.

Both are listed in `[workspace.exclude]` of the root `Cargo.toml`. The
freenet-email workspace re-exports the same types via
`freenet-email-core::facade::*` (path-dep on `freenet-email-facade-types`)
so signer + UI keep their existing imports unchanged.

Net effect: bumping `dioxus`, `chrono`, `ml-dsa`, or any other
workspace dep cannot rotate `container.wasm`, because cargo resolves the
container build against `contracts/facade/Cargo.lock` — not the workspace
lockfile — with the rustc pinned in `contracts/facade/rust-toolchain.toml`.
A deliberate bump of either re-keys the container contract, i.e. changes
the bookmarkable URL.

**Build hygiene**: `scripts/check-container-byte-equal.sh` rebuilds the
container contract (from `contracts/facade/`, with its own manifest and
toolchain) and
`cmp`s against `published-contract/container.wasm`. CI runs this step in
`check-contract-wasm.yml`. The main `build.yml` workflow also runs
`cargo fmt`, `cargo clippy`, `cargo test`, and a wasm32 release build
inside `contracts/facade/` so PRs that touch it are still gated.

**Status (#206 closed)**: the committed snapshot at
`published-contract/container{.wasm,.parameters,-id.txt}` is the canonical
artifact. It was produced by CI under linux/amd64 with the rustc version
pinned in `contracts/facade/rust-toolchain.toml` (1.95.0). Container builds
embed the build path, so only a build in CI's checkout path reproduces the
committed bytes; a local build elsewhere differs. The CI byte-equality
step in `check-contract-wasm.yml` is now a **release blocker**: any
rebuild that doesn't match the committed bytes fails the PR.
`check-drift` is required and runs on every PR except docs-only ones
(#339).

To regenerate the snapshot deliberately (e.g. after bumping the rustc
pin in `contracts/facade/rust-toolchain.toml` or a `=x.y.z` dep pin in
`contracts/facade/Cargo.toml`), knowing it moves the stable URL:

**On native linux/amd64**:

```bash
scripts/build-container-snapshot-linux.sh
git add published-contract/container{.wasm,.parameters,-id.txt}
git commit -m "chore(container): regenerate snapshot — <reason>"
```

**On macOS / arm64 / anything else**: qemu emulation produces wasm
bytes that drift from CI's native amd64 build (verified empirically),
so local rebuilds can't match the gate. Use the CI-bootstrap path:

1. Push the change with whatever container.wasm bytes are on disk (any
   non-empty file works — gate WILL fail).
2. The `check-contract-wasm.yml` job rebuilds and uploads the
   canonical wasm as workflow artifact `facade-wasm-rebuilt-<sha>`.
3. Download via
   `gh run download <run-id> -n facade-wasm-rebuilt-<sha>`.
4. Replace `published-contract/container.wasm`, recompute the id with
   `fdev get-contract-id --code … --parameters …`, write to
   `published-contract/container-id.txt`, commit, push.
5. CI passes.

The local `check-container-byte-equal.sh` skips with a warning on
non-canonical hosts so dev rebuilds aren't blocked.

### Reproducibility caveats

The webapp contract id is `hash(frozen wasm, production verifying key)`,
so it is fixed: `published-contract/contract-id.txt` never changes. What
differs per release is the contract's state, whose signed metadata carries
a version: the **unix timestamp at signing time** (see `sign-webapp` /
`sign-webapp-test` in `Makefile.toml`).

Why timestamp instead of a deterministic-from-source value: the
on-chain webapp contract update check requires strictly monotonic
versions. The previous scheme (commit-hash hex truncated to u32) was
not monotonic — newer commits could hash lower than the deployed
state — and broke the v0.1.1 publish. Commit count
(`git rev-list --count HEAD`) is monotonic per branch but starts at
~22, far below the version (~1.6e9) the chain already accepted under
the broken scheme. Timestamp is the simplest source that's always
above the deployed value, and a re-run after a failed publish always
signs a newer version than any attempt before it.

GNU tar is still required by `compress-webapp` for the
`--sort=name --mtime=… --owner=0 --group=0` flags; the resulting
archive is reproducible given the same UI build, but the per-build
timestamp injected at signing time means the final signed bytes differ.
Install GNU tar:

```bash
brew install gnu-tar   # provides `gtar`
```

The `cargo make compress-webapp` target detects `gtar` / GNU `tar`
automatically and emits a loud warning when falling back to BSD tar.
`scripts/release.sh` errors out at preflight if GNU tar is missing.

### Security — committed test key

The ed25519 keypair at `test-contract/web-container-keys.toml` is
**committed on purpose** so the test contract ID is reproducible
across clones. Anyone with read access to this repository can sign
webapps under the test contract ID, but the key grants no access to
any user data and must never be reused for production. See
`test-contract/README.md` for the full threat model.

### Regenerating test keys

Two committed test keys live under `test-contract/`:

1. **Web container signer** (`test-contract/web-container-keys.toml`) —
   ed25519, used to sign test webapps. Gives the test contract id, which
   `derive-test-contract-id` writes to `target/webapp/contract-id.txt`.
2. **Identity delegate** (`test-contract/identity/identity-manager-key.*.pem`) —
   P-384, used by the `identity-management` delegate. The shipped delegate
   parameters derived from it are frozen as
   `published-contract/wasm/v1/identity-manager-params`.

**To rotate the web-container test key:**

```bash
rm test-contract/web-container-keys.toml
cargo make generate-web-container-keys
cargo make derive-test-contract-id   # the new test id, under target/
git add test-contract/web-container-keys.toml
git commit -m "chore: rotate committed web-container test key"
```

The test contract id changes; the production snapshot in
`published-contract/` does not.

**Do not rotate the identity delegate key.** The delegate's key is
`blake3(code_hash ‖ params)`, so new parameters mean a new delegate key, and
every identity stored under the shipped one would need a migration. The UI
embeds the frozen parameters, so regenerating them under
`modules/identity-management/build/` (`cargo make generate-identity-params`)
changes nothing that ships until a new generation adopts them.

## End-to-end testing

### QA inventory

`docs/qa/manual-test-inventory.md` is the source of truth for what's
covered automatically vs what needs manual exercise. Consult it before
merging non-trivial UI/contract changes and update it when a test is
added or removed. The `freenet-mail-qa` skill at
`.claude/skills/freenet-mail-qa/SKILL.md` instructs agents on when and
how to use the matrix.

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

There's also `ui/tests/production-liveness.spec.ts`, a minimal
browser-loads-and-mounts check used by
`scripts/smoke-test-production.sh` against a deployed `use-node`
webapp. It deliberately doesn't exercise identity creation or
messaging — see `RELEASING.md` §"Post-release smoke test" for the
scope and the rationale.

### Automated real-node harness

`ui/tests/live-node.spec.ts` drives the real `use-node` build through
the AFT permission flow against the isolated 2-node network from
`scripts/run-isolated-nodes.sh`. One command runs the full pipeline:

```bash
cargo make test-e2e-real-node
```

This wipes any prior iso-node state, brings up gw (7510) + peer
(7511), publishes the webapp to the gw, then runs Playwright with
`FREENET_EMAIL_BASE_URL` pointing at the published contract URL.
The spec covers identity creation, reload-persistence, and (gated on
`FREENET_LIVE_E2E_SEND=1`) the send-via-address-book → AFT permission
→ inbox UPDATE round trip.

To leave the iso nodes up for inspection after the run:

```bash
FREENET_E2E_KEEP=1 cargo make test-e2e-real-node
cargo make iso-nodes-status
cargo make iso-nodes-down   # when done
```

The host's permission overlay is driven by polling
`/permission/pending` on the gateway and POSTing
`{"index": 0}` to `/permission/{nonce}/respond` — see the
`startPermissionPump` helper in the spec. This avoids coupling
to the gateway shell page's overlay HTML.

Log assertions tail `~/freenet-mail-iso/gw/logs/freenet.*.log`
(override via `FREENET_ISO_GW_LOG_DIR`) and grep for
`UPDATE_PROPAGATION`, `allocate_token`, and identity-management
markers. Day-1 AFT cap is dodged by wiping node data per run, so
single-identity self-send works for the first send of the run.

CI scope: this target is heavy (full freenet network + dx build
+ headed browser) and is intended for tags / nightly, not every PR.

### Manual E2E checklist (against a local node)

This checklist validates the pieces that unit tests and Playwright
can't cover: real WebSocket framing, real AFT token mint/burn, real
ML-KEM encapsulation + ChaCha20-Poly1305 round trip through the inbox
contract state.

1. `cargo make run-node` in one terminal
2. `cargo make publish-email-test` in another
3. Open the published webapp URL in the browser
4. Create identity A and identity B
5. As B, click "Share address" and copy the share text — bs58 inbox
   address (~44 chars) on its own line, optionally followed by a
   `verify: <six words>` fingerprint line for out-of-band verification (#249)
6. As A, click "+ Import contact", paste B's card, set a local label, click Import
7. A sends a message to B by typing the imported alias into the To field
   (the compose form should show a fingerprint badge once the alias resolves);
   sending burns an AFT token
8. B receives, decrypts, and reads the message
9. Token accounting check: A's remaining tokens decremented

Notes:
- Single-user identity creation only validates the inbox/AFT/encryption
  pipeline. Cross-identity messaging requires the address-book share/import
  flow because contact pubkeys are not auto-discovered yet (see issue #42).
- For two browsers / two nodes, use the iso-nodes harness from #41 and run
  steps 5–6 on each side.
