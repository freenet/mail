# Releasing freenet-email

This document is the runbook for cutting a production release.

## TL;DR

```bash
# One-time, first release only:
scripts/generate-production-key.sh

# Every release:
freenet network   # in another terminal (network-connected node)
scripts/release.sh 0.3.0      # publishes, flips the container pointer, tags
scripts/smoke-test-production.sh
```

Everything else is automation around those commands.

## Overview

A release is a git tag plus a newly signed webapp state, published under
the fixed webapp contract id `GeQLXXR8sfGe31BNRJoVxkvGUTnBkufJ4gTaoX5NWnU5`.
The contract and delegate WASM are frozen in `published-contract/` (see
`published-contract/README.md`); a release builds and signs only the UI.

1. `scripts/release.sh` builds the UI, signs it with the production key,
   checks the key and the committed snapshot agree, publishes the webapp
   state to the real Freenet network, flips the container contract's
   pointer, and tags the commit it built from (`scripts/release-tag.sh
   --sha`). Since nothing under `published-contract/` changes, there is no
   snapshot commit.
2. `scripts/smoke-test-production.sh` runs the Playwright suite against
   the deployed webapp via the Freenet gateway to confirm the release
   actually works end to end.

If a release ever does change `published-contract/` (a deliberate new
generation landed without its snapshot, for example), `release.sh` commits
it on `release/v<version>`, opens a PR (`main` takes only squash-merged
PRs), and `scripts/release-tag.sh <version>` tags the merge commit
afterwards.

The publish and the container pointer flip are irreversible and visible to
every user of the project. The script prompts before each, and aborts on
failure of any preflight check.

## Preconditions

Before running `scripts/release.sh`:

### 1. Production key (one-time)

Generate the ed25519 keypair that signs every release:

```bash
scripts/generate-production-key.sh
```

This writes to `~/.config/freenet-email/web-container-keys.toml` with
`chmod 600`. Override the path with `WEB_CONTAINER_KEY_FILE=...`.

**Back it up immediately** to somewhere offline and durable. Losing
this key means no further release can be signed for the production
contract id; every user would have to move to a new URL. Suggested backup options (pick at
least two):

- Password manager with secure notes
- Encrypted USB in a safe
- Printed QR code in a fire-safe

### 2. Network-connected Freenet node

Production publishes go to the real Freenet network, not a
`freenet local` sandbox. In another terminal:

```bash
freenet network
```

Wait until it reports connected peers. The release script pings the
node's HTTP gateway on `127.0.0.1:7509` at preflight and warns if it
doesn't respond. Override with `FREENET_PORT=...` if your node binds
elsewhere.

See AGENTS.md §"Running a Freenet node" for the local-vs-network
distinction.

### 3. Clean working tree on `main`

```bash
git checkout main
git pull --ff-only
git status   # must be clean
```

The release script refuses to run from any other branch or with
uncommitted changes.

### 4. Workspace version bumped to match the release tag

`ui/src/lib.rs` bakes `env!("CARGO_PKG_VERSION")` into the wasm, and
that string is what the sidebar shows. If `Cargo.toml`'s workspace
`version` doesn't match the tag, the published webapp will display the
old version forever (this is how v0.1.9 through v0.1.11 all shipped with
`v0.1.8` baked in).

Bump it BEFORE running `scripts/release.sh`:

```bash
# In Cargo.toml [workspace.package], set version = "<new>"
cargo update --workspace      # refreshes Cargo.lock
git commit -am "chore: bump workspace version to <new>"
git push
```

`scripts/release.sh` now preflight-checks that the workspace version
matches its argument and aborts otherwise.

### 5. GNU tar, fdev, dioxus-cli, cargo-make, gh

All preflight-checked by `scripts/release.sh`. On macOS:

```bash
brew install gnu-tar gh
cargo install fdev
cargo binstall --version 0.7.10 dioxus-cli
cargo binstall cargo-make
```

On Linux, tar is already GNU tar; install the rest the same way.

## The release

```bash
scripts/release.sh 0.3.0
```

What happens, in order:

1. **Preflight checks** — branch, clean tree, tag availability, key
   present, tools installed, Freenet node reachable.
2. **Test gate** — `cargo make test`, `test-inbox`, `clippy`. Any
   failure aborts.
3. **First confirmation prompt** — summarizes the steps about to run.
   Type `y` to proceed.
4. **Build + sign + publish** — `cargo make publish-production` chains
   `build` → `sign-webapp` → `verify-published-contract` →
   `publish-email`. The verify step refuses to publish unless the signing
   key matches `published-contract/webapp.parameters` and the committed
   WASM and parameters still derive `contract-id.txt`. The publish pushes
   the signed webapp state to the live Freenet network via fdev.
5. **Container pointer flip** — re-signs the container state for the
   webapp id and UPDATEs it (prompted).
6. **Diff verification** — checks whether `published-contract/`
   changed. Normally it didn't: there is nothing to commit and the script
   tags the published commit directly (step 10 with `--sha`), and the
   release is done. Steps 7-10 run only when something there changed.
7. **Commit** `published-contract/` on a new `release/v$VERSION`
   branch (prompted), with `Published-From: <sha>` naming the main
   commit the webapp was built from. Local `main` is not touched.
8. **Push + PR** — pushes `release/v$VERSION` and opens the snapshot PR
   (prompted).
9. **Squash-merge the PR before merging anything else.** If main moves
   first, the merged commit would contain code that was never published.
10. **`scripts/release-tag.sh $VERSION`** — finds the
    `chore(release): v$VERSION ...` commit on `origin/main`, refuses if
    its parent isn't the `Published-From` commit (override:
    `--allow-base-drift`), checks the version, creates the annotated
    tag `v$VERSION` on that commit with release notes since the last
    tag, pushes it, and fast-forwards a clean local `main` so the smoke
    test reads the new contract id.

To auto-confirm all prompts (useful for CI or scripting), pass
`--yes`:

```bash
scripts/release.sh 0.3.0 --yes
```

## Post-release smoke test

After `release.sh` succeeds, wait ~30s for the contract to propagate
through Freenet's routing, then:

```bash
scripts/smoke-test-production.sh
```

With no argument, this defaults to
`http://127.0.0.1:7509/v1/contract/web/<committed-contract-id>/` (the
local network-connected node serving the just-published contract).
Override the port with `FREENET_PORT=...`. Pass an explicit gateway
URL to test against a remote peer:

```bash
scripts/smoke-test-production.sh http://some-peer.example:7509/v1/contract/web/<id>/
```

### What the smoke test covers

`smoke-test-production.sh` runs
`ui/tests/production-liveness.spec.ts` against the deployed webapp
across all five browser profiles. The spec is intentionally minimal:

- The gateway serves the webapp
- The WASM bundle loads
- Dioxus mounts and renders the "Freenet Email" header
- The login screen shows the "Create new identity" link

What it catches: every failure mode in the publish pipeline that
results in a webapp that won't boot — corrupted tar archive, wrong
signature, stale contract id, routing misconfiguration.

### What the smoke test does NOT cover

The production webapp is a `use-node` build and can only do
user-facing work (create an identity, send a message, receive a
message) when attached to a real Freenet node that has the inbox,
AFT, and identity-management contracts published. Exercising that
flow requires spinning up a disposable `freenet local` node alongside
the test, which is out of scope for `smoke-test-production.sh`.

There are two ways to cover the real round trip:

1. **Automated**: `cargo make test-ui-live` runs
   `ui/tests/live-node.spec.ts` against a fresh `freenet local` node
   with a disposable data directory. This exercises real RSA keygen,
   real inbox contract puts, real AFT token burn, and real decrypted
   message delivery between two identities in a single browser
   session. Safe to run on every CI build because it's fully
   isolated from the real network.
2. **Manual**: the 7-step checklist in AGENTS.md §"End-to-end
   testing", run against a real `freenet network` node. This is the
   canonical acceptance gate for a real release.

Post the liveness result and whichever of (1) or (2) you ran as a
comment on the release tracking issue.

## Container contract update (issue #200)

The container contract (id `122f6AR7PyF8d8mhczuNQM4xrLtBf5t8g2iB7PEVT7KC`)
is the stable bookmarkable entry point; its state points at the webapp.
See AGENTS.md §"Container contract" for the architecture. The webapp
contract id no longer changes between releases either, so the pointer
normally names the same app id; it is re-signed with a newer version on
every release regardless.

`scripts/release.sh` does this for you. After the webapp publish, the
script:

1. Re-renders the loader with the `current_app_id` baked in
   (`cargo make build-container-loader` with `FACADE_CURRENT_APP_ID` set).
2. Signs a new container state with the production key (`cargo make
   sign-container-state`).
3. Prompts to push the container UPDATE to the network (`fdev execute
   update --as-state <container id> target/container/container.state`).

The flip is **conditional on `published-contract/container-id.txt` being
committed**; without it the script warns and skips the flip.

### Verifying the pointer flip worked

After release.sh exits, sanity-check that the container contract points
at the webapp:

```bash
NEW_APP_ID=$(cat published-contract/contract-id.txt)
FACADE_ID=$(cat published-contract/container-id.txt)

# 1. The container contract serves the loader, which bakes in the app id.
curl -s "http://127.0.0.1:7509/v1/contract/web/${FACADE_ID}/?__sandbox=1" \
  | grep -F "${NEW_APP_ID}"
# expect: var CURRENT_APP_ID = "<app id>";

# 2. The new webapp itself serves.
curl -sI "http://127.0.0.1:7509/v1/contract/web/${NEW_APP_ID}/" | head -1
# expect: HTTP/1.1 200 OK

# 3. Browser smoke: open the container URL in a real browser. The loader
# postMessages the gateway shell, which navigates to the app.
echo "open http://127.0.0.1:7509/v1/contract/web/${FACADE_ID}/"
```

### Manual pointer flip (if release.sh aborts post-publish)

If the script aborts after step 4 (publish webapp) — most commonly
because `fdev publish` returns a 300s client timeout despite the
server-side publish succeeding (freenet-core#4102) — the webapp may have
been published while the container pointer was not flipped. Re-running
`scripts/release.sh` is safe (it signs a newer version), or resume by hand:

```bash
# Re-sign the container state and push the pointer update.
cargo make sign-container-state
fdev execute update --as-state \
    "$(cat published-contract/container-id.txt)" \
    target/container/container.state
# expect: "Contract updated successfully" + StateSummary blob

# Verify (same as §"Verifying the pointer flip worked" above), then tag
# the commit the webapp was built from (release.sh printed it):
scripts/release-tag.sh <version> --sha <full 40-char sha>
```

**Important**: `--as-state` is required on the `fdev execute update`
invocation. The facade contract's `update_state` only accepts
`UpdateData::State`; without the flag fdev sends `UpdateData::Delta`
and the contract silently rejects the update as `InvalidUpdate`.

### Loader template (`contracts/facade-loader/src/index.html.tmpl`)

The loader is a static HTML+JS shell that the container contract serves. It
embeds the current app id via `__CURRENT_APP_ID__` placeholder and
hands the user off to the new webapp via a shell postMessage:

```js
window.parent.postMessage({
    __freenet_shell__: true,
    type: 'navigate',
    href: target
}, '*');
```

**Why postMessage instead of `window.location.replace`?** The gateway
wraps every contract URL in a shell page with `X-Frame-Options: DENY`
and serves the contract inside a sandboxed iframe. A same-window
`location.replace` from inside the sandbox would try to load the new
contract's shell page *inside our iframe*, which the browser blocks
("Firefox Can't Open This Page"). The freenet-core shell already
handles cross-contract navigation via the `__freenet_shell__`
postMessage protocol — see `crates/core/src/server/path_handlers.rs`
line ~836 in freenet-core.

When the loader is opened standalone (`?__sandbox=1` or no parent
frame), it falls back to `window.location.replace` so dev fetches
still work.

If you ever need to hand-edit the loader, edit the `.tmpl` file —
**not** the rendered `dist/index.html`, which is overwritten on every
build.

**One-time container publish (per environment)**: the production
container contract is already published and its snapshot committed. For a
new environment (e.g. a local sandbox), publish it once:

```bash
# Publish (PUT) the container contract with initial state pointing at the
# webapp id. After this, every release.sh run updates its state.
cargo make publish-container-test    # for the local sandbox
# OR for production (one-shot, requires WEB_CONTAINER_KEY_FILE or
# the default ~/.config/freenet-email/web-container-keys.toml):
cargo make publish-container
```

`publish-container` mirrors `publish-container-test` but drops the
`--port` override so fdev publishes to the live-network node. It is a
one-time-per-environment operation — every subsequent release updates
the container pointer via UPDATE, not PUT.

**Snapshot stability (#206)**: the committed
`published-contract/container{.wasm,.parameters,-id.txt}` snapshot is the
canonical artifact. CI rebuilds it under linux/amd64 with the rustc
version pinned in `contracts/facade/rust-toolchain.toml` and fails the PR
on any byte-level drift. **If `scripts/check-container-byte-equal.sh` fails on
CI, treat it as a release blocker** — either revert the change that
rotated the bytes or regenerate the snapshot deliberately:

```bash
scripts/build-container-snapshot-linux.sh
git add published-contract/container{.wasm,.parameters,-id.txt}
```

Bumping the rustc pin or any `=x.y.z` dep pin under
`contracts/facade/Cargo.toml` rotates the bytes and requires a paired
snapshot regeneration in the same PR. Rotating the snapshot also
rotates the container contract id, which breaks every existing bookmark —
treat it as a deliberate, announced action.

## Recovery

### Publish failed halfway

Re-run `scripts/release.sh <version>`. The webapp contract id is fixed, so
a re-run publishes the same contract with a newly signed state whose
version (the signing timestamp) is higher than anything an earlier
attempt may have landed; the newer state wins. Nothing is committed or
tagged before the publish and pointer flip complete.

If the script stops after publishing but before tagging, it prints how to
finish by hand: check the container pointer (§"Manual pointer flip"), then
`scripts/release-tag.sh <version> --sha <sha>`.

### Production key lost

Generate a new one with `scripts/generate-production-key.sh`. The new
key gives new webapp and container contract ids; every existing user will
have to move to the new URL. Announce the rotation loudly.

### Smoke test fails post-publish

The webapp is live but broken for users. Options:

1. **Roll forward** — fix the bug, bump the version, release again.
   The new signed state replaces the broken one under the same id.
2. **Roll back** — release an older commit. It is signed with a newer
   version than the broken state, so it replaces it under the same id.

## Release cadence and versioning

Semver per `Cargo.toml`. Bump minor for new features, patch for fixes,
major once the protocol stabilizes (we're not there yet).

Normally the tag sits on the main commit the release was built from
(`release-tag.sh --sha`). When a release does produce a snapshot PR, the
`chore(release): vX.Y.Z` squash commit is the tag's anchor instead: keep
its title (`release-tag.sh` finds the commit by it) and the
`Contract ID:` / `Published-From:` lines in the squash message body (it
checks them, and the only way past a missing one is `--allow-base-drift`,
which waives every check). Its diff is always exactly
`published-contract/` — any release that touches other files is a bug.
