# Releasing freenet-email

This document is the runbook for cutting a production release.

## TL;DR

```bash
# One-time, first release only:
scripts/generate-production-key.sh

# Every release:
freenet network   # in another terminal (network-connected node)
scripts/release.sh 0.1.0
# squash-merge the snapshot PR it opens once CI is green, then:
scripts/release-tag.sh 0.1.0
scripts/smoke-test-production.sh
```

Everything else is automation around those commands.

## Overview

A release is a tuple of `(git tag, contract id, signed webapp)`:

1. `scripts/release.sh` builds the webapp, signs it with the production
   key, publishes the contract to the real Freenet network, commits the
   updated `published-contract/` snapshot on a `release/v<version>`
   branch, and opens a PR for it. `main` is protected (required checks,
   squash-only merges), so the snapshot cannot be pushed there directly.
2. Once that PR is squash-merged, `scripts/release-tag.sh <version>`
   creates the annotated tag on main's merge commit and pushes it.
3. `scripts/smoke-test-production.sh` runs the Playwright suite against
   the deployed webapp via the Freenet gateway to confirm the release
   actually works end to end.

The publish and the facade pointer flip are irreversible and visible to
every user of the project; the snapshot branch and PR are public. The
script prompts before each of those, and aborts on failure of any
preflight check.

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
this key means rotating the production contract id — every user of the
old deployment will be orphaned. Suggested backup options (pick at
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
old version forever (and the wasm bytes will be byte-equal to the
previous release, so the release script reports "unchanged bytes" and
nothing actually moves between tags — this is how v0.1.9 through
v0.1.11 all shipped with `v0.1.8` baked in).

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
cargo binstall --version 0.7.3 dioxus-cli
cargo binstall cargo-make
```

On Linux, tar is already GNU tar; install the rest the same way.

## The release

```bash
scripts/release.sh 0.1.0
```

What happens, in order:

1. **Preflight checks** — branch, clean tree, tag availability, key
   present, tools installed, Freenet node reachable.
2. **Test gate** — `cargo make test`, `test-inbox`, `clippy`. Any
   failure aborts.
3. **First confirmation prompt** — summarizes the six irreversible
   steps about to run. Type `y` to proceed.
4. **Build + sign + publish** — `cargo make publish-production` chains
   `build` → `update-published-contract-prod` → `publish-email`. This
   pushes the signed contract to the live Freenet network via fdev.
5. **Facade pointer flip** — re-signs the facade state for the new
   webapp id and UPDATEs it (prompted).
6. **Diff verification** — checks whether `published-contract/`
   changed. If it didn't, there is nothing to commit and the script tags
   the published commit directly (step 10 with `--sha`).
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
scripts/release.sh 0.1.0 --yes
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

## Facade contract update (issue #200, Phases 1 + 3)

The web-container contract id rotates per release (issue #198). The
facade contract gives users a stable bookmarkable URL across releases.
See AGENTS.md §"Facade contract" for the architecture.

**Phase 3 (#200) — automatic per-release flip**: `scripts/release.sh`
now does this for you. After the contract publish + before the commit,
the script:

1. Re-renders the loader with the new `current_app_id` baked in
   (`cargo make build-facade-loader` with `FACADE_CURRENT_APP_ID` set).
2. Signs a new facade state with the production key (`cargo make
   sign-facade-state`).
3. Prompts to push the facade UPDATE to the network (`fdev execute
   update <FACADE_ID> target/facade/facade.state network`).

The facade-flip block is **conditional on
`published-contract/facade-id.txt` being committed** — i.e. the facade
must have been published once and its id committed first. Until then,
the script warns and skips the flip; the rest of the release still goes
through.

### Verifying the pointer flip worked

After release.sh exits, sanity-check that the facade actually points
at the new webapp:

```bash
NEW_APP_ID=$(cat published-contract/contract-id.txt)
FACADE_ID=$(cat published-contract/facade-id.txt)

# 1. Facade serves the loader, and the loader bakes in the new app id.
curl -s "http://127.0.0.1:7509/v1/contract/web/${FACADE_ID}/?__sandbox=1" \
  | grep -F "${NEW_APP_ID}"
# expect: var CURRENT_APP_ID = "<new app id>";

# 2. The new webapp itself serves.
curl -sI "http://127.0.0.1:7509/v1/contract/web/${NEW_APP_ID}/" | head -1
# expect: HTTP/1.1 200 OK

# 3. Browser smoke: open the facade URL in a real browser. The loader
# postMessages the gateway shell, which navigates to the new app.
echo "open http://127.0.0.1:7509/v1/contract/web/${FACADE_ID}/"
```

### Manual pointer flip (if release.sh aborts post-publish)

If the script aborts after step 4 (publish webapp) — most commonly
because `fdev publish` returns a 300s client timeout despite the
server-side publish succeeding (freenet-core#4102) — the webapp WAS
published but the facade pointer was not flipped. Resume manually:

```bash
# Confirm the webapp landed despite fdev's complaint.
NEW_APP_ID=$(cat published-contract/contract-id.txt)
curl -sI "http://127.0.0.1:7509/v1/contract/web/${NEW_APP_ID}/" | head -1
# expect HTTP/1.1 200 — if you get a 4xx/5xx, the publish actually failed
# and you need to re-run the publish step.

# Re-sign facade state with the new app id and push the pointer update.
cargo make sign-facade-state
fdev execute update --as-state \
    "$(cat published-contract/facade-id.txt)" \
    target/facade/facade.state
# expect: "Contract updated successfully" + StateSummary blob

# Verify (same as §"Verifying the pointer flip worked" above).

# Then land the snapshot the way release.sh would have (main only takes
# squash-merged PRs):
git checkout -b release/v<version>
git add published-contract/
# Published-From: the main commit the webapp was built from (release.sh
# prints it; it is origin/main at the time you ran it). release-tag.sh
# refuses a snapshot commit without it.
git commit -m "chore(release): v<version> — production publish" \
    -m "Published-From: <full 40-char sha>"
git push -u origin release/v<version>
gh pr create --base main --head release/v<version> \
    --title "chore(release): v<version> — production publish" \
    --body "Release snapshot. Published-From: <full 40-char sha>"
git checkout main
# After the PR is squash-merged:
scripts/release-tag.sh <version>
```

**Important**: `--as-state` is required on the `fdev execute update`
invocation. The facade contract's `update_state` only accepts
`UpdateData::State`; without the flag fdev sends `UpdateData::Delta`
and the contract silently rejects the update as `InvalidUpdate`.

### Loader template (`contracts/facade-loader/src/index.html.tmpl`)

The loader is a static HTML+JS shell that the facade serves. It
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

**One-time facade publish (per environment)**: before Phase 3 runs for
the first time on a network, publish the facade contract once and
commit its id. Manual steps:

```bash
# Build the facade and produce the snapshot.
cargo make update-published-facade
git add published-contract/facade.{wasm,parameters} published-contract/facade-id.txt
git commit -m "chore(facade): commit production facade snapshot"

# Publish (PUT) the facade with initial state pointing at the current
# web-container id. After this, every subsequent release.sh run flips
# its state via UPDATE.
cargo make publish-facade-test    # for the local sandbox
# OR for production (one-shot, requires WEB_CONTAINER_KEY_FILE or
# the default ~/.config/freenet-email/web-container-keys.toml):
cargo make publish-facade
```

`publish-facade` mirrors `publish-facade-test` but drops the
`--port` override so fdev publishes to the live-network node. It is a
one-time-per-environment operation — every subsequent release flips
the facade pointer via UPDATE, not PUT.

**Snapshot stability (#206)**: the committed
`published-contract/facade.{wasm,parameters,id.txt}` snapshot is the
canonical artifact. CI rebuilds it under linux/amd64 with the rustc
version pinned in `rust-toolchain.toml` and fails the PR on any
byte-level drift. **If `scripts/check-facade-byte-equal.sh` fails on
CI, treat it as a release blocker** — either revert the change that
rotated the bytes or regenerate the snapshot deliberately:

```bash
scripts/build-facade-snapshot-linux.sh
git add published-contract/facade.{wasm,parameters,id.txt}
```

Bumping the rustc pin or any `=x.y.z` dep pin under
`contracts/facade/Cargo.toml` rotates the bytes and requires a paired
snapshot regeneration in the same PR. Rotating the snapshot also
rotates the facade contract id, which breaks every existing bookmark —
treat it as a deliberate, announced action.

## Recovery

### Publish failed halfway

If the build or publish fails, re-run `scripts/release.sh 0.1.0`: nothing
is committed or pushed before the publish succeeds.

Once the publish has succeeded, do **not** re-run `release.sh`: it would
publish again. If anything after that point fails (facade flip, commit,
push, `gh pr create`, or a declined prompt), the script prints the steps
to finish by hand. In short:

1. If the facade was not UPDATEd, follow §"Manual pointer flip" above.
2. Commit `published-contract/` on `release/v0.1.0` (create the branch if
   the script didn't get that far) with a `Published-From: <sha>` line
   naming the commit it was built from (the script prints it),
   `git push -u origin release/v0.1.0`, and open a PR against `main`.
3. After the squash merge, `scripts/release-tag.sh 0.1.0`.

`release-tag.sh` only tags the `chore(release): v0.1.0 ...` commit it
finds on `origin/main`, so running it before the PR merges is refused
rather than tagging the wrong commit.

### Production key lost

Generate a new one with `scripts/generate-production-key.sh`. The new
contract id will differ; every existing user will have to re-point
their client at the new webapp URL. Announce the rotation loudly.

### Smoke test fails post-publish

The webapp is live but broken for users. Options:

1. **Roll forward** — fix the bug, bump the version, release again.
   The new contract id replaces the old one for new users; old users
   keep the broken version until they visit the new URL.
2. **Temporary rollback** — there is no formal rollback. Publishing an
   older commit will produce an older contract id, not overwrite the
   current one. Point users at the older id in the meantime.

## Release cadence and versioning

Semver per `Cargo.toml`. Bump minor for new features, patch for fixes,
major once the protocol stabilizes (we're not there yet).

The `chore(release): vX.Y.Z` commit (the squash-merged snapshot PR) is
the annotated tag's anchor; keep that title when merging, since
`release-tag.sh` finds the commit by it. Its diff is always exactly
`published-contract/` — any release that touches other files is a bug.
