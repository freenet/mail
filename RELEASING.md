# Releasing freenet-email

This document is the runbook for cutting a production release.

## TL;DR

```bash
# One-time, first release only:
scripts/generate-production-key.sh

# Every release:
freenet network   # in another terminal (network-connected node)
scripts/release.sh 0.1.0
scripts/smoke-test-production.sh
```

Everything else is automation around those three commands.

## Overview

A release is a tuple of `(git tag, contract id, signed webapp)`:

1. `scripts/release.sh` builds the webapp, signs it with the production
   key, publishes the contract to the real Freenet network, commits the
   updated `published-contract/` snapshot, creates an annotated tag, and
   pushes both commit and tag to `origin/main`.
2. `scripts/smoke-test-production.sh` runs the Playwright suite against
   the deployed webapp via the Freenet gateway to confirm the release
   actually works end to end.

Steps 3, 4, 5, 6 of `release.sh` (publish, commit, tag, push) are
irreversible and visible to every user of the project. The script
prompts before each of those, and aborts on failure of any preflight
check.

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
node's HTTP gateway on `127.0.0.1:50509` at preflight and warns if it
doesn't respond.

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

### 4. GNU tar, fdev, dioxus-cli, cargo-make, gh

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
5. **Diff verification** — confirms `published-contract/` actually
   changed. If not, the script aborts with a diagnostic.
6. **Second confirmation prompt** — shows the new contract id and
   diff, asks whether to commit + tag.
7. **Commit** `published-contract/` with a standard message.
8. **Annotated tag** `v$VERSION` with auto-generated release notes from
   the git log since the last tag.
9. **Third confirmation prompt** — asks whether to push commit + tag
   to `origin/main`.
10. **Push** both to origin.

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
`http://127.0.0.1:50509/contract/web/<committed-contract-id>/` (the
local network-connected node serving the just-published contract).
Pass an explicit gateway URL to test against a remote peer:

```bash
scripts/smoke-test-production.sh http://some-peer.example:50509/contract/web/<id>/
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

## Recovery

### Publish failed halfway

The script is idempotent up to step 7 (commit). If any step 1-6 fails,
re-run `scripts/release.sh 0.1.0` — no state persists between runs
until commit time.

If the publish succeeded but the tag push failed:

```bash
git tag -d v0.1.0            # drop the local tag
scripts/release.sh 0.1.0     # start over
```

If the commit + tag both succeeded but the push failed, you're in an
inconsistent state between your local and origin. Either:

```bash
git push origin main
git push origin v0.1.0
```

...or unwind:

```bash
git reset --hard HEAD~1
git tag -d v0.1.0
```

Unwinding leaves the published contract on Freenet, but without the
committed snapshot to pin its id. Re-run `release.sh` to rebuild and
re-publish (the second publish will likely produce a different id if
anything about the build environment shifted; that's fine for a failed
release).

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

Don't squash release commits: the `chore(release): vX.Y.Z` commit is
the annotated tag's anchor. Its diff is always exactly
`published-contract/` — any release that touches other files is a bug.
