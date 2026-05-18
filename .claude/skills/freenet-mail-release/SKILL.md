---
name: freenet-mail-release
description: Production release runbook for freenet-email. Use when the user asks to "cut a release", "release v0.X.Y", "publish to production", or after a non-trivial bug sweep that should reach users. Source of truth is RELEASING.md.
---

# Freenet Mail Release

## When to invoke

- User says: "cut a release", "release v0.X.Y", "publish to production",
  "do the release", "release.sh", "tag a new version".
- A bug-fix sweep just landed on `main` and the user asks whether to
  ship it.
- A new feature merged with user-facing behavior that warrants a tag.

Do NOT invoke for: facade-only pointer updates without webapp changes
(those are a separate flow; see `RELEASING.md` §"Facade contract
update"), test/CI-only commits, doc-only commits.

## What you can do vs. what only the user can do

You **CAN**:

- Audit commits since the last tag (`git log v0.1.X..main`).
- Verify preflight requirements: clean tree, tag availability,
  production key file presence, GNU tar (`gtar`), `fdev`, `dx`,
  `cargo-make`, `gh`.
- Confirm a `freenet network` node is reachable on `127.0.0.1:7509`
  (or whatever `FREENET_PORT` overrides to).
- Draft release notes from the commit log.
- Run the post-release smoke test (`scripts/smoke-test-production.sh`).
- Verify the facade pointer flip post-publish (curl probes).

You **CANNOT**:

- Run `scripts/release.sh` itself unsupervised. It signs with the
  production key, pushes to the live network, commits + tags + pushes
  to `origin/main`. Steps 4-10 are irreversible. The user must drive
  this, or explicitly authorize each confirmation.
- Start `freenet network`. The node is a long-running interactive
  process whose output the user should be watching during publish.
- Generate or rotate the production key. That lives at
  `~/.config/freenet-email/web-container-keys.toml` and is the user's
  asset.

## Preflight checklist

Run these checks before suggesting `release.sh`:

```bash
# 1. Clean tree, on main, up to date with origin.
git status                              # must report "nothing to commit"
git rev-parse --abbrev-ref HEAD         # must be `main`
git fetch origin main && git status     # must be ahead == 0 behind == 0

# 2. Tag is free.
git tag | grep "^v<VERSION>$" && echo "TAG TAKEN" || echo "TAG OK"

# 3. Commits since last tag — confirm there's actual user-facing change.
git log $(git describe --tags --abbrev=0)..main --oneline

# 4. Production key present.
ls -la ~/.config/freenet-email/web-container-keys.toml

# 5. GNU tar — required by compress-webapp for reproducible archives.
which gtar || (tar --version | grep -q GNU && echo "system tar is GNU") || \
    echo "MISSING gtar — `brew install gnu-tar`"

# 6. Network-connected node reachable (or warn the user to start one).
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:7509/
# 200 / 404 / 405 = node is up; 000 = not running, user must run `freenet network`

# 7. Required tools.
which fdev dx cargo-make gh
```

Report any failures as a punch list before the user runs `release.sh`.
Do not paper over them.

## Picking the version

Semver per `Cargo.toml`:

- **Patch bump** (`v0.1.X` → `v0.1.X+1`): bug fixes only. The recent
  228+ sweep was a patch.
- **Minor bump** (`v0.1.X` → `v0.2.0`): user-visible features, schema
  additions, new contracts.
- **Major bump**: protocol stabilizes (we're not there yet).

Confirm the version with the user before suggesting; do not pick
unilaterally.

## Running the release

The user runs:

```bash
freenet network                          # other terminal — wait for peers
scripts/release.sh <VERSION>             # interactive, three confirmations
scripts/smoke-test-production.sh         # post-publish liveness check
```

`release.sh` prompts at:

1. Before publish (irreversible step starts).
2. After publish, before commit + tag.
3. Before push to origin.

If the user wants you to type "y" at each prompt, they should pass
`--yes` to `release.sh` and confirm authorization explicitly. Don't
assume.

## Post-release verification

After `release.sh` exits successfully (or if it aborted post-publish —
see "Recovery" below), verify the deploy actually works:

```bash
# 1. Smoke test the new webapp.
scripts/smoke-test-production.sh
# Runs ui/tests/production-liveness.spec.ts across 5 browser profiles.
# Asserts: gateway serves the webapp, WASM loads, Dioxus mounts,
# "Create new identity" link renders. Does NOT exercise identity
# creation / messaging — that needs the manual checklist in AGENTS.md.

# 2. Facade pointer flipped to new app id.
NEW_APP_ID=$(cat published-contract/contract-id.txt)
FACADE_ID=$(cat published-contract/facade-id.txt)
curl -s "http://127.0.0.1:7509/v1/contract/web/${FACADE_ID}/?__sandbox=1" \
  | grep -F "${NEW_APP_ID}"
# expect: var CURRENT_APP_ID = "<new app id>";

# 3. The new webapp serves directly.
curl -sI "http://127.0.0.1:7509/v1/contract/web/${NEW_APP_ID}/" | head -1
# expect: HTTP/1.1 200 OK
```

If facade `?__sandbox=1` shows the OLD app id, the gateway is serving
a stale extracted webapp from its on-disk cache. See AGENTS.md
§"Manual pointer flip / recovery" for the cache-bust recipe.

## Recovery

### `release.sh` aborts during publish (fdev 300s timeout)

freenet-core#4102: `fdev publish` returns a 300s client timeout despite
the server-side publish having succeeded. The webapp landed; the
facade pointer didn't flip. Recipe lives in RELEASING.md §"Manual
pointer flip"; the key facts:

- `fdev execute update` needs `--as-state`, not the default
  `UpdateData::Delta` (the facade contract silently rejects Delta as
  `InvalidUpdate`). See memory `fdev_update_needs_as_state.md`.
- The facade `web` slot must be an xz-tar containing index.html, not
  raw HTML. `cargo make sign-facade-state` (which chains
  `pack-facade-loader`) gets this right; do not skip it. See memory
  `facade_state_framing.md`.

### Smoke test fails post-publish

The webapp is live but broken. Options:

1. **Roll forward**: fix the bug, bump the version, release again.
2. **Temporary mitigation**: point users at the previous contract id
   (which is still served by the network). There is no formal
   rollback.

Do not attempt to delete or overwrite the bad contract — Freenet
contracts are immutable; only the facade pointer can be flipped, and
only forward.

### Production key lost

Generate a new one with `scripts/generate-production-key.sh`. The new
contract id will differ; every existing user must re-point their
client. Announce the rotation. Treat this as a last-resort recovery
path, not a routine action.

## Anti-patterns

- **Don't** run `release.sh` from a dirty tree or a non-`main` branch.
  The script refuses, but if forced via a flag, the resulting tag
  points at non-main state and is unrecoverable.
- **Don't** skip the smoke test. The publish pipeline has multiple
  silent-failure modes (corrupted tar, wrong signature, stale id);
  the smoke test is the only thing that catches them before users do.
- **Don't** push a release that only contains test or CI changes. The
  contract id rotates anyway because workspace `Cargo.lock` churn
  shifts wasm bytes (#198) — burning a version on a no-op release
  wastes a bookmark migration for users.
- **Don't** edit `published-contract/` by hand. Every committed file
  there is produced by `update-published-contract-prod` (or the facade
  equivalent) and signed with the production key.
- **Don't** commit `target/facade/facade.state`. Per-release signed
  artifact; only the WASM/parameters/id snapshot under
  `published-contract/facade.*` is tracked.

## Cross-references

- `RELEASING.md` — full runbook with recovery and facade details.
- `AGENTS.md` §"Publishing" — facade architecture, framing, lockfile
  isolation.
- Memory `fdev_update_needs_as_state.md` — flag required for facade
  UPDATEs.
- Memory `facade_state_framing.md` — `web` slot framing requirement.
- Memory `test_vs_prod_snapshot.md` — why the test snapshot drifts
  between test and prod publishes.
