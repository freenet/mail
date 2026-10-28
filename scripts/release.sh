#!/usr/bin/env bash
# End-to-end release driver for freenet-email.
#
# Runs the entire Phase 5 (#9) production-release workflow as a single
# command. Stops at each irreversible action and asks for confirmation.
#
# Preconditions (checked up front, fail fast):
#   • Working tree is clean and on `main`
#   • `cargo make test` passes
#   • The production ed25519 key exists at
#     $WEB_CONTAINER_KEY_FILE (default ~/.config/freenet-email/web-container-keys.toml)
#   • A Freenet network-connected node is running and reachable
#     (not a `freenet local` sandbox)
#   • `gh` is authenticated to push a branch and open a PR
#   • GNU tar is installed (for reproducible archives)
#
# Usage:
#     scripts/release.sh 0.1.0
#     scripts/release.sh 0.1.0 --yes   # auto-confirm every prompt
#
# After the snapshot PR it opens is squash-merged, finish with
# `scripts/release-tag.sh <version>`.
#
# The script is idempotent up to the publish: re-running after a failed
# build or publish re-runs it and prompts again. Once the publish has
# succeeded, do NOT re-run it; follow the recovery steps it prints.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# ─── Argument parsing ──────────────────────────────────────────────────────

VERSION="${1:-}"
SKIP_CONFIRM="${2:-}"

if [ -z "$VERSION" ]; then
    echo "usage: $0 <version> [--yes]" >&2
    echo "  e.g. $0 0.1.0" >&2
    exit 1
fi

if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?$ ]]; then
    echo "error: '$VERSION' is not a valid semver version" >&2
    echo "       expected e.g. 0.1.0 or 0.1.0-rc1" >&2
    exit 1
fi

TAG="v$VERSION"

# ─── Helpers ───────────────────────────────────────────────────────────────

die() {
    echo "error: $*" >&2
    exit 1
}

confirm() {
    local prompt="$1"
    if [ "$SKIP_CONFIRM" = "--yes" ]; then
        echo "$prompt (auto-confirmed via --yes)"
        return 0
    fi
    read -r -p "$prompt [y/N] " reply
    case "$reply" in
        y|Y|yes|YES) return 0 ;;
        *) echo "aborted."; exit 1 ;;
    esac
}

# ─── Preflight ─────────────────────────────────────────────────────────────

echo "═══ Preflight ══════════════════════════════════════════════════════"

# Git state
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$CURRENT_BRANCH" != "main" ]; then
    die "not on main (current branch: $CURRENT_BRANCH)"
fi
if [ -n "$(git status --porcelain)" ]; then
    die "working tree is dirty. Commit or stash first."
fi

# Tag must not already exist
if git rev-parse "$TAG" >/dev/null 2>&1; then
    die "tag $TAG already exists locally. Delete with 'git tag -d $TAG' first if re-running."
fi
# `ls-remote --exit-code` exits 2 when the ref is absent; anything else
# non-zero is a network/auth error, which must not read as "absent".
remote_ref_absent() {
    local rc=0
    git ls-remote --exit-code origin "$1" >/dev/null 2>&1 || rc=$?
    case "$rc" in
        0) return 1 ;;
        2) return 0 ;;
        *) die "could not query origin for $1 (git ls-remote exit $rc)" ;;
    esac
}
remote_ref_absent "refs/tags/$TAG" \
    || die "tag $TAG already exists on origin. Either bump the version or delete it remotely."

# The snapshot goes up as release/$TAG after the publish. Check now, so a
# leftover branch can't fail the run after the irreversible steps.
RELEASE_BRANCH="release/$TAG"
if git rev-parse -q --verify "refs/heads/$RELEASE_BRANCH" >/dev/null; then
    die "branch $RELEASE_BRANCH already exists locally (git branch -D $RELEASE_BRANCH if it is stale)"
fi
remote_ref_absent "refs/heads/$RELEASE_BRANCH" \
    || die "branch $RELEASE_BRANCH already exists on origin (delete it if it is stale)"

# Publish exactly what is on origin/main.
git fetch -q origin +refs/heads/main:refs/remotes/origin/main
if [ "$(git rev-parse HEAD)" != "$(git rev-parse origin/main)" ]; then
    die "local main ($(git rev-parse --short HEAD)) is not origin/main ($(git rev-parse --short origin/main)). Pull first."
fi
# Recorded in the snapshot commit; release-tag.sh refuses to tag if the
# snapshot was merged onto any other base (it would carry unpublished code).
SOURCE_SHA=$(git rev-parse HEAD)

# Workspace Cargo.toml version must match the requested release version.
# `ui/src/lib.rs` bakes `env!("CARGO_PKG_VERSION")` into the wasm; if the
# workspace version drifts behind the tag the published webapp shows the
# old version in its sidebar and CI byte-equality reports "unchanged
# bytes" because nothing actually moved between releases (this is how
# v0.1.9/v0.1.10/v0.1.11 all shipped with v0.1.8 baked in).
CARGO_VERSION=$(awk '
    /^\[workspace\.package\]/ { in_section = 1; next }
    /^\[/                     { in_section = 0 }
    in_section && /^version *= *"/ {
        match($0, /"[^"]+"/)
        print substr($0, RSTART + 1, RLENGTH - 2)
        exit
    }
' Cargo.toml)
if [ -z "$CARGO_VERSION" ]; then
    die "could not parse [workspace.package] version from Cargo.toml"
fi
if [ "$CARGO_VERSION" != "$VERSION" ]; then
    die "Cargo.toml workspace version ($CARGO_VERSION) does not match release version ($VERSION).
Bump it first:
  sed -i.bak 's/^version = \"$CARGO_VERSION\"/version = \"$VERSION\"/' Cargo.toml && rm Cargo.toml.bak
  cargo update --workspace
  git commit -am 'chore: bump workspace version to $VERSION'"
fi
echo "  ✓ Cargo.toml workspace version = $VERSION"

# Production key
KEY_FILE="${WEB_CONTAINER_KEY_FILE:-$HOME/.config/freenet-email/web-container-keys.toml}"
if [ ! -f "$KEY_FILE" ]; then
    die "production key not found at $KEY_FILE

Run scripts/generate-production-key.sh first."
fi
echo "  ✓ production key at $KEY_FILE"

# Required tools
command -v fdev >/dev/null || die "fdev not in PATH (cargo install fdev)"
command -v dx >/dev/null || die "dx (dioxus-cli) not in PATH"
command -v cargo-make >/dev/null || die "cargo-make not in PATH"
command -v gh >/dev/null || die "gh (GitHub CLI) not in PATH"
# `gh pr create` runs after the irreversible publish; fail here instead.
gh auth status >/dev/null 2>&1 || die "gh is not authenticated (gh auth login)"

# fdev must support the --as-state flag for facade pointer flips.
# Older builds silently wrap the file as `UpdateData::Delta` and the
# facade contract then returns `InvalidUpdate`, so the pointer never
# moves and users hitting the stable facade URL get a stale app.
if ! fdev execute update --help 2>&1 | grep -q -- '--as-state'; then
    die "fdev does not support \`--as-state\` (required for facade UPDATE).
Build a newer fdev from freenet-core HEAD:
  cargo install --path /path/to/freenet-core/crates/fdev"
fi

# GNU tar — required for reproducible archive
if command -v gtar >/dev/null 2>&1; then
    echo "  ✓ GNU tar available (gtar)"
elif tar --version 2>/dev/null | grep -qi 'gnu tar'; then
    echo "  ✓ GNU tar available (tar)"
else
    die "GNU tar not found. Install it:
  macOS: brew install gnu-tar
  linux: already default"
fi

# Freenet node — probe the WS API / HTTP gateway port (7509 is the
# default for current freenet builds; pre-0.2 builds used 50509).
# Override with FREENET_PORT=... if your node binds elsewhere.
FREENET_PORT="${FREENET_PORT:-7509}"
if ! curl -sf -o /dev/null "http://127.0.0.1:${FREENET_PORT}/" 2>/dev/null; then
    echo "  ⚠️  could not reach a Freenet node at http://127.0.0.1:${FREENET_PORT}"
    echo "     Make sure \`freenet network\` (NOT \`freenet local\`) is running"
    echo "     in another terminal and is connected to the network."
    echo "     Override the probe port with FREENET_PORT=... if needed."
    confirm "Continue anyway?"
else
    echo "  ✓ Freenet node reachable on :${FREENET_PORT}"
fi

echo "  ✓ clean tree on main"
echo "  ✓ tag $TAG available"

# Tests
echo ""
echo "═══ Running tests ══════════════════════════════════════════════════"
cargo make test
cargo make test-inbox
cargo make clippy
echo "  ✓ cargo make test, test-inbox, clippy green"

# Real-node E2E (on by default; opt-out via FREENET_RELEASE_E2E=0).
# Heavy: spins up a 2-node iso Freenet network + dx build + headed
# chromium, runs 5–10min. On by default so the pre-tag smoke catches
# regressions before they hit users; CI runs the same target on tag
# push (.github/workflows/e2e-real-node.yml) as a second gate.
if [ "${FREENET_RELEASE_E2E:-1}" = "1" ]; then
    echo ""
    echo "═══ Real-node E2E (pre-tag smoke) ═════════════════════════════"
    cargo make test-e2e-real-node
    echo "  ✓ test-e2e-real-node green"
else
    echo "  • skipped test-e2e-real-node (FREENET_RELEASE_E2E=0)"
fi

# ─── Confirmation ──────────────────────────────────────────────────────────

echo ""
echo "═══ About to release $TAG ════════════════════════════════════════════"
echo ""
echo "This will:"
echo "  1. Build the UI and contracts in release mode"
echo "  2. Sign the webapp with the PRODUCTION key at $KEY_FILE"
echo "  3. Publish the contract to the real Freenet network via fdev"
echo "  4. Flip the stable facade pointer to the new webapp"
echo "  5. Commit the new published-contract/ snapshot on $RELEASE_BRANCH"
echo "  6. Push that branch and open the snapshot PR"
echo ""
echo "Steps 3-6 are PUBLICLY VISIBLE; 3 and 4 cannot be undone."
echo "Tag afterwards with scripts/release-tag.sh $VERSION once the PR merges."
confirm "Proceed?"

# ─── Build + publish ───────────────────────────────────────────────────────

echo ""
echo "═══ Building and publishing ═══════════════════════════════════════"

# Armed BEFORE the publish: fdev can time out after the server-side publish
# succeeded (freenet-core#4102). From here a re-run may publish again, so
# say how to finish by hand instead.
RELEASE_FINISHED=0
SNAPSHOT_CHANGED=""
on_post_publish_exit() {
    [ "$RELEASE_FINISHED" = "1" ] && return
    echo "" >&2
    if [ -z "$SNAPSHOT_CHANGED" ]; then
        # Stopped inside `cargo make publish-production`: work out whether the
        # publish itself happened before telling the user what to do.
        local new_id old_id
        new_id=$(tr -d '[:space:]' < published-contract/contract-id.txt 2>/dev/null || true)
        old_id=$(git show "$SOURCE_SHA:published-contract/contract-id.txt" 2>/dev/null | tr -d '[:space:]' || true)
        if [ -z "$new_id" ] || [ "$new_id" = "$old_id" ]; then
            # Either the build failed before writing a new id, or the build
            # reproduced the live contract exactly; publishing an identical
            # contract again changes nothing, so a re-run is safe either way.
            echo "✗ release.sh stopped before anything new was published for $TAG" >&2
            echo "  (build or signing step, or the build reproduced the live contract id)." >&2
            echo "  Fix the error, run 'git checkout -- published-contract/' if it shows" >&2
            echo "  changes, and re-run scripts/release.sh $VERSION." >&2
            return
        fi
        if ! curl -sf -m 60 -o /dev/null "http://127.0.0.1:${FREENET_PORT}/v1/contract/web/${new_id}/"; then
            echo "✗ release.sh stopped while publishing $TAG, and the gateway does not serve" >&2
            echo "  the new webapp ($new_id). It most likely did not land: run" >&2
            echo "  'git checkout -- published-contract/' and re-run scripts/release.sh $VERSION." >&2
            return
        fi
        echo "✗ release.sh stopped, but the new webapp ($new_id) IS live (fdev timeout?)." >&2
    else
        echo "✗ release.sh stopped after publishing $TAG." >&2
    fi
    echo "  Do NOT re-run release.sh; it would publish again." >&2
    echo "  Current branch: $(git rev-parse --abbrev-ref HEAD)" >&2
    echo "  To finish by hand (RELEASING.md 'Recovery'):" >&2
    echo "    1. Check the facade points at the new webapp; if not, see 'Manual pointer flip'." >&2
    if [ "$SNAPSHOT_CHANGED" = "0" ]; then
        echo "    2. Nothing to commit: scripts/release-tag.sh $VERSION --sha $SOURCE_SHA" >&2
    else
        echo "    2. Commit published-contract/ on $RELEASE_BRANCH (git checkout -b if needed)," >&2
        echo "       git push -u origin $RELEASE_BRANCH, and open a PR against main. The commit" >&2
        echo "       message must contain these two lines (release-tag.sh checks them):" >&2
        echo "         Contract ID: $(tr -d '[:space:]' < published-contract/contract-id.txt 2>/dev/null || echo '<id from published-contract/contract-id.txt>')" >&2
        echo "         Published-From: $SOURCE_SHA" >&2
        echo "    3. After the squash merge: scripts/release-tag.sh $VERSION" >&2
    fi
}
# EXIT, not ERR: `die` and a declined `confirm` leave via `exit`.
trap on_post_publish_exit EXIT

cargo make publish-production

# ─── Verify the commit-worthy diff ─────────────────────────────────────────

SNAPSHOT_CHANGED=1
if [ -z "$(git status --porcelain -- published-contract/)" ]; then
    SNAPSHOT_CHANGED=0
    echo "  ⚠️  published-contract/ unchanged — wasm bytes + parameters identical to last release."
    echo "      Lockfile-isolated build (#198) kept wasm reproducible. Signature has a"
    echo "      fresh timestamp and was re-published, but the snapshot files are bit-equal."
    echo "      Will tag $TAG against current HEAD without an empty release commit."
fi

CONTRACT_ID=$(cat published-contract/contract-id.txt)
echo ""
echo "  ✓ published contract id: $CONTRACT_ID"
echo ""

# ─── Facade pointer flip (issue #200 Phase 3) ──────────────────────────────
#
# The web-container contract id rotates per release (#198 root cause).
# Users hit the facade contract instead — a stable bookmarkable URL whose
# state points at the current release's webapp. Per release we re-render
# the facade loader with the new current_app_id baked in, sign a new
# facade state with bumped version, and UPDATE the facade contract.
#
# Conditional: only runs when published-contract/facade-id.txt exists
# (i.e. the facade has been published once and its id committed). Until
# then, this step warns + skips so the rest of the release still goes
# through. See #200 Phase 1 (PR #205) and #206 (Linux-built snapshot).

if [ -f published-contract/facade-id.txt ]; then
    FACADE_ID=$(cat published-contract/facade-id.txt | tr -d '[:space:]')
    echo "═══ Flipping facade pointer (issue #200) ════════════════════════════"
    echo "  facade contract id: $FACADE_ID"
    echo "  pointing at:        $CONTRACT_ID"

    # Re-render the loader with the new current_app_id and sign the
    # facade state with the production key (same key that signs the
    # web-container — facade reuses it).
    FACADE_CURRENT_APP_ID="$CONTRACT_ID" cargo make build-facade-loader
    cargo make sign-facade-state

    FACADE_STATE="$REPO_ROOT/target/facade/facade.state"
    if [ ! -f "$FACADE_STATE" ]; then
        die "facade state not produced at $FACADE_STATE — sign step failed?"
    fi

    confirm "Push facade UPDATE to the network now?"

    # fdev execute update takes positional args KEY DELTA [RELEASE].
    # The RELEASE positional is currently a no-op in fdev (and errors
    # if set), so we omit it. The update always targets whichever node
    # the local fdev API points at; since release prerequisites assert
    # a `freenet network` daemon, the update propagates network-wide.
    #
    # --as-state: facade `update_state` only matches `UpdateData::State`.
    # Without this flag fdev wraps the file as `UpdateData::Delta` and
    # the contract returns `InvalidUpdate`. Requires fdev with the
    # `--as-state` flag (freenet-core PR; older fdev silently fails).
    fdev execute update --as-state "$FACADE_ID" "$FACADE_STATE"

    echo "  ✓ facade UPDATEd; bookmarked URL stays stable across releases"
    echo ""
else
    echo "  ⚠️  published-contract/facade-id.txt not committed yet."
    echo "      Skipping facade pointer flip (issue #200 Phase 1 prerequisite)."
    echo "      Once the facade is published once and the id committed, this"
    echo "      step will run automatically per release."
    echo ""
fi

if [ "$SNAPSHOT_CHANGED" = "1" ]; then
    echo "Diff in published-contract/:"
    git status --short -- published-contract/
    echo ""
    confirm "Commit this snapshot on release/$TAG and open a PR?"

    # ─── Commit on a release branch ────────────────────────────────────────────
    #
    # main is protected by a ruleset (required checks, squash-only merges), so
    # the snapshot cannot be pushed to main directly. It goes up as
    # release/$TAG with a PR, and local main is left untouched. The tag is
    # created after the squash merge by scripts/release-tag.sh, because
    # squashing gives the commit a new SHA.

    git checkout -b "$RELEASE_BRANCH"
    git add published-contract/
    git commit -m "chore(release): $TAG — production publish

Contract ID: $CONTRACT_ID
Published-From: $SOURCE_SHA

Signed with the uncommitted production key at
~/.config/freenet-email/web-container-keys.toml.
"

    echo ""
    echo "═══ Pushing release branch ═════════════════════════════════════════"
    confirm "Push $RELEASE_BRANCH and open the snapshot PR?"

    git push -u origin "$RELEASE_BRANCH"
    PR_URL=$(gh pr create --base main --head "$RELEASE_BRANCH" \
        --title "chore(release): $TAG — production publish" \
        --body "Release snapshot from \`scripts/release.sh $VERSION\`, already published to the network.

- webapp contract id: \`$CONTRACT_ID\`
- built and published from main at \`$SOURCE_SHA\`

Squash-merge once CI is green, **before merging anything else**: if main moves first, the merged commit would include code that was never published, and \`scripts/release-tag.sh\` will refuse to tag it. Then run \`scripts/release-tag.sh $VERSION\` on main.

Contract ID: $CONTRACT_ID
Published-From: $SOURCE_SHA")
    git checkout main
    RELEASE_FINISHED=1

    echo ""
    echo "✅ published $TAG; snapshot PR: $PR_URL"
    echo ""
    echo "Finish the release once that PR is merged:"
    echo "  scripts/release-tag.sh $VERSION"
else
    confirm "Tag current HEAD as $TAG (no snapshot commit)?"
    "$REPO_ROOT/scripts/release-tag.sh" "$VERSION" --sha "$SOURCE_SHA" --yes
    RELEASE_FINISHED=1
    echo ""
    echo "✅ released $TAG"
fi

echo ""
echo "Next steps:"
echo "  1. Wait ~30s for the contract (and facade UPDATE, if applicable)"
echo "     to propagate"
echo "  2. Smoke-test against the rotating webapp id:"
echo "       scripts/smoke-test-production.sh \\"
echo "         http://<gw>:<port>/contract/web/$CONTRACT_ID/"
if [ -f published-contract/facade-id.txt ]; then
    FACADE_ID_FOR_NOTES=$(cat published-contract/facade-id.txt | tr -d '[:space:]')
    echo "  3. Smoke-test against the STABLE facade URL (issue #200):"
    echo "       scripts/smoke-test-production.sh \\"
    echo "         http://<gw>:<port>/contract/web/$FACADE_ID_FOR_NOTES/"
    echo "     The facade URL is what users bookmark and what stays stable"
    echo "     across releases."
    echo "  4. Post the smoke-test result as a comment on issue #9"
else
    echo "  3. Post the smoke-test result as a comment on issue #9"
fi
echo ""
