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
#   • `gh` is authenticated to push tags
#   • GNU tar is installed (for reproducible archives)
#
# Usage:
#     scripts/release.sh 0.1.0
#     scripts/release.sh 0.1.0 --yes   # skip the final confirmation prompt
#
# The script is idempotent up to the point of committing
# `published-contract/`: re-running after a failed publish re-runs the
# build and prompts again, so recovery from a transient network error is
# just `scripts/release.sh $version` again.

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
if git ls-remote --exit-code --tags origin "$TAG" >/dev/null 2>&1; then
    die "tag $TAG already exists on origin. Either bump the version or delete it remotely."
fi

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
echo "  4. Commit the new published-contract/ snapshot"
echo "  5. Create an annotated tag $TAG"
echo "  6. Push the commit AND tag to origin/main"
echo ""
echo "Steps 3, 4, 5, 6 are PUBLICLY VISIBLE and hard to undo."
confirm "Proceed?"

# ─── Build + publish ───────────────────────────────────────────────────────

echo ""
echo "═══ Building and publishing ═══════════════════════════════════════"
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
    confirm "Commit this snapshot and tag as $TAG?"

    # ─── Commit ────────────────────────────────────────────────────────────────

    git add published-contract/
    git commit -m "chore(release): $TAG — production publish

Contract ID: $CONTRACT_ID

Signed with the uncommitted production key at
~/.config/freenet-email/web-container-keys.toml.
"
else
    confirm "Tag current HEAD as $TAG (no snapshot commit)?"
fi

COMMIT=$(git rev-parse HEAD)

# ─── Tag ───────────────────────────────────────────────────────────────────

# Pull the changelog from the last tag (if any) for the annotated message.
PREV_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
if [ -n "$PREV_TAG" ]; then
    CHANGELOG=$(git log --pretty=format:'  - %s' "$PREV_TAG..HEAD")
    RANGE="since $PREV_TAG"
else
    CHANGELOG=$(git log --pretty=format:'  - %s')
    RANGE="initial release"
fi

git tag -a "$TAG" -m "freenet-email $TAG

Production webapp contract id: $CONTRACT_ID

Changes $RANGE:
$CHANGELOG
"

echo "  ✓ tagged $TAG at $COMMIT"

# ─── Push ──────────────────────────────────────────────────────────────────

echo ""
echo "═══ Pushing to origin ══════════════════════════════════════════════"
confirm "Push the commit AND tag to origin/main?"

git push origin main
git push origin "$TAG"

echo ""
echo "✅ released $TAG"
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
