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

# Freenet node — check the UI gateway port (50509 is the default for
# `freenet network`; the exact check depends on your node's HTTP gateway).
if ! curl -sf -o /dev/null "http://127.0.0.1:50509/contract/web/" 2>/dev/null; then
    echo "  ⚠️  could not reach a Freenet node at http://127.0.0.1:50509"
    echo "     Make sure \`freenet network\` (NOT \`freenet local\`) is running"
    echo "     in another terminal and is connected to the network."
    confirm "Continue anyway?"
else
    echo "  ✓ Freenet node reachable on :50509"
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

if [ -z "$(git status --porcelain -- published-contract/)" ]; then
    die "expected published-contract/ to change but git status shows no diff.
Something went wrong in the build — the committed snapshot may already
match the current build output (unusual for a first production publish)."
fi

CONTRACT_ID=$(cat published-contract/contract-id.txt)
echo ""
echo "  ✓ published contract id: $CONTRACT_ID"
echo ""
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
echo "  1. Wait ~30s for the contract to propagate"
echo "  2. Run: scripts/smoke-test-production.sh <gateway-url>"
echo "     (the gateway URL will look like"
echo "      http://<gateway-host>:<port>/contract/web/$CONTRACT_ID/)"
echo "  3. Post the smoke-test result as a comment on issue #9"
echo ""
