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
#   • GNU tar is installed (for reproducible archives)
#   • The frozen artifacts in published-contract/ match their pins
#
# Usage:
#     scripts/release.sh 0.1.0
#     scripts/release.sh 0.1.0 --yes   # auto-confirm every prompt
#
# The contract WASM is frozen, so a release changes nothing in the repo:
# it publishes a newly signed webapp state under the fixed webapp contract
# id, updates the container contract's pointer, and tags the commit it
# built from.
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

# Publish exactly what is on origin/main.
git fetch -q origin +refs/heads/main:refs/remotes/origin/main
if [ "$(git rev-parse HEAD)" != "$(git rev-parse origin/main)" ]; then
    die "local main ($(git rev-parse --short HEAD)) is not origin/main ($(git rev-parse --short origin/main)). Pull first."
fi
# The commit the release is built from, published from, and tagged.
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

# fdev must support the --as-state flag for container pointer flips.
# Older builds silently wrap the file as `UpdateData::Delta` and the
# container contract then returns `InvalidUpdate`, so the pointer never
# moves and users hitting the stable container URL get a stale app.
if ! fdev execute update --help 2>&1 | grep -q -- '--as-state'; then
    die "fdev does not support \`--as-state\` (required for container UPDATE).
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

# The frozen artifacts the release publishes and the UI embeds.
bash "$REPO_ROOT/scripts/check-frozen-artifacts.sh" >/dev/null \
    || die "published-contract/ does not match its pins (see scripts/check-frozen-artifacts.sh)"
echo "  ✓ frozen artifacts match their pins"

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

CONTRACT_ID=$(tr -d '[:space:]' < published-contract/contract-id.txt)

echo ""
echo "═══ About to release $TAG ════════════════════════════════════════════"
echo ""
echo "This will:"
echo "  1. Build the UI in release mode (contract WASM is frozen, not rebuilt)"
echo "  2. Sign the webapp with the PRODUCTION key at $KEY_FILE"
echo "  3. Publish the webapp to the real Freenet network via fdev, under the"
echo "     webapp contract id $CONTRACT_ID"
echo "  4. Update the container contract's pointer to that webapp"
echo "  5. Tag $SOURCE_SHA as $TAG and push the tag"
echo ""
echo "Steps 3-5 are PUBLICLY VISIBLE; 3 and 4 cannot be undone."
confirm "Proceed?"

# ─── Build + publish ───────────────────────────────────────────────────────

echo ""
echo "═══ Building and publishing ═══════════════════════════════════════"

# Armed BEFORE the publish: fdev can time out after the server-side publish
# succeeded (freenet-core#4102).
RELEASE_FINISHED=0
PUBLISHED=0
on_post_publish_exit() {
    [ "$RELEASE_FINISHED" = "1" ] && return
    echo "" >&2
    if [ "$PUBLISHED" = "0" ]; then
        # Stopped inside `cargo make publish-production`. The webapp
        # contract is frozen, so its id is the same whether or not the new
        # state landed. A re-run signs with a newer timestamp version, which
        # supersedes whatever a timed-out publish left behind.
        echo "✗ release.sh stopped in the build, sign or publish step for $TAG." >&2
        echo "  The new webapp may or may not have landed (fdev can time out after a" >&2
        echo "  publish that succeeded). A re-run signs a newer version, which supersedes" >&2
        echo "  it: fix the error and re-run scripts/release.sh $VERSION." >&2
        return
    fi
    echo "✗ release.sh stopped after publishing $TAG." >&2
    echo "  To finish by hand (RELEASING.md 'Recovery'):" >&2
    echo "    1. Check the container contract points at the webapp; if not, see 'Manual pointer flip'." >&2
    echo "    2. scripts/release-tag.sh $VERSION --sha $SOURCE_SHA" >&2
    echo "  Re-running release.sh instead is also safe: it signs a newer version." >&2
}
# EXIT, not ERR: `die` and a declined `confirm` leave via `exit`.
trap on_post_publish_exit EXIT

cargo make publish-production
PUBLISHED=1

# Nothing in the repo may change during a release: published-contract/
# holds the frozen artifacts, and a change there means something wrote to
# them. Stop rather than commit it.
if [ -n "$(git status --porcelain -- published-contract/)" ]; then
    git status --short -- published-contract/ >&2
    die "published-contract/ changed during the release. Those files are frozen:
restore them with 'git checkout -- published-contract/' and find what wrote to them."
fi
echo "  ✓ published-contract/ unchanged"
echo "  ✓ published webapp contract id: $CONTRACT_ID"
echo ""

# ─── Container pointer flip (issue #200 Phase 3) ──────────────────────────────
#
# Users bookmark the container contract, a stable URL whose state points at
# the webapp. The webapp contract is frozen, so the pointer normally names the
# same app id every release; it is still re-signed with a bumped version and
# UPDATEd each release.
#
# Conditional: only runs when published-contract/container-id.txt exists
# (i.e. the container contract has been published once and its id committed). Until
# then, this step warns + skips so the rest of the release still goes
# through. See #200 Phase 1 (PR #205) and #206 (Linux-built snapshot).

if [ -f published-contract/container-id.txt ]; then
    FACADE_ID=$(cat published-contract/container-id.txt | tr -d '[:space:]')
    echo "═══ Flipping container pointer (issue #200) ════════════════════════════"
    echo "  container contract id: $FACADE_ID"
    echo "  pointing at:        $CONTRACT_ID"

    # Re-render the loader with the current_app_id and sign the container
    # state with the production key (the same key signs the webapp
    # contract's state).
    FACADE_CURRENT_APP_ID="$CONTRACT_ID" cargo make build-container-loader
    cargo make sign-container-state

    FACADE_STATE="$REPO_ROOT/target/container/container.state"
    if [ ! -f "$FACADE_STATE" ]; then
        die "container state not produced at $FACADE_STATE — sign step failed?"
    fi

    confirm "Push container UPDATE to the network now?"

    # fdev execute update takes positional args KEY DELTA [RELEASE].
    # The RELEASE positional is currently a no-op in fdev (and errors
    # if set), so we omit it. The update always targets whichever node
    # the local fdev API points at; since release prerequisites assert
    # a `freenet network` daemon, the update propagates network-wide.
    #
    # --as-state: the container's `update_state` only matches `UpdateData::State`.
    # Without this flag fdev wraps the file as `UpdateData::Delta` and
    # the contract returns `InvalidUpdate`. Requires fdev with the
    # `--as-state` flag (freenet-core PR; older fdev silently fails).
    fdev execute update --as-state "$FACADE_ID" "$FACADE_STATE"

    echo "  ✓ container contract UPDATEd; bookmarked URL stays stable across releases"
    echo ""
else
    echo "  ⚠️  published-contract/container-id.txt not committed yet."
    echo "      Skipping container pointer flip (issue #200 Phase 1 prerequisite)."
    echo "      Once the container contract is published once and the id committed, this"
    echo "      step will run automatically per release."
    echo ""
fi

confirm "Tag $SOURCE_SHA as $TAG?"
"$REPO_ROOT/scripts/release-tag.sh" "$VERSION" --sha "$SOURCE_SHA" --yes
RELEASE_FINISHED=1
echo ""
echo "✅ released $TAG"

echo ""
echo "Next steps:"
echo "  1. Wait ~30s for the webapp and container updates to propagate"
echo "  2. Smoke-test against the webapp id:"
echo "       scripts/smoke-test-production.sh \\"
echo "         http://<gw>:<port>/contract/web/$CONTRACT_ID/"
if [ -f published-contract/container-id.txt ]; then
    FACADE_ID_FOR_NOTES=$(cat published-contract/container-id.txt | tr -d '[:space:]')
    echo "  3. Smoke-test against the STABLE container URL (issue #200):"
    echo "       scripts/smoke-test-production.sh \\"
    echo "         http://<gw>:<port>/contract/web/$FACADE_ID_FOR_NOTES/"
    echo "     The container URL is what users bookmark and what stays stable"
    echo "     across releases."
    echo "  4. Post the smoke-test result as a comment on issue #9"
else
    echo "  3. Post the smoke-test result as a comment on issue #9"
fi
echo ""
