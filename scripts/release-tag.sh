#!/usr/bin/env bash
# Tag a freenet-email release on main and push the tag.
#
# scripts/release.sh publishes, then opens the published-contract/ snapshot
# PR (release/v<version>). main only takes squash merges, so the snapshot
# lands under a new SHA; run this once that PR has merged to tag the merge
# commit. release.sh also calls it directly when there is no snapshot to
# commit.
#
# Usage:
#     scripts/release-tag.sh 0.2.7
#     scripts/release-tag.sh 0.2.7 --yes   # skip the confirmation prompt

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

VERSION="${1:-}"
SKIP_CONFIRM="${2:-}"

if [ -z "$VERSION" ]; then
    echo "usage: $0 <version> [--yes]" >&2
    exit 1
fi

TAG="v$VERSION"

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

CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
[ "$CURRENT_BRANCH" = "main" ] || die "not on main (current branch: $CURRENT_BRANCH)"
[ -z "$(git status --porcelain)" ] || die "working tree is dirty"

git fetch -q origin main --tags
git merge -q --ff-only origin/main || die "local main has diverged from origin/main"

git rev-parse -q --verify "refs/tags/$TAG" >/dev/null && die "tag $TAG already exists locally"
git ls-remote --exit-code --tags origin "refs/tags/$TAG" >/dev/null 2>&1 \
    && die "tag $TAG already exists on origin"

CARGO_VERSION=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
[ "$CARGO_VERSION" = "$VERSION" ] \
    || die "Cargo.toml workspace version ($CARGO_VERSION) does not match $VERSION"

CONTRACT_ID=$(tr -d '[:space:]' < published-contract/contract-id.txt)
SUBJECT=$(git log -1 --format=%s)
case "$SUBJECT" in
    "chore(release): $TAG"*) ;;
    *) echo "⚠️  HEAD is not the $TAG snapshot commit: \"$SUBJECT\""
       confirm "Tag it anyway?" ;;
esac

PREV_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
if [ -n "$PREV_TAG" ]; then
    CHANGELOG=$(git log --pretty=format:'  - %s' "$PREV_TAG..HEAD")
    RANGE="since $PREV_TAG"
else
    CHANGELOG=$(git log --pretty=format:'  - %s')
    RANGE="initial release"
fi

confirm "Tag $(git rev-parse --short HEAD) as $TAG and push the tag?"

git tag -a "$TAG" -m "freenet-email $TAG

Production webapp contract id: $CONTRACT_ID

Changes $RANGE:
$CHANGELOG
"
git push origin "$TAG"

echo "  ✓ tagged $TAG at $(git rev-parse HEAD) and pushed"
