#!/usr/bin/env bash
# Tag a freenet-email release and push the tag.
#
# scripts/release.sh publishes, then opens the published-contract/ snapshot
# PR (release/v<version>). main only takes squash merges, so the snapshot
# lands under a new SHA. Once that PR has merged, run this: it finds the
# `chore(release): v<version> ...` commit on origin/main and tags exactly
# that commit, so it cannot tag a later commit or an unmerged state.
#
# With --head it tags origin/main's tip instead (release.sh uses this when
# the release produced no snapshot change); local HEAD must equal it.
#
# Usage:
#     scripts/release-tag.sh 0.2.7
#     scripts/release-tag.sh 0.2.7 --yes          # skip the confirmation prompt
#     scripts/release-tag.sh 0.2.7 --head --yes   # tag origin/main's tip

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
    echo "usage: $0 <version> [--head] [--yes]" >&2
    exit 1
fi
shift
SKIP_CONFIRM=""
TAG_HEAD=0
for arg in "$@"; do
    case "$arg" in
        --yes) SKIP_CONFIRM="--yes" ;;
        --head) TAG_HEAD=1 ;;
        *) echo "unknown argument: $arg" >&2; exit 1 ;;
    esac
done

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

git fetch -q origin main

git rev-parse -q --verify "refs/tags/$TAG" >/dev/null \
    && die "tag $TAG already exists locally"
remote_ref_absent "refs/tags/$TAG" || die "tag $TAG already exists on origin"

if [ "$TAG_HEAD" = "1" ]; then
    SHA=$(git rev-parse origin/main)
    [ "$(git rev-parse HEAD)" = "$SHA" ] \
        || die "local HEAD is not origin/main ($(git rev-parse --short origin/main)); --head tags only what was published"
else
    # The trailing space keeps v0.2.7 from matching v0.2.70 or v0.2.7-rc1.
    # awk reads to the end (no `exit`): exiting early would SIGPIPE git log,
    # which pipefail turns into a failed lookup on a long history.
    SHA=$(git log --format='%H%x09%s' origin/main \
        | awk -F'\t' -v p="chore(release): $TAG " '!found && index($2, p) == 1 { print $1; found = 1 }')
    [ -n "$SHA" ] \
        || die "no \"chore(release): $TAG ...\" commit on origin/main yet. Merge the release/$TAG PR first."
fi

CARGO_VERSION=$(git show "$SHA:Cargo.toml" | awk '
    /^\[workspace\.package\]/ { in_section = 1; next }
    /^\[/                     { in_section = 0 }
    in_section && /^version *= *"/ {
        match($0, /"[^"]+"/)
        print substr($0, RSTART + 1, RLENGTH - 2)
        exit
    }
')
[ "$CARGO_VERSION" = "$VERSION" ] \
    || die "Cargo.toml workspace version at $(git rev-parse --short "$SHA") is $CARGO_VERSION, not $VERSION"

CONTRACT_ID=$(git show "$SHA:published-contract/contract-id.txt" 2>/dev/null | tr -d '[:space:]') \
    || die "published-contract/contract-id.txt missing at $(git rev-parse --short "$SHA")"
[ -n "$CONTRACT_ID" ] || die "published-contract/contract-id.txt is empty at $(git rev-parse --short "$SHA")"

PREV_TAG=$(git describe --tags --abbrev=0 "$SHA" 2>/dev/null || echo "")
if [ -n "$PREV_TAG" ]; then
    CHANGELOG=$(git log --pretty=format:'  - %s' "$PREV_TAG..$SHA")
    RANGE="since $PREV_TAG"
else
    CHANGELOG=$(git log --pretty=format:'  - %s' "$SHA")
    RANGE="initial release"
fi

echo "  commit:      $(git log -1 --format='%h %s' "$SHA")"
echo "  contract id: $CONTRACT_ID"
confirm "Tag it as $TAG and push the tag?"

git tag -a "$TAG" -m "freenet-email $TAG

Production webapp contract id: $CONTRACT_ID

Changes $RANGE:
$CHANGELOG
" "$SHA"
git push origin "refs/tags/$TAG"

echo "  ✓ tagged $TAG at $SHA and pushed"
