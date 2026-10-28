#!/usr/bin/env bash
# Tag a freenet-email release and push the tag.
#
# scripts/release.sh publishes, then opens the published-contract/ snapshot
# PR (release/v<version>). main only takes squash merges, so the snapshot
# lands under a new SHA. Once that PR has merged, run this: it finds the
# `chore(release): v<version> ...` commit on origin/main and tags exactly
# that commit, so it cannot tag a later commit or an unmerged state.
#
# The snapshot commit records `Published-From: <sha>`, the main commit the
# webapp was built from. If the snapshot was merged onto any other base,
# the tagged tree would include code that was never published, so this
# refuses unless --allow-base-drift is given.
#
# With --sha <commit> it tags that commit directly (release.sh uses this
# when the release produced no snapshot change).
#
# Usage:
#     scripts/release-tag.sh 0.2.7
#     scripts/release-tag.sh 0.2.7 --yes
#     scripts/release-tag.sh 0.2.7 --sha <published-commit> --yes

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
    echo "usage: $0 <version> [--sha <commit>] [--allow-base-drift] [--yes]" >&2
    exit 1
fi
shift
SKIP_CONFIRM=""
EXPLICIT_SHA=""
ALLOW_BASE_DRIFT=0
while [ $# -gt 0 ]; do
    case "$1" in
        --yes) SKIP_CONFIRM="--yes" ;;
        --sha) EXPLICIT_SHA="${2:-}"; shift ;;
        --allow-base-drift) ALLOW_BASE_DRIFT=1 ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
    shift
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

git fetch -q origin +refs/heads/main:refs/remotes/origin/main
# Tags only feed the changelog's starting point; a clash with a stale local
# tag must not stop the release.
git fetch -q origin --tags 2>/dev/null \
    || echo "  ⚠️  could not fetch all tags; changelog may start from an older tag"

git rev-parse -q --verify "refs/tags/$TAG" >/dev/null \
    && die "tag $TAG already exists locally (push it with: git push origin refs/tags/$TAG)"
remote_ref_absent "refs/tags/$TAG" || die "tag $TAG already exists on origin"

if [ -n "$EXPLICIT_SHA" ]; then
    SHA=$(git rev-parse -q --verify "$EXPLICIT_SHA^{commit}") || die "--sha $EXPLICIT_SHA is not a commit"
    git merge-base --is-ancestor "$SHA" origin/main || die "--sha $EXPLICIT_SHA is not on origin/main"
else
    # The trailing space keeps v0.2.7 from matching v0.2.70 or v0.2.7-rc1.
    # awk reads to the end (no `exit`): exiting early would SIGPIPE git log,
    # which pipefail turns into a failed lookup on a long history.
    SHA=$(git log --format='%H%x09%s' origin/main \
        | awk -F'\t' -v p="chore(release): $TAG " '!found && index($2, p) == 1 { print $1; found = 1 }')
    [ -n "$SHA" ] \
        || die "no \"chore(release): $TAG ...\" commit on origin/main yet. Merge the release/$TAG PR first."

    PUBLISHED_FROM=$(git log -1 --format=%B "$SHA" | sed -n 's/^Published-From: *\([0-9a-f]\{40\}\).*/\1/p' | head -1)
    PARENT=$(git rev-parse "$SHA^")
    if [ -z "$PUBLISHED_FROM" ]; then
        echo "  $(git rev-parse --short "$SHA") has no Published-From line, so there is no way to check" >&2
        echo "  it matches what was published." >&2
        [ "$ALLOW_BASE_DRIFT" = "1" ] \
            || die "refusing to tag. Check by hand, then pass --allow-base-drift."
    elif [ "$PARENT" != "$PUBLISHED_FROM" ]; then
        echo "  The webapp was published from $(git rev-parse --short "$PUBLISHED_FROM"), but the snapshot" >&2
        echo "  was merged onto $(git rev-parse --short "$PARENT"). These commits are in the tagged tree" >&2
        echo "  but were never published:" >&2
        git log --format='    %h %s' "$PUBLISHED_FROM..$PARENT" >&2
        [ "$ALLOW_BASE_DRIFT" = "1" ] \
            || die "refusing to tag. Cut a new release that includes them, or pass --allow-base-drift."
    fi

    # The snapshot commit must be exactly published-contract/; anything else
    # in it was never built or published.
    # --no-renames so a file moved INTO published-contract/ still lists its source.
    OTHER_CHANGES=$(git diff --no-renames --name-only "$SHA^" "$SHA" | grep -v '^published-contract/' || true)
    if [ -n "$OTHER_CHANGES" ]; then
        echo "  $(git rev-parse --short "$SHA") changes files outside published-contract/:" >&2
        printf '    %s\n' $OTHER_CHANGES >&2
        die "refusing to tag: those changes were never published. Cut a new release."
    fi
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
git push origin "refs/tags/$TAG" \
    || die "tag $TAG was created locally but not pushed; retry with: git push origin refs/tags/$TAG"

echo "  ✓ tagged $TAG at $SHA and pushed"

# The smoke test reads published-contract/contract-id.txt from the working
# tree, so bring local main up to the release.
# The tag is already pushed, so nothing here may fail the script.
if [ "$(git rev-parse --abbrev-ref HEAD)" = "main" ] && [ -z "$(git status --porcelain)" ] \
    && git merge-base --is-ancestor HEAD origin/main \
    && git merge -q --ff-only origin/main 2>/dev/null \
    && [ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ]; then
    echo "  ✓ local main fast-forwarded to $(git rev-parse --short HEAD)"
else
    echo "  Note: update your main checkout before running scripts/smoke-test-production.sh."
fi
