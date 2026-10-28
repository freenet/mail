#!/usr/bin/env bash
# Check that no frozen artifact changed relative to a base commit.
#
# scripts/check-frozen-artifacts.sh checks that the frozen files are
# consistent with their pins. A change that rewrites a WASM, its code hash and
# its pin together stays consistent, so this script checks the history
# instead: against <base>,
#   * no existing file under published-contract/wasm/ is modified, deleted,
#     renamed or changes type (new generation directories may be added);
#   * every row of the base's published-contract/frozen.sha256 is still
#     present unchanged (new rows may be added). With the byte pins checked
#     by check-frozen-artifacts.sh, this keeps every pinned file outside
#     wasm/ (the webapp and container contracts) unchanged too.
#
# Usage: scripts/check-frozen-immutable.sh <base-commit>
#   CI passes HEAD^1: on a pull_request run that is the base branch side of
#   the merge commit, on a push to main the previous main commit.
# Exit status: 0 = nothing frozen changed, 1 = something did, 2 = usage.

set -uo pipefail

BASE="${1:-}"
if [ -z "$BASE" ]; then
    echo "usage: $0 <base-commit>" >&2
    exit 2
fi
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$ROOT"
MANIFEST="published-contract/frozen.sha256"

if ! git rev-parse --verify --quiet "$BASE^{commit}" >/dev/null; then
    echo "error: base commit $BASE is not available (is the checkout deep enough?)" >&2
    exit 2
fi

failed=0
changed=$(git diff --no-renames --name-status --diff-filter=MDT "$BASE" HEAD -- published-contract/wasm/)
if [ -n "$changed" ]; then
    echo "FAIL: existing frozen artifacts changed since $BASE:" >&2
    printf '%s\n' "$changed" | sed 's/^/  /' >&2
    failed=1
fi

if git cat-file -e "$BASE:$MANIFEST" 2>/dev/null; then
    lost=$(comm -23 <(git show "$BASE:$MANIFEST" | sort) <(git show "HEAD:$MANIFEST" 2>/dev/null | sort))
    if [ -n "$lost" ]; then
        echo "FAIL: rows of $MANIFEST were removed or changed since $BASE:" >&2
        printf '%s\n' "$lost" | sed 's/^/  /' >&2
        failed=1
    fi
fi

if [ "$failed" -ne 0 ]; then
    echo "" >&2
    echo "Shipped artifacts are the keys users' data lives under and never change." >&2
    echo "A new generation goes in a new published-contract/wasm/v<N>/ directory" >&2
    echo "(see published-contract/README.md)." >&2
    exit 1
fi
echo "ok: no frozen artifact changed since $(git rev-parse --short "$BASE")"
