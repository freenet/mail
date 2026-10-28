#!/usr/bin/env bash
# Check that no frozen artifact or registry row changed relative to a base
# commit.
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
#     wasm/ (the webapp and container contracts) unchanged too;
#   * every [[contract]] / [[delegate]] row of the base's legacy_*.toml
#     registries is still present unchanged (they are append-only: a changed
#     or removed row strands the users still on that generation).
#
# Fails closed: any command that cannot run (a git error, an unreadable
# file) fails the check rather than leaving an empty result that reads as
# "nothing changed".
#
# Usage: scripts/check-frozen-immutable.sh <base-commit>
#   CI passes the commit the change is measured against: the base branch
#   side of the merge commit on a pull_request run, the previous head on a
#   push.
# Exit status: 0 = nothing frozen changed, 1 = something did, 2 = usage or a
# command failed.

set -euo pipefail
trap 'echo "error: check-frozen-immutable.sh: a command failed (line $LINENO); failing closed" >&2; exit 2' ERR

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

# Print each [[table]] row of a registry as one line: comments and blank
# lines dropped, whitespace normalised, keys in file order.
registry_rows() {
    awk '
        { sub(/#.*/, ""); gsub(/^[ \t]+|[ \t]+$/, ""); gsub(/[ \t]+/, " ") }
        /^\[\[/ { if (row != "") print row; row = $0; next }
        row != "" && $0 != "" { row = row " ; " $0 }
        END { if (row != "") print row }
    '
}

# Lines of $1 that are missing from $2 (both newline-separated).
missing_lines() {
    local base="$1" head="$2" line
    while IFS= read -r line; do
        [ -z "$line" ] && continue
        grep -qxF -- "$line" <<< "$head" || printf '%s\n' "$line"
    done <<< "$base"
}

failed=0

changed="$(git diff --no-renames --name-status --diff-filter=MDT "$BASE" HEAD -- published-contract/wasm/)"
if [ -n "$changed" ]; then
    echo "FAIL: existing frozen artifacts changed since $BASE:" >&2
    printf '%s\n' "$changed" | sed 's/^/  /' >&2
    failed=1
fi

if git cat-file -e "$BASE:$MANIFEST" 2>/dev/null; then
    base_pins="$(git show "$BASE:$MANIFEST")"
    head_pins="$(git show "HEAD:$MANIFEST")"
    lost="$(missing_lines "$base_pins" "$head_pins")"
    if [ -n "$lost" ]; then
        echo "FAIL: rows of $MANIFEST were removed or changed since $BASE:" >&2
        printf '%s\n' "$lost" | sed 's/^/  /' >&2
        failed=1
    fi
fi

# ls-tree takes paths, not globs: list the top level and filter.
top_level="$(git ls-tree --name-only "$BASE")"
registries="$(printf '%s\n' "$top_level" | { grep -E '^legacy_.*\.toml$' || true; })"
echo "checking registries: $(printf '%s' "$registries" | tr '\n' ' ')"
while IFS= read -r registry; do
    [ -z "$registry" ] && continue
    if ! git cat-file -e "HEAD:$registry" 2>/dev/null; then
        echo "FAIL: registry $registry was removed since $BASE" >&2
        failed=1
        continue
    fi
    base_rows="$(git show "$BASE:$registry" | registry_rows)"
    head_rows="$(git show "HEAD:$registry" | registry_rows)"
    lost="$(missing_lines "$base_rows" "$head_rows")"
    if [ -n "$lost" ]; then
        echo "FAIL: rows of $registry were removed or changed since $BASE:" >&2
        printf '%s\n' "$lost" | sed 's/^/  /' >&2
        failed=1
    fi
done <<< "$registries"

if [ "$failed" -ne 0 ]; then
    echo "" >&2
    echo "Shipped artifacts are the keys users' data lives under and never change," >&2
    echo "and registry rows are append-only. A new generation goes in a new" >&2
    echo "published-contract/wasm/v<N>/ directory with new registry rows" >&2
    echo "(see published-contract/README.md)." >&2
    exit 1
fi
echo "ok: no frozen artifact or registry row changed since $(git rev-parse --short "$BASE")"
