#!/usr/bin/env bash
# Tests that scripts/release.sh refuses to run while a release freeze file
# exists, before it looks at anything else, and gets past the freeze check
# when there is none.
#
# Usage: scripts/release-freeze_test.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
mkdir -p "$ROOT/target"
TMP="$(mktemp -d "$ROOT/target/release-freeze-test.XXXXXX")"
trap 'rm -r -- "$TMP"' EXIT

failures=0

echo "frozen for the test" > "$TMP/freeze"
set +e
RELEASE_FREEZE_FILE="$TMP/freeze" "$ROOT/scripts/release.sh" 0.3.0 --yes > "$TMP/out" 2>&1
code=$?
set -e
if [ "$code" -eq 3 ] && grep -q "releases are frozen" "$TMP/out"; then
    echo "ok - a freeze file stops release.sh with exit 3"
else
    echo "not ok - a freeze file did not stop release.sh (exit $code)"
    cat "$TMP/out"
    failures=$((failures + 1))
fi

set +e
RELEASE_FREEZE_FILE="$TMP/absent" "$ROOT/scripts/release.sh" 0.3.0 --yes > "$TMP/out" 2>&1
code=$?
set -e
if [ "$code" -ne 3 ] && ! grep -q "releases are frozen" "$TMP/out"; then
    echo "ok - without a freeze file release.sh goes past the freeze check"
else
    echo "not ok - release.sh reported a freeze with no freeze file (exit $code)"
    cat "$TMP/out"
    failures=$((failures + 1))
fi

if [ -e "$ROOT/.release-freeze" ]; then
    set +e
    "$ROOT/scripts/release.sh" 0.3.0 --yes > "$TMP/out" 2>&1
    code=$?
    set -e
    if [ "$code" -eq 3 ]; then
        echo "ok - the committed .release-freeze stops release.sh"
    else
        echo "not ok - the committed .release-freeze did not stop release.sh (exit $code)"
        failures=$((failures + 1))
    fi
fi

[ "$failures" -eq 0 ]
