#!/usr/bin/env bash
# Show check-fdev-verify-merge.sh failing: on states its parameters do not fit
# (every case inconclusive, which is not a pass), on a corpus too small to
# mean anything, and with a binary that cannot verify a merge at all.
# Its passing run is the CI step itself.
#
# Exit status: 0 = the check did what it should every time, 1 = it did not.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
mkdir -p "$ROOT/target"
DIR="$(mktemp -d "$ROOT/target/verify-merge-test.XXXXXX")"
trap 'rm -r -- "$DIR"' EXIT
failures=0

mkdir "$DIR/good" "$DIR/wrong-params" "$DIR/small"
(cd "$ROOT/contracts/inbox-v2" \
    && INBOX_CAPTURE_DIR="$DIR/good" cargo test --locked --test merge_laws capture_states_for_fdev) \
    > "$DIR/capture.log" 2>&1 || { cat "$DIR/capture.log"; exit 1; }
cp "$DIR"/good/state-*.bin "$DIR/wrong-params/"
head -c 57 /dev/zero | tr '\0' '\002' > "$DIR/wrong-params/params.bin"
cp "$DIR/good/params.bin" "$DIR/good/state-00.bin" "$DIR/good/state-01.bin" "$DIR/small/"

expect_fail() { # label message args...
    local label="$1" message="$2"
    shift 2
    if "$ROOT/scripts/check-fdev-verify-merge.sh" "$@" > "$DIR/out" 2>&1; then
        echo "not ok - $label (it passed)"
        failures=$((failures + 1))
    elif grep -q -F -- "$message" "$DIR/out"; then
        echo "ok - $label"
    else
        echo "not ok - $label (failed, but not with: $message)"
        cat "$DIR/out"
        failures=$((failures + 1))
    fi
}

expect_fail "inconclusive is not a pass" "inconclusive (not a pass)" --corpus "$DIR/wrong-params" --cases 20
expect_fail "a corpus that is too small" "want at least 12" --corpus "$DIR/small"
FDEV=/bin/false expect_fail "a binary with no verify-merge" "has no verify-merge subcommand"

[ "$failures" -eq 0 ] || exit 1
echo "ok: the verify-merge check fails as it should"
