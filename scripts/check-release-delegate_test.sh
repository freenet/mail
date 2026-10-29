#!/usr/bin/env bash
# Tests for scripts/check-release-delegate.sh: each refusal it promises is
# shown happening, and a release that meets the rules passes.
#
# Usage: scripts/check-release-delegate_test.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CHECK="$ROOT/scripts/check-release-delegate.sh"
mkdir -p "$ROOT/target"
TMP="$(mktemp -d "$ROOT/target/release-delegate-test.XXXXXX")"
trap 'rm -r -- "$TMP"' EXIT

mkdir -p "$TMP/ui-clean/src" "$TMP/ui-candidate/src"
echo 'const W: &[u8] = include_bytes!("../../published-contract/wasm/v2/mail_delegate");' \
    > "$TMP/ui-clean/src/lib.rs"
echo 'const W: &[u8] = include_bytes!("../../published-contract/candidate/mail_delegate");' \
    > "$TMP/ui-candidate/src/lib.rs"
printf 'no seed marker here' > "$TMP/clean.wasm"

failures=0
expect() {
    local want="$1" what="$2"
    shift 2
    if "$CHECK" "$@" > "$TMP/out" 2>&1; then got=pass; else got=fail; fi
    if [ "$got" = "$want" ]; then
        echo "ok - $what"
    else
        echo "not ok - $what (expected $want, got $got)"
        cat "$TMP/out"
        failures=$((failures + 1))
    fi
}

expect pass "a release before 0.3.0 is not checked" 0.2.8 --wasm "$TMP/missing" --ui-dir "$TMP/ui-candidate"
expect pass "a frozen delegate without v1-transition passes" 0.3.0 --wasm "$TMP/clean.wasm" --ui-dir "$TMP/ui-clean"
expect fail "the committed candidate (built with v1-transition) is refused" \
    0.3.0 --wasm "$ROOT/published-contract/candidate/mail_delegate" --ui-dir "$TMP/ui-clean"
expect fail "a UI embedding the candidate is refused" 0.3.0 --wasm "$TMP/clean.wasm" --ui-dir "$TMP/ui-candidate"
expect fail "a missing frozen delegate is refused" 0.3.1 --wasm "$TMP/missing" --ui-dir "$TMP/ui-clean"
expect fail "a pre-release of 0.3.0 is checked too" 0.3.0-rc.1 --wasm "$TMP/missing" --ui-dir "$TMP/ui-clean"
# Versions compare numerically, not as text (no sort -V: macOS lacks it).
expect fail "0.10.0 is after 0.3.0" 0.10.0 --wasm "$TMP/missing" --ui-dir "$TMP/ui-clean"
expect fail "1.0.0 is after 0.3.0" 1.0.0 --wasm "$TMP/missing" --ui-dir "$TMP/ui-clean"
expect pass "0.2.99 is before 0.3.0" 0.2.99 --wasm "$TMP/missing" --ui-dir "$TMP/ui-candidate"
expect fail "a malformed version is refused" 0.3 --wasm "$TMP/clean.wasm" --ui-dir "$TMP/ui-clean"

[ "$failures" -eq 0 ] || { echo "$failures failure(s)"; exit 1; }
echo "all check-release-delegate tests pass"
