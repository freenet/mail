#!/usr/bin/env bash
# Tests that a release cannot ship with scrub off: check-release-scrub.sh
# refuses a build without the marker, and the production publish path, and the
# legacy real-node task, set the flag for their whole flow.
#
# It never runs a release. It runs apart from scripts/release.sh on purpose:
# while `.release-freeze` exists, release.sh stops before it reaches any of
# this, so only this test shows the check works before the freeze lifts.
#
# Usage: scripts/check-release-scrub_test.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CHECK="$ROOT/scripts/check-release-scrub.sh"
MAKEFILE="$ROOT/Makefile.toml"
mkdir -p "$ROOT/target"
TMP="$(mktemp -d "$ROOT/target/release-scrub-test.XXXXXX")"
trap 'rm -r -- "$TMP"' EXIT

failures=0
pass() { echo "ok - $1"; }
fail() { echo "not ok - $1"; failures=$((failures + 1)); }
check() { # <description> <expected exit> args...
    local what="$1" want="$2" code=0
    shift 2
    "$CHECK" "$@" > "$TMP/out" 2>&1 || code=$?
    if [ "$code" -eq "$want" ]; then pass "$what"; else
        fail "$what"
        sed 's/^/    /' "$TMP/out"
    fi
}
task() { # <name>: the task's lines
    awk -v t="[tasks.$1]" '
        $0 == t { inside = 1; next }
        inside && /^\[tasks\./ { exit }
        inside { print }
    ' "$MAKEFILE"
}

MARKER=$(sed -n 's/^MARKER="\(.*\)"$/\1/p' "$CHECK")
if grep -q -F "const BUILD_MARKER: &str = \"$MARKER\";" "$ROOT/ui/src/migration/scrub.rs"; then
    pass "the marker is the one scrub.rs compiles in"
else
    fail "the marker is not the one scrub.rs compiles in"
fi

mkdir -p "$TMP/with/wasm" "$TMP/without/wasm" "$TMP/none"
printf 'bytes %s bytes' "$MARKER" > "$TMP/with/wasm/app_bg.wasm"
printf 'bytes only' > "$TMP/without/wasm/app_bg.wasm"
check "a build with the marker passes" 0 --dir "$TMP/with"
check "a build without the marker is refused" 1 --dir "$TMP/without"
check "a directory with no WASM is refused" 1 --dir "$TMP/none"

deps=$(task publish-email | tr -d '\n ' | sed -n 's/.*dependencies=\[\([^]]*\)\].*/\1/p')
case "$deps" in
    *'"sign-webapp","check-webapp-scrub"'*) pass "publish-email checks the build after building it" ;;
    *) fail "publish-email does not check the build after building it" ;;
esac
if task check-webapp-scrub | grep -q 'scripts/check-release-scrub.sh'; then
    pass "that task runs the check"
else
    fail "that task does not run the check"
fi
if task publish-production | grep -q '^FREENET_MAIL_SCRUB=1 cargo make publish-production-flow$'; then
    pass "publish-production sets the flag for the whole flow"
else
    fail "publish-production does not set the flag"
fi
if grep -q '^cargo make publish-production$' "$ROOT/scripts/release.sh"; then
    pass "release.sh publishes through publish-production"
else
    fail "release.sh does not publish through publish-production"
fi
if task test-e2e-legacy-migration | grep -q 'FREENET_MAIL_SCRUB=1 .*cargo make publish-email-iso'; then
    pass "test-e2e-legacy-migration builds with the flag"
else
    fail "test-e2e-legacy-migration does not build with the flag"
fi
if [ "$(grep -c 'FREENET_MAIL_SCRUB=1 ' "$MAKEFILE")" -eq 2 ]; then
    pass "nothing else in the Makefile sets the flag"
else
    fail "something else in the Makefile sets the flag"
fi

[ "$failures" -eq 0 ]
