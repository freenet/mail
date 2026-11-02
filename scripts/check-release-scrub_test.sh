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
# The text must be written once, in the branch the flag selects: a second copy
# (a log line of its own) would put it into a build with scrub off.
if [ "$(grep -r -F -c -- "\"$MARKER\"" "$ROOT/ui/src" | awk -F: '{ n += $2 } END { print n }')" -eq 1 ] \
    && grep -q -F -B1 -A2 "if BUILT_IN {" "$ROOT/ui/src/migration/scrub.rs" \
    && grep -A1 -F "if BUILT_IN {" "$ROOT/ui/src/migration/scrub.rs" | grep -q -F "\"$MARKER\""; then
    pass "the marker is written once, in the branch the flag selects"
else
    fail "the marker is not written once in the branch the flag selects"
fi

PROBE=$(sed -n 's/^PROBE_MARKER="\(.*\)"$/\1/p' "$CHECK")
# Written once, in the branch the feature selects, and logged where the loop
# starts under the same feature.
if [ -n "$PROBE" ] \
    && [ "$(grep -r -F -c -- "\"$PROBE\"" "$ROOT/ui/src" | awk -F: '{ n += $2 } END { print n }')" -eq 2 ] \
    && grep -A1 -F 'if cfg!(feature = "e2e-probe") {' "$ROOT/ui/src/jobs.rs" | grep -q -F "\"$PROBE\"" \
    && grep -B1 -F 'crate::log::info(PROBE_MARKER);' "$ROOT/ui/src/jobs.rs" | grep -q -F '#[cfg(feature = "e2e-probe")]'; then
    pass "the probe marker is chosen by the feature and logged under it"
else
    fail "the probe marker is not chosen by the feature and logged under it"
fi

mkdir -p "$TMP/with/wasm" "$TMP/without/wasm" "$TMP/none"
printf 'bytes %s bytes' "$MARKER" > "$TMP/with/wasm/app_bg.wasm"
printf 'bytes only' > "$TMP/without/wasm/app_bg.wasm"
check "a build with the marker passes" 0 --dir "$TMP/with"
check "a build without the marker is refused" 1 --dir "$TMP/without"
check "a directory with no WASM is refused" 1 --dir "$TMP/none"
mkdir -p "$TMP/two"
cp "$TMP/with/wasm/app_bg.wasm" "$TMP/two/new.wasm"
cp "$TMP/without/wasm/app_bg.wasm" "$TMP/two/old.wasm"
check "two builds side by side are refused" 1 --dir "$TMP/two"
check "two builds side by side are refused for a test publish" 1 --absent --dir "$TMP/two"
mkdir -p "$TMP/probe/wasm" "$TMP/probe-scrub/wasm"
printf 'bytes %s bytes' "$PROBE" > "$TMP/probe/wasm/app_bg.wasm"
printf 'bytes %s %s bytes' "$MARKER" "$PROBE" > "$TMP/probe-scrub/wasm/app_bg.wasm"
check "a production build with the probe is refused" 1 --dir "$TMP/probe-scrub"
check "a production build with the probe and no scrub is refused" 1 --dir "$TMP/probe"
check "a test publish refuses a build with the probe" 1 --absent --dir "$TMP/probe"
check "a test publish refuses a build with scrub and the probe" 1 --absent --dir "$TMP/probe-scrub"
FREENET_E2E_PROBE_ISO=1 check "the background proof's test publish takes the probe" 0 --absent --dir "$TMP/probe"
FREENET_E2E_PROBE_ISO=1 check "a production build refuses the probe whatever the variable says" 1 --dir "$TMP/probe-scrub"
check "a test publish refuses a build with the marker" 1 --absent --dir "$TMP/with"
check "a test publish takes a build without it" 0 --absent --dir "$TMP/without"
check "a test publish refuses a directory with no WASM" 1 --absent --dir "$TMP/none"

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
if task test-e2e-legacy-migration | grep -q 'FREENET_MAIL_SCRUB=1 FREENET_MAIL_SCRUB_ISO=1 .*cargo make publish-email-iso'; then
    pass "test-e2e-legacy-migration builds with the flag, for the harness's nodes"
else
    fail "test-e2e-legacy-migration does not build with the flag, for the harness's nodes"
fi
if task test-e2e-legacy-migration | grep -q '^bash "$ROOT/scripts/check-release-scrub.sh"$'; then
    pass "test-e2e-legacy-migration checks the build it published has the marker"
else
    fail "test-e2e-legacy-migration does not check the build it published"
fi
if task test-e2e-background-run | grep -q '^ *\*"e2e-probe test instrumentation"\*) ;;$'; then
    pass "test-e2e-background checks that its probe build is recognised"
else
    fail "test-e2e-background does not check that its probe build is recognised"
fi
if [ "$(grep -r -l 'FREENET_E2E_PROBE_ISO=1' "$ROOT/Makefile.toml" "$ROOT/.github" "$ROOT/scripts/release.sh" 2>/dev/null | wc -l)" -eq 1 ] \
    && task test-e2e-background | grep -q '^FREENET_E2E_PROBE_ISO=1 FREENET_UI_FEATURES=e2e-probe exec cargo make test-e2e-background-run$'; then
    pass "only the background proof's build allows the probe"
else
    fail "something besides the background proof's build allows the probe"
fi
real_node="$(task test-e2e-real-node)"
if printf '%s\n' "$real_node" | grep -q 'check-release-scrub.sh' \
    && printf '%s\n' "$real_node" | grep -q '^ *\*"has scrub off"\*) ;;$'; then
    pass "test-e2e-real-node checks that the default build is refused"
else
    fail "test-e2e-real-node does not check that the default build is refused"
fi
if task sign-webapp-test | grep -q 'check-release-scrub.sh" --absent' \
    && task publish-email-test | grep -q 'check-release-scrub.sh" --absent'; then
    pass "a test publish refuses a build with scrub in it"
else
    fail "a test publish does not refuse a build with scrub in it"
fi
if task publish-email-test | grep -q 'env -u FREENET_E2E_PROBE_ISO '; then
    pass "publish-email-test ignores the probe opt-in"
else
    fail "publish-email-test honours the probe opt-in, which is for the harness's nodes"
fi
# Only the legacy real-node task may bring the flag to the test build, and the
# variable that allows it must not be set anywhere else, in any syntax.
if [ "$(grep -r -l 'FREENET_MAIL_SCRUB_ISO' "$ROOT/Makefile.toml" "$ROOT/.cargo" "$ROOT/ui/.cargo" "$ROOT/.github" 2>/dev/null | wc -l)" -eq 1 ] \
    && ! grep -q -E '^\s*FREENET_MAIL_SCRUB(_ISO)?\s*=\s*"' "$ROOT/Makefile.toml"; then
    pass "the flag is set nowhere else in the Makefile or the cargo config"
else
    fail "the flag is set elsewhere in the Makefile or the cargo config"
fi
if [ "$(grep -c 'FREENET_MAIL_SCRUB=1 ' "$MAKEFILE")" -eq 2 ]; then
    pass "nothing else in the Makefile sets the flag"
else
    fail "something else in the Makefile sets the flag"
fi

[ "$failures" -eq 0 ]
