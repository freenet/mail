#!/usr/bin/env bash
# Tests the release freeze: scripts/check-release-freeze.sh refuses while a
# freeze file exists, its test override cannot switch the freeze off
# elsewhere, scripts/release.sh runs it before anything else, and every
# production publish task in Makefile.toml runs it first.
#
# Never runs a release: release.sh is only ever invoked with
# `--check-freeze`, which stops right after the gate even if the gate were
# removed.
#
# Usage: scripts/release-freeze_test.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
GATE="$ROOT/scripts/check-release-freeze.sh"
mkdir -p "$ROOT/target"
TMP="$(mktemp -d "$ROOT/target/release-freeze-test.XXXXXX")"
trap 'rm -r -- "$TMP"' EXIT

failures=0
expect() { # <description> <expected exit> <actual exit> [pattern]
    if [ "$3" -eq "$2" ] && { [ -z "${4:-}" ] || grep -q -- "$4" "$TMP/out"; }; then
        echo "ok - $1"
    else
        echo "not ok - $1 (exit $3, expected $2)"
        sed 's/^/    /' "$TMP/out"
        failures=$((failures + 1))
    fi
}
run() { set +e; "$@" > "$TMP/out" 2>&1; code=$?; set -e; }

echo "frozen for the test" > "$TMP/freeze"

run env RELEASE_FREEZE_TEST=1 RELEASE_FREEZE_FILE="$TMP/freeze" "$GATE"
expect "a freeze file stops the gate with exit 3" 3 "$code" "releases are frozen"

run env RELEASE_FREEZE_TEST=1 RELEASE_FREEZE_FILE="$TMP/absent" "$GATE"
expect "without a freeze file the gate passes" 0 "$code"

if [ -e "$ROOT/.release-freeze" ]; then
    run env RELEASE_FREEZE_FILE="$TMP/absent" "$GATE"
    expect "RELEASE_FREEZE_FILE without the test flag does not lift the freeze" 3 "$code" "is ignored outside the freeze test"

    run "$ROOT/scripts/release.sh" --check-freeze
    expect "the committed .release-freeze stops release.sh at the gate" 3 "$code" "releases are frozen"
fi

run env RELEASE_FREEZE_TEST=1 RELEASE_FREEZE_FILE="$TMP/freeze" "$ROOT/scripts/release.sh" --check-freeze
expect "release.sh runs the gate" 3 "$code" "releases are frozen"

run env RELEASE_FREEZE_TEST=1 RELEASE_FREEZE_FILE="$TMP/absent" "$ROOT/scripts/release.sh" --check-freeze
expect "release.sh --check-freeze stops right after a passing gate" 0 "$code" "release freeze check passed"

# release.sh runs the gate before it parses arguments or does anything else.
gate_line=$(grep -n 'scripts/check-release-freeze.sh"$' "$ROOT/scripts/release.sh" | head -1 | cut -d: -f1)
first_action=$(grep -n '^VERSION=' "$ROOT/scripts/release.sh" | head -1 | cut -d: -f1)
if [ -n "$gate_line" ] && [ -n "$first_action" ] && [ "$gate_line" -lt "$first_action" ]; then
    echo "ok - release.sh runs the gate before argument parsing"
else
    echo "not ok - release.sh does not run the gate first (gate ${gate_line:-none}, VERSION= ${first_action:-none})"
    failures=$((failures + 1))
fi

# Every task that publishes with the production key lists the gate as its
# first dependency.
for task in publish-email publish-container publish-production; do
    deps=$(awk -v t="[tasks.$task]" '
        $0 == t { inside = 1; next }
        inside && /^\[tasks\./ { exit }
        inside { print }
    ' "$ROOT/Makefile.toml" | tr -d '\n ' | sed -n 's/.*dependencies=\[\([^]]*\)\].*/\1/p')
    first=$(printf '%s' "$deps" | cut -d, -f1 | tr -d '"')
    if [ "$first" = "check-release-freeze" ]; then
        echo "ok - $task runs check-release-freeze first"
    else
        echo "not ok - $task does not run check-release-freeze first (dependencies: ${deps:-none})"
        failures=$((failures + 1))
    fi
done

[ "$failures" -eq 0 ]
