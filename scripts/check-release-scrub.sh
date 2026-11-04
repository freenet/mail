#!/usr/bin/env bash
# Refuse a webapp build with scrub off. A build has scrub only if it was made
# with FREENET_MAIL_SCRUB=1 (ui/src/migration/scrub.rs), and off is silent: the
# release would work, and superseded local stores would never be cleared. The
# WASM holds the marker only if scrub is
# compiled in, so this reads the build that is about to be published, and not
# the flags that were meant to produce it.
#
# With --absent it checks the other way, for a test publish: a build that has
# scrub must not reach a node that may hold real data, whatever the
# environment says (an exported FREENET_MAIL_SCRUB=1 builds it in silently).
#
# Usage: scripts/check-release-scrub.sh [--absent] [--dir DIR]
#   DIR is the build's public directory. The option exists for the tests.
# Exit status: 0 = as wanted, 1 = refused, 2 = usage error.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
DIR="$ROOT/target/dx/app/release/web/public"
ABSENT=0
if [ "${1:-}" = "--absent" ]; then
    ABSENT=1
    shift
fi
if [ "${1:-}" = "--dir" ]; then
    DIR="${2:?usage: $0 [--absent] [--dir DIR]}"
elif [ $# -gt 0 ]; then
    echo "usage: $0 [--absent] [--dir DIR]" >&2
    exit 2
fi
MARKER="freenet-mail:scrub-built-in"
# In the WASM only with the `e2e-probe` feature (ui/src/jobs.rs), the real-node
# tests' build, which lists every kept copy of every identity on the page.
# FREENET_UI_FEATURES, read by build-ui, can put it in silently. No publish
# takes it, a test publish included, except the real-node background proof,
# which sets FREENET_E2E_PROBE_ISO=1 for its publish to the harness's own
# nodes. The variable is read only with --absent.
PROBE_MARKER="freenet-mail:e2e-probe-built-in"
# In the WASM only with the `test-ghost-master` feature (ui/src/ghostkeys.rs):
# inbox parameters name a test Ghost Key master and the page answers its own
# Ghost Key requests with test keys. No publish takes it except the inbox v2
# real-node test, which sets FREENET_TEST_GHOST_ISO=1 for its publish to the
# harness's own nodes. The variable is read only with --absent.
GHOST_MARKER="freenet-mail:test-ghost-master-built-in"

found=0
while IFS= read -r -d '' file; do
    found=$((found + 1))
    if grep -a -q -F -- "$PROBE_MARKER" "$file" \
        && ! { [ "$ABSENT" -eq 1 ] && [ "${FREENET_E2E_PROBE_ISO:-}" = "1" ]; }; then
        echo "error: $file has the e2e-probe test instrumentation: it was built with FREENET_UI_FEATURES=e2e-probe." >&2
        echo "       No publish may carry it. Unset the variable and rebuild." >&2
        exit 1
    fi
    if grep -a -q -F -- "$GHOST_MARKER" "$file" \
        && ! { [ "$ABSENT" -eq 1 ] && [ "${FREENET_TEST_GHOST_ISO:-}" = "1" ]; }; then
        echo "error: $file has the test Ghost Key master: it was built with FREENET_UI_FEATURES=test-ghost-master." >&2
        echo "       No publish may carry it. Unset the variable and rebuild." >&2
        exit 1
    fi
    if [ "$ABSENT" -eq 1 ]; then
        if grep -a -q -F -- "$MARKER" "$file"; then
            echo "error: $file has scrub: it was built with FREENET_MAIL_SCRUB=1." >&2
            echo "       A test publish must not carry it. Unset the variable and rebuild." >&2
            exit 1
        fi
    elif ! grep -a -q -F -- "$MARKER" "$file"; then
        echo "error: $file has scrub off: it was built without FREENET_MAIL_SCRUB=1." >&2
        echo "       Publish with \`cargo make publish-production\`, which sets it." >&2
        exit 1
    fi
done < <(find "$DIR" -type f -name '*.wasm' -print0 2>/dev/null)
if [ "$found" -eq 0 ]; then
    echo "error: no WASM under $DIR to check for scrub" >&2
    exit 1
fi
# build-ui clears this directory. More than one file is an old build left
# beside the new one, and this check could not say which of them ships.
if [ "$found" -gt 1 ]; then
    echo "error: $found WASM files under $DIR: rebuild with \`cargo make build-ui\`" >&2
    exit 1
fi
if [ "$ABSENT" -eq 1 ]; then echo "ok: the build has no scrub"; else echo "ok: the build has scrub"; fi
