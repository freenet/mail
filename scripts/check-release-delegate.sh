#!/usr/bin/env bash
# Refuse a release of v0.3.0 or later that would ship the mail delegate in
# a state only meant for development:
#
#   1. the UI still embeds published-contract/candidate/ (the unfrozen
#      build) instead of the frozen published-contract/wasm/v2/;
#   2. the frozen delegate is missing;
#   3. the frozen delegate was built with the `v1-transition` feature, whose
#      V1AftParams operation hands the identity's signing seed to the app
#      without asking. Detected by the serde field name `generator_seed`,
#      which only that operation's code puts in the WASM.
#
# Releases before 0.3.0 do not ship this delegate and pass.
#
# Usage: scripts/check-release-delegate.sh <version> [--wasm FILE] [--ui-dir DIR]
#   --wasm and --ui-dir override the checked files (for the script's tests).
# Exit status: 0 = ok, 1 = refused, 2 = usage error.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
VERSION="${1:-}"
[ -n "$VERSION" ] || { echo "usage: $0 <version> [--wasm FILE] [--ui-dir DIR]" >&2; exit 2; }
shift
WASM="$ROOT/published-contract/wasm/v2/mail_delegate"
UI_DIR="$ROOT/ui"
while [ $# -gt 0 ]; do
    case "$1" in
        --wasm) WASM="$2"; shift 2 ;;
        --ui-dir) UI_DIR="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

# Strip any pre-release suffix, then compare as versions.
base="${VERSION%%-*}"
if [ "$(printf '%s\n%s\n' "$base" 0.3.0 | sort -V | head -1)" != 0.3.0 ]; then
    echo "ok: $VERSION predates the mail delegate"
    exit 0
fi

failed=0
if grep -rn --include='*.rs' 'published-contract/candidate' "$UI_DIR" > /dev/null 2>&1; then
    echo "FAIL: the UI embeds published-contract/candidate/; freeze the delegate into" >&2
    echo "      published-contract/wasm/v2/ and point the UI there first." >&2
    grep -rn --include='*.rs' 'published-contract/candidate' "$UI_DIR" >&2 || true
    failed=1
fi
if [ ! -f "$WASM" ]; then
    echo "FAIL: $WASM is missing: v$VERSION must ship a frozen mail delegate." >&2
    failed=1
elif grep -a -q -F 'generator_seed' "$WASM"; then
    echo "FAIL: $WASM was built with the v1-transition feature (it can hand the" >&2
    echo "      identity's signing seed to the app). Build it without that feature." >&2
    failed=1
fi
[ "$failed" -eq 0 ] || exit 1
echo "ok: v$VERSION ships a frozen mail delegate built without v1-transition"
