#!/usr/bin/env bash
# Refuse a release of v0.3.0 or later that would ship the mail delegate in
# a state only meant for development:
#
#   1. the UI still references published-contract/candidate/ (the unfrozen
#      build) instead of the frozen published-contract/wasm/v2/;
#   2. the frozen delegate is missing;
#   3. the frozen delegate was built with the `v1-transition` feature, whose
#      V1AftParams operation hands the identity's signing seed to the app
#      without asking. Proven two ways on real builds: the WASM must not
#      contain the marker string that feature compiles in
#      (handlers::V1_TRANSITION_MARKER), and it must be byte-identical to a
#      fresh build of this source WITHOUT the feature.
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
MARKER="freenet-mail-delegate:v1-transition-enabled"

# Whether dotted version $1 is lower than $2. Plain bash, because release.sh
# also runs on macOS, whose BSD sort has no -V.
version_lt() {
    local IFS=.
    local -a a b
    read -r -a a <<< "$1"
    read -r -a b <<< "$2"
    local i x y
    for i in 0 1 2; do
        x="${a[i]:-0}"
        y="${b[i]:-0}"
        if ((10#$x < 10#$y)); then return 0; fi
        if ((10#$x > 10#$y)); then return 1; fi
    done
    return 1
}

# Strip any pre-release suffix, then compare as versions.
base="${VERSION%%-*}"
if ! [[ "$base" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "error: '$VERSION' is not a version" >&2
    exit 2
fi
if version_lt "$base" 0.3.0; then
    echo "ok: $VERSION predates the mail delegate"
    exit 0
fi

failed=0
if grep -rn 'published-contract/candidate' "$UI_DIR" > /dev/null 2>&1; then
    echo "FAIL: the UI references published-contract/candidate/; freeze the delegate" >&2
    echo "      into published-contract/wasm/v2/ and point the UI there first." >&2
    grep -rn 'published-contract/candidate' "$UI_DIR" >&2 || true
    failed=1
fi
if [ ! -f "$WASM" ]; then
    echo "FAIL: $WASM is missing: v$VERSION must ship a frozen mail delegate." >&2
    exit 1
fi
if grep -a -q -F "$MARKER" "$WASM"; then
    echo "FAIL: $WASM was built with the v1-transition feature (it can hand the" >&2
    echo "      identity's signing seed to the app). Build it without that feature." >&2
    exit 1
fi
mkdir -p "$ROOT/target"
OUT="$(mktemp -d "$ROOT/target/release-delegate.XXXXXX")"
trap 'rm -r -- "$OUT"' EXIT
"$ROOT/scripts/build-wasm.sh" delegates/mail-delegate delegate freenet-main-delegate \
    "$OUT/mail_delegate" > "$OUT/build.log" 2>&1 \
    || { cat "$OUT/build.log" >&2; echo "FAIL: could not build the delegate" >&2; exit 1; }
if ! cmp -s "$OUT/mail_delegate" "$WASM"; then
    echo "FAIL: $WASM is not this source built without v1-transition." >&2
    failed=1
fi
[ "$failed" -eq 0 ] || exit 1
echo "ok: v$VERSION ships this source's mail delegate, built without v1-transition"
