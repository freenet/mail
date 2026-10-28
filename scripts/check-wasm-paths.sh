#!/usr/bin/env bash
# Refuse a WASM artifact that still contains a build-machine path.
#
# Panic-location and debug strings embed source paths. If any of them names
# this machine (a home directory, CARGO_HOME, RUSTUP_HOME, the checkout or the
# target dir), the bytes — and so the contract/delegate key — depend on where
# the build ran, and nobody else can reproduce them (freenet/mail#348).
#
# Usage: scripts/check-wasm-paths.sh <wasm-file> [<extra-path-to-forbid> ...]
# Exit status: 0 = clean, 1 = a build-machine path was found, 2 = usage error.

set -euo pipefail

if [ $# -lt 1 ] || [ ! -f "$1" ]; then
    echo "usage: $0 <wasm-file> [<extra-path-to-forbid> ...]" >&2
    exit 2
fi
FILE="$1"
shift

FORBIDDEN=("/home/" "/Users/" "/root/" "C:\\Users\\")
for p in "${HOME:-}" "${CARGO_HOME:-}" "${RUSTUP_HOME:-}" "$@"; do
    [ -n "$p" ] && FORBIDDEN+=("$p")
done

found=0
for p in "${FORBIDDEN[@]}"; do
    if grep -a -q -F -- "$p" "$FILE"; then
        count=$(grep -a -o -F -- "$p" "$FILE" | wc -l)
        echo "error: $FILE contains the build-machine path '$p' ($count occurrence(s))" >&2
        found=1
    fi
done

if [ "$found" -ne 0 ]; then
    echo "Rebuild with scripts/build-wasm.sh, which remaps these paths." >&2
    exit 1
fi
echo "ok: no build-machine paths in $FILE"
