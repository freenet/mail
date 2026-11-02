#!/usr/bin/env bash
# Refuse a webapp build with scrub off. A build has scrub only if it was made
# with FREENET_MAIL_SCRUB=1 (ui/src/migration/scrub.rs), and off is silent: the
# release would work, and the old copy of every user's keys would stay in the
# v0.2.x delegates for good. The WASM holds the marker only if scrub is
# compiled in, so this reads the build that is about to be published, and not
# the flags that were meant to produce it.
#
# Usage: scripts/check-release-scrub.sh [--dir DIR]
#   DIR is the build's public directory. The option exists for the tests.
# Exit status: 0 = the build has scrub, 1 = refused, 2 = usage error.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
DIR="$ROOT/target/dx/app/release/web/public"
if [ "${1:-}" = "--dir" ]; then
    DIR="${2:?usage: $0 [--dir DIR]}"
elif [ $# -gt 0 ]; then
    echo "usage: $0 [--dir DIR]" >&2
    exit 2
fi
MARKER="freenet-mail:scrub-built-in"

found=0
while IFS= read -r -d '' file; do
    found=1
    if ! grep -a -q -F -- "$MARKER" "$file"; then
        echo "error: $file has scrub off: it was built without FREENET_MAIL_SCRUB=1." >&2
        echo "       Publish with \`cargo make publish-production\`, which sets it." >&2
        exit 1
    fi
done < <(find "$DIR" -type f -name '*.wasm' -print0 2>/dev/null)
if [ "$found" -eq 0 ]; then
    echo "error: no WASM under $DIR to check for scrub" >&2
    exit 1
fi
echo "ok: the build has scrub"
