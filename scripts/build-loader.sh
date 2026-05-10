#!/usr/bin/env bash
# Build the facade loader by substituting CURRENT_APP_ID into the template.
# Issue #200 / Phase 1.
#
# Usage:
#   scripts/build-loader.sh <current_app_id>
#
# Writes contracts/facade-loader/dist/index.html. The facade contract's
# freenet.toml lists `dist/` as its webapp source-dir, so a subsequent
# `cargo make build-facade` packages this loader as the facade webapp.

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <current_app_id>" >&2
    exit 1
fi

CURRENT_APP_ID="$1"

# Sanity: app IDs are base58 of a 32-byte hash. Length is ~43-44 chars and
# must be base58 alphabet. Catches obvious mistakes (path/URL pasted in).
if ! printf '%s' "$CURRENT_APP_ID" | grep -Eq '^[1-9A-HJ-NP-Za-km-z]{32,50}$'; then
    echo "error: '$CURRENT_APP_ID' does not look like a base58 contract id" >&2
    exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/contracts/facade-loader/src/index.html.tmpl"
DIST_DIR="$ROOT/contracts/facade-loader/dist"
DEST="$DIST_DIR/index.html"

mkdir -p "$DIST_DIR"

# sed escape: contract IDs are base58 with no `/`, `&`, or `\`, so a plain
# substitution is safe.
sed "s|__CURRENT_APP_ID__|$CURRENT_APP_ID|g" "$SRC" > "$DEST"

echo "wrote $DEST (current_app_id=$CURRENT_APP_ID, $(wc -c < "$DEST") bytes)"
