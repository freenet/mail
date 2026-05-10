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

# Sanity: app IDs are base58 of a 32-byte hash, which always encodes to
# 43 or 44 chars depending on the leading-byte zero count. Reject anything
# else — narrow regex catches paths, URLs, and truncated/extended ids that
# would otherwise be silently accepted and later rejected on-chain.
if ! printf '%s' "$CURRENT_APP_ID" | grep -Eq '^[1-9A-HJ-NP-Za-km-z]{43,44}$'; then
    echo "error: '$CURRENT_APP_ID' does not look like a base58-encoded 32-byte contract id (expected 43-44 base58 chars)" >&2
    exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/contracts/facade-loader/src/index.html.tmpl"
DIST_DIR="$ROOT/contracts/facade-loader/dist"
DEST="$DIST_DIR/index.html"

if [ ! -f "$SRC" ]; then
    echo "error: $SRC not found" >&2
    exit 1
fi

# Refuse to substitute against a template that doesn't contain the
# placeholder — silent no-op would produce a broken loader that redirects
# to /v1/contract/web/__CURRENT_APP_ID__/.
if ! grep -q '__CURRENT_APP_ID__' "$SRC"; then
    echo "error: $SRC has no __CURRENT_APP_ID__ placeholder" >&2
    exit 1
fi

mkdir -p "$DIST_DIR"

# sed escape: base58 alphabet excludes `|`, `/`, `\`, `&` — plain
# substitution with `|` delimiter is safe.
sed "s|__CURRENT_APP_ID__|$CURRENT_APP_ID|g" "$SRC" > "$DEST"

# Belt-and-braces: if any placeholder survived (template malformed,
# multiple placeholders missed by sed pattern), bail.
if grep -q '__CURRENT_APP_ID__' "$DEST"; then
    echo "error: $DEST still contains __CURRENT_APP_ID__ after substitution" >&2
    rm -f "$DEST"
    exit 1
fi

echo "wrote $DEST (current_app_id=$CURRENT_APP_ID, $(wc -c < "$DEST") bytes)"
