#!/usr/bin/env bash
# Generate the production ed25519 keypair used to sign release webapps.
#
# The key is written to the path in $WEB_CONTAINER_KEY_FILE, defaulting to
# ~/.config/freenet-email/web-container-keys.toml. This file is NEVER
# committed — losing it means rotating the production contract ID.
#
# Usage:
#     scripts/generate-production-key.sh
#     WEB_CONTAINER_KEY_FILE=/custom/path.toml scripts/generate-production-key.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KEY_FILE="${WEB_CONTAINER_KEY_FILE:-$HOME/.config/freenet-email/web-container-keys.toml}"

if [ -f "$KEY_FILE" ]; then
    echo "error: key file already exists at $KEY_FILE" >&2
    echo "" >&2
    echo "Overwriting would rotate the production contract ID and invalidate" >&2
    echo "every previously-signed release. If that's actually what you want:" >&2
    echo "" >&2
    echo "  1. Back up the existing file somewhere safe first" >&2
    echo "  2. Delete it: rm $KEY_FILE" >&2
    echo "  3. Re-run this script" >&2
    echo "" >&2
    exit 1
fi

KEY_DIR="$(dirname "$KEY_FILE")"
mkdir -p "$KEY_DIR"
chmod 700 "$KEY_DIR" 2>/dev/null || true

echo "generating fresh ed25519 keypair at $KEY_FILE..."
cd "$REPO_ROOT"
cargo run --quiet -p web-container-sign -- generate --output "$KEY_FILE"

chmod 600 "$KEY_FILE"

echo ""
echo "✅ wrote $KEY_FILE"
echo ""
echo "IMPORTANT: back this file up NOW to somewhere offline and durable."
echo ""
echo "The public verifying key becomes part of the production contract ID"
echo "via hash(wasm, parameters). If you lose this file:"
echo "  • You cannot sign another release under the same contract ID."
echo "  • You must rotate: generate a new key, publish the new ID, and"
echo "    notify every existing user to point their clients at the new one."
echo ""
echo "Suggested backup options (pick at least two):"
echo "  • Password manager with secure notes (1Password, Bitwarden)"
echo "  • Encrypted USB stored in a safe"
echo "  • Printed QR code in a fire-safe"
echo ""
