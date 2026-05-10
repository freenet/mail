#!/usr/bin/env bash
# Issue #200 / Phase 1.
#
# The facade contract's reason to exist is a stable contract ID across
# releases. Contract id = hash(facade_wasm, facade_parameters). Both must
# stay byte-identical. This script rebuilds the facade wasm from source
# and compares against the committed `published-contract/facade.wasm`.
#
# A drift here means a workspace dep change leaked into facade.wasm
# (typical cause: dioxus / chrono / freenet-stdlib / ed25519-dalek bump).
# That rotates the facade contract id and breaks every bookmarked URL.
# Fix the regression OR consciously accept the rotation, regenerate the
# committed snapshot, and bump documentation.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Issue #198: facade lives in its own workspace at contracts/facade/ with
# a separate Cargo.lock. Build artifacts go under contracts/facade/target/.
WASM_OUT="$ROOT/contracts/facade/target/wasm32-unknown-unknown/release/freenet_email_facade.wasm"
COMMITTED="$ROOT/published-contract/facade.wasm"

if [ ! -f "$COMMITTED" ]; then
    echo "warn: $COMMITTED missing — first run? Skipping byte-equality check." >&2
    exit 0
fi

# Build with the same flags the publish pipeline uses. Use the facade's
# own manifest + lockfile (issue #198).
(
    cd "$ROOT/contracts/facade"
    cargo build --release --target wasm32-unknown-unknown
)

if ! cmp -s "$WASM_OUT" "$COMMITTED"; then
    echo "FAIL: facade wasm drift detected." >&2
    echo "  built:     $WASM_OUT ($(wc -c < "$WASM_OUT") bytes, $(shasum -a 256 "$WASM_OUT" | cut -d' ' -f1))" >&2
    echo "  committed: $COMMITTED ($(wc -c < "$COMMITTED") bytes, $(shasum -a 256 "$COMMITTED" | cut -d' ' -f1))" >&2
    echo "" >&2
    echo "If this drift is intentional (e.g. a deliberate facade upgrade)," >&2
    echo "regenerate the committed snapshot:" >&2
    echo "  cargo make update-published-facade" >&2
    echo "  git add published-contract/facade.{wasm,parameters} published-contract/facade-id.txt" >&2
    echo "Then update RELEASING.md / AGENTS.md to record the new facade id." >&2
    exit 1
fi

echo "ok: facade wasm matches committed snapshot ($(wc -c < "$COMMITTED") bytes)"
