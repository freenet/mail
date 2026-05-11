#!/usr/bin/env bash
# Issue #200 + #206.
#
# The facade contract's reason to exist is a stable contract ID across
# releases. Contract id = hash(facade_wasm, facade_parameters). Both must
# stay byte-identical. This script rebuilds the facade wasm from source
# and compares against the committed `published-contract/facade.wasm`.
#
# A drift here means a workspace dep change leaked into facade.wasm
# (typical cause: dioxus / chrono / freenet-stdlib / ed25519-dalek bump)
# OR a rustc bump that wasn't paired with a snapshot regeneration.
# That rotates the facade contract id and breaks every bookmarked URL.
# Fix the regression OR consciously accept the rotation, regenerate the
# committed snapshot via scripts/build-facade-snapshot-linux.sh, and bump
# documentation.
#
# Snapshot canonicalization (issue #206): the committed bytes are
# produced on linux/amd64 with the rustc version pinned in
# rust-toolchain.toml. CI runs on linux/amd64 with the same pin, so the
# rebuild matches. Other host arch/OS combos (e.g. macOS arm64 dev
# machines) produce different wasm bytes — same source, different
# codegen — and will trigger a spurious failure here. Detect non-canonical
# hosts and skip with a warning so local devs aren't blocked.

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

# Snapshot canonicalization (issue #206). The committed bytes only match
# rebuilds on the same canonical host the snapshot was produced on:
# linux/amd64 with the pinned rustc. Skip with a warning otherwise.
HOST_OS=$(uname -s)
HOST_ARCH=$(uname -m)
if [ "$HOST_OS" != "Linux" ] || [ "$HOST_ARCH" != "x86_64" ]; then
    echo "warn: facade byte-equality check is canonical only on linux/amd64."
    echo "      This host is $HOST_OS/$HOST_ARCH — skipping rebuild + compare."
    echo "      To rebuild the snapshot deliberately, run:"
    echo "        scripts/build-facade-snapshot-linux.sh"
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
