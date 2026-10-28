#!/usr/bin/env bash
# Issue #206. Rebuild published-contract/container{.wasm,.parameters,-id.txt}
# from source. ONLY canonical on native linux/amd64 hosts — the bytes
# CI produces under qemu emulation (Docker on macOS / arm64) drift
# slightly even with identical rustc + source, so emulated rebuilds
# WILL NOT match the CI byte-equality gate.
#
# Use this when:
#   • Bumping rustc in contracts/facade/rust-toolchain.toml.
#   • Bumping a `=x.y.z` pin under contracts/facade/Cargo.toml or
#     contracts/facade-types/Cargo.toml.
#   • Editing the container contract source.
#
# On non-Linux/amd64 hosts: do NOT use this. Instead rely on the
# CI bootstrap path:
#   1. Push the change with whatever container.wasm bytes you have locally.
#   2. The check-contract-wasm.yml job will fail byte-equality and
#      upload the canonical CI-built wasm as a workflow artifact named
#      `facade-wasm-rebuilt-<sha>`.
#   3. Download that artifact, replace published-contract/container.wasm
#      with its bytes, recompute container-id.txt via
#      `fdev get-contract-id`, commit, push.
#   4. CI passes.
#
# Regenerating the snapshot moves the container contract id, which is the
# bookmarkable URL every user has. It is a deliberate re-key: after this
# script, update CONTAINER_CONTRACT_ID in scripts/check-frozen-artifacts.sh
# and the container rows of published-contract/frozen.sha256, and expect
# scripts/check-frozen-immutable.sh to flag the change for review.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# The pinned channel, from contracts/facade/rust-toolchain.toml.
PINNED_RUSTC=$(awk -F'"' '/^channel/ {print $2; exit}' contracts/facade/rust-toolchain.toml)
if [ -z "$PINNED_RUSTC" ] || [ "$PINNED_RUSTC" = "stable" ]; then
    echo "error: contracts/facade/rust-toolchain.toml has no explicit version pin (channel=$PINNED_RUSTC)." >&2
    echo "       Pin to an exact version (e.g. 1.95.0) before regenerating the snapshot." >&2
    exit 1
fi

WASM_OUT="$ROOT/contracts/facade/target/wasm32-unknown-unknown/release/freenet_email_facade.wasm"

HOST_OS=$(uname -s)
HOST_ARCH=$(uname -m)
if [ "$HOST_OS" != "Linux" ] || [ "$HOST_ARCH" != "x86_64" ]; then
    echo "error: this host is $HOST_OS/$HOST_ARCH; canonical snapshot bytes can only" >&2
    echo "       be produced on native linux/amd64 (qemu emulation drifts vs CI)." >&2
    echo "       Use the CI bootstrap path documented at the top of this script." >&2
    exit 1
fi

echo "→ building the container contract natively (linux/amd64 host with rustc $PINNED_RUSTC)"
(
    cd "$ROOT/contracts/facade"
    # shellcheck source=scripts/container-toolchain.sh
    . "$ROOT/scripts/container-toolchain.sh"
    cargo build --release --target wasm32-unknown-unknown
)

if [ ! -f "$WASM_OUT" ]; then
    echo "error: build claimed to succeed but $WASM_OUT does not exist" >&2
    exit 1
fi

# Reuse the existing parameters file. The 32-byte verifying key is
# orthogonal to the container contract source — it's the publisher identity, not
# something the build produces. If parameters are missing (first-ever
# bootstrap), defer to `cargo make update-published-container` to mint them
# from the committed test key.
PARAMS="$ROOT/published-contract/container.parameters"
if [ ! -f "$PARAMS" ]; then
    echo "error: $PARAMS not found." >&2
    echo "       For a first-ever bootstrap, run \`cargo make update-published-container\`" >&2
    echo "       once natively to mint parameters, then re-run this script to overwrite" >&2
    echo "       the wasm with the canonical Linux-built bytes." >&2
    exit 1
fi

cp "$WASM_OUT" "$ROOT/published-contract/container.wasm"

NEW_ID=$(CARGO_TARGET_DIR="$ROOT/target" fdev get-contract-id \
    --code "$ROOT/published-contract/container.wasm" \
    --parameters "$PARAMS")
echo "$NEW_ID" > "$ROOT/published-contract/container-id.txt"

echo ""
echo "✓ container snapshot regenerated:"
echo "    container-id.txt    = $NEW_ID"
echo "    container.wasm      = $(wc -c < "$ROOT/published-contract/container.wasm") bytes"
echo "    container.parameters= $(wc -c < "$PARAMS") bytes"
echo ""
echo "This moves the container contract id (the bookmarkable URL). Update"
echo "CONTAINER_CONTRACT_ID in scripts/check-frozen-artifacts.sh and the"
echo "container rows of published-contract/frozen.sha256 in the same PR."
