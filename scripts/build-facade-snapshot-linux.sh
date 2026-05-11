#!/usr/bin/env bash
# Issue #206. Rebuild published-contract/facade.{wasm,parameters,id.txt}
# from source. ONLY canonical on native linux/amd64 hosts — the bytes
# CI produces under qemu emulation (Docker on macOS / arm64) drift
# slightly even with identical rustc + source, so emulated rebuilds
# WILL NOT match the CI byte-equality gate.
#
# Use this when:
#   • Bumping rustc in rust-toolchain.toml.
#   • Bumping a `=x.y.z` pin under contracts/facade/Cargo.toml or
#     contracts/facade-types/Cargo.toml.
#   • Editing facade source.
#
# On non-Linux/amd64 hosts: do NOT use this. Instead rely on the
# CI bootstrap path:
#   1. Push the change with whatever facade.wasm bytes you have locally.
#   2. The check-contract-wasm.yml job will fail byte-equality and
#      upload the canonical CI-built wasm as a workflow artifact named
#      `facade-wasm-rebuilt-<sha>`.
#   3. Download that artifact, replace published-contract/facade.wasm
#      with its bytes, recompute facade-id.txt via
#      `fdev get-contract-id`, commit, push.
#   4. CI passes.
#
# After this script succeeds (linux/amd64 only), the new bytes are in
# published-contract/. Commit them as part of the same PR as the change
# that caused the rotation. The CI gate fails until both the bytes AND
# the change land in the same PR.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Read the pinned channel from rust-toolchain.toml so the docker image
# tag and the host-native rustup tracker stay in sync.
PINNED_RUSTC=$(awk -F'"' '/^channel/ {print $2; exit}' rust-toolchain.toml)
if [ -z "$PINNED_RUSTC" ] || [ "$PINNED_RUSTC" = "stable" ]; then
    echo "error: rust-toolchain.toml has no explicit version pin (channel=$PINNED_RUSTC)." >&2
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

echo "→ building facade natively (linux/amd64 host with rustc $PINNED_RUSTC)"
(
    cd "$ROOT/contracts/facade"
    cargo build --release --target wasm32-unknown-unknown
)

if [ ! -f "$WASM_OUT" ]; then
    echo "error: build claimed to succeed but $WASM_OUT does not exist" >&2
    exit 1
fi

# Reuse the existing parameters file. The 32-byte verifying key is
# orthogonal to the facade source — it's the publisher identity, not
# something the build produces. If parameters are missing (first-ever
# bootstrap), defer to `cargo make update-published-facade` to mint them
# from the committed test key.
PARAMS="$ROOT/published-contract/facade.parameters"
if [ ! -f "$PARAMS" ]; then
    echo "error: $PARAMS not found." >&2
    echo "       For a first-ever bootstrap, run \`cargo make update-published-facade\`" >&2
    echo "       once natively to mint parameters, then re-run this script to overwrite" >&2
    echo "       the wasm with the canonical Linux-built bytes." >&2
    exit 1
fi

cp "$WASM_OUT" "$ROOT/published-contract/facade.wasm"

NEW_ID=$(CARGO_TARGET_DIR="$ROOT/target" fdev get-contract-id \
    --code "$ROOT/published-contract/facade.wasm" \
    --parameters "$PARAMS")
echo "$NEW_ID" > "$ROOT/published-contract/facade-id.txt"

echo ""
echo "✓ facade snapshot regenerated:"
echo "    facade-id.txt    = $NEW_ID"
echo "    facade.wasm      = $(wc -c < "$ROOT/published-contract/facade.wasm") bytes"
echo "    facade.parameters= $(wc -c < "$PARAMS") bytes"
echo ""
echo "Commit the diff in published-contract/ alongside the change that"
echo "rotated the bytes. The CI byte-equality gate will fail until both"
echo "land in the same PR."
