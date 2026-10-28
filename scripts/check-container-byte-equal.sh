#!/usr/bin/env bash
# Issue #200 + #206.
#
# The container contract's reason to exist is a stable contract id across
# releases: id = hash(container.wasm, container.parameters), the bookmarkable
# URL. This script rebuilds the container contract from source and compares
# it with the committed `published-contract/container.wasm`.
#
# A drift here means something that feeds the build changed: a dependency
# pin in contracts/facade/Cargo.toml or contracts/facade-types/Cargo.toml,
# the container source, or the rustc pin in contracts/facade/rust-toolchain.toml.
# Any of those would move the URL, so revert the change.
#
# Canonical bytes (issue #206): the committed snapshot was built by CI on
# linux/amd64 with the pinned rustc, and the build embeds the checkout path,
# so the rebuild matches only in CI's checkout path. Elsewhere the bytes
# differ and this check reports drift; on hosts other than linux/amd64 it
# skips with a warning.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Issue #198: the container contract is its own workspace at contracts/facade/
# with a separate Cargo.lock. Build artifacts go under contracts/facade/target/.
WASM_OUT="$ROOT/contracts/facade/target/wasm32-unknown-unknown/release/freenet_email_facade.wasm"
COMMITTED="$ROOT/published-contract/container.wasm"

if [ ! -f "$COMMITTED" ]; then
    echo "FAIL: $COMMITTED is missing; restore it with git checkout -- published-contract/" >&2
    exit 1
fi

HOST_OS=$(uname -s)
HOST_ARCH=$(uname -m)
if [ "$HOST_OS" != "Linux" ] || [ "$HOST_ARCH" != "x86_64" ]; then
    echo "warn: the container byte-equality check is canonical only on linux/amd64."
    echo "      This host is $HOST_OS/$HOST_ARCH — skipping rebuild + compare."
    exit 0
fi

(
    cd "$ROOT/contracts/facade"
    # shellcheck source=scripts/container-toolchain.sh
    . "$ROOT/scripts/container-toolchain.sh"
    cargo build --release --target wasm32-unknown-unknown
)

if ! cmp -s "$WASM_OUT" "$COMMITTED"; then
    echo "FAIL: container wasm drift detected." >&2
    echo "  built:     $WASM_OUT ($(wc -c < "$WASM_OUT") bytes, $(sha256sum "$WASM_OUT" | cut -d' ' -f1))" >&2
    echo "  committed: $COMMITTED ($(wc -c < "$COMMITTED") bytes, $(sha256sum "$COMMITTED" | cut -d' ' -f1))" >&2
    echo "" >&2
    echo "The container contract is frozen: its id is the bookmarkable URL. Revert" >&2
    echo "the dependency, source or toolchain change that moved the bytes." >&2
    exit 1
fi

echo "ok: container wasm matches committed snapshot ($(wc -c < "$COMMITTED") bytes)"
