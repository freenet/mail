#!/usr/bin/env bash
# Build every contract and delegate crate to WASM the way a new generation
# would be built (scripts/build-wasm.sh: build paths remapped, and the output
# refused if any build-machine path survives).
#
# The shipped bytes are frozen under published-contract/wasm/, so nothing
# else compiles these sources for wasm32. This keeps them building, and keeps
# build-wasm.sh and check-wasm-paths.sh working, for the day a new generation
# is needed. The output is thrown away; it need not match the frozen v1 bytes
# (those were built before path remapping and on another toolchain).
#
# Usage: scripts/check-wasm-builds.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$ROOT"
mkdir -p target
OUT="$(mktemp -d "$ROOT/target/wasm-builds.XXXXXX")"
trap 'rm -r -- "$OUT"' EXIT

# <crate dir> <kind> <features> <output name>
CRATES=(
    "contracts/inbox contract contract freenet_email_inbox"
    "contracts/web-container contract freenet-main-contract,contract freenet_email_app_web"
    "modules/antiflood-tokens/contracts/token-allocation-record contract freenet-main-contract freenet_token_allocation_record"
    "modules/antiflood-tokens/delegates/token-generator delegate freenet-main-delegate freenet_token_generator"
    "modules/identity-management delegate freenet-main-delegate,contract identity_management"
    "modules/mail-local-state delegate freenet-main-delegate,contract mail_local_state"
)
for row in "${CRATES[@]}"; do
    read -r dir kind features name <<< "$row"
    echo "== $dir"
    scripts/build-wasm.sh "$dir" "$kind" "$features" "$OUT/$name"
done
echo "all contract and delegate crates build to WASM with no build-machine paths"
