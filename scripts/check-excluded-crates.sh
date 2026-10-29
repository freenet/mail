#!/usr/bin/env bash
# Run fmt, clippy or tests in every crate excluded from the workspace (each
# has its own Cargo.lock; see [workspace.exclude] in Cargo.toml). The
# workspace commands never reach them. --locked fails a lockfile that has
# drifted from its manifest.
#
# Usage: scripts/check-excluded-crates.sh fmt|clippy|test

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CRATES=(
    contracts/inbox
    contracts/web-container
    delegates/mail-delegate
    modules/antiflood-tokens/interfaces
    modules/antiflood-tokens/contracts/token-allocation-record
    modules/antiflood-tokens/delegates/token-generator
    modules/identity-management
    modules/mail-local-state
    wire-v1/capture
)

case "${1:-}" in
    fmt) cmd=(cargo fmt -- --check) ;;
    clippy) cmd=(cargo clippy --locked --all-targets -- -D warnings) ;;
    test) cmd=(cargo test --locked) ;;
    *) echo "usage: $0 fmt|clippy|test" >&2; exit 2 ;;
esac

for crate in "${CRATES[@]}"; do
    echo "== $crate: ${cmd[*]}"
    (cd "$ROOT/$crate" && "${cmd[@]}")
done
