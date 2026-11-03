#!/usr/bin/env bash
# Branch coverage of inbox v2's rules: every arm visited or allowed.
#
# Runs the crate's tests under `cargo llvm-cov --branch` on a nightly (branch
# coverage is an unstable rustc flag) and hands the JSON to
# check-branch-coverage.py, which fails on any arm no test visits and on any
# allowlist entry (contracts/inbox-v2/coverage-allowlist.toml) that excuses
# nothing.
#
# llvm-cov instruments every dependency as well, so the signature code in the
# merge-law fuzzer runs far slower than it does in a plain test run. Set
# FORK_SEEDS low (the workflow uses 3); every arm the full run reaches is
# reached by the deterministic tests, and the allowlist holds the rest.
#
# Usage: scripts/check-branch-coverage.sh
# Environment: COVERAGE_NIGHTLY names the toolchain (default: nightly).
# Exit status: 0 = every arm visited or allowed, 1 = otherwise.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
NIGHTLY="${COVERAGE_NIGHTLY:-nightly}"
OUT="$ROOT/target/branch-coverage"
mkdir -p "$OUT"

(cd "$ROOT/contracts/inbox-v2" \
    && CARGO_TARGET_DIR="$OUT/target" cargo "+$NIGHTLY" llvm-cov --branch --locked \
        --json --output-path "$OUT/report.json") > "$OUT/run.log" 2>&1 \
    || { tail -40 "$OUT/run.log" >&2; echo "FAIL: the instrumented test run failed." >&2; exit 1; }

python3 -I "$ROOT/scripts/check-branch-coverage.py" "$OUT/report.json" \
    "$ROOT/contracts/inbox-v2" "$ROOT/contracts/inbox-v2/coverage-allowlist.toml"
