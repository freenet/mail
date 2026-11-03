#!/usr/bin/env bash
# Check that inbox v2's worst calls stay under decision 8's 2.5 s line, by a
# measure that is the same on every machine: wasmtime fuel, one unit per wasm
# instruction executed.
#
# A contract call is limited to 5 s, and the rules cannot be patched after
# publish, so a change that makes the worst merge slower must be seen before
# it ships. Wall clock depends on the machine; fuel does not.
#
# What runs: tools/inbox-v2-cost/guest, the contract's `is_valid` and `apply`
# behind a C ABI, built with the contract's release profile (opt level 3), on
# the inputs tests/worst_case.rs writes (`dump_the_cost_gate_inputs`): validate
# the worst state; merge two worst states with nothing in common; and the most
# a peer can send in one call, as a delta, as a state, and split over a state
# and a delta (decision 16).
#
# Calibration (2026-11-03, nova: Intel i9-9900K at 3.60 GHz, wasmtime 47.0.4,
# cranelift, no fuel, best of three, rustc 1.99.1):
#
#   case                             fuel             ms     ps/fuel
#   validate a                       12,115,758,969    718   59.3
#   update a, state b                23,413,070,715   1385   59.2
#   update a, delta d1               24,698,679,787   1453   58.8
#   update a, state s1               24,736,087,412   1461   59.1
#   update a, state h1 + delta h2    24,728,863,051   1467   59.3
#   update b, state h1 + delta h2    24,777,951,024   1462   59.0
#
# The slowest run seen of any case was 1666 ms for s1 (machine under load),
# 67.4 ps per fuel. At that rate 2.5 s is 37.1e9 fuel, so the budget is
# 37,000,000,000: at or under the 2.5 s line even at the worst rate seen. The
# worst case uses 67% of it today. The rate depends on the mix of work (RSA,
# Ed25519, ML-DSA, CBOR); if a change moves the mix, re-measure with
# `host time` and record it here.
#
# Usage: scripts/check-inbox-cost.sh
#   INBOX_COST_BUDGET=<fuel> overrides the budget (to show the gate failing).
# Exit status: 0 = every case is under the budget, 1 = one is not.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
BUDGET="${INBOX_COST_BUDGET:-37000000000}"
if ! [[ "$BUDGET" =~ ^[0-9]+$ ]]; then
    echo "FAIL: INBOX_COST_BUDGET is '$BUDGET', not a number of fuel." >&2
    exit 1
fi
TOOLS="$ROOT/tools/inbox-v2-cost"
mkdir -p "$ROOT/target"
DATA="$(mktemp -d "$ROOT/target/inbox-cost.XXXXXX")"
trap 'rm -r -- "$DATA"' EXIT

(cd "$ROOT/contracts/inbox-v2" \
    && INBOX_V2_DUMP_DIR="$DATA" cargo test --locked --test worst_case dump_the_cost_gate_inputs) \
    > "$DATA/dump.log" 2>&1 || { cat "$DATA/dump.log" >&2; echo "FAIL: the inputs were not written." >&2; exit 1; }
for f in params a b d1 s1 h1 h2; do
    [ -s "$DATA/$f.bin" ] || { echo "FAIL: input $f.bin is missing." >&2; exit 1; }
done
(cd "$TOOLS/guest" && cargo build --locked --release --target wasm32-unknown-unknown)
(cd "$TOOLS/host" && cargo build --locked --release)
GUEST="$TOOLS/guest/target/wasm32-unknown-unknown/release/inbox_v2_cost_guest.wasm"
HOST="$TOOLS/host/target/release/inbox-v2-cost-host"

# Each case with the verdict it must reach, so a call that is refused early,
# and so costs little, cannot pass as cheap.
CASES=(
    "validate:a.bin 1"
    "update:a.bin:state:b.bin 1670880"
    "update:a.bin:delta:d1.bin 3791380"
    "update:a.bin:state:s1.bin 3791380"
    "update:a.bin:both:h1.bin:h2.bin 3791380"
    "update:b.bin:both:h1.bin:h2.bin 3791383"
)
names=()
for c in "${CASES[@]}"; do names+=("${c%% *}"); done
"$HOST" fuel "$GUEST" "$DATA" "${names[@]}" > "$DATA/fuel.txt"

failed=0
for c in "${CASES[@]}"; do
    name="${c%% *}" want="${c##* }"
    line="$(grep -F -- "$name ret=" "$DATA/fuel.txt" || true)"
    ret="$(sed -n 's/.* ret=\([0-9]*\) .*/\1/p' <<< "$line")"
    fuel="$(sed -n 's/.* fuel=\([0-9]*\)$/\1/p' <<< "$line")"
    if [ -z "$fuel" ]; then
        echo "FAIL: $name did not run." >&2
        failed=1
    elif [ "$ret" != "$want" ]; then
        echo "FAIL: $name returned $ret, not $want: it did not do the work it is meant to measure." >&2
        failed=1
    elif [ "$fuel" -gt "$BUDGET" ]; then
        echo "FAIL: $name used $fuel fuel, over the budget of $BUDGET (2.5 s)." >&2
        failed=1
    else
        echo "ok - $name: $fuel fuel, $((fuel * 100 / BUDGET))% of the budget"
    fi
done
[ "$failed" -eq 0 ] || exit 1
echo "ok: every worst call is under the 2.5 s budget of $BUDGET fuel"
