#!/usr/bin/env bash
# The sharded guard run must cover every guard exactly once: the union of
# `check-guards-fail.sh --shard I/N --list` over I equals the unsharded list,
# by count and by name, no name is in two shards, and no shard is empty.
# Runs no mutation, so it is quick. N comes from the CI matrix, and the matrix
# must be exactly 0..N-1 with the run line saying /N: a leg dropped from it
# would leave a share of the guards unrun with every job still green.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
WORKFLOW="$ROOT/.github/workflows/check-contract-wasm.yml"
legs=$(sed -n 's/^ *shard: \[\(.*\)\]$/\1/p' "$WORKFLOW" | tr -d ' ')
[ -n "$legs" ] && [ "$(wc -l <<< "$legs")" -eq 1 ] \
    || { echo "FAIL: no single shard matrix in $WORKFLOW"; exit 1; }
N=$(($(tr -cd ',' <<< "$legs" | wc -c) + 1))
want=$(seq -s, 0 $((N - 1)))
[ "$legs" = "$want" ] || { echo "FAIL: the matrix is [$legs], want [$want]"; exit 1; }
grep -q -F -- "--shard \${{ matrix.shard }}/$N" "$WORKFLOW" \
    || { echo "FAIL: the guard step does not run --shard I/$N"; exit 1; }
T="$(mktemp -d)"
trap 'rm -r -- "$T"' EXIT
"$ROOT/scripts/check-guards-fail.sh" --list | sort > "$T/all"
total=$(wc -l < "$T/all")
[ "$total" -gt 0 ] || { echo "FAIL: no guards listed"; exit 1; }
[ "$(uniq -d < "$T/all" | wc -l)" -eq 0 ] || { echo "FAIL: duplicate guard names:"; uniq -d < "$T/all"; exit 1; }
: > "$T/union"
for ((i = 0; i < N; i++)); do
    "$ROOT/scripts/check-guards-fail.sh" --shard "$i/$N" --list | sort > "$T/s$i"
    c=$(wc -l < "$T/s$i")
    echo "shard $i/$N: $c guards"
    [ "$c" -gt 0 ] || { echo "FAIL: shard $i/$N has no guard"; exit 1; }
    cat "$T/s$i" >> "$T/union"
done
sort "$T/union" > "$T/union.sorted"
if ! diff "$T/all" "$T/union.sorted" > "$T/diff"; then
    echo "FAIL: the shards' guards differ from the full list:"
    cat "$T/diff"
    exit 1
fi
echo "ok - $total guards, each in exactly one of $N shards"
