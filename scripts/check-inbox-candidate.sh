#!/usr/bin/env bash
# Check that the committed inbox v2 candidate is exactly what the source builds,
# and that its committed code hash is that build's hash.
#
# The candidate (published-contract/candidate/) is inbox v2's WASM between
# releases; a release freezes it into published-contract/wasm/v2/. Every user's
# inbox id derives from the WASM, and its merge rules cannot be patched after
# publish, so the bytes reviewed must be the bytes shipped.
#
# Usage: scripts/check-inbox-candidate.sh
# Exit status: 0 = matches, 1 = it does not.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$ROOT"
WASM=published-contract/candidate/inbox_v2
HASH_FILE=published-contract/candidate/inbox_v2_code_hash
mkdir -p target
OUT="$(mktemp -d "$ROOT/target/inbox-candidate.XXXXXX")"
trap 'rm -r -- "$OUT"' EXIT

if ! scripts/build-wasm.sh contracts/inbox-v2 contract contract "$OUT/inbox_v2" > "$OUT/build.log" 2>&1; then
    grep -E '^error' -A3 "$OUT/build.log" >&2 || tail -20 "$OUT/build.log" >&2
    echo "FAIL: contracts/inbox-v2 did not build." >&2
    exit 1
fi
built_hash="$(sed -n 's/^code hash: *//p' "$OUT/build.log" | tr -d '[:space:]')"

failed=0
# A contract's rules must be a function of its inputs. The host offers a clock
# and randomness, and the imports check allows them because a delegate may use
# them. A contract that imported either would not be deterministic.
for import in __frnt__time__utc_now __frnt__rand__rand_bytes; do
    if grep -aqF "$import" "$OUT/inbox_v2"; then
        echo "FAIL: contracts/inbox-v2 imports $import." >&2
        failed=1
    fi
done
if ! cmp -s "$OUT/inbox_v2" "$WASM"; then
    # Keep the rebuild: CI uploads it, so the canonical bytes can be committed
    # from a machine whose build differs.
    mkdir -p target/inbox-candidate-rebuilt
    cp "$OUT/inbox_v2" target/inbox-candidate-rebuilt/inbox_v2
    echo "$built_hash" > target/inbox-candidate-rebuilt/inbox_v2_code_hash
    echo "FAIL: $WASM is not what contracts/inbox-v2 builds." >&2
    echo "      rebuilt sha256: $(sha256sum "$OUT/inbox_v2" | cut -d' ' -f1)" >&2
    echo "      Rebuild it with scripts/build-wasm.sh, or take CI's build" >&2
    echo "      (see published-contract/candidate/README.md)." >&2
    failed=1
fi
if [ "$(tr -d '[:space:]' < "$HASH_FILE")" != "$built_hash" ]; then
    echo "FAIL: $HASH_FILE does not hold the built code hash ($built_hash)." >&2
    failed=1
fi
[ "$failed" -eq 0 ] || exit 1
echo "ok: the inbox v2 candidate is the source's build (code hash $built_hash)"
