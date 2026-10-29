#!/usr/bin/env bash
# Check that the committed mail-delegate candidate is exactly what the source
# builds, and that its committed code hash is that build's hash.
#
# The candidate (published-contract/candidate/) is the mail delegate's WASM
# between releases; a release freezes it into published-contract/wasm/v2/.
# A delegate's key is derived from its WASM, so the committed bytes ARE the
# key users' data lives under: a source change not rebuilt into the
# candidate would ship a delegate other than the one reviewed.
#
# Usage: scripts/check-delegate-candidate.sh
# Exit status: 0 = matches, 1 = it does not.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$ROOT"
WASM=published-contract/candidate/mail_delegate
HASH_FILE=published-contract/candidate/mail_delegate_code_hash
mkdir -p target
OUT="$(mktemp -d "$ROOT/target/delegate-candidate.XXXXXX")"
trap 'rm -r -- "$OUT"' EXIT

scripts/build-wasm.sh delegates/mail-delegate delegate freenet-main-delegate \
    "$OUT/mail_delegate" > "$OUT/build.log"
built_hash="$(sed -n 's/^code hash: *//p' "$OUT/build.log" | tr -d '[:space:]')"

failed=0
if ! cmp -s "$OUT/mail_delegate" "$WASM"; then
    # Keep the rebuild: CI uploads it, so the canonical bytes can be
    # committed from a machine whose build differs.
    mkdir -p target/delegate-candidate-rebuilt
    cp "$OUT/mail_delegate" target/delegate-candidate-rebuilt/mail_delegate
    echo "$built_hash" > target/delegate-candidate-rebuilt/mail_delegate_code_hash
    echo "FAIL: $WASM is not what delegates/mail-delegate builds." >&2
    echo "      rebuilt sha256: $(sha256sum "$OUT/mail_delegate" | cut -d' ' -f1)" >&2
    echo "      Rebuild it with scripts/build-wasm.sh, or take CI's build" >&2
    echo "      (see published-contract/candidate/README.md)." >&2
    failed=1
fi
if [ "$(tr -d '[:space:]' < "$HASH_FILE")" != "$built_hash" ]; then
    echo "FAIL: $HASH_FILE does not hold the built code hash ($built_hash)." >&2
    failed=1
fi
[ "$failed" -eq 0 ] || exit 1
echo "ok: the mail-delegate candidate is the source's build (code hash $built_hash)"
