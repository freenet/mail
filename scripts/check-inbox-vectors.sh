#!/usr/bin/env bash
# Check that contracts/inbox-v2/tests/fixtures/vectors.txt is exactly what
# vectors.py writes.
#
# vectors.py is a second implementation of the inbox's byte layouts, written
# from the spec; tests/vectors.rs compares the contract against vectors.txt. A
# hand edit of vectors.txt, or a script left out of step with it, would make
# that comparison mean nothing, so the file is regenerated here and diffed.
#
# Needs cbor2 and b3sum. The script runs isolated (python3 -I), so cbor2 must
# be importable without the user site: set VECTORS_PYTHON to an interpreter
# that has it, such as a venv's (CI pins cbor2 5.8.0 and b3sum 1.8.5).
#
# Usage: scripts/check-inbox-vectors.sh
# Exit status: 0 = they match, 1 = they do not, or the script could not run.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
DIR="$ROOT/contracts/inbox-v2/tests/fixtures"
PYTHON="${VECTORS_PYTHON:-python3}"
mkdir -p "$ROOT/target"
OUT="$(mktemp "$ROOT/target/vectors.XXXXXX")"
trap 'rm -f -- "$OUT"' EXIT

if ! (cd "$DIR" && "$PYTHON" -I vectors.py) > "$OUT"; then
    echo "FAIL: vectors.py did not run (it needs cbor2 and b3sum)." >&2
    exit 1
fi
if ! diff -u "$DIR/vectors.txt" "$OUT" >&2; then
    echo "FAIL: vectors.txt is not what vectors.py writes." >&2
    exit 1
fi
echo "ok: vectors.txt is what vectors.py writes ($(wc -l < "$OUT") vectors)"
