#!/usr/bin/env bash
# Run `fdev verify-merge` (core's own merge-law verifier) on the inbox v2
# candidate, over states the crate's generator writes, and count its verdicts.
#
# A verdict is explicit when the verifier says a case held or was violated.
# Inconclusive is not a pass: this fails unless every case held, and it fails if
# the verifier ran fewer cases than asked for, saw fewer states than it was
# given, or does not know the subcommand (an fdev older than the laws).
#
# The candidate (published-contract/candidate/inbox_v2) is what `fdev build`
# writes: a 40-byte header, then the WASM. The verifier wants the WASM alone.
#
# Usage: scripts/check-fdev-verify-merge.sh [--cases N] [--corpus DIR] [--wasm FILE]
#   --corpus  a directory holding params.bin and state-*.bin, instead of
#             generating one (the guard in check-guards-fail.sh uses it)
#   --wasm    a candidate-format file to check, instead of the committed one
# Environment: FDEV names the binary (default: fdev on PATH).
# Exit status: 0 = every case held, 1 = anything else.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
FDEV="${FDEV:-fdev}"
CASES=200
CORPUS=""
CANDIDATE="$ROOT/published-contract/candidate/inbox_v2"
while [ $# -gt 0 ]; do
    case "$1" in
        --cases) CASES="$2"; shift ;;
        --corpus) CORPUS="$2"; shift ;;
        --wasm) CANDIDATE="$2"; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

mkdir -p "$ROOT/target"
WORK="$(mktemp -d "$ROOT/target/verify-merge.XXXXXX")"
trap 'rm -r -- "$WORK"' EXIT

if ! "$FDEV" verify-merge --help > /dev/null 2>&1; then
    echo "FAIL: $FDEV has no verify-merge subcommand ($("$FDEV" --version 2>&1 | head -1))." >&2
    exit 1
fi

# The header is 40 bytes; the WASM magic must follow it.
if [ "$(tail -c +41 "$CANDIDATE" | head -c 4 | od -An -tx1 | tr -d ' \n')" != "0061736d" ]; then
    echo "FAIL: $CANDIDATE is not a 40-byte header and a WASM module." >&2
    exit 1
fi
tail -c +41 "$CANDIDATE" > "$WORK/inbox_v2.wasm"

if [ -z "$CORPUS" ]; then
    CORPUS="$WORK/corpus"
    mkdir -p "$CORPUS"
    (cd "$ROOT/contracts/inbox-v2" \
        && INBOX_CAPTURE_DIR="$CORPUS" cargo test --locked --test merge_laws capture_states_for_fdev) \
        > "$WORK/capture.log" 2>&1 || { cat "$WORK/capture.log" >&2; exit 1; }
fi
states=()
for f in "$CORPUS"/state-*.bin; do
    [ -e "$f" ] && states+=(--state "$f")
done
given=$(( ${#states[@]} / 2 ))
if [ "$given" -lt 12 ] || [ ! -s "$CORPUS/params.bin" ]; then
    echo "FAIL: the corpus has $given states and no usable params.bin (want at least 12)." >&2
    exit 1
fi

status=0
"$FDEV" verify-merge --wasm "$WORK/inbox_v2.wasm" --params "$CORPUS/params.bin" \
    "${states[@]}" --max-cases "$CASES" --json > "$WORK/report.json" 2> "$WORK/report.err" || status=$?

python3 -I - "$WORK/report.json" "$given" "$CASES" "$status" << 'EOF' || exit 1
import json, sys
path, given, cases, status = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
try:
    r = json.load(open(path))
except ValueError:
    print("FAIL: fdev verify-merge wrote no report (exit status %d)." % status, file=sys.stderr)
    sys.exit(1)
held, ran = r["holds"], r["cases_run"]
print("verify-merge: %d states, %d cases, %d held, %d violations, %d inconclusive"
      % (r["corpus_states"], ran, held, r["violations"], r["inconclusive"]))
problems = []
if r["corpus_states"] != given:
    problems.append("saw %d of the %d states given" % (r["corpus_states"], given))
if ran < cases:
    problems.append("ran %d cases, asked for %d" % (ran, cases))
if r["violations"] or r["enforceable_violations"] or r["diagnostic_violations"]:
    problems.append("the merge violated a law: %s" % json.dumps(r["findings"])[:2000])
if r["inconclusive"]:
    problems.append("%d inconclusive (not a pass): %s" % (r["inconclusive"], r["inconclusive_reasons"][:3]))
if held != ran:
    problems.append("only %d of %d cases held" % (held, ran))
if status != 0 and not problems:
    problems.append("fdev exited with status %d" % status)
if problems:
    for p in problems:
        print("FAIL: " + p, file=sys.stderr)
    sys.exit(1)
EOF
echo "ok: fdev verify-merge held on every case ($("$FDEV" --version 2>&1 | head -1))"
