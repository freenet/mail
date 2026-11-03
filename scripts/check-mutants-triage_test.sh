#!/usr/bin/env bash
# Show check-mutants-triage.sh passing and failing, on hand-written outcome
# files and triage files.
#
# Exit status: 0 = the check did what it should every time, 1 = it did not.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
mkdir -p "$ROOT/target"
DIR="$(mktemp -d "$ROOT/target/triage-test.XXXXXX")"
trap 'rm -r -- "$DIR"' EXIT
failures=0

printf '%s\n' 'src/merge.rs:10:5: replace a with b in f' \
    'src/sync.rs:20:9: replace c with d in g' > "$DIR/missed.txt"
printf '%s\n' '- `src/merge.rs: replace a with b in f` an equivalent mutant' \
    '- `src/sync.rs: replace c with d in g` the reason' > "$DIR/full.md"
printf '%s\n' '- `src/merge.rs: replace a with b in f` an equivalent mutant' > "$DIR/short.md"
printf '%s\n' '- `src/merge.rs: replace a with b in f` x' \
    '- `src/sync.rs: replace c with d in g` y' \
    '- `src/sync.rs: replace e with f in h` a survivor that has since died' > "$DIR/stale.md"

expect() { # want(pass|fail) label message args...
    local want="$1" label="$2" message="$3" got=pass
    shift 3
    "$ROOT/scripts/check-mutants-triage.sh" "$@" > "$DIR/out" 2>&1 || got=fail
    if [ "$got" = "$want" ] && grep -q -F -- "$message" "$DIR/out"; then
        echo "ok - $label"
    else
        echo "not ok - $label (got $got)"
        cat "$DIR/out"
        failures=$((failures + 1))
    fi
}

expect pass "every survivor triaged, line numbers ignored" "ok: 2 survivors" \
    --triage "$DIR/full.md" "$DIR/missed.txt"
expect fail "a survivor with no triage line" "survivor with no triage line: src/sync.rs: replace c with d in g" \
    --triage "$DIR/short.md" "$DIR/missed.txt"
expect pass "a stale line is ignored on a partial run" "ok: 2 survivors" \
    --triage "$DIR/stale.md" "$DIR/missed.txt"
expect fail "a stale line fails a complete run" "no longer survives: src/sync.rs: replace e with f in h" \
    --complete --triage "$DIR/stale.md" "$DIR/missed.txt"
expect pass "a complete run with nothing stale" "ok: 2 survivors" \
    --complete --triage "$DIR/full.md" "$DIR/missed.txt"

[ "$failures" -eq 0 ] || exit 1
echo "ok: the triage check passes and fails as it should"
