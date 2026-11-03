#!/usr/bin/env bash
# Show check-branch-coverage.py passing and failing, on a hand-made crate and
# a hand-made llvm-cov report.
#
# Exit status: 0 = the check did what it should every time, 1 = it did not.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
mkdir -p "$ROOT/target"
DIR="$(mktemp -d "$ROOT/target/coverage-test.XXXXXX")"
trap 'rm -r -- "$DIR"' EXIT
failures=0

mkdir -p "$DIR/crate/src"
printf '%s\n' 'fn f(a: bool) -> u8 {' '    if a {' '        1' '    } else {' '        2' '    }' '}' \
    > "$DIR/crate/src/lib.rs"

# One branch on line 2: [line, col, line, col, taken, not taken, file, expanded, kind]
report() { # taken not_taken
    cat > "$DIR/report.json" << EOF
{"data": [{"files": [
  {"filename": "$DIR/crate/src/lib.rs", "branches": [[2, 8, 2, 9, $1, $2, 0, 0, 4]]},
  {"filename": "/cargo/registry/dep/src/lib.rs", "branches": [[1, 1, 1, 2, 0, 0, 0, 0, 4]]}
]}]}
EOF
}
allow() { # arm why
    printf '[[allow]]\nfile = "src/lib.rs"\ncode = "if a {"\narm = "%s"\nwhy = "%s"\n' "$1" "$2" \
        > "$DIR/allow.toml"
}

expect() { # want(pass|fail) label message
    local want="$1" label="$2" message="$3" got=pass
    python3 -I "$ROOT/scripts/check-branch-coverage.py" "$DIR/report.json" "$DIR/crate" "$DIR/allow.toml" \
        > "$DIR/out" 2>&1 || got=fail
    if [ "$got" = "$want" ] && grep -q -F -- "$message" "$DIR/out"; then
        echo "ok - $label"
    else
        echo "not ok - $label (got $got)"
        cat "$DIR/out"
        failures=$((failures + 1))
    fi
}

: > "$DIR/allow.toml"
report 3 1
expect pass "every arm visited, a dependency's arms ignored" "0 unvisited"
report 3 0
expect fail "an unvisited arm fails" "the false arm of \`if a {\` is never visited"
allow false "the caller always passes true"
expect pass "an allowed arm passes" "1 allowed"
report 3 1
expect fail "a stale allowlist entry fails" "allowlist entry matches no unvisited arm"
report 3 0
allow true "wrong arm"
expect fail "an allowance for the other arm does not excuse it" "never visited"
allow false " "
expect fail "an allowance with no reason is refused" "why is not empty"

[ "$failures" -eq 0 ] || exit 1
echo "ok: the coverage check passes and fails as it should"
