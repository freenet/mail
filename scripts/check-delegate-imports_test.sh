#!/usr/bin/env bash
# Show check-delegate-imports.sh passing and failing, on small hand-built
# modules: each is a real WASM binary that links the named import.
#
# Exit status: 0 = the check did what it should every time, 1 = it did not.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
mkdir -p "$ROOT/target"
DIR="$(mktemp -d "$ROOT/target/imports-test.XXXXXX")"
trap 'rm -r -- "$DIR"' EXIT
failures=0

# A module with one function type `() -> ()` that imports module::name.
stub() { # file module name [func|memory]
    python3 - "$@" <<'PY'
import sys

path, module, name = sys.argv[1:4]
kind = sys.argv[4] if len(sys.argv) > 4 else "func"


def leb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def s(text):
    return leb(len(text)) + text.encode()


def section(kind_id, body):
    return bytes([kind_id]) + leb(len(body)) + body


desc = {"func": b"\x00\x00", "memory": b"\x02\x00\x01"}[kind]
body = b"\0asm\x01\0\0\0"
body += section(1, b"\x01\x60\x00\x00")
body += section(2, b"\x01" + s(module) + s(name) + desc)
open(path, "wb").write(body)
PY
}

expect() { # want(pass|fail) label message file
    local want="$1" label="$2" message="$3" file="$4" got=pass
    "$ROOT/scripts/check-delegate-imports.sh" "$file" > "$DIR/out" 2>&1 || got=fail
    if [ "$got" = "$want" ] && grep -q -F -- "$message" "$DIR/out"; then
        echo "ok - $label"
    else
        echo "not ok - $label (got $got)"
        cat "$DIR/out"
        failures=$((failures + 1))
    fi
}

stub "$DIR/allowed" freenet_delegate_secrets __frnt__delegate__get_secret
expect pass "an allowed import passes" "all 1 imports" "$DIR/allowed"

for name in __frnt__delegate__put_contract_state __frnt__delegate__update_contract_state \
    __frnt__delegate__subscribe_contract __frnt__delegate__schedule_wakeup; do
    stub "$DIR/retired" freenet_delegate_contracts "$name"
    expect fail "a retired import fails: $name" "$name is not in the host's set" "$DIR/retired"
done

stub "$DIR/bindgen" __wbindgen_placeholder__ __wbindgen_describe
expect fail "a wasm-bindgen placeholder fails" "wasm-bindgen placeholder" "$DIR/bindgen"

stub "$DIR/memory" freenet_delegate_secrets __frnt__delegate__get_secret memory
expect fail "an import that is not a function fails" "is not a function" "$DIR/memory"

printf '\0asm\x01\0\0\0' > "$DIR/none"
expect fail "a module with no imports is not a pass" "no import section" "$DIR/none"

printf 'not wasm at all, not even close to it' > "$DIR/text"
expect fail "something else is not a pass" "not a WASM module" "$DIR/text"

[ "$failures" -eq 0 ] || { echo "$failures case(s) failed"; exit 1; }
echo "check-delegate-imports fails on what it should"
