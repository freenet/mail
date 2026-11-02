#!/usr/bin/env bash
# Check that the built mail delegate imports only what a node provides.
#
# A module that imports a function the host does not register fails to
# INSTANTIATE: the delegate stops working for every user, at load, with nothing
# to fall back on. Core removed its contract write and subscribe host functions,
# and a wasm-bindgen dependency brings `__wbindgen_*` placeholders no node has.
# This lists the imports of the delegate's WASM and compares them to
# scripts/delegate-imports-allowlist.txt, the stdlib's own host set. It also
# fails on an import that is not a function, and on a file with no import
# section to read, which is never a delegate that passes.
#
# Usage: scripts/check-delegate-imports.sh [delegate file]
#        (default: the candidate; a raw module or fdev's wrapped form)
# Exit status: 0 = every import is allowed, 1 = one is not.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
FILE="${1:-$ROOT/published-contract/candidate/mail_delegate}"
ALLOW="$ROOT/scripts/delegate-imports-allowlist.txt"

python3 - "$FILE" "$ALLOW" <<'PY'
import sys

path, allow_path = sys.argv[1:]
data = open(path, "rb").read()
allowed = set()
for line in open(allow_path):
    line = line.strip()
    if line and not line.startswith("#"):
        module, name = line.split()
        allowed.add((module, name))


def bail(message):
    print(f"FAIL: {path}: {message}", file=sys.stderr)
    sys.exit(1)


# fdev wraps the module in a header: a version, a hash and a length.
start = data.find(b"\0asm\x01\0\0\0")
if start < 0 or start > 64:
    bail("not a WASM module")
data = data[start:]


def uleb(at):
    value, shift = 0, 0
    while True:
        byte = data[at]
        at += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, at


def text(at):
    n, at = uleb(at)
    return data[at : at + n].decode(), at + n


imports = []
sections = 0
at = 8
try:
    while at < len(data):
        kind = data[at]
        size, at = uleb(at + 1)
        end = at + size
        if end > len(data):
            bail("a section runs past the end of the file")
        if kind == 2:
            sections += 1
            count, p = uleb(at)
            for _ in range(count):
                module, p = text(p)
                name, p = text(p)
                desc = data[p]
                p += 1
                if desc == 0:
                    _, p = uleb(p)
                elif desc == 1:  # table: reftype, limits
                    flags = data[p + 1]
                    _, p = uleb(p + 2)
                    if flags & 1:
                        _, p = uleb(p)
                elif desc == 2:  # memory: limits
                    flags = data[p]
                    _, p = uleb(p + 1)
                    if flags & 1:
                        _, p = uleb(p)
                elif desc == 3:  # global: type, mutability
                    p += 2
                else:
                    bail(f"import {module}::{name} has unknown kind {desc}")
                imports.append((module, name, desc))
        at = end
except (IndexError, UnicodeDecodeError) as e:
    bail(f"the module does not parse: {e}")

if sections == 0:
    bail("no import section: nothing was checked")

bad = []
for module, name, desc in imports:
    if "__wbindgen" in name or "__wbindgen" in module:
        bad.append(f"{module}::{name} is a wasm-bindgen placeholder no node provides")
    elif (module, name) not in allowed:
        bad.append(f"{module}::{name} is not in the host's set")
    elif desc != 0:
        bad.append(f"{module}::{name} is not a function")
if bad:
    for line in bad:
        print(f"FAIL: {path}: {line}", file=sys.stderr)
    sys.exit(1)
print(f"ok: all {len(imports)} imports of {path} are in the host's set")
PY
