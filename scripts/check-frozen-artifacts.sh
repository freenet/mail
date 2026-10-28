#!/usr/bin/env bash
# Check that every frozen published artifact is the exact bytes that shipped.
#
# A contract's or delegate's key is derived from its WASM (and parameters), so
# these files ARE the keys users' data and URLs live under. They are never
# rebuilt (a rebuild embeds build-machine paths, freenet/mail#348); a new
# generation is added beside them under published-contract/wasm/v<N>/.
#
# This script checks the tree as it stands. That the files did not change
# relative to the base branch is scripts/check-frozen-immutable.sh's job:
# a consistent rewrite of a WASM, its code hash and its pin passes here.
#
# Checks, all run (every failure is reported, not just the first):
#   1. byte pins: every row of published-contract/frozen.sha256 matches its
#      file, and every file under published-contract/wasm/ has a row;
#   2. generations: every file in a wasm/v<N>/ directory is a known WASM,
#      code-hash or parameters file, each WASM has its code-hash file, and
#      v1 holds all five artifacts;
#   3. code hashes: `fdev inspect` of each WASM equals its committed
#      *_code_hash file, and for v1 also the hash pinned below;
#   4. build paths: WASM in generations after v1 contains no build-machine
#      path (scripts/check-wasm-paths.sh). v1 is exempt: it is the bytes that
#      shipped, built before path remapping existed, and they embed the
#      original build machine's paths (#348); changing them would re-key;
#   5. contract ids: hash(wasm, parameters) equals the committed id file and
#      the id pinned below, for the webapp and container contracts.
#
# Usage: scripts/check-frozen-artifacts.sh
# Needs: fdev, and sha256sum or shasum.
# Exit status: 0 = all checks pass, 1 = a check failed.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$ROOT"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

# The production ids. Users' bookmarks point at these; they never change.
WEBAPP_CONTRACT_ID="GeQLXXR8sfGe31BNRJoVxkvGUTnBkufJ4gTaoX5NWnU5"
CONTAINER_CONTRACT_ID="122f6AR7PyF8d8mhczuNQM4xrLtBf5t8g2iB7PEVT7KC"

# <wasm name> <fdev inspect kind> <code-hash file> <v1 code hash>
ARTIFACTS=(
    "freenet_email_inbox code inbox_code_hash Av3KF7WSod8E5qkABKWDYenhPkF246rC5aUMcHZ3Frdc"
    "freenet_token_allocation_record code token_allocation_record_code_hash 4cLK44213nxHtt9pCZQgQkPg6sXGukcYojjRt6k1oEev"
    "freenet_token_generator delegate token_generator_code_hash H4kgUiEdhRS8F4A53Pfv9ohvSPYPrr1oQsgA3JdxBbCy"
    "identity_management delegate identity_management_code_hash BbtKhHhRR24CZ1vdnzErMtJejWxNL3VKAisgu6Wggkht"
    "mail_local_state delegate mail_local_state_code_hash 5FGNJrAWVxvXjkZxwRm4MptGXu53XUP6epnaGAGT4wGT"
)
PARAMS_FILES=(identity-manager-params mail-local-state-params)

MANIFEST="published-contract/frozen.sha256"
failed=0
fail() { echo "FAIL: $*" >&2; failed=1; }
pass() { echo "ok:   $*"; }

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

# ── 1. Byte pins ────────────────────────────────────────────────────────────
if [ ! -s "$MANIFEST" ]; then
    fail "$MANIFEST is missing or empty"
else
    rows=0
    while read -r want path; do
        [ -n "$want" ] || continue
        rows=$((rows + 1))
        if [ ! -f "$path" ]; then
            fail "$path is pinned in $MANIFEST but missing"
        elif [ "$(sha256 "$path")" != "$want" ]; then
            fail "$path does not match its pin in $MANIFEST"
        fi
    done < "$MANIFEST"
    pass "checked $rows pinned files"
fi
while IFS= read -r -d '' f; do
    awk -v f="$f" '$2 == f { found = 1 } END { exit !found }' "$MANIFEST" 2>/dev/null \
        || fail "$f is not pinned in $MANIFEST"
done < <(find published-contract/wasm -type f -print0 2>/dev/null)

# ── 2-4. Generations, code hashes, build paths ──────────────────────────────
inspect() {
    local file="$1" kind="$2" out
    if ! out=$(fdev inspect "$file" "$kind" 2>&1); then
        echo "$out" >&2
        return 1
    fi
    printf '%s\n' "$out" | sed -n 's/^code hash: *//p' | tr -d '[:space:]'
}

for dir in published-contract/wasm/*/; do
    gen=$(basename "$dir")
    case "$gen" in
        v[0-9]*) ;;
        *) fail "${dir} is not a generation directory (expected v<N>)"; continue ;;
    esac

    # Every file must be something this script knows how to check.
    while IFS= read -r -d '' f; do
        name=${f#"$dir"}
        known=0
        for row in "${ARTIFACTS[@]}"; do
            read -r wasm _ hash_file _ <<< "$row"
            [ "$name" = "$wasm" ] || [ "$name" = "$hash_file" ] && known=1
        done
        for p in "${PARAMS_FILES[@]}"; do [ "$name" = "$p" ] && known=1; done
        [ "$known" = 1 ] || fail "$f is not a known WASM, code-hash or parameters file"
    done < <(find "$dir" -mindepth 1 \( -type f -o -type l -o -type d \) -print0)

    for row in "${ARTIFACTS[@]}"; do
        read -r wasm kind hash_file pinned <<< "$row"
        if [ ! -f "$dir$wasm" ]; then
            [ "$gen" = v1 ] && fail "$dir$wasm is missing (v1 ships all five artifacts)"
            [ -f "$dir$hash_file" ] && fail "$dir$hash_file has no $wasm beside it"
            continue
        fi
        if [ ! -s "$dir$hash_file" ]; then
            fail "$dir$wasm has no code-hash file $dir$hash_file"
            continue
        fi
        committed=$(tr -d '[:space:]' < "$dir$hash_file")
        if ! actual=$(inspect "$dir$wasm" "$kind") || [ -z "$actual" ]; then
            fail "fdev inspect could not read $dir$wasm"
        elif [ "$actual" != "$committed" ]; then
            fail "$dir$wasm has code hash $actual, $dir$hash_file says $committed"
        elif [ "$gen" = v1 ] && [ "$actual" != "$pinned" ]; then
            fail "$dir$wasm has code hash $actual, the pinned v1 hash is $pinned"
        else
            pass "$dir$wasm code hash $actual"
        fi
        if [ "$gen" != v1 ]; then
            scripts/check-wasm-paths.sh "$dir$wasm" >/dev/null || fail "$dir$wasm contains a build-machine path"
        fi
    done
done

# ── 5. Contract ids ─────────────────────────────────────────────────────────
check_id() {
    local name="$1" wasm="$2" params="$3" id_file="$4" pinned="$5" out derived committed
    if ! out=$(fdev get-contract-id --code "$wasm" --parameters "$params" 2>&1); then
        echo "$out" >&2
        fail "fdev get-contract-id could not derive the $name id from $wasm + $params"
        return
    fi
    derived=$(printf '%s' "$out" | tr -d '[:space:]')
    committed=$(tr -d '[:space:]' < "$id_file" 2>/dev/null)
    if [ "$derived" != "$pinned" ]; then
        fail "$name: $wasm + $params give $derived, the pinned id is $pinned"
    elif [ "$committed" != "$pinned" ]; then
        fail "$name: $id_file says ${committed:-<missing>}, the pinned id is $pinned"
    else
        pass "$name contract id $derived"
    fi
}
check_id webapp published-contract/web_container_contract.wasm \
    published-contract/webapp.parameters published-contract/contract-id.txt \
    "$WEBAPP_CONTRACT_ID"
check_id container published-contract/container.wasm \
    published-contract/container.parameters published-contract/container-id.txt \
    "$CONTAINER_CONTRACT_ID"

if [ "$failed" -ne 0 ]; then
    echo "" >&2
    echo "Frozen artifacts must not change. Restore them with:" >&2
    echo "  git checkout -- published-contract/" >&2
    echo "A deliberate new generation goes in a new published-contract/wasm/v<N>/" >&2
    echo "directory, built with scripts/build-wasm.sh, with rows added to $MANIFEST." >&2
    exit 1
fi
echo "all frozen artifacts verified"
