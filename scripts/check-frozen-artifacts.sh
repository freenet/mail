#!/usr/bin/env bash
# Check that every frozen published artifact is the exact bytes that shipped.
#
# A contract's or delegate's key is derived from its WASM (and parameters), so
# these files ARE the keys users' data and URLs live under. They are never
# rebuilt (a rebuild embeds build-machine paths, freenet/mail#348); a new
# generation is added beside them under published-contract/wasm/v<N>/.
#
# Checks, all run (every failure is reported, not just the first):
#   1. byte pins: every file in published-contract/frozen.sha256 matches, and
#      every file under published-contract/wasm/ is pinned;
#   2. code hashes: `fdev inspect` of each WASM equals its committed
#      *_code_hash file;
#   3. contract ids: hash(wasm, parameters) equals the committed id file and
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

MANIFEST="published-contract/frozen.sha256"
failed=0
fail() { echo "FAIL: $*" >&2; failed=1; }
pass() { echo "ok:   $*"; }

# ── 1. Byte pins ────────────────────────────────────────────────────────────
if command -v sha256sum >/dev/null 2>&1; then
    SHA=(sha256sum)
else
    SHA=(shasum -a 256)
fi
if [ ! -s "$MANIFEST" ]; then
    fail "$MANIFEST is missing or empty"
elif "${SHA[@]}" --check --quiet "$MANIFEST"; then
    pass "all $(wc -l < "$MANIFEST" | tr -d ' ') files in $MANIFEST match"
else
    fail "a frozen artifact's bytes differ from $MANIFEST (see FAILED lines above)"
fi
for f in published-contract/wasm/*/*; do
    [ -f "$f" ] || continue
    grep -qF "  $f" "$MANIFEST" 2>/dev/null || fail "$f is not pinned in $MANIFEST"
done

# ── 2. Code hashes ──────────────────────────────────────────────────────────
# <wasm name> <fdev inspect kind> <committed code-hash file>, per generation.
CODE_HASHES=(
    "freenet_email_inbox code inbox_code_hash"
    "freenet_token_allocation_record code token_allocation_record_code_hash"
    "freenet_token_generator delegate token_generator_code_hash"
    "identity_management delegate identity_management_code_hash"
    "mail_local_state delegate mail_local_state_code_hash"
)
for dir in published-contract/wasm/v*/; do
    for row in "${CODE_HASHES[@]}"; do
        read -r wasm kind hash_file <<< "$row"
        [ -f "$dir$wasm" ] || continue
        committed=$(tr -d '[:space:]' < "$dir$hash_file" 2>/dev/null)
        actual=$(fdev inspect "$dir$wasm" "$kind" 2>/dev/null | sed -n 's/^code hash: *//p' | tr -d '[:space:]')
        if [ -z "$actual" ]; then
            fail "fdev inspect could not read $dir$wasm"
        elif [ "$actual" != "$committed" ]; then
            fail "$dir$wasm has code hash $actual, $dir$hash_file says ${committed:-<missing>}"
        else
            pass "$dir$wasm code hash $actual"
        fi
    done
done

# ── 3. Contract ids ─────────────────────────────────────────────────────────
check_id() {
    local name="$1" wasm="$2" params="$3" id_file="$4" pinned="$5" derived committed
    derived=$(fdev get-contract-id --code "$wasm" --parameters "$params" 2>/dev/null | tr -d '[:space:]')
    committed=$(tr -d '[:space:]' < "$id_file" 2>/dev/null)
    if [ -z "$derived" ]; then
        fail "fdev get-contract-id could not derive the $name id from $wasm + $params"
    elif [ "$derived" != "$pinned" ]; then
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
