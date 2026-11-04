#!/usr/bin/env bash
# select-guards.sh decides which guards a pull request runs, so a wrong
# answer is a guard that silently stops running. This asserts the answer for
# lists of changed files, that every area's inputs cover the crates' path
# dependencies, and that the shards split a selection with nothing lost.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
SEL="$ROOT/scripts/select-guards.sh"
T="$(mktemp -d)"
trap 'rm -r -- "$T"' EXIT
"$ROOT/scripts/check-guards-fail.sh" --list-files > "$T/guards"
total=$(wc -l < "$T/guards")
fails=0
ok() { echo "ok - $1"; }
bad() { echo "not ok - $1"; fails=$((fails + 1)); }
# select EVENT path... : the selection goes to $T/sel, its exit status is returned
select_for() {
    local event="$1"
    shift
    printf '%s\n' "$@" | "$SEL" "$event" > "$T/sel" 2> "$T/err"
}
count() { grep -c . "$T/sel" || true; }
files_of_selected() { # the mutated files of the selected guards
    awk -F'\t' 'NR == FNR { want[$0] = 1; next } $1 in want { print $2 }' "$T/sel" "$T/guards" | sort -u > "$T/files"
}
has() { grep -q "$1" "$T/files"; } # grep -q ends a pipe early, which pipefail reports as failure

# Everything runs off a pull request, whatever the paths.
select_for push README.md
[ "$(count)" -eq "$total" ] && ok "a push runs every guard" || bad "a push runs every guard"
select_for schedule README.md
[ "$(count)" -eq "$total" ] && ok "a scheduled run runs every guard" || bad "a scheduled run runs every guard"

# Only the harness changed (and only a workflow, a lockfile, a toolchain pin, cargo config).
for p in scripts/check-guards-fail.sh .github/workflows/check-contract-wasm.yml Cargo.lock Cargo.toml \
    rust-toolchain.toml Makefile.toml contracts/.cargo/config.toml .release-freeze; do
    select_for pull_request "$p"
    [ "$(count)" -eq "$total" ] && ok "harness change $p runs every guard" || bad "harness change $p runs every guard"
done

# Only documentation, or a crate with no guard: nothing, and no error.
for p in README.md docs/qa/manual-test-inventory.md common/src/lib.rs tools/v1-node-seed/src/main.rs; do
    if select_for pull_request "$p" && [ "$(count)" -eq 0 ]; then ok "$p alone selects no guard"; else bad "$p alone selects no guard"; fi
done

# One crate: its guards, and only guards whose area reads that crate.
select_for pull_request ui/src/app.rs
n=$(count)
files_of_selected
if [ "$n" -gt 0 ] && [ "$n" -lt "$total" ] && ! grep -qE '^(delegates/|contracts/|protocol/|scripts/|Makefile)' "$T/files"; then
    ok "a ui change runs the ui guards only ($n)"
else bad "a ui change runs the ui guards only ($n)"; fi
select_for pull_request protocol/src/lib.rs
files_of_selected
has '^protocol/' && has '^ui/' \
    && has '^delegates/' && ! has '^contracts/inbox-v2/' \
    && ok "a protocol change runs protocol, delegate and ui guards, not the contract's" \
    || bad "a protocol change runs protocol, delegate and ui guards, not the contract's"
select_for pull_request contracts/inbox-v2/src/merge.rs
files_of_selected
has '^contracts/inbox-v2/' && has '^delegates/' \
    && has '^ui/' && ! has '^protocol/' \
    && ok "an inbox contract change runs the contract, delegate and ui guards" \
    || bad "an inbox contract change runs the contract, delegate and ui guards"
select_for pull_request delegates/mail-delegate/src/store.rs README.md
files_of_selected
has '^delegates/' && has '^ui/' \
    && ! has '^contracts/inbox-v2/' \
    && ok "a delegate change (with a doc) runs the delegate and ui guards" \
    || bad "a delegate change (with a doc) runs the delegate and ui guards"

# A guard whose own mutated file changed runs (here the metadata list).
select_for pull_request docs/metadata-fields.toml
grep -q 'the toml' "$T/sel" && ok "a mutated file's guards run" || bad "a mutated file's guards run"

# A new mutated file with no area fails closed.
if ! (eval "$(sed -n '/^area_of()/,/^}/p' "$SEL")"; area_of new-dir/file.rs) > /dev/null 2>&1; then
    ok "a mutated file with no area is refused"
else bad "a mutated file with no area is refused"; fi

# Every area's inputs include the path dependencies of the crates it covers.
dirs_of() { # manifest -> the repo-relative directories of its path dependencies
    cargo metadata --no-deps --offline --format-version 1 --manifest-path "$ROOT/$1" \
        | python3 -c '
import json, os, sys
root = sys.argv[1]
d = json.load(sys.stdin)
for p in d["packages"]:
    if os.path.dirname(p["manifest_path"]).endswith(sys.argv[2]):
        for x in p["dependencies"]:
            if x.get("path"):
                print(os.path.relpath(x["path"], root) + "/")
' "$ROOT" "$2"
}
covered() { # area manifest dir
    local re missing=0 d
    re="$(sed -n "/^area_inputs()/,/^}/p" "$SEL" | grep -E "^ +$1\)" | sed -E "s/.*echo '(.*)'.*/\1/")"
    while IFS= read -r d; do
        [ -z "$d" ] || printf '%s\n' "${d}x" | grep -qE "$re" || { echo "  $1 does not cover $d"; missing=1; }
    done < <(dirs_of "$2" "$3")
    return $missing
}
covered delegate delegates/mail-delegate/Cargo.toml delegates/mail-delegate && ok "delegate inputs cover its path dependencies" || bad "delegate inputs cover its path dependencies"
covered ui Cargo.toml ui && ok "ui inputs cover its path dependencies" || bad "ui inputs cover its path dependencies"
covered protocol Cargo.toml protocol && ok "protocol inputs cover its path dependencies" || bad "protocol inputs cover its path dependencies"
covered inbox contracts/inbox-v2/Cargo.toml contracts/inbox-v2 && ok "inbox inputs cover its path dependencies" || bad "inbox inputs cover its path dependencies"

# The shards split a selection: every selected guard in exactly one shard, none outside it.
select_for pull_request ui/src/app.rs
cp "$T/sel" "$T/ui"
: > "$T/union"
for i in 0 1 2 3 4 5 6 7; do
    "$ROOT/scripts/check-guards-fail.sh" --only "$T/ui" --shard "$i/8" --list >> "$T/union"
done
if [ "$(sort "$T/union")" = "$(sort "$T/ui")" ] && [ -z "$(sort "$T/union" | uniq -d)" ]; then
    ok "the 8 shards cover a selection once"
else bad "the 8 shards cover a selection once"; fi

[ "$fails" -eq 0 ] || { echo "$fails check(s) failed"; exit 1; }
echo "ok - the guard selection holds"
