#!/usr/bin/env bash
# Show that the mail delegate's guards fail when what they guard is broken.
#
# A check only ever watched passing is not known to work. For each guard
# this applies the regression it exists to catch to a staged copy of the
# checkout (never to the checkout itself) and requires the guard to FAIL.
# A mutation whose target text is not found fails this script: an
# unapplied mutation proves nothing.
#
# Usage: scripts/check-guards-fail.sh            (all guards)
#        scripts/check-guards-fail.sh --no-wasm  (skip the WASM rebuild)
# Exit status: 0 = every guard failed as it should, 1 = one did not.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
WASM=1
[ "${1:-}" = "--no-wasm" ] && WASM=0
mkdir -p "$ROOT/target"
STAGE="$(mktemp -d "$ROOT/target/guards.XXXXXX")"
trap 'rm -r -- "$STAGE"' EXIT
# Shared across mutations so dependencies compile once.
export CARGO_TARGET_DIR="$ROOT/target/guards-cargo"

(cd "$ROOT" && git ls-files -z --cached --others --exclude-standard \
    | tar --null --ignore-failed-read -T - -cf -) | tar -xf - -C "$STAGE"
D="$STAGE/delegates/mail-delegate/src"

replace() { # file old new: exact, single occurrence
    python3 - "$1" "$2" "$3" <<'PY'
import sys
path, old, new = sys.argv[1:]
s = open(path).read()
if s.count(old) != 1:
    sys.exit(f"MUTATION NOT APPLIED: {old!r} found {s.count(old)} times in {path}")
open(path, "w").write(s.replace(old, new))
PY
}

failures=0
guard() { # name file old new command...
    local name="$1" file="$2" old="$3" new="$4"
    shift 4
    cp "$file" "$file.orig"
    if ! replace "$file" "$old" "$new"; then
        failures=$((failures + 1))
        mv "$file.orig" "$file"
        return
    fi
    if "$@" > "$STAGE/out" 2>&1; then
        echo "not ok - $name: the guard PASSED with the regression applied"
        failures=$((failures + 1))
    else
        echo "ok - $name"
    fi
    mv "$file.orig" "$file"
}

tests() { cargo test --quiet --manifest-path "$STAGE/delegates/mail-delegate/Cargo.toml"; }

guard "origin gate refuses delegate callers" "$D/handlers.rs" \
    'Some(MessageOrigin::Delegate(_)) => Err(DelegateError::Other(' \
    'Some(MessageOrigin::Delegate(_)) => Ok(Origin([1; 32])), Some(MessageOrigin::Delegate(_)) => Err(DelegateError::Other(' \
    tests
guard "compare-and-swap refuses a stale writer" "$D/handlers.rs" \
    'Some(g) => g == current_gen,' 'Some(_) => true,' tests
guard "origins get separate namespaces" "$D/store.rs" \
    'format!("o/{}/", hex(&origin.0))' '{ let _ = origin; "o/shared/".to_string() }' tests
guard "index records enforce per-kind caps" "$D/store.rs" \
    'if ids.len() >= cap {' 'if ids.len() >= cap + 1_000_000 {' tests
guard "the export grant is the only way to skip the prompt" "$D/consent.rs" \
    'if kind == Kind::Export && s.get(EXPORT_GRANT).is_some() {' 'if kind == Kind::Export {' tests
guard "the successor export holds no bookkeeping" "$D/handlers.rs" \
    'rels.sort();' 'rels.push("mt/gen".to_string()); rels.sort();' tests
guard "deletion cascades to the identity's items" "$D/handlers.rs" \
    'for kind in ALL_KINDS.into_iter().filter(|k| store::shape(*k).0) {
        let ix = index_rel(kind, Some(addr));' \
    'for kind in ALL_KINDS.into_iter().filter(|_| false) {
        let ix = index_rel(kind, Some(addr));' tests
guard "removals need the message in the inbox" "$D/handlers.rs" \
    'if hashes.iter().any(|h| !present.contains(&h.0)) {' 'if hashes.iter().any(|h| h.0 == [0xff; 32] && !present.contains(&h.0)) {' tests
guard "an interrupted delete is finished by its retry" "$D/handlers.rs" \
    'finish that now.
        s.index_remove(&ix, &item.id)?;' 'finish that now.' tests
guard "a request for an unknown operation gets a typed answer" "$D/handlers.rs" \
    'FailureCode::UnknownOperation,' 'FailureCode::BadInput,' tests
guard "protocol encoding is pinned" "$STAGE/protocol/src/lib.rs" \
    'pub enum FailureCode {
    NotFound,' 'pub enum FailureCode {
    Gone,
    NotFound,' cargo test --quiet --manifest-path "$STAGE/Cargo.toml" -p freenet-mail-protocol
if [ "$WASM" -eq 1 ]; then
    guard "the candidate is the source's build" "$STAGE/delegates/mail-delegate/src/store.rs" \
        'pub const MAX_PENDING_PROMPTS: usize = 4;' 'pub const MAX_PENDING_PROMPTS: usize = 5;' \
        "$STAGE/scripts/check-delegate-candidate.sh"
fi

# The release guard has its own tests, which include the refusals.
if "$ROOT/scripts/check-release-delegate_test.sh" > "$STAGE/out" 2>&1; then
    echo "ok - release guard refuses the candidate, a missing or v1-transition delegate"
else
    echo "not ok - release guard tests"
    cat "$STAGE/out"
    failures=$((failures + 1))
fi

[ "$failures" -eq 0 ] || { echo "$failures guard(s) did not fail as they should"; exit 1; }
echo "every guard fails when what it guards is broken"
