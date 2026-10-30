#!/usr/bin/env bash
# Show that the mail delegate's guards fail when what they guard is broken.
#
# A check only ever watched passing is not known to work. This first runs
# every guard on an unmodified staged copy of the checkout and requires it
# to PASS. Then, for each guard, it applies the regression the guard exists
# to catch to the staged copy (never to the checkout itself) and requires
# the guard's own failure: the NAMED test(s) failing (`test ...<name> ...
# FAILED`; other tests failing alongside does not count), or the guard
# script's FAIL message. A build or toolchain error is not that failure,
# and neither is a mutation whose target text is not found.
#
# Usage: scripts/check-guards-fail.sh            (all guards)
#        scripts/check-guards-fail.sh --no-wasm  (skip the WASM rebuilds)
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
# The copy keeps the checkout's mtimes, which can be older than artifacts in
# the shared target dir built from a MUTATED copy by an earlier run; cargo
# would then think those fresh. Make every staged file newer.
find "$STAGE" -type f -exec touch {} +
D="$STAGE/delegates/mail-delegate/src"

# The seeded fault-injection run is slow, so the per-guard delegate runs skip
# it and the guards it backs run it alone.
FAULT_RUN=invariants_hold_over_a_host_that_misses_reads_and_refuses_writes
BLIND_RUN=invariants_hold_while_a_key_stays_unreadable
delegate_tests() {
    cargo test --manifest-path "$STAGE/delegates/mail-delegate/Cargo.toml" --features v1-transition \
        -- --skip "$FAULT_RUN" --skip "$BLIND_RUN"
}
fault_tests() {
    cargo test --manifest-path "$STAGE/delegates/mail-delegate/Cargo.toml" --features v1-transition \
        -- --exact "tests::faults::$FAULT_RUN"
}
blind_tests() {
    cargo test --manifest-path "$STAGE/delegates/mail-delegate/Cargo.toml" --features v1-transition \
        -- --exact "tests::faults::$BLIND_RUN"
}
protocol_tests() {
    cargo test --manifest-path "$STAGE/Cargo.toml" -p freenet-mail-protocol
}
candidate_check() { "$STAGE/scripts/check-delegate-candidate.sh"; }
freeze_tests() { "$STAGE/scripts/release-freeze_test.sh"; }

failures=0

# ── Baseline: every guard passes on the unmodified copy ─────────────────────
baseline() { # name command...
    local name="$1"
    shift
    if "$@" > "$STAGE/out" 2>&1; then
        echo "ok - baseline: $name passes"
    else
        echo "not ok - baseline: $name fails before any mutation"
        tail -30 "$STAGE/out"
        failures=$((failures + 1))
    fi
}
baseline "delegate tests" delegate_tests
baseline "delegate fault-injection runs" fault_tests
baseline "delegate unreadable-key runs" blind_tests
baseline "protocol tests" protocol_tests
baseline "release freeze tests" freeze_tests
[ "$WASM" -eq 1 ] && baseline "candidate check" candidate_check
if [ "$failures" -ne 0 ]; then
    echo "the guards fail without any regression applied; nothing below would mean anything"
    exit 1
fi

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

# Whether the output shows the expected failure. `expected` is either
# `tests:<name>[,<name>...]` (each named test must be reported FAILED) or a
# fixed string the guard prints.
shows() {
    local expected="$1" out="$2" name
    case "$expected" in
        tests:*)
            local IFS=,
            for name in ${expected#tests:}; do
                grep -q -E "^test ([a-z0-9_]+::)*${name} \.\.\. FAILED$" "$out" || return 1
            done
            ;;
        *) grep -q -F -- "$expected" "$out" ;;
    esac
}

guard() { # name file old new expected command...
    local name="$1" file="$2" old="$3" new="$4" expected="$5"
    shift 5
    cp "$file" "$file.orig"
    if ! replace "$file" "$old" "$new"; then
        echo "not ok - $name: mutation not applied"
        failures=$((failures + 1))
        mv "$file.orig" "$file"
        return
    fi
    if "$@" > "$STAGE/out" 2>&1; then
        echo "not ok - $name: the guard PASSED with the regression applied"
        failures=$((failures + 1))
    elif shows "$expected" "$STAGE/out"; then
        echo "ok - $name"
    else
        echo "not ok - $name: failed, but not as $expected (build error or another test?)"
        grep -E "FAILED|^error" "$STAGE/out" | head -10
        failures=$((failures + 1))
    fi
    mv "$file.orig" "$file"
    # cp gave the copy an mtime older than the mutated build; make the restored
    # file newer, or cargo would keep using the mutated build.
    touch "$file"
}

dt() { guard "$1" "$2" "$3" "$4" "tests:$5" delegate_tests; }

dt "origin gate refuses delegate callers" "$D/handlers.rs" \
    'Some(MessageOrigin::Delegate(_)) => Err(DelegateError::Other(' \
    'Some(MessageOrigin::Delegate(_)) => Ok(Origin([1; 32])), Some(MessageOrigin::Delegate(_)) => Err(DelegateError::Other(' \
    origin_gate_truth_table,delegate_and_unattested_callers_change_nothing
dt "creation returns the new identity's own recovery key" "$D/handlers.rs" \
    'let recovery_key = recovery_key::encode(&dsa, &kem);' \
    'let recovery_key = recovery_key::encode(&dsa, &KemSeed([0; 64]));' \
    the_recovery_key_comes_back_on_creation_only
dt "compare-and-swap refuses a stale writer" "$D/handlers.rs" \
    'Some(g) => g == current_gen,' 'Some(_) => true,' cas_refuses_a_stale_writer_and_accepts_the_current_one
dt "origins get separate namespaces" "$D/store.rs" \
    'format!("o/{}/", hex(&origin.0))' '{ let _ = origin; "o/shared/".to_string() }' \
    origins_and_kinds_never_share_a_key,a_foreign_origin_can_neither_read_nor_change_another_namespace
dt "index records enforce per-kind caps" "$D/store.rs" \
    'if ids.len() >= cap {' 'if ids.len() >= cap + 1_000_000 {' per_kind_caps_are_enforced_from_the_index
dt "an interrupted deletion is listed for finishing" "$D/handlers.rs" \
    '            && r.deleting
        {
            out.push(info(addr, g, &r));' \
    '            && !r.deleting
        {
            out.push(info(addr, g, &r));' \
    an_interrupted_deletion_is_listed_and_finishes_without_asking
dt "the export grant is the only way to skip the prompt" "$D/consent.rs" \
    'if kind == Kind::Export && s.get(EXPORT_GRANT).is_some() {' 'if kind == Kind::Export {' \
    an_export_asks_and_only_an_allow_releases_the_key
dt "an export session must match its cursor" "$D/consent.rs" \
    '&& after == Some(session.cursor.as_slice())' '' \
    an_approved_export_continues_under_its_session_and_nothing_else
dt "an export session has a page limit" "$D/consent.rs" \
    '&& session.pages_left > 0;' ';' a_session_serves_no_more_pages_than_it_has_left
dt "revoking ends the export session" "$D/handlers.rs" \
    '.and_then(|()| s.del(store::EXPORT_SESSION))' '' revoking_the_grant_ends_the_export_session
dt "prompts expire" "$D/consent.rs" \
    'n.saturating_sub(c) > PROMPT_TTL_SECS ||' 'n.saturating_sub(c) > PROMPT_TTL_SECS * 1000 ||' \
    prompts_expire_and_an_expired_answer_is_refused
dt "a stash dated in the future is expired" "$D/consent.rs" \
    ' || c > n + MAX_CLOCK_SKEW_SECS,' ',' a_stash_dated_in_the_future_is_treated_as_expired
dt "the successor export holds no bookkeeping" "$D/handlers.rs" \
    'rels.sort();' 'rels.push("mt/gen".to_string()); rels.sort();' \
    the_successor_export_asks_and_holds_exactly_the_data
dt "the successor export leaves out deleting identities" "$D/handlers.rs" \
    'if load_identity(s, &addr)?.is_some_and(|(_, r)| r.deleting) {' 'if false {' \
    the_successor_export_leaves_out_an_identity_being_deleted
dt "the exported identity index omits deleting identities" "$D/handlers.rs" \
    'is_some_and(|(_, r)| !r.deleting)' 'is_some()' \
    the_successor_export_leaves_out_an_identity_being_deleted
dt "deletion removes the identity's items" "$D/handlers.rs" \
    'for id in &batch {' 'for id in batch.iter().take(0) {' \
    deleting_an_identity_asks_every_time_and_removes_everything_it_owns
dt "deletion is bounded per step" "$D/handlers.rs" \
    'let batch: Vec<Vec<u8>> = ids.iter().take(budget).cloned().collect();' \
    'let batch: Vec<Vec<u8>> = ids.iter().cloned().collect();' \
    a_large_identity_is_deleted_in_bounded_steps_and_is_unusable_meanwhile
dt "removals need the message in the inbox" "$D/handlers.rs" \
    'if hashes.iter().any(|h| !present.contains(&h.0)) {' 'if hashes.is_empty() && !present.is_empty() {' \
    a_removal_is_signed_for_real_messages_in_ascending_order_only
dt "removal hashes must ascend" "$D/handlers.rs" \
    'if hashes.windows(2).any(|w| w[0].0 >= w[1].0) {' 'if hashes.is_empty() && hashes.len() > 1 {' \
    a_removal_is_signed_for_real_messages_in_ascending_order_only
# The three prompt orderings, each put back the way it used to be.
dt "a prompt's index slot is claimed before its stash" "$D/consent.rs" \
    's.index_add(PROMPT_INDEX, &prompt_id.to_be_bytes(), MAX_PENDING_PROMPTS)?;
    if let Err(f) = s.put(&prompt_rel(prompt_id), &stash) {
        let _ = s.index_remove(PROMPT_INDEX, &prompt_id.to_be_bytes());
        return Err(f);
    }' \
    's.put(&prompt_rel(prompt_id), &stash)?;
    s.index_add(PROMPT_INDEX, &prompt_id.to_be_bytes(), MAX_PENDING_PROMPTS)?;' \
    a_prompt_whose_index_slot_cannot_be_claimed_leaves_no_stash
dt "pruning keeps refusals it already built" "$D/consent.rs" \
    '        if s.del(&rel).is_err() {
            return;
        }' \
    '        if s.del(&rel).is_err() {
            out.clear();
            return;
        }' a_failed_cleanup_of_one_expired_prompt_does_not_drop_anothers_refusal
dt "an answer is given only once its stash is cleared" "$D/consent.rs" \
    '    if s.del(&rel).is_err() {
        return Err(DelegateError::Other(' \
    '    if s.del(&rel).is_err() && false {
        return Err(DelegateError::Other(' \
    an_answer_whose_stash_cannot_be_cleared_is_answered_once_later
dt "an answer survives a failed index cleanup" "$D/consent.rs" \
    'let _ = s.index_remove(PROMPT_INDEX, &answer.request_id.to_be_bytes());' \
    's.index_remove(PROMPT_INDEX, &answer.request_id.to_be_bytes()).map_err(|_| DelegateError::Other("x".into()))?;' \
    an_answer_whose_index_cleanup_fails_still_gets_its_response
dt "an interrupted delete is finished by its retry" "$D/handlers.rs" \
    '        s.index_remove(&ix, &item.id).map_err(partial)?;
        let _ = s.del(&marker);
        return Ok(Reply::Deleted);' '        let _ = s.del(&marker);
        return Ok(Reply::Deleted);' \
    an_item_delete_interrupted_before_the_index_update_is_finished_by_its_retry
dt "a request for an unknown operation gets a typed answer" "$D/handlers.rs" \
    'FailureCode::UnknownOperation,' 'FailureCode::BadInput,' \
    a_request_from_a_newer_ui_gets_a_typed_answer_with_its_id
dt "a recordless identity index entry is pruned" "$D/handlers.rs" \
    '    let _ = prune_recordless_identities(s);' '    let _ = s;' \
    a_recordless_identity_index_entry_is_pruned_when_deletions_are_listed
dt "a record that fails to read is never pruned" "$D/handlers.rs" \
    '        let Some(kind) = s.get(&marker) else {
            continue;
        };' '        let kind = s.get(&marker).unwrap_or_else(|| store::MARKER_DELETING.to_vec());' \
    a_record_that_fails_to_read_is_never_pruned_from_the_index
dt "an import re-indexes a present, unindexed identity" "$D/handlers.rs" \
    'if !s.index(IDENTITY_INDEX)?.1.contains(&addr.0[..]) {' 'if false {' \
    importing_a_present_but_unindexed_identity_indexes_it_again
dt "re-creating an identity clears its deletion marker" "$D/handlers.rs" \
    '            if s.del(&marker).is_err() && s.put(&marker, store::MARKER_SPENT).is_err() {' \
    '            if false {' \
    a_reimported_identity_clears_its_old_deletion_marker
dt "a delete removes a key that reads as absent" "$D/store.rs" \
    '            if !self.env.remove(&key) && !self.env.remove(&key) && self.fetch(&key).is_some() {' \
    '            if false {' \
    a_delete_removes_a_key_whose_reads_fail
dt "an unreadable index is not taken for empty" "$D/store.rs" \
    'if self.get(&index_marker_rel(rel)).as_deref() == Some(MARKER_LIVE) {' 'if false {' \
    an_unreadable_index_is_not_rebuilt_from_nothing
dt "the counter is read from both copies" "$D/store.rs" \
    '        [GENERATION, GENERATION_COPY]
            .iter()' '        [GENERATION]
            .iter()' \
    an_unreadable_counter_copy_does_not_restart_generations
dt "a spent create marker licenses no prune" "$D/handlers.rs" \
    '        if kind == store::MARKER_SPENT {' \
    '        if kind == store::MARKER_SPENT && load_identity(s, &addr)?.is_none() {
            gone.push(id);
            markers.push(marker);
            continue;
        }
        if kind == store::MARKER_SPENT {' \
    a_create_marker_beside_an_unreadable_record_licenses_nothing
dt "only a deletion's marker skips the prompt" "$D/handlers.rs" \
    's.get(&store::deleted_rel(addr)).as_deref() == Some(store::MARKER_DELETING)' \
    's.get(&store::deleted_rel(addr)).is_some()' \
    a_create_marker_beside_an_unreadable_record_licenses_nothing
dft() { guard "$1" "$2" "$3" "$4" "tests:$FAULT_RUN" fault_tests; }
dft "absence is believed only when a re-read agrees" "$D/store.rs" \
    'self.env.get(key).or_else(|| self.env.get(key))' 'self.env.get(key)'
dt "listing frees index entries whose item is gone" "$D/handlers.rs" \
    '        if s.index_remove_many(&ix, &ids).is_ok() {' '        if false && s.index_remove_many(&ix, &ids).is_ok() {' \
    listing_frees_an_index_entry_whose_item_is_gone
dbt() { guard "$1" "$2" "$3" "$4" "tests:$BLIND_RUN" blind_tests; }
dbt "a deletion answers Deleted only once its marker is confirmed removed" "$D/handlers.rs" \
    '    s.del_written(&marker)?;' '    s.del(&marker)?;'
dbt "an index that cannot be read may hold a failed create's entry" "$D/handlers.rs" \
    '            if s.index(&ix).is_ok_and(|(_, ids)| !ids.contains(&item.id)) {' \
    '            if !s.index(&ix).is_ok_and(|(_, ids)| ids.contains(&item.id)) {'
# Recovery from a key that stays unreadable.
dt "importing keys restores an identity whose record cannot be read" "$D/handlers.rs" \
    '        return restore_unreadable_identity(s, addr, dsa, kem, alias, description, confirmed).map(' \
    '        return Err(fail(FailureCode::Busy, "unreadable")).map(' \
    importing_keys_restores_a_listed_identity_whose_record_cannot_be_read
dt "an identity whose record cannot be read can be deleted" "$D/handlers.rs" \
    '            s.put_for_delete(&marker, store::MARKER_DELETING)?;' \
    '            return Err(fail(FailureCode::Busy, "unreadable"));' \
    an_identity_whose_record_cannot_be_read_can_be_deleted_after_asking
dt "an unreadable item is reported and a create replaces it" "$D/handlers.rs" \
    "fn listed_but_unreadable(s: &Space<'_>, item: &ItemRef) -> Result<bool, Failure> {" \
    "fn listed_but_unreadable(s: &Space<'_>, item: &ItemRef) -> Result<bool, Failure> {
    if true {
        return Ok(false);
    }" \
    an_unreadable_item_is_reported_and_a_create_replaces_it
dt "a readable index is never reset" "$D/consent.rs" \
    '            if s.index_unreadable(&rel) {' '            if true {' \
    a_readable_index_is_never_reset
dt "an unreadable index can be reset" "$D/handlers.rs" \
    '    s.reset_index(&rel)?;' '    let _ = &rel;' \
    an_unreadable_identity_index_can_be_reset_and_identities_restored,an_unreadable_item_index_can_be_reset
dt "deleting works when the budget is full" "$D/store.rs" \
    '        self.put_within(rel, value, RESERVED_KEYS, RESERVED_BYTES)' \
    '        self.put_within(rel, value, 0, 0)' \
    deleting_works_when_the_budget_is_full
dt "a create that never finished frees its slot" "$D/handlers.rs" \
    '        if kind == store::MARKER_CREATING && load_identity(s, &addr)?.is_none() {' \
    '        if false {' \
    a_create_that_never_finished_frees_its_slot_on_the_next_listing
dbt "a failure after a write is reported as partial" "$D/handlers.rs" \
    '    s.index_remove(&ix, &item.id).map_err(partial)?;
    // A `d` marker left behind' '    s.index_remove(&ix, &item.id)?;
    // A `d` marker left behind'
dt "a failed prune does not fail the deletion listing" "$D/handlers.rs" \
    '    let _ = prune_recordless_identities(s);' '    prune_recordless_identities(s)?;' \
    a_failed_prune_does_not_fail_the_deletion_listing
# A rename that still compiles: only the pinned bytes can catch it. (A new
# variant is caught earlier, by the wildcard-free match in golden.rs, at
# compile time.)
guard "protocol encoding is pinned" "$STAGE/protocol/src/lib.rs" \
    'pub enum FailureCode {
    NotFound,' 'pub enum FailureCode {
    #[serde(rename = "Missing")]
    NotFound,' "tests:golden_every_variant_encodes_to_its_pinned_bytes" protocol_tests
guard "release.sh runs the freeze gate" "$STAGE/scripts/release.sh" \
    '"$REPO_ROOT/scripts/check-release-freeze.sh"
' 'true
' "not ok - release.sh runs the gate" freeze_tests
guard "the production publish task runs the freeze gate" "$STAGE/Makefile.toml" \
    'dependencies = ["check-release-freeze", "sign-webapp", "verify-published-contract"]' \
    'dependencies = ["sign-webapp", "verify-published-contract"]' \
    "not ok - publish-email does not run check-release-freeze first" freeze_tests
guard "the freeze override needs the test flag" "$STAGE/scripts/check-release-freeze.sh" \
    'if [ "${RELEASE_FREEZE_TEST:-}" = "1" ]; then' 'if true; then' \
    "not ok - RELEASE_FREEZE_FILE without the test flag does not lift the freeze" freeze_tests
if [ "$WASM" -eq 1 ]; then
    guard "the candidate is the source's build" "$D/store.rs" \
        'pub const MAX_PENDING_PROMPTS: usize = 4;' 'pub const MAX_PENDING_PROMPTS: usize = 5;' \
        'FAIL: published-contract/candidate/mail_delegate is not what' candidate_check
    # The release guard's own tests build real WASM and show each refusal,
    # including each of its two feature checks alone.
    if "$ROOT/scripts/check-release-delegate_test.sh" > "$STAGE/out" 2>&1; then
        echo "ok - release guard: refusals shown on real builds"
    else
        echo "not ok - release guard tests"
        cat "$STAGE/out"
        failures=$((failures + 1))
    fi
fi

[ "$failures" -eq 0 ] || { echo "$failures guard(s) did not fail as they should"; exit 1; }
echo "every guard fails when what it guards is broken"
