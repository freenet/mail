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
ui_migration_tests() {
    cargo test --manifest-path "$STAGE/Cargo.toml" -p freenet-email-ui --lib migration
}
ui_notfound_tests() {
    cargo test --manifest-path "$STAGE/Cargo.toml" -p freenet-email-ui --lib notfound_routing
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
baseline "migration tests" ui_migration_tests
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
    '        // Present but unindexed (an index write that failed): list it again.
        if !s.index(IDENTITY_INDEX)?.1.contains(&addr.0[..]) {' \
    '        // Present but unindexed (an index write that failed): list it again.
        if false {' \
    importing_a_present_but_unindexed_identity_indexes_it_again
dt "re-creating an identity clears its deletion marker" "$D/handlers.rs" \
    '            if s.del(&marker).is_err() && s.put(&marker, store::MARKER_SPENT).is_err() {' \
    '            if false {' \
    a_reimported_identity_clears_its_old_deletion_marker
dt "one corrupt identity record does not fail every listing" "$D/handlers.rs" \
    '    freenet_mail_protocol::from_cbor(body).ok()' \
    '    Some(freenet_mail_protocol::from_cbor(body).expect("an identity record decodes"))' \
    a_corrupt_identity_record_is_left_out_and_counted_as_unreadable
dt "importing keys writes over a corrupt identity record" "$D/handlers.rs" \
    '|b| decodes_identity(b).is_some()' \
    '|_| true' \
    importing_keys_restores_an_identity_whose_record_is_corrupt
dt "removing an unreadable key counts one key fewer" "$D/store.rs" \
    '                // It was there, unreadable: one key fewer.
                self.forget_unsized_key();' \
    '                // It was there, unreadable: one key fewer.' \
    removing_an_unreadable_key_counts_one_key_fewer
dt "a refused write over an unreadable value keeps it" "$D/store.rs" \
    '            None => 0,
        };
        let generation = self.next_generation(floor)?;' \
    '            None => {
                if self.env.remove(&key) || self.env.remove(&key) {
                    self.forget_unsized_key();
                }
                0
            }
        };
        let generation = self.next_generation(floor)?;' \
    a_refused_write_over_an_unreadable_value_keeps_it,a_restore_refused_its_generation_keeps_the_unreadable_record
dt "a delete removes a key that reads as absent" "$D/store.rs" \
    '            if self.env.remove(&key) || self.env.remove(&key) || self.env.remove(&key) {' \
    '            if false {' \
    a_delete_removes_a_key_whose_reads_fail
dt "an unreadable index is not taken for empty" "$D/store.rs" \
    'if self.get(&index_marker_rel(rel)).as_deref() == Some(MARKER_LIVE) {' 'if false {' \
    an_unreadable_index_is_not_rebuilt_from_nothing
dt "an emptied index is written empty, not removed" "$D/store.rs" \
    '        if generation == 0 && ids.is_empty() {
            return Ok(());
        }' \
    '        if ids.is_empty() {
            if generation == 0 {
                return Ok(());
            }
            self.put_for_delete(&marker, MARKER_PENDING)?;
            if let Err(e) = self.del(rel) {
                let _ = self.put_for_delete(&marker, MARKER_LIVE);
                return Err(e);
            }
            let _ = self.del(&marker);
            return Ok(());
        }' \
    an_emptied_index_reads_the_same_whether_its_record_reads_or_not
dt "a new index lists nothing until it is live" "$D/store.rs" \
    '            let created = self.create_index(rel, &marker)?;' \
    '            self.put(&marker, MARKER_PENDING)?;
            let created = self.write_if(rel, 0, &body)?;
            self.put_for_delete(&marker, MARKER_LIVE)?;' \
    a_record_under_a_pending_marker_never_lists_an_entry
dt "a lost usage record is recounted, not taken as zero" "$D/store.rs" \
    '            None => self.recount()?,' '            None => Usage::default(),' \
    a_lost_usage_record_is_recounted_not_taken_as_zero
dt "a drifted usage record is recounted before refusing" "$D/store.rs" \
    '            if self.recount_state() != Some((RECOUNT_DONE, before)) {' '            if false {' \
    a_drifted_usage_record_is_recounted_before_refusing
dt "a recount continues where the last call stopped" "$D/store.rs" \
    '            Some((visited, u)) if visited != RECOUNT_DONE && visited as usize <= keys.len() => {' \
    '            Some((visited, u)) if false && visited <= keys.len() as u64 => {' \
    a_large_store_is_recounted_in_pages_and_recounts_agree
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
    a_create_marker_beside_an_unreadable_record_never_skips_the_prompt_and_stays_restorable
dt "only a deletion's marker skips the prompt" "$D/handlers.rs" \
    's.get(&store::deleted_rel(addr)).as_deref() == Some(store::MARKER_DELETING)' \
    's.get(&store::deleted_rel(addr)).is_some()' \
    a_create_marker_beside_an_unreadable_record_never_skips_the_prompt_and_stays_restorable
dft() { guard "$1" "$2" "$3" "$4" "tests:$FAULT_RUN" fault_tests; }
dft "absence is believed only when a re-read agrees" "$D/store.rs" \
    'self.env.get(key).or_else(|| self.env.get(key))' 'self.env.get(key)'
dt "listing frees index entries whose item is gone" "$D/handlers.rs" \
    '        if s.index_remove_many(&ix, &ids).is_ok() {' '        if false && s.index_remove_many(&ix, &ids).is_ok() {' \
    listing_frees_an_index_entry_whose_item_is_gone
dbt() { guard "$1" "$2" "$3" "$4" "tests:$BLIND_RUN" blind_tests; }
dt "a deletion answers Deleted only once its marker is confirmed removed" "$D/handlers.rs" \
    '    s.del_written(&marker)?;' '    s.del(&marker)?;' \
    a_deletion_is_not_reported_done_while_its_marker_may_remain
# Retired: "an index that cannot be read may hold a failed create's entry".
# Its mutation (put_item dropping a failed create's marker when the index
# cannot be read) can no longer fail any test: write_index adds an entry
# only once the index is live (`l`), in one write that lands or changes
# nothing, so a failed index_add never leaves its entry. That guarantee is
# guarded by "a new index lists nothing until it is live" above;
# a_failed_add_to_an_unreadable_index_never_leaks_its_slot still runs.
# Recovery from a key that stays unreadable.
dt "importing keys restores an identity whose record cannot be read" "$D/handlers.rs" \
    '        return restore_unreadable_identity(s, addr, dsa, kem, alias, description, confirmed).map(' \
    '        return Err(fail(FailureCode::Busy, "unreadable")).map(' \
    importing_keys_restores_a_listed_identity_whose_record_cannot_be_read
dt "an identity whose record cannot be read can be deleted" "$D/handlers.rs" \
    '            s.put_for_delete(&marker, store::MARKER_DELETING)?;' \
    '            return Err(fail(FailureCode::Busy, "unreadable"));' \
    an_identity_whose_record_cannot_be_read_can_be_deleted_after_asking
dt "an approved deletion is recorded before the record is touched" "$D/handlers.rs" \
    "        // \`deleting: false\`, undoing a deletion the user approved.
        s.put_for_delete(&marker, store::MARKER_DELETING)?;" \
    "        // \`deleting: false\`, undoing a deletion the user approved." \
    a_restore_cannot_undo_an_approved_deletion_whose_record_went_unreadable
dt "a create's marker does not stop deleting an unreadable identity" "$D/consent.rs" \
    '                && s.get(&crate::store::deleted_rel(addr)).as_deref()
                    != Some(crate::store::MARKER_DELETING)' \
    '                && s.get(&crate::store::deleted_rel(addr)).is_none()' \
    a_spent_create_marker_does_not_stop_deleting_an_unreadable_identity
dt "a failed create marks its slot free to reclaim" "$D/handlers.rs" \
    '        if kind != store::MARKER_FAILED && kind != store::MARKER_DELETING {' \
    '        if kind != store::MARKER_DELETING {' \
    a_failed_create_marks_its_slot_free_to_reclaim
dt "an unreadable list does not block deleting its identity" "$D/handlers.rs" \
    '            Err(_) if s.index_unreadable(&ix) => {' \
    '            Err(_) if false => {' \
    an_unreadable_item_index_does_not_block_deleting_the_identity
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
dt "a failure after a write is reported as partial" "$D/handlers.rs" \
    '    s.index_remove(&ix, &item.id).map_err(partial)?;
    // A `d` marker left behind' '    s.index_remove(&ix, &item.id)?;
    // A `d` marker left behind' \
    a_delete_whose_index_update_fails_after_the_record_went_is_partial
dt "a failed prune does not fail the deletion listing" "$D/handlers.rs" \
    '    let _ = prune_recordless_identities(s);' '    prune_recordless_identities(s)?;' \
    a_failed_prune_does_not_fail_the_deletion_listing
dt "writing over an unreadable value never counts low (keys)" "$D/store.rs" \
    '        let generation = self.next_generation(floor)?;
        self.put(rel, &encode_versioned(generation, body))?;' \
    '        let generation = self.next_generation(floor)?;
        self.put(rel, &encode_versioned(generation, body))?;
        self.adjust_usage(|u| Usage {
            keys: u.keys.saturating_sub(2),
            bytes: u.bytes,
        });' \
    replacing_an_unreadable_value_never_counts_low
dt "writing over an unreadable value never counts low (bytes)" "$D/store.rs" \
    '        let generation = self.next_generation(floor)?;
        self.put(rel, &encode_versioned(generation, body))?;' \
    '        let generation = self.next_generation(floor)?;
        self.put(rel, &encode_versioned(generation, body))?;
        self.adjust_usage(|u| Usage {
            keys: u.keys,
            bytes: u.bytes.saturating_sub(4096),
        });' \
    replacing_an_unreadable_value_never_counts_low
dt "migration records never reach a successor" "$D/store.rs" \
    '    !matches!(kind, ItemKind::MigrationJournal | ItemKind::MigrationMarker)' \
    '    let _ = kind;
    true' \
    migration_records_are_not_exported
dt "legacy imports take generations from the counter" "$D/store.rs" \
    '        let generation = self.next_generation(current)?;
        self.put(rel, &encode_versioned(generation, body))?;' \
    '        let generation = current + 1;
        self.put(rel, &encode_versioned(generation, body))?;' \
    imported_items_take_their_generation_from_the_counter

# The legacy walk.
M="$STAGE/ui/src/migration"
ut() { # name file old new test...
    guard "$1" "$2" "$3" "$4" "tests:$5" ui_migration_tests
}
ut "silence never reads as absence" "$M/legacy_delegates.rs" \
    '            LegacyReply::NoAnswer(_) => ProbeVerdict::NoReply,
        })
    }

    async fn fetch_secrets(
        &mut self,
        predecessor: &DelegateKey,
    ) -> Result<Vec<SecretPair>, String> {
        let entry = self
            .entry(predecessor)
            .ok_or("a predecessor outside the lineage")?;
        let read = self.read_row(&entry, predecessor).await;' \
    '            LegacyReply::NoAnswer(_) => ProbeVerdict::Executable,
        })
    }

    async fn fetch_secrets(
        &mut self,
        predecessor: &DelegateKey,
    ) -> Result<Vec<SecretPair>, String> {
        let entry = self
            .entry(predecessor)
            .ok_or("a predecessor outside the lineage")?;
        if matches!(
            self.reply(predecessor).await?,
            LegacyReply::NoAnswer(_)
        ) {
            return Ok(Vec::new());
        }
        let read = self.read_row(&entry, predecessor).await;' \
    a_silent_get_is_unresponsive_never_absent_never_sealed
ut "no reply in time is never an absence" "$M/node.rs" \
    '        .unwrap_or_else(|| LegacyReply::NoAnswer("no reply in time".to_string()))' \
    '        .unwrap_or(LegacyReply::NotInstalled)' \
    no_reply_in_time_is_a_silence_never_an_absence
ut "an empty answer is never sealed" "$M/legacy_delegates.rs" \
    '    if manager.is_empty() {
        return Err("answered with nothing, which does not prove it holds nothing".into());
    }' \
    '    if manager.is_empty() {
        return Ok((Vec::new(), HashMap::new()));
    }' \
    scenario_an_answered_empty_store_is_never_sealed
ut "an import never overwrites" "$M/successor.rs" \
    '        let conflict = match self.put(item.clone(), body, None).await {' \
    '        let conflict = match self.merged_put(item.clone(), |_| Some(body.clone())).await {' \
    scenario_an_import_never_overwrites_what_the_new_delegate_holds
ut "a conflict does not prove an item is stored" "$M/successor.rs" \
    '            Ok(None) => ItemWrite::retryable(format!("not stored after {conflict}")),' \
    '            Ok(None) => ItemWrite::already_authoritative(),' \
    scenario_a_false_conflict_does_not_pass_for_a_stored_item
ut "a migrated identity starts unconfirmed" "$M/successor.rs" \
    '                kind: ImportKind::Migration,' \
    '                kind: ImportKind::UserRestore,' \
    scenario_a_populated_node_carries_everything_over
ut "the archive is carried" "$M/legacy_delegates.rs" \
    '    for (id, archived) in &state.archived {' \
    '    for (id, archived) in state.archived.iter().take(0) {' \
    scenario_a_populated_node_carries_everything_over
ut "identities are walked first" "$M/mod.rs" \
    '        generation: e.generation + IDENTITY_GENERATION_OFFSET,' \
    '        generation: e.generation + IDENTITY_GENERATION_OFFSET - 2_000_000,' \
    scenario_identities_are_walked_before_any_local_state
ut "a silent identity generation holds back its aliases" "$M/legacy_delegates.rs" \
    '        if self.incomplete {
            return AliasOwner::Unresolved;
        }' \
    '' \
    a_silent_identity_generation_makes_an_unknown_alias_an_error
ut "only a generation's own identities can orphan its aliases" "$M/legacy_delegates.rs" \
    '        let Some((_, own)) = self.tables.iter().find(|(g, _)| *g == generation) else {
            return AliasOwner::Unresolved;
        };' \
    '        let Some((_, own)) = self.tables.iter().find(|(g, _)| *g == generation) else {
            return AliasOwner::NoIdentity;
        };' \
    scenario_local_state_waits_for_the_identities_of_its_generation
ut "a newer row holds older ones back" "$M/legacy_delegates.rs" \
    '                        .is_some_and(|row| row.attempts < HOLD_BACK_LOADS)' \
    '                        .is_some_and(|_| false)' \
    scenario_a_newer_row_that_answers_late_still_wins
ut "the hold on older rows ends" "$M/legacy_delegates.rs" \
    '                        .is_some_and(|row| row.attempts < HOLD_BACK_LOADS)' \
    '                        .is_some_and(|_| true)' \
    scenario_a_newer_row_that_stays_empty_holds_older_rows_only_for_a_while
ut "only the newest row sets an identity's markers" "$M/successor.rs" \
    '    if imported.is_some_and(|from| from >= generation) {' \
    '    if false {' \
    scenario_only_the_newest_row_holding_an_identity_sets_its_markers
ut "read marks come from the newest row holding the alias" "$M/legacy_delegates.rs" \
    '                let held = newer.aliases.contains(alias);' \
    '                let held = false;' \
    scenario_read_marks_come_from_the_newest_row_holding_the_alias
ut "a cap ends the walk" "$M/successor.rs" \
    '                self.counts.at_cap += 1;
                ItemWrite::permanent(text)' \
    '                self.counts.at_cap += 1;
                ItemWrite::retryable(text)' \
    scenario_a_cap_is_a_counted_rejection_and_the_walk_ends
ut "an identity on its way is not a deleted one" "$M/successor.rs" \
    '        let Some(owner) = owner.filter(|o| self.arrived.holds(o)) else {' \
    '        let Some(owner) = owner else {' \
    scenario_items_wait_for_an_identity_that_has_not_arrived
ut "an unreadable journal is rebuilt" "$M/successor.rs" \
    '            Err(e) if is_unreadable(&e) => {
                self.journal_generation = None;' \
    '            Err(e) if false && is_unreadable(&e) => {
                self.journal_generation = None;' \
    scenario_an_unreadable_journal_and_marker_are_rebuilt
ut "one walk at a time" "$M/mod.rs" \
    '    let _this_walk = one_walk.lock().await;' \
    '    let _ = &one_walk;' \
    scenario_walks_in_one_tab_run_one_at_a_time
ut "a marker never lowers its data flag" "$M/successor.rs" \
    '                started: Some(saw_data || self.started == Some(true)),' \
    '                started: Some(saw_data),' \
    a_marker_follows_the_crates_contract
ut "the wildcard status retries" "$M/mod.rs" \
    '        _ => Settled::Retry,' \
    '        _ => Settled::Complete,' \
    the_wildcard_status_arm_retries
ut "the settings merge keeps what is stored" "$M/successor.rs" \
    '        (present, _) => present.clone(),' \
    '        (_, other) => other.clone(),' \
    the_settings_merge_commutes_over_disjoint_fields

ut "a typed not-installed never raises the Restore alarm" "$M/legacy_delegates.rs" \
    '                LegacyReply::NotInstalled => false,' \
    '                LegacyReply::NotInstalled => true,' \
    only_a_silent_or_undecodable_row_counts_as_silent
ut "an orphan move never overwrites an item" "$M/orphans.rs" \
    '        Some(_) => Err("that identity already holds a different item with this id".to_string()),' \
    '        Some(_) => Ok(()),' \
    moving_an_orphan_never_overwrites_an_item_already_there
ut "a silent identity row never orphans its aliases" "$M/legacy_delegates.rs" \
    'AliasOwner::Unresolved if aliases.own_row_absent(generation) => None,' \
    'AliasOwner::Unresolved => None,' \
    scenario_a_silent_identity_row_never_orphans_its_aliases
ut "one absent answer does not stand" "$M/legacy_delegates.rs" \
    '.is_some_and(|answers| *answers >= HOLD_BACK_LOADS)' \
    '.is_none_or(|answers| *answers < u32::MAX)' \
    scenario_one_empty_answer_after_a_silence_orphans_nothing
ut "a resolved identity row never stands as absent" "$M/legacy_delegates.rs" \
    '        self.pending_walks
            .get(entry.delegate_key.as_slice())
            .is_some_and(|row| !row.started)
            && self' \
    '        true
            && self' \
    scenario_a_resolved_identity_row_never_stands_as_absent
ut "one typed not-installed does not release a held marker" "$M/legacy_delegates.rs" \
    '.is_some_and(|reply| row_holds_nothing(reply) && self.absence_stands(e))' \
    '.is_some_and(|reply| row_holds_nothing(reply))' \
    scenario_silence_past_the_hold_starts_no_contract_migration
ut "a row whose import began never stands as absent" "$M/legacy_delegates.rs" \
    '            .is_some_and(|row| !row.started)' \
    '            .is_some_and(|_| true)' \
    scenario_a_started_row_never_stands_as_absent
ut "absent answers count only in a row" "$M/mod.rs" \
    '                    l.absent_answers.remove(generation);' \
    '' \
    scenario_absent_answers_count_only_in_a_row
ut "another generation's transient empty does not orphan" "$M/legacy_delegates.rs" \
    '            } else if matches!(reply, Ok(r) if row_holds_nothing(&r)) && self.absence_stands(&entry)
            {
                tables.mark_absent(release);
            } else {
                tables.incomplete = true;
            }' \
    '            } else if matches!(&reply, Ok(r) if row_holds_nothing(r)) {
                if self.absence_stands(&entry) {
                    tables.mark_absent(release);
                }
            } else {
                tables.incomplete = true;
            }' \
    scenario_a_transient_empty_in_another_generation_orphans_nothing
ut "silence past the hold starts no contract migration" "$M/successor.rs" \
    '                adopted.pending_held = hold && adopted.has_pending();' \
    '                adopted.pending_held = false;' \
    scenario_silence_past_the_hold_starts_no_contract_migration
guard "held markers are not acted on" "$STAGE/ui/src/app/identity_store.rs" \
    '    let Some(mut markers) = read.filter(|m| !m.pending_held) else {' \
    '    let Some(mut markers) = read else {' \
    "tests:scenario_silence_past_the_hold_starts_no_contract_migration" ui_migration_tests
ut "held markers are released when the newer row settles" "$M/mod.rs" \
    '    let released_markers = release_held_markers(successor.store(), newest_unsettled).await;' \
    '    let released_markers = false && newest_unsettled.is_none();' \
    scenario_silence_past_the_hold_starts_no_contract_migration
ut "a held-back row counts nothing" "$M/legacy_delegates.rs" \
    '        let mut mapped = MappingCounts::default();
        let pairs = map_local_state(&bytes, entry.generation, &tables, &newer, &mut mapped)?;
        self.counts.add(mapped);' \
    '        let mut mapped = MappingCounts::default();
        let pairs = map_local_state(&bytes, entry.generation, &tables, &newer, &mut self.counts)?;
        self.counts.add(mapped);' \
    scenario_a_row_held_back_counts_nothing
guard "the gate asks an unconfirmed identity" "$STAGE/ui/src/app/migration_view.rs" \
    '    if confirmed == Some(false) {' \
    '    if confirmed == Some(true) {' \
    "tests:an_unconfirmed_identity_is_asked_and_the_rest_go" ui_migration_tests
guard "share asks the gate" "$STAGE/ui/src/app/settings.rs" \
    'match super::migration_view::gate(user.read().logged_id().map(|i| i.confirmed)) {' \
    'match (|_: Option<bool>| super::migration_view::Gate::Go)(user.read().logged_id().map(|i| i.confirmed)) {' \
    "tests:share_and_send_go_through_the_gate" ui_migration_tests
guard "an unconfirmed identity publishes nothing" "$STAGE/ui/src/api.rs" \
    '        (_, Some(false), _) | (_, None, Some(false)) => NotFoundRoute::OwnUnconfirmed,
        (_, Some(true), _) => NotFoundRoute::OwnInbox,
        (_, None, Some(true)) => NotFoundRoute::OwnAftRecord,' \
    '        (_, Some(_), _) => NotFoundRoute::OwnInbox,
        (_, None, Some(_)) => NotFoundRoute::OwnAftRecord,' \
    "tests:an_unconfirmed_identity_never_self_heals" ui_notfound_tests
ut "NotFound is confirmed before an identity counts as gone" "$M/successor.rs" \
    '            Ok(Reply::Status(status)) if status.unreadable_identities == 0' \
    '            Ok(Reply::Status(_))' \
    scenario_items_of_an_unreadable_identity_wait_for_it
ut "a retry reads before it writes" "$M/successor.rs" \
    '                Ok(Some(_)) => return ItemWrite::already_authoritative(),
                Err(e) if !is_unreadable(&e)' \
    '                Err(e) if !is_unreadable(&e)' \
    scenario_a_retry_does_not_count_what_already_arrived
guard "send asks the gate" "$STAGE/ui/src/app.rs" \
    '            migration_view::gate(user.read().logged_id().map(|i| i.confirmed))' \
    '            (|_: Option<bool>| migration_view::Gate::Go)(user.read().logged_id().map(|i| i.confirmed))' \
    "tests:share_and_send_go_through_the_gate" ui_migration_tests
guard "the list's word on confirmation wins" "$STAGE/ui/src/api.rs" \
    '    listed.unwrap_or(held)' \
    '    held' \
    "tests:the_flag_routes_a_not_found_from_unconfirmed_to_publishing" ui_notfound_tests
guard "an unconfirmed identity's arm publishes nothing" "$STAGE/ui/src/api.rs" \
    '                            "contract of an unconfirmed identity not found (key={key}): not published"
                        ));' \
    '                            "contract of an unconfirmed identity not found (key={key}): not published"
                        ));
                        crate::app::identity_store::spawn_detached(async {});' \
    "tests:the_unconfirmed_arm_has_no_publish_in_it" ui_notfound_tests

ut "a silent predecessor does not delay the list" "$STAGE/ui/src/app/identity_store.rs" \
    '    listing.await;
    walk.await;' \
    '    walk.await;
    listing.await;' \
    a_silent_predecessor_does_not_delay_the_list
ut "the hold-back is three loads" "$M/legacy_delegates.rs" \
    'pub(crate) const HOLD_BACK_LOADS: u32 = 3;' \
    'pub(crate) const HOLD_BACK_LOADS: u32 = 1;' \
    the_limits_are_the_documented_numbers,scenario_three_empty_loads_hold_back_and_the_fourth_releases
ut "the back-off is one load in ten" "$M/mod.rs" \
    'const BACKED_OFF_ONE_LOAD_IN: u8 = 10;' \
    'const BACKED_OFF_ONE_LOAD_IN: u8 = 2;' \
    the_back_off_runs_one_load_in_ten
ut "the slowdown is one load in four" "$M/mod.rs" \
    'const SLOWED_ONE_LOAD_IN: u8 = 4;' \
    'const SLOWED_ONE_LOAD_IN: u8 = 10;' \
    the_slowdown_runs_one_load_in_four
ut "one young row keeps the walk going" "$M/mod.rs" \
    '    let slowed = pending.iter().all(|p| {' \
    '    let slowed = pending.iter().any(|p| {' \
    one_young_row_keeps_the_walk_going_and_either_cause_slows_it
ut "either cause slows the walk" "$M/mod.rs" \
    '            && (p.absent_streak >= ABSENT_WALKS_BEFORE_BACKING_OFF
                || p.attempts >= SILENT_WALKS_BEFORE_SLOWING)' \
    '            && (p.absent_streak >= ABSENT_WALKS_BEFORE_BACKING_OFF
                && p.attempts >= SILENT_WALKS_BEFORE_SLOWING)' \
    one_young_row_keeps_the_walk_going_and_either_cause_slows_it
ut "a lost swap is retried" "$M/successor.rs" \
    'is_conflict(&e) && attempt + 1 < CAS_ATTEMPTS => attempt += 1,' \
    'is_conflict(&e) && false => attempt += 1,' \
    a_merged_write_retries_a_lost_swap_three_times
ut "a conflict on a create is not a stored item" "$M/successor.rs" \
    '            Ok(None) => ItemWrite::retryable(format!("not stored after {conflict}")),' \
    '            Ok(None) => ItemWrite::written(),' \
    scenario_a_false_conflict_is_not_a_stored_item_for_any_kind
ut "NotFound asks the identity list" "$M/successor.rs" \
    '                Ok(Reply::Identities(list)) if list.iter().all(|i| i.addr != owner)' \
    '                Ok(Reply::Identities(_))' \
    scenario_not_found_for_a_listed_identity_is_retried

ut "a keyless error goes to nobody when two requests wait" "$M/node.rs" \
    '        _ => None,
    }
}

/// Offer a node delegate error' \
    '        _ => waiting.first().cloned(),
    }
}

/// Offer a node delegate error' \
    an_error_is_attributed_to_one_waiter_or_to_none

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
