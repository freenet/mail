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
#        scripts/check-guards-fail.sh --shard I/N  (guards whose index mod N is I)
#        scripts/check-guards-fail.sh --list     (print the guard names, run none)
# Every shard runs the baselines. A shard with no guard fails.
# Exit status: 0 = every guard failed as it should, 1 = one did not.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
WASM=1
SHARD_I="" SHARD_N="" LIST=0
while [ $# -gt 0 ]; do
    case "$1" in
        --no-wasm) WASM=0 ;;
        --list) LIST=1 ;;
        --shard)
            shift
            [[ "${1:-}" =~ ^([0-9]+)/([0-9]+)$ ]] || { echo "usage: --shard I/N" >&2; exit 2; }
            SHARD_I="${BASH_REMATCH[1]}" SHARD_N="${BASH_REMATCH[2]}"
            if [ "$SHARD_N" -lt 1 ] || [ "$SHARD_I" -ge "$SHARD_N" ]; then
                echo "--shard I/N needs 0 <= I < N" >&2; exit 2
            fi
            ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done
GUARD_INDEX=0 GUARDS_RUN=0
# True when the next guard belongs to another shard. Advances the index, so
# it is called exactly once per guard, before any other filter.
other_shard() {
    local i=$GUARD_INDEX
    GUARD_INDEX=$((GUARD_INDEX + 1))
    [ -n "$SHARD_N" ] && [ $((i % SHARD_N)) -ne "$SHARD_I" ]
}
mkdir -p "$ROOT/target"
STAGE="$(mktemp -d "$ROOT/target/guards.XXXXXX")"
trap 'rm -r -- "$STAGE"' EXIT
# Shared across mutations so dependencies compile once.
export CARGO_TARGET_DIR="$ROOT/target/guards-cargo"

if [ "$LIST" -eq 0 ]; then
(cd "$ROOT" && git ls-files -z --cached --others --exclude-standard \
    | tar --null --ignore-failed-read -T - -cf -) | tar -xf - -C "$STAGE"
# The copy keeps the checkout's mtimes, which can be older than artifacts in
# the shared target dir built from a MUTATED copy by an earlier run; cargo
# would then think those fresh. Make every staged file newer.
find "$STAGE" -type f -exec touch {} +
fi
D="$STAGE/delegates/mail-delegate/src"

# The seeded fault-injection run is slow, so the per-guard delegate runs skip
# it and the guards it backs run it alone.
FAULT_RUN=invariants_hold_over_a_host_that_misses_reads_and_refuses_writes
BLIND_RUN=invariants_hold_while_a_key_stays_unreadable
# The delegate's tests link the inbox v2 contract as a dev-dependency, over the
# delegate's lockfile. Built in the target dir the contract's own runs use, the
# two builds of the contract crate collide and the tests stop compiling, so the
# delegate gets a target dir of its own.
DELEGATE_TARGET="$ROOT/target/guards-cargo-delegate"
delegate_tests() {
    CARGO_TARGET_DIR="$DELEGATE_TARGET" \
    cargo test --manifest-path "$STAGE/delegates/mail-delegate/Cargo.toml" --features v1-transition \
        -- --skip "$FAULT_RUN" --skip "$BLIND_RUN"
}
fault_tests() {
    CARGO_TARGET_DIR="$DELEGATE_TARGET" \
    cargo test --manifest-path "$STAGE/delegates/mail-delegate/Cargo.toml" --features v1-transition \
        -- --exact "tests::faults::$FAULT_RUN"
}
blind_tests() {
    CARGO_TARGET_DIR="$DELEGATE_TARGET" \
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
ui_local_tests() {
    cargo test --manifest-path "$STAGE/Cargo.toml" -p freenet-email-ui --lib \
        --no-default-features --features example-data,no-sync identity_store
}
ui_jobs_tests() {
    cargo test --manifest-path "$STAGE/Cargo.toml" -p freenet-email-ui --lib \
        --no-default-features --features example-data,no-sync \
        -- kept_import_is_unread unread_flags_mark an_import_between the_loop_starts the_probe_marker
}
candidate_check() { "$STAGE/scripts/check-delegate-candidate.sh"; }
inbox_candidate_check() { "$STAGE/scripts/check-inbox-candidate.sh"; }
inbox_rule_tests() {
    cargo test --manifest-path "$STAGE/contracts/inbox-v2/Cargo.toml" --test canonical --test rules
}
inbox_plausible_tests() {
    cargo test --manifest-path "$STAGE/contracts/inbox-v2/Cargo.toml" \
        --features plausible-mutants --test plausible_mutants
}
inbox_vectors_check() { "$STAGE/scripts/check-inbox-vectors.sh"; }
inbox_disclosure_tests() {
    cargo test --manifest-path "$STAGE/contracts/inbox-v2/Cargo.toml" --test metadata_disclosure
}
coverage_check_tests() { "$STAGE/scripts/check-branch-coverage_test.sh"; }
triage_check_tests() { "$STAGE/scripts/check-mutants-triage_test.sh"; }
verify_merge_check_tests() { "$STAGE/scripts/check-fdev-verify-merge_test.sh"; }
freeze_tests() { "$STAGE/scripts/release-freeze_test.sh"; }
scrub_release_tests() { "$STAGE/scripts/check-release-scrub_test.sh"; }

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
if [ "$LIST" -eq 0 ]; then
baseline "delegate tests" delegate_tests
baseline "delegate fault-injection runs" fault_tests
baseline "delegate unreadable-key runs" blind_tests
baseline "protocol tests" protocol_tests
baseline "migration tests" ui_migration_tests
baseline "local-delegate identity tests" ui_local_tests
baseline "UI background jobs tests" ui_jobs_tests
baseline "release freeze tests" freeze_tests
baseline "release scrub tests" scrub_release_tests
baseline "inbox v2 rule tests" inbox_rule_tests
baseline "inbox v2 plausible mutants" inbox_plausible_tests
baseline "inbox v2 disclosure gate" inbox_disclosure_tests
baseline "inbox v2 byte vectors" inbox_vectors_check
baseline "branch coverage check" coverage_check_tests
baseline "mutants triage check" triage_check_tests
baseline "verify-merge check" verify_merge_check_tests
[ "$WASM" -eq 1 ] && baseline "candidate check" candidate_check
[ "$WASM" -eq 1 ] && baseline "inbox candidate check" inbox_candidate_check
if [ "$failures" -ne 0 ]; then
    echo "the guards fail without any regression applied; nothing below would mean anything"
    exit 1
fi
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
    if [ "$LIST" -eq 1 ]; then
        other_shard || echo "$name"
        return
    fi
    if other_shard; then
        return
    fi
    if [ -n "${GUARD_ONLY:-}" ] && ! [[ "$name" =~ $GUARD_ONLY ]]; then
        return
    fi
    GUARDS_RUN=$((GUARDS_RUN + 1))
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
dt "inbox v2: a message is tombstoned only once stored" "$D/inbox_v2.rs" \
    'store_opened(s, me, id, m, opened, &mut out)?;' \
    'let _ = store_opened(s, me, id, m, opened, &mut out);' \
    a_refused_store_stops_the_drain,a_drain_over_a_faulty_host_never_tombstones_what_it_did_not_store
dt "inbox v2: an owner version is recorded before it leaves" "$D/inbox_v2.rs" \
    'save(s, item(ItemKind::InboxV2, addr, &[]), &rec, rec_gen)?;' \
    'let _ = (&rec, rec_gen);' \
    a_lost_update_never_reuses_a_version
dt "inbox v2: owner_time moves under the guard" "$D/inbox_v2.rs" \
    '.saturating_add(TIME_STEP_MAX)' '.saturating_add(TIME_STEP_MAX * 100)' \
    owner_time_moves_under_the_guard
dt "inbox v2: pass expiries are whole days" "$D/inbox_v2.rs" \
    'e.expiry = ceil_day(now + lifetime);' 'e.expiry = now + lifetime;' \
    pass_timing_is_coarse_and_spread,a_full_round_runs_through_the_contract
dt "inbox v2: the sender's binding names the message" "$D/sealing.rs" \
    'if !crypto::verify_v1(&binding, &envelope.sender_vk, &envelope.sender_sig) {' \
    'if false && !crypto::verify_v1(&binding, &envelope.sender_vk, &envelope.sender_sig) {' \
    a_restamped_copy_does_not_open
dt "a failed retry of a create keeps the earlier entry" "$D/handlers.rs" \
    'if listed_before {' 'if false && listed_before {' \
    a_failed_retry_of_a_create_keeps_the_earlier_entry
dt "inbox v2: a pass that cannot be kept does not hold mail back" "$D/inbox_v2.rs" \
    'Err(f) if !matches!(f.code, FailureCode::BadInput | FailureCode::CapReached) => {' \
    'Err(f) => {' \
    a_bad_reply_pass_does_not_hold_mail_in_the_inbox
dt "inbox v2: the page cannot write the delegate's records" "$D/store.rs" \
    'ItemKind::InboxV2 | ItemKind::PassLedger => (true, false, false),' \
    'ItemKind::InboxV2 | ItemKind::PassLedger => (true, true, true),' \
    the_page_cannot_rewrite_inbox_records_or_read_held_passes
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
    'AliasOwner::Unresolved if self.own_row_absent(generation) => Some(None),' \
    'AliasOwner::Unresolved if true => Some(None),' \
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
    '        let pairs = map_local_state(&bytes, entry.generation, &tables, &newer, &mut mapped);' \
    '        let pairs = map_local_state(&bytes, entry.generation, &tables, &newer, &mut self.counts);' \
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

# Scrub. Each check, removed, fails a test where it alone was holding.
S="$M/scrub.rs"
ut "scrub reaches a user whose journal never completes" "$S" \
    '    if targets.is_empty() {' \
    '    if targets.is_empty() || !status.is_complete() {' \
    scenario_the_usual_user_is_scrubbed
ut "scrub never takes a started row as clear" "$M/legacy_delegates.rs" \
    '.is_some_and(|row| !row.started)' \
    '.is_some()' \
    a_started_row_is_never_clear
ut "scrub wants the whole count of absent answers" "$M/legacy_delegates.rs" \
    '.is_some_and(|answers| *answers >= HOLD_BACK_LOADS)' \
    '.is_some_and(|answers| *answers >= 1)' \
    an_absence_short_of_the_count_is_not_clear
ut "a standing row must answer the same way at scrub time" "$S" \
    '&& !(adapter.absence_stands(entry) && adapter.holds_nothing(entry).await)' \
    '&& !adapter.absence_stands(entry)' \
    a_standing_row_must_answer_the_same_way_now
ut "a silent local-state row counts no absent answer" "$M/legacy_delegates.rs" \
    '        }
        LegacyReply::NoAnswer(_) => false,
    }
}

pub(crate) fn lineage_key' \
    '        }
        LegacyReply::NoAnswer(_) => true,
    }
}

pub(crate) fn lineage_key' \
    a_silent_row_is_not_clear
ut "an empty local-state row can stand as absent" "$M/legacy_delegates.rs" \
    'LocalState::try_from(bytes.as_slice()).is_ok_and(|mut state| {' \
    'LocalState::try_from(bytes.as_slice()).is_ok_and(|mut state| false && {' \
    a_row_that_answers_empty_stands_as_absent
ut "an identity row waits for its local-state row" "$S" \
    '    if !not_clear.is_empty() {' \
    '    if false && !not_clear.is_empty() {' \
    an_identity_row_waits_for_its_local_state_row
ut "a rejected item blocks scrub" "$S" \
    '    if rejected > 0 {' \
    '    if rejected > u32::MAX - 1 {' \
    a_rejected_item_blocks
ut "an orphan blocks scrub" "$S" \
    '    if !orphans.is_empty() {' \
    '    if orphans.len() == usize::MAX {' \
    an_orphan_blocks
ut "an unmappable entry blocks scrub" "$S" \
    '    if refused > 0 {' \
    '    if refused == usize::MAX {' \
    an_undecodable_identity_blocks
ut "an id that never landed blocks scrub" "$S" \
    'if !imported && !moved && !snapshot.contains(&snapshot_entry(key, &id16(&[value]))) {' \
    'if !imported && !moved && !snapshot.contains(&snapshot_entry(key, &id16(&[value]))) && ids == u32::MAX {' \
    an_item_that_never_arrived_blocks
ut "a user deletion passes by the snapshot" "$S" \
    'if !imported && !moved && !snapshot.contains(&snapshot_entry(key, &id16(&[value]))) {' \
    'if !imported && !moved {' \
    a_user_deletion_after_import_does_not_block
ut "an unreadable item is not a deletion" "$S" \
    'let imported = is_import_of(store, key, value, identities).await?;' \
    'let imported = snapshot.contains(&snapshot_entry(key, &id16(&[value]))) || is_import_of(store, key, value, identities).await?;' \
    an_unreadable_record_is_not_a_deletion
ut "a default build has scrub off" "$S" \
    '    None => false,
};' \
    '    None => true,
};' \
    a_default_build_cannot_reach_a_delete
ut "a build without the flag stops before anything" "$S" \
    '    if !BUILT_IN {' \
    '    if false {' \
    a_default_build_cannot_reach_a_delete
ut "the snapshot holds the value as well as the id" "$S" \
    '    entry[ID_BYTES..].copy_from_slice(value_hash);' \
    '    let _ = value_hash;' \
    an_item_changed_since_the_import_blocks,a_contact_changed_since_the_import_blocks,a_deleted_item_whose_row_then_changed_blocks
ut "an id alone is not the current import" "$S" \
    'return Ok(stored.body.as_slice() == value);' \
    'return Ok(true);' \
    an_item_changed_since_the_import_blocks,a_contact_changed_since_the_import_blocks
ut "the snapshot takes what the walk read" "$S" \
    'if let Some(read) = outcome.read_rows.get(&generation) {' \
    'if let Some(read) = outcome.read_rows.get(&u32::MAX) {' \
    an_older_copy_of_a_newer_item_does_not_block
ut "a late snapshot takes only what still equals the import" "$S" \
    'if is_import_of(store, &key, value, identities).await? {' \
    'if present(store, &key, identities).await? {' \
    a_late_snapshot_does_not_take_a_changed_setting
ut "the snapshot records only a value the delegate holds" "$S" \
    '                    || holds_now(store, &decoded, hash, settings.as_deref(), identities).await?' \
    '                    || present(store, &decoded, identities).await?' \
    a_silent_newer_row_answering_late_with_newer_text_blocks,a_resumed_row_that_an_old_tab_edited_blocks
ut "what the walk wrote is recorded as landed" "$S" \
    '                    || landed
' \
    '' \
    an_item_the_page_changed_after_the_walk_wrote_it_does_not_block
ut "landed means this value, not this key" "$S" \
    'let landed = outcome.landed.contains(&(generation, key.clone(), *hash));' \
    'let landed = outcome.landed.iter().any(|(g, k, _)| *g == generation && k == key);' \
    a_second_value_of_one_key_did_not_land
ut "an older copy of a newer item is recorded" "$S" \
    '                if newer
' \
    '                if false
' \
    an_older_copy_of_a_newer_item_does_not_block
ut "a differing KEM key blocks" "$S" \
    '    if mismatched > 0 {' \
    '    if false {' \
    a_row_whose_kem_seed_differs_from_the_delegates_blocks
ut "a message names the identity it belongs to" "$S" \
    '        PairKey::Message { owner, .. } => Some(*owner),' \
    '        PairKey::Message { .. } => None,' \
    a_message_or_settings_pair_alone_names_the_owner
ut "identity settings name the identity they belong to" "$S" \
    'PairKey::Identity(addr) | PairKey::Flags(addr) | PairKey::IdentitySettings(addr) => {' \
    'PairKey::Identity(addr) | PairKey::Flags(addr) => {' \
    a_message_or_settings_pair_alone_names_the_owner
ut "the build marker is chosen by the flag" "$S" \
    'const BUILD_MARKER: &str = if BUILT_IN {' \
    'const BUILD_MARKER: &str = if true {' \
    the_build_marker_is_there_only_with_scrub
ut "the snapshot is written as a row resolves" "$S" \
    '    write_snapshots(store, &mut adapter, &unrecorded, outcome, &identities).await?;' \
    '    if pending.is_empty() {
        write_snapshots(store, &mut adapter, &unrecorded, outcome, &identities).await?;
    }' \
    a_deletion_on_the_second_load_does_not_block
ut "a cleared identity row keeps its alias table" "$S" \
    '                keep_alias_table(store, adapter, entry).await?;' \
    '                let _ = keep_alias_table::<S, T>;' \
    a_row_that_returns_after_its_identity_row_went_is_filed
ut "the walk uses a kept alias table" "$M/legacy_delegates.rs" \
    'let table = self.kept_tables.get(&entry.generation).cloned().or(table);' \
    'let table = table.or(None);' \
    a_row_that_returns_after_its_identity_row_went_is_filed
ut "one empty load does not finish a row" "$S" \
    '            if answers >= EMPTY_LOADS {' \
    '            if answers >= 1 {' \
    a_row_needs_two_loads_of_empty_answers
ut "a row with something in it starts the count again" "$S" \
    'let answers = if deleted { 1 } else { before + 1 };' \
    'let answers = before + 1;' \
    a_resumed_row_is_finished_only_by_two_empty_loads_in_a_row
ut "identity rows wait for local state to be finished" "$S" \
    '            if mail_left {' \
    '            if mail_left && false {' \
    a_row_needs_two_loads_of_empty_answers
ut "a row is read again before its first delete" "$S" \
    'if adapter.reread(entry).await != Some(passed.as_slice()) {' \
    'if adapter.reread(entry).await.is_none() {' \
    a_row_changed_just_before_its_first_delete_is_left
ut "not being listed is not a deletion" "$S" \
    '            ledger.deleted_identities.contains(&addr)' \
    '            true' \
    an_identity_that_is_only_unlisted_blocks
ut "a deletion on record needs no backup" "$S" \
    '            ledger.deleted_identities.contains(&addr)' \
    '            false' \
    an_identity_the_user_deleted_does_not_block
ut "read marks with no identity hold nothing" "$M/legacy_delegates.rs" \
    '(alias.read.is_empty() || ownerless)' \
    'alias.read.is_empty()' \
    read_marks_with_no_identity_hold_nothing
ut "a discard takes only what was shown" "$M/orphans.rs" \
    'if group.items.iter().any(|(id, _)| *id == orphan.item.id) {' \
    'if !group.items.is_empty() {' \
    a_discard_takes_only_what_was_shown
ut "a discard is recorded" "$M/orphans.rs" \
    '            l.moved.push(id.clone());' \
    '            let _ = &l.moved;' \
    discarded_orphans_do_not_block
ut "a journal that failed to store blocks scrub" "$S" \
    '.is_some_and(|r| r.journal_error.is_some());' \
    '.is_some_and(|_| false);' \
    a_journal_that_was_not_stored_blocks
ut "a kept key that is no position stops the row" "$S" \
    'positions.map(|k| k.parse()).collect();' \
    'positions.filter_map(|k| k.parse().ok()).map(Ok).collect();' \
    a_kept_key_that_is_not_a_position_stops_the_row
guard "a finished deletion is recorded" "$STAGE/ui/src/app/identity_store.rs" \
    '        record_deletion(&mut crate::migration::PageStore, addr).await;' \
    '        let _ = record_deletion::<crate::migration::PageStore>;' \
    "tests:a_finished_deletion_is_recorded" ui_local_tests
ut "an unreadable identity is not a deletion" "$S" \
    'Reply::Status(status) if status.unreadable_identities == 0 => {}' \
    'Reply::Status(status) if status.unreadable_identities < u32::MAX => {}' \
    an_unreadable_record_is_not_a_deletion
ut "a moved orphan is recorded" "$M/orphans.rs" \
    '            l.moved.push(id.clone());' \
    '            let _ = &l.moved;' \
    an_orphan_moved_before_the_snapshot_does_not_block
ut "an imported backup time is not a backup" "$S" \
    'Ok(at.zip(since).is_some_and(|(at, since)| at > since))' \
    'Ok(at.zip(since).is_some())' \
    an_imported_backup_time_does_not_count
ut "every identity being scrubbed is backed up" "$S" \
    'let count = unprotected(store, scrubbed.collect(), ledger, identities).await?;' \
    'let count = unprotected(store, scrubbed.take(0).collect(), ledger, identities).await?;' \
    an_identity_the_ledger_does_not_list_needs_a_backup_too
ut "local state is cleared before identities" "$S" \
    '    local.into_iter().chain(identities).collect()' \
    '    identities.into_iter().chain(local).collect()' \
    scenario_local_state_is_cleared_before_identities
ut "a failed row forgets the empty loads it had counted" "$S" \
    '        let Some(deleted) = clear_row(adapter, entry).await else {
            update_ledger(store, |l| {
                l.scrub_empty.remove(&generation);
            })
            .await?;' \
    '        let Some(deleted) = clear_row(adapter, entry).await else {' \
    a_failed_row_starts_its_empty_loads_again
ut "a backup at the migration start is not after it" "$S" \
    'is_some_and(|(at, since)| at > since)' \
    'is_some_and(|(at, since)| at >= since)' \
    a_backup_stamped_at_the_migration_start_does_not_count
ut "a missing snapshot chunk blocks" "$S" \
    '            let chunk = chunk.ok_or(Blocker::NoSnapshot)?;' \
    '            let Some(chunk) = chunk else { continue };' \
    a_missing_snapshot_chunk_blocks
ut "a backup made before a late snapshot does not block" "$S" \
    '            fields.remove("last_backup_at");' \
    '            let _ = fields;' \
    a_snapshot_written_late_takes_what_still_equals_the_import
ut "only last_backup_at is left out of a settings comparison" "$S" \
    '            fields.remove("last_backup_at");' \
    '            fields.clear();' \
    a_late_snapshot_does_not_take_a_changed_setting
ut "a cleared row is not cleared again" "$S" \
    '.filter(|e| ledger.scrubbed.get(&e.generation) != Some(&true))' \
    '.filter(|e| ledger.scrubbed.get(&e.generation) != Some(&false) || true)' \
    a_row_needs_two_loads_of_empty_answers
ut "a row counts as cleared only once a re-read shows it" "$S" \
    'matches!(left, Some(Ok(requests)) if requests.is_empty())' \
    'matches!(left, Some(Ok(_)))' \
    a_delete_that_did_not_take_leaves_the_row_unfinished
ut "only a row whose clearing began may read empty" "$S" \
    'if ledger.scrubbed.contains_key(&generation)' \
    'if generation != u32::MAX' \
    a_row_that_imported_and_reads_empty_blocks
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
# A regression that takes a second edit: `also file old new guard ...`.
also() {
    local file="$1" old="$2" new="$3" keep
    shift 3
    if [ "$LIST" -eq 1 ]; then
        "$@"
        return
    fi
    keep="$(mktemp "$STAGE/also.XXXXXX")"
    cp "$file" "$keep"
    replace "$file" "$old" "$new"
    "$@"
    mv "$keep" "$file"
}
source "$ROOT/scripts/check-guards-fail-jobs.sh"
source "$ROOT/scripts/check-guards-fail-inbox.sh"

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
    'dependencies = ["check-release-freeze", "sign-webapp", "check-webapp-scrub", "verify-published-contract"]' \
    'dependencies = ["sign-webapp", "check-webapp-scrub", "verify-published-contract"]' \
    "not ok - publish-email does not run check-release-freeze first" freeze_tests
guard "the release check reads the build" "$STAGE/scripts/check-release-scrub.sh" \
    'if ! grep -a -q -F -- "$MARKER" "$file"; then' 'if false; then' \
    "not ok - a build without the marker is refused" scrub_release_tests
guard "a production publish checks the build for scrub" "$STAGE/Makefile.toml" \
    '"sign-webapp", "check-webapp-scrub", "verify-published-contract"' \
    '"sign-webapp", "verify-published-contract"' \
    "not ok - publish-email does not check the build after building it" scrub_release_tests
guard "the production publish sets the flag" "$STAGE/Makefile.toml" \
    'FREENET_MAIL_SCRUB=1 cargo make publish-production-flow' \
    'cargo make publish-production-flow' \
    "not ok - publish-production does not set the flag" scrub_release_tests
guard "release.sh goes through that publish" "$STAGE/scripts/release.sh" \
    'cargo make publish-production
PUBLISHED=1' \
    'cargo make publish-production-flow
PUBLISHED=1' \
    "not ok - release.sh does not publish through publish-production" scrub_release_tests
guard "the legacy real-node task builds with scrub" "$STAGE/Makefile.toml" \
    'FREENET_MAIL_SCRUB=1 FREENET_MAIL_SCRUB_ISO=1 FREENET_ISO_GW_PORT="$GW_PORT" cargo make publish-email-iso' \
    'FREENET_ISO_GW_PORT="$GW_PORT" cargo make publish-email-iso' \
    "not ok - test-e2e-legacy-migration does not build with the flag, for the harness's nodes" scrub_release_tests
guard "the legacy real-node task checks its build" "$STAGE/Makefile.toml" \
    '# The build that was published has scrub: the marker survived dx and wasm-opt.
bash "$ROOT/scripts/check-release-scrub.sh"' \
    '' \
    "not ok - test-e2e-legacy-migration does not check the build it published" scrub_release_tests
guard "the default real-node task checks its build is refused" "$STAGE/Makefile.toml" \
    '    *"has scrub off"*) ;;' \
    '    *) ;;' \
    "not ok - test-e2e-real-node does not check that the default build is refused" scrub_release_tests
guard "a test signing refuses a build with scrub" "$STAGE/Makefile.toml" \
    'if [ "${FREENET_MAIL_SCRUB_ISO:-}" != "1" ]; then
    "$ROOT/scripts/check-release-scrub.sh" --absent
fi' \
    '' \
    "not ok - a test publish does not refuse a build with scrub in it" scrub_release_tests
guard "a test publish refuses a build with scrub" "$STAGE/Makefile.toml" \
    '# Whatever the environment says, a build with scrub never goes here.
# The probe opt-in is for the harness'"'"'s own nodes, and this publish is not one.
env -u FREENET_E2E_PROBE_ISO "$ROOT/scripts/check-release-scrub.sh" --absent' \
    '' \
    "not ok - a test publish does not refuse a build with scrub in it" scrub_release_tests
guard "the absent check reads the build" "$STAGE/scripts/check-release-scrub.sh" \
    '        if grep -a -q -F -- "$MARKER" "$file"; then' \
    '        if false; then' \
    "not ok - a test publish refuses a build with the marker" scrub_release_tests
guard "the marker is written once" "$STAGE/ui/src/migration/scrub.rs" \
    '    crate::log::info(BUILD_MARKER);' \
    '    crate::log::info("freenet-mail:scrub-built-in");' \
    "not ok - the marker is not written once in the branch the flag selects" scrub_release_tests
guard "the probe marker is written once" "$STAGE/ui/src/jobs.rs" \
    '    crate::log::info(PROBE_MARKER);' \
    '    crate::log::info("freenet-mail:e2e-probe-built-in");' \
    "not ok - the probe marker is not chosen by the feature and logged under it" scrub_release_tests
guard "the probe marker is logged only under the feature" "$STAGE/ui/src/jobs.rs" \
    '    #[cfg(feature = "e2e-probe")]
    crate::log::info(PROBE_MARKER);' \
    '    crate::log::info(PROBE_MARKER);' \
    "not ok - the probe marker is not chosen by the feature and logged under it" scrub_release_tests
guard "the probe marker is chosen by the feature" "$STAGE/ui/src/jobs.rs" \
    'pub(crate) const PROBE_MARKER: &str = if cfg!(feature = "e2e-probe") {' \
    'pub(crate) const PROBE_MARKER: &str = if true {' \
    "tests:the_probe_marker_is_there_only_with_the_feature" ui_jobs_tests
guard "a publish refuses the probe" "$STAGE/scripts/check-release-scrub.sh" \
    '    if grep -a -q -F -- "$PROBE_MARKER" "$file" \' '    if false \' \
    "not ok - a production build with the probe is refused" scrub_release_tests
guard "the probe is allowed only where the background proof says so" "$STAGE/scripts/check-release-scrub.sh" \
    '[ "$ABSENT" -eq 1 ] && [ "${FREENET_E2E_PROBE_ISO:-}" = "1" ]' '[ "$ABSENT" -eq 1 ]' \
    "not ok - a test publish refuses a build with the probe" scrub_release_tests
guard "the freeze override needs the test flag" "$STAGE/scripts/check-release-freeze.sh" \
    'if [ "${RELEASE_FREEZE_TEST:-}" = "1" ]; then' 'if true; then' \
    "not ok - RELEASE_FREEZE_FILE without the test flag does not lift the freeze" freeze_tests
if [ "$WASM" -eq 1 ]; then
    guard "the candidate is the source's build" "$D/store.rs" \
        'pub const MAX_PENDING_PROMPTS: usize = 4;' 'pub const MAX_PENDING_PROMPTS: usize = 5;' \
        'FAIL: published-contract/candidate/mail_delegate is not what' candidate_check
    guard "the inbox candidate is the source's build" "$STAGE/contracts/inbox-v2/src/merge.rs" \
        'per_pass: 8,' 'per_pass: 9,' \
        'FAIL: published-contract/candidate/inbox_v2 is not what' inbox_candidate_check
    guard "inbox v2: a contract build with the test seam does not compile" "$STAGE/contracts/inbox-v2/Cargo.toml" \
        'default = ["freenet-main-contract"]' 'default = ["freenet-main-contract", "plausible-mutants"]' \
        'the plausible-mutants test seam is not part of the contract' inbox_candidate_check
    # The release guard's own tests build real WASM and show each refusal,
    # including each of its two feature checks alone.
    if [ "$LIST" -eq 1 ]; then
        other_shard || echo "release guard: refusals shown on real builds"
    elif ! other_shard; then
        GUARDS_RUN=$((GUARDS_RUN + 1))
        if "$ROOT/scripts/check-release-delegate_test.sh" > "$STAGE/out" 2>&1; then
            echo "ok - release guard: refusals shown on real builds"
        else
            echo "not ok - release guard tests"
            cat "$STAGE/out"
            failures=$((failures + 1))
        fi
    fi
fi

[ "$LIST" -eq 1 ] && exit 0
if [ -n "$SHARD_N" ] && [ -z "${GUARD_ONLY:-}" ] && [ "$GUARDS_RUN" -eq 0 ]; then
    echo "shard $SHARD_I/$SHARD_N ran no guard: a shard that checks nothing must not pass"
    exit 1
fi

[ "$failures" -eq 0 ] || { echo "$failures guard(s) did not fail as they should"; exit 1; }
echo "every guard fails when what it guards is broken"
