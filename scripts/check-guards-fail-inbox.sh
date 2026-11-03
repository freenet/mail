# Inbox v2's gates, sourced by check-guards-fail.sh. Each regression below
# names the test or message that must fail under it. Run them alone with
# GUARD_ONLY='^inbox v2: ' scripts/check-guards-fail.sh --no-wasm.
#
# Not here, because they take too long to repeat in every shard: a real branch
# coverage run, a real cargo-mutants run and a real fdev run. Their scripts are
# shown failing on small inputs instead (the *_test.sh files), and the PR that
# added them shows each failing once on the real thing.
I="$STAGE/contracts/inbox-v2"

# ── The canonical-CBOR check ────────────────────────────────────────────────
guard "inbox v2: a non-canonical encoding is refused" "$I/src/types.rs" \
    '    if encode(&value) != bytes {' '    if false {' \
    "tests:every_other_spelling_is_refused_everywhere,a_delta_is_held_to_the_same_spelling" \
    inbox_rule_tests

# ── The byte vectors come from the second implementation ───────────────────
guard "inbox v2: a hand edit of vectors.txt fails the vectors check" \
    "$I/tests/fixtures/vectors.txt" 'address_check 5a6a' 'address_check 5a6b' \
    'FAIL: vectors.txt is not what vectors.py writes.' inbox_vectors_check

# ── A real rule, broken ─────────────────────────────────────────────────────
guard "inbox v2: a rule broken by one character is caught" "$I/src/merge.rs" \
    '|| message.sent_time < self.owner_time.saturating_sub(WINDOW_BACK)' \
    '|| message.sent_time <= self.owner_time.saturating_sub(WINDOW_BACK)' \
    "tests:the_window_at_its_edges" inbox_rule_tests

# ── The plausible mutants ───────────────────────────────────────────────────
guard "inbox v2: a plausible mutant that is not switched on is not credited" "$I/src/merge.rs" \
    '        let tier_met = mutant::tier_met(tier_met);' \
    '        let tier_met = tier_met;' \
    "tests:tier_check_skipped" inbox_plausible_tests
guard "inbox v2: the real rules are held to a plausible mutant's law" "$I/src/merge.rs" \
    '        let tier_met = ghost.usd >= u64::from(min_usd.unwrap_or(0));' \
    '        let tier_met = true;' \
    "tests:tier_check_skipped" inbox_plausible_tests

# ── The disclosure gate ─────────────────────────────────────────────────────
guard "inbox v2: a plaintext field missing from the toml fails the gate" \
    "$STAGE/docs/metadata-fields.toml" 'path = "owner.version"' 'path = "owner.versions"' \
    "tests:the_toml_lists_exactly_the_plaintext_fields" inbox_disclosure_tests
guard "inbox v2: a map key missing from the toml fails the gate" \
    "$STAGE/docs/metadata-fields.toml" 'path = "revoked.[key]"' 'path = "revoked.[keys]"' \
    "tests:the_toml_lists_exactly_the_plaintext_fields" inbox_disclosure_tests
guard "inbox v2: a gate that skips map keys fails" \
    "$I/tests/metadata_disclosure.rs" \
    '                        out.insert(format!("{prefix}.[key]"));' \
    '                        let _ = &out;' \
    "tests:the_toml_lists_exactly_the_plaintext_fields" inbox_disclosure_tests
guard "inbox v2: a field with no reason fails the gate" \
    "$STAGE/docs/metadata-fields.toml" \
    'why = "The issuer'"'"'s signature over the owner time."' 'why = "x"' \
    "tests:every_field_says_what_it_is_and_why_it_is_public" inbox_disclosure_tests
guard "inbox v2: a proof outside a quarantine message fails the gate" \
    "$I/tests/metadata_disclosure.rs" \
    '            path.starts_with("messages.*.admission.Quarantine.ghost."),' \
    '            !path.starts_with("messages.*.admission.Quarantine.ghost."),' \
    "tests:a_ghost_key_proof_is_only_where_the_quarantine_is" inbox_disclosure_tests

# ── The scripts of the slow gates, on small inputs ──────────────────────────
guard "inbox v2: an unvisited branch fails the coverage gate" \
    "$STAGE/scripts/check-branch-coverage.py" '    missing = {key: at for key, at in unvisited.items() if key not in allowed}' \
    '    missing = {}' \
    'not ok - an unvisited arm fails' coverage_check_tests
guard "inbox v2: a stale allowlist entry fails the coverage gate" \
    "$STAGE/scripts/check-branch-coverage.py" '    stale = sorted(allowed - set(unvisited))' '    stale = []' \
    'not ok - a stale allowlist entry fails' coverage_check_tests
guard "inbox v2: a survivor with no triage fails the mutants gate" \
    "$STAGE/scripts/check-mutants-triage.sh" 'untriaged = sorted(survivors - triaged)' 'untriaged = []' \
    'not ok - a survivor with no triage line' triage_check_tests
guard "inbox v2: a mutants run that tested nothing fails the mutants gate" \
    "$STAGE/scripts/check-mutants-triage.sh" '    if not caught:' '    if False:' \
    'not ok - a run that tested nothing' triage_check_tests
guard "inbox v2: an inconclusive verdict fails the verify-merge gate" \
    "$STAGE/scripts/check-fdev-verify-merge.sh" 'if r["inconclusive"]:' 'if False:' \
    'not ok - inconclusive is not a pass' verify_merge_check_tests
