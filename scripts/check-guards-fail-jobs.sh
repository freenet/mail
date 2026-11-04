# The background jobs' guards, sourced by check-guards-fail.sh. Each regression
# below names the test that must fail under it; run them alone with
# GUARD_ONLY='^jobs: ' scripts/check-guards-fail.sh --no-wasm.
J="$D/jobs.rs"
W="$D/watch.rs"
H="$D/handlers.rs"
TAKE_OVER='        None => current.is_none(),'

# ── Manifest and allowlist ──────────────────────────────────────────────────
dt "jobs: the tags are the manifest's" "$J" '("rescan", Tick::Rescan)' '("rescann", Tick::Rescan)' \
    the_built_delegate_declares_its_lifecycle_capability_and_wake_ups
dt "jobs: the allowlist is the host set" "$STAGE/scripts/delegate-imports-allowlist.txt" \
    'freenet_rand __frnt__rand__rand_bytes
' '' the_import_allowlist_is_the_stdlib_host_set
dt "jobs: an unknown tag does nothing" "$H" \
    '            None => Vec::new(),
        }),' '            None => background(env, Trigger::Tick(Tick::Rescan)),
        }),' a_tag_this_build_does_not_know_does_nothing

# ── Ranking ─────────────────────────────────────────────────────────────────
dt "jobs: the subscription cap" "$J" 'pub const MAX_SUBSCRIPTIONS: usize = 256;' \
    'pub const MAX_SUBSCRIPTIONS: usize = 257;' ranking_stops_at_the_subscription_cap_exactly
dt "jobs: recent contacts first" "$J" 'std::cmp::Reverse(c.activity)' 'c.activity' \
    ranking_puts_own_before_v1_before_contacts_and_recent_contacts_first
dt "jobs: tiers order the ranking" "$J" 'ranked.sort_by_key(|(tier, position, _)| (*tier, *position));' \
    'ranked.sort_by_key(|(_, position, _)| *position);' \
    at_the_cap_a_contact_never_displaces_an_inbox
dt "jobs: origins take turns" "$J" '                *taken += 1;
                *taken' '                *taken' origins_take_turns_so_a_large_one_cannot_push_out_a_small_one
dt "jobs: one subscription per contract" "$J" \
    'if out.len() < MAX_SUBSCRIPTIONS && !out.contains(&id) {' 'if out.len() < MAX_SUBSCRIPTIONS {' \
    one_identity_in_two_origins_takes_one_subscription

# ── Budgets ─────────────────────────────────────────────────────────────────
dt "jobs: 300 operations a minute" "$J" 'pub const MAX_OPS_PER_MINUTE: u32 = 300;' \
    'pub const MAX_OPS_PER_MINUTE: u32 = 301;' operations_stop_at_300_a_minute_and_come_back_with_the_next
dt "jobs: 1% duty" "$J" 'pub const DUTY_REFILL_MS_PER_SEC: u64 = 10;' \
    'pub const DUTY_REFILL_MS_PER_SEC: u64 = 11;' duty_refills_at_one_percent_up_to_the_burst
dt "jobs: a 10 s burst" "$J" 'pub const DUTY_BURST_MS: u64 = 10_000;' \
    'pub const DUTY_BURST_MS: u64 = 10_001;' duty_refills_at_one_percent_up_to_the_burst
dt "jobs: a clock stepping back" "$J" 'if now / 60 > self.minute {' 'if now / 60 != self.minute {' \
    a_clock_stepping_back_a_little_refills_and_reopens_nothing
dt "jobs: a clock far back starts over" "$J" \
    'if now.saturating_add(CLOCK_RESET_SECS) < self.duty_at {' 'if false {' \
    a_clock_stepping_far_back_starts_the_budget_over
dt "jobs: a clock a little back does not" "$J" \
    'if now.saturating_add(CLOCK_RESET_SECS) < self.duty_at {' 'if now < self.duty_at {' \
    a_clock_stepping_back_a_little_refills_and_reopens_nothing
dt "jobs: a run takes 12 messages at most" "$J" \
    'pub const MAX_MESSAGES_PER_RUN: usize = 12;' 'pub const MAX_MESSAGES_PER_RUN: usize = 13;' \
    a_backlog_is_taken_a_batch_at_a_time_and_resumes
dt "jobs: the budget is saved before the imports" "$W" \
    '    if budget != before {
        save_budget(env, &budget);
    }
    let before = budget.clone();' '' \
    a_run_stopped_by_the_host_resumes_without_repeating_or_losing
dt "jobs: an inbox is charged by its size" "$W" 'budget.charge_bytes(read);' '' \
    a_large_inbox_state_is_charged_by_its_size
dt "jobs: a node run stops at its duty" "$J" \
    'MAX_MESSAGES_PER_RUN.min((self.duty_ms / MESSAGE_COST_MS) as usize)' 'MAX_MESSAGES_PER_RUN' \
    a_run_decrypts_at_most_a_batch_and_a_node_run_at_most_its_duty,a_node_run_spends_its_duty_and_stops
dt "jobs: a batch is the most a run decrypts" "$J" \
    'MAX_MESSAGES_PER_RUN.min((self.duty_ms / MESSAGE_COST_MS) as usize)' \
    '((self.duty_ms / MESSAGE_COST_MS) as usize)' \
    a_run_decrypts_at_most_a_batch_and_a_node_run_at_most_its_duty
dt "jobs: a run charges its messages" "$W" 'budget.charge_messages(plan.messages - left);' '' \
    the_kept_cap_stops_the_import_and_spends_no_more_of_the_slice
dt "jobs: a page is not on duty" "$J" 'if unprompted && !budget.take_duty(SCAN_COST_MS) {' \
    'if !budget.take_duty(SCAN_COST_MS) {' a_node_run_with_no_duty_left_scans_nothing_and_a_page_still_does
dt "jobs: scans stop at the duty" "$J" 'if unprompted && !budget.take_duty(SCAN_COST_MS) {' \
    'if false {' a_node_run_with_no_duty_left_scans_nothing_and_a_page_still_does
dt "jobs: scans rotate" "$J" 'budget.cursor = ((start + scan.len()) % eligible.len().max(1)) as u32;' \
    '' scans_rotate_so_every_inbox_is_reached_at_the_per_run_limit
dt "jobs: a contract keeps the rotation" "$J" 'if !matches!(trigger, Trigger::Contract(_)) {' \
    'if true {' a_contract_trigger_scans_only_that_contract_and_keeps_the_rotation
dt "jobs: a page run keeps the shared rotation" "$W" '        budget.cursor = before.cursor;' '' \
    a_page_run_does_not_move_the_rotation_of_a_later_identity
dt "jobs: a page rotates on its own cursor" "$W" \
    '            let _ = Space::new(&mut *env, o).put(PAGE_CURSOR, &budget.cursor.to_le_bytes());' '' \
    a_node_with_no_wake_ups_still_reaches_every_identity_of_a_page
dt "jobs: a refresh stops at the operations left" "$J" \
    'subscribe.truncate(budget.take_ops(subscribe.len()));' '' \
    a_refresh_past_the_operation_limit_subscribes_the_best_it_can

# ── One path, and what each trigger does ────────────────────────────────────
dt "jobs: the node's run is the page's" "$H" 'let (done, out) = watch::run(env, trigger);' \
    'let (done, out) = watch::run(env, Trigger::Tick(Tick::Renew));' the_page_and_the_node_store_the_same_bytes
dt "jobs: a GET answer is a reason to look" "$H" \
    'InboundDelegateMsg::GetContractResponse(r) => {
            let trigger = contract_trigger(&r.contract_id)?;
            Ok(background(env, trigger, "get-answer"))
        }' 'InboundDelegateMsg::GetContractResponse(_) => Ok(Vec::new()),' \
    every_trigger_imports_through_the_watch
dt "jobs: a run answers no page" "$H" 'let (done, out) = watch::run(env, trigger);' \
    'let (done, mut out) = watch::run(env, trigger); out.push(response_msg(RequestId([0; 16]), Ok(Reply::JobsRun(done))));' \
    a_run_tells_no_page_anything
dt "jobs: a new identity is recorded" "$H" 'watch::note_origin(&mut *s.env, origin);
            Ok(info(addr, generation, &record))' 'Ok(info(addr, generation, &record))' \
    a_new_identity_is_watched_with_no_page_ever_asking
dt "jobs: a subscription answer writes nothing" "$H" \
    'InboundDelegateMsg::SubscribeContractResponse(_) => Ok(Vec::new()),' \
    'InboundDelegateMsg::SubscribeContractResponse(_) => { env.set(b"x", b"y"); Ok(Vec::new()) }' \
    a_forged_subscription_answer_does_not_stop_the_next_refresh_asking
dt "jobs: a page run asks no network" "$W" '        if unprompted && plan.fetch_missing && budget.may_ask(&id)' '        if plan.fetch_missing && budget.may_ask(&id)' \
    a_page_run_never_asks_the_network_for_an_inbox_this_node_lacks
dt "jobs: a page run subscribes only held inboxes" "$W" \
    '.filter(|id| unprompted || held.contains(id))' '.filter(|_| true)' \
    a_page_run_never_asks_the_network_for_an_inbox_this_node_lacks
dt "jobs: a missing inbox backs off" "$J" '.is_none_or(|(_, _, next)| self.duty_at >= *next)' \
    '.is_none_or(|_| true)' \
    a_missing_inbox_is_asked_for_at_doubling_intervals_up_to_a_day
dt "jobs: the backoff doubles" "$J" '.saturating_mul(1u64 << (asks - 1).min(16))' '.saturating_mul(1)' \
    a_missing_inbox_is_asked_for_at_doubling_intervals_up_to_a_day
dt "jobs: the backoff stops at a day" "$J" '            .min(MISSING_BACKOFF_MAX_SECS);' '            ;' \
    a_missing_inbox_is_asked_for_at_doubling_intervals_up_to_a_day
dt "jobs: a refresh waits for the backoff" "$J" '            subscribe.retain(|id| budget.may_ask(id));' '' \
    a_missing_inbox_is_asked_for_at_doubling_intervals_up_to_a_day
dt "jobs: a success clears the backoff" "$W" '        budget.note_held(id);' '' \
    a_missing_inbox_found_is_asked_for_at_once_if_it_goes_missing_again
dt "jobs: a missing inbox is noted" "$W" '            budget.note_missing(id);
            noted.push(id);' '            noted.push(id);' \
    a_missing_inbox_is_asked_for_at_doubling_intervals_up_to_a_day
dt "jobs: an empty origin gives up its place" "$W" 'if !emptied.is_empty() {' 'if false {' \
    an_origin_with_no_identities_left_gives_up_its_place
dt "jobs: the hourly tick refreshes" "$J" \
    'Trigger::Tick(Tick::V1Watch) => &[Job::V1Refresh, Job::V1Scan],' \
    'Trigger::Tick(Tick::V1Watch) => &[Job::V1Scan],' \
    a_failed_subscription_is_asked_for_again_by_the_next_refresh,each_trigger_does_only_its_jobs_and_a_clock_tick_drains_first
dt "jobs: a rescan reads" "$J" \
    'Trigger::Tick(Tick::Rescan) => &[Job::V1Scan, Job::DrainOwn, Job::AdvanceClock, Job::Renew],' \
    'Trigger::Tick(Tick::Rescan) => &[Job::DrainOwn, Job::AdvanceClock, Job::Renew],' \
    a_rescan_recovers_a_dropped_notification
dt "jobs: a contract trigger is only that contract" "$J" \
    'Trigger::Contract(id) => targets.iter().filter(|t| t.id == id).copied().collect(),' \
    'Trigger::Contract(_) => targets.to_vec(),' \
    a_notification_for_a_contract_nobody_here_watches_does_nothing,a_contract_trigger_scans_only_that_contract_and_keeps_the_rotation

# ── Unknown is never absent ─────────────────────────────────────────────────
dt "jobs: no state is not an empty inbox" "$W" \
    '.ok_or_else(|| unknown("the inbox is not held here"))?;' \
    '.unwrap_or_else(|| b"{\"messages\":[]}".to_vec());' a_refused_get_is_unknown_and_asked_again
dt "jobs: an undecodable state is not an empty inbox" "$W" \
    'serde_json::from_slice(&state).map_err(|_| unknown("the inbox state does not decode"))?;' \
    'serde_json::from_slice(&state).unwrap_or(V1Inbox { messages: Vec::new() });' \
    a_state_that_does_not_decode_is_unknown
dt "jobs: the size limit" "$W" 'state.len() <= MAX_INBOX_BYTES' 'state.len() < MAX_INBOX_BYTES' \
    a_state_over_the_size_limit_is_unknown
dt "jobs: the watch reads v0.2.x states" "$W" '    content: Vec<u8>,
    #[serde(default)]
    sender_vk' '    #[serde(rename = "contents")]
    content: Vec<u8>,
    #[serde(default)]
    sender_vk' a_captured_v0_2_x_inbox_state_is_read
dt "jobs: an unread origin list is unknown" "$W" '            let Ok((_, ids)) = listed else {
                done.unknown += 1;
                return (Vec::new(), Vec::new());' '            let Ok((_, ids)) = listed else {
                return (Vec::new(), Vec::new());' \
    an_origin_list_that_cannot_be_read_is_unknown

# ── Notifications ───────────────────────────────────────────────────────────
ADOPT='    fn contract_state(&self, instance_id: &[u8; 32]) -> Option<Vec<u8>>;'
also "$D/env.rs" "$ADOPT" "$ADOPT
    fn adopt(&mut self, _id: [u8; 32], _state: Vec<u8>) {}" \
    also "$D/env.rs" '        fn now_secs(&self) -> Option<u64> {
            self.now
        }' '        fn now_secs(&self) -> Option<u64> {
            self.now
        }
        fn adopt(&mut self, id: [u8; 32], state: Vec<u8>) {
            self.contracts.insert(id, state);
        }' \
    dt "jobs: a notification's state is not used" "$H" \
    'InboundDelegateMsg::ContractNotification(n) => {' \
    'InboundDelegateMsg::ContractNotification(n) => {
            if let Ok(id) = <[u8; 32]>::try_from(n.contract_id.as_bytes()) {
                env.adopt(id, n.new_state.as_ref().to_vec());
            }' \
    what_a_notification_or_a_get_answer_carries_is_not_used,an_out_of_order_notification_reads_the_current_state

# ── Import ──────────────────────────────────────────────────────────────────
dt "jobs: the signature is checked" "$W" \
    'signature_valid: crypto::verify_v1(&m.content, &m.sender_vk, &m.signature),' \
    'signature_valid: true,' a_forged_signature_is_recorded_as_invalid_like_the_page_records_it
dt "jobs: the send time is kept" "$W" 'sent_at: Some(message.time.timestamp_millis()),' \
    'sent_at: None,' an_import_is_the_page_s_kept_copy_with_a_checked_signature
dt "jobs: an import is create-only" "$H" "$TAKE_OVER" '        None => true,' \
    a_copy_written_between_the_lists_and_the_write_stands,an_import_leaves_existing_flags_as_they_are
dt "jobs: an import says it is unread" "$W" \
    'br#"{"read":false,"deleted":false}"#;' 'br#"{"read":true,"deleted":false}"#;' \
    an_import_says_it_is_unread
dt "jobs: a held message is skipped before it is decrypted" "$W" \
    'if seen.contains(&id[..]) || held.contains(&id[..]) {' 'if seen.contains(&id[..]) {' \
    a_duplicate_notification_decrypts_nothing_and_is_charged_only_its_scan
dt "jobs: a message the page cannot read is not kept (no to)" "$W" \
    '    #[allow(dead_code)]
    to: Vec<Vec<u8>>,' '' a_message_the_page_could_not_read_is_not_kept_by_the_watch
dt "jobs: a message the page cannot read is not kept (no cc)" "$W" \
    '    #[allow(dead_code)]
    cc: Vec<String>,' '' a_message_the_page_could_not_read_is_not_kept_by_the_watch
also "$H" "$TAKE_OVER" '        None => true,' \
    dt "jobs: a held message is not imported" "$W" \
    'if seen.contains(&id[..]) || held.contains(&id[..]) {' 'if seen.contains(&id[..]) {' \
    an_import_never_overwrites_a_kept_copy,a_duplicate_notification_changes_nothing
dt "jobs: a backlog is sliced" "$W" '        *left -= 1;
' '' a_backlog_is_taken_a_batch_at_a_time_and_resumes
dt "jobs: a message that never decrypts is left alone" "$W" \
    '            note_seen(s, &owner, &id)?;
            continue;' '            continue;' a_message_that_never_decrypts_costs_one_slice
dt "jobs: the cap ends the slice" "$W" '                full = true;
                done.remaining += 1;
            }' '                done.remaining += 1;
            }' the_kept_cap_stops_the_import_and_spends_no_more_of_the_slice
dt "jobs: a refused write is retried" "$W" '            Err(_) => done.remaining += 1,' \
    '            Err(_) => note_seen(s, &owner, &id)?,' a_refused_kept_write_is_finished_by_the_next_run
dt "jobs: a refused flags write is retried" "$W" '            Err(_) => {
                done.remaining += 1;
                continue;
            }' '            Err(_) => {
                note_seen(s, &owner, &id)?;
                continue;
            }' a_refused_flags_write_is_finished_by_the_next_run

# ── Never brings back a deleted message ─────────────────────────────────────
dt "jobs: a tombstone stops an import" "$W" \
    'if seen.contains(&id[..]) || held.contains(&id[..]) {' 'if held.contains(&id[..]) {' \
    a_deleted_import_stays_deleted,a_reclaimed_mark_does_not_let_an_older_state_bring_a_message_back
NO_TOMBSTONE='let (ItemKind::Kept | ItemKind::Archived | ItemKind::Flags, Some(owner)) ='
dt "jobs: a delete leaves a tombstone" "$H" "$NO_TOMBSTONE" 'let (ItemKind::Draft, Some(owner)) =' \
    a_deleted_import_stays_deleted,a_reclaimed_mark_does_not_let_an_older_state_bring_a_message_back
guard "jobs: the fault runs see a deleted message return" "$H" "$NO_TOMBSTONE" \
    'let (ItemKind::Draft, Some(owner)) =' "tests:$FAULT_RUN" fault_tests
dt "jobs: a deleted flag stops an import" "$W" 'Some(true) => continue,' 'Some(true) => {}' \
    a_message_flagged_deleted_is_not_imported
dt "jobs: a read flag does not" "$W" 'Some(false) => {}' 'Some(false) => continue,' \
    a_message_flagged_read_is_imported
dt "jobs: an unreadable mark stops an import" "$W" '                None => {
                    done.remaining += 1;
                    continue;
                }' '                None => done.remaining += 1,' a_mark_that_cannot_be_read_stops_the_import
dt "jobs: an unreadable shard stops the scan" "$W" 'seen.extend(s.index(&rel)?.1);' \
    'seen.extend(s.index(&rel).map(|x| x.1).unwrap_or_default());' \
    an_unreadable_list_of_tombstones_stops_the_scan
dt "jobs: an unreadable shard does not block a delete" "$H" \
    'Err(_) if s.index_unreadable(&store::seen_rel(&owner, &item.id)) => Ok(()),' '' \
    an_unreadable_tombstone_list_does_not_block_a_delete
dt "jobs: only an unreadable shard skips the tombstone" "$H" \
    'Err(_) if s.index_unreadable(&store::seen_rel(&owner, &item.id)) => Ok(()),' \
    'Err(_) => Ok(()),' a_delete_with_no_tombstone_written_is_not_a_delete
dt "jobs: a full store can delete" "$H" \
    '        Err(f) if f.code == FailureCode::CapReached => Ok(()),
        // A shard' '        // A shard' a_store_at_its_budget_can_still_delete
dt "jobs: an archive counts as held" "$W" 'held.extend(
        s.index(&store::index_rel(ItemKind::Archived' 'let _ = (
        s.index(&store::index_rel(ItemKind::Archived' \
    an_archived_message_is_not_imported
dt "jobs: a full shard makes room" "$W" 'if ids.len() >= SEEN_PER_SHARD' 'if false' \
    a_full_shard_of_tombstones_makes_room
dt "jobs: tombstones are exported" "$H" \
    '.filter(|rel| matches!(s.index(rel), Ok((_, ids)) if !ids.is_empty())),' '.filter(|_| false),' \
    tombstones_travel_with_an_export_and_leave_with_the_identity
dt "jobs: tombstones leave with the identity" "$H" '    for rel in store::seen_rels(addr) {
        s.del(&rel)?;
        s.del(&store::index_marker_rel(&rel))?;
    }
' '' tombstones_travel_with_an_export_and_leave_with_the_identity
dt "jobs: a recount counts tombstones" "$D/store.rs" '                for rel in seen_rels(&addr) {
                    listed(&mut out, &rel);
                }
' '' a_recount_counts_the_tombstones

# ── Gate ────────────────────────────────────────────────────────────────────
also "$J" 'Trigger::RunJobs(origin) => targets
            .iter()
            .filter(|t| t.origin == origin)
            .copied()
            .collect(),
        Trigger::NodeStarted | Trigger::Tick(_) => targets.to_vec(),' \
    'Trigger::RunJobs(_) | Trigger::NodeStarted | Trigger::Tick(_) => targets.to_vec(),' \
    dt "jobs: a page runs only its own namespace" "$W" \
    'Trigger::RunJobs(origin) => vec![origin],
        Trigger::NodeStarted | Trigger::Tick(_) | Trigger::Contract(_) => {' \
    'Trigger::RunJobs(_) | Trigger::NodeStarted | Trigger::Tick(_) | Trigger::Contract(_) => {' \
    a_run_for_one_origin_says_nothing_of_another
dt "jobs: the gate still refuses no origin" "$H" '        None => Err(DelegateError::Other(
            "the mail delegate requires an attested web-app origin".into(),
        )),' '        None => Ok(Origin([9; 32])),' an_unattested_or_delegate_caller_still_cannot_ask
dt "jobs: the delegate's namespace is no app's" "$H" 'if Origin(bytes) == watch::GLOBAL {' 'if false {' \
    the_delegate_s_own_namespace_is_no_app_s_origin
dt "jobs: the origin cap" "$W" 'pub const MAX_ORIGINS: usize = 16;' 'pub const MAX_ORIGINS: usize = 18;' \
    each_origin_is_reached_and_a_17th_only_by_its_own_page
dt "jobs: a deleting identity is not watched" "$H" '            && !r.deleting
        {
            out.push((addr, g, r));' '        {
            out.push((addr, g, r));' an_identity_being_deleted_is_not_watched

# ── The page's side: unread imports, deletion, the loop ─────────────────────
UI="$STAGE/ui/src"
uj() { guard "$1" "$2" "$3" "$4" "tests:$5" ui_jobs_tests; }
uj "jobs: an import shows unread" "$UI/app.rs" \
    'let read = is_read(mid) || !is_unread_import(mid);' 'let read = true;' \
    kept_import_is_unread_until_read_and_a_migrated_copy_is_read
uj "jobs: a read mark overrides the unread flags" "$UI/app.rs" \
    'let read = is_read(mid) || !is_unread_import(mid);' 'let read = !is_unread_import(mid);' \
    kept_import_is_unread_until_read_and_a_migrated_copy_is_read
uj "jobs: only unread flags mark an import" "$UI/local_state/items.rs" \
    'if !f.read && !f.deleted {' 'if !f.deleted {' \
    unread_flags_mark_an_import_and_nothing_else_does
uj "jobs: a deleted flag is not an unread import" "$UI/local_state/items.rs" \
    'if !f.read && !f.deleted {' 'if !f.read {' \
    unread_flags_mark_an_import_and_nothing_else_does
uj "jobs: a delete takes back a copy imported meanwhile" "$UI/local_state/items.rs" \
    '    // A background import between the first delete and the flags (the
    // message had no kept copy yet) makes a copy beside the mark. The flags
    // now stop any further import, so one more delete takes it back.
    delete(message_item(ItemKind::Kept, &alias, msg_id)?)
        .await
        .map_err(boxed)
}' '    Ok(())
}' an_import_between_the_copies_and_the_mark_is_taken_back
uj "jobs: the page loop starts once" "$UI/jobs.rs" '!s.replace(true)' 'true' \
    the_loop_starts_once_however_often_the_identities_load
dt "jobs: a subscription counts as an ask" "$W" '                budget.note_missing(*id);' '' \
    a_missing_inbox_outside_the_scan_slice_waits_out_its_backoff,a_missing_inbox_with_the_duty_out_waits_out_its_backoff
dt "jobs: a page run spends no operations" "$J" '        if unprompted {
            subscribe.truncate(budget.take_ops(subscribe.len()));' '        {
            subscribe.truncate(budget.take_ops(subscribe.len()));' \
    a_page_run_does_not_use_up_the_operations_of_a_later_refresh
