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
dt "jobs: 60 writes a minute" "$J" 'pub const MAX_WRITES_PER_MINUTE: u32 = 60;' \
    'pub const MAX_WRITES_PER_MINUTE: u32 = 61;' writes_stop_at_60_a_minute_per_contract_and_count_as_operations
dt "jobs: 1% duty" "$J" 'pub const DUTY_REFILL_MS_PER_SEC: u64 = 10;' \
    'pub const DUTY_REFILL_MS_PER_SEC: u64 = 11;' duty_refills_at_one_percent_up_to_the_burst
dt "jobs: a 10 s burst" "$J" 'pub const DUTY_BURST_MS: u64 = 10_000;' \
    'pub const DUTY_BURST_MS: u64 = 10_001;' duty_refills_at_one_percent_up_to_the_burst
dt "jobs: a clock stepping back" "$J" 'if now / 60 > self.minute {' 'if now / 60 != self.minute {' \
    a_clock_stepping_back_refills_and_reopens_nothing
dt "jobs: a node run stops at its duty" "$J" \
    'MAX_DECRYPT_BATCH.min((self.duty_ms / MESSAGE_COST_MS) as usize)' 'MAX_DECRYPT_BATCH' \
    a_run_decrypts_at_most_a_batch_and_a_node_run_at_most_its_duty,a_node_run_spends_its_duty_and_stops
dt "jobs: a batch is the most a run decrypts" "$J" \
    'MAX_DECRYPT_BATCH.min((self.duty_ms / MESSAGE_COST_MS) as usize)' \
    '((self.duty_ms / MESSAGE_COST_MS) as usize)' \
    a_run_decrypts_at_most_a_batch_and_a_node_run_at_most_its_duty
dt "jobs: a run charges its messages" "$W" 'budget.charge_messages(plan.messages - left);' '' \
    a_node_run_spends_its_duty_and_stops
dt "jobs: a page is not on duty" "$J" 'if unprompted && !budget.take_duty(SCAN_COST_MS) {' \
    'if !budget.take_duty(SCAN_COST_MS) {' a_node_run_with_no_duty_left_scans_nothing_and_a_page_still_does
dt "jobs: scans stop at the duty" "$J" 'if unprompted && !budget.take_duty(SCAN_COST_MS) {' \
    'if false {' a_node_run_with_no_duty_left_scans_nothing_and_a_page_still_does
dt "jobs: scans rotate" "$J" 'budget.cursor = ((start + scan.len()) % eligible.len().max(1)) as u32;' \
    '' scans_rotate_so_every_inbox_is_reached_at_the_per_run_limit
dt "jobs: a contract keeps the rotation" "$J" 'if !matches!(trigger, Trigger::Contract(_)) {' \
    'if true {' a_contract_trigger_scans_only_that_contract_and_keeps_the_rotation
dt "jobs: a refresh stops at the operations left" "$J" \
    'subscribe.truncate(budget.take_ops(subscribe.len()));' '' \
    a_refresh_past_the_operation_limit_subscribes_the_best_it_can

# ── One path, and what each trigger does ────────────────────────────────────
dt "jobs: the node's run is the page's" "$H" 'watch::run(env, trigger).1' \
    'watch::run(env, Trigger::Tick(Tick::Renew)).1' the_page_and_the_node_store_the_same_bytes
dt "jobs: a GET answer is a reason to look" "$H" \
    'InboundDelegateMsg::GetContractResponse(r) => {
            Ok(background(env, contract_trigger(&r.contract_id)?))
        }' 'InboundDelegateMsg::GetContractResponse(_) => Ok(Vec::new()),' \
    every_trigger_imports_through_the_watch
dt "jobs: a run answers no page" "$H" 'watch::run(env, trigger).1' \
    '{ let (d, mut o) = watch::run(env, trigger); o.push(response_msg(RequestId([0; 16]), Ok(Reply::JobsRun(d)))); o }' \
    a_run_tells_no_page_anything
dt "jobs: a new identity is recorded" "$H" 'watch::note_origin(&mut *s.env, origin);
            Ok(info(addr, generation, &record))' 'Ok(info(addr, generation, &record))' \
    a_new_identity_is_watched_with_no_page_ever_asking
dt "jobs: node start refreshes" "$J" \
    'Trigger::NodeStarted => &[Job::V1Refresh, Job::V1Scan, Job::DrainOwn],' \
    'Trigger::NodeStarted => &[Job::V1Scan, Job::DrainOwn],' node_start_subscribes_again
dt "jobs: the hourly tick refreshes" "$J" \
    'Trigger::Tick(Tick::V1Watch) => &[Job::V1Refresh, Job::V1Scan],' \
    'Trigger::Tick(Tick::V1Watch) => &[Job::V1Scan],' \
    a_failed_subscription_is_asked_for_again_by_the_next_refresh,each_trigger_does_only_its_jobs_and_a_clock_tick_drains_first
dt "jobs: a rescan reads" "$J" \
    'Trigger::Tick(Tick::Rescan) | Trigger::Contract(_) => &[Job::V1Scan, Job::DrainOwn],' \
    'Trigger::Tick(Tick::Rescan) => &[Job::DrainOwn], Trigger::Contract(_) => &[Job::V1Scan, Job::DrainOwn],' \
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
dt "jobs: an unread origin list is unknown" "$W" '                done.unknown += 1;
                return Vec::new();' '                return Vec::new();' \
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
    a_copy_written_between_the_lists_and_the_write_stands
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
' '' the_kept_cap_stops_the_import_and_spends_no_more_of_the_slice
dt "jobs: a refused write is retried" "$W" '            Err(_) => done.remaining += 1,' \
    '            Err(_) => note_seen(s, &owner, &id)?,' a_refused_write_is_finished_by_the_next_run

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
    'Err(f) if matches!(f.code, FailureCode::CapReached | FailureCode::Busy) => Ok(()),' \
    'Err(f) if f.code == FailureCode::CapReached => Ok(()),' \
    an_unreadable_tombstone_list_does_not_block_a_delete
dt "jobs: a full store can delete" "$H" \
    'Err(f) if matches!(f.code, FailureCode::CapReached | FailureCode::Busy) => Ok(()),' \
    'Err(f) if f.code == FailureCode::Busy => Ok(()),' a_store_at_its_budget_can_still_delete
dt "jobs: an archive counts as held" "$W" 'held.extend(' 'let _ = (' \
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
dt "jobs: the origin cap" "$W" 'pub const MAX_ORIGINS: usize = 16;' 'pub const MAX_ORIGINS: usize = 17;' \
    each_origin_is_reached_and_a_17th_only_by_its_own_page
dt "jobs: a deleting identity is not watched" "$H" '            && !r.deleting
        {
            out.push((addr, g, r));' '        {
            out.push((addr, g, r));' an_identity_being_deleted_is_not_watched
