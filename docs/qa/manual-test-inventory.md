# Freenet Email — QA inventory

Single source of truth for what's tested and how. The `freenet-mail-qa`
skill (`.claude/skills/freenet-mail-qa/SKILL.md`) instructs agents to
read and update this file.

## Conventions

Status column:

- **auto** — covered by an automated test (offline Playwright, iso-harness
  Playwright, or Rust unit). Cell links to the spec and test title.
- **manual** — covered only by manual exercise. Recipe is in the
  "Manual recipe" column.
- **automatable** — manual today, but no infra blocker. Add to backlog.
- **blocked** — needs infra/feature work to automate (cite issue).

When you add or remove a test, update the matching row. When you fix a
manual gap by adding a test, flip status to `auto` and link the test.

## Suites

- **offline** — `ui/tests/email-app.spec.ts` + `ui/tests/threads.spec.ts`
  (#270). `--features example-data,no-sync`. No Freenet node. Run via
  `cargo make test-ui-playwright`.
- **iso** — `ui/tests/live-node.spec.ts`. Real `use-node` build against
  isolated 2-node net (`scripts/run-isolated-nodes.sh`). Run via `cargo
  make test-e2e-real-node`. Cross-node send tests gated on
  `FREENET_LIVE_E2E_SEND=1`.
- **liveness** — `ui/tests/production-liveness.spec.ts`. Smoke against
  deployed gateway. Run via `scripts/smoke-test-production.sh`.
- **rust** — `cargo test -p freenet-email-ui` (and per-crate).

## Coverage matrix

### Identity & login

| Behavior | Status | Test / recipe |
|---|---|---|
| Create identity (alias input + reveal stage + confirm) | auto | offline: `renders with mock identities and create link`; iso: `create identity → reload persists → drives permission flow` |
| Identity surfaces without manual reload (#76) | auto | iso: `create identity → reload persists` |
| Backup file-picker disabled until a backup is parsed | auto | offline: `opens a file-picker form with disabled Restore until a backup is parsed` |
| Backup → restore round-trip (export, wipe, import, identity present) | manual | Compose, generate backup, save file, log out, restore from file, confirm alias + sent + drafts present |
| Rename identity in place | auto | offline: `renames an id-row in place and surfaces the new alias` |
| Refuses duplicate alias on rename | auto | offline: `refuses to rename to an alias that already exists` |
| Delete identity (confirm-modal + row removed) | manual | Open IdentifiersList, click 🗑 on an id-row, type alias verbatim, click Delete identity, confirm row disappears and `Identity::get_alias()` no longer returns it. Inbox + AFT contracts remain on-chain (no on-chain delete primitive). |
| Delete identity refuses without exact alias match | manual | Open delete modal, type wrong alias, expect inline error "Type the alias exactly as shown to confirm." and no row removal. |
| Delete identity while logged in clears active id | manual | Open inbox, navigate back to IdentifiersList, delete the currently-active identity, confirm app falls back to the identifiers list and active selection is cleared. |
| 3+ identities switch + sidebar fingerprint flips | auto (2 ids) / manual (3+) | offline: `fingerprint changes when switching identities` covers 2; 3+ via `cargo make dev-example` + create another + cycle |
| Switcher in Settings (popover open/close + active row) | manual | Open Settings, click ident switcher button, click a non-active row, verify identity context flipped |

### Contacts / address book

| Behavior | Status | Test / recipe |
|---|---|---|
| Share modal contains six-word fingerprint + bs58 inbox address (#249) | auto | offline: `opens with six-word fingerprint, bs58 inbox address, and copy button` |
| Import contact: alias → resolves in compose | auto | offline: `import contact card → appears in contacts section → compose accepts alias` |
| Verify checkbox tick → badge flips to verified | auto | offline: `ticking the verify card flips the contact's badge to verified` |
| Verify button promotes unverified contact in place (#87) | auto | offline: `Verify button promotes an unverified contact in place` |
| `verify_on_send` blocks unverified-contact send (toast) | manual | Enable "Require known key to send" (off by default), import a contact without ticking verify, Send → expect "Recipient is not verified" toast, no Sent row |
| Edit / delete contact | manual | Open Contacts, click row, edit label / description, save; delete and confirm gone |
| Self-card in Contacts (own identity) | manual | Confirm own identity surfaces in Contacts with "you" indicator (or absent — verify intended behavior) |
| Contact import + reload + UpdateNotification stays sane (#198/#204) | auto | iso: `contact import + reload + UpdateNotification stays sane (#204)` |

### Inbox / message read flow

| Behavior | Status | Test / recipe |
|---|---|---|
| Inbox row click opens detail | auto | offline: `opens an email and shows content` |
| Click row stays as read (#106) | auto | iso: `multi-round + read + archive across nodes` |
| Cards show timestamps + newest-first sort (#49) | auto | offline: `inbox cards show timestamps and sort newest-first` |
| Detail header full timestamp | auto | offline: `detail header shows full timestamp` |
| Detail verified badge (verif-known / verif-unknown / unverified) | auto | offline: `detail header shows verified badge for incoming message` |
| Search filter | manual | Send 3 messages with distinct subjects, type substring in sidebar Search, only matching rows visible |
| Quarantine unknown sender | manual | Toggle in Settings → Inbox, send from unknown sender, confirm a Quarantine folder appears with a count badge and the row lands there (not Inbox); verified senders stay in Inbox |
| Hide unsigned (privacy pref) | manual | Toggle, deliver pre-#51 message, confirm hidden |

### Threading (#270)

Offline coverage lives in `ui/tests/threads.spec.ts`, driven by the
seeded conversation in `ui/src/app.rs::load_example_messages` (thread
"example-thread-0001", subject "Lunch tomorrow?", 3 messages + 2
standalone). All rows below are `auto`.

| Behavior | Status | Test / recipe |
|---|---|---|
| Inbox list collapses a back-and-forth into one row with a count badge; standalone rows stay separate | auto | offline (`threads.spec.ts`): `collapses a back-and-forth into one row with a count badge, standalone rows stay separate` |
| Clicking a thread group opens the threaded detail container | auto | offline (`threads.spec.ts`): `clicking the thread group opens the threaded detail container` |
| Nested view default-expands the last (leaf) message; collapsed nodes expand on click | auto | offline (`threads.spec.ts`): `default-expands the last message of the branch; collapsed nodes expand on click` |
| Nested view "in reply to" quote chip toggles the quoted excerpt | auto | offline (`threads.spec.ts`): `the 'in reply to' quote chip toggles` |
| Compact view default-expands only the newest message; clicking a row toggles it | auto | offline (`threads.spec.ts`): `default-expands only the newest message; clicking a row toggles it` |
| Reply within a thread stays in the same thread (no new top-level row); compose has no legacy "> " quote hack | auto | offline (`threads.spec.ts`): `reply keeps the conversation in the same thread (no new top-level row); compose body has no '> ' quote hack` |
| Thread grouping by thread_id / legacy subject+participant heuristic; depth capped at 4 | auto (rust) | `cargo test -p freenet-email-ui` — `app::thread_grouping_tests::*` (groups_by_thread_id, groups_legacy_by_heuristic_subject_and_participant, depth_computed_from_chain_and_capped, …) |
| Thread-component storybook: renders real `ThreadDetail`/`ThreadNested`/`ThreadCompact` from hand-built `ThreadGroup` props (not mailbox seeds); `.is-me` accent on own messages, depth-4 cap, Nested-vs-Compact per `?view=`; screenshots each story | auto | offline (`threads-storybook.spec.ts`): `sender-sent interleaved thread shows .is-me accents`, `deep-nest clamps at MAX_THREAD_DEPTH (depth-4)`, `Nested view rails + quote chips`, `Compact view one row per message`. Host is `example-data`-only + gated on `?story=` (`ui/src/app.rs::storybook`); zero surface in `use-node`. Open in-app via `cargo make dev-example` + `/?story=sender-sent-in-thread\|deep-nest\|nested-vs-compact[&view=compact]`. |

### Compose / send

| Behavior | Status | Test / recipe |
|---|---|---|
| Compose sheet renders + dismiss on Send | auto | offline: `compose sheet renders and log out returns to identity list`, `clicking Send dismisses the compose sheet` |
| Sending-as fingerprint label | auto | offline: `compose sheet shows 'Sending as: <fingerprint>' label` |
| Recipient fingerprint badge resolves | auto (implicit, used in many tests) | covered transitively |
| Cross-node send delivers | auto | iso: `alice → bob across nodes: send + receive end-to-end (#81)` |
| Multi-recipient (To: alice, bob, charlie) | manual | Compose, type comma-separated aliases, confirm 3 fingerprint badges, send, confirm 3 inboxes receive |
| Auto-sign appends signature once (idempotent on resend) | manual | Settings → Auto-sign on, set signature, send, inspect Sent body for sig; Resend, confirm not duplicated |
| Forward prefills blank recipient + Fwd: subject + quoted body | auto | offline: `Forward prefills blank recipient + Fwd: subject + quoted body` |
| Reply prefills recipient + Re: subject + quoted body (#274B) | auto | offline: `Reply prefills recipient + Re: subject` (asserts quoted body since #274B). |
| Resend prefills identical recipient/subject/body | auto | offline: `Resend prefills identical recipient/subject/body` |
| Reply from Archive folder | manual | Archive a message, open it from Archive, click Reply, confirm prefill |
| Empty body / no recipient → submit blocked or warns | manual | Compose, leave fields blank, click Send, observe behavior |

### Drafts

| Behavior | Status | Test / recipe |
|---|---|---|
| Typing populates Drafts; reopen restores fields | auto | offline: `typing in compose populates Drafts; reopening restores fields` |
| Discard removes the draft | auto | offline: `Discard removes the draft` |
| Send removes the draft | auto | offline: `Send removes the draft` |
| Sent doesn't leak into Drafts (#107) | auto | implicit via `Send removes the draft`; cross-node iso `multi-round` |
| Draft folder count badge | auto | offline: `draft folder count badge reflects pending drafts` |
| Long typing burst → debounced delegate save | manual | Type 200+ chars rapidly, wait 1s, reload, confirm draft state |

### Sent / delivery

| Behavior | Status | Test / recipe |
|---|---|---|
| Send populates Sent; click renders detail panel | auto | offline: `Send populates Sent; click renders detail panel` |
| Sent count badge | auto | offline: `Sent count badge reflects sent messages` |
| Offline Delivered state | auto | offline: `offline send marks the Sent row Delivered` |
| Sent row Pending → Delivered on UpdateResponse (cross-node) | auto | iso: `alice → bob` (transitively — Sent row visible after send) |
| Sent row Pending → Failed on send error | manual | Stop peer node post-send-click, observe Sent row flip to Failed |
| Read-receipt (#69) | blocked | Issue #69 — feature not implemented |

### Archive / delete

| Behavior | Status | Test / recipe |
|---|---|---|
| Archive moves Inbox row to Archive folder | auto | offline: `Archive moves message from Inbox to Archive folder` |
| Delete from Inbox does NOT create Archive entry | auto | offline: `Delete from Inbox does not produce an Archive entry` |
| Archive count badge | auto | offline: `Archive count badge reflects archived rows` |
| Delete on archived row removes from Archive | auto | offline: `Delete on archived row removes it from Archive too` |
| True unarchive (move back to Inbox) | blocked | Issue #60 — contract OwnerInsert not yet wired; UI button hidden |

### Settings

WIP controls (AFT screen, read_receipts, pad_length, display_name) are
gated behind the `wip-settings` cargo feature and hidden in default
builds. Build with `--features wip-settings` to surface them. See the
"WIP settings gating" section in the `freenet-mail-qa` skill for the
add/remove protocol.

| Behavior | Status | Test / recipe |
|---|---|---|
| Identity privacy: verify_on_send toggle | manual | Settings → Privacy, toggle, send to unverified contact, confirm send proceeds vs blocks |
| Identity privacy: hide_unsigned toggle | manual | Toggle, observe Inbox |
| Inbox: drafts_in_inbox toggle | manual | Settings → Inbox, toggle, observe Drafts surface in Inbox folder |
| Inbox: quarantine_unknown toggle | manual | Settings → Inbox, toggle on → Quarantine folder + badge appear in sidebar, unknown-sender rows move there; toggle off → folder disappears, rows return to Inbox |
| Auto-sign + signature persists | manual | Set, send, reload, send again, confirm sig still appended |
| Appearance: theme switch (data-theme attr) | manual | Settings → Appearance, change theme, confirm `.fm-app[data-theme]` reflects |
| Appearance: density (data-density attr) | manual | Change density, confirm `.fm-app[data-density]` reflects + row heights change |
| Appearance: serif_subjects toggle | manual | Toggle, confirm subjects flip font |
| Appearance: font-size scaling (#275) | manual | Settings → Appearance, change Font size (small / default / large / larger). Confirm `.fm-app[data-font-size]` attr matches; entire UI scales uniformly via CSS `zoom`. Reload → choice persists. |
| Advanced: custom relay URL takes effect on reload | manual | Set custom_relay + URL, reload, WS connects to that URL |
| Settings round-trip across reload | manual | Set value, reload, value persists |
| AFT tier picker dispatches ModifySettings (#85) | auto | iso: `recipient tier change before first send; sender mints at new tier (#221, #180 AFT_CAP_RAISED row)` (re-enabled in #223). |
| AFT "Your tokens" usage panel (#271) | manual | Settings → Anti-Flood (AFT). With no AFT activity expect "No AFT activity yet for this identity." After a successful send, reopen Settings → expect Total > 0 + per-tier slot-in-use cards. Expand "How AFT rationing works" disclosure → expect three-paragraph explainer. Read from `RECORDS` thread-local at render time; refreshes on next Settings open. |
| Sender resolves recipient tier from live `InboxSettings` (#221) | auto (unit + iso) | `ui/src/contact_tier_cache.rs` record/lookup/overwrite + iso cross-peer round-trip. |
| Inbox contract merge propagates settings; tier-policy uses `>=` (#223) | auto (host) | `contracts/inbox/tests/integration.rs` — 5 new tests covering merge LWW, stronger-tier acceptance, ModifySettings advances last_update, pre-existing higher-tier messages survive tier downgrade. |
| Inbox signature binds settings + last_update (#253) | auto (host) | `contracts/inbox/tests/integration.rs` — `update_state_arm_rejects_tampered_settings_in_state`, `update_state_arm_rejects_bumped_last_update_in_state` (the spam-gate-bypass attack: peer rebroadcasts legit ek+sig with attacker settings/bumped LWW → must reject), `modify_settings_pins_last_update_and_restate_verifies` (owner-signed delta pins last_update, result re-verifies), `modify_settings_rejects_forged_signature` / `_rejects_ek_mismatch`, plus flipped `validate_rejects_tampered_last_update`. Signed payload widened to `STATE_UPDATE \|\| owner_ek_bytes \|\| serde_json(settings) \|\| last_update_micros_be`; rotates inbox wasm hash → #213 migration (prior hash appended to `LEGACY_INBOX_CODE_HASHES`). |
| Per-identity inbox migration on contract id rotation (#213) | manual | Bump `contracts/inbox/Cargo.toml` patch / change inbox code; rebuild; reload UI; expect `inbox migration: detected drift … (#213)` log + toast "Inbox … migrated …" + delegate's `inbox_wasm_hash` now equals new hash. Schema bump (`AliasInfo.inbox_wasm_hash`) is backwards-compatible via `#[serde(default)]`. |
| Per-identity AFT-record migration on contract id rotation (#251 improvement 3) | manual | Bump `modules/antiflood-tokens/contracts/token-allocation-record/Cargo.toml` patch / change AFT code; rebuild; reload UI; expect `AFT migration: detected drift … (#251)` log + toast "AFT token ledger … migrated …" + delegate's `aft_record_wasm_hash` now equals new hash. Migrated `TokenAllocationRecord` revalidates under new contract id because `TokenDelegateParameters.generator_public_key` (= identity's ML-DSA VK) is unchanged. Schema bump (`AliasInfo.aft_record_wasm_hash`, `pending_aft_migration_from`) is backwards-compatible via `#[serde(default)]`. Append a prior `TOKEN_RECORD_CODE_HASH` to `LEGACY_TOKEN_RECORD_CODE_HASHES` (in `ui/src/aft.rs`) as part of the bump so users skipping releases still recover. |
| AFT verified-sender bypass toggle dispatches ModifySettings (#157) | auto | iso: `verified-skip toggle dispatches ModifySettings + flips state (#157)` |
| AFT settings copy distinguishes sender vs recipient scope (#266) | manual | Open Settings → Anti-Flood (AFT). Verify lede paragraph mentions sender-vs-recipient split. "When sending: skip permission pop-ups" Card refers to YOUR client + auto-confirm prompt only (no token effect). "Your inbox policy: let verified senders skip tokens" Card states recipient-side scope + cross-references the sender card. |
| AFT bypass not-applied diagnostic surfaces gate reason (#266) | manual | With recipient-side `allow_verified_skip_token` OFF (or sender VK not in `verified_senders`, or cache miss), send a message and grep node/UI logs for `send.start_sending: AFT bypass NOT applied … (#266)` line. Expect one of three reason strings matching the failing gate (cache miss / flag off / VK not in set). |
| WIP: read receipts toggle (gated) | blocked | Issue #69 — feature not implemented |
| WIP: pad_length toggle (gated) | blocked | No implementation; gated until designed |
| WIP: display_name field (gated) | blocked | No consumer of the field; gated until wired into Sent/Inbox surfaces |

### Layout / chrome

| Behavior | Status | Test / recipe |
|---|---|---|
| App renders in sandboxed iframe | auto | offline: `app renders inside a sandboxed iframe` |
| No overflow at 1280px | auto | offline: `no overflow at 1280px` |
| Mobile viewport (Pixel 5 project) | auto (offline) / manual (iso) | offline runs Pixel 5 project; iso harness chromium-only |

### Network / failure modes

| Behavior | Status | Test / recipe |
|---|---|---|
| Peer down mid-send | manual | iso harness up, kill peer, alice sends, expect graceful failure (toast / Sent Failed) |
| WebSocket reconnect | manual | Drop ws (devtools or kill node), reconnect, confirm UI recovers |
| AFT slot exhaustion (day-1 cap, #85) | blocked | Issue #85 — needs tier configurability |
| Concurrent same-alias sends from 2 devices | manual | Restore backup on second browser, both compose-and-send simultaneously, observe Sent rows |

## Auto coverage gaps to convert

`automatable` rows from the matrix above. Triage:

1. Multi-recipient send → low effort, big surface
2. `verify_on_send` toast on unverified contact → already wired toast, easy
3. Search filter → covered by sidebar testid, easy
4. Auto-sign idempotent on Resend → easy
5. Settings round-trip across reload → moderate (involves localStorage / delegate)
6. Backup → restore round-trip → moderate (file picker)
7. Multiple identities (3+) → easy in offline mode
8. Reply from Archive folder → easy
9. Sent Pending → Failed on send error → needs failure-injection harness

## When to use this matrix

- **Before merging a feature PR**: scan the matrix; if the feature touches a
  `manual` or `automatable` row, do the manual recipe before marking the
  PR done.
- **After fixing a bug**: pick or add a row, ensure it's `auto` or write
  the recipe that catches it.
- **Before a release**: walk the `manual` rows for the touched areas.
