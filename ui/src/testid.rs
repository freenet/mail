//! Centralized `data-testid` constants used by the UI and Playwright suite.
//!
//! Why this exists: Playwright selectors are stringly-typed at both ends. A
//! rename in rsx silently breaks tests; a rename in a spec silently selects
//! nothing. Pulling every testid into one module gives `cargo check` a way
//! to catch typos in rsx callsites and gives a single grep target when
//! pruning or renaming.
//!
//! Pairing with Playwright: the matching JSON file at
//! `ui/branding/testids.json` is the source of truth Playwright reads at
//! test time. Both files must be kept in sync until we wire a build-time
//! generator. The Rust `const`s and JSON keys share names; if you add one
//! here, mirror it in the JSON.

#![allow(dead_code)]

// Migration from v0.2.x
pub(crate) const FM_MIGRATION_STATUS: &str = "fm-migration-status";
pub(crate) const FM_MIGRATION_UNREACHABLE: &str = "fm-migration-unreachable";
pub(crate) const FM_MIGRATION_RESTORE: &str = "fm-migration-restore";
pub(crate) const FM_MIGRATION_NOTICE: &str = "fm-migration-notice";
pub(crate) const FM_MIGRATION_BACKUP: &str = "fm-migration-backup";
pub(crate) const FM_MIGRATION_DISMISS: &str = "fm-migration-dismiss";
pub(crate) const FM_MIGRATION_REPORT: &str = "fm-migration-report";
pub(crate) const FM_ORPHAN_GROUP: &str = "fm-orphan-group";
pub(crate) const FM_ORPHAN_TARGET: &str = "fm-orphan-target";
pub(crate) const FM_ORPHAN_MOVE: &str = "fm-orphan-move";
pub(crate) const FM_ORPHAN_DISCARD: &str = "fm-orphan-discard";
pub(crate) const FM_ORPHAN_DISCARD_CONFIRM: &str = "fm-orphan-discard-confirm";
pub(crate) const FM_ORPHAN_DISCARD_SUBMIT: &str = "fm-orphan-discard-submit";
pub(crate) const FM_ORPHAN_DISCARD_CANCEL: &str = "fm-orphan-discard-cancel";
pub(crate) const FM_CONFIRM_IDENTITY: &str = "fm-confirm-identity";
pub(crate) const FM_CONFIRM_IDENTITY_SUBMIT: &str = "fm-confirm-identity-submit";
pub(crate) const FM_CONFIRM_IDENTITY_CANCEL: &str = "fm-confirm-identity-cancel";

// App shell
pub(crate) const FM_APP: &str = "fm-app";
pub(crate) const FM_AVATAR: &str = "fm-avatar";
pub(crate) const FM_LOGOUT: &str = "fm-logout";
pub(crate) const FM_SEARCH: &str = "fm-search";

// Sidebar / folders
pub(crate) const FM_COMPOSE_BTN: &str = "fm-compose-btn";
// Mobile-only topbar control that opens the off-canvas sidebar drawer
// (<=768px). Hidden on desktop. Playwright's mobile-chrome profile must
// click this before any sidebar interaction.
pub(crate) const FM_HAMBURGER: &str = "fm-hamburger";
// Mobile-only "back to list" control in the detail toolbars (<=768px).
pub(crate) const FM_BACK: &str = "fm-back";

// Message list
pub(crate) const FM_LIST: &str = "fm-list";
pub(crate) const FM_MSG_CARD: &str = "fm-msg-card";
pub(crate) const FM_MSG_TIME: &str = "fm-msg-time";
pub(crate) const FM_DRAFT_CARD: &str = "fm-draft-card";
pub(crate) const FM_SENT_CARD: &str = "fm-sent-card";
pub(crate) const FM_ARCHIVE_CARD: &str = "fm-archive-card";
pub(crate) const FM_QUARANTINE_CARD: &str = "fm-quarantine-card";

// Detail header
pub(crate) const FM_DETAIL_TIME: &str = "fm-detail-time";
pub(crate) const FM_DETAIL_FINGERPRINT: &str = "fm-detail-fingerprint";
pub(crate) const FM_DETAIL_VERIF: &str = "fm-detail-verif";
pub(crate) const FM_ADD_TO_AB: &str = "fm-add-to-ab";
pub(crate) const FM_COMPOSE_SENDING_AS: &str = "fm-compose-sending-as";

// Sidebar
pub(crate) const FM_SIDEBAR_FINGERPRINT: &str = "fm-sidebar-fingerprint";
pub(crate) const FM_SIDEBAR_CONTACTS: &str = "fm-sidebar-contacts";
pub(crate) const FM_SIDEBAR_VERSION: &str = "fm-sidebar-version";

// Detail / open message
pub(crate) const FM_REPLY: &str = "fm-reply";
pub(crate) const FM_DELETE: &str = "fm-delete";
pub(crate) const FM_ARCHIVE: &str = "fm-archive";

// Sent message detail
pub(crate) const FM_SENT_BODY: &str = "fm-sent-body";
pub(crate) const FM_SENT_DELETE: &str = "fm-sent-delete";
pub(crate) const FM_SENT_DELIVERY: &str = "fm-sent-delivery";
pub(crate) const FM_SENT_FINGERPRINT: &str = "fm-sent-fingerprint";
pub(crate) const FM_SENT_FORWARD: &str = "fm-sent-forward";
pub(crate) const FM_SENT_REPLY: &str = "fm-sent-reply";
pub(crate) const FM_SENT_RESEND: &str = "fm-sent-resend";

// Archived message detail
pub(crate) const FM_ARCHIVE_BODY: &str = "fm-archive-body";
pub(crate) const FM_ARCHIVE_DELETE: &str = "fm-archive-delete";
pub(crate) const FM_ARCHIVE_REPLY: &str = "fm-archive-reply";

// Compose
pub(crate) const FM_COMPOSE_SHEET: &str = "fm-compose-sheet";
pub(crate) const FM_SEND: &str = "fm-send";
pub(crate) const FM_COMPOSE_RECIPIENT_HINT: &str = "fm-compose-recipient-hint";
pub(crate) const FM_COMPOSE_AUTOCOMPLETE: &str = "fm-compose-autocomplete";
pub(crate) const FM_COMPOSE_AUTOCOMPLETE_ITEM: &str = "fm-compose-autocomplete-item";

// Threading (#270)
/// A message row inside the threaded detail view (Nested or Compact).
pub(crate) const FM_THREAD_ROW: &str = "fm-thread-row";
/// The expand/collapse caret on a threaded message row.
pub(crate) const FM_THREAD_EXPAND: &str = "fm-thread-expand";
/// The container wrapping the threaded detail view.
pub(crate) const FM_THREAD_CONTAINER: &str = "fm-thread-container";
/// The collapsed inbox-list row representing a whole conversation (carries
/// the message-count badge). Clicking it opens the threaded detail.
pub(crate) const FM_THREAD_GROUP: &str = "fm-thread-group";
/// The Settings → Inbox thread-view `<select>` (Nested / Compact).
pub(crate) const FM_THREAD_VIEW_SELECT: &str = "fm-thread-view-select";
/// The Settings → Appearance master threading on/off toggle. When off the
/// inbox renders flat (one row per message) and the thread-view select is
/// inert.
pub(crate) const FM_THREADING_ENABLED_TOGGLE: &str = "fm-threading-enabled-toggle";
/// The in-app storybook host wrapper (`example-data` builds only, gated on a
/// `?story=` query param). Wraps a single thread component rendered from a
/// hand-built `ThreadGroup` so the views can be screenshotted in isolation.
pub(crate) const FM_STORYBOOK: &str = "fm-storybook";

// Toast
pub(crate) const FM_TOAST: &str = "fm-toast";

// Login / first-run actions
pub(crate) const FM_ACTION_CREATE: &str = "fm-action-create";
pub(crate) const FM_ACTION_IMPORT: &str = "fm-action-import";
pub(crate) const FM_CREATE_ALIAS_INPUT: &str = "fm-create-alias-input";
pub(crate) const FM_CREATE_CONFIRM: &str = "fm-create-confirm";
pub(crate) const FM_CREATE_BACKUP_NOW: &str = "fm-create-backup-now";
pub(crate) const FM_CREATE_DISCARD: &str = "fm-create-discard";
pub(crate) const FM_CREATE_SUBMIT: &str = "fm-create-submit";
pub(crate) const FM_VERIFY_CHECK: &str = "fm-verify-check";
pub(crate) const FM_RESTORE_FILE: &str = "fm-restore-file";
pub(crate) const FM_RESTORE_SUBMIT: &str = "fm-restore-submit";

// Recovery key backup / restore (BackupKeyPanel, ImportForm, Settings)
pub(crate) const FM_RESTORE_PASTE: &str = "fm-restore-paste";
pub(crate) const FM_RESTORE_ERROR: &str = "fm-restore-error";
pub(crate) const FM_RESTORE_ALIAS: &str = "fm-restore-alias";
pub(crate) const FM_RESTORE_EXISTING: &str = "fm-restore-existing";
pub(crate) const FM_BACKUP_MODAL: &str = "fm-backup-modal";
/// Shown while the delegate's prompt to reveal a recovery key is open.
pub(crate) const FM_BACKUP_WAITING: &str = "fm-backup-waiting";
pub(crate) const FM_BACKUP_PANEL: &str = "fm-backup-panel";
pub(crate) const FM_BACKUP_ENTRY_TITLE: &str = "fm-backup-entry-title";
pub(crate) const FM_BACKUP_KEY: &str = "fm-backup-key";
pub(crate) const FM_BACKUP_KEY_MASKED: &str = "fm-backup-key-masked";
pub(crate) const FM_BACKUP_REVEAL: &str = "fm-backup-reveal";
pub(crate) const FM_BACKUP_COPY: &str = "fm-backup-copy";
pub(crate) const FM_BACKUP_DOWNLOAD: &str = "fm-backup-download";
pub(crate) const FM_BACKUP_STATUS: &str = "fm-backup-status";
pub(crate) const FM_BACKUP_SAVED: &str = "fm-backup-saved";
pub(crate) const FM_BACKUP_SAVED_NOTE: &str = "fm-backup-saved-note";
pub(crate) const FM_SETTINGS_BACKUP: &str = "fm-settings-backup";
pub(crate) const FM_SETTINGS_BACKUP_BANNER: &str = "fm-settings-backup-banner";
pub(crate) const FM_SETTINGS_REVOKE_EXPORT: &str = "fm-settings-revoke-export";

// Identity rows
pub(crate) const FM_ID_ROW: &str = "fm-id-row";
pub(crate) const FM_ID_OPEN: &str = "fm-id-open";
pub(crate) const FM_ID_CREATE: &str = "fm-id-create";
pub(crate) const FM_ID_BACKUP: &str = "fm-id-backup";
pub(crate) const FM_ID_RESTORE: &str = "fm-id-restore";
pub(crate) const FM_ID_RENAME: &str = "fm-id-rename";
pub(crate) const FM_ID_SHARE: &str = "fm-id-share";
pub(crate) const FM_ID_DELETE: &str = "fm-id-delete";
pub(crate) const FM_ID_UNFINISHED_DELETE: &str = "fm-id-unfinished-delete";
pub(crate) const FM_ID_FINISH_DELETE: &str = "fm-id-finish-delete";
pub(crate) const FM_ID_REPAIR_STORAGE: &str = "fm-id-repair-storage";
pub(crate) const FM_ID_REPAIR_STORAGE_NOTE: &str = "fm-id-repair-storage-note";
pub(crate) const FM_ID_REPAIR_LIST: &str = "fm-id-repair-list";
pub(crate) const FM_ID_REPAIR_LIST_NOTE: &str = "fm-id-repair-list-note";
pub(crate) const FM_RENAME_INPUT: &str = "fm-rename-input";
pub(crate) const FM_RENAME_SUBMIT: &str = "fm-rename-submit";
pub(crate) const FM_DELETE_CONFIRM_INPUT: &str = "fm-delete-confirm-input";
pub(crate) const FM_DELETE_CONFIRM_SUBMIT: &str = "fm-delete-confirm-submit";
pub(crate) const FM_DELETE_CONFIRM_CANCEL: &str = "fm-delete-confirm-cancel";

// Address book — share / import
pub(crate) const FM_SHARE_MODAL: &str = "fm-share-modal";
pub(crate) const FM_SHARE_COPY: &str = "fm-share-copy";
pub(crate) const FM_CONTACT_IMPORT: &str = "fm-contact-import";
pub(crate) const FM_IMPORT_CONTACT_MODAL: &str = "fm-import-contact-modal";
pub(crate) const FM_IMPORT_FP: &str = "fm-import-fp";
pub(crate) const FM_IMPORT_SUBMIT: &str = "fm-import-submit";
pub(crate) const FM_CONTACT_VERIFY: &str = "fm-contact-verify";
pub(crate) const FM_VERIFY_CONTACT_MODAL: &str = "fm-verify-contact-modal";
pub(crate) const FM_VERIFY_CONTACT_SUBMIT: &str = "fm-verify-contact-submit";

// Contacts settings screen — Import… / Share my card buttons (inbox-side triggers for #158)
pub(crate) const FM_CONTACTS_IMPORT_BTN: &str = "fm-contacts-import-btn";
pub(crate) const FM_CONTACTS_SHARE_BTN: &str = "fm-contacts-share-btn";

// Settings
pub(crate) const FM_SETTINGS_BTN: &str = "fm-settings-btn";
pub(crate) const FM_SETTINGS_SHELL: &str = "fm-settings-shell";
pub(crate) const FM_SETTINGS_BACK: &str = "fm-settings-back";
pub(crate) const FM_SETTINGS_NAV_ITEM: &str = "fm-settings-nav-item";
// AFT verified-sender bypass toggle (Settings → AFT).
// `data-state` mirrors the bool: "on" / "off".
pub(crate) const FM_AFT_VERIFIED_SKIP_TOGGLE: &str = "fm-aft-verified-skip-toggle";

// Inbox v2: address, invites, contacts and passes (Settings → Address &
// contacts), the compose note, the last send's outcome, decision 25.
pub(crate) const FM_V2_ADDRESS: &str = "fm-v2-address";
pub(crate) const FM_V2_INBOX_STATE: &str = "fm-v2-inbox-state";
pub(crate) const FM_V2_INVITE_CREATE: &str = "fm-v2-invite-create";
pub(crate) const FM_V2_INVITE_TEXT: &str = "fm-v2-invite-text";
pub(crate) const FM_V2_ADD_INPUT: &str = "fm-v2-add-input";
pub(crate) const FM_V2_ADD_NAME: &str = "fm-v2-add-name";
pub(crate) const FM_V2_ADD_SUBMIT: &str = "fm-v2-add-submit";
pub(crate) const FM_V2_ADD_RESULT: &str = "fm-v2-add-result";
pub(crate) const FM_V2_LABEL_WARNING: &str = "fm-v2-label-warning";
pub(crate) const FM_V2_CONTACT_ROW: &str = "fm-v2-contact-row";
pub(crate) const FM_V2_PASS_HELD: &str = "fm-v2-pass-held";
pub(crate) const FM_V2_PASS_ISSUED: &str = "fm-v2-pass-issued";
pub(crate) const FM_V2_REVOKE: &str = "fm-v2-revoke";
pub(crate) const FM_V2_RECIPIENT_NOTE: &str = "fm-v2-recipient-note";
pub(crate) const FM_V2_GHOST_BADGE: &str = "fm-v2-ghost-badge";
pub(crate) const FM_V2_OUTCOME: &str = "fm-v2-outcome";
pub(crate) const FM_V2_FOREIGN_WARNING: &str = "fm-v2-foreign-warning";
pub(crate) const FM_V2_QUARANTINE_MODE: &str = "fm-v2-quarantine-mode";
pub(crate) const FM_V2_GHOST_PANEL: &str = "fm-v2-ghost-panel";
pub(crate) const FM_V2_GHOST_USE: &str = "fm-v2-ghost-use";
pub(crate) const FM_V2_GHOST_PICKER: &str = "fm-v2-ghost-picker";
pub(crate) const FM_V2_GHOST_TIER: &str = "fm-v2-ghost-tier";
pub(crate) const FM_V2_GHOST_GET: &str = "fm-v2-ghost-get";
pub(crate) const FM_V2_GHOST_GET_LINK: &str = "fm-v2-ghost-get-link";
pub(crate) const FM_V2_GHOST_RECHECK: &str = "fm-v2-ghost-recheck";
pub(crate) const FM_V2_GHOST_DISCLOSURE: &str = "fm-v2-ghost-disclosure";
pub(crate) const FM_V2_QUEUE: &str = "fm-v2-queue";
pub(crate) const FM_V2_QUEUE_ROW: &str = "fm-v2-queue-row";
pub(crate) const FM_V2_QUEUE_ACCEPT: &str = "fm-v2-queue-accept";
pub(crate) const FM_V2_QUEUE_DROP: &str = "fm-v2-queue-drop";
pub(crate) const FM_V2_QUEUE_TIP: &str = "fm-v2-queue-tip";
pub(crate) const FM_V2_QUEUE_DROPPED: &str = "fm-v2-queue-dropped";
pub(crate) const FM_V2_NOT_CONTACT: &str = "fm-v2-not-contact";
pub(crate) const FM_V2_QUEUE_PETNAME: &str = "fm-v2-queue-petname";
pub(crate) const FM_V2_QUEUE_CONFIRM: &str = "fm-v2-queue-confirm";

#[cfg(test)]
mod tests {
    /// Guard against drift between the Rust constants in this module and
    /// the JSON file consumed by the Playwright suite. Each line here
    /// pairs a Rust const with the JSON key Playwright imports. If they
    /// disagree, this test fails.
    #[test]
    fn json_matches_rust_consts() {
        let json: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(include_str!("../branding/testids.json"))
                .expect("ui/branding/testids.json failed to parse");
        let pairs: &[(&str, &str)] = &[
            ("fmMigrationStatus", super::FM_MIGRATION_STATUS),
            ("fmMigrationUnreachable", super::FM_MIGRATION_UNREACHABLE),
            ("fmMigrationRestore", super::FM_MIGRATION_RESTORE),
            ("fmMigrationNotice", super::FM_MIGRATION_NOTICE),
            ("fmMigrationBackup", super::FM_MIGRATION_BACKUP),
            ("fmMigrationDismiss", super::FM_MIGRATION_DISMISS),
            ("fmMigrationReport", super::FM_MIGRATION_REPORT),
            ("fmOrphanGroup", super::FM_ORPHAN_GROUP),
            ("fmOrphanTarget", super::FM_ORPHAN_TARGET),
            ("fmOrphanMove", super::FM_ORPHAN_MOVE),
            ("fmOrphanDiscard", super::FM_ORPHAN_DISCARD),
            ("fmOrphanDiscardConfirm", super::FM_ORPHAN_DISCARD_CONFIRM),
            ("fmOrphanDiscardSubmit", super::FM_ORPHAN_DISCARD_SUBMIT),
            ("fmOrphanDiscardCancel", super::FM_ORPHAN_DISCARD_CANCEL),
            ("fmConfirmIdentity", super::FM_CONFIRM_IDENTITY),
            ("fmConfirmIdentitySubmit", super::FM_CONFIRM_IDENTITY_SUBMIT),
            ("fmConfirmIdentityCancel", super::FM_CONFIRM_IDENTITY_CANCEL),
            ("fmApp", super::FM_APP),
            ("fmAvatar", super::FM_AVATAR),
            ("fmLogout", super::FM_LOGOUT),
            ("fmSearch", super::FM_SEARCH),
            ("fmComposeBtn", super::FM_COMPOSE_BTN),
            ("fmHamburger", super::FM_HAMBURGER),
            ("fmBack", super::FM_BACK),
            ("fmList", super::FM_LIST),
            ("fmMsgCard", super::FM_MSG_CARD),
            ("fmMsgTime", super::FM_MSG_TIME),
            ("fmDraftCard", super::FM_DRAFT_CARD),
            ("fmSentCard", super::FM_SENT_CARD),
            ("fmArchiveCard", super::FM_ARCHIVE_CARD),
            ("fmQuarantineCard", super::FM_QUARANTINE_CARD),
            ("fmDetailTime", super::FM_DETAIL_TIME),
            ("fmDetailFingerprint", super::FM_DETAIL_FINGERPRINT),
            ("fmDetailVerif", super::FM_DETAIL_VERIF),
            ("fmAddToAb", super::FM_ADD_TO_AB),
            ("fmComposeSendingAs", super::FM_COMPOSE_SENDING_AS),
            ("fmSidebarFingerprint", super::FM_SIDEBAR_FINGERPRINT),
            ("fmSidebarContacts", super::FM_SIDEBAR_CONTACTS),
            ("fmSidebarVersion", super::FM_SIDEBAR_VERSION),
            ("fmReply", super::FM_REPLY),
            ("fmDelete", super::FM_DELETE),
            ("fmArchive", super::FM_ARCHIVE),
            ("fmSentBody", super::FM_SENT_BODY),
            ("fmSentDelete", super::FM_SENT_DELETE),
            ("fmSentDelivery", super::FM_SENT_DELIVERY),
            ("fmSentFingerprint", super::FM_SENT_FINGERPRINT),
            ("fmSentForward", super::FM_SENT_FORWARD),
            ("fmSentReply", super::FM_SENT_REPLY),
            ("fmSentResend", super::FM_SENT_RESEND),
            ("fmArchiveBody", super::FM_ARCHIVE_BODY),
            ("fmArchiveDelete", super::FM_ARCHIVE_DELETE),
            ("fmArchiveReply", super::FM_ARCHIVE_REPLY),
            ("fmComposeSheet", super::FM_COMPOSE_SHEET),
            ("fmSend", super::FM_SEND),
            ("fmComposeRecipientHint", super::FM_COMPOSE_RECIPIENT_HINT),
            ("fmComposeAutocomplete", super::FM_COMPOSE_AUTOCOMPLETE),
            (
                "fmComposeAutocompleteItem",
                super::FM_COMPOSE_AUTOCOMPLETE_ITEM,
            ),
            ("fmThreadRow", super::FM_THREAD_ROW),
            ("fmThreadExpand", super::FM_THREAD_EXPAND),
            ("fmThreadContainer", super::FM_THREAD_CONTAINER),
            ("fmThreadGroup", super::FM_THREAD_GROUP),
            ("fmThreadViewSelect", super::FM_THREAD_VIEW_SELECT),
            (
                "fmThreadingEnabledToggle",
                super::FM_THREADING_ENABLED_TOGGLE,
            ),
            ("fmStorybook", super::FM_STORYBOOK),
            ("fmToast", super::FM_TOAST),
            ("fmActionCreate", super::FM_ACTION_CREATE),
            ("fmActionImport", super::FM_ACTION_IMPORT),
            ("fmCreateAliasInput", super::FM_CREATE_ALIAS_INPUT),
            ("fmCreateConfirm", super::FM_CREATE_CONFIRM),
            ("fmCreateBackupNow", super::FM_CREATE_BACKUP_NOW),
            ("fmCreateDiscard", super::FM_CREATE_DISCARD),
            ("fmCreateSubmit", super::FM_CREATE_SUBMIT),
            ("fmVerifyCheck", super::FM_VERIFY_CHECK),
            ("fmRestoreFile", super::FM_RESTORE_FILE),
            ("fmRestoreSubmit", super::FM_RESTORE_SUBMIT),
            ("fmRestorePaste", super::FM_RESTORE_PASTE),
            ("fmRestoreError", super::FM_RESTORE_ERROR),
            ("fmRestoreAlias", super::FM_RESTORE_ALIAS),
            ("fmRestoreExisting", super::FM_RESTORE_EXISTING),
            ("fmBackupModal", super::FM_BACKUP_MODAL),
            ("fmBackupWaiting", super::FM_BACKUP_WAITING),
            ("fmBackupPanel", super::FM_BACKUP_PANEL),
            ("fmBackupEntryTitle", super::FM_BACKUP_ENTRY_TITLE),
            ("fmBackupKey", super::FM_BACKUP_KEY),
            ("fmBackupKeyMasked", super::FM_BACKUP_KEY_MASKED),
            ("fmBackupReveal", super::FM_BACKUP_REVEAL),
            ("fmBackupCopy", super::FM_BACKUP_COPY),
            ("fmBackupDownload", super::FM_BACKUP_DOWNLOAD),
            ("fmBackupStatus", super::FM_BACKUP_STATUS),
            ("fmBackupSaved", super::FM_BACKUP_SAVED),
            ("fmBackupSavedNote", super::FM_BACKUP_SAVED_NOTE),
            ("fmSettingsBackup", super::FM_SETTINGS_BACKUP),
            ("fmSettingsBackupBanner", super::FM_SETTINGS_BACKUP_BANNER),
            ("fmSettingsRevokeExport", super::FM_SETTINGS_REVOKE_EXPORT),
            ("fmIdRow", super::FM_ID_ROW),
            ("fmIdOpen", super::FM_ID_OPEN),
            ("fmIdCreate", super::FM_ID_CREATE),
            ("fmIdBackup", super::FM_ID_BACKUP),
            ("fmIdRestore", super::FM_ID_RESTORE),
            ("fmIdRename", super::FM_ID_RENAME),
            ("fmIdShare", super::FM_ID_SHARE),
            ("fmIdDelete", super::FM_ID_DELETE),
            ("fmIdUnfinishedDelete", super::FM_ID_UNFINISHED_DELETE),
            ("fmIdFinishDelete", super::FM_ID_FINISH_DELETE),
            ("fmIdRepairStorage", super::FM_ID_REPAIR_STORAGE),
            ("fmIdRepairStorageNote", super::FM_ID_REPAIR_STORAGE_NOTE),
            ("fmIdRepairList", super::FM_ID_REPAIR_LIST),
            ("fmIdRepairListNote", super::FM_ID_REPAIR_LIST_NOTE),
            ("fmRenameInput", super::FM_RENAME_INPUT),
            ("fmRenameSubmit", super::FM_RENAME_SUBMIT),
            ("fmDeleteConfirmInput", super::FM_DELETE_CONFIRM_INPUT),
            ("fmDeleteConfirmSubmit", super::FM_DELETE_CONFIRM_SUBMIT),
            ("fmDeleteConfirmCancel", super::FM_DELETE_CONFIRM_CANCEL),
            ("fmShareModal", super::FM_SHARE_MODAL),
            ("fmShareCopy", super::FM_SHARE_COPY),
            ("fmContactImport", super::FM_CONTACT_IMPORT),
            ("fmImportContactModal", super::FM_IMPORT_CONTACT_MODAL),
            ("fmImportFp", super::FM_IMPORT_FP),
            ("fmImportSubmit", super::FM_IMPORT_SUBMIT),
            ("fmSettingsBtn", super::FM_SETTINGS_BTN),
            ("fmSettingsShell", super::FM_SETTINGS_SHELL),
            ("fmSettingsBack", super::FM_SETTINGS_BACK),
            ("fmSettingsNavItem", super::FM_SETTINGS_NAV_ITEM),
            ("fmContactVerify", super::FM_CONTACT_VERIFY),
            ("fmVerifyContactModal", super::FM_VERIFY_CONTACT_MODAL),
            ("fmVerifyContactSubmit", super::FM_VERIFY_CONTACT_SUBMIT),
            ("fmContactsImportBtn", super::FM_CONTACTS_IMPORT_BTN),
            ("fmContactsShareBtn", super::FM_CONTACTS_SHARE_BTN),
            (
                "fmAftVerifiedSkipToggle",
                super::FM_AFT_VERIFIED_SKIP_TOGGLE,
            ),
            ("fmV2Address", super::FM_V2_ADDRESS),
            ("fmV2InboxState", super::FM_V2_INBOX_STATE),
            ("fmV2InviteCreate", super::FM_V2_INVITE_CREATE),
            ("fmV2InviteText", super::FM_V2_INVITE_TEXT),
            ("fmV2AddInput", super::FM_V2_ADD_INPUT),
            ("fmV2AddName", super::FM_V2_ADD_NAME),
            ("fmV2AddSubmit", super::FM_V2_ADD_SUBMIT),
            ("fmV2AddResult", super::FM_V2_ADD_RESULT),
            ("fmV2LabelWarning", super::FM_V2_LABEL_WARNING),
            ("fmV2ContactRow", super::FM_V2_CONTACT_ROW),
            ("fmV2PassHeld", super::FM_V2_PASS_HELD),
            ("fmV2PassIssued", super::FM_V2_PASS_ISSUED),
            ("fmV2Revoke", super::FM_V2_REVOKE),
            ("fmV2RecipientNote", super::FM_V2_RECIPIENT_NOTE),
            ("fmV2GhostBadge", super::FM_V2_GHOST_BADGE),
            ("fmV2Outcome", super::FM_V2_OUTCOME),
            ("fmV2ForeignWarning", super::FM_V2_FOREIGN_WARNING),
            ("fmV2QuarantineMode", super::FM_V2_QUARANTINE_MODE),
            ("fmV2GhostPanel", super::FM_V2_GHOST_PANEL),
            ("fmV2GhostUse", super::FM_V2_GHOST_USE),
            ("fmV2GhostPicker", super::FM_V2_GHOST_PICKER),
            ("fmV2GhostTier", super::FM_V2_GHOST_TIER),
            ("fmV2GhostGet", super::FM_V2_GHOST_GET),
            ("fmV2GhostGetLink", super::FM_V2_GHOST_GET_LINK),
            ("fmV2GhostRecheck", super::FM_V2_GHOST_RECHECK),
            ("fmV2GhostDisclosure", super::FM_V2_GHOST_DISCLOSURE),
            ("fmV2Queue", super::FM_V2_QUEUE),
            ("fmV2QueueRow", super::FM_V2_QUEUE_ROW),
            ("fmV2QueueAccept", super::FM_V2_QUEUE_ACCEPT),
            ("fmV2QueueDrop", super::FM_V2_QUEUE_DROP),
            ("fmV2QueueTip", super::FM_V2_QUEUE_TIP),
            ("fmV2QueueDropped", super::FM_V2_QUEUE_DROPPED),
            ("fmV2NotContact", super::FM_V2_NOT_CONTACT),
            ("fmV2QueuePetname", super::FM_V2_QUEUE_PETNAME),
            ("fmV2QueueConfirm", super::FM_V2_QUEUE_CONFIRM),
        ];
        assert_eq!(
            json.len(),
            pairs.len(),
            "JSON has {} entries, Rust has {} — both must match exactly",
            json.len(),
            pairs.len(),
        );
        for (key, expected) in pairs {
            let got = json
                .get(*key)
                .unwrap_or_else(|| panic!("JSON missing key {key}"))
                .as_str()
                .unwrap_or_else(|| panic!("JSON key {key} is not a string"));
            assert_eq!(
                got, *expected,
                "JSON {key} = {got:?} but Rust const = {expected:?}",
            );
        }
    }
}
