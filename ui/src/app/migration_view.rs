//! What the migration from v0.2.x shows: a line while it runs, the upgrade
//! notice, the orphans and the confirm prompt. The walk itself is
//! [`crate::migration`]; this is its page side.

use dioxus::prelude::*;
use freenet_mail_protocol::Addr;
use freenet_migrate::JournalStatus;

use super::login::{Identity, ImportBackup};
use crate::migration::ledger;
use crate::migration::orphans::{self, OrphanGroup};
use crate::migration::successor::MigrationCounts;
use crate::migration::{self, PageStore};
use crate::testid;

pub(crate) const CHECKING_TEXT: &str = "Checking for your previous Mail data";
const CLEARING_TEXT: &str = "Clearing superseded local stores";
const UNREACHABLE_TEXT: &str = "We couldn't open your previous Mail data on this node. If you \
     have a recovery key, restore it now.";
const RETRY_DISCLOSURE: &str = "Something you delete while this migration is still retrying can \
     return when it retries, and an identity you deleted in a newer version can return from an \
     older one.";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct MigrationView {
    pub walking: bool,
    /// Scrub has passed its checks and is deleting.
    pub clearing: bool,
    /// A row went silent or gave an unreadable answer. Never a typed "not
    /// installed", which is what every new user's node says.
    pub unreachable: bool,
    pub totals: MigrationCounts,
    /// The identities the walk brought in.
    pub migrated: Vec<Addr>,
    pub rejected: u32,
    /// The move may be part done ([`crate::migration::WalkOutcome::unfinished`]).
    pub in_progress: bool,
    pub notice_dismissed: bool,
    pub orphans: Vec<OrphanGroup>,
    pub report: String,
}

/// What sending or sharing as an identity does first. A migrated identity is
/// confirmed by its owner before it first sends or shares; one that is not
/// logged in (`None`) is not asked, and the action fails on its own terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Gate {
    /// Show the confirm prompt and do nothing else yet.
    Ask,
    /// Go ahead.
    Go,
}

/// The gate for an identity whose confirmed flag is `confirmed`.
pub(crate) fn gate(confirmed: Option<bool>) -> Gate {
    if confirmed == Some(false) {
        Gate::Ask
    } else {
        Gate::Go
    }
}

/// The identity whose recovery-key panel the notice asked to open.
pub(crate) static BACKUP_REQUEST: GlobalSignal<Option<Addr>> = Signal::global(|| None);

pub(crate) static MIGRATION: GlobalSignal<MigrationView> = Signal::global(MigrationView::default);

/// The summary line of the upgrade notice. While the move is `in_progress`
/// the counts are what has arrived so far, and it does not say "Moved".
pub(crate) fn notice_summary(c: &MigrationCounts, rejected: u32, in_progress: bool) -> String {
    let lead = if in_progress {
        "Your move from your previous version of Mail is still in progress. So far"
    } else {
        "Moved from your previous version of Mail"
    };
    format!(
        "{lead}: {} identities, {} contacts, {} drafts, {} sent, {} kept, {} archived. {} \
         skipped, {} orphaned, {} rejected.",
        c.identities,
        c.contacts,
        c.drafts,
        c.sent,
        c.kept,
        c.archived,
        c.flags_skipped,
        c.orphaned,
        rejected,
    )
}

/// The walk is about to run: an empty list means "not known yet" until it ends.
pub(crate) fn walk_starting() {
    MIGRATION.write().walking = true;
}

async fn refresh(status: Option<&JournalStatus>) {
    let mut store = PageStore;
    let ledger = ledger::read_ledger(&mut store).await;
    if let Err(e) = &ledger {
        crate::log::error(format!("reading the migration's record failed: {e}"), None);
    }
    let orphans = match orphans::stored(&mut store).await {
        Ok(items) => orphans::groups(&items),
        Err(e) => {
            crate::log::error(format!("listing migrated orphans failed: {e}"), None);
            MIGRATION.read().orphans.clone()
        }
    };
    let mut view = MIGRATION.write();
    // A failed read says nothing about the record: what is showing stays.
    let shown = ledger::Ledger {
        totals: view.totals,
        ..Default::default()
    };
    let report = migration::status_report(status, ledger.as_ref().unwrap_or(&shown));
    crate::log::info(format!("migration status: {report}"));
    if let Ok(ledger) = ledger {
        view.totals = ledger.totals;
        view.migrated = ledger.migrated;
        view.notice_dismissed = ledger.notice_dismissed;
    }
    view.rejected = status.map_or(0, JournalStatus::rejected_items);
    view.orphans = orphans;
    view.report = report;
}

/// Everything that follows the first identity listing: the walk, the list
/// again if it brought anything, and confirming identities that have an inbox.
#[cfg(any(feature = "use-node", feature = "example-data"))]
pub(crate) async fn after_listing<T, I>(transport: T, mut inbox: I)
where
    T: migration::legacy_delegates::LegacyTransport + Clone,
    I: migration::successor::V1InboxReader + Clone,
{
    use crate::app::identity_store::load_identities;
    use crate::mail_delegate::ops;
    let roll = crate::rng::random_bytes::<1>()[0];
    let outcome = migration::run(PageStore, transport.clone(), inbox.clone(), roll, || {
        crate::app::identity_store::spawn_detached(load_identities());
    })
    .await;
    if let Some(line) = migration::status_line(&outcome) {
        crate::log::info(line);
    }
    if !outcome.counts.is_empty() || outcome.released_markers {
        load_identities().await;
    }
    {
        let mut view = MIGRATION.write();
        view.walking = false;
        view.unreachable = outcome.silent_rows > 0;
        view.in_progress = outcome.unfinished();
    }
    refresh(outcome.status.as_ref()).await;
    let mut store = PageStore;
    let blockers = migration::scrub::run(&mut store, transport, &outcome, || {
        MIGRATION.write().clearing = true;
    })
    .await;
    MIGRATION.write().clearing = false;
    if !blockers.is_empty() {
        crate::log::info(format!("migration: not clearing yet: {blockers:?}"));
    }
    if let Ok(listed) = ops::list_identities().await {
        let confirmed = migration::confirm_by_inbox(&mut PageStore, &mut inbox, &listed).await;
        if !confirmed.is_empty() {
            load_identities().await;
        }
    }
    refresh(outcome.status.as_ref()).await;
}

async fn move_orphans(alias: String, owner: Addr) {
    let result = orphans::move_alias(&mut PageStore, &alias, owner).await;
    let moved = result.moved;
    let (text, level) = match result.failure {
        None => (
            format!("Moved {moved} item(s) from `{alias}`."),
            crate::toast::ToastLevel::Success,
        ),
        Some(why) => (
            format!(
                "Moved {moved} item(s) from `{alias}`. {} stayed: {why}",
                result.stayed
            ),
            crate::toast::ToastLevel::Error,
        ),
    };
    crate::toast::push_toast_detached(text, level);
    crate::app::identity_store::load_identities().await;
    let items = orphans::stored(&mut PageStore).await;
    if let Ok(items) = items {
        MIGRATION.write().orphans = orphans::groups(&items);
    }
}

async fn discard_orphans(group: OrphanGroup) {
    let (discarded, failure) = orphans::discard(&mut PageStore, &group).await;
    let alias = &group.alias;
    let (text, level) = match failure {
        None => (
            format!("Discarded {discarded} item(s) from `{alias}`."),
            crate::toast::ToastLevel::Success,
        ),
        Some(why) => (
            format!("Discarded {discarded} item(s) from `{alias}`. The rest stayed: {why}"),
            crate::toast::ToastLevel::Error,
        ),
    };
    crate::toast::push_toast_detached(text, level);
    if let Ok(items) = orphans::stored(&mut PageStore).await {
        MIGRATION.write().orphans = orphans::groups(&items);
    }
}

async fn dismiss_notice() {
    MIGRATION.write().notice_dismissed = true;
    if let Err(e) = ledger::update_ledger(&mut PageStore, |l| l.notice_dismissed = true).await {
        crate::log::error(format!("saving the dismissed notice failed: {e}"), None);
    }
}

#[component]
fn OrphanRow(group: OrphanGroup, identities: Vec<(String, Addr)>) -> Element {
    let mut target = use_signal(|| 0usize);
    let mut confirming = use_signal(|| false);
    let count = group.items.len();
    let shown = group.clone();
    let what = group
        .kinds
        .iter()
        .map(|(kind, n)| format!("{n} {kind}"))
        .collect::<Vec<_>>()
        .join(", ");
    let alias = group.alias.clone();
    let chosen = identities.get(*target.read()).map(|(_, addr)| *addr);
    rsx! {
        div {
            class: "field-help",
            "data-testid": testid::FM_ORPHAN_GROUP,
            "data-alias": "{group.alias}",
            style: "display:flex; align-items:center; justify-content:space-between; gap:10px; margin-bottom:10px;",
            span { "`{group.alias}`: {what}" }
            select {
                class: "input",
                style: "max-width:180px;",
                "data-testid": testid::FM_ORPHAN_TARGET,
                onchange: move |evt| target.set(evt.value().parse().unwrap_or(0)),
                for (index, (name, _)) in identities.iter().enumerate() {
                    option { value: "{index}", "{name}" }
                }
            }
            button {
                class: "btn btn-secondary",
                "data-testid": testid::FM_ORPHAN_MOVE,
                disabled: chosen.is_none(),
                onclick: move |_| {
                    if let Some(owner) = chosen {
                        crate::app::identity_store::spawn_detached(move_orphans(alias.clone(), owner));
                    }
                },
                "Move here"
            }
            button {
                class: "btn btn-ghost",
                "data-testid": testid::FM_ORPHAN_DISCARD,
                onclick: move |_| confirming.set(true),
                "Discard"
            }
        }
        if confirming() {
            div {
                class: "field-help",
                "data-testid": testid::FM_ORPHAN_DISCARD_CONFIRM,
                style: "margin-bottom:10px;",
                p { "Discard {count} item(s) from `{group.alias}`? They are deleted for good." }
                ul {
                    for (_, line) in group.items.iter() {
                        li { "{line}" }
                    }
                }
                button {
                    class: "btn btn-secondary",
                    "data-testid": testid::FM_ORPHAN_DISCARD_CANCEL,
                    onclick: move |_| confirming.set(false),
                    "Keep them"
                }
                button {
                    class: "btn btn-ghost",
                    "data-testid": testid::FM_ORPHAN_DISCARD_SUBMIT,
                    onclick: move |_| {
                        confirming.set(false);
                        crate::app::identity_store::spawn_detached(discard_orphans(shown.clone()));
                    },
                    "Discard {count} item(s)"
                }
            }
        }
    }
}

/// The migration's lines at the top of Your identities.
#[component]
pub(crate) fn MigrationPanel(identities: Vec<(String, Addr)>) -> Element {
    let view = MIGRATION.read().clone();
    let mut import_backup = use_context::<Signal<ImportBackup>>();
    let line = if view.clearing {
        Some(CLEARING_TEXT)
    } else {
        view.walking.then_some(CHECKING_TEXT)
    };
    let to_back_up: Vec<(String, Addr)> = identities
        .iter()
        .filter(|(_, addr)| view.migrated.contains(addr))
        .cloned()
        .collect();
    // Nothing counted means nothing was found to move: a user with no v0.2.x
    // data, whose journal could not be stored this load, sees no notice.
    let show_notice = !view.notice_dismissed && !view.totals.is_empty();
    rsx! {
        if let Some(line) = line {
            div { class: "field-help", "data-testid": testid::FM_MIGRATION_STATUS, "{line}" }
        }
        if view.unreachable {
            div {
                class: "field-help",
                "data-testid": testid::FM_MIGRATION_UNREACHABLE,
                style: "display:flex; align-items:center; justify-content:space-between; gap:10px; margin-bottom:10px;",
                span { "{UNREACHABLE_TEXT}" }
                button {
                    class: "btn btn-secondary",
                    "data-testid": testid::FM_MIGRATION_RESTORE,
                    onclick: move |_| import_backup.write().0 = true,
                    "Restore"
                }
            }
        }
        if show_notice {
            div {
                class: "field-help",
                "data-testid": testid::FM_MIGRATION_NOTICE,
                style: "margin-bottom:10px;",
                p { "{notice_summary(&view.totals, view.rejected, view.in_progress)}" }
                p { "{RETRY_DISCLOSURE}" }
                for (alias, addr) in to_back_up {
                    button {
                        key: "{alias}",
                        class: "btn btn-secondary",
                        "data-testid": testid::FM_MIGRATION_BACKUP,
                        "data-alias": "{alias}",
                        onclick: move |_| *BACKUP_REQUEST.write() = Some(addr),
                        "Save the recovery key for {alias}"
                    }
                }
                button {
                    class: "btn btn-ghost",
                    "data-testid": testid::FM_MIGRATION_DISMISS,
                    onclick: move |_| {
                        crate::app::identity_store::spawn_detached(dismiss_notice());
                    },
                    "Dismiss"
                }
            }
        }
        for group in view.orphans.iter().cloned() {
            OrphanRow { key: "{group.alias}", group, identities: identities.clone() }
        }
        if !view.report.is_empty() {
            details { class: "field-help", style: "margin-bottom:10px;",
                summary { "Migration status" }
                pre {
                    "data-testid": testid::FM_MIGRATION_REPORT,
                    style: "white-space:pre-wrap; word-break:break-all;",
                    "{view.report}"
                }
            }
        }
    }
}

/// "Confirm this identity is yours", before a migrated identity first sends
/// or is shared.
#[component]
pub(crate) fn ConfirmIdentityPrompt(
    identity: Identity,
    on_confirmed: EventHandler<()>,
    on_cancel: EventHandler<()>,
) -> Element {
    let user = use_context::<Signal<crate::app::User>>();
    let mut error = use_signal(String::new);
    let mut working = use_signal(|| false);
    let addr = identity.addr;
    let address = crate::app::address_book::ContactCard::from_identity(&identity).encode();
    let fingerprint = crate::app::address_book::fingerprint_words(
        &identity.ml_dsa_vk_bytes(),
        &identity.ml_kem_ek_bytes(),
    )
    .join("-");
    rsx! {
        div { class: "veil",
            div {
                class: "modal",
                "data-testid": testid::FM_CONFIRM_IDENTITY,
                h2 { class: "display md", "Confirm this identity is yours" }
                p { "“{identity.alias}” came from your previous version of Mail." }
                p { "Address: " code { style: "word-break:break-all;", "{address}" } }
                p { "Fingerprint: " code { "{fingerprint}" } }
                if !error.read().is_empty() {
                    div { class: "field-help", style: "color:#b91c1c;", "{error.read()}" }
                }
                div { style: "display:flex; gap:10px; margin-top:14px;",
                    button {
                        class: "btn btn-ghost",
                        "data-testid": testid::FM_CONFIRM_IDENTITY_CANCEL,
                        // Leaving now would drop the wait for the token
                        // record, and the send would then fail without one.
                        disabled: *working.read(),
                        onclick: move |_| on_cancel.call(()),
                        "Cancel"
                    }
                    button {
                        class: "btn btn-primary",
                        "data-testid": testid::FM_CONFIRM_IDENTITY_SUBMIT,
                        disabled: *working.read(),
                        onclick: move |_| {
                            working.set(true);
                            error.set(String::new());
                            spawn(async move {
                                let confirmed =
                                    crate::app::identity_store::confirm_identity(addr, user).await;
                                working.set(false);
                                match confirmed {
                                    Ok(()) => on_confirmed.call(()),
                                    Err(e) => error.set(e),
                                }
                            });
                        },
                        if *working.read() { "Confirming…" } else { "This is mine" }
                    }
                }
            }
        }
    }
}
