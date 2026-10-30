//! Identities in the mail delegate, which holds their keys, plus the
//! per-identity contract-migration markers (#213/#251) the v0.2.x client
//! kept on its identity-management delegate.
//!
//! Every call here waits for the delegate, so it runs in a task of its own,
//! never in the node loop (`api::node_comms`), which delivers the
//! delegate's answers. What the node loop needs back arrives as a
//! [`NodeAction`](crate::app::NodeAction) ([`send_action`]).

use std::cell::Cell;

use dioxus::prelude::{Coroutine, GlobalSignal, Signal};
use freenet_mail_protocol::{Addr, IdentityInfo, ItemKind, ItemRef};
use serde::{Deserialize, Serialize};

use crate::DynError;
use crate::app::{Identity, NodeAction};
use crate::mail_delegate::ops;

thread_local! {
    static ACTIONS: Cell<Option<Coroutine<NodeAction>>> = const { Cell::new(None) };
}

/// Remember the node loop's action channel, so tasks can hand it results.
pub(crate) fn set_action_sender(actions: Coroutine<NodeAction>) {
    ACTIONS.with(|a| a.set(Some(actions)));
}

/// Hand an action to the node loop.
pub(crate) fn send_action(action: NodeAction) {
    match ACTIONS.with(Cell::get) {
        Some(actions) => actions.send(action),
        None => crate::log::error("no node loop to send an action to", None),
    }
}

/// Run `fut` in a task that outlives the view that started it (a scoped
/// task is cancelled when its view unmounts, and the node loop can be polled
/// with no scope on the stack at all).
pub(crate) fn spawn_detached(fut: impl std::future::Future<Output = ()> + 'static) {
    let _task = dioxus::core::spawn_forever(fut);
}

/// Delete an identity and everything it owns from the mail delegate (which
/// asks the user first), showing how much is left while a large one is
/// deleted page by page. A small identity finishes in one step and never
/// shows it. Used by the node and the offline builds alike.
///
/// The error is the text to show the user: once the deletion has started, or
/// when it is not known whether it did, it says the deletion may be
/// incomplete and will finish on a retry ([`deletion_failure_text`]).
pub(crate) async fn delete_with_progress(
    addr: Addr,
    generation: u64,
    alias: &str,
) -> Result<(), String> {
    let mut progress: Option<crate::toast::ToastId> = None;
    let mut started = false;
    let deleted = ops::delete_identity(addr, generation, |remaining| {
        started = true;
        let text = deletion_progress_text(alias, remaining);
        crate::log::info(text.clone());
        match progress {
            Some(id) => crate::toast::update_toast_detached(id, text),
            None => {
                progress =
                    crate::toast::push_sticky_toast_detached(text, crate::toast::ToastLevel::Info)
            }
        }
    })
    .await;
    if let Some(id) = progress {
        crate::toast::dismiss_toast_detached(id);
    }
    deleted.map_err(|e| {
        crate::log::error(format!("deleting identity `{alias}` failed: {e}"), None);
        deletion_failure_text(alias, &e, started)
    })
}

/// What the user is told when a deletion did not finish. A deletion that
/// started (a page was removed), or whose outcome is unknown, may be partly
/// done: the identity is hidden but some of its data is left, and a retry
/// finishes it without asking again.
pub(crate) fn deletion_failure_text(
    alias: &str,
    error: &crate::mail_delegate::CallError,
    started: bool,
) -> String {
    if started || matches!(error, crate::mail_delegate::CallError::Unknown(_)) {
        format!(
            "Deleting identity `{alias}` may be incomplete; it will finish when you retry \
             (Your identities → Finish deleting)."
        )
    } else {
        format!("Identity `{alias}` was not deleted: {error}")
    }
}

/// Identities whose approved deletion was interrupted (the page closed or
/// lost the node midway). The delegate hides them; the identities screen
/// offers to finish each.
pub(crate) static UNFINISHED_DELETIONS: GlobalSignal<Vec<IdentityInfo>> = Signal::global(Vec::new);

/// Ask the delegate which deletions are unfinished and show them. Returns
/// the list (empty if the delegate could not be asked).
///
/// `None` when the delegate could not be asked, after a few tries: unknown,
/// never "none", since it is asked right after a deletion failed, which is
/// when it is most likely to fail too.
pub(crate) async fn refresh_unfinished_deletions() -> Option<Vec<IdentityInfo>> {
    let mut attempt = 0u32;
    loop {
        match ops::list_deleting_identities().await {
            Ok(list) => {
                if dioxus::core::Runtime::try_current().is_some() {
                    *UNFINISHED_DELETIONS.write() = list.clone();
                }
                return Some(list);
            }
            Err(e) => {
                crate::log::error(format!("listing unfinished deletions failed: {e}"), None);
                if attempt >= UNFINISHED_LIST_RETRIES {
                    return None;
                }
                attempt += 1;
                ops::pause_ms(500 << attempt).await;
            }
        }
    }
}

/// Retries of the unfinished-deletions listing before it counts as unknown.
const UNFINISHED_LIST_RETRIES: u32 = 2;

/// After a failed deletion: take the identity out of the page if its
/// deletion began ([`drop_if_deletion_started`]); if that cannot be known,
/// say so rather than guess. Returns whether it was taken out.
pub(crate) fn settle_after_failed_deletion(
    identity: &crate::app::login::Identity,
    unfinished: Option<&[IdentityInfo]>,
    user: &mut crate::app::User,
) -> bool {
    match unfinished {
        Some(list) => drop_if_deletion_started(identity, list, user),
        None => {
            crate::toast::push_toast_detached(
                format!(
                    "Couldn't check whether deleting `{}` began. Reload to see it under Your identities, finished or offered to finish.",
                    identity.alias
                ),
                crate::toast::ToastLevel::Warning,
            );
            false
        }
    }
}

/// Take a deleted identity out of this page: the live identities, the
/// identities list, the signed-in identity and its in-page state.
pub(crate) fn drop_from_page(identity: &crate::app::login::Identity, user: &mut crate::app::User) {
    crate::app::login::Identity::remove_in_place_by_addr(&identity.addr);
    crate::local_state::forget_identity(&identity.addr);
    crate::app::address_book::remove_own_identity(identity);
    let was_logged_in = user.logged_id().is_some_and(|i| i.addr == identity.addr);
    user.identities.retain(|i| i.addr != identity.addr);
    if was_logged_in {
        user.logout();
    }
}

/// After a deletion that did not finish: once the delegate lists the
/// identity in `unfinished`, its deletion has begun, and the delegate hides
/// it and refuses to use it. Take it out of the page as well, so the user
/// sees the "Finish deleting" entry rather than that plus a row that no
/// longer works, and nothing is left behind once it is finished. Returns
/// whether it was taken out.
pub(crate) fn drop_if_deletion_started(
    identity: &crate::app::login::Identity,
    unfinished: &[IdentityInfo],
    user: &mut crate::app::User,
) -> bool {
    let started = unfinished.iter().any(|i| i.addr == identity.addr);
    if started {
        drop_from_page(identity, user);
    }
    started
}

/// Finish an interrupted deletion. The user approved it before, so the
/// delegate does not ask again.
pub(crate) async fn finish_deletion(info: IdentityInfo) {
    // A second click while this runs must not start a second paged
    // deletion of the same identity.
    if !begin_finishing(info.addr) {
        return;
    }
    let _done = FinishingGuard(info.addr);
    match delete_with_progress(info.addr, info.generation, &info.alias).await {
        Ok(()) => {
            // By address: a new identity may carry this one's alias.
            crate::app::login::Identity::remove_in_place_by_addr(&info.addr);
            crate::local_state::forget_identity(&info.addr);
            crate::toast::push_toast_detached(
                format!("Identity `{}` deleted", info.alias),
                crate::toast::ToastLevel::Success,
            );
        }
        Err(text) => {
            crate::toast::push_toast_detached(text, crate::toast::ToastLevel::Error);
        }
    }
    refresh_unfinished_deletions().await;
}

thread_local! {
    /// Identities whose unfinished deletion is being finished now.
    static FINISHING: std::cell::RefCell<std::collections::HashSet<Addr>> =
        std::cell::RefCell::new(std::collections::HashSet::new());
}

/// The deletions being finished, for the identities screen to render from:
/// the thread-local above is the guard, and a render reading it would not
/// re-run when it changes, so the "Finish deleting" button would stay
/// enabled (or stay disabled) until something else re-rendered the screen.
pub(crate) static FINISHING_VIEW: GlobalSignal<std::collections::HashSet<Addr>> =
    Signal::global(std::collections::HashSet::new);

fn sync_finishing_view() {
    if dioxus::core::Runtime::try_current().is_some() {
        *FINISHING_VIEW.write() = FINISHING.with(|f| f.borrow().clone());
    }
}

/// Claim the right to finish `addr`'s deletion; `false` if it is already
/// being finished.
fn begin_finishing(addr: Addr) -> bool {
    let claimed = FINISHING.with(|f| f.borrow_mut().insert(addr));
    sync_finishing_view();
    claimed
}

/// Whether `addr`'s deletion is being finished now.
#[cfg(test)]
pub(crate) fn is_finishing(addr: &Addr) -> bool {
    FINISHING.with(|f| f.borrow().contains(addr))
}

/// Releases the claim when the attempt ends, however it ends.
struct FinishingGuard(Addr);

impl Drop for FinishingGuard {
    fn drop(&mut self) {
        FINISHING.with(|f| f.borrow_mut().remove(&self.0));
        sync_finishing_view();
    }
}

/// What a restore says when the delegate refuses an identity because its
/// deletion is unfinished: finish the deletion first, then restore.
pub(crate) fn restore_failure_text(error: &crate::mail_delegate::CallError) -> String {
    match error {
        crate::mail_delegate::CallError::Failed(f)
            if f.code == freenet_mail_protocol::FailureCode::Refused
                && f.detail.contains("being deleted") =>
        {
            "This identity's deletion has not finished. Finish deleting it under \
             Your identities, then restore it."
                .into()
        }
        other => format!("Couldn't restore the identity: {other}"),
    }
}

/// What creating says when its answer was lost and the identity turned out
/// not to be usable yet. Never a plain "couldn't create": it may exist.
pub(crate) fn lost_create_text(
    alias: &str,
    lost: &crate::mail_delegate::ops::LostCreate,
) -> String {
    use crate::mail_delegate::ops::LostCreate;
    match lost {
        LostCreate::NotCreated | LostCreate::Created(..) => format!(
            "Mail didn't hear back while creating `{alias}`, and it was not created. Try again."
        ),
        LostCreate::CreatedKeyUnavailable(info, e) => format!(
            "`{}` was created, but its recovery key couldn't be shown ({e}). \
             Reload, then back it up from Your identities before using it.",
            info.alias
        ),
        LostCreate::Unknown(e) => format!(
            "Mail didn't hear back while creating `{alias}`, so it may have been created ({e}). \
             Reload and check Your identities before trying again."
        ),
    }
}

/// What a restore says when the keys are already here (`stored_alias`):
/// nothing was changed, and a different name is not silently dropped.
pub(crate) fn already_present_text(stored_alias: &str, requested_alias: &str) -> String {
    if stored_alias == requested_alias {
        format!("`{stored_alias}` is already here; nothing was changed.")
    } else {
        format!(
            "These keys are already here as `{stored_alias}`, so nothing was changed. \
             To call it `{requested_alias}`, rename it under Your identities."
        )
    }
}

/// What discarding a just-created identity says when its deletion was not
/// confirmed. The identity may still be stored, and the user can finish it.
pub(crate) fn discard_failure_text(alias: &str, error: &crate::mail_delegate::CallError) -> String {
    match error {
        crate::mail_delegate::CallError::Unknown(_) => format!(
            "Mail didn't confirm that `{alias}` was discarded. If it is listed under Your \
             identities after a reload, delete it there."
        ),
        crate::mail_delegate::CallError::Failed(f) => format!(
            "`{alias}` was not discarded ({}). It is still stored: reload and delete it under \
             Your identities.",
            f.detail
        ),
    }
}

/// What the user sees while a large identity is deleted page by page.
fn deletion_progress_text(alias: &str, remaining: u32) -> String {
    let items = if remaining == 1 { "item" } else { "items" };
    format!("Deleting identity `{alias}`… {remaining} {items} left")
}

/// Contract-migration markers for one identity (#213, #251). Stored in the
/// identity's `IdentitySettings` item under `"migration"`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MigrationMarkers {
    /// The inbox code hash this identity's inbox was last observed under.
    #[serde(default)]
    pub inbox_wasm_hash: Option<String>,
    /// Set before an inbox migration GET and cleared once its PUT lands.
    #[serde(default)]
    pub pending_migration_from: Option<String>,
    #[serde(default)]
    pub aft_record_wasm_hash: Option<String>,
    #[serde(default)]
    pub pending_aft_migration_from: Option<String>,
}

const MARKERS_FIELD: &str = "migration";

fn settings_item(addr: Addr) -> ItemRef {
    ItemRef {
        kind: ItemKind::IdentitySettings,
        owner: Some(addr),
        id: Vec::new(),
    }
}

/// The markers inside an `IdentitySettings` body (absent or unreadable:
/// none recorded).
pub(crate) fn markers_from_body(body: Option<&[u8]>) -> MigrationMarkers {
    body.and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
        .and_then(|v| v.get(MARKERS_FIELD).cloned())
        .and_then(|m| serde_json::from_value(m).ok())
        .unwrap_or_default()
}

/// `body` with its markers replaced by `markers`, every other field kept.
pub(crate) fn body_with_markers(body: Option<&[u8]>, markers: &MigrationMarkers) -> Vec<u8> {
    let mut value = body
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
        .filter(serde_json::Value::is_object)
        .unwrap_or_else(|| serde_json::json!({}));
    value[MARKERS_FIELD] = serde_json::to_value(markers).expect("markers always encode");
    serde_json::to_vec(&value).expect("a JSON value always encodes")
}

pub(crate) async fn load_markers(addr: Addr) -> Result<MigrationMarkers, DynError> {
    let item = ops::get_item(settings_item(addr)).await?;
    Ok(markers_from_body(item.as_ref().map(|i| i.body.as_slice())))
}

/// Change one identity's markers (merged with what is stored, so another
/// tab's settings survive).
pub(crate) async fn update_markers(
    addr: Addr,
    change: impl Fn(&mut MigrationMarkers),
) -> Result<(), DynError> {
    ops::put_item_merged(settings_item(addr), |stored| {
        let mut markers = markers_from_body(stored);
        let before = markers.clone();
        change(&mut markers);
        (markers != before).then(|| body_with_markers(stored, &markers))
    })
    .await?;
    Ok(())
}

/// An identity as the node loop needs it on load: its public view and the
/// contract code hashes to migrate its inbox and AFT record from, if they
/// drifted (#213, #251). It carries no key material: the token-generator
/// parameters (which hold the signing seed) are fetched only to send.
#[derive(Clone, Debug)]
pub(crate) struct LoadedIdentity {
    pub info: IdentityInfo,
    pub inbox_migrate_from: Option<String>,
    pub aft_migrate_from: Option<String>,
}

/// How one contract's migration markers change on load, given the hash it
/// was last observed under (`recorded`), the pending marker and the current
/// hash. Returns the hash to migrate from, if any, and the new markers.
///
/// On drift the pending marker is set (so a session whose GET never resolves
/// retries next time) and the current hash is stamped (so drift doesn't fire
/// every session); the pending marker is cleared only once the migration PUT
/// lands. With no drift, a first observation stamps the baseline and a stale
/// pending marker is cleared.
pub(crate) fn plan_migration(
    recorded: &mut Option<String>,
    pending: &mut Option<String>,
    current: &str,
) -> Option<String> {
    let from = crate::inbox::select_migrate_from(recorded.as_deref(), pending.as_deref(), current);
    match &from {
        Some(prior) => {
            *pending = Some(prior.clone());
            *recorded = Some(current.to_string());
        }
        None => {
            if recorded.is_none() {
                *recorded = Some(current.to_string());
            }
            *pending = None;
        }
    }
    from
}

/// Read the identities from the mail delegate and hand them to the node
/// loop ([`NodeAction::IdentitiesLoaded`]).
pub(crate) async fn load_and_report() {
    let infos = match ops::list_identities().await {
        Ok(infos) => infos,
        Err(e) => {
            crate::log::error(format!("loading identities failed: {e}"), None);
            crate::toast::push_toast_detached(
                format!("Couldn't load your identities: {e}"),
                crate::toast::ToastLevel::Error,
            );
            return;
        }
    };
    // Local state is keyed by address (`local_state::addr_key`), never by
    // alias, so a rename or a reused alias can't misfile it.
    #[cfg(feature = "use-node")]
    let owners: Vec<(String, Addr)> = infos
        .iter()
        .map(|i| (crate::local_state::addr_key(&i.addr), i.addr))
        .collect();
    let mut loaded = Vec::with_capacity(infos.len());
    for info in infos {
        loaded.push(prepare(info).await);
    }
    // Announce the identities first. Loading their drafts, sent mail, read
    // marks and settings takes a delegate round trip per item, and while it
    // ran the user could create an identity that the late announcement then
    // hid (#286). Views opened before the load lands re-render when it does.
    #[cfg(feature = "use-node")]
    {
        let keys: Vec<String> = owners.iter().map(|(key, _)| key.clone()).collect();
        let merged = announce_then_merge(
            &keys,
            || send_action(NodeAction::IdentitiesLoaded { identities: loaded }),
            async {
                refresh_unfinished_deletions().await;
            },
            || crate::local_state::load(&owners),
        )
        .await;
        if let Err(e) = merged {
            crate::log::error(format!("loading local mail state failed: {e}"), None);
            crate::toast::push_toast_detached(
                format!("Couldn't load your drafts, sent mail and settings: {e}"),
                crate::toast::ToastLevel::Error,
            );
        }
    }
    #[cfg(not(feature = "use-node"))]
    {
        send_action(NodeAction::IdentitiesLoaded { identities: loaded });
        refresh_unfinished_deletions().await;
    }
}

/// Announce the identities, let `meanwhile` run, then load their local state
/// and merge it over the page's changes. Journaling starts BEFORE the
/// announcement: from the moment the identities are usable the user can
/// change their state, and every such change, including those made while
/// `meanwhile` runs, is replayed over the load rather than replaced by it.
#[cfg(any(test, feature = "use-node"))]
async fn announce_then_merge<Load, LoadFut>(
    owners: &[String],
    announce: impl FnOnce(),
    meanwhile: impl std::future::Future<Output = ()>,
    load: Load,
) -> Result<(), crate::mail_delegate::CallError>
where
    Load: FnOnce() -> LoadFut,
    LoadFut: std::future::Future<
            Output = Result<
                freenet_mail_wire_v1::local_state::LocalState,
                crate::mail_delegate::CallError,
            >,
        >,
{
    let mark = crate::local_state::begin_load();
    announce();
    meanwhile.await;
    let state = load().await?;
    crate::local_state::merge_loaded(state, owners, mark);
    Ok(())
}

/// The migrations to run for an identity whose markers read as `read`, and
/// the markers to write back, if they changed. Markers that could not be
/// read (`None`) are unknown, never absent: nothing is planned and nothing
/// is written, since writing defaults would wipe a pending migration marker.
/// The next session tries again.
pub(crate) fn plan_load(
    read: Option<MigrationMarkers>,
) -> (Option<String>, Option<String>, Option<MigrationMarkers>) {
    let Some(mut markers) = read else {
        return (None, None, None);
    };
    let before = markers.clone();
    let inbox = plan_migration(
        &mut markers.inbox_wasm_hash,
        &mut markers.pending_migration_from,
        crate::inbox::INBOX_CODE_HASH,
    );
    let aft = plan_migration(
        &mut markers.aft_record_wasm_hash,
        &mut markers.pending_aft_migration_from,
        crate::aft::TOKEN_RECORD_CODE_HASH,
    );
    let write = (markers != before).then_some(markers);
    (inbox, aft, write)
}

/// Everything the node loop needs for one identity. Records the migration
/// markers before the node loop dispatches any migration GET, so a crash in
/// between still leaves the retry marker set.
pub(crate) async fn prepare(info: IdentityInfo) -> LoadedIdentity {
    let read = match load_markers(info.addr).await {
        Ok(markers) => Some(markers),
        Err(e) => {
            crate::log::error(
                format!(
                    "reading migration markers for `{}` failed; skipping migrations this session: {e}",
                    info.alias
                ),
                None,
            );
            None
        }
    };
    let (inbox_migrate_from, aft_migrate_from, write) = plan_load(read);
    if let Some(new) = write
        && let Err(e) = update_markers(info.addr, move |m| *m = new.clone()).await
    {
        crate::log::error(
            format!(
                "recording migration markers for `{}` failed: {e}",
                info.alias
            ),
            None,
        );
    }
    LoadedIdentity {
        info,
        inbox_migrate_from,
        aft_migrate_from,
    }
}

/// A migration's PUT landed: clear its pending marker, then say so.
pub(crate) fn migration_landed(addr: Addr, alias: String, aft: bool) {
    spawn_detached(async move {
        let cleared = update_markers(addr, move |m| {
            if aft {
                m.pending_aft_migration_from = None;
            } else {
                m.pending_migration_from = None;
            }
        })
        .await;
        match cleared {
            Ok(()) => drop(crate::toast::push_toast_detached(
                if aft {
                    format!(
                        "Token ledger `{alias}` migrated to the new contract id after webapp upgrade."
                    )
                } else {
                    format!("Inbox `{alias}` migrated to the new contract id after webapp upgrade.")
                },
                crate::toast::ToastLevel::Info,
            )),
            // The marker stays set, so the migration is retried next session
            // (#260); saying "migrated" now would over-promise.
            Err(e) => {
                crate::log::error(
                    format!(
                        "migration: clearing the pending marker for `{alias}` failed: {e} — will retry next session (#260)"
                    ),
                    None,
                );
            }
        }
    });
}

/// The signed initial state of `identity`'s inbox, with the given anti-flood
/// policy (#85). The delegate signs it.
pub(crate) async fn initial_inbox_state(
    identity: &Identity,
    required_tier: freenet_mail_wire_v1::aft::Tier,
    max_age_secs: u64,
) -> Result<Vec<u8>, DynError> {
    use freenet_mail_wire_v1::inbox::{Inbox, InboxSettings};
    let settings = InboxSettings {
        minimum_tier: required_tier,
        max_age_secs,
        private: Default::default(),
        ..InboxSettings::default()
    };
    let (last_update, signature) = crate::inbox::sign_authority(identity.addr, &settings).await?;
    let inbox = Inbox::with_signature(
        settings,
        Vec::new(),
        last_update,
        identity.ml_kem_ek_bytes(),
        signature,
    );
    Ok(inbox.serialize()?)
}

/// Publish a new or restored identity: its inbox, its AFT record and its
/// token-generator delegate, then the identity itself. Runs in a task; the
/// node work is handed to the node loop.
pub(crate) async fn publish(identity: Identity, backed_up: bool) -> Result<(), DynError> {
    // Offline, the in-page delegate holds the identity and there is no node
    // to publish contracts to.
    if cfg!(not(feature = "use-node")) {
        send_action(NodeAction::CreateIdentity {
            identity: Box::new(identity),
            backed_up,
        });
        return Ok(());
    }
    let state =
        initial_inbox_state(&identity, identity.required_tier, identity.max_age_secs).await?;
    let aft_params = ops::SecretBytes(
        ops::v1_aft_params(identity.addr)
            .await
            .map_err(|e| format!("token generator parameters: {e}"))?,
    );
    let alias = identity.alias.clone();
    send_action(NodeAction::CreateContract {
        alias: alias.clone(),
        contract_type: crate::app::ContractType::InboxContract,
        identity: Box::new(identity.clone()),
        inbox_state: state,
    });
    send_action(NodeAction::CreateDelegate {
        alias: alias.clone(),
        identity: Box::new(identity.clone()),
        aft_params,
    });
    send_action(NodeAction::CreateContract {
        alias,
        contract_type: crate::app::ContractType::AFTContract,
        identity: Box::new(identity.clone()),
        inbox_state: Vec::new(),
    });
    send_action(NodeAction::CreateIdentity {
        identity: Box::new(identity),
        backed_up,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(alias: &str, seed: u8) -> IdentityInfo {
        IdentityInfo {
            addr: Addr([seed; 24]),
            vk: vec![seed; 1952].into(),
            ek: vec![seed; 1184].into(),
            alias: alias.to_string(),
            description: String::new(),
            confirmed: true,
            generation: 1,
        }
    }

    /// When it cannot be known whether a failed deletion began, the
    /// identity stays on the page (with a message) rather than being taken
    /// out, or kept, on a guess that "nothing is unfinished".
    #[test]
    fn an_unknown_deletion_state_keeps_the_identity_and_says_so() {
        use crate::app::{User, UserId, login::Identity};
        let id = Identity::from_info(&info("unk-del", 0x74), UserId(0));
        let mut user = User {
            logged: false,
            identified: false,
            active_id: None,
            identities: vec![id.clone()],
        };
        assert!(!settle_after_failed_deletion(&id, None, &mut user));
        assert_eq!(user.identities.len(), 1);
        let began = [info("unk-del", 0x74)];
        assert!(settle_after_failed_deletion(&id, Some(&began), &mut user));
        assert!(user.identities.is_empty());
    }

    /// A create whose answer was lost never reads as a plain failure while
    /// the identity may exist, and says when retrying is safe.
    #[test]
    fn a_lost_create_is_never_reported_as_a_plain_failure() {
        use crate::mail_delegate::{CallError, ops::LostCreate};
        let unknown = lost_create_text("lc", &LostCreate::Unknown(CallError::Unknown("x".into())));
        assert!(unknown.contains("may have been created"), "{unknown}");
        assert!(!unknown.starts_with("Couldn't create"), "{unknown}");
        let none = lost_create_text("lc", &LostCreate::NotCreated);
        assert!(none.contains("Try again"), "{none}");
        let no_key = lost_create_text(
            "lc",
            &LostCreate::CreatedKeyUnavailable(info("lc", 1), CallError::Unknown("x".into())),
        );
        assert!(no_key.contains("was created"), "{no_key}");
    }

    /// Restoring keys already stored says so, under the stored name, and a
    /// different requested name is not dropped silently.
    #[test]
    fn restoring_keys_already_here_says_under_which_name() {
        assert!(already_present_text("bob", "bob").contains("already here"));
        let renamed = already_present_text("bob", "robert");
        assert!(
            renamed.contains("`bob`") && renamed.contains("`robert`"),
            "{renamed}"
        );
    }

    /// A discard that was not confirmed tells the user where to finish it.
    #[test]
    fn an_unconfirmed_discard_tells_the_user() {
        use crate::mail_delegate::CallError;
        let t = discard_failure_text("dc", &CallError::Unknown("x".into()));
        assert!(t.contains("delete it there"), "{t}");
        let f = freenet_mail_protocol::Failure {
            code: freenet_mail_protocol::FailureCode::Busy,
            detail: "busy".into(),
        };
        let t = discard_failure_text("dc", &CallError::Failed(f));
        assert!(t.contains("still stored"), "{t}");
    }

    /// A deleted identity leaves the address book too, in both builds:
    /// otherwise typing its name sends to an inbox nobody can read.
    #[test]
    fn a_dropped_identity_leaves_the_address_book() {
        use crate::app::{User, UserId, address_book, login::Identity};
        let mut info = info("ab-gone", 0x73);
        info.vk = crate::test_util::real_vk_bytes(0x73).into();
        let gone = Identity::from_info(&info, UserId(0));
        address_book::register_identity(&gone);
        assert!(address_book::lookup("ab-gone").is_some());
        let mut user = User {
            logged: false,
            identified: false,
            active_id: None,
            identities: vec![gone.clone()],
        };
        drop_from_page(&gone, &mut user);
        assert!(address_book::lookup("ab-gone").is_none());
    }

    /// A deletion that stopped after it began leaves the identity hidden
    /// and refused by the delegate. The page must drop it too (and sign it
    /// out if it was open), leaving only the "Finish deleting" entry; one
    /// whose deletion never began stays.
    #[test]
    fn an_identity_whose_deletion_began_leaves_the_page() {
        use crate::app::{User, UserId, login::Identity};
        let gone = Identity::from_info(&info("dl-gone", 0x71), UserId(0));
        let kept = Identity::from_info(&info("dl-kept", 0x72), UserId(1));
        Identity::register_live_for_test(gone.clone());
        Identity::register_live_for_test(kept.clone());
        let mut user = User {
            logged: true,
            identified: true,
            active_id: Some(UserId(0)),
            identities: vec![gone.clone(), kept.clone()],
        };

        // Nothing listed: the deletion never began, so nothing changes.
        assert!(!drop_if_deletion_started(&gone, &[], &mut user));
        assert_eq!(user.identities.len(), 2);

        let unfinished = [info("dl-gone", 0x71)];
        assert!(drop_if_deletion_started(&gone, &unfinished, &mut user));
        assert_eq!(
            user.identities.iter().map(|i| i.addr).collect::<Vec<_>>(),
            vec![kept.addr],
            "only the identity being deleted is dropped"
        );
        assert!(
            user.logged_id().is_none(),
            "it was open, so it is signed out"
        );
        assert!(
            Identity::get_alias("dl-gone").is_none(),
            "not a live identity"
        );
        assert!(Identity::get_alias("dl-kept").is_some());
    }

    /// "Finish deleting" clicked twice starts one deletion; the claim is
    /// released when that attempt ends, so a later retry can run.
    #[test]
    fn finishing_a_deletion_runs_once_at_a_time() {
        let addr = Addr([0x61; 24]);
        assert!(begin_finishing(addr));
        let guard = FinishingGuard(addr);
        assert!(!begin_finishing(addr), "a second click is ignored");
        assert!(is_finishing(&addr));
        drop(guard);
        assert!(!is_finishing(&addr));
        assert!(begin_finishing(addr), "a later retry may run");
        drop(FinishingGuard(addr));
    }

    /// R5: a change the user makes as soon as the identities are announced,
    /// or while unfinished deletions are listed, lands before the local
    /// state load; the merge must replay it, not replace it with the load.
    #[test]
    fn a_change_made_between_the_announcement_and_the_load_is_replayed() {
        use freenet_mail_wire_v1::local_state::{Draft, LocalState};
        use futures::executor::block_on;
        let draft = |subject: &str| Draft {
            subject: subject.into(),
            ..Draft::default()
        };
        let owner = "r5-alice".to_string();
        let loaded_without_them = || {
            let mut state = LocalState::default();
            state.aliases_mut().entry(owner.clone()).or_default();
            async { Ok(state) }
        };
        block_on(announce_then_merge(
            std::slice::from_ref(&owner),
            || {
                crate::local_state::local_save_draft(
                    &owner,
                    "d-announce",
                    draft("at the announcement"),
                )
            },
            async {
                crate::local_state::local_save_draft(&owner, "d-meanwhile", draft("meanwhile"))
            },
            loaded_without_them,
        ))
        .unwrap();
        let mut ids: Vec<String> = crate::local_state::drafts_for(&owner)
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        ids.sort();
        assert_eq!(
            ids,
            vec!["d-announce".to_string(), "d-meanwhile".to_string()]
        );
    }

    /// The button's `disabled` reads `FINISHING_VIEW`, a signal, so a render
    /// re-runs when a deletion starts or ends. The signal must follow the
    /// claim and its release inside a real runtime.
    #[test]
    fn the_finish_button_state_is_a_signal_that_follows_the_claim() {
        use dioxus::prelude::*;
        fn app() -> Element {
            rsx! {}
        }
        let mut dom = VirtualDom::new(app);
        dom.rebuild_in_place();
        let addr = Addr([0x62; 24]);
        dom.in_scope(ScopeId::ROOT, || {
            assert!(!FINISHING_VIEW.read().contains(&addr));
            assert!(begin_finishing(addr));
            assert!(
                FINISHING_VIEW.read().contains(&addr),
                "the button disables while the deletion runs"
            );
            drop(FinishingGuard(addr));
            assert!(
                !FINISHING_VIEW.read().contains(&addr),
                "and re-enables when it ends"
            );
        });
    }

    #[test]
    fn a_deletion_that_may_be_partly_done_is_never_called_not_deleted() {
        use crate::mail_delegate::CallError;
        let refused = CallError::Failed(freenet_mail_protocol::Failure {
            code: freenet_mail_protocol::FailureCode::Refused,
            detail: "the user declined".into(),
        });
        let unknown = CallError::Unknown("timed out".into());
        // Nothing was removed and the delegate said so.
        assert!(deletion_failure_text("alice", &refused, false).contains("was not deleted"));
        // A page was removed, or nobody knows: it may be partly done.
        for (e, started) in [(&refused, true), (&unknown, false), (&unknown, true)] {
            let text = deletion_failure_text("alice", e, started);
            assert!(text.contains("may be incomplete"), "{text}");
            assert!(!text.contains("was not deleted"), "{text}");
        }
    }

    #[test]
    fn restoring_an_identity_being_deleted_says_to_finish_the_deletion() {
        use crate::mail_delegate::CallError;
        let being_deleted = CallError::Failed(freenet_mail_protocol::Failure {
            code: freenet_mail_protocol::FailureCode::Refused,
            detail: "this identity is being deleted".into(),
        });
        assert!(restore_failure_text(&being_deleted).contains("Finish deleting"));
        let other = CallError::Unknown("timed out".into());
        assert!(restore_failure_text(&other).starts_with("Couldn't restore the identity"));
    }

    #[test]
    fn deletion_progress_names_the_identity_and_what_is_left() {
        assert_eq!(
            deletion_progress_text("alice", 744),
            "Deleting identity `alice`… 744 items left"
        );
        assert_eq!(
            deletion_progress_text("bob", 1),
            "Deleting identity `bob`… 1 item left"
        );
    }

    #[test]
    fn markers_round_trip_and_keep_other_settings() {
        let stored = br#"{"theme":"dark"}"#;
        let markers = MigrationMarkers {
            inbox_wasm_hash: Some("abc".into()),
            pending_migration_from: None,
            aft_record_wasm_hash: Some("def".into()),
            pending_aft_migration_from: Some("old".into()),
        };
        let body = body_with_markers(Some(stored), &markers);
        assert_eq!(markers_from_body(Some(&body)), markers);
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["theme"], "dark");
    }

    #[test]
    fn migration_plan_matches_the_v0_2_marker_rules() {
        // First observation: stamp the baseline, nothing to migrate.
        let (mut rec, mut pend) = (None, None);
        assert_eq!(plan_migration(&mut rec, &mut pend, "cur"), None);
        assert_eq!((rec.as_deref(), pend.as_deref()), (Some("cur"), None));
        // Drift: migrate from the recorded hash, mark it pending, stamp now.
        let (mut rec, mut pend) = (Some("old".to_string()), None);
        assert_eq!(
            plan_migration(&mut rec, &mut pend, "cur"),
            Some("old".into())
        );
        assert_eq!(
            (rec.as_deref(), pend.as_deref()),
            (Some("cur"), Some("old"))
        );
        // A pending marker from a session whose GET never landed wins over
        // the recorded hash, and stays set until the PUT lands.
        let (mut rec, mut pend) = (Some("mid".to_string()), Some("old".to_string()));
        assert_eq!(
            plan_migration(&mut rec, &mut pend, "cur"),
            Some("old".into())
        );
        assert_eq!(
            (rec.as_deref(), pend.as_deref()),
            (Some("cur"), Some("old"))
        );
        // Recorded == current with a leftover pending marker: stale, cleared.
        let (mut rec, mut pend) = (Some("cur".to_string()), Some("old".to_string()));
        assert_eq!(plan_migration(&mut rec, &mut pend, "cur"), None);
        assert_eq!(pend, None);
    }

    #[test]
    fn unreadable_markers_plan_nothing_and_write_nothing() {
        assert_eq!(plan_load(None), (None, None, None));
    }

    #[test]
    fn readable_markers_plan_and_record_a_drift() {
        let read = MigrationMarkers {
            inbox_wasm_hash: Some("old-inbox".into()),
            pending_migration_from: None,
            aft_record_wasm_hash: Some(crate::aft::TOKEN_RECORD_CODE_HASH.to_string()),
            pending_aft_migration_from: None,
        };
        let (inbox, aft, write) = plan_load(Some(read));
        assert_eq!(inbox.as_deref(), Some("old-inbox"));
        assert_eq!(aft, None);
        let write = write.expect("a drift is recorded");
        assert_eq!(write.pending_migration_from.as_deref(), Some("old-inbox"));
        assert_eq!(
            write.inbox_wasm_hash.as_deref(),
            Some(crate::inbox::INBOX_CODE_HASH)
        );
    }

    #[test]
    fn unchanged_markers_are_not_written() {
        let read = MigrationMarkers {
            inbox_wasm_hash: Some(crate::inbox::INBOX_CODE_HASH.to_string()),
            pending_migration_from: None,
            aft_record_wasm_hash: Some(crate::aft::TOKEN_RECORD_CODE_HASH.to_string()),
            pending_aft_migration_from: None,
        };
        assert_eq!(plan_load(Some(read)), (None, None, None));
    }

    #[test]
    fn absent_or_unreadable_settings_have_no_markers() {
        assert_eq!(markers_from_body(None), MigrationMarkers::default());
        assert_eq!(
            markers_from_body(Some(b"not json")),
            MigrationMarkers::default()
        );
        assert_eq!(
            markers_from_body(Some(b"[1,2]")),
            MigrationMarkers::default()
        );
    }
}
