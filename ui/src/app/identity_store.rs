//! Identities in the mail delegate, which holds their keys, plus the
//! per-identity contract-migration markers (#213/#251) the v0.2.x client
//! kept on its identity-management delegate.
//!
//! Every call here waits for the delegate, so it runs in a task of its own,
//! never in the node loop (`api::node_comms`), which delivers the
//! delegate's answers. What the node loop needs back arrives as a
//! [`NodeAction`](crate::app::NodeAction) ([`send_action`]).

use std::cell::Cell;

use dioxus::prelude::Coroutine;
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

/// An identity as the node loop needs it on load: its public view, the v1
/// token-generator parameters (the AFT generator delegate is registered with
/// them on every session), and the contract code hashes to migrate its inbox
/// and AFT record from, if they drifted (#213, #251).
#[derive(Clone, Debug)]
pub(crate) struct LoadedIdentity {
    pub info: IdentityInfo,
    pub aft_params: Option<Vec<u8>>,
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
            crate::toast::push_toast(
                format!("Couldn't load your identities: {e}"),
                crate::toast::ToastLevel::Error,
            );
            return;
        }
    };
    // Drafts, sent, read marks and settings for these identities. Loaded
    // before the identities are announced, so the views they open start
    // from what is stored.
    #[cfg(feature = "use-node")]
    {
        let owners: Vec<(String, Addr)> = infos.iter().map(|i| (i.alias.clone(), i.addr)).collect();
        match crate::local_state::load(&owners).await {
            Ok(state) => crate::local_state::replace_snapshot(state),
            Err(e) => {
                crate::log::error(format!("loading local mail state failed: {e}"), None);
                crate::toast::push_toast(
                    format!("Couldn't load your drafts, sent mail and settings: {e}"),
                    crate::toast::ToastLevel::Error,
                );
            }
        }
    }
    let mut loaded = Vec::with_capacity(infos.len());
    for info in infos {
        loaded.push(prepare(info).await);
    }
    send_action(NodeAction::IdentitiesLoaded { identities: loaded });
}

/// Everything the node loop needs for one identity. Records the migration
/// markers before the node loop dispatches any migration GET, so a crash in
/// between still leaves the retry marker set.
pub(crate) async fn prepare(info: IdentityInfo) -> LoadedIdentity {
    let mut markers = load_markers(info.addr).await.unwrap_or_else(|e| {
        crate::log::error(
            format!("reading migration markers for `{}` failed: {e}", info.alias),
            None,
        );
        MigrationMarkers::default()
    });
    let before = markers.clone();
    let inbox_migrate_from = plan_migration(
        &mut markers.inbox_wasm_hash,
        &mut markers.pending_migration_from,
        crate::inbox::INBOX_CODE_HASH,
    );
    let aft_migrate_from = plan_migration(
        &mut markers.aft_record_wasm_hash,
        &mut markers.pending_aft_migration_from,
        crate::aft::TOKEN_RECORD_CODE_HASH,
    );
    if markers != before {
        let new = markers.clone();
        if let Err(e) = update_markers(info.addr, move |m| *m = new.clone()).await {
            crate::log::error(
                format!(
                    "recording migration markers for `{}` failed: {e}",
                    info.alias
                ),
                None,
            );
        }
    }
    let aft_params = match ops::v1_aft_params(info.addr).await {
        Ok(p) => Some(p),
        Err(e) => {
            crate::log::error(
                format!("token generator parameters for `{}`: {e}", info.alias),
                None,
            );
            None
        }
    };
    LoadedIdentity {
        info,
        aft_params,
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
            Ok(()) => drop(crate::toast::push_toast(
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
    let aft_params = ops::v1_aft_params(identity.addr)
        .await
        .map_err(|e| format!("token generator parameters: {e}"))?;
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
