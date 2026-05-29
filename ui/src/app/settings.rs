//! Settings shell — full-screen takeover inside `.fm-app`. Ported from
//! the Claude Design handoff bundle (`mail-config-ui-design`).
//!
//! Persistence: settings live in the `mail-local-state` delegate's
//! encrypted secret store (same stash as drafts / sent / read-tracking,
//! never broadcast to the network). Each on-change handler issues
//! `local_state::persist_identity_settings` / `persist_global_settings`,
//! which optimistically patches the in-memory snapshot for an immediate
//! re-render and fires a fire-and-forget delegate dispatch under
//! `use-node`. Under `example-data,no-sync` the dispatch is a no-op.
//!
//! Mobile (`.fm-m*`) classes from the prototype are intentionally not
//! ported in this pass; first cut is desktop-only.

use dioxus::prelude::*;
#[cfg(any(all(target_family = "wasm", feature = "use-node"), test))]
use mail_local_state::IdentityAftPrefs;
use mail_local_state::{
    Density, FontSize, GlobalSettings, IdentityPrivacyPrefs, IdentitySettings, InboxSettings,
    PermissionDecision, Theme, ThreadView,
};

use crate::app::User;
use crate::app::address_book;
use crate::app::menu;
use crate::local_state;
use crate::testid;

/// Read the identity-settings bucket for the active identity. Re-runs when
/// `local_state::GENERATION` advances, so an external refresh of the
/// snapshot (e.g. delegate `GetAll` reply) re-renders dependent screens.
fn use_identity_settings() -> (String, IdentitySettings) {
    let user = use_context::<Signal<User>>();
    let alias = user
        .read()
        .logged_id()
        .map(|id| id.alias.to_string())
        .unwrap_or_default();
    let alias_for_memo = alias.clone();
    let settings = use_memo(move || {
        // Subscribe to GENERATION so this re-runs on snapshot mutation.
        let _gen = local_state::GENERATION();
        local_state::identity_settings_for(&alias_for_memo)
    });
    (alias, settings())
}

fn use_global_settings() -> GlobalSettings {
    let settings = use_memo(move || {
        let _gen = local_state::GENERATION();
        local_state::global_settings()
    });
    settings()
}

#[allow(non_snake_case)]
pub(crate) fn SettingsShell() -> Element {
    let mut menu_selection = use_context::<Signal<menu::MenuSelection>>();
    let mut user = use_context::<Signal<User>>();
    let mut inbox = use_context::<Signal<crate::app::InboxView>>();

    let screen = menu_selection
        .read()
        .settings()
        .unwrap_or(menu::SettingsScreen::Account);

    let alias = user
        .read()
        .logged_id()
        .map(|id| id.alias.to_string())
        .unwrap_or_default();
    let initial = alias.chars().next().unwrap_or('·').to_string();
    let fp_short_segs: [&'static str; 3] = user
        .read()
        .logged_id()
        .map(|id| {
            let words =
                address_book::fingerprint_words(&id.ml_dsa_vk_bytes(), &id.ml_kem_ek_bytes());
            [words[0], words[1], words[2]]
        })
        .unwrap_or([""; 3]);

    let mut switcher_open = use_signal(|| false);

    // Snapshot the identity list so the popover renders something stable
    // even if the User signal changes while it's open.
    let switcher_rows: Vec<(crate::app::UserId, String, String)> = user
        .read()
        .identities
        .iter()
        .map(|id| {
            let words =
                address_book::fingerprint_words(&id.ml_dsa_vk_bytes(), &id.ml_kem_ek_bytes());
            let fp = format!("{} · {} · {}", words[0], words[1], words[2]);
            (id.id, id.alias.to_string(), fp)
        })
        .collect();
    let active_user_id = user.read().logged_id().map(|i| i.id);

    rsx! {
        div { class: "fm-settings", "data-testid": testid::FM_SETTINGS_SHELL,
            aside { class: "fm-set-side",
                button {
                    class: "fm-set-back",
                    "data-testid": testid::FM_SETTINGS_BACK,
                    onclick: move |_| menu_selection.write().close_settings(),
                    span { class: "arrow", "←" }
                    "Back to mailbox"
                }
                div { class: "fm-set-title", "Settings" }
                button {
                    class: "fm-set-ident",
                    style: "all: unset; display: flex; align-items: center; gap: 8px; padding: 6px 8px; border-radius: 8px; cursor: pointer;",
                    "data-testid": "fm-settings-ident-switcher",
                    "aria-haspopup": "listbox",
                    "aria-expanded": "{switcher_open()}",
                    onclick: move |_| {
                        let cur = *switcher_open.read();
                        switcher_open.set(!cur);
                    },
                    span { class: "fm-set-ident-av", "{initial}" }
                    div { class: "fm-set-ident-text",
                        span { class: "fm-set-ident-name", "{alias}" }
                        span { class: "fm-set-ident-meta", "{fp_short_segs[0]} · {fp_short_segs[1]}…" }
                    }
                    span { class: "fm-set-ident-caret", "▾" }
                }
                if switcher_open() {
                    div {
                        class: "fm-set-ident-pop",
                        role: "listbox",
                        style: "border: 1px solid var(--line); border-radius: 10px; background: #fff; box-shadow: 0 8px 24px rgba(0,0,0,0.08); margin: 4px 0 12px; overflow: hidden;",
                        for (uid, row_alias, fp) in switcher_rows.iter() {
                            {
                                let uid = *uid;
                                let is_active = active_user_id == Some(uid);
                                let row_alias_owned = row_alias.clone();
                                let row_initial = row_alias_owned
                                    .chars()
                                    .next()
                                    .map(|c| c.to_string())
                                    .unwrap_or_else(|| "·".into());
                                let row_fp = fp.clone();
                                let bg = if is_active { "var(--bg-soft)" } else { "#fff" };
                                let style = format!(
                                    "all: unset; display: flex; gap: 10px; align-items: center; width: 100%; padding: 8px 12px; cursor: pointer; background: {bg};",
                                );
                                rsx! {
                                    button {
                                        key: "{uid:?}",
                                        role: "option",
                                        "aria-selected": "{is_active}",
                                        style: "{style}",
                                        onclick: move |_| {
                                            user.write().set_logged_id(uid);
                                            inbox.write().set_active_id(uid);
                                            switcher_open.set(false);
                                        },
                                        span { class: "fm-set-ident-av", "{row_initial}" }
                                        div { style: "display: flex; flex-direction: column;",
                                            span { style: "font-weight: 500;", "{row_alias_owned}" }
                                            span { style: "font-family: 'Geist Mono', monospace; font-size: 11px; color: var(--ink3);", "{row_fp}" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                NavBlock { current: screen }
            }
            main { class: "fm-set-main",
                BarHeader { current: screen, alias: alias.clone() }
                div { class: "fm-set-body",
                    match screen {
                        menu::SettingsScreen::Account => rsx! { ScrAccount {} },
                        menu::SettingsScreen::Privacy => rsx! { ScrPrivacy {} },
                        menu::SettingsScreen::Aft => rsx! { ScrAft {} },
                        menu::SettingsScreen::Inbox => rsx! { ScrInbox {} },
                        menu::SettingsScreen::Contacts => rsx! { ScrContacts {} },
                        menu::SettingsScreen::Appearance => rsx! { ScrAppearance {} },
                        menu::SettingsScreen::Advanced => rsx! { ScrAdvanced {} },
                    }
                }
            }
        }
    }
}

#[component]
fn BarHeader(current: menu::SettingsScreen, alias: String) -> Element {
    let scope_class = if current.is_global() {
        "fm-set-bar-scope"
    } else {
        "fm-set-bar-scope identity"
    };
    let scope_text = if current.is_global() {
        "GLOBAL".to_string()
    } else {
        format!("for {alias}")
    };
    rsx! {
        div { class: "fm-set-bar",
            div { class: "fm-set-bar-title", "{current.label()}" }
            span { class: "{scope_class}", "{scope_text}" }
            span { class: "fm-set-bar-grow" }
            span { class: "fm-set-bar-meta", "⌘," }
        }
    }
}

#[component]
fn NavBlock(current: menu::SettingsScreen) -> Element {
    let mut menu_selection = use_context::<Signal<menu::MenuSelection>>();

    let identity_items: Vec<(menu::SettingsScreen, &str)> = vec![
        (menu::SettingsScreen::Account, "◉ Account & profile"),
        (menu::SettingsScreen::Privacy, "▣ Privacy & security"),
        (menu::SettingsScreen::Aft, "▶ Anti-Flood (AFT)"),
        (menu::SettingsScreen::Inbox, "◌ Inbox & folders"),
        (menu::SettingsScreen::Contacts, "· Contacts"),
    ];
    let global_items: Vec<(menu::SettingsScreen, &str)> = vec![
        (menu::SettingsScreen::Appearance, "◐ Appearance"),
        (menu::SettingsScreen::Advanced, "≡ Advanced & Diagnostics"),
    ];
    let groups: Vec<(&str, Vec<(menu::SettingsScreen, &str)>)> =
        vec![("GLOBAL", global_items), ("IDENTITY", identity_items)];

    rsx! {
        div { class: "fm-set-nav",
            for (heading, items) in groups.iter() {
                div { class: "fm-set-nav-group", "{heading}" }
                for (item, label) in items.iter() {
                    {
                        let item = *item;
                        let glyph = label.split_whitespace().next().unwrap_or("·").to_string();
                        let text = label
                            .split_once(' ')
                            .map(|x| x.1)
                            .unwrap_or(label)
                            .to_string();
                        let is_active = current == item;
                        let class = if is_active {
                            "fm-set-nav-item is-active"
                        } else {
                            "fm-set-nav-item"
                        };
                        rsx! {
                            button {
                                key: "{label}",
                                class: "{class}",
                                "data-testid": testid::FM_SETTINGS_NAV_ITEM,
                                "data-screen": item.slug(),
                                onclick: move |_| menu_selection.write().open_settings(item),
                                span { class: "glyph", "{glyph}" }
                                span { class: "label", "{text}" }
                            }
                        }
                    }
                }
            }
        }
    }
}

// ===== Atoms =====

#[component]
fn Card(title: Option<String>, sub: Option<String>, children: Element) -> Element {
    rsx! {
        div { class: "fm-card",
            if title.is_some() || sub.is_some() {
                div { class: "fm-card-head",
                    if let Some(t) = title { div { class: "fm-card-title", "{t}" } }
                    if let Some(s) = sub { div { class: "fm-card-sub", "{s}" } }
                }
            }
            {children}
        }
    }
}

#[component]
fn SettingRow(
    label: String,
    help: Option<String>,
    stacked: Option<bool>,
    control: Element,
) -> Element {
    let class = if stacked.unwrap_or(false) {
        "fm-row-set stacked"
    } else {
        "fm-row-set"
    };
    rsx! {
        div { class: "{class}",
            div {
                div { class: "fm-row-set-label", "{label}" }
                if let Some(h) = help { div { class: "fm-row-set-help", "{h}" } }
            }
            div { {control} }
        }
    }
}

#[component]
fn Toggle(on: bool, ontoggle: EventHandler<()>) -> Element {
    let cls = if on { "fm-toggle on" } else { "fm-toggle" };
    rsx! {
        button {
            class: "{cls}",
            r#type: "button",
            role: "switch",
            "aria-checked": "{on}",
            onclick: move |_| ontoggle.call(()),
        }
    }
}

#[component]
fn FpGrid(seed: String) -> Element {
    // Deterministic 8x8 fingerprint visualization derived from `seed`.
    // Mirrors the prototype's `FpGrid` LCG so the visual is stable for a
    // given identity. Not cryptographically meaningful — a glanceable
    // identity check that complements the word-based fingerprint.
    let cells = {
        let mut h: u32 = 0;
        for b in seed.as_bytes() {
            h = h.wrapping_mul(31).wrapping_add(*b as u32);
        }
        let mut r = if h == 0 { 1u32 } else { h };
        let palette = ["#0066cc", "#339966", "#bfdbfe", "#cbd5e1", "#1f2937"];
        let mut out = Vec::with_capacity(64);
        for _ in 0..64 {
            r = r.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let pick = (r % 7) as usize;
            let color = match pick {
                0..=4 => palette[pick],
                _ => "transparent",
            };
            out.push(color.to_string());
        }
        out
    };
    rsx! {
        div { class: "fm-fp-grid", "aria-label": "key fingerprint",
            for (i, c) in cells.iter().enumerate() {
                span { key: "{i}", class: "cell", style: "background: {c}" }
            }
        }
    }
}

// ===== Screens =====

#[allow(non_snake_case)]
fn ScrAccount() -> Element {
    let user = use_context::<Signal<User>>();
    let alias = user
        .read()
        .logged_id()
        .map(|id| id.alias.to_string())
        .unwrap_or_default();
    let (fp_short, fp_kem_short, vk_seed) = user
        .read()
        .logged_id()
        .map(|id| {
            let words =
                address_book::fingerprint_words(&id.ml_dsa_vk_bytes(), &id.ml_kem_ek_bytes());
            let fp_short = format!("{} · {} · {}", words[0], words[1], words[2]);
            let fp_kem = format!("{} · {} · {}", words[3], words[4], words[5]);
            let seed = id
                .ml_dsa_vk_bytes()
                .iter()
                .take(16)
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            (fp_short, fp_kem, seed)
        })
        .unwrap_or_default();

    let (alias_key, ident) = use_identity_settings();
    let signature = ident.signature.clone();
    let auto_sign = ident.auto_sign;
    let last_backup_at = ident.last_backup_at;
    let backed_up = last_backup_at.is_some();
    let last_backup_label = match last_backup_at {
        Some(ms) => chrono::DateTime::from_timestamp_millis(ms)
            .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
            .unwrap_or_else(|| format!("{ms}")),
        None => "Never".to_string(),
    };

    let alias_key_sig = alias_key.clone();
    let ident_sig = ident.clone();
    let on_signature = move |ev: Event<FormData>| {
        let mut next = ident_sig.clone();
        next.signature = ev.value();
        local_state::persist_identity_settings(alias_key_sig.clone(), next);
    };
    let alias_key_as = alias_key.clone();
    let ident_as = ident.clone();
    let on_auto_sign = move |_| {
        let mut next = ident_as.clone();
        next.auto_sign = !next.auto_sign;
        local_state::persist_identity_settings(alias_key_as.clone(), next);
    };

    // Back-up: serialise the active identity to JSON, trigger a browser
    // download, then stamp `last_backup_at` so the amber banner stops
    // showing and the "Last backup" row updates.
    let user_for_backup = user;
    let alias_key_bk = alias_key.clone();
    let ident_bk = ident.clone();
    let on_backup = move |_| {
        let Some(active) = user_for_backup.read().logged_id().cloned() else {
            return;
        };
        let backup = crate::app::login::IdentityBackup::from_identity(&active);
        let Ok(json) = serde_json::to_vec_pretty(&backup) else {
            return;
        };
        let words = crate::app::address_book::fingerprint_words(
            &active.ml_dsa_vk_bytes(),
            &active.ml_kem_ek_bytes(),
        );
        let fname = crate::app::login::backup_filename(&active.alias, &words);
        if let Err(e) = crate::app::login::trigger_browser_download(&fname, &json) {
            crate::log::info(format!("Backup download failed: {e}"));
            return;
        }
        let mut next = ident_bk.clone();
        next.last_backup_at = Some(chrono::Utc::now().timestamp_millis());
        local_state::persist_identity_settings(alias_key_bk.clone(), next);
    };

    // Restore: route through the existing import-backup modal; close
    // settings so the modal is visible over the login pane.
    let mut menu_selection = use_context::<Signal<menu::MenuSelection>>();
    let mut import_backup = use_context::<Signal<crate::app::login::ImportBackup>>();
    let on_restore = move |_| {
        menu_selection.write().close_settings();
        import_backup.write().0 = true;
    };

    rsx! {
        div { class: "fm-set-inner",
            p { class: "fm-set-lede",
                "Identity-scoped settings. These follow this identity across devices once sync lands. Switch the active identity in the sidebar to edit a different one."
            }
            if !backed_up {
                div { class: "fm-banner amber",
                    span { class: "fm-banner-glyph", "!" }
                    div { class: "fm-banner-text",
                        strong { "This identity has not been backed up." }
                        " If you lose this browser's storage, the keys go with it. There is no server-side recovery."
                    }
                    div { class: "fm-banner-actions",
                        button {
                            class: "fm-btn-primary",
                            onclick: on_backup.clone(),
                            "Back up now"
                        }
                    }
                }
            }
            Card {
                title: "Profile",
                sub: "Visible to anyone you send to.",
                SettingRow {
                    label: "Alias",
                    help: "The handle others type to reach you. Bound to this identity's keys; cannot be changed without rotating.",
                    control: rsx! { input { class: "fm-input mono", value: "{alias}", disabled: true, style: "width: 180px" } },
                }
                SettingRow {
                    label: "Signature",
                    help: "Appended to outgoing messages from this identity. Plain text only.",
                    stacked: true,
                    control: rsx! {
                        textarea {
                            class: "fm-textarea",
                            value: "{signature}",
                            oninput: on_signature,
                        }
                    },
                }
                SettingRow {
                    label: "Append signature to new messages",
                    help: "Disable per-message in the compose footer.",
                    control: rsx! { Toggle { on: auto_sign, ontoggle: on_auto_sign } },
                }
            }
            Card {
                title: "Keys",
                sub: "Post-quantum keypair. Burned into your alias.",
                div { class: "fm-keys-grid",
                    div { class: "fm-key-card",
                        div { class: "fm-key-card-head",
                            span { class: "fm-key-card-name", "ML-DSA-65 · signing" }
                        }
                        div { style: "display: flex; gap: 14px; align-items: center;",
                            FpGrid { seed: vk_seed.clone() }
                            div { class: "fm-key-card-fp", "{fp_short}" }
                        }
                    }
                    div { class: "fm-key-card",
                        div { class: "fm-key-card-head",
                            span { class: "fm-key-card-name", "ML-KEM-768 · encryption" }
                        }
                        div { style: "display: flex; gap: 14px; align-items: center;",
                            FpGrid { seed: format!("{vk_seed}-kem") }
                            div { class: "fm-key-card-fp", "{fp_kem_short}" }
                        }
                    }
                }
            }
            Card {
                title: "Backup & restore",
                sub: "Backups are an encrypted bundle of both keys. There's no server-side recovery; lose this and the alias is gone.",
                SettingRow {
                    label: "Last backup",
                    help: last_backup_label.clone(),
                    control: rsx! {
                        button {
                            class: "fm-btn-primary",
                            onclick: on_backup,
                            "Back up now"
                        }
                    },
                }
                SettingRow {
                    label: "Restore from backup",
                    help: "Replaces the active identity's keys. The current keys will be unrecoverable after this.",
                    control: rsx! {
                        button {
                            class: "fm-btn-secondary",
                            onclick: on_restore,
                            "Restore…"
                        }
                    },
                }
            }
        }
    }
}

#[allow(non_snake_case)]
fn ScrPrivacy() -> Element {
    let (alias_key, ident) = use_identity_settings();
    let priv_now = ident.privacy.clone();
    let verify_on_send = priv_now.verify_on_send;
    let hide_unsigned = priv_now.hide_unsigned;

    let mk_toggle = move |mutate: fn(&mut IdentityPrivacyPrefs)| {
        let alias_key = alias_key.clone();
        let ident = ident.clone();
        move |_| {
            let mut next = ident.clone();
            mutate(&mut next.privacy);
            local_state::persist_identity_settings(alias_key.clone(), next);
        }
    };
    let on_verify = mk_toggle(|p| p.verify_on_send = !p.verify_on_send);
    let on_hide_unsigned = mk_toggle(|p| p.hide_unsigned = !p.hide_unsigned);
    rsx! {
        div { class: "fm-set-inner",
            p { class: "fm-set-lede",
                "How keys are verified, what counts as trusted, and what to do with messages that aren't."
            }
            Card { title: "Sender verification",
                SettingRow {
                    label: "Require known key to send",
                    help: "Block compose to recipients whose ML-DSA-65 key isn't in your known-keys set. Forces you to verify out-of-band first.",
                    control: rsx! { Toggle { on: verify_on_send, ontoggle: on_verify } },
                }
                SettingRow {
                    label: "Hide unsigned messages",
                    help: "Drop messages with no valid ML-DSA signature from the list entirely. For unknown-but-signed senders, use Quarantine in Inbox settings instead.",
                    control: rsx! { Toggle { on: hide_unsigned, ontoggle: on_hide_unsigned } },
                }
            }
        }
    }
}

/// Map an `IdentityAftPrefs.required_tier` string back to the typed
/// enum. Mirrors the names the `TIER_ROWS` picker writes to local
/// state (#85). Returns `None` for unrecognized values so the
/// caller can surface the error rather than silently defaulting.
fn parse_tier(s: &str) -> Option<freenet_aft_interface::Tier> {
    use freenet_aft_interface::Tier::*;
    Some(match s {
        "Min1" => Min1,
        "Min5" => Min5,
        "Min10" => Min10,
        "Min30" => Min30,
        "Hour1" => Hour1,
        "Hour3" => Hour3,
        "Hour6" => Hour6,
        "Hour12" => Hour12,
        "Day1" => Day1,
        "Day7" => Day7,
        "Day15" => Day15,
        "Day30" => Day30,
        "Day90" => Day90,
        "Day180" => Day180,
        "Day365" => Day365,
        _ => return None,
    })
}

/// Capacity values larger than this collapse to "ample" in the AFT
/// usage panel. A `Min1` tier at the default 365d window has 525,600
/// theoretical slots — surfacing the integer is more noise than
/// signal. The cutoff is chosen so the longer-period tiers (Hour1 and
/// up at 365d, all tiers at <1d windows) still render their numeric
/// capacity, since those are the ones a user can plausibly exhaust.
const CAPACITY_AMPLE_THRESHOLD: u64 = 10_000;

/// Every `Tier` variant in cheapest → most-expensive order. Mirrors
/// `TIER_ROWS` but holds the enum values (not display strings) so the
/// AFT usage panel can compute capacity per tier from
/// `Tier::tier_duration`.
const ALL_TIERS: &[freenet_aft_interface::Tier] = {
    use freenet_aft_interface::Tier::*;
    &[
        Min1, Min5, Min10, Min30, Hour1, Hour3, Hour6, Hour12, Day1, Day7, Day15, Day30, Day90,
        Day180, Day365,
    ]
};

/// Pretty name for a `Tier` enum value matching the labels in
/// `TIER_ROWS` (`"Day1"`, `"Hour1"`, etc.). `Tier`'s `Display` impl is
/// strum-`lowercase` (`"day1"`); we want title-cased identifiers in
/// the AFT settings screen for visual consistency with the tier
/// picker.
fn tier_display_name(t: freenet_aft_interface::Tier) -> &'static str {
    use freenet_aft_interface::Tier::*;
    match t {
        Min1 => "Min1",
        Min5 => "Min5",
        Min10 => "Min10",
        Min30 => "Min30",
        Hour1 => "Hour1",
        Hour3 => "Hour3",
        Hour6 => "Hour6",
        Hour12 => "Hour12",
        Day1 => "Day1",
        Day7 => "Day7",
        Day15 => "Day15",
        Day30 => "Day30",
        Day90 => "Day90",
        Day180 => "Day180",
        Day365 => "Day365",
    }
}

/// One row per real `freenet_aft_interface::Tier`. The "rate" column is
/// derived from the tier name (1 token per N time-unit) — there is no
/// `tokens_per_period` getter on the enum, so the period text is encoded
/// here rather than in `freenet-aft-interface` to keep the AFT crate from
/// taking on UI vocabulary.
const TIER_ROWS: &[(&str, &str)] = &[
    ("Min1", "1 / minute"),
    ("Min5", "1 / 5 minutes"),
    ("Min10", "1 / 10 minutes"),
    ("Min30", "1 / 30 minutes"),
    ("Hour1", "1 / hour"),
    ("Hour3", "1 / 3 hours"),
    ("Hour6", "1 / 6 hours"),
    ("Hour12", "1 / 12 hours"),
    ("Day1", "1 / day"),
    ("Day7", "1 / 7 days"),
    ("Day15", "1 / 15 days"),
    ("Day30", "1 / 30 days"),
    ("Day90", "1 / 90 days"),
    ("Day180", "1 / 180 days"),
    ("Day365", "1 / year"),
];

/// A helper that derives which `PermissionDecision` (if any) should be applied
/// automatically for a recipient identified by `fingerprint_full` given the
/// active identity's AFT preferences.
///
/// Returns `Some(Accept)` or `Some(Deny)` when a saved or policy-driven
/// decision is available; `None` when the permission modal should be shown.
///
/// Priority order:
/// 1. Per-recipient saved decision (`permission_decisions` map).
/// 2. `auto_accept_verified_contacts` + `is_verified`.
/// 3. No automatic decision → `None`.
#[cfg(any(all(target_family = "wasm", feature = "use-node"), test))]
pub(crate) fn resolve_permission_decision(
    prefs: &IdentityAftPrefs,
    fingerprint_full: &str,
    is_verified: bool,
) -> Option<PermissionDecision> {
    if let Some(saved) = prefs.permission_decisions.get(fingerprint_full) {
        return Some(*saved);
    }
    if prefs.auto_accept_verified_contacts && is_verified {
        return Some(PermissionDecision::Accept);
    }
    None
}

/// Collect the ML-DSA-65 verifying key bytes of every contact the user has
/// explicitly marked as verified in the address book. Used to keep the
/// `verified_senders` set in the inbox contract in sync with the local
/// address book when the bypass toggle changes.
fn collect_verified_sender_vk_bytes() -> std::collections::BTreeSet<Vec<u8>> {
    address_book::all_contacts()
        .into_iter()
        .filter(|c| c.verified)
        .map(|c| c.ml_dsa_vk_bytes)
        .collect()
}

#[allow(non_snake_case)]
fn ScrAft() -> Element {
    let (alias_key, ident) = use_identity_settings();
    let aft_now = ident.aft.clone();
    let selected_tier = aft_now.required_tier.clone();
    let max_age_days = aft_now.max_age_days;
    let auto_accept_verified = aft_now.auto_accept_verified_contacts;
    let allow_verified_skip_token = aft_now.allow_verified_skip_token;
    let actions = use_coroutine_handle::<crate::app::NodeAction>();

    /// Resolve the current identity for dispatcher helpers.
    fn identity_for_alias(alias: &str) -> Option<crate::app::login::Identity> {
        crate::app::address_book::lookup(alias)
            .filter(|r| r.is_own)
            .and_then(|_| {
                crate::app::login::Identity::get_aliases()
                    .borrow()
                    .iter()
                    .find(|i| i.alias.as_ref() == alias)
                    .cloned()
            })
    }

    // #85: dispatch a `ModifySettings` delta to the inbox contract so
    // the new policy actually gates incoming sends — without this the
    // change is local-state-only and senders keep minting at the old
    // tier.
    let push_policy = move |alias: &str, tier_str: &str, max_age_days: u64| {
        let Some(identity) = identity_for_alias(alias) else {
            crate::log::error(
                format!("AFT settings: no own identity for alias `{alias}`"),
                None,
            );
            return;
        };
        let Some(tier) = parse_tier(tier_str) else {
            crate::log::error(format!("AFT settings: invalid tier `{tier_str}`"), None);
            return;
        };
        let max_age_secs = max_age_days.saturating_mul(86_400);
        actions.send(crate::app::NodeAction::UpdateInboxPolicy {
            identity: Box::new(identity),
            required_tier: tier,
            max_age_secs,
        });
    };

    let alias_key_t = alias_key.clone();
    let ident_t = ident.clone();
    let on_tier = move |new_tier: String| {
        let mut next = ident_t.clone();
        next.aft.required_tier = new_tier.clone();
        local_state::persist_identity_settings(alias_key_t.clone(), next.clone());
        push_policy(&alias_key_t, &new_tier, next.aft.max_age_days);
    };
    let alias_key_m = alias_key.clone();
    let ident_m = ident.clone();
    let on_max_age = move |ev: Event<FormData>| {
        let raw = ev.value();
        let parsed: u64 = raw.parse().unwrap_or(365).clamp(1, 730);
        let mut next = ident_m.clone();
        next.aft.max_age_days = parsed;
        local_state::persist_identity_settings(alias_key_m.clone(), next.clone());
        push_policy(&alias_key_m, &next.aft.required_tier, parsed);
    };

    // Toggle for auto-accept verified contacts (Part 3, #149).
    let alias_key_av = alias_key.clone();
    let ident_av = ident.clone();
    let on_auto_accept_verified = move |_| {
        let mut next = ident_av.clone();
        next.aft.auto_accept_verified_contacts = !next.aft.auto_accept_verified_contacts;
        local_state::persist_identity_settings(alias_key_av.clone(), next);
    };

    // Snapshot decisions so the list is stable while the component renders.
    let decisions: Vec<(String, PermissionDecision)> = {
        let mut v: Vec<_> = aft_now
            .permission_decisions
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    };

    // Remove a saved decision for a specific fingerprint.
    let alias_key_rm = alias_key.clone();
    let ident_rm = ident.clone();
    let on_remove_decision = move |fp: String| {
        let mut next = ident_rm.clone();
        next.aft.permission_decisions.remove(&fp);
        local_state::persist_identity_settings(alias_key_rm.clone(), next);
    };

    // Contacts available for the "add decision" picker (non-own, sorted by alias).
    let picker_contacts: Vec<(String, String)> = {
        let mut v: Vec<_> = address_book::all_contacts()
            .into_iter()
            .filter(|c| {
                !aft_now
                    .permission_decisions
                    .contains_key(&c.fingerprint_full())
            })
            .map(|c| (c.local_alias.to_string(), c.fingerprint_full()))
            .collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    };

    // Local form state for the "Add decision" form.
    let mut add_fp = use_signal(String::new);
    let mut add_accept = use_signal(|| true); // true = Accept, false = Deny

    let alias_key_add = alias_key.clone();
    let ident_add = ident.clone();
    let on_add_decision = move |_| {
        let fp = add_fp.read().clone();
        if fp.is_empty() {
            return;
        }
        let decision = if *add_accept.read() {
            PermissionDecision::Accept
        } else {
            PermissionDecision::Deny
        };
        let mut next = ident_add.clone();
        next.aft.permission_decisions.insert(fp, decision);
        local_state::persist_identity_settings(alias_key_add.clone(), next);
        // Reset form.
        add_fp.set(String::new());
        add_accept.set(true);
    };

    // #150: toggle "Don't require tokens from verified senders". When
    // turned ON, push the current verified-senders set from the address
    // book alongside the flag. When turned OFF, push an empty set (the
    // contract enforces the flag, not the set content, but clearing the
    // set avoids stale data accumulating in the contract state).
    let alias_key_v = alias_key.clone();
    let ident_v = ident.clone();
    let on_verified_bypass = move |_| {
        let new_flag = !ident_v.aft.allow_verified_skip_token;
        let mut next = ident_v.clone();
        next.aft.allow_verified_skip_token = new_flag;
        local_state::persist_identity_settings(alias_key_v.clone(), next);

        let Some(identity) = identity_for_alias(&alias_key_v) else {
            crate::log::error(
                format!(
                    "AFT verified-bypass toggle: no own identity for `{}`",
                    alias_key_v
                ),
                None,
            );
            return;
        };
        // When turning ON, snapshot the verified VKs from the address book.
        // When turning OFF, send an empty set to clear stale entries.
        let verified_senders = if new_flag {
            collect_verified_sender_vk_bytes()
        } else {
            std::collections::BTreeSet::new()
        };
        actions.send(crate::app::NodeAction::UpdateVerifiedBypass {
            identity: Box::new(identity),
            allow_verified_skip_token: new_flag,
            verified_senders,
        });
    };

    // #271: Surface AFT slot usage + remaining slots per tier for the
    // active identity. Read at render time from the `RECORDS`
    // thread-local — no reactive subscription, so values refresh on
    // next Settings open.
    //
    // Capacity per tier is computed against the sender's OWN max_age
    // (`capacity = max_age_secs / tier_period_secs`). A recipient
    // running a shorter `max_age` will see fewer free slots — the copy
    // calls that out explicitly. Tiers with capacity above
    // CAPACITY_AMPLE_THRESHOLD render the rate as "ample" instead of a
    // huge integer (a Min1 tier at 365d has 525k slots — surfacing the
    // number is more noise than signal).
    let max_age_secs: u64 = max_age_days.saturating_mul(86_400);
    let used_by_tier: std::collections::HashMap<freenet_aft_interface::Tier, usize> =
        identity_for_alias(&alias_key)
            .map(|id| {
                crate::aft::AftRecords::used_counts_by_tier(&id)
                    .into_iter()
                    .collect()
            })
            .unwrap_or_default();
    let tier_rows: Vec<(&'static str, usize, u64)> = ALL_TIERS
        .iter()
        .map(|tier| {
            let period_secs = tier.tier_duration().as_secs().max(1);
            let capacity = max_age_secs / period_secs;
            let used = used_by_tier.get(tier).copied().unwrap_or(0);
            (tier_display_name(*tier), used, capacity)
        })
        .collect();
    let total_tokens_spent: usize = used_by_tier.values().copied().sum();

    rsx! {
        div { class: "fm-set-inner",
            p { class: "fm-set-lede",
                "Anti-Flood Tokens rate-limit the network without a server. Recipients require senders to hold a token of at least the recipient's chosen tier. Settings on this screen are a mix: some control how YOUR client sends mail (sender-side), others publish policy that other senders see and obey when sending to YOUR inbox (recipient-side). Each card below labels which side it affects."
            }
            Card {
                title: "Your tokens",
                sub: "Each sent message burns one AFT slot at one tier. Slots roll out as they age past the recipient's max-age window, so the “free” counts below are computed against your own max-age — a recipient running a shorter window will see fewer slots than shown.",
                div { style: "padding: 4px 16px 12px;",
                    div { style: "font-size: 13px; color: var(--ink2); margin-bottom: 8px;",
                        "Total slots in use for "
                        b { "{alias_key}" }
                        ": "
                        b { "{total_tokens_spent}" }
                    }
                    div { class: "fm-tier-grid",
                        for (tier_name, used, capacity) in tier_rows.iter() {
                            {
                                let tier_name = *tier_name;
                                let used = *used;
                                let capacity = *capacity;
                                let free = capacity.saturating_sub(used as u64);
                                let rate_text = if capacity > CAPACITY_AMPLE_THRESHOLD {
                                    if used == 0 {
                                        "ample free".to_string()
                                    } else {
                                        format!("{used} used · ample free")
                                    }
                                } else {
                                    format!("{used} used · {free} free")
                                };
                                let is_exhausted = capacity > 0 && free == 0;
                                let extra_style = if is_exhausted {
                                    "border-color: var(--red, #ef4444);"
                                } else {
                                    ""
                                };
                                rsx! {
                                    div {
                                        key: "{tier_name}",
                                        class: "fm-tier",
                                        style: "display: flex; flex-direction: column; gap: 4px; border: 1px solid var(--line); border-radius: 11px; padding: 12px 12px 10px; background: #fff; {extra_style}",
                                        "data-testid": "fm-aft-usage-tier",
                                        "data-tier": "{tier_name}",
                                        "data-used": "{used}",
                                        "data-capacity": "{capacity}",
                                        div { class: "fm-tier-name", "{tier_name}" }
                                        div { class: "fm-tier-rate", "{rate_text}" }
                                    }
                                }
                            }
                        }
                    }
                    details { style: "margin-top: 14px;",
                        summary { style: "font-size: 12px; color: var(--ink2); cursor: pointer;",
                            "How AFT rationing works"
                        }
                        div { style: "font-size: 12px; color: var(--ink2); line-height: 1.5; margin-top: 8px;",
                            p {
                                "Each tier mints one slot per period (e.g. Day1 = one slot per day, Hour1 = one slot per hour). When you send a message, your client picks the cheapest tier the recipient accepts and burns one slot at that tier. Slots are tied to time, not to a wallet — a slot from yesterday cannot be re-spent."
                            }
                            p { style: "margin-top: 8px;",
                                "Slots stay in the record until they age past the recipient's “max age” window (default 365 days). After that they roll out and free up a new slot in the same tier. You can shorten the window above to rotate slots faster."
                            }
                            p { style: "margin-top: 8px;",
                                "If you run out of slots in a tier the recipient accepts, sends are blocked until time passes. Lowering your “Required tier for incoming mail” gives senders more headroom but weakens the spam filter."
                            }
                        }
                    }
                }
            }
            Card {
                title: "Required tier for incoming mail",
                sub: "Senders must hold a token of this tier or higher to land in your inbox. Lower-tier sends are refused by the inbox contract.",
                div { class: "fm-tier-grid",
                    for (id, rate) in TIER_ROWS.iter() {
                        {
                            let id_str = id.to_string();
                            let active = selected_tier == id_str;
                            let cls = if active { "fm-tier is-active" } else { "fm-tier" };
                            let on_tier_click = on_tier.clone();
                            rsx! {
                                button {
                                    key: "{id}",
                                    class: "{cls}",
                                    r#type: "button",
                                    style: "all: unset; display: flex; flex-direction: column; gap: 4px; cursor: pointer; border: 1px solid var(--line); border-radius: 11px; padding: 12px 12px 10px; background: #fff;",
                                    "data-testid": "fm-aft-tier",
                                    "data-tier": "{id}",
                                    "data-active": "{active}",
                                    onclick: move |_| on_tier_click(id_str.clone()),
                                    div { class: "fm-tier-name", "{id}" }
                                    div { class: "fm-tier-rate", "{rate}" }
                                }
                            }
                        }
                    }
                }
            }
            Card {
                title: "Token max age",
                SettingRow {
                    label: "Token max age",
                    help: "Sender's AFT delegate uses this when picking a free slot. Capped at 730 days by the AFT crate; lower values rotate the cap faster.",
                    control: rsx! {
                        input {
                            class: "fm-input",
                            r#type: "number",
                            min: "1",
                            max: "730",
                            value: "{max_age_days}",
                            style: "width: 100px",
                            // Use onchange (not oninput) so persist_identity_settings and
                            // push_policy (which dispatches a signed ML-DSA inbox-state UPDATE
                            // over WebSocket) fire only when the user commits the value —
                            // e.g. pressing Enter or blurring the field — not on every
                            // keystroke. Typing "365" must not send three signed contract
                            // updates for 3, 36, 365.
                            onchange: on_max_age,
                        }
                    },
                }
            }
            Card {
                title: "When sending: skip permission pop-ups",
                sub: "These settings affect THIS client's send path. They tell your client when to auto-confirm the Freenet gateway's AFT permission prompt instead of asking you. They do NOT change whether a token is minted — only whether you are prompted.",
                SettingRow {
                    label: "Auto-confirm prompt for verified contacts",
                    help: "When on, sending to a contact you have verified (fingerprint confirmed in Settings → Contacts) auto-confirms the AFT permission prompt — no pop-up. The token is still minted normally; you just aren't asked. Independent of the recipient's policy below.",
                    control: rsx! {
                        Toggle {
                            on: auto_accept_verified,
                            ontoggle: on_auto_accept_verified,
                        }
                    },
                }
                if !decisions.is_empty() {
                    div { style: "padding: 12px 16px 4px; border-top: 1px solid var(--line2);",
                        div { style: "font-size: 11.5px; color: var(--ink3); margin-bottom: 8px;",
                            "Saved per-recipient decisions"
                        }
                        for (fp, decision) in decisions.iter() {
                            {
                                let fp_clone = fp.clone();
                                let on_rm = on_remove_decision.clone();
                                let decision_label = match decision {
                                    PermissionDecision::Accept => "always accept",
                                    PermissionDecision::Deny => "always deny",
                                };
                                let decision_color = match decision {
                                    PermissionDecision::Accept => "var(--green, #22c55e)",
                                    PermissionDecision::Deny => "var(--red, #ef4444)",
                                };
                                rsx! {
                                    div {
                                        key: "{fp_clone}",
                                        style: "display: flex; align-items: center; gap: 8px; padding: 4px 0;",
                                        span {
                                            style: "font-family: 'Geist Mono', monospace; font-size: 11px; color: var(--ink2); flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;",
                                            "{fp_clone}"
                                        }
                                        span {
                                            style: "font-size: 11px; color: {decision_color}; font-weight: 500; white-space: nowrap;",
                                            "{decision_label}"
                                        }
                                        button {
                                            class: "fm-btn-secondary",
                                            style: "height: 22px; padding: 0 7px; font-size: 11px;",
                                            onclick: move |_| on_rm(fp_clone.clone()),
                                            "Remove"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                // "Add decision" form — only shown when at least one contact
                // exists that doesn't already have a saved decision.
                if !picker_contacts.is_empty() {
                    div {
                        style: "padding: 12px 16px 8px; border-top: 1px solid var(--line2);",
                        "data-testid": "fm-aft-add-decision",
                        div {
                            style: "font-size: 11.5px; color: var(--ink3); margin-bottom: 8px;",
                            "Add per-recipient decision"
                        }
                        div { style: "display: flex; align-items: center; gap: 8px; flex-wrap: wrap;",
                            select {
                                class: "fm-select",
                                "data-testid": "fm-aft-add-decision-contact",
                                value: "{add_fp.read()}",
                                onchange: move |ev| add_fp.set(ev.value()),
                                option { value: "", disabled: true, selected: add_fp.read().is_empty(), "— choose contact —" }
                                for (alias, fp) in picker_contacts.iter() {
                                    {
                                        let fp_clone = fp.clone();
                                        rsx! {
                                            option {
                                                key: "{fp_clone}",
                                                value: "{fp_clone}",
                                                "{alias}"
                                            }
                                        }
                                    }
                                }
                            }
                            // Accept / Deny radio group
                            label {
                                style: "display: flex; align-items: center; gap: 4px; font-size: 12px; cursor: pointer;",
                                input {
                                    r#type: "radio",
                                    name: "add-decision-choice",
                                    "data-testid": "fm-aft-add-decision-accept",
                                    checked: *add_accept.read(),
                                    onchange: move |_| add_accept.set(true),
                                }
                                "Accept"
                            }
                            label {
                                style: "display: flex; align-items: center; gap: 4px; font-size: 12px; cursor: pointer;",
                                input {
                                    r#type: "radio",
                                    name: "add-decision-choice",
                                    "data-testid": "fm-aft-add-decision-deny",
                                    checked: !*add_accept.read(),
                                    onchange: move |_| add_accept.set(false),
                                }
                                "Deny"
                            }
                            button {
                                class: "fm-btn-primary",
                                style: "height: 28px; padding: 0 12px; font-size: 12px;",
                                "data-testid": "fm-aft-add-decision-save",
                                r#type: "button",
                                disabled: add_fp.read().is_empty(),
                                onclick: on_add_decision,
                                "Save"
                            }
                        }
                    }
                }
            }
            Card {
                title: "Your inbox policy: let verified senders skip tokens",
                sub: "This is a RECIPIENT-side policy. It tells the network that your inbox will accept messages from senders you have verified WITHOUT requiring an AFT token. When on, your client publishes the list of contacts you have marked verified to your inbox contract; their clients (if they have observed your inbox settings) will skip minting a token when sending to you. Trade the spam shield for convenience with trusted contacts. Use with care: a compromised verified contact can send unlimited messages to your inbox.",
                SettingRow {
                    label: "Accept verified senders without tokens",
                    help: "Recipient-side. Toggling this here does NOT affect whether tokens are minted when you send mail to others — that depends on the recipient's policy, which their client publishes the same way. To stop pop-ups when YOU send, see the “When sending” card above.",
                    control: rsx! {
                        div {
                            "data-testid": crate::testid::FM_AFT_VERIFIED_SKIP_TOGGLE,
                            "data-state": if allow_verified_skip_token { "on" } else { "off" },
                            Toggle {
                                on: allow_verified_skip_token,
                                ontoggle: on_verified_bypass,
                            }
                        }
                    },
                }
            }
        }
    }
}

#[allow(non_snake_case)]
fn ScrInbox() -> Element {
    let g = use_global_settings();
    let drafts_in_inbox = g.inbox.drafts_in_inbox;
    let quarantine_unknown = g.inbox.quarantine_unknown;
    // #270: how a collapsed conversation expands in the detail pane.
    let thread_view_value = match g.inbox.thread_view {
        ThreadView::Nested => "nested",
        ThreadView::Compact => "compact",
    };

    // #270: thread-view picker follows the FontSize <select> pattern from
    // ScrAppearance — onchange maps the string value back to the enum and
    // persists the whole GlobalSettings snapshot. Clone before the toggle
    // builder moves `g`.
    let g_thread_view = g.clone();
    let mk_global_toggle = move |mutate: fn(&mut InboxSettings)| {
        let g = g.clone();
        move |_| {
            let mut next = g.clone();
            mutate(&mut next.inbox);
            local_state::persist_global_settings(next);
        }
    };
    let on_drafts_in_inbox = mk_global_toggle(|i| i.drafts_in_inbox = !i.drafts_in_inbox);
    let on_quarantine = mk_global_toggle(|i| i.quarantine_unknown = !i.quarantine_unknown);
    let on_thread_view = move |ev: Event<FormData>| {
        let mut next = g_thread_view.clone();
        next.inbox.thread_view = match ev.value().as_str() {
            "compact" => ThreadView::Compact,
            _ => ThreadView::Nested,
        };
        local_state::persist_global_settings(next);
    };
    rsx! {
        div { class: "fm-set-inner",
            p { class: "fm-set-lede", "How messages move through this inbox." }
            Card { title: "Folders",
                SettingRow {
                    label: "Show drafts in Inbox",
                    help: "Off: drafts stay in Drafts only. On: surface them in Inbox above the unread band.",
                    control: rsx! { Toggle { on: drafts_in_inbox, ontoggle: on_drafts_in_inbox } },
                }
            }
            Card { title: "Conversations",
                SettingRow {
                    label: "Thread view",
                    help: "Nested: indent replies under their parent. Compact: a tight, scannable list.",
                    control: rsx! {
                        select {
                            class: "fm-select",
                            "data-testid": testid::FM_THREAD_VIEW_SELECT,
                            value: "{thread_view_value}",
                            onchange: on_thread_view,
                            option { value: "nested", "nested" }
                            option { value: "compact", "compact" }
                        }
                    },
                }
            }
            Card {
                title: "Quarantine",
                sub: "Where messages with verification problems land.",
                SettingRow {
                    label: "Hold messages with unknown keys",
                    help: "Land them in Quarantine instead of Inbox. You'll see a count badge.",
                    control: rsx! { Toggle { on: quarantine_unknown, ontoggle: on_quarantine } },
                }
            }
        }
    }
}

#[allow(non_snake_case)]
fn ScrContacts() -> Element {
    // Subscribe to address-book generation so additions *and* removals
    // (dispatched via NodeAction::DeleteContact) both trigger a re-render.
    let ab_gen = use_context::<crate::app::AddressBookGen>();
    let mut search = use_signal(String::new);

    let mut import_contact_form = use_context::<Signal<crate::app::login::ImportContact>>();
    let mut share_contact_form = use_context::<Signal<crate::app::login::ShareContact>>();
    let mut share_pending = use_context::<Signal<crate::app::login::SharePending>>();
    let user = use_context::<Signal<User>>();
    let actions = use_coroutine_handle::<crate::app::NodeAction>();

    let on_import = move |_| {
        // Leave Settings open underneath — the modal renders inside
        // div.fm-app (app.rs) and is now styled in that scope, so it
        // overlays the Contacts panel instead of dropping to the inbox.
        *import_contact_form.write() = crate::app::login::ImportContact::opened();
    };
    let on_share = move |_| {
        let Some(active) = user.read().logged_id().cloned() else {
            return;
        };
        let card = address_book::ContactCard::from_identity(&active);
        let fp =
            address_book::fingerprint_words(&active.ml_dsa_vk_bytes(), &active.ml_kem_ek_bytes())
                .join("-");
        let share_text = format!("{}\nverify: {}", card.encode(), fp);
        share_pending.set(crate::app::login::SharePending {
            data: Some(crate::app::login::SharePendingData {
                alias: active.alias.to_string(),
                share_text,
            }),
        });
        share_contact_form.write().0 = true;
    };

    let needle = search.read().to_lowercase();
    let _ = ab_gen.0.read(); // re-run when a contact is added or removed.
    let contacts: Vec<address_book::Contact> = address_book::all_contacts()
        .into_iter()
        .filter(|c| {
            if needle.is_empty() {
                return true;
            }
            c.local_alias.to_lowercase().contains(&needle)
                || c.fingerprint_short().to_lowercase().contains(&needle)
                || c.description.to_lowercase().contains(&needle)
        })
        .collect();

    rsx! {
        div { class: "fm-set-inner",
            p { class: "fm-set-lede",
                "Your address book. Imported via contact cards or share links; identified by their post-quantum fingerprint."
            }
            Card {
                div { style: "display: flex; align-items: center; gap: 8px; padding: 12px 16px; border-bottom: 1px solid var(--line2);",
                    input {
                        class: "fm-input",
                        placeholder: "Search contacts, fingerprints…",
                        style: "flex: 1",
                        value: "{search.read()}",
                        oninput: move |ev| search.set(ev.value()),
                    }
                    button {
                        class: "fm-btn-secondary",
                        "data-testid": crate::testid::FM_CONTACTS_IMPORT_BTN,
                        onclick: on_import,
                        "Import…"
                    }
                    button {
                        class: "fm-btn-primary",
                        "data-testid": crate::testid::FM_CONTACTS_SHARE_BTN,
                        onclick: on_share,
                        "Share my card"
                    }
                }
                div { class: "fm-contact-list",
                    if contacts.is_empty() {
                        div { style: "padding: 24px 16px; color: var(--ink3); text-align: center;",
                            if needle.is_empty() {
                                "No contacts yet. Use Import… to paste a contact card."
                            } else {
                                "No contacts match this search."
                            }
                        }
                    }
                    for c in contacts.iter() {
                        {
                            let alias = c.local_alias.clone();
                            let initial = alias
                                .chars()
                                .next()
                                .map(|ch| ch.to_string())
                                .unwrap_or_else(|| "·".into());
                            let fp_short = c.fingerprint_short();
                            let fp_full = c.fingerprint_full();
                            let trust_class = if c.verified { "known" } else { "unknown" };
                            let trust_label = if c.verified { "verified" } else { "imported" };
                            let label = c.description.clone();
                            let alias_for_remove: String = alias.to_string();
                            rsx! {
                                div { key: "{alias}", class: "fm-contact-row",
                                    span { class: "fm-contact-av", "{initial}" }
                                    span { class: "fm-contact-name",
                                        span { class: "alias", "{alias}" }
                                        span { class: "fp", title: "{fp_full}", "{fp_short}" }
                                        if !label.is_empty() {
                                            span {
                                                style: "font-style: italic; color: var(--ink3); font-size: 11.5px; margin-left: 8px;",
                                                "· {label}"
                                            }
                                        }
                                    }
                                    span { class: "fm-contact-trust {trust_class}", "{trust_label}" }
                                    button {
                                        class: "fm-btn-secondary",
                                        style: "height: 26px; padding: 0 9px; font-size: 11px;",
                                        onclick: move |_| {
                                            actions.send(crate::app::NodeAction::DeleteContact {
                                                alias: alias_for_remove.clone(),
                                            });
                                        },
                                        "Remove"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[allow(non_snake_case)]
fn ScrAppearance() -> Element {
    let g = use_global_settings();
    let serif_subjects = g.appearance.serif_subjects;
    let theme_value = match g.appearance.theme {
        Theme::System => "auto",
        Theme::Light => "light",
        Theme::Dark => "dark",
    };
    let density_value = match g.appearance.density {
        Density::Comfortable => "comfortable",
        Density::Compact => "compact",
    };
    let font_size_value = match g.appearance.font_size {
        FontSize::Small => "small",
        FontSize::Default => "default",
        FontSize::Large => "large",
        FontSize::Larger => "larger",
    };

    let g_theme = g.clone();
    let on_theme = move |ev: Event<FormData>| {
        let mut next = g_theme.clone();
        next.appearance.theme = match ev.value().as_str() {
            "light" => Theme::Light,
            "dark" => Theme::Dark,
            _ => Theme::System,
        };
        local_state::persist_global_settings(next);
    };
    let g_density = g.clone();
    let on_density = move |ev: Event<FormData>| {
        let mut next = g_density.clone();
        next.appearance.density = match ev.value().as_str() {
            "compact" => Density::Compact,
            _ => Density::Comfortable,
        };
        local_state::persist_global_settings(next);
    };
    let g_serif = g.clone();
    let on_serif = move |_| {
        let mut next = g_serif.clone();
        next.appearance.serif_subjects = !next.appearance.serif_subjects;
        local_state::persist_global_settings(next);
    };
    let g_font_size = g.clone();
    let on_font_size = move |ev: Event<FormData>| {
        let mut next = g_font_size.clone();
        next.appearance.font_size = match ev.value().as_str() {
            "small" => FontSize::Small,
            "large" => FontSize::Large,
            "larger" => FontSize::Larger,
            _ => FontSize::Default,
        };
        local_state::persist_global_settings(next);
    };
    rsx! {
        div { class: "fm-set-inner",
            p { class: "fm-set-lede", "Visual settings shared across every identity on this device." }
            Card { title: "Theme",
                SettingRow {
                    label: "Color theme",
                    help: "Dark theme matches the system; nothing is themed per identity.",
                    control: rsx! {
                        select {
                            class: "fm-select",
                            value: "{theme_value}",
                            onchange: on_theme,
                            option { value: "auto", "auto" }
                            option { value: "light", "light" }
                            option { value: "dark", "dark" }
                        }
                    },
                }
                SettingRow {
                    label: "Density",
                    help: "Affects row height and padding throughout the mailbox.",
                    control: rsx! {
                        select {
                            class: "fm-select",
                            value: "{density_value}",
                            onchange: on_density,
                            option { value: "compact", "compact" }
                            option { value: "comfortable", "comfortable" }
                        }
                    },
                }
                SettingRow {
                    label: "Font size",
                    help: "Scales every text element uniformly. Use Large/Larger for high-DPI screens or low vision.",
                    control: rsx! {
                        select {
                            class: "fm-select",
                            value: "{font_size_value}",
                            onchange: on_font_size,
                            option { value: "small", "small" }
                            option { value: "default", "default" }
                            option { value: "large", "large" }
                            option { value: "larger", "larger" }
                        }
                    },
                }
                SettingRow {
                    label: "Subjects in serif",
                    help: "Off: subjects render in DM Sans like the rest of the UI.",
                    control: rsx! { Toggle { on: serif_subjects, ontoggle: on_serif } },
                }
            }
        }
    }
}

/// Read the WebSocket host the UI is currently talking to. The page is
/// served from the same origin as the gateway (see `ui/src/api.rs`), so
/// `window.location.host` is the live answer. Falls back to "—" off-WASM
/// or if the call errors.
fn current_ws_host() -> String {
    #[cfg(target_family = "wasm")]
    {
        if let Some(window) = web_sys::window()
            && let Ok(host) = window.location().host()
        {
            return host;
        }
    }
    "—".to_string()
}

#[allow(non_snake_case)]
fn ScrAdvanced() -> Element {
    let g = use_global_settings();
    let custom_relay = g.advanced.custom_relay;
    let custom_relay_url = g.advanced.custom_relay_url.clone();

    let g_toggle = g.clone();
    let on_custom_relay = move |_| {
        let mut next = g_toggle.clone();
        next.advanced.custom_relay = !next.advanced.custom_relay;
        local_state::persist_global_settings(next);
    };
    let g_url = g.clone();
    let on_custom_relay_url = move |ev: Event<FormData>| {
        let mut next = g_url.clone();
        next.advanced.custom_relay_url = ev.value();
        local_state::persist_global_settings(next);
    };

    let host = current_ws_host();

    rsx! {
        div { class: "fm-set-inner",
            p { class: "fm-set-lede",
                "Network plumbing. Most users will never come here."
            }
            Card { title: "Node connection",
                SettingRow {
                    label: "Page origin",
                    help: "The host this UI was served from. The default WebSocket connects back to the same origin so the gateway's same-origin check passes.",
                    control: rsx! {
                        span { style: "font-family: 'Geist Mono', monospace; font-size: 11.5px; color: var(--ink2);", "{host}" }
                    },
                }
                SettingRow {
                    label: "Use custom relay",
                    help: "Override the default WebSocket URL. Takes effect on next reload.",
                    control: rsx! { Toggle { on: custom_relay, ontoggle: on_custom_relay } },
                }
                if custom_relay {
                    SettingRow {
                        label: "Relay URL",
                        help: "Full ws:// or wss:// URL of a Freenet gateway. Empty falls back to the page origin.",
                        control: rsx! {
                            input {
                                class: "fm-input",
                                style: "width: 320px",
                                placeholder: "ws://127.0.0.1:7510",
                                value: "{custom_relay_url}",
                                oninput: on_custom_relay_url,
                            }
                        },
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefs_default() -> IdentityAftPrefs {
        IdentityAftPrefs::default()
    }

    const FP: &str = "abandon-ability-able-about-above-absent";

    /// No saved decision + auto-accept OFF → `None` (show modal).
    #[test]
    fn no_policy_returns_none() {
        let prefs = prefs_default();
        assert_eq!(resolve_permission_decision(&prefs, FP, false), None,);
    }

    /// Saved Accept decision → always `Some(Accept)`, even if not verified.
    #[test]
    fn saved_accept_overrides_everything() {
        let mut prefs = prefs_default();
        prefs
            .permission_decisions
            .insert(FP.to_string(), PermissionDecision::Accept);
        assert_eq!(
            resolve_permission_decision(&prefs, FP, false),
            Some(PermissionDecision::Accept),
        );
        // Even when auto-accept-verified is off.
        assert_eq!(
            resolve_permission_decision(&prefs, FP, true),
            Some(PermissionDecision::Accept),
        );
    }

    /// Saved Deny decision → `Some(Deny)`, even for a verified contact.
    #[test]
    fn saved_deny_overrides_auto_accept_verified() {
        let mut prefs = prefs_default();
        prefs.auto_accept_verified_contacts = true;
        prefs
            .permission_decisions
            .insert(FP.to_string(), PermissionDecision::Deny);
        assert_eq!(
            resolve_permission_decision(&prefs, FP, true),
            Some(PermissionDecision::Deny),
        );
    }

    /// `auto_accept_verified_contacts` ON + verified → `Some(Accept)`.
    #[test]
    fn auto_accept_verified_returns_accept_for_verified() {
        let mut prefs = prefs_default();
        prefs.auto_accept_verified_contacts = true;
        assert_eq!(
            resolve_permission_decision(&prefs, FP, true),
            Some(PermissionDecision::Accept),
        );
    }

    /// `auto_accept_verified_contacts` ON + NOT verified → `None` (show modal).
    #[test]
    fn auto_accept_verified_returns_none_for_unverified() {
        let mut prefs = prefs_default();
        prefs.auto_accept_verified_contacts = true;
        assert_eq!(resolve_permission_decision(&prefs, FP, false), None,);
    }

    /// Saved decision takes priority over `auto_accept_verified_contacts`.
    #[test]
    fn saved_decision_has_priority_over_auto_accept() {
        let mut prefs = prefs_default();
        prefs.auto_accept_verified_contacts = true;
        prefs
            .permission_decisions
            .insert(FP.to_string(), PermissionDecision::Deny);
        // Saved Deny wins even though auto-accept is on and contact is verified.
        assert_eq!(
            resolve_permission_decision(&prefs, FP, true),
            Some(PermissionDecision::Deny),
        );
    }

    /// Missing fingerprint in the decisions map still falls through to
    /// `auto_accept_verified_contacts` logic.
    #[test]
    fn unknown_fingerprint_falls_through_to_auto_accept_policy() {
        let mut prefs = prefs_default();
        prefs.auto_accept_verified_contacts = true;
        prefs
            .permission_decisions
            .insert("other-fp".to_string(), PermissionDecision::Deny);
        // FP is not in the map → check auto_accept_verified.
        assert_eq!(
            resolve_permission_decision(&prefs, FP, true),
            Some(PermissionDecision::Accept),
        );
    }

    /// Write-path: `local_set_identity_settings` persists a new
    /// `PermissionDecision` entry and `identity_settings_for` reads it
    /// back. This covers the production write path exercised by the
    /// Settings → AFT "Add decision" Save button (#159).
    #[test]
    fn permission_decision_write_path_persists_and_reads_back() {
        use crate::local_state;
        use mail_local_state::{IdentitySettings, LocalState};

        // Seed a clean snapshot so the test is isolated.
        let mut state = LocalState::default();
        let alias = "alice";
        state
            .aliases_mut()
            .entry(alias.to_string())
            .or_default()
            .settings = IdentitySettings::default();
        local_state::replace_snapshot(state);

        // Simulate the Save-button handler: read current settings, insert
        // the decision, then persist via `local_set_identity_settings`.
        let mut settings = local_state::identity_settings_for(alias);
        assert!(
            settings.aft.permission_decisions.is_empty(),
            "no decisions yet"
        );
        settings
            .aft
            .permission_decisions
            .insert(FP.to_string(), PermissionDecision::Accept);
        local_state::local_set_identity_settings(alias, settings);

        // Read back via the same path the permission pump uses.
        let read_back = local_state::identity_settings_for(alias);
        assert_eq!(
            read_back.aft.permission_decisions.get(FP),
            Some(&PermissionDecision::Accept),
            "persisted Accept decision must round-trip through SNAPSHOT"
        );

        // Inserting Deny for a second fingerprint must not disturb the first.
        let fp2 = "balance-better-bitter-black-blame-blind";
        let mut settings2 = local_state::identity_settings_for(alias);
        settings2
            .aft
            .permission_decisions
            .insert(fp2.to_string(), PermissionDecision::Deny);
        local_state::local_set_identity_settings(alias, settings2);

        let read_back2 = local_state::identity_settings_for(alias);
        assert_eq!(
            read_back2.aft.permission_decisions.get(FP),
            Some(&PermissionDecision::Accept),
            "first decision must survive second insert"
        );
        assert_eq!(
            read_back2.aft.permission_decisions.get(fp2),
            Some(&PermissionDecision::Deny),
            "second decision must be persisted"
        );
    }

    /// Remove-path: removing a saved decision from the map and persisting
    /// must make it disappear from `identity_settings_for`. Covers the
    /// "Revoke" button handler (#159).
    #[test]
    fn permission_decision_remove_path_clears_entry() {
        use crate::local_state;
        use mail_local_state::{IdentitySettings, LocalState};

        let mut state = LocalState::default();
        let alias = "bob";
        let mut base = IdentitySettings::default();
        base.aft
            .permission_decisions
            .insert(FP.to_string(), PermissionDecision::Deny);
        state
            .aliases_mut()
            .entry(alias.to_string())
            .or_default()
            .settings = base;
        local_state::replace_snapshot(state);

        // Verify it's there before removal.
        let before = local_state::identity_settings_for(alias);
        assert_eq!(
            before.aft.permission_decisions.get(FP),
            Some(&PermissionDecision::Deny),
            "precondition: Deny must be present before removal"
        );

        // Simulate the Remove button handler.
        let mut settings = local_state::identity_settings_for(alias);
        settings.aft.permission_decisions.remove(FP);
        local_state::local_set_identity_settings(alias, settings);

        let after = local_state::identity_settings_for(alias);
        assert!(
            !after.aft.permission_decisions.contains_key(FP),
            "removed decision must not appear in SNAPSHOT"
        );
    }
}
