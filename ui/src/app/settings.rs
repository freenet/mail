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
use mail_local_state::{
    Density, GlobalSettings, IdentityPrivacyPrefs, IdentitySettings, InboxSettings, Theme,
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
    let display_name = ident.display_name.clone();
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

    let alias_key_dn = alias_key.clone();
    let ident_dn = ident.clone();
    let on_display_name = move |ev: Event<FormData>| {
        let mut next = ident_dn.clone();
        next.display_name = ev.value();
        local_state::persist_identity_settings(alias_key_dn.clone(), next);
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
        let fname = format!("freenet-identity-{}.json", &*active.alias);
        crate::app::login::trigger_browser_download(&fname, &json);
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
                    label: "Display name",
                    help: "Shown next to your alias in recipients' inboxes. Plain text, no verification.",
                    control: rsx! {
                        input {
                            class: "fm-input",
                            value: "{display_name}",
                            style: "width: 180px",
                            oninput: on_display_name,
                        }
                    },
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
    let pad_length = priv_now.pad_length;
    let read_receipts = priv_now.read_receipts;

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
    let on_pad = mk_toggle(|p| p.pad_length = !p.pad_length);
    let on_receipts = mk_toggle(|p| p.read_receipts = !p.read_receipts);
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
                    help: "Move messages with no ML-DSA signature directly to a quarantine folder.",
                    control: rsx! { Toggle { on: hide_unsigned, ontoggle: on_hide_unsigned } },
                }
            }
            Card {
                title: "Linkability",
                sub: "Information that reveals patterns across your identities.",
                SettingRow {
                    label: "Share read receipts",
                    help: "Senders see when you opened the message. Off by default; off is the unlinkable option.",
                    control: rsx! { Toggle { on: read_receipts, ontoggle: on_receipts } },
                }
                SettingRow {
                    label: "Pad message length",
                    help: "Round ciphertext size to fixed buckets so observers can't infer content size. Adds ~5% bandwidth.",
                    control: rsx! { Toggle { on: pad_length, ontoggle: on_pad } },
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

#[allow(non_snake_case)]
fn ScrAft() -> Element {
    let (alias_key, ident) = use_identity_settings();
    let aft_now = ident.aft.clone();
    let selected_tier = aft_now.required_tier.clone();
    let max_age_days = aft_now.max_age_days;
    let allow_known = aft_now.allow_known;
    let allow_anon = aft_now.allow_anon;
    let bounce = aft_now.bounce_message.clone();
    let actions = use_coroutine_handle::<crate::app::NodeAction>();

    // #85: dispatch a `ModifySettings` delta to the inbox contract so
    // the new policy actually gates incoming sends — without this the
    // change is local-state-only and senders keep minting at the old
    // tier.
    let push_policy = move |alias: &str, tier_str: &str, max_age_days: u64| {
        let identity = crate::app::address_book::lookup(alias)
            .filter(|r| r.is_own)
            .and_then(|_| {
                crate::app::login::Identity::get_aliases()
                    .borrow()
                    .iter()
                    .find(|i| i.alias.as_ref() == alias)
                    .cloned()
            });
        let Some(identity) = identity else {
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
    let alias_key_k = alias_key.clone();
    let ident_k = ident.clone();
    let on_allow_known = move |_| {
        let mut next = ident_k.clone();
        next.aft.allow_known = !next.aft.allow_known;
        local_state::persist_identity_settings(alias_key_k.clone(), next);
    };
    let alias_key_a = alias_key.clone();
    let ident_a = ident.clone();
    let on_allow_anon = move |_| {
        let mut next = ident_a.clone();
        next.aft.allow_anon = !next.aft.allow_anon;
        local_state::persist_identity_settings(alias_key_a.clone(), next);
    };
    let alias_key_b = alias_key.clone();
    let ident_b = ident.clone();
    let on_bounce = move |ev: Event<FormData>| {
        let mut next = ident_b.clone();
        next.aft.bounce_message = ev.value();
        local_state::persist_identity_settings(alias_key_b.clone(), next);
    };

    rsx! {
        div { class: "fm-set-inner",
            p { class: "fm-set-lede",
                "Anti-Flood Tokens rate-limit the network without a server. Recipients require senders to hold a token of at least the recipient's chosen tier. Pick the floor your inbox accepts."
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
                title: "Token max age (days)",
                sub: "Sender's AFT delegate uses this when picking a free slot. Capped at 730 days by the AFT crate; lower values rotate the cap faster.",
                div { class: "field",
                    input {
                        class: "input",
                        r#type: "number",
                        min: "1",
                        max: "730",
                        value: "{max_age_days}",
                        onchange: on_max_age,
                    }
                }
            }
            Card {
                title: "Trust overrides",
                SettingRow {
                    label: "Allow lower tiers from known contacts",
                    help: "People in your address book bypass the tier floor.",
                    control: rsx! { Toggle { on: allow_known, ontoggle: on_allow_known } },
                }
                SettingRow {
                    label: "Allow no-tier (anonymous)",
                    help: "Off by default. Recommended only for public dropboxes.",
                    control: rsx! { Toggle { on: allow_anon, ontoggle: on_allow_anon } },
                }
                SettingRow {
                    label: "Bounce message",
                    help: "Returned to senders below your floor. They see this; you don't.",
                    stacked: true,
                    control: rsx! {
                        textarea {
                            class: "fm-textarea",
                            value: "{bounce}",
                            oninput: on_bounce,
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
    // Subscribe to address-book changes. The address book bumps an internal
    // generation when contacts are added / removed; treat the trash button
    // as an explicit re-render trigger.
    let mut tick = use_signal(|| 0u32);
    let mut search = use_signal(String::new);

    let mut menu_selection = use_context::<Signal<menu::MenuSelection>>();
    let mut import_contact_form = use_context::<Signal<crate::app::login::ImportContact>>();
    let mut share_contact_form = use_context::<Signal<crate::app::login::ShareContact>>();
    let mut share_pending = use_context::<Signal<crate::app::login::SharePending>>();
    let user = use_context::<Signal<User>>();

    let on_import = move |_| {
        menu_selection.write().close_settings();
        import_contact_form.write().0 = true;
    };
    let on_share = move |_| {
        let Some(active) = user.read().logged_id().cloned() else {
            return;
        };
        let card = address_book::ContactCard::from_identity(&active);
        let fp = card.fingerprint().join("-");
        let share_text = format!("verify: {}\n{}", fp, card.encode());
        share_pending.set(crate::app::login::SharePending {
            data: Some(crate::app::login::SharePendingData {
                alias: active.alias.to_string(),
                share_text,
            }),
        });
        menu_selection.write().close_settings();
        share_contact_form.write().0 = true;
    };

    let needle = search.read().to_lowercase();
    let _ = tick.read(); // re-run the memo when `tick` bumps.
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
                        onclick: on_import,
                        "Import…"
                    }
                    button {
                        class: "fm-btn-primary",
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
                                            address_book::remove_contact(&alias_for_remove);
                                            let prev = *tick.read();
                                            tick.set(prev + 1);
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
