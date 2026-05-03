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

use std::sync::atomic::Ordering;

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
        let _gen = local_state::GENERATION.load(Ordering::Relaxed);
        local_state::identity_settings_for(&alias_for_memo)
    });
    (alias, settings())
}

fn use_global_settings() -> GlobalSettings {
    let settings = use_memo(move || {
        let _gen = local_state::GENERATION.load(Ordering::Relaxed);
        local_state::global_settings()
    });
    settings()
}

#[allow(non_snake_case)]
pub(crate) fn SettingsShell() -> Element {
    let mut menu_selection = use_context::<Signal<menu::MenuSelection>>();
    let user = use_context::<Signal<User>>();

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
    let _fp_short = format!(
        "{} · {} · {}",
        fp_short_segs[0], fp_short_segs[1], fp_short_segs[2]
    );

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
                div { class: "fm-set-ident",
                    span { class: "fm-set-ident-av", "{initial}" }
                    div { class: "fm-set-ident-text",
                        span { class: "fm-set-ident-name", "{alias}" }
                        span { class: "fm-set-ident-meta", "{fp_short_segs[0]} · {fp_short_segs[1]}…" }
                    }
                    span { class: "fm-set-ident-caret", "▾" }
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

    let groups: &[(&str, &[(menu::SettingsScreen, &str)])] = &[
        (
            "GLOBAL",
            &[
                (menu::SettingsScreen::Appearance, "◐ Appearance"),
                (menu::SettingsScreen::Advanced, "≡ Advanced & Diagnostics"),
            ],
        ),
        (
            "IDENTITY",
            &[
                (menu::SettingsScreen::Account, "◉ Account & profile"),
                (menu::SettingsScreen::Privacy, "▣ Privacy & security"),
                (menu::SettingsScreen::Aft, "▶ Anti-Flood (AFT)"),
                (menu::SettingsScreen::Inbox, "◌ Inbox & folders"),
                (menu::SettingsScreen::Contacts, "· Contacts"),
            ],
        ),
    ];

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
    // Backups not yet wired — treat every identity as un-backed-up so the
    // amber banner shows. Real value will read from a per-identity local
    // record once #51 lands.
    let backed_up = false;

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
                        button { class: "fm-btn-primary", "Back up now" }
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
                            span { class: "fm-key-card-tag", "verified" }
                        }
                        div { style: "display: flex; gap: 14px; align-items: center;",
                            FpGrid { seed: vk_seed.clone() }
                            div { class: "fm-key-card-fp", "{fp_short}" }
                        }
                        div { class: "fm-key-card-foot",
                            div { class: "fm-key-meta-list",
                                span { "rotates ", span { class: "v", "never" } }
                            }
                            div { class: "fm-key-actions",
                                button { class: "fm-btn-secondary", "Show full key" }
                                button { class: "fm-btn-secondary", "Copy" }
                            }
                        }
                    }
                    div { class: "fm-key-card",
                        div { class: "fm-key-card-head",
                            span { class: "fm-key-card-name", "ML-KEM-768 · encryption" }
                            span { class: "fm-key-card-tag", "verified" }
                        }
                        div { style: "display: flex; gap: 14px; align-items: center;",
                            FpGrid { seed: format!("{vk_seed}-kem") }
                            div { class: "fm-key-card-fp", "{fp_kem_short}" }
                        }
                        div { class: "fm-key-card-foot",
                            div { class: "fm-key-meta-list",
                                span { "rotates ", span { class: "v", "on demand" } }
                            }
                            div { class: "fm-key-actions",
                                button { class: "fm-btn-secondary", "Show full key" }
                                button { class: "fm-btn-secondary", "Rotate" }
                            }
                        }
                    }
                }
                div { class: "fm-sub-row",
                    span { class: "label", "Fingerprint" }
                    span { class: "v", "{fp_short}" }
                    button { class: "fm-btn-secondary", "Show QR" }
                }
            }
            Card {
                title: "Backup & restore",
                sub: "Backups are an encrypted bundle of both keys. There's no server-side recovery; lose this and the alias is gone.",
                SettingRow {
                    label: "Last backup",
                    help: "No backup on record. Export one before relying on this identity.",
                    control: rsx! { button { class: "fm-btn-primary", "Back up now" } },
                }
                SettingRow {
                    label: "Restore from backup",
                    help: "Replaces the active identity's keys. The current keys will be unrecoverable after this.",
                    control: rsx! { button { class: "fm-btn-secondary", "Restore…" } },
                }
            }
            Card {
                title: "Danger zone",
                SettingRow {
                    label: "Delete this identity",
                    help: "Wipes the keypair from this browser. There is no recovery. If you have a backup, you can restore it elsewhere.",
                    control: rsx! { button { class: "fm-btn-danger", "Delete identity…" } },
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
                SettingRow {
                    label: "Auto-accept new keys",
                    help: "When does a sender's key get pinned as 'known' without an explicit verify?",
                    control: rsx! {
                        select { class: "fm-select",
                            option { value: "never", "Never (manual only)" }
                            option { value: "known", selected: true, "Only from known senders" }
                            option { value: "any", "On first message" }
                        }
                    },
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
            Card {
                title: "Identity delegate",
                sub: "The contract that resolves your alias to keys.",
                SettingRow {
                    label: "Delegate",
                    help: "identity-management/8c4a… · refreshed 4 min ago",
                    control: rsx! { button { class: "fm-btn-secondary", "Refresh" } },
                }
            }
        }
    }
}

#[allow(non_snake_case)]
fn ScrAft() -> Element {
    let used: u32 = 47;
    let cap: u32 = 365;
    let pct = used as f32 / cap as f32;
    let fill_class = if pct > 0.8 {
        "fm-quota-fill warn"
    } else {
        "fm-quota-fill"
    };
    let pct_pct = (pct * 100.0).round() as u32;

    let history: [(&str, f32); 7] = [
        ("MON", 0.18),
        ("TUE", 0.45),
        ("WED", 0.31),
        ("THU", 0.62),
        ("FRI", 0.92),
        ("SAT", 0.08),
        ("SUN", 0.13),
    ];

    let tiers: [(&str, &str, &str, &str); 4] = [
        ("Min1", "3", "/ day", "Lowest tier. Casual identities."),
        ("Min2", "30", "/ day", "Default. Most users sit here."),
        ("Mid1", "365", "/ day", "Heavy use. Mailing lists, devs."),
        ("Mid2", "10K", "/ day", "Power tier. Requires reputation."),
    ];

    let (alias_key, ident) = use_identity_settings();
    let aft_now = ident.aft.clone();
    let selected_tier = aft_now.required_tier.clone();
    let allow_known = aft_now.allow_known;
    let allow_anon = aft_now.allow_anon;
    let bounce = aft_now.bounce_message.clone();

    let alias_key_t = alias_key.clone();
    let ident_t = ident.clone();
    let on_tier = move |new_tier: String| {
        let mut next = ident_t.clone();
        next.aft.required_tier = new_tier;
        local_state::persist_identity_settings(alias_key_t.clone(), next);
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
    // Silence unused-variable warnings when only one of the two refs is read.
    let _ = (&aft_now, &alias_key);

    rsx! {
        div { class: "fm-set-inner",
            p { class: "fm-set-lede",
                "Anti-Flood Tokens rate-limit the network without a server. Recipients require senders to hold a token of at least the recipient's chosen tier. You set both: what you require, and what you carry."
            }
            Card {
                title: "Today's quota",
                sub: "Tokens you've used to send. Resets at local midnight.",
                div { class: "fm-quota",
                    div { class: "fm-quota-head",
                        div {
                            div { class: "fm-quota-num",
                                "{used} "
                                span { class: "of", "/" }
                                " "
                                span { class: "denom", "{cap}" }
                            }
                            div { class: "fm-quota-label", style: "margin-top: 6px",
                                "Mid1 · 365 / day"
                            }
                        }
                        div { style: "text-align: right",
                            div { class: "fm-quota-label", "resets in" }
                            div { style: "font-family: 'Geist Mono', monospace; font-size: 13px; margin-top: 2px;",
                                "09:28:11"
                            }
                        }
                    }
                    div { class: "fm-quota-bar",
                        div { class: "{fill_class}", style: "width: {pct * 100.0}%" }
                    }
                    div { class: "fm-quota-foot",
                        span { "0" }
                        span { "{pct_pct}% used" }
                        span { "{cap}" }
                    }
                }
                div { class: "fm-spark",
                    for (day, v) in history.iter() {
                        div { key: "{day}", class: "fm-spark-row",
                            span { class: "day", "{day}" }
                            span { class: "fm-spark-track",
                                span { class: "fm-spark-fill", style: "width: {v * 100.0}%" }
                            }
                            span { class: "val", "{(v * cap as f32) as u32}" }
                        }
                    }
                }
                div { class: "fm-sub-row",
                    span { class: "label", "Notify at" }
                    span { class: "v", "80% used (toast) · 95% used (modal)" }
                    span { style: "flex: 1" }
                    button { class: "fm-btn-secondary", "Edit thresholds" }
                }
            }
            Card {
                title: "Your tier",
                sub: "The cap your local node mints against. Higher tiers cost reputation; lower tiers throttle.",
                div { class: "fm-tier-grid",
                    for (id, rate, per, help) in tiers.iter() {
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
                                    style: "all: unset; display: flex; flex-direction: column; gap: 4px; cursor: default; border: 1px solid var(--line); border-radius: 11px; padding: 12px 12px 10px; background: #fff;",
                                    onclick: move |_| on_tier_click(id_str.clone()),
                                    div { class: "fm-tier-name", "{id}" }
                                    div { class: "fm-tier-rate",
                                        "{rate}"
                                        span { class: "unit", " {per}" }
                                    }
                                    div { class: "fm-tier-help", "{help}" }
                                }
                            }
                        }
                    }
                }
            }
            Card {
                title: "Required tier for incoming mail",
                sub: "Senders must hold a token of this tier or higher to land in your inbox. Lower-tier sends bounce.",
                SettingRow {
                    label: "Minimum tier",
                    help: "Tighten this if you're seeing spam. Loosen it if you're being bounced from senders who don't carry your floor.",
                    control: {
                        let on_tier_select = on_tier.clone();
                        let cur = selected_tier.clone();
                        rsx! {
                            select {
                                class: "fm-select",
                                value: "{cur}",
                                onchange: move |ev| on_tier_select(ev.value()),
                                option { value: "Min1", "Min1" }
                                option { value: "Min2", "Min2" }
                                option { value: "Mid1", "Mid1" }
                                option { value: "Mid2", "Mid2" }
                            }
                        }
                    },
                }
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
                    label: "Auto-archive after",
                    help: "Read messages move from Inbox to Archive after this delay. Local rule; doesn't notify the sender.",
                    control: rsx! {
                        select { class: "fm-select",
                            option { value: "never", selected: true, "Never" }
                            option { value: "7d", "7 days" }
                            option { value: "30d", "30 days" }
                            option { value: "90d", "90 days" }
                        }
                    },
                }
                SettingRow {
                    label: "Sent retention",
                    help: "How long to keep sent messages. Sent items also count against your contract storage.",
                    control: rsx! {
                        select { class: "fm-select",
                            option { value: "forever", selected: true, "Forever" }
                            option { value: "1y", "1 year" }
                            option { value: "30d", "30 days" }
                        }
                    },
                }
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
                SettingRow {
                    label: "Auto-delete from Quarantine after",
                    help: "Messages here never count against unread. They burn no token from you on receipt.",
                    control: rsx! {
                        select { class: "fm-select",
                            option { value: "7d", "7 days" }
                            option { value: "14d", selected: true, "14 days" }
                            option { value: "30d", "30 days" }
                            option { value: "never", "Never" }
                        }
                    },
                }
            }
            Card { title: "Compose defaults",
                SettingRow {
                    label: "Save drafts every",
                    help: "Drafts are written to local IndexedDB only. Lose the browser, lose the draft.",
                    control: rsx! {
                        select { class: "fm-select",
                            option { value: "off", "off" }
                            option { value: "10s", selected: true, "10s" }
                            option { value: "30s", "30s" }
                            option { value: "60s", "60s" }
                        }
                    },
                }
                SettingRow {
                    label: "Default reply behavior",
                    help: "Reply-all is unusual on Freenet — most threads are 1:1.",
                    control: rsx! {
                        select { class: "fm-select",
                            option { value: "reply", selected: true, "Reply (sender only)" }
                            option { value: "all", "Reply all" }
                        }
                    },
                }
            }
        }
    }
}

#[allow(non_snake_case)]
fn ScrContacts() -> Element {
    // Stub list — replaced when we wire to the real address book signal.
    let contacts: &[(&str, &str, &str, &str, &str, &str)] = &[
        ("alice.freenet", "a", "known", "Mid1", "ce11d8a93f02", ""),
        (
            "ian.freenet",
            "i",
            "known",
            "Min2",
            "7afd220e9c11",
            "@ml-kem co-author",
        ),
        (
            "freenet-aft",
            "f",
            "known",
            "Mid2",
            "system",
            "AFT mint daemon",
        ),
        ("kex-bot", "k", "unknown", "Min2", "3f2a1c80de7b", ""),
        ("ml-dsa-test", "m", "unsigned", "Min1", "9911aa00bb22", ""),
    ];
    rsx! {
        div { class: "fm-set-inner",
            p { class: "fm-set-lede",
                "Your address book. Names you've assigned, trust levels you've accepted, and the tier each contact runs at."
            }
            Card {
                div { style: "display: flex; align-items: center; gap: 8px; padding: 12px 16px; border-bottom: 1px solid var(--line2);",
                    input { class: "fm-input", placeholder: "Search contacts, fingerprints…", style: "flex: 1" }
                    select { class: "fm-select",
                        option { value: "all", "All trust levels" }
                        option { value: "known", "Known only" }
                        option { value: "unknown", "Unknown" }
                        option { value: "unsigned", "Unsigned" }
                    }
                    button { class: "fm-btn-secondary", "Import…" }
                    button { class: "fm-btn-primary", "Share my card" }
                }
                div { class: "fm-contact-list",
                    for (alias, initial, trust, tier, fp, label) in contacts.iter() {
                        div { key: "{alias}", class: "fm-contact-row",
                            span { class: "fm-contact-av", "{initial}" }
                            span { class: "fm-contact-name",
                                span { class: "alias", "{alias}" }
                                span { class: "fp", "…{fp}" }
                                if !label.is_empty() {
                                    span {
                                        style: "font-style: italic; color: var(--ink3); font-size: 11.5px; margin-left: 8px;",
                                        "· {label}"
                                    }
                                }
                            }
                            span { class: "fm-contact-trust {trust}", "{trust}" }
                            span { class: "fm-contact-tier", "{tier}" }
                            button { class: "fm-btn-secondary", style: "height: 26px; padding: 0 9px; font-size: 11px;", "Edit" }
                        }
                    }
                }
            }
            Card { title: "Defaults for new contacts",
                SettingRow {
                    label: "Trust on first message",
                    help: "Sets the starting trust level when someone new sends you a verifiable signed message.",
                    control: rsx! {
                        select { class: "fm-select",
                            option { value: "unknown", selected: true, "unknown" }
                            option { value: "known", "known" }
                        }
                    },
                }
                SettingRow {
                    label: "Format for share-my-card",
                    help: "What gets copied when you click 'Share my card'.",
                    control: rsx! {
                        select { class: "fm-select",
                            option { value: "contact-uri", selected: true, "contact:// URI (default)" }
                            option { value: "qr", "QR code" }
                            option { value: "vcard", "vCard 4.0" }
                        }
                    },
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
            Card { title: "Typography",
                SettingRow {
                    label: "UI font size",
                    help: "13.5px is the design default. 15 is recommended for small displays.",
                    control: rsx! {
                        select { class: "fm-select",
                            option { value: "12", "12" }
                            option { value: "13.5", selected: true, "13.5" }
                            option { value: "15", "15" }
                        }
                    },
                }
            }
        }
    }
}

#[allow(non_snake_case)]
fn ScrAdvanced() -> Element {
    let g = use_global_settings();
    let custom_relay = g.advanced.custom_relay;
    let g_relay = g.clone();
    let on_custom_relay = move |_| {
        let mut next = g_relay.clone();
        next.advanced.custom_relay = !next.advanced.custom_relay;
        local_state::persist_global_settings(next);
    };
    let log: &[(&str, &str, &str)] = &[
        (
            "14:32:01",
            "info",
            "ws connected · 127.0.0.1:7509 · 12ms rtt",
        ),
        ("14:32:01", "ok", "inbox contract resolved · 8f3c…d8a93f02"),
        ("14:31:48", "info", "aft mint cap reached daily quota check"),
        (
            "14:31:46",
            "ok",
            "burned 1 token · msg sent to alice.freenet",
        ),
        ("14:30:12", "warn", "delegate stale (4m); refreshing"),
        ("14:30:13", "ok", "delegate ok · ml-dsa-65 verified"),
        (
            "14:28:55",
            "info",
            "web-container hash matches contract-id.txt",
        ),
        (
            "14:28:54",
            "info",
            "boot · ui v0.1.4-pre-alpha · wasm 1.4MB",
        ),
    ];
    rsx! {
        div { class: "fm-set-inner",
            p { class: "fm-set-lede",
                "Network plumbing, logs, factory reset. Most users will never come here."
            }
            Card { title: "Node connection",
                SettingRow {
                    label: "Local node",
                    help: "127.0.0.1:7509 · ML-KEM · ML-DSA · WebSocket alive",
                    control: rsx! { button { class: "fm-btn-secondary", "Reconnect" } },
                }
                SettingRow {
                    label: "Use custom relay",
                    help: "By default we connect to the local Freenet node. Override only if you know what you're doing.",
                    control: rsx! { Toggle { on: custom_relay, ontoggle: on_custom_relay } },
                }
            }
            Card {
                title: "Storage",
                sub: "Everything is local to this browser. Encrypted on disk only by the OS.",
                SettingRow {
                    label: "IndexedDB usage",
                    help: "Messages, drafts, address book.",
                    control: rsx! {
                        span { style: "font-family: 'Geist Mono', monospace; font-size: 11px; color: var(--ink2);", "14.2 MB / 80 MB" }
                    },
                }
                SettingRow {
                    label: "Clear local cache",
                    help: "Wipes cached contract state. Forces a full re-sync. Does not touch keys or messages.",
                    control: rsx! { button { class: "fm-btn-secondary", "Clear cache" } },
                }
            }
            Card {
                title: "Diagnostics",
                sub: "Last 8 events from this session. Useful when filing issues.",
                div { class: "fm-term",
                    for (i, (ts, lvl, txt)) in log.iter().enumerate() {
                        div { key: "{i}",
                            span { class: "ts", "{ts}" }
                            " "
                            span { class: "lvl-{lvl}", "{lvl.to_uppercase()}" }
                            " "
                            span { "{txt}" }
                        }
                    }
                }
                div { class: "fm-sub-row",
                    span { class: "label", "Build" }
                    span { class: "v", "ui v0.1.4-pre-alpha · wasm 1.4 MB" }
                    span { style: "flex: 1" }
                    button { class: "fm-btn-secondary", "Copy report" }
                }
            }
            Card { title: "Danger zone",
                SettingRow {
                    label: "Factory reset",
                    help: "Deletes all identities, contacts, messages, and the address book from this browser. Irreversible.",
                    control: rsx! { button { class: "fm-btn-danger", "Reset everything…" } },
                }
            }
        }
    }
}
