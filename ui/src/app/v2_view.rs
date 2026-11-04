//! Inbox v2 on screen: your address and invites, v2 contacts with their
//! passes, the compose note for a v2 recipient, and the warning that an
//! identity is active on another node.

use dioxus::prelude::*;
use freenet_mail_protocol::Addr;
use freenet_mail_protocol::inbox_v2::QuarantineMode;

use super::User;
use crate::address;
use crate::testid;
use crate::v2::contacts::{self, Issued, PassState};

fn day(secs: u64) -> String {
    chrono::DateTime::from_timestamp(secs as i64, 0)
        .map(|t| t.format("%Y-%m-%d").to_string())
        .unwrap_or_default()
}

fn own_label(alias: &str) -> Option<String> {
    address::normalize_label(alias, false).ok().map(|l| l.0)
}

/// Decision 25: the inbox holds an owner version this node did not sign.
#[component]
pub(crate) fn ForeignNodeWarning(addr: Addr) -> Element {
    if !crate::v2::owner::status(&addr).foreign_version {
        return rsx! {};
    }
    rsx! {
        div { class: "info",
            "data-testid": testid::FM_V2_FOREIGN_WARNING,
            style: "margin: 8px 12px; padding: 10px 12px; border: 1px solid var(--amber, #c80); border-radius: 6px;",
            "This identity is active on another node. Use it on one node only: two nodes \
             signing for one inbox can undo each other's changes, and mail already read can \
             show up again."
        }
    }
}

/// Settings: your v2 address, invites, and v2 contacts.
#[component]
pub(crate) fn ScrAddress() -> Element {
    let user = use_context::<Signal<User>>();
    let Some(me) = user.read().logged_id().cloned() else {
        return rsx! {};
    };
    let addr = me.addr;
    let alias = me.alias.to_string();
    let status = crate::v2::owner::status(&addr);
    let shown = address::full_address(own_label(&alias).as_deref(), &addr.0);

    let mut invite = use_signal(|| None::<Result<String, String>>);
    let alias_for_invite = alias.clone();
    let make_invite = move |_| {
        let alias = alias_for_invite.clone();
        spawn(async move {
            let made = contacts::create_invite(addr, own_label(&alias).as_deref(), 3).await;
            invite.set(Some(made));
        });
    };

    let mut add_input = use_signal(String::new);
    let mut add_name = use_signal(String::new);
    let mut add_result = use_signal(|| None::<Result<contacts::Added, String>>);
    let mut adding = use_signal(|| false);
    let on_add = move |_| {
        if *adding.read() {
            return;
        }
        adding.set(true);
        let input = add_input.read().clone();
        let name = add_name.read().clone();
        spawn(async move {
            let r = contacts::add(addr, &input, &name).await;
            if r.is_ok() {
                add_input.set(String::new());
                add_name.set(String::new());
            }
            add_result.set(Some(r));
            adding.set(false);
        });
    };

    let rows = use_resource(move || async move {
        let _ = contacts::GEN.read();
        contacts::rows(addr).await
    });

    // Who may write to you without a pass (decision D8): anyone, or only
    // senders who prove a Ghost Key, at a tier.
    let mut mode_error = use_signal(|| None::<String>);
    let mut mode_busy = use_signal(|| false);
    let set_mode = use_callback(move |mode: QuarantineMode| {
        if *mode_busy.read() {
            return;
        }
        mode_busy.set(true);
        spawn(async move {
            let r = contacts::change_own(
                addr,
                freenet_mail_protocol::OwnerChange::SetQuarantine(mode),
            )
            .await;
            mode_error.set(r.err());
            crate::v2::owner::refresh(addr).await;
            mode_busy.set(false);
        });
    });
    let mode_slug = match status.quarantine {
        Some(QuarantineMode::RequireGhost { min_usd }) => format!("ghost-{}", min_usd.unwrap_or(0)),
        Some(QuarantineMode::Open) => "open".to_string(),
        None => "unknown".to_string(),
    };

    rsx! {
        div { class: "fm-set-inner",
            ForeignNodeWarning { addr }
            p { class: "fm-set-lede",
                "Your address is what people write to. The name before the @ is only a \
                 suggestion: a contact who saved you under another name sees theirs."
            }
            super::settings::Card { title: "Your address".to_string(),
                div { style: "padding: 12px 16px; display: flex; gap: 8px; align-items: center; flex-wrap: wrap;",
                    code {
                        "data-testid": testid::FM_V2_ADDRESS,
                        style: "word-break: break-all;",
                        "{shown}"
                    }
                    button {
                        class: "fm-btn-secondary",
                        onclick: {
                            let shown = shown.clone();
                            move |_| {
                                let _ = crate::clipboard::copy_text(shown.clone(), |outcome| {
                                    if matches!(outcome, crate::clipboard::CopyOutcome::Failed(_)) {
                                        crate::toast::push_toast_detached(
                                            "Couldn't copy: select the address and copy it by hand.",
                                            crate::toast::ToastLevel::Warning,
                                        );
                                    }
                                });
                            }
                        },
                        "Copy"
                    }
                }
                div { style: "padding: 0 16px 12px; color: var(--ink3); font-size: 12px;",
                    "data-testid": testid::FM_V2_INBOX_STATE,
                    "data-ready": "{status.ready}",
                    if let Some(e) = &status.error {
                        "Your inbox is not ready: {e}"
                    } else if status.ready {
                        "Your inbox is on the network."
                    } else {
                        "Starting your inbox\u{2026}"
                    }
                }
            }
            super::settings::Card {
                title: "New contacts".to_string(),
                sub: "Mail from someone you have not accepted waits in your new-contacts queue \
                      (16 places). You can let anyone in, or only senders who prove a Ghost Key."
                    .to_string(),
                div { style: "padding: 12px 16px; display: flex; gap: 8px; flex-wrap: wrap; align-items: center;",
                    "data-testid": testid::FM_V2_QUARANTINE_MODE,
                    "data-mode": "{mode_slug}",
                    button {
                        class: if mode_slug == "open" { "fm-btn-primary" } else { "fm-btn-secondary" },
                        disabled: *mode_busy.read() || !status.ready,
                        "data-value": "open",
                        onclick: move |_| set_mode.call(QuarantineMode::Open),
                        "Anyone"
                    }
                    for (usd, text) in [(None, "Ghost Key"), (Some(5u32), "Ghost Key, $5 or more"), (Some(20u32), "Ghost Key, $20 or more")] {
                        button {
                            class: if mode_slug == format!("ghost-{}", usd.unwrap_or(0)) { "fm-btn-primary" } else { "fm-btn-secondary" },
                            disabled: *mode_busy.read() || !status.ready,
                            "data-value": "ghost-{usd.unwrap_or(0)}",
                            onclick: move |_| set_mode.call(QuarantineMode::RequireGhost { min_usd: usd }),
                            "{text}"
                        }
                    }
                    if let Some(e) = &*mode_error.read() {
                        div { class: "err", style: "width: 100%;", "Not changed: {e}" }
                    }
                }
            }
            super::settings::Card {
                title: "New-contacts queue".to_string(),
                sub: "Mail from people you have not accepted. Accepting sends them a pass, so \
                      their mail goes straight to your inbox; dropping tells them nothing."
                    .to_string(),
                QueueView { me: addr }
            }
            super::settings::Card {
                title: "Invite someone".to_string(),
                sub: "An invite lets whoever holds it write to you 3 times within 14 days, \
                      straight to your inbox. Send it privately: anyone who has it can use it."
                    .to_string(),
                div { style: "padding: 12px 16px;",
                    button {
                        class: "fm-btn-primary",
                        "data-testid": testid::FM_V2_INVITE_CREATE,
                        disabled: !status.ready,
                        onclick: make_invite,
                        "Create an invite"
                    }
                    match &*invite.read() {
                        Some(Ok(text)) => rsx! {
                            textarea {
                                class: "fm-input",
                                "data-testid": testid::FM_V2_INVITE_TEXT,
                                readonly: true,
                                style: "width: 100%; margin-top: 8px; min-height: 80px; font-family: monospace;",
                                value: "{text}",
                            }
                        },
                        Some(Err(e)) => rsx! { div { class: "err", "Couldn't create an invite: {e}" } },
                        None => rsx! {},
                    }
                }
            }
            super::settings::Card {
                title: "Add a contact".to_string(),
                sub: "Paste their address (name@address works too) or an invite they sent you."
                    .to_string(),
                div { style: "padding: 12px 16px; display: flex; flex-direction: column; gap: 8px;",
                    input {
                        class: "fm-input",
                        "data-testid": testid::FM_V2_ADD_INPUT,
                        placeholder: "name@address, or fmail-invite-1:\u{2026}",
                        value: "{add_input}",
                        oninput: move |ev| add_input.set(ev.value()),
                    }
                    input {
                        class: "fm-input",
                        "data-testid": testid::FM_V2_ADD_NAME,
                        placeholder: "Your name for them (optional)",
                        value: "{add_name}",
                        oninput: move |ev| add_name.set(ev.value()),
                    }
                    button {
                        class: "fm-btn-primary",
                        "data-testid": testid::FM_V2_ADD_SUBMIT,
                        disabled: *adding.read() || add_input.read().trim().is_empty(),
                        onclick: on_add,
                        if *adding.read() { "Adding\u{2026}" } else { "Add" }
                    }
                    match &*add_result.read() {
                        Some(Ok(added)) => rsx! {
                            div { "data-testid": testid::FM_V2_ADD_RESULT,
                                if added.own && added.invite {
                                    "{added.name} is one of your own identities: the invite is kept, so you can write to it straight to its inbox."
                                } else if added.own {
                                    "{added.name} is one of your own identities, so it is not added as a contact. Write to its address."
                                } else if added.invite {
                                    "Added {added.name}. Your invite lets you write straight to their inbox."
                                } else {
                                    "Added {added.name}. Your first message goes to their new-contacts queue until they accept you."
                                }
                            }
                            for w in added.warnings.iter() {
                                div { class: "warn", "data-testid": testid::FM_V2_LABEL_WARNING,
                                    "{added.name} {w}"
                                }
                            }
                        },
                        Some(Err(e)) => rsx! {
                            div { class: "err", "data-testid": testid::FM_V2_ADD_RESULT, "Not added: {e}" }
                        },
                        None => rsx! {},
                    }
                }
            }
            super::settings::Card { title: "Contacts".to_string(),
                match &*rows.read() {
                    None => rsx! { div { style: "padding: 12px 16px;", "Loading\u{2026}" } },
                    Some(Err(e)) => rsx! { div { class: "err", style: "padding: 12px 16px;", "{e}" } },
                    Some(Ok(rows)) if rows.is_empty() => rsx! {
                        div { style: "padding: 12px 16px; color: var(--ink3);", "No contacts with a new address yet." }
                    },
                    Some(Ok(rows)) => rsx! {
                        for row in rows.iter().cloned() {
                            ContactRow { me: addr, row }
                        }
                    },
                }
            }
        }
    }
}

/// The new-contacts queue (§5.5): strangers' mail waiting to be accepted
/// (which sends them a pass) or dropped, the tip to require a Ghost Key once
/// the queue fills, and how many earlier strangers' messages this node let
/// go to stay within its budget (decision 21).
#[component]
fn QueueView(me: Addr) -> Element {
    let status = crate::v2::owner::status(&me);
    let waiting = crate::v2::owner::inbound(&me, true);
    let count = waiting.len();
    let mut busy = use_signal(|| false);
    let mut said = use_signal(|| None::<Result<String, String>>);
    // The row being accepted, and the petname typed for it.
    let mut asking = use_signal(|| None::<([u8; 32], String)>);
    let tip = match status.quarantine {
        Some(QuarantineMode::Open) if status.queue_was_full => Some(
            "Your new-contacts queue filled up, so some strangers' messages may have been \
             pushed out before they reached you. To keep it for people who prove a Ghost Key, \
             choose a Ghost Key option under \u{201c}New contacts\u{201d}.",
        ),
        Some(QuarantineMode::RequireGhost { .. }) if status.queue_was_full => Some(
            "Your new-contacts queue filled up even with a Ghost Key required. A higher tier \
             under \u{201c}New contacts\u{201d} lets fewer senders in.",
        ),
        _ => None,
    };
    rsx! {
        div { "data-testid": testid::FM_V2_QUEUE, "data-count": "{count}",
            if let Some(tip) = tip {
                div { class: "warn", "data-testid": testid::FM_V2_QUEUE_TIP, style: "padding: 12px 16px;", "{tip}" }
            }
            if status.strangers_dropped > 0 {
                div { "data-testid": testid::FM_V2_QUEUE_DROPPED,
                    "data-dropped": "{status.strangers_dropped}",
                    style: "padding: 0 16px 12px; color: var(--ink3); font-size: 12px;",
                    "{status.strangers_dropped} earlier messages from new contacts were removed \
                     from this node to make room: it keeps the newest 1024."
                }
            }
            if count == 0 {
                div { style: "padding: 12px 16px; color: var(--ink3);", "Nobody is waiting." }
            }
            for m in waiting {
                {
                    let (name, warnings) = contacts::sender_name(&m.from, m.body.label.as_deref());
                    let address = address::display(&m.from.0);
                    let (for_accept, for_drop) = (m.clone(), m.clone());
                    rsx! {
                        div { class: "fm-contact-row",
                            "data-testid": testid::FM_V2_QUEUE_ROW,
                            "data-address": "{address}",
                            "data-title": "{m.body.title}",
                            style: "flex-wrap: wrap;",
                            span { class: "fm-contact-name",
                                span { class: "alias", "{name}" }
                                span { class: "fp", style: "word-break: break-all;", "{address}" }
                            }
                            for w in warnings.iter() {
                                div { class: "warn", "data-testid": testid::FM_V2_LABEL_WARNING, style: "width: 100%;",
                                    "{name} {w}"
                                }
                            }
                            div { style: "width: 100%;",
                                strong { "{m.body.title}" }
                                div { style: "white-space: pre-wrap; font-size: 12px;", "{m.body.content}" }
                            }
                            if asking.read().as_ref().is_some_and(|(id, _)| *id == m.id) {
                                PetnameForm { me, m: for_accept.clone(), asking, busy, said }
                            } else {
                                button {
                                    class: "fm-btn-primary",
                                    "data-testid": testid::FM_V2_QUEUE_ACCEPT,
                                    disabled: *busy.read(),
                                    onclick: move |_| {
                                        let m = for_accept.clone();
                                        // A saved contact keeps the name it has.
                                        if contacts::by_addr(&m.from).is_some() {
                                            busy.set(true);
                                            spawn(async move {
                                                said.set(Some(crate::v2::queue::accept(me, &m, "").await));
                                                busy.set(false);
                                            });
                                            return;
                                        }
                                        let prefill = m
                                            .body
                                            .label
                                            .as_deref()
                                            .and_then(|l| address::normalize_label(l, true).ok())
                                            .map(|l| l.0)
                                            .unwrap_or_default();
                                        asking.set(Some((m.id, prefill)));
                                    },
                                    "Accept"
                                }
                            }
                            button {
                                class: "fm-btn-secondary",
                                "data-testid": testid::FM_V2_QUEUE_DROP,
                                disabled: *busy.read(),
                                onclick: move |_| {
                                    let m = for_drop.clone();
                                    busy.set(true);
                                    spawn(async move {
                                        let r = crate::v2::queue::drop_message(me, &m).await;
                                        said.set(Some(r.map(|()| "Dropped.".to_string())));
                                        busy.set(false);
                                    });
                                },
                                "Drop"
                            }
                        }
                    }
                }
            }
            match &*said.read() {
                Some(Ok(t)) => rsx! { div { class: "info", style: "padding: 8px 16px;", "{t}" } },
                Some(Err(e)) => rsx! { div { class: "err", style: "padding: 8px 16px;", "Not done: {e}" } },
                None => rsx! {},
            }
        }
    }
}

/// Accepting a stranger (M2): the name to save them under, prefilled with
/// the label they gave and editable, with what is wrong with it shown before
/// anything is saved. Their label never becomes a petname unseen.
#[component]
fn PetnameForm(
    me: Addr,
    m: crate::v2::owner::Inbound,
    asking: Signal<Option<([u8; 32], String)>>,
    busy: Signal<bool>,
    said: Signal<Option<Result<String, String>>>,
) -> Element {
    let typed = asking
        .read()
        .as_ref()
        .map(|(_, p)| p.clone())
        .unwrap_or_default();
    let invalid = match typed.trim() {
        "" => None,
        p => address::normalize_label(p, true)
            .err()
            .map(|e| e.to_string()),
    };
    let taken = contacts::petnames()
        .iter()
        .any(|(p, a)| p == typed.trim() && *a != m.from.0);
    let warnings = crate::v2::queue::petname_warnings(&m, &typed);
    let shown = match typed.trim() {
        "" => address::display(&m.from.0)[..8].to_string(),
        p => p.to_string(),
    };
    let blocked = *busy.read() || invalid.is_some() || taken;
    rsx! {
        div { style: "width: 100%; display: flex; flex-direction: column; gap: 6px;",
            label { style: "font-size: 12px;",
                "Save them as (your name for them; theirs is only a suggestion):"
            }
            input {
                class: "fm-input",
                "data-testid": testid::FM_V2_QUEUE_PETNAME,
                value: "{typed}",
                placeholder: "{shown}",
                oninput: move |ev| {
                    let id = m.id;
                    asking.set(Some((id, ev.value())));
                },
            }
            if let Some(e) = &invalid {
                div { class: "err", "That name {e}." }
            }
            if taken {
                div { class: "err", "data-testid": testid::FM_V2_LABEL_WARNING,
                    "You already have a contact called \u{201c}{typed.trim()}\u{201d}. Choose another name."
                }
            }
            for w in warnings.iter() {
                div { class: "warn", "data-testid": testid::FM_V2_LABEL_WARNING, "{shown} {w}" }
            }
            div { style: "display: flex; gap: 8px;",
                button {
                    class: "fm-btn-primary",
                    "data-testid": testid::FM_V2_QUEUE_CONFIRM,
                    disabled: blocked,
                    onclick: {
                        let m = m.clone();
                        let typed = typed.clone();
                        move |_| {
                            let (m, typed) = (m.clone(), typed.clone());
                            busy.set(true);
                            spawn(async move {
                                said.set(Some(crate::v2::queue::accept(me, &m, &typed).await));
                                asking.set(None);
                                busy.set(false);
                            });
                        }
                    },
                    if warnings.is_empty() { "Save and accept" } else { "Accept anyway" }
                }
                button {
                    class: "fm-btn-secondary",
                    onclick: move |_| asking.set(None),
                    "Cancel"
                }
            }
        }
    }
}

/// Above the message list: how many strangers' messages wait in the
/// new-contacts queue, which is in Settings.
#[component]
pub(crate) fn QueueNotice(addr: Addr) -> Element {
    let n = crate::v2::owner::inbound(&addr, true).len();
    if n == 0 {
        return rsx! {};
    }
    rsx! {
        div { class: "info", style: "margin: 8px 12px; font-size: 12px;",
            "{n} message(s) from new contacts wait in your new-contacts queue: Settings, \
             \u{201c}Address & new contacts\u{201d}."
        }
    }
}

#[component]
fn ContactRow(me: Addr, row: contacts::Row) -> Element {
    let mut revoking = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let held = match row.held {
        PassState::Held => "You hold their pass: your mail goes straight to their inbox.",
        PassState::Lapsed => {
            "Your pass to them has lapsed: your mail goes to their new-contacts queue until they accept you again."
        }
        PassState::None => {
            "No pass from them yet: your first message goes to their new-contacts queue."
        }
    };
    let held_slug = match row.held {
        PassState::Held => "held",
        PassState::Lapsed => "lapsed",
        PassState::None => "none",
    };
    let (issued, issued_slug) = match &row.issued {
        Issued::NotYet => (
            "They have no pass from you yet; your first message gives them one.".to_string(),
            "none",
        ),
        Issued::Live { expiry, .. } => (
            format!("Their pass to you is live until {}, renewed while you are in touch.", day(*expiry)),
            "live",
        ),
        Issued::Revoked => (
            "You revoked their pass: their mail goes to your new-contacts queue. Writing to them gives them a new one."
                .to_string(),
            "revoked",
        ),
    };
    let to = row.addr;
    let live = matches!(row.issued, Issued::Live { .. });
    let full = address::display(&to.0);
    rsx! {
        div { class: "fm-contact-row",
            "data-testid": testid::FM_V2_CONTACT_ROW,
            "data-address": "{full}",
            style: "flex-wrap: wrap;",
            span { class: "fm-contact-name",
                span { class: "alias", "{row.name}" }
                span { class: "fp", style: "word-break: break-all;", "{full}" }
            }
            for w in row.label_warnings.iter() {
                div { class: "warn", "data-testid": testid::FM_V2_LABEL_WARNING, style: "width: 100%;",
                    "{row.name} {w}"
                }
            }
            div { style: "width: 100%; font-size: 12px;",
                div { "data-testid": testid::FM_V2_PASS_HELD, "data-state": held_slug, "{held}" }
                div { "data-testid": testid::FM_V2_PASS_ISSUED, "data-state": issued_slug, "{issued}" }
            }
            if live {
                button {
                    class: "fm-btn-secondary",
                    "data-testid": testid::FM_V2_REVOKE,
                    disabled: *revoking.read(),
                    onclick: move |_| {
                        revoking.set(true);
                        spawn(async move {
                            if let Err(e) = contacts::revoke(me, to).await {
                                error.set(Some(e));
                            }
                            revoking.set(false);
                        });
                    },
                    if *revoking.read() { "Revoking\u{2026}" } else { "Revoke their pass" }
                }
            }
            if let Some(e) = &*error.read() {
                div { class: "err", style: "width: 100%;", "Not revoked: {e}" }
            }
        }
    }
}

/// "Use Ghost Key" for a recipient whose inbox takes new contacts only with
/// one (§5.5 as amended by decisions 2 and 19). Advisory like the badge: Send
/// stays enabled, and Ghost Key's answer at send decides.
#[component]
fn GhostPanel(
    to: Addr,
    min_usd: Option<u32>,
    draft_id: String,
    draft_saved: bool,
    save_draft: Callback<()>,
) -> Element {
    use crate::ghostkeys::{self, Refusal};
    use crate::v2::send::{GHOST_CHOICE, GhostChoice};
    let need = u64::from(min_usd.unwrap_or(0));
    let mut checks = use_signal(|| 0u32);
    let presence = use_resource(move || async move {
        let _ = checks.read();
        ghostkeys::presence().await
    });
    let keys = use_resource(move || async move {
        let _ = checks.read();
        ghostkeys::keys().await
    });
    let mut want_link = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let mut asking = use_signal(|| false);
    let choose = move |key: ghostkeys::Key, default: Option<String>| {
        let default = default.as_deref() == Some(key.fingerprint.as_str());
        *GHOST_CHOICE.write() = Some((to, GhostChoice { key, default }));
    };
    // The default key is chosen once the keys are known, unless the user
    // chose otherwise.
    use_effect(move || {
        if let Some(Ok((list, default))) = &*keys.read()
            && crate::v2::send::ghost_for(GHOST_CHOICE.peek().clone(), &to).is_none()
            && let Some(k) = list
                .iter()
                .find(|k| Some(&k.fingerprint) == default.as_ref())
                .or(list.first())
        {
            choose(k.clone(), default.clone());
        }
    });
    let chosen = crate::v2::send::ghost_for(GHOST_CHOICE.read().clone(), &to);
    let usable = match &*presence.read() {
        Some(Ok(p)) => p.usable.to_string(),
        _ => String::new(),
    };
    let get = rsx! {
        button {
            class: "fm-btn-secondary",
            "data-testid": testid::FM_V2_GHOST_GET,
            onclick: move |_| {
                want_link.set(true);
                save_draft.call(());
            },
            "Get a Ghost Key"
        }
        if *want_link.read() {
            if draft_saved {
                span {
                    "Your draft is saved. "
                    a {
                        "data-testid": testid::FM_V2_GHOST_GET_LINK,
                        href: "{ghostkeys::get_link(&draft_id)}",
                        target: "_blank",
                        rel: "noopener",
                        "Get one at freenet.org"
                    }
                    ", then come back to this draft from the Ghost Key vault."
                }
                button {
                    class: "fm-btn-secondary",
                    "data-testid": testid::FM_V2_GHOST_RECHECK,
                    onclick: move |_| *checks.write() += 1,
                    "I have one now"
                }
            } else {
                span { "Saving your draft first\u{2026}" }
            }
        }
    };
    let body = match &*presence.read() {
        None => rsx! { span { "Looking for your Ghost Key\u{2026}" } },
        Some(Err(e)) => rsx! { span { class: "err", "{e}" } {get} },
        Some(Ok(p)) if p.usable == 0 && p.unusable > 0 => rsx! {
            span {
                "Your Ghost Key cannot sign here: its signing key is missing. Restore it in the \
                 Ghost Key vault from your backup."
            }
            {get}
        },
        Some(Ok(p)) if p.usable == 0 => rsx! { span { "You have no Ghost Key." } {get} },
        Some(Ok(_)) => match &*keys.read() {
            None => rsx! { span { "\u{2026}" } },
            Some(Err(e)) => rsx! { span { class: "err", "{e}" } },
            Some(Ok((list, _))) if list.is_empty() => rsx! {
                button {
                    class: "fm-btn-secondary",
                    "data-testid": testid::FM_V2_GHOST_USE,
                    disabled: *asking.read(),
                    onclick: move |_| {
                        asking.set(true);
                        spawn(async move {
                            match ghostkeys::request_access().await {
                                Ok(_) => error.set(None),
                                Err(Refusal::Denied) => error.set(Some(
                                    "You declined. Choose \"Use Ghost Key\" again to be asked again."
                                        .into(),
                                )),
                                Err(e) => error.set(Some(e.to_string())),
                            }
                            *checks.write() += 1;
                            asking.set(false);
                        });
                    },
                    "Use Ghost Key"
                }
            },
            Some(Ok((list, default))) => {
                let list = list.clone();
                let default = default.clone();
                let picked = chosen.as_ref().map(|c| c.key.fingerprint.clone());
                rsx! {
                    label {
                        input {
                            r#type: "checkbox",
                            "data-testid": testid::FM_V2_GHOST_USE,
                            checked: chosen.is_some(),
                            onchange: {
                                let list = list.clone();
                                let default = default.clone();
                                move |ev: FormEvent| {
                                    if ev.checked() {
                                        if let Some(k) = list.first() {
                                            choose(k.clone(), default.clone());
                                        }
                                    } else {
                                        *GHOST_CHOICE.write() = None;
                                    }
                                }
                            },
                        }
                        " Use Ghost Key"
                    }
                    select {
                        class: "fm-input",
                        "data-testid": testid::FM_V2_GHOST_PICKER,
                        disabled: chosen.is_none(),
                        onchange: {
                            let list = list.clone();
                            let default = default.clone();
                            move |ev: FormEvent| {
                                if let Some(k) = list.iter().find(|k| k.fingerprint == ev.value()) {
                                    choose(k.clone(), default.clone());
                                }
                            }
                        },
                        for k in list.iter() {
                            option {
                                value: "{k.fingerprint}",
                                selected: picked.as_deref() == Some(k.fingerprint.as_str()),
                                "{k.name()}"
                            }
                        }
                    }
                    if let Some(c) = &chosen
                        && c.key.usd.is_some_and(|u| u < need)
                    {
                        span { class: "warn", "data-testid": testid::FM_V2_GHOST_TIER,
                            "This key is ${c.key.usd.unwrap_or(0)}, and they take new contacts only \
                             with ${need} or more: the message will not be sent with it."
                        }
                    }
                    if chosen.is_some() {
                        span { "data-testid": testid::FM_V2_GHOST_DISCLOSURE,
                            "Using it links this first message to your Ghost Key: the proof is \
                             public in their inbox until they pick the message up, and anyone \
                             watching that inbox can see which key sent it, its tier and the \
                             month it was issued. Once they accept you, your mail goes by pass \
                             and carries no proof."
                        }
                    }
                }
            }
        },
    };
    rsx! {
        div {
            "data-testid": testid::FM_V2_GHOST_PANEL,
            "data-usable": "{usable}",
            "data-chosen": "{chosen.as_ref().map(|c| c.key.fingerprint.clone()).unwrap_or_default()}",
            style: "display: flex; gap: 8px; flex-wrap: wrap; align-items: center; width: 100%;",
            {body}
            if let Some(e) = &*error.read() {
                span { class: "err", "{e}" }
            }
        }
    }
}

/// Under the compose To field: what will happen to mail for a v2 recipient.
/// Advisory only: it never disables Send, and the delegate decides at send.
#[component]
pub(crate) fn RecipientNote(
    to: String,
    from: Addr,
    draft_id: String,
    draft_saved: bool,
    save_draft: Callback<()>,
) -> Element {
    if contacts::is_invite(&to) {
        return rsx! {
            div { class: "sheet-field err", "data-testid": testid::FM_V2_RECIPIENT_NOTE,
                "This is an invite, not an address. Add it as a contact under Settings, \
                 \u{201c}Address & new contacts\u{201d}, then write to them by name."
            }
        };
    }
    let Some(to_addr) = contacts::recipient_addr(&to) else {
        return rsx! {};
    };
    let label = address::parse_recipient(&to)
        .ok()
        .and_then(|r| r.label().map(str::to_string));
    let resolved = use_resource(use_reactive!(|(to_addr,)| async move {
        contacts::resolve(to_addr).await
    }));
    let _ = contacts::GEN.read();
    let held = contacts::held(from, to_addr);
    let (name, warnings) = contacts::sender_name(&to_addr, label.as_deref());
    let body = match &*resolved.read() {
        None => rsx! { span { "Looking up {name}\u{2026}" } },
        Some(Err(e)) => rsx! { span { class: "err", "{e}" } },
        Some(Ok(r)) => {
            let ghost = match r.quarantine {
                QuarantineMode::RequireGhost { min_usd } if held != PassState::Held => {
                    Some(min_usd)
                }
                _ => None,
            };
            rsx! {
                if let Some(min_usd) = ghost {
                    span {
                        class: "fm-contact-trust unknown",
                        "data-testid": testid::FM_V2_GHOST_BADGE,
                        "data-tier": "{min_usd.unwrap_or(0)}",
                        match min_usd {
                            Some(usd) => rsx! { "Ghost Key required (${usd} or more)" },
                            None => rsx! { "Ghost Key required" },
                        }
                    }
                    GhostPanel { to: to_addr, min_usd, draft_id: draft_id.clone(), draft_saved, save_draft }
                }
                span {
                    match held {
                        PassState::Held => "Straight to their inbox (you hold their pass).",
                        PassState::Lapsed => "Your pass to them lapsed: this goes to their new-contacts queue.",
                        PassState::None => "First contact: this goes to their new-contacts queue until they accept you.",
                    }
                }
            }
        }
    };
    let (waiting, drained) = match &*resolved.read() {
        Some(Ok(r)) => (r.waiting.to_string(), r.drained.to_string()),
        _ => (String::new(), String::new()),
    };
    rsx! {
        div { class: "sheet-field",
            "data-testid": testid::FM_V2_RECIPIENT_NOTE,
            // How many messages their inbox holds undrained, and how many
            // its owner drained: public state, which shows whether their
            // node has picked mail up.
            "data-waiting": "{waiting}",
            "data-drained": "{drained}",
            "data-held": match held { PassState::Held => "held", PassState::Lapsed => "lapsed", PassState::None => "none" },
            style: "font-size: 12px; gap: 8px; flex-wrap: wrap;",
            span { class: "field-lbl", "v2" }
            span { "{name}" }
            {body}
            for w in warnings.iter() {
                span { class: "warn", "data-testid": testid::FM_V2_LABEL_WARNING, "{name} {w}" }
            }
        }
    }
}

/// The last v2 send's outcome, above the message list until the next one.
#[component]
pub(crate) fn LastOutcome() -> Element {
    let Some(outcome) = crate::v2::send::LAST_OUTCOME.read().clone() else {
        return rsx! {};
    };
    let (seq, text, delivered) = (outcome.0, outcome.1.clone(), outcome.2.delivered());
    rsx! {
        div { class: "info",
            "data-testid": testid::FM_V2_OUTCOME,
            "data-delivered": "{delivered}",
            "data-seq": "{seq}",
            style: "margin: 8px 12px; font-size: 12px;",
            "{text}"
        }
    }
}
