//! Shared "back up this identity" panel: shows the identity's recovery key
//! (masked by default), copies it for a password manager, offers a .txt
//! download, and asks the user to confirm they saved it.
//!
//! Used by all three export sites (identity row, create flow, Settings).
//! The panel never decides on its own that a backup happened: the caller
//! records "backed up" only from `on_saved`, which fires when the user
//! clicks "I've saved it". Copying or downloading fires `on_exported`,
//! which the create flow uses to warn before discarding a key that has
//! already left the browser.
//!
//! Styling uses classes that exist in both CSS scopes (`.fm-pre` in
//! login.css, `.fm-app` in settings.css): `.field`, `.field-label`,
//! `.token-block`, `.btn*`, plus the `.bk-*` rules defined in both files.

use dioxus::prelude::*;

use crate::clipboard::{CopyOutcome, copy_text};
use crate::testid;

/// Suggested name for the password-manager entry. Includes the first two
/// fingerprint words (the same pair shown on the identity row) so two
/// identities with similar aliases stay distinguishable.
pub(crate) fn entry_title(alias: &str, words: &[String]) -> String {
    let fp = words.iter().take(2).cloned().collect::<Vec<_>>().join(" ");
    match (alias.trim().is_empty(), fp.is_empty()) {
        (false, false) => format!("Freenet Mail: {} ({fp})", alias.trim()),
        (false, true) => format!("Freenet Mail: {}", alias.trim()),
        (true, false) => format!("Freenet Mail ({fp})"),
        (true, true) => "Freenet Mail".to_string(),
    }
}

/// Masked rendering of a recovery key: the visible prefix plus dots, so the
/// user can tell what kind of secret it is without exposing it.
fn masked(token: &str) -> String {
    let prefix = super::backup_token::TOKEN_PREFIX;
    if token.starts_with(prefix) {
        format!("{prefix}{}", "•".repeat(28))
    } else {
        "•".repeat(28)
    }
}

#[component]
pub(crate) fn BackupKeyPanel(
    /// The recovery key (`fmail-key-1:...`).
    token: String,
    /// Alias, for the entry title and download filename.
    alias: String,
    /// The identity's six fingerprint words.
    words: Vec<String>,
    /// Whether the user already confirmed this backup in this session.
    saved: bool,
    /// Fired after a successful copy or download.
    on_exported: EventHandler<()>,
    /// Fired when the user confirms they saved the key.
    on_saved: EventHandler<()>,
) -> Element {
    let mut revealed = use_signal(|| false);
    let mut copy_status: Signal<Option<CopyOutcome>> = use_signal(|| None);
    let mut download_status: Signal<Option<Result<String, String>>> = use_signal(|| None);
    // The gateway shell drops a download that arrives within 2s of the
    // previous one without telling us, so hold the button off for that
    // long rather than report a download that never happens.
    let mut download_cooling = use_signal(|| false);

    let title = entry_title(&alias, &words);
    let is_revealed = *revealed.read();

    let on_copy = {
        let token = token.clone();
        move |_| {
            copy_status.set(None);
            copy_text(token.clone(), move |outcome| {
                // SentToShell counts: the key may have reached the clipboard.
                if !matches!(outcome, CopyOutcome::Failed(_)) {
                    on_exported.call(());
                }
                copy_status.set(Some(outcome));
            });
        }
    };

    let on_download = {
        let token = token.clone();
        let alias = alias.clone();
        let words = words.clone();
        move |_| {
            if *download_cooling.read() {
                return;
            }
            let fname = super::login::backup_filename(&alias, &words);
            let body = format!("{token}\n");
            match super::login::trigger_browser_download(&fname, body.as_bytes(), "text/plain") {
                Ok(()) => {
                    download_status.set(Some(Ok(fname)));
                    on_exported.call(());
                    download_cooling.set(true);
                    spawn(async move {
                        gloo_timers::future::TimeoutFuture::new(2_100).await;
                        download_cooling.set(false);
                    });
                }
                Err(e) => download_status.set(Some(Err(e))),
            }
        }
    };

    let copy_label = match &*copy_status.read() {
        Some(CopyOutcome::Copied) => "Copied",
        _ => "Copy recovery key",
    };

    rsx! {
        div { class: "bk-panel", "data-testid": testid::FM_BACKUP_PANEL,
            // The panel can open far from the button that opened it (Settings
            // renders it at the top of a long, scrolled screen; the create
            // flow below the fingerprint grid), so bring it into view.
            onmounted: move |evt| async move {
                let _ = evt.scroll_to(ScrollBehavior::Smooth).await;
            },
            p { class: "bk-lede",
                strong { "Save this recovery key in your password manager." }
                " Anyone who has it can read your mail and send as you. It is the only way to get this identity back if this browser's storage is lost."
            }
            div { class: "field",
                span { class: "field-label", "Suggested entry name" }
                div { class: "bk-entry-title", "data-testid": testid::FM_BACKUP_ENTRY_TITLE, "{title}" }
            }
            div { class: "field",
                div { class: "bk-key-head",
                    span { class: "field-label", "Recovery key" }
                    button {
                        class: "bk-link",
                        r#type: "button",
                        "data-testid": testid::FM_BACKUP_REVEAL,
                        "aria-pressed": "{is_revealed}",
                        onclick: move |_| {
                            let next = !*revealed.read();
                            revealed.set(next);
                        },
                        if is_revealed { "Hide" } else { "Reveal" }
                    }
                }
                if is_revealed {
                    div { class: "token-block bk-key", "data-testid": testid::FM_BACKUP_KEY, "{token}" }
                } else {
                    div {
                        class: "token-block bk-key bk-masked",
                        "data-testid": testid::FM_BACKUP_KEY_MASKED,
                        "aria-label": "Recovery key (hidden)",
                        "{masked(&token)}"
                    }
                }
            }
            div { class: "bk-actions",
                button {
                    class: "btn btn-primary",
                    r#type: "button",
                    "data-testid": testid::FM_BACKUP_COPY,
                    onclick: on_copy,
                    "{copy_label}"
                }
                button {
                    class: "btn btn-secondary",
                    r#type: "button",
                    "data-testid": testid::FM_BACKUP_DOWNLOAD,
                    disabled: *download_cooling.read(),
                    onclick: on_download,
                    "Download as .txt"
                }
            }
            div { "data-testid": testid::FM_BACKUP_STATUS, role: "status", "aria-live": "polite",
                match &*copy_status.read() {
                    Some(CopyOutcome::Copied) => rsx! {
                        p { class: "bk-status ok", "Copied. Paste it into a new password-manager entry now." }
                    },
                    Some(CopyOutcome::SentToShell) => rsx! {
                        p { class: "bk-status warn",
                            "Sent to your clipboard through Freenet, which can't confirm it worked. Paste it somewhere to check, or reveal the key and copy it by hand."
                        }
                    },
                    Some(CopyOutcome::Failed(why)) => rsx! {
                        p { class: "bk-status err",
                            "Couldn't copy: {why}. Reveal the key, select it and copy it by hand, or download it as a file."
                        }
                    },
                    None => rsx! {},
                }
                match &*download_status.read() {
                    Some(Ok(fname)) => rsx! {
                        p { class: "bk-status ok", "Downloading {fname}. Store the file somewhere safe, or delete it once the key is in your password manager." }
                    },
                    Some(Err(e)) => rsx! {
                        p { class: "bk-status err", "Download failed: {e}" }
                    },
                    None => rsx! {},
                }
            }
            div { class: "bk-confirm",
                if saved {
                    p { class: "bk-status ok", "data-testid": testid::FM_BACKUP_SAVED_NOTE,
                        "✓ Marked as backed up."
                    }
                } else {
                    button {
                        class: "btn bk-btn-confirm",
                        r#type: "button",
                        "data-testid": testid::FM_BACKUP_SAVED,
                        onclick: move |_| on_saved.call(()),
                        "I've saved it"
                    }
                    span { class: "field-help", "Only click once the key is stored somewhere you can find it again." }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words() -> Vec<String> {
        ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    #[test]
    fn entry_title_uses_alias_and_first_two_words() {
        assert_eq!(
            entry_title("mira", &words()),
            "Freenet Mail: mira (alpha bravo)"
        );
        assert_eq!(entry_title("  ", &words()), "Freenet Mail (alpha bravo)");
        assert_eq!(entry_title("mira", &[]), "Freenet Mail: mira");
    }

    #[test]
    fn masked_never_contains_the_payload() {
        let token = "fmail-key-1:abcdefSECRET";
        let m = masked(token);
        assert!(m.starts_with("fmail-key-1:"));
        assert!(!m.contains("SECRET"));
    }
}
