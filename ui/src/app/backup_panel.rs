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

/// Last download result shown in the panel. `Ok((file, route))`: handed
/// off. `Err(None)`: refused because another download just went out (a
/// notice, not a failure). `Err(Some(e))`: the download failed.
type DownloadStatus = Option<Result<(String, super::login::DownloadRoute), Option<String>>>;

/// What the create flow knows about copies of a not-yet-created identity's
/// key, for its "you already copied this key" discard warning.
///
/// Owned by the PARENT (a `Signal` in the create flow), not the panel: the
/// panel is unmounted whenever the discard-confirm dialog opens, but an
/// async copy started from it keeps running and may still land. Each copy
/// settles against this record directly, so the count can't be lost with a
/// remount, and a copy that succeeds after its panel is gone still counts.
///
/// `generation` ties each copy to the keypair it was started for: a reset
/// (new keypair, or discard) bumps it, and copies from before the reset no
/// longer change anything.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CopyTracker {
    generation: u32,
    in_flight: u32,
    landed: bool,
}

impl CopyTracker {
    /// The key may be on the clipboard: a copy landed, or one is still in
    /// flight. A copy that never settles keeps this true, deliberately:
    /// the browser may still complete it.
    pub(crate) fn possibly_exported(&self) -> bool {
        self.landed || self.in_flight > 0
    }

    /// A copy of the current key may have reached the clipboard.
    pub(crate) fn landed(&self) -> bool {
        self.landed
    }

    /// Copies of the current key that haven't settled yet.
    pub(crate) fn in_flight(&self) -> u32 {
        self.in_flight
    }

    /// Forget everything (new keypair, or discarded). Copies already in
    /// flight become stale and are ignored when they settle.
    pub(crate) fn reset(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.in_flight = 0;
        self.landed = false;
    }

    /// An async copy started; returns the ticket it must settle with.
    pub(crate) fn start(&mut self) -> u32 {
        self.in_flight += 1;
        self.generation
    }

    /// A copy started with `ticket` finished; `landed` if it may have
    /// reached the clipboard. Returns whether the ticket is still current:
    /// `false` means the copy was for a keypair since reset, and the caller
    /// must not report it anywhere (it would count against the NEXT key).
    #[must_use]
    pub(crate) fn settle(&mut self, ticket: u32, landed: bool) -> bool {
        if ticket != self.generation {
            return false;
        }
        self.in_flight = self.in_flight.saturating_sub(1);
        self.landed |= landed;
        true
    }
}

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

/// Source of per-panel DOM ids (key element + its label), so `aria-controls`
/// and `aria-labelledby` stay unique even if two panels are mounted.
static NEXT_PANEL_ID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// How many times [`settle_copy`] retries a busy tracker before giving up.
const SETTLE_ATTEMPTS: u8 = 20;

/// Settle a finished copy on the caller's tracker, then `report(current)`,
/// where `current` says whether the copy still belongs to the tracker's
/// current keypair.
///
/// `try_write` fails in two different ways, handled differently:
/// - `Dropped`: the tracker's owner (the create flow) is gone. Nobody is
///   left to warn, so the copy is reported as not current.
/// - `AlreadyBorrowed` / `AlreadyBorrowedMut`: something holds a borrow of
///   the tracker. Not expected here: every borrow of it is taken and
///   released synchronously within one render or event handler, and this
///   runs from a separate task, so it can't interleave with one. Handled
///   anyway rather than assumed, because skipping would leave the copy
///   counted as in flight forever: retry on a later tick, and if the
///   borrow never clears, still show the outcome and keep the copy counted
///   as in flight (the discard warning stays on, the safe side).
fn settle_copy(
    mut tracker: Signal<CopyTracker>,
    ticket: u32,
    landed: bool,
    attempts_left: u8,
    report: impl FnOnce(bool) + 'static,
) {
    // Finish with the borrow before deciding, so the retry can move
    // `tracker` into its task.
    let settled: Result<bool, String> = match tracker.try_write() {
        Ok(mut rec) => Ok(rec.settle(ticket, landed)),
        Err(dioxus::signals::BorrowMutError::Dropped(_)) => Ok(false),
        Err(e) => Err(e.to_string()),
    };
    match settled {
        Ok(current) => report(current),
        Err(e) if attempts_left > 0 => {
            crate::log::debug!("copy tracker busy ({e}); retrying");
            wasm_bindgen_futures::spawn_local(async move {
                gloo_timers::future::TimeoutFuture::new(0).await;
                settle_copy(tracker, ticket, landed, attempts_left - 1, report);
            });
        }
        Err(e) => {
            crate::log::error(
                format!("copy tracker stayed busy ({e}); leaving the copy counted as in flight"),
                None,
            );
            report(true);
        }
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
    /// The caller's record of copies of this key (see [`CopyTracker`]).
    /// Every copy settles against it, even one that finishes after this
    /// panel has unmounted.
    #[props(default)]
    copy_tracker: Option<Signal<CopyTracker>>,
    /// Fired when the user confirms they saved the key.
    on_saved: EventHandler<()>,
    /// Bump to scroll the panel back into view (e.g. "Back up now" clicked
    /// again while the panel is already open somewhere off-screen).
    #[props(default)]
    scroll_request: u32,
) -> Element {
    let mut revealed = use_signal(|| false);
    let mut copy_status: Signal<Option<CopyOutcome>> = use_signal(|| None);
    let mut download_status: Signal<DownloadStatus> = use_signal(|| None);
    // Visual cooldown for this button. The binding limit (the gateway
    // shell drops a download within 2s of the previous one, app-wide) is
    // enforced in `login::trigger_browser_download`, across every panel.
    let mut download_cooling = use_signal(|| false);
    let ids = use_hook(|| {
        let n = NEXT_PANEL_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        (
            format!("fm-backup-key-value-{n}"),
            format!("fm-backup-key-label-{n}"),
        )
    });
    let (key_element_id, key_label_id) = ids;
    let mut mounted: Signal<Option<std::rc::Rc<MountedData>>> = use_signal(|| None);

    // Re-scroll when the caller asks again. The first scroll happens in
    // `onmounted`; this effect only fires for later bumps.
    let mut last_scroll_request = use_signal(|| scroll_request);
    use_effect(use_reactive!(|scroll_request| {
        if *last_scroll_request.peek() == scroll_request {
            return;
        }
        last_scroll_request.set(scroll_request);
        if let Some(el) = mounted.peek().clone() {
            spawn(async move {
                let _ = el.scroll_to(ScrollBehavior::Smooth).await;
            });
        }
    }));

    let title = entry_title(&alias, &words);
    let is_revealed = *revealed.read();

    let on_copy = {
        let token = token.clone();
        move |_| {
            copy_status.set(None);
            // Filled in after `copy_text` returns, if the copy went async;
            // the async completion can only run after that.
            let ticket: std::rc::Rc<std::cell::Cell<Option<u32>>> = Default::default();
            let ticket_for_done = ticket.clone();
            let settled = copy_text(token.clone(), move |outcome| {
                // SentToShell counts: the key may have reached the clipboard.
                let landed = !matches!(outcome, CopyOutcome::Failed(_));
                // This panel's own display. Runs outside its task scope: if
                // the panel is gone (modal closed, identity switched),
                // writing its signals would panic, so check first.
                let report = move |current: bool| {
                    if !current {
                        // The copy belongs to a key the create flow has
                        // since reset (Discard), or the flow is gone.
                        // Reporting it would count against whatever key
                        // comes next. In today's UI a reset also closes the
                        // form, so the panel is normally gone too and its
                        // own guard below would stop the report; this gate
                        // doesn't rely on that.
                        return;
                    }
                    if copy_status.try_peek().is_err() {
                        return;
                    }
                    if landed {
                        on_exported.call(());
                    }
                    copy_status.set(Some(outcome));
                };
                // Settle against the parent's record first: it outlives this
                // panel, so a copy that finishes after the panel unmounted
                // still clears its in-flight entry, and a late success
                // still counts as exported.
                match (copy_tracker, ticket_for_done.get()) {
                    (Some(tracker), Some(t)) => {
                        settle_copy(tracker, t, landed, SETTLE_ATTEMPTS, report)
                    }
                    _ => report(true),
                }
            });
            if !settled
                && let Some(mut tracker) = copy_tracker
                && let Ok(mut rec) = tracker.try_write()
            {
                ticket.set(Some(rec.start()));
            }
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
                Ok(route) => {
                    download_status.set(Some(Ok((fname, route))));
                    on_exported.call(());
                    download_cooling.set(true);
                    // `spawn` is scoped to this component: it is cancelled
                    // if the panel unmounts first.
                    spawn(async move {
                        gloo_timers::future::TimeoutFuture::new(2_100).await;
                        download_cooling.set(false);
                    });
                }
                Err(super::login::DownloadError::TooSoon) => download_status.set(Some(Err(None))),
                Err(super::login::DownloadError::Failed(e)) => {
                    download_status.set(Some(Err(Some(e))))
                }
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
                let el = evt.data();
                mounted.set(Some(el.clone()));
                let _ = el.scroll_to(ScrollBehavior::Smooth).await;
            },
            p { class: "bk-lede",
                strong { "Save this recovery key in your password manager." }
                " Anyone who has it can read your mail and send as you. It is the only way to get this identity back if your Freenet node's data is lost."
            }
            div { class: "field",
                span { class: "field-label", "Suggested entry name" }
                div { class: "bk-entry-title", "data-testid": testid::FM_BACKUP_ENTRY_TITLE, "{title}" }
            }
            div { class: "field",
                div { class: "bk-key-head",
                    span { class: "field-label", id: "{key_label_id}", "Recovery key" }
                    // Fixed label; the state is carried by aria-pressed (and
                    // the pressed styling), so assistive tech hears one
                    // control whose state flips, not a renamed button.
                    button {
                        class: "bk-link",
                        r#type: "button",
                        "data-testid": testid::FM_BACKUP_REVEAL,
                        "aria-pressed": "{is_revealed}",
                        "aria-controls": "{key_element_id}",
                        onclick: move |_| {
                            let next = !*revealed.read();
                            revealed.set(next);
                        },
                        "Show key"
                    }
                }
                if is_revealed {
                    div {
                        class: "token-block bk-key",
                        id: "{key_element_id}",
                        "data-testid": testid::FM_BACKUP_KEY,
                        role: "textbox",
                        "aria-readonly": "true",
                        "aria-multiline": "true",
                        "aria-labelledby": "{key_label_id}",
                        tabindex: "0",
                        "{token}"
                    }
                } else {
                    div {
                        class: "token-block bk-key bk-masked",
                        id: "{key_element_id}",
                        "data-testid": testid::FM_BACKUP_KEY_MASKED,
                        role: "img",
                        "aria-label": "Recovery key, hidden. Press Show key to display it.",
                        "{masked(&token)}"
                    }
                }
                span { class: "field-help",
                    "The key doesn't include this identity's alias or description; you'll choose an alias when you restore it."
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
                            "Sent to your clipboard through Freenet, which can't confirm it worked. Paste it somewhere to check, or show the key and copy it by hand."
                        }
                    },
                    Some(CopyOutcome::Failed(why)) => rsx! {
                        p { class: "bk-status err",
                            "Couldn't copy: {why}. Show the key, select it and copy it by hand, or download it as a file."
                        }
                    },
                    None => rsx! {},
                }
                match &*download_status.read() {
                    Some(Ok((fname, super::login::DownloadRoute::Local))) => rsx! {
                        p { class: "bk-status ok", "Downloading {fname}. Store the file somewhere safe, or delete it once the key is in your password manager." }
                    },
                    // The gateway saves it and can't report back: don't
                    // claim the file arrived.
                    Some(Ok((fname, super::login::DownloadRoute::Relayed))) => rsx! {
                        p { class: "bk-status warn", "Asked Freenet to save {fname}. If no download appears, show the key and copy it by hand instead." }
                    },
                    Some(Err(None)) => rsx! {
                        p { class: "bk-status warn", "Another download just went out. Wait a moment and try again." }
                    },
                    Some(Err(Some(e))) => rsx! {
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

    /// Review #349 round 3, sequence A: an async copy is in flight, the
    /// panel unmounts (discard dialog) and remounts, and the copy then
    /// FAILS. The record must end clear, not stuck "possibly exported".
    #[test]
    fn copy_tracker_failed_copy_after_remount_clears() {
        let mut t = CopyTracker::default();
        let first = t.start();
        assert!(t.possibly_exported(), "in flight counts");
        assert!(t.settle(first, false));
        assert!(!t.possibly_exported());
    }

    /// Sequence B: copy 1 is in flight; copy 2 (from a remounted panel)
    /// settles first and fails; copy 1 then succeeds. The record must stay
    /// "possibly exported" throughout and end exported.
    #[test]
    fn copy_tracker_later_copy_cannot_clear_an_earlier_one() {
        let mut t = CopyTracker::default();
        let first = t.start();
        let second = t.start();
        assert!(t.settle(second, false));
        assert!(t.possibly_exported(), "copy 1 is still in flight");
        assert!(t.settle(first, true));
        assert!(t.possibly_exported(), "copy 1 landed");
    }

    #[test]
    fn copy_tracker_ignores_copies_from_before_a_reset() {
        let mut t = CopyTracker::default();
        let stale = t.start();
        t.reset();
        assert!(!t.possibly_exported());
        assert!(
            !t.settle(stale, true),
            "a stale ticket is reported as stale, so the panel won't fire on_exported"
        );
        assert!(
            !t.possibly_exported(),
            "an old keypair's copy can't mark the new one"
        );
        // And a never-settling copy keeps the warning, deliberately.
        let _pending = t.start();
        assert!(t.possibly_exported());
    }

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
