//! Clipboard writes that work inside the gateway's sandboxed iframe and
//! report what actually happened.
//!
//! The webapp runs in an opaque-origin `<iframe sandbox>`, where
//! `navigator.clipboard` is often missing or rejects (River hit this; the
//! gateway's own shell code says the same). So [`copy_text`] tries, in order:
//!
//! 1. `document.execCommand("copy")` on an off-screen textarea. Works in a
//!    sandboxed iframe during a click and returns whether it succeeded, so
//!    it is the one path that can honestly say "Copied".
//! 2. `navigator.clipboard.writeText`, whose promise also reports success.
//! 3. Inside the gateway shell only: the shell's `{type: "clipboard"}`
//!    postMessage proxy. It is fire-and-forget (no reply, rate-limited by
//!    the shell), so it yields [`CopyOutcome::SentToShell`] rather than
//!    `Copied` and the UI tells the user to check.
//!
//! Call it from inside a click handler: every path needs the transient
//! user activation that a click provides.

/// Result of [`copy_text`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CopyOutcome {
    /// The browser confirmed the text is on the clipboard.
    Copied,
    /// Handed to the Freenet gateway shell, which cannot confirm it.
    #[cfg_attr(not(target_family = "wasm"), allow(dead_code))]
    SentToShell,
    /// Nothing worked. The string says why, for the user.
    Failed(String),
}

/// Copy `text` to the clipboard and call `done` with the outcome. `done`
/// runs synchronously when the first path succeeds, otherwise after the
/// Clipboard API promise settles.
#[cfg(target_family = "wasm")]
pub(crate) fn copy_text(text: String, done: impl FnOnce(CopyOutcome) + 'static) {
    if exec_command_copy(&text) {
        done(CopyOutcome::Copied);
        return;
    }
    wasm_bindgen_futures::spawn_local(async move {
        match clipboard_api_write(&text).await {
            Ok(()) => done(CopyOutcome::Copied),
            Err(api_err) => {
                if shell_proxy_copy(&text) {
                    done(CopyOutcome::SentToShell);
                } else {
                    done(CopyOutcome::Failed(api_err));
                }
            }
        }
    });
}

#[cfg(not(target_family = "wasm"))]
pub(crate) fn copy_text(_text: String, done: impl FnOnce(CopyOutcome) + 'static) {
    done(CopyOutcome::Failed(
        "no clipboard outside the browser".into(),
    ));
}

/// Path 1: select an off-screen textarea and run `execCommand("copy")`.
/// Returns `true` only if the browser reports the copy succeeded.
#[cfg(target_family = "wasm")]
fn exec_command_copy(text: &str) -> bool {
    use wasm_bindgen::JsCast;
    use web_sys::{HtmlDocument, HtmlElement, HtmlTextAreaElement};

    let Some(document) = web_sys::window().and_then(|w| w.document()) else {
        return false;
    };
    let Some(body) = document.body() else {
        return false;
    };
    let Some(textarea) = document
        .create_element("textarea")
        .ok()
        .and_then(|el| el.dyn_into::<HtmlTextAreaElement>().ok())
    else {
        return false;
    };
    // Remember focus so keyboard users land back on the button they pressed.
    let previously_focused = document
        .active_element()
        .and_then(|el| el.dyn_into::<HtmlElement>().ok());
    textarea.set_value(text);
    let _ = textarea.set_attribute("readonly", "");
    let _ = textarea.set_attribute("aria-hidden", "true");
    let _ = textarea.set_attribute(
        "style",
        "position:fixed;top:0;left:-9999px;width:1px;height:1px;opacity:0;",
    );
    if body.append_child(&textarea).is_err() {
        return false;
    }
    textarea.select();
    let ok = document
        .dyn_ref::<HtmlDocument>()
        .and_then(|d| d.exec_command("copy").ok())
        .unwrap_or(false);
    // Clear before removal so the secret doesn't linger in a detached node.
    textarea.set_value("");
    let _ = body.remove_child(&textarea);
    if let Some(el) = previously_focused {
        let _ = el.focus();
    }
    ok
}

/// Path 2: the async Clipboard API, if this context exposes it.
#[cfg(target_family = "wasm")]
async fn clipboard_api_write(text: &str) -> Result<(), String> {
    use wasm_bindgen::JsCast;
    use web_sys::js_sys;

    let window = web_sys::window().ok_or("no browser window")?;
    // `navigator.clipboard` is undefined in insecure or restricted
    // contexts; calling through it unguarded would throw out of wasm.
    let clipboard = js_sys::Reflect::get(&window.navigator(), &"clipboard".into())
        .ok()
        .filter(|v| !v.is_undefined() && !v.is_null())
        .ok_or("this browser blocked clipboard access here")?;
    let clipboard: web_sys::Clipboard = clipboard.unchecked_into();
    wasm_bindgen_futures::JsFuture::from(clipboard.write_text(text))
        .await
        .map(|_| ())
        .map_err(|_| "this browser blocked clipboard access here".to_string())
}

/// Path 3: ask the gateway shell (parent window) to write the clipboard.
/// Returns `false` when not embedded in a shell or the post fails.
#[cfg(target_family = "wasm")]
fn shell_proxy_copy(text: &str) -> bool {
    use web_sys::js_sys;

    let Some(window) = web_sys::window() else {
        return false;
    };
    let Some(parent) = window.parent().ok().flatten() else {
        return false;
    };
    if js_sys::Object::is(parent.as_ref(), window.as_ref()) {
        // Top-level page: no shell to delegate to.
        return false;
    }
    let msg = js_sys::Object::new();
    let set = |k: &str, v: wasm_bindgen::JsValue| js_sys::Reflect::set(&msg, &k.into(), &v).is_ok();
    if !(set("__freenet_shell__", true.into())
        && set("type", "clipboard".into())
        && set("text", text.into()))
    {
        return false;
    }
    parent.post_message(&msg, "*").is_ok()
}
