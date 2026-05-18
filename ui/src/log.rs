use crate::api::TryNodeAction;

pub(crate) fn _log(msg: impl AsRef<str>) {
    let msg = msg.as_ref();
    #[cfg(target_family = "wasm")]
    {
        web_sys::console::info_1(&serde_wasm_bindgen::to_value(&msg).unwrap());
    }
    let _ = msg;
}

/// Info-level log that goes to the browser console (wasm) and to
/// `tracing` on native builds. Use for one-shot startup banners or
/// build-time diagnostics that should always appear.
pub(crate) fn info(msg: impl AsRef<str>) {
    let msg = msg.as_ref();
    tracing::info!(%msg);
    #[cfg(target_family = "wasm")]
    {
        web_sys::console::info_1(&serde_wasm_bindgen::to_value(&msg).unwrap());
    }
}

macro_rules! debug {
    ($($msg:tt)*) => {{
        #[cfg(debug_assertions)]
        {
            let msg = format!($($msg)*);
            crate::log::__debug_internal(msg)
        }
    }};
}

pub(crate) use debug;

pub(crate) fn __debug_internal(msg: impl AsRef<str>) {
    let msg = msg.as_ref();
    #[cfg(target_family = "wasm")]
    {
        web_sys::console::debug_1(&serde_wasm_bindgen::to_value(&msg).unwrap());
    }
    let _ = msg;
}

/// Build the user-facing toast text for an async local-state write
/// failure. Split from the side-effecting helper so the wording can be
/// unit-tested without spinning up the Dioxus toast runtime (#231, #232).
pub(crate) fn local_state_failure_toast_msg(op: &str) -> String {
    format!("Couldn't {op} — changes may not persist after reload.")
}

/// Build the developer-facing log line for an async local-state write
/// failure. Same split rationale as `local_state_failure_toast_msg`.
pub(crate) fn local_state_failure_log_msg(op: &str, err: impl std::fmt::Display) -> String {
    format!("{op} failed: {err}")
}

/// Log an async local-state write failure AND surface it to the user via an
/// error toast. The optimistic in-memory write made the UI look correct;
/// without this surfacing the persistent write failure is silent and the row
/// silently un-mutates on the next reload (#231, #232).
///
/// `op` is the user-facing verb ("save draft", "delete draft", "mark read",
/// "archive", "save sent", "update delivery state"). The toast reads
/// "Couldn't <op> — changes may not persist after reload."
pub(crate) fn local_state_failure(op: &str, err: impl std::fmt::Display) {
    error(local_state_failure_log_msg(op, err), None);
    crate::toast::push_toast(
        local_state_failure_toast_msg(op),
        crate::toast::ToastLevel::Error,
    );
}

pub(crate) fn error(msg: impl AsRef<str>, action: Option<TryNodeAction>) {
    let error = msg.as_ref();
    if let Some(action) = action {
        tracing::error!(%error, %action);
        #[cfg(target_family = "wasm")]
        {
            let error = format!("error while `{action}`: {error}");
            web_sys::console::error_1(&serde_wasm_bindgen::to_value(&error).unwrap());
        }
    } else {
        tracing::error!(%error);
        #[cfg(target_family = "wasm")]
        {
            web_sys::console::error_1(&serde_wasm_bindgen::to_value(&error).unwrap());
        }
    }
}

#[cfg(test)]
mod local_state_failure_tests {
    use super::{local_state_failure_log_msg, local_state_failure_toast_msg};

    /// Regression for #231/#232: the toast must be a non-empty, user-readable
    /// sentence including the op verb. Pre-fix, these failures only hit
    /// `console.error` — no user surface at all.
    #[test]
    fn toast_msg_contains_op_and_persistence_hint() {
        let msg = local_state_failure_toast_msg("save draft");
        assert!(msg.contains("save draft"), "must name the op: {msg}");
        assert!(
            msg.contains("persist") || msg.contains("reload"),
            "must hint at the data-loss-on-reload failure mode: {msg}"
        );
        assert!(!msg.is_empty());
    }

    /// Log line is the developer signal and must carry both the op verb
    /// and the underlying error text. Without the error text the bug is
    /// undiagnosable from the console alone.
    #[test]
    fn log_msg_includes_op_and_error_detail() {
        let msg = local_state_failure_log_msg("delete draft", "websocket dropped");
        assert!(msg.contains("delete draft"));
        assert!(msg.contains("websocket dropped"));
    }

    /// Covers every op verb wired through `local_state_failure` in the
    /// current codebase. If a new local-state writer is added without a
    /// corresponding toast call site, the verb won't appear here — keeping
    /// the list explicit forces a maintainer to think about it.
    #[test]
    fn all_known_ops_format_distinctly() {
        let ops = [
            "save draft",
            "delete draft",
            "mark message read",
            "archive message",
            "save sent message",
            "update delivery state",
        ];
        let mut msgs: Vec<String> = ops
            .iter()
            .map(|op| local_state_failure_toast_msg(op))
            .collect();
        msgs.sort();
        msgs.dedup();
        assert_eq!(
            msgs.len(),
            ops.len(),
            "each op must produce a distinct toast"
        );
    }
}
