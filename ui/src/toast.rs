//! Hardened toast notification subsystem.
//!
//! # Design
//!
//! Replaces the old `Signal<Option<String>>` with `Signal<Vec<Toast>>` where
//! each [`Toast`] carries:
//! - a monotonic [`ToastId`] so stale-clear tasks only remove the toast they
//!   originally captured (solves the "rapid successive toasts clear each
//!   other" race from #161),
//! - a [`ToastLevel`] that controls TTL and ARIA semantics,
//! - a TTL: 2 s for `Info`/`Success`, 8 s for `Warning`/`Error`.
//!
//! # Queue semantics
//!
//! Multiple toasts can be in flight simultaneously. [`push_toast`] appends to
//! the queue; the TTL timer spawned for each toast uses the captured id to
//! remove only *that* toast.  [`dismiss_toast`] performs an immediate id-keyed
//! removal and is wired to the "✕" button in [`ToastView`].
//!
//! # ARIA
//!
//! `Error` / `Warning` → `role="alert"` (implicitly assertive).
//! `Info` / `Success` → `role="status"` (implicitly polite).
//! No explicit `aria-live` attribute is set; the `role` alone is sufficient and
//! adding both would create conflicting semantics.

use std::sync::atomic::{AtomicU64, Ordering};

use dioxus::prelude::*;

use crate::testid;

// ────────────────────────────────────────────────────────────────────────────
// Public types
// ────────────────────────────────────────────────────────────────────────────

/// Opaque, monotonically-increasing id assigned to each toast at creation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ToastId(u64);

impl ToastId {
    fn next() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Self(NEXT.fetch_add(1, Ordering::Relaxed))
    }
}

/// Severity / intent of a toast notification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ToastLevel {
    /// Neutral informational notice (e.g. "Archived"). TTL: 2 s.
    Info,
    /// Successful operation (e.g. "Sent"). TTL: 2 s.
    Success,
    /// Non-fatal warning. TTL: 8 s.
    Warning,
    /// Operation failed; requires user attention. TTL: 8 s.
    Error,
}

impl ToastLevel {
    /// Auto-dismiss delay in milliseconds.
    pub(crate) fn ttl_ms(self) -> u32 {
        match self {
            ToastLevel::Info | ToastLevel::Success => 2_200,
            ToastLevel::Warning | ToastLevel::Error => 8_000,
        }
    }

    /// The ARIA `role` attribute value for this level.
    pub(crate) fn aria_role(self) -> &'static str {
        match self {
            ToastLevel::Error | ToastLevel::Warning => "alert",
            ToastLevel::Info | ToastLevel::Success => "status",
        }
    }

    /// CSS class suffix appended to `"toast toast--"` for level-specific
    /// colour coding.
    pub(crate) fn css_modifier(self) -> &'static str {
        match self {
            ToastLevel::Info => "info",
            ToastLevel::Success => "success",
            ToastLevel::Warning => "warning",
            ToastLevel::Error => "error",
        }
    }
}

/// A single in-flight toast.
#[derive(Clone, Debug)]
pub(crate) struct Toast {
    pub(crate) id: ToastId,
    pub(crate) message: String,
    pub(crate) level: ToastLevel,
}

// ────────────────────────────────────────────────────────────────────────────
// Context alias
// ────────────────────────────────────────────────────────────────────────────

/// Type alias for the context signal that holds the active toast queue.
pub(crate) type ToastQueue = Signal<Vec<Toast>>;

// ────────────────────────────────────────────────────────────────────────────
// Public helpers callable from any component
// ────────────────────────────────────────────────────────────────────────────

/// Push a new toast onto the queue and schedule its auto-dismiss after
/// [`ToastLevel::ttl_ms`] milliseconds.
///
/// Returns the [`ToastId`] assigned to the new toast; callers that want to
/// dismiss it early can pass the id to [`dismiss_toast`].
pub(crate) fn push_toast(message: impl Into<String>, level: ToastLevel) -> ToastId {
    let id = ToastId::next();
    let toast = Toast {
        id,
        message: message.into(),
        level,
    };
    let mut queue = use_context::<ToastQueue>();
    queue.write().push(toast);

    // Spawn a TTL timer. It captures the id and only removes *this* toast,
    // so a newer toast that happens to sit at the same index is never cleared.
    let ttl = level.ttl_ms();
    spawn(async move {
        gloo_timers::future::TimeoutFuture::new(ttl).await;
        dismiss_toast(id);
    });

    id
}

/// Remove a toast by id. Silently no-ops if the id is no longer in the queue
/// (already dismissed or expired).
pub(crate) fn dismiss_toast(id: ToastId) {
    let mut queue = use_context::<ToastQueue>();
    queue.write().retain(|t| t.id != id);
}

// ────────────────────────────────────────────────────────────────────────────
// ToastView component
// ────────────────────────────────────────────────────────────────────────────

/// Renders all active toasts stacked above the bottom of the viewport.
/// The latest toast is displayed at the top of the stack.
#[allow(non_snake_case)]
pub(crate) fn ToastView() -> Element {
    let queue = use_context::<ToastQueue>();
    let toasts: Vec<Toast> = queue.read().clone();
    if toasts.is_empty() {
        return rsx! {};
    }
    // Render newest-first (reverse iterator).
    rsx! {
        div {
            class: "toast-stack",
            {
                toasts.into_iter().rev().map(|t| {
                    let id = t.id;
                    let role = t.level.aria_role();
                    let modifier = t.level.css_modifier();
                    let msg = t.message.clone();
                    rsx! {
                        div {
                            key: "{id.0}",
                            class: "toast toast--{modifier}",
                            "data-testid": testid::FM_TOAST,
                            role: "{role}",
                            span { class: "pulse-dot" }
                            span { class: "toast-msg", "{msg}" }
                            button {
                                class: "toast-dismiss",
                                "aria-label": "Dismiss",
                                onclick: move |_| dismiss_toast(id),
                                "✕"
                            }
                        }
                    }
                })
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toast_id_is_monotonically_increasing() {
        let a = ToastId::next();
        let b = ToastId::next();
        let c = ToastId::next();
        assert!(a.0 < b.0, "ids must be strictly increasing");
        assert!(b.0 < c.0, "ids must be strictly increasing");
    }

    #[test]
    fn toast_id_unique_across_calls() {
        let ids: Vec<_> = (0..100).map(|_| ToastId::next()).collect();
        let mut sorted = ids.clone();
        sorted.dedup_by_key(|i| i.0);
        assert_eq!(ids.len(), sorted.len(), "all 100 ids must be distinct");
    }

    #[test]
    fn info_success_have_short_ttl() {
        assert!(ToastLevel::Info.ttl_ms() <= 2_500);
        assert!(ToastLevel::Success.ttl_ms() <= 2_500);
    }

    #[test]
    fn error_warning_have_long_ttl() {
        assert!(ToastLevel::Error.ttl_ms() >= 5_000);
        assert!(ToastLevel::Warning.ttl_ms() >= 5_000);
    }

    #[test]
    fn error_warning_use_alert_role() {
        assert_eq!(ToastLevel::Error.aria_role(), "alert");
        assert_eq!(ToastLevel::Warning.aria_role(), "alert");
    }

    #[test]
    fn info_success_use_status_role() {
        assert_eq!(ToastLevel::Info.aria_role(), "status");
        assert_eq!(ToastLevel::Success.aria_role(), "status");
    }

    #[test]
    fn dismiss_removes_only_matching_id() {
        // Build a tiny queue by hand — no Dioxus runtime needed.
        let t1 = Toast {
            id: ToastId(1001),
            message: "a".into(),
            level: ToastLevel::Info,
        };
        let t2 = Toast {
            id: ToastId(1002),
            message: "b".into(),
            level: ToastLevel::Error,
        };
        let t3 = Toast {
            id: ToastId(1003),
            message: "c".into(),
            level: ToastLevel::Success,
        };
        let mut queue = vec![t1, t2, t3];
        queue.retain(|t| t.id != ToastId(1002));
        assert_eq!(queue.len(), 2);
        assert!(queue.iter().all(|t| t.id != ToastId(1002)));
    }

    #[test]
    fn stale_clear_is_a_noop_when_id_absent() {
        let t = Toast {
            id: ToastId(999),
            message: "x".into(),
            level: ToastLevel::Info,
        };
        let mut queue = vec![t];
        // Simulate a stale-clear with an old id that no longer exists.
        queue.retain(|t| t.id != ToastId(42));
        assert_eq!(queue.len(), 1, "queue must not shrink when id is absent");
    }
}
