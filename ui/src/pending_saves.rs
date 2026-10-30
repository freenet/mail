//! Draft saves this page has started and the mail delegate has not yet
//! answered.
//!
//! A save is async: it reaches the delegate over the node's WebSocket a
//! few round trips later. Closing the compose sheet hands its last edit to
//! a task that outlives the sheet, but a reload or a closed tab ends the
//! page, and that task with it, so an edit made just before is lost. The
//! count is published synchronously as `data-pending-saves` on the
//! document element, which is what a test waits on before reloading, and
//! while it is above zero the page asks the browser to warn before
//! leaving (best effort: a sandboxed frame may not be allowed to prompt).

use std::cell::Cell;

thread_local! {
    static PENDING: Cell<u32> = const { Cell::new(0) };
}

/// One save in flight, from when it is scheduled until its task ends
/// (answered, failed, or dropped). Move it into the task doing the save.
#[must_use = "a save is counted only while its guard lives"]
pub(crate) struct PendingSave(());

/// Count a save as in flight until the returned guard is dropped.
pub(crate) fn begin() -> PendingSave {
    let n = PENDING.with(|p| {
        p.set(p.get() + 1);
        p.get()
    });
    publish(n);
    PendingSave(())
}

impl Drop for PendingSave {
    fn drop(&mut self) {
        let n = PENDING.with(|p| {
            p.set(p.get().saturating_sub(1));
            p.get()
        });
        publish(n);
    }
}

/// How many saves are in flight. Read by the browser's leave-page warning.
#[cfg(any(target_family = "wasm", test))]
pub(crate) fn pending() -> u32 {
    PENDING.with(Cell::get)
}

#[cfg(target_family = "wasm")]
fn publish(n: u32) {
    use wasm_bindgen::JsCast;
    use wasm_bindgen::closure::Closure;
    thread_local! {
        static WARN_INSTALLED: Cell<bool> = const { Cell::new(false) };
    }
    let Some(window) = web_sys::window() else {
        return;
    };
    if let Some(root) = window.document().and_then(|d| d.document_element()) {
        let _ = root.set_attribute("data-pending-saves", &n.to_string());
    }
    if n > 0 && !WARN_INSTALLED.with(|w| w.replace(true)) {
        let warn = Closure::<dyn FnMut(web_sys::BeforeUnloadEvent)>::new(
            |e: web_sys::BeforeUnloadEvent| {
                if pending() > 0 {
                    e.prevent_default();
                    e.set_return_value("");
                }
            },
        );
        let _ =
            window.add_event_listener_with_callback("beforeunload", warn.as_ref().unchecked_ref());
        // Lives for the page.
        warn.forget();
    }
}

#[cfg(not(target_family = "wasm"))]
fn publish(_n: u32) {}

#[cfg(test)]
mod tests {
    use super::*;

    /// A save counts from `begin` until its guard drops, however it ends,
    /// and overlapping saves are counted separately.
    #[test]
    fn a_save_counts_until_its_guard_drops() {
        assert_eq!(pending(), 0);
        let a = begin();
        let b = begin();
        assert_eq!(pending(), 2);
        drop(a);
        assert_eq!(pending(), 1);
        drop(b);
        assert_eq!(pending(), 0);
    }
}
