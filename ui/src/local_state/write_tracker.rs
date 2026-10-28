//! Tracks requests to the local-state delegate until the node answers them,
//! so the UI reports a write as done only once it is stored (#286).
//!
//! The node answers every request with a `DelegateResponse` once the delegate
//! has run it, or with an error. Answers carry no request id and may arrive
//! out of order, so this counts: when nothing is unanswered, every request
//! sent so far has been answered. Every request to the delegate is counted,
//! including its registration, so the count is exact.
//!
//! An error that names no delegate cannot be attributed. If one arrives while
//! requests are unanswered, the count can no longer be trusted, and from then
//! on a wait reports [`Stored::Unknown`] rather than risk reporting a write
//! done when it is not. Known limitation: that lasts for the rest of the page
//! session (nothing re-establishes the count); PR B replaces this count with
//! per-request acks.

use futures::channel::oneshot;

/// What became of the writes a waiter was waiting for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stored {
    /// Every request sent before the wait was answered successfully.
    Yes,
    /// A request answered with an error while waiting (possibly this one).
    Failed,
    /// It cannot be known: an answer could not be attributed, or the wait
    /// timed out.
    Unknown,
}

#[derive(Default)]
pub(crate) struct WriteTracker {
    unanswered: usize,
    /// An answer arrived that the count could not account for.
    untrusted: bool,
    waiters: Vec<oneshot::Sender<Stored>>,
}

impl WriteTracker {
    /// A request was sent.
    pub(crate) fn sent(&mut self) -> usize {
        self.unanswered += 1;
        self.unanswered
    }

    /// A request counted with [`Self::sent`] never left (the send failed), so
    /// nothing will answer it.
    pub(crate) fn unsent(&mut self) {
        self.take_answer();
        self.settle_if_idle();
    }

    /// The node answered a request: successfully, or with an error that names
    /// this delegate.
    pub(crate) fn answered(&mut self, ok: bool) -> usize {
        self.take_answer();
        if ok {
            self.settle_if_idle();
        } else {
            // Its write may be the one a waiter is waiting for. Conservative:
            // every pending waiter is told its write may not have been saved.
            self.resolve(Stored::Failed);
        }
        self.unanswered
    }

    /// The node reported an error that names no delegate. It may have been
    /// the answer to one of ours, so the count is no longer exact.
    pub(crate) fn unattributed_error(&mut self) {
        if self.unanswered > 0 {
            self.untrusted = true;
            self.resolve(Stored::Unknown);
        }
    }

    /// Wait for every request sent so far. `Err` carries the outcome when it
    /// is already known.
    pub(crate) fn wait(&mut self) -> Result<oneshot::Receiver<Stored>, Stored> {
        if self.untrusted {
            return Err(Stored::Unknown);
        }
        if self.unanswered == 0 {
            return Err(Stored::Yes);
        }
        let (tx, rx) = oneshot::channel();
        // Drop waiters that gave up (timed out), so they do not accumulate.
        self.waiters.retain(|w| !w.is_canceled());
        self.waiters.push(tx);
        Ok(rx)
    }

    /// Nothing unanswered: every waiter's writes are settled.
    fn settle_if_idle(&mut self) {
        if self.unanswered == 0 {
            let outcome = if self.untrusted {
                Stored::Unknown
            } else {
                Stored::Yes
            };
            self.resolve(outcome);
        }
    }

    fn take_answer(&mut self) {
        if self.unanswered == 0 {
            // Every request is counted, so this means one was not. Logged, not
            // asserted (the tracker is borrowed here): the count is distrusted
            // rather than wrapped, and the e2e test fails on the log line.
            crate::log::info("local-state answer with none unanswered");
            self.untrusted = true;
            self.resolve(Stored::Unknown);
            return;
        }
        self.unanswered -= 1;
    }

    fn resolve(&mut self, outcome: Stored) {
        for waiter in self.waiters.drain(..) {
            let _ = waiter.send(outcome);
        }
    }
}

/// Wait for `rx`, or report [`Stored::Unknown`] once `timeout` completes.
pub(crate) async fn stored_or_timeout(
    wait: Result<oneshot::Receiver<Stored>, Stored>,
    timeout: impl std::future::Future<Output = ()>,
) -> Stored {
    use futures::FutureExt;
    let rx = match wait {
        Ok(rx) => rx,
        Err(known) => return known,
    };
    futures::select! {
        outcome = rx.fuse() => outcome.unwrap_or(Stored::Unknown),
        () = timeout.fuse() => Stored::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::FutureExt;
    use futures::future::{pending, ready};

    fn waiting(tracker: &mut WriteTracker) -> oneshot::Receiver<Stored> {
        tracker.wait().expect("requests are unanswered")
    }

    /// The startup sequence: the node answers the registration too (with an
    /// empty response for the same key), so it must be counted. Otherwise a
    /// write sent before the last startup answer takes that answer as its
    /// own and is reported stored first (#286).
    #[test]
    fn a_write_during_startup_waits_for_its_own_answer() {
        let mut t = WriteTracker::default();
        t.sent(); // RegisterDelegate
        t.sent(); // Init
        t.sent(); // GetAll
        t.answered(true);
        t.answered(true);
        t.sent(); // the user's delete
        let mut rx = waiting(&mut t);
        t.answered(true); // GetAll's answer, not the delete's
        assert_eq!(
            rx.try_recv().unwrap(),
            None,
            "reported before the delete was answered"
        );
        t.answered(true);
        assert_eq!(rx.try_recv().unwrap(), Some(Stored::Yes));
    }

    #[test]
    fn an_error_answer_fails_the_wait() {
        let mut t = WriteTracker::default();
        t.sent();
        t.sent();
        let mut rx = waiting(&mut t);
        t.answered(false);
        assert_eq!(rx.try_recv().unwrap(), Some(Stored::Failed));
        // The count recovers: the other request's answer settles it.
        assert_eq!(t.answered(true), 0);
        assert_eq!(t.wait().unwrap_err(), Stored::Yes);
    }

    #[test]
    fn an_unattributed_error_makes_every_later_wait_unknown() {
        let mut t = WriteTracker::default();
        t.sent();
        let mut rx = waiting(&mut t);
        t.unattributed_error();
        assert_eq!(rx.try_recv().unwrap(), Some(Stored::Unknown));
        t.sent();
        assert_eq!(t.wait().unwrap_err(), Stored::Unknown);
    }

    #[test]
    fn an_unattributed_error_with_nothing_unanswered_changes_nothing() {
        let mut t = WriteTracker::default();
        t.unattributed_error();
        assert_eq!(t.wait().unwrap_err(), Stored::Yes);
    }

    /// A send that fails while a waiter is pending can be the last thing it
    /// was waiting for: the waiter settles then, not at its timeout.
    #[test]
    fn a_failed_send_that_leaves_nothing_unanswered_settles_waiters() {
        let mut t = WriteTracker::default();
        t.sent();
        t.sent();
        let mut rx = waiting(&mut t);
        t.answered(true);
        t.unsent();
        assert_eq!(rx.try_recv().unwrap(), Some(Stored::Yes));
    }

    #[test]
    fn a_failed_send_is_not_waited_for() {
        let mut t = WriteTracker::default();
        t.sent();
        t.unsent();
        assert_eq!(t.wait().unwrap_err(), Stored::Yes);
    }

    #[test]
    fn no_answer_times_out_as_unknown() {
        let mut t = WriteTracker::default();
        t.sent();
        let outcome = stored_or_timeout(t.wait(), ready(())).now_or_never();
        assert_eq!(outcome, Some(Stored::Unknown));
    }

    #[test]
    fn an_answer_before_the_timeout_wins() {
        let mut t = WriteTracker::default();
        t.sent();
        let wait = t.wait();
        t.answered(true);
        let outcome = stored_or_timeout(wait, pending()).now_or_never();
        assert_eq!(outcome, Some(Stored::Yes));
    }

    #[test]
    fn a_timed_out_waiter_does_not_accumulate() {
        let mut t = WriteTracker::default();
        t.sent();
        for _ in 0..10 {
            let _ = stored_or_timeout(t.wait(), ready(())).now_or_never();
        }
        let _live = waiting(&mut t);
        assert_eq!(t.waiters.len(), 1);
    }
}
