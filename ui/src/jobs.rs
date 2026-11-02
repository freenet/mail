//! The page's side of the delegate's background jobs.
//!
//! A node that grants the delegate its Background permission runs the jobs by
//! itself. A node that is older, or whose user declined, does not, so while
//! the page is open it asks the delegate to run them: on load, then every
//! [`PERIOD_MS`]. It is the same planner and the same budgets as a run the
//! node starts (`Op::RunJobs`), so the two cannot disagree about what to do.
//!
//! Each run is spawned, never awaited by anything the user is doing. With the
//! `e2e-probe` feature (the real-node tests' build, never a shipped one) the
//! last one is published as `data-jobs-run` on the document element: its
//! counts, how long the run took, and how long an unrelated delegate call took
//! when it was sent while the run was out (`probe_ms`), which is how long a
//! page's calls wait behind a run. After the first run, and after any run that
//! imported, it also holds how many kept copies the identities have and how
//! many of them carry a valid signature, so a test can see what a run the node
//! started stored.
//!
//! The page cannot tell whether the node granted Background, so it asks on
//! every load: the planner's budgets make a run that finds nothing cheap.

use crate::mail_delegate::{CallError, ops};

/// How often an open page asks, after the first run.
pub(crate) const PERIOD_MS: u32 = 10 * 60 * 1000;
/// Delay before the probe call, so it is sent while the run is out.
#[cfg(feature = "e2e-probe")]
const PROBE_AFTER_MS: u32 = 100;

/// One run: the delegate's reply, and the time it took.
pub(crate) async fn run_once() -> Result<(freenet_mail_protocol::JobsRun, i64), CallError> {
    let started = chrono::Utc::now().timestamp_millis();
    let run = ops::run_jobs().await?;
    Ok((run, chrono::Utc::now().timestamp_millis() - started))
}

/// How long a call that is not part of the jobs waits while one is out.
#[cfg(feature = "e2e-probe")]
async fn probe() -> i64 {
    ops::pause_ms(PROBE_AFTER_MS).await;
    let started = chrono::Utc::now().timestamp_millis();
    let _ = ops::get_status().await;
    chrono::Utc::now().timestamp_millis() - started
}

/// The kept copies of every identity: how many, how many carry a valid
/// signature, and their titles, read from the stored copies themselves.
#[cfg(any(test, feature = "e2e-probe"))]
#[derive(Debug, Default, PartialEq)]
struct Kept {
    kept: u32,
    verified: u32,
    titles: Vec<String>,
}

#[cfg(feature = "e2e-probe")]
async fn kept_summary() -> Option<Kept> {
    let identities = ops::list_identities().await.ok()?;
    let mut out = Kept::default();
    for identity in identities {
        let items = ops::list_all_items(freenet_mail_protocol::ItemKind::Kept, Some(identity.addr))
            .await
            .ok()?;
        for item in items {
            out.kept += 1;
            if let Ok(m) =
                serde_json::from_slice::<freenet_mail_wire_v1::local_state::KeptMessage>(&item.body)
            {
                out.verified += u32::from(m.signature_valid);
                out.titles.push(m.title);
            }
        }
    }
    Some(out)
}

thread_local! {
    /// Whether this page already runs the loop below.
    static STARTED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether the caller is the one to start the loop: true once per page. The
/// identity list is loaded again by the repair paths, and each load would
/// otherwise add a loop.
fn claim_start() -> bool {
    STARTED.with(|s| !s.replace(true))
}

/// Ask for the jobs on load and then periodically, for as long as the page is
/// open. A failed run is logged and the next one is tried at its time.
pub(crate) async fn fallback() {
    if !claim_start() {
        return;
    }
    #[cfg(feature = "e2e-probe")]
    let mut runs: u32 = 0;
    loop {
        #[cfg(feature = "e2e-probe")]
        {
            let (result, probe_ms) = futures::join!(run_once(), probe());
            runs += 1;
            match result {
                Ok((run, ms)) => {
                    let kept = if runs == 1 || run.imported > 0 {
                        kept_summary().await
                    } else {
                        None
                    };
                    publish(runs, &run, ms, probe_ms, kept);
                }
                Err(e) => crate::log::error(format!("background jobs: {e}"), None),
            }
        }
        #[cfg(not(feature = "e2e-probe"))]
        if let Err(e) = run_once().await {
            crate::log::error(format!("background jobs: {e}"), None);
        }
        ops::pause_ms(PERIOD_MS).await;
    }
}

#[cfg(any(test, feature = "e2e-probe"))]
fn describe(
    runs: u32,
    run: &freenet_mail_protocol::JobsRun,
    ms: i64,
    probe_ms: i64,
    kept: Option<Kept>,
) -> String {
    let kept = match kept {
        Some(k) => format!(
            ",\"kept\":{},\"verified\":{},\"titles\":{}",
            k.kept,
            k.verified,
            serde_json::to_string(&k.titles).unwrap_or_default()
        ),
        None => String::new(),
    };
    format!(
        "{{\"runs\":{runs},\"scanned\":{},\"imported\":{},\"unknown\":{},\"remaining\":{},\"ms\":{ms},\"probe_ms\":{probe_ms}{kept}}}",
        run.scanned, run.imported, run.unknown, run.remaining
    )
}

#[cfg(feature = "e2e-probe")]
fn publish(
    runs: u32,
    run: &freenet_mail_protocol::JobsRun,
    ms: i64,
    probe_ms: i64,
    kept: Option<Kept>,
) {
    let text = describe(runs, run, ms, probe_ms, kept);
    crate::log::info(format!("background jobs: {text}"));
    #[cfg(target_family = "wasm")]
    if let Some(root) = web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.document_element())
    {
        let _ = root.set_attribute("data-jobs-run", &text);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_published_record_names_every_count() {
        let run = freenet_mail_protocol::JobsRun {
            scanned: 1,
            imported: 2,
            unknown: 3,
            remaining: 4,
        };
        assert_eq!(
            describe(
                7,
                &run,
                55,
                9,
                Some(Kept {
                    kept: 5,
                    verified: 4,
                    titles: vec!["a".into(), "b".into()],
                })
            ),
            "{\"runs\":7,\"scanned\":1,\"imported\":2,\"unknown\":3,\"remaining\":4,\"ms\":55,\"probe_ms\":9,\"kept\":5,\"verified\":4,\"titles\":[\"a\",\"b\"]}"
        );
        assert!(!describe(7, &run, 55, 9, None).contains("kept"));
    }

    #[test]
    fn the_loop_starts_once_however_often_the_identities_load() {
        assert!(claim_start());
        assert!(!claim_start());
        assert!(!claim_start());
    }
}
