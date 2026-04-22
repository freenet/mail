// Under `--no-default-features --features example-data,no-sync` the
// `use-node` flag is off, which makes large swathes of the WebSocket /
// contract-bridge code unreachable. Rather than gate hundreds of items
// individually, we suppress dead-code / unused-import warnings for the
// whole crate when running in offline mode. The default `use-node` build
// is still warning-clean and remains the source of truth for clippy.
#![cfg_attr(
    not(feature = "use-node"),
    allow(dead_code, unused_imports, unused_variables, unused_mut)
)]

extern crate core;

pub(crate) mod aft;
mod api;
mod app;
pub(crate) mod inbox;
pub(crate) mod log;
#[cfg(test)]
pub(crate) mod test_util;

#[allow(dead_code)] // TODO: wire into the Dioxus mount point
const MAIN_ELEMENT_ID: &str = "freenet-email-main";

/// Consumer-facing product name. The text is stored in
/// `ui/branding/app-name.txt` so it's shared verbatim with the
/// Playwright suite (which reads the same file at test time).
/// `trim_ascii` strips the trailing newline so editors can keep the
/// file POSIX-clean. Consumed by `document::Title` in `app::app` and
/// by the login screen heading.
pub(crate) const APP_NAME: &str = include_str!("../branding/app-name.txt").trim_ascii();

/// The base58-encoded `ContractInstanceId` of the signed webapp contract
/// produced by `cargo make update-published-contract`.
///
/// This is the source of truth for "which web-container contract does the
/// UI target" at compile time. Any change to the web-container WASM or to
/// `test-contract/web-container-keys.toml` shifts this ID, and
/// `update-published-contract` must be re-run and the resulting diff
/// committed.
///
/// Under `--no-default-features --features example-data,no-sync` the
/// committed snapshot may be stale or absent, so we fall back to an empty
/// string in offline builds (mirroring how the other contract hashes are
/// handled in `ui/src/inbox.rs` and `ui/src/aft.rs`).
#[cfg(feature = "use-node")]
pub(crate) const WEB_CONTAINER_CONTRACT_ID: &str =
    include_str!("../../published-contract/contract-id.txt");
#[cfg(not(feature = "use-node"))]
pub(crate) const WEB_CONTAINER_CONTRACT_ID: &str = "";

type DynError = Box<dyn std::error::Error + Send + Sync>;

pub fn main() {
    #[cfg(not(target_family = "wasm"))]
    {
        use tracing_subscriber::{EnvFilter, filter::LevelFilter};
        let _e = tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::INFO.into())
                    .from_env_lossy(),
            )
            .try_init();
    }

    // Log which committed contract ID this UI was built against so that
    // a developer looking at devtools can instantly tell whether
    // `published-contract/contract-id.txt` is up to date relative to the
    // source they're staring at. Only meaningful under `use-node`; the
    // offline build's constant is an empty string, see lib.rs:25-33.
    #[cfg(feature = "use-node")]
    {
        let id = WEB_CONTAINER_CONTRACT_ID.trim();
        log::info(format!("web-container contract id (build-embedded): {id}"));
    }

    // In offline mode (`no-sync` / `!use-node`), the WebSocket bridge never
    // runs, so WEB_API_SENDER is never populated. Initialize it with the
    // stub so that components like NewMessageWindow and OpenMessage don't
    // panic on `.get().unwrap()`.
    #[cfg(not(feature = "use-node"))]
    {
        let _ = api::WEB_API_SENDER.set(api::WebApiRequestClient);
    }

    dioxus::launch(app::app);
}
