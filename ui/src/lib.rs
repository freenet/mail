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

type DynError = Box<dyn std::error::Error + Send + Sync>;

pub fn main() {
    #[cfg(not(target_family = "wasm"))]
    {
        use tracing_subscriber::{filter::LevelFilter, EnvFilter};
        let _e = tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::builder()
                    .with_default_directive(LevelFilter::INFO.into())
                    .from_env_lossy(),
            )
            .try_init();
    }

    dioxus::launch(app::app);
}
