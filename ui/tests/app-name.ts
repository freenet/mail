// Consumer-facing product name expected by the Playwright suite.
// MUST match `APP_NAME` in ui/src/lib.rs — there is no build-time
// bridge between Rust and TypeScript, so this is the one place on the
// test side. If you rebrand the app, update both constants together.
export const APP_NAME = "Mail";
