import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.ts",
  // The real-node migration spec needs the nodes and seed that
  // `cargo make test-e2e-legacy-migration` sets up, which also sets this. The
  // offline suite does not run it at all (a skip would exit 0), and the task
  // finds no test, which Playwright reports as an error, if the variable is
  // ever dropped.
  testIgnore: [
    ...(process.env.FREENET_LEGACY_SEEDED === "1" ? [] : ["legacy-migration.spec.ts"]),
    // Likewise `cargo make test-e2e-background`, which sets this.
    ...(process.env.FREENET_BACKGROUND_PROOF === "1" ? [] : ["background-proof.spec.ts"]),
    // And `cargo make test-e2e-inbox-v2`.
    ...(process.env.FREENET_INBOX_V2_LIVE === "1" ? [] : ["inbox-v2-live.spec.ts"]),
    // And `cargo make test-e2e-v1-transition`.
    ...(process.env.FREENET_V1_TRANSITION === "1" ? [] : ["v1-transition.spec.ts"]),
  ],
  timeout: 120_000,
  retries: 2,
  use: {
    // Override with FREENET_EMAIL_BASE_URL to run against a deployed
    // webapp (e.g., scripts/smoke-test-production.sh points this at the
    // Freenet gateway URL for the published contract id).
    baseURL: process.env.FREENET_EMAIL_BASE_URL || "http://127.0.0.1:8092",
    navigationTimeout: 30_000,
    actionTimeout: 10_000,
    // A failure that only reproduces in CI is otherwise undiagnosable: the
    // uploaded report then carries the trace (network, console, DOM).
    trace: "on-first-retry",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
    // Mobile viewport reuses the chromium engine — no extra download.
    {
      name: "mobile-chrome",
      use: { ...devices["Pixel 5"] },
    },
    // Firefox and webkit omitted from CI to keep browser install fast.
    // Run locally with: npx playwright test --project=firefox --project=webkit
  ],
  // The dev server must already be running:
  // cd ui && dx serve --port 8092 --features example-data,no-sync --no-default-features
});
