import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.ts",
  timeout: 120_000,
  retries: 2,
  use: {
    // Override with FREENET_EMAIL_BASE_URL to run against a deployed
    // webapp (e.g., scripts/smoke-test-production.sh points this at the
    // Freenet gateway URL for the published contract id).
    baseURL: process.env.FREENET_EMAIL_BASE_URL || "http://127.0.0.1:8082",
    navigationTimeout: 30_000,
    actionTimeout: 10_000,
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
  // cd ui && dx serve --port 8082 --features example-data,no-sync --no-default-features
});
