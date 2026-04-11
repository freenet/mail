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
    // Desktop browsers
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
    {
      name: "firefox",
      use: { ...devices["Desktop Firefox"] },
    },
    {
      name: "webkit",
      use: { ...devices["Desktop Safari"] },
    },
    // Mobile viewports (Chromium engine)
    {
      name: "mobile-chrome",
      use: { ...devices["Pixel 5"] },
    },
    {
      name: "mobile-safari",
      use: { ...devices["iPhone 13"] },
    },
  ],
  // The dev server must already be running:
  // cd ui && dx serve --port 8082 --features example-data,no-sync --no-default-features
});
