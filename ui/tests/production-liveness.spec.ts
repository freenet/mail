import { test, expect } from "@playwright/test";

// Production liveness check.
//
// This spec runs against a *deployed* `use-node` webapp served through
// a Freenet gateway. Unlike `email-app.spec.ts`, which assumes the
// offline `example-data,no-sync` build with pre-seeded mock
// identities, the production build starts with an empty identity list
// and requires a running Freenet node to do anything useful. That
// means we can't exercise compose, send, or multi-inbox delivery from
// Playwright alone — the real end-to-end round trip is covered by
// `live-node.spec.ts` (PR B) and the manual 7-step checklist in
// AGENTS.md §"End-to-end testing".
//
// What this spec IS for: proving that the publish pipeline
// (`compress-webapp` → `sign-webapp` → `publish-email` → gateway
// routing) produced a webapp that a browser can load, mount, and
// render the login screen for. It's the fastest check that catches
// the "did we corrupt bytes along the way" class of failures without
// needing a node, identities, or contract state.
//
// baseURL is read from FREENET_EMAIL_BASE_URL by playwright.config.ts
// and pointed at the deployed gateway URL by
// `scripts/smoke-test-production.sh`.

test.describe("Production liveness", () => {
  test("webapp loads and renders the login screen", async ({ page }) => {
    await page.goto("/");

    // The Dioxus root mounts into <div id="main">. The "Mail"
    // heading is part of the LoginHeader component and is the first
    // user-visible proof that the WASM loaded and the app's root
    // component mounted successfully.
    await expect(page.locator("h1")).toContainText("Mail", {
      timeout: 60_000,
    });

    // The "Create new identity" link is rendered by `CreateLinks` when
    // the user has no identified state, which is the initial state on
    // a fresh production build (no localStorage, no mock seeding).
    await expect(page.getByText("Create new identity")).toBeVisible({
      timeout: 10_000,
    });
  });
});
