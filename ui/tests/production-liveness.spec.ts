import { test, expect } from "@playwright/test";
import { APP_NAME } from "./app-name";

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
    // Use "" so the baseURL is used verbatim (including the
    // /v1/contract/web/<id>/ path). page.goto("/") would resolve
    // against the baseURL's origin only and land on the node
    // dashboard at port 7509's root, not the webapp.
    await page.goto("");

    // The Freenet gateway wraps every webapp in a `freenetBridge`
    // iframe shell (id="app", src=`?__sandbox=1`). The actual Dioxus
    // app mounts inside that iframe, so all assertions target the
    // iframe content via frameLocator, not the top-level page.
    const app = page.frameLocator("iframe#app");

    // The APP_NAME heading is part of the LoginHeader component and
    // is the first user-visible proof that the WASM loaded and the
    // app's root component mounted successfully.
    await expect(app.locator("h1")).toContainText(APP_NAME, {
      timeout: 60_000,
    });

    // The "Create new identity" link is rendered by `CreateLinks` when
    // the user has no identified state, which is the initial state on
    // a fresh production build (no localStorage, no mock seeding).
    await expect(app.getByText("Create new identity")).toBeVisible({
      timeout: 10_000,
    });
  });
});
