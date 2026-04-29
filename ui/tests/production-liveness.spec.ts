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
// routing) produced a webapp that a browser can load, mount, render
// the login screen for, *and* loaded its bundled stylesheets. It is
// the fastest check that catches the "did we corrupt bytes along the
// way" class of failures and the "vendored asset path regressed" class
// without needing a node, identities, or contract state.
//
// baseURL is read from FREENET_EMAIL_BASE_URL by playwright.config.ts
// and pointed at the deployed gateway URL by
// `scripts/smoke-test-production.sh`.

// Skip the whole suite outside of `scripts/smoke-test-production.sh`.
// The offline dev server used by CI (`dx serve` with example-data,no-sync
// on :8082) does not wrap the webapp in the freenetBridge iframe shell,
// so the iframe-targeted assertions below would always fail there. The
// only intended runner is the smoke-test script, which sets
// FREENET_EMAIL_BASE_URL to the deployed gateway URL.
test.describe("Production liveness", () => {
  test.skip(
    !process.env.FREENET_EMAIL_BASE_URL ||
      !process.env.FREENET_EMAIL_BASE_URL.includes("/v1/contract/web/"),
    "production-liveness only runs against a deployed gateway URL " +
      "(set FREENET_EMAIL_BASE_URL=http://<host>:7509/v1/contract/web/<id>/ " +
      "or use scripts/smoke-test-production.sh)",
  );

  test("webapp loads, renders the login screen, and styles apply", async ({
    page,
  }) => {
    // Capture console errors so we can fail loud on CSP violations,
    // missing assets, or WASM panics that would otherwise silently
    // degrade the UI.
    const consoleErrors: string[] = [];
    page.on("console", (msg) => {
      if (msg.type() === "error") consoleErrors.push(msg.text());
    });

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
    const heading = app.locator("h1");
    await expect(heading).toContainText(APP_NAME, { timeout: 60_000 });

    // The "Create new identity" link is rendered by `CreateLinks` when
    // the user has no identified state, which is the initial state on
    // a fresh production build (no localStorage, no mock seeding).
    await expect(app.getByText("Create new identity")).toBeVisible({
      timeout: 10_000,
    });

    // Bulma's `.title` class sets `font-weight: 600` while the user-agent
    // default for h1 is `bold` (700). The value flips iff the vendored
    // stylesheet failed to load (CSP block, missing file, path regression).
    const fontWeight = await heading.evaluate(
      (el) => getComputedStyle(el).fontWeight,
    );
    expect(
      fontWeight,
      "Bulma's .title sets font-weight: 600. A different value " +
        "almost certainly means vendor/css/bulma.min.css did not load " +
        "(CSP block, missing asset, or path regression).",
    ).toBe("600");

    // Fail on any console error. CSP-blocked assets and WASM errors
    // both surface here, so this is the cheapest catch-all for the
    // class of regressions that don't break the DOM but break the UX.
    expect(
      consoleErrors,
      `unexpected console errors:\n  ${consoleErrors.join("\n  ")}`,
    ).toEqual([]);
  });
});
