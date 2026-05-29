import { test, expect, Page } from "@playwright/test";
import { TID } from "./testids";

// ─── #270 thread-component storybook ─────────────────────────────────────────
//
// Drives the in-app storybook host (ui/src/app.rs::storybook). The host
// compiles ONLY under `--features example-data` and renders ONLY when the URL
// carries `?story=<name>`, so this spec runs against the same offline
// dev-server the rest of the Playwright suite uses (example-data,no-sync).
//
// Each story builds a hand-crafted `ThreadGroup` (prefilled props, NOT seeded
// mailbox data) and renders the REAL `ThreadDetail` (which branches
// Nested/Compact on the `thread_view` setting the host wires from `?view=`).
//
// Beyond screenshots, the structural assertions make the storybook double as a
// regression test: `.is-me` accent on own messages, the depth-4 cap in the
// nested tree, and the data-thread-view + row-count invariants per view.

async function waitForStory(page: Page) {
  await page
    .locator(`[data-testid="${TID.fmStorybook}"]`)
    .waitFor({ timeout: 60_000 });
  await page
    .locator(`[data-testid="${TID.fmThreadContainer}"]`)
    .waitFor({ timeout: 60_000 });
}

test.describe("#270 thread-component storybook", () => {
  test("story 1 — sender-sent interleaved thread shows .is-me accents", async ({
    page,
  }, testInfo) => {
    await page.goto("/?story=sender-sent-in-thread");
    await waitForStory(page);

    // Own messages (from = logged-in alias "address1") render with the
    // `.is-me` accent in the Nested view.
    await expect(
      page.locator(".ft-nest-msg.is-me").first(),
    ).toBeVisible();
    expect(
      await page.locator(".ft-nest-msg.is-me").count(),
    ).toBeGreaterThanOrEqual(1);

    await page.screenshot({
      path: testInfo.outputPath("storybook-sender-sent.png"),
      fullPage: true,
    });
  });

  test("story 2 — deep-nest clamps at MAX_THREAD_DEPTH (depth-4)", async ({
    page,
  }, testInfo) => {
    await page.goto("/?story=deep-nest");
    await waitForStory(page);

    // A 6-deep in_reply_to chain (0←1←2←3←4←5) clamps at depth 4: the cap
    // class exists, and nothing renders deeper than it.
    await expect(page.locator(".ft-nest-msg.depth-4").first()).toBeVisible();
    expect(await page.locator(".ft-nest-msg.depth-5").count()).toBe(0);

    await page.screenshot({
      path: testInfo.outputPath("storybook-deep-nest.png"),
      fullPage: true,
    });
  });

  test("story 3 (nested) — Nested view rails + quote chips", async ({
    page,
  }, testInfo) => {
    await page.goto("/?story=nested-vs-compact&view=nested");
    await waitForStory(page);

    const container = page.locator(
      `[data-testid="${TID.fmThreadContainer}"]`,
    );
    await expect(container).toHaveAttribute("data-thread-view", "nested");
    await expect(container.locator(".ft-nest")).toHaveCount(1);

    await page.screenshot({
      path: testInfo.outputPath("storybook-nested.png"),
      fullPage: true,
    });
  });

  test("story 3 (compact) — Compact view one row per message", async ({
    page,
  }, testInfo) => {
    await page.goto("/?story=nested-vs-compact&view=compact");
    await waitForStory(page);

    const container = page.locator(
      `[data-testid="${TID.fmThreadContainer}"]`,
    );
    await expect(container).toHaveAttribute("data-thread-view", "compact");
    // One `.ft-cz-row` per message in the thread (the story group has 4).
    await expect(container.locator(".ft-cz-row")).toHaveCount(4);

    await page.screenshot({
      path: testInfo.outputPath("storybook-compact.png"),
      fullPage: true,
    });
  });
});
