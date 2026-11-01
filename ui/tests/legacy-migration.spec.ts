import { expect, test } from "@playwright/test";
import { APP_NAME } from "./app-name";

// A v0.2.7 user's data arrives in the current UI, on a real node running the
// frozen delegates. Run by `cargo make test-e2e-legacy-migration`, which
// starts fresh nodes and fills the delegates with `tools/v1-node-seed`.
//
// It proves the path: that this client can reach those delegates through the
// node and that what they hold lands. What the walk does in every other case
// is in `ui/src/migration/tests.rs`.

const SEEDED = process.env.FREENET_LEGACY_SEEDED === "1";
const ISO_GW_PORT = parseInt(process.env.FREENET_ISO_GW_PORT ?? "7510", 10);
const ISO_GW_ORIGIN = `http://127.0.0.1:${ISO_GW_PORT}`;

const ALIAS = "alice";
const ARCHIVED_TITLE = "kept from v0.2.7";
const ARCHIVED_BODY = "this message exists only in the old delegate";

test.describe.configure({ retries: 0 });

test("a v0.2.7 identity and its archive arrive from the frozen delegates", async ({
  page,
}, testInfo) => {
  test.skip(
    !SEEDED || testInfo.project.name !== "chromium",
    "needs a seeded node: run `cargo make test-e2e-legacy-migration`",
  );
  // The walk's reads and the first delegate compile take a while, and the
  // identity arrives after the walk.
  test.setTimeout(180_000);

  // The gateway asks before the delegates run for this page.
  const pump = setInterval(async () => {
    try {
      const res = await fetch(`${ISO_GW_ORIGIN}/permission/pending`, {
        headers: { Origin: ISO_GW_ORIGIN },
      });
      const prompts = (await res.json()) as { nonce: string }[];
      for (const { nonce } of prompts) {
        await fetch(`${ISO_GW_ORIGIN}/permission/${nonce}/respond`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Origin: ISO_GW_ORIGIN },
          body: JSON.stringify({ index: 0 }),
        });
      }
    } catch {
      // The node can be busy while a delegate registers; the assertions
      // below are what report a failure.
    }
  }, 200);

  try {
    await page.goto("");
    const app = page.frameLocator("iframe#app");
    await expect(app.locator(".brand-name").first()).toContainText(APP_NAME, {
      timeout: 60_000,
    });

    const identity = app.locator(
      `[data-testid="fm-id-row"][data-alias="${ALIAS}"]`,
    );
    await expect(identity, "the identity arrives").toBeVisible({
      timeout: 120_000,
    });
    await identity.locator('[data-testid="fm-id-open"]').click();

    await app.locator('[data-testid="fm-folder-archive"]').click();
    const card = app
      .locator('[data-testid="fm-archive-card"]')
      .filter({ hasText: ARCHIVED_TITLE });
    await expect(card, "the archived message arrives").toBeVisible({
      timeout: 30_000,
    });
    await card.click();
    await expect(app.locator('[data-testid="fm-archive-body"]')).toContainText(
      ARCHIVED_BODY,
    );
  } finally {
    clearInterval(pump);
  }
});
