import { expect, test } from "@playwright/test";
import { APP_NAME } from "./app-name";

// A v0.2.7 user's data arrives in the current UI, on a real node running the
// frozen delegates. Run by `cargo make test-e2e-legacy-migration`, which
// starts fresh nodes and fills the delegates with `tools/v1-node-seed`.
//
// It proves the path: that this client can reach those delegates through the
// node and that what they hold lands, and that after a backup the app clears
// them and still holds the data. The cargo task then reads the delegates to
// check they were cleared. What the walk and scrub do in every other case is
// in `ui/src/migration/tests.rs`.

const SEEDED = process.env.FREENET_LEGACY_SEEDED === "1";
// Set by `cargo make test-e2e-legacy-migration`, which picks free ports. The
// default is the iso harness's own, for running the spec by hand.
const ISO_GW_PORT = parseInt(process.env.FREENET_ISO_GW_PORT ?? "7510", 10);
const ISO_GW_ORIGIN = `http://127.0.0.1:${ISO_GW_PORT}`;
// In CI a spec that cannot run is a failure: a skip exits 0 and would let the
// whole real-node migration pass without running.
const IN_CI = !!process.env.CI;

const ALIAS = "alice";
const ARCHIVED_TITLE = "kept from v0.2.7";
const ARCHIVED_BODY = "this message exists only in the old delegate";

test.describe.configure({ retries: 0 });

test("a v0.2.7 identity and its archive arrive from the frozen delegates", async ({
  page,
}, testInfo) => {
  const cannotRun = !SEEDED || testInfo.project.name !== "chromium";
  if (cannotRun && IN_CI) {
    throw new Error(
      `the legacy migration spec cannot run (seeded=${SEEDED}, project=${testInfo.project.name}): ` +
        "it needs `cargo make test-e2e-legacy-migration`, and the chromium project",
    );
  }
  test.skip(
    cannotRun,
    "needs a seeded node: run `cargo make test-e2e-legacy-migration`",
  );
  // The walk's reads and the first delegate compile take a while, and the
  // identity arrives after the walk, and scrub takes several loads.
  test.setTimeout(480_000);

  // The gateway asks before the delegates run for this page. A request that
  // fails while the node is busy registering a delegate is tried again on the
  // next tick; anything else ends the test, and so does a closed page.
  let pumpError: unknown = null;
  let pumping = false;
  let busyTicks = 0;
  const pump = setInterval(async () => {
    if (pumping || page.isClosed()) return;
    pumping = true;
    try {
      const res = await fetch(`${ISO_GW_ORIGIN}/permission/pending`, {
        headers: { Origin: ISO_GW_ORIGIN },
      });
      if (!res.ok) throw new Error(`permission/pending answered ${res.status}`);
      const prompts = (await res.json()) as { nonce: string }[];
      for (const { nonce } of prompts) {
        const answered = await fetch(`${ISO_GW_ORIGIN}/permission/${nonce}/respond`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Origin: ISO_GW_ORIGIN },
          body: JSON.stringify({ index: 0 }),
        });
        if (!answered.ok) {
          throw new Error(`permission/${nonce}/respond answered ${answered.status}`);
        }
      }
      busyTicks = 0;
    } catch (e) {
      // A refused connection or a 5xx is the node being busy: tolerated for
      // a second of ticks in a row. Anything else is a bug in the pump or
      // the protocol: report it.
      const busy =
        e instanceof TypeError || /answered 5\d\d/.test(String((e as Error)?.message));
      busyTicks += 1;
      if (!busy || busyTicks > 5) pumpError = e;
      return;
    } finally {
      pumping = false;
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

    // The seeded identity has no v1 inbox, so it arrives unconfirmed. Sending
    // asks the user to confirm it, and confirming must resume the send on a
    // real node: the token record is created on the node and the page has to
    // hold it before the send runs. An offline test cannot show this.
    const burger = app.locator('[data-testid="fm-hamburger"]');
    if (await burger.isVisible().catch(() => false)) await burger.click();
    await app.locator('[data-testid="fm-compose-btn"]').click();
    const sheet = app.locator('[data-testid="fm-compose-sheet"]');
    await sheet.locator('input[placeholder="alias or address"]').fill(ALIAS);
    await sheet.locator('input[placeholder="subject"]').fill("sent after confirming");
    await sheet.locator("textarea.sheet-textarea").fill("body after confirming");
    await sheet.locator('[data-testid="fm-send"]').click();
    const prompt = app.locator('[data-testid="fm-confirm-identity"]');
    await expect(prompt, "an unconfirmed identity is asked to confirm").toBeVisible({
      timeout: 15_000,
    });
    await app.locator('[data-testid="fm-confirm-identity-submit"]').click();
    await expect(prompt, "the prompt closes once confirmed").toHaveCount(0, {
      timeout: 60_000,
    });
    await expect(sheet, "the send resumed and the sheet closed").toHaveCount(0, {
      timeout: 30_000,
    });
    if (await burger.isVisible().catch(() => false)) await burger.click();
    await app.locator('[data-testid="fm-folder-sent"]').click();
    const sent = app.locator('[data-testid="fm-sent-card"]');
    await expect(
      sent.filter({ hasText: "sent after confirming" }),
      "the message reaches Sent as delivered",
    ).toHaveAttribute("data-delivery-state", "Delivered", { timeout: 90_000 });
    await expect(
      sent.filter({ hasText: "sent after confirming" }).and(app.locator('[data-delivery-state="Failed"]')),
      "the new message has no Failed row",
    ).toHaveCount(0);
    // The seeded identity has a draft of its own; the one just sent is gone.
    if (await burger.isVisible().catch(() => false)) await burger.click();
    await app.locator('[data-testid="fm-folder-drafts"]').click();
    await expect(
      app.locator('[data-testid="fm-draft-card"]').filter({ hasText: "sent after confirming" }),
      "no draft of the sent message is left",
    ).toHaveCount(0);
    await expect(
      app.locator('[data-testid="fm-draft-card"]').filter({ hasText: "unsent" }),
      "the seeded draft is still there",
    ).toHaveCount(1);

    // Save the recovery key from the notice, then load until the other
    // generation's rows stand as absent and the old copy is cleared.
    await page.goto("");
    const notice = app.locator(`[data-testid="fm-migration-backup"][data-alias="${ALIAS}"]`);
    await expect(notice, "the notice offers the key").toBeVisible({ timeout: 120_000 });
    await notice.click();
    const modal = app.locator('[data-testid="fm-backup-modal"]');
    await modal.locator('[data-testid="fm-backup-reveal"]').click();
    await expect(modal.locator('[data-testid="fm-backup-key"]')).toBeVisible({ timeout: 30_000 });
    await modal.locator('[data-testid="fm-backup-saved"]').click();
    await expect(modal.locator('[data-testid="fm-backup-saved-note"]')).toBeVisible();
    await expect(app.locator("html"), "the stamp is stored").toHaveAttribute(
      "data-pending-saves",
      "0",
      { timeout: 30_000 },
    );

    const report = app.locator('[data-testid="fm-migration-report"]');
    const cleared = /"scrubbed":\{"1000206":true,"206":true\}/;
    await expect(async () => {
      await page.reload();
      await expect(report).toContainText('"scrub_blockers":', { timeout: 60_000, useInnerText: false });
      await expect(report).toContainText(cleared, { timeout: 5_000, useInnerText: false });
    }, "the old copy is cleared").toPass({ timeout: 240_000 });

    await identity.locator('[data-testid="fm-id-open"]').click();
    await app.locator('[data-testid="fm-folder-archive"]').click();
    await expect(card, "the new delegate still holds it").toBeVisible({ timeout: 30_000 });
    // The rest of what was cleared from the old copy: the identity (opened
    // above), the draft, the sent messages and the contact.
    if (await burger.isVisible().catch(() => false)) await burger.click();
    await app.locator('[data-testid="fm-folder-drafts"]').click();
    await expect(
      app.locator('[data-testid="fm-draft-card"]').filter({ hasText: "unsent" }),
      "the draft is still there",
    ).toHaveCount(1, { timeout: 30_000 });
    if (await burger.isVisible().catch(() => false)) await burger.click();
    await app.locator('[data-testid="fm-folder-sent"]').click();
    await expect(
      app.locator('[data-testid="fm-sent-card"]'),
      "the seeded sent message and the one sent here",
    ).toHaveCount(2, { timeout: 30_000 });
    if (await burger.isVisible().catch(() => false)) await burger.click();
    await app.locator('[data-testid="fm-sidebar-contacts"]').click();
    await expect(
      app.locator(".fm-contact-row .alias").filter({ hasText: "bob" }),
      "the contact is still there",
    ).toHaveCount(1, { timeout: 30_000 });
    expect(pumpError, "the permission pump hit an error").toBeNull();
  } finally {
    clearInterval(pump);
  }
});
