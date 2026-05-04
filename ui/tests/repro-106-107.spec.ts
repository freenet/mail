// Focused repro spec for #106 (disappear-on-click) and #107
// (sent-leaking-into-drafts). Drives the iso 2-node harness with
// extensive console + screenshot logging so each failure points at a
// concrete UI/log state. Not part of the standard CI suite — run
// manually via:
//
//   FREENET_EMAIL_BASE_URL=http://127.0.0.1:7510/v1/contract/web/<id>/ \
//     npx playwright test --config ui/tests/playwright.config.ts \
//     --project=chromium ui/tests/repro-106-107.spec.ts --headed
//
// Or non-headed with traces:
//
//   FREENET_EMAIL_BASE_URL=... npx playwright test \
//     --config ui/tests/playwright.config.ts --project=chromium \
//     ui/tests/repro-106-107.spec.ts --trace on
import { test, expect, type FrameLocator, type Page } from "@playwright/test";
import { APP_NAME } from "./app-name";

const ISO_GW_PORT = parseInt(process.env.FREENET_ISO_GW_PORT ?? "7510", 10);
const ISO_PEER_PORT = parseInt(process.env.FREENET_ISO_PEER_PORT ?? "7511", 10);
const ISO_GW_ORIGIN = `http://127.0.0.1:${ISO_GW_PORT}`;
const ISO_PEER_ORIGIN = `http://127.0.0.1:${ISO_PEER_PORT}`;

const BASE_URL = process.env.FREENET_EMAIL_BASE_URL ?? "";
const CONTRACT_ID_MATCH = BASE_URL.match(/\/v1\/contract\/web\/([^/]+)\//);
const CONTRACT_ID = CONTRACT_ID_MATCH ? CONTRACT_ID_MATCH[1] : "";
const PEER_BASE_URL = CONTRACT_ID
  ? `${ISO_PEER_ORIGIN}/v1/contract/web/${CONTRACT_ID}/`
  : "";

function startPermissionPump(origin: string) {
  let stopped = false;
  void (async () => {
    while (!stopped) {
      try {
        const r = await fetch(`${origin}/permission/pending`);
        if (r.ok) {
          const data = (await r.json()) as { nonce?: string }[];
          for (const item of data) {
            if (item.nonce) {
              await fetch(`${origin}/permission/${item.nonce}/respond`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ index: 0 }),
              }).catch(() => {});
            }
          }
        }
      } catch {
        /* ignore */
      }
      await new Promise((r) => setTimeout(r, 200));
    }
  })();
  return () => {
    stopped = true;
  };
}

function attachConsole(page: Page, label: string, sink: string[]) {
  page.on("console", (m) => {
    sink.push(`[${label}/${m.type()}] ${m.text()}`);
  });
  page.on("pageerror", (e) => {
    sink.push(`[${label}/pageerror] ${e.message}`);
  });
}

async function createIdentity(page: Page, alias: string) {
  const app = page.frameLocator("iframe#app");
  await expect(app.locator(".brand-name").first()).toContainText(APP_NAME, {
    timeout: 60_000,
  });
  await app.locator('[data-testid="fm-id-create"]').click();
  await app.locator('[data-testid="fm-create-alias-input"]').fill(alias);
  await app.locator('[data-testid="fm-create-submit"]').click();
  await app.locator('[data-testid="fm-create-confirm"]').click();
  await expect(
    app.locator(`[data-testid="fm-id-row"][data-alias="${alias}"]`),
    `${alias} surfaces after create`,
  ).toBeVisible({ timeout: 30_000 });
}

async function shareCard(app: FrameLocator): Promise<string> {
  await app.locator('[data-testid="fm-id-share"]').first().click();
  const modal = app.locator('[data-testid="fm-share-modal"]');
  await modal.waitFor({ timeout: 5_000 });
  const card = (await modal.getAttribute("data-share-text")) ?? "";
  await modal.locator(".modal-x").click();
  return card;
}

async function importContact(app: FrameLocator, card: string, label: string) {
  await app.locator('[data-testid="fm-contact-import"]').click();
  await app
    .locator('[data-testid="fm-import-contact-modal"] textarea')
    .fill(card);
  await app
    .locator('input[placeholder="e.g. Alice (work)"]')
    .fill(label);
  // Tick the "I verified these six words" checkbox so the imported
  // contact is marked verified — `verify_on_send` defaults to true so
  // an unverified import would silently drop the send (the compose
  // veil stays up and no toast surfaces). The checkbox only renders
  // once `fingerprint_words` resolves from the card; wait for it.
  const verifyCheck = app.locator('[data-testid="fm-verify-check"]');
  await verifyCheck.waitFor({ timeout: 15_000 });
  await verifyCheck.click();
  await app.locator('[data-testid="fm-import-submit"]').click();
}

async function openIdentity(app: FrameLocator, alias: string) {
  await app
    .locator(
      `[data-testid="fm-id-row"][data-alias="${alias}"] [data-testid="fm-id-open"]`,
    )
    .first()
    .click();
}

async function compose(
  app: FrameLocator,
  to: string,
  subject: string,
  body: string,
) {
  await app.locator('[data-testid="fm-compose-btn"]').click();
  const sheet = app.locator('[data-testid="fm-compose-sheet"]');
  await sheet.locator('input[placeholder="alias or address"]').fill(to);
  await expect(
    app.getByTestId("compose-recipient-fingerprint"),
    `fingerprint resolves for ${to}`,
  ).toBeVisible({ timeout: 30_000 });
  await sheet.locator('input[placeholder="subject"]').fill(subject);
  await sheet.locator("textarea.sheet-textarea").fill(body);
  await sheet.locator('[data-testid="fm-send"]').click();
}

test.describe.configure({ retries: 0 });
test.describe("Repro #106 + #107", () => {
  test.skip(
    !CONTRACT_ID,
    "set FREENET_EMAIL_BASE_URL to the iso gw contract URL",
  );
  test.beforeEach(async ({}, info) => {
    test.skip(
      info.project.name !== "chromium",
      "repro spec runs on chromium only",
    );
  });

  test("alice sends to bob → bob clicks → row disappears (#106) + alice's draft persists (#107)", async ({
    browser,
  }, testInfo) => {
    test.setTimeout(360_000);
    const stopGw = startPermissionPump(ISO_GW_ORIGIN);
    const stopPeer = startPermissionPump(ISO_PEER_ORIGIN);
    const aliceCtx = await browser.newContext();
    const bobCtx = await browser.newContext();
    const alicePage = await aliceCtx.newPage();
    const bobPage = await bobCtx.newPage();

    const aliceLog: string[] = [];
    const bobLog: string[] = [];
    attachConsole(alicePage, "alice", aliceLog);
    attachConsole(bobPage, "bob", bobLog);

    try {
      await Promise.all([alicePage.goto(""), bobPage.goto(PEER_BASE_URL)]);
      await Promise.all([
        createIdentity(alicePage, "alice"),
        createIdentity(bobPage, "bob"),
      ]);

      const aliceApp = alicePage.frameLocator("iframe#app");
      const bobApp = bobPage.frameLocator("iframe#app");

      const bobCard = await shareCard(bobApp);
      await importContact(aliceApp, bobCard, "bob");

      await openIdentity(aliceApp, "alice");
      await openIdentity(bobApp, "bob");

      await compose(aliceApp, "bob", "round one", "first body");

      // Snapshot post-send so we can see what alice sees before any
      // poll on bob (catches drafts-leak in #107 even if cross-node
      // delivery never lands).
      await alicePage.screenshot({
        path: testInfo.outputPath("alice-post-send.png"),
        fullPage: true,
      });
      await bobPage.screenshot({
        path: testInfo.outputPath("bob-post-send.png"),
        fullPage: true,
      });
      const fs = await import("node:fs/promises");

      // Probe alice's Drafts BEFORE waiting on bob. #107 may repro even
      // when cross-node delivery doesn't, because Drafts is alice's
      // local state alone.
      const draftsLink = aliceApp.getByText(/^Drafts$/).first();
      if (await draftsLink.isVisible().catch(() => false)) {
        await draftsLink.click();
        await alicePage.screenshot({
          path: testInfo.outputPath("alice-drafts-immediately.png"),
          fullPage: true,
        });
        const sentInDrafts = await aliceApp
          .getByText(/round one/i)
          .first()
          .isVisible()
          .catch(() => false);
        console.log(
          `[#107 immediate] sent in Drafts after Send: ${sentInDrafts}`,
        );
        // Go back to inbox so the rest of the test can continue.
        const inboxLink = aliceApp.getByText(/^Inbox$/).first();
        if (await inboxLink.isVisible().catch(() => false)) {
          await inboxLink.click();
        }
      }

      // Wait for inbox row on bob.
      const subjectLocator = bobApp.getByText(/round one/i).first();
      let bobReceived = true;
      try {
        await expect(subjectLocator, "bob receives round one").toBeVisible({
          timeout: 90_000,
        });
      } catch (e) {
        bobReceived = false;
        await bobPage.screenshot({
          path: testInfo.outputPath("bob-no-receive-timeout.png"),
          fullPage: true,
        });
        await fs.writeFile(
          testInfo.outputPath("alice-console.log"),
          aliceLog.join("\n"),
        );
        await fs.writeFile(
          testInfo.outputPath("bob-console.log"),
          bobLog.join("\n"),
        );
        console.log("[#106 unreproducible — bob never received]");
        console.log(`bob console tail: ${bobLog.slice(-30).join("\n")}`);
      }
      if (!bobReceived) {
        // Bail before #106 click flow — can't repro click-disappear
        // without a row to click. #107 already probed above.
        return;
      }

      await bobPage.screenshot({
        path: testInfo.outputPath("bob-inbox-pre-click.png"),
        fullPage: true,
      });

      // Click the row on bob.
      await subjectLocator.click();
      // Wait for detail open (detail timestamp surfaces).
      await bobApp
        .locator('[data-testid="fm-detail-time"]')
        .waitFor({ timeout: 10_000 });

      await bobPage.screenshot({
        path: testInfo.outputPath("bob-detail-open.png"),
        fullPage: true,
      });

      // Navigate back to inbox list. There's no testid'd Back button —
      // click the brand to go home then re-enter inbox via the id-row.
      await bobApp.locator(".brand-name").first().click();
      await openIdentity(bobApp, "bob");

      await bobPage.screenshot({
        path: testInfo.outputPath("bob-inbox-post-back.png"),
        fullPage: true,
      });

      // ── #106 assertion: row should still be visible (read=true).
      const stillVisible = await bobApp
        .getByText(/round one/i)
        .first()
        .isVisible()
        .catch(() => false);
      console.log(
        `[#106 result] row visible after click+back: ${stillVisible}`,
      );

      // ── #107 assertion: alice's Drafts should still be empty after
      // sending (also probed immediately above; this re-probes after
      // bob's click round-trip in case the leak is async).
      await alicePage.screenshot({
        path: testInfo.outputPath("alice-pre-drafts.png"),
        fullPage: true,
      });
      const draftsLink2 = aliceApp.getByText(/^Drafts$/).first();
      if (await draftsLink2.isVisible().catch(() => false)) {
        await draftsLink2.click();
      }
      await alicePage.screenshot({
        path: testInfo.outputPath("alice-drafts.png"),
        fullPage: true,
      });
      const draftsHasSent = await aliceApp
        .getByText(/round one/i)
        .first()
        .isVisible()
        .catch(() => false);
      console.log(`[#107 result] sent message in Drafts: ${draftsHasSent}`);

      // Dump console logs to test artifacts for inspection.
      await fs.writeFile(
        testInfo.outputPath("alice-console.log"),
        aliceLog.join("\n"),
      );
      await fs.writeFile(
        testInfo.outputPath("bob-console.log"),
        bobLog.join("\n"),
      );

      // Soft assertions so we always reach the artifact dump.
      expect.soft(stillVisible, "#106: row stays visible after click+back").toBe(true);
      expect.soft(draftsHasSent, "#107: sent message NOT in Drafts").toBe(false);
    } finally {
      await aliceCtx.close().catch(() => {});
      await bobCtx.close().catch(() => {});
      stopGw();
      stopPeer();
    }
  });
});
