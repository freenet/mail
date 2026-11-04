import { test, expect, type BrowserContext, type Page, type FrameLocator } from "@playwright/test";
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import { APP_NAME } from "./app-name";
import { TID } from "./testids";

// The v1 transition between two real nodes (`cargo make
// test-e2e-v1-transition`). The gateway holds a v0.2.7 user, alice, seeded by
// `tools/v1-node-seed --transition`: her frozen delegates (with `vbob`, a
// contact she verified) and her v0.2.x inbox holding one v0.2.7 message from
// vbob. vbob restores his identity from its recovery key on the peer.
//
//  * the v0.2.7 message in her v1 inbox is imported once, and stays one
//    message across loads;
//  * once vbob has a v2 inbox, alice's page sends him her pass through his
//    new-contacts queue, and he then writes to her by that pass;
//  * at the end of the window (the delegate's test clock, which only a
//    `v1-transition` build has) her v1 inbox is closed: the imported
//    message removed, then `Day365` with the exemption off, signed once:
//    `last_update` does not move on later loads.

const GW_PORT = process.env.FREENET_ISO_GW_PORT ?? "";
const GW = `http://127.0.0.1:${GW_PORT}`;
const PEER = `http://127.0.0.1:${process.env.FREENET_ISO_PEER_PORT ?? ""}`;
const BASE_URL = process.env.FREENET_EMAIL_BASE_URL ?? "";
const CONTRACT_ID = BASE_URL.match(/\/v1\/contract\/web\/([^/]+)\//)?.[1] ?? "";
const PEER_URL = `${PEER}/v1/contract/web/${CONTRACT_ID}/`;
const SEED_BIN = process.env.FREENET_V1_SEED_BIN ?? "";
const BOB_KEY = process.env.FREENET_V1_BOB_KEY ?? "";
const IN_CI = !!process.env.CI;
const V1_TITLE = "sent on v0.2.7 before the move";

test.describe.configure({ retries: 0 });

const tid = (id: string) => `[data-testid="${id}"]`;
const app = (page: Page): FrameLocator => page.frameLocator("iframe#app");

function pump(origin: string): () => void {
  const answered = new Set<string>();
  const tick = async () => {
    try {
      const res = await fetch(`${origin}/permission/pending`, { headers: { Origin: origin } });
      if (!res.ok) return;
      for (const p of (await res.json()) as { nonce: string }[]) {
        if (answered.has(p.nonce)) continue;
        answered.add(p.nonce);
        await fetch(`${origin}/permission/${p.nonce}/respond`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Origin: origin },
          body: JSON.stringify({ index: 0 }),
        });
      }
    } catch {
      // The node can be busy while it registers a delegate.
    }
  };
  const id = setInterval(tick, 200);
  return () => clearInterval(id);
}

/** Alice's v1 inbox as the gateway holds it. */
function v1Inbox(): { messages: number; minimum_tier: string; exemption: boolean; last_update: string } {
  const out = execFileSync(SEED_BIN, [GW_PORT, "--inbox"]).toString().trim().split("\n");
  return JSON.parse(out[out.length - 1]);
}

async function load(ctx: BrowserContext, url: string): Promise<Page> {
  const page = await ctx.newPage();
  // What the page says about the transition, for a failure's diagnosis.
  page.on("console", (m) => {
    if (/transition|end window/.test(m.text())) console.log(`[page] ${m.text()}`);
  });
  await page.goto(url);
  await expect(app(page).locator(".brand-name").first()).toContainText(APP_NAME, {
    timeout: 60_000,
  });
  return page;
}

async function openIdentity(page: Page, alias: string) {
  const a = app(page);
  const row = a.locator(`${tid(TID.fmIdRow)}[data-alias="${alias}"]`);
  await expect(row, `${alias} is listed`).toBeVisible({ timeout: 180_000 });
  await row.locator(tid(TID.fmIdOpen)).first().click();
  await a.locator(tid(TID.fmApp)).waitFor({ timeout: 30_000 });
}

async function addressOf(page: Page): Promise<string> {
  const a = app(page);
  await a.locator(tid(TID.fmSettingsBtn)).click();
  await a.locator(`${tid(TID.fmSettingsNavItem)}[data-screen="address"]`).click();
  await expect(a.locator(tid(TID.fmV2InboxState))).toHaveAttribute("data-ready", "true", {
    timeout: 180_000,
  });
  const shown = (await a.locator(tid(TID.fmV2Address)).innerText()).trim();
  await a.locator(tid(TID.fmSettingsBack)).click();
  return shown.slice(shown.lastIndexOf("@") + 1);
}

async function v1Copies(page: Page): Promise<number> {
  return app(page).locator(`${tid(TID.fmList)} article`, { hasText: V1_TITLE }).count();
}

test("the v1 transition between two nodes", async ({ browser }, testInfo) => {
  const cannotRun = !CONTRACT_ID || !SEED_BIN || !BOB_KEY || testInfo.project.name !== "chromium";
  if (cannotRun && IN_CI) throw new Error("needs `cargo make test-e2e-v1-transition` (chromium)");
  test.skip(cannotRun, "needs `cargo make test-e2e-v1-transition`");
  test.setTimeout(40 * 60_000);
  const stopGw = pump(GW);
  const stopPeer = pump(PEER);
  const gwCtx = await browser.newContext();
  const peerCtx = await browser.newContext();
  try {
    // 1. The v0.2.7 message arrives once.
    expect(v1Inbox().messages, "the seeded inbox holds the message").toBe(1);
    let gw = await load(gwCtx, BASE_URL);
    await openIdentity(gw, "alice");
    await expect
      .poll(() => v1Copies(gw), { timeout: 300_000, message: "imported from the v1 inbox" })
      .toBe(1);
    // A migrated identity has no v2 inbox (so no window yet) until it is
    // confirmed. One whose v1 inbox is on the network arrives confirmed; any
    // other is asked at its first send.
    const a = app(gw);
    const gwBurger = a.locator(tid(TID.fmHamburger));
    if (await gwBurger.isVisible().catch(() => false)) await gwBurger.click();
    await a.locator(tid(TID.fmComposeBtn)).click();
    const own = a.locator(tid(TID.fmComposeSheet));
    await own.locator('input[placeholder="alias or address"]').fill("alice");
    await own.locator('input[placeholder="subject"]').fill("confirming");
    await own.locator("textarea.sheet-textarea").fill("confirming alice");
    await own.locator(tid(TID.fmSend)).click();
    const prompt = a.locator('[data-testid="fm-confirm-identity"]');
    const asked = await prompt
      .waitFor({ state: "visible", timeout: 15_000 })
      .then(() => true)
      .catch(() => false);
    if (asked) {
      await a.locator('[data-testid="fm-confirm-identity-submit"]').click();
      await expect(prompt).toHaveCount(0, { timeout: 60_000 });
    }
    await expect(own, "the send finished").toHaveCount(0, { timeout: 120_000 });
    const alice = await addressOf(gw);
    await gw.close();
    gw = await load(gwCtx, BASE_URL);
    await openIdentity(gw, "alice");
    await expect.poll(() => v1Copies(gw), { timeout: 120_000 }).toBe(1);
    // A later run of the jobs imports nothing more.
    await gw.waitForTimeout(20_000);
    expect(await v1Copies(gw), "still one copy").toBe(1);

    // 2. vbob, verified by alice in v0.2.7, restores on the peer: a v2 inbox.
    const peer = await load(peerCtx, PEER_URL);
    const p = app(peer);
    await p.locator(tid(TID.fmIdRestore)).click();
    await p.locator(tid(TID.fmRestorePaste)).fill(fs.readFileSync(BOB_KEY, "utf8").trim());
    await p.locator(tid(TID.fmRestoreAlias)).fill("vbob");
    await p.locator(tid(TID.fmRestoreSubmit)).click();
    await openIdentity(peer, "vbob");
    const bob = await addressOf(peer);
    expect(bob).toHaveLength(36);

    // Alice's next load sends him her pass through his queue. His node
    // drains it (the public tombstone count of his inbox, read from hers,
    // grows); he then holds a pass for her inbox.
    await gw.close();
    gw = await load(gwCtx, BASE_URL);
    await openIdentity(gw, "alice");
    const ga = app(gw);
    const drained = async () => {
      const b = ga.locator(tid(TID.fmHamburger));
      if (await b.isVisible().catch(() => false)) await b.click();
      await ga.locator(tid(TID.fmComposeBtn)).click();
      const s = ga.locator(tid(TID.fmComposeSheet));
      await s.locator('input[placeholder="alias or address"]').fill(bob);
      const note = s.locator(tid(TID.fmV2RecipientNote));
      await expect(note).toHaveAttribute("data-drained", /\d+/, { timeout: 60_000 });
      const n = Number(await note.getAttribute("data-drained"));
      await s.locator(".foot-actions button", { hasText: "Discard" }).click();
      return n;
    };
    await expect
      .poll(drained, { timeout: 600_000, intervals: [15_000], message: "vbob drained her pass" })
      .toBeGreaterThan(0);
    const burger = p.locator(tid(TID.fmHamburger));
    if (await burger.isVisible().catch(() => false)) await burger.click();
    await p.locator(tid(TID.fmComposeBtn)).click();
    const sheet = p.locator(tid(TID.fmComposeSheet));
    await sheet.locator('input[placeholder="alias or address"]').fill(alice);
    await sheet.locator('input[placeholder="subject"]').fill("t1 by the transition pass");
    await sheet.locator("textarea.sheet-textarea").fill("body of t1");
    const outcome = p.locator(tid(TID.fmV2Outcome));
    await p.locator(tid(TID.fmSend)).click();
    await expect(outcome).toHaveAttribute("data-delivered", "true", { timeout: 240_000 });
    await expect(outcome, "delivered by pass, not through her queue").not.toContainText("queue");
    await expect(
      app(gw).locator(`${tid(TID.fmList)} article`, { hasText: "t1 by the transition pass" }),
      "alice receives it in her inbox",
    ).toBeVisible({ timeout: 240_000 });

    // 3. The end of the window: the test clock, then the close.
    await gw.close();
    gw = await load(gwCtx, `${BASE_URL}?e2e_end_v1_window`);
    await expect
      .poll(() => v1Inbox(), { timeout: 600_000, intervals: [10_000] })
      .toMatchObject({ messages: 0, minimum_tier: "Day365", exemption: false });
    const closedAt = v1Inbox().last_update;
    // Later loads, and their jobs, sign nothing more.
    for (let i = 0; i < 2; i++) {
      await gw.close();
      gw = await load(gwCtx, BASE_URL);
      await openIdentity(gw, "alice");
      await gw.waitForTimeout(20_000);
    }
    expect(v1Inbox().last_update, "signed once").toBe(closedAt);
    expect(await v1Copies(gw), "the imported copy stays").toBe(1);
  } finally {
    stopGw();
    stopPeer();
    await gwCtx.close();
    await peerCtx.close();
  }
});
