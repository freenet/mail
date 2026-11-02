import {
  test,
  expect,
  type BrowserContext,
  type Page,
} from "@playwright/test";
import * as fs from "node:fs";
import * as path from "node:path";
import { APP_NAME } from "./app-name";

// What the mail delegate's background jobs do on a real node, with no page
// open. Run by `cargo make test-e2e-background`.
//
// Two nodes, so two experiments run side by side:
//
//  * gateway ("wake-up"): one message arrives in a v1 inbox while the
//    delegate has not subscribed to it (no page has loaded since the identity
//    existed), and the tab is closed. The only trigger that can import it is
//    the manifest's `rescan` wake-up. A page opened after that must find it
//    already kept.
//  * peer ("cost"): three messages arrive the same way and a page is opened
//    soon after, before any wake-up, so its own `RunJobs` imports all three.
//    That run's time, and a later run that has nothing to import, give what a
//    scan and a message cost in the node's WASM runtime.
//
// What the node itself does is read from its log (info level only: the
// release build compiles lower levels out), what the delegate did from the
// page's `data-jobs-run` record (ui/src/jobs.rs). Findings are printed as
// `PROOF <key> <json>` lines and written to BACKGROUND_PROOF_OUT.

const ISO_GW_PORT = parseInt(process.env.FREENET_ISO_GW_PORT ?? "7510", 10);
const ISO_PEER_PORT = parseInt(process.env.FREENET_ISO_PEER_PORT ?? "7511", 10);
const GW = `http://127.0.0.1:${ISO_GW_PORT}`;
const PEER = `http://127.0.0.1:${ISO_PEER_PORT}`;
const GW_LOG_DIR = process.env.FREENET_ISO_GW_LOG_DIR ?? "";
const PEER_LOG_DIR = process.env.FREENET_ISO_PEER_LOG_DIR ?? "";
const BASE_URL = process.env.FREENET_EMAIL_BASE_URL ?? "";
const CONTRACT_ID = BASE_URL.match(/\/v1\/contract\/web\/([^/]+)\//)?.[1] ?? "";
const PEER_BASE_URL = `${PEER}/v1/contract/web/${CONTRACT_ID}/`;
const OUT = process.env.BACKGROUND_PROOF_OUT ?? "";
// The manifest's `rescan` interval is 900 s; the wait is that plus margin.
const WAKEUP_WAIT_S = parseInt(process.env.BACKGROUND_WAKEUP_WAIT_S ?? "1000", 10);
const IN_CI = !!process.env.CI;

test.describe.configure({ retries: 0 });

type Prompt = { at: number; origin: string; nonce: string; body: unknown };
type JobsRecord = {
  runs: number;
  scanned: number;
  imported: number;
  unknown: number;
  remaining: number;
  ms: number;
  probe_ms: number;
  kept?: number;
  verified?: number;
};

const findings: Record<string, unknown> = {};
function note(key: string, value: unknown) {
  findings[key] = value;
  console.log(`PROOF ${key} ${JSON.stringify(value)}`);
  if (OUT) fs.writeFileSync(OUT, JSON.stringify(findings, null, 2));
}

/** Answer every host prompt with its first button, and remember each one. */
function pump(origin: string, seen: Prompt[]): () => void {
  const answered = new Set<string>();
  const tick = async () => {
    try {
      const res = await fetch(`${origin}/permission/pending`, {
        headers: { Origin: origin },
      });
      if (!res.ok) return;
      for (const p of (await res.json()) as { nonce: string }[]) {
        if (answered.has(p.nonce)) continue;
        answered.add(p.nonce);
        seen.push({ at: Date.now(), origin, nonce: p.nonce, body: p });
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

function logLines(dir: string, needle: RegExp): string[] {
  const out: string[] = [];
  let entries: fs.Dirent[] = [];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const ent of entries) {
    if (!ent.isFile() || !ent.name.startsWith("freenet.")) continue;
    try {
      for (const line of fs.readFileSync(path.join(dir, ent.name), "utf8").split("\n")) {
        if (needle.test(line)) out.push(line);
      }
    } catch {
      // rotated away
    }
  }
  return out;
}

async function brand(page: Page) {
  await expect(
    page.frameLocator("iframe#app").locator(".brand-name").first(),
  ).toContainText(APP_NAME, { timeout: 60_000 });
}

async function createIdentity(page: Page, alias: string) {
  const app = page.frameLocator("iframe#app");
  await brand(page);
  await app.locator('[data-testid="fm-id-create"]').click();
  await app.locator('[data-testid="fm-create-alias-input"]').fill(alias);
  await app.locator('[data-testid="fm-create-submit"]').click();
  await app.locator('[data-testid="fm-create-confirm"]').click();
  await expect(
    app.locator(`[data-testid="fm-id-row"][data-alias="${alias}"]`),
  ).toBeVisible({ timeout: 30_000 });
}

/** alice imports bob's card, then sends `count` messages to bob. */
async function sendMessages(page: Page, alice: string, bob: string, count: number) {
  const app = page.frameLocator("iframe#app");
  await app
    .locator(`[data-testid="fm-id-row"][data-alias="${bob}"] [data-testid="fm-id-share"]`)
    .click();
  const share = app.locator('[data-testid="fm-share-modal"]');
  await share.waitFor({ timeout: 10_000 });
  const card = (await share.getAttribute("data-share-text")) ?? "";
  await share.locator(".modal-x").click();
  await app.locator('[data-testid="fm-contact-import"]').click();
  await app.locator('[data-testid="fm-import-contact-modal"] textarea').fill(card);
  await app.locator('input[placeholder="e.g. Alice (work)"]').fill(bob);
  const verify = app.locator('[data-testid="fm-verify-check"]');
  await verify.waitFor({ timeout: 30_000 });
  await verify.click();
  await app.locator('[data-testid="fm-import-submit"]').click();
  await app
    .locator(`[data-testid="fm-id-row"][data-alias="${alice}"] [data-testid="fm-id-open"]`)
    .first()
    .click();
  const burger = app.locator('[data-testid="fm-hamburger"]');
  for (let i = 1; i <= count; i++) {
    await app.locator('[data-testid="fm-compose-btn"]').click();
    const sheet = app.locator('[data-testid="fm-compose-sheet"]');
    await sheet.locator('input[placeholder="alias or address"]').fill(bob);
    await expect(app.getByTestId("compose-recipient-fingerprint")).toBeVisible({
      timeout: 15_000,
    });
    await sheet.locator('input[placeholder="subject"]').fill(`background ${i}`);
    await sheet.locator("textarea.sheet-textarea").fill(`body ${i}`);
    await sheet.locator('[data-testid="fm-send"]').click();
    await expect(sheet).toHaveCount(0, { timeout: 60_000 });
    if (await burger.isVisible().catch(() => false)) await burger.click();
    await app.locator('[data-testid="fm-folder-sent"]').click();
    await expect(
      app.locator('[data-testid="fm-sent-card"][data-delivery-state="Delivered"]'),
      `message ${i} is delivered`,
    ).toHaveCount(i, { timeout: 120_000 });
    if (await burger.isVisible().catch(() => false)) await burger.click();
    await app.locator('[data-testid="fm-folder-inbox"]').click();
  }
}

/** The page's first background-jobs record, once it exists. */
async function jobsRecord(page: Page, timeoutMs = 120_000): Promise<JobsRecord> {
  const root = page.frameLocator("iframe#app").locator("html");
  await expect(root).toHaveAttribute("data-jobs-run", /./, { timeout: timeoutMs });
  const text = (await root.getAttribute("data-jobs-run")) ?? "{}";
  return JSON.parse(text) as JobsRecord;
}

async function openPage(
  ctx: BrowserContext,
  url: string,
): Promise<Page> {
  const page = await ctx.newPage();
  await page.goto(url);
  await brand(page);
  return page;
}

test("the delegate's background jobs on a real node", async ({ browser }, testInfo) => {
  const cannotRun = !CONTRACT_ID || testInfo.project.name !== "chromium";
  if (cannotRun && IN_CI) {
    throw new Error("the background proof needs `cargo make test-e2e-background`");
  }
  test.skip(cannotRun, "needs `cargo make test-e2e-background`");
  test.setTimeout(60 * 60_000);

  const run = Date.now().toString(36);
  const prompts: Prompt[] = [];
  const stopGw = pump(GW, prompts);
  const stopPeer = pump(PEER, prompts);
  const gwCtx = await browser.newContext();
  const peerCtx = await browser.newContext();
  try {
    const gwPage = await openPage(gwCtx, BASE_URL);
    const peerPage = await openPage(peerCtx, PEER_BASE_URL);
    const registeredAt = Date.now();

    // 1. The manifest is accepted and the Background permission is asked for.
    await expect
      .poll(() => prompts.length, { timeout: 60_000, message: "a host prompt appeared" })
      .toBeGreaterThan(0);
    note(
      "prompts",
      prompts.map((p) => ({ origin: p.origin, body: p.body })),
    );
    const background = prompts.filter((p) => /background/i.test(JSON.stringify(p.body)));
    expect(background.length, "a prompt asks for background permission").toBeGreaterThan(0);

    await expect
      .poll(() => logLines(GW_LOG_DIR, /Arming background delegates' wake-ups/).length, {
        timeout: 60_000,
        message: "the node armed the delegate's wake-ups after the grant",
      })
      .toBeGreaterThan(0);
    note("gw_arming_log", logLines(GW_LOG_DIR, /Arming background delegates' wake-ups/));
    const armedAt = Date.now();

    // 2. Identities, then messages that arrive with nothing subscribed.
    const names = {
      gw: { alice: `ga${run}`, bob: `gb${run}` },
      peer: { alice: `pa${run}`, bob: `pb${run}` },
    };
    await createIdentity(gwPage, names.gw.alice);
    await createIdentity(gwPage, names.gw.bob);
    await createIdentity(peerPage, names.peer.alice);
    await createIdentity(peerPage, names.peer.bob);
    await sendMessages(gwPage, names.gw.alice, names.gw.bob, 1);
    await sendMessages(peerPage, names.peer.alice, names.peer.bob, 3);
    const sentAt = Date.now();
    // What the pages published while they were open: their first run found no
    // identity, so nothing was subscribed.
    note("gw_open_page_run", await jobsRecord(gwPage));
    await gwCtx.close();
    await peerCtx.close();

    // 3. Cost, on the peer: a page opened before any wake-up imports the three.
    const peerCtx2 = await browser.newContext();
    const peerOpen = await openPage(peerCtx2, PEER_BASE_URL);
    const first = await jobsRecord(peerOpen);
    note("peer_first_run", first);
    const steady: JobsRecord[] = [];
    for (let i = 0; i < 3; i++) {
      await peerOpen.reload();
      await brand(peerOpen);
      steady.push(await jobsRecord(peerOpen));
    }
    note("peer_steady_runs", steady);
    await peerCtx2.close();

    // 4. Wake-up, on the gateway: wait for the rescan, then open a page.
    const waitMs = Math.max(0, armedAt + WAKEUP_WAIT_S * 1000 - Date.now());
    note("wakeup_wait_ms", waitMs);
    await new Promise((r) => setTimeout(r, waitMs));
    const gwCtx2 = await browser.newContext();
    const gwOpen = await openPage(gwCtx2, BASE_URL);
    const woke = await jobsRecord(gwOpen);
    note("gw_after_wakeup_first_run", woke);
    note("sent_to_wakeup_check_ms", Date.now() - sentAt);
    note("registered_to_check_ms", Date.now() - registeredAt);
    note("gw_failed_runs", logLines(GW_LOG_DIR, /Lifecycle run failed/));
    await gwCtx2.close();

    // What each experiment must show.
    expect(first.unknown, "the cost run read every inbox").toBe(0);
    expect(woke.imported, "a page's own run had nothing left to import").toBe(0);
    expect(woke.scanned, "the page's run read the inbox").toBe(1);
    expect(woke.unknown, "the inbox was known").toBe(0);
    expect(woke.kept, "the message was kept before any page asked").toBe(1);
    expect(woke.verified, "its signature verified inside the node's WASM").toBe(1);
  } finally {
    stopGw();
    stopPeer();
    await gwCtx.close().catch(() => {});
    await peerCtx.close().catch(() => {});
  }
});
