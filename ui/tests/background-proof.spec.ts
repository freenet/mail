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
//  * peer ("notification"): that page run also subscribed the delegate to the
//    peer's inboxes. With the tab closed again, a fourth message arrives, and
//    a page opened a little later finds it already kept. No `rescan` fire can
//    fall in that stretch (see "no rescan" below), so only the subscription's
//    notification can have imported it.
//
// What the node itself does is read from its log (info level only: the
// release build compiles lower levels out), what the delegate did from the
// page's `data-jobs-run` record (ui/src/jobs.rs, built in by the `e2e-probe`
// feature, which `cargo make test-e2e-background` turns on). Findings are printed as
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
// `rescan` first fires within 65 s of the grant, then every 900 s plus up to 10%: the second fire is due by 1055 s.
// No rescan: it cannot fire again before 900 s after the first, so none falls between 65 s and 900 s after the grant.
const FIRST_FIRE_WINDOW_S = 90;
const NO_RESCAN_UNTIL_S = 900;
const WAKEUP_WAIT_S = parseInt(process.env.BACKGROUND_WAKEUP_WAIT_S ?? "1070", 10);
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
  titles?: string[];
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

/** The share card of identity `alias`, read from the home view. */
async function cardOf(page: Page, alias: string): Promise<string> {
  const app = page.frameLocator("iframe#app");
  await app
    .locator(`[data-testid="fm-id-row"][data-alias="${alias}"] [data-testid="fm-id-share"]`)
    .click();
  const share = app.locator('[data-testid="fm-share-modal"]');
  await share.waitFor({ timeout: 10_000 });
  const card = (await share.getAttribute("data-share-text")) ?? "";
  await share.locator(".modal-x").click();
  return card;
}

/**
 * `alice`, on `page`, imports `bob`'s card and sends him `count` messages.
 * Bob lives on the other node: a node's page loads every identity's inbox as
 * its own, so importing an identity of the same node does not look it up.
 */
async function sendMessages(
  page: Page,
  alice: string,
  bob: string,
  card: string,
  count: number,
  delivered = 0,
) {
  const app = page.frameLocator("iframe#app");
  await app.locator('[data-testid="fm-contact-import"]').click();
  await app.locator('[data-testid="fm-import-contact-modal"] textarea').fill(card);
  await app.locator('input[placeholder="e.g. Alice (work)"]').fill(bob);
  const verify = app.locator('[data-testid="fm-verify-check"]');
  await verify.waitFor({ timeout: 90_000 });
  await verify.click();
  await app.locator('[data-testid="fm-import-submit"]').click();
  await sendLoop(page, alice, bob, count, delivered);
}

/**
 * `alice` sends `count` messages to the contact `bob`, who is already in her
 * address book, when `delivered` messages of hers are already delivered.
 */
async function sendLoop(
  page: Page,
  alice: string,
  bob: string,
  count: number,
  delivered: number,
) {
  const app = page.frameLocator("iframe#app");
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
    await sheet.locator('input[placeholder="subject"]').fill(`background ${delivered + i}`);
    await sheet.locator("textarea.sheet-textarea").fill(`body ${delivered + i}`);
    await sheet.locator('[data-testid="fm-send"]').click();
    await expect(sheet).toHaveCount(0, { timeout: 60_000 });
    // The page counts the send as unfinished work from the Send click until
    // the recipient's inbox answers it, and that stretch includes the node's
    // permission prompt for the token. The node's overlay for that prompt
    // can appear over the app frame in the instant between Playwright's
    // hit-target check and the click, and then swallows the click (it is
    // outside the frame, so Playwright does not see it): the click is "done",
    // the folder never changes, and the wait below sees no sent card for its
    // whole timeout. So go to Sent only once the send is over.
    await expect(
      app.locator("html"),
      `message ${i} is answered by the recipient's inbox`,
    ).toHaveAttribute("data-pending-saves", "0", { timeout: 120_000 });
    if (await burger.isVisible().catch(() => false)) await burger.click();
    await app.locator('[data-testid="fm-folder-sent"]').click();
    await expect(
      app.locator('[data-testid="fm-sent-card"][data-delivery-state="Delivered"]'),
      `message ${i} is delivered`,
    ).toHaveCount(delivered + i, { timeout: 120_000 });
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
    // The node's own prompt for the capability: it names running with the tab
    // closed, and offers Allow and Not now. One per node.
    const asksBackground = (p: Prompt) =>
      /even with its tab closed/.test(JSON.stringify(p.body));
    await expect
      .poll(() => new Set(prompts.filter(asksBackground).map((p) => p.origin)).size, {
        timeout: 60_000,
        message: "each node asked for the Background permission",
      })
      .toBe(2);
    note(
      "prompts",
      prompts.filter(asksBackground).map((p) => ({ origin: p.origin, body: p.body })),
    );

    // Each node asked once, not once per origin or per load.
    for (const origin of [GW, PEER]) {
      expect(
        prompts.filter((p) => asksBackground(p) && p.origin === origin).length,
        `${origin} asked for the Background permission once`,
      ).toBe(1);
    }

    // The node arms the wake-ups when the grant is stored (it logs that only at
    // a node start). Each one's FIRST fire comes 5 to 65 s later, whatever its
    // interval, and `v1watch` subscribes: so no identity is created until
    // those have passed, or a later notification could import what the
    // `rescan` wake-up is meant to. The window is twice the longest first
    // fire, so a slow node cannot reach the identities first. The next fires
    // are an interval later (900 s plus up to 10%, for `rescan`; 3600 s for
    // `v1watch`).
    const armedAt = Math.max(...prompts.filter(asksBackground).map((p) => p.at));
    note("first_fire_window_s", FIRST_FIRE_WINDOW_S);
    await new Promise((r) =>
      setTimeout(r, Math.max(0, armedAt + FIRST_FIRE_WINDOW_S * 1000 - Date.now())),
    );

    // 2. The sender, on the gateway, and the first receiver, on the peer. Both
    // receivers are on the peer, so a page opened on the gateway to send never
    // subscribes the delegate to anything under test.
    const names = {
      alice: `ga${run}`,
      bob: `pb${run}`,
      wake: `pw${run}`,
    };
    await createIdentity(gwPage, names.alice);
    await createIdentity(peerPage, names.bob);
    const bobCard = await cardOf(peerPage, names.bob);
    await sendMessages(gwPage, names.alice, names.bob, bobCard, 3);
    // What the pages published while they were open: their first run found no
    // identity, so nothing was subscribed.
    const gwBefore = await jobsRecord(gwPage);
    note("gw_open_page_run", gwBefore);
    expect(gwBefore.runs, "no page run happened after the identity existed").toBe(1);
    const peerBefore = await jobsRecord(peerPage);
    note("peer_open_page_run", peerBefore);
    expect(peerBefore.runs, "no page run happened after the identity existed").toBe(1);
    await gwCtx.close();
    await peerCtx.close();

    // 3. Cost: a page opened before any wake-up imports the three, and
    // subscribes the delegate to the inboxes the node holds.
    const peerCtx2 = await browser.newContext();
    const peerOpen = await openPage(peerCtx2, PEER_BASE_URL);
    const first = await jobsRecord(peerOpen);
    note("peer_first_run", first);
    await peerCtx2.close();

    // 3b. Notification: with every tab of the peer closed, a fourth message
    // arrives, and a page opened after it is delivered finds it kept already.
    const gwCtx3 = await browser.newContext();
    const gwSender = await openPage(gwCtx3, BASE_URL);
    await sendLoop(gwSender, names.alice, names.bob, 1, 3);
    await new Promise((r) => setTimeout(r, 20_000));
    const peerCtx3 = await browser.newContext();
    const peerLater = await openPage(peerCtx3, PEER_BASE_URL);
    const notified = await jobsRecord(peerLater);
    note("peer_after_notification_first_run", notified);
    note("notification_check_s_after_prompt", (Date.now() - armedAt) / 1000);
    expect(
      Date.now() - armedAt,
      "the check fell in the stretch where no rescan can fire",
    ).toBeLessThan(NO_RESCAN_UNTIL_S * 1000);
    expect(notified.imported, "the notification imported it before this page ran").toBe(0);
    expect(notified.kept, "all four are kept").toBe(4);
    expect(notified.titles, "the fourth message is among them").toContain("background 4");

    // 4. Wake-up: a second receiver on the peer, made in this page and never
    // loaded by another, so nothing has subscribed the delegate to it (the
    // `v1watch` fires were an hour apart and the first was long ago). A message
    // arrives with every tab of the peer closed; only `rescan` can import it.
    await createIdentity(peerLater, names.wake);
    const wakeCard = await cardOf(peerLater, names.wake);
    await peerCtx3.close();
    await gwSender.reload();
    await brand(gwSender);
    await sendMessages(gwSender, names.alice, names.wake, wakeCard, 1, 4);
    const sentAt = Date.now();
    expect(
      sentAt - armedAt,
      "the message arrived before the second rescan can fire",
    ).toBeLessThan(NO_RESCAN_UNTIL_S * 1000 + 5_000);
    await gwCtx3.close();
    const waitMs = Math.max(0, armedAt + WAKEUP_WAIT_S * 1000 - Date.now());
    note("wakeup_wait_ms", waitMs);
    await new Promise((r) => setTimeout(r, waitMs));
    const peerCtx4 = await browser.newContext();
    const peerOpen4 = await openPage(peerCtx4, PEER_BASE_URL);
    const woke = await jobsRecord(peerOpen4);
    note("peer_after_wakeup_first_run", woke);
    note("sent_to_wakeup_check_ms", Date.now() - sentAt);
    note("registered_to_check_ms", Date.now() - registeredAt);
    const failedRuns = [
      ...logLines(GW_LOG_DIR, /Lifecycle run failed/),
      ...logLines(PEER_LOG_DIR, /Lifecycle run failed/),
    ];
    note("failed_runs", failedRuns);
    expect(failedRuns, "no run the node started failed").toEqual([]);
    expect(
      prompts.filter(asksBackground).length,
      "the permission was asked for exactly once per node, to the end",
    ).toBe(2);

    // Cost: runs with nothing to import give what a scan costs.
    const steady: JobsRecord[] = [];
    for (let i = 0; i < 3; i++) {
      await peerOpen4.reload();
      await brand(peerOpen4);
      steady.push(await jobsRecord(peerOpen4));
    }
    note("peer_steady_runs", steady);
    await peerCtx4.close();

    // What each experiment must show.
    expect(first.unknown, "the cost run read every inbox").toBe(0);
    expect(first.imported, "the page run imported the three").toBe(3);
    expect(first.verified, "and verified their signatures").toBe(3);
    expect(notified.verified, "the notification's import verified too").toBe(4);
    expect(woke.imported, "a page's own run had nothing left to import").toBe(0);
    // Each identity has a v1 inbox and, since the page makes one for every
    // confirmed identity, a v2 inbox; the delegate counts a scan of each
    // inbox the node holds (`watch.rs`, `inbox_jobs.rs`), and `unknown` 0
    // below says the node held all four.
    expect(woke.scanned, "the page run read both identities' v1 and v2 inboxes").toBe(4);
    expect(woke.unknown, "the inboxes were known").toBe(0);
    expect(woke.kept, "the message was kept before any page asked").toBe(5);
    expect(woke.verified, "its signature verified inside the node's WASM").toBe(5);
    // Read from the stored kept copy, not from the live inbox's rows.
    expect(woke.titles?.sort(), "the kept copies are the messages sent").toEqual([
      "background 1",
      "background 2",
      "background 3",
      "background 4",
      "background 5",
    ]);
  } finally {
    stopGw();
    stopPeer();
    await gwCtx.close().catch(() => {});
    await peerCtx.close().catch(() => {});
  }
});
