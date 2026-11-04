import { test, expect, type BrowserContext, type Page, type FrameLocator, type Locator } from "@playwright/test";
import * as fs from "node:fs";
import * as path from "node:path";
import { APP_NAME } from "./app-name";
import { TID } from "./testids";

// Inbox v2 between two real nodes, the gateway and the peer of the harness
// (`cargo make test-e2e-inbox-v2`, which publishes this build to them).
// Alice, Carol and Dave live on the gateway, Bob on the peer, so every
// message crosses the network:
//
//  * first contact through Bob's new-contacts queue (Open), which Bob
//    accepts from the queue view (that sends Alice a pass), then mail both
//    ways by pass;
//  * an invite letting Carol's first message in by pass;
//  * revoking Alice's pass: her next message is told the pass lapsed and
//    goes to the queue, and still lands;
//  * RequireGhost under the test Ghost Key master (this build has the
//    `test-ghost-master` feature, so the page's test vault signs and the
//    inbox contract on Bob's node checks the proof): Dave, holding no pass,
//    sees the badge with its tier and is told plainly that nothing landed
//    without a proof; with "Use Ghost Key" his message lands in Bob's queue,
//    Bob accepts him, and his next message goes straight in by pass;
//  * a drain with every tab closed: Carol writes while Bob has no page open,
//    and Bob's inbox, read from the gateway, empties anyway (the delegate's
//    own jobs drained it), and Bob finds the message when he opens a page.
//    The inbox's notification must wake Bob's delegate and drain it within
//    NOTIFY_BOUND_MS; which run drained it is read from the peer's log (the
//    delegate logs each run the node starts, `mail delegate run: woken_by=`).
//    When the notification does not, the test still waits for the `rescan`
//    wake-up, so the run shows whether that fallback works, and then fails.
//
// Not here: a renewal reaching a contact. A contact pass lives 335 to 395
// days and is renewed at 40 to 60% of that, and expiries are day-aligned
// (decision 17), so a test cannot shorten it. A renewal travels the way the
// pass mail above does.

const GW = `http://127.0.0.1:${process.env.FREENET_ISO_GW_PORT ?? ""}`;
const PEER = `http://127.0.0.1:${process.env.FREENET_ISO_PEER_PORT ?? ""}`;
const BASE_URL = process.env.FREENET_EMAIL_BASE_URL ?? "";
const CONTRACT_ID = BASE_URL.match(/\/v1\/contract\/web\/([^/]+)\//)?.[1] ?? "";
const PEER_URL = `${PEER}/v1/contract/web/${CONTRACT_ID}/`;
const PEER_LOG_DIR = process.env.FREENET_ISO_PEER_LOG_DIR ?? "";
// The inbox's notification reaches Bob's delegate, which drains at once.
const NOTIFY_BOUND_MS = 120_000;
// The delegate's `rescan` wake-up comes every 900 s plus up to 10%.
const TAB_CLOSED_WAIT_MS = 1_100_000;

test.describe.configure({ retries: 0 });

const tid = (id: string) => `[data-testid="${id}"]`;

/** Answer every host prompt with its first button (Allow). */
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

const app = (page: Page): FrameLocator => page.frameLocator("iframe#app");

async function open(ctx: BrowserContext, url: string): Promise<Page> {
  const page = await ctx.newPage();
  await page.goto(url);
  await expect(app(page).locator(".brand-name").first()).toContainText(APP_NAME, {
    timeout: 60_000,
  });
  return page;
}

async function createIdentity(page: Page, alias: string) {
  const a = app(page);
  await a.locator(tid(TID.fmIdCreate)).click();
  await a.locator('[data-testid="fm-create-alias-input"]').fill(alias);
  await a.locator('[data-testid="fm-create-submit"]').click();
  await a.locator('[data-testid="fm-create-confirm"]').click();
  await expect(a.locator(`${tid(TID.fmIdRow)}[data-alias="${alias}"]`)).toBeVisible({
    timeout: 60_000,
  });
}

async function openIdentity(page: Page, alias: string) {
  const a = app(page);
  if (await a.locator(tid(TID.fmApp)).isVisible().catch(() => false)) {
    const burger = a.locator(tid(TID.fmHamburger));
    if (await burger.isVisible().catch(() => false)) await burger.click();
    await a.locator(tid(TID.fmLogout)).click();
  }
  await a.locator(`${tid(TID.fmIdRow)}[data-alias="${alias}"] ${tid(TID.fmIdOpen)}`).first().click();
  await a.locator(tid(TID.fmApp)).waitFor({ timeout: 30_000 });
}

async function settings(page: Page) {
  const a = app(page);
  if (!(await a.locator(tid(TID.fmV2AddInput)).isVisible().catch(() => false))) {
    await a.locator(tid(TID.fmSettingsBtn)).click();
    await a.locator(`${tid(TID.fmSettingsNavItem)}[data-screen="address"]`).click();
  }
  await expect(a.locator(tid(TID.fmV2InboxState))).toHaveAttribute("data-ready", "true", {
    timeout: 120_000,
  });
}

async function closeSettings(page: Page) {
  await app(page).locator(tid(TID.fmSettingsBack)).click();
}

async function addressOf(page: Page): Promise<string> {
  await settings(page);
  const shown = (await app(page).locator(tid(TID.fmV2Address)).innerText()).trim();
  await closeSettings(page);
  return shown.slice(shown.lastIndexOf("@") + 1);
}

async function addContact(page: Page, input: string, name: string): Promise<Locator> {
  await settings(page);
  const a = app(page);
  await a.locator(tid(TID.fmV2AddInput)).fill(input);
  await a.locator(tid(TID.fmV2AddName)).fill(name);
  await a.locator(tid(TID.fmV2AddSubmit)).click();
  const result = a.locator(tid(TID.fmV2AddResult));
  await expect(result).toBeVisible({ timeout: 120_000 });
  return result;
}

async function compose(page: Page, to: string, subject: string) {
  const a = app(page);
  const burger = a.locator(tid(TID.fmHamburger));
  if (await burger.isVisible().catch(() => false)) await burger.click();
  await a.locator(tid(TID.fmComposeBtn)).click();
  const sheet = a.locator(tid(TID.fmComposeSheet));
  await sheet.waitFor({ timeout: 10_000 });
  await sheet.locator('input[placeholder="alias or address"]').fill(to);
  await sheet.locator('input[placeholder="subject"]').fill(subject);
  await sheet.locator("textarea.sheet-textarea").fill(`body of ${subject}`);
  return sheet;
}

async function clickSend(page: Page): Promise<Locator> {
  const outcome = app(page).locator(tid(TID.fmV2Outcome));
  const before = Number((await outcome.getAttribute("data-seq", { timeout: 1_000 }).catch(() => null)) ?? "0");
  await app(page).locator(tid(TID.fmSend)).click();
  await expect(outcome).toHaveAttribute("data-seq", String(before + 1), { timeout: 240_000 });
  return outcome;
}

async function send(page: Page, to: string, subject: string): Promise<Locator> {
  await compose(page, to, subject);
  return clickSend(page);
}

/**
 * `subject` waits in the new-contacts queue; accept its sender. A sender who
 * is not a contact yet is saved under the name the form suggests.
 */
async function accepts(page: Page, subject: string, contact = false) {
  await settings(page);
  const a = app(page);
  const row = a.locator(`${tid(TID.fmV2QueueRow)}[data-title="${subject}"]`);
  await expect(row, `${subject} is in the new-contacts queue`).toBeVisible({ timeout: 180_000 });
  await row.locator(tid(TID.fmV2QueueAccept)).click();
  if (!contact) {
    await row.locator(tid(TID.fmV2QueueConfirm)).click();
  }
  await expect(row).toHaveCount(0, { timeout: 240_000 });
  await expect(a.locator(tid(TID.fmV2Queue))).toContainText("Accepted");
  await closeSettings(page);
}

async function sees(page: Page, subject: string) {
  await expect(
    app(page).locator(`${tid(TID.fmList)} article`, { hasText: subject }),
    `${subject} is in the inbox`,
  ).toBeVisible({ timeout: 180_000 });
}

/**
 * The recipient's inbox as `page` reads it: messages held undrained, and
 * messages its owner drained (tombstoned), which grows only when the owner's
 * node signs a drain.
 */
async function inboxOf(page: Page, to: string): Promise<{ waiting: number; drained: number }> {
  const sheet = await compose(page, to, "(not sent)");
  const note = sheet.locator(tid(TID.fmV2RecipientNote));
  await expect(note).toHaveAttribute("data-drained", /\d+/, { timeout: 60_000 });
  const waiting = Number(await note.getAttribute("data-waiting"));
  const drained = Number(await note.getAttribute("data-drained"));
  // Discard, not close: closing keeps the typed draft, and this runs every
  // few seconds for up to 18 minutes.
  await sheet.locator(".foot-actions button", { hasText: "Discard" }).click();
  await expect(sheet).toHaveCount(0);
  return { waiting, drained };
}

/** The runs Bob's node started, from the peer's log (`mail delegate run:`). */
function delegateRuns(): string[] {
  const out: string[] = [];
  let names: string[] = [];
  try {
    names = fs.readdirSync(PEER_LOG_DIR);
  } catch {
    return out;
  }
  // `freenet.error.*` repeats lines of the main log; read the main log only.
  for (const name of names.filter((n) => /^freenet\.\d{4}-\d{2}-\d{2}/.test(n)).sort()) {
    for (const line of fs.readFileSync(path.join(PEER_LOG_DIR, name), "utf8").split("\n")) {
      const at = line.indexOf("mail delegate run: ");
      if (at >= 0) out.push(line);
    }
  }
  return out;
}

/** What woke the first run in `runs` that drained or imported anything. */
function drainedBy(runs: string[]): string | null {
  for (const line of runs) {
    const m = line.match(/woken_by=(\S+) scanned=\d+ imported=(\d+)/);
    if (m && Number(m[2]) > 0) return m[1];
  }
  return null;
}

test("inbox v2 between two nodes", async ({ browser }) => {
  test.skip(!CONTRACT_ID, "needs `cargo make test-e2e-inbox-v2`");
  test.setTimeout(60 * 60_000);
  const stopGw = pump(GW);
  const stopPeer = pump(PEER);
  const gwCtx = await browser.newContext();
  let peerCtx = await browser.newContext();
  try {
    const gw = await open(gwCtx, BASE_URL);
    let peer = await open(peerCtx, PEER_URL);
    const run = Date.now().toString(36).slice(-5);
    const n = { alice: `alice${run}`, carol: `carol${run}`, dave: `dave${run}`, bob: `bob${run}` };
    await createIdentity(gw, n.alice);
    await createIdentity(gw, n.carol);
    await createIdentity(gw, n.dave);
    await createIdentity(peer, n.bob);

    await openIdentity(peer, n.bob);
    const bob = await addressOf(peer);
    await openIdentity(gw, n.alice);
    const alice = await addressOf(gw);
    expect(bob).toHaveLength(36);

    // 1. First contact, Open: Bob's new-contacts queue.
    await expect(await addContact(gw, `${n.bob}@${bob}`, "bob")).toContainText("Added bob");
    await closeSettings(gw);
    let out = await send(gw, "bob", "q1 first contact");
    await expect(out).toHaveAttribute("data-delivered", "true");
    await expect(out).toContainText("new-contacts queue");
    await accepts(peer, "q1 first contact");
    await sees(peer, "q1 first contact");

    // 2. Passes: accepting sent Alice a pass, and kept her as a contact.
    // Bob's reply goes by the pass Alice's message carried, and Alice's next
    // by Bob's.
    out = await send(peer, alice, "p1 reply");
    await expect(out).toHaveText(/^Delivered to [^ ]+\.$/);
    await sees(gw, "p1 reply");
    out = await send(gw, "bob", "p2 by pass");
    await expect(out).toHaveText(/^Delivered to bob\./);
    await sees(peer, "p2 by pass");

    // 3. An invite: Carol's first message goes in by pass.
    await settings(peer);
    await app(peer).locator(tid(TID.fmV2InviteCreate)).click();
    const invite = (await app(peer).locator(tid(TID.fmV2InviteText)).inputValue()).trim();
    await closeSettings(peer);
    await openIdentity(gw, n.carol);
    await expect(await addContact(gw, invite, "")).toContainText(
      "invite lets you write straight to their inbox",
    );
    await closeSettings(gw);
    out = await send(gw, bob, "i1 invited");
    await expect(out).toHaveText(/^Delivered to /);
    await expect(out).not.toContainText("queue");
    await sees(peer, "i1 invited");

    // 4. Revocation: Bob revokes Alice's pass; her next message is told the
    // pass lapsed, goes to the queue, and lands.
    await settings(peer);
    const row = app(peer).locator(`${tid(TID.fmV2ContactRow)}[data-address="${alice}"]`);
    await expect(row.locator(tid(TID.fmV2PassIssued))).toHaveAttribute("data-state", "live", {
      timeout: 60_000,
    });
    await row.locator(tid(TID.fmV2Revoke)).click();
    await expect(row.locator(tid(TID.fmV2PassIssued))).toHaveAttribute("data-state", "revoked", {
      timeout: 120_000,
    });
    await closeSettings(peer);
    await openIdentity(gw, n.alice);
    out = await send(gw, "bob", "r1 after revoke");
    await expect(out).toHaveAttribute("data-delivered", "true");
    await expect(out).toContainText("lapsed");
    await accepts(peer, "r1 after revoke", true);
    await sees(peer, "r1 after revoke");

    // 5. RequireGhost at $5: Dave holds no pass. The badge shows the tier,
    // Send stays enabled, and he is told nothing landed.
    await settings(peer);
    const mode = app(peer).locator(tid(TID.fmV2QuarantineMode));
    await mode.locator('[data-value="ghost-5"]').click();
    await expect(mode).toHaveAttribute("data-mode", "ghost-5", { timeout: 120_000 });
    await closeSettings(peer);
    await openIdentity(gw, n.dave);
    const sheet = await compose(gw, `bob@${bob}`, "g1 needs a key");
    const badge = sheet.locator(tid(TID.fmV2GhostBadge));
    await expect(badge).toHaveAttribute("data-tier", "5", { timeout: 120_000 });
    await expect(app(gw).locator(tid(TID.fmSend))).toBeEnabled();
    out = await clickSend(gw);
    await expect(out).toHaveAttribute("data-delivered", "false");
    await expect(out).toContainText("only with a Ghost Key");

    // With a Ghost Key: the test vault holds one $5 key this app may not use
    // yet; "Use Ghost Key" asks once, and the proof gets the message into
    // Bob's queue on his node. Bob accepts Dave, whose next message goes
    // straight in.
    await compose(gw, `bob@${bob}`, "g2 proven");
    const panel = app(gw).locator(tid(TID.fmV2GhostPanel));
    await expect(panel).toHaveAttribute("data-usable", "1", { timeout: 120_000 });
    await panel.locator(tid(TID.fmV2GhostUse)).click();
    await expect(panel).not.toHaveAttribute("data-chosen", "", { timeout: 60_000 });
    await expect(panel.locator(tid(TID.fmV2GhostDisclosure))).toBeVisible();
    out = await clickSend(gw);
    await expect(out).toHaveAttribute("data-delivered", "true");
    await expect(out).toContainText("new-contacts queue");
    await accepts(peer, "g2 proven");
    await sees(peer, "g2 proven");
    out = await send(gw, `bob@${bob}`, "g3 by pass");
    await expect(out).toHaveText(/^Delivered to bob\./);
    await sees(peer, "g3 by pass");

    // 6. Every tab of Bob's closed: Carol writes (her invite's second
    // message), and Bob's own node drains it with no page open. Bob's page
    // lists g3 once it is stored, and tombstones it in an update after that:
    // wait for the inbox to show nothing waiting before closing the tab, so
    // the tab never closes mid-drain.
    await expect
      .poll(async () => (await inboxOf(gw, bob)).waiting, {
        message: "Bob's page drained everything before it closed",
        timeout: 120_000,
        intervals: [2_000],
      })
      .toBe(0);
    await peerCtx.close();
    await openIdentity(gw, n.carol);
    const before = await inboxOf(gw, bob);
    expect(before.waiting).toBe(0);
    const runsBefore = new Set(delegateRuns());
    out = await send(gw, bob, "t1 while closed");
    await expect(out).toHaveAttribute("data-delivered", "true");
    const sentAt = Date.now();
    const drainedNow = (s: { waiting: number; drained: number }) =>
      s.drained > before.drained && s.waiting === 0;
    // The notification: Bob's delegate follows his inbox, so it drains at once.
    let now = before;
    while (Date.now() < sentAt + NOTIFY_BOUND_MS) {
      now = await inboxOf(gw, bob);
      if (drainedNow(now)) break;
      await new Promise((r) => setTimeout(r, 3_000));
    }
    const byNotification = drainedNow(now);
    // The fallback, its own case: when no notification drained it, the next
    // `rescan` wake-up must. Waited for so a missed notification still says
    // whether the fallback works.
    while (!drainedNow(now) && Date.now() < sentAt + TAB_CLOSED_WAIT_MS) {
      await new Promise((r) => setTimeout(r, 15_000));
      now = await inboxOf(gw, bob);
    }
    const elapsedMs = Date.now() - sentAt;
    const runs = delegateRuns().filter((l) => !runsBefore.has(l));
    const drainPath = drainedBy(runs);
    console.log(
      `PROOF tab_closed_drain ${JSON.stringify({
        before,
        after: now,
        elapsed_ms: elapsedMs,
        within_notify_bound: byNotification,
        drained_by: drainPath,
        runs: runs.map((l) => l.slice(l.indexOf("mail delegate run: "))),
      })}`,
    );
    expect(now.drained, "Bob's node drained t1 with every tab closed").toBeGreaterThan(
      before.drained,
    );
    expect(now.waiting).toBe(0);
    expect(drainPath, "the run that drained t1, from the peer's log").not.toBeNull();
    expect(
      byNotification && drainPath === "notification",
      `the inbox's notification drained t1 within ${NOTIFY_BOUND_MS} ms (drained by ${drainPath} after ${elapsedMs} ms)`,
    ).toBe(true);
    peerCtx = await browser.newContext();
    peer = await open(peerCtx, PEER_URL);
    await openIdentity(peer, n.bob);
    await sees(peer, "t1 while closed");
  } finally {
    stopGw();
    stopPeer();
    await gwCtx.close().catch(() => {});
    await peerCtx.close().catch(() => {});
  }
});
