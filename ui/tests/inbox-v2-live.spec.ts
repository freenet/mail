import { test, expect, type BrowserContext, type Page, type FrameLocator, type Locator } from "@playwright/test";
import { APP_NAME } from "./app-name";
import { TID } from "./testids";

// Inbox v2 between two real nodes, the gateway and the peer of the harness
// (`cargo make test-e2e-inbox-v2`, which publishes this build to them).
// Alice, Carol and Dave live on the gateway, Bob on the peer, so every
// message crosses the network:
//
//  * first contact through Bob's new-contacts queue (Open), then mail both
//    ways by the pass each message carried;
//  * an invite letting Carol's first message in by pass;
//  * revoking Alice's pass: her next message is told the pass lapsed and
//    goes to the queue, and still lands;
//  * RequireGhost: Dave, holding no pass, sees the badge with its tier and is
//    told plainly that nothing landed (delivery WITH a proof is the Ghost Key
//    flow, which is not in this build);
//  * a drain with every tab closed: Carol writes while Bob has no page open,
//    and Bob's inbox, read from the gateway, empties anyway (the delegate's
//    own jobs drained it), and Bob finds the message when he opens a page.
//
// Not here: a renewal reaching a contact. A contact pass lives 335 to 395
// days and is renewed at 40 to 60% of that, and nothing shortens it.

const GW = `http://127.0.0.1:${process.env.FREENET_ISO_GW_PORT ?? ""}`;
const PEER = `http://127.0.0.1:${process.env.FREENET_ISO_PEER_PORT ?? ""}`;
const BASE_URL = process.env.FREENET_EMAIL_BASE_URL ?? "";
const CONTRACT_ID = BASE_URL.match(/\/v1\/contract\/web\/([^/]+)\//)?.[1] ?? "";
const PEER_URL = `${PEER}/v1/contract/web/${CONTRACT_ID}/`;
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
  await app(page).locator(".sheet-x").click();
  return { waiting, drained };
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
    await sees(peer, "q1 first contact");

    // 2. Passes: Bob's reply goes by the pass Alice's message carried, and
    // Alice's next by the one Bob's reply carried.
    await expect(await addContact(peer, alice, "alice")).toContainText("Added alice");
    await closeSettings(peer);
    out = await send(peer, "alice", "p1 reply");
    await expect(out).toHaveText(/^Delivered to alice\./);
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

    // 6. Every tab of Bob's closed: Carol writes (her invite's second
    // message), and Bob's own node drains it with no page open.
    await peerCtx.close();
    await openIdentity(gw, n.carol);
    const before = await inboxOf(gw, bob);
    expect(before.waiting, "Bob's page drained everything before it closed").toBe(0);
    out = await send(gw, bob, "t1 while closed");
    await expect(out).toHaveAttribute("data-delivered", "true");
    // Bob's node may drain at once (its delegate follows the inbox) or at the
    // next `rescan` wake-up; either way no page of his is open.
    const deadline = Date.now() + TAB_CLOSED_WAIT_MS;
    let now = before;
    while (Date.now() < deadline) {
      now = await inboxOf(gw, bob);
      if (now.drained > before.drained && now.waiting === 0) break;
      await new Promise((r) => setTimeout(r, 15_000));
    }
    console.log(`PROOF tab_closed_drain ${JSON.stringify({ before, after: now })}`);
    expect(now.drained, "Bob's node drained t1 with every tab closed").toBeGreaterThan(
      before.drained,
    );
    expect(now.waiting).toBe(0);
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
