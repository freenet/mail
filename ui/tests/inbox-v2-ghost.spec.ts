/**
 * Inbox v2 in the offline build, part 2: the Ghost Key flow in compose and
 * the new-contacts queue view. Ghost Key is the page's test vault (the
 * `test-ghost-master` feature, which offline builds have): it holds the keys
 * of contracts/inbox-v2/tests/fixtures/ghost-keys.txt, whose master the
 * offline inboxes name, and reads what it holds from localStorage
 * `fmail-ghostkeys-mock` (fixture indices: 0 to 3 are $1, 4 to 7 $5, 8 and 9
 * $20). The offline inboxes check a proof as the contract does: the pinned
 * requestor, the payload binding the message, the signature, the chain to
 * the master and the tier, so a message that lands in a RequireGhost inbox
 * carried a proof that passed.
 *
 *   cd ui && dx serve --port 8092 --features example-data,no-sync --no-default-features
 */

import { test, expect, Page, ConsoleMessage, Locator } from "@playwright/test";
import { APP_NAME } from "./app-name";
import { TID } from "./testids";

const tid = (id: string) => `[data-testid="${id}"]`;
const VAULT = "fmail-ghostkeys-mock";

type Vault = { keys: number[]; default?: number | null; granted?: number[]; deny?: boolean; prompts?: number };

async function setVault(page: Page, v: Vault) {
  await page.evaluate(([k, s]) => localStorage.setItem(k, s), [VAULT, JSON.stringify(v)]);
}

async function vault(page: Page): Promise<Vault> {
  return JSON.parse((await page.evaluate((k) => localStorage.getItem(k), VAULT)) ?? "{}");
}

async function waitForApp(page: Page) {
  await page.locator(`.brand-name, ${tid(TID.fmApp)}`).first().waitFor({ timeout: 60_000 });
  await expect(page.locator(".brand-name").first()).toContainText(APP_NAME);
}

async function openNav(page: Page) {
  const burger = page.locator(tid(TID.fmHamburger));
  if (await burger.isVisible().catch(() => false)) {
    await burger.click();
    await page.locator(tid(TID.fmComposeBtn)).waitFor({ state: "visible" });
  }
}

async function selectIdentity(page: Page, alias: string) {
  await page.locator(`${tid(TID.fmIdRow)}[data-alias="${alias}"] ${tid(TID.fmIdOpen)}`).click();
  await page.locator(tid(TID.fmApp)).waitFor({ timeout: 10_000 });
}

async function switchTo(page: Page, alias: string) {
  await openNav(page);
  await page.locator(tid(TID.fmLogout)).click();
  await selectIdentity(page, alias);
}

async function openAddressSettings(page: Page) {
  if (!(await page.locator(tid(TID.fmV2AddInput)).isVisible().catch(() => false))) {
    await page.locator(tid(TID.fmSettingsBtn)).click();
    await page.locator(tid(TID.fmSettingsShell)).waitFor({ timeout: 5_000 });
    await page.locator(`${tid(TID.fmSettingsNavItem)}[data-screen="address"]`).click();
  }
  await expect(page.locator(tid(TID.fmV2InboxState))).toHaveAttribute("data-ready", "true", {
    timeout: 30_000,
  });
}

async function closeSettings(page: Page) {
  await page.locator(tid(TID.fmSettingsBack)).click();
}

async function myAddress(page: Page): Promise<string> {
  await openAddressSettings(page);
  const shown = (await page.locator(tid(TID.fmV2Address)).innerText()).trim();
  await closeSettings(page);
  return shown.slice(shown.lastIndexOf("@") + 1);
}

async function setNewContacts(page: Page, value: string) {
  await openAddressSettings(page);
  const mode = page.locator(tid(TID.fmV2QuarantineMode));
  await mode.locator(`[data-value="${value}"]`).click();
  await expect(mode).toHaveAttribute("data-mode", value, { timeout: 30_000 });
  await closeSettings(page);
}

async function compose(page: Page, to: string, subject: string) {
  await openNav(page);
  await page.locator(tid(TID.fmComposeBtn)).click();
  const sheet = page.locator(tid(TID.fmComposeSheet));
  await sheet.waitFor({ timeout: 5_000 });
  await sheet.locator('input[placeholder="alias or address"]').fill(to);
  await sheet.locator('input[placeholder="subject"]').fill(subject);
  await sheet.locator("textarea.sheet-textarea").fill(`body of ${subject}`);
  return sheet;
}

async function clickSend(page: Page): Promise<Locator> {
  const outcome = page.locator(tid(TID.fmV2Outcome));
  const before = Number((await outcome.getAttribute("data-seq").catch(() => null)) ?? "0");
  await page.locator(tid(TID.fmSend)).click();
  await expect(outcome).toHaveAttribute("data-seq", String(before + 1), { timeout: 60_000 });
  return outcome;
}

function watchConsole(page: Page): string[] {
  const errors: string[] = [];
  page.on("console", (m: ConsoleMessage) => {
    if (m.type() === "error") errors.push(m.text());
  });
  page.on("pageerror", (e) => errors.push(String(e)));
  return errors;
}

/** Load the app with the vault holding `v`, and bob requiring a $5 key. */
async function setup(page: Page, v: Vault): Promise<{ bob: string }> {
  await page.goto("/");
  await waitForApp(page);
  await setVault(page, v);
  await selectIdentity(page, "address2");
  const bob = await myAddress(page);
  await setNewContacts(page, "ghost-5");
  await switchTo(page, "address1");
  return { bob };
}

async function queueCount(page: Page): Promise<number> {
  await openAddressSettings(page);
  const queue = page.locator(tid(TID.fmV2Queue));
  return Number(await queue.getAttribute("data-count"));
}

test.describe("Inbox v2: Ghost Key and the new-contacts queue (offline)", () => {
  test("Use Ghost Key: consent once, the proof gets a first message in", async ({ page }) => {
    const errors = watchConsole(page);
    const { bob } = await setup(page, { keys: [4], default: 4 });

    // The vault holds a key this app may not use yet: offered, not chosen.
    let sheet = await compose(page, `bob@${bob}`, "proven 1");
    const panel = sheet.locator(tid(TID.fmV2GhostPanel));
    await expect(panel).toHaveAttribute("data-usable", "1", { timeout: 30_000 });
    await expect(panel).toHaveAttribute("data-chosen", "");
    await panel.locator(tid(TID.fmV2GhostUse)).click();
    // The vault asked once; the key is now chosen, with what it discloses.
    await expect(panel).not.toHaveAttribute("data-chosen", "", { timeout: 30_000 });
    expect((await vault(page)).prompts).toBe(1);
    await expect(panel.locator(tid(TID.fmV2GhostDisclosure))).toContainText("links this first message");
    await expect(panel.locator(tid(TID.fmV2GhostTier))).toHaveCount(0);
    await expect(page.locator(tid(TID.fmSend))).toBeEnabled();
    let outcome = await clickSend(page);
    await expect(outcome).toHaveAttribute("data-delivered", "true");
    await expect(outcome).toContainText("new-contacts queue");

    // A second message: the key is chosen at once, and nothing asks again.
    sheet = await compose(page, `bob@${bob}`, "proven 2");
    await expect(sheet.locator(tid(TID.fmV2GhostPanel))).not.toHaveAttribute("data-chosen", "", {
      timeout: 30_000,
    });
    outcome = await clickSend(page);
    await expect(outcome).toHaveAttribute("data-delivered", "true");
    expect((await vault(page)).prompts).toBe(1);

    // Both landed in bob's RequireGhost inbox, so both proofs passed its
    // checks, and wait in his new-contacts queue.
    await switchTo(page, "address2");
    await expect.poll(() => queueCount(page), { timeout: 30_000 }).toBe(2);
    const rows = page.locator(tid(TID.fmV2QueueRow));
    await expect(rows.filter({ hasText: "proven 1" })).toHaveCount(1);
    expect(errors).toEqual([]);
  });

  test("the picker: the default key first, a key below the tier said plainly", async ({ page }) => {
    const errors = watchConsole(page);
    const { bob } = await setup(page, { keys: [0, 8], default: 0, granted: [0, 8] });
    await compose(page, `bob@${bob}`, "tiers");
    const panel = page.locator(tid(TID.fmV2GhostPanel));
    const picker = panel.locator(tid(TID.fmV2GhostPicker));
    await expect(picker.locator("option")).toHaveCount(2, { timeout: 30_000 });
    await expect(picker.locator("option:checked")).toContainText("($1)");
    await expect(panel.locator(tid(TID.fmV2GhostTier))).toContainText("$5 or more");
    // Sending with it anyway: refused plainly, and nothing goes out.
    let outcome = await clickSend(page);
    await expect(outcome).toHaveAttribute("data-delivered", "false");
    await expect(outcome).toContainText("your Ghost Key is $1");

    await compose(page, `bob@${bob}`, "tiers 2");
    const value = await picker.locator("option", { hasText: "($20)" }).getAttribute("value");
    await picker.selectOption(value!);
    await expect(panel.locator(tid(TID.fmV2GhostTier))).toHaveCount(0);
    outcome = await clickSend(page);
    await expect(outcome).toHaveAttribute("data-delivered", "true");
    expect(errors).toEqual([]);
  });

  test("a declined prompt and no key to sign with are handled", async ({ page }) => {
    const errors = watchConsole(page);
    const { bob } = await setup(page, { keys: [4], default: 4, deny: true });
    await compose(page, `bob@${bob}`, "declined");
    const panel = page.locator(tid(TID.fmV2GhostPanel));
    await panel.locator(tid(TID.fmV2GhostUse)).click();
    await expect(panel).toContainText("You declined", { timeout: 30_000 });
    // Asked again, the user says yes.
    await setVault(page, { ...(await vault(page)), deny: false });
    await panel.locator(tid(TID.fmV2GhostUse)).click();
    await expect(panel).not.toHaveAttribute("data-chosen", "", { timeout: 30_000 });

    // The key is gone from the vault by the time of sending.
    await setVault(page, { keys: [], default: null });
    const outcome = await clickSend(page);
    await expect(outcome).toHaveAttribute("data-delivered", "false");
    await expect(outcome).toContainText("no Ghost Key that can sign");
    // Declined at send: the key is chosen, then the app may no longer use
    // it, and the user says no when the vault asks.
    await setVault(page, { keys: [4], default: 4, granted: [4] });
    await compose(page, `bob@${bob}`, "declined at send");
    await expect(page.locator(tid(TID.fmV2GhostPanel))).not.toHaveAttribute("data-chosen", "", {
      timeout: 30_000,
    });
    await setVault(page, { keys: [4], default: 4, granted: [], deny: true });
    const declined = await clickSend(page);
    await expect(declined).toHaveAttribute("data-delivered", "false");
    await expect(declined).toContainText("Ghost Key access was declined");
    expect(errors).toEqual([]);
  });

  test("Get a Ghost Key: the draft is saved first and survives the round trip", async ({ page }) => {
    const errors = watchConsole(page);
    const { bob } = await setup(page, { keys: [], default: null });
    const sheet = await compose(page, `bob@${bob}`, "round trip");
    const panel = sheet.locator(tid(TID.fmV2GhostPanel));
    await expect(panel).toHaveAttribute("data-usable", "0", { timeout: 30_000 });
    await expect(panel).toContainText("You have no Ghost Key");
    await panel.locator(tid(TID.fmV2GhostGet)).click();
    const link = panel.locator(tid(TID.fmV2GhostGetLink));
    await expect(link).toBeVisible({ timeout: 30_000 });
    const href = new URL((await link.getAttribute("href"))!);
    expect(href.origin + href.pathname).toBe("https://freenet.org/ghostkey/create/");
    expect(href.searchParams.get("return_to")).toBe("GeQLXXR8sfGe31BNRJoVxkvGUTnBkufJ4gTaoX5NWnU5");
    const route = href.searchParams.get("return_path")!;
    const draft = route.match(/^#\/compose\?draft=([A-Za-z0-9_-]+)$/)?.[1];
    expect(draft, route).toBeTruthy();

    // Away to buy one; the sheet is closed meanwhile.
    await page.locator(".sheet-x").click();
    await expect(page.locator(tid(TID.fmComposeSheet))).toHaveCount(0);
    await setVault(page, { keys: [8], default: 8 });
    // The vault's way back: the route opens the draft as it was, and the
    // panel asks the vault again.
    await page.evaluate((r) => {
      window.location.hash = r;
    }, route);
    const back = page.locator(tid(TID.fmComposeSheet));
    await expect(back).toBeVisible({ timeout: 30_000 });
    await expect(back.locator('input[placeholder="subject"]')).toHaveValue("round trip");
    await expect(back.locator("textarea.sheet-textarea")).toHaveValue("body of round trip");
    await expect(back.locator(tid(TID.fmV2GhostPanel))).toHaveAttribute("data-usable", "1", {
      timeout: 30_000,
    });
    expect(errors).toEqual([]);
  });

  test("the queue: a full queue suggests a Ghost Key; drop and accept", async ({ page }) => {
    const errors = watchConsole(page);
    await page.goto("/?v2-queue-fixture");
    await waitForApp(page);
    await selectIdentity(page, "address1");
    // The fixture fills one identity's queue from the other while it does
    // not drain. Find which.
    let full = "address1";
    await expect
      .poll(
        async () => {
          if ((await queueCount(page)) === 16) return true;
          await closeSettings(page);
          full = full === "address1" ? "address2" : "address1";
          await switchTo(page, full);
          return false;
        },
        { timeout: 60_000, intervals: [1_000] },
      )
      .toBe(true);
    await expect(page.locator(tid(TID.fmV2QueueTip))).toContainText("filled up");
    const rows = page.locator(tid(TID.fmV2QueueRow));
    await expect(rows).toHaveCount(16);
    // Dropped: gone, and only it.
    await rows.and(page.locator('[data-title="queued 0"]')).locator(tid(TID.fmV2QueueDrop)).click();
    await expect(rows).toHaveCount(15, { timeout: 30_000 });
    await expect(rows.and(page.locator('[data-title="queued 0"]'))).toHaveCount(0);
    // Accepted: the sender's messages move to the inbox.
    const accepted = rows.and(page.locator('[data-title="queued 1"]'));
    await accepted.locator(tid(TID.fmV2QueueAccept)).click();
    await accepted.locator(tid(TID.fmV2QueueConfirm)).click();
    await expect(rows).toHaveCount(0, { timeout: 60_000 });
    await expect(page.locator(tid(TID.fmV2Queue))).toContainText("Accepted");
    await closeSettings(page);
    await expect(page.locator(tid(TID.fmList)).getByText("queued 1", { exact: true })).toBeVisible({
      timeout: 30_000,
    });
    await expect(page.locator(tid(TID.fmList)).getByText("queued 0", { exact: true })).toHaveCount(0);
    expect(errors).toEqual([]);
  });
});
