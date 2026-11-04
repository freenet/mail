/**
 * Inbox v2 in the offline build (example-data): addresses and labels, an
 * invite, the compose note and its Ghost Key badge, the send outcomes the
 * page can reach without a node, and the warning that an identity is active
 * on another node. The mail delegate is the real one, run in the page; the
 * inboxes are the page's model of the contract. Both identities live in one
 * page, so they are each other's own identities, never contacts: contact
 * rows, passes and revocation between two people are proven on real nodes
 * (inbox-v2-live.spec.ts) and against the delegate in `ui/src/v2/flows.rs`.
 *
 *   cd ui && dx serve --port 8092 --features example-data,no-sync --no-default-features
 */

import { test, expect, Page, ConsoleMessage, Locator } from "@playwright/test";
import { APP_NAME } from "./app-name";
import { TID } from "./testids";

const tid = (id: string) => `[data-testid="${id}"]`;

async function waitForApp(page: Page) {
  await page
    .locator(`.brand-name, ${tid(TID.fmApp)}`)
    .first()
    .waitFor({ timeout: 60_000 });
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
  await page
    .locator(`${tid(TID.fmIdRow)}[data-alias="${alias}"] ${tid(TID.fmIdOpen)}`)
    .click();
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
    await page
      .locator(`${tid(TID.fmSettingsNavItem)}[data-screen="address"]`)
      .click();
  }
  await expect(page.locator(tid(TID.fmV2InboxState))).toHaveAttribute(
    "data-ready",
    "true",
    { timeout: 30_000 },
  );
}

async function closeSettings(page: Page) {
  await page.locator(tid(TID.fmSettingsBack)).click();
}

/** The active identity's address (36 characters, after any `name@`). */
async function myAddress(page: Page): Promise<string> {
  await openAddressSettings(page);
  const shown = (await page.locator(tid(TID.fmV2Address)).innerText()).trim();
  await closeSettings(page);
  const address = shown.slice(shown.lastIndexOf("@") + 1);
  expect(address).toHaveLength(36);
  return address;
}

async function addContact(page: Page, input: string): Promise<Locator> {
  await openAddressSettings(page);
  await page.locator(tid(TID.fmV2AddInput)).fill(input);
  await page.locator(tid(TID.fmV2AddSubmit)).click();
  const result = page.locator(tid(TID.fmV2AddResult));
  await expect(result).toBeVisible({ timeout: 30_000 });
  return result;
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

/** Send what the sheet holds and return the outcome of THIS send. */
async function clickSend(page: Page): Promise<Locator> {
  const outcome = page.locator(tid(TID.fmV2Outcome));
  const before = Number((await outcome.getAttribute("data-seq").catch(() => null)) ?? "0");
  await page.locator(tid(TID.fmSend)).click();
  await expect(outcome).toHaveAttribute("data-seq", String(before + 1), {
    timeout: 60_000,
  });
  return outcome;
}

async function send(page: Page, to: string, subject: string): Promise<Locator> {
  await compose(page, to, subject);
  return clickSend(page);
}

/** A new identity, made from the identity list. */
async function createIdentity(page: Page, alias: string) {
  if (await page.locator(tid(TID.fmApp)).isVisible().catch(() => false)) {
    await openNav(page);
    await page.locator(tid(TID.fmLogout)).click();
  }
  await page.locator(tid(TID.fmIdCreate)).click();
  await page.locator(tid(TID.fmCreateAliasInput)).fill(alias);
  await page.locator(tid(TID.fmCreateSubmit)).click();
  await page.locator(tid(TID.fmCreateConfirm)).click();
  await expect(page.locator(`${tid(TID.fmIdRow)}[data-alias="${alias}"]`)).toBeVisible({
    timeout: 30_000,
  });
}

/** `owner`'s invite, made in its address settings. */
async function inviteOf(page: Page): Promise<string> {
  await openAddressSettings(page);
  await page.locator(tid(TID.fmV2InviteCreate)).click();
  const invite = (await page.locator(tid(TID.fmV2InviteText)).inputValue()).trim();
  await closeSettings(page);
  return invite;
}

const inboxRow = (page: Page, subject: string) =>
  page.locator(`${tid(TID.fmList)} article`, { hasText: subject });

/** Open `subject`'s conversation and return its message row. */
async function openRow(page: Page, subject: string): Promise<Locator> {
  await inboxRow(page, subject).click();
  const container = page.locator(tid(TID.fmThreadContainer));
  await container.waitFor({ state: "attached", timeout: 10_000 });
  return container.locator(tid(TID.fmThreadRow), { hasText: subject }).first();
}

/**
 * Back from an open message to the list. On a phone the list and the
 * message are one screen each, so the list is hidden while a message is
 * open; on a desktop the back button is hidden and the list never was.
 * The synthetic click reaches the button either way.
 */
async function backToList(page: Page) {
  await page.locator(tid(TID.fmBack)).first().dispatchEvent("click");
  await expect(page.locator(tid(TID.fmList))).toBeVisible();
}

/** Collects console errors and page errors, to assert a clean console. */
function watchConsole(page: Page): string[] {
  const errors: string[] = [];
  page.on("console", (m: ConsoleMessage) => {
    if (m.type() === "error") errors.push(m.text());
  });
  page.on("pageerror", (e) => errors.push(String(e)));
  return errors;
}

test.describe("Inbox v2 (offline)", () => {
  test("addresses and labels: parsed, refused plainly, and warned about", async ({
    page,
  }) => {
    const errors = watchConsole(page);
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address2");
    const bob = await myAddress(page);
    await switchTo(page, "address1");
    const alice = await myAddress(page);
    expect(alice).not.toEqual(bob);

    // A typo fails the check bytes; a v0.2 id is recognised and deferred.
    const typo = bob.slice(0, 20) + (bob[20] === "z" ? "y" : "z") + bob.slice(21);
    await expect(await addContact(page, typo)).toContainText("typo");
    await expect(await addContact(page, "4".repeat(44))).toContainText("old (v0.2) address");
    // An incoming name outside plain ASCII is refused (a Cyrillic а here).
    await expect(await addContact(page, `pаypal@${bob}`)).toContainText(
      "outside plain ASCII",
    );
    // One of your own identities is not made a contact.
    await expect(await addContact(page, `fmail:Bob@${bob}`)).toContainText(
      "one of your own identities",
    );
    await closeSettings(page);

    // A label that looks like a contact's name (the seeded alice-example) on
    // another address is warned about in compose.
    const sheet = await compose(page, `a1ice-example@${bob}`, "lookalike");
    await expect(sheet.locator(tid(TID.fmV2LabelWarning))).toContainText(
      "looks like your contact",
    );
    await page.locator(".sheet-x").click();
    expect(errors).toEqual([]);
  });

  test("first contact, the reply by pass, and the Ghost Key badge", async ({ page }) => {
    const errors = watchConsole(page);
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");
    const alice = await myAddress(page);
    await switchTo(page, "address2");
    const bob = await myAddress(page);

    // Bob requires a Ghost Key at $5: alice, holding no pass, sees the
    // badge with its tier, Send stays enabled, and the outcome says why
    // nothing landed.
    await setNewContacts(page, "ghost-5");
    await switchTo(page, "address1");
    let sheet = await compose(page, `bob@${bob}`, "needs a key");
    const badge = sheet.locator(tid(TID.fmV2GhostBadge));
    await expect(badge).toHaveAttribute("data-tier", "5", { timeout: 30_000 });
    await expect(badge).toContainText("$5");
    await expect(page.locator(tid(TID.fmSend))).toBeEnabled();
    let outcome = await clickSend(page);
    await expect(outcome).toHaveAttribute("data-delivered", "false");
    await expect(outcome).toContainText("only with a Ghost Key");

    // Open again: the badge goes, and first contact lands in the queue.
    await switchTo(page, "address2");
    await setNewContacts(page, "open");
    await switchTo(page, "address1");
    sheet = await compose(page, `bob@${bob}`, "first contact");
    await expect(sheet.locator(tid(TID.fmV2RecipientNote))).toHaveAttribute(
      "data-held",
      "none",
    );
    await expect(sheet.locator(tid(TID.fmV2GhostBadge))).toHaveCount(0);
    outcome = await clickSend(page);
    await expect(outcome).toHaveAttribute("data-delivered", "true");
    await expect(outcome).toContainText("bob's new-contacts queue");

    // Bob drains it into his new-contacts queue, accepts alice (which sends
    // her a pass), finds it in his inbox, and replies by pass (alice's
    // message carried one).
    await switchTo(page, "address2");
    await openAddressSettings(page);
    const row = page.locator(tid(TID.fmV2QueueRow), { hasText: "first contact" });
    await row.locator(tid(TID.fmV2QueueAccept)).click({ timeout: 30_000 });
    // Accepting asks for a name: prefilled with the label alice gave, and
    // editable; nothing is saved until it is confirmed.
    const petname = row.locator(tid(TID.fmV2QueuePetname));
    await expect(petname).toHaveValue("address1");
    await petname.fill("alice");
    await row.locator(tid(TID.fmV2QueueConfirm)).click();
    await expect(row).toHaveCount(0, { timeout: 30_000 });
    await closeSettings(page);
    await expect(page.locator(`${tid(TID.fmList)} article`, { hasText: "first contact" })).toBeVisible({
      timeout: 30_000,
    });
    outcome = await send(page, `alice@${alice}`, "reply");
    await expect(outcome).toHaveText(/^Delivered to alice\./);

    // Delete removes bob's stored copy, not a v1 inbox row: once his next
    // mail is drained and the list is read from the delegate again, the
    // deleted message is still gone.
    const first = page.locator(`${tid(TID.fmList)} article`, { hasText: "first contact" });
    await first.click();
    await page.locator(`${tid(TID.fmThreadContainer)} ${tid(TID.fmDelete)}`).first().click();
    await expect(first).toHaveCount(0, { timeout: 30_000 });
    await switchTo(page, "address1");
    outcome = await send(page, `bob@${bob}`, "after delete");
    await expect(outcome).toHaveText(/^Delivered to bob\./);
    await switchTo(page, "address2");
    await expect(page.locator(`${tid(TID.fmList)} article`, { hasText: "after delete" })).toBeVisible({
      timeout: 30_000,
    });
    await expect(first).toHaveCount(0);

    // Requiring a Ghost Key again does not touch alice: she holds bob's
    // pass now, so no badge, and her mail goes straight in.
    await setNewContacts(page, "ghost-5");
    await switchTo(page, "address1");
    await expect(page.locator(`${tid(TID.fmList)} article`, { hasText: "reply" })).toBeVisible({
      timeout: 30_000,
    });
    sheet = await compose(page, `bob@${bob}`, "by pass");
    const note = sheet.locator(tid(TID.fmV2RecipientNote));
    await expect(note).toHaveAttribute("data-held", "held");
    await expect(note).toContainText("Straight to their inbox");
    await expect(sheet.locator(tid(TID.fmV2GhostBadge))).toHaveCount(0);
    outcome = await clickSend(page);
    await expect(outcome).toHaveText(/^Delivered to bob\./);
    expect(errors).toEqual([]);
  });

  test("an invite lets the first message in by pass", async ({ page }) => {
    const errors = watchConsole(page);
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address2");
    const bob = await myAddress(page);
    await openAddressSettings(page);
    await page.locator(tid(TID.fmV2InviteCreate)).click();
    const invite = (await page.locator(tid(TID.fmV2InviteText)).inputValue()).trim();
    expect(invite.startsWith("fmail-invite-1:")).toBe(true);
    await closeSettings(page);

    await switchTo(page, "address1");
    await expect(await addContact(page, invite)).toContainText("the invite is kept");
    await closeSettings(page);
    const sheet = await compose(page, bob, "invited");
    await expect(sheet.locator(tid(TID.fmV2RecipientNote))).toHaveAttribute(
      "data-held",
      "held",
    );
    const outcome = await clickSend(page);
    await expect(outcome).toHaveText(/^Delivered to /);
    await expect(outcome).not.toContainText("queue");
    expect(errors).toEqual([]);
  });

  test("an identity active on another node is warned about", async ({ page }) => {
    // The fixture: another node signs a record for the identity (with its
    // keys), and this node's delegate drains the inbox and signs past it
    // before the page reads it, so the warning can come only from the
    // delegate's note, not from comparing versions.
    await page.goto("/?v2-foreign-fixture");
    await waitForApp(page);
    await selectIdentity(page, "address1");
    // The message the fixture's drain stored: the delegate did see it.
    await expect(inboxRow(page, "while another node signed")).toBeVisible({ timeout: 30_000 });
    await expect(page.locator(tid(TID.fmV2ForeignWarning))).toContainText(
      "active on another node",
      { timeout: 30_000 },
    );
  });

  test("archiving a drained v2 message keeps it out of the inbox and in Archive", async ({
    page,
  }) => {
    const errors = watchConsole(page);
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address2");
    const bob = await myAddress(page);
    const invite = await inviteOf(page);
    await switchTo(page, "address1");
    await expect(await addContact(page, invite)).toContainText("the invite is kept");
    await closeSettings(page);
    await expect(await send(page, bob, "archive me")).toHaveAttribute("data-delivered", "true");

    await switchTo(page, "address2");
    await expect(inboxRow(page, "archive me")).toBeVisible({ timeout: 30_000 });
    // The delegate's drained copies of bob's mail (the list hides archived
    // rows itself, so only this shows a copy really went).
    const list = page.locator(tid(TID.fmList));
    await expect(list).toHaveAttribute("data-v2-stored", "1");
    const row = await openRow(page, "archive me");
    await row.locator(tid(TID.fmArchive)).dispatchEvent("click");
    await expect(inboxRow(page, "archive me")).toHaveCount(0, { timeout: 30_000 });

    // Its drained copy is gone from the delegate: once the next message is
    // drained and the list is read from the delegate again, it stays out.
    await switchTo(page, "address1");
    await expect(await send(page, bob, "after archive")).toHaveAttribute(
      "data-delivered",
      "true",
    );
    await switchTo(page, "address2");
    await expect(inboxRow(page, "after archive")).toBeVisible({ timeout: 30_000 });
    await expect(inboxRow(page, "archive me")).toHaveCount(0);
    await expect(list).toHaveAttribute("data-v2-stored", "1");

    await openNav(page);
    await page.locator('[data-testid="fm-folder-archive"]').click();
    await expect(
      page.locator(tid(TID.fmArchiveCard), { hasText: "archive me" }),
    ).toBeVisible();
    expect(errors).toEqual([]);
  });

  test("deleting a drained v2 message that was opened removes its stored copy", async ({
    page,
  }) => {
    const errors = watchConsole(page);
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address2");
    const bob = await myAddress(page);
    const invite = await inviteOf(page);
    await switchTo(page, "address1");
    await expect(await addContact(page, invite)).toContainText("the invite is kept");
    await closeSettings(page);
    await expect(await send(page, bob, "delete me")).toHaveAttribute("data-delivered", "true");

    await switchTo(page, "address2");
    await expect(inboxRow(page, "delete me")).toBeVisible({ timeout: 30_000 });
    const list = page.locator(tid(TID.fmList));
    await expect(list).toHaveAttribute("data-v2-stored", "1");
    // Opened first, so its read mark is written, then deleted.
    const row = await openRow(page, "delete me");
    await row.locator(tid(TID.fmDelete)).dispatchEvent("click");
    await expect(inboxRow(page, "delete me")).toHaveCount(0, { timeout: 30_000 });
    await expect(list).toHaveAttribute("data-v2-stored", "0", { timeout: 30_000 });
    await expect(page.getByText("Deleted", { exact: true }).first()).toBeVisible({
      timeout: 30_000,
    });
    expect(errors).toEqual([]);
  });

  test("a lookalike sender who is not a contact is flagged in the list and the message", async ({
    page,
  }) => {
    const errors = watchConsole(page);
    await page.goto("/");
    await waitForApp(page);
    // A third identity whose name looks like the saved contact alice-example.
    await createIdentity(page, "a1ice-example");
    await selectIdentity(page, "address2");
    const bob = await myAddress(page);
    const invite = await inviteOf(page);
    await switchTo(page, "a1ice-example");
    await expect(await addContact(page, invite)).toContainText("the invite is kept");
    await closeSettings(page);
    await expect(await send(page, bob, "from a lookalike")).toHaveAttribute(
      "data-delivered",
      "true",
    );

    // address1 writes first contact, and bob accepts it under the name it
    // gave, which looks like nobody else's. (Every identity here is the
    // page's own, so none can be saved as a contact: the contact side of the
    // note is not reachable offline.)
    await switchTo(page, "address1");
    await expect(await send(page, `bob@${bob}`, "from address1")).toHaveAttribute(
      "data-delivered",
      "true",
    );
    await switchTo(page, "address2");
    await openAddressSettings(page);
    const queued = page.locator(tid(TID.fmV2QueueRow), { hasText: "from address1" });
    await queued.locator(tid(TID.fmV2QueueAccept)).click({ timeout: 30_000 });
    await expect(queued.locator(tid(TID.fmV2QueuePetname))).toHaveValue("address1");
    await queued.locator(tid(TID.fmV2QueueConfirm)).click();
    await expect(queued).toHaveCount(0, { timeout: 30_000 });
    await closeSettings(page);

    // The stranger: warned about in the list, and in the open message,
    // which also says they are not a contact.
    const stranger = inboxRow(page, "from a lookalike");
    await expect(stranger.locator(tid(TID.fmV2LabelWarning))).toContainText(
      "looks like your contact",
      { timeout: 30_000 },
    );
    let row = await openRow(page, "from a lookalike");
    await expect(row.locator(tid(TID.fmV2LabelWarning))).toContainText("looks like your contact");
    await expect(row.locator(tid(TID.fmV2NotContact))).toBeVisible();
    await backToList(page);

    // A name like nobody else's: no warning, in the list or the message.
    const plain = inboxRow(page, "from address1");
    await expect(plain).toBeVisible({ timeout: 30_000 });
    await expect(plain.locator(tid(TID.fmV2LabelWarning))).toHaveCount(0);
    row = await openRow(page, "from address1");
    await expect(row).toBeVisible();
    await expect(row.locator(tid(TID.fmV2LabelWarning))).toHaveCount(0);
    expect(errors).toEqual([]);
  });

  test("Add to address book on a v2 sender uses the v2 flow, never the v1 import", async ({
    page,
  }) => {
    const errors = watchConsole(page);
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address2");
    const bob = await myAddress(page);
    // By invite, so the message lands in the inbox rather than the queue.
    const invite = await inviteOf(page);
    await switchTo(page, "address1");
    await expect(await addContact(page, invite)).toContainText("the invite is kept");
    await closeSettings(page);
    await expect(await send(page, bob, "add me")).toHaveAttribute("data-delivered", "true");
    await switchTo(page, "address2");
    const row = await openRow(page, "add me");
    await row.locator(tid(TID.fmAddToAb)).click();
    // The v2 flow answers with a toast (every identity here is the page's
    // own, so nothing is added); the v1 import form never opens.
    await expect(page.locator(tid(TID.fmToast)).filter({ hasText: "your own identities" })).toBeVisible({
      timeout: 30_000,
    });
    await expect(page.locator(tid(TID.fmImportContactModal))).toHaveCount(0);
    expect(errors).toEqual([]);
  });

  test("without the fixture there is no such warning", async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");
    await myAddress(page);
    await expect(page.locator(tid(TID.fmV2ForeignWarning))).toHaveCount(0);
  });
});
