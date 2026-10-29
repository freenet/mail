import { test, expect, Page } from "@playwright/test";
import { APP_NAME } from "./app-name";
import { TID } from "./testids";

// Identity keys live in the mail delegate. The offline build runs the real
// delegate code in the page (it answers its own consent prompts), so these
// exercise the protocol the node build uses: the recovery key the create
// flow shows comes back from the create, a later reveal is the delegate's
// export, and deleting an identity deletes it from the delegate.

async function waitForApp(page: Page) {
  await page
    .locator(`.brand-name, [data-testid="${TID.fmApp}"]`)
    .first()
    .waitFor({ timeout: 60_000 });
  await expect(page.locator(".brand-name").first()).toContainText(APP_NAME);
}

function idRow(page: Page, alias: string) {
  return page.locator(`[data-testid="${TID.fmIdRow}"][data-alias="${alias}"]`);
}

async function rowFingerprint(page: Page, alias: string): Promise<string> {
  return (await idRow(page, alias).locator(".id-fp").innerText())
    .replace(/Fingerprint/i, "")
    .trim();
}

// Open an identity's backup modal and read its revealed recovery key.
async function revealFromRow(page: Page, alias: string): Promise<string> {
  await idRow(page, alias).locator(`[data-testid="${TID.fmIdBackup}"]`).click();
  const modal = page.locator(`[data-testid="${TID.fmBackupModal}"]`);
  await modal.locator(`[data-testid="${TID.fmBackupReveal}"]`).click();
  const key = (await modal.locator(`[data-testid="${TID.fmBackupKey}"]`).innerText()).trim();
  expect(key).toMatch(/^fmail-key-1:/);
  return key;
}

test("the key shown at creation is the one a later reveal exports, and leaves the page on close", async ({
  page,
}) => {
  await page.goto("/");
  await waitForApp(page);
  await page.locator(`[data-testid="${TID.fmIdCreate}"]`).click();
  await page.locator(`[data-testid="${TID.fmCreateAliasInput}"]`).fill("kira");
  await page.locator(`[data-testid="${TID.fmCreateSubmit}"]`).click();
  await expect(page.getByText("Your fingerprint")).toBeVisible({ timeout: 5_000 });

  // The create flow's key, returned once by the delegate's create.
  await page.locator(`[data-testid="${TID.fmCreateBackupNow}"]`).click();
  const panel = page.locator(`[data-testid="${TID.fmBackupPanel}"]`);
  await panel.locator(`[data-testid="${TID.fmBackupReveal}"]`).click();
  const created = (await panel.locator(`[data-testid="${TID.fmBackupKey}"]`).innerText()).trim();
  expect(created).toMatch(/^fmail-key-1:/);
  await panel.locator(`[data-testid="${TID.fmBackupSaved}"]`).click();
  await page.locator(`[data-testid="${TID.fmCreateConfirm}"]`).click();
  await expect(idRow(page, "kira")).toBeVisible();

  // A later reveal goes through the delegate's export: the same key.
  const exported = await revealFromRow(page, "kira");
  expect(exported).toBe(created);

  // Closing the panel drops the key from the page.
  await page
    .locator(`[data-testid="${TID.fmBackupModal}"]`)
    .getByRole("button", { name: "Close" })
    .click();
  await expect(page.locator(`[data-testid="${TID.fmBackupModal}"]`)).toHaveCount(0);
  const payload = created.slice("fmail-key-1:".length);
  expect(await page.content()).not.toContain(payload);
});

test("a deleted identity is gone from the delegate: its key restores it as new", async ({
  page,
}) => {
  await page.goto("/");
  await waitForApp(page);
  const fingerprint = await rowFingerprint(page, "address2");
  const key = await revealFromRow(page, "address2");
  await page
    .locator(`[data-testid="${TID.fmBackupModal}"]`)
    .getByRole("button", { name: "Close" })
    .click();

  await idRow(page, "address2").locator(`[data-testid="${TID.fmIdDelete}"]`).click();
  await page.locator(`[data-testid="${TID.fmDeleteConfirmInput}"]`).fill("address2");
  await page.locator(`[data-testid="${TID.fmDeleteConfirmSubmit}"]`).click();
  await expect(idRow(page, "address2")).toHaveCount(0, { timeout: 5_000 });

  // Had the delete stayed in the page's memory only, the delegate would
  // still hold the identity and the restore form would say it is already
  // on this device.
  await page.locator(`[data-testid="${TID.fmIdRestore}"]`).click();
  await page.locator(`[data-testid="${TID.fmRestorePaste}"]`).fill(key);
  await expect(page.locator(`[data-testid="${TID.fmRestoreExisting}"]`)).toHaveCount(0);
  await page.locator(`[data-testid="${TID.fmRestoreAlias}"]`).fill("address2-back");
  await page.locator(`[data-testid="${TID.fmRestoreSubmit}"]`).click();
  await expect(idRow(page, "address2-back")).toBeVisible({ timeout: 10_000 });
  expect(await rowFingerprint(page, "address2-back")).toBe(fingerprint);
});
