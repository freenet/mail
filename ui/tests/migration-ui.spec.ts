import { test, expect, Page } from "@playwright/test";
import { APP_NAME } from "./app-name";
import { TID } from "./testids";

// What a person sees when their data comes from the v0.2.x delegates. The
// offline build runs the real walk in the page against a scripted node
// (`?migration-fixture=`, ui/src/app/migration_fixture.rs) whose replies are
// the captured golden bytes. What the walk imports in every other case is in
// `ui/src/migration/tests.rs`.

async function open(page: Page, fixture: string) {
  await page.goto(`/?migration-fixture=${fixture}`);
  await page
    .locator(`.brand-name, [data-testid="${TID.fmApp}"]`)
    .first()
    .waitFor({ timeout: 60_000 });
  await expect(page.locator(".brand-name").first()).toContainText(APP_NAME);
  // The status report is drawn once the walk has ended.
  await page
    .locator(`[data-testid="${TID.fmMigrationReport}"]`)
    .waitFor({ state: "attached", timeout: 30_000 });
}

const testid = (page: Page, id: string) => page.locator(`[data-testid="${id}"]`);

test("a node that never ran the old version shows no alarm and no notice", async ({
  page,
}) => {
  await open(page, "not-installed");
  await expect(testid(page, TID.fmMigrationUnreachable)).toHaveCount(0);
  await expect(testid(page, TID.fmMigrationNotice)).toHaveCount(0);
  await expect(testid(page, TID.fmMigrationStatus)).toHaveCount(0);
  await expect(testid(page, TID.fmIdCreate)).toBeVisible();
});

test("a previous version that does not answer says so and offers Restore", async ({
  page,
}) => {
  await open(page, "silent");
  await expect(testid(page, TID.fmMigrationUnreachable)).toBeVisible();
  await testid(page, TID.fmMigrationRestore).click();
  await expect(testid(page, TID.fmRestorePaste)).toBeVisible();
});

test("the notice says what moved, discloses retries and offers the recovery key", async ({
  page,
}) => {
  await open(page, "data");
  const notice = testid(page, TID.fmMigrationNotice);
  await expect(notice).toContainText("Moved from your previous version of Mail");
  await expect(notice).toContainText("1 identities");
  await expect(notice).toContainText("can return when it retries");
  await expect(notice).toContainText("an identity you deleted in a newer version");

  await testid(page, TID.fmMigrationBackup).click();
  await expect(testid(page, TID.fmBackupModal)).toBeVisible();
  await testid(page, TID.fmBackupModal).locator(`[data-testid="${TID.fmBackupReveal}"]`).click();
  await expect(
    testid(page, TID.fmBackupModal).locator(`[data-testid="${TID.fmBackupKey}"]`),
  ).toContainText("fmail-key-1:");
});

test("mail of an alias no identity has can be moved to one, and the notice can be dismissed", async ({
  page,
}) => {
  await open(page, "data");
  const group = testid(page, TID.fmOrphanGroup).filter({ hasText: "old-alias" });
  await expect(group).toBeVisible();
  await group.locator(`[data-testid="${TID.fmOrphanMove}"]`).click();
  await expect(group).toHaveCount(0);

  await testid(page, TID.fmMigrationDismiss).click();
  await expect(testid(page, TID.fmMigrationNotice)).toHaveCount(0);
});

test("orphans can be discarded, after a confirmation naming them", async ({ page }) => {
  await open(page, "data");
  const group = testid(page, TID.fmOrphanGroup).filter({ hasText: "old-alias" });
  await expect(group).toBeVisible();
  await expect(group.locator(`[data-testid="${TID.fmOrphanMove}"]`)).toBeVisible();

  await group.locator(`[data-testid="${TID.fmOrphanDiscard}"]`).click();
  const confirm = testid(page, TID.fmOrphanDiscardConfirm);
  await expect(confirm).toContainText("Discard 5 item(s) from `old-alias`?");
  await expect(confirm.locator("li")).toHaveCount(5);
  await expect(confirm).toContainText("draft: ");

  await testid(page, TID.fmOrphanDiscardCancel).click();
  await expect(confirm).toHaveCount(0);
  await expect(group).toBeVisible();

  await group.locator(`[data-testid="${TID.fmOrphanDiscard}"]`).click();
  await testid(page, TID.fmOrphanDiscardSubmit).click();
  await expect(group).toHaveCount(0);
  await expect(confirm).toHaveCount(0);
});

test("a migrated identity is confirmed before it is shared", async ({ page }) => {
  await open(page, "data");
  const row = page.locator(`[data-testid="${TID.fmIdRow}"][data-alias="alice"]`);
  await expect(row).toBeVisible();
  await row.locator(`[data-testid="${TID.fmIdShare}"]`).click();
  const prompt = testid(page, TID.fmConfirmIdentity);
  await expect(prompt).toContainText("Confirm this identity is yours");
  await expect(prompt).toContainText("Fingerprint:");

  await testid(page, TID.fmConfirmIdentityCancel).click();
  await expect(prompt).toHaveCount(0);

  await row.locator(`[data-testid="${TID.fmIdShare}"]`).click();
  await testid(page, TID.fmConfirmIdentitySubmit).click();
  await expect(prompt).toHaveCount(0);
  await expect(testid(page, TID.fmShareModal)).toBeVisible();
});

// An identity nobody has confirmed does not send. The prompt shows, nothing
// leaves (no Sent toast, nothing in Sent), and confirming sends exactly once.
// Deleting the early return in the send handler fails this test.
test("a migrated identity cannot send until it is confirmed, and confirming sends", async ({
  page,
}) => {
  await open(page, "data");
  await page
    .locator(`[data-testid="${TID.fmIdRow}"][data-alias="alice"] [data-testid="${TID.fmIdOpen}"]`)
    .click();
  await page.locator(`[data-testid="${TID.fmApp}"]`).waitFor({ timeout: 10_000 });
  const burger = page.locator('[data-testid="fm-hamburger"]');
  if (await burger.isVisible().catch(() => false)) await burger.click();
  await testid(page, TID.fmComposeBtn).click();
  const sheet = testid(page, TID.fmComposeSheet);
  await sheet.waitFor({ timeout: 5_000 });
  await sheet.locator('input[placeholder="alias or address"]').fill("address2");
  await sheet.locator('input[placeholder="subject"]').fill("held until confirmed");
  await sheet.locator("textarea.sheet-textarea").fill("body");

  await testid(page, TID.fmSend).click();
  const prompt = testid(page, TID.fmConfirmIdentity);
  await expect(prompt).toContainText("Confirm this identity is yours");
  // Long enough for a send that was not held to show its toast.
  await page.waitForTimeout(1_500);
  const sent = page.locator(`[data-testid="${TID.fmToast}"]`).filter({ hasText: "Sent" });
  await expect(sent).toHaveCount(0);
  await expect(sheet).toBeVisible();

  await testid(page, TID.fmConfirmIdentitySubmit).click();
  await expect(prompt).toHaveCount(0);
  await expect(sent).toHaveCount(1, { timeout: 5_000 });
  if (await burger.isVisible().catch(() => false)) await burger.click();
  await page.locator('[data-testid="fm-folder-sent"]').click();
  await expect(testid(page, TID.fmSentCard)).toHaveCount(1);
});
