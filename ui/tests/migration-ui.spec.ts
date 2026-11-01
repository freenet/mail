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
