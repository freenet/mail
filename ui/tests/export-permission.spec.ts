import { test, expect, Page } from "@playwright/test";
import { APP_NAME } from "./app-name";
import { TID } from "./testids";

// Settings → Backup & restore → "Remembered export permission" sends
// RevokeExportGrant to the mail delegate. The offline build runs the real
// delegate code in the page, so this exercises the protocol round trip, not
// a stub.

async function waitForApp(page: Page) {
  await page
    .locator(`.brand-name, [data-testid="${TID.fmApp}"]`)
    .first()
    .waitFor({ timeout: 60_000 });
  await expect(page.locator(".brand-name").first()).toContainText(APP_NAME);
}

async function selectIdentity(page: Page, alias: string) {
  await page
    .locator(
      `[data-testid="${TID.fmIdRow}"][data-alias="${alias}"] [data-testid="${TID.fmIdOpen}"]`,
    )
    .click();
  await page.locator(`[data-testid="${TID.fmApp}"]`).waitFor({ timeout: 10_000 });
}

test("revoking the remembered export permission reports success", async ({ page }) => {
  await page.goto("/");
  await waitForApp(page);
  await selectIdentity(page, "address1");
  await page.locator(`[data-testid="${TID.fmSettingsBtn}"]`).click();
  await page
    .locator(`[data-testid="${TID.fmSettingsShell}"]`)
    .waitFor({ timeout: 5_000 });
  await page
    .locator(`[data-testid="${TID.fmSettingsNavItem}"][data-screen="account"]`)
    .click();
  await page.locator(`[data-testid="${TID.fmSettingsRevokeExport}"]`).click();
  await expect(page.locator(".toast-msg")).toContainText(
    "Exports will ask for permission again",
    { timeout: 10_000 },
  );
});
