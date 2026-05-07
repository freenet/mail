/**
 * Playwright tests for compose-sheet To-field autocomplete (#132).
 *
 * Requires the dev server running with example-data + no-sync:
 *   cd ui && dx serve --port 8092 --features example-data,no-sync --no-default-features
 *
 * The `alice-example` contact is seeded by the example-data feature flag in
 * User::new() so these tests work without any manual import steps.
 */

import { test, expect, Page } from "@playwright/test";
import { APP_NAME } from "./app-name";
import { TID } from "./testids";

async function waitForApp(page: Page) {
  await page
    .locator('.brand-name, [data-testid="fm-app"]')
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

async function openCompose(page: Page) {
  await page.locator(`[data-testid="${TID.fmComposeBtn}"]`).click();
  await page
    .locator(`[data-testid="${TID.fmComposeSheet}"]`)
    .waitFor({ timeout: 5_000 });
}

test.describe("Compose To-field autocomplete (#132)", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");
    await openCompose(page);
  });

  test("dropdown appears when typing a matching substring", async ({ page }) => {
    const sheet = page.locator(`[data-testid="${TID.fmComposeSheet}"]`);
    const toInput = sheet.locator('input[placeholder="alias or address"]');

    // "alice" should match the seeded "alice-example" contact.
    await toInput.fill("alice");

    const dropdown = sheet.locator(
      `[data-testid="${TID.fmComposeAutocomplete}"]`,
    );
    await expect(dropdown).toBeVisible({ timeout: 3_000 });

    const items = dropdown.locator(
      `[data-testid="${TID.fmComposeAutocompleteItem}"]`,
    );
    await expect(items).toHaveCount(1);
    await expect(items.first()).toContainText("alice-example");
  });

  test("no dropdown on empty To field", async ({ page }) => {
    const sheet = page.locator(`[data-testid="${TID.fmComposeSheet}"]`);
    const dropdown = sheet.locator(
      `[data-testid="${TID.fmComposeAutocomplete}"]`,
    );

    // Field starts empty — dropdown should not be present.
    await expect(dropdown).toHaveCount(0);
  });

  test("no dropdown when input exactly matches an alias", async ({ page }) => {
    const sheet = page.locator(`[data-testid="${TID.fmComposeSheet}"]`);
    const toInput = sheet.locator('input[placeholder="alias or address"]');

    // Exact match — no autocomplete needed.
    await toInput.fill("alice-example");

    const dropdown = sheet.locator(
      `[data-testid="${TID.fmComposeAutocomplete}"]`,
    );
    await expect(dropdown).toHaveCount(0);
  });

  test("clicking a suggestion fills the To field and hides the dropdown", async ({
    page,
  }) => {
    const sheet = page.locator(`[data-testid="${TID.fmComposeSheet}"]`);
    const toInput = sheet.locator('input[placeholder="alias or address"]');

    await toInput.fill("alice");

    const dropdown = sheet.locator(
      `[data-testid="${TID.fmComposeAutocomplete}"]`,
    );
    await expect(dropdown).toBeVisible();

    // Click the suggestion.
    await dropdown
      .locator(`[data-testid="${TID.fmComposeAutocompleteItem}"]`)
      .first()
      .click();

    // The input must now hold the alias.
    await expect(toInput).toHaveValue("alice-example");

    // Dropdown should be gone.
    await expect(dropdown).toHaveCount(0);
  });

  test("keyboard ArrowDown + Enter selects suggestion", async ({ page }) => {
    const sheet = page.locator(`[data-testid="${TID.fmComposeSheet}"]`);
    const toInput = sheet.locator('input[placeholder="alias or address"]');

    await toInput.fill("alice");

    const dropdown = sheet.locator(
      `[data-testid="${TID.fmComposeAutocomplete}"]`,
    );
    await expect(dropdown).toBeVisible();

    // Arrow-down to highlight first item, then Enter to pick it.
    await toInput.press("ArrowDown");
    await toInput.press("Enter");

    await expect(toInput).toHaveValue("alice-example");
    await expect(dropdown).toHaveCount(0);
  });

  test("Escape key dismisses dropdown without changing the input", async ({
    page,
  }) => {
    const sheet = page.locator(`[data-testid="${TID.fmComposeSheet}"]`);
    const toInput = sheet.locator('input[placeholder="alias or address"]');

    await toInput.fill("alice");

    const dropdown = sheet.locator(
      `[data-testid="${TID.fmComposeAutocomplete}"]`,
    );
    await expect(dropdown).toBeVisible();

    await toInput.press("Escape");

    // Dropdown gone; original text preserved.
    await expect(dropdown).toHaveCount(0);
    await expect(toInput).toHaveValue("alice");
  });

  test("suggestion shows verified badge", async ({ page }) => {
    const sheet = page.locator(`[data-testid="${TID.fmComposeSheet}"]`);
    const toInput = sheet.locator('input[placeholder="alias or address"]');

    await toInput.fill("alice");

    const dropdown = sheet.locator(
      `[data-testid="${TID.fmComposeAutocomplete}"]`,
    );
    await expect(dropdown).toBeVisible();

    // alice-example is seeded as verified=true, so the ✓ badge should appear.
    const item = dropdown
      .locator(`[data-testid="${TID.fmComposeAutocompleteItem}"]`)
      .first();
    await expect(item.locator(".compose-ac-trust.known")).toBeVisible();
  });

  test("Escape only consumes event when dropdown is visible", async ({
    page,
  }) => {
    const sheet = page.locator(`[data-testid="${TID.fmComposeSheet}"]`);
    const toInput = sheet.locator('input[placeholder="alias or address"]');
    const dropdown = sheet.locator(
      `[data-testid="${TID.fmComposeAutocomplete}"]`,
    );

    // Type to open the dropdown, then press Escape — dropdown closes.
    await toInput.fill("alice");
    await expect(dropdown).toBeVisible();
    await toInput.press("Escape");
    await expect(dropdown).toHaveCount(0);

    // Press Escape a second time with no dropdown — the compose sheet
    // should still be present (event was not consumed by the autocomplete).
    await toInput.press("Escape");
    await expect(sheet).toBeVisible();
  });
});

test.describe("Compose autocomplete — touch long-press (Pixel 5)", () => {
  // Spread the Pixel 5 device profile but omit `defaultBrowserType` —
  // Playwright forbids that property inside a describe block (it forces a
  // new worker and must live at the project level in the config instead).
  const { defaultBrowserType: _unused, ...pixel5 } =
    require("@playwright/test").devices["Pixel 5"];
  test.use({ ...pixel5 });

  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await page
      .locator('.brand-name, [data-testid="fm-app"]')
      .first()
      .waitFor({ timeout: 60_000 });
    await page
      .locator(
        `[data-testid="${TID.fmIdRow}"][data-alias="address1"] [data-testid="${TID.fmIdOpen}"]`,
      )
      .click();
    await page.locator(`[data-testid="${TID.fmApp}"]`).waitFor({ timeout: 10_000 });
    await page.locator(`[data-testid="${TID.fmComposeBtn}"]`).click();
    await page
      .locator(`[data-testid="${TID.fmComposeSheet}"]`)
      .waitFor({ timeout: 5_000 });
  });

  test("long-press on touch device selects suggestion and fills To field", async ({
    page,
  }) => {
    const sheet = page.locator(`[data-testid="${TID.fmComposeSheet}"]`);
    const toInput = sheet.locator('input[placeholder="alias or address"]');

    await toInput.fill("alice");

    const dropdown = sheet.locator(
      `[data-testid="${TID.fmComposeAutocomplete}"]`,
    );
    await expect(dropdown).toBeVisible({ timeout: 3_000 });

    const item = dropdown
      .locator(`[data-testid="${TID.fmComposeAutocompleteItem}"]`)
      .first();

    // Simulate a long-press: touchstart held for 600 ms then touchend.
    // The pointerdown handler on the item must commit the selection even
    // though blur may fire during the hold — the ignore-blur guard prevents
    // premature dropdown close before the selection lands.
    const box = await item.boundingBox();
    if (!box) throw new Error("item bounding box not found");
    const cx = box.x + box.width / 2;
    const cy = box.y + box.height / 2;

    await page.touchscreen.tap(cx, cy);

    // After tap, the To field must hold the alias.
    await expect(toInput).toHaveValue("alice-example", { timeout: 3_000 });
    await expect(dropdown).toHaveCount(0);
  });
});
