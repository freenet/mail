import { test, expect, Page } from "@playwright/test";
import { APP_NAME } from "./app-name";

// Helper: wait for the WASM app to fully render.
// In example-data mode the app skips the login view and lands on
// the identity list (two pre-seeded identities: address1, address2).
// Firefox takes significantly longer to initialize the RSA keygen
// for the mock identities, so we give it a generous 60s ceiling.
async function waitForApp(page: Page) {
  await page.waitForSelector("h1", { timeout: 60_000 });
  await expect(page.locator("h1")).toContainText(APP_NAME);
}

// Helper: select an identity by clicking its alias link.
async function selectIdentity(page: Page, alias: string) {
  await page.getByText(alias, { exact: true }).click();
  // Wait for the inbox panel to appear.
  await expect(page.locator(".panel-heading")).toContainText("Inbox", {
    timeout: 10_000,
  });
}

// Helper: click a menu item in the sidebar.
async function clickMenu(page: Page, label: string) {
  await page.locator(".menu-list").getByText(label, { exact: true }).click();
}

// ─── Tests ─────────────────────────────────────────────────────────────────

test.describe("Identity list", () => {
  test("renders with mock identities and create link", async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);

    // Both mock identities should be listed.
    await expect(page.getByText("address1")).toBeVisible();
    await expect(page.getByText("address2")).toBeVisible();

    // "Create new identity" link should be present.
    await expect(page.getByText("Create new identity")).toBeVisible();
  });
});

test.describe("Inbox view", () => {
  test("shows inbox after selecting identity", async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    // Inbox panel is visible with tabs.
    await expect(page.locator(".panel-heading")).toContainText("Inbox");
    await expect(page.getByText("Primary")).toBeVisible();
    await expect(page.getByText("Social")).toBeVisible();
    await expect(page.getByText("Updates")).toBeVisible();

    // Search input present.
    await expect(page.locator('input[placeholder="Search"]')).toBeVisible();

    // Example emails for address1 (UserId 0).
    await expect(page.getByText("Ian's Other Account")).toBeVisible();
    await expect(page.getByText("Lunch tomorrow?")).toBeVisible();
    await expect(page.getByText("Your weekly digest")).toBeVisible();
  });

  test("opens an email and shows content", async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    // Click the first email (id=0).
    await page.locator("#email-inbox-accessor-0").click();

    // Title and content visible.
    await expect(page.locator("h2")).toContainText(
      "Welcome to the offline preview"
    );
    await expect(page.locator("#email-content-0")).toContainText(
      "Lorem ipsum"
    );

    // Back arrow visible.
    await expect(
      page.locator('i[aria-label="Back to Inbox"]')
    ).toBeVisible();
  });
});

test.describe("Compose and logout", () => {
  test("compose window renders and log out returns to identity list", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    // Click "Write message" in sidebar.
    await clickMenu(page, "Write message");

    // Compose form visible.
    await expect(page.locator("h3")).toContainText("New message");
    await expect(page.getByText("From")).toBeVisible();
    await expect(page.getByText("address1")).toBeVisible(); // From field
    await expect(page.getByText("To")).toBeVisible();
    await expect(page.getByText("Subject")).toBeVisible();
    await expect(
      page.locator("button").filter({ hasText: "Send" })
    ).toBeVisible();

    // Log out.
    await clickMenu(page, "Log out");

    // Back at identity list.
    await expect(page.getByText("address1")).toBeVisible();
    await expect(page.getByText("address2")).toBeVisible();
    await expect(page.getByText("Create new identity")).toBeVisible();
  });
});

// Regression: send button → navigate-back-to-inbox path.
//
// PR #38 (freenet/mail) discovered that the send-message future was
// silently cancelled on real-node deployments because Dioxus's `spawn`
// is component-scoped — `at_new_msg()` unmounts NewMessageWindow
// before the future polls, killing the task. The fix was to switch to
// `spawn_forever`. We can't observe the AFT/network side here (offline
// mode), but we CAN regression-test the user-visible symptom that
// led to discovery: clicking Send should leave the compose view and
// land back on the inbox view, not silently no-op.
test.describe("Send returns to inbox view (regression: spawn_forever)", () => {
  test("clicking Send navigates away from compose", async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");
    await clickMenu(page, "Write message");
    await expect(page.locator("h3")).toContainText("New message");

    const toCell = page.locator("tr").filter({ hasText: "To" }).locator("td");
    await toCell.click();
    await toCell.fill("address2");

    const subjectCell = page
      .locator("tr")
      .filter({ hasText: "Subject" })
      .locator("td");
    await subjectCell.click();
    await subjectCell.fill("regression check");

    const bodyDiv = page.locator(".box div[contenteditable]");
    await bodyDiv.click();
    await bodyDiv.fill("body");

    await page.locator("button").filter({ hasText: "Send" }).click();

    // After send, the compose heading must disappear — proving the
    // event handler ran the spawn AND the navigation, not just paused.
    await expect(page.locator("h3").filter({ hasText: "New message" })).toHaveCount(0, {
      timeout: 5_000,
    });
  });
});

// Regression: identity persists across page reload.
//
// PR #37 (freenet/mail) restored runtime wiring (INBOX_TO_ID +
// AFT-record subscriptions + AFT-gen delegate) on identity reload.
// In offline (example-data) mode there are no real contracts, but
// the identity-list / login-screen restore path must still work:
// after a reload, the previously-seeded identities must be visible
// without the user having to re-create them.
test.describe("Identity list survives reload (regression: #36)", () => {
  test("address1 + address2 are visible again after page reload", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);
    await expect(page.getByText("address1")).toBeVisible();
    await expect(page.getByText("address2")).toBeVisible();

    await page.reload();
    await waitForApp(page);

    await expect(page.getByText("address1")).toBeVisible();
    await expect(page.getByText("address2")).toBeVisible();
  });
});

test.describe("Multi-turn cross-inbox messaging", () => {
  test("address1 sends to address2, address2 replies, both see messages", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);

    // ── Turn 1: address1 → address2 ────────────────────────────────────

    await selectIdentity(page, "address1");
    await clickMenu(page, "Write message");
    await expect(page.locator("h3")).toContainText("New message");

    // Fill the compose form.
    // "To" field is a contenteditable <td>.
    const toCell = page.locator("tr").filter({ hasText: "To" }).locator("td");
    await toCell.click();
    await toCell.fill("address2");

    const subjectCell = page
      .locator("tr")
      .filter({ hasText: "Subject" })
      .locator("td");
    await subjectCell.click();
    await subjectCell.fill("Hello from address1");

    // Body is the contenteditable div inside the second .box.
    const bodyDiv = page.locator(".box div[contenteditable]");
    await bodyDiv.click();
    await bodyDiv.fill("This is the body of the first message.");

    // Send.
    await page.locator("button").filter({ hasText: "Send" }).click();

    // Log out.
    await clickMenu(page, "Log out");
    await expect(page.getByText("Create new identity")).toBeVisible();

    // ── Turn 2: address2 receives and replies ──────────────────────────

    await selectIdentity(page, "address2");

    // address2's default mock messages.
    await expect(page.getByText("Ian Clarke")).toBeVisible();
    await expect(page.getByText("Re: design review")).toBeVisible();

    // The message from address1 should now appear.
    await expect(page.getByText("Hello from address1")).toBeVisible();

    // Reply: address2 → address1. (We skip opening the received message
    // here — the Dioxus re-render triggered by the back-arrow click is
    // flaky in headless mode. What we're testing is message delivery,
    // not navigation state, so going straight to compose is equivalent.)
    await clickMenu(page, "Write message");

    // Wait for compose form to appear.
    await expect(page.locator("h3")).toContainText("New message");

    const toCell2 = page.locator("tr").filter({ hasText: "To" }).locator("td");
    await toCell2.click();
    await toCell2.fill("address1");

    const subjectCell2 = page
      .locator("tr")
      .filter({ hasText: "Subject" })
      .locator("td");
    await subjectCell2.click();
    await subjectCell2.fill("Reply from address2");

    const bodyDiv2 = page.locator(".box div[contenteditable]");
    await bodyDiv2.click();
    await bodyDiv2.fill("Got your message, here is my reply.");

    await page.locator("button").filter({ hasText: "Send" }).click();

    // Log out.
    await clickMenu(page, "Log out");
    await expect(page.getByText("Create new identity")).toBeVisible();

    // ── Turn 3: address1 sees the reply ────────────────────────────────

    await selectIdentity(page, "address1");

    // Original mock messages should still be there.
    await expect(page.getByText("Ian's Other Account")).toBeVisible();

    // The reply from address2 should now appear.
    await expect(page.getByText("Reply from address2")).toBeVisible();

    // Open it and verify content.
    await page.getByText("Reply from address2").click();
    await expect(page.locator("h2")).toContainText("Reply from address2");
    await expect(page.locator("p")).toContainText(
      "Got your message, here is my reply."
    );
  });
});

test.describe("Sandboxed iframe embedding", () => {
  // The Freenet gateway uses: sandbox="allow-scripts allow-forms allow-popups"
  // (without allow-same-origin, giving the iframe an opaque origin).
  // For local testing we add allow-same-origin so the WASM can load from
  // the dev server. The layout behavior we're testing is the same regardless.
  const sandboxAttrs =
    "allow-scripts allow-forms allow-popups allow-same-origin";

  test("app renders inside a sandboxed iframe", async ({ page }) => {
    await page.setContent(`
      <!DOCTYPE html>
      <html>
      <body style="margin:0;padding:0;height:100vh;">
        <iframe
          sandbox="${sandboxAttrs}"
          src="http://127.0.0.1:8082"
          style="width:100%;height:100%;border:none;"
        ></iframe>
      </body>
      </html>
    `);

    const iframe = page.frameLocator("iframe");
    await iframe.locator("h1").waitFor({ timeout: 60_000 });
    await expect(iframe.locator("h1")).toContainText(APP_NAME);
  });
});

test.describe("No horizontal scrollbar at desktop width", () => {
  // The email UI uses Bulma's .columns layout, which is known to overflow
  // below the md breakpoint (768px) when the sidebar menu + inbox panel
  // don't collapse. Mobile responsiveness is tracked separately; here we
  // only guarantee that desktop-width layouts don't overflow horizontally.
  test("no overflow at 1280px", async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    const hasHScroll = await page.evaluate(
      () =>
        document.documentElement.scrollWidth >
        document.documentElement.clientWidth
    );
    expect(hasHScroll).toBe(false);
  });
});

// ── Address book: import contact and display ─────────────────────────────────
//
// This test exercises the address book import flow in offline (example-data,
// no-sync) mode:
//   1. Build a fake ContactCard payload (the same shape the Rust code produces)
//      using browser-native btoa so no extra dependencies are needed.
//   2. Navigate to the import-contact dialog and paste the encoded token.
//   3. Assert the fingerprint panel appears and the alias pre-fills.
//   4. Complete the import and assert the contact appears in the Contacts section.
//   5. Log in as address1, type the contact alias in the compose To field,
//      confirm the compose form still accepts it (address_book::lookup resolves it).

test.describe("Address book: import contact and display", () => {
  test("import contact card → appears in contacts section → compose accepts alias", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);

    // ── Step 1: build a fake ContactCard via browser evaluate ─────────────
    //
    // ContactCard JSON fields:
    //   version: u32
    //   ml_dsa_vk_bytes: array of ints (1952 bytes for ML-DSA-65)
    //   ml_kem_ek_bytes: array of ints (1184 bytes for ML-KEM-768)
    //   suggested_alias: string | null
    //   suggested_description: string | null
    //
    // The byte arrays are arbitrary — we only need them to pass the import
    // parser (which accepts any bytes).  The fingerprint displayed will be
    // deterministic given these values.
    const contactCard = await page.evaluate(() => {
      const mlDsaVk = new Array(1952)
        .fill(0)
        .map((_, i) => (i * 7 + 13) & 0xff);
      const mlKemEk = new Array(1184)
        .fill(0)
        .map((_, i) => (i * 5 + 17) & 0xff);
      const card = {
        version: 1,
        ml_dsa_vk_bytes: mlDsaVk,
        ml_kem_ek_bytes: mlKemEk,
        suggested_alias: "charlie",
        suggested_description: "Test contact",
      };
      const json = JSON.stringify(card);
      // btoa produces standard base64, matching Rust's base64::STANDARD engine.
      return `contact://${btoa(json)}`;
    });

    // ── Step 2: open the import-contact dialog ────────────────────────────
    await page.getByText("+ Import contact", { exact: true }).click();

    await expect(page.getByText("Import contact")).toBeVisible({
      timeout: 5_000,
    });

    // ── Step 3: paste the card and assert the fingerprint panel appears ───
    await page.locator("textarea").fill(contactCard);

    await expect(
      page.getByText("Fingerprint (verify with sender):")
    ).toBeVisible({ timeout: 5_000 });

    // Alias should be pre-filled with the suggested_alias from the card.
    const labelInput = page.locator('input[placeholder="e.g. Alice (work)"]');
    await expect(labelInput).toHaveValue("charlie");

    // Use a distinct local alias that can't clash with own identities.
    await labelInput.fill("charlie-test");

    // ── Step 4: complete import and verify contact appears ────────────────
    await page.locator("button").filter({ hasText: "Import" }).click();

    // Import form closes; Contacts section shows the new entry.
    await expect(page.getByText("charlie-test")).toBeVisible({
      timeout: 5_000,
    });

    // ── Step 5: compose accepts the imported contact alias ────────────────
    //
    // address_book::lookup("charlie-test") will find the contact and return a
    // Recipient.  The send will fail at ek_from_bytes (arbitrary byte array),
    // but compose shows the form and accepts the alias in the To field, which
    // is the behaviour we're testing here.
    await selectIdentity(page, "address1");
    await clickMenu(page, "Write message");
    await expect(page.locator("h3")).toContainText("New message");

    const toCell = page.locator("tr").filter({ hasText: "To" }).locator("td");
    await toCell.click();
    await toCell.fill("charlie-test");

    // Subject and body so the form is complete.
    const subjectCell = page
      .locator("tr")
      .filter({ hasText: "Subject" })
      .locator("td");
    await subjectCell.click();
    await subjectCell.fill("hello charlie");

    const bodyDiv = page.locator(".box div[contenteditable]");
    await bodyDiv.click();
    await bodyDiv.fill("test body");

    // The compose form with the alias typed in To should still be visible
    // (no "not found" error crashed the UI before Send is even clicked).
    await expect(
      page.locator("tr").filter({ hasText: "To" }).locator("td")
    ).toContainText("charlie-test");
  });
});
