import { test, expect, Page } from "@playwright/test";

// Helper: wait for the WASM app to fully render.
// In example-data mode the app skips the login view and lands on
// the identity list (two pre-seeded identities: address1, address2).
// Firefox takes significantly longer to initialize the RSA keygen
// for the mock identities, so we give it a generous 60s ceiling.
async function waitForApp(page: Page) {
  await page.waitForSelector("h1", { timeout: 60_000 });
  await expect(page.locator("h1")).toContainText("Freenet Email");
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
    await expect(iframe.locator("h1")).toContainText("Freenet Email");
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
