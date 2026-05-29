import { test, expect, Page } from "@playwright/test";
import { APP_NAME } from "./app-name";

// Helper: wait for the WASM app to fully render.
// In example-data mode the app skips the login view and lands on
// the identity list (two pre-seeded identities: address1, address2).
// Firefox takes significantly longer to initialize the RSA keygen
// for the mock identities, so we give it a generous 60s ceiling.
async function waitForApp(page: Page) {
  // Pre-login screens render the redesigned topbar; post-login mounts
  // the .fm-app shell. Either is enough to know the WASM finished
  // booting.
  await page
    .locator('.brand-name, [data-testid="fm-app"]')
    .first()
    .waitFor({ timeout: 60_000 });
  await expect(page.locator(".brand-name").first()).toContainText(APP_NAME);
}

// Helper: select an identity by clicking its row's "Open inbox"
// button. Identity rows are now structural (id-row), so clicking the
// alias text alone no longer logs in.
async function selectIdentity(page: Page, alias: string) {
  await page
    .locator(`[data-testid="fm-id-row"][data-alias="${alias}"] [data-testid="fm-id-open"]`)
    .click();
  await page.locator('[data-testid="fm-app"]').waitFor({ timeout: 10_000 });
  await expect(page.locator(".list-title")).toContainText("Inbox", {
    timeout: 10_000,
  });
}

// Helper: click the redesigned sidebar logout.
async function logout(page: Page) {
  await page.locator('[data-testid="fm-logout"]').click();
}

// Helper: open the compose sheet via the sidebar's "New message" button.
async function openCompose(page: Page) {
  await page.locator('[data-testid="fm-compose-btn"]').click();
  await page
    .locator('[data-testid="fm-compose-sheet"]')
    .waitFor({ timeout: 5_000 });
}

// Helper: fill compose form fields. Inputs are real `<input>` /
// `<textarea>` elements in the redesign — no contenteditable cells.
async function fillCompose(
  page: Page,
  to: string,
  subject: string,
  body: string,
) {
  const sheet = page.locator('[data-testid="fm-compose-sheet"]');
  await sheet.locator('input[placeholder="alias or address"]').fill(to);
  await sheet.locator('input[placeholder="subject"]').fill(subject);
  await sheet.locator("textarea.sheet-textarea").fill(body);
}

async function clickSend(page: Page) {
  await page.locator('[data-testid="fm-send"]').click();
}

// ─── Tests ─────────────────────────────────────────────────────────────────

test.describe("Identity list", () => {
  test("renders with mock identities and create link", async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);

    // Both mock identities should be listed as id-rows.
    await expect(
      page.locator('[data-testid="fm-id-row"][data-alias="address1"]'),
    ).toBeVisible();
    await expect(
      page.locator('[data-testid="fm-id-row"][data-alias="address2"]'),
    ).toBeVisible();

    // "+ Create new identity" affordance should be present.
    await expect(page.locator('[data-testid="fm-id-create"]')).toBeVisible();
  });
});

test.describe("Inbox view", () => {
  test("shows redesigned shell after selecting identity", async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    // Folder nav is visible with all four folders.
    await expect(page.locator('[data-testid="fm-folder-inbox"]')).toBeVisible();
    await expect(page.locator('[data-testid="fm-folder-sent"]')).toBeVisible();
    await expect(page.locator('[data-testid="fm-folder-drafts"]')).toBeVisible();
    await expect(
      page.locator('[data-testid="fm-folder-archive"]'),
    ).toBeVisible();

    // Topbar search is present.
    await expect(page.locator('[data-testid="fm-search"]')).toBeVisible();

    // Example emails for address1 (UserId 0) appear as message cards.
    await expect(page.getByText("Ian's Other Account")).toBeVisible();
    await expect(page.getByText("Lunch tomorrow?")).toBeVisible();
    await expect(page.getByText("Your weekly digest")).toBeVisible();
  });

  test("opens a conversation and shows the threaded detail", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    // #270: inbox rows are now thread GROUPS, and the accessor id is the
    // thread root_id (ui/src/app.rs ~2602). accessor-0 is the seeded
    // "Lunch tomorrow?" conversation (ids 0/1/2), not a single message.
    await page.locator("#email-inbox-accessor-0").click();

    // Opening shows the threaded detail container (ThreadDetail), not the
    // single-message OpenMessage panel.
    const container = page.locator('[data-testid="fm-thread-container"]');
    await container.waitFor({ state: "attached", timeout: 10_000 });
    // Header subject carries the conversation subject.
    await expect(container.locator(".ft-subj")).toContainText("Lunch tomorrow?");
    // All three members render as thread rows.
    await expect(
      container.locator('[data-testid="fm-thread-row"]'),
    ).toHaveCount(3);
    // Default Nested view expands the leaf (newest, id=2) so its body shows.
    await expect(container).toContainText("Perfect, see you there!");

    // Per-message affordances are present on the rows (Reply + Archive +
    // Delete restored onto every thread row in #270 BLOCKER-1). The footer
    // also carries a conversation-level Reply, so assert "at least one".
    const leafRow = container.locator(
      '[data-testid="fm-thread-row"][data-msg-id="2"]',
    );
    await expect(leafRow.locator('[data-testid="fm-reply"]')).toHaveCount(1);
    await expect(leafRow.locator('[data-testid="fm-archive"]')).toHaveCount(1);
    await expect(leafRow.locator('[data-testid="fm-delete"]')).toHaveCount(1);
  });

  test("non-inbox folders show empty state", async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    await page.locator('[data-testid="fm-folder-sent"]').click();
    // 47b changed the empty Sent detail-panel hint to "Select a sent message"
    // because Sent now backs a real list. The list-col still says "Sent is
    // empty"; the detail-col prompt for the empty selection is what we
    // assert against here.
    await expect(page.locator(".empty-hint")).toContainText("Select a sent message");

    await page.locator('[data-testid="fm-folder-drafts"]').click();
    await expect(page.locator(".empty-hint")).toContainText(
      "Drafts is empty",
    );

    await page.locator('[data-testid="fm-folder-archive"]').click();
    // 47c: Archive backs a real list; empty detail prompt mirrors Sent.
    await expect(page.locator(".empty-hint")).toContainText(
      "Select an archived message",
    );
  });
});

test.describe("Quarantine folder", () => {
  // Helper: open Settings → Inbox and flip the quarantine toggle.
  async function toggleQuarantine(page: Page) {
    await page.locator('[data-testid="fm-settings-btn"]').click();
    await page
      .locator('[data-testid="fm-settings-shell"]')
      .waitFor({ timeout: 5_000 });
    await page.locator('[data-testid="fm-settings-nav-item"][data-screen="inbox"]').click();
    // The quarantine row owns the only "unknown keys" label on this screen.
    const row = page
      .locator(".fm-row-set", { hasText: "Hold messages with unknown keys" });
    await row.locator('[role="switch"]').click();
    // Back out to the mailbox.
    await page.locator('[data-testid="fm-settings-back"]').click();
    await page.locator('[data-testid="fm-app"]').waitFor({ timeout: 5_000 });
  }

  test("hidden until enabled, then diverts unknown senders with a badge", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    // Off by default: no Quarantine folder in the sidebar, and the example
    // (unknown-sender) messages all live in the Inbox.
    await expect(
      page.locator('[data-testid="fm-folder-quarantine"]'),
    ).toHaveCount(0);
    await expect(page.getByText("Lunch tomorrow?")).toBeVisible();

    await toggleQuarantine(page);

    // Quarantine folder now appears with a count badge = the UNREAD count over
    // unverified rows (folder_count, ui/src/app.rs ~1881). The #270 seed has 5
    // messages, all unsigned/unknown, of which 2 are unread (id=2 "Perfect, see
    // you there!" and id=3 "Welcome to the offline preview"); the rest are
    // pre-read. So the badge is "2".
    const quarantineBtn = page.locator('[data-testid="fm-folder-quarantine"]');
    await expect(quarantineBtn).toBeVisible();
    await expect(quarantineBtn.locator(".count")).toHaveText("2");

    // Inbox is now empty — every example sender is unknown.
    await page.locator('[data-testid="fm-folder-inbox"]').click();
    await expect(page.getByText("Lunch tomorrow?")).toHaveCount(0);

    // The diverted rows render in Quarantine. #270 unified the inbox/quarantine
    // list onto the grouped `fm-thread-group` row (the old `fm-quarantine-card`
    // testid is now only carried as the `data-msg-card-testid` ATTRIBUTE, not a
    // real testid). The 5 unverified messages group into 3 rows: the seeded
    // "Lunch tomorrow?" conversation + the 2 standalone messages.
    await quarantineBtn.click();
    const rows = page.locator('[data-testid="fm-thread-group"]');
    await expect(rows).toHaveCount(3);
    // The rows carry the quarantine card testid as an attribute marker.
    await expect(
      page.locator(
        '[data-testid="fm-thread-group"][data-msg-card-testid="fm-quarantine-card"]',
      ),
    ).toHaveCount(3);
    await expect(page.getByText("Lunch tomorrow?")).toBeVisible();
    // Each quarantined row shows the `unverified` badge.
    await expect(rows.first().locator(".badge")).toContainText("unverified");
  });
});

test.describe("Compose and logout", () => {
  test("compose sheet renders and log out returns to identity list", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    await openCompose(page);

    // Sheet shows the redesigned compose form.
    const sheet = page.locator('[data-testid="fm-compose-sheet"]');
    await expect(sheet.locator(".sheet-title")).toContainText("New message");
    await expect(sheet.getByText("From")).toBeVisible();
    await expect(sheet.getByText("address1")).toBeVisible();
    await expect(sheet.getByText("To", { exact: true })).toBeVisible();
    await expect(sheet.getByText("Re", { exact: true })).toBeVisible();
    await expect(page.locator('[data-testid="fm-send"]')).toBeVisible();

    // Discard the sheet, then log out.
    await sheet.locator(".sheet-x").click();
    await expect(sheet).toHaveCount(0);
    await logout(page);

    // Back at identity list. Mobile viewports squeeze the alias text
    // off-screen inside `.id-name` (overflow: hidden in the redesigned
    // CSS), so assert the structural id-row testids instead — the row
    // is mounted whether or not its label is laid out within the
    // viewport.
    await expect(
      page.locator('[data-testid="fm-id-row"][data-alias="address1"]'),
    ).toHaveCount(1);
    await expect(
      page.locator('[data-testid="fm-id-row"][data-alias="address2"]'),
    ).toHaveCount(1);
    await expect(page.locator('[data-testid="fm-id-create"]')).toBeVisible();
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
  test("clicking Send dismisses the compose sheet", async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");
    await openCompose(page);

    await fillCompose(page, "address2", "regression check", "body");
    await clickSend(page);

    // After send, the compose sheet must disappear — proving the
    // event handler ran the spawn AND the navigation, not just paused.
    await expect(
      page.locator('[data-testid="fm-compose-sheet"]'),
    ).toHaveCount(0, { timeout: 5_000 });
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
    // Mobile viewport: alias text inside `.id-name` is overflow:hidden
    // and reports `hidden` to Playwright. Assert the structural row
    // testids instead — that's what survives reload either way.
    await expect(
      page.locator('[data-testid="fm-id-row"][data-alias="address1"]'),
    ).toHaveCount(1);
    await expect(
      page.locator('[data-testid="fm-id-row"][data-alias="address2"]'),
    ).toHaveCount(1);

    await page.reload();
    await waitForApp(page);

    await expect(
      page.locator('[data-testid="fm-id-row"][data-alias="address1"]'),
    ).toHaveCount(1);
    await expect(
      page.locator('[data-testid="fm-id-row"][data-alias="address2"]'),
    ).toHaveCount(1);
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
    await openCompose(page);
    await fillCompose(
      page,
      "address2",
      "Hello from address1",
      "This is the body of the first message.",
    );
    await clickSend(page);
    await expect(
      page.locator('[data-testid="fm-compose-sheet"]'),
    ).toHaveCount(0, { timeout: 5_000 });

    // Log out.
    await logout(page);
    await expect(page.locator('[data-testid="fm-id-create"]')).toBeVisible();

    // ── Turn 2: address2 receives and replies ──────────────────────────

    await selectIdentity(page, "address2");

    // address2's default mock messages.
    await expect(page.getByText("Ian Clarke")).toBeVisible();
    await expect(page.getByText("Re: design review")).toBeVisible();

    // The message from address1 should now appear.
    await expect(page.getByText("Hello from address1")).toBeVisible();

    // Reply: address2 → address1. (We skip opening the received message
    // here — going straight to compose is equivalent for testing message
    // delivery, not navigation state.)
    await openCompose(page);
    await fillCompose(
      page,
      "address1",
      "Reply from address2",
      "Got your message, here is my reply.",
    );
    await clickSend(page);
    await expect(
      page.locator('[data-testid="fm-compose-sheet"]'),
    ).toHaveCount(0, { timeout: 5_000 });

    // Log out.
    await logout(page);
    await expect(page.locator('[data-testid="fm-id-create"]')).toBeVisible();

    // ── Turn 3: address1 sees the reply ────────────────────────────────

    await selectIdentity(page, "address1");

    // Original mock messages should still be there.
    await expect(page.getByText("Ian's Other Account")).toBeVisible();

    // The reply from address2 should now appear.
    await expect(page.getByText("Reply from address2")).toBeVisible();

    // Open it and verify content. The fresh reply has no thread_id, so it is a
    // standalone single-message conversation (#270): clicking the row opens the
    // threaded detail with one message. Subject lands in `.ft-subj`; the body
    // is the (default-expanded, sole-leaf) `.ft-body-text`.
    await page.getByText("Reply from address2").click();
    const container = page.locator('[data-testid="fm-thread-container"]');
    await container.waitFor({ state: "attached", timeout: 10_000 });
    await expect(container.locator(".ft-subj")).toContainText(
      "Reply from address2",
    );
    await expect(
      container.locator('[data-testid="fm-thread-row"]'),
    ).toHaveCount(1);
    await expect(container).toContainText("Got your message, here is my reply.");
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
    const baseURL =
      process.env.FREENET_EMAIL_BASE_URL || "http://127.0.0.1:8092";
    await page.setContent(`
      <!DOCTYPE html>
      <html>
      <body style="margin:0;padding:0;height:100vh;">
        <iframe
          sandbox="${sandboxAttrs}"
          src="${baseURL}"
          style="width:100%;height:100%;border:none;"
        ></iframe>
      </body>
      </html>
    `);

    const iframe = page.frameLocator("iframe");
    // Pre-login renders the app brand block in the redesigned topbar;
    // post-login mounts the .fm-app shell. Either is enough to know
    // the WASM finished booting.
    await iframe
      .locator(".brand-name")
      .first()
      .waitFor({ timeout: 60_000 });
    await expect(iframe.locator(".brand-name").first()).toContainText(
      APP_NAME,
    );
  });
});

test.describe("No horizontal scrollbar at desktop width", () => {
  // The mailbox shell uses a fixed three-column flex layout. At desktop width
  // the sidebar (218px) + list (300px) + flex detail must fit inside the
  // viewport without horizontal overflow.
  test("no overflow at 1280px", async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    const hasHScroll = await page.evaluate(
      () =>
        document.documentElement.scrollWidth >
        document.documentElement.clientWidth,
    );
    expect(hasHScroll).toBe(false);
  });
});

// ── Address book: import contact and display ─────────────────────────────────
//
// This test exercises the address book import flow in offline (example-data,
// no-sync) mode. The pre-login screens (#52 work) still use Bulma; only the
// compose-side recipient badge has moved to the redesigned sheet.
//   1. Build a fake ContactCard payload using browser-native btoa.
//   2. Open the import dialog and paste the encoded token.
//   3. Assert the fingerprint panel appears and the alias pre-fills.
//   4. Complete the import and assert the contact appears in the Contacts section.
//   5. Log in as address1, type the contact alias in the redesigned compose
//      To input, confirm the recipient badge resolves it.

test.describe("Address book: import contact and display", () => {
  test("import contact card → appears in contacts section → compose accepts alias", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);

    // ── Step 1: build a fake bs58 inbox address ────────────────────────────
    // Post-#249 the wire format is the bare bs58 ContractInstanceId
    // (32-byte hash, 43-44 chars in bs58). The offline (no-sync) build
    // synthesizes deterministic placeholder pubkeys from this address so
    // the fingerprint is stable across runs and the import flow
    // exercises end-to-end without a node.
    const contactCard = "EqJ5YpEEV3XLqEvKWLQHFhGAac2qXzSUoE6k2zbdnXBr";

    // ── Step 2: open the import-contact dialog ────────────────────────────
    await page.locator('[data-testid="fm-contact-import"]').click();

    const importModal = page.locator('[data-testid="fm-import-contact-modal"]');
    await importModal.waitFor({ timeout: 5_000 });

    // ── Step 3: paste the card and assert the fingerprint panel appears ───
    await importModal.locator("textarea").fill(contactCard);

    const fingerprintPanel = page.locator('[data-testid="fm-import-fp"]');
    await expect(fingerprintPanel).toBeVisible({ timeout: 5_000 });

    // bs58 addresses don't carry a suggested alias — the user always
    // chooses their own local label.
    const labelInput = page.locator('input[placeholder="e.g. Alice (work)"]');
    await labelInput.fill("charlie-test");

    // The verify-words block lays each word out in a `.verify-word .w`
    // grid cell — pull all six and form the inline short form.
    const fingerprintWords = await fingerprintPanel
      .locator(".verify-word .w")
      .allTextContents();
    expect(fingerprintWords).toHaveLength(6);
    const fingerprintShort = `${fingerprintWords[0]}-${fingerprintWords[1]}-${fingerprintWords[2]}`;
    const fingerprintFull = fingerprintWords.join("-");

    // ── Step 4: complete import and verify contact appears ────────────────
    await page.locator('[data-testid="fm-import-submit"]').click();

    await expect(page.getByText("Contacts", { exact: true })).toBeVisible({
      timeout: 5_000,
    });

    const contactRow = page.locator(
      '[data-testid="contact-row"][data-alias="charlie-test"]',
    );
    await expect(contactRow).toBeVisible({ timeout: 5_000 });

    await expect(
      contactRow.locator('[data-testid="contact-fingerprint"]'),
    ).toContainText(fingerprintShort);
    await expect(
      contactRow.locator('[data-testid="contact-fingerprint"]'),
    ).toHaveAttribute("title", fingerprintFull);

    await expect(
      contactRow.locator('[data-testid="contact-verify-badge"]'),
    ).toContainText("⚠");

    // ── Step 5: redesigned compose recognises the contact via the badge ────
    await selectIdentity(page, "address1");
    await openCompose(page);

    const sheet = page.locator('[data-testid="fm-compose-sheet"]');
    const toInput = sheet.locator('input[placeholder="alias or address"]');
    await toInput.fill("charlie-test");

    // Badge shows `unverified` (not ticked at import) and the same
    // fingerprint short form as the contact row.
    await expect(
      page.locator('[data-testid="compose-recipient-badge-label"]'),
    ).toContainText("unverified", { timeout: 5_000 });
    await expect(
      page.locator('[data-testid="compose-recipient-fingerprint"]'),
    ).toContainText(fingerprintShort);

    // Sanity: typing a non-existent alias removes the badge.
    await toInput.fill("nobody-here");
    await expect(
      page.locator('[data-testid="compose-recipient-badge"]'),
    ).toHaveCount(0, { timeout: 2_000 });

    // Close the sheet and log out before the contact-removal step.
    await sheet.locator(".sheet-x").click();
    await logout(page);

    // ── Step 6: Remove button removes the contact (regression: needs the
    // login-controller bump in the coroutine to re-render ContactsSection).
    await expect(
      page.locator('[data-testid="contact-row"][data-alias="charlie-test"]'),
    ).toBeVisible();
    await page
      .locator(
        '[data-testid="contact-row"][data-alias="charlie-test"] [data-testid="contact-remove"]',
      )
      .click();
    await expect(
      page.locator('[data-testid="contact-row"][data-alias="charlie-test"]'),
    ).toHaveCount(0, { timeout: 5_000 });
  });
});

// Drafts (issue #47/47a). Offline mode talks to a stubbed delegate path
// (no use-node), so the optimistic local update from the compose form is
// what these tests observe. The delegate roundtrip itself is covered by
// the unit tests in `modules/mail-local-state`.
test.describe("Drafts folder (#47a)", () => {
  test("typing in compose populates Drafts; reopening restores fields", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    await openCompose(page);
    await fillCompose(page, "address2", "draft subject", "draft body text");

    // Close the sheet without sending: draft should persist in the folder.
    const sheet = page.locator('[data-testid="fm-compose-sheet"]');
    await sheet.locator(".sheet-x").click();
    await expect(sheet).toHaveCount(0);

    // Switch to Drafts. The card carries the typed To/subject/body.
    await page.locator('[data-testid="fm-folder-drafts"]').click();
    const draftCard = page
      .locator('[data-testid="fm-draft-card"]')
      .first();
    await expect(draftCard).toBeVisible();
    await expect(draftCard.locator(".msg-sender")).toContainText("address2");
    await expect(draftCard.locator(".msg-subj")).toContainText(
      "draft subject",
    );
    await expect(draftCard.locator(".msg-prev")).toContainText(
      "draft body text",
    );

    // Click the card → compose sheet re-opens with fields prefilled.
    await draftCard.click();
    const reopened = page.locator('[data-testid="fm-compose-sheet"]');
    await reopened.waitFor({ timeout: 5_000 });
    await expect(
      reopened.locator('input[placeholder="alias or address"]'),
    ).toHaveValue("address2");
    await expect(
      reopened.locator('input[placeholder="subject"]'),
    ).toHaveValue("draft subject");
    await expect(reopened.locator("textarea.sheet-textarea")).toHaveValue(
      "draft body text",
    );
  });

  test("Discard removes the draft", async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    await openCompose(page);
    await fillCompose(page, "address2", "to be discarded", "throwaway");

    // Discard from the footer button.
    const sheet = page.locator('[data-testid="fm-compose-sheet"]');
    await sheet.getByRole("button", { name: "Discard" }).click();
    await expect(sheet).toHaveCount(0);

    // Drafts folder is empty again.
    await page.locator('[data-testid="fm-folder-drafts"]').click();
    await expect(page.locator('[data-testid="fm-draft-card"]')).toHaveCount(0);
  });

  test("Send removes the draft", async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    await openCompose(page);
    await fillCompose(page, "address2", "send and clear", "body");

    await Promise.all([
      page.locator('[data-testid="fm-compose-sheet"]').waitFor({ state: "detached", timeout: 10_000 }),
      clickSend(page),
    ]);

    await page.locator('[data-testid="fm-folder-drafts"]').click();
    await expect(page.locator('[data-testid="fm-draft-card"]')).toHaveCount(0);
  });

  test("draft folder count badge reflects pending drafts", async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    const draftsBtn = page.locator('[data-testid="fm-folder-drafts"]');
    // Initially no count badge text.
    await expect(draftsBtn.locator(".count")).toHaveText("");

    await openCompose(page);
    await fillCompose(page, "address2", "counted", "yo");
    const sheet = page.locator('[data-testid="fm-compose-sheet"]');
    await sheet.locator(".sheet-x").click();

    await expect(draftsBtn.locator(".count")).toHaveText("1");
  });
});

// ── Pre-login redesign coverage (issue #52) ───────────────────────────────
//
// These tests pin the redesigned login + address-book flows so they don't
// regress silently. Offline mode's coroutine handles CreateContact /
// DeleteContact only — CreateIdentity is dropped — so the assertions stop
// at the UI surface (form → reveal → dismiss). The actual identity
// commit + delegate roundtrip is exercised by `live-node.spec.ts`.

test.describe("Create-alias reveal stage (#52)", () => {
  test("form → Generate shows six-word fingerprint + amber nudge", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);

    await page.locator('[data-testid="fm-id-create"]').click();
    await page.locator('[data-testid="fm-create-alias-input"]').fill("mira");
    await page.locator('[data-testid="fm-create-submit"]').click();

    // Reveal stage replaces the form. The six-word grid is rendered as
    // `.verify-word .w` cells inside the heading "Your fingerprint" card.
    await expect(page.getByText("Your fingerprint")).toBeVisible({
      timeout: 5_000,
    });
    const words = await page.locator(".verify-word .w").allTextContents();
    expect(words).toHaveLength(6);
    for (const w of words) {
      expect(w.trim().length).toBeGreaterThan(0);
    }

    // Amber backup nudge.
    await expect(page.getByText(/Back up the key before you continue/)).toBeVisible();

    // Discard returns to hub.
    await page.getByRole("button", { name: "Discard" }).click();
    await expect(
      page.locator('[data-testid="fm-id-row"][data-alias="address1"]'),
    ).toBeVisible();
  });

  // #117 — refuse-with-error guard. Typing an alias that already exists
  // in offline mode (`address1`) must NOT advance to the reveal stage; an
  // inline error banner replaces the form's six-word fingerprint reveal.
  test("submitting an existing alias name shows an error and does not reveal keys", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);

    await page.locator('[data-testid="fm-id-create"]').click();
    await page.locator('[data-testid="fm-create-alias-input"]').fill("address1");
    await page.locator('[data-testid="fm-create-submit"]').click();

    await expect(
      page.getByText(/An identity named "address1" already exists/i),
    ).toBeVisible({ timeout: 3_000 });
    await expect(
      page.getByRole("heading", { name: "Your fingerprint" }),
    ).toHaveCount(0);
  });
});

test.describe("Share modal (#52)", () => {
  test("opens with six-word fingerprint, bs58 inbox address, and copy button", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);

    await page
      .locator('[data-testid="fm-id-row"][data-alias="address1"] [data-testid="fm-id-share"]')
      .click();

    const modal = page.locator('[data-testid="fm-share-modal"]');
    await expect(modal).toBeVisible({ timeout: 5_000 });

    // Six-word fingerprint grid.
    const words = await modal.locator(".verify-word .w").allTextContents();
    expect(words).toHaveLength(6);

    // Token block carries the bs58 inbox address (43-44 chars); the
    // full share text (address + verify line) rides on `data-share-text`.
    const shareText = await modal.getAttribute("data-share-text");
    expect(shareText).toMatch(/^[1-9A-HJ-NP-Za-km-z]{43,44}\nverify: /);

    // Copy button + close. mobile-chrome stacks columns and pre-login
    // background rows (id-rows, contact-rows, brand) intercept pointer
    // events at the modal-x position, so a synthetic click is needed
    // — same pattern used by the toolbar action tests below.
    await expect(page.locator('[data-testid="fm-share-copy"]')).toBeVisible();
    await modal.locator(".modal-x").dispatchEvent("click");
    await expect(modal).toHaveCount(0);
  });
});

test.describe("Import contact verify-check (#52)", () => {
  test("ticking the verify card flips the contact's badge to verified", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);

    // Same fake card the offline import test uses, but we tick the
    // verify-check before submitting and assert the row gets the
    // trust-green badge instead of the warn-amber one.
    const contactCard = "AmcVD92D3UjMxgC5JfqgFm78qmKCBmw2qBSDocsfYBJa";

    await page.locator('[data-testid="fm-contact-import"]').click();
    const importModal = page.locator('[data-testid="fm-import-contact-modal"]');
    await importModal.locator("textarea").fill(contactCard);
    await page
      .locator('input[placeholder="e.g. Alice (work)"]')
      .fill("delta-test");

    // Tick the meaningful verify card.
    const check = page.locator('[data-testid="fm-verify-check"]');
    await expect(check).toBeVisible();
    await check.click();
    // Class change confirms the visual lock-in.
    await expect(check).toHaveClass(/checked/);

    await page.locator('[data-testid="fm-import-submit"]').click();

    const row = page.locator(
      '[data-testid="contact-row"][data-alias="delta-test"]',
    );
    await expect(row).toBeVisible({ timeout: 5_000 });
    // Verified path — green ✓ badge, not the amber ⚠ one.
    await expect(
      row.locator('[data-testid="contact-verify-badge"]'),
    ).toContainText("✓");
  });

  // Regression for #87 — promote an unverified contact via the row's
  // Verify button. The row had no escape from `⚠ unverified` short of
  // delete-and-reimport, which also dropped the local description.
  test("Verify button promotes an unverified contact in place (#87)", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);

    const contactCard = "5kKKaNuU8RXkbZH1J1pzkRRJiGqYJqFFR5rsTBHpAk2y";

    // Import without ticking the verify checkbox.
    await page.locator('[data-testid="fm-contact-import"]').click();
    const importModal = page.locator('[data-testid="fm-import-contact-modal"]');
    await importModal.locator("textarea").fill(contactCard);
    await page
      .locator('input[placeholder="e.g. Alice (work)"]')
      .fill("echo-test");
    await page.locator('[data-testid="fm-import-submit"]').click();

    const row = page.locator(
      '[data-testid="contact-row"][data-alias="echo-test"]',
    );
    await expect(row).toBeVisible({ timeout: 5_000 });
    await expect(
      row.locator('[data-testid="contact-verify-badge"]'),
    ).toContainText("⚠");

    // The ⚠ badge itself is the primary CTA — clicking it opens the
    // verify modal (#228). The adjacent Verify button still works as a
    // fallback (covered below).
    await row.locator('[data-testid="contact-verify-badge"]').click();
    const verifyModal = page.locator('[data-testid="fm-verify-contact-modal"]');
    await expect(verifyModal).toBeVisible({ timeout: 5_000 });
    // Close it so the rest of the test exercises the explicit Verify button.
    await page.keyboard.press("Escape").catch(() => {});
    await verifyModal
      .locator(".modal-x")
      .click()
      .catch(() => {});
    await expect(verifyModal).toBeHidden({ timeout: 5_000 });

    // Row also exposes an explicit Verify button while the badge is amber.
    await row.locator('[data-testid="fm-contact-verify"]').click();
    await expect(verifyModal).toBeVisible({ timeout: 5_000 });

    // Submit is disabled until the same six-word checkbox is ticked.
    const submit = page.locator('[data-testid="fm-verify-contact-submit"]');
    await expect(submit).toBeDisabled();
    await page.locator('[data-testid="fm-verify-check"]').click();
    await expect(submit).toBeEnabled();
    await submit.click();

    // Modal closes, badge flips to green ✓, and the Verify button is
    // gone (only rendered for unverified rows).
    await expect(verifyModal).toBeHidden();
    await expect(
      row.locator('[data-testid="contact-verify-badge"]'),
    ).toContainText("✓", { timeout: 5_000 });
    await expect(row.locator('[data-testid="fm-contact-verify"]')).toHaveCount(
      0,
    );
  });
});

test.describe("Restore backup card (#52)", () => {
  test("opens a file-picker form with disabled Restore until a backup is parsed", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);

    await page.locator('[data-testid="fm-id-restore"]').click();

    // Heading + amber nudge.
    await expect(page.getByText("Restore identity")).toBeVisible({
      timeout: 5_000,
    });
    await expect(
      page.getByText(/Backup files contain raw private keys\./),
    ).toBeVisible();

    // File input + alias/description placeholders.
    await expect(
      page.locator('[data-testid="fm-restore-file"]'),
    ).toBeVisible();
    await expect(
      page.locator('input[placeholder="pre-filled from backup file"]').first(),
    ).toBeVisible();

    // Restore stays disabled until a parsed backup is in hand.
    await expect(
      page.locator('[data-testid="fm-restore-submit"]'),
    ).toBeDisabled();

    // Cancel returns to hub.
    await page.getByRole("button", { name: "Cancel" }).click();
    await expect(
      page.locator('[data-testid="fm-id-row"][data-alias="address1"]'),
    ).toBeVisible();
  });
});

// Sent (issue #47/47b). Offline mode talks to a stubbed delegate path; the
// UI's optimistic local snapshot is what these tests observe. Real-node
// delegate roundtrip is tracked in the 47a-coverage-gap follow-up.
test.describe("Sent folder (#47b)", () => {
  test("Send populates Sent; click renders detail panel", async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    await openCompose(page);
    await fillCompose(page, "address2", "sent subject", "sent body");
    await Promise.all([
      page
        .locator('[data-testid="fm-compose-sheet"]')
        .waitFor({ state: "detached", timeout: 10_000 }),
      clickSend(page),
    ]);

    await page.locator('[data-testid="fm-folder-sent"]').click();
    const card = page.locator('[data-testid="fm-sent-card"]').first();
    await expect(card).toBeVisible();
    await expect(card.locator(".msg-sender")).toContainText("address2");
    await expect(card.locator(".msg-subj")).toContainText("sent subject");

    await card.click();
    await expect(page.locator(".detail-subj")).toContainText("sent subject");
    await expect(page.locator('[data-testid="fm-sent-body"]')).toContainText(
      "sent body",
    );
    // Element is rendered (text checked) — visibility is viewport-dependent
    // on mobile-chrome where detail-col sits below the fold.
    await expect(page.locator('[data-testid="fm-sent-fingerprint"]')).toHaveCount(1);
  });

  test("Sent count badge reflects sent messages", async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    const sentBtn = page.locator('[data-testid="fm-folder-sent"]');
    await expect(sentBtn.locator(".count")).toHaveText("");

    await openCompose(page);
    await fillCompose(page, "address2", "first", "body");
    await Promise.all([
      page
        .locator('[data-testid="fm-compose-sheet"]')
        .waitFor({ state: "detached", timeout: 10_000 }),
      clickSend(page),
    ]);

    await expect(sentBtn.locator(".count")).toHaveText("1");
  });

  test("Reply prefills recipient + Re: subject", async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    await openCompose(page);
    await fillCompose(page, "address2", "original", "hello");
    await Promise.all([
      page
        .locator('[data-testid="fm-compose-sheet"]')
        .waitFor({ state: "detached", timeout: 10_000 }),
      clickSend(page),
    ]);

    await page.locator('[data-testid="fm-folder-sent"]').click();
    await page.locator('[data-testid="fm-sent-card"]').first().click();
    // Mobile viewports stack columns and the message list overlays the
    // detail toolbar — the native click event is intercepted by the list-col
    // pointer surface even with `force: true`. dispatchEvent fires the
    // synthetic click directly on the button, which Dioxus's event delegator
    // picks up regardless of layout.
    await page.locator('[data-testid="fm-sent-reply"]').dispatchEvent("click");

    const sheet = page.locator('[data-testid="fm-compose-sheet"]');
    await sheet.waitFor({ timeout: 5_000 });
    await expect(sheet.locator('input[placeholder="alias or address"]')).toHaveValue(
      "address2",
    );
    await expect(sheet.locator('input[placeholder="subject"]')).toHaveValue(
      "Re: original",
    );
    // #270: the reply rework replaced the "> "-prefixed body quote with a
    // STRUCTURED quoted_excerpt that rides on the outgoing message (not the
    // textarea). The body now starts EMPTY — assert no legacy "> " hack.
    const body = await sheet.locator("textarea.sheet-textarea").inputValue();
    expect(body).toBe("");
    expect(body).not.toContain("> ");
  });

  test("Forward prefills blank recipient + Fwd: subject + verbatim body", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    await openCompose(page);
    await fillCompose(page, "address2", "fwd-me", "first line\nsecond line");
    await Promise.all([
      page
        .locator('[data-testid="fm-compose-sheet"]')
        .waitFor({ state: "detached", timeout: 10_000 }),
      clickSend(page),
    ]);

    await page.locator('[data-testid="fm-folder-sent"]').click();
    await page.locator('[data-testid="fm-sent-card"]').first().click();
    await page.locator('[data-testid="fm-sent-forward"]').dispatchEvent("click");

    const sheet = page.locator('[data-testid="fm-compose-sheet"]');
    await sheet.waitFor({ timeout: 5_000 });
    await expect(sheet.locator('input[placeholder="alias or address"]')).toHaveValue("");
    await expect(sheet.locator('input[placeholder="subject"]')).toHaveValue(
      "Fwd: fwd-me",
    );
    // #270: a forward starts a NEW conversation and keeps the original body
    // VERBATIM (ui/src/app.rs::OpenSentMessage forward_prefill) — no more
    // "> "-prefixed quoting.
    await expect(sheet.locator("textarea.sheet-textarea")).toHaveValue(
      "first line\nsecond line",
    );
  });

  test("Resend prefills identical recipient/subject/body", async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    await openCompose(page);
    await fillCompose(page, "address2", "resend-me", "again");
    await Promise.all([
      page
        .locator('[data-testid="fm-compose-sheet"]')
        .waitFor({ state: "detached", timeout: 10_000 }),
      clickSend(page),
    ]);

    await page.locator('[data-testid="fm-folder-sent"]').click();
    await page.locator('[data-testid="fm-sent-card"]').first().click();
    await page.locator('[data-testid="fm-sent-resend"]').dispatchEvent("click");

    const sheet = page.locator('[data-testid="fm-compose-sheet"]');
    await sheet.waitFor({ timeout: 5_000 });
    await expect(sheet.locator('input[placeholder="alias or address"]')).toHaveValue(
      "address2",
    );
    await expect(sheet.locator('input[placeholder="subject"]')).toHaveValue(
      "resend-me",
    );
    await expect(sheet.locator("textarea.sheet-textarea")).toHaveValue("again");
  });
});

// Issue #32 — rename own identity. Delete+create with same key at the
// UI layer. Offline mode handles the action by relabelling ALIASES;
// the use-node delegate round-trip is exercised by live-node.spec.ts.
test.describe("Rename identity (#32)", () => {
  test("renames an id-row in place and surfaces the new alias", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);

    const row = page.locator('[data-testid="fm-id-row"][data-alias="address2"]');
    await row.locator('[data-testid="fm-id-rename"]').click();

    const input = page.locator('[data-testid="fm-rename-input"]');
    await input.waitFor({ timeout: 5_000 });
    await input.fill("workmate");

    await page.locator('[data-testid="fm-rename-submit"]').click();

    await expect(
      page.locator('[data-testid="fm-id-row"][data-alias="workmate"]'),
    ).toBeVisible({ timeout: 5_000 });
    // Old alias is gone.
    await expect(
      page.locator('[data-testid="fm-id-row"][data-alias="address2"]'),
    ).toHaveCount(0);
  });

  test("refuses to rename to an alias that already exists", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);

    const row = page.locator('[data-testid="fm-id-row"][data-alias="address1"]');
    await row.locator('[data-testid="fm-id-rename"]').click();

    const input = page.locator('[data-testid="fm-rename-input"]');
    await input.waitFor({ timeout: 5_000 });
    await input.fill("address2");

    await page.locator('[data-testid="fm-rename-submit"]').click();

    // Inline error surfaces; the row keeps its original data-alias and
    // the editor stays open.
    await expect(page.getByText(/already in use/)).toBeVisible({
      timeout: 5_000,
    });
    await expect(
      page.locator('[data-testid="fm-id-row"][data-alias="address1"]'),
    ).toBeVisible();
  });
});

// Delete own identity (offline branch). Online use-node branch round-trips
// through the identity-management delegate; covered by live-node.spec.ts
// when the harness includes a delete step.
test.describe("Delete identity", () => {
  test("deletes an id-row after confirming the alias verbatim", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);

    const row = page.locator('[data-testid="fm-id-row"][data-alias="address2"]');
    await expect(row).toBeVisible();
    await row.locator('[data-testid="fm-id-delete"]').click();

    const input = page.locator('[data-testid="fm-delete-confirm-input"]');
    await input.waitFor({ timeout: 5_000 });
    await input.fill("address2");

    await page.locator('[data-testid="fm-delete-confirm-submit"]').click();

    await expect(
      page.locator('[data-testid="fm-id-row"][data-alias="address2"]'),
    ).toHaveCount(0, { timeout: 5_000 });
    // address1 stays.
    await expect(
      page.locator('[data-testid="fm-id-row"][data-alias="address1"]'),
    ).toBeVisible();
  });

  test("refuses to delete without the alias typed verbatim", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);

    const row = page.locator('[data-testid="fm-id-row"][data-alias="address1"]');
    await row.locator('[data-testid="fm-id-delete"]').click();

    const input = page.locator('[data-testid="fm-delete-confirm-input"]');
    await input.waitFor({ timeout: 5_000 });
    await input.fill("wrong-alias");

    await page.locator('[data-testid="fm-delete-confirm-submit"]').click();

    await expect(page.getByText(/Type the alias exactly/)).toBeVisible({
      timeout: 5_000,
    });
    // Row still there.
    await expect(
      page.locator('[data-testid="fm-id-row"][data-alias="address1"]'),
    ).toBeVisible();
  });
});

// Archive (issue #47/47c). Archive splits from Delete: Archive stashes the
// message locally and removes it from the inbox contract; Delete only
// removes (no local trace). Re-PUT-on-unarchive lands in #60.
test.describe("Archive folder (#47c)", () => {
  test("Archive moves message from Inbox to Archive folder", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    // #270: inbox rows are thread groups. Use the STANDALONE row id=3
    // ("Welcome to the offline preview") — a one-message conversation —
    // so archiving its sole row empties the conversation and removes the
    // top-level row, matching the original single-message semantics.
    await page.locator("#email-inbox-accessor-3").click();
    const container = page.locator('[data-testid="fm-thread-container"]');
    await container.waitFor({ state: "attached", timeout: 10_000 });
    await expect(container.locator(".ft-subj")).toContainText(
      "Welcome to the offline preview",
    );

    // Archive the single thread row via its per-row Archive action (#270
    // BLOCKER-1). dispatchEvent fires the synthetic click directly so a
    // stacked list-col on mobile viewports can't intercept it.
    const row = container.locator(
      '[data-testid="fm-thread-row"][data-msg-id="3"]',
    );
    await row.locator('[data-testid="fm-archive"]').dispatchEvent("click");

    // Inbox no longer shows the row (removing the sole member empties the
    // conversation → returns to the list, group row gone).
    await expect(page.locator("#email-inbox-accessor-3")).toHaveCount(0);

    // Archive folder shows the row.
    await page.locator('[data-testid="fm-folder-archive"]').click();
    const card = page.locator('[data-testid="fm-archive-card"]').first();
    await expect(card).toBeVisible();
    await expect(card.locator(".msg-subj")).toContainText(
      "Welcome to the offline preview",
    );

    await card.click();
    await expect(page.locator(".detail-subj")).toContainText(
      "Welcome to the offline preview",
    );
    // Unarchive button is intentionally hidden (not just disabled)
    // until #60 lands — the dead affordance was confusing per user
    // feedback. Assert it's absent rather than disabled.
    const unarchive = page.locator('[data-testid="fm-archive-unarchive"]');
    await expect(unarchive).toHaveCount(0);
  });

  test("Delete from Inbox does not produce an Archive entry", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    // Standalone row id=4 ("Your weekly digest") — delete its sole row.
    await page.locator("#email-inbox-accessor-4").click();
    const container = page.locator('[data-testid="fm-thread-container"]');
    await container.waitFor({ state: "attached", timeout: 10_000 });
    await container
      .locator('[data-testid="fm-thread-row"][data-msg-id="4"]')
      .locator('[data-testid="fm-delete"]')
      .dispatchEvent("click");

    await expect(page.locator("#email-inbox-accessor-4")).toHaveCount(0);

    await page.locator('[data-testid="fm-folder-archive"]').click();
    await expect(page.locator('[data-testid="fm-archive-card"]')).toHaveCount(0);
  });

  test("Archive count badge reflects archived rows", async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    const archiveBtn = page.locator('[data-testid="fm-folder-archive"]');
    await expect(archiveBtn.locator(".count")).toHaveText("");

    // Archive the standalone "Your weekly digest" (id=4).
    await page.locator("#email-inbox-accessor-4").click();
    const container = page.locator('[data-testid="fm-thread-container"]');
    await container.waitFor({ state: "attached", timeout: 10_000 });
    await container
      .locator('[data-testid="fm-thread-row"][data-msg-id="4"]')
      .locator('[data-testid="fm-archive"]')
      .dispatchEvent("click");

    await expect(archiveBtn.locator(".count")).toHaveText("1");
  });

  test("archiving one message in a conversation drops the thread count", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    // The seeded "Lunch tomorrow?" conversation (root_id=0) has 3 members.
    const group = page
      .locator('[data-testid="fm-thread-group"]')
      .filter({ hasText: "Lunch tomorrow?" });
    await expect(group.locator(".ft-count")).toHaveText("3");

    await page.locator("#email-inbox-accessor-0").click();
    const container = page.locator('[data-testid="fm-thread-container"]');
    await container.waitFor({ state: "attached", timeout: 10_000 });
    await expect(
      container.locator('[data-testid="fm-thread-row"]'),
    ).toHaveCount(3);

    // Archive the leaf reply (id=2). It's NOT the root, and members remain,
    // so the detail re-opens the now-smaller thread instead of bouncing to
    // the list. The thread row count drops 3 → 2.
    await container
      .locator('[data-testid="fm-thread-row"][data-msg-id="2"]')
      .locator('[data-testid="fm-archive"]')
      .dispatchEvent("click");
    await expect(
      container.locator('[data-testid="fm-thread-row"]'),
    ).toHaveCount(2);

    // Back at the list the conversation's count badge has dropped to 2.
    await expect(group.locator(".ft-count")).toHaveText("2");

    // The archived reply landed in Archive.
    await page.locator('[data-testid="fm-folder-archive"]').click();
    await expect(
      page.locator('[data-testid="fm-archive-card"]'),
    ).toHaveCount(1);
  });

  test("deleting one message in a conversation drops the thread count", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    const group = page
      .locator('[data-testid="fm-thread-group"]')
      .filter({ hasText: "Lunch tomorrow?" });
    await expect(group.locator(".ft-count")).toHaveText("3");

    await page.locator("#email-inbox-accessor-0").click();
    const container = page.locator('[data-testid="fm-thread-container"]');
    await container.waitFor({ state: "attached", timeout: 10_000 });

    // Delete the mid reply (id=1) — a non-root member; the thread stays open.
    await container
      .locator('[data-testid="fm-thread-row"][data-msg-id="1"]')
      .locator('[data-testid="fm-delete"]')
      .dispatchEvent("click");
    await expect(
      container.locator('[data-testid="fm-thread-row"]'),
    ).toHaveCount(2);
    await expect(group.locator(".ft-count")).toHaveText("2");

    // Delete leaves no Archive trace.
    await page.locator('[data-testid="fm-folder-archive"]').click();
    await expect(
      page.locator('[data-testid="fm-archive-card"]'),
    ).toHaveCount(0);
  });

  test("Delete on archived row removes it from Archive too", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    // Archive the standalone "Welcome…" (id=3), then delete it in Archive.
    await page.locator("#email-inbox-accessor-3").click();
    const container = page.locator('[data-testid="fm-thread-container"]');
    await container.waitFor({ state: "attached", timeout: 10_000 });
    await container
      .locator('[data-testid="fm-thread-row"][data-msg-id="3"]')
      .locator('[data-testid="fm-archive"]')
      .dispatchEvent("click");

    await page.locator('[data-testid="fm-folder-archive"]').click();
    await page.locator('[data-testid="fm-archive-card"]').first().click();
    await page.locator('[data-testid="fm-archive-delete"]').dispatchEvent("click");

    await expect(page.locator('[data-testid="fm-archive-card"]')).toHaveCount(0);
  });
});

test.describe("Message timestamps (#49)", () => {
  test("inbox cards show timestamps and sort newest-first", async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    const times = page.locator('[data-testid="fm-msg-time"]');
    // #270: address1's 5 example messages collapse into 3 inbox rows (the
    // "Lunch tomorrow?" conversation + 2 standalone), each row carrying one
    // `fm-msg-time` on its `.ft-group-time`.
    await expect(times).toHaveCount(3);
    // First one (~15min ago) is rendered as `H:MM`, contains a colon.
    await expect(times.first()).toContainText(":");

    // Newest-first sort over the grouped rows (`fm-thread-group`, keyed by
    // root_id via data-msg-id). Each group sorts by its NEWEST member:
    //   id=3 "Welcome…"        ~15min ago   (newest)
    //   id=0 "Lunch…" thread   newest member id=2, ~26h ago
    //   id=4 "Your weekly…"    ~4 days ago  (oldest)
    // So the DOM order of root ids is 3, 0, 4.
    const idAttrs = await page
      .locator('[data-testid="fm-thread-group"]')
      .evaluateAll((els) => els.map((e) => e.getAttribute("data-msg-id")));
    expect(idAttrs.indexOf("3")).toBeLessThan(idAttrs.indexOf("0"));
    expect(idAttrs.indexOf("0")).toBeLessThan(idAttrs.indexOf("4"));
  });

  test("thread row shows a per-message timestamp", async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    // #270: the threaded detail has no single `fm-detail-time` header; each
    // message row carries its own short timestamp (`.ft-msg-time`, which is
    // also the Nested expand control `fm-thread-expand`). Open the recent
    // standalone "Welcome…" (id=3, ~15min ago) — its short time is H:MM.
    await page.locator("#email-inbox-accessor-3").click();
    const container = page.locator('[data-testid="fm-thread-container"]');
    await container.waitFor({ state: "attached", timeout: 10_000 });

    const rowTime = container
      .locator('[data-testid="fm-thread-row"][data-msg-id="3"]')
      .locator('[data-testid="fm-thread-expand"]');
    await expect(rowTime).toHaveCount(1);
    // Today → rendered as `H:MM`, so it contains a colon.
    await expect(rowTime).toContainText(/\d{1,2}:\d{2}/);
  });
});

test.describe("Sender trust badge (#51)", () => {
  test("thread row shows a per-message trust pill for incoming message", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");
    await page.locator("#email-inbox-accessor-0").click();

    // #270: the threaded detail surfaces trust per message via the `.ft-pill`
    // (ui/src/app.rs::thread_pill) instead of the single-message header's
    // `fm-detail-verif`. example-data messages are unsigned (no real send
    // path), so the pill reads "unsigned".
    const container = page.locator('[data-testid="fm-thread-container"]');
    await container.waitFor({ state: "attached", timeout: 10_000 });
    const pills = container.locator(".ft-pill");
    // Presence + content (the detail-col collapses to zero-size on mobile).
    await expect(pills.first()).toContainText("unsigned");
  });

  test("compose sheet shows 'Sending as: <fingerprint>' label", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");
    await page.locator('[data-testid="fm-compose-btn"]').click();

    const label = page.locator('[data-testid="fm-compose-sending-as"]');
    await expect(label).toHaveCount(1);
    // "Sending as: <three-word fingerprint>".
    await expect(label).toHaveText(/^Sending as: [a-z]+-[a-z]+-[a-z]+$/);
    // Tooltip exposes the full six-word fingerprint.
    await expect(label).toHaveAttribute(
      "title",
      /^[a-z]+-[a-z]+-[a-z]+-[a-z]+-[a-z]+-[a-z]+$/,
    );
  });
});

test.describe("Sidebar fingerprint (#48)", () => {
  test("sidebar shows three-word fingerprint for active identity", async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    const fp = page.locator('[data-testid="fm-sidebar-fingerprint"]');
    await expect(fp).toHaveCount(1);
    // Three BIP-39 words joined by `-`, lowercase a-z only.
    await expect(fp).toHaveText(/^[a-z]+-[a-z]+-[a-z]+$/);
    // Hover tooltip carries the full six-word fingerprint.
    await expect(fp).toHaveAttribute(
      "title",
      /^[a-z]+-[a-z]+-[a-z]+-[a-z]+-[a-z]+-[a-z]+$/,
    );
  });

  test("fingerprint changes when switching identities", async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    const fp = page.locator('[data-testid="fm-sidebar-fingerprint"]');
    const fpA = await fp.textContent();

    await page.locator('[data-testid="fm-logout"]').click();
    await selectIdentity(page, "address2");

    const fpB = await fp.textContent();
    expect(fpA).not.toEqual(fpB);
  });
});

// Issue #58 — per-message delivery ack from the inbox contract. The
// offline build (`example-data,no-sync`) has no async ack signal, so
// the UI sets `Delivered` synchronously. These tests guard the offline
// happy path; the use-node Pending → Delivered/Failed transitions are
// driven by the api.rs UpdateResponse handler and exercised in
// live-node.spec.ts.
test.describe("Sent delivery state (#58)", () => {
  test("offline send marks the Sent row Delivered", async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    await openCompose(page);
    await fillCompose(page, "address2", "delivered subj", "delivered body");
    await Promise.all([
      page
        .locator('[data-testid="fm-compose-sheet"]')
        .waitFor({ state: "detached", timeout: 10_000 }),
      clickSend(page),
    ]);

    await page.locator('[data-testid="fm-folder-sent"]').click();
    const card = page.locator('[data-testid="fm-sent-card"]').first();
    await expect(card).toBeVisible();
    await expect(card).toHaveAttribute("data-delivery-state", "Delivered");
    // Delivered is the happy path → no badge rendered.
    await expect(card.locator(".badge-pending")).toHaveCount(0);
    await expect(card.locator(".badge-failed")).toHaveCount(0);

    await card.click();
    await expect(page.locator('[data-testid="fm-sent-delivery"]')).toContainText(
      "delivered",
    );
  });
});

// ── bs58 inbox address as the wire format (#249) ──────────────────────────────
//
// Post-#249 ContactCard collapses to the bare bs58 ContractInstanceId. The
// recipient's anti-flood policy is no longer on the card — it lives on the
// inbox state itself (`Inbox::settings.minimum_tier` + `max_age_secs`), so
// the sender reads it back at import time via the inbox-state Get.

test.describe("ContactCard #249 — bs58 wire format", () => {
  test("bs58 inbox address imports successfully", async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);

    const contactCard = "9Z2RVTGgN3KX31fL6gp17hAjQXfRkx1cAcPwgkLh8WSY";

    await page.locator('[data-testid="fm-contact-import"]').click();
    const importModal = page.locator('[data-testid="fm-import-contact-modal"]');
    await importModal.waitFor({ timeout: 5_000 });

    await importModal.locator("textarea").fill(contactCard);

    const fingerprintPanel = page.locator('[data-testid="fm-import-fp"]');
    await expect(fingerprintPanel).toBeVisible({ timeout: 5_000 });

    await page
      .locator('input[placeholder="e.g. Alice (work)"]')
      .fill("bs58-contact");
    await page.locator('[data-testid="fm-import-submit"]').click();

    const contactRow = page.locator(
      '[data-testid="contact-row"][data-alias="bs58-contact"]',
    );
    await expect(contactRow).toBeVisible({ timeout: 5_000 });
  });

  test("invalid bs58 input is rejected with no fingerprint panel", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);

    await page.locator('[data-testid="fm-contact-import"]').click();
    const importModal = page.locator('[data-testid="fm-import-contact-modal"]');
    await importModal.waitFor({ timeout: 5_000 });
    // 0/O/I/l are excluded from the bs58 alphabet; whitespace too.
    await importModal.locator("textarea").fill("not a real address");

    // Fingerprint panel must NOT render (decoder rejected the address).
    await expect(page.locator('[data-testid="fm-import-fp"]')).toHaveCount(0);
  });
});

// ── Regression: #158 — contact modals dead inside inbox ──────────────────────
//
// Before the fix the ImportContact / ShareContact / SharePending signals were
// provided only by the login pane (IdentifiersList). Once the user logged in
// the login pane unmounted, taking the signal providers with it.  Any attempt
// to open a modal from Settings → Contacts inside the inbox would silently
// no-op because `use_context` found no provider.
//
// The fix lifts the three signals to the app() root so they survive the
// login → inbox transition.  These tests guard the regression path:
//   1. enter the inbox (signals survive the mount transition)
//   2. open Settings → Contacts via the sidebar button
//   3. click Import… → ImportContactForm modal must appear
//   4. close modal, click Share my card → ShareContactModal must appear
//
// A separate pair of tests confirms the same modals still open from the
// pre-login screen (IdentifiersList) so we don't regress the original flow.
test.describe("Regression #158: contact modals mount inside inbox", () => {
  // The regression we guard against is `modal silently fails to open` —
  // i.e. the trigger button no-ops because `use_context` finds no
  // provider after the login → inbox mount transition. Asserting the
  // modal becomes visible is sufficient to prove the fix; we do not
  // bother dismissing it (`.modal-x` clicks are layout-flaky on the
  // mobile-chrome profile because narrow viewports stack columns and
  // background elements intercept pointer events — see how
  // `fm-archive` etc. rely on `dispatchEvent('click')`).
  test("Import… button inside inbox opens ImportContactForm modal", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    // Open Settings → Contacts via the sidebar button.
    await page.locator('[data-testid="fm-sidebar-contacts"]').click();
    await page
      .locator('[data-testid="fm-settings-shell"]')
      .waitFor({ timeout: 5_000 });

    // Click the Import… button that lives inside the Contacts settings screen.
    await page.locator('[data-testid="fm-contacts-import-btn"]').click();

    // The modal must appear — before the fix this was a silent no-op.
    const importModal = page.locator('[data-testid="fm-import-contact-modal"]');
    await expect(importModal).toBeVisible({ timeout: 5_000 });
  });

  test("Share my card button inside inbox opens ShareContactModal", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    // Open Settings → Contacts via the sidebar button.
    await page.locator('[data-testid="fm-sidebar-contacts"]').click();
    await page
      .locator('[data-testid="fm-settings-shell"]')
      .waitFor({ timeout: 5_000 });

    // Click the Share my card button inside the Contacts settings screen.
    await page.locator('[data-testid="fm-contacts-share-btn"]').click();

    // The modal must appear — before the fix this was a silent no-op.
    const shareModal = page.locator('[data-testid="fm-share-modal"]');
    await expect(shareModal).toBeVisible({ timeout: 5_000 });

    // Share modal token block holds the bs58 inbox address (#249 — was
    // `contact://<base64-json>` pre-PR; now ~44-char bs58 string).
    await expect(shareModal.locator(".token-block")).toContainText(
      /[1-9A-HJ-NP-Za-km-z]{43,44}/,
    );
  });

  // Confirm the pre-login flows that triggered these modals from the
  // identity list are still intact after the signal lift.
  test("Import… button on login pane still opens ImportContactForm modal", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);

    // Pre-login: fm-contact-import is the import trigger on the identity list.
    await page.locator('[data-testid="fm-contact-import"]').click();
    const importModal = page.locator('[data-testid="fm-import-contact-modal"]');
    await expect(importModal).toBeVisible({ timeout: 5_000 });
  });

  test("Share button on identity row still opens ShareContactModal", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);

    // Pre-login: fm-id-share on an identity row triggers the share modal.
    await page
      .locator(
        '[data-testid="fm-id-row"][data-alias="address1"] [data-testid="fm-id-share"]',
      )
      .click();
    const shareModal = page.locator('[data-testid="fm-share-modal"]');
    await expect(shareModal).toBeVisible({ timeout: 5_000 });
  });
});
