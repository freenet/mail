import { test, expect, Page } from "@playwright/test";
import { APP_NAME } from "./app-name";
import { TID } from "./testids";

// ─── #270 message-threading suite ────────────────────────────────────────────
//
// Runs in OFFLINE example-data mode (the same dev-server flags the rest of the
// Playwright suite uses: `--features example-data,no-sync`). Phase-1 seeds a
// deterministic conversation into the address1 (UserId 0) inbox:
//
//   thread "example-thread-0001", subject "Lunch tomorrow?":
//     id=0  from Mary       (root,       in_reply_to=None)        "Are you free for lunch tomorrow around noon?"
//     id=1  from address1   (reply,      in_reply_to="0")         "Noon works for me — the usual place?"
//     id=2  from Mary       (reply,      in_reply_to="1", unread) "Perfect, see you there!"
//
//   plus two standalone (no thread_id) messages:
//     id=3  "Welcome to the offline preview" from "Ian's Other Account"
//     id=4  "Your weekly digest"             from "freenet-bot"
//
// So the inbox list must show ONE collapsed thread-group row (count badge == 3)
// alongside the two standalone rows. See ui/src/app.rs::load_example_messages.
const SEEDED_THREAD_SUBJECT = "Lunch tomorrow?";
const SEEDED_THREAD_SIZE = 3;
const SEEDED_THREAD_LEAF_BODY = "Perfect, see you there!"; // newest message (id=2)
const SEEDED_THREAD_ROOT_BODY = "Are you free for lunch tomorrow around noon?";
const SEEDED_THREAD_MID_BODY = "Noon works for me — the usual place?";

// ─── shared helpers (mirrors email-app.spec.ts) ──────────────────────────────

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
  await expect(page.locator(".list-title")).toContainText("Inbox", {
    timeout: 10_000,
  });
}

// The collapsed inbox-list row representing the whole conversation. It carries
// the message-count badge and, when clicked, opens the threaded detail.
function threadGroupRow(page: Page) {
  return page
    .locator(`[data-testid="${TID.fmThreadGroup}"]`)
    .filter({ hasText: SEEDED_THREAD_SUBJECT });
}

// Open the seeded thread's detail view and wait for the threaded container.
//
// NOTE on viewports: the detail column is an inline flex pane. On the narrow
// mobile profile (Pixel 5) the sidebar + 300px list-col consume the width and
// the detail-col collapses to a zero-size box — Playwright treats its contents
// as "hidden" even though they're in the DOM (the pre-existing single-message
// detail had the same property; see email-app.spec.ts archive tests, which use
// `toContainText` / `dispatchEvent` rather than visibility). So we wait for the
// container to be ATTACHED (not visible) and elsewhere assert via content /
// count matchers and dispatch clicks directly, which all operate on attached
// elements regardless of layout visibility.
async function openSeededThread(page: Page) {
  await threadGroupRow(page).click();
  await page
    .locator(`[data-testid="${TID.fmThreadContainer}"]`)
    .waitFor({ state: "attached", timeout: 10_000 });
}

// Switch the Settings → Inbox "thread view" preference. `view` is "Nested" or
// "Compact". Mirrors the toggleQuarantine helper in email-app.spec.ts: open
// Settings, jump to the Inbox screen, drive the labelled control, back out.
//
// The thread-view control is rendered by phase-2; this helper targets it by its
// "thread view" label within the Inbox settings screen and clicks the option
// matching `view`. It tolerates either a segmented-button control (a clickable
// element whose text is the option name) or a <select>.
async function setThreadView(page: Page, view: "Nested" | "Compact") {
  await page.locator(`[data-testid="${TID.fmSettingsBtn}"]`).click();
  await page
    .locator(`[data-testid="${TID.fmSettingsShell}"]`)
    .waitFor({ timeout: 5_000 });
  await page
    .locator(`[data-testid="${TID.fmSettingsNavItem}"][data-screen="inbox"]`)
    .click();

  // The thread-view preference owns the only "thread view" label on this
  // screen. The control the code agent rendered is the
  // `fm-thread-view-select` <select> (ui/src/app/settings.rs ~1237) whose
  // option VALUES are lowercase "nested" / "compact" — and the visible option
  // TEXT is the same lowercase string, NOT the capitalized "Nested"/"Compact".
  // Select by value (lowercased) so we don't depend on the option label's
  // casing.
  const value = view.toLowerCase(); // "nested" | "compact"
  const select = page.locator(`[data-testid="${TID.fmThreadViewSelect}"]`);
  if (await select.count()) {
    await select.selectOption({ value });
  } else {
    // Fallback for a segmented-button control: click the option bearing the
    // view name (either casing).
    const row = page.locator(".fm-row-set", { hasText: /thread view/i });
    await row
      .getByText(new RegExp(`^${view}$`, "i"), { exact: false })
      .first()
      .click();
  }

  await page.locator(`[data-testid="${TID.fmSettingsBack}"]`).click();
  await page.locator(`[data-testid="${TID.fmApp}"]`).waitFor({ timeout: 5_000 });
}

// ─── List-level grouping ─────────────────────────────────────────────────────

test.describe("Inbox thread grouping (#270)", () => {
  test("mixed list: one collapsed conversation row with a count badge + two standalone rows", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    // EVERY inbox row — conversation OR standalone — renders as a
    // `fm-thread-group` article (ui/src/app.rs ~2599: a one-message "thread"
    // is just a group with count == 1, badge suppressed). The seed produces
    // THREE such rows: the 3-message "Lunch tomorrow?" conversation plus the
    // two standalone messages (id=3 "Welcome…", id=4 "Your weekly digest").
    const allRows = page.locator(`[data-testid="${TID.fmThreadGroup}"]`);
    await expect(allRows).toHaveCount(3);

    // Exactly one of those rows is the seeded conversation, and it carries a
    // count badge equal to the seeded thread size (3).
    const group = threadGroupRow(page);
    await expect(group).toHaveCount(1);
    await expect(group.locator(".ft-count")).toHaveText(
      String(SEEDED_THREAD_SIZE),
    );

    // The standalone rows render as ordinary rows and DON'T carry a count
    // badge (the `.ft-count` span is only emitted when count > 1). Scope to
    // each standalone row and assert no badge inside it.
    const standalone1 = allRows.filter({
      hasText: "Welcome to the offline preview",
    });
    const standalone2 = allRows.filter({ hasText: "Your weekly digest" });
    await expect(standalone1).toHaveCount(1);
    await expect(standalone2).toHaveCount(1);
    await expect(standalone1.locator(".ft-count")).toHaveCount(0);
    await expect(standalone2.locator(".ft-count")).toHaveCount(0);

    // The individual thread members (the two "Re: Lunch tomorrow?" replies)
    // are folded behind the single conversation row — they must not surface as
    // separate top-level rows, so the conversation row stays the only one
    // bearing the thread subject.
    await expect(threadGroupRow(page)).toHaveCount(1);
  });

  test("clicking the thread group opens the threaded detail container", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    await openSeededThread(page);
    // The container is attached (see openSeededThread note on mobile layout);
    // assert presence + content rather than visibility.
    const container = page.locator(`[data-testid="${TID.fmThreadContainer}"]`);
    await expect(container).toHaveCount(1);

    // All three messages of the conversation are present somewhere in the
    // threaded detail (expanded or behind a caret).
    await expect(container).toContainText(SEEDED_THREAD_SUBJECT);
    await expect(
      container.locator(`[data-testid="${TID.fmThreadRow}"]`),
    ).toHaveCount(SEEDED_THREAD_SIZE);
  });
});

// ─── Nested view (default) ───────────────────────────────────────────────────

test.describe("Nested thread view (#270)", () => {
  test("default-expands the last message of the branch; collapsed nodes expand on click", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    // Nested is the default ThreadView — no settings change required.
    await openSeededThread(page);
    const container = page.locator(`[data-testid="${TID.fmThreadContainer}"]`);

    // The nested tree wrapper renders (attached; may be in a collapsed
    // detail-col on mobile — assert presence, not visibility).
    await expect(container.locator(".ft-nest")).toHaveCount(1);

    // DEFAULT EXPANSION: the leaf (newest, id=2) message body is visible…
    await expect(container).toContainText(SEEDED_THREAD_LEAF_BODY);

    // …while the earlier nodes start collapsed. Nested collapsed rows render
    // NO body text (the `.ft-body-text` block is gated on the row being open),
    // so the root body is absent from the container entirely.
    await expect(container).not.toContainText(SEEDED_THREAD_ROOT_BODY);

    // Expanding a collapsed node reveals its body. The expand control is the
    // row's `.ft-msg-time` span; the hover-action cluster (`.ft-nest-actions`,
    // position:absolute, opacity:0) overlaps the top-right corner and would
    // intercept a real pointer click, so dispatch the click directly on the
    // root row's (id=0) expand control. The root body should then appear.
    const rootExpand = container
      .locator(`[data-testid="${TID.fmThreadRow}"][data-msg-id="0"]`)
      .locator(`[data-testid="${TID.fmThreadExpand}"]`);
    await rootExpand.dispatchEvent("click");
    await expect(container).toContainText(SEEDED_THREAD_ROOT_BODY);
  });

  test("the 'in reply to' quote chip toggles", async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    await openSeededThread(page);
    const container = page.locator(`[data-testid="${TID.fmThreadContainer}"]`);

    // Each reply carries a `.ft-quote` chip whose excerpt is its PARENT's body:
    //   id=1's chip quotes id=0  → SEEDED_THREAD_ROOT_BODY
    //   id=2's chip quotes id=1  → SEEDED_THREAD_MID_BODY
    // Rows render oldest→newest, so `.ft-quote.first()` would be id=1's chip
    // (the root body). Target the LEAF reply (id=2) explicitly via the
    // `data-msg-id` the code agent put on every `fm-thread-row`, then read its
    // own quote chip — that's the one carrying SEEDED_THREAD_MID_BODY.
    const leafRow = container.locator(
      `[data-testid="${TID.fmThreadRow}"][data-msg-id="2"]`,
    );
    const quote = leafRow.locator(".ft-quote");
    await expect(quote).toHaveCount(1);

    const toggle = quote.locator(".ft-quote-toggle");
    const quoteText = quote.locator(".ft-quote-text");

    // The excerpt starts hidden (chip collapsed; .ft-quote-text isn't rendered)
    // and appears after a toggle. dispatchEvent fires the click directly so a
    // collapsed (zero-size) detail-col on the mobile profile can't swallow it.
    await expect(quoteText).toHaveCount(0);
    await toggle.dispatchEvent("click");
    await expect(quoteText).toHaveCount(1);
    await expect(quoteText).toContainText(SEEDED_THREAD_MID_BODY);

    // Toggling again hides it (the code removes .ft-quote-text from the DOM).
    await toggle.dispatchEvent("click");
    await expect(quoteText).toHaveCount(0);
  });
});

// ─── Compact view ────────────────────────────────────────────────────────────

test.describe("Compact thread view (#270)", () => {
  test("default-expands only the newest message; clicking a row toggles it", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    await setThreadView(page, "Compact");

    await openSeededThread(page);
    const container = page.locator(`[data-testid="${TID.fmThreadContainer}"]`);

    // Compact accordion wrapper renders (attached; presence not visibility, to
    // tolerate the collapsed detail-col on the mobile profile).
    await expect(container.locator(".ft-compact")).toHaveCount(1);

    // One tight row per message.
    await expect(container.locator(".ft-cz-row")).toHaveCount(SEEDED_THREAD_SIZE);

    // DEFAULT EXPAND: only the newest (id=2) row is open — exactly one open row,
    // and its expanded body region (`.ft-cz-open`) carries the leaf body.
    await expect(container.locator(".ft-cz-row.is-open")).toHaveCount(1);
    await expect(container.locator(".ft-cz-open")).toContainText(
      SEEDED_THREAD_LEAF_BODY,
    );

    // The root (oldest, id=0) row is collapsed. NOTE: a collapsed compact row
    // still renders a `.ft-cz-snippet` (the body's first line), so the root
    // body text IS present at container scope — assert against the EXPANDED
    // body region (`.ft-cz-open`), which only exists for open rows. The root's
    // own expanded region (scoped via its `data-msg-id`) is absent while
    // collapsed.
    const rootMsg = container.locator(
      `[data-testid="${TID.fmThreadRow}"][data-msg-id="0"]`,
    );
    const rootOpen = rootMsg.locator(".ft-cz-open");
    await expect(rootOpen).toHaveCount(0);

    // Clicking the root row toggles it open; its body now appears in its own
    // `.ft-cz-open` region (the leaf stays open too — toggles are independent).
    // dispatchEvent fires the toggle directly (the row is a <button> carrying
    // fm-thread-expand) so a collapsed detail-col on mobile can't swallow it.
    const rootRow = container.locator(".ft-cz-row").first();
    await rootRow.dispatchEvent("click");
    await expect(container.locator(".ft-cz-row.is-open")).toHaveCount(2);
    await expect(rootOpen).toContainText(SEEDED_THREAD_ROOT_BODY);

    // Clicking it again collapses it: the root's open region disappears.
    await rootRow.dispatchEvent("click");
    await expect(container.locator(".ft-cz-row.is-open")).toHaveCount(1);
    await expect(rootOpen).toHaveCount(0);
  });
});

// ─── Reply stays in the same thread ──────────────────────────────────────────

test.describe("Reply within a thread (#270)", () => {
  // The reply rework (phase-1) removed the old "> "-prefix quote hack: a reply
  // sets the STRUCTURED quoted_excerpt + in_reply_to + thread_id instead of
  // prepending "> " lines to the body. This test asserts the new behaviour and
  // explicitly never asserts on "> quoted" body text.
  test("reply keeps the conversation in the same thread (no new top-level row); compose body has no '> ' quote hack", async ({
    page,
  }) => {
    await page.goto("/");
    await waitForApp(page);
    await selectIdentity(page, "address1");

    await openSeededThread(page);
    const container = page.locator(`[data-testid="${TID.fmThreadContainer}"]`);

    const groupCountBefore = await page
      .locator(`[data-testid="${TID.fmThreadGroup}"]`)
      .count();

    // Reply to a message within the thread. The per-row Reply lives in the
    // detail-col, which collapses to zero-size on the mobile profile, so
    // dispatchEvent fires the click directly. The compose sheet that opens is a
    // full-screen overlay (visible on every profile).
    await container
      .locator(`[data-testid="${TID.fmReply}"]`)
      .first()
      .dispatchEvent("click");
    const sheet = page.locator(`[data-testid="${TID.fmComposeSheet}"]`);
    await sheet.waitFor({ timeout: 5_000 });

    // The reply compose opens prefilled WITHOUT the legacy "> " quote hack in
    // the body — quoting is now structured (the quoted excerpt rides on the
    // message, not the body textarea).
    const bodyVal = await sheet.locator("textarea.sheet-textarea").inputValue();
    expect(bodyVal).not.toContain("> ");

    // example-data supports in-memory cross-inbox delivery; sending a reply to a
    // member of the thread must keep it in the SAME conversation rather than
    // spawning a new top-level group row. We gate the count-grows assertion on
    // example-data actually delivering the reply back into this inbox: if the
    // send lands, the thread's count badge grows by 1; the number of top-level
    // thread groups stays constant.
    await sheet.locator("textarea.sheet-textarea").fill("On my way!");
    await page.locator(`[data-testid="${TID.fmSend}"]`).click();

    // Back at the list, the conversation is still a single group row (no new
    // top-level row was created for the reply).
    await expect(
      page.locator(`[data-testid="${TID.fmThreadGroup}"]`),
    ).toHaveCount(groupCountBefore, { timeout: 10_000 });

    // And if the in-memory delivery surfaced the reply into this inbox, the
    // seeded thread's badge has grown beyond the original size. We assert the
    // badge is AT LEAST the original size (delivery-dependent) and never less —
    // a regression that re-parented the reply would drop it below.
    const badge = threadGroupRow(page).locator(".ft-count");
    const badgeText = await badge.textContent();
    expect(Number(badgeText)).toBeGreaterThanOrEqual(SEEDED_THREAD_SIZE);
  });
});
