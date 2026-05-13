import { test, expect } from "@playwright/test";
import * as fs from "node:fs";
import * as path from "node:path";
import { APP_NAME } from "./app-name";

// Live-node E2E spec.
//
// Drives the production `use-node` webapp through the AFT permission
// flow against the isolated 2-node Freenet network spun up by
// `scripts/run-isolated-nodes.sh`. Unlike `email-app.spec.ts` (offline
// mock data) and `production-liveness.spec.ts` (smoke-only against a
// deployed gateway), this spec exercises the real WebSocket bridge,
// real delegate registration, real AFT token allocation, and real
// inbox UPDATE round trip.
//
// Required env (set by `cargo make test-e2e-real-node`):
//   FREENET_EMAIL_BASE_URL  http://127.0.0.1:7510/v1/contract/web/<id>/
//   FREENET_ISO_GW_PORT     gateway ws-api port (default 7510)
//   FREENET_ISO_GW_LOG_DIR  gateway log dir for log assertions
//
// The harness short-circuits the host's permission overlay by POSTing
// directly to /permission/{nonce}/respond. The overlay DOM is rendered
// by the gateway shell page (parent frame), not by the Dioxus app —
// driving it via Playwright selectors would mean coupling to gateway
// HTML; the HTTP API is the contract.

const ISO_GW_PORT = parseInt(process.env.FREENET_ISO_GW_PORT ?? "7510", 10);
const ISO_PEER_PORT = parseInt(process.env.FREENET_ISO_PEER_PORT ?? "7511", 10);
const ISO_GW_ORIGIN = `http://127.0.0.1:${ISO_GW_PORT}`;
const ISO_PEER_ORIGIN = `http://127.0.0.1:${ISO_PEER_PORT}`;
const GW_LOG_DIR =
  process.env.FREENET_ISO_GW_LOG_DIR ??
  path.join(process.env.HOME ?? "", "freenet-mail-iso/gw/logs");
const PEER_LOG_DIR =
  process.env.FREENET_ISO_PEER_LOG_DIR ??
  path.join(process.env.HOME ?? "", "freenet-mail-iso/peer/logs");

// FREENET_EMAIL_BASE_URL points at the gw (`http://127.0.0.1:7510/v1/contract/web/<id>/`).
// Derive the contract id so we can build a peer-side URL for the
// cross-node test — peer (7511) caches + serves the same contract id
// once requested.
const BASE_URL = process.env.FREENET_EMAIL_BASE_URL ?? "";
const CONTRACT_ID_MATCH = BASE_URL.match(/\/v1\/contract\/web\/([^/]+)\//);
const CONTRACT_ID = CONTRACT_ID_MATCH ? CONTRACT_ID_MATCH[1] : "";
const PEER_BASE_URL = CONTRACT_ID
  ? `${ISO_PEER_ORIGIN}/v1/contract/web/${CONTRACT_ID}/`
  : "";

// Iso harness wipes state per make-task invocation, but Playwright
// retries reuse the same iso net — second attempt collides with the
// first run's AFT slot / identity-management state. Keep this spec
// single-shot; flake is a real bug, not a transient.
test.describe.configure({ retries: 0 });

// Each test gets unique alias names so identity-management delegate
// state on the gw (and peer) doesn't collide across tests in the same
// run. The harness wipes once at the start of `cargo make
// test-e2e-real-node`, but the 3 specs run sequentially against the
// same iso net — without per-test suffixes, test 2's "alice" creation
// hits `Identity::get_alias` Some-branch (alias already registered),
// `pending` never sets, and `fm-create-confirm` never renders.
const ALIAS_T1_ALICE = "alice1";
const ALIAS_T2_ALICE = "alice2";
const ALIAS_T2_BOB = "bob2";
const ALIAS_T3_ALICE = "alice3";
const ALIAS_T3_BOB = "bob3";
const ALIAS_T4_ALICE = "alice4";
const ALIAS_T4_BOB = "bob4";
const ALIAS_T5_ALICE = "alice5";
const ALIAS_T5_BOB = "bob5";
const ALIAS_T6_ALICE = "alice6";
const ALIAS_T6_BOB = "bob6";
test.describe("Live node E2E", () => {
  test.skip(
    !process.env.FREENET_EMAIL_BASE_URL?.includes("/v1/contract/web/"),
    "live-node requires FREENET_EMAIL_BASE_URL pointing at the iso gateway " +
      "(set by `cargo make test-e2e-real-node`)",
  );

  // Single-project run keeps the harness fast and the CI install
  // bare-minimum (chromium only, no firefox/webkit, no mobile-chrome).
  // Mobile / cross-browser coverage stays in the offline suite. The
  // skip is keyed on project name and resolved per-test (not via a
  // beforeAll), so running the full suite without `--project=chromium`
  // does not trip a beforeEach against an unreachable gateway.
  test.beforeEach(async ({}, testInfo) => {
    test.skip(
      testInfo.project.name !== "chromium",
      "live-node spec runs on chromium only",
    );
    // Sanity: gateway permission API reachable from test runner.
    const res = await fetch(`${ISO_GW_ORIGIN}/permission/pending`);
    expect(res.ok, "iso gateway /permission/pending must respond").toBe(true);
  });

  test("create identity → reload persists → drives permission flow", async ({
    page,
  }) => {
    // Pump permission responses in the background: any time the gateway
    // surfaces a pending nonce, auto-click index 0 (the "allow" button).
    // Ends when the test scope ends.
    const stopPermissionPump = startPermissionPump();

    try {
      await page.goto("");

      const app = page.frameLocator("iframe#app");
      await expect(
        app.locator(".brand-name").first(),
        "APP_NAME brand block",
      ).toContainText(APP_NAME, { timeout: 60_000 });

      // ── Step 1: create identity ─────────────────────────────────────
      // Pre-login first-run shows two action-cards. Click the create one,
      // which lands on the alias-input form; the legacy "John Smith"
      // placeholder is replaced with `e.g. mira`.
      await app.locator('[data-testid="fm-id-create"]').click();
      await app.locator('[data-testid="fm-create-alias-input"]').fill(ALIAS_T1_ALICE);
      // Form stage's "Generate" button → reveal stage → "Continue to inbox".
      await app.locator('[data-testid="fm-create-submit"]').click();
      await app.locator('[data-testid="fm-create-confirm"]').click();

      // Regression for #76: identity must appear without a manual
      // reload. PR #88 fixed `LoginController.updated` not firing on
      // CreateIdentity. The reload-tolerant fallback this test used
      // to carry hid the bug — assert directly that alice is visible
      // within the first-run keygen + delegate round-trip window.
      const alice = app.locator(`[data-testid="fm-id-row"][data-alias="${ALIAS_T1_ALICE}"]`);
      await expect(
        alice,
        "identity must appear without reload (regression for #76)",
      ).toBeVisible({ timeout: 30_000 });

      // ── Step 2: reload-persistence (covers PR #37) ────────────────
      await page.reload();
      const appAfterReload = page.frameLocator("iframe#app");
      await expect(
        appAfterReload.locator(".brand-name").first(),
        "app re-mounts after reload",
      ).toContainText(APP_NAME, { timeout: 60_000 });
      await expect(
        appAfterReload.locator(`[data-testid="fm-id-row"][data-alias="${ALIAS_T1_ALICE}"]`),
        "identity persists across reload",
      ).toBeVisible({ timeout: 30_000 });

      // ── Step 3: assert delegate registered + Init idempotent ──────
      // PR #34 fix: Init must skip if secret already exists. Probe via
      // gateway log.
      await expect
        .poll(
          () =>
            grepLog(
              new RegExp(
                `create alias .*${ALIAS_T1_ALICE}|set_aliases count=\\d+|init skipped — secret already exists`,
              ),
            ),
          {
            message:
              "expected gateway log to show identity-management activity " +
              "(create alias / set_aliases / init-skip)",
            timeout: 30_000,
          },
        )
        .toBe(true);

      // ── Step 4: regression for #78 (Init/CreateIdentity race) ─────
      // The lazy-init delegate fix (6757631) treats a missing secret
      // as `IdentityManagement::default()`, so a CreateIdentity that
      // wins the race against Init must NOT log `secret not found`
      // anymore. Symptom on regression: identity appears to commit
      // but then doesn't persist; gateway log is the canonical
      // signal.
      expect(
        grepLog(/secret not found/),
        "no `secret not found` (regression for #78 — Init/CreateIdentity race)",
      ).toBe(false);

      // ── Step 5: regression for #77 (export download blocked) ──────
      // freenet-core#4008 (`allow-downloads` in iframe sandbox) shipped
      // in v0.2.54. PR #194 then moved the actual download to a
      // shell-page proxy: the sandboxed app-frame has an opaque origin
      // and `<a download>` either silently fails (Firefox) or saves
      // unreachably (Chrome). Inside the iframe the app posts the
      // payload to the parent shell via `__freenet_shell__: true,
      // type: "download"`; the gateway shell page does the actual
      // download from its own origin (handler in freenet-core
      // path_handlers.rs).
      //
      // Asserting `page.waitForEvent("download")` is brittle here —
      // depends on which frame fires the event under the shell-proxy
      // path. The contract that PR #194 ships is the postMessage
      // payload itself, so assert on that instead. Install the listener
      // on the shell page BEFORE the click so we don't race the post.
      // Two-step pattern: install captures the next matching message on
      // `window.__fm_proxy_download__`; await polls for it.
      await page.evaluate(() => {
        const w = window as unknown as { __fm_proxy_download__?: unknown };
        w.__fm_proxy_download__ = undefined;
        window.addEventListener("message", function handler(ev: MessageEvent) {
          const data = ev.data as Record<string, unknown> | null;
          if (!data || typeof data !== "object") return;
          if (data.__freenet_shell__ !== true || data.type !== "download") return;
          window.removeEventListener("message", handler);
          w.__fm_proxy_download__ = {
            filename: String(data.filename ?? ""),
            mimeType: String(data.mimeType ?? ""),
            base64Len: typeof data.base64 === "string" ? data.base64.length : 0,
          };
        });
      });
      await appAfterReload
        .locator(`[data-testid="fm-id-row"][data-alias="${ALIAS_T1_ALICE}"] [data-testid="fm-id-backup"]`)
        .click();
      const proxyMessage = await page.waitForFunction(
        () => {
          const w = window as unknown as { __fm_proxy_download__?: unknown };
          return w.__fm_proxy_download__;
        },
        undefined,
        { timeout: 10_000 },
      ).then((handle) =>
        handle.jsonValue() as Promise<{ filename: string; mimeType: string; base64Len: number }>,
      );
      expect(
        proxyMessage.filename,
        "backup filename matches freenet-identity-<alias>.json (regression for #77)",
      ).toMatch(/freenet-identity-.+\.json/);
      expect(
        proxyMessage.mimeType,
        "backup proxied as application/json",
      ).toBe("application/json");
      expect(
        proxyMessage.base64Len,
        "backup payload is non-empty base64",
      ).toBeGreaterThan(0);
    } finally {
      stopPermissionPump();
    }
  });

  // Cross-node send: alice on gw (7510), bob on peer (7511). Each
  // Cross-node send + receive end-to-end. Each node has its own
  // identity-management delegate state, so bob's keypair stays on
  // the peer and never lands in alice's ADDRESS_BOOK as Entry::Own.
  // Single-gateway-with-two-contexts is unsupported for this
  // verification — alice on gw, bob on peer is the canonical setup.
  //
  // FREENET_LIVE_E2E_SEND was the kill switch while #114 (duplicate
  // inbox per alias on shared delegate state) caused intermittent
  // failures. With #114 + #115 fixed and the iso harness verified
  // green in PR #122, the gate is removed.
  test("alice → bob across nodes: send + receive end-to-end (#81)", async ({
    browser,
  }) => {
    test.skip(
      !PEER_BASE_URL,
      "cross-node test requires FREENET_EMAIL_BASE_URL to include the contract id",
    );
    const stopGwPump = startPermissionPump(ISO_GW_ORIGIN);
    const stopPeerPump = startPermissionPump(ISO_PEER_ORIGIN);
    const aliceCtx = await browser.newContext();
    const bobCtx = await browser.newContext();
    const alicePage = await aliceCtx.newPage();
    const bobPage = await bobCtx.newPage();

    try {
      // alice → gw (uses Playwright `baseURL`); bob → peer (explicit
      // URL to the same contract id served by the peer node).
      await Promise.all([
        alicePage.goto(""),
        bobPage.goto(PEER_BASE_URL),
      ]);

      await Promise.all([
        createIdentity(alicePage, ALIAS_T2_ALICE),
        createIdentity(bobPage, ALIAS_T2_BOB),
      ]);

      // ── Bob shares his contact card ─────────────────────────────
      // Scope to bob2's row, NOT `.first()`. Identity rows are sorted
      // alphabetically (login.rs:380), so .first() returns the
      // alphabetically-first identity on the node — which on a peer that
      // already saw bob1/bob2 in earlier tests is NOT the one this test
      // just created. (#174 root cause: in test 3, .first() returned
      // bob2's row, alice imported bob2's keys under local alias "bob3",
      // and her send went to bob2's inbox — orphan UPDATE since no UI
      // was watching that inbox.)
      const bobApp = bobPage.frameLocator("iframe#app");
      await bobApp
        .locator(`[data-testid="fm-id-row"][data-alias="${ALIAS_T2_BOB}"] [data-testid="fm-id-share"]`)
        .click();
      const shareModal = bobApp.locator('[data-testid="fm-share-modal"]');
      await shareModal.waitFor({ timeout: 5_000 });
      const bobCard = (await shareModal.getAttribute("data-share-text")) ?? "";
      expect(bobCard, "bob share text contains contact:// payload").toMatch(
        /verify: .+\ncontact:\/\//,
      );
      await shareModal.locator(".modal-x").click();

      // ── Alice imports bob ───────────────────────────────────────
      const aliceApp = alicePage.frameLocator("iframe#app");
      await aliceApp.locator('[data-testid="fm-contact-import"]').click();
      const importModal = aliceApp.locator(
        '[data-testid="fm-import-contact-modal"]',
      );
      await importModal.locator("textarea").fill(bobCard);
      await aliceApp
        .locator('input[placeholder="e.g. Alice (work)"]')
        .fill(ALIAS_T2_BOB);
      // Tick the "I verified these six words" checkbox so the contact
      // is stored verified. `verify_on_send` defaults to true, so an
      // unverified import silently rejects the send (toast: "Recipient
      // is not verified") and bob never receives — root cause of the
      // harness-only failure tracked in #105. Checkbox renders only
      // after `fingerprint_words` resolves from the card.
      const verifyCheck = aliceApp.locator('[data-testid="fm-verify-check"]');
      await verifyCheck.waitFor({ timeout: 15_000 });
      await verifyCheck.click();
      await aliceApp.locator('[data-testid="fm-import-submit"]').click();

      // ── Alice composes + sends to bob ───────────────────────────
      // `.first()` defends against duplicate id-rows after the
      // create-identity reload fallback in `createIdentity` (the
      // delegate-echoed alias and the locally-created one can both
      // surface briefly post-reload). Either row points at the same
      // identity, so opening the first is correct.
      await aliceApp
        .locator(`[data-testid="fm-id-row"][data-alias="${ALIAS_T2_ALICE}"] [data-testid="fm-id-open"]`)
        .first()
        .click();
      await aliceApp.locator('[data-testid="fm-compose-btn"]').click();
      const aliceSheet = aliceApp.locator('[data-testid="fm-compose-sheet"]');
      await aliceSheet
        .locator('input[placeholder="alias or address"]')
        .fill(ALIAS_T2_BOB);
      await expect(
        aliceApp.getByTestId("compose-recipient-fingerprint"),
        `fingerprint badge resolves for ${ALIAS_T2_BOB}`,
      ).toBeVisible({ timeout: 15_000 });
      await aliceSheet
        .locator('input[placeholder="subject"]')
        .fill("hello bob");
      await aliceSheet.locator("textarea.sheet-textarea").fill("body text");

      const sendStart = Date.now();
      await aliceSheet.locator('[data-testid="fm-send"]').click();

      // ── Wire-level: gw shows the UPDATE got broadcast ───────────
      await expect
        .poll(() => grepLog(/UPDATE_PROPAGATION|inbox.*updated/), {
          message:
            "expected inbox UPDATE on gateway log within 60s of Send click",
          timeout: 60_000,
        })
        .toBe(true);
      // (No `allocate_token` log assertion: that string is never emitted
      // by freenet-core or the AFT delegate. The wire-level UPDATE_PROPAGATION
      // poll above plus the bob-inbox visibility assertion below cover the
      // user-visible behavior we actually care about.)

      // ── Bob opens his inbox and sees alice's message ────────────
      // Canonical "bob receives" assertion. Catches every failure mode
      // a wire-level UPDATE_PROPAGATION grep alone misses (#71 tier
      // deser, #72 slot collision, #80 missing-related, core #4003
      // panic): regardless of which layer eats the message, bob's
      // inbox staying empty is the user-visible signal.
      await bobApp
        .locator(`[data-testid="fm-id-row"][data-alias="${ALIAS_T2_BOB}"] [data-testid="fm-id-open"]`)
        .first()
        .click();
      await expect(
        bobApp.getByText(/hello bob/i),
        "bob's inbox must show alice's message subject",
      ).toBeVisible({ timeout: 60_000 });

      // Negative log asserts — same as before. These add diagnostic
      // value (when the positive assert fails, the log grep tells
      // which layer failed) but the positive bob-receives check is
      // the gate.
      // Scope to inbox/AFT failure modes only. Excludes web-container
      // re-publish noise ("New state version N must be higher than
      // current version N" — version equality is a benign stale
      // rebroadcast on the WC contract, not an inbox bug).
      // Targets:
      //  - #71: AFT tier deserialization (`missing field "tier"`)
      //  - #72: inbox slot-collision (`slot.*collision`, `delta_apply_failed`)
      //  - generic deserialize panics on inbox state
      const receiverErrors = grepPeerLog(
        /missing field `tier`|delta_apply_failed|slot.*collision|failed to deserialize.*Inbox|InboxUpdateError/,
      );
      expect(
        receiverErrors,
        "expected NO inbox/AFT contract-side errors during cross-node delivery (#71/#72)",
      ).toBe(false);
      expect(
        grepLog(/task .* panicked|missing related contract/),
        "no panic / missing-related on gateway (#80 + core #4003)",
      ).toBe(false);
      expect(
        grepPeerLog(/task .* panicked|missing related contract/),
        "no panic / missing-related on peer (#80 + core #4003)",
      ).toBe(false);

      console.log(`send round-trip: ${Date.now() - sendStart}ms`);
    } finally {
      await aliceCtx.close().catch(() => {});
      await bobCtx.close().catch(() => {});
      stopGwPump();
      stopPeerPump();
    }
  });

  // Multi-round cross-node flow: send, click-to-read, reply, archive.
  // Catches the regression class where (a) clicking a received message
  // makes it disappear instead of staying visible as read, (b) replies
  // back to the sender don't surface, (c) archive doesn't move the row
  // into the Archive folder, (d) UpdateNotification decode panics
  // (#102 follow-up: api.rs:1085 was unwrapping a StoredInbox decode of
  // a Delta wire payload that's actually `UpdateInbox::AddMessages`).
  test("multi-round + read + archive across nodes", async ({ browser }) => {
    // FREENET_LIVE_E2E_SEND gate dropped — verified green on iso
    // after #114 + #115 fixes plus the spec-side reload-instead-of-
    // goBack correction (the SPA doesn't push history entries on
    // click, so `goBack` was navigating to about:blank rather than
    // the inbox). Round 3 stays uncoverable until #221 — see the
    // explanation around round 2 below.
    test.skip(
      !PEER_BASE_URL,
      "cross-node test requires FREENET_EMAIL_BASE_URL to include the contract id",
    );
    const stopGwPump = startPermissionPump(ISO_GW_ORIGIN);
    const stopPeerPump = startPermissionPump(ISO_PEER_ORIGIN);
    // Per-context tracing — captures DOM snapshots, console messages, and
    // network activity for both browser contexts. Saved alongside other
    // playwright artifacts so #113 (kept_for rebuild miss after click-
    // to-read) can be diagnosed from CI logs without local repro.
    const aliceCtx = await browser.newContext();
    const bobCtx = await browser.newContext();
    await aliceCtx.tracing.start({ screenshots: true, snapshots: true });
    await bobCtx.tracing.start({ screenshots: true, snapshots: true });
    const alicePage = await aliceCtx.newPage();
    const bobPage = await bobCtx.newPage();
    // Mirror every console message verbatim into the test log so that
    // crash-time error_context.md captures what each side saw — narrows
    // down whether the row vanished due to a wasm panic, a delegate
    // dispatch failure, or a quiet `kept_for` returning empty.
    for (const [page, label] of [
      [alicePage, "alice"],
      [bobPage, "bob"],
    ] as const) {
      page.on("console", (m) => {
        console.log(`[console:${label}:${m.type()}] ${m.text()}`);
      });
      page.on("pageerror", (e) => {
        console.log(`[pageerror:${label}] ${e.message}`);
      });
    }

    // Surface WASM panics + console errors immediately so test failure
    // points at the original panic frame, not a downstream timeout.
    const consoleErrors: string[] = [];
    for (const [page, label] of [
      [alicePage, "alice"],
      [bobPage, "bob"],
    ] as const) {
      page.on("console", (m) => {
        const t = m.text();
        if (
          /WASM PANIC|RuntimeError: unreachable executed|Result::unwrap.*on an .Err/.test(
            t,
          )
        ) {
          consoleErrors.push(`[${label}] ${t}`);
        }
      });
    }

    try {
      await Promise.all([alicePage.goto(""), bobPage.goto(PEER_BASE_URL)]);
      await Promise.all([
        createIdentity(alicePage, ALIAS_T3_ALICE),
        createIdentity(bobPage, ALIAS_T3_BOB),
      ]);

      const aliceApp = alicePage.frameLocator("iframe#app");
      const bobApp = bobPage.frameLocator("iframe#app");

      // Capture both share cards up-front while we're still on the
      // home view. fm-id-share / fm-id-row only exist on the
      // pre-login screen; once an inbox is opened, the home view
      // unmounts and these locators stop resolving.
      // Scope each share locator by data-alias (#174 — peer delegate
      // accumulates bob2/bob3, gw delegate accumulates alice1/2/3).
      await bobApp
        .locator(`[data-testid="fm-id-row"][data-alias="${ALIAS_T3_BOB}"] [data-testid="fm-id-share"]`)
        .click();
      const bobShare = bobApp.locator('[data-testid="fm-share-modal"]');
      await bobShare.waitFor({ timeout: 5_000 });
      const bobCard = (await bobShare.getAttribute("data-share-text")) ?? "";
      await bobShare.locator(".modal-x").click();

      await aliceApp
        .locator(`[data-testid="fm-id-row"][data-alias="${ALIAS_T3_ALICE}"] [data-testid="fm-id-share"]`)
        .click();
      const aliceShareEarly = aliceApp.locator('[data-testid="fm-share-modal"]');
      await aliceShareEarly.waitFor({ timeout: 5_000 });
      const aliceCard =
        (await aliceShareEarly.getAttribute("data-share-text")) ?? "";
      await aliceShareEarly.locator(".modal-x").click();

      // Alice imports bob so round 1 (alice→bob) can resolve.
      await aliceApp.locator('[data-testid="fm-contact-import"]').click();
      await aliceApp
        .locator('[data-testid="fm-import-contact-modal"] textarea')
        .fill(bobCard);
      await aliceApp
        .locator('input[placeholder="e.g. Alice (work)"]')
        .fill(ALIAS_T3_BOB);
      // verify_on_send defaults true; tick checkbox so import is verified
      // (#105 root cause: silent send rejection on unverified contact).
      const aliceVerify = aliceApp.locator('[data-testid="fm-verify-check"]');
      await aliceVerify.waitFor({ timeout: 15_000 });
      await aliceVerify.click();
      await aliceApp.locator('[data-testid="fm-import-submit"]').click();

      // Bob imports alice up-front too — needed for round-2 reply.
      // fm-contact-import is on the home view; once bob opens his
      // inbox, it unmounts.
      await bobApp.locator('[data-testid="fm-contact-import"]').click();
      await bobApp
        .locator('[data-testid="fm-import-contact-modal"] textarea')
        .fill(aliceCard);
      await bobApp
        .locator('input[placeholder="e.g. Alice (work)"]')
        .fill(ALIAS_T3_ALICE);
      const bobVerify = bobApp.locator('[data-testid="fm-verify-check"]');
      await bobVerify.waitFor({ timeout: 15_000 });
      await bobVerify.click();
      await bobApp.locator('[data-testid="fm-import-submit"]').click();

      // Open both inboxes.
      await aliceApp
        .locator(
          `[data-testid="fm-id-row"][data-alias="${ALIAS_T3_ALICE}"] [data-testid="fm-id-open"]`,
        )
        .first()
        .click();
      await bobApp
        .locator(
          `[data-testid="fm-id-row"][data-alias="${ALIAS_T3_BOB}"] [data-testid="fm-id-open"]`,
        )
        .first()
        .click();

      // ── Round 1: alice → bob ────────────────────────────────────
      await composeAndSend(aliceApp, ALIAS_T3_BOB, "round one", "first body");
      await expect(
        bobApp.getByText(/round one/i),
        "bob receives round one",
      ).toBeVisible({ timeout: 60_000 });

      // Click to open: message must NOT vanish from the inbox list.
      // Regression target: post-#102 click-to-read deletes the row
      // from the in-memory model + bumps local-state, but the inbox
      // list rebuild is supposed to merge the kept-locally copy back
      // in. If kept_for() doesn't fire or the rebuild doesn't run,
      // the row disappears entirely.
      await bobApp.getByText(/round one/i).click();
      await bobApp.locator('[data-testid="fm-detail-time"]').waitFor({
        timeout: 5_000,
      });
      // After click, the row stays in the list (now `selected`) and
      // the detail panel mounts beside it. Reload the page to force
      // a fresh GetIdentities + delegate echo round trip — this is
      // the actual #113 regression target: the kept-locally snapshot
      // must survive a stale delegate echo on reload, otherwise the
      // row disappears because the contract has evicted the message.
      // SPA doesn't push history entries on click, so `goBack()`
      // would navigate to about:blank — use reload + re-open inbox
      // instead.
      await bobPage.reload();
      await bobApp.locator(".brand-name").first().waitFor({ timeout: 30_000 });
      await bobApp
        .locator(
          `[data-testid="fm-id-row"][data-alias="${ALIAS_T3_BOB}"] [data-testid="fm-id-open"]`,
        )
        .first()
        .click();
      await expect(
        bobApp.getByText(/round one/i),
        "round one stays visible after click-to-read + reload",
      ).toBeVisible({ timeout: 30_000 });

      // ── Round 2: bob → alice (reply path) ────────────────────────
      // Bob already imported alice at setup; just send the reply.
      await composeAndSend(bobApp, ALIAS_T3_ALICE, "round two reply", "reply body");
      await expect(
        aliceApp.getByText(/round two reply/i),
        "alice receives bob's reply",
      ).toBeVisible({ timeout: 60_000 });

      // Round 3 (alice → bob a second time) is currently uncoverable
      // on iso: bob's contact card encodes the recipient's tier at
      // share time and the sender mints against that frozen value
      // (#221), so a recipient-side ModifySettings tier change leaves
      // the sender minting at the old tier and the contract rejecting.
      // Re-enable once #221 ships sender-side dynamic tier resolution.

      // ── Archive: bob archives round one. Should leave the inbox
      // list and surface in the Archive folder.
      await bobApp.getByText(/round one/i).click();
      const archiveBtn = bobApp.locator('[data-testid="fm-archive"]');
      if (await archiveBtn.isVisible().catch(() => false)) {
        await archiveBtn.click();
        await expect(
          bobApp.getByText(/round one/i),
          "round one no longer in inbox after archive",
        ).toHaveCount(0, { timeout: 10_000 });
        // Switch to Archive folder via menu.
        await bobApp.getByText(/^Archive$/).click();
        await expect(
          bobApp.getByText(/round one/i),
          "round one visible in Archive folder",
        ).toBeVisible({ timeout: 10_000 });
      }

      expect(
        consoleErrors,
        `no WASM panics in either browser context: ${consoleErrors.join("\n")}`,
      ).toEqual([]);
    } finally {
      // Stop + persist traces before context close so they survive
      // even when the test fails mid-flow. Filenames land under
      // test-results/ so they're picked up by the e2e-real-node CI
      // artifact upload step.
      await aliceCtx.tracing
        .stop({ path: "test-results/multi-round-alice-trace.zip" })
        .catch(() => {});
      await bobCtx.tracing
        .stop({ path: "test-results/multi-round-bob-trace.zip" })
        .catch(() => {});
      await aliceCtx.close().catch(() => {});
      await bobCtx.close().catch(() => {});
      stopGwPump();
      stopPeerPump();
    }
  });

  // #204 regression: contact-share + reload + UpdateNotification on a
  // contact's primed inbox. Pre-#198 fix path:
  //   1. alice imports bob via share-card (CreateContact-prime
  //      subscribes alice's node to bob's inbox key)
  //   2. alice reloads (rehydrate-prime path re-subscribes on boot)
  //   3. bob's inbox emits an UpdateNotification (any UPDATE — here
  //      alice → bob)
  //   4. alice's api.rs UpdateNotification arm dispatches by contract
  //      key. bob's inbox key isn't in alice's `inboxes` and isn't in
  //      `token_rec_to_id`, so pre-#198 it hit `unreachable!` and the
  //      whole webapp crashed.
  //
  // Asserts:
  //   - `rehydrate primed contact inbox` log fires (subscription is
  //     actually established post-reload — without this the test could
  //     pass for the wrong reason)
  //   - no WASM panic / `unreachable executed` in alice's console
  //   - no `UpdateNotification for unknown contract key` error in
  //     alice's console (the regression marker if the contact-key
  //     guard breaks)
  //   - bob still receives the message end-to-end (sanity)
  test("contact import + reload + UpdateNotification stays sane (#204)", async ({
    browser,
  }) => {
    test.skip(
      !PEER_BASE_URL,
      "cross-node test requires FREENET_EMAIL_BASE_URL to include the contract id",
    );
    const stopGwPump = startPermissionPump(ISO_GW_ORIGIN);
    const stopPeerPump = startPermissionPump(ISO_PEER_ORIGIN);
    const aliceCtx = await browser.newContext();
    const bobCtx = await browser.newContext();
    const alicePage = await aliceCtx.newPage();
    const bobPage = await bobCtx.newPage();

    // Surface alice's panics + the specific "unknown contract key"
    // marker so a regression points at the right frame.
    const aliceErrors: string[] = [];
    // Track the rehydrate-prime log emitted from the webapp (`crate::log::info`
    // lands in the browser console, not in the gateway log files).
    let rehydratePrimed = false;
    alicePage.on("console", (m) => {
      const t = m.text();
      if (
        /WASM PANIC|RuntimeError: unreachable executed|UpdateNotification for unknown contract key|tried to get wrong contract key/.test(
          t,
        )
      ) {
        aliceErrors.push(`[${m.type()}] ${t}`);
      }
      // Loose match: the rehydrate path iterates every persisted
      // contact and the test only needs to confirm the path fired
      // post-reload (so subscriptions are re-armed). bob4 contact-row
      // presence in the UI post-reload separately confirms bob4
      // specifically made it through the delegate round-trip.
      if (/rehydrate primed contact inbox .* for .* \(#191\)/.test(t)) {
        rehydratePrimed = true;
      }
    });
    alicePage.on("pageerror", (e) => {
      aliceErrors.push(`[pageerror] ${e.message}`);
    });

    try {
      await Promise.all([alicePage.goto(""), bobPage.goto(PEER_BASE_URL)]);
      await Promise.all([
        createIdentity(alicePage, ALIAS_T4_ALICE),
        createIdentity(bobPage, ALIAS_T4_BOB),
      ]);

      // ── Bob shares his card ─────────────────────────────────────
      const bobApp = bobPage.frameLocator("iframe#app");
      await bobApp
        .locator(`[data-testid="fm-id-row"][data-alias="${ALIAS_T4_BOB}"] [data-testid="fm-id-share"]`)
        .click();
      const bobShare = bobApp.locator('[data-testid="fm-share-modal"]');
      await bobShare.waitFor({ timeout: 5_000 });
      const bobCard = (await bobShare.getAttribute("data-share-text")) ?? "";
      expect(bobCard, "bob share text contains contact:// payload").toMatch(
        /verify: .+\ncontact:\/\//,
      );
      await bobShare.locator(".modal-x").click();

      // ── Alice imports bob ───────────────────────────────────────
      const aliceApp = alicePage.frameLocator("iframe#app");
      await aliceApp.locator('[data-testid="fm-contact-import"]').click();
      await aliceApp
        .locator('[data-testid="fm-import-contact-modal"] textarea')
        .fill(bobCard);
      await aliceApp
        .locator('input[placeholder="e.g. Alice (work)"]')
        .fill(ALIAS_T4_BOB);
      const verifyCheck = aliceApp.locator('[data-testid="fm-verify-check"]');
      await verifyCheck.waitFor({ timeout: 15_000 });
      await verifyCheck.click();

      // Watch for the `primed contact inbox … for <alias> (#191)` log
      // BEFORE the import-submit click, so the handler is armed when
      // CreateContact emits it. (The rehydrate-variant happens only on
      // reload; this is the initial-import variant.)
      // Also surface bob4 contact-related logs to stdout so a regression
      // points at the right webapp branch.
      const primedRe = new RegExp(
        `primed contact inbox .* for ${ALIAS_T4_BOB} \\(#191\\)`,
      );
      let importPrimed = false;
      alicePage.on("console", (m) => {
        const t = m.text();
        if (primedRe.test(t)) importPrimed = true;
        if (
          /(create_contact|insert_contact|prime contact inbox|primed contact inbox|address book rejected|failed to store contact)/.test(
            t,
          )
        ) {
          console.log(`[console:alice4:${m.type()}] ${t}`);
        }
      });
      await aliceApp.locator('[data-testid="fm-import-submit"]').click();

      // Wait for the import to commit to the local node + identity-management
      // delegate before reloading — otherwise the reload races the in-flight
      // CreateContact and the rehydrated address book lacks bob, so the
      // post-reload compose can't resolve bob's fingerprint.
      // Two-stage check: the `primed contact inbox` log confirms the
      // local-node Get-with-subscribe went out, then bob's contact-row
      // surfacing in alice's UI confirms `insert_contact` ran. A 2s
      // dwell after both is enough for the delegate ack to round-trip
      // (the delegate write is fire-and-forget — no log marks it).
      await expect
        .poll(() => importPrimed, {
          message: `expected initial \`primed contact inbox … for ${ALIAS_T4_BOB}\` log before reload`,
          timeout: 20_000,
        })
        .toBe(true);
      await expect(
        aliceApp.locator(`[data-testid="contact-row"][data-alias="${ALIAS_T4_BOB}"]`),
        `${ALIAS_T4_BOB} contact-row visible in alice's UI before reload`,
      ).toBeVisible({ timeout: 10_000 });
      await alicePage.waitForTimeout(2_000);

      // ── Reload alice — rehydrate-prime path re-subscribes to bob's
      // inbox key. Wait for the log marker so we're certain the
      // subscription is established before bob's inbox updates.
      await alicePage.reload();
      await alicePage
        .frameLocator("iframe#app")
        .locator(".brand-name")
        .first()
        .waitFor({ timeout: 60_000 });
      await expect
        .poll(() => rehydratePrimed, {
          message:
            "expected `rehydrate primed contact inbox` console log within 30s of " +
            "alice reload (otherwise the #204 path isn't actually exercised)",
          timeout: 30_000,
        })
        .toBe(true);

      // ── Drive an UPDATE on bob's inbox: alice opens her inbox and
      // sends to bob. This puts traffic on the contract key alice is
      // now subscribed to via rehydrate-prime. Pre-#198 fix: the
      // resulting UpdateNotification arm panics with `unreachable`.
      const aliceAppReloaded = alicePage.frameLocator("iframe#app");
      await aliceAppReloaded
        .locator(`[data-testid="fm-id-row"][data-alias="${ALIAS_T4_ALICE}"] [data-testid="fm-id-open"]`)
        .first()
        .click();
      await composeAndSend(
        aliceAppReloaded,
        ALIAS_T4_BOB,
        "ping after reload",
        "this drives an UPDATE on bob's inbox, which alice is now subscribed to",
      );

      // Sanity: bob still receives end-to-end.
      await bobApp
        .locator(`[data-testid="fm-id-row"][data-alias="${ALIAS_T4_BOB}"] [data-testid="fm-id-open"]`)
        .first()
        .click();
      await expect(
        bobApp.getByText(/ping after reload/i),
        "bob receives the post-reload message",
      ).toBeVisible({ timeout: 60_000 });

      // Give the UpdateNotification a moment to reach alice (the
      // subscription is established, but the broadcast back to alice
      // is async). 5s is generous on the iso harness.
      await alicePage.waitForTimeout(5_000);

      expect(
        aliceErrors,
        `alice must not panic / log unknown-contract-key on contact's inbox notification (#204):\n${aliceErrors.join("\n")}`,
      ).toEqual([]);
    } finally {
      await aliceCtx.close().catch(() => {});
      await bobCtx.close().catch(() => {});
      stopGwPump();
      stopPeerPump();
    }
  });

  // #157 / #180 regression: turning on the verified-sender bypass
  // toggle in Settings → AFT must dispatch a signed `ModifySettings`
  // delta to the inbox contract — without it the change is local-only
  // and senders keep paying the AFT cost. The bypass itself is a
  // recipient-side policy; this test exercises the ON path's wire
  // dispatch:
  //   1. Alice creates an identity, imports bob as a verified contact
  //   2. Alice opens her inbox + Settings → AFT
  //   3. Alice flicks the verified-skip toggle ON
  //   4. The webapp emits `UpdateVerifiedBypass dispatched … allow=true`
  //      (signed ModifySettings → inbox contract) and the toggle's
  //      `data-state` flips to "on"
  // Sender-side cost-avoidance (bob sends without minting + alice
  // receives) is a separate test gated on AFT cap configurability
  // (#85 / #179) — once those land, an inverted assertion can verify
  // the bypass actually frees sends through a depleted cap.
  test("verified-skip toggle dispatches ModifySettings + flips state (#157)", async ({
    page,
  }) => {
    const stopPermissionPump = startPermissionPump();
    let bypassDispatched = false;
    page.on("console", (m) => {
      if (
        /UpdateVerifiedBypass dispatched for `.+` allow=true \(#157\)/.test(
          m.text(),
        )
      ) {
        bypassDispatched = true;
      }
    });

    try {
      await page.goto("");
      const app = page.frameLocator("iframe#app");
      await expect(app.locator(".brand-name").first()).toContainText(APP_NAME, {
        timeout: 60_000,
      });

      // Create alice + import bob (synthetic contact card — we don't
      // need a real second peer for this test, just an entry whose VK
      // alice's settings can list as verified).
      await createIdentity(page, ALIAS_T5_ALICE);

      // Generate bob's share card by spinning a second browser context
      // long enough to read his contact:// payload. The actual cross-
      // node send + receive isn't exercised here; we just need bob's
      // VK in alice's verified-senders set.
      const bobCtx = await page.context().browser()!.newContext();
      try {
        const bobPage = await bobCtx.newPage();
        await bobPage.goto(PEER_BASE_URL);
        await createIdentity(bobPage, ALIAS_T5_BOB);
        const bobApp = bobPage.frameLocator("iframe#app");
        await bobApp
          .locator(`[data-testid="fm-id-row"][data-alias="${ALIAS_T5_BOB}"] [data-testid="fm-id-share"]`)
          .click();
        const bobShare = bobApp.locator('[data-testid="fm-share-modal"]');
        await bobShare.waitFor({ timeout: 5_000 });
        const bobCard = (await bobShare.getAttribute("data-share-text")) ?? "";
        expect(bobCard).toMatch(/verify: .+\ncontact:\/\//);

        // Alice imports bob (verified).
        await app.locator('[data-testid="fm-contact-import"]').click();
        await app
          .locator('[data-testid="fm-import-contact-modal"] textarea')
          .fill(bobCard);
        await app
          .locator('input[placeholder="e.g. Alice (work)"]')
          .fill(ALIAS_T5_BOB);
        const verifyCheck = app.locator('[data-testid="fm-verify-check"]');
        await verifyCheck.waitFor({ timeout: 15_000 });
        await verifyCheck.click();
        await app.locator('[data-testid="fm-import-submit"]').click();
        await expect(
          app.locator(`[data-testid="contact-row"][data-alias="${ALIAS_T5_BOB}"]`),
          "bob5 imported as verified contact",
        ).toBeVisible({ timeout: 15_000 });
      } finally {
        await bobCtx.close().catch(() => {});
      }

      // Open alice's inbox so the Settings button is reachable.
      await app
        .locator(`[data-testid="fm-id-row"][data-alias="${ALIAS_T5_ALICE}"] [data-testid="fm-id-open"]`)
        .first()
        .click();
      await app.locator('[data-testid="fm-settings-btn"]').click();
      await app
        .locator('[data-testid="fm-settings-nav-item"][data-screen="aft"]')
        .click();

      // Flick the verified-skip toggle ON. The toggle's `data-state`
      // is "off" by default; after click it must flip to "on" AND the
      // webapp must dispatch a ModifySettings delta (asserted via the
      // console log marker).
      const toggle = app.locator('[data-testid="fm-aft-verified-skip-toggle"]');
      await toggle.waitFor({ timeout: 10_000 });
      await expect(toggle).toHaveAttribute("data-state", "off");
      await toggle.click();
      await expect(toggle).toHaveAttribute("data-state", "on", {
        timeout: 5_000,
      });

      await expect
        .poll(() => bypassDispatched, {
          message:
            "expected `UpdateVerifiedBypass dispatched … allow=true (#157)` " +
            "console log within 10s of toggle click — otherwise the wire " +
            "dispatch path didn't fire and the bypass is local-only",
          timeout: 10_000,
        })
        .toBe(true);
    } finally {
      stopPermissionPump();
    }
  });

  // #221: post-#85 the recipient's `InboxSettings.minimum_tier` is
  // mutable, but contact cards encode the tier at share time. Without
  // sender-side dynamic tier resolution, alice would mint at the
  // card's frozen tier and the recipient's contract would reject with
  // `PolicyTierMismatch`.
  //
  // This was the "FREENET_LIVE_E2E_AFT_CAP_RAISED" row in #180. The
  // #221 fix lives in the sender:
  //   1. UI populates a `RecipientPolicy` cache on every GetResponse
  //      / UpdateNotification for a contact's inbox.
  //   2. The send path consults the cache before falling back to the
  //      stale contact-card tier.
  //
  // Sender-side cache + send-path wiring are exercised by the rust
  // unit tests in `ui/src/contact_tier_cache.rs`. The cross-peer e2e
  // proving "bob retunes mid-run, alice mints at new tier, recipient
  // accepts" was re-enabled in #223 alongside the contract-side fix
  // (`Inbox::merge` now propagates `settings`; `verify_token_policy`
  // uses `>=` not `==`). #180's AFT_CAP_RAISED row is closed via this
  // test together with the unit-test coverage.
  test("recipient tier change before first send; sender mints at new tier (#221, #180 AFT_CAP_RAISED row)", async ({
    browser,
  }) => {
    test.skip(
      !PEER_BASE_URL,
      "cross-node test requires FREENET_EMAIL_BASE_URL to include the contract id",
    );
    const stopGwPump = startPermissionPump(ISO_GW_ORIGIN);
    const stopPeerPump = startPermissionPump(ISO_PEER_ORIGIN);
    const aliceCtx = await browser.newContext();
    const bobCtx = await browser.newContext();
    const alicePage = await aliceCtx.newPage();
    const bobPage = await bobCtx.newPage();

    const consoleErrors: string[] = [];
    let cacheRecordedMin1 = false;
    let cacheOverrideOnSend = false;
    let bobUpdatePolicyMin1 = false;
    for (const [page, label] of [
      [alicePage, "alice"],
      [bobPage, "bob"],
    ] as const) {
      page.on("console", (m) => {
        const t = m.text();
        console.log(`[console:${label}:${m.type()}] ${t}`);
        if (
          /WASM PANIC|RuntimeError: unreachable executed|PolicyTierMismatch/.test(
            t,
          )
        ) {
          consoleErrors.push(`[${label}] ${t}`);
        }
        if (
          label === "alice" &&
          /contact tier cache: recorded .+ tier=Min1 .+ \(#221\)/.test(t)
        ) {
          cacheRecordedMin1 = true;
        }
        if (
          label === "alice" &&
          /send: contact-tier-cache hit for `.+` tier=Min1 .+ \(#221\)/.test(t)
        ) {
          cacheOverrideOnSend = true;
        }
        if (
          label === "bob" &&
          /UpdateInboxPolicy dispatched for `.+` tier=Min1 .+ \(#85\)/.test(t)
        ) {
          bobUpdatePolicyMin1 = true;
        }
      });
      page.on("pageerror", (e) => {
        console.log(`[pageerror:${label}] ${e.message}`);
      });
    }

    try {
      await Promise.all([alicePage.goto(""), bobPage.goto(PEER_BASE_URL)]);
      await Promise.all([
        createIdentity(alicePage, ALIAS_T6_ALICE),
        createIdentity(bobPage, ALIAS_T6_BOB),
      ]);

      const aliceApp = alicePage.frameLocator("iframe#app");
      const bobApp = bobPage.frameLocator("iframe#app");

      // Capture bob's share card (default tier Min10).
      await bobApp
        .locator(`[data-testid="fm-id-row"][data-alias="${ALIAS_T6_BOB}"] [data-testid="fm-id-share"]`)
        .click();
      const bobShare = bobApp.locator('[data-testid="fm-share-modal"]');
      await bobShare.waitFor({ timeout: 5_000 });
      const bobCard = (await bobShare.getAttribute("data-share-text")) ?? "";
      await bobShare.locator(".modal-x").click();
      expect(bobCard).toMatch(/verify: .+\ncontact:\/\//);

      // Alice imports bob (verified so verify_on_send doesn't block).
      await aliceApp.locator('[data-testid="fm-contact-import"]').click();
      await aliceApp
        .locator('[data-testid="fm-import-contact-modal"] textarea')
        .fill(bobCard);
      await aliceApp
        .locator('input[placeholder="e.g. Alice (work)"]')
        .fill(ALIAS_T6_BOB);
      const aliceVerify = aliceApp.locator('[data-testid="fm-verify-check"]');
      await aliceVerify.waitFor({ timeout: 15_000 });
      await aliceVerify.click();
      await aliceApp.locator('[data-testid="fm-import-submit"]').click();

      // Open both inboxes.
      await aliceApp
        .locator(`[data-testid="fm-id-row"][data-alias="${ALIAS_T6_ALICE}"] [data-testid="fm-id-open"]`)
        .first()
        .click();
      await bobApp
        .locator(`[data-testid="fm-id-row"][data-alias="${ALIAS_T6_BOB}"] [data-testid="fm-id-open"]`)
        .first()
        .click();

      // ── Bob switches AFT tier to Min1 via Settings → AFT BEFORE any
      // send (see header comment for the contract-level reason). ─────
      await bobApp.locator('[data-testid="fm-settings-btn"]').click();
      await bobApp
        .locator('[data-testid="fm-settings-nav-item"][data-screen="aft"]')
        .click();
      await bobApp
        .locator('[data-testid="fm-aft-tier"][data-tier="Min1"]')
        .click();
      await expect
        .poll(() => bobUpdatePolicyMin1, {
          message:
            "expected bob's `UpdateInboxPolicy dispatched … tier=Min1 (#85)` " +
            "console log within 15s of tier-button click",
          timeout: 15_000,
        })
        .toBe(true);

      // Reload alice's page so the rehydrate-prime path re-fetches
      // every contact's inbox state via Get-with-subscribe. The
      // GetResponse for bob's inbox lands in the contact-inbox arm of
      // api.rs and updates the tier cache with the new `minimum_tier`.
      //
      // We reload rather than wait on a live UpdateNotification because
      // post-CreateContact subscriptions on the iso gateway don't
      // reliably deliver UpdateNotifications to client subscribers
      // (the gateway sees `is_subscribed=false` for the client on the
      // subsequent Get; the broadcast propagates between nodes but
      // doesn't fan out to subscribed clients). That's a separate
      // gateway-side bug — #221 fixes the sender-side cache lookup
      // either way, and the rehydrate refresh is the canonical
      // populated-at-startup path. Filed as a follow-up.
      //
      // Wait a beat first so the propagation reaches the gw before
      // alice's Get pulls the new state.
      await alicePage.waitForTimeout(3_000);
      await alicePage.reload();
      await aliceApp.locator(".brand-name").first().waitFor({ timeout: 30_000 });
      await aliceApp
        .locator(`[data-testid="fm-id-row"][data-alias="${ALIAS_T6_ALICE}"] [data-testid="fm-id-open"]`)
        .first()
        .click();
      await expect
        .poll(() => cacheRecordedMin1, {
          message:
            "expected alice's `contact tier cache: recorded … tier=Min1 (#221)` " +
            "console log within 60s of reload — rehydrate-prime path's " +
            "GetResponse on bob's contact inbox must populate the cache",
          timeout: 60_000,
        })
        .toBe(true);

      // Back out of Settings on bob's side too so any subsequent UI
      // navigation doesn't confuse the compose flow on alice.
      await bobApp.locator('[data-testid="fm-settings-back"]').click();

      // ── alice → bob, sender must mint at Min1 (not Min10 from card). ──
      await composeAndSend(aliceApp, ALIAS_T6_BOB, "post-retune", "after tier flip");
      await expect
        .poll(() => cacheOverrideOnSend, {
          message:
            "expected alice's `send: contact-tier-cache hit for … tier=Min1 (#221)` " +
            "log on send — without this the sender used the stale card tier",
          timeout: 20_000,
        })
        .toBe(true);
      await expect(
        bobApp.getByText(/post-retune/i),
        "bob receives the message after tier retune; sender minted at new tier",
      ).toBeVisible({ timeout: 60_000 });

      expect(
        consoleErrors,
        `no WASM panics / PolicyTierMismatch in either browser context: ${consoleErrors.join("\n")}`,
      ).toEqual([]);
    } finally {
      await aliceCtx.close().catch(() => {});
      await bobCtx.close().catch(() => {});
      stopGwPump();
      stopPeerPump();
    }
  });

});

async function composeAndSend(
  app: import("@playwright/test").FrameLocator,
  recipientAlias: string,
  subject: string,
  body: string,
) {
  await app.locator('[data-testid="fm-compose-btn"]').click();
  const sheet = app.locator('[data-testid="fm-compose-sheet"]');
  await sheet
    .locator('input[placeholder="alias or address"]')
    .fill(recipientAlias);
  await expect(
    app.getByTestId("compose-recipient-fingerprint"),
    `fingerprint badge resolves for ${recipientAlias}`,
  ).toBeVisible({ timeout: 15_000 });
  await sheet.locator('input[placeholder="subject"]').fill(subject);
  await sheet.locator("textarea.sheet-textarea").fill(body);
  await sheet.locator('[data-testid="fm-send"]').click();
}

// ─── Helpers ─────────────────────────────────────────────────────────────

/**
 * Create an identity with the given alias and wait for it to surface
 * in the home view. Tolerates the known race where the delegate
 * response lands after the create handler returns (see comment in the
 * first test) by reloading once before failing.
 */
async function createIdentity(page: import("@playwright/test").Page, alias: string) {
  const app = page.frameLocator("iframe#app");
  // Topbar carries the brand name in both pre-login and the mailbox.
  await expect(app.locator(".brand-name").first()).toContainText(APP_NAME, {
    timeout: 60_000,
  });
  await app.locator('[data-testid="fm-id-create"]').click();
  await app.locator('[data-testid="fm-create-alias-input"]').fill(alias);
  await app.locator('[data-testid="fm-create-submit"]').click();
  await app.locator('[data-testid="fm-create-confirm"]').click();

  const target = app.locator(`[data-testid="fm-id-row"][data-alias="${alias}"]`);
  try {
    await expect(target).toBeVisible({ timeout: 15_000 });
  } catch {
    await page.reload();
    const reloaded = page.frameLocator("iframe#app");
    await expect(reloaded.locator(".brand-name").first()).toContainText(
      APP_NAME,
      { timeout: 60_000 },
    );
    await expect(
      reloaded.locator(`[data-testid="fm-id-row"][data-alias="${alias}"]`),
      `${alias} should appear after reload fallback`,
    ).toBeVisible({ timeout: 30_000 });
  }
}


interface PendingPrompt {
  nonce: string;
  message?: string;
  labels?: string[];
}

/**
 * Background loop polling /permission/pending and POSTing index:0
 * (the first/allow button) on every nonce. The gateway shell page
 * does the same, but we run headless against the gateway origin
 * (no shell JS in the test page), so the harness has to drive it.
 *
 * Defaults to the iso gateway origin; pass an explicit origin (e.g.
 * the peer at 7511) when running cross-node tests.
 *
 * Returns a stop function that clears the interval.
 */
function startPermissionPump(origin: string = ISO_GW_ORIGIN): () => void {
  const seen = new Set<string>();
  const tick = async () => {
    try {
      const res = await fetch(`${origin}/permission/pending`, {
        headers: { Origin: origin },
      });
      if (!res.ok) return;
      const prompts = (await res.json()) as PendingPrompt[];
      for (const p of prompts) {
        if (seen.has(p.nonce)) continue;
        seen.add(p.nonce);
        const r = await fetch(`${origin}/permission/${p.nonce}/respond`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Origin: origin,
          },
          body: JSON.stringify({ index: 0 }),
        });
        if (!r.ok) {
          console.error(
            `permission respond failed origin=${origin} nonce=${p.nonce} status=${r.status}`,
          );
        }
      }
    } catch {
      // Pump is best-effort; the node can churn briefly during
      // delegate registration. Errors here surface as test timeouts
      // on the actual assertion.
    }
  };
  const interval = setInterval(tick, 200);
  return () => clearInterval(interval);
}

/**
 * Tail the gateway's freenet.*.log files and return true if any line
 * matches the predicate. Cheap and synchronous; intended for
 * `expect.poll`.
 */
function grepLog(re: RegExp): boolean {
  return grepLogDir(GW_LOG_DIR, re);
}

/**
 * Same as `grepLog` but targets the peer's freenet log dir. Receiver-side
 * contract errors (delta apply failures, merge rejections) only appear on
 * the destination node, not on the gateway.
 */
function grepPeerLog(re: RegExp): boolean {
  return grepLogDir(PEER_LOG_DIR, re);
}

function grepLogDir(dir: string, re: RegExp): boolean {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return false;
  }
  for (const ent of entries) {
    if (!ent.isFile() || !ent.name.startsWith("freenet.")) continue;
    const full = path.join(dir, ent.name);
    try {
      // Read tail only — full read on a multi-MB log is slow.
      const stat = fs.statSync(full);
      const size = stat.size;
      const window = Math.min(size, 256 * 1024);
      const buf = Buffer.alloc(window);
      const fd = fs.openSync(full, "r");
      try {
        fs.readSync(fd, buf, 0, window, size - window);
      } finally {
        fs.closeSync(fd);
      }
      if (re.test(buf.toString("utf8"))) return true;
    } catch {
      // Concurrent rotation can race; ignore and try next file.
    }
  }
  return false;
}
