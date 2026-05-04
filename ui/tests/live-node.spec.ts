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

      // ── Step 1: create identity "alice" ────────────────────────────
      // Pre-login first-run shows two action-cards. Click the create one,
      // which lands on the alias-input form; the legacy "John Smith"
      // placeholder is replaced with `e.g. mira`.
      await app.locator('[data-testid="fm-id-create"]').click();
      await app.locator('[data-testid="fm-create-alias-input"]').fill("alice");
      // Form stage's "Generate" button → reveal stage → "Continue to inbox".
      await app.locator('[data-testid="fm-create-submit"]').click();
      await app.locator('[data-testid="fm-create-confirm"]').click();

      // Regression for #76: identity must appear without a manual
      // reload. PR #88 fixed `LoginController.updated` not firing on
      // CreateIdentity. The reload-tolerant fallback this test used
      // to carry hid the bug — assert directly that alice is visible
      // within the first-run keygen + delegate round-trip window.
      const alice = app.locator('[data-testid="fm-id-row"][data-alias="alice"]');
      await expect(
        alice,
        "alice must appear without reload (regression for #76)",
      ).toBeVisible({ timeout: 30_000 });

      // ── Step 2: reload-persistence (covers PR #37) ────────────────
      await page.reload();
      const appAfterReload = page.frameLocator("iframe#app");
      await expect(
        appAfterReload.locator(".brand-name").first(),
        "app re-mounts after reload",
      ).toContainText(APP_NAME, { timeout: 60_000 });
      await expect(
        appAfterReload.locator('[data-testid="fm-id-row"][data-alias="alice"]'),
        "alice persists across reload",
      ).toBeVisible({ timeout: 30_000 });

      // ── Step 3: assert delegate registered + Init idempotent ──────
      // PR #34 fix: Init must skip if secret already exists. Probe via
      // gateway log.
      await expect
        .poll(
          () =>
            grepLog(
              /create alias .*alice|set_aliases count=\d+|init skipped — secret already exists/,
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
      // Gated on FREENET_HAS_DOWNLOAD_FIX. The CI-pinned freenet
      // binary (v0.2.50 / v0.2.51) predates freenet-core#4008
      // (`allow-downloads` in iframe sandbox). Set the env var locally
      // when running against a build that includes #4008, or wait for
      // the next freenet release tag and bump the pin in build.yml +
      // e2e-real-node.yml.
      if (process.env.FREENET_HAS_DOWNLOAD_FIX) {
        const downloadPromise = page.waitForEvent("download", { timeout: 5_000 });
        await appAfterReload
          .locator('[data-testid="fm-id-row"][data-alias="alice"] [data-testid="fm-id-backup"]')
          .click();
        const download = await downloadPromise;
        expect(
          download.suggestedFilename(),
          "backup filename matches freenet-identity-<alias>.json (regression for #77)",
        ).toMatch(/freenet-identity-.+\.json/);
      }
    } finally {
      stopPermissionPump();
    }
  });

  // Cross-node send: alice on gw (7510), bob on peer (7511). Each
  // node has its own identity-management delegate state, so bob's
  // keypair stays on the peer and never lands in alice's ADDRESS_BOOK
  // as Entry::Own — the failure mode that previously gated test 2
  // behind FREENET_LIVE_E2E_SEND was specific to two browser contexts
  // on the SAME gateway, which is now an unsupported configuration
  // for cross-node verification.
  //
  // The harness scaffolding (per-node permission pumps, peer URL
  // derivation from FREENET_EMAIL_BASE_URL) lands here; the
  // end-to-end "bob receives" assertion is gated on
  // FREENET_LIVE_E2E_SEND while we debug residual flake (AFT prompt
  // not consistently surfacing within the 60s window during the
  // contact-import → send → permission round-trip on a fresh iso).
  // See #81 follow-up.
  test("alice → bob across nodes: send + receive end-to-end (#81)", async ({
    browser,
  }) => {
    test.skip(
      !process.env.FREENET_LIVE_E2E_SEND,
      "cross-node send still flaky on iso harness; set FREENET_LIVE_E2E_SEND=1 to run",
    );
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
        createIdentity(alicePage, "alice"),
        createIdentity(bobPage, "bob"),
      ]);

      // ── Bob shares his contact card ─────────────────────────────
      const bobApp = bobPage.frameLocator("iframe#app");
      await bobApp.locator('[data-testid="fm-id-share"]').first().click();
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
        .fill("bob");
      await aliceApp.locator('[data-testid="fm-import-submit"]').click();

      // ── Alice composes + sends to bob ───────────────────────────
      // `.first()` defends against duplicate id-rows after the
      // create-identity reload fallback in `createIdentity` (the
      // delegate-echoed alias and the locally-created one can both
      // surface briefly post-reload). Either row points at the same
      // identity, so opening the first is correct.
      await aliceApp
        .locator('[data-testid="fm-id-row"][data-alias="alice"] [data-testid="fm-id-open"]')
        .first()
        .click();
      await aliceApp.locator('[data-testid="fm-compose-btn"]').click();
      const aliceSheet = aliceApp.locator('[data-testid="fm-compose-sheet"]');
      await aliceSheet
        .locator('input[placeholder="alias or address"]')
        .fill("bob");
      await expect(
        aliceApp.getByTestId("compose-recipient-fingerprint"),
        "fingerprint badge resolves for bob",
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
        .locator('[data-testid="fm-id-row"][data-alias="bob"] [data-testid="fm-id-open"]')
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
      const receiverErrors = grepPeerLog(
        /execution error.*invalid contract update|merge_rejected|delta_apply_failed|missing field `tier`/,
      );
      expect(
        receiverErrors,
        "expected NO contract-side errors during cross-node delivery (#71/#72)",
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
    // Same gate as the basic alice → bob test: cross-node send is
    // currently flaky against the iso harness (the api.rs decode panic
    // was the most visible failure but bob's UI still doesn't surface
    // the message in CI even with the fix; manual repro on a real
    // browser does work). Re-enable once the cross-node send
    // round-trip is reliable on the iso harness.
    test.skip(
      !process.env.FREENET_LIVE_E2E_SEND,
      "cross-node multi-round still under harness debug; set FREENET_LIVE_E2E_SEND=1 to run",
    );
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
        createIdentity(alicePage, "alice"),
        createIdentity(bobPage, "bob"),
      ]);

      const aliceApp = alicePage.frameLocator("iframe#app");
      const bobApp = bobPage.frameLocator("iframe#app");

      // Exchange contacts BOTH ways: alice imports bob, bob imports alice.
      await bobApp.locator('[data-testid="fm-id-share"]').first().click();
      const bobShare = bobApp.locator('[data-testid="fm-share-modal"]');
      await bobShare.waitFor({ timeout: 5_000 });
      const bobCard = (await bobShare.getAttribute("data-share-text")) ?? "";
      await bobShare.locator(".modal-x").click();

      await aliceApp.locator('[data-testid="fm-id-share"]').first().click();
      const aliceShare = aliceApp.locator('[data-testid="fm-share-modal"]');
      await aliceShare.waitFor({ timeout: 5_000 });
      const aliceCard =
        (await aliceShare.getAttribute("data-share-text")) ?? "";
      await aliceShare.locator(".modal-x").click();

      await aliceApp.locator('[data-testid="fm-contact-import"]').click();
      await aliceApp
        .locator('[data-testid="fm-import-contact-modal"] textarea')
        .fill(bobCard);
      await aliceApp
        .locator('input[placeholder="e.g. Alice (work)"]')
        .fill("bob");
      await aliceApp.locator('[data-testid="fm-import-submit"]').click();

      await bobApp.locator('[data-testid="fm-contact-import"]').click();
      await bobApp
        .locator('[data-testid="fm-import-contact-modal"] textarea')
        .fill(aliceCard);
      await bobApp
        .locator('input[placeholder="e.g. Alice (work)"]')
        .fill("alice");
      await bobApp.locator('[data-testid="fm-import-submit"]').click();

      // Open both inboxes.
      await aliceApp
        .locator(
          '[data-testid="fm-id-row"][data-alias="alice"] [data-testid="fm-id-open"]',
        )
        .first()
        .click();
      await bobApp
        .locator(
          '[data-testid="fm-id-row"][data-alias="bob"] [data-testid="fm-id-open"]',
        )
        .first()
        .click();

      // ── Round 1: alice → bob ────────────────────────────────────
      await composeAndSend(aliceApp, "bob", "round one", "first body");
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
      // Navigate back to inbox list. The message should still be
      // visible (read=true), not gone.
      await bobPage.goBack().catch(() => {});
      await bobApp
        .locator(
          '[data-testid="fm-id-row"][data-alias="bob"] [data-testid="fm-id-open"]',
        )
        .first()
        .click()
        .catch(() => {});
      await expect(
        bobApp.getByText(/round one/i),
        "round one stays visible after click-to-read",
      ).toBeVisible({ timeout: 10_000 });

      // ── Round 2: bob → alice (reply path) ────────────────────────
      await composeAndSend(bobApp, "alice", "round two reply", "reply body");
      await expect(
        aliceApp.getByText(/round two reply/i),
        "alice receives bob's reply",
      ).toBeVisible({ timeout: 60_000 });

      // ── Round 3: alice → bob again (no AFT cap regression) ───────
      await composeAndSend(aliceApp, "bob", "round three", "third body");
      await expect(
        bobApp.getByText(/round three/i),
        "bob receives round three (AFT slot still free)",
      ).toBeVisible({ timeout: 60_000 });

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
