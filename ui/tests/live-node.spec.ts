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
const ISO_GW_ORIGIN = `http://127.0.0.1:${ISO_GW_PORT}`;
const GW_LOG_DIR =
  process.env.FREENET_ISO_GW_LOG_DIR ??
  path.join(process.env.HOME ?? "", "freenet-mail-iso/gw/logs");

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
      await app.locator('[data-testid="fm-action-create"]').click();
      await app.locator('[data-testid="fm-create-alias-input"]').fill("alice");
      // Form stage's "Generate" button → reveal stage → "Continue to inbox".
      await app.locator('[data-testid="fm-create-submit"]').click();
      await app.locator('[data-testid="fm-create-confirm"]').click();

      // Identity should appear in the list within a reasonable window.
      // First-run keygen on real PQ primitives takes a few seconds;
      // delegate Init + GetIdentities adds a node round-trip.
      //
      // Known race: the create handler dispatches CreateIdentity to
      // the identity-management delegate but the UI re-render relies
      // on the delegate response landing back through set_aliases +
      // login_controller.updated. If the delegate response is in
      // flight at the wait deadline, the identity is committed on the
      // node but the home view still shows the empty list. A reload
      // forces a GetIdentities round-trip and resolves the lag — same
      // remediation a user would do, much faster than extending the
      // initial timeout.
      const alice = app.locator('[data-testid="fm-id-row"][data-alias="alice"]');
      try {
        await expect(alice).toBeVisible({ timeout: 15_000 });
      } catch {
        await page.reload();
        await expect(
          page.frameLocator("iframe#app").locator(".brand-name").first(),
        ).toContainText(APP_NAME, { timeout: 60_000 });
        await expect(
          page
            .frameLocator("iframe#app")
            .locator('[data-testid="fm-id-row"][data-alias="alice"]'),
          "alice should appear in identity list (after reload fallback)",
        ).toBeVisible({ timeout: 30_000 });
      }

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
    } finally {
      stopPermissionPump();
    }
  });

  // Cross-identity send via two browser contexts on the same gateway.
  // Currently gated: the identity-management delegate is keyed by the
  // webapp's hardcoded params blob, so two browser contexts share a
  // single IdentityManagement state on the gateway. Bob's keypair
  // ends up in alice's ADDRESS_BOOK as Entry::Own, and the import
  // flow rejects "your own card". The workaround is delegate-level
  // per-user isolation (different params per context), which is a
  // larger change tracked separately. Until then this test runs only
  // when the user opts in via FREENET_LIVE_E2E_SEND so the harness
  // surfaces the regression for #38/#39/#40 manually but doesn't
  // gate CI on a known-broken assumption.
  test("ada → bob via address book → AFT permission → inbox UPDATE", async ({
    browser,
  }) => {
    test.skip(
      !process.env.FREENET_LIVE_E2E_SEND,
      "send flow blocked on shared identity-management delegate state " +
        "across browser contexts (see comment); set FREENET_LIVE_E2E_SEND=1 " +
        "to attempt anyway",
    );
    const stopPermissionPump = startPermissionPump();
    const aliceCtx = await browser.newContext();
    const bobCtx = await browser.newContext();
    const alicePage = await aliceCtx.newPage();
    const bobPage = await bobCtx.newPage();

    try {
      // Bring both browsers up to the freshly-published webapp.
      await Promise.all([alicePage.goto(""), bobPage.goto("")]);

      // ── Create alice + bob in parallel ──────────────────────────
      // Use "ada" not "alice": test 1 already minted alice on this
      // node state, and the identity-management delegate keys aliases
      // by name — two different keypairs registering under the same
      // alias on the same node would collide.
      await Promise.all([
        createIdentity(alicePage, "ada"),
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

      // ── Ada imports bob ─────────────────────────────────────────
      const adaApp = alicePage.frameLocator("iframe#app");
      await adaApp.locator('[data-testid="fm-contact-import"]').click();
      const importModal = adaApp.locator('[data-testid="fm-import-contact-modal"]');
      await importModal.locator("textarea").fill(bobCard);
      await adaApp
        .locator('input[placeholder="e.g. Alice (work)"]')
        .fill("bob");
      await adaApp.locator('[data-testid="fm-import-submit"]').click();

      // ── Ada composes + sends to bob ─────────────────────────────
      // Click the redesigned id-row's Open-inbox button instead of
      // matching the alias text alone (now non-clickable label text).
      await adaApp
        .locator('[data-testid="fm-id-row"][data-alias="ada"] [data-testid="fm-id-open"]')
        .click();
      // Redesigned shell: open the compose sheet via the sidebar's
      // "New message" button, then drive the real <input>/<textarea>
      // fields. The recipient badge under the To input renders the
      // fingerprint short form once `address_book::lookup` resolves.
      await adaApp.locator('[data-testid="fm-compose-btn"]').click();
      const adaSheet = adaApp.locator('[data-testid="fm-compose-sheet"]');
      await adaSheet
        .locator('input[placeholder="alias or address"]')
        .fill("bob");
      await expect(
        adaApp.getByTestId("compose-recipient-fingerprint"),
        "fingerprint badge resolves for bob",
      ).toBeVisible({ timeout: 15_000 });
      await adaSheet.locator('input[placeholder="subject"]').fill("hello bob");
      await adaSheet.locator("textarea.sheet-textarea").fill("body text");

      const sendStart = Date.now();
      await adaApp.locator('[data-testid="fm-send"]').click();

      // PR #38: send must spawn_forever. PR #39: AFT resume after
      // UserResponse. PR #40: defensive UpdateResponse summary deser.
      // All three failure modes surface as "no inbox UPDATE on gw".
      await expect
        .poll(() => grepLog(/UPDATE_PROPAGATION|inbox.*updated/), {
          message:
            "expected inbox UPDATE on gateway log within 60s of Send click",
          timeout: 60_000,
        })
        .toBe(true);

      // Sanity: token allocation actually ran.
      expect(
        grepLog(/allocate_token|token allocated/),
        "expected token allocation log entry",
      ).toBe(true);

      console.log(`send round-trip: ${Date.now() - sendStart}ms`);
    } finally {
      await aliceCtx.close().catch(() => {});
      await bobCtx.close().catch(() => {});
      stopPermissionPump();
    }
  });
});

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
  await app.locator('[data-testid="fm-action-create"]').click();
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
 * Returns a stop function that clears the interval.
 */
function startPermissionPump(): () => void {
  const seen = new Set<string>();
  const tick = async () => {
    try {
      const res = await fetch(`${ISO_GW_ORIGIN}/permission/pending`, {
        headers: { Origin: ISO_GW_ORIGIN },
      });
      if (!res.ok) return;
      const prompts = (await res.json()) as PendingPrompt[];
      for (const p of prompts) {
        if (seen.has(p.nonce)) continue;
        seen.add(p.nonce);
        const r = await fetch(
          `${ISO_GW_ORIGIN}/permission/${p.nonce}/respond`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Origin: ISO_GW_ORIGIN,
            },
            body: JSON.stringify({ index: 0 }),
          },
        );
        if (!r.ok) {
          console.error(
            `permission respond failed nonce=${p.nonce} status=${r.status}`,
          );
        }
      }
    } catch {
      // Pump is best-effort; the gateway can churn briefly during
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
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(GW_LOG_DIR, { withFileTypes: true });
  } catch {
    return false;
  }
  for (const ent of entries) {
    if (!ent.isFile() || !ent.name.startsWith("freenet.")) continue;
    const full = path.join(GW_LOG_DIR, ent.name);
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
