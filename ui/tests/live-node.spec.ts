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
const PEER_LOG_DIR =
  process.env.FREENET_ISO_PEER_LOG_DIR ??
  path.join(process.env.HOME ?? "", "freenet-mail-iso/peer/logs");

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
      // The gateway-served webapp lives inside an iframe whose sandbox
      // omitted `allow-downloads` until freenet-core#4008. Programmatic
      // `<a download>` clicks were silently blocked by Chromium, so
      // `fm-id-backup` looked like a no-op. The fix is in the gw shell
      // HTML; this test asserts the download path actually fires.
      const downloadPromise = page.waitForEvent("download", { timeout: 5_000 });
      await appAfterReload
        .locator('[data-testid="fm-id-row"][data-alias="alice"] [data-testid="fm-id-backup"]')
        .click();
      const download = await downloadPromise;
      expect(
        download.suggestedFilename(),
        "backup filename matches freenet-identity-<alias>.json (regression for #77)",
      ).toMatch(/freenet-identity-.+\.json/);
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

      // Receiver-side delivery assertion: catches the regressions we previously
      // missed by only checking gw-side UPDATE_PROPAGATION (#71/#72). The
      // contract on the receiving node either applies the delta cleanly or
      // logs an "execution error" / "merge_rejected" trace — either of which
      // means the message did not reach bob's inbox even though the wire
      // propagation happened. Asserting on the **negative** signals catches
      // the failure modes we observed during manual QA without requiring a
      // second browser context to navigate bob's inbox UI (still gated on
      // shared-delegate-state — see comment above test).
      const receiverErrors = grepPeerLog(
        /execution error.*invalid contract update|merge_rejected|delta_apply_failed|missing field `tier`/,
      );
      expect(
        receiverErrors,
        "expected NO contract-side errors during cross-node delivery " +
          "(see #71/#72 — slot collision and tier-deser failure modes)",
      ).toBe(false);

      // Regression for #80 (cross-node UPDATE blocked by missing
      // related contract) + freenet/freenet-core#4003 (executor task
      // panic on unknown UpdateData variant). Either signal kills
      // delivery silently — wire propagation looks fine, but the
      // receiver's contract apply path bails. Grep both the gateway
      // (sender side, where the executor died in the original repro)
      // and the peer (receiver side, where missing-related shows up).
      expect(
        grepLog(/task .* panicked|missing related contract/),
        "no panic / missing-related on gateway (regression for #80 + core #4003)",
      ).toBe(false);
      expect(
        grepPeerLog(/task .* panicked|missing related contract/),
        "no panic / missing-related on peer (regression for #80 + core #4003)",
      ).toBe(false);

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
