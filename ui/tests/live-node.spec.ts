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
      await expect(app.locator("h1"), "APP_NAME heading").toContainText(
        APP_NAME,
        { timeout: 60_000 },
      );

      // ── Step 1: create identity "alice" ────────────────────────────
      await app.getByText("Create new identity", { exact: true }).click();
      await app.locator('input[placeholder="John Smith"]').fill("alice");
      // The submit control is an `<a class="button">` (not <button>),
      // so getByRole("button") doesn't resolve it. Match by exact text
      // on the styled-as-button anchor.
      await app.locator("a.button", { hasText: /^Create$/ }).click();

      // Identity should appear in the list within a reasonable window.
      // First-run keygen on real PQ primitives takes a few seconds;
      // delegate Init + GetIdentities adds a node round-trip.
      await expect(
        app.getByText("alice", { exact: true }),
        "alice should appear in identity list after create",
      ).toBeVisible({ timeout: 30_000 });

      // ── Step 2: reload-persistence (covers PR #37) ────────────────
      await page.reload();
      const appAfterReload = page.frameLocator("iframe#app");
      await expect(
        appAfterReload.locator("h1"),
        "app re-mounts after reload",
      ).toContainText(APP_NAME, { timeout: 60_000 });
      await expect(
        appAfterReload.getByText("alice", { exact: true }),
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

  // Send-message flow is intentionally separate from identity creation
  // so a regression in one path doesn't mask the other in test output.
  // Same fixture: alice already exists from the preceding test on the
  // same node state. Day-1 AFT collision is avoided because
  // `cargo make test-e2e-real-node` wipes node data per run.
  test("send-self via address book → AFT permission → inbox UPDATE", async ({
    page,
  }) => {
    test.skip(
      !process.env.FREENET_LIVE_E2E_SEND,
      "send flow is gated on FREENET_LIVE_E2E_SEND while #43 cross-id " +
        "harness lands; single-identity self-send is the planned first cut",
    );
    const stopPermissionPump = startPermissionPump();

    try {
      await page.goto("");
      const app = page.frameLocator("iframe#app");

      await expect(
        app.getByText("alice", { exact: true }),
        "alice already created by previous test",
      ).toBeVisible({ timeout: 60_000 });

      // Capture own contact card via Share address.
      await app.getByRole("button", { name: /Share address/ }).click();
      const card = await app
        .locator("textarea.is-family-monospace")
        .inputValue();
      expect(card, "share text contains contact:// payload").toMatch(
        /verify: .+\ncontact:\/\//,
      );
      await app.getByRole("button", { name: /Close/ }).click();

      // Import own contact under a local label.
      await app.getByText("+ Import contact").click();
      await app.locator("textarea").first().fill(card);
      await app.locator('input[placeholder="e.g. Alice (work)"]').fill("self");
      await app.getByRole("button", { name: /^Import$/ }).click();

      // Compose self-message.
      await app.getByText("alice", { exact: true }).click();
      await app.getByRole("button", { name: /Compose|New/ }).first().click();
      // contenteditable cells — type into the To/Subject/Body cells in order.
      await app.locator('td[contenteditable="true"]').nth(0).fill("self");
      await expect(
        app.getByTestId("compose-recipient-fingerprint"),
        "fingerprint badge resolves",
      ).toBeVisible({ timeout: 10_000 });
      await app.locator('td[contenteditable="true"]').nth(1).fill("hello");
      await app
        .locator('div[contenteditable="true"]')
        .last()
        .fill("body text");

      const sendStart = Date.now();
      await app.getByRole("button", { name: "Send" }).click();

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
      stopPermissionPump();
    }
  });
});

// ─── Helpers ─────────────────────────────────────────────────────────────

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
