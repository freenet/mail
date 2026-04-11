#!/usr/bin/env bash
# Production liveness check for a deployed freenet-email webapp.
#
# Usage:
#     scripts/smoke-test-production.sh <gateway-url>
#
# Example:
#     scripts/smoke-test-production.sh http://127.0.0.1:50509/contract/web/<contract-id>/
#
# With no argument, defaults to the local `freenet network` gateway
# serving the contract id from `published-contract/contract-id.txt`.
#
# ─── Scope ─────────────────────────────────────────────────────────────────
#
# This runs `ui/tests/production-liveness.spec.ts` against the deployed
# webapp. The spec is intentionally MINIMAL:
#
#   • Proves the publish pipeline didn't corrupt bytes (gateway serves
#     the webapp, WASM loads, Dioxus mounts, login screen renders).
#   • Runs in ~15s across all five browser profiles.
#
# What it explicitly does NOT cover:
#
#   • Real identity creation (RSA keygen + inbox contract put)
#   • Real AFT token mint/burn
#   • Real message send/receive round trip
#
# The production webapp is a `use-node` build — it expects a running
# Freenet node to do anything user-facing — so a Playwright test that
# loads it from a gateway and clicks "Create new identity" would need
# to also spin up a disposable `freenet local` node, publish the test
# contract to it, and wait through RSA-4096 keygen + contract-put
# propagation. That's what `ui/tests/live-node.spec.ts` + `cargo make
# test-ui-live` do (see Phase 5 PR B).
#
# The manual 7-step checklist in AGENTS.md §"End-to-end testing" is
# the human-driven equivalent of the live-node test and is still the
# canonical acceptance gate for a real release.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

GATEWAY_URL="${1:-}"

if [ -z "$GATEWAY_URL" ]; then
    if [ ! -f "published-contract/contract-id.txt" ]; then
        echo "usage: $0 <gateway-url>" >&2
        echo "       (no published-contract/contract-id.txt to auto-derive from)" >&2
        exit 1
    fi
    CONTRACT_ID=$(cat published-contract/contract-id.txt)
    GATEWAY_URL="http://127.0.0.1:50509/contract/web/$CONTRACT_ID/"
    echo "no URL supplied; defaulting to local freenet network gateway:"
    echo "  $GATEWAY_URL"
fi

# Sanity check: the gateway should return something.
if ! curl -sf -o /dev/null "$GATEWAY_URL" 2>/dev/null; then
    echo "error: $GATEWAY_URL is not responding" >&2
    echo "" >&2
    echo "Make sure:" >&2
    echo "  1. \`freenet network\` is running and connected" >&2
    echo "  2. The contract has propagated (wait ~30s after publish)" >&2
    echo "  3. The gateway URL is correct (default port 50509)" >&2
    exit 1
fi

# Playwright browsers must be installed.
if [ ! -d "ui/tests/node_modules" ]; then
    echo "error: ui/tests/node_modules missing. Run:" >&2
    echo "  cargo make test-ui-playwright-setup" >&2
    exit 1
fi

echo ""
echo "═══ Production liveness check ═════════════════════════════════════"
echo "  baseURL: $GATEWAY_URL"
echo "  spec:    ui/tests/production-liveness.spec.ts"
echo ""

cd "$REPO_ROOT/ui/tests"
FREENET_EMAIL_BASE_URL="$GATEWAY_URL" npx playwright test production-liveness.spec.ts

echo ""
echo "✅ liveness check passed against $GATEWAY_URL"
echo ""
echo "For the full end-to-end round trip (create identities, send,"
echo "receive, burn AFT tokens), run the manual checklist in"
echo "AGENTS.md §\"End-to-end testing\" or wait for the automated"
echo "live-node test landing in Phase 5 PR B."
