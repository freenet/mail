#!/usr/bin/env bash
# Run the Playwright E2E suite against a deployed freenet-email webapp.
#
# Usage:
#     scripts/smoke-test-production.sh <gateway-url>
#
# Example:
#     scripts/smoke-test-production.sh http://127.0.0.1:50509/contract/web/<contract-id>/
#
# Defaults the gateway URL to the local `freenet network` node serving
# the contract id from `published-contract/contract-id.txt` if no argument
# is provided.
#
# What this exercises:
#   • The Playwright spec at ui/tests/email-app.spec.ts (same 7 scenarios
#     that run against the local dev server in offline mode), pointed at
#     the real gateway instead of a dx serve on localhost:8082.
#   • Rendering, identity seeding, compose, and in-memory cross-inbox
#     messaging — i.e., the full offline UI contract, as served by the
#     real webapp contract. Does NOT exercise real AFT token mint/burn or
#     real inbox contract state (that's the manual live-node checklist in
#     AGENTS.md §End-to-end testing).
#
# Exit code: non-zero if any Playwright test fails.

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

# Sanity check: the gateway should return SOMETHING.
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
echo "═══ Running Playwright smoke tests against production ═════════════"
echo "  baseURL: $GATEWAY_URL"
echo ""

cd "$REPO_ROOT/ui/tests"
FREENET_EMAIL_BASE_URL="$GATEWAY_URL" npx playwright test

echo ""
echo "✅ smoke test passed against $GATEWAY_URL"
