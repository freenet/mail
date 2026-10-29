#!/usr/bin/env bash
# Refuses (exit 3) while a release freeze is in place: `.release-freeze` at
# the repository root exists. Every production publish path runs this first:
# scripts/release.sh and the publish-email / publish-container /
# publish-production cargo-make tasks.
#
# The freeze file can be replaced only for this script's own test, which
# must set both RELEASE_FREEZE_TEST=1 and RELEASE_FREEZE_FILE; anywhere
# else RELEASE_FREEZE_FILE is ignored with a warning, so it cannot be used
# to switch the freeze off.
#
# Usage: scripts/check-release-freeze.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
FREEZE_FILE="$ROOT/.release-freeze"
if [ -n "${RELEASE_FREEZE_FILE:-}" ]; then
    if [ "${RELEASE_FREEZE_TEST:-}" = "1" ]; then
        echo "warning: freeze check reading $RELEASE_FREEZE_FILE (test mode)" >&2
        FREEZE_FILE="$RELEASE_FREEZE_FILE"
    else
        echo "warning: RELEASE_FREEZE_FILE is ignored outside the freeze test; checking $FREEZE_FILE" >&2
    fi
fi

if [ -e "$FREEZE_FILE" ]; then
    echo "error: releases are frozen ($FREEZE_FILE exists):" >&2
    sed 's/^/  /' "$FREEZE_FILE" >&2
    exit 3
fi
