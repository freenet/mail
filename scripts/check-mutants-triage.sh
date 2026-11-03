#!/usr/bin/env bash
# Compare what cargo-mutants left standing against contracts/inbox-v2/mutants-triage.md.
#
# Every mutant that survived, or timed out (a hang is not a pass), must have a
# line in the triage file. With --complete (the files come from a run of every
# shard) a triage line no survivor matches fails too: a mutant that now dies,
# or code that no longer exists, must not leave its excuse behind.
#
# A triage line is a bullet that starts with the mutant as cargo-mutants names
# it, minus the position, in backticks:
#
#   - `src/merge.rs: replace >= with > in Filter::admit_pass` and then the reason
#
# The position is left out so an edit above does not stale the line. When two
# mutants share a name, one line covers both, so the reason must hold for both.
#
# Usage: scripts/check-mutants-triage.sh [--complete] [--triage FILE] OUTCOME_FILE...
#   OUTCOME_FILE is a missed.txt or timeout.txt from `cargo mutants`.
# Exit status: 0 = every survivor is triaged, 1 = one is not (or one is stale).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TRIAGE="$ROOT/contracts/inbox-v2/mutants-triage.md"
COMPLETE=0
FILES=()
while [ $# -gt 0 ]; do
    case "$1" in
        --complete) COMPLETE=1 ;;
        --triage) TRIAGE="$2"; shift ;;
        -*) echo "unknown argument: $1" >&2; exit 2 ;;
        *) FILES+=("$1") ;;
    esac
    shift
done
[ "${#FILES[@]}" -gt 0 ] || { echo "usage: $0 [--complete] OUTCOME_FILE..." >&2; exit 2; }

python3 -I - "$TRIAGE" "$COMPLETE" "${FILES[@]}" << 'EOF'
import re, sys

triage_path, complete, files = sys.argv[1], sys.argv[2] == "1", sys.argv[3:]
survivors = set()
for path in files:
    for line in open(path):
        line = line.strip()
        if line:
            # src/merge.rs:123:45: replace x with y in f  ->  src/merge.rs: replace x with y in f
            survivors.add(re.sub(r"^([^:]+):\d+:\d+:", r"\1:", line))
triaged = set()
for line in open(triage_path):
    m = re.match(r"^- `([^`]+)`", line)
    if m:
        triaged.add(m.group(1))

untriaged = sorted(survivors - triaged)
stale = sorted(triaged - survivors) if complete else []
for s in untriaged:
    print("FAIL: survivor with no triage line: " + s, file=sys.stderr)
for s in stale:
    print("FAIL: triage line for a mutant that no longer survives: " + s, file=sys.stderr)
if untriaged or stale:
    sys.exit(1)
print("ok: %d survivors, all triaged" % len(survivors))
EOF
