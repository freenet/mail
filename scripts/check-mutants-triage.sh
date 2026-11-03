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
# A run that tested nothing has no survivors, so it would pass. Each directory
# the outcome files are in is a run's mutants.out: its caught.txt must name at
# least one mutant, and caught, missed and timeout together at least
# --min-tested (default 10; a shard of the ~245 holds about 30). Unviable
# mutants never ran against a test, so they do not count.
#
# Usage: scripts/check-mutants-triage.sh [--complete] [--triage FILE]
#            [--min-tested N] OUTCOME_FILE...
#   OUTCOME_FILE is a missed.txt or timeout.txt from `cargo mutants`.
# Exit status: 0 = every survivor is triaged, 1 = one is not (or one is stale,
# or a run tested too little).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TRIAGE="$ROOT/contracts/inbox-v2/mutants-triage.md"
COMPLETE=0
MIN_TESTED=10
FILES=()
while [ $# -gt 0 ]; do
    case "$1" in
        --complete) COMPLETE=1 ;;
        --triage) TRIAGE="$2"; shift ;;
        --min-tested) MIN_TESTED="$2"; shift ;;
        -*) echo "unknown argument: $1" >&2; exit 2 ;;
        *) FILES+=("$1") ;;
    esac
    shift
done
[ "${#FILES[@]}" -gt 0 ] || { echo "usage: $0 [--complete] OUTCOME_FILE..." >&2; exit 2; }

python3 -I - "$TRIAGE" "$COMPLETE" "$MIN_TESTED" "${FILES[@]}" << 'EOF'
import os, re, sys

triage_path, complete = sys.argv[1], sys.argv[2] == "1"
min_tested, files = int(sys.argv[3]), sys.argv[4:]


def lines(path):
    if not os.path.exists(path):
        return None
    return sum(1 for line in open(path) if line.strip())


thin = False
for run in sorted({os.path.dirname(os.path.abspath(path)) for path in files}):
    caught = lines(os.path.join(run, "caught.txt"))
    tested = sum(lines(os.path.join(run, name)) or 0
                 for name in ("caught.txt", "missed.txt", "timeout.txt"))
    if not caught:
        print("FAIL: %s: no mutant caught (caught.txt %s): the run tested nothing"
              % (run, "empty" if caught == 0 else "missing"), file=sys.stderr)
        thin = True
    elif tested < min_tested:
        print("FAIL: %s: %d mutants tested, under the floor of %d" % (run, tested, min_tested),
              file=sys.stderr)
        thin = True

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
if untriaged or stale or thin:
    sys.exit(1)
print("ok: %d survivors, all triaged" % len(survivors))
EOF
