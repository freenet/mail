#!/usr/bin/env python3
"""Fail on any branch arm of the crate's rules that no test visits.

Reads the JSON that `cargo llvm-cov --branch --json` writes. For every branch
in the crate's own `src/` each arm (taken and not taken) must have run at
least once, or the arm must be listed in the allowlist with a reason. An
allowlist entry that matches no unvisited arm fails too: a stale excuse is
worse than none, because it keeps a hole open for code that is not there.

An allowlist entry names the arm by the text of the source line the branch
starts on, not by its number, so an edit above does not stale it:

    [[allow]]
    file = "src/merge.rs"
    code = "if let Some(x) = y {"
    arm = "false"          # "true" or "false": the arm that is never visited
    why = "unreachable: the caller has already checked y"

Usage: check-branch-coverage.py REPORT.json CRATE_DIR ALLOWLIST.toml
Exit status: 0 = every arm visited or allowed, 1 = otherwise, 2 = bad input.
"""
import json
import os
import sys
import tomllib


def fail(message, status=1):
    print("FAIL: " + message, file=sys.stderr)
    sys.exit(status)


def main(argv):
    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    report_path, crate, allow_path = argv[1:]
    crate = os.path.realpath(crate)
    src = os.path.join(crate, "src") + os.sep

    with open(allow_path, "rb") as f:
        allow = tomllib.load(f).get("allow", [])
    for n, entry in enumerate(allow, 1):
        if set(entry) != {"file", "code", "arm", "why"}:
            fail("allowlist entry %d needs exactly file, code, arm and why" % n, 2)
        if entry["arm"] not in ("true", "false") or not entry["why"].strip():
            fail("allowlist entry %d: arm is true or false, and why is not empty" % n, 2)

    with open(report_path) as f:
        report = json.load(f)
    files = report["data"][0]["files"]

    seen_files = 0
    arms = 0
    visited = 0
    unvisited = {}
    for entry in files:
        name = os.path.realpath(entry["filename"])
        if not name.startswith(src):
            continue
        seen_files += 1
        rel = os.path.relpath(name, crate)
        with open(name) as f:
            lines = f.read().split("\n")
        for branch in entry.get("branches", []):
            line, _, _, _, taken, not_taken = branch[:6]
            # A branch inside a macro expansion belongs to the macro's file.
            if len(branch) > 7 and branch[6] != branch[7]:
                continue
            code = lines[line - 1].strip()
            for arm, count in (("true", taken), ("false", not_taken)):
                arms += 1
                if count > 0:
                    visited += 1
                else:
                    unvisited.setdefault((rel, code, arm), []).append(line)

    if seen_files == 0:
        fail("the report has no file under %s: was the crate measured?" % src, 2)
    if arms == 0:
        fail("the report has no branch: was it built with --branch?", 2)

    allowed = {(e["file"], e["code"], e["arm"]) for e in allow}
    missing = {key: at for key, at in unvisited.items() if key not in allowed}
    stale = sorted(allowed - set(unvisited))

    print("branch coverage: %d arms in %d files, %d visited, %d allowed, %d unvisited"
          % (arms, seen_files, visited, len(unvisited) - len(missing), len(missing)))
    if missing:
        for (rel, code, arm), at in sorted(missing.items()):
            print("FAIL: %s:%s: the %s arm of `%s` is never visited"
                  % (rel, ",".join(map(str, at)), arm, code), file=sys.stderr)
    if stale:
        for rel, code, arm in stale:
            print("FAIL: allowlist entry matches no unvisited arm: %s `%s` (%s)"
                  % (rel, code, arm), file=sys.stderr)
    return 1 if (missing or stale) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
