#!/usr/bin/env bash
# select-guards.sh decides which guards a pull request runs, so a wrong
# answer is a guard that silently stops running. This asserts the answer for
# lists of changed files, that every area's inputs cover the crates' path
# dependencies, and that the shards split a selection with nothing lost.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
SEL="$ROOT/scripts/select-guards.sh"
T="$(mktemp -d)"
trap 'rm -r -- "$T"' EXIT
"$ROOT/scripts/check-guards-fail.sh" --list-files > "$T/guards"
total=$(wc -l < "$T/guards")
fails=0
ok() { echo "ok - $1"; }
bad() { echo "not ok - $1"; fails=$((fails + 1)); }
# select EVENT path... : the selection goes to $T/sel, its exit status is returned
select_for() {
    local event="$1"
    shift
    printf '%s\n' "$@" | "$SEL" "$event" > "$T/sel" 2> "$T/err"
}
count() { grep -c . "$T/sel" || true; }
files_of_selected() { # the mutated files of the selected guards
    awk -F'\t' 'NR == FNR { want[$0] = 1; next } $1 in want { print $2 }' "$T/sel" "$T/guards" | sort -u > "$T/files"
}
has() { grep -q "$1" "$T/files"; } # grep -q ends a pipe early, which pipefail reports as failure

# Everything runs off a pull request, whatever the paths.
select_for push README.md
[ "$(count)" -eq "$total" ] && ok "a push runs every guard" || bad "a push runs every guard"
select_for schedule README.md
[ "$(count)" -eq "$total" ] && ok "a scheduled run runs every guard" || bad "a scheduled run runs every guard"

# Only the harness changed (and only a workflow, a lockfile, a toolchain pin, cargo config).
for p in scripts/check-guards-fail.sh .github/workflows/check-contract-wasm.yml Cargo.lock Cargo.toml \
    rust-toolchain.toml Makefile.toml contracts/.cargo/config.toml .release-freeze \
    published-contract/candidate/mail_delegate published-contract/README.md; do
    select_for pull_request "$p"
    [ "$(count)" -eq "$total" ] && ok "harness change $p runs every guard" || bad "harness change $p runs every guard"
done

# Only documentation, or a crate with no guard: nothing, and no error.
for p in README.md docs/qa/manual-test-inventory.md common/src/lib.rs tools/v1-node-seed/src/main.rs; do
    if select_for pull_request "$p" && [ "$(count)" -eq 0 ]; then ok "$p alone selects no guard"; else bad "$p alone selects no guard"; fi
done

# One crate: its guards, and only guards whose area reads that crate.
select_for pull_request ui/src/app.rs
n=$(count)
files_of_selected
if [ "$n" -gt 0 ] && [ "$n" -lt "$total" ] && ! grep -qE '^(delegates/|contracts/|protocol/|scripts/|Makefile)' "$T/files"; then
    ok "a ui change runs the ui guards only ($n)"
else bad "a ui change runs the ui guards only ($n)"; fi
select_for pull_request protocol/src/lib.rs
files_of_selected
has '^protocol/' && has '^ui/' \
    && has '^delegates/' && ! has '^contracts/inbox-v2/' \
    && ok "a protocol change runs protocol, delegate and ui guards, not the contract's" \
    || bad "a protocol change runs protocol, delegate and ui guards, not the contract's"
select_for pull_request contracts/inbox-v2/src/merge.rs
files_of_selected
has '^contracts/inbox-v2/' && has '^delegates/' \
    && has '^ui/' && ! has '^protocol/' \
    && ok "an inbox contract change runs the contract, delegate and ui guards" \
    || bad "an inbox contract change runs the contract, delegate and ui guards"
select_for pull_request delegates/mail-delegate/src/store.rs README.md
files_of_selected
has '^delegates/' && has '^ui/' \
    && ! has '^contracts/inbox-v2/' \
    && ok "a delegate change (with a doc) runs the delegate and ui guards" \
    || bad "a delegate change (with a doc) runs the delegate and ui guards"

# A guard whose own mutated file changed runs (here the metadata list).
select_for pull_request docs/metadata-fields.toml
grep -q 'the toml' "$T/sel" && ok "a mutated file's guards run" || bad "a mutated file's guards run"

# A new mutated file with no area fails closed.
if ! (eval "$(sed -n '/^area_of()/,/^}/p' "$SEL")"; area_of new-dir/file.rs) > /dev/null 2>&1; then
    ok "a mutated file with no area is refused"
else bad "a mutated file with no area is refused"; fi

# Every area's inputs include the path-dependency CLOSURE of the crates it covers.
closure_dirs() { # manifest dir -> the repo-relative directories of its transitive path dependencies
    cargo metadata --no-deps --offline --format-version 1 --manifest-path "$ROOT/$1" \
        | python3 -I -c '
import json, os, sys
root = os.path.realpath(sys.argv[1])
start = os.path.join(root, sys.argv[2])
pk = {os.path.dirname(p["manifest_path"]): p for p in json.load(sys.stdin)["packages"]}
if start not in pk:
    sys.exit("no package at " + sys.argv[2])
seen, todo = set(), [start]
while todo:
    d = todo.pop()
    for x in pk[d]["dependencies"]:
        if x.get("path") and x["path"] not in seen:
            seen.add(x["path"])
            if x["path"] in pk:
                todo.append(x["path"])
for d in sorted(seen):
    print(os.path.relpath(d, root) + "/")
' "$ROOT" "$2"
}
covered() { # area manifest dir
    local re missing=0 d
    re="$(sed -n "/^area_inputs()/,/^}/p" "$SEL" | grep -E "^ +$1\)" | sed -E "s/.*echo '(.*)'.*/\1/")"
    while IFS= read -r d; do
        [ -z "$d" ] || printf '%s\n' "${d}x" | grep -qE "$re" || { echo "  $1 does not cover $d"; missing=1; }
    done < <(closure_dirs "$2" "$3")
    return $missing
}
covered delegate delegates/mail-delegate/Cargo.toml delegates/mail-delegate && ok "delegate inputs cover its path-dependency closure" || bad "delegate inputs cover its path-dependency closure"
covered ui Cargo.toml ui && ok "ui inputs cover its path-dependency closure" || bad "ui inputs cover its path-dependency closure"
covered protocol Cargo.toml protocol && ok "protocol inputs cover its path-dependency closure" || bad "protocol inputs cover its path-dependency closure"
covered inbox contracts/inbox-v2/Cargo.toml contracts/inbox-v2 && ok "inbox inputs cover its path-dependency closure" || bad "inbox inputs cover its path-dependency closure"
# The walk itself is transitive: ui reaches protocol and wire-v1 through the
# delegate or the contract, so they must appear in ui's closure.
closure_dirs Cargo.toml ui > "$T/ui.closure"
grep -qx 'protocol/' "$T/ui.closure" && grep -qx 'delegates/mail-delegate/' "$T/ui.closure" \
    && ok "the closure walk follows dependencies of dependencies" || bad "the closure walk follows dependencies of dependencies"

# Every file a source reads at build or test time is an input of each area that
# builds that source, so a change to only that file selects the area. Fail
# closed: a read the scan cannot resolve to a literal path is an error naming
# the file and line, unless it is in the reviewed EXEMPT list below (a CLI
# argument, an ignored test, a build script); a stale exemption is an error.
# Detected:
#   include!/include_str!/include_bytes!, fs::* calls, File::open/create,
#   Path::new/PathBuf::from(env!("CARGO_MANIFEST_DIR")) with .join("lit"),
#   and any other use of env!("CARGO_MANIFEST_DIR").
# A path may be a normal or raw string literal, concat! of literals and
# env!("CARGO_MANIFEST_DIR"), or a const/static/let defined once in the same
# file as such. concat!(env!("OUT_DIR"), ...) is accepted when the crate has a
# build.rs (which is in the area). A path computed at run time from anything
# else is refused, never guessed. Rust files outside the guarded areas
# (tools/, common/) are not scanned: no guard builds them.
area_re() { sed -n "/^area_inputs()/,/^}/p" "$SEL" | grep -E "^ +$1\)" | sed -E "s/.*echo '(.*)'.*/\1/"; }
for a in delegate inbox protocol ui; do area_re "$a" > "$T/re.$a"; done
sed -n "s/^HARNESS='\(.*\)'$/\1/p" "$SEL" > "$T/re.harness"
cat > "$T/reads.py" <<'PY'
import os, re, sys
mode, root, tmp = sys.argv[1], sys.argv[2], sys.argv[3]
res = {a: re.compile(open(f"{tmp}/re.{a}").read().strip()) for a in ("delegate", "inbox", "protocol", "ui")}
harness = re.compile(open(f"{tmp}/re.harness").read().strip())  # a harness path runs every guard

# Reviewed reads that name no repository file. (source, site text without whitespace) -> reason.
EXEMPT = {
    ("modules/identity-management/src/bin/tool.rs", "fs::read(path)"): "CLI argument, not a repository input",
    ("modules/mail-local-state/src/bin/tool.rs", "fs::read(path)"): "CLI argument, not a repository input",
    ("modules/antiflood-tokens/contracts/token-allocation-record/tests/test.rs", 'env!("CARGO_MANIFEST_DIR")'): "#[ignore]d test of a fixture that is not in the repository",
    ("modules/antiflood-tokens/contracts/token-allocation-record/tests/test.rs", "fs::read(path)"): "#[ignore]d test of a fixture that is not in the repository",
    ("ui/build.rs", "fs::read_to_string(&container_id_path)"): "reads published-contract/, which runs every guard",
    ("ui/build.rs", "fs::metadata(path)"): "existence check of the artifacts the includes name (published-contract/)",
}
used = set()

STR = r'"(?:\\.|[^"\\])*"'
RAW = r'r(?P<h>#*)"(?:.|\n)*?"(?P=h)'
LEX = re.compile(rf'(?P<raw>{RAW})|(?P<str>{STR})|(?P<chr>\'(?:\\[^\']+|[^\'\\\n])\')|(?P<lc>//[^\n]*)|(?P<bc>/\*(?:.|\n)*?\*/)')
def blank(m): return re.sub(r"[^\n]", " ", m.group(0))
def clean(text):
    """(text with comments blanked, text with comments and string contents blanked); same length."""
    def keep(m):
        return blank(m) if m.lastgroup in ("lc", "bc") else m.group(0)
    def mask(m):
        if m.lastgroup in ("lc", "bc"): return blank(m)
        g = m.group(0)
        if m.lastgroup == "str": return g[0] + re.sub(r"[^\n]", "x", g[1:-1]) + g[-1]
        if m.lastgroup == "raw": return re.sub(r"[^\n]", "x", g)
        return g
    return LEX.sub(keep, text), LEX.sub(mask, text)

LIT = re.compile(rf'^\s*(?:{STR}|r(#*)"(?:.|\n)*?"\1)\s*$')
def litval(s):
    s = s.strip()
    m = re.match(r'^r(#*)"((?:.|\n)*)"\1$', s)
    if m: return m.group(2)
    return re.sub(r'\\(.)', r'\1', s[1:-1])
def balanced(t, i):
    """index just past the paren that closes the one before t[i]; None if unbalanced"""
    depth = 1
    while i < len(t):
        m = LEX.match(t, i)
        if m: i = m.end(); continue
        if t[i] in "([{": depth += 1
        elif t[i] in ")]}":
            depth -= 1
            if depth == 0: return i + 1
        i += 1
    return None
def split_top(s):
    parts, depth, cur, i = [], 0, "", 0
    while i < len(s):
        m = LEX.match(s, i)
        if m: cur += m.group(0); i = m.end(); continue
        c = s[i]
        if c in "([{": depth += 1
        elif c in ")]}": depth -= 1
        if c == "," and depth == 0: parts.append(cur); cur = ""
        else: cur += c
        i += 1
    if cur.strip(): parts.append(cur)
    return parts
def manifest_dir(path):
    d = os.path.dirname(path)
    while d and not os.path.exists(os.path.join(root, d, "Cargo.toml")):
        d = os.path.dirname(d)
    return d
CMD = r'env!\s*\(\s*"CARGO_MANIFEST_DIR"\s*\)'
OUTD = r'env!\s*\(\s*"OUT_DIR"\s*\)'
F3 = rf'(?:std::path::)?(?:Path::new|PathBuf::from)\s*\(\s*{CMD}\s*\)(?:\s*\.join\s*\(\s*{STR}\s*\))*'
FORM3 = re.compile(F3)

def resolve(expr, src, text, rel_to, depth=0):
    """-> a repo-relative path, "GEN" (generated by the crate's build.rs), or None (cannot resolve)."""
    e = expr.strip().lstrip("&").strip()
    md = manifest_dir(src)
    if LIT.match(e):
        return os.path.normpath(os.path.join(rel_to, litval(e)))
    m = re.match(r'^concat\s*!\s*\((.*)\)$', e, re.S)
    if m:
        parts, base, out = split_top(m.group(1)), None, ""
        for k, p in enumerate(parts):
            if k == 0 and re.match(rf'^\s*{CMD}\s*$', p): base = md
            elif k == 0 and re.match(rf'^\s*{OUTD}\s*$', p):
                return "GEN" if os.path.exists(os.path.join(root, md, "build.rs")) else None
            elif LIT.match(p): out += litval(p)
            else: return None
        return os.path.normpath(os.path.join(base, out.lstrip("/"))) if base is not None else os.path.normpath(os.path.join(rel_to, out))
    if FORM3.fullmatch(e):
        out = "/".join(litval(x) for x in re.findall(STR, e.split(")", 1)[1]))
        return os.path.normpath(os.path.join(md, out))
    if depth < 3 and re.match(r"^[A-Za-z_]\w*$", e):
        defs = re.findall(rf'\b(?:const|static|let)\s+(?:mut\s+)?{e}\b[^=;]*=\s*((?:.|\n)*?);', text)
        if len(defs) == 1:
            return resolve(defs[0], src, text, rel_to, depth + 1)
    return None

# Sites are found in the text with string contents masked to x, so the env
# names match by length (CARGO_MANIFEST_DIR is 18). A different 18-character
# name is read as this one and then fails to resolve, which refuses it.
MCMD = r'env!\s*\(\s*"x{18}"\s*\)'
MF3 = rf'(?:std::path::)?(?:Path::new|PathBuf::from)\s*\(\s*{MCMD}\s*\)(?:\s*\.join\s*\(\s*{STR}\s*\))*'
SITE = re.compile(
    r'\b(?P<inc>include(?:_str|_bytes)?)\s*!\s*\('
    r'|\b(?P<fs>(?:std::)?fs::(?!write\b|create_dir|remove_|rename\b|set_permissions\b|hard_link\b|soft_link\b|symlink)[\w:]+)\s*\('
    r'|\b(?P<file>File::(?:open|options|open_buffered))\s*\('
    r'|\bOpenOptions::new\s*\('
    rf'|(?P<f3>{MF3})'
    rf'|(?P<env>{MCMD})'
    r'|(?P<use>\buse\s+std::fs::(?:\{[^}]*\b(?:read|read_to_string|read_dir|File|OpenOptions)\b|read\b|read_to_string\b|read_dir\b|File\b|OpenOptions\b))')

def scan(src, raw):
    """-> (refused, uncovered): lists of strings"""
    text, masked = clean(raw)
    areas = [a for a, r in res.items() if r.match(src)]
    refused, uncovered, consumed = [], [], []
    for m in SITE.finditer(masked):
        if any(a <= m.start() < b for a, b in consumed):
            continue
        line = masked.count("\n", 0, m.start()) + 1
        if m.group("env"):
            # Another 18-character name is not ours. The manifest dir as the head of a
            # concat! is checked where the concatenation is read (and refused there if
            # that read cannot be resolved).
            if not re.fullmatch(CMD, text[m.start():m.end()]) or re.search(r"concat\s*!\s*\(\s*$", masked[:m.start()]):
                continue
        if m.group("f3") or m.group("env") or m.group("use"):
            end = m.end()
        else:
            end = balanced(masked, m.end())
            if end is None:
                refused.append(f"{src}:{line}: unbalanced call"); continue
        consumed.append((m.start(), end))
        site = text[m.start():end]
        norm = re.sub(r"\s+", "", site).removeprefix("std::")
        if (src, norm) in EXEMPT:
            used.add((src, norm)); continue
        if m.group("use"):
            refused.append(f"{src}:{line}: an fs function is imported; call it as fs::name so the scan can see the path")
            continue
        if m.group("f3"):
            target = resolve(site, src, text, manifest_dir(src))
        elif m.group("env"):
            target = None
        else:
            args = split_top(text[m.end():end - 1])
            if m.group("inc"):
                target = resolve(args[0], src, text, os.path.dirname(src)) if len(args) == 1 else None
            else:
                target = resolve(args[0], src, text, manifest_dir(src)) if args else None
        if target is None:
            refused.append(f"{src}:{line}: cannot resolve the path read by " + re.sub(r"\s+", " ", site)[:90])
            continue
        if target == "GEN":
            continue
        for a in areas:
            ways = (target, target + "/") if m.group("f3") else (target,)
            if not any(res[a].match(w) for w in ways) and not harness.search(target):
                uncovered.append(f"  {a}: {src}:{line} reads {target}")
    return refused, uncovered

if mode == "selftest":
    # (name, source, expected): "ok", "refused" or the uncovered path
    cases = [
        ("covered literal", 'include_str!("../../published-contract/wasm/v1/h");', "ok"),
        ("covered by the ui area", 'include_bytes!("../../protocol/x.bin");', "ok"),
        ("raw string", 'include_str!(r"../../tools/x");', "tools/x"),
        ("raw string with hashes", 'include_str!(r#"../../tools/x"#);', "tools/x"),
        ("concat of literals", 'include_str!(concat!("../../tools/", "x"));', "tools/x"),
        ("multi-line include", 'include_str!(\n    "../../tools/x"\n);', "tools/x"),
        ("Path::new(env).join", 'let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tools/x");', "tools/x"),
        ("PathBuf::from(env).join.join", 'let p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("tools/x");', "tools/x"),
        ("format with the manifest dir", 'let p = format!("{}/x", env!("CARGO_MANIFEST_DIR"));', "refused"),
        ("fs::read_to_string literal", 'let s = std::fs::read_to_string("../tools/x");', "tools/x"),
        ("fs::read(concat env)", 'let s = fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../tools/x"));', "tools/x"),
        ("File::open of a literal", 'let f = File::open("../tools/x");', "tools/x"),
        ("File::open of a variable", 'let f = File::open(p);', "refused"),
        ("fs::read of a computed path", 'let s = fs::read(dir.join(name));', "refused"),
        ("const path then read", 'const P: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../tools/x");\nlet s = fs::read_to_string(P);', "tools/x"),
        ("macro-built include path", 'include_str!(path_macro!());', "refused"),
        ("OUT_DIR include", 'include!(concat!(env!("OUT_DIR"), "/x.rs"));', "ok"),
        ("imported fs function", 'use std::fs::read_to_string;', "refused"),
        ("block comment", '/* include_str!("../../tools/x") */', "ok"),
        ("line comment", '// include_str!("../../tools/x")', "ok"),
        ("string literal text", 'let s = "include_str!(\\"../../tools/x\\")";', "ok"),
    ]
    bad = 0
    for name, src_text, want in cases:
        refused, uncovered = scan("ui/src/zz_selftest.rs", src_text)
        got = "refused" if refused else (uncovered[0].split(" reads ")[1] if uncovered else "ok")
        if got != want:
            print(f"  selftest {name}: wanted {want}, got {got} {refused or uncovered}"); bad += 1
    sys.exit(1 if bad else 0)

for src in sys.stdin.read().split():
    if not any(r.match(src) for r in res.values()):
        continue
    refused, uncovered = scan(src, open(os.path.join(root, src), encoding="utf-8").read())
    for r in refused: print("  REFUSED " + r)
    for u in uncovered: print(u)
for k in sorted(set(EXEMPT) - used):
    print(f"  REFUSED stale exemption {k[0]}: {k[1]} (no such read; remove it)")
PY
python3 -I "$T/reads.py" selftest "$ROOT" "$T" && ok "the read scan resolves or refuses each form of file read" || bad "the read scan resolves or refuses each form of file read"
git -C "$ROOT" ls-files '*.rs' | python3 -I "$T/reads.py" scan "$ROOT" "$T" | sort -u > "$T/uncovered"
if [ ! -s "$T/uncovered" ]; then ok "every area lists the files its sources read, and every read resolves"
else cat "$T/uncovered"; bad "every area lists the files its sources read, and every read resolves"; fi

# Every guard is selected by a change to its own mutated file alone.
unselected=0
while IFS= read -r file; do
    select_for pull_request "$file" || true
    while IFS=$'\t' read -r name _; do
        grep -qxF -- "$name" "$T/sel" || { echo "  $name not selected by $file"; unselected=1; }
    done < <(awk -F'\t' -v f="$file" '$2 == f' "$T/guards")
done < <(cut -f2 "$T/guards" | sort -u)
[ "$unselected" -eq 0 ] && ok "a change to a guard's mutated file selects that guard" || bad "a change to a guard's mutated file selects that guard"

# A manifest of any workspace member changes what cargo loads for every guard.
for p in common/Cargo.toml tools/v1-node-seed/Cargo.toml ui/Cargo.toml protocol/Cargo.toml; do
    select_for pull_request "$p"
    [ "$(count)" -eq "$total" ] && ok "manifest change $p runs every guard" || bad "manifest change $p runs every guard"
done

# The shards split a selection: every selected guard in exactly one shard, none outside it.
select_for pull_request ui/src/app.rs
cp "$T/sel" "$T/ui"
: > "$T/union"
for i in 0 1 2 3 4 5 6 7; do
    "$ROOT/scripts/check-guards-fail.sh" --only "$T/ui" --shard "$i/8" --list >> "$T/union"
done
if [ "$(sort "$T/union")" = "$(sort "$T/ui")" ] && [ -z "$(sort "$T/union" | uniq -d)" ]; then
    ok "the 8 shards cover a selection once"
else bad "the 8 shards cover a selection once"; fi

[ "$fails" -eq 0 ] || { echo "$fails check(s) failed"; exit 1; }
echo "ok - the guard selection holds"
