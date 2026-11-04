#!/usr/bin/env bash
# Which guards a change can reach. Reads the changed paths (one per line) on
# stdin, prints the names of the guards to run, one per line.
#
# Usage: select-guards.sh EVENT < changed-paths
#   (CI feeds it the PR's diff: the names from `git diff --name-only HEAD^1 HEAD`)
#
# Every guard runs unless EVENT is pull_request, and on a pull request when
# a path the guard harness itself depends on changed. Otherwise a guard runs
# when its area's inputs changed, or its own mutated file did.
#
# A guard's area is decided by the file its mutation edits. What the guard's
# command reads besides that file is the area's input list below: the crate's
# path-dependency closure plus the data it embeds (select-guards_test.sh
# checks the closure against cargo metadata).
# Exit 1 when a guarded area changed and the selection is empty: a selection
# that runs nothing must never pass a change that touched guarded code.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
EVENT="${1:?usage: select-guards.sh EVENT < changed-paths}"

# What every guard depends on: the scripts and workflows that run them, the
# toolchain and the root manifests, and any cargo config.
HARNESS='^(scripts/|\.github/|\.githooks/|\.release-freeze$|Cargo\.toml$|Cargo\.lock$|rust-toolchain\.toml$|Makefile\.toml$)|(^|/)\.cargo/'
area_inputs() {
    case "$1" in
        delegate) echo '^(delegates/mail-delegate/|protocol/|wire-v1/|contracts/inbox-v2/|published-contract/)' ;;
        inbox) echo '^(contracts/inbox-v2/|docs/metadata-fields\.toml$|published-contract/)' ;;
        protocol) echo '^protocol/' ;;
        ui) echo '^(ui/|protocol/|wire-v1/|delegates/mail-delegate/|contracts/inbox-v2/|legacy_[a-z_]+\.toml$|published-contract/|modules/)' ;;
        harness) echo '^$' ;; # its inputs are all harness paths
    esac
}
AREAS="delegate inbox protocol ui harness"
area_of() { # the area of the file a guard's mutation edits
    case "$1" in
        delegates/mail-delegate/*) echo delegate ;;
        contracts/inbox-v2/* | docs/metadata-fields.toml) echo inbox ;;
        protocol/*) echo protocol ;;
        ui/*) echo ui ;;
        scripts/* | Makefile.toml | Cargo.toml) echo harness ;;
        *) echo "select-guards: no area for the mutated file $1; add it to area_of" >&2; return 1 ;;
    esac
}

changed="$(cat)"
guards="$("$ROOT/scripts/check-guards-fail.sh" --list-files)"
[ -n "$guards" ] || { echo "select-guards: no guards listed" >&2; exit 1; }

if [ "$EVENT" != pull_request ] || grep -qE "$HARNESS" <<< "$changed"; then
    echo "select-guards: mode=all ($(wc -l <<< "$guards") guards)" >&2
    cut -f1 <<< "$guards"
    exit 0
fi
hit=" "
for a in $AREAS; do
    re="$(area_inputs "$a")"
    ! grep -qE "$re" <<< "$changed" || hit="$hit$a "
done
selected=""
while IFS=$'\t' read -r name file; do
    area="$(area_of "$file")" || exit 1
    if [[ "$hit" == *" $area "* ]] || grep -qxF -- "$file" <<< "$changed"; then
        selected="$selected$name"$'\n'
    fi
done <<< "$guards"
if [ "$hit" = " " ]; then
    echo "select-guards: mode=none (no guarded area changed)" >&2
    exit 0
fi
if [ -z "$selected" ]; then
    echo "select-guards: areas$hit changed but no guard is selected" >&2
    exit 1
fi
echo "select-guards: mode=scoped areas$hit($(grep -c . <<< "$selected") of $(wc -l <<< "$guards") guards)" >&2
printf '%s' "$selected"
