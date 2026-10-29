#!/usr/bin/env bash
# Reproducible contract/delegate WASM build.
#
# A contract's or delegate's key is derived from its WASM bytes, so the bytes
# must not depend on who built them or where. This script:
#   * remaps CARGO_HOME, RUSTUP_HOME, the checkout and the target dir to fixed
#     prefixes (/cargo, /rustup, /build, /target), so embedded source paths are
#     the same on every machine;
#   * builds from a copy of the checkout at a fixed path
#     (/tmp/freenet-mail-wasm-build), because cargo hashes the absolute path
#     of out-of-workspace path dependencies into symbol names;
#   * builds into a fresh throwaway target dir with --locked;
#   * refuses the output if any build-machine path survived
#     (scripts/check-wasm-paths.sh).
#
# The toolchain is whatever rust-toolchain.toml selects for the crate, so pin it
# there. Build on linux/amd64 (CI is the canonical builder).
#
# Usage:
#   scripts/build-wasm.sh <crate-dir> <contract|delegate> <features> <out-file>
# e.g.
#   scripts/build-wasm.sh modules/mail-local-state delegate \
#       freenet-main-delegate,contract published-contract/wasm/v2/mail_local_state

set -euo pipefail

if [ $# -ne 4 ]; then
    echo "usage: $0 <crate-dir> <contract|delegate> <features> <out-file>" >&2
    exit 2
fi
CRATE_DIR="$1"
KIND="$2"
FEATURES="$3"
# Resolve now: the build below runs from inside the crate directory.
mkdir -p "$(dirname "$4")"
OUT="$(cd "$(dirname "$4")" && pwd -P)/$(basename "$4")"

case "$KIND" in
    contract|delegate) ;;
    *) echo "error: kind must be 'contract' or 'delegate', got '$KIND'" >&2; exit 2 ;;
esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CRATE_REL="$(cd "$CRATE_DIR" && pwd -P)"
case "$CRATE_REL" in
    "$REPO_ROOT"/*) CRATE_REL="${CRATE_REL#"$REPO_ROOT"/}" ;;
    *) echo "error: $CRATE_DIR is not inside $REPO_ROOT" >&2; exit 2 ;;
esac
CARGO_HOME_ABS="$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd -P)"
RUSTUP_HOME_ABS="$(cd "${RUSTUP_HOME:-$HOME/.rustup}" && pwd -P)"

# Build from a copy of the checkout at ONE fixed path. Cargo hashes the
# absolute path of every path dependency outside the building workspace's
# root into that crate's -C metadata, which appears in every mangled symbol
# name; path remapping does not reach it. The mail delegate's protocol/ and
# wire-v1/ are such dependencies, so the same commit built in two checkouts
# gave two different WASMs, and CI a third. At a fixed path every machine
# hashes the same bytes. The lock serializes builds on a shared machine.
# Linux (flock) and one user per machine: the path is fixed by design, so
# two users building at once would contend for it.
STAGE=/tmp/freenet-mail-wasm-build
exec 9> "$STAGE.lock"
flock -w 3600 9 || { echo "error: timed out waiting for $STAGE.lock" >&2; exit 1; }
if [ -e "$STAGE" ]; then rm -r -- "$STAGE"; fi
mkdir -p "$STAGE"
trap 'rm -r -- "$STAGE"' EXIT
# Tracked and untracked-but-not-ignored files, as they are on disk; from a
# source export with no git metadata, everything but target/ and build/.
if git -C "$REPO_ROOT" rev-parse --is-inside-work-tree > /dev/null 2>&1; then
    (cd "$REPO_ROOT" && git ls-files -z --cached --others --exclude-standard \
        | tar --null --ignore-failed-read -T - -cf -) | tar -xf - -C "$STAGE"
else
    (cd "$REPO_ROOT" && tar --exclude=./target --exclude='*/target' \
        --exclude='*/build/freenet' -cf - .) | tar -xf - -C "$STAGE"
fi
CRATE_ABS="$STAGE/$CRATE_REL"
BUILD_TARGET="$STAGE/target/wasm-build"
mkdir -p "$BUILD_TARGET"

# Order matters: rustc applies the LAST matching remap, so list the most
# specific prefixes last (the target dir sits inside the stage).
REMAPS=(
    "--remap-path-prefix=$CARGO_HOME_ABS=/cargo"
    "--remap-path-prefix=$RUSTUP_HOME_ABS=/rustup"
    "--remap-path-prefix=$STAGE=/build"
    "--remap-path-prefix=$BUILD_TARGET=/target"
)
# Env RUSTFLAGS replaces the target rustflags from contracts/.cargo/ and
# modules/.cargo/config.toml, so repeat the one flag those files set.
FLAGS=(--cfg 'getrandom_backend="custom"' "${REMAPS[@]}")
export CARGO_ENCODED_RUSTFLAGS
CARGO_ENCODED_RUSTFLAGS="$(printf '%s\x1f' "${FLAGS[@]}")"
CARGO_ENCODED_RUSTFLAGS="${CARGO_ENCODED_RUSTFLAGS%$'\x1f'}"

cd "$CRATE_ABS"
args=(build --features "$FEATURES")
[ "$KIND" = "delegate" ] && args+=(--package-type delegate)
CARGO_TARGET_DIR="$BUILD_TARGET" CARGO_NET_OFFLINE="${CARGO_NET_OFFLINE:-false}" \
    fdev "${args[@]}"

NAME="$(sed -n 's/^name *= *"\(.*\)"/\1/p' Cargo.toml | head -1 | tr '-' '_')"
BUILT="$CRATE_ABS/build/freenet/$NAME"
[ -f "$BUILT" ] || { echo "error: fdev produced no $BUILT" >&2; exit 1; }

"$REPO_ROOT/scripts/check-wasm-paths.sh" "$BUILT" "$REPO_ROOT" "$STAGE"

cp "$BUILT" "$OUT"
inspect_kind=code
[ "$KIND" = "delegate" ] && inspect_kind=delegate
CARGO_TARGET_DIR="$BUILD_TARGET" fdev inspect "$OUT" "$inspect_kind" | grep 'code hash:'
echo "wrote $OUT"
