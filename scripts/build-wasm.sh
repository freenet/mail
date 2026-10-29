#!/usr/bin/env bash
# Reproducible contract/delegate WASM build.
#
# A contract's or delegate's key is derived from its WASM bytes, so the bytes
# must not depend on who built them or where. This script:
#   * remaps CARGO_HOME, RUSTUP_HOME, the checkout and the target dir to fixed
#     prefixes (/cargo, /rustup, /build, /target), so embedded source paths are
#     the same on every machine;
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
CRATE_ABS="$(cd "$CRATE_DIR" && pwd -P)"
CARGO_HOME_ABS="$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd -P)"
RUSTUP_HOME_ABS="$(cd "${RUSTUP_HOME:-$HOME/.rustup}" && pwd -P)"

mkdir -p "$REPO_ROOT/target"
BUILD_TARGET="$(mktemp -d "$REPO_ROOT/target/wasm-build.XXXXXX")"
trap 'rm -r -- "$BUILD_TARGET"' EXIT

# Order matters: rustc applies the LAST matching remap, so list the most
# specific prefixes last (the target dir sits inside the checkout).
REMAPS=(
    "--remap-path-prefix=$CARGO_HOME_ABS=/cargo"
    "--remap-path-prefix=$RUSTUP_HOME_ABS=/rustup"
    "--remap-path-prefix=$REPO_ROOT=/build"
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

"$REPO_ROOT/scripts/check-wasm-paths.sh" "$BUILT" "$REPO_ROOT" "$BUILD_TARGET" "$CRATE_ABS"

cp "$BUILT" "$OUT"
inspect_kind=code
[ "$KIND" = "delegate" ] && inspect_kind=delegate
CARGO_TARGET_DIR="$BUILD_TARGET" fdev inspect "$OUT" "$inspect_kind" | grep 'code hash:'
echo "wrote $OUT"
