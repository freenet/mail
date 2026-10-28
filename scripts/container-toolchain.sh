# shellcheck shell=bash
# Source this before building the container contract. Usage:
#   . scripts/container-toolchain.sh   # with ROOT set to the repo root
#
# container.wasm bytes (and so the container contract id, the bookmarkable
# URL) depend on the rustc version, pinned in contracts/facade/rust-toolchain.toml.
# rustup only reads that file when nothing overrides it, and running under
# `cargo make` does override it: the rustup proxy exports RUSTUP_TOOLCHAIN
# (the repo root's toolchain) to every child process. So set it explicitly,
# then refuse to go on unless rustc and cargo really are the pinned version.

CONTAINER_RUSTC=$(awk -F'"' '/^channel/ {print $2; exit}' "$ROOT/contracts/facade/rust-toolchain.toml")
if [ -z "$CONTAINER_RUSTC" ]; then
    echo "error: no channel pin in contracts/facade/rust-toolchain.toml" >&2
    exit 1
fi
export RUSTUP_TOOLCHAIN="$CONTAINER_RUSTC"
unset RUSTC RUSTDOC
for tool in rustc cargo; do
    version=$("$tool" --version 2>&1)
    case "$version" in
        "$tool $CONTAINER_RUSTC "*) ;;
        *)
            echo "error: the container contract must be built with $tool $CONTAINER_RUSTC," >&2
            echo "       but '$tool --version' says: $version" >&2
            exit 1
            ;;
    esac
done
echo "container toolchain: $(rustc --version)"
