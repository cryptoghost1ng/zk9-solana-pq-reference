#!/bin/sh
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PINNED="$HERE/../solana-proof-buffer-v1"
export CARGO_HOME="$HERE/../solana-verifier-profile-v1/sbf-cargo-home"
export CARGO_TARGET_DIR="$HERE/sbf-target"
export PATH="$PINNED/platform-tools-v1.52/rust/bin:/usr/bin:/bin:/usr/sbin:/sbin"
unset RUSTC RUSTDOC RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
cd "$HERE"
exec <HOME>/.local/share/solana/install/releases/3.1.10/solana-release/bin/cargo-build-sbf --manifest-path "$HERE/sbf-probe/Cargo.toml" --tools-version v1.52 --sbf-sdk "$PINNED/sbf-sdk" --skip-tools-install --no-rustup-override --offline --sbf-out-dir "$HERE/sbf-bin" "$@"
