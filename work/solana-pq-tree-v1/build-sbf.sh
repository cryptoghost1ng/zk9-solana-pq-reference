#!/bin/sh
set -eu
ZK9_HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ZK9_TOOLS="$ZK9_HERE/../solana-proof-buffer-v1"
export CARGO_HOME="$ZK9_HERE/../solana-verifier-profile-v1/sbf-cargo-home"
export CARGO_TARGET_DIR="$ZK9_HERE/sbf-target"
export PATH="$ZK9_TOOLS/platform-tools-v1.52/rust/bin:/usr/bin:/bin:/usr/sbin:/sbin"
unset RUSTC RUSTDOC RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
cd "$ZK9_HERE"
exec <HOME>/.local/share/solana/install/releases/3.1.10/solana-release/bin/cargo-build-sbf \
 --manifest-path "$ZK9_HERE/sbf-probe/Cargo.toml" --tools-version v1.52 \
 --sbf-sdk "$ZK9_TOOLS/sbf-sdk" --skip-tools-install --no-rustup-override \
 --offline --sbf-out-dir "$ZK9_HERE/sbf-bin" "$@"
