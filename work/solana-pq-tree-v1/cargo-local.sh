#!/bin/sh
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TOOLS="$HERE/../gloas-native-integration-v1/native/.toolchain"
export PATH="$TOOLS/rust/bin:/usr/bin:/bin:/usr/sbin:/sbin"
# Existing isolated union cache includes both native proof and Solana crates.
export CARGO_HOME="$HERE/../solana-verifier-profile-v1/sbf-cargo-home"
export CARGO_TARGET_DIR="$HERE/target"
export RUSTC="$TOOLS/rust/bin/rustc"
export RUSTDOC="$TOOLS/rust/bin/rustdoc"
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
cd "$HERE"
exec "$TOOLS/rust/bin/cargo" "$@"
