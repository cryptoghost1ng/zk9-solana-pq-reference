#!/bin/sh
set -eu
ZK9_HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ZK9_TOOLS="$ZK9_HERE/../gloas-native-integration-v1/native/.toolchain"
export PATH="$ZK9_TOOLS/rust/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export CARGO_HOME="$ZK9_TOOLS/cargo"
export CARGO_TARGET_DIR="$ZK9_HERE/target"
export RUSTC="$ZK9_TOOLS/rust/bin/rustc"
export RUSTDOC="$ZK9_TOOLS/rust/bin/rustdoc"
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
cd "$ZK9_HERE"
exec "$ZK9_TOOLS/rust/bin/cargo" "$@"
