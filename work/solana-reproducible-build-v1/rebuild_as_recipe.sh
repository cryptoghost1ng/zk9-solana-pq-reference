#!/bin/sh
# Runs a program's build EXACTLY the way its recipe (build-pool.sh / build-verifier.sh) does, with the same unnormalised paths (`<dir>/../solana-verifier-profile-v1/sbf-cargo-home`), but writing the
# target and the output to a SCRATCH directory, then compares the result with the pinned binary. The cargo cache is used in place, read-only in practice (--offline --locked).
# usage: rebuild_as_recipe.sh pool|send|withdraw|buffer OUTDIR
set -eu
W=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WHICH=$1; OUT=$2; mkdir -p "$OUT/target" "$OUT/sbf-out"
case $WHICH in
  pool)     HERE="$W/solana-beta-withdraw-v1"; MAN=pool/Cargo.toml;     NAME=zk9_solana_beta_settlement.so;  PIN="$W/solana-beta-withdraw-v1/sbf-bin/zk9_solana_beta_settlement.so";;
  send)     HERE="$W/solana-beta-spend-v1";    MAN=verifier/Cargo.toml;  NAME=zk9_solana_beta_verifier.so;    PIN="$W/solana-beta-spend-v1/sbf-bin/zk9_solana_beta_verifier.so";;
  withdraw) HERE="$W/solana-beta-withdraw-v1"; MAN=verifier/Cargo.toml;  NAME=zk9_solana_withdraw_verifier.so; PIN="$W/solana-beta-withdraw-v1/sbf-bin/zk9_solana_withdraw_verifier.so";;
  buffer)   HERE="$W/solana-proof-buffer-v1";  MAN=Cargo.toml;           NAME=zk9_solana_proof_buffer_lab.so; PIN="$W/../results/solana-proof-buffer-v1/bin/zk9_solana_proof_buffer_lab.so";;
esac
ZK9_HERE=$(CDPATH= cd -- "$HERE" && pwd)
ZK9_TOOLS="$ZK9_HERE/../solana-proof-buffer-v1"
export CARGO_HOME="$ZK9_HERE/../solana-verifier-profile-v1/sbf-cargo-home"
if [ "$WHICH" = buffer ]; then ZK9_TOOLS="$ZK9_HERE"; export CARGO_HOME="$ZK9_HERE/cargo-home"; fi   # the buffer recipe keeps its cache and its tools inside its own directory
export CARGO_TARGET_DIR="$OUT/target"
export PATH="$ZK9_TOOLS/platform-tools-v1.52/rust/bin:/usr/bin:/bin:/usr/sbin:/sbin"
unset RUSTC RUSTDOC RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
cd "$ZK9_HERE"
<HOME>/.local/share/solana/install/releases/3.1.10/solana-release/bin/cargo-build-sbf \
 --manifest-path "$ZK9_HERE/$MAN" --tools-version v1.52 \
 --sbf-sdk "$ZK9_TOOLS/sbf-sdk" --skip-tools-install --no-rustup-override \
 --offline --sbf-out-dir "$OUT/sbf-out" -- --locked --lib > "$OUT/build.log" 2>&1
shasum -a 256 "$OUT/sbf-out/$NAME" "$PIN"
cmp "$OUT/sbf-out/$NAME" "$PIN" && echo "IDENTICAL to the pinned binary" || echo "DIFFERENT from the pinned binary"
