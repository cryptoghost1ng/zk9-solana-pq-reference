#!/bin/sh
set -eu
ZK9_HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ZK9_PY=/private/tmp/zk9-gloas-complete-cold-install-20261014-1/backend/operator/runtime/zk9-chain/.toolchain/python/bin/zk9-python
cd "$ZK9_HERE"
test "$#" -eq 1
ZK9_LABEL=$1
case "$ZK9_LABEL" in qualify-[0-9][0-9]) ;; *) exit 2 ;; esac
"$ZK9_PY" -E -s -B check-smoke.py smoke-02 > /dev/null
test ! -e "evidence/$ZK9_LABEL"
mkdir "evidence/$ZK9_LABEL-run"
"$ZK9_PY" -E -s -B preflight.py > "evidence/$ZK9_LABEL-run/baseline.json"
sh cargo-local.sh metadata --offline --locked --format-version 1 > "evidence/$ZK9_LABEL-run/metadata.json"
"$ZK9_PY" -E -s -B capture.py "$ZK9_LABEL-run" before
sh cargo-local.sh build --release --offline --locked > "evidence/$ZK9_LABEL-run/build.stdout" 2> "evidence/$ZK9_LABEL-run/build.stderr"
"$ZK9_PY" -E -s -B record-binary.py "$ZK9_LABEL-run"
target/release/zk9-public-bind-proof-lab qualify "evidence/$ZK9_LABEL" > "evidence/$ZK9_LABEL-run/run.stdout" 2> "evidence/$ZK9_LABEL-run/run.stderr"
"$ZK9_PY" -E -s -B capture.py "$ZK9_LABEL-run" after
"$ZK9_PY" -E -s -B check-qualification-v2.py "$ZK9_LABEL"
