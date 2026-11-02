#!/bin/sh
set -eu
ZK9_HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ZK9_HERE"
test "$#" -eq 1
case "$1" in prefix-[0-9][0-9]) ;; *) exit 2 ;; esac
ZK9_LABEL=$1
ZK9_PY=/private/tmp/zk9-gloas-complete-cold-install-20261014-1/backend/operator/runtime/zk9-chain/.toolchain/python/bin/zk9-python
"$ZK9_PY" -E -s -B preflight.py > /dev/null
test ! -e "evidence/$ZK9_LABEL"
mkdir -p "evidence/$ZK9_LABEL"
trap 'ZK9_EXIT=$?; printf "%s\n" "$ZK9_EXIT" > "evidence/$ZK9_LABEL/driver.exit-code"' 0
"$ZK9_PY" -E -s -B preflight.py > "evidence/$ZK9_LABEL/parent.json"
if test ! -f harness/Cargo.lock; then
    sh cargo-local.sh generate-lockfile --offline > "evidence/$ZK9_LABEL/lock.stdout" 2> "evidence/$ZK9_LABEL/lock.stderr"
fi
sh cargo-local.sh metadata --offline --locked --format-version 1 > "evidence/$ZK9_LABEL/metadata.json"
"$ZK9_PY" -E -s -B capture.py "$ZK9_LABEL" before
sh cargo-local.sh build --release --offline --locked > "evidence/$ZK9_LABEL/build.stdout" 2> "evidence/$ZK9_LABEL/build.stderr"
"$ZK9_PY" -E -s -B capture.py "$ZK9_LABEL" binary
target/release/zk9-public-bind-prefix-check ../../results/pq-public-bind-wire-v1/evidence/transport-01/output "evidence/$ZK9_LABEL/output" > "evidence/$ZK9_LABEL/run.stdout" 2> "evidence/$ZK9_LABEL/run.stderr"
"$ZK9_PY" -E -s -B capture.py "$ZK9_LABEL" after
"$ZK9_PY" -E -s -B check.py "$ZK9_LABEL"
