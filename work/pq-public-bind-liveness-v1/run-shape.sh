#!/bin/sh
# Observe the measurement process's terminal exit before invoking this script.
# This performs native shape/constraint checks only, never proof generation.
set -eu
ZK9_HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ZK9_PY=/private/tmp/zk9-gloas-complete-cold-install-20261014-1/backend/operator/runtime/zk9-chain/.toolchain/python/bin/zk9-python
cd "$ZK9_HERE"
test "$#" -eq 1
ZK9_RUN=$1
case "$ZK9_RUN" in shape-[0-9][0-9]) ;; *) exit 2 ;; esac
"$ZK9_PY" -E -s -B preflight.py > /dev/null
mkdir "evidence/$ZK9_RUN"
"$ZK9_PY" -E -s -B preflight.py > "evidence/$ZK9_RUN/baseline.json"
if test ! -f Cargo.lock; then
    sh cargo-local.sh generate-lockfile --offline > "evidence/$ZK9_RUN/lock.stdout" 2> "evidence/$ZK9_RUN/lock.stderr"
fi
sh cargo-local.sh metadata --offline --locked --format-version 1 > "evidence/$ZK9_RUN/metadata.json"
"$ZK9_PY" -E -s -B capture.py "$ZK9_RUN" before
sh cargo-local.sh build --release --offline --locked > "evidence/$ZK9_RUN/build.stdout" 2> "evidence/$ZK9_RUN/build.stderr"
target/release/zk9-public-bind-liveness-lab profile > "evidence/$ZK9_RUN/profile-01.json"
target/release/zk9-public-bind-liveness-lab profile > "evidence/$ZK9_RUN/profile-02.json"
sh cargo-local.sh test --release --offline --locked -- --test-threads=1 > "evidence/$ZK9_RUN/tests.stdout" 2> "evidence/$ZK9_RUN/tests.stderr"
"$ZK9_PY" -E -s -B capture.py "$ZK9_RUN" after
"$ZK9_PY" -E -s -B check-shape.py "$ZK9_RUN"
