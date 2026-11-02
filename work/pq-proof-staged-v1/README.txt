ZK9 staged proof-format experiment

Frozen result: results/pq-proof-staged-v1. Development: work/pq-proof-staged-v1.
See PROTOCOL.txt for the trust boundary and REPORT.txt for measured results.
This is a format reader with authenticated progress, not a proof verifier.

Reproduction uses the existing sibling lab toolchains, original prover sources,
prior borrowed reader, caches, SDK and synthetic fixtures, all pinned in
environment.json. Copy this archive to a fresh sibling under zk9-chain/work to
rebuild. It is not a standalone portable installer. Do not replace frozen data.

Use the isolated Python, assertions enabled (never -O):
/private/tmp/zk9-gloas-complete-cold-install-20261014-1/backend/operator/runtime/zk9-chain/.toolchain/python/bin/zk9-python -E -s -B qualify.py

Native differential checks, twice with new output files:
./cargo-local.sh build --release --offline --locked --manifest-path harness/Cargo.toml --bins
./target/release/zk9-proof-staged-check ../../results/pq-private-send-keeper-v1/fixtures

Native parser timings, with other lab workloads stopped after compilation:
./target/release/bench ../../results/pq-private-send-keeper-v1/fixtures
30 samples/fixture, 3 warmups, rotating four variants: original allocating decoder,
prior borrowed Serde reader, new state machine, and state machine with checkpoint
serialization/reload after every 4096 operations. Input already in memory; OS
cache not flushed; original proof destruction outside timer. No allocator counter
during timings. These are not cryptographic or end-to-end payment measurements.

Solana build uses pinned Agave3.1.10/platform-tools-v1.52, cdylib-only and locked:
./build-sbf.sh -- --locked
The SDK's empty syscall list causes warnings, but local runtime loading is checked
byte for byte. Deprecated loader-module warning retained. Native rust-objcopy
stripping warning about missing libLLVM does not stop executable build/execution.

Full local runtime (requires loopback binding permission), two distinct labels:
/private/tmp/zk9-gloas-complete-cold-20261014-1/builds/legacy-wallet/tools/node-v22.11.0-darwin-arm64/bin/node runtime.mjs reproduction-01
Then test source upgrade authority rejection:
/private/tmp/zk9-gloas-complete-cold-20261014-1/builds/legacy-wallet/tools/node-v22.11.0-darwin-arm64/bin/node runtime.mjs reproduction-mutable mutable-source

Only localhost, public synthetic keys and funds. New validators and ledgers each
run. The full large source is correctly encoded and preloaded sealed in genesis;
this isolates staged processing and does not retest its full upload. Prior
results/solana-proof-buffer-v1 separately measured real chunk upload/seal. The
session is really created, advanced across signed transactions and closed. A
small replacement at the same source address is really uploaded and sealed to
test source closure/recreation. Program upgrade authority is explicitly revoked
with the loader and read back before normal scans. The negative mode retains it.
All validators stop and temporary ledgers are removed in finally blocks.

Each runtime output label refuses overwrite. Successful runtime JSON includes
per-step CU, requested budgets, transaction sizes and fees, failed compute probes,
signed transaction receipts, final serialized checkpoint and control checks.
Simulations reject attackers; successful steps are actual confirmed transactions.
Adaptive halving of operation limit on compute exhaustion is part of this client.
Do not claim that every request for the maximum limit fits a single transaction.

History: runtime-01 stopped at an immutability assertion because genesis ProgramData
still carried an authority. No safety check was removed; explicit revocation was
added. runtime-02 completes with an earlier checkpoint validator and its ELF is
retained. The final checks, counter hardening and source correspond to native
final-04/05, timing-02 and runtime-03/04/mutable-01. Older logs remain as evidence.
CURRENT.json, installed wallet and website are unchanged.
