PREPARED SOURCE ONLY. No Rust compilation or behavioral tests yet; wait for benchmark32183.

This separate native crate prepares a versioned transport for the qualified
public-bind circuit. ZK9PQS3/version3 cannot be sent to the existing v2 programs.
Reuses bounded/canonical decoder unchanged, reuses payment/ciphertext digest
binding and candidate proof verifier, adds explicit fixed-profile shape checks.
Source origins recorded. Existing measured sources remain untouched.

After the benchmark ends: sh run.sh transport-01, then transport-02. The runner
refuses before successful benchmark completion, verifies the frozen proof parent,
generates an offline Cargo.lock if absent, captures sources/compiler/features,
builds --release --offline --locked, then uses the qualified fixture directory
../../results/pq-public-bind-proof-v1/evidence/qualify-02 and a new output path.
It checks source equality before/after and the recorded binary hash.
Finally use laboratory Python with -E -s -B: check.py transport-01 transport-02.
Every label must be fresh; failed evidence is retained. No test run started yet.
The harness consumes qualified local fixture proof bytes and compares their
recorded public values/hash. Actual network decode goes through bounded parsing.
It also derives the candidate shape seed using the pinned native StarkShape,
and records native alpha/zeta/continuation values for a later portable comparison.
profile.rs reuses the original oracle with only its module binding changed;
preflight enforces the exact source transformation. No new seed has been generated
yet: these outputs will exist only after the harness successfully runs.
It verifies v3 and the original v2 positive control, tests framing/truncation/context/duplicate-note/ciphertext/public
mutations, and rejects cross-version header/proof relabelling. Test twice.

Remaining Solana port is explicit: generate the new shape seed with native
StarkShape; update transcript domain and width; compile the actual candidate AIR
schedule; version/rebuild all transitively profile-dependent verifier crates;
update session/receipt binding; measure full zero-session verification and pool.
Do not just replace width in one crate or reuse v2 seed.bin/schedule.bin.
Source fees remain signed statement data; this transport is not a pool fee policy.
Fixture packets are fixed bytes, not a demonstration of encryption or recovery.
No public deployment, network acceptance, deposit/withdrawal or production claim.
