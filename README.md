# ZK9 — post-quantum private payments on Solana (research snapshot)

> **Status: experimental research snapshot. Not audited. Not for real funds. Privacy is not demonstrated.**
> Everything here ran on an isolated local Solana validator, with public test seeds, one operator and a local Tor test network.
> It has never run on devnet or mainnet, and nothing in this repository should be used to hold or move real value.

## What this is

A reference implementation, and a measurement record, of private token payments on Solana whose validity proofs are **hash-based STARKs** (FRI, no pairings, no trusted setup),
so that the proof layer does not rely on assumptions a quantum computer is known to break. The goal is to be a worked, reproducible, honestly-labelled example of what such a system
costs in proof size, transactions, compute and time — not a product.

The payment path in this snapshot: a browser wallet creates a proof locally, hands it over Tor to a *relay*, and a *sponsor* account owned by the relay uploads the proof to the chain in
900-byte chunks and verifies it on-chain in bounded stages; the pool then settles the payment. The wallet confirms the result from validated pool history, never from the relay's word.

## What is in this snapshot

| Path | What |
|---|---|
| `work/pq-private-send-v1`, `work/pq-private-withdraw-v2`, `work/pq-public-bind-liveness-v1` and their path dependencies | The Rust proof system for private send and withdrawal. Plonky3 (MIT OR Apache-2.0, pinned revision `f98331687e47…`) is vendored with its licences under `work/pq-pool-selection-v1/plonky3` |
| `work/solana-proof-buffer-v1` | Source of the on-chain proof-buffer program (chunked upload, seal, close), with its build notes |
| `work/solana-relay-windowed-v1`, `work/solana-private-relay-v1`, `work/solana-relay-performance-v1`, `work/solana-chrome-wallet-v1`, `work/solana-unified-wallet-v1` | The relay and wallet-side libraries: durable signed-attempt journal, funding limits, publication policy, sender. `solana-relay-windowed-v1` is the revision that uploads proof chunks in windows |
| `work/solana-relay-cleanup-v1`, `work/solana-onion-relay-service-v3` | The latest relay revision and its service: after the pool has settled a payment the relay closes the verifier receipt and the proof buffer it created, so their rent returns to the sponsor (`DESIGN.md` in the first directory) |
| `work/solana-onion-relay-service-v2`, `work/solana-onion-e2e-v1` | The previous relay service composition and the end-to-end drivers (needs macOS, Chrome 156, a Solana test validator and a Tor test network; **not runnable from this snapshot alone**) |
| `work/solana-beta-withdraw-v1/pool`, `work/solana-beta-spend-v1/verifier`, `work/solana-beta-withdraw-v1/verifier`, `work/solana-proof-buffer-v1` and their path dependencies, `PROGRAM-HASHES.json` | Sources of the four on-chain programs (settlement pool, send verifier, withdrawal verifier, proof buffer); sha256 of the four binaries the local validator loaded. The binaries and the build toolchain are not published |
| `work/solana-upload-pipeline-v1` | Measurement code and results: transaction anatomy of a payment, upload strategies, trace width and proof-size model |
| `evidence`-style files under each `work/*/evidence/*` | Result summaries (sha256-pinned inputs, verdicts). Raw network captures, browser profiles and logs are deliberately not published |
| `REVIEW.md` | Where each review question lives in the code, what exists to help, and what a reviewer is asked to send back |
| `.github/workflows/checks.yml` | Runs the relay-layer checks and the mutation-pattern tests on every push |
| `MANIFEST.json`, `EXPORT-REPORT.json` | sha256 of every file here, and a record of what was left out, patched and scanned |

## What has been verified, and where

- 40 model checks and 79 mutants of the windowed relay revision (every mutant is caught by a named check): `work/solana-relay-windowed-v1/evidence/checks-02`, `mutation-03`.
- 62 model checks (the 40 above, unmodified, plus 22 for account closing) and 36 further mutants of the cleanup revision: `work/solana-relay-cleanup-v1/evidence/checks-03`, `mutation-03`. The history of that revision, including a first generation that passed its checks and did nothing in the real payment, is in `work/solana-relay-cleanup-v1/DESIGN.md`.
- The same full payment with the relay closing its two temporary accounts after each settlement and returning their rent to the sponsor: `work/solana-onion-e2e-v1/evidence/full-09/RESULT.json` (59/59 checks). Summed from the validator's own ledger, each of the four accounts returned exactly what had been deposited in it, and the sponsor was out of pocket by about 0.129 SOL (59,605,000 lamports of fees and 68,987,520 of the pool's permanent records) instead of about 55.7 SOL. The attempts before it are kept: `full-06` found a defect in the first version of the cleanup, and `full-07` and `full-08` closed the accounts but their accounting checks (mine) failed (each run's `NOTE.txt`).
- A full local private send of 10 and public withdrawal of 1 through the relay behind a local Tor test network, in disposable Chrome profiles, with the relay killed once per payment
  and resumed: `work/solana-onion-e2e-v1/evidence/full-05/RESULT.json` (50/50 checks) and `smoke-07`. Summary: `work/solana-relay-windowed-v1/evidence/windowed-qualification-01`.
- Measurements of proof size, transaction counts, compute and time: [MEASUREMENTS.md](MEASUREMENTS.md).

## What has NOT been verified

No independent security review. No review of the cryptographic parameters (see [CLAIMS.md](CLAIMS.md): the proven security level of the configured FRI parameters is about 96 bits, not 128).
No public network, no independent operators, no real Tor (a one-machine test network only), no real funds. Behaviour of the chunk windows on a real cluster is untested. Privacy is not demonstrated in any sense.
The full list is in [LIMITATIONS.md](LIMITATIONS.md).

## Reproducing what can be reproduced

See [REPRODUCE.md](REPRODUCE.md). The relay-layer checks run with Node and the files in this snapshot; the Rust crates can be type-checked offline against their `Cargo.lock`.

## Licence

Apache-2.0 ([LICENSE](LICENSE)). Third-party notices: [NOTICE](NOTICE). Security reports: [SECURITY.md](SECURITY.md). What would have to be true before any use with real value: [ROADMAP.md](ROADMAP.md).
