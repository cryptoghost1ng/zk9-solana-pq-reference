# Reproducing

Run everything from the root of this snapshot. The `work/<directory>` layout is preserved from the original tree on purpose, so relative imports and Cargo path dependencies resolve without edits.

## 1. Relay-layer checks (Node 24 — tested with v24.22.1 —, no network, a few minutes)

```sh
export ZK9_WIRE_ARCHIVE="$PWD/work/solana-multiwallet-privacy-v1/evidence/privacy-live-02/public-capsule"
cd work/solana-relay-windowed-v1
node --test --test-timeout=300000 checks.mjs        # 40 checks: journal v2, funded repository, fee quote, windowed sender, task wiring
python3 mutation_control.py --verify-patterns        # confirms every one of the 79 mutated texts matches its source exactly once
```

The checks use real SQLite, real Ed25519 signing, the real transaction decoder, the real buffer-account layout and a model of the cluster (`harness.mjs`, see its header for what it does and does not model).
The checks need `node:sqlite`, which older Node releases only ship behind `--experimental-sqlite`. `python3 mutation_control.py mutation-NN` repeats the full mutation control (several minutes; it writes a new evidence directory and needs `work/solana-chrome-wallet-v1/offline_guard.py`).

The latest relay revision (account closing after a settled payment) is checked the same way; its `checks.mjs` is the 40-check suite above run unmodified, and `cleanup-checks.mjs` adds 20 checks:

```sh
cd work/solana-relay-cleanup-v1
node --test --test-timeout=300000 checks.mjs cleanup-checks.mjs   # 40 + 20 checks
python3 mutation_control.py --verify-patterns                      # confirms every one of the 29 mutated texts matches its source exactly once
```

## 2. Rust proof system (type-check, offline)

The three crates are `work/pq-private-send-v1`, `work/pq-private-withdraw-v2` and `work/pq-public-bind-liveness-v1`. Their dependencies are path dependencies inside this snapshot plus crates.io versions pinned by each `Cargo.lock`.

```sh
cd work/pq-private-send-v1 && cargo check --locked        # network needed once to fetch crates.io dependencies
```

Proving and verifying a payment natively takes tens of seconds and a few GB of RAM; see each crate's `README.txt` and `PROTOCOL.txt`.

## 3. What cannot be reproduced from this snapshot

The end-to-end run (`work/solana-onion-e2e-v1`) needs macOS arm64, Chrome 156 with the extension loaded through the DevTools protocol, a Solana test validator 3.1.10 with the compiled programs, a local Tor test network and the
author's native-host launcher. Its recorded result is `work/solana-onion-e2e-v1/evidence/full-05/RESULT.json`; its pinned inputs reference files that are not part of this snapshot.
The on-chain program binaries are not published here. The sources of the four programs and their build scripts are, and `PROGRAM-HASHES.json` lists the sha256 of the binaries the local validator loaded; the build toolchain
(platform-tools v1.52, Solana 3.1.10) is not part of this snapshot, so the correspondence between those sources and those hashes cannot be re-checked from here.
