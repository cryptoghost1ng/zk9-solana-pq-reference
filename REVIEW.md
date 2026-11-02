# Review guide — ZK9 (Solana, hash-based private payments)

For someone outside the project who wants to scope, quote or perform a review without a call. Nothing in it is an audit result: every statement about security below is either a measurement of this system or an open question for you.

## 1. What is being reviewed

An experimental private-payment layer on Solana whose validity proofs are **hash-based STARKs (Plonky3 FRI)**, so the proof layer does not depend on pairings or a trusted setup.
A browser wallet builds a proof locally, hands it over Tor to a **relay**; a **sponsor** account owned by the relay uploads the proof to chain in 900-byte chunks (a **buffer** program),
verifies it in bounded stages (a **verifier** program that keeps a **receipt** account), and a **pool** program settles the payment (note commitments, nullifiers, a token vault).
The wallet confirms from validated pool history, never from the relay's word. Deposits and public withdrawals are ordinary Ed25519 Solana transactions; note delivery uses ML-KEM-1024 + AES-256-GCM.

Everything has run on an isolated local validator only: public fixture seeds, one operator, a one-machine Tor test network. It has never run on devnet or mainnet. **Privacy is not demonstrated and not claimed.**

## 2. Two reviews, possibly two different people

### A. Cryptography (the decision that matters most)

| Question | Where | Author's current position |
|---|---|---|
| Is the configured FRI soundness enough, and how should it be stated? `log_blowup=3` (rate 1/8), `num_queries=64`, no grinding, BabyBear^8 (≈2^248), 512-bit MMCS over Keccak-f, SHA3-512 challenges | `work/pq-private-send-v1/src/config.rs:40`, same lines in `pq-private-withdraw-v2`, `pq-private-relation-v1`, `pq-pool-component-v1/src/lib.rs:47` | ≈96 bits with the Johnson bound, ≈192 only if the capacity conjecture is accepted; target 128. Reaching 128 on proven bounds ≈ 86 queries, proof ≈ +25 %. Arithmetic in `CLAIMS.md`; **not reviewed by anyone** |
| Is the Fiat–Shamir transcript bound to everything it must be (public values, program/genesis/asset context, domain separation between send and withdraw)? | the two `config.rs` files and the relation crates | believed yes; the wire carries a 108-byte context read by the verifier (`wire_context` in `work/solana-beta-spend-v1/verifier/src/lib.rs`) |
| Soundness and completeness of the two AIRs (private send: 2 inputs → 2 outputs; withdrawal): value conservation, nullifier derivation and uniqueness, Merkle membership, owner binding, range of amounts | `work/pq-private-relation-v1`, `pq-private-send-v1`, `pq-private-withdraw-v2` (path dependencies listed in `rust-closure.json`) | tested by the authors only; no external constraint review |
| Note delivery: ML-KEM-1024 + HKDF-SHA512 + AES-256-GCM | `work/pq-note-delivery-v1` | the code itself says experimental: **no forward secrecy, no anonymity proof for the recipient** |
| What may honestly be called "post-quantum" here? Ed25519 deposits/fees/withdrawals, Solana itself and Tor are classical | `CLAIMS.md` | the author proposes: "hash-based proofs and ML-KEM note delivery, settled on a classical chain"; not "quantum-safe" |
| A measurement-based mistake to keep in mind | `work/solana-upload-pipeline-v1/width-probe/PREDICTION.txt` | one prediction (withdrawal trace width) was wrong: 10,214 predicted, 10,729 measured |

### B. Solana programs, relay and wallet (security engineering)

| Question | Where |
|---|---|
| **The programs are meant to be deployed immutable**: a defect cannot be patched. Account validation, ownership and signer checks, PDA derivation, arithmetic, rent, resize/assign on close, CPI to Token-2022 (`transfer_checked`, mint/account checks) | four programs: settlement pool `work/solana-beta-withdraw-v1/pool` (builds `zk9_solana_beta_settlement.so`); send verifier `work/solana-beta-spend-v1/verifier`; withdrawal verifier `work/solana-beta-withdraw-v1/verifier`; proof buffer `work/solana-proof-buffer-v1/src/lib.rs`. Their path dependencies are the proof-system crates in section 2.A plus `pq-proof-staged-v1`, `pq-public-bind-*`, `solana-pq-tree-v1` and the receipt crates |
| Staged verification: can a stage be replayed, skipped, reordered or run against a different buffer? Compute-unit bounds per stage (≤1.4 M CU, stages use 48–87 %), griefing (anyone can create a buffer or a receipt?) | each verifier's `process()` (five accounts: receipt, proof buffer, authority and the buffer program with its program data): input byte 0 selects *init* (0), *close* (2) or one of the verification stages; the receipt carries `MAGIC`, the recorded authority and the source binding |
| Close semantics (rent recovery): buffer opcode 3 and verifier opcode 2 return lamports only to the recorded writable-signer authority | same files; review note `work/solana-rent-recovery-review-v1/REPORT.txt` |
| Relay: durable signed-attempt journal (a transaction is stored before it is sent), funding limits (per request and total), idempotent admission, a malicious wallet or a malicious proof (the relay verifies a proof natively before spending any SOL), restart behaviour, what a malicious submitter can make the sponsor pay for | `work/solana-relay-windowed-v1`, `work/solana-relay-cleanup-v1`, `work/solana-private-relay-v1`, `work/solana-onion-relay-service-v3/serve.mjs` |
| Wallet: key derivation, local vault (PBKDF2-SHA256 600k + AES-GCM), the native-messaging host and the extension's permissions, the 5-minute auto-lock | `work/solana-chrome-wallet-v1`, `work/solana-unified-wallet-v1`, `work/solana-native-launcher-v1` |

## 3. What exists to help you

- This repository (with `MANIFEST.json`, sha256 of every file): sources, 62 relay-layer checks (Node 24, no network), 115 mutants and their verdicts, result summaries of the local end-to-end runs, `CLAIMS.md`, `LIMITATIONS.md`, `MEASUREMENTS.md`, `REPRODUCE.md`.
- The Rust crates type-check offline against their `Cargo.lock` (`cargo check --locked --offline`). The Solana programs' build toolchain (platform-tools v1.52, Solana 3.1.10) is **not** in the snapshot, so "this source builds to this binary" is **not** something the snapshot lets you verify; the binaries were built by the author on one Mac. Ask for the build recipe (`build-sbf.sh`, `build-verifier.sh`) and the pinned ELF hashes if you want that checked.
- The pool, the two verifiers and the proof buffer have each other's program ids compiled in, as SHA-256 hashes of fixed strings (`BUFFER_ID` in the verifiers; `PROOF_PROGRAM` and `BUFFER_PROGRAM` in the `receipt` crates the pool links), so these exact binaries run only on a validator that places them at fixed addresses; a real deployment needs a rebuild chain and a requalification (`LIMITATIONS.md`). Whether to keep identities compiled in at all is a fair question for a reviewer.
- The wallet, relay and native verifier accept only a loopback RPC at version 3.1.10, on purpose (`local-network.mjs`).
- Known facts you should not have to rediscover: proof ≈ 2.97 MB (send v3) / ≈ 4.0 MB (withdrawal v2); a sponsored payment is ≈ 5,100 (send) / 6,800 (withdrawal) transactions; verifier compute ≈ 1.6–2.0 G CU in ≈ 1,800–2,300 stages.

## 4. Out of scope

Plonky3 itself (a pinned upstream revision, vendored with its licences), Solana's runtime, Tor, Chrome, ML-KEM implementation correctness in the library used, anything on a real network, legal matters, economic design.

## 5. What the author would like back

1. A written statement of the security level the configured parameters actually give, in a form that can be quoted, and the cheapest change that reaches 128 bits on proven bounds.
2. A list of findings with severity for each program, and an explicit view on whether the programs should be deployed immutable at all (an upgrade authority has its own risks).
3. Whether the wallet/relay split (relay sees the proof and the timing, never the keys) leaks more than the author thinks; the author makes **no** privacy claim and wants to know which claims could ever be made.
4. A go/no-go for "public devnet beta with no value" and, separately, for anything with value.

## 6. Logistics

- Findings that are not vulnerabilities: open a GitHub issue. Vulnerabilities: private vulnerability reporting on this repository (see `SECURITY.md`).
- Please identify the bytes you reviewed by the commit hash and `MANIFEST.json`, so that findings pin to exact files.
- Licence: Apache-2.0; third-party notices in `NOTICE`.
- Budget, timeline and who pays are the author's decisions and are not part of this guide. A reviewer who wants a smaller first engagement can start with section 2.A row 1 alone (the FRI parameters), which is independent of everything else.
