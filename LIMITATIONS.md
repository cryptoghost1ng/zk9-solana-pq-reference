# Known limitations

Plain list of what this snapshot does not do or does not establish. If a sentence elsewhere seems to say otherwise, this file wins.

## Security and privacy

- **No independent review** of the cryptography, the Solana programs, the relay or the wallet. Tests written by the authors and AI-assisted reviews are not independent review.
- **The proof parameters are unreviewed.** About 96 bits with what is proven, up to about 192 only under a conjecture; a 128-bit target is not demonstrated ([CLAIMS.md](CLAIMS.md)).
- **Privacy is not demonstrated.** Test wallets use public fixture seeds; one operator runs the validator, the relay and the history service; Tor is a one-machine test network (`real_tor: false`).
  There is no anonymity-set analysis, no timing-correlation study and no adversarial rehearsal.
- **Part of the stack is classical** (Ed25519 deposits, sponsor fees and public withdrawals; Solana itself; Tor).
- **The on-chain programs are deployed as immutable.** A defect cannot be patched in place.

## Operation

- **Rent recovery exists only in the latest relay revision, and only for payments that settle.** After the pool has settled a payment, the relay closes the verifier receipt and the proof buffer it created for it,
  and their rent goes back to the sponsor. Measured on a local validator in one full run (`full-09`, 59 of 59 checks), summed from the validator's own ledger: the four accounts of the two payments were gone afterwards, each returned
  exactly what had been deposited in it (about 23.7 SOL held while the send was in flight, 31.9 SOL for the withdrawal), and the sponsor ended up out of pocket by 128,592,520 lamports (about 0.129 SOL) instead of the 55.7 SOL that stayed locked in `full-05`:
  59,605,000 in network fees and 68,987,520 in the pool's permanent per-payment records, to the lamport. One run on one machine.
  Not covered: a payment that ends `conflicted` keeps its accounts, and there is no tool yet to close them; closing happens at the `confirmed` commitment the relay already uses to reconcile settlement, not `finalized`;
  the relay's funding budget does not credit the rent back, so a long-lived relay needs its caps reset or raised by the operator; the relay treats an absent account as closed and does not itself check the amount refunded (the test driver does, from the ledger).
  A first version of this revision passed all its own checks and did nothing in the real payment (found by the live run `full-06`), and two later runs (`full-07`, `full-08`) closed the accounts but had accounting checks of mine that failed for understood reasons (their `NOTE.txt`); the history is in `work/solana-relay-cleanup-v1/DESIGN.md`.
- **These exact program binaries can only run on a validator that places them at fixed addresses.** The pool, the two verifiers and the proof buffer have each other's program ids compiled in, and those ids are SHA-256 hashes of fixed strings
  (`BUFFER_ID` in the two verifiers, `work/solana-beta-spend-v1/verifier/src/lib.rs` and `work/solana-beta-withdraw-v1/verifier/src/lib.rs`; `PROOF_PROGRAM` and `BUFFER_PROGRAM` in the two `receipt` crates the pool links). A test validator can start with programs at any
  address; on a public cluster a program can only be deployed at an address whose key you hold. A real deployment therefore needs a rebuild chain (the buffer first, then the verifiers with the buffer's real id, then the pool with all three), new binary hashes and a full requalification.
  The wallet, the relay and the native verifier also accept only a loopback RPC at version 3.1.10 (`local-network.mjs`), by design, so that nobody points this at real funds by mistake; a public devnet would need a reviewed generalisation of that guard.
  What deploying the four binaries as final costs was measured in a local rehearsal: about 83.8 SOL of permanent rent and about 11,900 transactions.
- **One payment at a time**, one sponsor, no rate limits, no quotas, no abuse policy.
- **The wallet locks itself after 5 minutes**; a sponsored payment takes about 20–25 minutes end to end, so the wallet must be unlocked again to see settlement (the relay does not need it to publish).
- **Chunk windows are untested on a real cluster.** The relay uploads up to 64 proof chunks per window. That was measured on a local single-node validator only; there is no data on real network
  admission, priority fees, per-account write limits, packet loss or provider rate limits.
- **Program versions.** The programs were built and tested against a local Solana test validator 3.1.10. A public-profile observation dated 2026-10-19 reported devnet on 4.4.0-beta.0 and mainnet on 4.3.0;
  compatibility with those was not tested.

## Distribution and platform

- Tested on macOS (arm64) with Chrome 156 in disposable profiles. The extension and its native-messaging host have **not** been installed in a normal browser profile; the host did not start from a path under
  `~/Documents` (permission error, mechanism not established). macOS signing/notarization and any store review were not evaluated.
- The end-to-end driver is tied to one machine's layout (`<HOME>` placeholders replace the author's home directory in this snapshot).

## Honesty about the evidence

- Timings come from one Mac, two observations for the upload measurements and one full end-to-end run for the windowed relay. They are not a benchmark.
- Provenance files in this snapshot record sha256 values of the original tree; those cannot be re-checked here except through `MANIFEST.json` (see [EXPORT-NOTES.md](EXPORT-NOTES.md)).
- One prediction made before measuring was wrong (the withdrawal trace width: predicted about 10,214 columns, measured 10,729). It is recorded in `work/solana-upload-pipeline-v1/width-probe/PREDICTION.txt`.
