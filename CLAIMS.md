# What may be claimed about this work, and what may not

Written for readers who need to quote this project accurately. It is not an audit and not a statement of security.

## Supported by the code and by the local runs

- "An **experimental** private-payment layer whose validity proofs are hash-based STARKs (FRI), whose note delivery uses ML-KEM-1024 + AES-256-GCM, exercised end to end on a local
  validator running the real on-chain programs."
- "Settled on Solana, whose signatures, consensus and public addresses are classical (Ed25519)."
- "On a local validator, the relay returns to the sponsor the rent of the two temporary accounts it creates for each payment once the payment has settled." (not: on a public cluster)

## Not supported — do not say it

*quantum-proof*, *quantum-safe end to end*, *anonymous*, *private* (as a demonstrated property), *128-bit post-quantum security*, *audited*, *production-ready*,
*better or more secure than* any other project.

## Per-layer inventory (payment path exercised here)

| Layer | Mechanism | Status |
|---|---|---|
| Validity proof of a payment | Plonky3 FRI/STARK: BabyBear with a degree-8 extension, 512-bit Merkle commitments (MMCS over Keccak-f), SHA3-512 Fiat–Shamir challenges, 64 queries, rate 1/8, no grinding | Hash-based only. Exact security level **not established** (below) |
| Commitments, owner, nullifiers, note tree | SHA3-512 with domain separation | Hash-based |
| Encrypted note delivery | ML-KEM-1024 + HKDF-SHA512 + AES-256-GCM. The code itself says: **experimental**, no forward secrecy, no anonymity proof for the recipient | PQ primitives, experimental construction |
| Wallet keys | Spend key by HKDF-SHA512, ML-KEM-1024 receive key, both derived from the seed | PQ |
| Local vault | PBKDF2-SHA256 (600,000 iterations) + AES-256-GCM | Symmetric; real strength is the password |
| On-chain verification | SBF program verifying the proof in bounded stages | Cryptographically hash-based; depends on Solana's integrity |
| Public deposit, sponsor fees, public withdrawal | Ed25519 signatures of Solana | **Classical.** A quantum adversary could forge signatures of any public address |
| Base chain (consensus, accounts, SHA-256) | Solana | **Classical**, outside this project's control |
| Transport | Tor v3 (Ed25519/Curve25519) | **Classical** (general knowledge, not measured): recorded traffic could be decrypted later. Proofs end up public; who-and-when metadata does not |
| Relay and sponsor | Solana Ed25519 keys | Classical; they add no privacy by themselves |

Not reviewed in this snapshot: the ML-DSA transport/consensus work, the authority modules and the separate own-chain line that live elsewhere in the author's tree.
Post-quantum cryptography does not fix: anonymity-set size, correlation by amounts and timing, the address a relay sees without Tor, or the fact that public deposits reveal their opening.

## Proof parameters and the security arithmetic (the author's order of magnitude, not an analysis)

Configuration of the payment proofs: rate ρ = 1/8 (`log_blowup = 3`), 64 queries, no proof-of-work, field of about 2^248 (BabyBear^8).
With the standard per-query FRI error (about 1 − δ, δ being the distance up to which the guarantee holds):

| Regime assumed | δ | bits per query | with 64 queries | queries needed for 128 bits |
|---|---|---|---|---|
| Unique decoding | (1 − ρ)/2 = 0.4375 | 0.83 | ≈ 53 | ≈ 154 |
| Johnson bound (what is published as proven) | 1 − √ρ ≈ 0.646 | 1.5 | ≈ 96 | 86 |
| Capacity (conjecture) | 1 − ρ = 0.875 | 3 | ≈ 192 | 43 |

Reading: the configuration reaches about 192 bits **only if the capacity conjecture is accepted**; with what is proven it is around 96. Reaching 128 bits on proven bounds would take about 86 queries and
make the proof roughly 25 % larger. Ignored: minor FRI error terms (commit phase, DEEP, field size), the quantum random-oracle model for Fiat–Shamir, and the open discussion on the capacity conjecture.
**This is the most important security decision of the project and needs a cryptographer.**
