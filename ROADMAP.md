# What would have to be true before this is used with real value

This is not a launch plan. It is the list of gates between this research snapshot and any use with real funds, in the order they would have to be closed. Each gate says who can close it.

| # | Gate | Today | Who |
|---|---|---|---|
| 1 | **Independent cryptographic review of the proof parameters** (64 queries, rate 1/8: ≈96 bits proven, up to ≈192 only under a conjecture; a 128-bit target is not demonstrated) and a decision on the scope of "post-quantum" (Ed25519 signatures and authorities are classical) | Not done; nothing sent to a reviewer | An external cryptographer |
| 2 | **Independent security review** of the on-chain programs (deployed immutable), the relay and the wallet | Not done | External reviewers |
| 3 | **Rent recovery**: the relay closes the proof-buffer and receipt accounts after settlement | Shown on a local validator in one full run (`full-09`, 59/59: the real programs accept the closes, every account returns exactly what was deposited, the sponsor ends about 0.129 SOL out of pocket instead of 55.7). Open: payments that end `conflicted`, `finalized` instead of `confirmed`, crediting the funding budget, an independent look, a second clean run | Implementation + qualification (done locally) |
| 4 | **A real cluster**: behaviour of the 64-chunk windows, compute limits, priority fees, per-account write limits and the programs' compatibility with the cluster's validator version, first on devnet | Never run outside an isolated local validator | Implementation; deploying immutable programs to a public network is a one-way step |
| 5 | **A real operator model**: a real onion service instead of a one-machine Tor test network, more than one operator, rate limits, quotas, an abuse policy, monitoring and an incident plan (the programs are immutable: the off-switch is the relay and the wallet) | One operator, one payment at a time | Operators |
| 6 | **Wallet distribution**: install in a normal browser profile, native-host registration outside protected folders, signing/notarization, store review | Only disposable Chrome 156 profiles on macOS arm64 | Maintainer |
| 7 | **Privacy evaluation**: anonymity-set size, amount and timing correlation, a pre-registered adversarial rehearsal, external review of the result | Not done; privacy is not demonstrated | Researchers |
| 8 | **Legal review** of operating a relay that pays for and publishes privacy-preserving transactions | Not done | A lawyer |

Steps that carry no value at risk — publishing this snapshot, measurements and documentation — need none of the gates above beyond honest labelling ([CLAIMS.md](CLAIMS.md), [LIMITATIONS.md](LIMITATIONS.md)).
A public devnet beta (no value) needs gates 4–6. Anything with value needs all of them.
