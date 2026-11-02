# Measurements

Local, synthetic, one Apple M1 Max, a Solana test validator 3.1.10 with the real programs. These are measurements of a research system, not benchmarks and not a statement about any public network.
Source material: `work/solana-upload-pipeline-v1` (design note, scripts, results) and `work/solana-relay-windowed-v1/DESIGN.md`.

## Proof size and trace width

Proof size follows the width of the execution trace almost linearly: **bytes ≈ 321.11 × columns + 552,374**. The slope has a reason: 256 B of opened rows (64 queries × 4 B) plus 64 B of
out-of-domain openings. Fitted only on the two send proofs and then tested on the withdrawal proofs (not used in the fit), it predicts them to +0.30 % and −0.12 %.

| Relation | Columns | Proof | Note |
|---|---|---|---|
| Send, version 2 | 10,406 | 3,893,829 B | |
| Send, version 3 (current) | 7,525 | 2,968,715 B | −27.7 % columns, −23.8 % proof, native proving −11.8 % |
| Withdrawal, version 2 | 10,729 | 3,985,621 – 4,002,466 B | version 3's public-binding change was not applied to it; the model suggests ≈3.07 MB if it could be (hypothesis) |

## Anatomy of a sponsored payment (four archived payments, local)

| | Send (wire ≈ 2.97 MB) | Withdrawal (wire ≈ 4.0 MB) |
|---|---|---|
| Sponsor transactions | 5,117–5,123 | 6,767–6,798 |
| Proof upload (900-byte chunks, 7,689 CU each) | 3,302 | ≈4,440 |
| Bounded verifier stages | 1,812 | ≈2,335 |
| Verifier compute | 1.58 G CU (62 % of the 1.4 M CU per-transaction cap) | 1.99 G CU (61 %) |
| Rent deposited (buffer + receipt) | ≈23.7 SOL | ≈31.7 SOL |
| Network fees | ≈0.026 SOL | ≈0.034 SOL |

Each transaction takes ≈0.54 s when confirmed one at a time (confirmation wait, not compute). Merkle openings are ≈33–36 % of the verifier's compute, the AIR ≈25–29 %.
The verifier is compute-bound; because the sender asks for maximum work, simulates and halves on overflow, stages use only 48–87 % of the cap.

## Uploading the proof one chunk at a time vs in windows

Upload of the 3,302 chunks of a send proof to the real buffer program (two observations, reproducible to 1.5 %; every case checked the stored bytes against the archived wire):

| Strategy | Whole upload |
|---|---|
| One chunk, confirmed before the next (what the relay did) | ≈1,600–1,790 s |
| Window of 8 | ≈221 s |
| Window of 32 | ≈56 s |
| Window of 128 | ≈13.7 s |

## The windowed relay, end to end (`full-04` vs `full-05`)

Same flow and same checks; only the relay differs. Local, one run each.

| | One chunk at a time (`full-04`) | Window of 64 (`full-05`) |
|---|---|---|
| Send: relay, admitted → settled | 2,719 s · 15,947 relay steps | **1,010 s** · 5,972 steps |
| Withdrawal: relay | 3,513 s · 19,300 steps | **1,344 s** · 7,368 steps |
| Proof upload, send | ≈1,790 s | 35–57 s (with a SIGKILL of the relay inside it) |
| Proof upload, withdrawal | ≈2,400 s | 70–90 s |
| Verifier stages (serial, unchanged) | ≈16 min · ≈21 min | ≈16 min · ≈21 min |
| Wallet auto-locks during the two legs | 9 and 11 | 3 and 4 |

The relay was killed with SIGKILL once per payment, mid-upload, and reopened the same stored request. 40 model checks and 79 mutants back the windowed journal
(`work/solana-relay-windowed-v1`). Window safety rules: nothing leaves before its durable commit; a restart releases exactly the stored bytes; an expiry needs a missing signature in two lookups **and** a block
height past the blockhash lifetime; a chunk is confirmed only when its effect is visible in the buffer; a chunk that lands with an error stops the step.

## Rent recovery (`full-09`)

Same flow and same checks as `full-05`; the relay now closes its two accounts after each settled payment. Local, one full run (59 of 59 checks) with the validator keeping its whole ledger; every number below is summed from the sponsor's own transactions on that ledger.

| | Send | Withdrawal |
|---|---|---|
| Rent held by the verifier receipt + proof buffer, and returned by the two closes (lamports) | 2,288,865,600 + 21,402,716,880 = 23,691,582,480 | 2,931,106,560 + 28,943,967,360 = 31,875,073,920 |
| Deposit minus refund, per account | 0 and 0 | 0 and 0 |
| From the first close to the relay's `finished` | 1.2 s | 1.05 s |
| Permanent pool records paid at settlement (nullifiers, notes, root, withdrawal record; not recoverable) | 33,352,320 | 35,635,200 |

Sponsor out of pocket for the whole payment: **128,592,520 lamports** (about 0.129 SOL) = 59,605,000 in fees (11,913 transactions at 5,000 and 4 account-creating ones at 10,000) + 68,987,520 in the pool's permanent records
(computed from the program source before the run and matched to the lamport). `full-05`, without the cleanup: 55,721,596,840 lamports.

## Not measured

Real clusters, real Tor, mainnet cost, multiple concurrent payments, hardware other than one Mac, or any property of privacy.
