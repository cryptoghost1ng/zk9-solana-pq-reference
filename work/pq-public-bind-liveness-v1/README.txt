SOURCE DRAFT — not compiled, measured, tested or qualified.

Purpose: compare the existing payment AIR with public digest bindings enforced
at their fixed producer's final Keccak round. Free those six digest registers
after their last consumer. Keep context, balance and second-active bit stationary.
The first root is mandatory; the second root remains gated by a zero-amount-only
second input. Hash jobs, SHA3 domains, note semantics and schedule are unchanged.

This directory is isolated from the live same-runtime pool measurement.
BASELINE.json pins copied baseline files. Original files were not modified.
Do NOT compile, run profile or test while either full-01 or full-02 measurement
is active in ../solana-pq-integrated-pool-v1. Observe the actual process handles.

After both measurements finish and their evidence is checked:
Use `sh run-shape.sh shape-01` only after observing the repeat's terminal exit and
freezing the baseline. It verifies that frozen repeated result, uses the pinned
local Rust/cache offline, records source/tool inputs before and after, compares
two symbolic profiles and runs tests serially. It does not generate proofs.
The preflight refusal while the repeated result is absent was tested successfully
(evidence/preflight-refusal.json); only Python/shell syntax has been checked.
The Rust build/profile/constraint tests below remain unexecuted.

1. Verify baseline pins. Generate Cargo.lock offline with the pinned lab toolchain.
2. Build in release mode. Run `profile` and record symbolic width/count/degree.
3. Run tests serially: exact live owners, full valid traces, every public digest
   limb at its producer, zero-second-input semantics and stationary active flag.
4. Add adversarial schedule/ownership/amount and malicious witness checks; compare
   acceptance against the original relation. Existing tests alone are not a proof
   of equivalence or sufficient for adoption.
5. Only if promising, add a NEW circuit domain/config and new blinded native
   proofs, with original parameters and rejection tests. Then measure proof size,
   time and actual SBF verification costs in a separate versioned implementation.

No proving API/config, source envelope, verifier schedule or pool integration is
provided here. Do not feed this AIR to the old PRIVATE-SEND/v2 configuration or
accept new proofs in the existing pool. Delivery associated-data semantics remain
unchanged and are not proof of correct ciphertext plaintext. No claimed savings,
audit, public launch readiness or end-to-end post-quantum budget.
