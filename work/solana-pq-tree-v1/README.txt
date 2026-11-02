ZK9 — exact native note tree for local Solana pool integration

Fixed32-level SHA3-512 tree, existing ZK9MRK01 domain and u32LE level encoding.
An even number of leaves is required. The two-output payment relation appends a
pair using32parent hashes, sharing their path; two individual appends need64.
No hash function, tree depth, leaf meaning or proof parameter was weakened.
The authenticated serialized frontier uses2128bytes; probeauthority adds32bytes.
Unused frontier slots are zero. Count comparison prevents a stale append from
overwriting newer state. Hashing itself has no fallible step after validation.

This library is only for trusted program-owned state. It does NOT authenticate
proofs or old roots, check global nullifiers/duplicate commitments, settle fees,
or create a spend authorization. The probe accepts arbitrary outputs for testing.
Production pool code must supply outputs from the completed-proof callback and
atomically write note/nullifier/root records, ciphertext packets and settlement.

Native tests compare the original sparse tree and an independent Python hashlib
fixture,1024pairs, all serialized frontier bytes for genesis and3payments, stale
counts, invalid outputs and the final capacity edge. Capacity-edge state is
synthetic and does not claim to allocate2^32leaves. Solana runs use an actual
new SystemProgram-created account,6genesis pairs plus3payment output pairs, and
confirm rollback after deliberately failing following a full tree write.

Reproduction (isolated toolchains/cache; offline; run one benchmark at a time):
  laboratory-python -E -s -B prepare.py
  sh cargo-local.sh test --release --offline --locked -- --test-threads=1
  sh build-sbf.sh -- --locked
  laboratory-node runtime.mjs UNIQUE_LABEL
Pinned evidence labels tree-01/tree-02 are checked by qualify.py. Preserve prior
evidence, do not overwrite it. No global shell/toolchain changes, no public RPC.

SBF32KiB heap; build logs checked for stack warnings. The SDK syscall-list warning
is retained; real runtime execution passed. No claim of whole-system security.
