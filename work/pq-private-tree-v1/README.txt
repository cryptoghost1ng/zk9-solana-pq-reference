ZK9 — Fixed depth32 private payment and sparse append-only note tree

This candidate extends pq-private-compact-v1. It is not installed in the node,
wallet or bridge. It retains the same note, owner, nullifier and SHA3 parent
formats and cryptographic parameters. A distinct transcript domain fixes depth32.
The verifier accepts only the resulting fixed trace degree; the prover cannot
choose a tree depth, root authority, security parameters or alternative circuit.

SparseTree stores only materialized nodes in a BTreeMap. Empty hashes are
computed once by level. An append hashes32ancestors and a membership path reads
32siblings; it never allocates2^32leaves. Logical capacity is4,294,967,296notes.
That capacity is not a measured throughput, anonymity set or production promise.
The current store is in memory. Persistence, rollback/crash handling, concurrent
writers, wallet history and encrypted recovery are not implemented in this step.

Append order uses u64 indices bounded by2^32; the witness also uses u64. All32
direction bits are constrained by the circuit. The empty leaf is zero; append
rejects that reserved value and refuses full capacity before mutation. Duplicate
commitments and double spends are rejected by Ledger. Initial leaves come from
the trusted synthetic fixture, never from a submitted proof. Ledger applies
to a cloned next state and replaces only after validation; cloning is not the
final persistent database design and will need improvement for large ledgers.

Tests cover a small dense reference after every append, an independent Python
recursive SHA3 implementation with eight depth32 root/path cases,10,000leaves
with fewer than20,100materialized nodes, full capacity using depth4, invalid
indices, reserved zeros and high path bits. The real payment test spends newly
created notes in two subsequent payments, reaching18leaves and6spentnullifiers.
Root/path equivalence is not an independent cryptographic audit of the AIR.

Build and test in this work directory, preserving frozen parent work directories:
sh cargo-local.sh build --locked --offline --release
sh cargo-local.sh test --locked --offline --release -- --test-threads=1
PYTHON -E -s -B run-one.py check evidence/NEW_CHECK
PYTHON -E -s -B run-one.py prove evidence/NEW_PROOF
PYTHON -E -s -B measure.py 30 NEW_SERIES
PYTHON -E -s -B generate-tree-vectors.py

Use the isolated zk9-python from the cold-installed operator runtime. Each output
must be new. cargo-local.sh selects the isolated Rust1.98.1 toolchain and pinned
Cargo.lock, without global changes. Local dependencies are not duplicated into
this result; it is an evidence snapshot, not a standalone source distribution.
generate-tree-vectors.py deterministically regenerates the independent fixture.

Profile command: target/release/zk9-private-tree-lab profile
baseline|tree EXISTING_PROOF NEW_OUTPUT_DIRECTORY. Baseline means the prior
compact depth4 circuit. It verifies with that circuit before profiling. These
CLI file readers are for trusted laboratory files; hostile decoding still needs
a bounded versioned network representation. No RPC limit is changed here.

The proof relation remains experimental, not a reviewed quantum security budget.
Transport, note encryption/discovery, persistent accounting, public operators,
external review and limits of bridges remain part of the overall launch goal.
