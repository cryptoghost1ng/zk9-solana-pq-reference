ZK9 — Compact register experiment, not an installed private pool

Inherits the exact note/owner/nullifier/Merkle relation and fixed depth4 from
pq-private-relation-v1. No security parameters reduced, no classical wrapper,
no changed hashes. A new transcript domain distinguishes this circuit version.

Layout::new determines logical bit lifetimes from all graph inputs and outputs.
Balance bits, context, roots, public nullifiers and outputs remain live through
padding. Other bits occupy a shared column only after the previous bit's LAST
consumer. Variables used within the same permutation never alias. The one-hot
schedule is fixed by first-row and transition constraints. A physical register
may change only at a final round whose fixed boundary changes its logical owner.
Every other transition enforces equality. Every physical bit remains boolean.

SHA3 capacity1024bits has no message XOR. We retain its64limbs and constrain
initial zero/reset/preservation directly to upstream KeccakAir's output limbs,
whose ranges follow from its boolean round constraints. This removes2048
redundant input/output boolean columns while keeping every capacity limb.
Only576ratebits need the additional XOR representation. Upstream unchanged.

Reproduce in this work directory, with the same local parent sources/toolchain:
sh cargo-local.sh build --locked --offline --release
sh cargo-local.sh test --locked --offline --release -- --test-threads=1
PYTHON -E -s -B run-one.py check evidence/NEW_CHECK
PYTHON -E -s -B run-one.py prove evidence/NEW_PROOF
PYTHON -E -s -B measure.py 30 NEW_SERIES
Each output must be new. PYTHON is the isolated zk9-python interpreter already
installed by the cold-build experiment. No global shell/toolchain changes.

Profile a trusted laboratory proof with the binary's
profile baseline|compact EXISTING_PROOF NEW_OUTPUT_DIRECTORY
command. It verifies under the appropriate circuit before writing size data.
The profiler/CLI reads local trusted lab fixtures; it is NOT an untrusted RPC
decoder. Fixed encodings and bounded hostile decoding remain integration work.
The baseline dependency is used only to verify old proofs in this analysis CLI.

All model fixtures are synthetic. Proof masks use fresh OS entropy. Timings
separate layout, trace, initialization, proving and verifying. Proof serialization
and additional roundtrip verification occur outside reported verify_ms. RSS is
the highwater of exactly one native child per fresh Python measurement process.

No protection against quantum attacks is certified by passing these tests.
The end-to-end FRI/hiding/transcript budget, hostile input limits, real tree
capacity, persistent state, encrypted note discovery, recovery and independent
operators remain requirements before public use with funds. No product adoption,
network deployment, sale, personal wallet access or secret exports occur here.
