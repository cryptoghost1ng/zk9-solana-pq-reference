PREPARED SOURCE ONLY. Missing generated/seed.bin is intentional. No build/test.

Candidate portable Fiat-Shamir prefix for v3-public-bind-lifetime, width7525.
wire magic/version3 and prefix magicZK9PFX3 are separate from old v2profile.
The generic format scanner and SHA3-512 challenger implementation are reused
unchanged. The seed MUST come from candidate native StarkShape output after
pq-public-bind-wire-v1 passes twice. Never copy or edit v2seed.bin by hand.

Harness compares the candidate portable prefix to the native v3 oracle, alpha,
zeta,64continuation scalars, publicfields, quotient/random/traceopening views and
zero-allocation operation. It retains original challenger streaming/conversion
checks, malformed context/framing/shape cases and ciphertext transcriptbinding.
One synthetic two-input fixture is currently included; do not describe this as
sixfixtures or completed PCS/AIR/fullproof verification on Solana.

Before use: finish benchmark, compile/qualify native v3transport with captured
sources and dependencies, freeze it, then run prepare.py (laboratory Python with
-E -s -B) to pin/copy its derived seed into generated/seed.bin. Then run:
  sh run.sh prefix-01
  sh run.sh prefix-02
  laboratory-Python -E -s -B check.py prefix-01 prefix-02
  laboratory-Python -E -s -B freeze.py
The prepared runner captures dependencies/lock/compiler/source before and after,
builds the harness offline in release, records the binary and terminal exit code.
Freeze requires both successful runs and preserves originals under results.
No Rust build, generated seed, actual comparison or frozen artifact exists yet.
SOURCE-ORIGIN.json records copied upstream files. All new sources are uncompiled.
The original proof/shape/transport sources and deployed release stay unchanged.
