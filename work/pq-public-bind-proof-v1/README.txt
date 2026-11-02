Native proof experiment for the preserved public-binding lifetime AIR.
Current status: implementation prepared; no completed proof run yet.

Original source/shape and SBF programs remain unchanged. Configuration differs
from PRIVATE-SEND/v2 ONLY in the domain string: v3-public-bind-lifetime. The
preflight enforces exact text equality apart from this domain. Parameters are
not weakened. This is not a new network wire format, wallet release or pool.

First run: sh run-smoke.sh smoke-01
The pinned local Rust/Cargo cache is used offline. Capture resolved inputs before
and after. The smoke generates baseline/candidate proofs with identical public
values, verifies and roundtrips both, tests cross-version rejection in both
directions and public/proof mutations. Each proof uses fresh OS entropy.
One timing sample per variant is exploratory, not a speedup conclusion.

Then run the `qualify NEW_DIRECTORY` command after reviewing the smoke: valid
one/two-input and u64-max cases; eleven actual malformed-trace proofs generated
by the release prover and rejected by the verifier. A host builder refusing an
invalid witness does not count as verifier rejection. The packets are fixed
placeholders, not actual encrypted-note demonstrations. All keys/funds synthetic.

The `baseline NEW_DIRECTORY` and `candidate NEW_DIRECTORY` commands generate one
matched benchmark sample. They separate initialization, trace generation, prove,
verify and serialization; wrapper/roundtrip validation runs outside verify time.
Use independent processes and sequential alternating order for a later series.
Raw postcard proof files are local evidence only; no network decoder is offered.
No SBF performance, audit or integral post-quantum security claim follows here.
