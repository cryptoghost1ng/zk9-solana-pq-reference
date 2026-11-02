ZK9 — Solana proof buffer laboratory, v1

Scope: a compiled sBPF byte transport experiment on an isolated local Agave
validator. No token, pool, bridge, Solana proof verifier or public deployment.
Read REPORT.txt and PROTOCOL.txt before interpreting SEALED_BYTES_ONLY.

Requirements for reproduction on this existing Mac/workspace:
- Node v22.11.0 (no npm modules). Tested executable:
  /private/tmp/zk9-gloas-complete-cold-20261014-1/builds/legacy-wallet/tools/node-v22.11.0-darwin-arm64/bin/node
- Existing pinned Agave 3.1.10 installation at the path in environment.json.
- Public native fixture at the absolute BASE.json path, with matching SHA256.
  This is a workspace-dependent reproducer; it is not a portable installer.
- Permission to start a local validator and bind loopback ports. Synthetic keys
  are public deterministic test fixtures. Never send real funds to these keys.

Run from this directory, substituting the Node executable above:
  node trial.mjs reproduce-01
Use a new label each time. Existing evidence is deliberately not overwritten.
The test creates a temporary ledger under /private/tmp, performs all 17 checks,
stops its own validator and removes that temporary ledger. It writes logs and
one JSON evidence file here. It never selects a user's wallet or RPC endpoint.

Validate the two accepted runs:
  node compare.mjs
This checks functional equivalence, measured costs, ELF hash, and scope flags.
Timing is two local observations, not a statistical or mainnet performance claim.
The first run did not record the validator's terminating signal; null exit code
must not be read as exit code 0. The second run records signal and forced-kill use.

Rebuild in the original work directory:
  ./build.sh -- --locked
This needs the existing isolated cargo-home cache, target and platform-tools-v1.52
folders. These large generated folders are not copied into frozen results.
The official compiler archive URL and SHA256 are in environment.json. Extract it
into platform-tools-v1.52 with safe archive extraction and verify its SHA first.
The small SDK snapshot is included as sbf-sdk; its dependencies/platform-tools
must point to this local platform-tools-v1.52. SDK env.sh only checks that local
llvm-objcopy exists; it does not run the original global tool installer.
Cargo.lock pins the graph, and the build uses --offline and --locked. The accepted
build log is evidence/build-06.log. Its unknown-syscall warnings reflect an empty
syscalls.txt shipped with this SDK; the actual compiled ELF passed both runtime
trials. Earlier failed build and smoke logs are retained as diagnostic history.

Rebuilding without the original cache requires populating an isolated CARGO_HOME
with the Cargo.lock dependencies; that provisioning is not tested here. Do not
substitute a newer toolchain silently. Cached platform-tools v1.57 produced an
ELF rejected by the pinned validator, and v1.48 could not parse a dependency's
edition2024 metadata. Only v1.52 is accepted for these measurements.

The frozen MANIFEST.json covers included files except itself. Toolchain binaries,
build output directories, generated deployment keypairs, and temporary ledgers
are excluded. Public fixture remains in its separately frozen parent artifact.
CURRENT.json, installed wallet, website and prior frozen results are unchanged.
