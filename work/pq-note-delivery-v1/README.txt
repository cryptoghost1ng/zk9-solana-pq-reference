ZK9 — Payment-bound encrypted note delivery, EXPERIMENTAL candidate v1

No real funds or personal keys. No product/node installation. The fixture seeds
are public, synthetic and forbidden for real funds. The exercise CLI accepts
only the fixed synthetic funding fixture; library APIs accept payment witnesses.

Reproduce from this workspace (pinned local Rust/Go, no global shell changes):
  sh cargo-local.sh build --offline --locked --release
  sh go-local.sh test -count=2 -v ./...
  LAB_PY=/private/tmp/zk9-gloas-complete-cold-install-20261014-1/backend/operator/runtime/zk9-chain/.toolchain/python/bin/zk9-python
  "$LAB_PY" -E -s -B run-checks.py YOUR_NEW_RUN_NAME
Choose a fresh name. Native builds/proofs/tests run sequentially. No daemon,
network connection, purchase or token creation is performed. Parent path
dependencies and their exact frozen source manifests are in QUALIFICATION.json.

Construction and limits
- 2-in/2-out depth32 payment relation is imported unchanged from tree-v1.
- Transcript domain NOTE-DELIVERY/v1, 276 public field values instead of212.
- Two SHA3-512 delivery digests bind network/genesis/asset/output commitment,
  output slot and each entire mandatory1732byte packet.
- Pinned Plonky3 uni-stark/src/transcript.rs absorbs ALL public scalars before
  sampling alpha on both sides and binds public-value count into transcript.
  The extra64fields are associated data, intentionally not AIR assertions of
  correct encryption. Adding unconstrained values without this transcript
  binding would not be sufficient. Both domain and public shape change here.
- Header440bytes, magic ZK9PQD1\0/version1, then two fixed packets, then bounded
  canonical Postcard proof <=4MiB. Public digests are recomputed from packets,
  not accepted from an unauthenticated relayer. Maximum4198208bytes total.
- A relayer cannot replace, reorder or strip packets while retaining a valid
  proof. This does not stop withholding/censorship of the entire transaction.
- Encryption: ML-KEM-1024, HKDF-SHA512, AES-256-GCM, OS randomness per encryption,
  fixed128byte plaintext (owner64/rho32/amount8/zero padding24). Packet header8,
  KEM ciphertext1568, nonce12, padded ciphertext128, tag16. No recipient tag.
- Recipient independently checks AEAD, owner, canonical padding and commitment.
  A dishonest sender CAN bind garbage or encrypt to a wrong key; this protocol
  does not prove encryption correctness and must not advertise that guarantee.
- Wallet seed32bytes derives separate spend-secret32 and ML-KEM seed64 under
  context/domain separated HKDF. Caller authenticates the recipient address/key
  and accepted chain state. The receive key is static: no forward secrecy.
- ML-KEM recipient anonymity / key privacy, scanning timing and metadata,
  recovery distribution and network transport require separate review. A lack
  of a public recipient tag does not establish anonymous encryption.
- Best-effort Go clear is not a guarantee against runtime memory copies.
- Recovery test driver verifies in Rust before passing the envelope to the Go
  test harness. It is NOT a wallet API for trusting raw files or JSON receipts.

Next: versioned consensus keeper/App acceptance and durable packet availability,
wallet discovery/index synchronization, SQLite recovery/reorgs, user address
format and address authentication. Existing keeper/app-v1 still accept the old
format and must NOT be relabelled as supporting delivery-v1. Existing genesis
funding remains synthetic; deposits/withdrawals are not supplied by this layer.
Independent security review, transport, protected signer packaging and external
operators remain launch requirements. This candidate is not PQ-integral proof.
