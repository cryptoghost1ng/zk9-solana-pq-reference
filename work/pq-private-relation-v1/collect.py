"""Freeze measured laboratory evidence, without promoting it to the product."""
import json
import shutil
import statistics
import subprocess
import sys
import tomllib
from pathlib import Path

w = Path(__file__).resolve().parent
r = w.parents[1]
sys.path.insert(0, str(r / 'work/private-rpc-product-v1/source-kit'))
from common import sha, read, save, freeze, verify

d = r / 'results/pq-private-relation-v1'
assert not d.exists(), 'Never replace frozen results'
parent_pin = '220725a8bd0dd24c98575f1cbd2621184a15a47701b68507dd2c24919d99d43f'
parent = r / 'results/pq-pool-component-v1'
verify(parent, parent_pin)
for name in ['Cargo.toml', 'Cargo.lock', *['src/' + p.name for p in (parent / 'src').glob('*.rs')]]:
    assert sha(parent / name) == sha(r / 'work/pq-pool-component-v1' / name), name
up = r / 'work/pq-pool-selection-v1'
expected = read(up / 'SOURCE-INVENTORY.json')
actual = {str(p.relative_to(up / 'plonky3')) for p in (up / 'plonky3').rglob('*') if p.is_file()}
assert actual == set(expected)
for name, meta in expected.items():
    p = up / 'plonky3' / name
    assert not p.is_symlink() and sha(p) == meta['sha256'], name

assert '6 passed; 0 failed; 0 ignored' in (w / 'evidence/tests-01.log').read_text()
series = w / 'evidence/series-01'
rows = read(series / 'samples.json')
assert len(rows) == 30
proof_hashes = []
for i, row in enumerate(rows):
    process = read(series / f'process-{i:02}.json')
    raw = read(series / f'sample-{i:02}/sample.json')
    assert process['returncode'] == 0 and process['stderr'] == ''
    assert json.loads(process['stdout']) == raw
    assert row == dict(sample=i, **raw) and raw['verified'] is True
    assert raw['production_ready'] is False and raw['pq_security_budget_verified'] is False
    p = series / f'sample-{i:02}/proof.postcard'
    assert p.stat().st_size == raw['proof_bytes']
    proof_hashes.append(sha(p))
assert len(set(proof_hashes)) == 30, 'Fresh randomized proofs must differ'
assert read(w / 'evidence/proof-01.process.json')['exit_code'] == 0
assert read(w / 'evidence/proof-01/sample.json')['verified'] is True
stats = {}
for key in ('prepare_ms', 'init_ms', 'prove_ms', 'verify_ms', 'proof_bytes'):
    values = [s[key] for s in rows]
    median = statistics.median(values)
    stats[key] = dict(median=median, mad=statistics.median(abs(x-median) for x in values),
                      minimum=min(values), maximum=max(values))
assert stats == read(series / 'statistics.json')
config_file = r / 'work/pq-signer-guard-v1/network/node0/config/config.toml'
config = tomllib.loads(config_file.read_text())
genesis_file = config_file.with_name('genesis.json')
genesis = read(genesis_file)
limits = dict(config_sha256=sha(config_file), genesis_sha256=sha(genesis_file),
              rpc_max_body_bytes=config['rpc']['max_body_bytes'],
              mempool_max_tx_bytes=config['mempool']['max_tx_bytes'],
              consensus_block=genesis['consensus']['params']['block'])
save(w / 'INTEGRATION-LIMITS.json', limits)
result = dict(status='PASS_EXPERIMENTAL_PRIVATE_RELATION_DEPTH4',
              adopted_in_product=False, public_launch_ready=False,
              integral_post_quantum=False, pq_security_budget_verified=False,
              durable_state=False, ciphertext_and_wallet_integrated=False,
              upstream_revision='f98331687e47106a64ab82a77e2e1d0d66c9161b',
              upstream_files_unchanged=len(expected), balance_parent_manifest=parent_pin,
              tests_passed=6, samples=30, independent_initial_proof_verified=True,
              statistics=stats, proof_hashes=proof_hashes, integration_limits=limits,
              cumulative_child_peak_rss_bytes=max(read(p)['cumulative_child_max_rss_bytes'] for p in series.glob('process-*.json')),
              binary_sha256=sha(w / 'target/release/zk9-private-relation-lab'),
              cargo_lock_sha256=sha(w / 'Cargo.lock'),
              rustc=subprocess.check_output([str(r / 'work/gloas-native-integration-v1/native/.toolchain/rust/bin/rustc'), '-vV'], text=True),
              measurement_limits=['Single M1 Max; desktop/browser remain open; no parallel laboratory native workloads',
                                  'OS cache not flushed; each sample uses a fresh process',
                                  'RSS is cumulative child-process highwater, not a per-operation distribution',
                                  'Depth4 synthetic tree; proof does not benchmark production pool capacity',
                                  'Serialization and second roundtrip verification are outside reported verify_ms'])
save(w / 'QUALIFICATION.json', result)
d.mkdir()
for name in ('Cargo.toml', 'Cargo.lock', 'cargo-local.sh', 'README.txt', 'hash-vectors.json',
             'QUALIFICATION.json', 'INTEGRATION-LIMITS.json', 'REPORT.txt', 'measure.py', 'collect.py'):
    shutil.copy2(w / name, d / name)
shutil.copytree(w / 'src', d / 'src')
shutil.copytree(w / 'evidence', d / 'evidence')
pin = freeze(d, {'scope': 'Experimental private relation only; no product adoption or public deployment'})
verify(d, pin)
save(w / 'FINAL-VERIFICATION.json', dict(status='PASS', manifest_sha256=pin, result_directory=str(d)))
print(json.dumps(dict(manifest_sha256=pin, statistics=stats, integration_limits=limits), indent=2))
