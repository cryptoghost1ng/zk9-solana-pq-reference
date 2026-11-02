"""Freeze this component only; never promote it to the installed product."""
import json
import shutil
import statistics
import subprocess
import sys
from pathlib import Path

w = Path(__file__).resolve().parent
r = w.parents[1]
sys.path.insert(0, str(r / 'work/private-rpc-product-v1/source-kit'))
from common import sha, read, save, freeze, verify

up = r / 'work/pq-pool-selection-v1'
expected = read(up / 'SOURCE-INVENTORY.json')
actual = {str(p.relative_to(up / 'plonky3')) for p in (up / 'plonky3').rglob('*') if p.is_file()}
assert actual == set(expected)
for name, meta in expected.items():
    p = up / 'plonky3' / name
    assert not p.is_symlink() and sha(p) == meta['sha256'], name
for name in ('tests-01.log', 'tests-02.log'):
    assert '5 passed; 0 failed' in (w / 'evidence' / name).read_text()
samples = read(w / 'evidence/series-01/samples.json')['samples']
assert len(samples) == 30 and all(s['verified'] for s in samples)
assert read(w / 'evidence/repeat-01/samples.json')['samples'][0]['verified']
assert read(w / 'evidence/series-01.process.json')['returncode'] == 0
assert read(w / 'evidence/repeat-01.process.json')['returncode'] == 0
stats = {}
for key in ('init_ms', 'prepare_ms', 'prove_ms', 'verify_ms', 'proof_bytes'):
    v = [s[key] for s in samples]
    median = statistics.median(v)
    stats[key] = dict(median=median, minimum=min(v), maximum=max(v),
                      median_absolute_deviation=statistics.median(abs(x-median) for x in v))
result = dict(status='PASS_HIDING_BALANCE_COMPONENT_ONLY',
              full_payment=False, post_quantum_security_budget_verified=False,
              adopted_in_product=False, public_launch_ready=False,
              upstream_revision='f98331687e47106a64ab82a77e2e1d0d66c9161b',
              upstream_files_unchanged=len(expected), tests_per_run=5, test_runs=2,
              samples=30, independent_process_repeat=1, statistics=stats,
              binary_sha256=sha(w / 'target/release/zk9-hiding-balance-component'),
              cargo_lock_sha256=sha(w / 'Cargo.lock'),
              rustc=subprocess.check_output([str(r / 'work/gloas-native-integration-v1/native/.toolchain/rust/bin/rustc'), '-vV'], text=True),
              measurement_limits=['single machine; user desktop and browser remain open',
                                  'short component timing, not full payment benchmark',
                                  'OS cache not flushed; RSS measured for entire child process'])
save(w / 'QUALIFICATION.json', result)
d = r / 'results/pq-pool-component-v1'
d.mkdir(exist_ok=False)
for name in ('Cargo.toml', 'Cargo.lock', 'cargo-local.sh', 'README.txt', 'QUALIFICATION.json', 'measure.py', 'collect.py'):
    shutil.copy2(w / name, d / name)
shutil.copytree(w / 'src', d / 'src')
shutil.copytree(w / 'evidence', d / 'evidence')
pin = freeze(d, {'scope':'isolated balance component, not private payment or production adoption'})
verify(d, pin)
save(w / 'FINAL-VERIFICATION.json', {'status':'PASS', 'manifest_sha256':pin, 'result_directory':str(d)})
print(json.dumps({'manifest_sha256':pin, 'statistics':stats}, indent=2))
