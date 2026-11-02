"""Sequential, synthetic-only qualification. Fresh paths; retains failed runs."""
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import time

root = Path(__file__).resolve().parent
name = sys.argv[1]
if not name.isascii() or not name.replace('-', '').isalnum():
    raise SystemExit('invalid run name')
binary = root / 'target/release/qualify'
dest = root / 'evidence' / name
log = dest.with_suffix('.jsonl')
result = dest.with_suffix('.result.json')
if dest.exists() or log.exists() or result.exists():
    raise SystemExit('run paths must be new')
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def source_state():
    files = [root/'Cargo.toml', root/'Cargo.lock', root/'cargo-local.sh']
    files += sorted((root/'src').rglob('*.rs'))
    return {str(p.relative_to(root)): digest(p) for p in files}
sources = source_state()
started = time.monotonic()
with log.open('xb') as stream:
    child = subprocess.Popen([str(binary), str(dest)], stdout=stream, stderr=subprocess.STDOUT)
    code = child.wait()
elapsed = time.monotonic() - started
rows = []
for line in log.read_text().splitlines():
    try:
        value = json.loads(line)
    except ValueError:
        continue
    if isinstance(value, dict):
        rows.append(value)
expected = {
    'one-real-input', 'two-real-inputs', 'one-u64-max', 'wallet-constructed-one-input',
    'public-proof-wire-rejections', 'protocol-version-isolation', 'balance-rejections',
    'nonzero-input-cannot-be-padding', 'field-modulus-is-not-zero-value',
    'first-membership-required', 'first-ownership-required',
    'active-second-membership-required', 'active-flag-must-be-boolean',
    'active-flag-must-be-stationary',
}
cases = [r['case'] for r in rows if 'case' in r]
passed = (code == 0 and sources == source_state() and len(cases) == len(expected)
          and set(cases) == expected and all(r.get('status') == 'PASS' for r in rows)
          and rows[-1].get('malicious_trace_verifier_rejections') == 7)
record = dict(status='PASS' if passed else 'FAIL', child_exit=code, cases=cases,
              wall_seconds=elapsed, source_files=sources, binary_sha256=digest(binary),
              peak_rss=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
              peak_rss_units='bytes' if sys.platform == 'darwin' else 'KiB',
              platform=sys.platform, architecture=os.uname().machine,
              measurements='functional observations, not a performance benchmark',
              log_sha256=digest(log))
with result.open('x') as stream:
    json.dump(record, stream, indent=2)
    stream.write('\n')
print(json.dumps({k: record[k] for k in ('status', 'child_exit', 'wall_seconds', 'peak_rss', 'peak_rss_units')}), flush=True)
raise SystemExit(0 if passed else 1)
