"""Serial native samples. macOS child max RSS is process-wide, in bytes."""
import csv
import json
import resource
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parent
label, count = sys.argv[1:]
if label not in ('series-01', 'repeat-01') or not 1 <= int(count) <= 30:
    raise SystemExit('invalid measurement arguments')
out = root / 'evidence' / label
cmd = [str(root / 'target/release/zk9-hiding-balance-component'), count, str(out)]
run = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
meta = dict(command=cmd, returncode=run.returncode, stdout=run.stdout,
            stderr=run.stderr, max_rss_bytes=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
            memory_scope='whole child process, all samples; not per operation',
            os_cache='not flushed', workload='synthetic balance component, not private payment')
(root / 'evidence' / (label + '.process.json')).write_text(json.dumps(meta, indent=2) + '\n')
if run.returncode:
    raise SystemExit(run.returncode)
data = json.loads((out / 'samples.json').read_text())
with (out / 'samples.csv').open('x') as f:
    writer = csv.DictWriter(f, fieldnames=list(data['samples'][0]))
    writer.writeheader()
    writer.writerows(data['samples'])
print(json.dumps({k: v for k, v in meta.items() if k not in ('stdout', 'stderr', 'command')}))
