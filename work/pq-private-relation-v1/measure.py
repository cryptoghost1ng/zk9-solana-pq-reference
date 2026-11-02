"""Run real relation proofs serially, recording process status and macOS RSS."""
import csv
import json
import resource
import statistics
import subprocess
import sys
from pathlib import Path
w=Path(__file__).resolve().parent
count=int(sys.argv[1])
if not 1<=count<=30: raise SystemExit('samples must be1..30')
dest=w/'evidence'/'series-01'
dest.mkdir(exist_ok=False)
rows=[]
for i in range(count):
    path=dest/f'sample-{i:02}'
    cmd=[str(w/'target/release/zk9-private-relation-lab'),'prove',str(path)]
    run=subprocess.run(cmd,capture_output=True,text=True,timeout=600)
    meta=dict(returncode=run.returncode,stdout=run.stdout,stderr=run.stderr,
              cumulative_child_max_rss_bytes=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
    (dest/f'process-{i:02}.json').write_text(json.dumps(meta,indent=2)+'\n')
    if run.returncode: raise SystemExit(run.returncode)
    row=json.loads((path/'sample.json').read_text())
    if row['verified'] is not True: raise SystemExit('not verified')
    rows.append(dict(sample=i,**row))
    print(f'sample {i+1}/{count}: verified; prove={row["prove_ms"]:.1f}ms, verify={row["verify_ms"]:.1f}ms',flush=True)
(dest/'samples.json').write_text(json.dumps(rows,indent=2)+'\n')
with (dest/'samples.csv').open('x') as f:
    c=csv.DictWriter(f,fieldnames=list(rows[0]));c.writeheader();c.writerows(rows)
stats={}
for k in ('prepare_ms','init_ms','prove_ms','verify_ms','proof_bytes'):
    v=[r[k] for r in rows];m=statistics.median(v)
    stats[k]=dict(median=m,mad=statistics.median(abs(x-m) for x in v),minimum=min(v),maximum=max(v))
(dest/'statistics.json').write_text(json.dumps(stats,indent=2)+'\n')
