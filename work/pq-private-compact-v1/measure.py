"""Serial fresh processes, with original rows, statistics and truthful RSS."""
import csv
import json
import statistics
import subprocess
import sys
from pathlib import Path
w=Path(__file__).resolve().parent
count=int(sys.argv[1]);assert 1<=count<=30
dest=w/'evidence'/sys.argv[2];dest.mkdir(exist_ok=False)
rows=[]
for i in range(count):
    output=dest/f'sample-{i:02}'
    run=subprocess.run([sys.executable,'-E','-s','-B',str(w/'run-one.py'),'prove',str(output)],capture_output=True,text=True,timeout=660)
    if run.returncode:print(run.stderr);raise SystemExit(run.returncode)
    row=json.loads((output/'sample.json').read_text())
    process=json.loads(output.with_name(output.name+'.process.json').read_text())
    assert row['verified'] is True and process['exit_code']==0
    rows.append(dict(sample=i,**row,child_peak_rss_bytes=process['child_peak_rss_bytes']))
    print(f'{i+1}/{count} verified: prove={row["prove_ms"]:.2f}ms, bytes={row["proof_bytes"]}',flush=True)
(dest/'samples.json').write_text(json.dumps(rows,indent=2)+'\n')
with (dest/'samples.csv').open('x') as f:
    writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
stats={}
for key in ('layout_ms','prepare_ms','init_ms','prove_ms','verify_ms','proof_bytes','child_peak_rss_bytes'):
    values=[row[key] for row in rows];median=statistics.median(values)
    stats[key]=dict(median=median,mad=statistics.median(abs(v-median) for v in values),minimum=min(values),maximum=max(values))
(dest/'statistics.json').write_text(json.dumps(stats,indent=2)+'\n')
