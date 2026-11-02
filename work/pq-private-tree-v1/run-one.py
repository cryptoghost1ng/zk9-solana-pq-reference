"""One native child in a fresh Python process, for per-process macOS RSS."""
import json
import resource
import subprocess
import sys
from pathlib import Path
w=Path(__file__).resolve().parent
out=Path(sys.argv[-1])
log=out.with_name(out.name+'.process.json')
assert not out.exists() and not log.exists()
command=[str(w/'target/release/zk9-private-tree-lab'),*sys.argv[1:]]
result=subprocess.run(command,capture_output=True,text=True,timeout=600)
record=dict(command=command,exit_code=result.returncode,stdout=result.stdout,stderr=result.stderr,
            child_peak_rss_bytes=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
log.write_text(json.dumps(record,indent=2)+'\n')
print(result.stdout,end='');print(result.stderr,file=sys.stderr,end='')
raise SystemExit(result.returncode)
