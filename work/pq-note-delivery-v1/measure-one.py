"""Fresh supervisor with exactly one child; no sysctl/global process access."""
import json, resource, subprocess, sys, time
from pathlib import Path
output=Path(sys.argv[1]);assert not output.exists()
started=time.monotonic()
result=subprocess.run(sys.argv[2:])
usage=resource.getrusage(resource.RUSAGE_CHILDREN)
output.write_text(json.dumps(dict(exit_code=result.returncode,elapsed_s=time.monotonic()-started,
    max_rss_bytes=usage.ru_maxrss if sys.platform=='darwin' else usage.ru_maxrss*1024,
    child_count=1,platform=sys.platform,user_s=usage.ru_utime,system_s=usage.ru_stime),indent=2)+'\n')
sys.exit(result.returncode)
