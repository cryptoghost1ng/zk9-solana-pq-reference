"""Serial synthetic qualification. Unique paths, complete source capture, explicit exit."""
import hashlib,json,os,resource,subprocess,sys,time
from pathlib import Path
W=Path(__file__).resolve().parent
def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1048576),b''):h.update(b)
    return h.hexdigest()
def capture():
    paths=[p for p in W.iterdir() if p.is_file()]
    paths+=list((W/'src').rglob('*.rs'))+list((W/'source').rglob('*'))
    paths=[p for p in paths if p.is_file()]
    paths+=[W/'target/release/qualify',W/'evidence/environment-01.json']
    env=json.loads((W/'evidence/environment-01.json').read_text())
    for p,pin in env['local_source_pins'].items():
        assert sha(p)==pin,('dependency changed',p)
    # Go uses the pinned note-delivery implementation, not a rewritten cipher.
    paths += [W.parent/'pq-note-delivery-v1/source'/n for n in ('go.mod','note.go')]
    return {str(p):sha(p) for p in sorted(set(paths))}
name=sys.argv[1];smoke=len(sys.argv)>2 and sys.argv[2]=='smoke'
assert name.isascii() and name.replace('-','').isalnum()
dest=W/'evidence'/name;log=dest.with_suffix('.jsonl');result=dest.with_suffix('.result.json')
assert not any(p.exists() for p in (dest,log,result))
before=capture();env=os.environ.copy();env['ZK9_WITHDRAW_FIXTURE']=str(W/'fixture-helper')
cmd=[str(W/'target/release/qualify'),str(dest)]+(['smoke'] if smoke else [])
start=time.monotonic()
with log.open('xb') as f:
    p=subprocess.Popen(cmd,env=env,stdout=f,stderr=subprocess.STDOUT);code=p.wait()
rows=[]
for line in log.read_text().splitlines():
    try:rows.append(json.loads(line))
    except ValueError:pass
cases=[r['case'] for r in rows if 'case' in r]
expected=['single-with-change','binding-and-wire']
if not smoke:expected+=['maximum-withdrawal','two-inputs','protocol-isolation','builder-guards','wallet-built',
    'amount-cannot-create-value','withdrawal-cannot-wrap-u64','carry-constrained','recipient-constrained','mode-constrained',
    'nonzero-padding','modulus-not-zero','membership','ownership','active-second-membership','flag-boolean','flag-stationary']
passed=code==0 and before==capture() and cases==expected and all(r.get('status')=='PASS' for r in rows)
if not smoke:passed=passed and rows[-1].get('malicious_trace_verifier_rejections')==12
record=dict(status='PASS' if passed else 'FAIL',child_exit=code,child_pid=p.pid,wall_seconds=time.monotonic()-start,
    source_files=before,cases=cases,smoke=smoke,log_sha256=sha(log),
    peak_rss=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,peak_rss_units='bytes' if sys.platform=='darwin' else 'KiB',
    measurements='functional observations, not benchmarks',current_sha256=sha(W.parent.parent/'CURRENT.json'))
with result.open('x') as f:json.dump(record,f,indent=2,sort_keys=True);f.write('\n')
print(json.dumps({k:record[k] for k in ('status','child_exit','wall_seconds','peak_rss')}),flush=True)
raise SystemExit(0 if passed else 1)
