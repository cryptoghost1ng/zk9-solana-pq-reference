"""Cross-language C client against every successful withdrawal fixture, serial."""
import hashlib,json,subprocess,sys,time
from pathlib import Path
W=Path(__file__).resolve().parent
def sha(p):
    h=hashlib.sha256()
    with Path(p).open('rb') as f:
        for b in iter(lambda:f.read(1048576),b''):h.update(b)
    return h.hexdigest()
name,label=sys.argv[1:]
assert name.isascii() and name.replace('-','').isalnum()
assert label in ('qualification-01','qualification-02')
q=json.loads((W/'evidence'/f'{label}.result.json').read_text());assert q['status']=='PASS' and q['child_exit']==0
for p,pin in q['source_files'].items():assert sha(p)==pin,('source changed',p)
dest=W/'evidence'/name;dest.mkdir()
started=time.monotonic();runs=[]
for case in ('single-with-change','maximum-withdrawal','two-inputs','wallet-built'):
    wire=W/'evidence'/label/f'{case}.wire'
    cmd=[str(W/'bin/c-verify'),str(wire),str(W/'reference20.wire')]
    with (dest/f'{case}.stdout').open('xb') as out,(dest/f'{case}.stderr').open('xb') as err:
        p=subprocess.Popen(cmd,stdout=out,stderr=err);code=p.wait()
    record={'case':case,'exit':code,'pid':p.pid,'wire_sha256':sha(wire)}
    (dest/f'{case}.exit-code').write_text(str(code)+'\n')
    if code!=0:raise SystemExit('C ABI failure: '+case)
    detail=json.loads((dest/f'{case}.stdout').read_text());assert detail['status']=='PASS' and detail['checks']==48
    record['detail']=detail;runs.append(record)
for p,pin in q['source_files'].items():assert sha(p)==pin,('source changed',p)
record={'status':'PASS','label':label,'runs':runs,'wall_seconds':time.monotonic()-started,
    'client_sha256':sha(W/'bin/c-verify'),'staticlib_sha256':sha(W/'target/release/libzk9_private_withdraw32_lab.a'),
    'scope':'actual C-linked calls, 48checks per fresh process; no bank payout or registered-account check'}
(dest/'RESULT.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')
print(json.dumps({k:record[k] for k in ('status','label','wall_seconds')}),flush=True)
