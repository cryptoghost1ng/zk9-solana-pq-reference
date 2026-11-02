"""Sequential, fresh synthetic Go -> Rust proof -> Go seed recovery checks."""
import json, os, subprocess, sys, time
from pathlib import Path
W=Path(__file__).resolve().parent
name=sys.argv[1]
assert name and Path(name).name==name and name not in ('.','..')
out=W/'evidence'/name
out.mkdir(exist_ok=False)
processes=[]
def run(label,args,env=None):
    start=time.monotonic()
    with (out/(label+'.log')).open('wb') as log:
        result=subprocess.run(args,stdout=log,stderr=subprocess.STDOUT,env={**os.environ,**(env or {})})
    processes.append(dict(label=label,command=args,exit_code=result.returncode,elapsed_s=time.monotonic()-start))
    (out/'processes.json').write_text(json.dumps(processes,indent=2)+'\n')
    if result.returncode:raise RuntimeError(f'{label} failed, retained log at {out}')
    print(label+' PASS',flush=True)
run('export',['sh',str(W/'go-local.sh'),'test','-count=1','-v','-run','^TestExportSyntheticFixture$','./...'],
    {'ZK9_NOTE_FIXTURE':str(out/'fixture')})
run('proof',[sys.executable,'-E','-s','-B',str(W/'measure-one.py'),str(out/'proof-process.json'),
    str(W/'target/release/zk9-note-delivery'),'exercise',str(out/'fixture'),str(out/'verified')])
run('restore',['sh',str(W/'go-local.sh'),'test','-count=1','-v','-run','^TestRecoverAfterRustProofVerification$','./...'],
    {'ZK9_NOTE_RECOVER':str(out/'verified')})
checks=json.loads((out/'verified/checks.json').read_text())
assert checks['status']=='PASS_BOUND_DELIVERY_LAB' and len(checks['rejections'])>=90
assert 'restored two wallets from seeds: total=1499999' in (out/'restore.log').read_text()
(out/'summary.json').write_text(json.dumps(dict(status='PASS',processes=len(processes),
    rejections=len(checks['rejections']),amounts=checks['amounts'],fee=checks['fee']),indent=2)+'\n')
print('PASS: bound encrypted notes recovered from both synthetic wallet seeds',flush=True)
