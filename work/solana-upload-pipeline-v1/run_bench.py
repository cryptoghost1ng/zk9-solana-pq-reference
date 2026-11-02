"""Serialized launcher of bench.mjs (upload-strategy benchmark on an isolated loopback validator). Takes the lab lock, refuses to start if another validator is
running (it would perturb the timings), runs the benchmark with a minimal environment, keeps stdout/stderr as evidence and checks that nothing is left alive.
usage: python3 -B run_bench.py LABEL [--smoke]      (a new label each time; evidence is never overwritten)"""
import json,os,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent;WORK=ROOT.parent
sys.path[:0]=[str(WORK/'solana-chrome-wallet-v1')]
from offline_guard import acquire
args=[a for a in sys.argv[1:] if a!='--smoke'];smoke='--smoke' in sys.argv[1:]
assert len(args)==1 and re.fullmatch(r'[a-z0-9-]+',args[0]),'a new evidence label is required'
label=args[0];ev=ROOT/'evidence'
lock=acquire()
NODE=Path.home()/'.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node'
def validators():
    ps=subprocess.run(['/bin/ps','-axo','pid=,args='],capture_output=True,text=True).stdout
    return [l.strip()[:120] for l in ps.splitlines() if 'solana-test-validator' in l and 'grep' not in l]
busy=validators();assert not busy,'another validator is running: %s'%busy
env={'PATH':'/usr/bin:/bin','HOME':str(Path.home()),'TMPDIR':'/private/tmp','LANG':'en_US.UTF-8'}
if smoke:env['BENCH_SMOKE']='1'
with (ev/(label+'.stdout')).open('x') as so,(ev/(label+'.stderr')).open('x') as se:
    code=subprocess.run([str(NODE),str(ROOT/'bench.mjs'),label],cwd=ROOT,env=env,stdout=so,stderr=se).returncode
left=validators()
print(json.dumps({'label':label,'exit':code,'smoke':smoke,'validators_left_alive':left}))
sys.exit(0 if code==0 and not left else 1)
