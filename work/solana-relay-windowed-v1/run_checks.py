"""Serial run of the windowed publication revision's checks: pins every input (this directory's code, the frozen modules it imports and the five frozen
files it was derived from), runs checks.mjs once, and writes a NEW evidence directory with the raw output and a result. It proves nothing about the real
cluster, about privacy or about anonymity: the cluster is the model of harness.mjs (see its header).
usage: run_checks.py checks-NN"""
import hashlib,json,os,re,shutil,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent;WORK=ROOT.parent
sys.path[:0]=[str(WORK/'solana-chrome-wallet-v1')]
from offline_guard import acquire
assert len(sys.argv)==2 and re.fullmatch(r'checks-[0-9]+',sys.argv[1])
lock=acquire();out=ROOT/'evidence'/sys.argv[1];out.mkdir(parents=True,exist_ok=False)
NODE=Path(shutil.which('node') or 'node')
ARCHIVE=WORK/'solana-multiwallet-privacy-v1/evidence/privacy-live-02/public-capsule'
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
# The five frozen files this revision was derived from. They must be byte-identical to what they were when the revision was started.
FROZEN={'solana-private-relay-v1/relay-publication.mjs':'29a984f75273cf835e63339cdbd4db3e23706af5650361d1fc9afcc51eafa2c7',
        'solana-private-relay-v1/relay-repository.mjs':'d3f9731c7682ed22be78a2eda38c12549dfba74704a40e867d8bd635794f62ae',
        'solana-private-relay-v1/relay-funding.mjs':'686a66f0a62aeba0b5de3a2e1d11866cf71af1dd0a727908dd6be0e8d1cda6d8',
        'solana-private-relay-v1/relay-task.mjs':'d169b464c681556d724e6aebd878a8cb9c3ab8c699bdb5c4a22542a263325321',
        'solana-unified-wallet-v1/recovery/publication-sender.mjs':'4f7890df0be67265b9ebe73dd51ab070dbface081337b6f2636d12464963e4c9'}
touched=[n for n,h in FROZEN.items() if sha(WORK/n)!=h]
assert not touched,'a frozen source changed: %s'%touched
imported=['solana-private-relay-v1/relay-request.mjs','solana-private-relay-v1/relay-transport.mjs','solana-private-relay-v1/relay-settlement.mjs',
          'solana-private-relay-v1/relay-offer.mjs','solana-private-relay-v1/native-verifier.mjs',
          'solana-relay-performance-v1/candidate/publication-policy.mjs','solana-relay-performance-v1/candidate/proof-buffer.mjs','solana-relay-performance-v1/candidate/local-network.mjs',
          'solana-chrome-wallet-v1/recovery/solana-transaction.mjs','solana-chrome-wallet-v1/recovery/checkpoint.mjs','solana-chrome-wallet-v1/recovery/payment-wire.mjs',
          'solana-chrome-wallet-v1/recovery/proof-progress.mjs','solana-chrome-wallet-v1/recovery/settlement-sender.mjs',
          'solana-unified-wallet-v1/recovery/simulation-result.mjs','solana-unified-wallet-v1/recovery/checkpoint.mjs','solana-unified-wallet-v1/recovery/solana-transaction.mjs',
          'solana-unified-wallet-v1/recovery/proof-progress.mjs',
          'solana-chrome-wallet-v1/evidence/settlement-plan-01/PUBLIC-FIXTURES.json','solana-chrome-wallet-v1/evidence/settlement-journal-01/INPUTS.json']
own=[*sorted(p.name for p in ROOT.glob('*.mjs')),'mutation_control.py','run_checks.py']
pins={**{str(ROOT/n):sha(ROOT/n) for n in own},**{str(WORK/n):sha(WORK/n) for n in imported},**{str(WORK/n):h for n,h in FROZEN.items()},
      str(NODE):sha(NODE),str(Path(sys.executable).resolve()):sha(Path(sys.executable).resolve())}
for wire in sorted(ARCHIVE.glob('*.wire')):pins[str(wire)]=sha(wire)
(out/'INPUTS.json').write_text(json.dumps(pins,indent=2)+'\n')
env={**os.environ,'ZK9_WIRE_ARCHIVE':str(ARCHIVE)}
with (out/'node.stdout').open('x') as so,(out/'node.stderr').open('x') as se:
    code=subprocess.run([str(NODE),'--test','--test-timeout=300000',str(ROOT/'checks.mjs')],stdout=so,stderr=se,timeout=1800,env=env,cwd=ROOT).returncode
text=(out/'node.stdout').read_text()
tests=re.search(r'ℹ tests (\d+)',text);passed=re.search(r'ℹ pass (\d+)',text);failed=re.search(r'ℹ fail (\d+)',text)
names=re.findall(r'^✔ ([A-Z][0-9]+[^\n]*?) \(',text,re.M)
unchanged=all(sha(p)==h for p,h in pins.items() if not p.endswith(('/node',sys.executable)) and Path(p).exists())
ok=code==0 and tests and passed and failed and tests.group(1)==passed.group(1) and failed.group(1)=='0' and unchanged and len(names)==int(tests.group(1))
result={'status':'PASS_WINDOWED_PUBLICATION_CHECKS' if ok else 'FAIL_WINDOWED_PUBLICATION_CHECKS','exit_code':code,
        'tests':int(tests.group(1)) if tests else None,'passed':int(passed.group(1)) if passed else None,'failed':int(failed.group(1)) if failed else None,
        'inputs_unchanged_during_the_run':unchanged,'frozen_sources_byte_identical':True,'checks':names,
        'cluster':'model (harness.mjs): real buffer layout and rules, real SQLite, real Ed25519 signing, real transaction decoder; no validator, no verifier program, no pool',
        'proves_nothing_about':['the real cluster','privacy','anonymity','mainnet']}
(out/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:result[k] for k in ('status','tests','passed','failed','inputs_unchanged_during_the_run')}))
sys.exit(0 if ok else 1)
