"""Refuse to start candidate computation before the repeated baseline is frozen."""
import hashlib,json,pathlib,subprocess,sys
assert __debug__
W=pathlib.Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
for name,digest in json.loads((W/'BASELINE.json').read_text())['source_pins'].items():
    assert sha(pathlib.Path(name))==digest,name
parent=(W/'../../results/solana-pq-integrated-pool-v1').resolve()
assert (parent/'MANIFEST.json').is_file(), 'Wait for both baseline runs, their terminal exits and freezing'
manifest=json.loads((parent/'MANIFEST.json').read_text())
assert manifest['milestone']=='solana-pq-integrated-pool-v1'
for name,digest in manifest['sha256'].items():assert sha(parent/name)==digest,name
q=json.loads(subprocess.check_output([sys.executable,'-E','-s','-B',str(parent/'qualify.py')],text=True))
assert q['status']=='PASS_REPEATED_ZERO_SESSION_PROOF_TO_POOL' and q['runtimes']==2
assert not q['completed_receipt_preloaded'] and not q['pool_preloaded']
print(json.dumps(dict(status='PASS_REPEATED_BASELINE_REQUIRED',parent=str(parent),manifest_sha256=sha(parent/'MANIFEST.json')),indent=2))
