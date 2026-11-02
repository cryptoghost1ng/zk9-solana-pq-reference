"""Recheck the retained shape experiment without rewriting its evidence."""
import hashlib,json,pathlib,re,sys
assert __debug__
W=pathlib.Path(__file__).resolve().parent
R=W/'evidence/shape-01'
def read(p):return json.loads(p.read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
env=read(R/'environment-before.json');assert env==read(R/'environment-after.json')
metadata=read(R/'metadata.json')
own=next(p for p in metadata['packages'] if p['name']=='zk9-public-bind-liveness-lab')
original=pathlib.Path(own['manifest_path']).parent
for name,digest in env['source_pins'].items():
    p=pathlib.Path(name)
    if p.is_relative_to(original):
        p=W/p.relative_to(original)
        if p.name=='README.txt' and (W/'SOURCE-DRAFT-README.txt').exists():p=W/'SOURCE-DRAFT-README.txt'
    assert sha(p)==digest,name
a=read(R/'profile-01.json');assert a==read(R/'profile-02.json')
assert a['baseline']==dict(constraints=56105,max_degree=6,registers=6472,width=10406)
assert a['candidate']==dict(constraints=50343,max_degree=6,registers=3591,width=7525)
assert (a['height'],a['blocks'])==(4096,148)
assert len(a['bindings'])==6 and sum(x['second_input'] for x in a['bindings'])==1
assert not any(a[k] for k in ['proof_generated','equivalent_security_proven','production_ready'])
s=read(R/'summary.json')
assert s['status']=='PASS_NATIVE_SHAPE_AND_CONSTRAINT_CHECKS' and s['profile']==a
assert s['width_reduction']==2881 and s['max_degree_change']==0
assert not any(s[k] for k in ['proof_size_measured','proof_time_measured','sbf_compute_measured','security_equivalence_proven','production_ready'])
tests=(R/'tests.stdout').read_text()
for name in ['every_consumer_and_producer_retains_its_exact_logical_owner',
             'valid_trace_and_all_public_digest_limbs_at_each_producer',
             'zero_second_input_relaxes_only_second_root']:
    assert re.search(r'(?m)^test '+name+r' \.\.\. ok$',tests),name
assert '3 passed; 0 failed; 0 ignored' in tests and 'test result: FAILED' not in tests
assert 'Finished `release`' in (R/'build.stderr').read_text()
assert (W/'evidence/shape-01-driver.stderr').read_bytes()==b''
parent=pathlib.Path(env['parent']['parent'])
assert sha(parent/'MANIFEST.json')==env['parent']['manifest_sha256']=='f3577bc757da5e517ce2ca9989a29fe847c68e1d457cf106b7580e06d16df644'
for name,digest in read(parent/'MANIFEST.json')['sha256'].items():assert sha(parent/name)==digest,name
if (W/'MANIFEST.json').exists():
    for name,digest in read(W/'MANIFEST.json')['sha256'].items():assert sha(W/name)==digest,name
print(json.dumps(dict(status='PASS_SHAPE_EXPERIMENT_ONLY',profiles=2,tests=3,
    width_before=10406,width_after=7525,width_reduction_percent=2881/10406*100,
    max_degree_before=6,max_degree_after=6,proof_benchmark=False,production_ready=False),indent=2))
