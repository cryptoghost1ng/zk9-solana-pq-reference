"""Report only observations supported by native shape and constraint tests."""
import hashlib,json,pathlib,re,sys
assert __debug__
W=pathlib.Path(__file__).resolve().parent
label=sys.argv[1];assert re.fullmatch(r'shape-[0-9]{2}',label)
R=W/'evidence'/label
read=lambda name:json.loads((R/name).read_text())
a=read('profile-01.json');assert a==read('profile-02.json')
assert a['status']=='MEASURED_AIR_SHAPE_ONLY' and len(a['bindings'])==6
assert not a['proof_generated'] and not a['equivalent_security_proven'] and not a['production_ready']
assert a['height']>0 and a['blocks']>0
assert a['candidate']['max_degree']<=9,'Candidate no longer fits the unchanged blowup bound'
before=read('environment-before.json');assert before==read('environment-after.json')
for name,digest in before['source_pins'].items():
    assert hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest()==digest,name
tests=(R/'tests.stdout').read_text()
for name in ['every_consumer_and_producer_retains_its_exact_logical_owner',
             'valid_trace_and_all_public_digest_limbs_at_each_producer',
             'zero_second_input_relaxes_only_second_root']:
    assert re.search(r'(?m)^test '+name+r' \.\.\. ok$',tests),name
assert '3 passed; 0 failed; 0 ignored' in tests
assert 'test result: FAILED' not in tests
result=dict(status='PASS_NATIVE_SHAPE_AND_CONSTRAINT_CHECKS',profile=a,
    width_reduction=a['baseline']['width']-a['candidate']['width'],
    max_degree_change=a['candidate']['max_degree']-a['baseline']['max_degree'],
    proof_size_measured=False,proof_time_measured=False,sbf_compute_measured=False,
    security_equivalence_proven=False,production_ready=False)
with (R/'summary.json').open('x') as f:json.dump(result,f,indent=2);f.write('\n')
print(json.dumps(result,indent=2))
