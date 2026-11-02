"""Qualification of the REPEATED private-payment run. Two full runs (private send of 10 + public withdrawal of 1, settled by the relay service behind a real
local Tor onion, proofs generated inside disposable Chrome 156 profiles) were made with the SAME pinned input bytes; each one has its own payment-qualification record.
This record checks that both passed, that they really pinned identical inputs, that they are two different instances (not a copy), that the package differs ONLY
where it must (the sponsor key, the extension key and the validator profile; the allowed set was written before the second run finished), and that every outcome that
must be deterministic is identical. Timings and counts that depend on the chain and on Tor are reported side by side, not asserted. It proves nothing about privacy or
anonymity, and two passes are two passes, not a statistical guarantee.
usage: python3 -B qualify_payment_pair.py payment-pair-qualification-NN payment-qualification-A payment-qualification-B
Do NOT run it with the Python of the Chutney venv: the leftover-process check looks for "chutney" in the process list and would match this very process
(this is how evidence/payment-qualification-02 failed, see its NOTE.txt)."""
import hashlib,json,os,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent;WORK=ROOT.parent;EV=ROOT/'evidence'
sys.path[:0]=[str(WORK/'solana-chrome-wallet-v1')]
from offline_guard import acquire
assert len(sys.argv)==4 and re.fullmatch(r'payment-pair-qualification-[0-9]+',sys.argv[1]) and all(re.fullmatch(r'payment-qualification-[0-9]+',a) for a in sys.argv[2:]) and sys.argv[2]!=sys.argv[3]
lock=acquire();out=EV/sys.argv[1];out.mkdir(parents=True,exist_ok=False)
HOME=Path.home();HOST_DIRS=[HOME/'Library/Application Support/Google/Chrome/NativeMessagingHosts',Path('/Library/Google/Chrome/NativeMessagingHosts'),HOME/'Library/Application Support/Chromium/NativeMessagingHosts']
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
read=lambda p:json.loads(Path(p).read_text())
listing=lambda d:sorted((e.name,e.stat(follow_symlinks=False).st_size,e.stat(follow_symlinks=False).st_mtime_ns) for e in os.scandir(d)) if Path(d).is_dir() else None
before={str(d):listing(d) for d in HOST_DIRS}
# Written before the second run finished: what a package may differ in between two runs (sponsor authority in config.mjs, extension key in manifest.json, validator profile in the flow config).
ALLOWED_PACKAGE_DIFFERENCES={'config.mjs','manifest.json','INSTALLED-FLOW-CONFIG.json'}
quals=[read(EV/n/'RESULT.json') for n in sys.argv[2:]]
assert all(q['status']=='PASS_ONION_PRIVATE_PAYMENT_FULL_ONE_RUN' and q['inputs_unchanged'] and q['browser_host_directories_unchanged'] for q in quals),'a payment qualification did not pass'
labels=[q['run'] for q in quals];assert labels[0]!=labels[1]
runs=[read(EV/l/'RESULT.json') for l in labels]
assert all(r['status']=='PASS_ONION_PAYMENT_FULL' and r['error'] is None and all(r['checks'].values()) for r in runs),'a full run did not pass'
assert runs[0]['checks'].keys()==runs[1]['checks'].keys()
same_inputs=(EV/labels[0]/'INPUTS.json').read_text()==(EV/labels[1]/'INPUTS.json').read_text()
pins=read(EV/labels[1]/'INPUTS.json')
stale=[p for p,h in pins.items() if '/Google Chrome' not in p and sha(p)!=h]
packages=[read(EV/l/'PACKAGE.json') for l in labels]
differing=sorted(k for k in set(packages[0]['files'])|set(packages[1]['files']) if packages[0]['files'].get(k)!=packages[1]['files'].get(k))
other_keys_equal={k:packages[0][k]==packages[1][k] for k in packages[0] if k not in ('files','base','extension_id','changed')}
# `changed` maps file -> {base_sha256,new_sha256} against the base package: compared file by file, with the same allowed set (evidence/payment-pair-qualification-02/NOTE.txt)
changed_same_files=set(packages[0]['changed'])==set(packages[1]['changed'])
changed_differing=sorted(k for k in set(packages[0]['changed'])|set(packages[1]['changed']) if packages[0]['changed'].get(k)!=packages[1]['changed'].get(k))
progress=[[json.loads(l) for l in (EV/lb/'PROGRESS.jsonl').read_text().splitlines()] for lb in labels]
sponsors=[next(e['sponsor'] for e in p if e['event']=='relay_ready') for p in progress]
operations=[(r['steps']['send']['operation'],r['steps']['withdraw']['operation']) for r in runs]
different_instances=(runs[0]['validator_run']!=runs[1]['validator_run'] and sponsors[0]!=sponsors[1] and runs[0]['extension_id']!=runs[1]['extension_id'] and not set(operations[0])&set(operations[1])
                     and sha(EV/labels[0]/'RESULT.json')!=sha(EV/labels[1]/'RESULT.json'))
pick=lambda q,*path:__import__('functools').reduce(lambda a,k:a[k],path,q)
deterministic={
  'validator_ground_truth':[q['ground_truth_from_the_validator'] for q in quals],
  'wallet_views':[q['wallet_views'] for q in quals],
  'idle_probes':[q['idle_probes'] for q in quals],
  'sponsor_never_the_wallet':[(q['sponsor']['wallet_authority_in_any_sponsor_transaction'],q['sponsor']['recipient_authority_ever_transacted']) for q in quals],
  'final_states':[(q['send']['final_state'],q['withdraw']['final_state']) for q in quals],
  'relay_killed_and_resumed_same_request':[(q['send']['relay_killed_by_SIGKILL_and_resumed_same_request'],q['withdraw']['relay_killed_by_SIGKILL_and_resumed_same_request']) for q in quals],
  'direct_http_requests_from_the_extension':[(q['send']['direct_http_requests_from_the_extension'],q['withdraw']['direct_http_requests_from_the_extension']) for q in quals],
  'relay_events_that_must_not_vary':[{k:q['relay_events'][k] for k in ('admitted','refused','recovered','task_error','parked','finished','fatal')} for q in quals],
}
deterministic_equal={k:v[0]==v[1] for k,v in deterministic.items()}
expected_ok=all(q['ground_truth_from_the_validator']=={'vault_units_after_both':12,'recipient_token_units_after_withdrawal':1} and q['relay_events']['task_error']==0 and q['relay_events']['parked']==0 and q['relay_events']['fatal']==0
                and q['send']['direct_http_requests_from_the_extension']==0 and q['withdraw']['direct_http_requests_from_the_extension']==0 and q['send']['relay_killed_by_SIGKILL_and_resumed_same_request'] and q['withdraw']['relay_killed_by_SIGKILL_and_resumed_same_request']
                and not q['sponsor']['wallet_authority_in_any_sponsor_transaction'] for q in quals)
varies=lambda f:[f(q) for q in quals]
side_by_side={
  'send_seconds':varies(lambda q:q['send']['seconds']),'withdraw_seconds':varies(lambda q:q['withdraw']['seconds']),
  'send_prove_seconds':varies(lambda q:q['send']['prove_seconds_in_the_extension']),'withdraw_prove_seconds':varies(lambda q:q['withdraw']['prove_seconds_in_the_extension']),
  'send_relay_steps':varies(lambda q:q['send']['relay_steps']),'withdraw_relay_steps':varies(lambda q:q['withdraw']['relay_steps']),
  'send_wallet_reopens':varies(lambda q:q['send']['wallet_session_reopened_after_auto_lock']),'withdraw_wallet_reopens':varies(lambda q:q['withdraw']['wallet_session_reopened_after_auto_lock']),
  'sponsor_signatures':varies(lambda q:q['sponsor']['signatures_seen']),'sponsor_lamports_spent_synthetic':varies(lambda q:q['sponsor']['lamports_spent_synthetic']),
  'duplicate_resubmits_answered_200':varies(lambda q:q['relay_events']['duplicate']),'sponsor_signatures_at_kill':varies(lambda q:[q['send']['sponsor_signatures_at_kill'],q['withdraw']['sponsor_signatures_at_kill']]),
}
files=[*[EV/n/'RESULT.json' for n in sys.argv[2:]],*[EV/n/'INPUTS.json' for n in sys.argv[2:]],*[EV/l/f for l in labels for f in ('RESULT.json','INPUTS.json','PACKAGE.json','relay-events.json','PROGRESS.jsonl')],ROOT/'run_payment_v3.py',ROOT/'qualify_payment.py',ROOT/'qualify_payment_pair.py']
local={str(p):sha(p) for p in dict.fromkeys(files)};(out/'INPUTS.json').write_text(json.dumps(local,indent=2)+'\n')
leftover=subprocess.run(['/bin/ps','-axo','pid=,args='],capture_output=True,text=True).stdout
processes=[l for l in leftover.splitlines() if re.search(r'chrome-pay-|solana-test-validator|managed-validator\.mjs|chutney|solana-onion-relay-service-v1/serve\.mjs',l)]
after={str(d):listing(d) for d in HOST_DIRS}
names={row[0] for rows in after.values() for row in (rows or [])}
ok=(same_inputs and not stale and set(differing)<=ALLOWED_PACKAGE_DIFFERENCES and all(other_keys_equal.values()) and changed_same_files and set(changed_differing)<=ALLOWED_PACKAGE_DIFFERENCES and different_instances and all(deterministic_equal.values()) and expected_ok
    and all(sha(p)==h for p,h in local.items()) and before==after and not processes and not names&{'com.zk9.onion_history_c1.json','com.zk9.onion_relay_c1.json'})
report={'status':'PASS_ONION_PRIVATE_PAYMENT_FULL_TWO_IDENTICAL_RUNS' if ok else 'FAIL_ONION_PRIVATE_PAYMENT_FULL_TWO_IDENTICAL_RUNS','runs':labels,'qualifications':sys.argv[2:],'chrome':[q['chrome'] for q in quals],
  'checks_passed':[q['checks_passed'] for q in quals],'pinned_inputs_byte_identical_between_the_runs':same_inputs,'sources_unchanged_since_the_second_run':not stale,
  'package':{'files_that_differ':differing,'allowed_to_differ':sorted(ALLOWED_PACKAGE_DIFFERENCES),'other_fields_equal':other_keys_equal,'changed_against_base':{'same_files':changed_same_files,'entries_that_differ':changed_differing}},
  'two_different_instances':{'validator_runs':[r['validator_run'] for r in runs],'sponsor_authorities_differ':sponsors[0]!=sponsors[1],'extension_ids_differ':runs[0]['extension_id']!=runs[1]['extension_id'],'operation_ids_disjoint':not set(operations[0])&set(operations[1]),'different_instances':different_instances},
  'deterministic_outcomes_equal':deterministic_equal,'deterministic_outcomes':deterministic,'varies_with_chain_and_tor_reported_not_asserted':side_by_side,
  'full_runs_that_passed':2,'identical_repeat_of_the_full_run':same_inputs,
  'inputs_unchanged':all(sha(p)==h for p,h in local.items()),'browser_host_directories_unchanged':before==after,
  'synthetic_values':True,'loaded_in_the_users_chrome':False,'native_host_registered':False,'installed':False,'public_fixture_seeds':True,'real_funds':False,'real_tor':False,
  'independent_operator':False,'privacy_proven':False,
  'scope':'Two local, synthetic, end-to-end runs with identical pinned inputs: real validator programs, local Tor (not public) with two onion services, relay service with its own funded sponsor, disposable Chrome 156 profiles. Each settled a private send of 10 and a public withdrawal of 1 with the relay SIGKILLed once per payment. NOT shown: privacy, anonymity against network or timing observers, independent operators, a public network, long-run service worker behaviour beyond 2 hours, concurrent payments, abuse controls of a public service, an adversarial trial, external review. Two passes on one machine are not a statistical guarantee.'}
(out/'RESULT.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k] for k in ('status','checks_passed','pinned_inputs_byte_identical_between_the_runs','inputs_unchanged','browser_host_directories_unchanged')}));sys.exit(0 if ok else 1)
