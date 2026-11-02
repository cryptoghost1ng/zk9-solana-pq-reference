"""Qualification record of the private-payment run (send of 10 and public withdrawal of 1 through the relay service behind a real local Tor onion).
Pins every input, re-verifies that the run's frozen inputs are unchanged, summarizes the numbers that matter and lists the preserved failures. It does NOT rerun the
2-hour trial: ONE full run passed; a second identical run has not been made. Proves nothing about privacy or anonymity.
usage: qualify_payment.py payment-qualification-NN full-NN"""
import hashlib,json,os,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent;WORK=ROOT.parent
sys.path[:0]=[str(WORK/'solana-chrome-wallet-v1')]
from offline_guard import acquire
assert len(sys.argv)==3 and re.fullmatch(r'payment-qualification-[0-9]+',sys.argv[1]) and re.fullmatch(r'full-[0-9]+',sys.argv[2])
lock=acquire();out=ROOT/'evidence'/sys.argv[1];out.mkdir(parents=True,exist_ok=False)
HOME=Path.home();HOST_DIRS=[HOME/'Library/Application Support/Google/Chrome/NativeMessagingHosts',Path('/Library/Google/Chrome/NativeMessagingHosts'),HOME/'Library/Application Support/Chromium/NativeMessagingHosts']
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
read=lambda p:json.loads(Path(p).read_text())
listing=lambda d:sorted((e.name,e.stat(follow_symlinks=False).st_size,e.stat(follow_symlinks=False).st_mtime_ns) for e in os.scandir(d)) if Path(d).is_dir() else None
before={str(d):listing(d) for d in HOST_DIRS}
run=read(ROOT/'evidence'/sys.argv[2]/'RESULT.json')
assert run['status']=='PASS_ONION_PAYMENT_FULL' and run['error'] is None and all(run['checks'].values()),'the run did not pass'
service=read(WORK/'solana-onion-relay-service-v1/evidence/service-qualification-01/RESULT.json');assert service['status']=='PASS_RELAY_SERVICE_CANDIDATE'
pins=read(ROOT/'evidence'/sys.argv[2]/'INPUTS.json')
stale=[p for p,h in pins.items() if '/Google Chrome' not in p and sha(p)!=h]
assert not stale,'sources changed since the run: %s'%stale
events=read(ROOT/'evidence'/sys.argv[2]/'relay-events.json');s=run['steps']
finished={e['kind']:e for e in events if e['type']=='finished'}
def leg(kind):
    x=s[kind];return {'seconds':x['seconds'],'prove_seconds_in_the_extension':x['prove_seconds'],'relay_steps':finished[kind]['steps'],'relay_seconds':round(finished[kind]['elapsed_ms']/1000,1),
        'wallet_session_reopened_after_auto_lock':len(x['locks']),'relay_killed_by_SIGKILL_and_resumed_same_request':x['restart']['resumed'],'sponsor_signatures_at_kill':x['restart']['sponsor_signatures_at_kill'],
        'direct_http_requests_from_the_extension':len(x['direct_http_during_leg']),'final_state':x['final_state']}
paths=[ROOT/'evidence'/sys.argv[2]/n for n in ('RESULT.json','INPUTS.json','relay-events.json','PACKAGE.json')]+[ROOT/'run_payment_v3.py',ROOT/'qualify_payment.py']
local={str(p):sha(p) for p in paths};(out/'INPUTS.json').write_text(json.dumps(local,indent=2)+'\n')
leftover=subprocess.run(['/bin/ps','-axo','pid=,args='],capture_output=True,text=True).stdout
processes=[l for l in leftover.splitlines() if re.search(r'chrome-pay-|solana-test-validator|managed-validator\.mjs|chutney',l)]
after={str(d):listing(d) for d in HOST_DIRS}
names={row[0] for rows in after.values() for row in (rows or [])}
ok=all(sha(p)==h for p,h in local.items()) and before==after and not processes and not names&{'com.zk9.onion_history_c1.json','com.zk9.onion_relay_c1.json'}
report={'status':'PASS_ONION_PRIVATE_PAYMENT_FULL_ONE_RUN' if ok else 'FAIL_ONION_PRIVATE_PAYMENT_FULL_ONE_RUN','run':sys.argv[2],'checks_passed':sum(run['checks'].values()),'chrome':run['chrome'],
  'send':leg('send'),'withdraw':leg('withdraw'),
  'ground_truth_from_the_validator':{'vault_units_after_both':s['ground_truth_final']['vault_units'],'recipient_token_units_after_withdrawal':s['ground_truth_final']['recipient_token_units']},
  'wallet_views':{'sender_after_deposit':s['sender_sync_after_deposit']['spendable_units'],'sender_after_send':s['sender_sync_after_send']['spendable_units'],'recipient_restored_from_words_after_send':s['recipient_sync_after_send']['spendable_units'],'sender_after_withdrawal':s['sender_sync_after_withdraw']['spendable_units']},
  'sponsor':{'signatures_seen':s['sponsor_cost']['sponsor_signatures'],'lamports_spent_synthetic':s['sponsor_cost']['lamports_spent'],'wallet_authority_in_any_sponsor_transaction':bool(s['withdraw_authority_check']['overlap']),'recipient_authority_ever_transacted':False},
  'relay_events':s['relay_event_counts'],'idle_probes':{k:s['idle_probes_after_send'][k] for k in ('duplicate','tampered','status_route')},
  'preserved_failures':{'full-01':'harness read the wallet 5-minute auto-lock as a lost operation (stopped at 7 min)','full-02':'harness sampler died on a validator RPC error object at 25 min','smoke-01':'Chutney onion-service tag','smoke-02':'mis-scoped network window'},
  'full_runs_that_passed':1,'identical_repeat_of_the_full_run':False,
  'inputs_unchanged':all(sha(p)==h for p,h in local.items()),'browser_host_directories_unchanged':before==after,
  'synthetic_values':True,'loaded_in_the_users_chrome':False,'native_host_registered':False,'installed':False,'public_fixture_seeds':True,'real_funds':False,'real_tor':False,
  'independent_operator':False,'privacy_proven':False,
  'scope':'One local, synthetic, end-to-end run: real validator programs, local Tor (not public) with two onion services, relay service with its own funded sponsor, disposable Chrome 156 profiles with the onion-routed package naming the real sponsor. A private send of 10 and a public withdrawal of 1 settled; both proofs were generated inside the extension; the relay was SIGKILLed once per payment and resumed. NOT shown: privacy, anonymity against network or timing observers, independent operators, a public network, a repeat run, long-run service worker behaviour beyond 2 hours, abuse controls of a public service.'}
(out/'RESULT.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k] for k in ('status','checks_passed','inputs_unchanged','browser_host_directories_unchanged')}));sys.exit(0 if ok else 1)
