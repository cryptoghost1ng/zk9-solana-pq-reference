"""Serial qualification of the WINDOWED publication revision. Pins every input, preserves failures, writes a NEW evidence directory and verifies, from evidence that
already exists: (1) the model checks passed, (2) the mutation control detected every mutation, (3) the real-process runs of the windowed relay (validator with the real
programs, local Tor with two onion services, Chrome 156 disposable profiles) passed all their checks with the same pinned inputs the revision has now, and (4) the frozen
sources it derives from are byte-identical and nothing was registered in the user's browser. It proves nothing about privacy or anonymity.
usage: qualify.py windowed-qualification-NN CHECKS MUTATION RUN [RUN ...]     (e.g. checks-02 mutation-03 smoke-07 full-05)
Every RUN is the label of a run_payment_v4.py evidence directory: smoke-NN (PASS_ONION_PAYMENT_SMOKE) or full-NN (PASS_ONION_PAYMENT_FULL)."""
import hashlib,json,os,re,shutil,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent;WORK=ROOT.parent;E2E=WORK/'solana-onion-e2e-v1'
sys.path[:0]=[str(WORK/'solana-chrome-wallet-v1')]
from offline_guard import acquire
assert len(sys.argv)>=5 and re.fullmatch(r'windowed-qualification-[0-9]+',sys.argv[1]) and re.fullmatch(r'checks-[0-9]+',sys.argv[2]) and re.fullmatch(r'mutation-[0-9]+',sys.argv[3])
runs=sys.argv[4:];assert all(re.fullmatch(r'(smoke|full)-[0-9]+',r) for r in runs)
lock=acquire();out=ROOT/'evidence'/sys.argv[1];out.mkdir(parents=True,exist_ok=False)
HOME=Path.home();HOST_DIRS=[HOME/'Library/Application Support/Google/Chrome/NativeMessagingHosts',Path('/Library/Google/Chrome/NativeMessagingHosts'),HOME/'Library/Application Support/Chromium/NativeMessagingHosts']
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
read=lambda p:json.loads(Path(p).read_text())
listing=lambda d:sorted((e.name,e.stat(follow_symlinks=False).st_size,e.stat(follow_symlinks=False).st_mtime_ns) for e in os.scandir(d)) if Path(d).is_dir() else None
before={str(d):listing(d) for d in HOST_DIRS}
checks=read(ROOT/'evidence'/sys.argv[2]/'RESULT.json');assert checks['status']=='PASS_WINDOWED_PUBLICATION_CHECKS' and checks['tests']==checks['passed'] and checks['failed']==0
mutation=read(ROOT/'evidence'/sys.argv[3]/'MUTATION.json');assert mutation['all_detected'] is True and not mutation['undetected'] and mutation['count']>=70
results={r:read(E2E/'evidence'/r/'RESULT.json') for r in runs}
for label,result in results.items():
    expected='PASS_ONION_PAYMENT_SMOKE' if label.startswith('smoke') else 'PASS_ONION_PAYMENT_FULL'
    assert result['status']==expected and result['error'] is None and all(result['checks'].values()),'%s did not pass: %s'%(label,result['status'])
    assert result['steps'].get('relay_window')==64,'%s was not run with the windowed relay'%label
# Every run must have used these exact sources: the pins of its INPUTS.json for this revision's files equal the files now.
mine=[str(p) for p in ROOT.glob('*.mjs')]+[str(ROOT/'mutation_control.py'),str(WORK/'solana-onion-relay-service-v2/serve.mjs')]
stale={}
for label in runs:
    pins=read(E2E/'evidence'/label/'INPUTS.json')
    missing=[p for p in mine if p not in pins];assert not missing,'%s did not pin %s'%(label,missing)
    stale[label]=[p for p in mine if sha(p)!=pins[p]]
    stale[label]+=[p for p,h in pins.items() if '/Google Chrome' not in p and p not in mine and Path(p).exists() and sha(p)!=h]
assert not any(stale.values()),'sources changed since the runs: %s'%stale
# The model checks pinned every input they used, the five frozen sources included (with the hashes they had when this revision was started): none may differ now.
checks_pins=read(ROOT/'evidence'/sys.argv[2]/'INPUTS.json')
drift=[p for p,h in checks_pins.items() if Path(p).exists() and sha(p)!=h];assert not drift,'inputs of the model checks changed since they ran: %s'%drift
FROZEN=('solana-private-relay-v1/relay-publication.mjs','solana-private-relay-v1/relay-repository.mjs','solana-private-relay-v1/relay-funding.mjs','solana-private-relay-v1/relay-task.mjs','solana-unified-wallet-v1/recovery/publication-sender.mjs')
frozen_unchanged=all(str(WORK/n) in checks_pins and sha(WORK/n)==checks_pins[str(WORK/n)] for n in FROZEN)
def window_facts(label):
    steps=results[label]['steps'];send=steps['send'];facts={'relay_window':steps['relay_window'],'send_relay_journal':steps.get('relay_journal_after_send')}
    facts['send_sponsor_signatures_at_kill']=(send.get('restart') or {}).get('sponsor_signatures_at_kill')
    facts['send_seconds']=send.get('seconds');facts['send_prove_seconds']=send.get('prove_seconds')
    if 'withdraw' in steps and isinstance(steps['withdraw'],dict) and 'seconds' in steps['withdraw']:
        facts['withdraw_seconds']=steps['withdraw']['seconds'];facts['withdraw_relay_journal']=steps.get('relay_journal_after_withdraw')
    facts['sponsor_cost']=steps.get('sponsor_cost');return facts
after={str(d):listing(d) for d in HOST_DIRS}
names={row[0] for rows in after.values() for row in (rows or [])}
ok=before==after and not names&{'com.zk9.onion_history_c1.json','com.zk9.onion_relay_c1.json'} and frozen_unchanged
settled=any(l.startswith('full') for l in runs)
report={'status':'PASS_WINDOWED_RELAY_QUALIFICATION' if ok else 'FAIL_WINDOWED_RELAY_QUALIFICATION',
        'model_checks':{'evidence':'evidence/'+sys.argv[2],'tests':checks['tests'],'passed':checks['passed']},
        'mutations':{'evidence':'evidence/'+sys.argv[3],'count':mutation['count'],'all_detected':True},
        'real_process_runs':{label:{'status':results[label]['status'],'checks_passed':sum(results[label]['checks'].values()),'chrome':results[label]['chrome'],'facts':window_facts(label)} for label in runs},
        'inputs_unchanged_since_the_runs':True,'frozen_sources_byte_identical':frozen_unchanged,'browser_host_directories_unchanged':before==after,
        'private_payment_settled':settled,'withdrawal':any(l.startswith('full') for l in runs),
        'synthetic_values':True,'loaded_in_the_users_chrome':False,'native_host_registered':False,'installed':False,
        'public_fixture_seeds':True,'real_funds':False,'real_tor':False,'independent_operator':False,'privacy_proven':False,'mainnet':False,
        'scope':('The windowed publication revision (journal v2, funded repository v2, funding quote v2, windowed sender, task and service wiring) qualified by %d model checks, %d mutants and %d real-process run(s) of '
                 'the whole local stack. %s It does NOT show that the windows behave on a public cluster, and it changes nothing about the cryptography.')%(checks['tests'],mutation['count'],len(runs),
                 'A settled private send and public withdrawal are shown by the full run(s).' if settled else 'The smoke run(s) stop while the sponsored send is still being published, so a settled payment is NOT shown by this record.')}
(out/'RESULT.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:report[k] for k in ('status','private_payment_settled','browser_host_directories_unchanged','frozen_sources_byte_identical')}));sys.exit(0 if ok else 1)
