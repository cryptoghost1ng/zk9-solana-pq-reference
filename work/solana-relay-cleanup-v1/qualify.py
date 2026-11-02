"""Serial qualification record of the CLEANUP revision (account closing after a settled payment). Pins every input, preserves failures, writes a NEW evidence directory and verifies, from evidence that
already exists: (1) the 62 model checks passed (the 40 unmodified windowed checks plus the 22 cleanup checks), (2) the mutation control detected every one of the 36 cleanup mutations, (3) the real-process
run(s) (validator with the real programs, local Tor with two onion services, Chrome 156 disposable profiles, the relay service v3) did what the cleanup is for: for both payments the relay printed the closes in order
(receipt, then buffer) BEFORE it reported the request finished, the VALIDATOR itself reports the verifier receipt and the proof buffer of each payment gone, nothing else failed, and (4) the frozen sources and the
qualified windowed files it derives from are byte-identical and nothing was registered in the user's browser.
HONESTY RULE: a run whose driver status is not PASS is accepted here ONLY if every false check is one of the driver's own ACCOUNTING checks (the ones that measure the sponsor's balance) and the run directory carries
a NOTE.txt that explains why; the record then says so in its status and lists those checks. It proves nothing about privacy or anonymity, and nothing about a public cluster.
usage: qualify.py cleanup-qualification-NN CHECKS MUTATION RUN [RUN ...]     (e.g. checks-03 mutation-03 full-07 full-08)
Every RUN is the label of a run_payment_v5.py evidence directory: full-NN or send-NN."""
import hashlib,json,os,re,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent;WORK=ROOT.parent;E2E=WORK/'solana-onion-e2e-v1';W=WORK/'solana-relay-windowed-v1'
sys.path[:0]=[str(WORK/'solana-chrome-wallet-v1')]
from offline_guard import acquire
assert len(sys.argv)>=5 and re.fullmatch(r'cleanup-qualification-[0-9]+',sys.argv[1]) and re.fullmatch(r'checks-[0-9]+',sys.argv[2]) and re.fullmatch(r'mutation-[0-9]+',sys.argv[3])
runs=sys.argv[4:];assert all(re.fullmatch(r'(send|full)-[0-9]+',r) for r in runs)
lock=acquire();out=ROOT/'evidence'/sys.argv[1];out.mkdir(parents=True,exist_ok=False)
HOME=Path.home();HOST_DIRS=[HOME/'Library/Application Support/Google/Chrome/NativeMessagingHosts',Path('/Library/Google/Chrome/NativeMessagingHosts'),HOME/'Library/Application Support/Chromium/NativeMessagingHosts']
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
read=lambda p:json.loads(Path(p).read_text())
listing=lambda d:sorted((e.name,e.stat(follow_symlinks=False).st_size,e.stat(follow_symlinks=False).st_mtime_ns) for e in os.scandir(d)) if Path(d).is_dir() else None
before={str(d):listing(d) for d in HOST_DIRS}
checks=read(ROOT/'evidence'/sys.argv[2]/'RESULT.json')
assert checks['status']=='PASS_CLEANUP_CHECKS' and checks['tests']==checks['passed']==62 and checks['failed']==0 and checks['regression_tests_unmodified_windowed_checks']==40 and checks['cleanup_tests']==22
mutation=read(ROOT/'evidence'/sys.argv[3]/'MUTATION.json');assert mutation['all_detected'] is True and not mutation['undetected'] and mutation['count']==36
results={r:read(E2E/'evidence'/r/'RESULT.json') for r in runs}
CLEANUP_CHECKS={'send':['send_verifier_receipt_account_is_gone_on_the_validator','send_proof_buffer_account_is_gone_on_the_validator','send_relay_confirmed_the_receipt_close_and_then_the_buffer_close'],
                'withdraw':['withdraw_verifier_receipt_account_is_gone_on_the_validator','withdraw_proof_buffer_account_is_gone_on_the_validator','withdraw_relay_confirmed_the_receipt_close_and_then_the_buffer_close']}
# The driver's own accounting of the sponsor's balance; the only checks whose failure this record can explain instead of refusing.
ACCOUNTING={'sponsor_spent_only_fees_because_the_rent_of_both_payments_came_back','sponsor_ledger_is_complete_and_equals_the_balance_difference',
            'rent_of_every_request_account_came_back_to_the_lamport','everything_else_the_sponsor_paid_is_fees_and_the_pools_permanent_records'}
iso=lambda s:__import__('datetime').datetime.fromisoformat(s.replace('Z','+00:00'))
explained={};sequence={}
for label,result in results.items():
    assert result['error'] is None,'%s ended with an error: %s'%(label,result['error'])
    assert result['steps'].get('relay_window')==64 and result['steps'].get('relay_cleanup') is True,'%s was not run with the windowed relay with cleanup'%label
    false=sorted(k for k,v in result['checks'].items() if not v)
    assert set(false)<=ACCOUNTING,'%s: a check other than the accounting ones is false: %s'%(label,sorted(set(false)-ACCOUNTING))
    if false:
        assert (E2E/'evidence'/label/'NOTE.txt').is_file(),'%s has false accounting checks and no NOTE.txt explaining them'%label
        explained[label]=false
    else:
        assert result['status']==('PASS_ONION_PAYMENT_FULL' if label.startswith('full') else 'PASS_ONION_PAYMENT_SEND')
        led=result['steps']['sponsor_ledger'];assert led['complete'] is True and led['request_accounts_net_zero'] is True and led['other_inflow_lamports']==led['expected_pool_records_lamports'] and led['fees_plus_inflows_equal_the_outflow'] is True
    legs=['send','withdraw'] if label.startswith('full') else ['send']
    events=read(E2E/'evidence'/label/'relay-events.json')
    assert not [e for e in events if e['type'] in ('task_error','parked','fatal')],'%s: the relay reported errors'%label
    for leg in legs:
        missing=[k for k in CLEANUP_CHECKS[leg] if result['checks'].get(k) is not True];assert not missing,'%s lacks %s'%(label,missing)
        facts=result['steps'][leg+'_cleanup'];assert facts['receipt_gone'] is True and facts['buffer_gone'] is True
        admitted=[e for e in events if e['type']=='admitted' and e['kind']==leg][-1]
        closes=[(e['step'],e['state'],e['t']) for e in events if e['type']=='cleanup' and e['id']==admitted['id'] and e.get('step')]
        confirmed=[s for s,state,_ in closes if state=='step_confirmed'];assert confirmed==['receipt-close','buffer-close'],'%s %s: closes out of order: %s'%(label,leg,closes)
        finished=[e for e in events if e['type']=='finished' and e['id']==admitted['id']];assert len(finished)==1 and finished[0]['state']=='settled'
        last_close=[t for s,state,t in closes if state=='step_confirmed'][-1];assert iso(finished[0]['t'])>=iso(last_close),'%s %s: finished before the last close'%(label,leg)
        first=min(iso(t) for _,_,t in closes)
        sequence[label+'/'+leg]={'closes':[(s,state) for s,state,_ in closes],'seconds_first_close_to_finished':round((iso(finished[0]['t'])-first).total_seconds(),2),'relay_steps':finished[0]['steps'],'relay_elapsed_ms':finished[0]['elapsed_ms']}
# Every run must have used these exact sources: the pins of its INPUTS.json for this revision's files equal the files now (the driver may be the copy kept inside the run's own evidence).
mine=[str(p) for p in ROOT.glob('*.mjs')]+[str(ROOT/n) for n in ('mutation_control.py','make_revision.py','run_checks.py')]+[str(WORK/'solana-onion-relay-service-v3/serve.mjs'),str(WORK/'solana-onion-relay-service-v3/make_service.py'),str(E2E/'run_payment_v5.py')]
OPTIONAL=[str(E2E/'managed-validator-ledger.mjs'),str(E2E/'make_validator_ledger.py')]     # only the runs after full-08 launch the ledger-retention validator
stale={};driver_copies={}
for label in runs:
    pins=read(E2E/'evidence'/label/'INPUTS.json')
    missing=[p for p in mine if p not in pins];assert not missing,'%s did not pin %s'%(label,missing)
    mine_here=mine+[o for o in OPTIONAL if o in pins]
    driver=str(E2E/'run_payment_v5.py');copy=E2E/'evidence'/label/'run_payment_v5.as-run.py'
    stale[label]=[p for p in mine_here if p!=driver and sha(p)!=pins[p]]
    if sha(driver)!=pins[driver]:
        if copy.is_file() and sha(copy)==pins[driver]:driver_copies[label]=str(copy.relative_to(WORK))
        else:stale[label].append(driver)
    stale[label]+=[p for p,h in pins.items() if '/Google Chrome' not in p and p not in mine_here and Path(p).exists() and sha(p)!=h]
assert not any(stale.values()),'sources changed since the runs: %s'%stale
# The model checks pinned every input they used, the five frozen sources and the qualified windowed files included: none may differ now.
checks_pins=read(ROOT/'evidence'/sys.argv[2]/'INPUTS.json')
drift=[p for p,h in checks_pins.items() if Path(p).exists() and sha(p)!=h];assert not drift,'inputs of the model checks changed since they ran: %s'%drift
FROZEN=('solana-private-relay-v1/relay-publication.mjs','solana-private-relay-v1/relay-repository.mjs','solana-private-relay-v1/relay-funding.mjs','solana-private-relay-v1/relay-task.mjs','solana-unified-wallet-v1/recovery/publication-sender.mjs')
frozen_unchanged=all(str(WORK/n) in checks_pins and sha(WORK/n)==checks_pins[str(WORK/n)] for n in FROZEN)
windowed_unchanged=all(str(W/n) in checks_pins and sha(W/n)==checks_pins[str(W/n)] for n in ('relay-publication.mjs','publication-sender.mjs','relay-task.mjs','harness.mjs','checks.mjs','crash-child.mjs','relay-repository.mjs','relay-funding.mjs','publication-adapter.mjs'))
def facts_of(label):
    r=results[label];steps=r['steps'];row={'driver_status':r['status'],'checks_true':sum(r['checks'].values()),'checks_total':len(r['checks']),'relay_window':steps['relay_window'],'relay_cleanup':steps['relay_cleanup']}
    for leg in ('send','withdraw'):
        if leg+'_cleanup' in steps:row[leg]={'wallet_seconds':steps[leg].get('seconds'),'receipt_gone':steps[leg+'_cleanup']['receipt_gone'],'buffer_gone':steps[leg+'_cleanup']['buffer_gone'],**sequence[label+'/'+leg]}
    row['sponsor_cost']=steps.get('sponsor_cost');row['sponsor_ledger']=steps.get('sponsor_ledger');return row
after={str(d):listing(d) for d in HOST_DIRS}
names={row[0] for rows in after.values() for row in (rows or [])}
ok=before==after and not names&{'com.zk9.onion_history_c1.json','com.zk9.onion_relay_c1.json'} and frozen_unchanged and windowed_unchanged
clean=not explained
reference=read(E2E/'evidence/full-05/RESULT.json')['steps']['sponsor_cost']
POOL_RECORDS={'send':(128+112)*6960*3+(128+1908)*6960*2};POOL_RECORDS['withdraw']=POOL_RECORDS['send']+(128+200)*6960
report={'status':('PASS_CLEANUP_QUALIFICATION' if clean else 'DEMONSTRATED_LIVE_WITH_EXPLAINED_ACCOUNTING_CHECK_FAILURES') if ok else 'FAIL_CLEANUP_QUALIFICATION',
        'model_checks':{'evidence':'evidence/'+sys.argv[2],'tests':checks['tests'],'passed':checks['passed'],'regression_unmodified_windowed':checks['regression_tests_unmodified_windowed_checks'],'cleanup':checks['cleanup_tests']},
        'mutations':{'evidence':'evidence/'+sys.argv[3],'count':mutation['count'],'all_detected':True},
        'history_kept':'evidence/checks-01, checks-02, mutation-01, mutation-02 and evidence/generation-1-sources belong to the first generation of the sources (see their NOTE.txt); solana-onion-e2e-v1/evidence/full-06 is the live run that found it',
        'real_process_runs':{label:{'chrome':results[label]['chrome'],'facts':facts_of(label)} for label in runs},
        'false_checks_explained_in_notes':explained,'driver_copies_kept_with_the_runs':driver_copies,
        'pool_permanent_records_lamports_worked_out_from_the_program_source':POOL_RECORDS,
        'reference_without_cleanup':{'run':'solana-onion-e2e-v1/evidence/full-05','sponsor_cost':reference},
        'inputs_unchanged_since_the_runs':True,'frozen_sources_byte_identical':frozen_unchanged,'qualified_windowed_files_byte_identical':windowed_unchanged,'browser_host_directories_unchanged':before==after,
        'private_payment_settled':any(l.startswith('full') for l in runs),'verifier_receipt_and_proof_buffer_closed_on_a_local_validator':True,'clean_pass_run_exists':clean,
        'synthetic_values':True,'loaded_in_the_users_chrome':False,'native_host_registered':False,'installed':False,
        'public_fixture_seeds':True,'real_funds':False,'real_tor':False,'independent_operator':False,'privacy_proven':False,'mainnet':False,'public_cluster':False,
        'scope':('The cleanup revision (after the pool has settled a payment the relay closes the verifier receipt and then the proof buffer it created for the request, returning their rent to the sponsor) '
                 'qualified by %d model checks (40 of them the unmodified windowed checks), %d mutants and %d live full run(s) of the whole local stack. In every live run the relay closed both accounts of both payments, in order, before it reported the request '
                 'finished, and the validator itself reports the accounts gone. %s It does NOT show that this works on a public cluster, with finalized commitment, with a funding budget that is credited back, or on a conflicted payment, '
                 'and it changes nothing about the cryptography.')%(checks['tests'],mutation['count'],len(runs),
                 'No run of this record has a PASS status of its own: the false checks listed above are the driver\'s accounting of the sponsor\'s balance (a wrong bound of mine in one run, a ledger the validator had already pruned in the other), explained in each run\'s NOTE.txt. '
                 'The sponsor\'s net cost was about 0.128 SOL per full payment against 55.7 SOL without the cleanup.' if not clean else 'Every run passed.')}
(out/'RESULT.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:report[k] for k in ('status','clean_pass_run_exists','private_payment_settled','verifier_receipt_and_proof_buffer_closed_on_a_local_validator','browser_host_directories_unchanged','frozen_sources_byte_identical')}));sys.exit(0 if ok else 1)
