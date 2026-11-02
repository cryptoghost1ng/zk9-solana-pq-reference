"""Generates run_payment_v5.py from the qualified run_payment_v4.py by exact-match patches (each asserted to match exactly once), so the whole difference is this file.
v5 = v4 unchanged except: the relay service it launches is solana-onion-relay-service-v3 (cleanup), its gates and pins name the cleanup revision's evidence, and after each
settled payment it asks the VALIDATOR whether the verifier receipt and the proof buffer of that request are gone, and at the end whether the sponsor spent only fees.
usage: make_run_payment_v5.py (once; refuses to overwrite)"""
import difflib
from pathlib import Path
HERE=Path(__file__).resolve().parent
SRC=HERE/'run_payment_v4.py';OUT=HERE/'run_payment_v5.py'
assert not OUT.exists(),'refusing to overwrite run_payment_v5.py'
text=SRC.read_text()
HELPERS = '''    def account_gone(address):
        """Ground truth from the validator itself, never from the relay: an account that was closed has no data and no lamports."""
        return validator_rpc('getAccountInfo',[address,{'commitment':'confirmed','encoding':'base64'}])['value'] is None
    def cleanup_facts(kind):
        """What the validator says about the two accounts the relay created for this request, and the closes the relay says it confirmed."""
        admitted=[e for e in relay.of('admitted') if e['kind']==kind][-1];transport=admitted['transport']
        events=[(e.get('step'),e['state']) for e in relay.of('cleanup') if e['id']==admitted['id']]
        return {'receipt':transport['receipt'],'buffer':transport['source'],'receipt_gone':account_gone(transport['receipt']),'buffer_gone':account_gone(transport['source']),'cleanup_events':events}
    def cleanup_checks_for(kind,facts):
        confirmed=[step for step,state in facts['cleanup_events'] if state=='step_confirmed']
        return {'%s_verifier_receipt_account_is_gone_on_the_validator'%kind:facts['receipt_gone'] is True,
                '%s_proof_buffer_account_is_gone_on_the_validator'%kind:facts['buffer_gone'] is True,
                '%s_relay_confirmed_the_receipt_close_and_then_the_buffer_close'%kind:confirmed==['receipt-close','buffer-close']}
    # Permanent records the pool program allocates at every settlement, paid by the fee payer (work/solana-beta-withdraw-v1/pool/src/spend.rs and withdraw.rs); rent = (128 + size) * 6960.
    # send: 2 nullifier records + 2 note records + 1 root record; withdrawal: the same plus the 200-byte withdrawal record. Sizes: nullifier and root 112; note 176 + the 1732-byte packet = 1908.
    # Worked out from the program source BEFORE the run that tests it (full-07 had shown a residual of this size and no explanation).
    POOL_RECORD_RENT={'send':(128+112)*6960*3+(128+1908)*6960*2}
    POOL_RECORD_RENT['withdraw']=POOL_RECORD_RENT['send']+(128+200)*6960
    def sponsor_ledger(spent,request_accounts):
        """Ground truth from the validator's own ledger: every transaction the sponsor paid for (fee payer = first account key), summed from the balance changes of its accounts."""
        sample();signatures=set(sponsor_watch.seen);before=None
        while True:   # one complete listing at the end, in case the watcher missed a few between its polls
            options={'limit':1000,'commitment':'confirmed'}
            if before:options['before']=before
            page=validator_rpc('getSignaturesForAddress',[SPONSOR,options]);signatures.update(r['signature'] for r in page)
            if len(page)<1000:break
            before=page[-1]['signature']
        fees=paid=unavailable=0;positive={};negative={};fee_values={}
        for signature in sorted(signatures):
            if signature not in tx_cache:
                tx=validator_rpc('getTransaction',[signature,{'encoding':'json','maxSupportedTransactionVersion':0,'commitment':'confirmed'}])
                if tx is None:unavailable+=1;continue
                meta=tx['meta'];keys=tx['transaction']['message']['accountKeys'];tx_cache[signature]=(keys[0],meta['fee'],list(zip(keys,meta['preBalances'],meta['postBalances'])))
            payer,fee,balances=tx_cache[signature]
            if payer!=SPONSOR:continue          # the faucet airdrop is paid by the faucet
            paid+=1;fees+=fee;fee_values[fee]=fee_values.get(fee,0)+1
            for key,pre,post in balances:
                if post>pre:positive[key]=positive.get(key,0)+post-pre
                elif post<pre:negative[key]=negative.get(key,0)+pre-post
        net={k:positive.get(k,0)-negative.get(k,0) for k in set(positive)|set(negative)}
        outflow=-net.get(SPONSOR,0);others={k:v for k,v in net.items() if k!=SPONSOR and k not in request_accounts}
        accounts={a:{'deposited_lamports':positive.get(a,0),'refunded_lamports':negative.get(a,0),'net_lamports':net.get(a,0)} for a in request_accounts}
        return {'transactions_listed':len(signatures),'transactions_paid_by_the_sponsor':paid,'transactions_not_available':unavailable,'fees_lamports':fees,'fee_values_lamports':dict(sorted(fee_values.items())),
                'sponsor_net_outflow_lamports':outflow,'balance_difference_lamports':spent,'complete':unavailable==0 and outflow==spent,
                'request_accounts':accounts,'request_accounts_net_zero':len(accounts)>0 and all(v['deposited_lamports']>0 and v['net_lamports']==0 for v in accounts.values()),
                'other_inflow_lamports':sum(others.values()),'fees_plus_inflows_equal_the_outflow':fees+sum(others.values())+sum(v['net_lamports'] for v in accounts.values())==outflow,
                'largest_other_inflows':[[v,k] for v,k in sorted(((v,k) for k,v in others.items()),reverse=True)[:6]]}
'''
PAIRS=[
 ('"""PAYMENT LEGS of the end-to-end onion trial with the WINDOWED relay (v4:',
  '"""PAYMENT LEGS of the end-to-end onion trial with the WINDOWED relay and ACCOUNT CLEANUP (v5: this driver is v4 unchanged except that the relay service it launches is\nsolana-onion-relay-service-v3, which after each settled payment also closes the verifier receipt and the proof buffer so their rent returns to the sponsor (solana-relay-cleanup-v1),\nand that it asks the validator whether those accounts are gone and whether the sponsor spent only fees. v4 stays frozen with evidence/full-05.\nv4:'),
 ('usage: with_free_ports.py run_payment_v4.py smoke-07','usage: with_free_ports.py run_payment_v5.py full-06'),
 ("WINDOWED=WORK/'solana-relay-windowed-v1'\nWINDOWED_MUTATION='mutation-03';WINDOWED_CHECKS='checks-02'\n",
  "WINDOWED=WORK/'solana-relay-windowed-v1';SERVICE3=WORK/'solana-onion-relay-service-v3';CLEANUP=WORK/'solana-relay-cleanup-v1'\nWINDOWED_MUTATION='mutation-03';WINDOWED_CHECKS='checks-02'\nCLEANUP_MUTATION='mutation-03';CLEANUP_CHECKS='checks-03'\n"),
 ('"""The relay service process (solana-onion-relay-service-v2/serve.mjs, the windowed one) and the stream of events it prints."""',
  '"""The relay service process (solana-onion-relay-service-v3/serve.mjs, windowed with account cleanup) and the stream of events it prints."""'),
 ("str(SERVICE2/'serve.mjs'),str(state)","str(SERVICE3/'serve.mjs'),str(state)"),
 ("cwd=SERVICE2,env=","cwd=SERVICE3,env="),
 ("'the windowed revision checks have not passed'\ntor_reference=",
  "'the windowed revision checks have not passed'\n"
  "cleanup_mutation=read(CLEANUP/'evidence'/CLEANUP_MUTATION/'MUTATION.json');assert cleanup_mutation['all_detected'] is True and not cleanup_mutation['undetected'] and cleanup_mutation['count']>=36,'the cleanup revision mutation control has not passed'\n"
  "cleanup_checks=read(CLEANUP/'evidence'/CLEANUP_CHECKS/'RESULT.json');assert cleanup_checks['status']=='PASS_CLEANUP_CHECKS' and cleanup_checks['tests']==cleanup_checks['passed'] and cleanup_checks['failed']==0,'the cleanup revision checks have not passed'\n"
  "tor_reference="),
 ("'run_payment_v4.py','history_service.py')]","'run_payment_v4.py','run_payment_v5.py','history_service.py')]"),
 ("SERVICE2/'serve.mjs',*sorted(WINDOWED.glob('*.mjs')),",
  "SERVICE2/'serve.mjs',SERVICE3/'serve.mjs',SERVICE3/'make_service.py',*sorted(CLEANUP.glob('*.mjs')),CLEANUP/'mutation_control.py',CLEANUP/'make_revision.py',CLEANUP/'run_checks.py',CLEANUP/'evidence'/CLEANUP_MUTATION/'MUTATION.json',CLEANUP/'evidence'/CLEANUP_CHECKS/'RESULT.json',CLEANUP/'evidence'/CLEANUP_CHECKS/'INPUTS.json',*sorted(WINDOWED.glob('*.mjs')),"),
 ("if e['type'] in ('admitted','refused','duplicate','recovered','parked','finished','task_error')]","if e['type'] in ('admitted','refused','duplicate','recovered','parked','finished','task_error','cleanup')]"),
 ("    def wallet_authority_disjoint():\n        sample();overlap=",HELPERS+"    def wallet_authority_disjoint():\n        sample();overlap="),
 ("steps['relay_window']=(relay.of('ready') or [{}])[0].get('window');steps['relay_journal_after_send']=journal_summary()",
  "steps['relay_window']=(relay.of('ready') or [{}])[0].get('window');steps['relay_cleanup']=(relay.of('ready') or [{}])[0].get('cleanup');steps['relay_journal_after_send']=journal_summary()"),
 ("        checks['relay_recorded_the_send_as_settled']=len(finished)==1 and finished[0]['state']=='settled'\n",
  "        checks['relay_recorded_the_send_as_settled']=len(finished)==1 and finished[0]['state']=='settled'\n        steps['send_cleanup']=cleanup_facts('send');checks.update(cleanup_checks_for('send',steps['send_cleanup']))\n"),
 ("        checks['relay_recorded_the_withdrawal_as_settled']=len(finished)==1 and finished[0]['state']=='settled'\n",
  "        checks['relay_recorded_the_withdrawal_as_settled']=len(finished)==1 and finished[0]['state']=='settled'\n        steps['withdraw_cleanup']=cleanup_facts('withdraw');checks.update(cleanup_checks_for('withdraw',steps['withdraw_cleanup']))\n"),
 ("    steps['sponsor_cost']={'lamports_spent':sponsor_start-sponsor_end,'sponsor_signatures':len(sponsor_watch.seen),'note':'synthetic lamports on an isolated validator; not a mainnet cost'}\n",
  "    steps['sponsor_cost']={'lamports_spent':sponsor_start-sponsor_end,'sponsor_signatures':len(sponsor_watch.seen),'note':'synthetic lamports on an isolated validator; not a mainnet cost'}\n"
  "    # evidence/full-05 (windowed relay, no cleanup): 55,721,596,840 lamports spent over 11,828 sponsor signatures. evidence/full-07 (cleanup): 128,437,520; its one failed check was a bound of mine that forgot the pool's permanent records.\n"
  "    try:\n"
  "        steps['sponsor_ledger']=ledger=sponsor_ledger(sponsor_start-sponsor_end,[a for e in relay.of('admitted') for a in (e['transport']['receipt'],e['transport']['source'])])\n"
  "    except Exception as exc:\n"
  "        steps['sponsor_ledger']=ledger={'error':''.join(traceback.format_exception(exc))[-700:]}\n"
  "    if MODE in ('send','full'):\n"
  "        expected_records=POOL_RECORD_RENT['send']+(POOL_RECORD_RENT['withdraw'] if MODE=='full' else 0)\n"
  "        steps['sponsor_ledger']['expected_pool_records_lamports']=expected_records\n"
  "        checks['sponsor_ledger_is_complete_and_equals_the_balance_difference']=ledger.get('complete') is True\n"
  "        checks['rent_of_every_request_account_came_back_to_the_lamport']=ledger.get('request_accounts_net_zero') is True and len(ledger.get('request_accounts',{}))==(4 if MODE=='full' else 2)\n"
  "        checks['everything_else_the_sponsor_paid_is_fees_and_the_pools_permanent_records']=ledger.get('complete') is True and ledger.get('other_inflow_lamports')==expected_records and ledger.get('fees_plus_inflows_equal_the_outflow') is True\n"),
 ("('admitted','refused','duplicate','recovered','progress','task_error','parked','finished','fatal')}","('admitted','refused','duplicate','recovered','progress','task_error','parked','finished','fatal','cleanup')}"),
 ("'private_payment':MODE in ('send','full'),'withdrawal':MODE=='full',","'private_payment':MODE in ('send','full'),'withdrawal':MODE=='full','account_cleanup_shown':MODE in ('send','full'),"),
 # full-08: the validator forgot 11,484 of 11,726 transactions (--limit-ledger-size 10000). Two lines of defence: the validator now keeps its whole ledger, and every new sponsor transaction is read while it is fresh.
 ("    def sample():\n        # The watchers accumulate, so one missed sample costs nothing; a persistent failure shows in sampler_errors and in the final counts.\n        try:\n            a,b=sponsor_watch.poll(),sender_watch.poll();c=recipient_watch.poll() if recipient_watch else None\n        except Exception as exc:\n",
  "    tx_cache={}\n    def harvest():\n        \"\"\"Read each new sponsor transaction while the validator surely still remembers it: (fee payer, fee, [(account, balance before, balance after)]).\"\"\"\n        for signature in sorted(sponsor_watch.seen-set(tx_cache)):\n            tx=validator_rpc('getTransaction',[signature,{'encoding':'json','maxSupportedTransactionVersion':0,'commitment':'confirmed'}])\n            if tx is None:continue\n            meta=tx['meta'];keys=tx['transaction']['message']['accountKeys'];tx_cache[signature]=(keys[0],meta['fee'],list(zip(keys,meta['preBalances'],meta['postBalances'])))\n    def sample():\n        # The watchers accumulate, so one missed sample costs nothing; a persistent failure shows in sampler_errors and in the final counts.\n        try:\n            a,b=sponsor_watch.poll(),sender_watch.poll();c=recipient_watch.poll() if recipient_watch else None\n            harvest()\n        except Exception as exc:\n"),
 ("validator=subprocess.Popen([str(NODE),str(UNIFIED_DIR/'managed-validator.mjs'),str(vout)],","validator=subprocess.Popen([str(NODE),str(ROOT/'managed-validator-ledger.mjs'),str(vout)],"),
 ("UNIFIED_DIR/'managed-validator.mjs',UNIFIED_DIR/'host-lease.mjs',","UNIFIED_DIR/'managed-validator.mjs',ROOT/'managed-validator-ledger.mjs',ROOT/'make_validator_ledger.py',UNIFIED_DIR/'host-lease.mjs',"),
]
new=text
for old,rep in PAIRS:
    assert new.count(old)==1,(old[:90],new.count(old))
    new=new.replace(old,rep)
OUT.write_text(new)
(HERE/'run_payment_v5.py.diff').write_text(''.join(difflib.unified_diff(text.splitlines(True),new.splitlines(True),'run_payment_v4.py','run_payment_v5.py')))
print('written',OUT.name,len(new),'bytes')
