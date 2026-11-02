"""Negative control of the windowed publication revision: each mutation is applied to a COPY of this directory's sources, and the checks selected
for it must fail by a NAMED test. A mutant that does not parse, crashes or hangs is not detection. The real files are never touched.
Takes offline.lock. New output per run.
usage: mutation_control.py mutation-NN          (or: mutation_control.py --verify-patterns, which only checks that every mutated text exists exactly once)"""
import json,os,re,shutil,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent;WORK=ROOT.parent
sys.path.insert(0,str(WORK/'solana-chrome-wallet-v1'))
VERIFY=sys.argv[1:]==['--verify-patterns']
if not VERIFY:
    assert len(sys.argv)==2 and re.fullmatch(r'mutation-[0-9]+',sys.argv[1])
    from offline_guard import acquire
    lock=acquire();out=ROOT/'evidence'/sys.argv[1];out.mkdir(parents=True,exist_ok=False)
NODE=shutil.which('node') or 'node'
ARCHIVE=WORK/'solana-multiwallet-privacy-v1/evidence/privacy-live-02/public-capsule'
SIBLINGS=['solana-chrome-wallet-v1','solana-private-relay-v1','solana-relay-performance-v1','solana-beta-withdraw-v1','solana-unified-wallet-v1']
P='relay-publication.mjs';R='relay-repository.mjs';F='relay-funding.mjs';S='publication-sender.mjs';A='publication-adapter.mjs';T='relay-task.mjs'
def pat(*names):return '^('+'|'.join(names)+') '
# (name, file, old, new, tests selected by name pattern)
MUTATIONS=[
 # ---- journal v2 ----
 ('prepare_while_pending',P,"    require(!this.#state.pending.length,'Resolve the existing signed transaction first.');\n    let step;","    let step;",pat('J3')),
 ('prepare_chunks_while_pending',P,"    require(!this.#state.pending.length,'Resolve the existing signed transaction first.');\n    exact(action,['type','indexes']);","    exact(action,['type','indexes']);",pat('J3')),
 ('duplicate_chunk_indexes_allowed',P,"&&indexes.length<=MAX_WINDOW&&new Set(indexes).size===indexes.length,'Invalid chunk window.');","&&indexes.length<=MAX_WINDOW,'Invalid chunk window.');",pat('J4')),
 ('window_unbounded',P,"Array.isArray(indexes)&&indexes.length>=1&&indexes.length<=MAX_WINDOW&&new Set","Array.isArray(indexes)&&indexes.length>=1&&new Set",pat('J4')),
 ('empty_window_allowed',P,"Array.isArray(indexes)&&indexes.length>=1&&indexes.length<=MAX_WINDOW","Array.isArray(indexes)&&indexes.length<=MAX_WINDOW",pat('J4')),
 ('max_window_raised',P,"export const MAX_WINDOW=128;","export const MAX_WINDOW=200;",pat('R8')),
 ('sign_batch_commits_only_one',P,"await this.#commit({...this.#state,pending:attempts,attempts:this.#state.attempts+attempts.length});","await this.#commit({...this.#state,pending:attempts.slice(0,1),attempts:this.#state.attempts+attempts.length});",pat('J2')),
 ('attempt_counter_counts_one',P,"attempts:this.#state.attempts+attempts.length});","attempts:this.#state.attempts+1});",pat('J2')),
 ('sign_batch_not_stored',P,"    await this.#commit({...this.#state,pending:attempts,attempts:this.#state.attempts+attempts.length});\n    return {attempts","    return {attempts",pat('J2')),
 ('sign_not_stored',P,"    await this.#commit({...this.#state,pending:[attempt],attempts:this.#state.attempts+1});","",pat('J9','S2')),
 ('commit_failure_swallowed',P,"    await this.#commit({...this.#state,pending:attempts,attempts:this.#state.attempts+attempts.length});","    try{await this.#commit({...this.#state,pending:attempts,attempts:this.#state.attempts+attempts.length});}catch{}",pat('S10')),
 ('stored_attempts_not_verified',P,"      await this.#policy.verifyAttempt(a);\n      require(!signatures.has(a.signature)","      require(!signatures.has(a.signature)",pat('J5')),
 ('mixed_kinds_allowed',P,"        require(m&&!chunks.has(m[1]),'Only distinct chunk uploads may be pending together.');chunks.add(m[1]);","        chunks.add(m?.[1]);",pat('J5')),
 ('pending_may_exceed_attempts',P,"&&s.pending.length<=s.attempts,'Invalid pending publication list.'",",'Invalid pending publication list.'",pat('J5')),
 ('pending_list_unbounded',P,"require(Array.isArray(s.pending)&&s.pending.length<=MAX_WINDOW&&s.pending.length<=s.attempts,","require(Array.isArray(s.pending)&&s.pending.length<=s.attempts,",pat('J5')),
 ('pending_shape_unchecked',P,"require(Array.isArray(s.pending)&&s.pending.length<=MAX_WINDOW&&s.pending.length<=s.attempts,'Invalid pending publication list.');","",pat('J5')),
 ('unknown_signature_resolved',P,"require(a&&!gone.has(signature)&&['confirmed','failed','expired'].includes(outcome));","require(!gone.has(signature)&&['confirmed','failed','expired'].includes(outcome));",pat('J6')),
 ('duplicate_resolution_entry',P,"require(a&&!gone.has(signature)&&","require(a&&",pat('J6')),
 ('resolution_outcome_unchecked',P,"&&['confirmed','failed','expired'].includes(outcome));",");",pat('J6')),
 ('expiry_without_missing_proof',P,"require(missingAfterExpiry===true&&height>a.last_valid_height,'Unproven transaction expiry.')","require(height>a.last_valid_height,'Unproven transaction expiry.')",pat('J7')),
 ('expiry_before_blockhash_lifetime',P,"require(missingAfterExpiry===true&&height>a.last_valid_height,'Unproven transaction expiry.')","require(missingAfterExpiry===true,'Unproven transaction expiry.')",pat('J7')),
 ('last_resolution_not_recorded',P,"pending:this.#state.pending.filter(a=>!gone.has(a.signature)),last});","pending:this.#state.pending.filter(a=>!gone.has(a.signature)),last:this.#state.last});",pat('J6')),
 ('ticket_kind_not_checked',P,"&&!this.#state.pending.length&&p.batch===batch,'Unknown or stale relay ticket.'","&&!this.#state.pending.length,'Unknown or stale relay ticket.'",pat('J8')),
 ('probe_carries_a_signature',P,"return (await signedTransaction(unsigned(this.#sponsor.pub),step.instructions,extras,blockhash,0)).raw;","return (await signedTransaction(this.#sponsor,step.instructions,extras,blockhash,0)).raw;",pat('J2')),
 ('initial_pending_null',P,"revision:1,pending:[],attempts:0,last:null};","revision:1,pending:null,attempts:0,last:null};",pat('J1')),
 ('version_label_unchecked',P,"require(s.version===VERSION&&s.id===this.id","require(s.id===this.id",pat('J5')),
 ('wire_hash_unchecked',P,"&&s.wire_hash===this.#request.wire_hash\n      &&same(s.transport","\n      &&same(s.transport",pat('J5')),
 ('transport_unchecked',P,"&&same(s.transport,this.configuration.transport),'Relay request binding changed.');",",'Relay request binding changed.');",pat('J5')),
 # ---- funded repository v2 ----
 ('list_may_grow_while_pending',R,"      require(!before.length||!added.length,'Cannot replace unresolved funded transaction.');\n","",pat('R3')),
 ('retained_attempt_replaceable',R,"      for(const a of after)if(kept.has(a.signature))require(kept.get(a.signature).raw===a.raw,'Cannot replace unresolved funded transaction.');\n","",pat('R3','R7')),
 ('duplicate_pending_allowed',R,"      require(new Set(after.map(a=>a.signature)).size===after.length,'Duplicate pending attempt.');\n","",pat('R3')),
 ('new_attempts_without_debit',R,"      require(newlySigned?debit>0n:debit===0n,'Funding debit must match a new signed attempt.');","      require(newlySigned||debit===0n,'Funding debit must match a new signed attempt.');",pat('R7')),
 ('debit_on_a_resolution',R,"      require(newlySigned?debit>0n:debit===0n,'Funding debit must match a new signed attempt.');","      require(!newlySigned||debit>0n,'Funding debit must match a new signed attempt.');",pat('R2')),
 ('window_record_limit_for_every_record',R,"(value.version===PUBLICATION?WINDOW_RECORD_LIMIT:RECORD_LIMIT)","WINDOW_RECORD_LIMIT",pat('R8')),
 ('window_record_unbounded',R,"(value.version===PUBLICATION?WINDOW_RECORD_LIMIT:RECORD_LIMIT)","(value.version===PUBLICATION?1e9:RECORD_LIMIT)",pat('R8')),
 ('other_records_unbounded',R,"(value.version===PUBLICATION?WINDOW_RECORD_LIMIT:RECORD_LIMIT)","(value.version===PUBLICATION?WINDOW_RECORD_LIMIT:1e9)",pat('R8')),
 ('foreign_journal_accepted',R,"    require(value.version===PUBLICATION?id===requestId\n      :value.version===SETTLEMENT&&value.request_id===requestId,'Foreign funded journal.');","    require(true,'Foreign funded journal.');",pat('R8')),
 ('request_cap_ignored',R,"require(used<=units(reservation.cap),'Request funding limit exceeded.');","",pat('R4')),
 ('pending_list_shape_unchecked',R,"(require(Array.isArray(pending),'Pending attempt list required.'),pending)","pending",pat('R3')),
 # ---- funding quote v2 ----
 ('window_charged_as_one',F,"const debit=rent+maximum*BigInt(list.length);","const debit=rent+maximum;",pat('R1','J2')),
 ('fee_cap_unchecked',F,"require(quoted.value>0&&BigInt(quoted.value)<=maximum,'Fee unavailable or above operator cap.');","require(quoted.value>0,'Fee unavailable or above operator cap.');",pat('R6')),
 ('zero_fee_accepted',F,"require(quoted.value>0&&BigInt(quoted.value)<=maximum,'Fee unavailable or above operator cap.');","require(BigInt(quoted.value)<=maximum,'Fee unavailable or above operator cap.');",pat('R6')),
 ('balance_unchecked',F,"require(balance.context.slot>=slot&&BigInt(balance.value)>=debit,'Sponsor balance insufficient or stale.');","require(balance.context.slot>=slot,'Sponsor balance insufficient or stale.');",pat('R6')),
 ('stale_balance_accepted',F,"require(balance.context.slot>=slot&&BigInt(balance.value)>=debit,'Sponsor balance insufficient or stale.');","require(BigInt(balance.value)>=debit,'Sponsor balance insufficient or stale.');",pat('R6')),
 ('foreign_authority_unchecked',F,"require(b58(tx.authority)===sponsor&&tx.signature===a.signature,'Foreign funding authority.');","require(tx.signature===a.signature,'Foreign funding authority.');",pat('R10')),
 ('whole_transaction_sent_to_the_fee_rpc',F,"const message=toBase64(bytes.subarray(1+count*64));","const message=toBase64(bytes);",pat('R1')),
 ('empty_window_quoted',F,"require(Array.isArray(list)&&list.length>=1&&list.length<=MAX_WINDOW,'Missing signed attempts.');","require(Array.isArray(list),'Missing signed attempts.');",pat('R10')),
 ('every_commit_quoted',F,"const entering=value.version===PUB?value.pending.length>0&&!old?.pending?.length:!!value.pending&&!old?.pending;","const entering=value.version===PUB?value.pending.length>0:!!value.pending&&!old?.pending;",pat('R1','J6')),
 ('attempt_cap_ignored',F,"      if(value.version===PUB)require(value.attempts<=maxPublicationAttempts,'Local relay publication budget exhausted.');\n","",pat('R5')),
 # ---- windowed sender ----
 ('window_size_ignored_in_choice',S,"buffer.pending.slice(0,this.#window)","buffer.pending.slice(0,128)",pat('S12','S13')),
 ('window_path_never_chosen',S,"return this.#window>1?{type:'chunks'","return this.#window>1000?{type:'chunks'",pat('S3')),
 ('window_size_unvalidated',S,"    require(Number.isSafeInteger(window)&&window>=1&&window<=MAX_WINDOW,'Invalid chunk window size.');\n","",pat('S13')),
 ('chunk_simulation_rejection_ignored',S,"      require(r.value.err===null,simulationFailure(r.value,'chunks'));","",pat('S11')),
 ('effect_not_checked_before_resolving',S,"if(buffer&&!buffer.pending.includes(Number(attempt.descriptor.name.slice(6))))entries.push(","if(true)entries.push(",pat('S9')),
 ('failure_recorded_as_confirmed',S,"else{entries.push({signature:attempt.signature,outcome:'failed',height:status.slot});failed++;}","else{entries.push({signature:attempt.signature,outcome:'confirmed',height:status.slot});failed++;}",pat('S8')),
 ('failure_not_fatal',S,"    require(failed===0,'A chunk upload of the window failed on the cluster.');\n","",pat('S8')),
 ('failure_not_listed_last',S,"    entries.sort((a,b)=>(a.outcome==='failed')-(b.outcome==='failed'));\n","",pat('S8')),
 ('processed_counts_as_landed',S,"const DONE=['confirmed','finalized'];","const DONE=['confirmed','finalized','processed'];",pat('S16')),
 ('expiry_without_blockheight',S,"      const late=remaining.filter(a=>height>a.last_valid_height);","      const late=remaining;",pat('S6')),
 ('expiry_without_second_lookup',S,"const again=await this.#statuses(late.map(a=>a.signature)),second=new Map(late.map((a,i)=>[a.signature,again[i]]));","const second=new Map(late.map(a=>[a.signature,null]));",pat('S7')),
 ('dead_blockhash_sent_again',S,"const unsent=remaining.filter(a=>height<=a.last_valid_height&&status.get(a.signature)===null);","const unsent=remaining.filter(a=>status.get(a.signature)===null);",pat('S17')),
 ('landed_chunk_sent_again',S,"const unsent=remaining.filter(a=>height<=a.last_valid_height&&status.get(a.signature)===null);","const unsent=remaining.filter(a=>height<=a.last_valid_height);",pat('S9')),
 ('awaiting_progress_not_reported',S,"return {...result,state:waiting>0?'awaiting_progress':'pending'};","return {...result,state:'pending'};",pat('S9')),
 ('all_expired_reported_as_confirmed',S,"state:confirmedCount>0?'step_confirmed':'expired'","state:'step_confirmed'",pat('S6')),
 ('concurrent_steps_allowed',S,"require(!this.#busy,'Wait for the current publication step.');this.#busy=true;","this.#busy=true;",pat('S14')),
 ('min_slot_error_fatal',S,"      if(e?.rpcCode===-32016)return {id,state:'pending',reason:'rpc_minimum_slot_not_reached'};\n","",pat('S15')),
 ('unknown_send_outcome_fatal',S,"catch(e){return {a,error:true};}","catch(e){throw e;}",pat('S3')),
 ('different_send_signature_accepted',S,"        for(const s of sent)if(!s.error)require(s.signature===s.a.signature,'RPC returned a different publication signature.');\n","",pat('S18')),
 ('short_status_list_accepted',S,"Array.isArray(r.value)&&r.value.length===signatures.length,'Invalid publication status response.'","Array.isArray(r.value),'Invalid publication status response.'",pat('S18')),
 ('pending_not_rechecked_before_resend',S,"        for(const a of unsent)require(stored.get(a.signature)===a.raw,'Pending publication changed before send.');\n","",pat('S18')),
 # ---- adapter ----
 ('chunk_window_prepare_unchecked_id',A,"prepareChunks:(id,action)=>{checkedId(id);return pub.prepareChunks(action);},","prepareChunks:(id,action)=>{return pub.prepareChunks(action);},",pat('A1')),
 ('sign_batch_unchecked_id',A,"signBatch:(id,ticket,blockhash,height)=>{checkedId(id);return pub.signBatch(ticket,blockhash,height);},","signBatch:(id,ticket,blockhash,height)=>{return pub.signBatch(ticket,blockhash,height);},",pat('A1')),
 ('resolve_many_unchecked_id',A,"resolveMany:(id,entries)=>{checkedId(id);return pub.resolveMany(entries);},","resolveMany:(id,entries)=>{return pub.resolveMany(entries);},",pat('A1')),
 ('bind_ignores_settling',A,"require(isSettling(),'Proof already spent or conflicted.');","",pat('A1')),
 # ---- task wiring ----
 ('task_window_unvalidated',T,"    require(Number.isSafeInteger(window)&&window>=1&&window<=MAX_WINDOW,'Invalid chunk window size.');\n","",pat('A2')),
 ('task_window_not_given_to_sender',T,"kind:request.kind,signal,window});","kind:request.kind,signal});",pat('A3')),
 ('task_uses_the_frozen_sender',T,"import {PublicationSender} from './publication-sender.mjs';","import {PublicationSender} from '../solana-unified-wallet-v1/recovery/publication-sender.mjs';",pat('A3')),
 ('task_uses_the_frozen_funding',T,"from './relay-funding.mjs';","from '../solana-private-relay-v1/relay-funding.mjs';",pat('A3')),
 ('task_uses_the_frozen_journal',T,"import {SponsoredPublication} from './relay-publication.mjs';","import {SponsoredPublication} from '../solana-private-relay-v1/relay-publication.mjs';",pat('A3')),
]
def patch(work,service,target,old,new):
    text=(service/target).read_text();assert text.count(old)==1,(target,old[:70],text.count(old))
    (service/target).write_text(text.replace(old,new,1))
    check=subprocess.run([NODE,'--check',str(service/target)],capture_output=True,text=True)
    if check.returncode!=0:raise SystemExit('mutant does not parse: '+target+check.stderr[:300])
if VERIFY:
    for name,target,old,new,_ in MUTATIONS:
        text=(ROOT/target).read_text();n=text.count(old)
        print(('OK  ' if n==1 else 'BAD ')+name,n)
        assert n==1,name
    print(len(MUTATIONS),'mutations; every mutated text occurs exactly once');sys.exit(0)
def run(name,target,old,new,pattern):
    work=out/name;work.mkdir()
    service=work/'solana-relay-windowed-v1';service.mkdir()
    for sibling in SIBLINGS:(work/sibling).symlink_to(WORK/sibling)
    for f in ROOT.glob('*.mjs'):shutil.copy2(f,service/f.name)
    if old is not None:patch(work,service,target,old,new)
    env={**os.environ,'ZK9_WIRE_ARCHIVE':str(ARCHIVE)}
    try:r=subprocess.run([NODE,'--test','--test-timeout=120000','--test-name-pattern='+pattern,str(service/'checks.mjs')],capture_output=True,text=True,timeout=400,env=env,cwd=service)
    except subprocess.TimeoutExpired:return {'mutation':name,'file':target,'exit_code':None,'timed_out':True,'selected':pattern,'failing_tests':[],'failing_count':0}
    fails=sorted(set(re.findall(r'^\s*✖ ([A-Z][0-9]+[^\n(]*?) \(',r.stdout+r.stderr,re.M)))
    (work/'output.txt').write_text(r.stdout+r.stderr)
    print(name,'->',fails[:2] or 'NOT DETECTED',file=sys.stderr,flush=True)
    return {'mutation':name,'file':target,'exit_code':r.returncode,'selected':pattern,'failing_tests':[f[:70] for f in fails[:8]],'failing_count':len(fails)}
results=[run('control_unmutated',P,None,None,'.')]
assert results[0]['exit_code']==0 and results[0]['failing_count']==0,'the copied harness does not pass unmutated: '+json.dumps(results[0])
for spec in MUTATIONS:results.append(run(*spec))
# Detected means at least one NAMED test failed; a crash, a hang or a build failure is not detection.
undetected=[r['mutation'] for r in results[1:] if r['exit_code'] in (None,0) or r['failing_count']==0]
(out/'MUTATION.json').write_text(json.dumps({'all_detected':not undetected,'undetected':undetected,'count':len(MUTATIONS),'results':results},indent=2)+'\n')
print(json.dumps({'all_detected':not undetected,'undetected':undetected,'count':len(MUTATIONS),'failing':{r['mutation']:r['failing_tests'][:2] for r in results[1:]}},indent=1));sys.exit(1 if undetected else 0)
