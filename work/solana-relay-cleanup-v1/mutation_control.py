"""Negative control of the CLEANUP revision: each mutation is applied to a COPY of this directory's sources, and the checks selected for it must fail by a NAMED test
(cleanup-checks.mjs). A mutant that does not parse, crashes or hangs is not detection. The real files are never touched.
The windowed regression suite (checks.mjs, 40 tests) has its own control (../solana-relay-windowed-v1) and is re-run unmodified against this directory by run_checks.py.
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
SIBLINGS=['solana-chrome-wallet-v1','solana-private-relay-v1','solana-relay-performance-v1','solana-beta-withdraw-v1','solana-unified-wallet-v1','solana-relay-windowed-v1']
Q='cleanup-policy.mjs';P='relay-publication.mjs';S='publication-sender.mjs';T='relay-task.mjs'
CHECKS='cleanup-checks.mjs'
def pat(*names):return '^('+'|'.join(names)+') '
RECEIPT_LINE="else if(name==='receipt-close') {require(work===0);instructions=[this.#proofIx(Uint8Array.of(2))];}"
BUFFER_LINE="else if(name==='buffer-close') {require(work===0);instructions=[this.#bufferIx(Uint8Array.of(3))];}"
DONE_LINE="return this.#cleanup?{id,state:'cleaned'}:{id,state:'verified',settled:false};"
# (name, file, old, new, tests selected by name pattern)
MUTATIONS=[
 # ---- the two instructions (policy) ----
 ('receipt_close_wrong_opcode',Q,RECEIPT_LINE,RECEIPT_LINE.replace('Uint8Array.of(2)','Uint8Array.of(1)'),pat('C5')),
 ('receipt_close_opcode_is_the_buffers',Q,RECEIPT_LINE,RECEIPT_LINE.replace('Uint8Array.of(2)','Uint8Array.of(3)'),pat('C5')),
 ('buffer_close_is_a_seal',Q,BUFFER_LINE,BUFFER_LINE.replace('Uint8Array.of(3)','Uint8Array.of(2)'),pat('C5','C1')),
 ('receipt_close_on_the_buffer_program',Q,RECEIPT_LINE,RECEIPT_LINE.replace('this.#proofIx','this.#bufferIx'),pat('C5')),
 ('buffer_close_on_the_verifier_program',Q,BUFFER_LINE,BUFFER_LINE.replace('this.#bufferIx','this.#proofIx'),pat('C5')),
 ('buffer_close_work_unchecked',Q,BUFFER_LINE,BUFFER_LINE.replace('require(work===0);',''),pat('C19')),
 ('receipt_close_work_unchecked',Q,RECEIPT_LINE,RECEIPT_LINE.replace('require(work===0);',''),pat('C19')),
 # ---- the journal's `close` action ----
 ('close_target_unchecked',P,"require(action.which==='receipt'||action.which==='buffer','Unknown cleanup target.');","",pat('C6')),
 ('close_extra_fields_allowed',P,"else if(action.type==='close'){exact(action,['type','which']);","else if(action.type==='close'){",pat('C6')),
 ('close_targets_swapped',P,"step=action.which==='receipt'?this.#policy.receiptClose():this.#policy.bufferClose();}","step=action.which==='receipt'?this.#policy.bufferClose():this.#policy.receiptClose();}",pat('C1','C5')),
 # ---- the sender: what to close, in which order, and when it counts as done ----
 ('buffer_closed_before_the_receipt',S,"      if(proof!==null)return {type:'close',which:'receipt'};\n","",pat('C1')),
 ('incomplete_buffer_closed',S,"require(view.sealed&&view.pending.length===0,'Cleanup found an incomplete proof buffer.');","",pat('C4')),
 ('buffer_closed_without_reading_it',S,"const view=await this.#bufferView(stored);require(view.sealed&&view.pending.length===0,'Cleanup found an incomplete proof buffer.');return {type:'close',which:'buffer'};}","return {type:'close',which:'buffer'};}",pat('C3','C4')),
 ('cleanup_mode_always_on',S,"    if(this.#cleanup) {\n      // Receipt first, then the buffer.","    if(true) {\n      // Receipt first, then the buffer.",pat('C2','C20')),
 ('cleanup_mode_on_by_default',S,"#cleanup=false;","#cleanup=true;",pat('C2','C20')),
 ('cleanup_end_reported_as_verified',S,DONE_LINE,"return {id,state:'verified',settled:false};",pat('C1','C14','C20')),
 ('publication_end_reported_as_cleaned',S,DONE_LINE,"return {id,state:'cleaned'};",pat('C20')),
 ('receipt_close_trusted_without_reading',S,"if(name==='receipt-close')return (await this.#account(c.transport.receipt))===null;","if(name==='receipt-close')return true;",pat('C12')),
 ('buffer_close_trusted_without_reading',S,"if(name==='buffer-close')return (await this.#account(c.transport.source))===null;","if(name==='buffer-close')return true;",pat('C12')),
 ('receipt_close_counts_when_buffer_is_gone',S,"if(name==='receipt-close')return (await this.#account(c.transport.receipt))===null;","if(name==='receipt-close')return (await this.#account(c.transport.source))===null;",pat('C1','C12','C15')),
 # ---- the task: only a settled payment, failures fatal, journal stays bound ----
 ('conflicted_payment_cleaned_too',T,"if(this.#state==='settled'&&this.#cleanup&&!this.#cleaned) {","if(this.#cleanup&&!this.#cleaned) {",pat('C18')),
 ('cleanup_failure_not_fatal',T,"          if(result.state==='failed')throw Error('A cleanup transaction failed on the cluster.');\n","",pat('C18')),
 ('cleanup_off_by_default',T,"window=64,cleanup=true,fetchImpl}","window=64,cleanup=false,fetchImpl}",pat('C17','C18')),
 ('cleanup_option_unvalidated',T,"    require(typeof cleanup==='boolean','Invalid cleanup option.');t.#cleanup=cleanup;\n","    t.#cleanup=cleanup;\n",pat('C17')),
 ('journal_refuses_during_cleanup',T,"isSettling:()=>t.#state==='settling'||(t.#cleaning&&t.#state==='settled')","isSettling:()=>t.#state==='settling'",pat('C18')),
 ('journal_not_told_cleanup_began',T,"this.#cleaning=true;this.#publisher.beginCleanup();","this.#publisher.beginCleanup();",pat('C18')),
 ('sender_not_told_cleanup_began',T,"this.#cleaning=true;this.#publisher.beginCleanup();","this.#cleaning=true;",pat('C18')),
 ('unfinished_cleanup_reported_done',T,"          if(result.state!=='cleaned')return {...result,id:this.id,phase:'cleanup'};\n","",pat('C18')),
 ('cleanup_never_marked_done',T,"          this.#cleaned=true;\n","",pat('C18')),
 # the router found necessary by full-06
 ('settled_from_the_sender_reaches_the_supervisor',T,"return routeStepResult(result,{id:this.id,state:this.#state,cleanup:this.#cleanup,cleaned:this.#cleaned});","return {...result,id:this.id};",pat('C22')),
 ('router_ignores_the_cleanup_option',T,"if(result.state==='settled'&&state==='settled'&&cleanup===true&&cleaned===false)","if(result.state==='settled'&&state==='settled'&&cleaned===false)",pat('C21')),
 ('router_ignores_that_cleanup_is_done',T,"if(result.state==='settled'&&state==='settled'&&cleanup===true&&cleaned===false)","if(result.state==='settled'&&state==='settled'&&cleanup===true)",pat('C21')),
 ('router_ignores_the_task_state',T,"if(result.state==='settled'&&state==='settled'&&cleanup===true&&cleaned===false)","if(result.state==='settled'&&cleanup===true&&cleaned===false)",pat('C21')),
 ('router_holds_back_every_result',T,"if(result.state==='settled'&&state==='settled'&&cleanup===true&&cleaned===false)","if(state==='settled'&&cleanup===true&&cleaned===false)",pat('C21')),
 ('router_drops_the_task_id',T,"  return {...result,id};\n}","  return {...result};\n}",pat('C21')),
 ('router_pending_state_is_final',T,"return {id,state:'cleanup_pending',phase:'cleanup'};","return {id,state:'settled',phase:'cleanup'};",pat('C21','C22')),
]
def patch(service,target,old,new):
    text=(service/target).read_text();assert text.count(old)==1,(target,old[:70],text.count(old))
    (service/target).write_text(text.replace(old,new,1))
    check=subprocess.run([NODE,'--check',str(service/target)],capture_output=True,text=True)
    if check.returncode!=0:raise SystemExit('mutant does not parse: '+target+check.stderr[:300])
if VERIFY:
    for name,target,old,new,_ in MUTATIONS:
        text=(ROOT/target).read_text();n=text.count(old)
        print(('OK  ' if n==1 else 'BAD ')+name,n)
        assert n==1 and old!=new,name
    print(len(MUTATIONS),'mutations; every mutated text occurs exactly once and differs from its replacement');sys.exit(0)
def run(name,target,old,new,pattern):
    work=out/name;work.mkdir()
    service=work/'solana-relay-cleanup-v1';service.mkdir()
    for sibling in SIBLINGS:(work/sibling).symlink_to(WORK/sibling)
    for f in ROOT.glob('*.mjs'):shutil.copy2(f,service/f.name)
    if old is not None:patch(service,target,old,new)
    env={**os.environ,'ZK9_WIRE_ARCHIVE':str(ARCHIVE)}
    try:r=subprocess.run([NODE,'--test','--test-timeout=120000','--test-name-pattern='+pattern,str(service/CHECKS)],capture_output=True,text=True,timeout=400,env=env,cwd=service)
    except subprocess.TimeoutExpired:return {'mutation':name,'file':target,'exit_code':None,'timed_out':True,'selected':pattern,'failing_tests':[],'failing_count':0}
    fails=sorted(set(re.findall(r'^\s*✖ ([A-Z][0-9]+[^\n(]*?) \(',r.stdout+r.stderr,re.M)))
    (work/'output.txt').write_text(r.stdout+r.stderr)
    print(name,'->',fails[:2] or 'NOT DETECTED',file=sys.stderr,flush=True)
    return {'mutation':name,'file':target,'exit_code':r.returncode,'selected':pattern,'failing_tests':[f[:70] for f in fails[:8]],'failing_count':len(fails)}
results=[run('control_unmutated',Q,None,None,'.')]
assert results[0]['exit_code']==0 and results[0]['failing_count']==0,'the copied harness does not pass unmutated: '+json.dumps(results[0])
for spec in MUTATIONS:results.append(run(*spec))
# Detected means at least one NAMED test failed; a crash, a hang or a build failure is not detection.
undetected=[r['mutation'] for r in results[1:] if r['exit_code'] in (None,0) or r['failing_count']==0]
(out/'MUTATION.json').write_text(json.dumps({'all_detected':not undetected,'undetected':undetected,'count':len(MUTATIONS),'results':results},indent=2)+'\n')
print(json.dumps({'all_detected':not undetected,'undetected':undetected,'count':len(MUTATIONS),'failing':{r['mutation']:r['failing_tests'][:2] for r in results[1:]}},indent=1));sys.exit(1 if undetected else 0)
