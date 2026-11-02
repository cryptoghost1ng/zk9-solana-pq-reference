// Checks of the CLEANUP phase: after a payment is settled the relay closes the two accounts it created for the request (the verifier receipt, then the proof buffer)
// so their rent returns to the sponsor. The 40 checks of the windowed revision (checks.mjs, unmodified) are the regression suite for everything else.
// Real SQLite, real signing, the real decoder; the cluster is the model of harness.mjs, which here also holds a receipt and closes accounts.
// Names start with a letter+digit so the mutation control can select tests by pattern.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {DatabaseSync} from 'node:sqlite';
import {createHash} from 'node:crypto';
import {makeEnv,BUFFER,temp} from './harness.mjs';
import {LocalRelayTask,routeStepResult} from './relay-task.mjs';
import {COST_POOL_SHA256} from './relay-funding.mjs';
import {RelayRepository} from './relay-repository.mjs';
import {encodeRequest,readRequest} from '../solana-private-relay-v1/relay-request.mjs';
import {privateSigner,b58,decodeTransaction} from '../solana-chrome-wallet-v1/recovery/solana-transaction.mjs';
import {digest} from '../solana-chrome-wallet-v1/recovery/payment-wire.mjs';

const HERE=path.dirname(fileURLToPath(import.meta.url));
const FEE=10000n,SEALED_RENT=21448444080,RECEIPT_RENT=2290000000;
async function env(t,options){const e=await makeEnv(options);t.after(()=>{try{e.close();}catch{}fs.rmSync(e.dir,{recursive:true,force:true});});return e;}
async function reopen(t,e,options){const n=await e.reopen(options);t.after(()=>{try{n.close();}catch{}});return n;}
const charged=async e=>BigInt((await e.fund()).charged_lamports);
// A payment the pool has settled, as publication leaves it: a full sealed buffer and the verifier's receipt. The task switches the phase on; so does this.
async function settled(t,options={}){const e=await env(t,{window:8,...options});e.arrangeSettled();e.sender.beginCleanup();return e;}
async function runCleanup(e,max=60){
  const results=[];
  for(let i=0;i<max;i++){const r=await e.step();results.push(r);if(r.state==='cleaned')return results;e.chain.tick();}
  throw Error('cleanup did not converge: '+JSON.stringify(results.slice(-3)));
}
const closedKeys=e=>e.chain.closed.map(c=>c.key);
const sends=e=>e.chain.log.filter(x=>x.t==='send');
function tamper(e,change){
  e.close();const db=new DatabaseSync(e.dir+'/state.sqlite');
  const row=db.prepare('SELECT body FROM operations WHERE id=?').get(e.request.id),body=JSON.parse(row.body);change(body);
  db.prepare('UPDATE operations SET body=? WHERE id=?').run(JSON.stringify(body),e.request.id);db.close();
}

test('C1 cleanup closes the receipt FIRST and the buffer second, each once, and the sponsor gets both rents back',async t=>{
  const e=await settled(t),before=e.chain.balance;
  const results=await runCleanup(e);
  assert.deepEqual(closedKeys(e),[e.transport.receipt,e.transport.source]);
  assert.equal(e.chain.balance-before,SEALED_RENT+RECEIPT_RENT,'both rents go to the sponsor, nothing else moves');
  assert.equal(results.at(-1).state,'cleaned');assert.equal(e.chain.accounts.size,0);
  const rec=await e.record();assert.equal(rec.attempts,2);assert.deepEqual(rec.pending,[]);assert.equal(rec.last.outcome,'confirmed');
  assert.equal(sends(e).length,2);assert.deepEqual(e.chain.violations,[],'both closes were durable before they left');
  assert.deepEqual(results.map(r=>r.state).filter(s=>s!=='pending'),['step_confirmed','step_confirmed','cleaned']);
});
test('C2 nothing is ever closed while the payment is still being published',async t=>{
  const e=await env(t,{window:8});
  await e.drive(async()=>e.buffer().received>=24&&(await e.record()).pending.length===0,{max:60});
  assert.equal(e.chain.closed.length,0);assert.ok(!e.chain.log.some(x=>x.tag===3),'no close instruction was sent');
  const rec=await e.record();assert.ok(rec.pending.every(a=>!/close/.test(a.descriptor.name)));
});
test('C3 the buffer is closed only while it still holds exactly the proof we hold',async t=>{
  const e=await settled(t);
  e.chain.accounts.get(e.transport.source).data[e.plan.start+10]^=1;      // one stored byte differs from the proof
  await assert.rejects(()=>runCleanup(e),/Stored chunk differs/);
  assert.deepEqual(closedKeys(e),[e.transport.receipt],'only the receipt went; the evidence in the buffer was kept');
  assert.ok(e.chain.accounts.has(e.transport.source));
});
test('C4 an unsealed or incomplete buffer is never closed',async t=>{
  const e=await settled(t);
  e.chain.accounts.get(e.transport.source).data[80]=1;                    // chunks all there, but not sealed
  await assert.rejects(()=>runCleanup(e),/Cleanup found an incomplete proof buffer/);
  assert.ok(e.chain.accounts.has(e.transport.source));assert.deepEqual(closedKeys(e),[e.transport.receipt]);
});
test('C5 the close instructions are exactly the verifier\'s and the buffer program\'s, on the request\'s own accounts, signed by the sponsor alone',async t=>{
  const e=await env(t,{window:8});
  const block=e.chain.issue();
  const sign=async which=>{const ticket=await e.publication.prepare({type:'close',which});const a=await e.publication.sign(ticket,block.blockhash,block.lastValidBlockHeight);
    await e.publication.resolve(a.signature,{outcome:'confirmed',height:1});return decodeTransaction(a.raw);};
  const receipt=await sign('receipt'),buffer=await sign('buffer');
  for(const tx of [receipt,buffer]){assert.equal(tx.signers.length,1);assert.equal(b58(tx.authority),e.authority);assert.equal(tx.instructions.length,1);}
  const r=receipt.instructions[0],b=buffer.instructions[0];
  assert.equal(b58(r.program),e.proofProgram);assert.deepEqual([...r.data],[2]);
  assert.deepEqual(r.accounts.map(a=>[b58(a.pub),a.signer,a.writable]),[
    [e.transport.receipt,false,true],[e.transport.source,false,false],[e.authority,true,true],[BUFFER,false,false],[e.programData[BUFFER],false,false]]);
  assert.equal(b58(b.program),BUFFER);assert.deepEqual([...b.data],[3]);
  assert.deepEqual(b.accounts.map(a=>[b58(a.pub),a.signer,a.writable]),[[e.transport.source,false,true],[e.authority,true,true]]);
});
test('C6 only the two request accounts can be named: no other target, no extra field',async t=>{
  const e=await env(t,{window:8});
  for(const action of [{type:'close',which:'vault'},{type:'close',which:'receipt',extra:1},{type:'close'},{type:'close',which:['receipt']},{type:'close',which:'Receipt'}])
    await assert.rejects(()=>e.publication.prepare(action),undefined,JSON.stringify(action));
  const block=e.chain.issue(),ticket=await e.publication.prepare({type:'close',which:'receipt'});
  const a=await e.publication.sign(ticket,block.blockhash,block.lastValidBlockHeight);
  tamper(e,r=>{r.pending[0].descriptor.name='buffer-close';});          // a stored receipt close relabelled as a buffer close
  await assert.rejects(()=>makeEnv({dir:e.dir,chain:e.chain,window:8}),/differs/);
  assert.ok(a.signature);
});
test('C7 a restart between the two closes does not close the first again, and finishes the second',async t=>{
  const e=await settled(t);
  await e.drive(async()=>e.chain.closed.length===1&&(await e.record()).pending.length===0,{max:30});
  assert.deepEqual(closedKeys(e),[e.transport.receipt]);
  const again=await reopen(t,e);again.sender.beginCleanup();
  const results=await runCleanup(again);
  assert.deepEqual(closedKeys(again),[e.transport.receipt,e.transport.source],'the receipt is closed once, the buffer once');
  assert.equal((await again.record()).attempts,2);assert.equal(sends(again).length,2);assert.equal(results.at(-1).state,'cleaned');
});
test('C8 a restart after the durable commit but before the send releases exactly the stored bytes',async t=>{
  const flag={crash:true};
  const wrap=base=>({...base,compareAndSwapFunded:async a=>{const r=await base.compareAndSwapFunded(a);
    if(flag.crash&&Array.isArray(a.value.pending)&&a.value.pending[0]?.descriptor.name==='receipt-close'){flag.crash=false;throw Error('process died after the durable commit');}return r;}});
  const e=await settled(t,{wrap});
  await assert.rejects(()=>e.step(),/process died after the durable commit/);
  assert.equal(sends(e).length,0,'nothing may leave before the commit returns');
  const stored=(await e.record()).pending;assert.equal(stored.length,1);
  const again=await reopen(t,e);again.sender.beginCleanup();
  await runCleanup(again);
  assert.deepEqual(sends(again).map(x=>x.sig).slice(0,1),[stored[0].signature],'the first thing released is the stored attempt');
  assert.equal((await again.record()).attempts,2,'no close was signed twice');assert.deepEqual(again.chain.violations,[]);
});
test('C9 a close that lands with an error is recorded as failed, the account stays, and retries are bounded by the attempt cap',async t=>{
  const e=await settled(t,{maxAttempts:3});
  e.chain.accounts.get(e.transport.receipt).authority=b58(new Uint8Array(32).fill(9));     // the receipt records another authority: the program refuses
  assert.equal((await e.step()).state,'pending');e.chain.tick();
  const failed=await e.step();assert.equal(failed.state,'failed');
  assert.equal((await e.record()).last.outcome,'failed');assert.ok(e.chain.accounts.has(e.transport.receipt));assert.equal(e.chain.closed.length,0);
  for(let i=0;i<2;i++){await e.step();e.chain.tick();await e.step();}
  await assert.rejects(()=>e.step(),/publication budget exhausted/);
  assert.equal((await e.record()).attempts,3);assert.equal(e.chain.closed.length,0);
});
test('C10 an uncertain send outcome keeps the same signed attempt and never signs another',async t=>{
  const e=await settled(t);e.chain.sendErrors=1;
  const first=await e.step();assert.equal(first.state,'pending');assert.equal(first.reason,'submission_outcome_unknown');
  assert.equal((await e.record()).attempts,1);
  await runCleanup(e);
  assert.equal((await e.record()).attempts,2,'one attempt per close even though the first send was lost');assert.deepEqual(closedKeys(e),[e.transport.receipt,e.transport.source]);
});
test('C11 a close whose blockhash expired before it landed is resolved as expired with proof, and signed again',async t=>{
  const e=await settled(t);e.chain.dropAllSends=true;
  assert.equal((await e.step()).state,'pending');e.chain.tick();e.chain.height+=500;
  const expired=await e.step();assert.equal(expired.state,'expired');
  assert.equal((await e.record()).last.outcome,'expired');assert.equal(e.chain.closed.length,0);
  e.chain.dropAllSends=false;await runCleanup(e);
  assert.equal((await e.record()).attempts,3,'the expired close, then both closes again');assert.deepEqual(closedKeys(e),[e.transport.receipt,e.transport.source]);
});
test('C12 a close counts as done only when the account is really gone, not when the status says so',async t=>{
  const e=await settled(t);
  await e.step();e.chain.tick();e.chain.staleReads=1;                    // the node answering has not seen the close yet
  const waiting=await e.step();
  assert.equal(waiting.state,'awaiting_progress');assert.equal((await e.record()).pending.length,1,'still pending until the account is seen gone');
  const next=await e.step();assert.equal(next.state,'step_confirmed');assert.deepEqual((await e.record()).pending,[]);
  e.chain.tick();e.chain.staleReads=0;
  // the same for the buffer
  await e.step();e.chain.tick();e.chain.staleReads=1;
  assert.equal((await e.step()).state,'awaiting_progress');assert.equal((await e.step()).state,'step_confirmed');
});
test('C13 each close costs one fee ceiling, and the per-request cap bounds the cleanup like everything else',async t=>{
  const e=await settled(t);await runCleanup(e);assert.equal(await charged(e),2n*FEE);
  const small=await settled(t,{requestLamports:'15000'});
  await assert.rejects(()=>runCleanup(small),/Request funding limit exceeded/);
  assert.equal(small.chain.closed.length,1,'the first close fitted; the second was refused before it left');assert.ok(small.chain.accounts.has(small.transport.source));
});
test('C14 once everything is closed a fresh sender finds nothing to do and sends nothing',async t=>{
  const e=await settled(t);await runCleanup(e);
  const before=sends(e).length;assert.equal(before,2);
  const again=await reopen(t,e);again.sender.beginCleanup();
  const result=await again.step();assert.equal(result.state,'cleaned');assert.equal(sends(again).length,before,'the cluster log is shared: nothing new was sent');
  assert.equal((await again.record()).attempts,2);assert.equal(again.chain.closed.length,2,'and nothing was conjured back or closed again');
});
test('C15 a missing receipt does not stop the buffer from being closed, and a missing buffer does not stop the receipt',async t=>{
  const noReceipt=await settled(t);noReceipt.chain.accounts.delete(noReceipt.transport.receipt);
  await runCleanup(noReceipt);assert.deepEqual(closedKeys(noReceipt),[noReceipt.transport.source]);
  const noBuffer=await settled(t);noBuffer.chain.accounts.delete(noBuffer.transport.source);
  await runCleanup(noBuffer);assert.deepEqual(closedKeys(noBuffer),[noBuffer.transport.receipt]);
});
test('C16 the withdrawal kind is cleaned the same way',async t=>{
  const e=await settled(t,{kind:'withdraw'});const before=e.chain.balance;
  await runCleanup(e);assert.deepEqual(closedKeys(e),[e.transport.receipt,e.transport.source]);assert.equal(e.chain.balance-before,SEALED_RENT+RECEIPT_RENT);
});
test('C17 the task validates the cleanup option before reserving any funds, and defaults to cleaning',async t=>{
  const base=path.join(HERE,'../solana-chrome-wallet-v1/'),fixturePath=fs.realpathSync(base+'evidence/settlement-plan-01/PUBLIC-FIXTURES.json');
  const bytes=fs.readFileSync(fixturePath),pins=JSON.parse(fs.readFileSync(base+'evidence/settlement-journal-01/INPUTS.json'));
  assert.equal(createHash('sha256').update(bytes).digest('hex'),pins[Object.keys(pins).find(k=>k.endsWith('/evidence/settlement-plan-01/PUBLIC-FIXTURES.json'))]);
  const row=JSON.parse(bytes).valid[0],r=row.request,wire=new Uint8Array(Buffer.from(r.wire,'base64')),raw=encodeRequest(r.kind,wire),context=r.history.context;
  const dir=temp();t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const repository=new RelayRepository(dir+'/state.sqlite');t.after(()=>repository.close());
  const sponsor=await privateSigner(new Uint8Array(32).fill(231)),hash=await digest(wire);
  const ledger=b58(new Uint8Array(Buffer.from(context.slice(64,128),'hex')));
  const profile={endpoint:'http://127.0.0.1:54321/',genesis:ledger,scope:'isolated-solana-validator-synthetic-only',version:'3.1.10',
    programs:{...Object.fromEntries(Object.keys(r.program_data).map(p=>[p,'00'.repeat(32)])),[r.history.program]:COST_POOL_SHA256}};
  let reserveCalls=0;
  const wrapped={read:id=>repository.read(id),compareAndSwapFunded:a=>repository.compareAndSwapFunded(a),configureFunding:a=>repository.configureFunding(a),
    reserveFunding:async(...a)=>{reserveCalls++;return repository.reserveFunding(...a);}};
  const validator=()=>{throw Error('no history here');};validator.settlement=validator;
  const options={raw,context,program:r.history.program,pool:r.history.pool,profile,programData:r.program_data,sponsor,transportSeed:new Uint8Array(32).fill(232),
    repository:wrapped,validator,funding:{totalLamports:'100000000000',requestLamports:'30000000000',maxFeeLamports:'10000'},
    verifyProof:async(k,w,c)=>k===r.kind&&c===context&&await digest(w)===hash,fetchImpl:async()=>{throw Error('no network here');}};
  for(const cleanup of ['yes',1,null])await assert.rejects(()=>LocalRelayTask.open({...options,cleanup}),/Invalid cleanup option/,String(cleanup));
  assert.equal(reserveCalls,0);
  for(const cleanup of [undefined,true,false]){const task=await LocalRelayTask.open(cleanup===undefined?options:{...options,cleanup});assert.ok(task.id);task.close();}
  assert.match(fs.readFileSync(path.join(HERE,'relay-task.mjs'),'utf8'),/cleanup=true,fetchImpl/,'cleaning is the default');
});
test('C18 (static) the task cleans only a SETTLED payment, makes a failed close fatal and lets the journal bind during cleanup',()=>{
  const source=fs.readFileSync(path.join(HERE,'relay-task.mjs'),'utf8');
  assert.match(source,/this\.#state==='settled'&&this\.#cleanup&&!this\.#cleaned/);
  assert.match(source,/if\(result\.state==='failed'\)throw Error\('A cleanup transaction failed on the cluster\.'\)/);
  assert.match(source,/isSettling:\(\)=>t\.#state==='settling'\|\|\(t\.#cleaning&&t\.#state==='settled'\)/);
  assert.match(source,/this\.#cleaning=true;this\.#publisher\.beginCleanup\(\)/);
  assert.match(source,/if\(result\.state!=='cleaned'\)return \{\.\.\.result,id:this\.id,phase:'cleanup'\};\n\s+this\.#cleaned=true;/,'an unfinished cleanup is reported as such and never marked done');
  assert.doesNotMatch(source,/'conflicted'[^;]{0,60}beginCleanup/);
  const sender=fs.readFileSync(path.join(HERE,'publication-sender.mjs'),'utf8');
  assert.match(sender,/beginCleanup\(\)\{this\.#cleanup=true;\}/);
  assert.match(sender,/if\(proof!==null\)return \{type:'close',which:'receipt'\};/);
});

test('C19 a stored close whose descriptor is not canonical (extra work or rent) is refused when the journal loads, for BOTH closes',async t=>{
  for(const [target,landed] of [['receipt-close',0],['buffer-close',1]])for(const field of ['work','rent']) {
    const e=await settled(t);
    for(let i=0;i<landed;i++){await e.step();e.chain.tick();assert.equal((await e.step()).state,'step_confirmed');}   // the earlier close lands and is resolved
    await e.step();                                                                                              // the target close is signed, made durable and sent
    const stored=(await e.record()).pending;assert.equal(stored.length,1);assert.equal(stored[0].descriptor.name,target);
    const ok=await reopen(t,e);assert.equal((await ok.record()).pending.length,1,'control: the untouched journal opens');
    tamper(ok,r=>{r.pending[0].descriptor[field]=1;});
    await assert.rejects(()=>makeEnv({dir:ok.dir,chain:ok.chain,window:8}),undefined,target+' '+field);
  }
});
test('C20 (static) publication mode reports a finished payment as verified, and only the cleanup phase can say cleaned',()=>{
  const sender=fs.readFileSync(path.join(HERE,'publication-sender.mjs'),'utf8');
  assert.match(sender,/if\(action===null\)return this\.#cleanup\?\{id,state:'cleaned'\}:\{id,state:'verified',settled:false\};/);
  assert.match(sender,/#cleanup=false;/);
  assert.equal((sender.match(/this\.#cleanup=/g)??[]).length,1,'the flag is set in exactly one place: beginCleanup()');
  assert.match(sender,/if\(this\.#cleanup\) \{\n      \/\/ Receipt first, then the buffer\./);
});

test('C21 a request the settlement sender reports as settled is NOT reported to the supervisor until its accounts are closed',()=>{
  const settled={id:'x',state:'settled',settled:true},on={id:'task',state:'settled',cleanup:true,cleaned:false};
  assert.deepEqual(routeStepResult(settled,on),{id:'task',state:'cleanup_pending',phase:'cleanup'});
  assert.deepEqual(routeStepResult(settled,{...on,cleanup:false}),{...settled,id:'task'},'cleanup off: reported as before');
  assert.deepEqual(routeStepResult(settled,{...on,cleaned:true}),{...settled,id:'task'},'already cleaned: reported');
  assert.deepEqual(routeStepResult(settled,{...on,state:'settling'}),{...settled,id:'task'},'the task state must also say settled');
  for(const state of ['conflicted','pending','step_confirmed','verified','awaiting_receipt','expired','awaiting_progress'])
    assert.deepEqual(routeStepResult({id:'x',state},on),{id:'task',state},'only settled is held back: '+state);
  assert.deepEqual(routeStepResult({...settled,extra:1},{...on,cleanup:false}),{...settled,extra:1,id:'task'},'the result is passed on whole, with the task id');
  for(const junk of ['yes',1,null,undefined])assert.equal(routeStepResult(settled,{...on,cleanup:junk}).state,'settled','a non-boolean option never holds a result back: '+String(junk));
});
test('C22 (static) the task hands the step result of publication and settlement to the router, the only thing between it and the supervisor',()=>{
  const source=fs.readFileSync(path.join(HERE,'relay-task.mjs'),'utf8');
  assert.match(source,/this\.#active\(\);if\(result\.state==='verified'\)this\.#published=true;\n\s+return routeStepResult\(result,\{id:this\.id,state:this\.#state,cleanup:this\.#cleanup,cleaned:this\.#cleaned\}\);/);
  assert.equal((source.match(/routeStepResult\(/g)??[]).length,2,'defined once, used once');
  assert.doesNotMatch(source,/return \{\.\.\.result,id:this\.id\};\n\s+\}catch/,'the old direct return is gone');
  assert.match(source,/state:'cleanup_pending',phase:'cleanup'/);
});
