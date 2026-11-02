// Checks of the WINDOWED publication revision: journal v2 (a list of pending attempts), funded repository v2, funding quote v2 and the
// windowed sender. Real SQLite, real Ed25519 signing, real transaction decoder and the real buffer account layout; the cluster is the
// model in harness.mjs (see its header for what it does and does not cover). No validator, no Tor, no Chrome: the real-process run is separate.
// Names start with a letter+digit so the mutation control can select tests by pattern.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {DatabaseSync} from 'node:sqlite';
import {makeEnv,FakeChain,BUFFER,WIRES,temp} from './harness.mjs';
import {MAX_WINDOW,VERSION,SponsoredPublication} from './relay-publication.mjs';
import {PublicationSender} from './publication-sender.mjs';
import {publicationJournal} from './publication-adapter.mjs';
import {RelayRepository} from './relay-repository.mjs';
import {LocalRelayTask} from './relay-task.mjs';
import {COST_POOL_SHA256} from './relay-funding.mjs';
import {encodeRequest,readRequest} from '../solana-private-relay-v1/relay-request.mjs';
import {privateSigner,b58} from '../solana-chrome-wallet-v1/recovery/solana-transaction.mjs';
import {digest} from '../solana-chrome-wallet-v1/recovery/payment-wire.mjs';

const HERE=path.dirname(fileURLToPath(import.meta.url));
const FEE=10000n;
async function env(t,options){const e=await makeEnv(options);t.after(()=>{try{e.close();}catch{}fs.rmSync(e.dir,{recursive:true,force:true});});return e;}
async function reopen(t,e,options){const n=await e.reopen(options);t.after(()=>{try{n.close();}catch{}});return n;}
const sigs=rec=>rec.pending.map(a=>a.signature);
const names=rec=>rec.pending.map(a=>a.descriptor.name);
const range=(a,b)=>Array.from({length:b-a},(_,i)=>a+i);
const budgetOf=e=>e.repository.configureFunding({sponsor:e.authority,genesis:e.profile.genesis,totalLamports:'160000000000'});
const charged=async e=>BigInt((await e.fund()).charged_lamports);
async function signWindow(e,indexes){
  const block=e.chain.issue(),ticket=await e.publication.prepareChunks({type:'chunks',indexes});
  return e.publication.signBatch(ticket,block.blockhash,block.lastValidBlockHeight);
}
async function signSingle(e,action){
  const block=e.chain.issue(),ticket=await e.publication.prepare(action);
  return e.publication.sign(ticket,block.blockhash,block.lastValidBlockHeight);
}
function tamper(e,change){
  e.close();const db=new DatabaseSync(e.dir+'/state.sqlite');
  const row=db.prepare('SELECT body FROM operations WHERE id=?').get(e.request.id),body=JSON.parse(row.body);change(body);
  db.prepare('UPDATE operations SET body=? WHERE id=?').run(JSON.stringify(body),e.request.id);db.close();
}
const sends=e=>e.chain.log.filter(x=>x.t==='send');
const done=e=>async()=>e.buffer().pending.length===0&&(await e.record()).pending.length===0;
const settled=(e,n)=>async()=>e.buffer().received>=n&&(await e.record()).pending.length===0;

// ======================================================= J. the journal: a list of pending attempts
test('J1 a new window journal starts empty at revision 1 and reopens identically with the same transport',async t=>{
  const e=await env(t,{window:4}),rec=await e.record();
  assert.equal(rec.version,VERSION);assert.deepEqual(rec.pending,[]);assert.equal(rec.attempts,0);assert.equal(rec.revision,1);assert.equal(rec.last,null);
  const again=await reopen(t,e);
  assert.deepEqual(await again.record(),rec);assert.deepEqual(again.transport,e.transport);
});
test('J2 a window is signed, verified and made durable in ONE commit, with one debit of N fee ceilings',async t=>{
  const e=await env(t,{window:8}),before=await e.record(),block=e.chain.issue();
  const ticket=await e.publication.prepareChunks({type:'chunks',indexes:range(0,8)});
  const probe=await e.publication.simulations(ticket,block.blockhash);
  assert.equal(probe.unsigned,true);assert.equal(probe.raws.length,8);
  for(const raw of probe.raws)assert.ok(Buffer.from(raw,'base64').subarray(1,65).every(x=>x===0),'the probe must carry no signature');
  const signed=await e.publication.signBatch(ticket,block.blockhash,block.lastValidBlockHeight);
  const after=await e.record();
  assert.equal(signed.durable,true);assert.equal(after.revision,before.revision+1);assert.equal(after.pending.length,8);assert.equal(after.attempts,8);
  assert.deepEqual(names(after),range(0,8).map(i=>'chunk-'+i));
  assert.deepEqual(after.pending.map(a=>a.raw),signed.attempts.map(a=>a.raw));
  assert.equal(new Set(sigs(after)).size,8);
  assert.equal(await charged(e),8n*FEE);
  assert.deepEqual((await e.publication.pending()).map(a=>a.signature),sigs(after));
});
test('J3 nothing new can be prepared while any attempt is pending',async t=>{
  const e=await env(t,{window:4});await signWindow(e,[0,1]);
  await assert.rejects(()=>e.publication.prepare({type:'seal'}),/Resolve the existing signed transaction first/);
  await assert.rejects(()=>e.publication.prepare({type:'chunk',index:5}),/Resolve the existing signed transaction first/);
  await assert.rejects(()=>e.publication.prepareChunks({type:'chunks',indexes:[5,6]}),/Resolve the existing signed transaction first/);
});
test('J4 a chunk window must be non-empty, distinct, in range and at most MAX_WINDOW',async t=>{
  const e=await env(t,{window:4});
  for(const indexes of [[],[1,1],range(0,MAX_WINDOW+1),[e.plan.count],[-1],[1.5],'0',[0,'1'],null])
    await assert.rejects(()=>e.publication.prepareChunks({type:'chunks',indexes}),undefined,JSON.stringify(indexes));
  await assert.rejects(()=>e.publication.prepareChunks({type:'chunks',indexes:[0],extra:1}));
  await assert.rejects(()=>e.publication.prepareChunks({type:'chunk',indexes:[0]}));
  const full=await signWindow(e,range(0,MAX_WINDOW));assert.equal(full.attempts.length,MAX_WINDOW);
  assert.equal((await e.record()).pending.length,MAX_WINDOW);
});
test('J5 a tampered or malformed pending list is refused when the journal is reopened',async t=>{
  const base=await env(t,{window:4});await signWindow(base,[0,1,2]);
  const original=await base.record(),seal=await (async()=>{
    const other=await env(t,{window:4});return signSingle(other,{type:'seal'});})();
  const cases={
    'a raw that belongs to another attempt':[r=>{r.pending[0].raw=r.pending[1].raw;},/Publication signer differs|differs/],
    'a duplicated attempt':[r=>{r.pending[1]=structuredClone(r.pending[0]);},/Duplicate pending|distinct chunk/],
    'a seal next to chunk uploads':[r=>{r.pending[1]={descriptor:seal.descriptor,raw:seal.raw,signature:seal.signature,last_valid_height:seal.last_valid_height};},/Only distinct chunk uploads/],
    'more pending attempts than were ever signed':[r=>{r.attempts=1;},/Invalid pending publication list/],
    'the original single-object shape':[r=>{r.pending=r.pending[0];},/Invalid pending publication list/],
    'the frozen v1 version label':[r=>{r.version='zk9-sponsored-publication-journal-v1';},/Relay request binding changed/],
    'a foreign wire hash':[r=>{r.wire_hash='00'.repeat(32);},/Relay request binding changed/],
    'a foreign transport':[r=>{r.transport.source=r.transport.receipt;},/Relay request binding changed/],
  };
  for(const [label,[change,expected]] of Object.entries(cases)) {
    const e=await env(t,{window:4});await signWindow(e,[0,1,2]);
    tamper(e,change);
    await assert.rejects(()=>makeEnv({dir:e.dir,chain:e.chain,window:4}),expected,label);
  }
  assert.equal(original.pending.length,3);
  // MAX_WINDOW + 1 DISTINCT, individually valid chunk uploads: only the bound on the list can refuse them.
  const wide=await env(t,{window:4}),extra=await env(t,{window:4});
  await signWindow(wide,range(0,MAX_WINDOW));const one=await signWindow(extra,[MAX_WINDOW]);
  tamper(wide,r=>{r.attempts=500;r.pending.push({descriptor:one.attempts[0].descriptor,raw:one.attempts[0].raw,signature:one.attempts[0].signature,last_valid_height:one.attempts[0].last_valid_height});});
  await assert.rejects(()=>makeEnv({dir:wide.dir,chain:wide.chain,window:4}),/Invalid pending publication list/,'129 distinct valid chunks');
});
test('J6 resolveMany resolves only the listed attempts, in one commit, and refuses everything else',async t=>{
  const e=await env(t,{window:8});const signed=await signWindow(e,range(0,6)),s=signed.attempts.map(a=>a.signature),before=await e.record();
  await e.publication.resolveMany([{signature:s[0],outcome:'confirmed',height:5},{signature:s[1],outcome:'failed',height:6}]);
  const after=await e.record();
  assert.equal(after.revision,before.revision+1);assert.deepEqual(sigs(after),s.slice(2));assert.equal(after.attempts,6);
  assert.deepEqual(after.last,{signature:s[1],outcome:'failed',height:6});
  const bad=[[],[{signature:'x'.repeat(88),outcome:'confirmed',height:1}],[{signature:s[2],outcome:'confirmed',height:1},{signature:s[2],outcome:'confirmed',height:1}],
    [{signature:s[0],outcome:'confirmed',height:1}],[{signature:s[2],outcome:'weird',height:1}],[{signature:s[2],outcome:'confirmed',height:-1}],
    [{signature:s[2],outcome:'confirmed',height:1.5}],[{signature:s[2],outcome:'confirmed',height:1,extra:true}],[null],
    [{signature:s[2],outcome:'weird',height:1},{signature:s[3],outcome:'confirmed',height:1}],
    [{signature:s[2],outcome:'confirmed',height:-1},{signature:s[3],outcome:'confirmed',height:1}],
    [{signature:s[2],outcome:'confirmed',height:1,extra:true},{signature:s[3],outcome:'confirmed',height:1}],
    Array.from({length:MAX_WINDOW+1},()=>({signature:s[2],outcome:'confirmed',height:1}))];
  for(const entries of bad)await assert.rejects(()=>e.publication.resolveMany(entries),undefined,JSON.stringify(entries).slice(0,80));
  assert.deepEqual(await e.record(),after,'a refused resolution must change nothing');
  await e.publication.resolve(s[2],{outcome:'confirmed',height:7});assert.deepEqual(sigs(await e.record()),s.slice(3));
});
test('J7 an expiry needs BOTH the missing-signature proof and a height past the blockhash lifetime; one unproven entry refuses the whole call',async t=>{
  const e=await env(t,{window:4});const signed=await signWindow(e,[0,1,2]),s=signed.attempts.map(a=>a.signature),last=signed.attempts[0].last_valid_height;
  await assert.rejects(()=>e.publication.resolveMany([{signature:s[0],outcome:'expired',height:last+1}]),/Unproven transaction expiry/);
  await assert.rejects(()=>e.publication.resolveMany([{signature:s[0],outcome:'expired',height:last+1,missingAfterExpiry:false}]),/Unproven transaction expiry/);
  await assert.rejects(()=>e.publication.resolveMany([{signature:s[0],outcome:'expired',height:last,missingAfterExpiry:true}]),/Unproven transaction expiry/);
  await assert.rejects(()=>e.publication.resolveMany([{signature:s[0],outcome:'expired',height:last+1,missingAfterExpiry:true},
    {signature:s[1],outcome:'expired',height:last-1,missingAfterExpiry:true}]),/Unproven transaction expiry/);
  assert.equal((await e.record()).pending.length,3,'nothing may be resolved by a refused call');
  await e.publication.resolveMany([{signature:s[0],outcome:'expired',height:last+1,missingAfterExpiry:true},{signature:s[1],outcome:'expired',height:last+9,missingAfterExpiry:true}]);
  assert.deepEqual(sigs(await e.record()),[s[2]]);
});
test('J8 a ticket serves only its own kind, only once, and only at the revision it was prepared',async t=>{
  const e=await env(t,{window:4}),block=e.chain.issue();
  const batch=await e.publication.prepareChunks({type:'chunks',indexes:[0,1]}),single=await e.publication.prepare({type:'seal'});
  await assert.rejects(()=>e.publication.sign(batch,block.blockhash,block.lastValidBlockHeight),/Unknown or stale relay ticket/);
  await assert.rejects(()=>e.publication.simulation(batch,block.blockhash),/Unknown or stale relay ticket/);
  await assert.rejects(()=>e.publication.signBatch(single,block.blockhash,block.lastValidBlockHeight),/Unknown or stale relay ticket/);
  await assert.rejects(()=>e.publication.simulations(single,block.blockhash),/Unknown or stale relay ticket/);
  await e.publication.signBatch(batch,block.blockhash,block.lastValidBlockHeight);
  await assert.rejects(()=>e.publication.signBatch(batch,block.blockhash,block.lastValidBlockHeight),/Unknown or stale relay ticket/);
  await assert.rejects(()=>e.publication.sign(single,block.blockhash,block.lastValidBlockHeight),/Unknown or stale relay ticket/);
});
test('J9 the attempt counter counts every signed attempt, window or single',async t=>{
  const e=await env(t,{window:8});
  const a=await signWindow(e,range(0,5));await e.publication.resolveMany(a.attempts.map(x=>({signature:x.signature,outcome:'confirmed',height:1})));
  const b=await signSingle(e,{type:'seal'});await e.publication.resolve(b.signature,{outcome:'failed',height:2});
  await signWindow(e,range(5,8));
  assert.equal((await e.record()).attempts,5+1+3);
});

// ======================================================= R. funded repository and funding quote
test('R1 a window is charged N fee CEILINGS (not the lower quote) and an empty-to-full commit is the only one that is charged',async t=>{
  const e=await env(t,{window:8,maxFee:'7'});e.chain.feeQuote=3;
  const real=e.net.rpc.bind(e.net),messages=[];e.net.rpc=async(method,params)=>{if(method==='getFeeForMessage')messages.push(params[0]);return real(method,params);};
  const signed=await signWindow(e,range(0,6));
  assert.equal(messages.length,6);
  for(const a of signed.attempts){const raw=Buffer.from(a.raw,'base64');assert.ok(messages.includes(raw.subarray(1+raw[0]*64).toString('base64')),'only the unsigned message is quoted');}
  assert.equal(await charged(e),6n*7n);
  const quoteCalls=e.net.calls.filter(m=>m==='getFeeForMessage').length;assert.equal(quoteCalls,6);
  await e.publication.resolveMany(signed.attempts.slice(0,2).map(a=>({signature:a.signature,outcome:'confirmed',height:1})));
  assert.equal(await charged(e),6n*7n,'a partial resolution costs nothing');
  assert.equal(e.net.calls.filter(m=>m==='getFeeForMessage').length,quoteCalls,'and asks for no quote');
});
test('R2 a shrinking pending list takes no debit, and a debit on a resolution is refused',async t=>{
  const e=await env(t,{window:8});await signWindow(e,range(0,6));
  const rec=await e.record(),budget=await budgetOf(e);
  const shrunk={...rec,revision:rec.revision+1,pending:rec.pending.slice(2),last:{signature:rec.pending[0].signature,outcome:'confirmed',height:5}};
  const commit=(value,debit)=>e.repository.compareAndSwapFunded({id:e.request.id,expectedRevision:rec.revision,value,budget,requestId:e.request.id,debitLamports:debit});
  await assert.rejects(()=>commit(shrunk,'1'),/Funding debit must match a new signed attempt/);
  await commit(shrunk,'0');assert.equal(await charged(e),6n*FEE);
});
test('R3 attempts can only enter an EMPTY list and a retained attempt can never be replaced or duplicated',async t=>{
  const e=await env(t,{window:8});await signWindow(e,range(0,4));
  const rec=await e.record(),budget=await budgetOf(e),extra={descriptor:{name:'chunk-99',rent:0,work:0},raw:'extra',signature:'extra-signature',last_valid_height:1};
  const commit=(value,debit='0')=>e.repository.compareAndSwapFunded({id:e.request.id,expectedRevision:rec.revision,value:{...rec,revision:rec.revision+1,...value},budget,requestId:e.request.id,debitLamports:debit});
  await assert.rejects(()=>commit({attempts:rec.attempts+1,pending:[...rec.pending,extra]},String(FEE)),/Cannot replace unresolved funded transaction/);
  await assert.rejects(()=>commit({attempts:rec.attempts+1,pending:[extra]},String(FEE)),/Cannot replace unresolved funded transaction/);
  await assert.rejects(()=>commit({pending:[{...rec.pending[0],raw:rec.pending[0].raw+'A'},...rec.pending.slice(1)]}),/Cannot replace unresolved funded transaction/);
  await assert.rejects(()=>commit({pending:[rec.pending[0],rec.pending[0]]}),/Duplicate pending attempt/);
  await assert.rejects(()=>commit({pending:'not a list'}),/Pending attempt list required/);
  assert.deepEqual(await e.record(),rec);assert.equal(await charged(e),4n*FEE);
});
test('R4 the per-request funding cap bounds the CUMULATIVE cost of windows; a refused window stores and charges nothing',async t=>{
  const e=await env(t,{window:32,requestLamports:'250000'});
  await assert.rejects(()=>signWindow(e,range(0,32)),/Request funding limit exceeded/);
  assert.deepEqual((await e.record()).pending,[]);assert.equal(await charged(e),0n);
  const a=await signWindow(e,range(0,24));assert.equal(await charged(e),24n*FEE);
  await e.publication.resolveMany(a.attempts.map(x=>({signature:x.signature,outcome:'confirmed',height:1})));
  await assert.rejects(()=>signWindow(e,range(24,48)),/Request funding limit exceeded/);
  assert.equal(await charged(e),24n*FEE);assert.equal((await e.record()).attempts,24);
});
test('R5 the attempt cap counts the whole window, and a window that fits exactly is accepted',async t=>{
  const e=await env(t,{window:32,maxAttempts:32});
  const a=await signWindow(e,range(0,32));assert.equal((await e.record()).attempts,32);
  await e.publication.resolveMany(a.attempts.map(x=>({signature:x.signature,outcome:'confirmed',height:1})));
  await assert.rejects(()=>signWindow(e,[32]),/Local relay publication budget exhausted/);
  assert.equal((await e.record()).attempts,32);
  const small=await env(t,{window:32,maxAttempts:20});
  await assert.rejects(()=>signWindow(small,range(0,32)),/Local relay publication budget exhausted/);
  assert.equal((await small.record()).attempts,0);
});
test('R6 the quote refuses a window when ANY fee is unavailable or above the cap, or the balance cannot cover all of it',async t=>{
  const e=await env(t,{window:32});
  e.chain.feeQuote=i=>i===31?20000:5000;await assert.rejects(()=>signWindow(e,range(0,32)),/Fee unavailable or above operator cap/);
  e.chain.feeQuote=0;await assert.rejects(()=>signWindow(e,range(0,32)),/Fee unavailable or above operator cap/);
  e.chain.feeQuote=5000;e.chain.balance=32*Number(FEE)-1;await assert.rejects(()=>signWindow(e,range(0,32)),/Sponsor balance insufficient or stale/);
  const real=e.net.rpc.bind(e.net);e.chain.balance=1e15;
  e.net.rpc=async(method,params)=>{const r=await real(method,params);return method==='getBalance'?{context:{slot:r.context.slot-1},value:r.value}:r;};
  await assert.rejects(()=>signWindow(e,range(0,32)),/Sponsor balance insufficient or stale/,'a balance older than the quotes');
  e.net.rpc=real;e.chain.balance=1e15;e.chain.balance=32*Number(FEE);
  await signWindow(e,range(0,32));
  assert.equal(await charged(e),32n*FEE);
});
test('R7 settlement journals keep the original single-attempt funding rules in the v2 repository',async t=>{
  const e=await env(t,{window:4}),rec=await e.record(),budget=await budgetOf(e),sid='44'.repeat(32);
  const state={version:'zk9-sponsored-settlement-v1',id:sid,request_id:e.request.id,wire_hash:'33'.repeat(32),transport:rec.transport,revision:1,observed_slot:0,pending:null,last:null};
  const commit=(value,expectedRevision,debit='0',id=sid)=>e.repository.compareAndSwapFunded({id,expectedRevision,value,budget,requestId:e.request.id,debitLamports:debit});
  await commit(state,null);
  const packet={raw:'settle-1',signature:'settle-sig-1',confirmed_slot:null};
  await assert.rejects(()=>commit({...state,revision:2,pending:packet},1,'0'),/Funding debit must match/);
  await commit({...state,revision:2,pending:packet},1,'300');
  await commit({...state,revision:3,pending:{...packet,confirmed_slot:77}},2,'0');
  await assert.rejects(()=>commit({...state,revision:4,pending:{...packet,raw:'other'}},3,'0'),/Cannot replace unresolved funded transaction/);
  await assert.rejects(()=>commit({...state,revision:4,pending:{raw:'settle-2',signature:'settle-sig-2'}},3,'300'),/Cannot replace unresolved funded transaction/);
  await assert.rejects(()=>commit({...state,revision:4,pending:{...packet,confirmed_slot:77}},3,'1'),/Funding debit must match/);
  await commit({...state,revision:4,pending:null},3,'0');
  await commit({...state,revision:5,pending:{raw:'settle-3',signature:'settle-sig-3'}},4,'300');
  assert.equal(await charged(e),600n);
});
test('R8 record sizes: a window record up to 512 KiB, every other record stays at 32 KiB, foreign labels are refused',async t=>{
  assert.equal(MAX_WINDOW,128,'the 512 KiB record bound was sized for 128 attempts');
  const e=await env(t,{window:4}),rec=await e.record(),budget=await budgetOf(e),sid='55'.repeat(32);
  const commit=(value,id=sid,expectedRevision=null,debit='0')=>e.repository.compareAndSwapFunded({id,expectedRevision,value,budget,requestId:e.request.id,debitLamports:debit});
  const settlement={version:'zk9-sponsored-settlement-v1',id:sid,request_id:e.request.id,transport:rec.transport,revision:1,pending:null};
  await assert.rejects(()=>commit({...settlement,junk:'x'.repeat(40000)}),/Relay record too large/);
  await commit({...settlement,junk:'x'.repeat(20000)});
  await assert.rejects(()=>commit({...rec,revision:2,junk:'x'.repeat(600000)},e.request.id,1),/Relay record too large/);
  await assert.rejects(()=>commit({...rec,revision:2,version:'zk9-sponsored-publication-journal-v1'},e.request.id,1),/Foreign funded journal/);
  await assert.rejects(()=>commit({...rec,revision:1,id:sid},sid,null),/Foreign funded journal/);
  const full=await signWindow(e,range(0,MAX_WINDOW));
  assert.ok(Buffer.byteLength(JSON.stringify(await e.record()))>200000&&full.attempts.length===MAX_WINDOW);
});
test('R10 the window quote is bound to the sponsor, to a non-empty bounded list and to the exact sum',async t=>{
  const {quoteFundingDebit}=await import('./relay-funding.mjs');
  const e=await env(t,{window:8});await signWindow(e,range(0,5));
  const value=await e.record(),quote=(patch={},sponsor=e.authority)=>quoteFundingDebit({value:{...value,...patch},network:e.net,sponsor,program:e.pool,kind:'send',maxFeeLamports:'10000'});
  assert.equal(await quote(),String(5n*FEE));
  await assert.rejects(()=>quote({},b58(new Uint8Array(32).fill(9))),/Foreign funding authority/);
  await assert.rejects(()=>quote({pending:[]}),/Missing signed attempts/);
  await assert.rejects(()=>quote({pending:null}),/Missing signed attempts/);
  await assert.rejects(()=>quote({pending:Array.from({length:MAX_WINDOW+1},()=>value.pending[0])}),/Missing signed attempts/);
});
test('R9 a window and its debit become durable together or not at all, across SIGKILL of the process',async t=>{
  for(const mode of ['before-commit','after-commit']) {
    const dir=temp();t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
    const child=spawnSync(process.execPath,[path.join(HERE,'crash-child.mjs'),dir,mode],{encoding:'utf8'});
    assert.equal(child.signal,'SIGKILL',mode+': '+child.stderr);
    const chain=new FakeChain();chain.issue();           // the child's blockhash (deterministic by height)
    const e=await env(t,{window:16,dir,chain}),rec=await e.record();
    if(mode==='before-commit') {
      assert.deepEqual(rec.pending,[]);assert.equal(rec.attempts,0);assert.equal(await charged(e),0n);
    }else{
      assert.equal(rec.pending.length,16);assert.equal(rec.attempts,16);assert.equal(await charged(e),16n*FEE,'the whole window is debited with its commit');
      const stored=sigs(rec);
      await e.step();                                         // the reopened relay releases exactly the stored bytes
      assert.deepEqual(sends(e).map(x=>x.sig).sort(),stored.slice().sort());assert.deepEqual(chain.violations,[]);
      assert.equal((await e.record()).attempts,16,'a restart must not sign again');
    }
  }
});

// ======================================================= S. the windowed sender
test('S1 a whole chunk phase with window 128: every chunk once, one commit to sign and one to resolve each window, the buffer equals the wire',{timeout:300000},async t=>{
  const e=await env(t,{window:128});
  await e.drive(done(e),{max:200});
  const buffer=e.buffer(),rec=await e.record(),windows=Math.ceil(e.plan.count/128);
  assert.equal(buffer.received,e.plan.count);assert.deepEqual(buffer.pending,[]);assert.equal(buffer.sealed,false);
  assert.equal(rec.attempts,e.plan.count,'no chunk needed a second attempt');
  assert.equal(sends(e).length,e.plan.count);assert.equal(new Set(sends(e).map(x=>x.idx)).size,e.plan.count);
  assert.deepEqual(e.chain.violations,[],'nothing was released before its commit');
  assert.equal(e.events.length,1+2*windows);
  assert.ok(e.events.every(ev=>ev.pending.length<=128));
  assert.equal(e.net.calls.filter(m=>m==='getFeeForMessage').length,e.plan.count);
  assert.equal(e.net.calls.filter(m=>m==='getBalance').length,windows);
  assert.equal(await charged(e),BigInt(e.plan.count)*FEE);
  await e.drive(async()=>e.buffer().sealed,{max:10});
  assert.equal((await e.record()).attempts,e.plan.count+1);
});
test('S2 window 1 is the original sender: one attempt, one commit pair and one transaction per chunk',async t=>{
  const e=await env(t,{window:1});
  const results=await e.drive(settled(e,12),{max:100});
  assert.ok(results.every(r=>/^chunk-\d+$/.test(r.step)),JSON.stringify(results[0]));
  assert.ok(e.events.every(ev=>ev.pending.length<=1));
  assert.equal((await e.record()).attempts,12);assert.equal(sends(e).length,12);assert.equal(await charged(e),12n*FEE);
  assert.deepEqual(e.chain.violations,[]);
});
test('S3 the step results of a clean window are pending, then step_confirmed; a lost send is not a failure',async t=>{
  const e=await env(t,{window:8});
  assert.equal((await e.step()).state,'pending');e.chain.tick();
  const second=await e.step();assert.equal(second.state,'step_confirmed');assert.equal(second.step,'chunks-8');
  assert.deepEqual((await e.record()).pending,[]);
  e.chain.sendErrors=3;const third=await e.step();assert.equal(third.state,'pending');
  e.chain.tick();await e.drive(settled(e,16),{max:20});
  assert.equal((await e.record()).attempts,16,'unknown send outcomes never re-sign');
});
test('S4 a restart after the durable commit but before any send releases exactly the stored bytes and signs nothing new',async t=>{
  const flag={crash:true};
  const wrap=base=>({...base,compareAndSwapFunded:async a=>{const r=await base.compareAndSwapFunded(a);
    if(flag.crash&&Array.isArray(a.value.pending)&&a.value.pending.length>1){flag.crash=false;throw Error('process died after the durable commit');}return r;}});
  const e=await env(t,{window:8,wrap});
  await assert.rejects(()=>e.step(),/process died after the durable commit/);
  assert.equal(sends(e).length,0,'nothing may leave before the commit returns');
  const stored=await e.record();assert.equal(stored.pending.length,8);
  const again=await reopen(t,e);
  await again.step();
  assert.deepEqual(sends(again).map(x=>x.sig).sort(),sigs(stored).slice().sort());assert.deepEqual(again.chain.violations,[]);
  again.chain.tick();await again.drive(settled(again,8),{max:20});
  assert.equal((await again.record()).attempts,8);assert.equal(again.buffer().received,8);
});
test('S5 a partial landing resends ONLY the chunks the cluster has not seen, with the same bytes',async t=>{
  const e=await env(t,{window:8});e.chain.dropSends.set(2,1);e.chain.dropSends.set(5,2);
  await e.drive(settled(e,8),{max:30});
  const perIndex=new Map();for(const s of sends(e))perIndex.set(s.idx,(perIndex.get(s.idx)??0)+1);
  assert.equal(perIndex.get(2),2);assert.equal(perIndex.get(5),3);
  for(const i of [0,1,3,4,6,7])assert.equal(perIndex.get(i),1,'chunk '+i+' landed and must never be resent');
  const bySig=new Map();for(const s of sends(e).filter(x=>x.idx===5))bySig.set(s.sig,true);
  assert.equal(bySig.size,1,'a resend carries the same signed bytes');
  assert.equal((await e.record()).attempts,8);assert.equal(e.buffer().received,8);assert.deepEqual(e.chain.violations,[]);
});
test('S6 a blockhash that expired with the chunk still unknown resolves it as EXPIRED with proof, and the chunk goes into a fresh window',async t=>{
  const e=await env(t,{window:8});e.chain.neverLand.add(3);e.chain.neverLand.add(6);
  assert.equal((await e.step()).state,'pending');e.chain.tick();
  assert.equal((await e.step()).state,'pending');e.chain.tick();
  assert.deepEqual(names(await e.record()),['chunk-3','chunk-6'],'six landed; the two unknown ones stay pending while the blockhash lives');
  e.chain.height+=500;
  const expired=await e.step();assert.equal(expired.state,'expired');
  const rec=await e.record();assert.deepEqual(rec.pending,[]);assert.equal(rec.last.outcome,'expired');
  assert.ok(e.events.some(ev=>ev.pending.length===0&&ev.revision===rec.revision&&ev.last?.outcome==='expired'));
  e.chain.neverLand.clear();
  await e.drive(settled(e,14),{max:30});
  const final=await e.record();
  assert.equal(final.attempts,16,'the two expired chunks were signed again, the six that landed were not');
  assert.equal(e.buffer().received,14);assert.deepEqual(e.chain.violations,[]);
});
test('S7 a chunk that shows up at the second lookup is CONFIRMED, never expired',async t=>{
  const e=await env(t,{window:4});
  await e.step();e.chain.tick();
  const real=e.net.rpc.bind(e.net);let lookups=0;
  e.net.rpc=async(method,params)=>{if(method==='getSignatureStatuses'&&++lookups===1)return {context:{slot:e.chain.slot},value:params[0].map(()=>null)};return real(method,params);};
  e.chain.height+=500;
  const result=await e.step();
  assert.equal(result.state,'step_confirmed');assert.equal((await e.record()).last.outcome,'confirmed');
  assert.ok(!e.events.some(ev=>ev.last?.outcome==='expired'),'no expiry may be recorded for a chunk that landed');
});
test('S8 a chunk that lands with an error is recorded as failed, the others are resolved, and the step does not go on silently',async t=>{
  const e=await env(t,{window:8});e.chain.failIdx.add(4);
  await e.step();e.chain.tick();
  await assert.rejects(()=>e.step(),/failed on the cluster/);
  const rec=await e.record();
  assert.deepEqual(rec.pending,[],'all eight are decided');assert.equal(rec.last.outcome,'failed','a failure is what `last` shows');
  assert.equal(e.buffer().received,7);
  const again=await reopen(t,e);                              // the supervisor reopens the task: chunk 4 goes into a new window
  await again.step();again.chain.tick();
  await assert.rejects(()=>again.step(),/failed on the cluster/);
  assert.equal((await again.record()).attempts,8+8);
});
test('S9 a confirmed status whose effect is not visible in the buffer stays pending as awaiting_progress',async t=>{
  const e=await env(t,{window:8});
  await e.step();e.chain.tick();
  e.chain.staleReads=1;
  const waiting=await e.step();
  assert.equal(waiting.state,'awaiting_progress');assert.equal((await e.record()).pending.length,1,'only the chunk whose effect is visible is resolved');
  assert.equal(sends(e).length,8,'a chunk the cluster already confirmed is never sent again');
  assert.equal(e.net.calls.filter(m=>m==='sendTransaction').length,8,'and it is not even offered to the RPC again');
  const next=await e.step();assert.equal(next.state,'step_confirmed');assert.deepEqual((await e.record()).pending,[]);
});
test('S10 a failing commit releases nothing: no send, no pending, no debit',async t=>{
  const flag={fail:true};
  const wrap=base=>({...base,compareAndSwapFunded:async a=>{if(flag.fail&&Array.isArray(a.value.pending)&&a.value.pending.length>1)throw Error('disk full');return base.compareAndSwapFunded(a);}});
  const e=await env(t,{window:8,wrap});
  await assert.rejects(()=>e.step(),/disk full/);
  assert.equal(sends(e).length,0);assert.deepEqual((await e.record()).pending,[]);assert.equal(await charged(e),0n);assert.equal((await e.record()).attempts,0);
  flag.fail=false;await e.step();assert.equal(sends(e).length,8);assert.deepEqual(e.chain.violations,[]);
});
test('S11 a simulation that rejects any chunk stops the window before anything is signed',async t=>{
  const e=await env(t,{window:8});e.chain.simulateFail=true;
  await assert.rejects(()=>e.step(),/Proof simulation rejected the instruction/);
  assert.deepEqual((await e.record()).pending,[]);assert.equal((await e.record()).attempts,0);assert.equal(sends(e).length,0);assert.equal(await charged(e),0n);
});
test('S12 a window left pending is finished whatever window the restarted sender is configured with, and later windows obey the new size',async t=>{
  const flag={crash:true};
  const wrap=base=>({...base,compareAndSwapFunded:async a=>{const r=await base.compareAndSwapFunded(a);
    if(flag.crash&&Array.isArray(a.value.pending)&&a.value.pending.length>1){flag.crash=false;throw Error('process died after the durable commit');}return r;}});
  const e=await env(t,{window:16,wrap});
  await assert.rejects(()=>e.step(),/process died/);
  const small=await reopen(t,e,{window:4});
  await small.step();assert.equal(sends(small).length,16,'all sixteen stored attempts are released although the window is now 4');
  small.chain.tick();
  await small.drive(settled(small,24),{max:40});
  assert.equal((await small.record()).attempts,16+8,'two further windows of 4');
  assert.ok(small.events.every(ev=>ev.pending.length<=4),'no new window is larger than the configured size');
  assert.ok(small.events.some(ev=>ev.pending.length===4));assert.deepEqual(small.chain.violations,[]);
});
test('S13 the window size is validated by the sender and never exceeded',async t=>{
  const e=await env(t,{window:5});
  const make=window=>new PublicationSender({network:e.net,journal:e.journal,synchronize:async()=>{},context:e.context,program:e.pool,kind:e.kind,window});
  for(const bad of [0,-1,1.5,MAX_WINDOW+1,'8',null,NaN])assert.throws(()=>make(bad),/Invalid chunk window size/,String(bad));
  assert.doesNotThrow(()=>make(1));assert.doesNotThrow(()=>make(MAX_WINDOW));
  await e.drive(async()=>e.buffer().received>=20&&(await e.record()).pending.length===0,{max:60});
  assert.ok(e.events.every(ev=>ev.pending.length<=5));
  assert.ok(e.events.some(ev=>ev.pending.length===5));
});
test('S14 only one step runs at a time',async t=>{
  const e=await env(t,{window:4});
  const first=e.step();await assert.rejects(()=>e.step(),/Wait for the current publication step/);
  await first;
});
test('S15 a cluster that has not reached the minimum slot is a pending result, not a failure',async t=>{
  const e=await env(t,{window:4});
  const real=e.net.rpc.bind(e.net);e.net.rpc=async(method,params)=>{if(method==='getLatestBlockhash'){const err=new Error('min context');err.rpcCode=-32016;throw err;}return real(method,params);};
  const result=await e.step();assert.equal(result.state,'pending');assert.equal(result.reason,'rpc_minimum_slot_not_reached');
  assert.equal(sends(e).length,0);
});

test('S16 a status that is only processed is neither a confirmation, nor an expiry, nor a reason to send again',async t=>{
  const e=await env(t,{window:4});e.chain.processedOnly.add(1);
  await e.step();e.chain.tick();
  const mid=await e.step();
  assert.equal(mid.state,'pending');assert.deepEqual(names(await e.record()),['chunk-1']);
  const before=e.net.calls.filter(m=>m==='sendTransaction').length;
  e.chain.height+=500;                                           // the blockhash is gone, the cluster still knows the signature
  const late=await e.step();
  assert.equal(late.state,'pending');assert.deepEqual(names(await e.record()),['chunk-1'],'processed-only is never recorded as expired');
  assert.equal(e.net.calls.filter(m=>m==='sendTransaction').length,before,'and a dead blockhash is not sent again');
  e.chain.processedOnly.clear();
  const final=await e.step();assert.equal(final.state,'step_confirmed');assert.deepEqual((await e.record()).pending,[]);
});
test('S17 an attempt that shows up as processed only between the two lookups is not sent again with a dead blockhash',async t=>{
  const e=await env(t,{window:4});e.chain.processedOnly.add(1);
  await e.step();e.chain.tick();
  const real=e.net.rpc.bind(e.net);let lookups=0;
  e.net.rpc=async(method,params)=>{if(method==='getSignatureStatuses'&&++lookups===1)return {context:{slot:e.chain.slot},value:params[0].map(()=>null)};return real(method,params);};
  const before=e.net.calls.filter(m=>m==='sendTransaction').length;
  e.chain.height+=500;
  const result=await e.step();
  assert.equal(result.state,'pending');assert.deepEqual(names(await e.record()),['chunk-1']);
  assert.equal(e.net.calls.filter(m=>m==='sendTransaction').length,before);
});
test('S18 the sender refuses an RPC that answers inconsistently: another signature, a short status list, a pending list that changed before the resend',async t=>{
  const e=await env(t,{window:4});const real=e.net.rpc.bind(e.net);
  e.net.rpc=async(method,params)=>{const r=await real(method,params);return method==='sendTransaction'?r.split('').reverse().join(''):r;};
  await assert.rejects(()=>e.step(),/different publication signature/);
  const f=await env(t,{window:4});await f.step();f.chain.tick();
  const realF=f.net.rpc.bind(f.net);
  f.net.rpc=async(method,params)=>{const r=await realF(method,params);return method==='getSignatureStatuses'?{...r,value:r.value.slice(1)}:r;};
  await assert.rejects(()=>f.step(),/Invalid publication status response/);
  const g=await env(t,{window:4});g.chain.neverLand.add(2);await g.step();g.chain.tick();
  const realPending=g.journal.pending;let calls=0;
  g.journal.pending=async id=>{const list=await realPending(id);return ++calls===2?list.map(a=>({...a,raw:a.raw.slice(0,-4)+'AAAA'})):list;};
  await assert.rejects(()=>g.step(),/Pending publication changed before send/);
});
// ======================================================= A. the adapter and the task
test('A1 the adapter checks the request id on every call and refuses to bind a payment that is no longer settling',async t=>{
  const e=await env(t,{window:4});
  const journal=publicationJournal({publication:e.publication,checkedId:id=>{if(id!==e.logicalId)throw Error('Foreign request entered relay task.');},isSettling:()=>false});
  const foreign='00'.repeat(16);
  for(const call of [()=>journal.pending(foreign),()=>journal.prepare(foreign,{type:'seal'}),()=>journal.prepareChunks(foreign,{type:'chunks',indexes:[0]}),
    ()=>journal.signBatch(foreign,{},'x',1),()=>journal.simulations(foreign,{},'x'),()=>journal.resolveMany(foreign,[{signature:'x',outcome:'confirmed',height:1}])])
    assert.throws(call,/Foreign request/);
  await assert.rejects(()=>journal.bind(e.logicalId),/Proof already spent or conflicted/);
  assert.deepEqual(await journal.pending(e.logicalId),[]);
});
test('A2 opening the task wires the v2 journal and v2 funding, validates the window before reserving funds, and reopens identically',async t=>{
  const base=path.join(HERE,'../solana-chrome-wallet-v1/'),fixturePath=fs.realpathSync(base+'evidence/settlement-plan-01/PUBLIC-FIXTURES.json');   // the pins are keyed by real path
  const bytes=fs.readFileSync(fixturePath),pins=JSON.parse(fs.readFileSync(base+'evidence/settlement-journal-01/INPUTS.json'));
  const {createHash}=await import('node:crypto');
  assert.equal(createHash('sha256').update(bytes).digest('hex'),pins[Object.keys(pins).find(k=>k.endsWith('/evidence/settlement-plan-01/PUBLIC-FIXTURES.json'))]);
  const fixtures=JSON.parse(bytes),dir=temp();t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
  const repository=new RelayRepository(dir+'/state.sqlite');t.after(()=>repository.close());
  const sponsor=await privateSigner(new Uint8Array(32).fill(231)),transportSeed=new Uint8Array(32).fill(232);
  const funding={totalLamports:'100000000000',requestLamports:'30000000000',maxFeeLamports:'10000'};
  const validator=()=>{throw Error('No history/settlement execution allowed in this check');};validator.settlement=validator;
  for(const row of fixtures.valid) {
    const r=row.request,wire=new Uint8Array(Buffer.from(r.wire,'base64')),raw=encodeRequest(r.kind,wire),context=r.history.context;
    const request=await readRequest(raw,context),hash=await digest(wire),ledger=b58(new Uint8Array(Buffer.from(context.slice(64,128),'hex')));
    const profile={endpoint:'http://127.0.0.1:54321/',genesis:ledger,scope:'isolated-solana-validator-synthetic-only',version:'3.1.10',
      programs:{...Object.fromEntries(Object.keys(r.program_data).map(p=>[p,'00'.repeat(32)])),[r.history.program]:COST_POOL_SHA256}};
    let reserveCalls=0;
    const wrapped={read:id=>repository.read(id),compareAndSwapFunded:a=>repository.compareAndSwapFunded(a),configureFunding:a=>repository.configureFunding(a),
      reserveFunding:async(...a)=>{reserveCalls++;return repository.reserveFunding(...a);}};
    const options={raw,context,program:r.history.program,pool:r.history.pool,profile,programData:r.program_data,sponsor,transportSeed,repository:wrapped,validator,funding,
      verifyProof:async(k,w,c)=>k===r.kind&&c===context&&await digest(w)===hash,fetchImpl:async()=>{throw Error('Network execution forbidden here');}};
    for(const window of [0,MAX_WINDOW+1,1.5,'8'])await assert.rejects(()=>LocalRelayTask.open({...options,window}),/Invalid chunk window size/,String(window));
    assert.equal(reserveCalls,0,'a bad window must be refused before any funds are reserved');
    const task=await LocalRelayTask.open({...options,window:32});
    assert.equal(task.id,request.id);assert.equal(task.transport.authority,b58(sponsor.pub));
    const sid=await digest(new TextEncoder().encode('zk9-sponsored-settlement-v1\0'+request.id));
    const pub=await repository.read(request.id),settle=await repository.read(sid);
    assert.equal(pub.version,VERSION);assert.deepEqual(pub.pending,[]);assert.equal(settle.pending,null,'settlement is still the frozen single-attempt journal');
    await assert.rejects(()=>repository.compareAndSwap(request.id,1,{...pub,revision:2}),'a funded journal needs its atomic debit');
    task.close();const again=await LocalRelayTask.open({...options,window:32});assert.equal(again.id,task.id);assert.deepEqual(again.transport,task.transport);
    assert.equal((await repository.read(request.id)).revision,1);again.close();
  }
});
test('A3 (static) the task is wired to the windowed journal, funding and sender, and hands its window to the sender',()=>{
  const source=fs.readFileSync(path.join(HERE,'relay-task.mjs'),'utf8');
  assert.match(source,/import \{PublicationSender\} from '\.\/publication-sender\.mjs';/);
  assert.match(source,/import \{SponsoredPublication\} from '\.\/relay-publication\.mjs';/);
  assert.match(source,/from '\.\/relay-funding\.mjs';/);
  assert.match(source,/new PublicationSender\(\{[^}]*\bwindow\}\)/);
});
