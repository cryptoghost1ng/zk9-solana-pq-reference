// Native-only, synthetic loopback publisher. Not a browser wallet or remote RPC
// trust model. The verified launcher supplies network/code pins and a journal
// backed by the unlocked SQLCipher session, never by webpage localStorage.
import assert from 'node:assert/strict';
import {createPrivateKey,createPublicKey,sign,verify,randomBytes} from 'node:crypto';
import {sha,u32,u64,b58,un58} from '../runtime-helpers.mjs';
import {bufferPlan} from '../upload-batch.mjs';
import {checkWire,readProgress,nextStep} from './plan.mjs';

const SYSTEM=Buffer.alloc(32),BUFFER=sha(Buffer.from('ZK9 local proof buffer program v1'));
const LOADER=un58('BPFLoaderUpgradeab1e11111111111111111111111');
const BUDGET=un58('ComputeBudget111111111111111111111111111111');
const MEMO=un58('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr');
const LIMIT=1400000;
const pause=ms=>new Promise(r=>setTimeout(r,ms));
const equal=(a,b)=>Buffer.isBuffer(a)&&Buffer.isBuffer(b)&&a.equals(b);
const meta=(pub,signer=false,writable=false)=>({pub,signer,writable});
const ixEqual=(a,b)=>equal(a.program,b.program)&&equal(a.data,b.data)&&a.accounts.length===b.accounts.length&&a.accounts.every((x,i)=>equal(x.pub,b.accounts[i].pub)&&x.signer===b.accounts[i].signer&&x.writable===b.accounts[i].writable);
const vec=n=>{assert.ok(Number.isInteger(n)&&n>=0&&n<65536);const a=[];do{let x=n&127;n>>>=7;if(n)x|=128;a.push(x)}while(n);return Buffer.from(a)};
const publicKey=pub=>createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),pub]),format:'der',type:'spki'});

export function identity(seed){
 assert.ok(Buffer.isBuffer(seed)&&seed.length===32&&!seed.equals(Buffer.alloc(32)));
 const secret=createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),seed]),format:'der',type:'pkcs8'});
 return {secret,pub:createPublicKey(secret).export({format:'der',type:'spki'}).subarray(-32)};
}

export function signedTransaction(authority,instructions,extraSigners,blockhash,lastValidHeight){
 assert.equal(un58(blockhash).length,32);assert.ok(Number.isSafeInteger(lastValidHeight)&&lastValidHeight>=0);
 const entries=new Map();
 const add=(pub,signer,writable)=>{assert.equal(pub.length,32);const key=b58(pub),old=entries.get(key);entries.set(key,{pub,signer:!!signer||!!old?.signer,writable:!!writable||!!old?.writable})};
 add(authority.pub,true,true);
 const all=[{program:BUDGET,accounts:[],data:Buffer.concat([Buffer.from([2]),u32(LIMIT)])},...instructions,{program:MEMO,accounts:[],data:Buffer.from('ZK9 '+randomBytes(4).toString('hex'))}];
 for(const ix of all){for(const a of ix.accounts)add(a.pub,a.signer,a.writable);add(ix.program,false,false)}
 const group=x=>x.signer?(x.writable?0:1):(x.writable?2:3);
 const keys=[...entries.values()].sort((a,b)=>group(a)-group(b));assert.ok(keys.length<=32);
 const signing=keys.filter(k=>k.signer),signers=[authority,...extraSigners];
 assert.ok(signing.length>=1&&signing.length<=3&&equal(signing[0].pub,authority.pub));
 assert.equal(new Set(signers.map(s=>b58(s.pub))).size,signers.length);assert.equal(signing.length,signers.length);
 const index=pub=>keys.findIndex(k=>equal(k.pub,pub));
 const header=Buffer.from([signing.length,signing.filter(k=>!k.writable).length,keys.filter(k=>!k.signer&&!k.writable).length]);
 const body=Buffer.concat([header,vec(keys.length),...keys.map(k=>k.pub),un58(blockhash),vec(all.length),...all.map(ix=>Buffer.concat([Buffer.from([index(ix.program)]),vec(ix.accounts.length),Buffer.from(ix.accounts.map(a=>index(a.pub))),vec(ix.data.length),ix.data]))]);
 const signatures=signing.map(k=>{const pair=signers.find(p=>equal(p.pub,k.pub));assert.ok(pair,'Unexpected signer');return sign(null,body,pair.secret)});
 const bytes=Buffer.concat([vec(signatures.length),...signatures,body]);assert.ok(bytes.length<=1232,'Transaction exceeds packet size');
 return Object.freeze({raw:bytes.toString('base64'),signature:b58(signatures[0]),last_valid_height:lastValidHeight,limit:LIMIT,wire_bytes:bytes.length});
}

// Inspect and authenticate persisted legacy bytes before any replay. No v0,
// address tables, extra instructions, or signatures supplied by web content.
export function decodeTransaction(raw){
 assert.ok(typeof raw==='string'&&raw.length<=1644);const bytes=Buffer.from(raw,'base64');assert.equal(bytes.toString('base64'),raw);assert.ok(bytes.length<=1232);
 let at=0;
 const take=n=>{assert.ok(n>=0&&at+n<=bytes.length,'Truncated transaction');const v=bytes.subarray(at,at+n);at+=n;return v};
 const length=()=>{let n=0,shift=0,start=at;for(let i=0;i<3;i++){const x=take(1)[0];n|=(x&127)<<shift;if(!(x&128)){assert.ok(vec(n).equals(bytes.subarray(start,at)),'Noncanonical vector');return n;}shift+=7;}throw Error('Oversized vector')};
 const count=length();assert.ok(count>=1&&count<=3);const sigs=Array.from({length:count},()=>take(64));const start=at;
 const header=take(3);assert.equal(header[0],count);assert.ok(header[1]<count);
 const keyCount=length();assert.ok(keyCount>=count&&keyCount<=32&&header[2]<=keyCount-count);
 const keys=Array.from({length:keyCount},()=>take(32));assert.equal(new Set(keys.map(b58)).size,keyCount);
 const blockhash=b58(take(32)),ixCount=length();assert.ok(ixCount>=3&&ixCount<=4);
 const key=i=>{assert.ok(i<keys.length);return keys[i]};
 const instructions=Array.from({length:ixCount},()=>{
  const program=key(take(1)[0]),n=length();assert.ok(n<=32);
  const accounts=Array.from(take(n),i=>meta(key(i),i<count,i<count?i<count-header[1]:i<keyCount-header[2]));
  return {program,accounts,data:take(length())};
 });
 assert.equal(at,bytes.length,'Trailing transaction bytes');
 for(let i=0;i<count;i++)assert.ok(verify(null,bytes.subarray(start),publicKey(keys[i]),sigs[i]),'Invalid persisted signature');
 assert.ok(ixEqual(instructions[0],{program:BUDGET,accounts:[],data:Buffer.concat([Buffer.from([2]),u32(LIMIT)])}),'Unexpected compute budget');
 const memo=instructions.at(-1);assert.ok(equal(memo.program,MEMO)&&memo.accounts.length===0&&/^ZK9 [0-9a-f]{8}$/.test(memo.data.toString()),'Unexpected memo');
 return {authority:keys[0],signers:keys.slice(0,count),signature:b58(sigs[0]),blockhash,instructions:instructions.slice(1,-1)};
}

export class LocalTransport {
 constructor({network,kind,wire,authority,source,receipt,journal,signal,onReceipt=()=>{},fetchImpl=fetch,pollDelay=100,maxPolls=600}){
  const url=new URL(network.endpoint);
  assert.ok(url.protocol==='http:'&&url.hostname==='127.0.0.1'&&url.port&&url.pathname==='/'&&!url.search&&!url.hash&&!url.username&&!url.password,'Only pinned loopback RPC is supported');
  assert.equal(network.scope,'isolated-solana-validator-synthetic-only');assert.equal(network.version,'3.1.10');assert.equal(un58(network.genesis).length,32);
  this.network=structuredClone(network);this.kind=kind;this.wire=Buffer.from(wire);this.profile=checkWire(wire,kind);this.plan=bufferPlan(wire);
  assert.ok(wire.subarray(44,76).equals(un58(network.genesis)),'Proof belongs to another local ledger');
  this.authority=authority;this.source=source;this.receipt=receipt;this.program=Buffer.from(this.profile.programHex,'hex');
  assert.equal(new Set([authority,source,receipt].map(k=>b58(k.pub))).size,3);
  for(const p of [BUFFER,this.program])assert.match(network.programs[b58(p)]??'',/^[0-9a-f]{64}$/);
  this.journal=journal;this.signal=signal;this.onReceipt=onReceipt;this.fetchImpl=fetchImpl;this.pollDelay=pollDelay;this.maxPolls=maxPolls;
  this.programData=new Map();this.prepared=new WeakMap();this.busy=new Set();this.rid=0;this.attested=false;
 }
 async rpc(method,params=[]){
  this.signal?.throwIfAborted();const id=++this.rid;
  const timeout=AbortSignal.timeout(15000),signal=this.signal?AbortSignal.any([this.signal,timeout]):timeout;
  const r=await this.fetchImpl(this.network.endpoint,{method:'POST',redirect:'error',headers:{'Content-Type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id,method,params}),signal});
  assert.equal(r.status,200);const v=await r.json();assert.equal(v.id,id);assert.equal(v.jsonrpc,'2.0');
  if(v.error)throw Object.assign(Error(method+' failed'),{rpcError:v.error});assert.ok(Object.hasOwn(v,'result'));return v.result;
 }
 async account(pub){return (await this.rpc('getAccountInfo',[b58(pub),{encoding:'base64',commitment:'confirmed'}])).value;}
 async validatePrograms(programs){
  assert.equal(await this.rpc('getGenesisHash'),this.network.genesis,'Local ledger changed');
  assert.equal((await this.rpc('getVersion'))['solana-core'],this.network.version,'Validator version changed');
  for(const pub of programs){
   const digest=this.network.programs[b58(pub)];assert.match(digest??'',/^[0-9a-f]{64}$/,'Unpinned program');
   const a=await this.account(pub);assert.ok(a?.executable===true&&a.owner===b58(LOADER)&&a.data?.[1]==='base64');
   const b=Buffer.from(a.data[0],'base64');assert.ok(b.length===36&&b.readUInt32LE()===2);
   const code=b.subarray(4),d=await this.account(code);assert.ok(d?.executable===false&&d.owner===b58(LOADER)&&d.data?.[1]==='base64');
   const bytes=Buffer.from(d.data[0],'base64');assert.ok(bytes.length>45&&bytes.readUInt32LE()===3&&bytes[12]===0,'Program is still upgradeable');
   assert.equal(sha(bytes.subarray(45)).toString('hex'),digest,'Program code changed');this.programData.set(b58(pub),code);
  }
  this.attested=this.programData.has(b58(BUFFER))&&this.programData.has(b58(this.program));
 }
 bufferIx(data,init=false){return {program:BUFFER,accounts:[meta(this.source.pub,init,true),meta(this.authority.pub,true,true)],data};}
 proofIx(data,init=false){return {program:this.program,accounts:[meta(this.receipt.pub,init,true),meta(this.source.pub),meta(this.authority.pub,true,true),meta(BUFFER),meta(this.programData.get(b58(BUFFER)))],data};}
 async policy(name,instructions,{resume=false}={}){
  assert.ok(this.attested,'Unattested local runtime');assert.match(name,/^[a-z0-9-]{1,100}$/);
  let expected;
  if(name==='buffer-create'||name==='proof-create'){
   const buffer=name==='buffer-create',pub=buffer?this.source.pub:this.receipt.pub,owner=buffer?BUFFER:this.program,size=buffer?this.plan.start+this.wire.length:this.profile.space;
   const rent=await this.rpc('getMinimumBalanceForRentExemption',[size]);assert.ok(Number.isSafeInteger(rent)&&rent>=0);
   expected=[{program:SYSTEM,accounts:[meta(this.authority.pub,true,true),meta(pub,true,true)],data:Buffer.concat([u32(0),u64(rent),u64(size),owner])},buffer?this.bufferIx(Buffer.concat([Buffer.from([0]),u32(this.wire.length),this.plan.root]),true):this.proofIx(Buffer.from([0]),true)];
  }else if(name==='buffer-seal')expected=[this.bufferIx(Buffer.from([2]))];
  else if(/^chunk-(0|[1-9][0-9]*)$/.test(name)){
   const index=Number(name.slice(6));assert.ok(index<this.plan.count);expected=[this.bufferIx(Buffer.concat([Buffer.from([1]),u32(index),this.wire.subarray(index*900,Math.min((index+1)*900,this.wire.length))]))];
  }else{
   assert.equal(instructions.length,1);const ix=instructions[0];assert.ok(ixEqual(ix,this.proofIx(ix.data)),'Foreign proof instruction');
   const op=ix.data[0],staticOp=[3,5,6].includes(op);assert.ok(op>=1&&op<=17&&op!==2);
   assert.equal(ix.data.length,staticOp?1:op===7?13:9);
   // On replay, the original authenticated transaction can already be applied.
   // Its instruction is still restricted to this proof receipt; signatures and
   // exact bytes, rather than a fabricated local cursor, determine identity.
   if(!resume){
    const progress=readProgress(await this.account(this.receipt.pub),{source:this.source.pub,authority:this.authority.pub,program:this.program,wire:this.wire,kind:this.kind});
    const step=nextStep(progress);assert.ok(step,'Proof is already complete');assert.equal(name,step.name+'-'+(step.sequence??0));
    const work=staticOp?0:op===7?ix.data.readUInt32LE(5)/1024:ix.data.readUInt32LE(5);
    assert.ok(equal(ix.data,step.build(work)),'Instruction differs from on-chain cursor');
   }
   expected=[this.proofIx(ix.data)];
  }
  assert.ok(instructions.length===expected.length&&instructions.every((ix,i)=>ixEqual(ix,expected[i])),'Instruction is outside the publication policy');
 }
 async prepare({name,instructions,extraSigners=[]}){
  await this.policy(name,instructions);const block=(await this.rpc('getLatestBlockhash',[{commitment:'confirmed'}])).value;
  const prepared=signedTransaction(this.authority,instructions,extraSigners,block.blockhash,block.lastValidBlockHeight);
  const decoded=decodeTransaction(prepared.raw);assert.ok(equal(decoded.authority,this.authority.pub));
  this.prepared.set(prepared,{name,instructions:instructions.map(ix=>({program:Buffer.from(ix.program),data:Buffer.from(ix.data),accounts:ix.accounts.map(a=>({...a,pub:Buffer.from(a.pub)}))}))});return prepared;
 }
 async replay(attempt){
  const parsed=decodeTransaction(attempt.raw);assert.equal(parsed.signature,attempt.signature);assert.ok(equal(parsed.authority,this.authority.pub));
  assert.ok(Number.isSafeInteger(attempt.last_valid_height)&&attempt.last_valid_height>=0);
  await this.policy(attempt.step,parsed.instructions,{resume:true});
  const expected=new Set([this.authority.pub,...(attempt.step==='buffer-create'?[this.source.pub]:attempt.step==='proof-create'?[this.receipt.pub]:[])].map(b58));
  assert.ok(parsed.signers.length===expected.size&&parsed.signers.every(p=>expected.has(b58(p))),'Unexpected persisted signer');
  for(let i=0;i<this.maxPolls;i++){
   this.signal?.throwIfAborted();
   const status=(await this.rpc('getSignatureStatuses',[[attempt.signature],{searchTransactionHistory:true}])).value[0];
   if(status&&['confirmed','finalized'].includes(status.confirmationStatus)){
    await this.journal.confirmed(attempt.signature,status.slot,status.err);
    await this.onReceipt({step:attempt.step,signature:attempt.signature,slot:status.slot,error:status.err});
    if(status.err!==null)throw Object.assign(Error('Publication instruction failed'),{transactionError:status.err,signature:attempt.signature});
    return {signature:attempt.signature,slot:status.slot};
   }
   const height=await this.rpc('getBlockHeight',[{commitment:'finalized'}]);
   if(height>attempt.last_valid_height){
    // Check again AFTER the finalized-height observation. A processed or
    // confirmed status prevents treating an uncertain attempt as expired.
    const later=(await this.rpc('getSignatureStatuses',[[attempt.signature],{searchTransactionHistory:true}])).value[0];
    if(later===null){await this.journal.expired(attempt.signature,height,true);return {expired:true};}
   }else if(i%10===0){
    try{const sig=await this.rpc('sendTransaction',[attempt.raw,{encoding:'base64',skipPreflight:true,maxRetries:0}]);assert.equal(sig,attempt.signature,'RPC returned a different signature');}
    catch(e){if(e.name==='AssertionError')throw e;this.signal?.throwIfAborted();/* uncertain; preserve original bytes */}
   }
   await pause(this.pollDelay);
  }
  throw Error('Publication outcome is uncertain; original transaction remains reserved for resume');
 }
 async recover(){
  assert.ok(this.attested);for(const attempt of await this.journal.pending())await this.replay(attempt);
 }
 async fundSyntheticAuthority(){
  assert.ok(this.attested,'Attest the isolated ledger before requesting test SOL');
  const balance=(await this.rpc('getBalance',[b58(this.authority.pub),{commitment:'confirmed'}])).value;
  assert.ok(Number.isSafeInteger(balance)&&balance>=0);
  // Megabyte-sized proof accounts need tens of SOL in rent-exempt reserves.
  // Count only missing accounts on resume, and keep rent separate from fees.
  let rent=0;
  for(const [pub,size] of [[this.source.pub,this.plan.start+this.wire.length],[this.receipt.pub,this.profile.space]]){
   if(await this.account(pub))continue;
   const minimum=await this.rpc('getMinimumBalanceForRentExemption',[size]);assert.ok(Number.isSafeInteger(minimum)&&minimum>=0&&minimum<=100000000000,'Invalid local rent quote');rent+=minimum;
  }
  const feeReserve=250000000,target=rent+feeReserve;assert.ok(target<=100000000000,'Synthetic funding bound exceeded');
  const funding={rent_reserve_lamports:rent,fee_reserve_lamports:feeReserve,required_balance_lamports:target};
  if(balance>=target)return {...funding,airdrop_requested:false,faucet_lamports:0};
  const amount=Math.ceil((target-balance)/1000000000)*1000000000;
  const signature=await this.rpc('requestAirdrop',[b58(this.authority.pub),amount]);assert.equal(un58(signature).length,64);
  for(let i=0;i<this.maxPolls;i++){
   const status=(await this.rpc('getSignatureStatuses',[[signature],{searchTransactionHistory:true}])).value[0];
   if(status&&['confirmed','finalized'].includes(status.confirmationStatus)){assert.equal(status.err,null);return {...funding,airdrop_requested:true,faucet_lamports:amount,signature,slot:status.slot};}
   this.signal?.throwIfAborted();await pause(this.pollDelay);
  }
  throw Error('Local test funding is uncertain; no proof transaction was sent');
 }
 async send({name,instructions,extraSigners=[],prepared}){
  assert.ok(!this.busy.has(name),'Publication step already active');this.busy.add(name);
  try{
   const pending=(await this.journal.pending()).filter(a=>a.step===name);assert.ok(pending.length<=1);
   if(pending.length){const result=await this.replay(pending[0]);if(!result.expired)return result;throw Error('Prior transaction expired; reread chain state before preparing a replacement');}
   if(!prepared)prepared=await this.prepare({name,instructions,extraSigners});
   const bound=this.prepared.get(prepared);assert.ok(bound&&bound.name===name&&bound.instructions.length===instructions.length&&instructions.every((ix,i)=>ixEqual(ix,bound.instructions[i])),'Unrecognized or modified prepared transaction');
   const ack=await this.journal.save({step:name,signature:prepared.signature,raw:prepared.raw,last_valid_height:prepared.last_valid_height});
   assert.ok(ack.durable===true&&ack.signature===prepared.signature&&ack.wire_sha256===sha(Buffer.from(prepared.raw,'base64')).toString('hex'),'Missing durable acknowledgement');
   this.prepared.delete(prepared);
   return await this.replay({step:name,...prepared});
  }finally{this.busy.delete(name);}
 }
}
