// Doubles for the windowed relay checks. NOT the cluster: a model that is just enough for the publication sender and the
// funding quote. What it models faithfully: the REAL buffer account layout and the buffer program's chunk / seal rules
// (idempotent exact retry, changed retry rejected), transactions decoded and signature-verified by the real decoder,
// blockhash lifetime, signature statuses with latency, and the RPC surface the sender uses. What it does NOT model: the
// verifier program, the pool, leader schedule, forks or any real latency. Real SQLite and real Ed25519 signing are used.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {RelayRepository} from './relay-repository.mjs';
import {fundedRepository,quoteFundingDebit,COST_POOL_SHA256} from './relay-funding.mjs';
import {SponsoredPublication} from './relay-publication.mjs';
import {PublicationSender} from './publication-sender.mjs';
import {publicationJournal} from './publication-adapter.mjs';
import {encodeRequest,readRequest} from '../solana-private-relay-v1/relay-request.mjs';
import {bufferPlan,inspectBuffer} from '../solana-relay-performance-v1/candidate/proof-buffer.mjs';
import {privateSigner,b58,un58,sha256,decodeTransaction} from '../solana-chrome-wallet-v1/recovery/solana-transaction.mjs';
import {digest} from '../solana-chrome-wallet-v1/recovery/payment-wire.mjs';
import {PROFILES} from '../solana-chrome-wallet-v1/recovery/proof-progress.mjs';

const HERE=path.dirname(fileURLToPath(import.meta.url));
const ARCHIVE=process.env.ZK9_WIRE_ARCHIVE??path.join(HERE,'../solana-multiwallet-privacy-v1/evidence/privacy-live-02/public-capsule');
const names=fs.readdirSync(ARCHIVE).filter(n=>n.endsWith('.wire')).sort();
export const WIRES={
  send:new Uint8Array(fs.readFileSync(path.join(ARCHIVE,names.find(n=>n.endsWith('.send.wire'))))),
  withdraw:new Uint8Array(fs.readFileSync(path.join(ARCHIVE,names.find(n=>n.endsWith('.withdraw.wire'))))),
};
export const BUFFER=b58(await sha256(new TextEncoder().encode('ZK9 local proof buffer program v1')));
const hex=b=>Buffer.from(b).toString('hex');
const bytes=h=>Uint8Array.from(h.match(/../g),v=>parseInt(v,16));
const addr=n=>b58(new Uint8Array(32).fill(n));
const u32=n=>{const b=Buffer.alloc(4);b.writeUInt32LE(n);return b;};
const PLANS={};
export const temp=()=>{const d=fs.mkdtempSync(path.join(os.tmpdir(),'zk9-windowed-'));fs.chmodSync(d,0o700);return d;};

// ---------------------------------------------------------------------------------------------------- the cluster model
export class FakeChain {
  slot=100;height=1000;balance=1e15;
  accounts=new Map();statuses=new Map();queue=[];hashes=new Map();log=[];
  // policies, all keyed by chunk index because signatures only exist after signing
  dropSends=new Map();      // idx -> how many sends are lost before one reaches the cluster
  neverLand=new Set();      // idx -> every send is lost
  failIdx=new Set();        // idx -> lands with a program error
  latency=1;                // slots between reaching the cluster and landing
  simulateFail=false;staleReads=0;sendErrors=0;feeQuote=5000;feeCalls=0;
  processedOnly=new Set();   // idx -> landed, but its status says only `processed`
  sigIdx=new Map();
  // Every signature the journal has made durable. A send of anything else is a violation of the release rule.
  committed=new Set();violations=[];requireCommitted=true;
  #previous=new Map();
  hashFor(height){return b58(createHash('sha256').update('block '+height).digest());}
  issue(){const hash=this.hashFor(this.height),last=this.height+150;this.hashes.set(hash,last);return {blockhash:hash,lastValidBlockHeight:last};}
  createBuffer({source,authority,plan}) {
    const data=Buffer.alloc(plan.start+plan.total);data.write('ZK9BUF1\0',0,'latin1');Buffer.from(un58(authority,32)).copy(data,8);
    data.writeUInt32LE(plan.total,40);Buffer.from(plan.root).copy(data,48);data[80]=1;
    this.accounts.set(source,{plan,data});
  }
  read(pub) {
    const a=this.accounts.get(pub);if(!a)return null;
    let data=a.data;if(this.staleReads>0&&this.#previous.has(pub)){this.staleReads--;data=this.#previous.get(pub);}
    return {executable:false,owner:BUFFER,lamports:1,data:[Buffer.from(data).toString('base64'),'base64']};
  }
  tick(n=1) {
    for(let i=0;i<n;i++) {
      this.slot++;this.height++;
      const ready=this.queue.filter(q=>q.readyAt<=this.slot);this.queue=this.queue.filter(q=>q.readyAt>this.slot);
      for(const q of ready)this.#land(q);
    }
  }
  async send(raw) {
    const tx=await decodeTransaction(raw);                      // real decoder: signature verified
    if(this.requireCommitted&&!this.committed.has(tx.signature)){this.violations.push(tx.signature);throw this.#error('SENT BEFORE DURABLE COMMIT');}
    const last=this.hashes.get(tx.blockhash);
    if(last===undefined||this.height>last)throw this.#error('BlockhashNotFound');
    if(this.statuses.has(tx.signature))throw this.#error('AlreadyProcessed');
    if(this.sendErrors>0){this.sendErrors--;throw this.#error('Node is unhealthy');}
    const ix=tx.instructions[0],tag=ix.data[0],idx=tag===1?Buffer.from(ix.data).readUInt32LE(1):null;
    this.log.push({t:'send',sig:tx.signature,idx,tag});if(idx!==null)this.sigIdx.set(tx.signature,idx);
    if(idx!==null){
      if(this.neverLand.has(idx))return tx.signature;
      const lost=this.dropSends.get(idx)??0;if(lost>0){this.dropSends.set(idx,lost-1);return tx.signature;}
    }
    if(!this.queue.some(q=>q.tx.signature===tx.signature))this.queue.push({tx,readyAt:this.slot+this.latency});
    return tx.signature;
  }
  #error(message){const e=new Error(message);e.rpcCode=-32002;return e;}
  #land({tx}) {
    const ix=tx.instructions[0],key=b58(ix.accounts[0].pub),a=this.accounts.get(key);
    const done=err=>this.statuses.set(tx.signature,{slot:this.slot,confirmations:null,err,confirmationStatus:'confirmed'});
    if(!a||ix.program.length!==32||b58(ix.program)!==BUFFER)return done({InstructionError:[1,'IncorrectProgramId']});
    if(b58(tx.authority)!==b58(a.data.subarray(8,40)))return done({InstructionError:[1,'MissingRequiredSignature']});
    const tag=ix.data[0],{plan}=a;
    if(tag===1) {
      const index=Buffer.from(ix.data).readUInt32LE(1),chunk=Buffer.from(ix.data.subarray(5));
      if(this.failIdx.has(index))return done({InstructionError:[1,{Custom:9}]});
      if(index>=plan.count||chunk.length!==Math.min(900,plan.total-index*900))return done({InstructionError:[1,{Custom:3}]});
      const hash=createHash('sha256').update('ZK9/SOLANA/BUFFER/LEAF/v1\0').update(u32(plan.total)).update(u32(index)).update(chunk).digest();
      const bit=1<<(index%8),at=85+(index>>3),slot=plan.start+index*900,stored=a.data.subarray(plan.hashStart+32*index,plan.hashStart+32*index+32);
      if(a.data[at]&bit) {   // exact retry counts once, a changed retry is refused
        if(!stored.equals(hash)||!a.data.subarray(slot,slot+chunk.length).equals(chunk))return done({InstructionError:[1,{Custom:2}]});
        return done(null);
      }
      this.#previous.set(key,Buffer.from(a.data));
      a.data[at]|=bit;hash.copy(a.data,plan.hashStart+32*index);chunk.copy(a.data,slot);a.data.writeUInt32LE(a.data.readUInt32LE(44)+1,44);
      return done(null);
    }
    if(tag===2) {
      if(a.data.readUInt32LE(44)!==plan.count)return done({InstructionError:[1,{Custom:4}]});
      this.#previous.set(key,Buffer.from(a.data));a.data[80]=2;return done(null);
    }
    return done({InstructionError:[1,'InvalidInstructionData']});
  }
}

// What the sender and the funding quote use of LocalNetwork. A new instance per "process" over the same cluster.
export class FakeNet {
  calls=[];#epoch=0;
  constructor({chain,profile,programData}){this.chain=chain;this._profile=profile;this.programData=programData;}
  get profile(){return structuredClone(this._profile);}
  invalidate(){this.#epoch++;}
  async attest(programs){this.invalidate();this.attested=new Set(programs);return {};}
  requireProgram(p){if(!this.attested?.has(p))throw Error('Attest the local program first.');return this.programData[p]??addr(7);}
  async checkLedger(){}
  async history(program,minSlot=0){return {context:{slot:this.chain.slot},value:[]};}
  async account(pub,minSlot){
    if(pub instanceof Uint8Array)pub=b58(pub);
    if(minSlot!==undefined&&this.chain.slot<minSlot){const e=new Error('Minimum context slot has not been reached');e.rpcCode=-32016;throw e;}
    return this.chain.read(pub);
  }
  async rpc(method,params=[]) {
    const c=this.chain;this.calls.push(method);const context={slot:c.slot};
    switch(method) {
      case 'getMinimumBalanceForRentExemption':return 2000000+params[0]*7;
      case 'getLatestBlockhash':return {context,value:c.issue()};
      case 'simulateTransaction':return {context,value:c.simulateFail?{err:{InstructionError:[1,{Custom:7}]},logs:[],unitsConsumed:100}:{err:null,logs:[],unitsConsumed:7689}};
      case 'getSignatureStatuses':return {context,value:params[0].map(s=>{const st=c.statuses.get(s)??null;return st&&c.processedOnly.has(c.sigIdx.get(s))?{...st,confirmationStatus:'processed'}:st;})};
      case 'getBlockHeight':return c.height;
      case 'sendTransaction':return c.send(params[0]);
      case 'getFeeForMessage':return {context,value:typeof c.feeQuote==='function'?c.feeQuote(c.feeCalls++):c.feeQuote};
      case 'getBalance':return {context,value:c.balance};
      default:throw Error('Unmodelled RPC method '+method);
    }
  }
}

// -------------------------------------------------------------------------------------------------------- one "process"
export async function makeEnv({kind='send',window=1,dir=temp(),chain=new FakeChain(),maxFee='10000',requestLamports='80000000000',totalLamports='160000000000',
  maxAttempts=12000,wrap=r=>r,verify=true,seed=231}={}) {
  const wire=WIRES[kind],context=hex(wire.subarray(12,108)),raw=encodeRequest(kind,wire),hash=await digest(wire),request=await readRequest(raw,context);
  const sponsor=await privateSigner(new Uint8Array(32).fill(seed)),transportSeed=new Uint8Array(32).fill(232);
  const pool=addr(5),proofProgram=b58(bytes(PROFILES[kind].programHex)),programData={[BUFFER]:addr(101),[proofProgram]:addr(102)};
  const genesis=b58(bytes(context.slice(64,128)));
  const profile={endpoint:'http://127.0.0.1:1/',genesis,scope:'isolated-solana-validator-synthetic-only',version:'3.1.10',
    programs:{[pool]:COST_POOL_SHA256,[BUFFER]:'00'.repeat(32),[proofProgram]:'00'.repeat(32)}};
  const net=new FakeNet({chain,profile,programData});
  await net.attest([pool,BUFFER,proofProgram]);   // as LocalRelayTask.step() does before it ever signs
  const repository=new RelayRepository(dir+'/state.sqlite');
  const events=[];
  const intercepted=wrap({read:id=>repository.read(id),configureFunding:a=>repository.configureFunding(a),reserveFunding:(...a)=>repository.reserveFunding(...a),
    compareAndSwapFunded:async a=>{const r=await repository.compareAndSwapFunded(a);
      for(const x of Array.isArray(a.value.pending)?a.value.pending:[])chain.committed.add(x.signature);
      events.push({t:'commit',revision:r,pending:a.value.pending,last:a.value.last,debit:a.debitLamports});chain.log.push({t:'commit',pending:Array.isArray(a.value.pending)?a.value.pending.length:null});return r;}},repository);
  const funded=await fundedRepository({repository:intercepted,requestId:request.id,sponsor:b58(sponsor.pub),genesis,
    funding:{totalLamports,requestLamports,maxFeeLamports:maxFee},maxPublicationAttempts:maxAttempts,
    quoteDebit:value=>quoteFundingDebit({value,network:net,sponsor:b58(sponsor.pub),program:pool,kind,maxFeeLamports:maxFee})});
  const publication=await SponsoredPublication.open({raw,context,programData,sponsor,transportSeed,repository:funded,
    verifyProof:async(k,w,c)=>verify&&k===kind&&c===context&&await digest(w)===hash});
  // What is durable after a (re)start is what the database holds, whoever wrote it.
  for(const a of (await repository.read(request.id))?.pending??[])chain.committed.add(a.signature);
  const logicalId=request.id.slice(0,32);
  const journal=publicationJournal({publication,checkedId:id=>{if(id!==logicalId)throw Error('Foreign request entered relay task.');},isSettling:()=>true});
  const synchronize=async response=>({context,slot:response.context.slot,synthetic_only:true,rpc_consensus_authenticated:false});
  const sender=new PublicationSender({network:net,journal,synchronize,context,program:pool,kind,window});
  const env={kind,wire,context,request,logicalId,sponsor,transportSeed,pool,proofProgram,programData,profile,chain,net,repository,funded,publication,journal,sender,dir,events,
    transport:publication.configuration.transport,authority:b58(sponsor.pub),maxFee,window,
    close(){sender.close();repository.close();},
    async fund(){return repository.funding(await repository.configureFunding({sponsor:b58(sponsor.pub),genesis,totalLamports}),request.id);},
    async record(){return repository.read(request.id);},
    buffer(){const a=chain.read(env.transport.source);return a?inspectBuffer(a,wire,un58(env.authority,32),un58(BUFFER,32),env.plan):null;},
    async reopen(options={}){env.close();return makeEnv({kind,window,dir,chain,maxFee,requestLamports,totalLamports,maxAttempts,wrap,verify,seed,...options});},
    async step(){return sender.step(logicalId);},
    // Time passes between steps the way it does for the supervisor: one slot.
    async drive(until,{max=400,tick=1}={}) {
      const results=[];
      for(let i=0;i<max;i++){if(await until())return results;results.push(await env.step());chain.tick(tick);}
      throw Error('Driver did not converge: '+JSON.stringify(results.slice(-3)));
    }};
  env.plan=PLANS[kind]??=await bufferPlan(wire);
  if(!chain.accounts.has(env.transport.source))chain.createBuffer({source:env.transport.source,authority:env.authority,plan:env.plan});
  return env;
}
