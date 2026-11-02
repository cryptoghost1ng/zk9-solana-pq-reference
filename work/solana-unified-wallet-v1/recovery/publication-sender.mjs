// Private bounded local-network driver. No secrets or arbitrary instructions
// here: the journal owns policy tickets, unsigned probes and durable signing.
// Verified proof receipt != settled payment. The final pool transition is separate.
import {requireState as require,integer,hexValue} from './checkpoint.mjs';
import {b58,un58,sha256,decodeTransaction,fromBase64} from './solana-transaction.mjs';
import {PROFILES} from './proof-progress.mjs';
import {publicationComputeExhausted,simulationFailure} from './simulation-result.mjs';
const BUFFER=b58(await sha256(new TextEncoder().encode('ZK9 local proof buffer program v1')));
const bytes=h=>Uint8Array.from(h.match(/../g),v=>parseInt(v,16));
const LIMIT=1300000;
export class PublicationSender {
  #network;#journal;#synchronize;#context;#poolProgram;#proofProgram;#kind;#signal;
  #closed=false;#busy=false;#id=null;#config=null;#slot=0;#receipt=null;#buffer=null;
  constructor({network,journal,synchronize,context,program,kind,signal}) {
    hexValue(context,96);un58(program,32);require(kind==='send'||kind==='withdraw');require(typeof synchronize==='function');
    this.#proofProgram=b58(bytes(PROFILES[kind].programHex));
    require(network.profile.genesis===b58(bytes(context.slice(64,128))),'Wrong configured proof network.');
    for(const p of [program,BUFFER,this.#proofProgram])require(Object.hasOwn(network.profile.programs,p),'Unpinned publication program.');
    this.#network=network;this.#journal=journal;this.#synchronize=synchronize;this.#context=context;
    this.#poolProgram=program;this.#kind=kind;this.#signal=signal;
  }
  close(){this.#closed=true;this.#reset();}
  requireSync(){this.#reset();}
  #reset(){this.#network.invalidate();this.#journal.requireSync();this.#id=null;this.#config=null;this.#receipt=null;this.#buffer=null;}
  #active(){require(!this.#closed,'Publication network session is closed.');this.#signal?.throwIfAborted();}
  #programs(){return [this.#poolProgram,BUFFER,this.#proofProgram];}
  async #start(id) {
    await this.#network.attest(this.#programs());this.#active();
    const raw=await this.#network.history(this.#poolProgram,this.#slot);this.#active();
    const synced=await this.#synchronize(raw);this.#active();
    require(synced?.context===this.#context&&synced.slot===raw.context.slot&&synced.synthetic_only===true&&synced.rpc_consensus_authenticated===false,'History did not pass private custody.');
    integer(synced.slot);require(synced.slot>=this.#slot);this.#slot=synced.slot;
    const config=await this.#journal.bind(id);this.#active();
    require(config.kind===this.#kind&&config.buffer_program===BUFFER&&config.proof_program===this.#proofProgram);
    for(const p of [BUFFER,this.#proofProgram])require(config.program_data?.[p]===this.#network.requireProgram(p),'Publication program data differs from attestation.');
    this.#config=config;this.#id=id;this.#receipt=null;this.#buffer=null;
  }
  async #account(pub){const a=await this.#network.account(pub,this.#slot);this.#active();return a;}
  async #bufferView(account) {
    const next=await this.#journal.buffer(this.#id,account);this.#active();
    if(this.#buffer) {
      const pending=new Set(this.#buffer.pending);
      require(next.received>=this.#buffer.received&&next.pending.every(i=>pending.has(i))&&(!this.#buffer.sealed||next.sealed),'Proof buffer progress rolled back.');
    }
    this.#buffer=next;return next;
  }
  async #receiptView(account) {
    const next=await this.#journal.receipt(this.#id,account,this.#receipt??undefined);this.#active();this.#receipt=next;return next;
  }
  async #choice() {
    const c=this.#config,stored=await this.#account(c.transport.source),proof=await this.#account(c.transport.receipt);
    if(stored===null){require(proof===null,'Receipt exists without its proof source.');return this.#create('buffer',c.buffer_size);}
    const buffer=await this.#bufferView(stored);if(proof!==null)require(buffer.sealed,'Receipt uses an unsealed proof buffer.');
    if(!buffer.sealed)return buffer.pending.length?{type:'chunk',index:buffer.pending[0]}:{type:'seal'};
    if(proof===null)return this.#create('proof',c.receipt_size);
    const state=await this.#receiptView(proof);
    if(state.complete)return null;
    return {type:'verify',receipt:state,work:state.next.max_work};
  }
  async #create(which,size) {
    integer(size);const rent=await this.#network.rpc('getMinimumBalanceForRentExemption',[size]);this.#active();integer(rent);
    require(rent>0&&rent<=100000000000,'Invalid synthetic account rent.');return {type:'create',which,rent};
  }
  async #block() {
    const r=await this.#network.rpc('getLatestBlockhash',[{commitment:'confirmed',minContextSlot:this.#slot}]);this.#active();
    integer(r?.context?.slot);require(r.context.slot>=this.#slot);un58(r.value?.blockhash,32);integer(r.value?.lastValidBlockHeight);this.#slot=r.context.slot;return r.value;
  }
  async #simulate(raw,sigVerify) {
    const r=await this.#network.rpc('simulateTransaction',[raw,{encoding:'base64',sigVerify,commitment:'confirmed',minContextSlot:this.#slot}]);this.#active();
    integer(r?.context?.slot);require(r.context.slot>=this.#slot&&r.value&&Object.hasOwn(r.value,'err'),'Invalid simulation response.');
    this.#slot=r.context.slot;if(r.value.err===null)integer(r.value.unitsConsumed);return r.value;
  }
  async #prepare(action) {
    const block=await this.#block();let ticket;
    for(let tries=0;tries<16;tries++) {
      ticket=await this.#journal.prepare(this.#id,action);this.#active();
      const probe=await this.#journal.simulation(this.#id,ticket,block.blockhash);this.#active();require(probe.unsigned===true);
      // Defense in depth: never send a real signed packet to the unsigned probe.
      const unsigned=fromBase64(probe.raw,1232),count=unsigned[0];
      require(count>=1&&count<=3&&unsigned.length>1+count*64&&unsigned.subarray(1,1+count*64).every(v=>v===0));
      const simulated=await this.#simulate(probe.raw,false);
      if(simulated.err===null&&simulated.unitsConsumed<=LIMIT) {
        const signed=await this.#journal.sign(this.#id,ticket,block.blockhash,block.lastValidBlockHeight);this.#active();require(signed.durable===true);
        const stored=await this.#journal.pending(this.#id);this.#active();
        require(stored&&stored.raw===signed.raw&&stored.signature===signed.signature,'Signed publication did not persist.');return stored;
      }
      // Only explicit compute exhaustion (or successful excessive CU usage)
      // permits shrinking. Never conceal cryptographic/custom program errors.
      require(simulated.err===null||publicationComputeExhausted(simulated,this.#proofProgram,action.type==='verify'),simulationFailure(simulated,action.receipt?.next?.name??action.type));
      require(action.type==='verify'&&action.work>action.receipt.next.min_work,'No safe compute budget for this publication step.');
      action={...action,work:Math.max(action.receipt.next.min_work,Math.floor(action.work/2))};
    }
    throw Error('Publication work sizing exceeded its bound.');
  }
  async #status(signature) {
    un58(signature,64);const r=await this.#network.rpc('getSignatureStatuses',[[signature],{searchTransactionHistory:true}]);this.#active();
    integer(r?.context?.slot);require(r.context.slot>=this.#slot&&Array.isArray(r.value)&&r.value.length===1,'Invalid publication status response.');
    this.#slot=r.context.slot;const s=r.value[0];
    if(s!==null){require(s&&['processed','confirmed','finalized'].includes(s.confirmationStatus));integer(s.slot);
      require(s.err===null||typeof s.err==='string'||s.err&&typeof s.err==='object'&&!Array.isArray(s.err));require(JSON.stringify(s.err).length<=1024);}
    return s;
  }
  async #effect(attempt) {
    const name=attempt.descriptor.name,c=this.#config;
    const source=await this.#account(c.transport.source);if(source===null)return false;
    const buffer=await this.#bufferView(source);
    if(name==='buffer-create')return true;
    if(name.startsWith('chunk-'))return !buffer.pending.includes(Number(name.slice(6)));
    if(name==='buffer-seal')return buffer.sealed;
    require(buffer.sealed,'Confirmed proof step has an unsealed source.');
    const account=await this.#account(c.transport.receipt);if(account===null)return false;
    const receipt=await this.#receiptView(account);
    return name==='proof-create'||receipt.complete||receipt.next.name!==name;
  }
  async #confirmed(attempt,status) {
    this.#slot=Math.max(this.#slot,status.slot);
    if(status.err===null&&!await this.#effect(attempt))return {id:this.#id,state:'awaiting_progress',signature:attempt.signature};
    await this.#journal.confirmed(this.#id,attempt.signature,status.slot,status.err);this.#active();
    return {id:this.#id,state:status.err===null?'step_confirmed':'failed',step:attempt.descriptor.name,signature:attempt.signature};
  }
  async #submit(attempt) {
    const parsed=await decodeTransaction(attempt.raw);this.#active();
    require(parsed.signature===attempt.signature&&b58(parsed.authority)===this.#config.transport.authority);
    let status=await this.#status(attempt.signature);
    if(status&&['confirmed','finalized'].includes(status.confirmationStatus))return this.#confirmed(attempt,status);
    const height=await this.#network.rpc('getBlockHeight',[{commitment:'finalized'}]);this.#active();integer(height);
    if(height>attempt.last_valid_height) {
      status=await this.#status(attempt.signature);
      if(status&&['confirmed','finalized'].includes(status.confirmationStatus))return this.#confirmed(attempt,status);
      if(status===null){await this.#journal.expired(this.#id,attempt.signature,height,true);this.#active();return {id:this.#id,state:'expired',signature:attempt.signature};}
      return {id:this.#id,state:'pending',signature:attempt.signature};
    }
    if(status!==null)return {id:this.#id,state:'pending',signature:attempt.signature};
    const simulation=await this.#simulate(attempt.raw,true);
    if(simulation.err!==null||simulation.unitsConsumed>LIMIT)return {id:this.#id,state:'pending',signature:attempt.signature,reason:'signed_simulation_rejected_preserved'};
    await this.#network.checkLedger();this.#active();for(const p of this.#programs())this.#network.requireProgram(p);
    const current=await this.#journal.pending(this.#id);this.#active();
    require(current&&current.raw===attempt.raw&&current.signature===attempt.signature,'Pending publication changed before send.');
    let signature;
    try{signature=await this.#network.rpc('sendTransaction',[attempt.raw,{encoding:'base64',skipPreflight:false,preflightCommitment:'confirmed',minContextSlot:this.#slot,maxRetries:0}]);}
    catch(e){this.#active();return {id:this.#id,state:'pending',signature:attempt.signature,reason:'submission_outcome_unknown'};}
    this.#active();require(signature===attempt.signature,'RPC returned a different publication signature.');
    return {id:this.#id,state:'pending',signature};
  }
  async step(id) {
    this.#active();hexValue(id,16);require(!this.#busy,'Wait for the current publication step.');this.#busy=true;
    try {
      if(this.#id!==id)await this.#start(id);
      else {await this.#network.checkLedger();this.#active();for(const p of this.#programs())this.#network.requireProgram(p);}
      let pending=await this.#journal.pending(id);this.#active();
      if(!pending){const action=await this.#choice();this.#active();if(action===null)return {id,state:'verified',settled:false};pending=await this.#prepare(action);}
      // Public, policy-bound step name for diagnostic timing/progress. A pending
      // step is not a confirmation; preserve the actual state from submission.
      return {...await this.#submit(pending),step:pending.descriptor.name};
    }catch(e){
      this.#reset();
      // Solana's -32016 means the requested minimum slot is not available at
      // this commitment yet. Keep the floor and any durable signature; the
      // next bounded step reattests/reconciles instead of weakening freshness.
      if(e?.rpcCode===-32016)return {id,state:'pending',reason:'rpc_minimum_slot_not_reached'};
      throw e;
    }finally{this.#busy=false;}
  }
}
