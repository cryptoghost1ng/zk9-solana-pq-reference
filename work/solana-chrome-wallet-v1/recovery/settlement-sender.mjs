// Private pinned local-RPC adapter. Proof verification is necessary; only a
// fresh custody scan matching the approved operation can report settlement.
import {requireState as require,integer,hexValue} from './checkpoint.mjs';
import {b58,un58,sha256,decodeTransaction,fromBase64} from './solana-transaction.mjs';
import {parsePaymentWire} from './payment-wire.mjs';
import {PROFILES} from './proof-progress.mjs';
const bytes=h=>Uint8Array.from(h.match(/../g),x=>parseInt(x,16));
const BUFFER=b58(await sha256(new TextEncoder().encode('ZK9 local proof buffer program v1')));
export class SettlementSender {
 #network;#journal;#payments;#synchronize;#context;#program;#proof;#kind;#programData;#slot=0;#signal;#closed=false;#busy=false;
 constructor({network,journal,payments,synchronize,context,program,kind,programData,signal}){
  hexValue(context,96);un58(program,32);require(kind==='send'||kind==='withdraw');require(typeof synchronize==='function');
  this.#proof=b58(bytes(PROFILES[kind].programHex));
  require(network.profile.genesis===b58(bytes(context.slice(64,128))));
  for(const p of [program,BUFFER,this.#proof])require(Object.hasOwn(network.profile.programs,p));
  this.#network=network;this.#journal=journal;this.#payments=payments;this.#synchronize=synchronize;this.#context=context;this.#program=program;this.#kind=kind;this.#programData=structuredClone(programData);this.#signal=signal;
 }
 close(){this.#closed=true;this.requireSync();}
 requireSync(){this.#network.invalidate();this.#journal.requireSync();}
 #active(){require(!this.#closed,'Settlement network session is closed.');this.#signal?.throwIfAborted();}
 async #refresh(min=this.#slot){const raw=await this.#network.history(this.#program,Math.max(min,this.#slot));this.#active();
  const scan=await this.#synchronize(raw);this.#active();require(scan?.context===this.#context&&scan.slot===raw.context.slot&&scan.synthetic_only===true&&scan.rpc_consensus_authenticated===false);
  integer(scan.slot);this.#slot=scan.slot;
 }
 async #terminal(id){const state=await this.#payments.publicationState(id);this.#active();require(state.kind===this.#kind);
  if(!['settled','conflicted'].includes(state.state)){require(state.state==='settling','Payment is not ready for settlement.');return null;}
  const pending=await this.#journal.pending(id);this.#active();if(pending){await this.#journal.reconciled(id,pending.signature,state.state,this.#slot);this.#active();}
  return {id,state:state.state,settled:state.state==='settled'};
 }
 async #status(signature){const r=await this.#network.rpc('getSignatureStatuses',[[signature],{searchTransactionHistory:true}]);this.#active();
  integer(r?.context?.slot);require(r.context.slot>=this.#slot&&Array.isArray(r.value)&&r.value.length===1);this.#slot=r.context.slot;
  const s=r.value[0];if(s!==null){require(s&&['processed','confirmed','finalized'].includes(s.confirmationStatus));integer(s.slot);require(s.err===null||typeof s.err==='string'||s.err&&typeof s.err==='object'&&!Array.isArray(s.err));require(JSON.stringify(s.err).length<=1024);}return s;
 }
 async #simulate(raw,signed){const r=await this.#network.rpc('simulateTransaction',[raw,{encoding:'base64',sigVerify:signed,commitment:'confirmed',minContextSlot:this.#slot}]);this.#active();
  integer(r?.context?.slot);require(r.context.slot>=this.#slot&&r.value&&Object.hasOwn(r.value,'err'));this.#slot=r.context.slot;
  if(r.value.err===null)integer(r.value.unitsConsumed);return r.value;
 }
 async #prepare(id){
  const input=await this.#payments.settlementInput(id);this.#active();require(input.kind===this.#kind);
  const buffer=await this.#network.account(input.transport.source,this.#slot);this.#active();
  const receipt=await this.#network.account(input.transport.receipt,this.#slot);this.#active();
  let destination=null;
  if(this.#kind==='withdraw'){
   const proof=parsePaymentWire(fromBase64(input.wire),'withdraw'),owner=b58(bytes(proof.recipient));
   const accounts=await this.#network.rpc('getTokenAccountsByOwner',[owner,{mint:b58(bytes(this.#context.slice(128)))},{encoding:'base64',commitment:'confirmed',minContextSlot:this.#slot}]);this.#active();
   integer(accounts?.context?.slot);require(accounts.context.slot>=this.#slot&&Array.isArray(accounts.value));this.#slot=accounts.context.slot;
   require(accounts.value.length===1,'Withdrawal requires exactly one existing token account for the approved recipient.');
   destination=accounts.value[0];
  }
  const ticket=await this.#journal.prepare(id,{buffer,receipt,destination});this.#active();
  const block=await this.#network.rpc('getLatestBlockhash',[{commitment:'confirmed',minContextSlot:this.#slot}]);this.#active();
  integer(block?.context?.slot);require(block.context.slot>=this.#slot);this.#slot=block.context.slot;un58(block.value?.blockhash,32);integer(block.value?.lastValidBlockHeight);
  const probe=await this.#journal.simulation(id,ticket,block.value.blockhash);this.#active();const unsigned=fromBase64(probe.raw,1232);
  require(probe.unsigned===true&&unsigned[0]===1&&unsigned.length>65&&unsigned.subarray(1,65).every(x=>x===0));
  const simulation=await this.#simulate(probe.raw,false);require(simulation.err===null&&simulation.unitsConsumed<=1300000,'Final settlement simulation rejected.');
  const signed=await this.#journal.sign(id,ticket,block.value.blockhash,block.value.lastValidBlockHeight);this.#active();require(signed.durable===true);
  const stored=await this.#journal.pending(id);this.#active();require(stored&&stored.raw===signed.raw&&stored.signature===signed.signature);return stored;
 }
 async #confirmed(id,a,s){
  if(s.err!==null){await this.#journal.failed(id,a.signature,s.slot,s.err);this.#active();return {id,state:'failed',signature:a.signature};}
  await this.#journal.confirmed(id,a.signature,s.slot);this.#active();await this.#refresh(s.slot);
  return await this.#terminal(id)??{id,state:'awaiting_receipt',signature:a.signature,settled:false};
 }
 async step(id){this.#active();hexValue(id,16);require(!this.#busy,'Wait for the current settlement step.');this.#busy=true;
  try{
   await this.#network.attest([this.#program,BUFFER,this.#proof]);this.#active();
   for(const p of [BUFFER,this.#proof])require(this.#network.requireProgram(p)===this.#programData[p],'Settlement program data changed.');
   await this.#refresh();const terminal=await this.#terminal(id);if(terminal)return terminal;
   let a=await this.#journal.pending(id);this.#active();if(!a)a=await this.#prepare(id);
   if(a.confirmed_slot!==null)return {id,state:'awaiting_receipt',signature:a.signature,settled:false};
   const tx=await decodeTransaction(a.raw);this.#active();require(tx.signature===a.signature&&b58(tx.authority)===a.transport.authority);
   let status=await this.#status(a.signature);
   if(status&&['confirmed','finalized'].includes(status.confirmationStatus))return await this.#confirmed(id,a,status);
   const height=await this.#network.rpc('getBlockHeight',[{commitment:'finalized'}]);this.#active();integer(height);
   if(height>a.last_valid_height){
    status=await this.#status(a.signature);
    if(status&&['confirmed','finalized'].includes(status.confirmationStatus))return await this.#confirmed(id,a,status);
    if(status===null){await this.#journal.expired(id,a.signature,height,true);this.#active();return {id,state:'expired',signature:a.signature};}
    return {id,state:'pending',signature:a.signature};
   }
   if(status!==null)return {id,state:'pending',signature:a.signature};
   const simulation=await this.#simulate(a.raw,true);
   if(simulation.err!==null||simulation.unitsConsumed>1300000)return {id,state:'pending',signature:a.signature,reason:'signed_simulation_rejected_preserved'};
   await this.#network.checkLedger();this.#active();for(const p of [this.#program,BUFFER,this.#proof])this.#network.requireProgram(p);
   const saved=await this.#journal.pending(id);this.#active();require(saved&&saved.signature===a.signature&&saved.raw===a.raw);
   let signature;try{signature=await this.#network.rpc('sendTransaction',[a.raw,{encoding:'base64',skipPreflight:false,preflightCommitment:'confirmed',minContextSlot:this.#slot,maxRetries:0}]);}
   catch{this.#active();return {id,state:'pending',signature:a.signature,reason:'submission_outcome_unknown'};}
   this.#active();require(signature===a.signature,'RPC returned another settlement signature.');return {id,state:'pending',signature};
  }catch(error){
   this.requireSync();
   // Preserve both the monotonic slot floor and any already-signed attempt
   // while the requested commitment catches up. No other RPC error is hidden.
   if(error?.rpcCode===-32016)return {id,state:'pending',reason:'rpc_minimum_slot_not_reached'};
   throw error;
  }finally{this.#busy=false;}
 }
}
