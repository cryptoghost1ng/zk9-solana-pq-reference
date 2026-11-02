// Server-side sponsored final settlement. This is not an HTTP handler.
// The trusted network scheduler supplies pinned raw accounts; the real Wasm
// validator reconstructs pool history and the exact recipient-bound instruction.
import {readRequest} from './relay-request.mjs';
import {requireState as require,integer,hexValue} from '../solana-chrome-wallet-v1/recovery/checkpoint.mjs';
import {checkedTransport,digest,toBase64,historyEvents,reconcileOperation} from '../solana-chrome-wallet-v1/recovery/payment-wire.mjs';
import {PublicationPolicy} from '../solana-relay-performance-v1/candidate/publication-policy.mjs';
import {b58,un58,concat,u64,hex,signedTransaction,decodeTransaction,instructionEqual} from '../solana-chrome-wallet-v1/recovery/solana-transaction.mjs';
const VERSION='zk9-sponsored-settlement-v1';
const exact=(v,keys)=>require(v&&Object.keys(v).sort().join(',')===keys.slice().sort().join(','),'Invalid sponsored settlement record.');
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const bytes=s=>Uint8Array.from(s.match(/../g),x=>parseInt(x,16));

export class SponsoredSettlement {
  #request;#id;#context;#program;#pool;#transport;#programData;#sponsor;#repo;#validator;#policy;
  #state;#busy=false;#tickets=new WeakMap();
  static async open({raw,context,program,pool,transport,programData,sponsor,repository,validator,verifyProof}){
    const j=new SponsoredSettlement();j.#request=await readRequest(raw,context);
    require(typeof verifyProof==='function'&&await verifyProof(j.#request.kind,j.#request.wire.slice(),context)===true,'Settlement proof admission failed.');
    require(typeof validator==='function'&&typeof validator.settlement==='function','Pinned history/settlement validator required.');
    un58(program,32);un58(pool,32);j.#context=context;j.#program=program;j.#pool=pool;
    j.#transport=checkedTransport(transport);require(transport.authority===b58(sponsor.pub),'Settlement sponsor differs from publication.');
    j.#programData=structuredClone(programData);j.#sponsor=sponsor;j.#repo=repository;j.#validator=validator;
    j.#id=await digest(new TextEncoder().encode(`${VERSION}\0${j.#request.id}`));
    j.#policy=await PublicationPolicy.create({wire:j.#request.wire,kind:j.#request.kind,transport:j.#transport,programData:j.#programData});
    const stored=await repository.read(j.id);
    if(stored)j.#state=await j.#checked(stored);
    else{
      const initial={version:VERSION,id:j.id,request_id:j.#request.id,wire_hash:j.#request.wire_hash,transport:j.#transport,
        revision:1,observed_slot:0,pending:null,last:null};
      await repository.compareAndSwap(j.id,null,initial);j.#state=initial;
    }
    return j;
  }
  get id(){return this.#id;}
  get requestId(){return this.#request.id;}
  requireSync(){this.#tickets=new WeakMap();}
  #instruction(p){
    exact(p,['kind','context','before_count','snapshot_slot','root','instruction','synthetic_only']);
    require(p.kind===this.#request.kind&&p.context===this.#context&&p.synthetic_only===true);
    integer(p.before_count);integer(p.snapshot_slot);hexValue(p.root,64);
    require(p.before_count>=2&&p.before_count<=99998&&p.before_count%2===0);
    exact(p.instruction,['program','accounts','data']);require(p.instruction.program===this.#program);
    const a=p.instruction.accounts,n=this.#request.kind==='send'?18:20;
    const programs=this.#policy.configuration;
    require(Array.isArray(a)&&a.length===n&&new Set(a.map(x=>x.pub)).size===n);
    a.forEach((x,i)=>{exact(x,['pub','signer','writable']);un58(x.pub,32);
      require(x.signer===(i===4)&&x.writable===[0,1,4,7,8,9,10,11,18,19].includes(i));});
    require(a[0].pub===this.#pool&&a[2].pub===b58(bytes(this.#context.slice(128)))
      &&a[3].pub==='TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'
      &&a[4].pub===this.#transport.authority&&a[5].pub==='11111111111111111111111111111111'
      &&a[12].pub===this.#transport.receipt&&a[15].pub===this.#transport.source
      &&a[13].pub===programs.proof_program&&a[16].pub===programs.buffer_program
      &&this.#programData[a[13].pub]===a[14].pub&&this.#programData[a[16].pub]===a[17].pub);
    const expected=concat(Uint8Array.of(n===18?2:3),u64(p.before_count),bytes(this.#context.slice(64,128)));
    require(p.instruction.data===hex(expected),'Settlement instruction differs.');
    return {program:un58(this.#program,32),accounts:a.map(x=>({...x,pub:un58(x.pub,32)})),data:expected};
  }
  async #attempt(a){
    exact(a,['plan','raw','signature','last_valid_height','confirmed_slot']);integer(a.last_valid_height);
    if(a.confirmed_slot!==null){integer(a.confirmed_slot);require(a.confirmed_slot>=a.plan.snapshot_slot);}
    const expected=this.#instruction(a.plan),tx=await decodeTransaction(a.raw);
    require(tx.signature===a.signature&&b58(tx.authority)===this.#transport.authority&&tx.signers.length===1
      &&tx.instructions.length===1&&instructionEqual(tx.instructions[0],expected),'Stored settlement transaction changed.');
  }
  async #checked(s){
    exact(s,['version','id','request_id','wire_hash','transport','revision','observed_slot','pending','last']);
    require(s.version===VERSION&&s.id===this.id&&s.request_id===this.requestId&&s.wire_hash===this.#request.wire_hash
      &&same(s.transport,this.#transport),'Settlement request binding changed.');
    integer(s.revision);require(s.revision>0);integer(s.observed_slot);
    if(s.pending){await this.#attempt(s.pending);require(s.observed_slot>=s.pending.plan.snapshot_slot);}
    if(s.last){exact(s.last,['signature','outcome','height']);un58(s.last.signature,64);integer(s.last.height);
      require(['settled','conflicted','failed','expired'].includes(s.last.outcome));}
    return structuredClone(s);
  }
  async #exclusive(fn){require(!this.#busy,'Settlement operation already running.');this.#busy=true;
    try{const stored=await this.#repo.read(this.id);require(stored&&same(await this.#checked(stored),this.#state),'Settlement journal changed; reopen.');return await fn();}
    finally{this.#busy=false;}}
  async #commit(value){const next={...value,revision:this.#state.revision+1};await this.#checked(next);
    await this.#repo.compareAndSwap(this.id,this.#state.revision,next);this.#state=structuredClone(next);this.#tickets=new WeakMap();}
  async prepare({history,buffer,receipt,destination=null}){return this.#exclusive(async()=>{
    require(!this.#state.pending,'Reconcile the existing settlement first.');
    require((await this.#policy.buffer(buffer)).sealed,'Settlement proof buffer is incomplete.');
    require((await this.#policy.receipt(receipt)).complete,'Settlement verifier receipt is incomplete.');
    // The attestation can cover the pool and both verifiers. The strict Wasm
    // ABI takes exactly this operation's verifier and buffer program-data pair,
    // already checked and selected by PublicationPolicy; keep that ABI strict.
    const plan=this.#validator.settlement({kind:this.#request.kind,wire:toBase64(this.#request.wire),history,
      transport:this.#transport,program_data:this.#policy.configuration.program_data,destination});
    this.#instruction(plan);require(plan.snapshot_slot>=this.#state.observed_slot,'Settlement history rolled back.');
    const ticket=Object.freeze({});this.#tickets.set(ticket,{plan:structuredClone(plan),revision:this.#state.revision});return ticket;
  });}
  #plan(ticket){const p=this.#tickets.get(ticket);require(p&&p.revision===this.#state.revision&&!this.#state.pending,'Unknown or stale settlement ticket.');return p.plan;}
  async simulation(ticket,blockhash){return this.#exclusive(async()=>{
    const plan=this.#plan(ticket),unsigned={pub:this.#sponsor.pub,sign:async()=>new Uint8Array(64)};
    const tx=await signedTransaction(unsigned,[this.#instruction(plan)],[],blockhash,0);return {raw:tx.raw,unsigned:true};
  });}
  async sign(ticket,blockhash,lastValidHeight){return this.#exclusive(async()=>{
    integer(lastValidHeight);const plan=this.#plan(ticket);this.#tickets.delete(ticket);
    const tx=await signedTransaction(this.#sponsor,[this.#instruction(plan)],[],blockhash,lastValidHeight);
    const a={plan,raw:tx.raw,signature:tx.signature,last_valid_height:lastValidHeight,confirmed_slot:null};await this.#attempt(a);
    await this.#commit({...this.#state,pending:a,observed_slot:plan.snapshot_slot});return {...structuredClone(a),durable:true};
  });}
  async pending(){return this.#exclusive(async()=>{
    // Sender API includes the immutable sponsor binding. Keep the durable
    // attempt schema unchanged and derive this view from the checked journal.
    return this.#state.pending?structuredClone({...this.#state.pending,transport:this.#transport}):null;
  });}
  async confirmed(signature,slot){return this.#exclusive(async()=>{
    integer(slot);const a=this.#state.pending;require(a&&a.signature===signature&&slot>=a.plan.snapshot_slot);
    require(a.confirmed_slot===null||a.confirmed_slot===slot);
    await this.#commit({...this.#state,pending:{...a,confirmed_slot:slot}});return {confirmed:true,settled:false};
  });}
  // Only trusted pinned-RPC history can establish settlement, never a relay
  // status response or a successful signature confirmation by itself.
  async reconcile(history){return this.#exclusive(async()=>{
    require(history.program===this.#program&&history.pool===this.#pool&&history.context===this.#context);
    const snapshot=this.#validator(history),events=historyEvents(snapshot,history.response);
    const a=this.#state.pending;require(snapshot.slot>=Math.max(this.#state.observed_slot,a?.confirmed_slot??0),'Settlement history rolled back.');
    const statement=this.#request.statement;
    const operation={state:'settling',kind:this.#request.kind,fee:statement.fee,proof:{summary:statement,wire:null},transport:this.#transport,
      ...(this.#request.kind==='withdraw'?{amount:statement.amount,target:b58(bytes(statement.recipient))}:{})};
    const result=reconcileOperation(operation,snapshot,events);
    if(['settled','conflicted'].includes(result.state)&&a){
      await this.#commit({...this.#state,pending:null,observed_slot:snapshot.slot,last:{signature:a.signature,outcome:result.state,height:snapshot.slot}});
    }
    return {state:result.state,settled:result.state==='settled',slot:snapshot.slot};
  });}
  // Internal scheduler-only evidence. Finalized block HEIGHT is not a slot.
  async expired(signature,height,missingAfterExpiry){return this.#exclusive(async()=>{
    integer(height);const a=this.#state.pending;require(a&&a.signature===signature&&a.confirmed_slot===null
      &&missingAfterExpiry===true&&height>a.last_valid_height,'Unproven settlement expiry.');
    await this.#commit({...this.#state,pending:null,last:{signature,outcome:'expired',height}});
  });}
  async failed(signature,slot,error){return this.#exclusive(async()=>{
    integer(slot);require(error!==null&&error!==undefined&&JSON.stringify(error).length<=1024);
    const a=this.#state.pending;require(a&&a.signature===signature&&a.confirmed_slot===null);
    await this.#commit({...this.#state,pending:null,last:{signature,outcome:'failed',height:slot}});
  });}
}
