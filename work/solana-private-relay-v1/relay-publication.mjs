// Candidate SERVER-SIDE sponsored publication journal. Never installed in the
// wallet. The sponsor and transport seed belong to the relay, not a user.
// No network listener or broadcast here. Admission/chain verification, durable
// repository and trusted network scheduler must be supplied before deployment.
import {readRequest} from './relay-request.mjs';
import {requireState as require,integer} from '../solana-chrome-wallet-v1/recovery/checkpoint.mjs';
import {PublicationPolicy} from '../solana-relay-performance-v1/candidate/publication-policy.mjs';
import {b58,signedTransaction} from '../solana-chrome-wallet-v1/recovery/solana-transaction.mjs';
import {deriveRelayTransport} from './relay-transport.mjs';

const VERSION='zk9-sponsored-publication-journal-v1';
const exact=(v,keys)=>require(v&&Object.keys(v).sort().join(',')===keys.slice().sort().join(','),'Invalid relay journal record.');
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
export class SponsoredPublication {
  #request;#repository;#sponsor;#source;#receipt;#policy;#state;#tickets=new WeakMap();#busy=false;
  static async open({raw,context,programData,sponsor,transportSeed,repository,verifyProof}) {
    require(transportSeed instanceof Uint8Array&&transportSeed.length===32&&transportSeed.some(x=>x));
    require(typeof verifyProof==='function','Native proof admission is required before sponsor signing.');
    const j=new SponsoredPublication();j.#request=await readRequest(raw,context);
    // The verifier is a trusted LOCAL adapter, never a boolean from HTTP.
    require(await verifyProof(j.#request.kind,j.#request.wire.slice(),context)===true,'Proof admission failed.');
    j.#repository=repository;j.#sponsor=sponsor;
    const derived=await deriveRelayTransport(sponsor,transportSeed,j.#request.id);
    j.#source=derived.source;j.#receipt=derived.receipt;
    const transport=derived.transport;
    j.#policy=await PublicationPolicy.create({wire:j.#request.wire,kind:j.#request.kind,transport,programData});
    const stored=await repository.read(j.#request.id);
    if(stored)j.#state=await j.#checked(stored);
    else {
      const initial={version:VERSION,id:j.#request.id,wire_hash:j.#request.wire_hash,transport,
        revision:1,pending:null,attempts:0,last:null};
      await repository.compareAndSwap(j.#request.id,null,initial);j.#state=initial;
    }
    return j;
  }
  get id(){return this.#request.id;}
  get configuration(){return this.#policy.configuration;}
  requireSync(){this.#tickets=new WeakMap();}
  async #checked(s) {
    exact(s,['version','id','wire_hash','transport','revision','pending','attempts','last']);
    require(s.version===VERSION&&s.id===this.id&&s.wire_hash===this.#request.wire_hash
      &&same(s.transport,this.configuration.transport),'Relay request binding changed.');
    integer(s.revision);integer(s.attempts);require(s.revision>0);
    if(s.pending)await this.#policy.verifyAttempt(s.pending);
    if(s.last){exact(s.last,['signature','outcome','height']);integer(s.last.height);
      require(['confirmed','failed','expired'].includes(s.last.outcome));}
    return structuredClone(s);
  }
  async #fresh(){const s=await this.#repository.read(this.id);
    require(s&&s.revision===this.#state.revision,'Relay journal changed; reopen and reconcile.');
    require(same(await this.#checked(s),this.#state),'Relay journal content changed.');}
  async #exclusive(fn){require(!this.#busy,'Relay operation already running.');this.#busy=true;
    try{await this.#fresh();return await fn();}finally{this.#busy=false;}}
  async #commit(next){next={...next,revision:this.#state.revision+1};await this.#checked(next);
    await this.#repository.compareAndSwap(this.id,this.#state.revision,next);
    this.#state=structuredClone(next);this.#tickets=new WeakMap();}
  buffer(account){return this.#policy.buffer(account);}
  receipt(account,previous){return this.#policy.receipt(account,previous);}
  async prepare(action){return this.#exclusive(async()=>{
    require(!this.#state.pending,'Resolve the existing signed transaction first.');
    let step;
    if(action.type==='create'){exact(action,['type','which','rent']);step=this.#policy.accountCreation(action.which,action.rent);}
    else if(action.type==='chunk'){exact(action,['type','index']);step=this.#policy.chunk(action.index);}
    else if(action.type==='seal'){exact(action,['type']);step=this.#policy.seal();}
    else if(action.type==='verify'){exact(action,['type','receipt','work']);step=this.#policy.next(action.receipt,action.work);}
    else throw Error('Unknown relay action.');
    const ticket=Object.freeze({});this.#tickets.set(ticket,{step,revision:this.#state.revision});return ticket;
  });}
  #plan(ticket){const p=this.#tickets.get(ticket);
    require(p&&p.revision===this.#state.revision&&!this.#state.pending,'Unknown or stale relay ticket.');return p.step;}
  async simulation(ticket,blockhash){return this.#exclusive(async()=>{
    const p=this.#plan(ticket),unsigned=pub=>({pub,sign:async()=>new Uint8Array(64)});
    const extras=p.extra_signers.map(pub=>pub===b58(this.#source.pub)?unsigned(this.#source.pub):unsigned(this.#receipt.pub));
    const tx=await signedTransaction(unsigned(this.#sponsor.pub),p.instructions,extras,blockhash,0);
    return {raw:tx.raw,unsigned:true};
  });}
  async sign(ticket,blockhash,lastValidHeight){return this.#exclusive(async()=>{
    integer(lastValidHeight);const p=this.#plan(ticket);this.#tickets.delete(ticket);
    const extras=p.extra_signers.map(pub=>pub===b58(this.#source.pub)?this.#source:pub===b58(this.#receipt.pub)?this.#receipt:null);
    require(extras.every(Boolean));
    const tx=await signedTransaction(this.#sponsor,p.instructions,extras,blockhash,lastValidHeight);
    const attempt={descriptor:p.descriptor,raw:tx.raw,signature:tx.signature,last_valid_height:lastValidHeight};
    await this.#policy.verifyAttempt(attempt);
    // Never release signed bytes until the storage transaction commits.
    await this.#commit({...this.#state,pending:attempt,attempts:this.#state.attempts+1});
    return {...structuredClone(attempt),durable:true};
  });}
  async pending(){return this.#exclusive(async()=>structuredClone(this.#state.pending));}
  // These methods are for the trusted network scheduler, NOT client endpoints.
  // Confirmation needs chain effect checks; expiration needs a second missing
  // signature lookup after finalized height, as in PublicationSender.
  async resolve(signature,{outcome,height,missingAfterExpiry=false}){return this.#exclusive(async()=>{
    integer(height);const a=this.#state.pending;
    require(a&&a.signature===signature&&['confirmed','failed','expired'].includes(outcome));
    if(outcome==='expired')require(missingAfterExpiry===true&&height>a.last_valid_height,'Unproven transaction expiry.');
    await this.#commit({...this.#state,pending:null,last:{signature,outcome,height}});
  });}
}
