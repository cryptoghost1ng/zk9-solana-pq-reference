// Candidate local-only service composition. No HTTP API or wallet access.
// Reuses the existing bounded RPC senders (simulation, CU sizing, immutable code
// attestation, uncertain-send reconciliation) with relay-owned journals.
// WINDOWED revision: derived from ../solana-private-relay-v1/relay-task.mjs (frozen, untouched). The publication side
// uses the v2 journal (a list of pending attempts), the windowed sender and the v2 funding; settlement is the frozen one.
import {readRequest} from '../solana-private-relay-v1/relay-request.mjs';
import {SponsoredPublication} from './relay-publication.mjs';
import {SponsoredSettlement} from '../solana-private-relay-v1/relay-settlement.mjs';
import {LocalNetwork} from '../solana-relay-performance-v1/candidate/local-network.mjs';
// The unified sender (installed-connected-08 baseline: strict verifier/memo CU exhaustion handling, without weakening
// proof errors) plus the chunk window.
import {PublicationSender} from './publication-sender.mjs';
import {publicationJournal} from './publication-adapter.mjs';
import {SettlementSender} from '../solana-chrome-wallet-v1/recovery/settlement-sender.mjs';
import {toBase64,digest} from '../solana-chrome-wallet-v1/recovery/payment-wire.mjs';
import {b58,un58,sha256} from '../solana-chrome-wallet-v1/recovery/solana-transaction.mjs';
import {PROFILES} from '../solana-chrome-wallet-v1/recovery/proof-progress.mjs';
import {checkedFunding,fundedRepository,quoteFundingDebit,COST_POOL_SHA256} from './relay-funding.mjs';
import {MAX_WINDOW} from './relay-publication.mjs';
import {requireState as require,integer} from '../solana-chrome-wallet-v1/recovery/checkpoint.mjs';

export class LocalRelayTask {
  #id;#logicalId;#kind;#publication;#settlement;#publisher;#settler;#reader;#programs;
  #context;#program;#pool;#validator;#slot=0;#history=null;#state='settling';#published=false;#closed=false;#busy=false;#signal;
  static async open({raw,context,program,pool,profile,programData,sponsor,transportSeed,repository,validator,verifyProof,signal,
    funding,maxPublicationAttempts=12000,window=64,fetchImpl}){
    const t=new LocalRelayTask(),request=await readRequest(raw,context);
    integer(maxPublicationAttempts);require(maxPublicationAttempts>0&&maxPublicationAttempts<=20000,'Invalid local relay attempt cap.');
    require(Number.isSafeInteger(window)&&window>=1&&window<=MAX_WINDOW,'Invalid chunk window size.');
    t.#id=request.id;t.#logicalId=request.id.slice(0,32);t.#kind=request.kind;
    // Short ID is ONLY a sender-local API parameter. Full 256-bit request IDs
    // bind all storage, transport derivation and externally returned responses.
    const checkedId=id=>require(id===t.#logicalId,'Foreign request entered relay task.');
    funding=checkedFunding(funding);
    const network=()=>new LocalNetwork({profile,signal,...(fetchImpl?{fetchImpl}:{})});
    t.#reader=network();
    // Fail invalid operator configuration before reserving funds or writing
    // journals. PublicationSender also checks these on construction, but that
    // happens too late to prevent stranded reservations on a bad profile.
    const bytes=h=>Uint8Array.from(h.match(/../g),v=>parseInt(v,16));
    un58(program,32);un58(pool,32);
    require(typeof validator==='function'&&typeof validator.settlement==='function','History/settlement validator required.');
    require(profile.genesis===b58(bytes(context.slice(64,128))),'Wrong configured proof network.');
    require(profile.programs[program]===COST_POOL_SHA256,'Pool executable has no reviewed allocation budget.');
    const bufferProgram=b58(await sha256(new TextEncoder().encode('ZK9 local proof buffer program v1')));
    const proofProgram=b58(bytes(PROFILES[request.kind].programHex));
    for(const p of [bufferProgram,proofProgram]){require(Object.hasOwn(profile.programs,p),'Unpinned publication program.');un58(programData?.[p],32);}
    // Invalid proofs must not consume reservations. Cache ONLY this successful
    // trusted verification, bound to the complete wire hash, kind and context.
    require(typeof verifyProof==='function'&&await verifyProof(request.kind,request.wire.slice(),context)===true,'Native relay admission failed.');
    signal?.throwIfAborted();
    const admitted=async(kind,wire,c)=>kind===request.kind&&c===context&&await digest(wire)===request.wire_hash;
    const boundedRepository=await fundedRepository({repository,requestId:request.id,sponsor:b58(sponsor.pub),genesis:profile.genesis,
      funding,maxPublicationAttempts,quoteDebit:value=>quoteFundingDebit({value,network:t.#reader,sponsor:b58(sponsor.pub),
        program,kind:request.kind,maxFeeLamports:funding.maxFeeLamports})});
    t.#context=context;t.#program=program;t.#pool=pool;t.#validator=validator;t.#signal=signal;
    t.#publication=await SponsoredPublication.open({raw,context,programData,sponsor,transportSeed,repository:boundedRepository,verifyProof:admitted});
    const config=t.#publication.configuration;
    t.#settlement=await SponsoredSettlement.open({raw,context,program,pool,transport:config.transport,programData,sponsor,repository:boundedRepository,validator,verifyProof:admitted});
    t.#programs=[program,config.buffer_program,config.proof_program];
    const synchronize=response=>t.#synchronize(response);
    const pub=t.#publication;
    const journal=publicationJournal({publication:pub,checkedId,isSettling:()=>t.#state==='settling'});
    t.#publisher=new PublicationSender({network:network(),journal,synchronize,context,program,kind:request.kind,signal,window});
    const settlement=t.#settlement;
    const settlementJournal={
      requireSync:()=>settlement.requireSync(),
      prepare:(id,args)=>{checkedId(id);require(t.#history,'Relay history not synchronized.');return settlement.prepare({...args,history:t.#history});},
      simulation:(id,ticket,blockhash)=>{checkedId(id);return settlement.simulation(ticket,blockhash);},
      sign:(id,ticket,blockhash,height)=>{checkedId(id);return settlement.sign(ticket,blockhash,height);},
      pending:id=>{checkedId(id);return settlement.pending();},
      confirmed:(id,signature,slot)=>{checkedId(id);return settlement.confirmed(signature,slot);},
      failed:(id,signature,slot,error)=>{checkedId(id);return settlement.failed(signature,slot,error);},
      expired:(id,signature,height,missing)=>{checkedId(id);return settlement.expired(signature,height,missing);},
      reconciled:async(id,_signature,state)=>{checkedId(id);require(state===t.#state&&await settlement.pending()===null,'Settlement reconciliation incomplete.');},
    };
    const payments={
      publicationState:async id=>{checkedId(id);return {kind:request.kind,state:t.#state};},
      settlementInput:async id=>{checkedId(id);require(t.#state==='settling'&&t.#history,'Relay payment is not ready.');
        return {id,kind:request.kind,wire:toBase64(request.wire),transport:config.transport,history:t.#history};},
    };
    t.#settler=new SettlementSender({network:network(),journal:settlementJournal,payments,synchronize,context,program,kind:request.kind,programData,signal});
    return t;
  }
  get id(){return this.#id;}
  get transport(){return this.#publication.configuration.transport;}
  #active(){require(!this.#closed,'Relay task is closed.');this.#signal?.throwIfAborted();}
  async #synchronize(response){
    this.#active();const history={context:this.#context,program:this.#program,pool:this.#pool,response};
    const snapshot=this.#validator(history);integer(snapshot.slot);
    require(snapshot.context===this.#context&&snapshot.slot===response.context.slot&&snapshot.slot>=this.#slot,'Relay history rolled back.');
    const result=await this.#settlement.reconcile(history);this.#active();
    this.#slot=snapshot.slot;this.#history=history;this.#state=result.state;
    // Public pool validation only; this service performs NO private owner scan.
    return {context:this.#context,slot:this.#slot,synthetic_only:true,rpc_consensus_authenticated:false};
  }
  async step(){
    this.#active();require(!this.#busy,'Relay task is already stepping.');this.#busy=true;
    try{
      // Recheck effects before spending even on restart. A relay status message
      // alone is never authoritative for the user's wallet.
      await this.#reader.attest(this.#programs);this.#active();
      await this.#synchronize(await this.#reader.history(this.#program,this.#slot));this.#active();
      if(['settled','conflicted'].includes(this.#state))return {id:this.id,state:this.#state,settled:this.#state==='settled'};
      const result=this.#published?await this.#settler.step(this.#logicalId):await this.#publisher.step(this.#logicalId);
      this.#active();if(result.state==='verified')this.#published=true;
      return {...result,id:this.id};
    }catch(error){
      this.#reader.invalidate();this.#publication.requireSync();this.#settlement.requireSync();
      if(error?.rpcCode===-32016)return {id:this.id,state:'pending',reason:'rpc_minimum_slot_not_reached'};
      throw error;
    }finally{this.#busy=false;}
  }
  close(){this.#closed=true;this.#reader.invalidate();this.#publisher.close();this.#settler.close();}
}
