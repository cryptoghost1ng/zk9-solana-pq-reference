// The journal surface the publication sender sees, with the short request id checked on every call. It was inline in
// ../solana-private-relay-v1/relay-task.mjs (frozen); it is a module here so the sender + journal composition can be
// exercised without opening a whole relay task. The batch methods are new: prepareChunks / simulations / signBatch / resolveMany.
import {requireState as require} from '../solana-chrome-wallet-v1/recovery/checkpoint.mjs';

export function publicationJournal({publication:pub,checkedId,isSettling}) {
  require(pub&&typeof checkedId==='function'&&typeof isSettling==='function','Publication journal adapter needs its dependencies.');
  return {
    requireSync:()=>pub.requireSync(),
    bind:async id=>{checkedId(id);require(isSettling(),'Proof already spent or conflicted.');return pub.configuration;},
    buffer:(id,account)=>{checkedId(id);return pub.buffer(account);},
    receipt:(id,account,previous)=>{checkedId(id);return pub.receipt(account,previous);},
    prepare:(id,action)=>{checkedId(id);return pub.prepare(action);},
    prepareChunks:(id,action)=>{checkedId(id);return pub.prepareChunks(action);},
    simulation:(id,ticket,blockhash)=>{checkedId(id);return pub.simulation(ticket,blockhash);},
    simulations:(id,ticket,blockhash)=>{checkedId(id);return pub.simulations(ticket,blockhash);},
    sign:(id,ticket,blockhash,height)=>{checkedId(id);return pub.sign(ticket,blockhash,height);},
    signBatch:(id,ticket,blockhash,height)=>{checkedId(id);return pub.signBatch(ticket,blockhash,height);},
    pending:id=>{checkedId(id);return pub.pending();},
    confirmed:(id,signature,slot,error)=>{checkedId(id);return pub.resolve(signature,{outcome:error===null?'confirmed':'failed',height:slot});},
    expired:(id,signature,height,missing)=>{checkedId(id);return pub.resolve(signature,{outcome:'expired',height,missingAfterExpiry:missing});},
    resolveMany:(id,entries)=>{checkedId(id);return pub.resolveMany(entries);},
  };
}
