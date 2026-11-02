// Resumable bounded-concurrency transport. A sealed buffer is NOT a valid proof.
// The caller pins the RPC, buffer address and immutable buffer program before use.
import assert from 'node:assert/strict';
import {sha,u32,b58} from './runtime-helpers.mjs';
export function bufferPlan(wire){
 assert.ok(Buffer.isBuffer(wire)&&wire.length>0&&wire.length<=5*1024*1024);
 const total=wire.length,count=Math.ceil(total/900),hashStart=85+Math.ceil(count/8),start=hashStart+32*count;
 const leaves=Array.from({length:count},(_,i)=>sha(Buffer.from('ZK9/SOLANA/BUFFER/LEAF/v1\0'),u32(total),u32(i),wire.subarray(i*900,(i+1)*900)));
 const root=sha(Buffer.from('ZK9/SOLANA/BUFFER/ROOT/v1\0'),u32(total),Buffer.concat(leaves));
 return {total,count,hashStart,start,leaves,root};
}
export function inspectBuffer(account,wire,authority,program,plan=bufferPlan(wire)){
 assert.ok(account&&account.executable===false&&account.owner===b58(program),'Wrong buffer account owner');
 assert.equal(account.data?.[1],'base64');const bytes=Buffer.from(account.data[0],'base64');
 const {count,total,start,hashStart,leaves,root}=plan;
 assert.equal(bytes.length,start+total);assert.equal(bytes.subarray(0,8).toString(),'ZK9BUF1\0');
 assert.ok(bytes.subarray(8,40).equals(authority));assert.equal(bytes.readUInt32LE(40),total);
 assert.ok(bytes.subarray(48,80).equals(root));assert.ok(bytes.subarray(81,85).equals(Buffer.alloc(4)));
 assert.ok(bytes[80]===1||bytes[80]===2,'Unknown buffer state');
 let received=0;const pending=[];
 for(let i=0;i<count;i++){
  if(bytes[85+(i>>3)]&(1<<(i%8))){
   received++;assert.ok(bytes.subarray(hashStart+32*i,hashStart+32*(i+1)).equals(leaves[i]),'Stored chunk hash differs');
   assert.ok(bytes.subarray(start+i*900,start+Math.min((i+1)*900,total)).equals(wire.subarray(i*900,(i+1)*900)),'Stored chunk differs');
  }else pending.push(i);
 }
 if(count%8)assert.equal(bytes[85+Math.floor(count/8)]>>count%8,0,'Noncanonical bitmap tail');
 assert.equal(bytes.readUInt32LE(44),received,'Receipt count disagrees with bitmap');
 if(bytes[80]===2)assert.equal(pending.length,0,'Sealed incomplete buffer');
 return {received,pending,sealed:bytes[80]===2};
}
/** sendChunk must submit only the designated index/exact bytes to the pinned
 * account. Resolution/errors are advisory: the authenticated program-owned
 * bitmap and bytes decide whether a chunk is present. No proof checkpoint is
 * synthesized, and a transport completion never authorizes a spend. */
export async function uploadBuffer({wire,authority,program,readAccount,sendChunk,concurrency=8,maxAttempts=3,signal,onProgress=()=>{}}){
 assert.ok(Number.isInteger(concurrency)&&concurrency>=1&&concurrency<=16);
 assert.ok(Number.isInteger(maxAttempts)&&maxAttempts>=1&&maxAttempts<=5);
 const plan=bufferPlan(wire),attempts=new Map();let submitted=0;
 const inspect=async()=>inspectBuffer(await readAccount(),wire,authority,program,plan);
 let state=await inspect();onProgress({received:state.received,total:plan.count,submitted});
 while(state.pending.length){
  signal?.throwIfAborted();const batch=state.pending.slice(0,concurrency);
  for(const i of batch){const n=(attempts.get(i)??0)+1;assert.ok(n<=maxAttempts,`Chunk ${i} did not persist after bounded retries`);attempts.set(i,n);}
  const outcomes=await Promise.allSettled(batch.map(async i=>{submitted++;return sendChunk(i,wire.subarray(i*900,Math.min((i+1)*900,wire.length)));}));
  // Includes uncertain network outcomes that may already have committed.
  const next=await inspect();assert.ok(next.received>=state.received,'Buffer progress rolled back');
  const previouslyPending=new Set(state.pending);
  assert.ok(next.pending.every(i=>previouslyPending.has(i)),'A previously received chunk disappeared');
  const remaining=new Set(next.pending);
  for(let j=0;j<batch.length;j++){
   if(remaining.has(batch[j])&&outcomes[j].status==='fulfilled')throw Error(`Chunk ${batch[j]} reported success but is absent from the confirmed buffer`);
  }
  state=next;onProgress({received:state.received,total:plan.count,submitted});
 }
 return {received:state.received,total:plan.count,submitted,sealed:state.sealed,verifiedProof:false};
}
