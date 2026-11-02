// Browser port of the native immutable proof-buffer format. A sealed buffer
// establishes byte availability only; it never establishes proof validity.
import {requireState as require} from './checkpoint.mjs';
import {b58,concat,u32,sha256,equalBytes as equal,fromBase64} from './solana-transaction.mjs';
const text=s=>new TextEncoder().encode(s);
export async function bufferPlan(wire) {
  require(wire instanceof Uint8Array&&wire.length>0&&wire.length<=5*1024*1024);
  // Snapshot before awaiting hashes: callers cannot change bytes mid-plan.
  const bytes=wire.slice(),total=bytes.length,count=Math.ceil(total/900);
  const hashStart=85+Math.ceil(count/8),start=hashStart+32*count,leaves=[];
  // Bounded batches avoid thousands of concurrent WebCrypto promises.
  for(let at=0;at<count;at+=32) {
    const indices=Array.from({length:Math.min(32,count-at)},(_,i)=>at+i);
    leaves.push(...await Promise.all(indices.map(i=>sha256(concat(text('ZK9/SOLANA/BUFFER/LEAF/v1\0'),u32(total),u32(i),bytes.subarray(i*900,(i+1)*900))))));
  }
  const root=await sha256(concat(text('ZK9/SOLANA/BUFFER/ROOT/v1\0'),u32(total),...leaves));
  return {total,count,hashStart,start,leaves,root};
}
// plan must have been derived privately from this wire, not supplied by a page.
export function inspectBuffer(account,wire,authority,program,plan) {
  require(account?.executable===false&&account.owner===b58(program),'Wrong proof buffer owner.');
  require(account.data?.[1]==='base64');
  const {count,total,start,hashStart,leaves,root}=plan;
  require(total===wire.length&&count===Math.ceil(total/900)&&leaves.length===count);
  const bytes=fromBase64(account.data[0],start+total),view=new DataView(bytes.buffer);
  require(bytes.length===start+total&&equal(bytes.subarray(0,8),text('ZK9BUF1\0')));
  require(equal(bytes.subarray(8,40),authority)&&view.getUint32(40,true)===total);
  require(equal(bytes.subarray(48,80),root)&&bytes.subarray(81,85).every(x=>x===0));
  require(bytes[80]===1||bytes[80]===2,'Unknown proof buffer state.');
  let received=0;const pending=[];
  for(let i=0;i<count;i++) {
    if(bytes[85+(i>>3)]&(1<<(i%8))) {
      received++;
      require(equal(bytes.subarray(hashStart+32*i,hashStart+32*(i+1)),leaves[i]),'Stored chunk hash differs.');
      require(equal(bytes.subarray(start+i*900,start+Math.min((i+1)*900,total)),wire.subarray(i*900,(i+1)*900)),'Stored chunk differs.');
    }else pending.push(i);
  }
  if(count%8)require((bytes[85+Math.floor(count/8)]>>(count%8))===0,'Noncanonical bitmap tail.');
  require(view.getUint32(44,true)===received,'Receipt count disagrees with bitmap.');
  if(bytes[80]===2)require(pending.length===0,'Sealed incomplete buffer.');
  return {received,pending,sealed:bytes[80]===2};
}
