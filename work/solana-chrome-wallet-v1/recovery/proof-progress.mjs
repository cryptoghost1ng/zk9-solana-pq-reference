// Client scheduler for immutable, already-qualified verifier programs.
// It never manufactures checkpoints or substitutes for cryptographic verification.
// RPC/program-code trust is supplied by the pinned local network adapter.
import {requireState} from './checkpoint.mjs';
import {u32,b58,sha256,concat,equalBytes,hex,fromBase64} from './solana-transaction.mjs';
import {bufferPlan} from './proof-buffer.mjs';
const assert={ok:requireState,equal:(a,b,message)=>requireState(a===b,message)};
const text=s=>new TextEncoder().encode(s);
const string=b=>new TextDecoder('utf-8',{fatal:true}).decode(b);
const num=(b,at)=>new DataView(b.buffer,b.byteOffset,b.byteLength).getUint32(at,true);
const big=(b,at)=>new DataView(b.buffer,b.byteOffset,b.byteLength).getBigUint64(at,true);
const hash=async s=>hex(await sha256(text(s)));

export const PROFILES=Object.freeze({
 send:Object.freeze({magic:'ZK9PRF07',prefix:'ZK9PFX3\0',wire:'ZK9PQS3\0',version:3,header:440,space:328732,airState:88188,instructions:332613,programHex:await hash('ZK9 Solana beta context proof verifier v1')}),
 withdraw:Object.freeze({magic:'ZK9PRFW2',prefix:'ZK9PFXW2',wire:'ZK9PQW2\0',version:2,header:481,space:421008,airState:88272,instructions:362705,programHex:await hash('ZK9 Solana beta withdrawal verifier v1')}),
});
export function profile(kind){const p=PROFILES[kind];assert.ok(p,'Unknown proof kind');return p;}
export function checkWire(wire,kind){
 const p=profile(kind),start=p.header+3464;
 assert.ok(wire instanceof Uint8Array&&wire.length>start&&wire.length<=start+4*1024*1024,'Proof envelope size');
 assert.equal(string(wire.subarray(0,8)),p.wire);assert.equal(num(wire,8),p.version);
 assert.equal(num(wire,p.header-4),wire.length-start);
 for(const at of [12,44,76])assert.ok(!equalBytes(wire.subarray(at,at+32),new Uint8Array(32)),'Empty proof context');
 assert.equal(big(wire,108),1n,'Unsupported beta fee');
 if(kind==='withdraw'){assert.equal(wire[116],1);assert.ok(big(wire,117)>0n);}
 return p;
}
const zero=b=>b.every(v=>v===0);
function marker(bytes,at,end,magic){
 const part=bytes.subarray(at,end);if(zero(part))return false;
 assert.equal(string(part.subarray(0,8)),magic,'Unknown receipt checkpoint');return true;
}
export async function readProgress(account,{source,authority,program,wire,kind},plan){
 const p=checkWire(wire,kind);
 assert.ok(account&&account.executable===false&&account.owner===b58(program),'Foreign proof receipt');
 assert.equal(hex(program),p.programHex,'Unsupported proof program');
 assert.equal(account.data?.[1],'base64');const bytes=fromBase64(account.data[0],p.space);
 assert.equal(bytes.length,p.space);assert.equal(string(bytes.subarray(0,8)),p.magic);
 assert.ok(equalBytes(bytes.subarray(8,40),authority)&&equalBytes(bytes.subarray(40,72),source),'Wrong receipt binding');
 assert.equal(num(bytes,104),wire.length);
 assert.ok(equalBytes(bytes.subarray(72,104),(plan??await bufferPlan(wire)).root),'Receipt belongs to another proof');
 assert.ok(zero(bytes.subarray(124,128))&&zero(bytes.subarray(19000,19004))&&zero(bytes.subarray(86920,86924)),'Reserved receipt fields');
 const n=at=>num(bytes,at);
 const format=n(172);assert.ok(format===0||format===1,'Unknown format phase');
 const prefix=marker(bytes,768,1056,p.prefix);
 const opening=marker(bytes,1056,1408,'ZK9PCS01');assert.ok(bytes[1068]<=1);
 const openingsDone=opening&&bytes[1068]===1;
 const fri=marker(bytes,1472,2240,'ZK9FRI01');
 const views=marker(bytes,2240,4268,'ZK9MVW01');
 assert.ok(!prefix||format===1);assert.ok(!opening||prefix);assert.ok(!fri||openingsDone);assert.ok(!views||fri);
 const batch=n(120),phase=n(18992),round=n(18996),airPhase=n(86912),quotient=n(86916);
 assert.ok(batch<=3&&phase<=6&&round<=13&&airPhase<=4&&quotient<=16,'Unknown verification stage');
 assert.ok(batch===0||views);assert.ok(phase===0||batch===3);
 assert.ok(phase>=4||round===0);assert.ok((phase===6)===(round===13));
 assert.ok(airPhase===0||phase===6);assert.ok(airPhase===0?quotient===0:airPhase===1?quotient<16:quotient===16);
 if(airPhase===4)assert.equal(n(p.airState+8),p.instructions,'Incomplete AIR cursor');
 return {format,prefix,opening,openingsDone,fri,views,batch,phase,round,airPhase,quotient,
  sequences:[n(108),n(112),n(116),n(18988),n(86908)],reductionPhase:bytes[19012],bytes};
}
const ext=(op,seq,work)=>concat(Uint8Array.of(op),u32(seq),u32(work));
function step(name,op,seq,max,min=0){
 return {name,op,sequence:seq,maxWork:max,minWork:min,build:work=>{
  assert.ok(Number.isInteger(work)&&work>=min&&work<=max);
  return seq===null?Uint8Array.of(op):ext(op,seq,work);
 }};
}
export function nextStep(s){
 if(!s.format)return step('format',1,s.sequences[0],16384,32);
 if(!s.prefix)return step('prefix',3,null,0);
 if(!s.openingsDone)return step('openings',4,s.sequences[1],6144,64);
 if(!s.fri)return step('fri',5,null,0);
 if(!s.views)return step('input-init',6,null,0);
 if(s.batch<3){const x=step('input-mmcs',7,s.sequences[2],4,1);x.build=w=>{assert.ok(Number.isInteger(w)&&w>=1&&w<=4);return concat(ext(7,s.sequences[2],1024*w),u32(8*w));};return x;}
 const seq=s.sequences[3];
 if(s.phase===0)return step('reduction-init',8,seq,0);
 if(s.phase===1)return step('reduction',9,seq,s.reductionPhase===1?256:s.reductionPhase===2?48:16,1);
 if(s.phase===2)return step('fold-init',10,seq,0);
 if(s.phase===3)return step('fold',11,seq,16,1);
 if(s.phase===4)return step('round-init-'+s.round,12,seq,0);
 if(s.phase===5)return step('round-'+s.round,13,seq,128,1);
 const air=s.sequences[4];
 if(s.airPhase===0)return step('air-context',14,air,0);
 if(s.airPhase===1)return step('quotient-'+s.quotient,15,air,Math.min(2,16-s.quotient),1);
 if(s.airPhase===2)return step('air-init',16,air,0);
 if(s.airPhase===3)return step('air',17,air,1024,64);
 assert.equal(s.airPhase,4);return null;
}
export function assertForward(before,after){
 for(let i=0;i<before.sequences.length;i++)assert.ok(after.sequences[i]>=before.sequences[i],'Verification sequence rolled back');
 for(const k of ['format','prefix','opening','openingsDone','fri','views','batch','airPhase','quotient','round'])assert.ok(Number(after[k])>=Number(before[k]),'Verification progress rolled back');
 // Extension phase alternates 4 -> 5 -> 4 as each FRI round finishes.
 assert.ok(after.round>before.round||after.phase>=before.phase,'Verification stage rolled back');
}
