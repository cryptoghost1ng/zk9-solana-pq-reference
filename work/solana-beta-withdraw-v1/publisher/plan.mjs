// Client scheduler for immutable, already-qualified verifier programs.
// It never manufactures checkpoints or substitutes for cryptographic verification.
// RPC/program-code trust is supplied by the pinned local network adapter.
import assert from 'node:assert/strict';
import {sha,u32,b58} from '../runtime-helpers.mjs';
import {bufferPlan} from '../upload-batch.mjs';

export const PROFILES=Object.freeze({
 send:Object.freeze({magic:'ZK9PRF07',prefix:'ZK9PFX3\0',wire:'ZK9PQS3\0',version:3,header:440,space:328732,airState:88188,instructions:332613,programHex:sha(Buffer.from('ZK9 Solana beta context proof verifier v1')).toString('hex')}),
 withdraw:Object.freeze({magic:'ZK9PRFW2',prefix:'ZK9PFXW2',wire:'ZK9PQW2\0',version:2,header:481,space:421008,airState:88272,instructions:362705,programHex:sha(Buffer.from('ZK9 Solana beta withdrawal verifier v1')).toString('hex')}),
});
export function profile(kind){const p=PROFILES[kind];assert.ok(p,'Unknown proof kind');return p;}
export function checkWire(wire,kind){
 const p=profile(kind),start=p.header+3464;
 assert.ok(Buffer.isBuffer(wire)&&wire.length>start&&wire.length<=start+4*1024*1024,'Proof envelope size');
 assert.equal(wire.subarray(0,8).toString(),p.wire);assert.equal(wire.readUInt32LE(8),p.version);
 assert.equal(wire.readUInt32LE(p.header-4),wire.length-start);
 for(const at of [12,44,76])assert.ok(!wire.subarray(at,at+32).equals(Buffer.alloc(32)),'Empty proof context');
 assert.equal(wire.readBigUInt64LE(108),1n,'Unsupported beta fee');
 if(kind==='withdraw'){assert.equal(wire[116],1);assert.ok(wire.readBigUInt64LE(117)>0n);}
 return p;
}
const zero=b=>b.every(v=>v===0);
function marker(bytes,at,end,magic){
 const part=bytes.subarray(at,end);if(zero(part))return false;
 assert.equal(part.subarray(0,8).toString(),magic,'Unknown receipt checkpoint');return true;
}
export function readProgress(account,{source,authority,program,wire,kind}){
 const p=checkWire(wire,kind);
 assert.ok(account&&account.executable===false&&account.owner===b58(program),'Foreign proof receipt');
 assert.equal(program.toString('hex'),p.programHex,'Unsupported proof program');
 assert.equal(account.data?.[1],'base64');const bytes=Buffer.from(account.data[0],'base64');
 assert.equal(bytes.length,p.space);assert.equal(bytes.subarray(0,8).toString(),p.magic);
 assert.ok(bytes.subarray(8,40).equals(authority)&&bytes.subarray(40,72).equals(source),'Wrong receipt binding');
 assert.equal(bytes.readUInt32LE(104),wire.length);
 assert.ok(bytes.subarray(72,104).equals(bufferPlan(wire).root),'Receipt belongs to another proof');
 assert.ok(zero(bytes.subarray(124,128))&&zero(bytes.subarray(19000,19004))&&zero(bytes.subarray(86920,86924)),'Reserved receipt fields');
 const n=at=>bytes.readUInt32LE(at);
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
const ext=(op,seq,work)=>Buffer.concat([Buffer.from([op]),u32(seq),u32(work)]);
function step(name,op,seq,max,min=0){
 return {name,op,sequence:seq,maxWork:max,minWork:min,build:work=>{
  assert.ok(Number.isInteger(work)&&work>=min&&work<=max);
  return seq===null?Buffer.from([op]):ext(op,seq,work);
 }};
}
export function nextStep(s){
 if(!s.format)return step('format',1,s.sequences[0],16384,32);
 if(!s.prefix)return step('prefix',3,null,0);
 if(!s.openingsDone)return step('openings',4,s.sequences[1],6144,64);
 if(!s.fri)return step('fri',5,null,0);
 if(!s.views)return step('input-init',6,null,0);
 if(s.batch<3){const x=step('input-mmcs',7,s.sequences[2],4,1);x.build=w=>{assert.ok(Number.isInteger(w)&&w>=1&&w<=4);return Buffer.concat([ext(7,s.sequences[2],1024*w),u32(8*w)]);};return x;}
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
