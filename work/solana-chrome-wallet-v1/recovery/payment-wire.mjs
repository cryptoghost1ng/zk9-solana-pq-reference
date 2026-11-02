// Public wire parsing and history matching, NOT proof verification. Only private
// custody calls these helpers after a verified proof or a validated history.
import {requireState,integer} from './checkpoint.mjs';
export const MAX_WIRE=4*1024*1024+3945;
export const hex=bytes=>Array.from(bytes,x=>x.toString(16).padStart(2,'0')).join('');
const alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
export function un58(text,size) {
 requireState(typeof text==='string'&&text.length>0&&text.length<=90,'Invalid public identifier.');
 let n=0n;for(const c of text){const d=alphabet.indexOf(c);requireState(d>=0);n=n*58n+BigInt(d);}
 const bytes=[];while(n>0n){bytes.unshift(Number(n&255n));n>>=8n;}
 for(const c of text){if(c!=='1')break;bytes.unshift(0);}
 requireState(bytes.length===size,'Invalid public identifier size.');return Uint8Array.from(bytes);
}
export function toBase64(bytes) {
 let binary='';for(let i=0;i<bytes.length;i+=16384)binary+=String.fromCharCode(...bytes.subarray(i,i+16384));
 return btoa(binary);
}
export function fromBase64(text,max=MAX_WIRE) {
 requireState(typeof text==='string'&&text.length<=Math.ceil(max/3)*4);
 const bytes=Uint8Array.from(atob(text),x=>x.charCodeAt(0));
 requireState(bytes.length<=max&&toBase64(bytes)===text,'Noncanonical encoded wire.');return bytes;
}
export const digest=async bytes=>hex(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)));
export function parsePaymentWire(wire,kind) {
 requireState(wire instanceof Uint8Array&&wire.length<=MAX_WIRE&&['send','withdraw'].includes(kind));
 const withdrawal=kind==='withdraw',header=withdrawal?481:440,start=header+3464;
 requireState(wire.length>start,'Truncated payment proof.');
 const view=new DataView(wire.buffer,wire.byteOffset,wire.byteLength);
 requireState(new TextDecoder().decode(wire.subarray(0,8))===(withdrawal?'ZK9PQW2\0':'ZK9PQS3\0'));
 requireState(view.getUint32(8,true)===(withdrawal?2:3)&&view.getUint32(header-4,true)===wire.length-start);
 const rootAt=withdrawal?157:116,nfAt=rootAt+64,cmAt=nfAt+128;
 const nfs=[0,1].map(i=>hex(wire.subarray(nfAt+64*i,nfAt+64*(i+1))));
 const outputs=[0,1].map(i=>hex(wire.subarray(cmAt+64*i,cmAt+64*(i+1))));
 requireState(nfs[0]!==nfs[1]&&outputs[0]!==outputs[1]);
 return {context:hex(wire.subarray(12,108)),fee:view.getBigUint64(108,true).toString(),root:hex(wire.subarray(rootAt,rootAt+64)),nfs,outputs,
  ...(withdrawal?{mode:wire[116],amount:view.getBigUint64(117,true).toString(),recipient:hex(wire.subarray(125,157))}:{})};
}
export function checkProofBinding(proof,operation,context,validateTarget) {
 requireState(proof.context===context&&proof.fee===operation.fee&&proof.root===operation.root,'Proof anchor or context differs.');
 requireState(operation.inputs.every(n=>proof.nfs.includes(n.nf)),'Proof spends different inputs.');
 if(operation.kind==='withdraw') {
  const target=validateTarget({context,kind:'withdraw',target:operation.target});
  requireState(proof.mode===1&&proof.amount===operation.amount&&proof.recipient===target.recipient,'Withdrawal differs from review.');
 }
}
export function checkedTransport(value) {
 requireState(value&&Object.keys(value).sort().join(',')==='authority,receipt,source');
 for(const key of Object.values(value))un58(key,32);
 requireState(new Set(Object.values(value)).size===3,'Transport identities overlap.');return structuredClone(value);
}
export function historyEvents(snapshot,response) {
 requireState(response?.context?.slot===snapshot.slot&&snapshot.all_pool_records_checked===true);
 const pool=hex(un58(snapshot.pool,32)),events=new Map();
 for(const item of response.value) {
  const account=item.account;requireState(account.owner===snapshot.program&&account.executable===false&&account.data[1]==='base64');
  const bytes=fromBase64(account.data[0],64*1024*1024);
  if(bytes.length>=40&&hex(bytes.subarray(8,40))===pool&&new TextDecoder().decode(bytes.subarray(0,8))==='ZK9NULL1') {
   requireState(bytes.length===112);const nf=hex(bytes.subarray(40,104));
   const at=Number(new DataView(bytes.buffer).getBigUint64(104,true));integer(at);requireState(!events.has(nf));events.set(nf,at);
  }
 }
 requireState(events.size===snapshot.nullifiers.length&&snapshot.nullifiers.every(n=>events.has(n)));
 return events;
}
export const TERMINAL=new Set(['settled','conflicted','cancelled']);
export function reconcileOperation(op,snapshot,events) {
 if(TERMINAL.has(op.state))return op;
 const proof=op.proof?.summary,watched=proof?.nfs??op.inputs.map(i=>i.nf);
 if(!watched.some(n=>events.has(n)))return op;
 let matched=false;
 if(proof&&watched.every(n=>events.has(n))&&new Set(watched.map(n=>events.get(n))).size===1) {
  const at=events.get(watched[0]);const withdrawals=snapshot.withdrawals.filter(w=>w.first_leaf===at);
  matched=at%2===0&&at<snapshot.notes.length-1&&proof.outputs.every((cm,i)=>snapshot.notes[at+i].commitment===cm);
  if(op.kind==='withdraw')matched=matched&&withdrawals.length===1&&withdrawals[0].amount_units===op.amount
    &&withdrawals[0].fee_units===op.fee&&withdrawals[0].recipient===op.target&&(!op.transport||withdrawals[0].session===op.transport.receipt);
  else matched=matched&&withdrawals.length===0;
 }
 // Only authenticated history matching can finish an uncertain publication.
 // Terminal rows retain their binding/hash, not the multi-megabyte proof body.
 return {...op,state:matched?'settled':'conflicted',proof:op.proof?{...op.proof,wire:null}:null};
}
