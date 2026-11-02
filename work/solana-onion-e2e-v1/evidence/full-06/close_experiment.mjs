// EXPERIMENT (not part of any revision): run the two cleanup closes of the cleanup revision's policy against the REAL programs on the live full-06 validator, for the SEND request
// that already settled (its verifier receipt and proof buffer are still open because the task wiring did not clean). Uses the relay's own sponsor/transport seeds and the real
// SponsoredPublication journal (in memory), so the instructions are exactly the ones the relay would sign. Prints the simulation, the result on chain and the refund.
import fs from 'node:fs';
import path from 'node:path';
const WORK='<ZK9_ROOT>/work/';
const {SponsoredPublication}=await import(WORK+'solana-relay-cleanup-v1/relay-publication.mjs');
const {LocalNetwork}=await import(WORK+'solana-relay-performance-v1/candidate/local-network.mjs');
const {privateSigner,b58}=await import(WORK+'solana-chrome-wallet-v1/recovery/solana-transaction.mjs');
const [stateDir,configPath,requestId]=process.argv.slice(2);
const config=JSON.parse(fs.readFileSync(configPath));
const raw=new Uint8Array(fs.readFileSync(path.join(stateDir,'requests',requestId+'.request')));
const sponsor=await privateSigner(new Uint8Array(fs.readFileSync(path.join(stateDir,'sponsor.seed'))));
const transportSeed=new Uint8Array(fs.readFileSync(path.join(stateDir,'transport.seed')));
const endpoint=config.network.endpoint;
let n=0;
const rpc=async(method,params=[])=>{
  const r=await fetch(endpoint,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:++n,method,params})});
  const j=await r.json();if(j.error)throw Object.assign(new Error(method+': '+JSON.stringify(j.error)),{rpc:j.error});return j.result;
};
const programs=[config.program,config.buffer_program,config.proof_program,config.withdraw_program];
const observer=new LocalNetwork({profile:config.network});
const attested=await observer.attest(programs);
const store=new Map();
const repository={read:async id=>store.get(id)??null,compareAndSwap:async(id,old,next)=>{store.set(id,next);return next.revision;}};
const pub=await SponsoredPublication.open({raw,context:config.context,programData:attested.programs,sponsor,transportSeed,repository,verifyProof:async()=>true});
const transport=pub.configuration.transport;
console.log(JSON.stringify({request:requestId.slice(0,16),authority:transport.authority,receipt:transport.receipt,buffer:transport.source}));
const info=async key=>{const r=await rpc('getAccountInfo',[key,{encoding:'base64',commitment:'confirmed'}]);return r.value;};
const balance=async key=>(await rpc('getBalance',[key,{commitment:'confirmed'}])).value;
const before={receipt:await info(transport.receipt),buffer:await info(transport.source)};
console.log(JSON.stringify({before:{receipt_lamports:before.receipt?.lamports??null,receipt_owner:before.receipt?.owner??null,buffer_lamports:before.buffer?.lamports??null,buffer_owner:before.buffer?.owner??null}}));
for(const which of ['receipt','buffer']) {
  const key=which==='receipt'?transport.receipt:transport.source;
  if(!(await info(key))){console.log(JSON.stringify({which,skipped:'account already absent'}));continue;}
  const sponsorBefore=await balance(transport.authority);
  const ticket=await pub.prepare({type:'close',which});
  const block=(await rpc('getLatestBlockhash',[{commitment:'confirmed'}])).value;
  const probe=await pub.simulation(ticket,block.blockhash);
  const sim=await rpc('simulateTransaction',[probe.raw,{encoding:'base64',sigVerify:false,commitment:'confirmed'}]);
  console.log(JSON.stringify({which,simulation:{err:sim.value.err,unitsConsumed:sim.value.unitsConsumed,logs:(sim.value.logs??[]).slice(-6)}}));
  if(sim.value.err!==null){console.log(JSON.stringify({which,stopped:'simulation failed; nothing signed'}));process.exit(2);}
  const signed=await pub.sign(ticket,block.blockhash,block.lastValidBlockHeight);
  const sent=await rpc('sendTransaction',[signed.raw,{encoding:'base64',skipPreflight:false,preflightCommitment:'confirmed',maxRetries:0}]);
  let status=null;
  for(let i=0;i<60&&!status;i++){await new Promise(r=>setTimeout(r,1000));const s=await rpc('getSignatureStatuses',[[sent],{searchTransactionHistory:true}]);if(s.value[0]&&['confirmed','finalized'].includes(s.value[0].confirmationStatus))status=s.value[0];}
  const after=await info(key);const sponsorAfter=await balance(transport.authority);
  console.log(JSON.stringify({which,signature:sent,status:status&&{slot:status.slot,err:status.err},account_gone:after===null,sponsor_balance_delta_lamports:sponsorAfter-sponsorBefore,
    expected_refund_lamports:(before[which==='receipt'?'receipt':'buffer'])?.lamports}));
  await pub.resolve(sent,{outcome:status&&status.err===null?'confirmed':'failed',height:status?status.slot:0});
}
console.log('done');
