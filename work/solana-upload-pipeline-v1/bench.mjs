// Upload-strategy benchmark for the proof buffer program on an isolated loopback validator. All signing keys are public synthetic fixtures.
// DERIVED from ../solana-proof-buffer-v1/trial.mjs (frozen, left untouched; its sha256 is recorded in the result). Same validator flags, same compiled program,
// same transaction layout and chunk instruction. Only the upload phase differs: it compares how the chunks are submitted, with real archived payloads
// (the send and withdraw wires of privacy-live-02). It measures the transport of bytes only: no proof is verified, nothing here touches privacy, mainnet or the relay.
// usage: node bench.mjs LABEL   (a new label each time; existing evidence is never overwritten)   BENCH_SMOKE=1 shortens every case.
import {createHash,createPrivateKey,createPublicKey,sign} from 'node:crypto';
import {spawn} from 'node:child_process';
import {readFile,writeFile,mkdtemp,open,rm} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {join,dirname} from 'node:path';
import os from 'node:os';
import net from 'node:net';
import assert from 'node:assert/strict';
const W=dirname(fileURLToPath(import.meta.url)),WORK=dirname(W),BUF=join(WORK,'solana-proof-buffer-v1'),label=process.argv[2];
const SMOKE=process.env.BENCH_SMOKE==='1';
if(!/^[a-z0-9-]+$/.test(label??''))throw Error('A new evidence label is required');
const file=join(W,'evidence',label+'.json');try{await readFile(file);throw Error('Preserve evidence')}catch(e){if(e.code!=='ENOENT')throw e}
const sha=(...xs)=>createHash('sha256').update(Buffer.concat(xs)).digest();
const u32=n=>{const b=Buffer.alloc(4);b.writeUInt32LE(n);return b};
const u64=n=>{const b=Buffer.alloc(8);b.writeBigUInt64LE(BigInt(n));return b};
const alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58(b){let n=BigInt('0x'+b.toString('hex')),s='';while(n){s=alphabet[Number(n%58n)]+s;n/=58n}for(const x of b){if(x!==0)break;s='1'+s}return s}
function un58(s){let n=0n;for(const c of s){const i=alphabet.indexOf(c);assert.ok(i>=0);n=n*58n+BigInt(i)}let h=n.toString(16);if(h.length%2)h='0'+h;return Buffer.concat([Buffer.alloc(s.match(/^1*/)[0].length),n?Buffer.from(h,'hex'):Buffer.alloc(0)])}
function key(name){const seed=sha(Buffer.from('ZK9 public Solana buffer fixture/'+name));const secret=createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),seed]),format:'der',type:'pkcs8'});return {secret,pub:createPublicKey(secret).export({format:'der',type:'spki'}).subarray(-32)}}
const authority=key('authority');
const program=sha(Buffer.from('ZK9 local proof buffer program v1')),system=Buffer.alloc(32),budget=un58('ComputeBudget111111111111111111111111111111');
const CHUNK=900,HEADER=85;
const pause=ms=>new Promise(r=>setTimeout(r,ms));
async function freePort(){const s=net.createServer();await new Promise((r,j)=>{s.once('error',j);s.listen(0,'127.0.0.1',r)});const p=s.address().port;await new Promise(r=>s.close(r));return p}
const port=await freePort(),gossip=await freePort(),faucet=await freePort();
const endpoint='http://127.0.0.1:'+port;
const tmp=await mkdtemp('/private/tmp/zk9-solana-upload-');
await writeFile(join(tmp,'cli.yml'),'json_rpc_url: '+endpoint+'\nwebsocket_url: ""\nkeypair_path: '+join(tmp,'unused-keypair.json')+'\ncommitment: confirmed\n');
const log=await open(join(W,'evidence',label+'-validator.log'),'wx');
const command=process.env.SOLANA_TEST_VALIDATOR||'solana-test-validator';
const child=spawn(command,['--config',join(tmp,'cli.yml'),'--ledger',join(tmp,'ledger'),'--bind-address','127.0.0.1','--rpc-port',String(port),'--gossip-port',String(gossip),'--faucet-port',String(faucet),'--mint',b58(key('unused-genesis-mint').pub),'--bpf-program',b58(program),join(BUF,'bin/zk9_solana_proof_buffer_lab.so'),'--limit-ledger-size','10000','--quiet'],{stdio:['ignore',log.fd,log.fd],env:{PATH:'/usr/bin:/bin',TMPDIR:'/private/tmp',RUST_LOG:'error'}});
let ended=false,childCode,childSignal,forcedKill=false;
child.on('exit',(c,s)=>{ended=true;childCode=c;childSignal=s});
let rid=0,nonce=0,submitted=0,maxWire=0;
async function rpc(method,params=[]){
  const r=await fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:++rid,method,params}),signal:AbortSignal.timeout(30000)});
  assert.equal(r.status,200);const v=await r.json();if(v.error)throw Error(method+': '+JSON.stringify(v.error));return v.result;
}
function vec(n){const a=[];do{let x=n&127;n>>>=7;if(n)x|=128;a.push(x)}while(n);return Buffer.from(a)}
function tx(instructions,signers,hash){
  const entries=new Map();function add(pub,signer,writable){const k=b58(pub),old=entries.get(k);entries.set(k,{pub,signer:!!signer||old?.signer,writable:!!writable||old?.writable})}
  add(authority.pub,true,true);
  const ixs=[{program:budget,accounts:[],data:Buffer.concat([Buffer.from([2]),u32(1000000+(++nonce))])},...instructions];
  for(const ix of ixs){for(const a of ix.accounts)add(a.pub,a.signer,a.writable);add(ix.program,false,false)}
  const group=x=>x.signer?(x.writable?0:1):(x.writable?2:3);const keys=[...entries.values()].sort((a,b)=>group(a)-group(b));
  const index=pub=>keys.findIndex(k=>k.pub.equals(pub));const signing=keys.filter(k=>k.signer);
  const header=Buffer.from([signing.length,signing.filter(k=>!k.writable).length,keys.filter(k=>!k.signer&&!k.writable).length]);
  const body=Buffer.concat([header,vec(keys.length),...keys.map(k=>k.pub),un58(hash),vec(ixs.length),...ixs.map(ix=>Buffer.concat([Buffer.from([index(ix.program)]),vec(ix.accounts.length),Buffer.from(ix.accounts.map(a=>index(a.pub))),vec(ix.data.length),ix.data]))]);
  const sigs=signing.map(k=>{const pair=signers.find(s=>s.pub.equals(k.pub));assert.ok(pair);return sign(null,body,pair.secret)});
  const raw=Buffer.concat([vec(sigs.length),...sigs,body]);assert.ok(raw.length<=1232);maxWire=Math.max(maxWire,raw.length);return raw.toString('base64')
}
const meta=(pub,signer=false,writable=false)=>({pub,signer,writable});
function instruction(data,{target,bufferSigner=false,authWritable=false}){return {program,accounts:[meta(target.pub,bufferSigner,true),meta(authority.pub,true,authWritable)],data}}
async function hash(){return (await rpc('getLatestBlockhash',[{commitment:'confirmed'}])).value.blockhash}
async function statuses(sigs,pollMs=120){const deadline=Date.now()+90000;while(Date.now()<deadline){const values=(await rpc('getSignatureStatuses',[sigs])).value;if(values.every(x=>x&&['confirmed','finalized'].includes(x.confirmationStatus))){for(const x of values)assert.equal(x.err,null,JSON.stringify(x.err));return}if(ended)throw Error('Validator stopped');await pause(pollMs)}throw Error('Local transaction confirmation timed out')}
async function send(ixs,signers,blockhash,{maxRetries=4}={}){const raw=tx(ixs,signers,blockhash??await hash());const sig=await rpc('sendTransaction',[raw,{encoding:'base64',skipPreflight:false,preflightCommitment:'confirmed',maxRetries}]);submitted++;return sig}
async function commit(ixs,signers=[authority]){const sig=await send(ixs,signers);await statuses([sig]);return sig}
async function account(pair){const value=(await rpc('getAccountInfo',[b58(pair.pub),{encoding:'base64',commitment:'confirmed'}])).value;return value?{...value,bytes:Buffer.from(value.data[0],'base64')}:null}
const median=v=>{const s=[...v].sort((a,b)=>a-b);return s[Math.floor(s.length/2)]};
// Real archived payloads (read only). The buffer program stores bytes; it never looks at what they mean.
const CAP=join(WORK,'solana-multiwallet-privacy-v1/evidence/privacy-live-02/public-capsule');
const payloads={send:await readFile(join(CAP,'2e0996342aed43b1.send.wire')),withdraw:await readFile(join(CAP,'3d7c8907982a26eb.withdraw.wire'))};
const SMALL=SMOKE?12:150,BIG=SMOKE?200:'all';
const plan=[
  {name:'confirm-each',mode:'confirm-each',chunks:SMALL,pollMs:50,payload:'send'},
  {name:'relay-like',mode:'relay-like',chunks:SMALL,pollMs:150,reads:2,payload:'send'},
  {name:'window-8',mode:'window',W:8,chunks:BIG,payload:'send'},
  {name:'window-32',mode:'window',W:32,chunks:BIG,payload:'send',readSamples:5},
  {name:'window-128',mode:'window',W:128,chunks:BIG,payload:'send'},
  {name:'rolling-64',mode:'rolling',W:64,chunks:BIG,payload:'send'},
  {name:'rolling-64-withdraw-size',mode:'rolling',W:64,chunks:BIG,payload:'withdraw'},
];
async function runCase(spec){
  const payload=payloads[spec.payload],count=Math.ceil(payload.length/CHUNK),hashStart=HEADER+Math.ceil(count/8),start=hashStart+32*count,space=start+payload.length;
  const leaves=Array.from({length:count},(_,i)=>sha(Buffer.from('ZK9/SOLANA/BUFFER/LEAF/v1\0'),u32(payload.length),u32(i),payload.subarray(i*CHUNK,(i+1)*CHUNK)));
  const root=sha(Buffer.from('ZK9/SOLANA/BUFFER/ROOT/v1\0'),u32(payload.length),Buffer.concat(leaves));
  const target=key('buffer-'+label+'-'+spec.name);
  const rent=Number(await rpc('getMinimumBalanceForRentExemption',[space]));
  const create={program:system,accounts:[meta(authority.pub,true,true),meta(target.pub,true,true)],data:Buffer.concat([u32(0),u64(rent),u64(space),program])};
  const init=Buffer.concat([Buffer.from([0]),u32(payload.length),root]);
  await commit([create,instruction(init,{target,bufferSigner:true})],[authority,target]);
  const total=spec.chunks==='all'?count:Math.min(spec.chunks,count),chunk=i=>Buffer.concat([Buffer.from([1]),u32(i),payload.subarray(i*CHUNK,(i+1)*CHUNK)]);
  const before=submitted,begin=performance.now(),idx=Array.from({length:total},(_,i)=>i);
  if(spec.mode==='confirm-each'){
    // One transaction at a time, confirmed before the next, polled every pollMs: the floor of strictly sequential confirmation.
    for(const i of idx){const sig=await send([instruction(chunk(i),{target})],[authority]);await statuses([sig],spec.pollMs)}
  }else if(spec.mode==='relay-like'){
    // The cadence of the relay's publication sender: blockhash, unsigned probe simulation, send with preflight, then poll after a pause, plus full reads of the buffer account.
    for(const i of idx){
      const block=await hash();const raw=tx([instruction(chunk(i),{target})],[authority],block);
      const sim=await rpc('simulateTransaction',[raw,{encoding:'base64',sigVerify:false,commitment:'confirmed'}]);assert.equal(sim.value.err,null);
      const sig=await rpc('sendTransaction',[raw,{encoding:'base64',skipPreflight:false,preflightCommitment:'confirmed',maxRetries:0}]);submitted++;
      for(;;){await pause(spec.pollMs);const s=(await rpc('getSignatureStatuses',[[sig],{searchTransactionHistory:true}])).value[0];if(s&&['confirmed','finalized'].includes(s.confirmationStatus)){assert.equal(s.err,null);break}}
      for(let r=0;r<spec.reads;r++)await account(target);
    }
  }else if(spec.mode==='window'){
    // The sealed-trial strategy: send W transactions back to back on one blockhash, then wait for the whole batch.
    for(let offset=0;offset<total;offset+=spec.W){
      const block=await hash(),ids=[];
      for(let i=offset;i<Math.min(offset+spec.W,total);i++)ids.push(await send([instruction(chunk(i),{target})],[authority],block));
      await statuses(ids);
    }
  }else if(spec.mode==='rolling'){
    // W workers, each sending one chunk and waiting for its confirmation before taking the next index; no batch barrier.
    let cursor=0,block=await hash(),blockAt=Date.now();
    const worker=async()=>{for(;;){const k=cursor++;if(k>=total)return;if(Date.now()-blockAt>15000){block=await hash();blockAt=Date.now()}const sig=await send([instruction(chunk(k),{target})],[authority],block);await statuses([sig],200)}};
    await Promise.all(Array.from({length:spec.W},worker));
  }else throw Error('unknown mode');
  const wall=(performance.now()-begin)/1000,sent=submitted-before;
  const reads=[];if(spec.readSamples){for(let r=0;r<spec.readSamples;r++){const t=performance.now();const a=await account(target);reads.push({ms:Math.round(performance.now()-t),account_bytes:a.bytes.length})}}
  const saved=await account(target);
  assert.equal(saved.bytes.readUInt32LE(44),total,'stored chunk count');
  assert.ok(saved.bytes.subarray(start,start+Math.min(total*CHUNK,payload.length)).equals(payload.subarray(0,Math.min(total*CHUNK,payload.length))),'stored bytes equal the archived payload');
  await commit([instruction(Buffer.from([3]),{target,authWritable:true})]);assert.equal(await account(target),null);
  return {name:spec.name,mode:spec.mode,payload:spec.payload,payload_bytes:payload.length,payload_sha256:sha(payload).toString('hex'),window:spec.W??1,poll_ms:spec.pollMs??null,account_reads_per_chunk:spec.reads??0,
    chunks_total_in_payload:count,chunks_written:total,transactions_submitted:sent,wall_seconds:Number(wall.toFixed(3)),seconds_per_chunk:Number((wall/total).toFixed(4)),
    projected_seconds_for_the_whole_payload:Number((wall/total*count).toFixed(1)),stored_bytes_equal_payload:true,account_space_bytes:space,rent_lamports_returned_on_close:rent,
    full_account_reads:reads.length?{samples:reads,median_ms:median(reads.map(r=>r.ms))}:undefined};
}
let result={status:'FAIL_UPLOAD_PIPELINE_BENCH',label,smoke:SMOKE,cases:[]};
try{
  for(let i=0;i<180;i++){try{if(await rpc('getHealth')==='ok')break}catch{}if(ended)throw Error('Validator startup failed');if(i===179)throw Error('Validator startup timed out');await pause(250)}
  const version=await rpc('getVersion');assert.equal(version['solana-core'],'3.1.10');
  for(let n=0;n<2;n++){const airdrop=await rpc('requestAirdrop',[b58(authority.pub),100000000000]);await statuses([airdrop])}
  result.validator_version=version['solana-core'];
  for(const spec of plan){const r=await runCase(spec);result.cases.push(r);console.log('PASS',r.name,r.chunks_written+' chunks',r.wall_seconds+' s',r.seconds_per_chunk+' s/chunk');await pause(2000)}
  result.status='PASS_UPLOAD_PIPELINE_BENCH';
}catch(e){result.error=String(e.stack);console.error('FAIL',e)}
finally{
  if(!ended)child.kill('SIGINT');for(let i=0;i<100&&!ended;i++)await pause(100);if(!ended){forcedKill=true;child.kill('SIGKILL');for(let i=0;i<30&&!ended;i++)await pause(100)}await log.close();await rm(tmp,{recursive:true,force:true});
}
Object.assign(result,{
  inputs:{bench_sha256:sha(await readFile(fileURLToPath(import.meta.url))).toString('hex'),derived_from_trial_sha256:sha(await readFile(join(BUF,'trial.mjs'))).toString('hex'),
    program_sha256:sha(await readFile(join(BUF,'bin/zk9_solana_proof_buffer_lab.so'))).toString('hex'),node:process.version,wires:{send:'2e0996342aed43b1.send.wire',withdraw:'3d7c8907982a26eb.withdraw.wire'}},
  machine:{platform:os.platform(),release:os.release(),arch:os.arch(),cpus:os.cpus().length,cpu_model:os.cpus()[0]?.model},
  max_transaction_bytes:maxWire,validator_exit_code:childCode,validator_exit_signal:childSignal,validator_forced_kill:forcedKill,completed_at:new Date().toISOString(),
  scope:'Byte transport to the proof buffer program on an isolated loopback validator with real archived payloads. Local synthetic only: no proof is verified, no relay, no mainnet, no privacy claim. Timings are single local observations on this Mac, not a statistical or mainnet result.'});
await writeFile(file,JSON.stringify(result,null,2)+'\n',{flag:'wx'});
console.log(result.status,label);process.exit(result.status.startsWith('PASS')?0:1);
