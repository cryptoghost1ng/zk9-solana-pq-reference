// All signing keys below are public synthetic fixtures. Loopback-only local validator.
import {createHash,createPrivateKey,createPublicKey,sign} from 'node:crypto';
import {spawn} from 'node:child_process';
import {readFile,writeFile,mkdir,mkdtemp,open,rm} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {join,dirname} from 'node:path';
import net from 'node:net';
import assert from 'node:assert/strict';
const W=dirname(fileURLToPath(import.meta.url)),label=process.argv[2];
if(!/^[a-z0-9-]+$/.test(label??''))throw Error('A new evidence label is required');
const file=join(W,'evidence',label+'.json');try{await readFile(file);throw Error('Preserve evidence')}catch(e){if(e.code!=='ENOENT')throw e}
const sha=(...xs)=>createHash('sha256').update(Buffer.concat(xs)).digest();
const u32=n=>{const b=Buffer.alloc(4);b.writeUInt32LE(n);return b};
const u64=n=>{const b=Buffer.alloc(8);b.writeBigUInt64LE(BigInt(n));return b};
const alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58(b){let n=BigInt('0x'+b.toString('hex')),s='';while(n){s=alphabet[Number(n%58n)]+s;n/=58n}for(const x of b){if(x!==0)break;s='1'+s}return s}
function un58(s){let n=0n;for(const c of s){const i=alphabet.indexOf(c);assert.ok(i>=0);n=n*58n+BigInt(i)}let h=n.toString(16);if(h.length%2)h='0'+h;return Buffer.concat([Buffer.alloc(s.match(/^1*/)[0].length),n?Buffer.from(h,'hex'):Buffer.alloc(0)])}
function key(name){const seed=sha(Buffer.from('ZK9 public Solana buffer fixture/'+name));const secret=createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),seed]),format:'der',type:'pkcs8'});return {secret,pub:createPublicKey(secret).export({format:'der',type:'spki'}).subarray(-32)}}
const authority=key('authority'),buffer=key('buffer-'+label),attacker=key('attacker');
const program=sha(Buffer.from('ZK9 local proof buffer program v1')),system=Buffer.alloc(32),budget=un58('ComputeBudget111111111111111111111111111111');
assert.equal(b58(un58(b58(authority.pub))),b58(authority.pub));assert.equal(budget.length,32);
const CHUNK=900,HEADER=85;
const pause=ms=>new Promise(r=>setTimeout(r,ms));
async function freePort(){const s=net.createServer();await new Promise((r,j)=>{s.once('error',j);s.listen(0,'127.0.0.1',r)});const p=s.address().port;await new Promise(r=>s.close(r));return p}
const port=await freePort(),gossip=await freePort(),faucet=await freePort();
const endpoint='http://127.0.0.1:'+port;
const tmp=await mkdtemp('/private/tmp/zk9-solana-buffer-');
await writeFile(join(tmp,'cli.yml'),'json_rpc_url: '+endpoint+'\nwebsocket_url: ""\nkeypair_path: '+join(tmp,'unused-keypair.json')+'\ncommitment: confirmed\n');
const log=await open(join(W,'evidence',label+'-validator.log'),'wx');
const command=process.env.SOLANA_TEST_VALIDATOR||'solana-test-validator';
const child=spawn(command,['--config',join(tmp,'cli.yml'),'--ledger',join(tmp,'ledger'),'--bind-address','127.0.0.1','--rpc-port',String(port),'--gossip-port',String(gossip),'--faucet-port',String(faucet),'--mint',b58(key('unused-genesis-mint').pub),'--bpf-program',b58(program),join(W,'bin/zk9_solana_proof_buffer_lab.so'),'--limit-ledger-size','10000','--quiet'],{stdio:['ignore',log.fd,log.fd],env:{PATH:'/usr/bin:/bin',TMPDIR:'/private/tmp',RUST_LOG:'error'}});
let ended=false;let childCode,childSignal;let forcedKill=false;
child.on('exit',(c,s)=>{ended=true;childCode=c;childSignal=s});
let rid=0,nonce=0;let submitted=0,maxWire=0;
async function rpc(method,params=[]){assert.equal(new URL(endpoint).hostname,'127.0.0.1');const r=await fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:++rid,method,params}),signal:AbortSignal.timeout(15000)});assert.equal(r.status,200);const v=await r.json();if(v.error)throw Object.assign(Error('Local RPC rejected '+method),{rpcError:v.error});return v.result}
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
function instruction(data,{who=authority,target=buffer,bufferSigner=false,authWritable=false}={}){return {program,accounts:[meta(target.pub,bufferSigner,true),meta(who.pub,true,authWritable)],data}}
async function hash(){return (await rpc('getLatestBlockhash',[{commitment:'confirmed'}])).value.blockhash}
async function statuses(sigs){const deadline=Date.now()+90000;while(Date.now()<deadline){const values=(await rpc('getSignatureStatuses',[sigs])).value;if(values.every(x=>x&&['confirmed','finalized'].includes(x.confirmationStatus))){for(const x of values)assert.equal(x.err,null,JSON.stringify(x.err));return}if(ended)throw Error('Validator stopped');await pause(120)}throw Error('Local transaction confirmation timed out')}
async function send(ixs,signers=[authority],blockhash){const raw=tx(ixs,signers,blockhash??await hash());const sig=await rpc('sendTransaction',[raw,{encoding:'base64',skipPreflight:false,preflightCommitment:'confirmed',maxRetries:4}]);submitted++;return sig}
async function commit(ixs,signers=[authority]){const sig=await send(ixs,signers);await statuses([sig]);return sig}
async function account(pair=buffer){const value=(await rpc('getAccountInfo',[b58(pair.pub),{encoding:'base64',commitment:'confirmed'}])).value;return value?{...value,bytes:Buffer.from(value.data[0],'base64')}:null}
async function reject(ixs,signers=[authority],expected,target=buffer){const before=await account(target);const r=await rpc('simulateTransaction',[tx(ixs,signers,await hash()),{encoding:'base64',sigVerify:true,commitment:'confirmed'}]);assert.equal(r.value.err?.InstructionError?.[1]?.Custom,expected,JSON.stringify(r.value.err));const after=await account(target);assert.deepEqual(after?.bytes,before?.bytes);return r.value.err}
let result;
try{
 for(let i=0;i<180;i++){try{if(await rpc('getHealth')==='ok')break}catch{}if(ended)throw Error('Validator startup failed');if(i===179)throw Error('Validator startup timed out');await pause(250)}
 const version=await rpc('getVersion');assert.equal(version['solana-core'],'3.1.10');
 const airdrop=await rpc('requestAirdrop',[b58(authority.pub),100000000000]);await statuses([airdrop]);
 const base=JSON.parse(await readFile(join(W,'BASE.json'),'utf8'));const payload=await readFile(base.fixture);assert.equal(sha(payload).toString('hex'),base.fixture_sha256);
 const count=Math.ceil(payload.length/CHUNK),hashStart=HEADER+Math.ceil(count/8),start=hashStart+32*count,space=start+payload.length;
 const leaves=Array.from({length:count},(_,i)=>sha(Buffer.from('ZK9/SOLANA/BUFFER/LEAF/v1\0'),u32(payload.length),u32(i),payload.subarray(i*CHUNK,(i+1)*CHUNK)));
 const root=sha(Buffer.from('ZK9/SOLANA/BUFFER/ROOT/v1\0'),u32(payload.length),Buffer.concat(leaves));
 const rent=await rpc('getMinimumBalanceForRentExemption',[space]);const initial=(await rpc('getBalance',[b58(authority.pub),{commitment:'confirmed'}])).value;
 const create={program:system,accounts:[meta(authority.pub,true,true),meta(buffer.pub,true,true)],data:Buffer.concat([u32(0),u64(rent),u64(space),program])};
 const init=Buffer.concat([Buffer.from([0]),u32(payload.length),root]);
 const initSig=await commit([create,instruction(init,{bufferSigner:true})],[authority,buffer]);
 const checks=['compiled_sbf_loaded_in_local_validator','real_system_account_allocation_and_signed_initialization'];
 assert.equal((await account()).bytes[80],1);console.log('PASS initialized',payload.length,'payload bytes;',count,'chunks');
 await reject([instruction(init,{bufferSigner:true})],[authority,buffer],1006);checks.push('reinitialization_rejected');
 await reject([instruction(Buffer.from([2]))],[authority],1016);checks.push('incomplete_seal_rejected');
 const chunk=i=>Buffer.concat([Buffer.from([1]),u32(i),payload.subarray(i*CHUNK,(i+1)*CHUNK)]);
 await reject([instruction(chunk(count-1),{who:attacker})],[authority,attacker],1008);checks.push('unauthorized_writer_rejected');
 await reject([instruction(Buffer.concat([Buffer.from([1]),u32(count),Buffer.from([0])]))],[authority],1013);checks.push('out_of_range_chunk_rejected');
 await reject([instruction(chunk(0).subarray(0,20))],[authority],1014);checks.push('truncated_chunk_rejected');
 const firstSig=await commit([instruction(chunk(count-1))]);
 const beforeRetry=(await account()).bytes;await commit([instruction(chunk(count-1))]);assert.deepEqual((await account()).bytes,beforeRetry);checks.push('out_of_order_chunk_and_exact_retry_count_once');
 const altered=Buffer.from(chunk(count-1));altered[altered.length-1]^=1;await reject([instruction(altered)],[authority],1015);checks.push('changed_retry_rejected');
 const bad=key('bad-root-'+label),small=Buffer.from('public test bytes');
 const smallStart=HEADER+1+32,smallSpace=smallStart+small.length;
 const smallRoot=sha(Buffer.from('ZK9/SOLANA/BUFFER/ROOT/v1\0'),u32(small.length),sha(Buffer.from('ZK9/SOLANA/BUFFER/LEAF/v1\0'),u32(small.length),u32(0),small));
 const smallRent=await rpc('getMinimumBalanceForRentExemption',[smallSpace]);
 const badCreate={program:system,accounts:[meta(authority.pub,true,true),meta(bad.pub,true,true)],data:Buffer.concat([u32(0),u64(smallRent),u64(smallSpace),program])};
 const smallChanged=Buffer.from(small);smallChanged[0]^=1;
 await commit([badCreate,instruction(Buffer.concat([Buffer.from([0]),u32(small.length),smallRoot]),{target:bad,bufferSigner:true}),instruction(Buffer.concat([Buffer.from([1]),u32(0),smallChanged]),{target:bad})],[authority,bad]);
 await reject([instruction(Buffer.from([2]),{target:bad})],[authority],1017,bad);checks.push('complete_but_altered_payload_fails_declared_root');
 await commit([instruction(Buffer.from([3]),{target:bad,authWritable:true})]);assert.equal(await account(bad),null);checks.push('failed_upload_can_abort_without_sealing');
 const begin=performance.now();const samples=[];
 for(let offset=0;offset<count-1;offset+=32){
  const block=await hash();const ids=[];
  for(let i=offset;i<Math.min(offset+32,count-1);i++)ids.push(await send([instruction(chunk(i))],[authority],block));
  await statuses(ids);if(offset===0||offset+32>=count-1)samples.push(ids[0]);
  if(offset%512===0)console.log('PASS stored through chunk',Math.min(offset+32,count-1));
 }
 const elapsed=(performance.now()-begin)/1000;let saved=await account();assert.equal(saved.bytes.readUInt32LE(44),count);assert.ok(saved.bytes.subarray(start).equals(payload));checks.push('complete_original_payload_restored_byte_for_byte');
 const sealSig=await commit([instruction(Buffer.from([2]))]);saved=await account();assert.equal(saved.bytes[80],2);checks.push('full_hash_root_checked_before_sealing');
 await commit([instruction(Buffer.from([2]))]);checks.push('seal_retry_idempotent');
 await reject([instruction(chunk(0))],[authority],1012);checks.push('sealed_buffer_immutable');
 await reject([instruction(Buffer.from([3]),{who:attacker,authWritable:true})],[authority,attacker],1008);checks.push('unauthorized_close_rejected');
 const costs=[];
 for(const [operation,sig] of [['initialize',initSig],['write-last',firstSig],['write-first',samples[0]],['write-near-end',samples.at(-1)],['seal',sealSig]]){
  let t;for(let i=0;i<30;i++){t=await rpc('getTransaction',[sig,{encoding:'json',commitment:'confirmed',maxSupportedTransactionVersion:0}]);if(t)break;await pause(100)}assert.ok(t);assert.equal(t.meta.err,null);costs.push({operation,compute_units:t.meta.computeUnitsConsumed,fee_lamports:t.meta.fee});
 }
 await commit([instruction(Buffer.from([3]),{authWritable:true})]);assert.equal(await account(),null);checks.push('authorized_close_recovers_account_deposit');
 assert.ok(Number.isSafeInteger(initial));
 const ending=(await rpc('getBalance',[b58(authority.pub),{commitment:'confirmed'}])).value;
 result={status:'PASS_TRANSPORT_ONLY',checks,version,fixture_sha256:base.fixture_sha256,payload_bytes:payload.length,chunk_bytes:CHUNK,chunk_count:count,account_bytes:space,refundable_account_deposit_lamports:rent,submitted_transactions:submitted,max_transaction_bytes:maxWire,actual_fee_lamports:initial-ending,upload_wall_seconds:elapsed,compute_samples:costs,proof_verified_on_solana:false,bridge_implemented:false,private_transfers_implemented:false,public_network:false,keys:'public synthetic fixture',program_sha256:sha(await readFile(join(W,'bin/zk9_solana_proof_buffer_lab.so'))).toString('hex')};
}finally{
 if(!ended)child.kill('SIGINT');for(let i=0;i<100&&!ended;i++)await pause(100);if(!ended){forcedKill=true;child.kill('SIGKILL');for(let i=0;i<30&&!ended;i++)await pause(100)}assert.ok(ended);await log.close();await rm(tmp,{recursive:true,force:true});
}
result.validator_exit_code=childCode;
result.validator_exit_signal=childSignal;
result.validator_forced_kill=forcedKill;
result.completed_at=new Date().toISOString();
await writeFile(file,JSON.stringify(result,null,2)+'\n',{flag:'wx'});console.log('PASS',label,result.checks.length,'checks',result.submitted_transactions,'local transactions');
