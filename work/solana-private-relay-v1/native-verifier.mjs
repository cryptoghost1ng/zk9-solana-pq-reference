// Local native admission adapter. Only public proof envelopes enter the child.
// The operator supplies a hash-pinned profile; HTTP clients never select files.
import fs from 'node:fs';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {requireState as require,hexValue} from '../solana-chrome-wallet-v1/recovery/checkpoint.mjs';
import {checkWire} from '../solana-chrome-wallet-v1/recovery/proof-progress.mjs';
import {parsePaymentWire} from '../solana-chrome-wallet-v1/recovery/payment-wire.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const pipeBridge=fileURLToPath(new URL('./native-verifier-pipe.py',import.meta.url));
const python=fileURLToPath(new URL('../../.toolchain/python/bin/zk9-python',import.meta.url));
const transportPins=[pipeBridge,python].map(p=>[p,sha(fs.readFileSync(p))]);
export function nativeVerifier(profilePath,expectedDigest){
  hexValue(expectedDigest,32);require(path.isAbsolute(profilePath));
  const raw=fs.readFileSync(profilePath);require(raw.length<=32768&&sha(raw)===expectedDigest,'Native profile pin mismatch.');
  const profile=JSON.parse(raw);hexValue(profile.context,96);
  require(profile.scope==='isolated-solana-validator-synthetic-only','Only isolated synthetic admission is enabled.');
  const files={};
  for(const [kind,name] of [['send','send_envelope'],['withdraw','withdrawal_envelope']]){
    const item=profile.files[name];require(item&&path.isAbsolute(item.path));hexValue(item.sha256,32);
    files[kind]={path:item.path,sha256:item.sha256};
  }
  let busy=false;
  return async(kind,wire,context)=>{
    require(!busy,'Native admission already running.');busy=true;
    try{
      require(context===profile.context,'Wrong native admission context.');checkWire(wire,kind);
      require(parsePaymentWire(wire,kind).context===context,'Wire context differs.');
      const file=files[kind];require(sha(fs.readFileSync(profilePath))===expectedDigest
        &&sha(fs.readFileSync(file.path))===file.sha256,'Native verifier input changed.');
      require(transportPins.every(([p,h])=>sha(fs.readFileSync(p))===h),'Native pipe transport changed.');
      const request=JSON.stringify({version:kind==='send'?'zk9-verify-envelope-v1':'zk9-verify-withdrawal-envelope-v1',
        context:{network:context.slice(0,64),genesis:context.slice(64,128),asset:context.slice(128),fee:'1'},
        wire:Buffer.from(wire).toString('hex')});
      return await new Promise((resolve,reject)=>{
        const child=spawn(python,['-E','-s','-B',pipeBridge,file.path],{stdio:['pipe','pipe','pipe'],env:{PATH:'/usr/bin:/bin',RUST_BACKTRACE:'0'}});
        let output=[],outputLength=0,stderr=false,overLimit=false,timedOut=false;
        const timer=setTimeout(()=>{timedOut=true;child.kill('SIGKILL');},45000);
        child.stdout.on('data',b=>{outputLength+=b.length;if(outputLength>32768){overLimit=true;child.kill('SIGKILL');}else output.push(b);});
        child.stderr.on('data',()=>{stderr=true;});
        child.once('error',()=>{clearTimeout(timer);reject(Error('Native verifier could not start.'));});
        child.stdin.on('error',()=>{}); // A rejecting verifier may close input early.
        child.once('close',code=>{
          clearTimeout(timer);
          if(timedOut||overLimit)return reject(Error('Native verifier exceeded its resource bound.'));
          if(code!==0||stderr)return resolve(false);
          try{const r=JSON.parse(Buffer.concat(output).toString('utf8'));
            resolve(r&&Object.keys(r).join(',')==='verified'&&r.verified===true);
          }catch{resolve(false);}
        });
        child.stdin.end(request);
      });
    }finally{busy=false;}
  };
}
