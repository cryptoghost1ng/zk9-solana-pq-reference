// Durable list of admitted relay requests. Only PUBLIC proof envelopes and terminal outcomes are stored here:
// no wallet identifier, no network address, no timing of the caller. The sponsor journal itself lives in
// RelayRepository; this store only remembers which request a restarted service must reopen.
import fs from 'node:fs';
import path from 'node:path';
import {randomBytes} from 'node:crypto';
import {requireState as require,hexValue} from '../solana-chrome-wallet-v1/recovery/checkpoint.mjs';

export const MAX_STORED=Math.ceil((4*1024*1024+3945)/3)*4+128;
const TERMINAL=new Set(['settled','conflicted']);
const REQUEST=/^([0-9a-f]{64})\.request$/;

function ownerOnly(directory,what) {
  const stat=fs.lstatSync(directory);
  require(stat.isDirectory()&&!stat.isSymbolicLink()&&(stat.mode&0o077)===0&&stat.uid===process.getuid(),what+' needs an owner-only directory.');
}
function ownerFile(file) {
  const stat=fs.lstatSync(file);
  require(stat.isFile()&&!stat.isSymbolicLink()&&(stat.mode&0o077)===0&&stat.uid===process.getuid()&&stat.nlink===1,'Unsafe relay state file.');
  return stat;
}
function syncDirectory(directory) {
  const fd=fs.openSync(directory,fs.constants.O_RDONLY);
  try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
}
// Temp file + fsync + rename + directory fsync: a crash leaves either nothing or the complete record.
function atomicWrite(directory,name,bytes) {
  const temporary=path.join(directory,'.tmp-'+randomBytes(8).toString('hex'));
  const fd=fs.openSync(temporary,fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_WRONLY|fs.constants.O_NOFOLLOW,0o600);
  try{fs.writeSync(fd,bytes);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
  fs.renameSync(temporary,path.join(directory,name));
  syncDirectory(directory);
}

export function createRequestStore(root) {
  require(typeof root==='string'&&path.isAbsolute(root),'Absolute relay state directory required.');
  ownerOnly(root,'Relay state');
  const directory=name=>{
    const target=path.join(root,name);
    try{fs.mkdirSync(target,{mode:0o700});}catch(error){if(error.code!=='EEXIST')throw error;}
    ownerOnly(target,'Relay '+name);return target;
  };
  const requests=directory('requests'),outcomes=directory('outcomes');
  for(const name of fs.readdirSync(requests))if(name.startsWith('.tmp-'))fs.unlinkSync(path.join(requests,name));
  for(const name of fs.readdirSync(outcomes))if(name.startsWith('.tmp-'))fs.unlinkSync(path.join(outcomes,name));
  const requestPath=id=>path.join(requests,hexValue(id,32)+'.request');
  const outcomePath=id=>path.join(outcomes,hexValue(id,32)+'.json');
  function outcome(id) {
    const file=outcomePath(id);
    if(!fs.existsSync(file))return null;
    ownerFile(file);
    const value=JSON.parse(fs.readFileSync(file,'utf8'));
    require(value&&Object.keys(value).sort().join(',')==='id,state'&&value.id===id&&TERMINAL.has(value.state),'Unknown relay outcome record.');
    return value.state;
  }
  return Object.freeze({
    // Returns true when the request was stored now, false when the identical bytes were already there.
    save(id,raw) {
      require(raw instanceof Uint8Array&&raw.length>0&&raw.length<=MAX_STORED,'Relay request size rejected.');
      const file=requestPath(id);
      if(fs.existsSync(file)) {
        ownerFile(file);
        require(Buffer.compare(fs.readFileSync(file),Buffer.from(raw))===0,'A stored relay request cannot change.');
        return false;
      }
      atomicWrite(requests,hexValue(id,32)+'.request',raw);return true;
    },
    load(id) {
      const file=requestPath(id);
      if(!fs.existsSync(file))return null;
      ownerFile(file);return new Uint8Array(fs.readFileSync(file));
    },
    outcome,
    // A terminal state can be written once and never changed.
    finish(id,state) {
      require(TERMINAL.has(state),'Only a terminal outcome can be recorded.');
      const existing=outcome(id);
      if(existing!==null){require(existing===state,'A recorded relay outcome cannot change.');return false;}
      atomicWrite(outcomes,hexValue(id,32)+'.json',Buffer.from(JSON.stringify({id,state})+'\n'));return true;
    },
    // Admitted requests without a terminal outcome, oldest first. Parked requests are included: a restart is a new chance.
    unfinished() {
      const rows=[];
      for(const name of fs.readdirSync(requests)) {
        const match=REQUEST.exec(name);if(!match)continue;
        if(outcome(match[1])!==null)continue;
        rows.push({id:match[1],mtime:fs.lstatSync(path.join(requests,name)).mtimeMs});
      }
      return rows.sort((a,b)=>a.mtime-b.mtime||(a.id<b.id?-1:1)).map(row=>row.id);
    },
  });
}
