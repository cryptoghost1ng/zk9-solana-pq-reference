import {createHash,createPrivateKey,createPublicKey} from 'node:crypto';
import assert from 'node:assert/strict';
const sha=(...xs)=>createHash('sha256').update(Buffer.concat(xs)).digest();
const u32=n=>{const b=Buffer.alloc(4);b.writeUInt32LE(n);return b};
const u64=n=>{const b=Buffer.alloc(8);b.writeBigUInt64LE(BigInt(n));return b};
const alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58(b){let n=BigInt('0x'+b.toString('hex')),s='';while(n){s=alphabet[Number(n%58n)]+s;n/=58n}for(const x of b){if(x!==0)break;s='1'+s}return s}
function un58(s){let n=0n;for(const c of s){const i=alphabet.indexOf(c);assert.ok(i>=0);n=n*58n+BigInt(i)}let h=n.toString(16);if(h.length%2)h='0'+h;return Buffer.concat([Buffer.alloc(s.match(/^1*/)[0].length),n?Buffer.from(h,'hex'):Buffer.alloc(0)])}
function key(name){const seed=sha(Buffer.from('ZK9 public Solana buffer fixture/'+name));const secret=createPrivateKey({key:Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'),seed]),format:'der',type:'pkcs8'});return {secret,pub:createPublicKey(secret).export({format:'der',type:'spki'}).subarray(-32)}}

export {sha,u32,u64,b58,un58,key};
