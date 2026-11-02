// Wire-only relay boundary. Structural checks are NOT proof verification.
// There is deliberately no wallet ID, signature, payer, seed, endpoint, fee
// quote, callback URL, destination override or arbitrary instruction field.
import {requireState as require,hexValue} from '../solana-chrome-wallet-v1/recovery/checkpoint.mjs';
import {fromBase64,toBase64,digest,parsePaymentWire,MAX_WIRE} from '../solana-chrome-wallet-v1/recovery/payment-wire.mjs';
import {checkWire} from '../solana-chrome-wallet-v1/recovery/proof-progress.mjs';

export const VERSION='zk9-sponsored-proof-v1';
const encoder=new TextEncoder();
const MAX_REQUEST=Math.ceil(MAX_WIRE/3)*4+128;
// The commitment can be disclosed before the executable proof. It authorizes
// no spend and consumes no sponsor reservation by itself.
export async function requestCommitment(kind,context,wireHash) {
  require(kind==='send'||kind==='withdraw','Unknown proof kind.');
  hexValue(context,96);hexValue(wireHash,32);
  return digest(encoder.encode(`${VERSION}\0${kind}\0${context}\0${wireHash}`));
}
export function encodeRequest(kind,wire) {
  checkWire(wire,kind);
  return encoder.encode(JSON.stringify({version:VERSION,kind,wire:toBase64(wire)}));
}
export async function readRequest(raw,expectedContext) {
  hexValue(expectedContext,96);
  require(raw instanceof Uint8Array&&raw.length>0&&raw.length<=MAX_REQUEST,'Relay request size rejected.');
  const text=new TextDecoder('utf-8',{fatal:true}).decode(raw),r=JSON.parse(text);
  require(r&&Object.keys(r).sort().join(',')==='kind,version,wire'&&r.version===VERSION,'Unknown relay request fields.');
  // Canonical encoding rejects duplicate keys and alternate representations.
  require(text===JSON.stringify({version:VERSION,kind:r.kind,wire:r.wire}),'Noncanonical relay request.');
  const wire=fromBase64(r.wire);checkWire(wire,r.kind);
  const statement=parsePaymentWire(wire,r.kind);
  require(statement.context===expectedContext,'Relay context mismatch.');
  const wireHash=await digest(wire);
  const id=await requestCommitment(r.kind,expectedContext,wireHash);
  return {id,kind:r.kind,wire,wire_hash:wireHash,statement,cryptographically_verified:false};
}
