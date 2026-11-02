// Server-only derivation shared by the non-executable offer and proof admission.
// No on-chain account creation, funding reservation, signing or proof admission.
import {requireState as require,hexValue} from '../solana-chrome-wallet-v1/recovery/checkpoint.mjs';
import {privateSigner,b58} from '../solana-chrome-wallet-v1/recovery/solana-transaction.mjs';

export async function deriveRelayTransport(sponsor,transportSeed,requestId) {
  hexValue(requestId,32);
  require(transportSeed instanceof Uint8Array&&transportSeed.length===32&&transportSeed.some(x=>x));
  const key=await crypto.subtle.importKey('raw',transportSeed,'HKDF',false,['deriveBits']);
  const derive=async role=>{
    const seed=new Uint8Array(await crypto.subtle.deriveBits({name:'HKDF',hash:'SHA-256',
      salt:new TextEncoder().encode(`zk9-sponsored-publication-journal-v1\0${requestId}`),
      info:new TextEncoder().encode(role)},key,256));
    try{return await privateSigner(seed);}finally{seed.fill(0);}
  };
  const source=await derive('source'),receipt=await derive('receipt');
  return {source,receipt,transport:{authority:b58(sponsor.pub),source:b58(source.pub),receipt:b58(receipt.pub)}};
}
