// Internal server helper, not an exposed endpoint. A future endpoint still
// needs rate limits and fixed network/operator configuration.
import {requestCommitment} from './relay-request.mjs';
import {deriveRelayTransport} from './relay-transport.mjs';
import {requireState as require,hexValue} from '../solana-chrome-wallet-v1/recovery/checkpoint.mjs';
export const OFFER_VERSION='zk9-relay-offer-v1';
export async function relayOffer(request,{context,sponsor,transportSeed}) {
  require(request&&Object.keys(request).sort().join(',')==='context,kind,version,wire_hash','Unknown offer fields.');
  require(request.version===OFFER_VERSION&&request.context===context,'Foreign relay offer context.');
  hexValue(context,96);
  const id=await requestCommitment(request.kind,context,request.wire_hash);
  const {transport}=await deriveRelayTransport(sponsor,transportSeed,id);
  // No proof bytes received, no database or funds allocated. Actual admission
  // must still verify the full proof before any sponsor resources are spent.
  return {version:OFFER_VERSION,id,transport};
}
