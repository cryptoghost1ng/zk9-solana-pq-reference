// Local operator-funded execution, WINDOWED revision. The wallet request has no funding fields.
// This is conservative reservation accounting, NOT measured transaction costs.
// Derived from ../solana-private-relay-v1/relay-funding.mjs (frozen, untouched), which still prices settlement and
// owns the operator limits and the reviewed pool executable. What changes: a publication journal now carries a LIST
// of pending attempts, so a new window is priced as the SUM of its attempts (each charged the operator's fee
// ceiling, plus the rent of an account creation) and checked against the sponsor balance before any byte is released.
import {requireState as require,integer} from '../solana-chrome-wallet-v1/recovery/checkpoint.mjs';
import {decodeTransaction,b58,fromBase64,toBase64} from '../solana-chrome-wallet-v1/recovery/solana-transaction.mjs';
import {checkedFunding,quoteFundingDebit as quoteSettlementDebit,COST_POOL_SHA256,SETTLEMENT_ALLOCATIONS} from '../solana-private-relay-v1/relay-funding.mjs';
import {MAX_WINDOW} from './relay-publication.mjs';
export {checkedFunding,COST_POOL_SHA256,SETTLEMENT_ALLOCATIONS};
const PUB='zk9-sponsored-publication-journal-v2';
const amount=value=>{require(typeof value==='string'&&/^[1-9][0-9]{0,19}$/.test(value),'Positive canonical funding amount required.');
  const n=BigInt(value);require(n<2n**64n);return n;};
// Bounded concurrency for the per-attempt fee quotes of one window.
async function inGroups(tasks,size=16){const out=[];for(let i=0;i<tasks.length;i+=size)out.push(...await Promise.all(tasks.slice(i,i+size).map(t=>t())));return out;}

export async function quoteFundingDebit(args){
  const {value,network,sponsor,program,maxFeeLamports}=args;
  // Settlement is priced by the frozen function, unchanged.
  if(value.version!==PUB)return quoteSettlementDebit(args);
  const maximum=amount(maxFeeLamports),list=value.pending;
  require(Array.isArray(list)&&list.length>=1&&list.length<=MAX_WINDOW,'Missing signed attempts.');
  await network.checkLedger();network.requireProgram(program);
  const quotes=await inGroups(list.map(a=>async()=>{
    const tx=await decodeTransaction(a.raw);require(b58(tx.authority)===sponsor&&tx.signature===a.signature,'Foreign funding authority.');
    const bytes=fromBase64(a.raw,1232),count=bytes[0];require(count===tx.signers.length&&count>=1&&count<=3);
    // Only the unsigned MESSAGE goes to the fee RPC. Never leak a not-yet-durable
    // executable transaction to any endpoint, even a local fee estimator.
    const message=toBase64(bytes.subarray(1+count*64));
    const quoted=await network.rpc('getFeeForMessage',[message,{commitment:'confirmed'}]);
    integer(quoted?.context?.slot);integer(quoted?.value);require(quoted.value>0&&BigInt(quoted.value)<=maximum,'Fee unavailable or above operator cap.');
    integer(a.descriptor?.rent);return {slot:quoted.context.slot,rent:BigInt(a.descriptor.rent)};
  }));
  // Every attempt is charged the fee CEILING, so a window of N attempts costs N ceilings.
  const rent=quotes.reduce((sum,q)=>sum+q.rent,0n),slot=Math.max(...quotes.map(q=>q.slot));
  const debit=rent+maximum*BigInt(list.length);require(debit<2n**64n);
  const balance=await network.rpc('getBalance',[sponsor,{commitment:'confirmed',minContextSlot:slot}]);
  integer(balance?.context?.slot);integer(balance?.value);
  require(balance.context.slot>=slot&&BigInt(balance.value)>=debit,'Sponsor balance insufficient or stale.');
  // A balance observation is not a lock on the account. SQLite caps concurrent
  // allocations; the synthetic sponsor must be dedicated to this repository.
  return debit.toString();
}

export async function fundedRepository({repository,requestId,sponsor,genesis,funding,quoteDebit,maxPublicationAttempts}){
  funding=checkedFunding(funding);require(typeof quoteDebit==='function');integer(maxPublicationAttempts);require(maxPublicationAttempts>0);
  const budget=await repository.configureFunding({sponsor,genesis,totalLamports:funding.totalLamports});
  await repository.reserveFunding(budget,requestId,funding.requestLamports);
  return Object.freeze({
    read:id=>repository.read(id),
    compareAndSwap:async(id,expectedRevision,value)=>{
      require(value.transport?.authority===sponsor,'Foreign funded sponsor.');
      require(value.version===PUB?id===requestId:value.version==='zk9-sponsored-settlement-v1'&&value.request_id===requestId,'Foreign funded request.');
      if(value.version===PUB)require(value.attempts<=maxPublicationAttempts,'Local relay publication budget exhausted.');
      const old=await repository.read(id);require((old?.revision??null)===expectedRevision,'Funding journal changed.');
      // A debit is due only when a signed attempt (or a whole window) enters an EMPTY pending state.
      const entering=value.version===PUB?value.pending.length>0&&!old?.pending?.length:!!value.pending&&!old?.pending;
      const debit=entering?await quoteDebit(value):'0';
      // CAS rechecks after the asynchronous quote, then commits debit and signed
      // attempts in ONE transaction. A race must never release extra signed bytes.
      return repository.compareAndSwapFunded({id,expectedRevision,value,budget,requestId,debitLamports:debit});
    },
  });
}
