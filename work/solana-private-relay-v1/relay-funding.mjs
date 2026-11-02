// Local operator-funded execution. The wallet request has no funding fields.
// This is conservative reservation accounting, NOT measured transaction costs.
import {requireState as require,integer} from '../solana-chrome-wallet-v1/recovery/checkpoint.mjs';
import {decodeTransaction,b58,fromBase64,toBase64} from '../solana-chrome-wallet-v1/recovery/solana-transaction.mjs';
const PUB='zk9-sponsored-publication-journal-v1',SETTLE='zk9-sponsored-settlement-v1';
// Frozen beta-withdraw pool. Reject a new executable until its CPI allocations
// are reviewed. Source: pool/src/{spend,withdraw}.rs and receipt PACKET_BYTES.
export const COST_POOL_SHA256='94d918d5856d29ac2ffe53145abff133107d6ba45417db2488d5ba543450cf16';
export const SETTLEMENT_ALLOCATIONS=Object.freeze({send:Object.freeze([112,112,1908,1908,112]),
  withdraw:Object.freeze([112,112,1908,1908,112,200])});
const amount=value=>{require(typeof value==='string'&&/^[1-9][0-9]{0,19}$/.test(value),'Positive canonical funding amount required.');
  const n=BigInt(value);require(n<2n**64n);return n;};

export function checkedFunding(value){
  require(value&&Object.keys(value).sort().join(',')==='maxFeeLamports,requestLamports,totalLamports','Explicit operator funding limits required.');
  const total=amount(value.totalLamports),cap=amount(value.requestLamports),fee=amount(value.maxFeeLamports);
  require(fee<=cap&&cap<=total,'Inconsistent relay funding limits.');return Object.freeze({...value});
}

export async function quoteFundingDebit({value,network,sponsor,program,kind,maxFeeLamports}){
  const maximum=amount(maxFeeLamports),a=value.pending;require(a,'Missing signed attempt.');
  const tx=await decodeTransaction(a.raw);require(b58(tx.authority)===sponsor&&tx.signature===a.signature,'Foreign funding authority.');
  await network.checkLedger();network.requireProgram(program);
  const bytes=fromBase64(a.raw,1232),count=bytes[0];require(count===tx.signers.length&&count>=1&&count<=3);
  // Only the unsigned MESSAGE goes to the fee RPC. Never leak a not-yet-durable
  // executable transaction to any endpoint, even a local fee estimator.
  const message=toBase64(bytes.subarray(1+count*64));
  const quoted=await network.rpc('getFeeForMessage',[message,{commitment:'confirmed'}]);
  integer(quoted?.context?.slot);integer(quoted?.value);require(quoted.value>0&&BigInt(quoted.value)<=maximum,'Fee unavailable or above operator cap.');
  let rent=0n;
  if(value.version===PUB){integer(a.descriptor?.rent);rent=BigInt(a.descriptor.rent);}
  else{
    require(value.version===SETTLE&&a.plan?.kind===kind&&a.plan?.instruction?.program===program,'Foreign settlement cost request.');
    require(network.profile.programs[program]===COST_POOL_SHA256,'Pool executable has no reviewed allocation budget.');
    require(SETTLEMENT_ALLOCATIONS[kind],'Unknown settlement kind.');
    // Full rent minimum is an upper bound even if a PDA was prefunded. A
    // withdrawal destination must already exist; the settlement does not create it.
    for(const size of SETTLEMENT_ALLOCATIONS[kind]){
      const n=await network.rpc('getMinimumBalanceForRentExemption',[size,{commitment:'confirmed'}]);
      integer(n);require(n>0);rent+=BigInt(n);
    }
  }
  const debit=rent+maximum;require(debit<2n**64n);
  const balance=await network.rpc('getBalance',[sponsor,{commitment:'confirmed',minContextSlot:quoted.context.slot}]);
  integer(balance?.context?.slot);integer(balance?.value);
  require(balance.context.slot>=quoted.context.slot&&BigInt(balance.value)>=debit,'Sponsor balance insufficient or stale.');
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
      require(value.version===PUB?id===requestId:value.version===SETTLE&&value.request_id===requestId,'Foreign funded request.');
      if(value.version===PUB)require(value.attempts<=maxPublicationAttempts,'Local relay publication budget exhausted.');
      const old=await repository.read(id);require((old?.revision??null)===expectedRevision,'Funding journal changed.');
      const debit=value.pending&&!old?.pending?await quoteDebit(value):'0';
      // CAS rechecks after the asynchronous quote, then commits debit and signed
      // attempt in ONE transaction. A race must never release extra signed bytes.
      return repository.compareAndSwapFunded({id,expectedRevision,value,budget,requestId,debitLamports:debit});
    },
  });
}
