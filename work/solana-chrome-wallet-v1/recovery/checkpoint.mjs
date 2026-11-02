// Structural/continuity checks AFTER the real Rust history validator and Go
// ownership scanner. This module never authenticates an RPC or decrypts notes.
export function requireState(ok,message='Private wallet state is inconsistent.') {if(!ok)throw new Error(message);}
export function hexValue(value,size) {requireState(typeof value==='string'&&new RegExp(`^[0-9a-f]{${size*2}}$`).test(value));return value;}
export function integer(value) {requireState(Number.isSafeInteger(value)&&value>=0);return value;}
export function amount(value) {
  requireState(typeof value==='string'&&/^(0|[1-9][0-9]{0,19})$/.test(value));
  const n=BigInt(value);requireState(n<2n**64n);return n;
}
export function checkedCheckpoint(value) {
  requireState(value&&typeof value==='object'&&!Array.isArray(value));
  requireState(Object.keys(value).sort().join(',')==='commitments,context,leaf_count,nullifiers,owned_notes,root,slot,spendable_units,wallet_id');
  hexValue(value.context,96);hexValue(value.wallet_id,64);hexValue(value.root,64);integer(value.slot);
  const count=integer(value.leaf_count);requireState(count<=100000&&count%2===0);
  requireState(Array.isArray(value.commitments)&&value.commitments.length===count);
  const commitments=value.commitments.map(x=>hexValue(x,64));requireState(new Set(commitments).size===count);
  requireState(Array.isArray(value.nullifiers)&&value.nullifiers.length<=count);
  const nullifiers=value.nullifiers.map(x=>hexValue(x,64));const spent=new Set(nullifiers);requireState(spent.size===nullifiers.length);
  requireState(Array.isArray(value.owned_notes)&&value.owned_notes.length<=count);
  const indices=new Set(),nfs=new Set();let balance=0n;
  for(const note of value.owned_notes) {
    requireState(note&&Object.keys(note).sort().join(',')==='amount_units,commitment,index,nullifier,spent');
    const index=integer(note.index);hexValue(note.nullifier,64);
    requireState(index<count&&note.commitment===commitments[index]&&!indices.has(index)&&!nfs.has(note.nullifier));
    requireState(typeof note.spent==='boolean'&&note.spent===spent.has(note.nullifier));
    const units=amount(note.amount_units);if(!note.spent)balance+=units;
    requireState(balance<2n**64n);indices.add(index);nfs.add(note.nullifier);
  }
  requireState(amount(value.spendable_units)===balance);
  return structuredClone(value);
}
export function checkpointFromScan(context,walletId,snapshot,recovered) {
  requireState(snapshot?.version===1&&snapshot.all_pool_records_checked===true&&snapshot.context===context);
  requireState(recovered?.synthetic_only===true&&recovered.rpc_consensus_authenticated===false);
  requireState(recovered.context===context&&recovered.wallet_id===walletId&&recovered.slot===snapshot.slot&&recovered.root===snapshot.root);
  requireState(Array.isArray(snapshot.notes)&&snapshot.notes.every((n,i)=>n.index===i));
  requireState(Array.isArray(recovered.owned_notes));
  return checkedCheckpoint({context,wallet_id:walletId,slot:snapshot.slot,leaf_count:snapshot.leaf_count,
    root:snapshot.root,commitments:snapshot.notes.map(n=>n.commitment),nullifiers:snapshot.nullifiers,
    owned_notes:recovered.owned_notes.map(n=>({index:n.index,commitment:n.commitment,nullifier:n.nullifier,
      amount_units:n.amount_units,spent:n.spent})),spendable_units:recovered.spendable_units});
}
export function appendCheckpoint(previous,next) {
  const current=checkedCheckpoint(next);if(!previous)return current;
  const old=checkedCheckpoint(previous);
  requireState(old.context===current.context&&old.wallet_id===current.wallet_id,'Stored wallet identity differs.');
  requireState(current.slot>=old.slot&&current.leaf_count>=old.leaf_count,'History rolled back.');
  requireState(current.slot!==old.slot||(current.root===old.root&&current.leaf_count===old.leaf_count),'Same slot changed history.');
  requireState(current.leaf_count!==old.leaf_count||current.root===old.root,'History root changed without new notes.');
  requireState(old.commitments.every((cm,i)=>current.commitments[i]===cm),'Accepted history was replaced.');
  const spent=new Set(current.nullifiers);requireState(old.nullifiers.every(n=>spent.has(n)),'Spent history disappeared.');
  const owned=new Map(current.owned_notes.map(n=>[n.index,n]));
  for(const before of old.owned_notes) {
    const after=owned.get(before.index);
    requireState(after&&after.commitment===before.commitment&&after.nullifier===before.nullifier
      &&after.amount_units===before.amount_units&&(!before.spent||after.spent),'Owned note disappeared or changed.');
  }
  return current;
}
