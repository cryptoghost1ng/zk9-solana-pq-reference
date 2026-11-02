//! Consume only a completed immutable Solana proof receipt for this pool.
use super::*;
const PRIVATE_NOTE_SPACE:usize=176+receipt::PACKET_BYTES;

fn marker(a:&AccountInfo,pool:&Pubkey,nf:&[u8;64],count:u64)->ProgramResult{
    let mut b=a.try_borrow_mut_data()?;b[..8].copy_from_slice(b"ZK9NULL1");
    b[8..40].copy_from_slice(pool.as_ref());b[40..104].copy_from_slice(nf);put(&mut b,104,count);Ok(())
}

#[inline(never)]
pub(super) fn send(id:&Pubkey,a:&[AccountInfo],input:&[u8])->ProgramResult{
    // base6, accepted anchor, nf0,nf1,cm0,cm1,newroot, six receipt accounts.
    let genesis:[u8;32]=input[9..41].try_into().unwrap();common(id,a,&genesis)?;
    if a[0].owner!=id || a[0].data_len()!=SPACE{return Err(e(6))}
    let mut state=a[0].try_borrow_mut_data()?;
    let count=accounting(&state)?;
    let net=network(id,a[0].key);
    if state[8..40]!=genesis || &state[40..72]!=a[2].key.as_ref()
        || &state[72..104]!=a[1].key.as_ref() || state[104..136]!=net{return Err(e(6))}
    if count!=read(input,1){return Err(e(7))}
    let held=asset::account(a[1].owner,&a[1].try_borrow_data()?,a[2].key,a[0].key,a[3].key)?;
    if held<read(&state,152).checked_add(read(&state,160)).ok_or(e(6))?{return Err(e(8))}
    let context=receipt::Context{network:net,genesis,asset:a[2].key.to_bytes()};
    receipt::with_completed_proof(&receipt::Accounts{receipt:&a[12],proof_program:&a[13],proof_program_data:&a[14],source:&a[15],buffer_program:&a[16],buffer_program_data:&a[17]},&context,|proof,packets|{
        let anchor=record(id,b"root",a[0].key,proof.root()).0;address(&a[6],&anchor)?;
        if a[6].owner!=id || a[6].is_writable{return Err(e(10))}
        let root=a[6].try_borrow_data()?;
        if root.len()!=ROOT_SPACE || &root[..8]!=b"ZK9ROOT1" || &root[8..40]!=a[0].key.as_ref()
            || &root[40..104]!=proof.root() || read(&root,104)>count || read(&root,104)<2 || read(&root,104)&1!=0{return Err(e(10))}
        // Fixed beta fee in token base units, accrued inside the vault.
        if proof.fee()!=1 || read(&state,152)<proof.fee(){return Err(e(11))}
        let fees=read(&state,160).checked_add(proof.fee()).ok_or(e(11))?;
        let backing=read(&state,152)-proof.fee();
        let sends=read(&state,168).checked_add(1).ok_or(e(11))?;
        let mut bumps=[0u8;4];
        for i in 0..2{
            let (nf,b)=record(id,b"nf",a[0].key,&proof.nullifiers()[i]);address(&a[7+i],&nf)?;fresh(&a[7+i])?;bumps[i]=b;
            let (cm,b)=record(id,b"cm",a[0].key,&proof.outputs()[i]);address(&a[9+i],&cm)?;fresh(&a[9+i])?;bumps[2+i]=b;
        }
        let nextroot=tree::append_pair(&mut state[TREE_AT..],count,proof.outputs()).map_err(|_|e(5))?;
        let (rk,rb)=record(id,b"root",a[0].key,&nextroot);address(&a[11],&rk)?;fresh(&a[11])?;
        for i in 0..2{
            let nf=&proof.nullifiers()[i];
            allocate(&a[4],&a[7+i],&a[5],id,ROOT_SPACE,&[b"nf",a[0].key.as_ref(),&nf[..32],&nf[32..],&[bumps[i]]])?;
            marker(&a[7+i],a[0].key,nf,count)?;
            let cm=&proof.outputs()[i];
            allocate(&a[4],&a[9+i],&a[5],id,PRIVATE_NOTE_SPACE,&[b"cm",a[0].key.as_ref(),&cm[..32],&cm[32..],&[bumps[2+i]]])?;
            let mut n=a[9+i].try_borrow_mut_data()?;n[..8].copy_from_slice(b"ZK9NOTE1");n[8..40].copy_from_slice(a[0].key.as_ref());put(&mut n,40,count+i as u64);
            n[48..112].copy_from_slice(cm);n[112..176].copy_from_slice(&proof.delivery_digests()[i]);n[176..].copy_from_slice(packets[i]);
        }
        allocate(&a[4],&a[11],&a[5],id,ROOT_SPACE,&[b"root",a[0].key.as_ref(),&nextroot[..32],&nextroot[32..],&[rb]])?;
        write_root(&a[11],a[0].key,&nextroot,count+2)?;
        put(&mut state,152,backing);put(&mut state,160,fees);put(&mut state,168,sends);accounting(&state)?;
        // No asset moves on an internal send. Public withdrawal is a separate,
        // recipient-bound proof relation; this send proof cannot authorize it.
        Ok(())
    })
}
