//! Atomic, recipient-bound Token-2022 payout using the withdrawal proof producer.
use super::*;
const PRIVATE_NOTE_SPACE:usize=176+withdraw_receipt::PACKET_BYTES;
const WITHDRAWAL_SPACE:usize=200;

#[inline(never)]
pub(super) fn withdraw(id:&Pubkey,a:&[AccountInfo],input:&[u8])->ProgramResult {
    // base6, anchor,nf0,nf1,cm0,cm1,newroot,receipt6,destination,withdrawal record.
    // Recipient is a full wallet owner Pubkey inside the VERIFIED statement.
    let genesis:[u8;32]=input[9..41].try_into().unwrap();common(id,a,&genesis)?;
    if a[0].owner!=id || a[0].data_len()!=SPACE || !a[18].is_writable || a[18].executable || a[18].key==a[1].key {return Err(e(6))}
    let net=network(id,a[0].key);
    let context=withdraw_receipt::Context{network:net,genesis,asset:a[2].key.to_bytes()};
    withdraw_receipt::with_completed_withdrawal(&withdraw_receipt::Accounts{
        receipt:&a[12],proof_program:&a[13],proof_program_data:&a[14],source:&a[15],buffer_program:&a[16],buffer_program_data:&a[17],
    },&context,|proof,packets|{
        let mut state=a[0].try_borrow_mut_data()?;let count=accounting(&state)?;
        if state[8..40]!=genesis || &state[40..72]!=a[2].key.as_ref() || &state[72..104]!=a[1].key.as_ref() || state[104..136]!=net {return Err(e(6))}
        if count!=read(input,1){return Err(e(7))}
        let held=asset::account(a[1].owner,&a[1].try_borrow_data()?,a[2].key,a[0].key,a[3].key)?;
        let destination_pre=asset::account(a[18].owner,&a[18].try_borrow_data()?,a[2].key,proof.recipient(),a[3].key)?;
        if held<read(&state,152).checked_add(read(&state,160)).ok_or(e(6))? {return Err(e(8))}
        let anchor=record(id,b"root",a[0].key,proof.root()).0;address(&a[6],&anchor)?;
        if a[6].owner!=id || a[6].is_writable {return Err(e(10))}
        let root=a[6].try_borrow_data()?;
        if root.len()!=ROOT_SPACE || &root[..8]!=b"ZK9ROOT1" || &root[8..40]!=a[0].key.as_ref() || &root[40..104]!=proof.root()
            || read(&root,104)>count || read(&root,104)<2 || read(&root,104)&1!=0 {return Err(e(10))}
        drop(root);
        let amount=proof.amount();let debit=amount.checked_add(proof.fee()).ok_or(e(11))?;
        if proof.fee()!=1 || amount==0 || read(&state,152)<debit {return Err(e(11))}
        let backing=read(&state,152)-debit;
        let fees=read(&state,160).checked_add(proof.fee()).ok_or(e(11))?;
        let withdrawn=read(&state,176).checked_add(amount).ok_or(e(11))?;
        let withdrawals=read(&state,184).checked_add(1).ok_or(e(11))?;
        destination_pre.checked_add(amount).ok_or(e(11))?;
        let (withdraw_key,withdraw_bump)=record(id,b"withdraw",a[0].key,&proof.nullifiers()[0]);
        address(&a[19],&withdraw_key)?;fresh(&a[19])?;
        let mut bumps=[0;4];
        for i in 0..2 {
            // SAME nf domain as private sends: either operation consumes a note once.
            let (nf,b)=record(id,b"nf",a[0].key,&proof.nullifiers()[i]);address(&a[7+i],&nf)?;fresh(&a[7+i])?;bumps[i]=b;
            let (cm,b)=record(id,b"cm",a[0].key,&proof.outputs()[i]);address(&a[9+i],&cm)?;fresh(&a[9+i])?;bumps[2+i]=b;
        }
        let nextroot=tree::append_pair(&mut state[TREE_AT..],count,proof.outputs()).map_err(|_|e(5))?;
        let (rk,rb)=record(id,b"root",a[0].key,&nextroot);address(&a[11],&rk)?;fresh(&a[11])?;
        for i in 0..2 {
            let nf=&proof.nullifiers()[i];
            allocate(&a[4],&a[7+i],&a[5],id,ROOT_SPACE,&[b"nf",a[0].key.as_ref(),&nf[..32],&nf[32..],&[bumps[i]]])?;
            let mut marker=a[7+i].try_borrow_mut_data()?;marker[..8].copy_from_slice(b"ZK9NULL1");marker[8..40].copy_from_slice(a[0].key.as_ref());marker[40..104].copy_from_slice(nf);put(&mut marker,104,count);drop(marker);
            let cm=&proof.outputs()[i];
            allocate(&a[4],&a[9+i],&a[5],id,PRIVATE_NOTE_SPACE,&[b"cm",a[0].key.as_ref(),&cm[..32],&cm[32..],&[bumps[2+i]]])?;
            let mut note=a[9+i].try_borrow_mut_data()?;note[..8].copy_from_slice(b"ZK9NOTE1");note[8..40].copy_from_slice(a[0].key.as_ref());put(&mut note,40,count+i as u64);
            note[48..112].copy_from_slice(cm);note[112..176].copy_from_slice(&proof.delivery_digests()[i]);note[176..].copy_from_slice(packets[i]);
        }
        allocate(&a[4],&a[11],&a[5],id,ROOT_SPACE,&[b"root",a[0].key.as_ref(),&nextroot[..32],&nextroot[32..],&[rb]])?;
        write_root(&a[11],a[0].key,&nextroot,count+2)?;
        let nf0=&proof.nullifiers()[0];
        allocate(&a[4],&a[19],&a[5],id,WITHDRAWAL_SPACE,&[b"withdraw",a[0].key.as_ref(),&nf0[..32],&nf0[32..],&[withdraw_bump]])?;
        let mut record=a[19].try_borrow_mut_data()?;record[..8].copy_from_slice(b"ZK9WITH1");record[8..40].copy_from_slice(a[0].key.as_ref());
        record[40..72].copy_from_slice(proof.recipient().as_ref());put(&mut record,72,count);put(&mut record,80,amount);put(&mut record,88,proof.fee());put(&mut record,96,Clock::get()?.slot);
        record[104..136].copy_from_slice(proof.session().as_ref());record[136..200].copy_from_slice(nf0);drop(record);
        put(&mut state,152,backing);put(&mut state,160,fees);put(&mut state,176,withdrawn);put(&mut state,184,withdrawals);accounting(&state)?;
        // Release the pool data borrow before passing the pool PDA as CPI signer.
        // Solana rolls back every record and accounting write if payout fails.
        drop(state);
        let (_,bump)=pool(id,&genesis,a[2].key);
        invoke_signed(&spl_token_2022::instruction::transfer_checked(a[3].key,a[1].key,a[2].key,a[18].key,a[0].key,&[],amount,6)?,
            &[a[1].clone(),a[2].clone(),a[18].clone(),a[0].clone(),a[3].clone()],
            &[&[b"pool",&genesis,a[2].key.as_ref(),&[bump]]])?;
        let after=asset::account(a[1].owner,&a[1].try_borrow_data()?,a[2].key,a[0].key,a[3].key)?;
        let destination_after=asset::account(a[18].owner,&a[18].try_borrow_data()?,a[2].key,proof.recipient(),a[3].key)?;
        if held.checked_sub(after)!=Some(amount) || destination_after.checked_sub(destination_pre)!=Some(amount)
            || after<backing.checked_add(fees).ok_or(e(6))? {return Err(e(9))}
        Ok(())
    })
}
