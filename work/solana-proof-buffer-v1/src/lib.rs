//! Local transport experiment ONLY. A sealed buffer is NOT a verified ZK proof.
//! No tokens, deposits, withdrawals, bridge claims or verifier-authority shortcuts.
#![allow(unexpected_cfgs)]
use solana_program::{account_info::AccountInfo, entrypoint, entrypoint::ProgramResult,
    hash::hashv, program_error::ProgramError, pubkey::Pubkey, rent::Rent, sysvar::Sysvar};
entrypoint!(process_instruction);
const MAGIC: &[u8;8]=b"ZK9BUF1\0";
pub const CHUNK:usize=900;
pub const MAX:usize=5*1024*1024;
pub const HEADER:usize=85; // magic8, authority32, total4, received4, root32, state1
fn fail(code:u32)->ProgramError {ProgramError::Custom(1000+code)}
fn number(b:&[u8])->usize {u32::from_le_bytes(b.try_into().unwrap()) as usize}
fn layout(total:usize)->Result<(usize,usize,usize),ProgramError>{
    if total==0||total>MAX{return Err(fail(1))}
    let count=(total+CHUNK-1)/CHUNK;
    let hash_start=HEADER+(count+7)/8;
    Ok((count,hash_start,hash_start+32*count))
}
pub fn process_instruction(program:&Pubkey,accounts:&[AccountInfo],input:&[u8])->ProgramResult{
    if accounts.len()!=2||input.is_empty(){return Err(fail(2))}
    let buffer=&accounts[0];let authority=&accounts[1];
    if buffer.owner!=program||buffer.executable||!buffer.is_writable||!authority.is_signer||buffer.key==authority.key{return Err(fail(3))}
    let op=input[0];
    if op==0 {
        if input.len()!=37||!buffer.is_signer{return Err(fail(4))}
        let total=number(&input[1..5]);let (_,_,start)=layout(total)?;
        if buffer.data_len()!=start+total||!Rent::get()?.is_exempt(buffer.lamports(),buffer.data_len()){return Err(fail(5))}
        let mut data=buffer.try_borrow_mut_data()?;
        if data[..HEADER].iter().any(|b|*b!=0){return Err(fail(6))}
        // Only this program can write its data; no instruction writes before init.
        // System Program creation/allocate zeroes a new account. Close shrinks to 0.
        data[..8].copy_from_slice(MAGIC);data[8..40].copy_from_slice(authority.key.as_ref());
        data[40..44].copy_from_slice(&input[1..5]);data[48..80].copy_from_slice(&input[5..37]);data[80]=1;
        return Ok(())
    }
    if buffer.data_len()<HEADER{return Err(fail(7))}
    {
        let data=buffer.try_borrow_data()?;
        if &data[..8]!=MAGIC||&data[8..40]!=authority.key.as_ref()||data[81..85]!=[0;4]{return Err(fail(8))}
    }
    if op==3 {
        if input.len()!=1||!authority.is_writable{return Err(fail(9))}
        let balance=authority.lamports().checked_add(buffer.lamports()).ok_or(fail(10))?;
        buffer.resize(0)?;buffer.assign(&solana_program::system_program::id());
        **authority.try_borrow_mut_lamports()?=balance;**buffer.try_borrow_mut_lamports()?=0;
        return Ok(())
    }
    let mut data=buffer.try_borrow_mut_data()?;
    let total=number(&data[40..44]);let (count,hash_start,start)=layout(total)?;
    if data.len()!=start+total||number(&data[44..48])>count||![1,2].contains(&data[80]){return Err(fail(11))}
    match op {
        1=>{
            if data[80]!=1||input.len()<5{return Err(fail(12))}
            let index=number(&input[1..5]);if index>=count{return Err(fail(13))}
            let offset=index*CHUNK;let size=CHUNK.min(total-offset);
            if input.len()!=5+size{return Err(fail(14))}
            let slot=HEADER+index/8;let mask=1<<(index%8);
            if data[slot]&mask!=0 {
                if data[start+offset..start+offset+size]!=input[5..]{return Err(fail(15))}
                return Ok(()) // Exact retry does not increment receipt count.
            }
            let total_bytes=(total as u32).to_le_bytes();
            let digest=hashv(&[b"ZK9/SOLANA/BUFFER/LEAF/v1\0",&total_bytes,&input[1..5],&input[5..]]);
            data[start+offset..start+offset+size].copy_from_slice(&input[5..]);
            data[hash_start+32*index..hash_start+32*(index+1)].copy_from_slice(digest.as_ref());
            data[slot]|=mask;let received=(number(&data[44..48])+1) as u32;data[44..48].copy_from_slice(&received.to_le_bytes());
            Ok(())
        },
        2=>{
            if input.len()!=1||number(&data[44..48])!=count{return Err(fail(16))}
            if data[80]==2{return Ok(())}
            let total_bytes=(total as u32).to_le_bytes();
            let digest=hashv(&[b"ZK9/SOLANA/BUFFER/ROOT/v1\0",&total_bytes,&data[hash_start..start]]);
            if digest.as_ref()!=&data[48..80]{return Err(fail(17))}
            data[80]=2;Ok(()) // SEALED_BYTES_ONLY: no proof-verification instruction.
        },
        _=>Err(fail(18))
    }
}
