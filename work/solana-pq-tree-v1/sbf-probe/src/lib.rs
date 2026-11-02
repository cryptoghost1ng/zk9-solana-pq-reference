//! Tree cost/equivalence probe. Arbitrary outputs are allowed for this test;
//! the future pool MUST obtain them from an authenticated completed proof.
#![allow(unexpected_cfgs)]
use solana_program::{account_info::AccountInfo,entrypoint,entrypoint::ProgramResult,program_error::ProgramError,pubkey::Pubkey,rent::Rent,sysvar::Sysvar};
entrypoint!(process);
fn e(n:u32)->ProgramError{ProgramError::Custom(6300+n)}
fn map(e:tree::Error)->ProgramError{ProgramError::Custom(6320+e as u32)}
pub fn process(id:&Pubkey,accounts:&[AccountInfo],input:&[u8])->ProgramResult{
    if accounts.len()!=2 || input.is_empty(){return Err(e(0))}
    let who=&accounts[0];let account=&accounts[1];
    if !who.is_signer{return Err(e(1))}
    if account.owner!=id || !account.is_writable || account.executable || account.data_len()!=32+tree::SPACE{return Err(e(2))}
    let mut data=account.try_borrow_mut_data()?;
    match input[0]{
        0=>{
            if input.len()!=1 || !account.is_signer || data.iter().any(|b|*b!=0){return Err(e(3))}
            if !Rent::get()?.is_exempt(account.lamports(),data.len()){return Err(e(4))}
            tree::initialize(&mut data[32..]).map_err(map)?;data[..32].copy_from_slice(who.key.as_ref());Ok(())
        },
        1|2=>{
            if input.len()!=137{return Err(e(0))}
            if &data[..32]!=who.key.as_ref(){return Err(e(1))}
            let expected=u64::from_le_bytes(input[1..9].try_into().unwrap());
            let pair=[input[9..73].try_into().unwrap(),input[73..137].try_into().unwrap()];
            tree::append_pair(&mut data[32..],expected,&pair).map_err(map)?;
            if input[0]==2{return Err(e(99))} // Deliberate test-only rollback after tree writes.
            Ok(())
        },
        _=>Err(e(0)),
    }
}
