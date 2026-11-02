//! Explicitly reviewed transfer semantics, not provenance or finality verification.
use solana_program::{program_error::ProgramError, program_option::COption, program_pack::Pack, pubkey::Pubkey};
use spl_token_2022::{extension::{BaseStateWithExtensions, StateWithExtensions, ExtensionType, metadata_pointer::MetadataPointer}, state::{Mint, Account, AccountState}};
use spl_token_metadata_interface::state::TokenMetadata;

pub const CAP: u64 = 1_000_000_000_000_000;
pub fn e(n:u32)->ProgramError {ProgramError::Custom(7100+n)}

// SDK TLV enumeration stops at Uninitialized. Reject nonzero hidden trailing
// bytes and duplicates rather than approving an ambiguous extension inventory.
fn tlv(data:&[u8], base:usize, kind:u8)->Result<(),ProgramError>{
    if data.len()==base{return Ok(())}
    if data.len()<166 || data[base..165].iter().any(|b|*b!=0) || data[165]!=kind{return Err(e(2))}
    let mut at=166;let mut seen=Vec::new();
    while at<data.len(){
        if data[at..].iter().all(|b|*b==0){return Ok(())}
        if data.len()-at<4{return Err(e(2))}
        let t=u16::from_le_bytes(data[at..at+2].try_into().unwrap());
        let len=u16::from_le_bytes(data[at+2..at+4].try_into().unwrap()) as usize;
        if t==0 || seen.contains(&t) || len>data.len()-at-4{return Err(e(2))}
        seen.push(t);at+=4+len;
    }Ok(())
}

pub fn mint(key:&Pubkey, owner:&Pubkey, data:&[u8], expected:&Pubkey, token:&Pubkey)->Result<(),ProgramError>{
    if key!=expected || owner!=token{return Err(e(1))}
    if data.len()>4096{return Err(e(2))}
    let base=if token==&spl_token::id(){
        if data.len()!=Mint::LEN{return Err(e(2))}
        Mint::unpack(data)?
    }else if token==&spl_token_2022::id(){
        tlv(data,Mint::LEN,1)?;
        let state=StateWithExtensions::<Mint>::unpack(data)?;
        for t in state.get_extension_types()?{
            match t{
                ExtensionType::MetadataPointer=>{
                    let p=state.get_extension::<MetadataPointer>()?;
                    if Option::<Pubkey>::from(p.metadata_address)!=Some(*key){return Err(e(3))}
                    // Metadata authority does not grant token transfer or mint rights.
                },
                ExtensionType::TokenMetadata=>{
                    if state.get_variable_len_extension::<TokenMetadata>()?.mint!=*key{return Err(e(3))}
                },
                _=>return Err(e(4)),
            }
        }state.base
    }else{return Err(e(1))};
    if base.decimals!=6 || base.supply==0 || base.supply>CAP || base.mint_authority!=COption::None || base.freeze_authority!=COption::None{return Err(e(5))}
    Ok(())
}

pub fn account(owner:&Pubkey,data:&[u8],expected_mint:&Pubkey,authority:&Pubkey,token:&Pubkey)->Result<u64,ProgramError>{
    if owner!=token{return Err(e(1))}
    let base=if token==&spl_token::id(){
        if data.len()!=Account::LEN{return Err(e(2))}Account::unpack(data)?
    }else if token==&spl_token_2022::id(){
        tlv(data,Account::LEN,2)?;
        let state=StateWithExtensions::<Account>::unpack(data)?;
        for t in state.get_extension_types()?{
            if t!=ExtensionType::ImmutableOwner{return Err(e(4))}
            state.get_extension::<spl_token_2022::extension::immutable_owner::ImmutableOwner>()?;
        }state.base
    }else{return Err(e(1))};
    if base.mint!=*expected_mint || base.owner!=*authority || base.state!=AccountState::Initialized
        || base.delegate!=COption::None || base.delegated_amount!=0 || base.close_authority!=COption::None || base.is_native!=COption::None{return Err(e(6))}
    Ok(base.amount)
}
