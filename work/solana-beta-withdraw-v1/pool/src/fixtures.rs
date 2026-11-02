//! Public synthetic bytes serialized by the pinned official token libraries.
use solana_program::{program_option::COption, program_pack::Pack, pubkey::Pubkey};
use spl_token_2022::{state::{Mint, Account, AccountState}, extension::{StateWithExtensionsMut, BaseStateWithExtensionsMut, ExtensionType, metadata_pointer::MetadataPointer}};
use spl_token_metadata_interface::state::TokenMetadata;
use crate::{MINT,asset::CAP};
pub fn base_mint()->Mint{Mint{mint_authority:COption::None,supply:CAP,decimals:6,is_initialized:true,freeze_authority:COption::None}}
pub fn metadata_mint()->Vec<u8>{
    let mut b=vec![0;1024];
    let mut s=StateWithExtensionsMut::<Mint>::unpack_uninitialized(&mut b).unwrap();
    s.base=base_mint();
    let p=s.init_extension::<MetadataPointer>(false).unwrap();p.metadata_address=Some(MINT).try_into().unwrap();
    s.init_variable_len_extension(&TokenMetadata{mint:MINT,name:"ZK9 synthetic fixture".into(),symbol:"TEST".into(),uri:"https://example.invalid/fixture".into(),..Default::default()},false).unwrap();
    s.pack_base();s.init_account_type().unwrap();b
}
pub fn token_account(authority:Pubkey,amount:u64)->Vec<u8>{
    let mut b=vec![0;Account::LEN];
    Account::pack(Account{mint:MINT,owner:authority,amount,delegate:COption::None,state:AccountState::Initialized,is_native:COption::None,delegated_amount:0,close_authority:COption::None},&mut b).unwrap();b
}
pub fn extension_mint(t:ExtensionType)->Vec<u8>{
    let len=ExtensionType::try_calculate_account_len::<Mint>(&[t]).unwrap();
    let mut b=vec![0;len];Mint::pack(base_mint(),&mut b[..82]).unwrap();b[165]=1;
    b[166..168].copy_from_slice(&u16::from(t).to_le_bytes());
    b[168..170].copy_from_slice(&((len-170) as u16).to_le_bytes());b
}
