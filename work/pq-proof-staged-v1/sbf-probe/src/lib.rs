//! FORMAT-ONLY session over immutable sealed buffer bytes. No payment authority.
#![allow(unexpected_cfgs)]
use solana_program::{account_info::AccountInfo,entrypoint,entrypoint::ProgramResult,program_error::ProgramError,pubkey::Pubkey,rent::Rent,sysvar::Sysvar,bpf_loader_upgradeable};
use zk9_proof_staged::{Reader,CHECKPOINT_BYTES,MAX_STEP,MAX_BYTES};
entrypoint!(process);
const BUFFER_ID:Pubkey=Pubkey::new_from_array([231,138,104,189,143,12,113,233,104,11,207,43,153,194,139,84,167,203,114,202,199,220,160,15,198,101,146,200,130,3,130,73]);
const MAGIC:&[u8;8]=b"ZK9SCAN1";
const BASE:usize=128;
pub const SPACE:usize=BASE+CHECKPOINT_BYTES;
fn e(n:u32)->ProgramError{ProgramError::Custom(2000+n)}
fn n(b:&[u8])->usize{u32::from_le_bytes(b.try_into().unwrap())as usize}
fn sealed(source:&AccountInfo,owner:&AccountInfo,code:&AccountInfo,data:&[u8])->Result<usize,ProgramError>{
 if source.owner!=&BUFFER_ID||source.executable||source.is_writable{return Err(e(6))}
 // The known transport program must be immutable. Otherwise its authority could
 // modify sealed bytes without changing the root header between scanning steps.
 if owner.key!=&BUFFER_ID||!owner.executable||owner.owner!=&bpf_loader_upgradeable::id()||owner.is_writable||code.owner!=&bpf_loader_upgradeable::id()||code.executable||code.is_writable{return Err(e(7))}
 let program=owner.try_borrow_data()?;let program_data=code.try_borrow_data()?;
 if program.len()!=36||n(&program[..4])!=2||&program[4..36]!=code.key.as_ref()||program_data.len()<45||n(&program_data[..4])!=3||program_data[12]!=0{return Err(e(7))}
 if data.len()<85||&data[..8]!=b"ZK9BUF1\0"||data[80]!=2||data[81..85]!=[0;4]{return Err(e(8))}
 let total=n(&data[40..44]);if total<=3904||total>3904+MAX_BYTES{return Err(e(8))}
 let count=(total+899)/900;let start=85+(count+7)/8+32*count;
 if data.len()!=start+total||n(&data[44..48])!=count{return Err(e(8))}
 let wire=&data[start..];if &wire[..8]!=b"ZK9PQS2\0"||wire[8..12]!=2u32.to_le_bytes()||n(&wire[436..440])!=total-3904{return Err(e(9))}
 Ok(start+3904)
}
pub fn process(id:&Pubkey,accounts:&[AccountInfo],input:&[u8])->ProgramResult{
 if accounts.len()!=5||input.is_empty(){return Err(e(0))}
 let state=&accounts[0];let source=&accounts[1];let authority=&accounts[2];
 if state.owner!=id||state.executable||!state.is_writable||state.data_len()!=SPACE||state.key==source.key||state.key==authority.key{return Err(e(1))}
 if !authority.is_signer{return Err(e(2))}
 let mut saved=state.try_borrow_mut_data()?;
 if input[0]==0{
  if input.len()!=1||!state.is_signer{return Err(e(3))}
  if saved.iter().any(|x|*x!=0)||!Rent::get()?.is_exempt(state.lamports(),SPACE){return Err(e(4))}
 }else{
  if &saved[..8]!=MAGIC||saved[112..BASE].iter().any(|b|*b!=0){return Err(e(5))}
  if &saved[8..40]!=authority.key.as_ref(){return Err(e(2))}
 }
 if input[0]==2{
  if input.len()!=1||!authority.is_writable{return Err(e(3))}
  let balance=authority.lamports().checked_add(state.lamports()).ok_or(e(15))?;
  drop(saved);state.resize(0)?;state.assign(&solana_program::system_program::id());
  **authority.try_borrow_mut_lamports()?=balance;**state.try_borrow_mut_lamports()?=0;return Ok(())
 }
 let data=source.try_borrow_data()?;let offset=sealed(source,&accounts[3],&accounts[4],&data)?;
 let bytes=&data[offset..];
 match input[0]{
  0=>{
   let reader=Reader::new(bytes).map_err(|_|e(9))?;
   saved[..8].copy_from_slice(MAGIC);saved[8..40].copy_from_slice(authority.key.as_ref());saved[40..72].copy_from_slice(source.key.as_ref());saved[72..104].copy_from_slice(&data[48..80]);saved[104..108].copy_from_slice(&data[40..44]);
   reader.checkpoint(&mut saved[BASE..]).map_err(|_|e(5))?;
   solana_program::msg!("ZK9 FORMAT session initialized; no cryptographic authorization");Ok(())
  },
  1=>{
   if input.len()!=9{return Err(e(3))}
   if &saved[40..72]!=source.key.as_ref()||saved[72..104]!=data[48..80]||saved[104..108]!=data[40..44]{return Err(e(10))}
   let sequence=n(&saved[108..112]);if n(&input[1..5])!=sequence{return Err(e(11))}
   let limit=n(&input[5..9]);if limit==0||limit>MAX_STEP as usize{return Err(e(14))}
   let mut reader=Reader::resume_trusted(bytes,&saved[BASE..]).map_err(|_|e(5))?;
   if reader.done(){return Err(e(13))}
   let done=reader.advance(limit as u32).map_err(|_|e(12))?;
   reader.checkpoint(&mut saved[BASE..]).map_err(|_|e(5))?;
   saved[108..112].copy_from_slice(&u32::try_from(sequence+1).map_err(|_|e(15))?.to_le_bytes());
   if done{solana_program::msg!("ZK9 FORMAT COMPLETE ONLY; NOT A VERIFIED PROOF");}Ok(())
  },_=>Err(e(3))
 }
}
