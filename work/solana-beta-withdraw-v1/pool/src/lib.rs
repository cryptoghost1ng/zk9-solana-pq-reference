//! Candidate TEST-FUNDS-ONLY pool with deposit, private send and withdrawal.
//! New isolated program/state format. Runtime qualification is pending.
#![allow(unexpected_cfgs)]
pub mod asset;
#[cfg(not(target_os="solana"))] pub mod fixtures;
#[cfg(test)] mod tests;
mod spend;
mod withdraw;
use solana_program::{account_info::AccountInfo,entrypoint,entrypoint::ProgramResult,
    program::{invoke,invoke_signed},program_error::ProgramError,pubkey::Pubkey,
    rent::Rent,sysvar::Sysvar,clock::Clock,system_program,system_instruction,hash::hashv};
use tiny_keccak::{Hasher,Sha3};
entrypoint!(process);
// Used ONLY by the synthetic fixture generator, never by program admission.
pub const MINT:Pubkey=Pubkey::new_from_array([4;32]);
pub const TREE_AT:usize=192;
pub const SPACE:usize=TREE_AT+tree::SPACE;
pub const NOTE_SPACE:usize=216;
pub const ROOT_SPACE:usize=112;
pub const DEPOSIT_SPACE:usize=96;
fn e(n:u32)->ProgramError{ProgramError::Custom(7500+n)}
pub fn read(b:&[u8],at:usize)->u64{u64::from_le_bytes(b[at..at+8].try_into().unwrap())}
fn put(b:&mut[u8],at:usize,n:u64){b[at..at+8].copy_from_slice(&n.to_le_bytes())}
pub fn pool(id:&Pubkey,genesis:&[u8;32],mint:&Pubkey)->(Pubkey,u8){Pubkey::find_program_address(&[b"pool",genesis,mint.as_ref()],id)}
pub fn vault(id:&Pubkey,pool:&Pubkey)->(Pubkey,u8){Pubkey::find_program_address(&[b"vault",pool.as_ref()],id)}
pub fn record(id:&Pubkey,tag:&[u8],pool:&Pubkey,d:&[u8;64])->(Pubkey,u8){Pubkey::find_program_address(&[tag,pool.as_ref(),&d[..32],&d[32..]],id)}
pub fn deposit_record(id:&Pubkey,pool:&Pubkey,payer:&Pubkey,nonce:u64)->(Pubkey,u8){Pubkey::find_program_address(&[b"deposit",pool.as_ref(),payer.as_ref(),&nonce.to_le_bytes()],id)}
pub fn network(id:&Pubkey,pool:&Pubkey)->[u8;32]{hashv(&[b"ZK9 Solana beta pool context v1",id.as_ref(),pool.as_ref()]).to_bytes()}
/// Exact existing ZK9NOT01 relation encoding. Public opening, never spend secret.
pub fn commitment(network:&[u8;32],genesis:&[u8;32],asset:&Pubkey,note:&[u8])->Result<[u8;64],ProgramError>{
    if note.len()!=104 || note[..64].iter().all(|b|*b==0){return Err(e(3))}
    let mut h=Sha3::v512();h.update(b"ZK9NOT01");h.update(network);h.update(genesis);h.update(asset.as_ref());h.update(note);
    let mut out=[0;64];h.finalize(&mut out);Ok(out)
}
fn fresh(a:&AccountInfo)->ProgramResult{if !a.is_writable || a.executable || a.owner!=&system_program::id() || a.data_len()!=0{return Err(e(4))}Ok(())}
fn address(a:&AccountInfo,p:&Pubkey)->ProgramResult{if a.key!=p || a.executable{return Err(e(2))}Ok(())}
#[inline(never)]
fn allocate<'a>(payer:&AccountInfo<'a>,a:&AccountInfo<'a>,system:&AccountInfo<'a>,owner:&Pubkey,size:usize,seeds:&[&[u8]])->ProgramResult{
    fresh(a)?;let rent=Rent::get()?.minimum_balance(size);
    if a.lamports()<rent{invoke(&system_instruction::transfer(payer.key,a.key,rent-a.lamports()),&[payer.clone(),a.clone(),system.clone()])?;}
    invoke_signed(&system_instruction::allocate(a.key,size as u64),&[a.clone(),system.clone()],&[seeds])?;
    invoke_signed(&system_instruction::assign(a.key,owner),&[a.clone(),system.clone()],&[seeds])
}
fn common(id:&Pubkey,a:&[AccountInfo],genesis:&[u8;32])->ProgramResult{
    if *genesis==[0;32] || !a[0].is_writable || !a[1].is_writable || !a[4].is_signer || !a[4].is_writable
       || a[3].key!=&spl_token_2022::id() || !a[3].executable || a[5].key!=&system_program::id() || !a[5].executable || a[2].executable{return Err(e(1))}
    address(&a[0],&pool(id,genesis,a[2].key).0)?;address(&a[1],&vault(id,a[0].key).0)?;
    asset::mint(a[2].key,a[2].owner,&a[2].try_borrow_data()?,a[2].key,a[3].key)
}
#[inline(never)]
fn initialize(id:&Pubkey,a:&[AccountInfo],genesis:&[u8;32])->ProgramResult{
    // pool, vault, mint, Token2022, signed payer, System, empty-root record.
    common(id,a,genesis)?;fresh(&a[0])?;fresh(&a[1])?;fresh(&a[6])?;
    let root=tree::empty(32);let (rk,rb)=record(id,b"root",a[0].key,&root);address(&a[6],&rk)?;
    let (_,pb)=pool(id,genesis,a[2].key);let (_,vb)=vault(id,a[0].key);
    allocate(&a[4],&a[0],&a[5],id,SPACE,&[b"pool",genesis,a[2].key.as_ref(),&[pb]])?;
    let len=spl_token_2022::extension::ExtensionType::try_calculate_account_len::<spl_token_2022::state::Account>(&[spl_token_2022::extension::ExtensionType::ImmutableOwner])?;
    allocate(&a[4],&a[1],&a[5],a[3].key,len,&[b"vault",a[0].key.as_ref(),&[vb]])?;
    invoke(&spl_token_2022::instruction::initialize_immutable_owner(a[3].key,a[1].key)?,&[a[1].clone(),a[3].clone()])?;
    invoke(&spl_token_2022::instruction::initialize_account3(a[3].key,a[1].key,a[2].key,a[0].key)?,&[a[1].clone(),a[2].clone(),a[3].clone()])?;
    allocate(&a[4],&a[6],&a[5],id,ROOT_SPACE,&[b"root",a[0].key.as_ref(),&root[..32],&root[32..],&[rb]])?;
    let mut state=a[0].try_borrow_mut_data()?;state[..8].copy_from_slice(b"ZK9BETA3");state[8..40].copy_from_slice(genesis);
    state[40..72].copy_from_slice(a[2].key.as_ref());state[72..104].copy_from_slice(a[1].key.as_ref());state[104..136].copy_from_slice(&network(id,a[0].key));
    tree::initialize(&mut state[TREE_AT..]).map_err(|_|e(5))?;
    write_root(&a[6],a[0].key,&root,0)
}
fn write_root(a:&AccountInfo,pool:&Pubkey,root:&[u8;64],count:u64)->ProgramResult{
    let mut b=a.try_borrow_mut_data()?;b[..8].copy_from_slice(b"ZK9ROOT1");b[8..40].copy_from_slice(pool.as_ref());b[40..104].copy_from_slice(root);put(&mut b,104,count);Ok(())
}
/// All value is either private backing, accrued fees, or withdrawn value.
/// Fees remain in custody; this build has no fee collection instruction.
fn accounting(state:&[u8])->Result<u64,ProgramError>{
    if state.len()!=SPACE || &state[..8]!=b"ZK9BETA3"{return Err(e(6))}
    let count=tree::count(&state[TREE_AT..]).map_err(|_|e(5))?;
    let total=read(state,144).checked_add(read(state,168)).and_then(|v|v.checked_add(read(state,184))).and_then(|v|v.checked_mul(2)).ok_or(e(6))?;
    let custody=read(state,152).checked_add(read(state,160)).filter(|v|*v<=asset::CAP).ok_or(e(6))?;
    if total!=count || custody.checked_add(read(state,176))!=Some(read(state,136)){return Err(e(6))}
    Ok(count)
}
#[inline(never)]
fn deposit(id:&Pubkey,a:&[AccountInfo],input:&[u8])->ProgramResult{
    // base6, source token account, note0, note1, next-root, payer/nonce record.
    let genesis:[u8;32]=input[17..49].try_into().unwrap();common(id,a,&genesis)?;
    if a[0].owner!=id || a[0].data_len()!=SPACE || !a[6].is_writable || a[6].key==a[1].key || a[6].executable{return Err(e(6))}
    let nonce=read(input,1);let expected=read(input,9);
    let n0=&input[49..153];let n1=&input[153..257];
    let amount=read(n0,96).checked_add(read(n1,96)).filter(|v|*v>0 && *v<=asset::CAP).ok_or(e(3))?;
    let net=network(id,a[0].key);let cms=[commitment(&net,&genesis,a[2].key,n0)?,commitment(&net,&genesis,a[2].key,n1)?];
    if cms[0]==cms[1]{return Err(e(3))}
    let state=a[0].try_borrow_data()?;
    if &state[..8]!=b"ZK9BETA3" || state[8..40]!=genesis || &state[40..72]!=a[2].key.as_ref()
       || &state[72..104]!=a[1].key.as_ref() || state[104..136]!=net{return Err(e(6))}
    let count=accounting(&state)?;
    let deposited=read(&state,136);let deposits=read(&state,144);let backing=read(&state,152);
    if count!=expected{return Err(e(7))}
    let next=backing.checked_add(amount).filter(|v|*v<=asset::CAP).ok_or(e(3))?;
    let total_deposited=deposited.checked_add(amount).ok_or(e(3))?;
    let custody=backing.checked_add(read(&state,160)).ok_or(e(6))?;
    if custody.checked_add(amount).filter(|v|*v<=asset::CAP).is_none(){return Err(e(3))}
    let pre=asset::account(a[1].owner,&a[1].try_borrow_data()?,a[2].key,a[0].key,a[3].key)?;
    let source_pre=asset::account(a[6].owner,&a[6].try_borrow_data()?,a[2].key,a[4].key,a[3].key)?;
    if pre<custody || source_pre<amount{return Err(e(8))}
    let (dk,db)=deposit_record(id,a[0].key,a[4].key,nonce);address(&a[10],&dk)?;fresh(&a[10])?;
    let mut bumps=[0;2];
    for i in 0..2{let (key,b)=record(id,b"cm",a[0].key,&cms[i]);address(&a[7+i],&key)?;fresh(&a[7+i])?;bumps[i]=b;}
    drop(state);
    // Every state/CPI change below rolls back on any error in the transaction.
    let root={let mut state=a[0].try_borrow_mut_data()?;tree::append_pair(&mut state[TREE_AT..],count,&cms).map_err(|_|e(5))?};
    let (rk,rb)=record(id,b"root",a[0].key,&root);address(&a[9],&rk)?;fresh(&a[9])?;
    invoke(&spl_token_2022::instruction::transfer_checked(a[3].key,a[6].key,a[2].key,a[1].key,a[4].key,&[],amount,6)?,
        &[a[6].clone(),a[2].clone(),a[1].clone(),a[4].clone(),a[3].clone()])?;
    let post=asset::account(a[1].owner,&a[1].try_borrow_data()?,a[2].key,a[0].key,a[3].key)?;
    let source_post=asset::account(a[6].owner,&a[6].try_borrow_data()?,a[2].key,a[4].key,a[3].key)?;
    if post.checked_sub(pre)!=Some(amount) || source_pre.checked_sub(source_post)!=Some(amount){return Err(e(9))}
    for i in 0..2{
        let cm=&cms[i];allocate(&a[4],&a[7+i],&a[5],id,NOTE_SPACE,&[b"cm",a[0].key.as_ref(),&cm[..32],&cm[32..],&[bumps[i]]])?;
        let mut note=a[7+i].try_borrow_mut_data()?;note[..8].copy_from_slice(b"ZK9DEPN1");note[8..40].copy_from_slice(a[0].key.as_ref());put(&mut note,40,count+i as u64);
        note[48..112].copy_from_slice(cm);note[112..].copy_from_slice(if i==0{n0}else{n1});
    }
    allocate(&a[4],&a[9],&a[5],id,ROOT_SPACE,&[b"root",a[0].key.as_ref(),&root[..32],&root[32..],&[rb]])?;
    write_root(&a[9],a[0].key,&root,count+2)?;
    allocate(&a[4],&a[10],&a[5],id,DEPOSIT_SPACE,&[b"deposit",a[0].key.as_ref(),a[4].key.as_ref(),&nonce.to_le_bytes(),&[db]])?;
    let mut d=a[10].try_borrow_mut_data()?;d[..8].copy_from_slice(b"ZK9DEPR1");d[8..40].copy_from_slice(a[0].key.as_ref());d[40..72].copy_from_slice(a[4].key.as_ref());put(&mut d,72,count);put(&mut d,80,amount);put(&mut d,88,Clock::get()?.slot);
    let mut state=a[0].try_borrow_mut_data()?;put(&mut state,136,total_deposited);put(&mut state,144,deposits.checked_add(1).ok_or(e(3))?);put(&mut state,152,next);accounting(&state)?;Ok(())
}
pub fn process(id:&Pubkey,a:&[AccountInfo],input:&[u8])->ProgramResult{
    match input.first(){
        Some(0) if input.len()==33 && a.len()==7=>initialize(id,a,&input[1..33].try_into().unwrap()),
        Some(1) if input.len()==257 && a.len()==11=>deposit(id,a,input),
        Some(2) if input.len()==41 && a.len()==18=>spend::send(id,a,input),
        Some(3) if input.len()==41 && a.len()==20=>withdraw::withdraw(id,a,input),
        _=>Err(e(0)),
    }
}
