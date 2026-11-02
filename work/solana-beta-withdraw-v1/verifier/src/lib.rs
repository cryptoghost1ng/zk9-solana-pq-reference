//! Candidate withdrawal32 SBF verifier. Not yet qualified.
//! Adapted immutable source/context checks; payout authorization is separate.
#![allow(unexpected_cfgs)]
use solana_program::{account_info::AccountInfo,entrypoint,entrypoint::ProgramResult,program_error::ProgramError,pubkey::Pubkey,rent::Rent,sysvar::Sysvar,bpf_loader_upgradeable};
use fri::scan::{Reader,CHECKPOINT_BYTES,MAX_STEP,MAX_BYTES};
entrypoint!(process);
const BUFFER_ID:Pubkey=Pubkey::new_from_array([231,138,104,189,143,12,113,233,104,11,207,43,153,194,139,84,167,203,114,202,199,220,160,15,198,101,146,200,130,3,130,73]);
const MAGIC:&[u8;8]=b"ZK9PRFW2";
// Budget multiplier for scan, input MMCS and round MMCS (each inner call keeps the crate cap).
const PACK:usize=4;
const BASE:usize=128;
const FORMAT_END:usize=BASE+CHECKPOINT_BYTES;
const PREFIX_END:usize=FORMAT_END+candidate::RESULT_BYTES;
const PCS_END:usize=PREFIX_END+opening::CHECKPOINT_BYTES;
const INDEX_END:usize=PCS_END+fri::INDEX_BYTES;
const FRI_END:usize=INDEX_END+fri::RESULT_BYTES;
const VIEW_END:usize=FRI_END+mmcs::VIEW_BYTES;
const BATCH_INDEX:usize=VIEW_END+3*mmcs::STATE_BYTES;
const ROUND_INDEX:usize=BATCH_INDEX+24;
const CONTROL:usize=ROUND_INDEX+104;
const REDUCE:usize=CONTROL+16;
const FOLD:usize=REDUCE+arithmetic::reduce::STATE_BYTES;
const FRONTIER:usize=FOLD+arithmetic::fold::STATE_BYTES;
const ROOTS:usize=FRONTIER+round_mmcs::STATE_BYTES;
const AIR_CONTROL:usize=ROOTS+13*64;
const PUBLIC_CACHE:usize=AIR_CONTROL+16;
const SELECTORS:usize=PUBLIC_CACHE+air::PUBLIC*4;
const QUOTIENT:usize=SELECTORS+128;
const AIR_STATE:usize=QUOTIENT+32;
// Size is derived from the immutable, qualified compiler output, never caller input.
const AIR_SCRATCH_BYTES:usize=256+((SCHEDULE[20]as usize)|((SCHEDULE[21]as usize)<<8)|((SCHEDULE[22]as usize)<<16)|((SCHEDULE[23]as usize)<<24))*32;
pub const SPACE:usize=AIR_STATE+AIR_SCRATCH_BYTES;
const SCHEDULE:&[u8]=include_bytes!("../../generated/schedule.bin");
// Use the runtime comparison syscall rather than a VM byte loop for large
// zero accounts. This retains the complete zero-state requirement.
#[inline(never)]
fn all_zero(bytes:&[u8])->bool{const ZERO:[u8;1024]=[0;1024];bytes.chunks(1024).all(|part|solana_program::program_memory::sol_memcmp(part,&ZERO,part.len())==0)}
struct IndexedScan{fri:fri::Index,batches:[fri::scan::Span;3],rounds:[fri::scan::Span;13]}
impl<'a>fri::scan::Observe<'a> for IndexedScan{fn node(&mut self,parent:u8,index:u32,span:fri::scan::Span){self.fri.node(parent,index,span);if parent==22&&index<3{self.batches[index as usize]=span;}if parent==24&&index<13{self.rounds[index as usize]=span;}}}
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
 let total=n(&data[40..44]);if total<=3945||total>3945+MAX_BYTES{return Err(e(8))}
 let count=(total+899)/900;let start=85+(count+7)/8+32*count;
 if data.len()!=start+total||n(&data[44..48])!=count{return Err(e(8))}
 let wire=&data[start..];if &wire[..8]!=b"ZK9PQW2\0"||wire[8..12]!=2u32.to_le_bytes()||n(&wire[477..481])!=total-3945{return Err(e(9))}
 Ok(start+3945)
}
// Read context only from the already sealed source. Public values are bound
// by the transcript and AIR; accepting a proof does not authorize any pool.
fn wire_context(wire:&[u8])->Result<candidate::Context,ProgramError>{
 if wire.len()<108{return Err(e(19))}
 let network=wire[12..44].try_into().unwrap();let genesis=wire[44..76].try_into().unwrap();let asset=wire[76..108].try_into().unwrap();
 if network==[0;32]||genesis==[0;32]||asset==[0;32]{return Err(e(19))}
 Ok(candidate::Context{network,genesis,asset})
}
pub fn process(id:&Pubkey,accounts:&[AccountInfo],input:&[u8])->ProgramResult{
 if accounts.len()!=5||input.is_empty(){return Err(e(0))}
 let state=&accounts[0];let source=&accounts[1];let authority=&accounts[2];
 if state.owner!=id||state.executable||!state.is_writable||state.data_len()!=SPACE||state.key==source.key||state.key==authority.key{return Err(e(1))}
 if !authority.is_signer{return Err(e(2))}
 let mut saved=state.try_borrow_mut_data()?;
 if input[0]==0{
  if input.len()!=1||!state.is_signer{return Err(e(3))}
  if !all_zero(&saved)||!Rent::get()?.is_exempt(state.lamports(),SPACE){return Err(e(4))}
 }else{
  if &saved[..8]!=MAGIC||saved[124..BASE].iter().any(|b|*b!=0){return Err(e(5))}
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
 if input[0]!=0&&(&saved[40..72]!=source.key.as_ref()||saved[72..104]!=data[48..80]||saved[104..108]!=data[40..44]){return Err(e(10))}
 if input[0]==3{
  if input.len()!=1{return Err(e(3))}
  if saved[FORMAT_END..PREFIX_END].iter().any(|x|*x!=0){return Err(e(18))}
  let expected=wire_context(&data[offset-3945..])?;
  // Source binding and ownership checked above. These bytes come only from our
  // stored completed scan, never an instruction-supplied cursor or hash state.
  let prefix=candidate::derive(&expected,&data[offset-3945..],&saved[BASE..FORMAT_END]).map_err(|x|match x{candidate::Error::FormatState=>e(16),candidate::Error::Context=>e(19),_=>e(17)})?;
  prefix.encode(&mut saved[FORMAT_END..PREFIX_END]).map_err(|_|e(17))?;
  solana_program::msg!("ZK9 TRANSCRIPT PREFIX DERIVED; FULL PROOF NOT VERIFIED");return Ok(())
 }

 if input[0]==4{
  if input.len()!=9{return Err(e(3))}
  let sequence=n(&saved[112..116]);if n(&input[1..5])!=sequence{return Err(e(20))}
  let limit=n(&input[5..9]);if limit==0||limit>opening::MAX_STEP{return Err(e(21))}
  let claims=opening::Claims::from_trusted_format(&data[offset-3945..],&saved[BASE..FORMAT_END]).map_err(|_|e(22))?;
  let mut progress=if saved[PREFIX_END..PCS_END].iter().all(|x|*x==0){
   if sequence!=0{return Err(e(23))}
   opening::Progress::start(&saved[FORMAT_END..PREFIX_END]).map_err(|_|e(23))?
  }else{opening::Progress::resume_trusted(&saved[PREFIX_END..PCS_END]).map_err(|_|e(23))?};
  if progress.done(){return Err(e(24))}
  let done=progress.advance(&claims,limit).map_err(|_|e(25))?;
  progress.checkpoint(&mut saved[PREFIX_END..PCS_END]).map_err(|_|e(23))?;
  saved[112..116].copy_from_slice(&u32::try_from(sequence+1).map_err(|_|e(15))?.to_le_bytes());
  if done{solana_program::msg!("ZK9 PCS TRANSCRIPT COMPLETE; MERKLE/FRI/AIR NOT VERIFIED");}return Ok(())
 }

 if input[0]==5{
  if input.len()!=1{return Err(e(3))}
  if saved[INDEX_END..FRI_END].iter().any(|x|*x!=0){return Err(e(26))}
  let transcript=fri::derive(&data[offset-3945..],&saved[BASE..FORMAT_END],&saved[PCS_END..INDEX_END],&saved[PREFIX_END..PCS_END]).map_err(|x|match x{fri::Error::State=>e(27),_=>e(28)})?;
  transcript.encode(&mut saved[INDEX_END..FRI_END]).map_err(|_|e(28))?;
  solana_program::msg!("ZK9 FRI TRANSCRIPT DERIVED; MERKLE/FOLDS/AIR NOT VERIFIED");return Ok(())
 }

 if (14..=17).contains(&input[0]){return air_stage(&data[offset-3945..],&mut saved,input)}
 if (8..=13).contains(&input[0]){return extension(&data[offset-3945..],&mut saved,input)}
 if input[0]==6{return start_mmcs(&data[offset-3945..],&mut saved,input)}
 if input[0]==7{return advance_mmcs(&data[offset-3945..],&mut saved,input)}
 match input[0]{
  0=>{
   let reader=Reader::new(bytes).map_err(|_|e(9))?;
   saved[..8].copy_from_slice(MAGIC);saved[8..40].copy_from_slice(authority.key.as_ref());saved[40..72].copy_from_slice(source.key.as_ref());saved[72..104].copy_from_slice(&data[48..80]);saved[104..108].copy_from_slice(&data[40..44]);
   reader.checkpoint(&mut saved[BASE..FORMAT_END]).map_err(|_|e(5))?;
   solana_program::msg!("ZK9 FORMAT session initialized; no cryptographic authorization");Ok(())
  },
  1=>{
   if input.len()!=9{return Err(e(3))}
   if &saved[40..72]!=source.key.as_ref()||saved[72..104]!=data[48..80]||saved[104..108]!=data[40..44]{return Err(e(10))}
   let sequence=n(&saved[108..112]);if n(&input[1..5])!=sequence{return Err(e(11))}
   let limit=n(&input[5..9]);if limit==0||limit>PACK*MAX_STEP as usize{return Err(e(14))}
   let mut reader=Reader::resume_trusted(bytes,&saved[BASE..FORMAT_END]).map_err(|_|e(5))?;
   if reader.done(){return Err(e(13))}
   let mut index=IndexedScan{fri:fri::Index::resume_trusted(&saved[PCS_END..INDEX_END],&reader).map_err(|_|e(29))?,batches:core::array::from_fn(|i|fri::scan::Span{start:n(&saved[BATCH_INDEX+i*8..BATCH_INDEX+i*8+4])as u32,end:n(&saved[BATCH_INDEX+i*8+4..BATCH_INDEX+i*8+8])as u32}),rounds:core::array::from_fn(|i|fri::scan::Span{start:n(&saved[ROUND_INDEX+i*8..ROUND_INDEX+i*8+4])as u32,end:n(&saved[ROUND_INDEX+i*8+4..ROUND_INDEX+i*8+8])as u32})};
   let mut left=limit as u32;let mut done=false;
   while left>0&&!done{let step=left.min(MAX_STEP);done=reader.advance_with(step,&mut index).map_err(|_|e(12))?;left-=step;}
   index.fri.validate(&reader).map_err(|_|e(29))?;
   index.fri.checkpoint(&mut saved[PCS_END..INDEX_END]).map_err(|_|e(29))?;
   for(span,out)in index.batches.iter().zip(saved[BATCH_INDEX..ROUND_INDEX].chunks_exact_mut(8)){out[..4].copy_from_slice(&span.start.to_le_bytes());out[4..].copy_from_slice(&span.end.to_le_bytes());}
   for(span,out)in index.rounds.iter().zip(saved[ROUND_INDEX..CONTROL].chunks_exact_mut(8)){out[..4].copy_from_slice(&span.start.to_le_bytes());out[4..].copy_from_slice(&span.end.to_le_bytes());}
   reader.checkpoint(&mut saved[BASE..FORMAT_END]).map_err(|_|e(5))?;
   saved[108..112].copy_from_slice(&u32::try_from(sequence+1).map_err(|_|e(15))?.to_le_bytes());
   if done{solana_program::msg!("ZK9 FORMAT COMPLETE ONLY; NOT A VERIFIED PROOF");}Ok(())
  },_=>Err(e(3))
 }
}
#[inline(never)]
fn start_mmcs(wire:&[u8],saved:&mut[u8],input:&[u8])->ProgramResult{
 if input.len()!=1{return Err(e(3))}if saved[FRI_END..BATCH_INDEX].iter().any(|x|*x!=0){return Err(e(30))}
 let loaded=Box::new(mmcs::Views::from_trusted_indexed_scan(wire,&saved[BASE..FORMAT_END],&saved[PCS_END..INDEX_END],&saved[INDEX_END..FRI_END],&saved[BATCH_INDEX..ROUND_INDEX]));
 let views=loaded.as_ref().as_ref().map_err(|_|e(31))?;
 views.checkpoint(&mut saved[FRI_END..VIEW_END]).map_err(|_|e(31))?;
 mmcs::Progress::start(&mut saved[VIEW_END..VIEW_END+mmcs::STATE_BYTES],&views,0).map_err(|_|e(32))?;Ok(())
}
#[inline(never)]
fn advance_mmcs(wire:&[u8],saved:&mut[u8],input:&[u8])->ProgramResult{
 if input.len()!=13{return Err(e(3))}let seq=n(&saved[116..120]);if n(&input[1..5])!=seq{return Err(e(33))}
 let fields=n(&input[5..9]);let parents=n(&input[9..13]);if fields<2||fields>PACK*mmcs::MAX_FIELDS||parents==0||parents>PACK*mmcs::MAX_PARENTS{return Err(e(34))}
 let batch=n(&saved[120..124]);if batch>=3{return Err(e(35))}
 // Index was derived by our scanner and remains in this program-owned account.
 let start=n(&saved[PCS_END+32..PCS_END+36]);let end=n(&saved[PCS_END+36..PCS_END+40]);
 let bytes=wire.get(3945+start..3945+end).ok_or(e(31))?;
 let loaded=Box::new(mmcs::Views::resume_trusted(bytes,&saved[FRI_END..VIEW_END]));
 let v=loaded.as_ref().as_ref().map_err(|_|e(31))?;
 let at=VIEW_END+batch*mmcs::STATE_BYTES;
 let mut p=mmcs::Progress::resume_trusted(&mut saved[at..at+mmcs::STATE_BYTES]).map_err(|_|e(32))?;
 let(mut fields_left,mut parents_left,mut done)=(fields,parents,false);
 while !done&&fields_left>=2&&parents_left>0{let f=fields_left.min(mmcs::MAX_FIELDS);let q=parents_left.min(mmcs::MAX_PARENTS);done=p.advance(&v,f,q).map_err(|_|e(36))?;fields_left-=f;parents_left-=q;}
 saved[116..120].copy_from_slice(&u32::try_from(seq+1).map_err(|_|e(15))?.to_le_bytes());
 if done{saved[120..124].copy_from_slice(&((batch+1)as u32).to_le_bytes());if batch<2{mmcs::Progress::start(&mut saved[at+mmcs::STATE_BYTES..at+2*mmcs::STATE_BYTES],&v,batch+1).map_err(|_|e(32))?;}else{solana_program::msg!("ZK9 INPUT ROOTS AUTHENTICATED; FRI FOLDS/AIR/SPEND NOT VERIFIED");}}
 Ok(())
}

// Extension phases:0input authentication not yet handed off;1reduce;2reduced;
// 3fold;4round initialization;5round traversal;6PCS verified (NOT AIR or payment).
#[inline(never)]
fn extension(wire:&[u8],saved:&mut[u8],input:&[u8])->ProgramResult{
 if input.len()!=9{return Err(e(3))}
 let sequence=n(&saved[CONTROL..CONTROL+4]);
 if n(&input[1..5])!=sequence||sequence==u32::MAX as usize{return Err(e(39))}
 if saved[CONTROL+12..REDUCE]!=[0;4]{return Err(e(41))}
 let phase=n(&saved[CONTROL+4..CONTROL+8]);let round=n(&saved[CONTROL+8..CONTROL+12]);
 if phase>6||round>13{return Err(e(41))}
 let expected=match input[0]{8=>0,9=>1,10=>2,11=>3,12=>4,13=>5,_=>return Err(e(3))};
 if phase!=expected||(input[0]==8&&n(&saved[120..124])!=3)||(input[0]>=12&&round>=13){return Err(e(38))}
 let work=n(&input[5..9]);
 match input[0]{
  8=>{if work!=0{return Err(e(40))}start_reduction(wire,saved)?;put(saved,CONTROL+4,1);},
  9=>{if advance_reduction(wire,saved,work)?{put(saved,CONTROL+4,2);}},
  10=>{if work!=0{return Err(e(40))}start_fold(saved)?;put(saved,CONTROL+4,3);},
  11=>{if advance_fold(wire,saved,work)?{put(saved,CONTROL+4,4);}},
  12=>{if work!=0{return Err(e(40))}round_start(wire,saved,round)?;put(saved,CONTROL+4,5);},
  13=>{if round_advance(wire,saved,round,work)?{put(saved,CONTROL+8,round+1);put(saved,CONTROL+4,if round==12{6}else{4});}},
  _=>return Err(e(3))
 }
 put(saved,CONTROL,sequence+1);
 if n(&saved[CONTROL+4..CONTROL+8])==6{solana_program::msg!("ZK9 PCS VERIFIED; AIR/QUOTIENT AND SPEND NOT VERIFIED");}
 Ok(())
}
fn put(b:&mut[u8],at:usize,x:usize){b[at..at+4].copy_from_slice(&(x as u32).to_le_bytes());}
#[inline(never)]
fn start_reduction(wire:&[u8],saved:&mut[u8])->ProgramResult{
 let(head,body)=saved.split_at_mut(REDUCE);let(pre,auth)=head.split_at_mut(VIEW_END);
 let start=n(&pre[PCS_END+32..PCS_END+36]);let end=n(&pre[PCS_END+36..PCS_END+40]);
 let bytes=wire.get(3945+start..3945+end).ok_or(e(41))?;
 let loaded=Box::new(mmcs::Views::resume_trusted(bytes,&pre[FRI_END..VIEW_END]));let views=loaded.as_ref().as_ref().map_err(|_|e(41))?;
 arithmetic::reduce::Progress::start(&mut body[..arithmetic::reduce::STATE_BYTES],&pre[FORMAT_END..PREFIX_END],&pre[PREFIX_END..PCS_END],views,&mut auth[..3*mmcs::STATE_BYTES]).map_err(|_|e(42))?;
 Ok(())
}
#[inline(never)]
fn advance_reduction(wire:&[u8],saved:&mut[u8],work:usize)->Result<bool,ProgramError>{
 let(head,body)=saved.split_at_mut(REDUCE);
 let start=n(&head[PCS_END+32..PCS_END+36]);let end=n(&head[PCS_END+36..PCS_END+40]);
 let bytes=wire.get(3945+start..3945+end).ok_or(e(41))?;
 let loaded=Box::new(mmcs::Views::resume_trusted(bytes,&head[FRI_END..VIEW_END]));let views=loaded.as_ref().as_ref().map_err(|_|e(41))?;
 let claims=arithmetic::claims::Claims::from_trusted_format(wire,&head[BASE..FORMAT_END]).map_err(|_|e(41))?;
 let mut p=arithmetic::reduce::Progress::resume_trusted(&mut body[..arithmetic::reduce::STATE_BYTES]).map_err(|_|e(41))?;
 p.advance(&claims,views,work).map_err(|x|if x==arithmetic::Error::Limit{e(40)}else{e(42)})
}
#[inline(never)]
fn start_fold(saved:&mut[u8])->ProgramResult{
 let(head,body)=saved.split_at_mut(REDUCE);let(reduced,body)=body.split_at_mut(arithmetic::reduce::STATE_BYTES);
 arithmetic::fold::Progress::start(&mut body[..arithmetic::fold::STATE_BYTES],reduced,&head[INDEX_END..FRI_END]).map_err(|_|e(42))?;Ok(())
}
#[inline(never)]
fn advance_fold(wire:&[u8],saved:&mut[u8],work:usize)->Result<bool,ProgramError>{
 let(head,body)=saved.split_at_mut(FOLD);let mut p=arithmetic::fold::Progress::resume_trusted(&mut body[..arithmetic::fold::STATE_BYTES]).map_err(|_|e(41))?;
 let round=arithmetic::fold::Round::from_trusted_scan(wire,&head[BASE..FORMAT_END],&head[PCS_END..INDEX_END],&head[ROUND_INDEX..CONTROL],p.round()).map_err(|_|e(41))?;
 let loaded=Box::new(fri::Views::from_trusted_scan(wire,&head[BASE..FORMAT_END],&head[PCS_END..INDEX_END]));let views=loaded.as_ref().as_ref().map_err(|_|e(41))?;
 let mut poly=arithmetic::field::Ext::ZERO;
 for (i,x) in views.final_poly.iter().enumerate(){poly.0[i]=arithmetic::field::F::from_montgomery(*x).map_err(|_|e(41))?;}
 p.advance(&round,poly,work).map_err(|x|if x==arithmetic::Error::Limit{e(40)}else{e(42)})
}
#[inline(never)]
fn round_start(wire:&[u8],saved:&mut[u8],round:usize)->ProgramResult{
 let(head,body)=saved.split_at_mut(FOLD);let(folded,body)=body.split_at_mut(arithmetic::fold::STATE_BYTES);let frontier=&mut body[..round_mmcs::STATE_BYTES];
 let view=round_mmcs::View::from_trusted_scan(wire,&head[BASE..FORMAT_END],&head[PCS_END..INDEX_END],&head[ROUND_INDEX..CONTROL],folded,round).map_err(|_|e(41))?;
 frontier.fill(0);round_mmcs::Progress::start(frontier,&view).map_err(|_|e(42))?;Ok(())
}
#[inline(never)]
fn round_advance(wire:&[u8],saved:&mut[u8],round:usize,work:usize)->Result<bool,ProgramError>{
 let(head,body)=saved.split_at_mut(FOLD);let(folded,body)=body.split_at_mut(arithmetic::fold::STATE_BYTES);let(frontier,roots)=body.split_at_mut(round_mmcs::STATE_BYTES);
 let view=round_mmcs::View::from_trusted_scan(wire,&head[BASE..FORMAT_END],&head[PCS_END..INDEX_END],&head[ROUND_INDEX..CONTROL],folded,round).map_err(|_|e(41))?;
 let mut p=round_mmcs::Progress::resume_trusted(frontier).map_err(|_|e(41))?;
 if work==0||work>PACK*round_mmcs::MAX_LEAVES{return Err(e(40))}
 let(mut left,mut done)=(work,false);
 while left>0&&!done{let w=left.min(round_mmcs::MAX_LEAVES);done=p.advance(&view,w,32).map_err(|x|if x==round_mmcs::Error::Limit{e(40)}else{e(42)})?;left-=w;}
 if done{let root=p.result().ok_or(e(42))?;for(x,b)in root.iter().zip(roots[round*64..(round+1)*64].chunks_exact_mut(8)){b.copy_from_slice(&x.to_le_bytes());}}
 Ok(done)
}

// AIR phases0awaitPCS,1quotient,2ready,3evaluate,4full cryptographic proof valid.
// No phase grants acceptance of a pool root/nullifier or moves any asset.
#[inline(never)]
fn air_stage(wire:&[u8],saved:&mut[u8],input:&[u8])->ProgramResult{
 if input.len()!=9{return Err(e(3))}
 let sequence=n(&saved[AIR_CONTROL..AIR_CONTROL+4]);
 if n(&input[1..5])!=sequence||sequence==u32::MAX as usize{return Err(e(44))}
 let phase=n(&saved[AIR_CONTROL+4..AIR_CONTROL+8]);let chunk=n(&saved[AIR_CONTROL+8..AIR_CONTROL+12]);
 if phase>4||chunk>16||saved[AIR_CONTROL+12..PUBLIC_CACHE]!=[0;4]{return Err(e(46))}
 if n(&saved[CONTROL+4..CONTROL+8])!=6||n(&saved[CONTROL+8..CONTROL+12])!=13{return Err(e(43))}
 let expected=match input[0]{14=>0,15=>1,16=>2,17=>3,_=>return Err(e(3))};
 if phase!=expected{return Err(e(43))}let work=n(&input[5..9]);
 match input[0]{
  14=>{if work!=0||chunk!=0{return Err(e(45))}air_context(wire,saved)?;put(saved,AIR_CONTROL+4,1);},
  15=>{if work==0||work>2||chunk>=16{return Err(e(45))}let next=air_quotient(wire,saved,chunk,work)?;put(saved,AIR_CONTROL+8,next);if next==16{put(saved,AIR_CONTROL+4,2);}},
  16=>{if work!=0||chunk!=16{return Err(e(45))}air_start(saved)?;put(saved,AIR_CONTROL+4,3);},
  17=>{if work==0||work>1024||chunk!=16{return Err(e(45))}if air_advance(wire,saved,work)?{put(saved,AIR_CONTROL+4,4);solana_program::msg!("ZK9 FULL CRYPTOGRAPHIC PROOF VERIFIED; POOL STATE AND SPEND NOT AUTHORIZED");}},
  _=>return Err(e(3))
 }
 put(saved,AIR_CONTROL,sequence+1);Ok(())
}
#[inline(never)]
fn air_context(wire:&[u8],saved:&mut[u8])->ProgramResult{
 if !all_zero(&saved[PUBLIC_CACHE..]){return Err(e(46))}
 let expected=wire_context(wire)?;
 let public=candidate::public_values(&expected,wire).map_err(|_|e(47))?;
 if &saved[FORMAT_END..FORMAT_END+8]!=b"ZK9PFXW2"||saved[FORMAT_END+152..FORMAT_END+216]!=public.delivery[0]||saved[FORMAT_END+216..FORMAT_END+280]!=public.delivery[1]||saved[FORMAT_END+280..PREFIX_END]!=public.fee.to_le_bytes(){return Err(e(46))}
 let zeta=air::Ext::decode(&saved[FORMAT_END+40..FORMAT_END+72],false).map_err(|_|e(46))?;
 let selectors=air::domain::selectors(zeta).map_err(|_|e(47))?;
 for(i,x)in public.words_montgomery.iter().enumerate(){saved[PUBLIC_CACHE+i*4..PUBLIC_CACHE+i*4+4].copy_from_slice(&x.to_le_bytes());}
 for(i,x)in selectors.into_iter().enumerate(){x.encode(&mut saved[SELECTORS+i*32..SELECTORS+i*32+32]).map_err(|_|e(47))?;}Ok(())
}
#[inline(never)]
fn air_quotient(wire:&[u8],saved:&mut[u8],chunk:usize,work:usize)->Result<usize,ProgramError>{
 let claims=arithmetic::claims::Claims::from_trusted_format(wire,&saved[BASE..FORMAT_END]).map_err(|_|e(46))?;
 let zeta=air::Ext::decode(&saved[FORMAT_END+40..FORMAT_END+72],false).map_err(|_|e(46))?;
 let mut sum=air::Ext::decode(&saved[QUOTIENT..AIR_STATE],false).map_err(|_|e(46))?;
 let end=(chunk+work).min(16);for i in chunk..end{sum=sum+air::domain::quotient_chunk(&claims,zeta,i).map_err(|_|e(47))?;}
 sum.encode(&mut saved[QUOTIENT..AIR_STATE]).map_err(|_|e(47))?;Ok(end)
}
#[inline(never)]
fn air_start(saved:&mut[u8])->ProgramResult{
 let p=air::Program::from_trusted_compiler(SCHEDULE).map_err(|_|e(46))?;
 if p.state_bytes()!=SPACE-AIR_STATE||!all_zero(&saved[AIR_STATE..]){return Err(e(46))}
 // Byte-for-byte encoding of portable Progress::start, with the same whole-state
 // zero guard through sol_memcmp. No context/checkpoint comes from the caller.
 let(head,body)=saved.split_at_mut(AIR_STATE);body[..8].copy_from_slice(b"ZK9AIPW2");
 body[16..48].copy_from_slice(&head[FORMAT_END+8..FORMAT_END+40]);
 body[48..176].copy_from_slice(&head[SELECTORS..QUOTIENT]);
 body[176..208].copy_from_slice(&head[QUOTIENT..AIR_STATE]);
 Ok(())
}
#[inline(never)]
fn air_advance(wire:&[u8],saved:&mut[u8],work:usize)->Result<bool,ProgramError>{
 let program=air::Program::from_trusted_compiler(SCHEDULE).map_err(|_|e(46))?;
 let(head,body)=saved.split_at_mut(AIR_STATE);
 let claims=arithmetic::claims::Claims::from_trusted_format(wire,&head[BASE..FORMAT_END]).map_err(|_|e(46))?;
 let mut public=[0;air::PUBLIC];for(i,x)in public.iter_mut().enumerate(){*x=n(&head[PUBLIC_CACHE+i*4..PUBLIC_CACHE+i*4+4])as u32;}
 let inputs=Box::new(air::WireInputs{claims,public});let mut p=air::Progress::resume_trusted(body,&program).map_err(|_|e(46))?;
 let mut remaining=work;while remaining>0{let limit=remaining.min(64);remaining-=limit;if p.advance(&program,&*inputs,limit).map_err(|_|e(47))?{p.check_relation(&program).map_err(|_|e(48))?;return Ok(true)}}Ok(false)
}
