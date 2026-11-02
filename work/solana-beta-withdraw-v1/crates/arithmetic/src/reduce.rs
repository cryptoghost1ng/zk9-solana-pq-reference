//! Stream columns across all queries: one alpha ladder, fixed caller-owned state.
use crate::{Error,claims::Claims,field::{Ext,F,generator,query_x}};
pub const STATE_BYTES:usize=6400;
pub const MAX_Z_COLUMNS:usize=256;
pub const MAX_X_COLUMNS:usize=48;
pub const MAX_QUERIES:usize=16;
const ALPHA:usize=32;const ZETA:usize=64;const NEXT:usize=96;const SHIFT:usize=128;const POWER:usize=160;const Z:usize=192;const Z_NEXT:usize=224;const X:usize=256;const X_NEXT:usize=2304;const RESULT:usize=4352;
fn u32at(b:&[u8],at:usize)->usize{u32::from_le_bytes(b[at..at+4].try_into().unwrap())as usize}
fn set32(b:&mut[u8],at:usize,x:usize){b[at..at+4].copy_from_slice(&(x as u32).to_le_bytes())}
fn get(b:&[u8],at:usize)->Result<Ext,Error>{Ext::decode(&b[at..at+32],false)}
fn set(b:&mut[u8],at:usize,x:Ext)->Result<(),Error>{x.encode(&mut b[at..at+32])}
pub struct Progress<'s>{saved:&'s mut[u8]}
impl<'s>Progress<'s>{
 /// Inputs and transcripts MUST be bound to the same immutable source by the owner.
 pub fn start(saved:&'s mut[u8],prefix:&[u8],pcs:&[u8],inputs:&mmcs::Views,authenticated_mmcs:&mut[u8])->Result<Self,Error>{
  if saved.len()!=STATE_BYTES||saved.iter().any(|x|*x!=0)||authenticated_mmcs.len()!=3*mmcs::STATE_BYTES{return Err(Error::State)}
  for(b,s)in authenticated_mmcs.chunks_exact_mut(mmcs::STATE_BYTES).enumerate(){if s[8]as usize!=b{return Err(Error::UnauthenticatedInputs)}let p=mmcs::Progress::resume_trusted(s).map_err(|_|Error::UnauthenticatedInputs)?;if p.result()!=Some(inputs.roots[b]){return Err(Error::UnauthenticatedInputs)}}
  if prefix.len()!=288||&prefix[..8]!=b"ZK9PFXW2"{return Err(Error::State)}let zeta=Ext::decode(&prefix[40..72],false)?;
  if zeta.pow(4096)==Ext::ONE{return Err(Error::ZetaInDomain)}
  let pcs=opening::Progress::resume_trusted(pcs).map_err(|_|Error::State)?;let(alpha,_)=pcs.result().ok_or(Error::State)?;let alpha=Ext::canonical(alpha)?;
  saved[..8].copy_from_slice(b"ZK9RED01");saved[8]=1;
  set(saved,ALPHA,alpha)?;set(saved,ZETA,zeta)?;set(saved,NEXT,zeta.scale(generator(12)?))?;set(saved,SHIFT,alpha.pow((prefix::WIDTH+8) as u32))?;set(saved,POWER,Ext::ONE)?;Ok(Self{saved})
 }
 pub fn resume_trusted(saved:&'s mut[u8])->Result<Self,Error>{
  if saved.len()!=STATE_BYTES||&saved[..8]!=b"ZK9RED01"||!(1..=5).contains(&saved[8])||saved[10..12]!=[0;2]||saved[20..32]!=[0;12]{return Err(Error::State)}
  let phase=saved[8];let item=saved[9]as usize;let column=u32at(saved,12);let query=u32at(saved,16);
  if phase==1&&(item>=19||column>=Claims::width(item)?){return Err(Error::State)}
  if phase==2&&(item>=18||column>=if item==1{prefix::WIDTH+8}else{16}){return Err(Error::State)}
  if (phase==3||phase==4)&&query>=64{return Err(Error::State)}
  if phase==5&&query!=64{return Err(Error::State)}
  Ok(Self{saved})
 }
 pub fn phase(&self)->u8{self.saved[8]}
 pub fn done(&self)->bool{self.phase()==5}
 pub fn max_work(&self)->usize{match self.phase(){1=>MAX_Z_COLUMNS,2=>MAX_X_COLUMNS,3|4=>MAX_QUERIES,_=>0}}
 pub fn result(&self,query:usize)->Result<Ext,Error>{if !self.done()||query>=64{return Err(Error::State)}get(self.saved,RESULT+32*query)}
 pub fn advance(&mut self,claims:&Claims,inputs:&mmcs::Views,work:usize)->Result<bool,Error>{
  if self.done(){return Err(Error::Done)}if work==0||work>self.max_work(){return Err(Error::Limit)}let s=&mut *self.saved;
  match s[8]{
   1=>{
    let point=s[9]as usize;let start=u32at(s,12);let end=core::cmp::min(start+work,Claims::width(point)?);let alpha=get(s,ALPHA)?;let mut power=get(s,POWER)?;let at=if point==2{Z_NEXT}else{Z};let mut sum=get(s,at)?;
    for column in start..end{sum=sum+power*claims.get(point,column)?;power=power*alpha;}
    set(s,at,sum)?;set(s,POWER,power)?;set32(s,12,end);
    if end==Claims::width(point)?{s[9]+=1;set32(s,12,0);if s[9]==19{s[8]=2;s[9]=0;set(s,POWER,Ext::ONE)?;}}
   },
   2=>{
    let matrix=s[9]as usize;let width=if matrix==1{prefix::WIDTH+8}else{16};let start=u32at(s,12);let end=core::cmp::min(start+work,width);let alpha=get(s,ALPHA)?;let mut power=get(s,POWER)?;
    let(batch,offset)=match matrix{0=>(0,0),1=>(1,0),m=>(2,(m-2)*32)};let target=if matrix==1{X_NEXT}else{X};
    for column in start..end{for q in 0..64{let value=F::from_montgomery(inputs.field(batch,q,offset+column).map_err(|_|Error::Encoding)?)?;let at=target+q*32;let sum=get(s,at)?+power.scale(value);set(s,at,sum)?;}power=power*alpha;}
    set(s,POWER,power)?;set32(s,12,end);
    if end==width{set32(s,12,0);s[9]+=1;if matrix==1{set(s,POWER,power*get(s,SHIFT)?)?;s[8]=3;set32(s,16,0);}else if s[9]==18{s[8]=4;set32(s,16,0);}}
   },
   3=>{
    let start=u32at(s,16);let end=(start+work).min(64);let shift=get(s,SHIFT)?;
    for q in start..end{let trace=get(s,X_NEXT+q*32)?;set(s,X+q*32,get(s,X+q*32)?+trace)?;set(s,X_NEXT+q*32,trace*shift)?;}
    set32(s,16,end);if end==64{s[8]=2;set32(s,16,0);}
   },
   4=>{
    let start=u32at(s,16);let end=(start+work).min(64);let zeta=get(s,ZETA)?;let next=get(s,NEXT)?;let z=get(s,Z)?;let zn=get(s,Z_NEXT)?;
    for q in start..end{let x=Ext::base(query_x(inputs.indices[q])?);let a=(zeta-x).inverse().ok_or(Error::ZeroDenominator)?;let b=(next-x).inverse().ok_or(Error::ZeroDenominator)?;let r=(z-get(s,X+q*32)?)*a+(zn-get(s,X_NEXT+q*32)?)*b;set(s,RESULT+q*32,r)?;}
    set32(s,16,end);if end==64{s[8]=5;}
   },_=>return Err(Error::State)
  }Ok(self.done())
 }
}
