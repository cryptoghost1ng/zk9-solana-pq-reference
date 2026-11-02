//! FRI fold arithmetic and reconstructed rows. Round MMCS authentication is separate.
use crate::{Error,field::{Ext,fold_binary},reduce};
pub const STATE_BYTES:usize=56000;
pub const MAX_QUERIES:usize=16;
const VALUES:usize=704;const ROWS:usize=2752;
pub struct Round<'a>{siblings:&'a[u8]}
impl<'a>Round<'a>{
 /// Round spans must come from node(parent24,index) in the authenticated scan.
 pub fn from_trusted_scan(wire:&'a[u8],format:&[u8],index:&[u8],rounds:&[u8],round:usize)->Result<Self,Error>{
  if round>=13||rounds.len()!=104{return Err(Error::Shape)}let proof=wire.get(3904..).ok_or(Error::Encoding)?;let r=fri::scan::Reader::resume_trusted(proof,format).map_err(|_|Error::State)?;if !r.done(){return Err(Error::State)}let i=fri::Index::resume_trusted(index,&r).map_err(|_|Error::State)?;
  let whole=i.spans[5];if proof.get(whole.start as usize)!=Some(&13){return Err(Error::Shape)}let mut prior=whole.start as usize+1;let mut selected=(0,0);
  for(n,b)in rounds.chunks_exact(8).enumerate(){let start=u32::from_le_bytes(b[..4].try_into().unwrap())as usize;let end=u32::from_le_bytes(b[4..].try_into().unwrap())as usize;if start!=prior||start>=end||end>whole.end as usize{return Err(Error::State)}prior=end;if n==round{selected=(start,end);}}
  if prior!=whole.end as usize{return Err(Error::State)}let bytes=proof.get(selected.0..selected.1).ok_or(Error::Encoding)?;Self::from_round_bytes(bytes)
 }
 /// Source has been canonically scanned. This reads only sibling VALUES, not Merkle authentication.
 pub fn from_round_bytes(bytes:&'a[u8])->Result<Self,Error>{let mut c=mmcs::Cursor{bytes,at:0};c.count(64).map_err(|_|Error::Shape)?;let start=c.at;for _ in 0..64{c.count(1).map_err(|_|Error::Shape)?;c.take(32).map_err(|_|Error::Encoding)?;}Ok(Self{siblings:&bytes[start..c.at]})}
 pub fn sibling(&self,q:usize)->Result<Ext,Error>{if q>=64{return Err(Error::Shape)}Ext::decode(&self.siblings[q*33+1..q*33+33],true)}
}
fn num(b:&[u8],at:usize)->usize{u32::from_le_bytes(b[at..at+4].try_into().unwrap())as usize}
fn setnum(b:&mut[u8],at:usize,x:usize){b[at..at+4].copy_from_slice(&(x as u32).to_le_bytes())}
pub struct Progress<'s>{saved:&'s mut[u8]}
impl<'s>Progress<'s>{
 /// Reducer and FRI transcript must be program-owned and bound to the same proof.
 pub fn start(saved:&'s mut[u8],reduced:&mut[u8],transcript:&[u8])->Result<Self,Error>{
  if saved.len()!=STATE_BYTES||saved.iter().any(|x|*x!=0)||transcript.len()!=768||&transcript[..8]!=b"ZK9FRI01"||transcript[760..]!=[0;8]{return Err(Error::State)}
  let p=reduce::Progress::resume_trusted(reduced)?;if !p.done(){return Err(Error::State)}
  saved[..8].copy_from_slice(b"ZK9FLD01");saved[32..448].copy_from_slice(&transcript[8..424]);saved[448..704].copy_from_slice(&transcript[424..680]);
  for r in 0..13{Ext::decode(&saved[32+r*32..64+r*32],false)?;}for q in 0..64{if num(saved,448+q*4)>=65536{return Err(Error::State)}p.result(q)?.encode(&mut saved[VALUES+q*32..VALUES+q*32+32])?;}Ok(Self{saved})
 }
 pub fn resume_trusted(saved:&'s mut[u8])->Result<Self,Error>{
  if saved.len()!=STATE_BYTES||&saved[..8]!=b"ZK9FLD01"||saved[16..32]!=[0;16]||num(saved,8)>13||num(saved,12)>=64||(num(saved,8)==13&&num(saved,12)!=0){return Err(Error::State)}Ok(Self{saved})
 }
 pub fn round(&self)->usize{num(self.saved,8)}
 pub fn done(&self)->bool{self.round()==13}
 pub fn index(&self,round:usize,q:usize)->Result<usize,Error>{if round>=13||q>=64{return Err(Error::Shape)}Ok(num(self.saved,448+4*q)>>(round+1))}
 pub fn row(&self,round:usize,q:usize)->Result<[Ext;2],Error>{if round>=13||q>=64||!self.done(){return Err(Error::State)}let at=ROWS+(round*64+q)*64;Ok([Ext::decode(&self.saved[at..at+32],false)?,Ext::decode(&self.saved[at+32..at+64],false)?])}
 pub fn advance(&mut self,round:&Round,final_poly:Ext,queries:usize)->Result<bool,Error>{
  if self.done(){return Err(Error::Done)}if queries==0||queries>MAX_QUERIES{return Err(Error::Limit)}let r=self.round();let q=num(self.saved,12);let end=(q+queries).min(64);let beta=Ext::decode(&self.saved[32+r*32..64+r*32],false)?;
  for q in q..end{let current=Ext::decode(&self.saved[VALUES+q*32..VALUES+q*32+32],false)?;let sibling=round.sibling(q)?;let original=num(self.saved,448+4*q);let index=original>>r;let pair=if index&1==0{[current,sibling]}else{[sibling,current]};let folded=fold_binary((index>>1)as u32,15-r,beta,pair[0],pair[1])?;
   if r==12&&folded!=final_poly{return Err(Error::FinalPolynomial)}
   let at=ROWS+(r*64+q)*64;pair[0].encode(&mut self.saved[at..at+32])?;pair[1].encode(&mut self.saved[at+32..at+64])?;folded.encode(&mut self.saved[VALUES+q*32..VALUES+q*32+32])?;
  }setnum(self.saved,12,end);if end==64{setnum(self.saved,8,r+1);setnum(self.saved,12,0);}Ok(self.done())
 }
}
