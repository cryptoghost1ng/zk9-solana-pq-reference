//! FRI transcript derivation only. Merkle, folds, AIR and spend state are NOT checked.
#![no_std]
#![forbid(unsafe_code)]
pub mod scan;
pub const SEED:&[u8]=include_bytes!("../../../generated/fri-seed.bin");
pub const INDEX_BYTES:usize=64;
pub const RESULT_BYTES:usize=768;
pub const ROUNDS:usize=13;
pub const QUERIES:usize=64;
#[derive(Debug,Clone,Copy,PartialEq,Eq)]pub enum Error{Index,Format,Shape,Encoding,State}
#[derive(Clone,Default)]
pub struct Index{pub spans:[scan::Span;8]}
impl<'a>scan::Observe<'a> for Index{
 fn node(&mut self,parent:u8,index:u32,span:scan::Span){
  if parent==27&&index==0{self.spans[0]=span;}
  if parent==26&&index<7{self.spans[1+index as usize]=span;}
 }
}
impl Index{
 pub fn checkpoint(&self,out:&mut[u8])->Result<(),Error>{if out.len()!=INDEX_BYTES{return Err(Error::Index)}for(b,s)in out.chunks_exact_mut(8).zip(self.spans){b[..4].copy_from_slice(&s.start.to_le_bytes());b[4..].copy_from_slice(&s.end.to_le_bytes());}Ok(())}
 pub fn resume_trusted(saved:&[u8],reader:&scan::Reader)->Result<Self,Error>{
  if saved.len()!=INDEX_BYTES{return Err(Error::Index)}let mut s=Self::default();for(span,b)in s.spans.iter_mut().zip(saved.chunks_exact(8)){span.start=u32::from_le_bytes(b[..4].try_into().unwrap());span.end=u32::from_le_bytes(b[4..].try_into().unwrap());}s.validate(reader)?;Ok(s)
 }
 pub fn validate(&self,reader:&scan::Reader)->Result<(),Error>{
  let mut missing=false;let mut previous=None;
  for s in self.spans{
   if s.start==0&&s.end==0{missing=true;continue}
   if missing||s.start>=s.end||s.end as usize>reader.position()||previous.is_some_and(|end|s.start!=end){return Err(Error::Index)}previous=Some(s.end);
  }
  if reader.done()&&(missing||self.spans[0].start!=reader.sections()[2].start||self.spans[7].end!=reader.sections()[2].end){return Err(Error::Index)}Ok(())
 }
 fn section<'a>(&self,proof:&'a[u8],n:usize)->Result<&'a[u8],Error>{let s=self.spans[n];proof.get(s.start as usize..s.end as usize).ok_or(Error::Index)}
}
struct Cursor<'a>{bytes:&'a[u8],at:usize}
impl<'a>Cursor<'a>{
 fn new(bytes:&'a[u8])->Self{Self{bytes,at:0}}
 fn take(&mut self,n:usize)->Result<&'a[u8],Error>{let end=self.at.checked_add(n).ok_or(Error::Encoding)?;let b=self.bytes.get(self.at..end).ok_or(Error::Encoding)?;self.at=end;Ok(b)}
 fn uint(&mut self)->Result<u64,Error>{let mut v=0;for i in 0..10{let x=self.take(1)?[0];if i==9&&x>1{return Err(Error::Encoding)}v|=u64::from(x&127)<<(7*i);if x&128==0{if i>0&&x==0{return Err(Error::Encoding)}return Ok(v)}}Err(Error::Encoding)}
 fn end(&self)->Result<(),Error>{if self.at==self.bytes.len(){Ok(())}else{Err(Error::Encoding)}}
}
pub struct Views{pub caps:[[u64;8];ROUNDS],pub final_poly:[u32;8]}
impl Views{
 /// All cursors must come from the same authenticated completed format scan.
 #[inline(never)]
 pub fn from_trusted_scan(wire:&[u8],format:&[u8],saved_index:&[u8])->Result<Self,Error>{
  let proof=wire.get(3904..).ok_or(Error::Format)?;
  let reader=scan::Reader::resume_trusted(proof,format).map_err(|_|Error::Format)?;if !reader.done(){return Err(Error::Format)}
  let index=Index::resume_trusted(saved_index,&reader)?;
  if index.section(proof,1)?!=[0;4]||index.section(proof,7)?!=[0;4]{return Err(Error::Shape)}
  let mut witnesses=Cursor::new(index.section(proof,3)?);if witnesses.uint()?!=ROUNDS as u64{return Err(Error::Shape)}
  if witnesses.take(4*ROUNDS)?.iter().any(|x|*x!=0){return Err(Error::Shape)}witnesses.end()?;
  let mut commits=Cursor::new(index.section(proof,2)?);if commits.uint()?!=ROUNDS as u64{return Err(Error::Shape)}let mut caps=[[0;8];ROUNDS];
  for cap in &mut caps{if commits.uint()?!=1{return Err(Error::Shape)}for x in cap{*x=commits.uint()?}}commits.end()?;
  let mut poly=Cursor::new(index.section(proof,6)?);if poly.uint()?!=1{return Err(Error::Shape)}let mut final_poly=[0;8];
  for x in &mut final_poly{*x=u32::from_le_bytes(poly.take(4)?.try_into().unwrap());if *x>=prefix::PRIME{return Err(Error::Encoding)}}poly.end()?;
  Ok(Self{caps,final_poly})
 }
}
pub struct Transcript{pub betas:[[u32;8];ROUNDS],pub indices:[u32;QUERIES],pub challenger:[u8;80]}
impl Transcript{
 pub fn encode(&self,out:&mut[u8])->Result<(),Error>{
  if out.len()!=RESULT_BYTES{return Err(Error::Encoding)}out.fill(0);out[..8].copy_from_slice(b"ZK9FRI01");
  for(b,x)in out[8..424].chunks_exact_mut(4).zip(self.betas.iter().flatten()){b.copy_from_slice(&x.to_le_bytes());}
  for(b,x)in out[424..680].chunks_exact_mut(4).zip(self.indices){b.copy_from_slice(&x.to_le_bytes());}
  out[680..760].copy_from_slice(&self.challenger);Ok(())
 }
}
/// Original SerializingChallenger32 samples FOUR raw bytes then masks; there is
/// NO field rejection sampling for query bits. Do not use sample_field here.
pub fn sample_index(c:&mut prefix::challenger::Challenger)->u32{u32::from_le_bytes([c.sample_byte(),c.sample_byte(),c.sample_byte(),c.sample_byte()])&65535}
#[inline(never)]
pub fn derive(wire:&[u8],format:&[u8],index:&[u8],trusted_pcs:&[u8])->Result<Transcript,Error>{
 let views=Views::from_trusted_scan(wire,format,index)?;
 let pcs=opening::Progress::resume_trusted(trusted_pcs).map_err(|_|Error::State)?;
 let(_,saved)=pcs.result().ok_or(Error::State)?;
 let mut c=prefix::challenger::Challenger::resume_trusted(&saved).map_err(|_|Error::State)?;c.observe(SEED);
 let mut betas=[[0;8];ROUNDS];for (beta,cap) in betas.iter_mut().zip(views.caps){for x in cap{c.observe(&x.to_le_bytes())}*beta=c.sample_extension();}
 for x in views.final_poly{c.observe(&x.to_le_bytes())}
 let indices=core::array::from_fn(|_|sample_index(&mut c));let challenger=c.checkpoint_after_sample().map_err(|_|Error::State)?;
 Ok(Transcript{betas,indices,challenger})
}
