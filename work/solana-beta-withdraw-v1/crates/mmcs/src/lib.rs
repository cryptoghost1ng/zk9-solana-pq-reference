//! Fixed-profile input MMCS authentication. No FRI folds, AIR or spend authorization.
#![no_std]
#![forbid(unsafe_code)]
pub mod hash;
pub type Digest=[u64;8];
pub const QUERIES:usize=64;
pub const HEIGHT:usize=65536;
pub const DEPTH:usize=16;
pub const MAX_FIELDS:usize=1024;
pub const MAX_PARENTS:usize=8;
pub const STATE_BYTES:usize=256+72*QUERIES;
pub const VIEW_BYTES:usize=2028;
#[derive(Debug,Clone,Copy,PartialEq,Eq)]pub enum Error{Format,Shape,Encoding,State,Duplicate,Root,Siblings,Limit,Done}
#[derive(Clone,Copy)]pub struct Geometry{pub width:usize,pub matrices:usize}
pub const GEOMETRIES:[Geometry;3]=[Geometry{width:16,matrices:1},Geometry{width:prefix::WIDTH+8,matrices:1},Geometry{width:16,matrices:16}];
#[derive(Clone,Copy)]pub struct Cursor<'a>{pub bytes:&'a[u8],pub at:usize}
impl<'a>Cursor<'a>{
 pub fn take(&mut self,n:usize)->Result<&'a[u8],Error>{let end=self.at.checked_add(n).ok_or(Error::Encoding)?;let b=self.bytes.get(self.at..end).ok_or(Error::Encoding)?;self.at=end;Ok(b)}
 pub fn uint(&mut self)->Result<u64,Error>{let mut v=0;for i in 0..10{let x=self.take(1)?[0];if i==9&&x>1{return Err(Error::Encoding)}v|=u64::from(x&127)<<(7*i);if x&128==0{if i>0&&x==0{return Err(Error::Encoding)}return Ok(v)}}Err(Error::Encoding)}
 pub fn count(&mut self,n:usize)->Result<(),Error>{if self.uint()?!=n as u64{return Err(Error::Shape)}Ok(())}
 pub fn digest(&mut self)->Result<Digest,Error>{let mut d=[0;8];for x in &mut d{*x=self.uint()?}Ok(d)}
 pub fn end(&self)->Result<(),Error>{if self.at==self.bytes.len(){Ok(())}else{Err(Error::Encoding)}}
}
fn varlen(n:usize)->usize{if n<128{1}else{2}}
#[derive(Clone)]pub struct Batch{pub rows:[u32;64],pub salts:[u32;64],pub siblings_start:u32,pub siblings_end:u32,pub siblings_count:u32}
impl Default for Batch{fn default()->Self{Self{rows:[0;64],salts:[0;64],siblings_start:0,siblings_end:0,siblings_count:0}}}
pub struct Views<'a>{pub bytes:&'a[u8],pub batches:[Batch;3],pub roots:[Digest;3],pub indices:[u32;64]}
impl<'a>Views<'a>{
 pub fn checkpoint(&self,out:&mut[u8])->Result<(),Error>{
  if out.len()!=VIEW_BYTES{return Err(Error::State)}out[..8].copy_from_slice(b"ZK9MVW01");
  for(x,b)in self.roots.iter().flatten().zip(out[8..200].chunks_exact_mut(8)){b.copy_from_slice(&x.to_le_bytes())}
  for(x,b)in self.indices.iter().zip(out[200..456].chunks_exact_mut(4)){b.copy_from_slice(&x.to_le_bytes())}
  for(batch,b)in self.batches.iter().zip(out[456..].chunks_exact_mut(524)){for(x,c)in batch.rows.iter().chain(&batch.salts).chain([&batch.siblings_start,&batch.siblings_end,&batch.siblings_count]).zip(b.chunks_exact_mut(4)){c.copy_from_slice(&x.to_le_bytes())}}Ok(())
 }
 /// Only reload metadata written by this verifier, bound to the same sealed input span.
 #[inline(never)]
 pub fn resume_trusted(bytes:&'a[u8],saved:&[u8])->Result<Self,Error>{
  if saved.len()!=VIEW_BYTES||&saved[..8]!=b"ZK9MVW01"{return Err(Error::State)}let mut roots=[[0;8];3];for(x,b)in roots.iter_mut().flatten().zip(saved[8..200].chunks_exact(8)){*x=u64::from_le_bytes(b.try_into().unwrap())}
  let mut indices=[0;64];for(x,b)in indices.iter_mut().zip(saved[200..456].chunks_exact(4)){*x=u32::from_le_bytes(b.try_into().unwrap());if *x>=65536{return Err(Error::State)}}
  let mut batches=core::array::from_fn(|_|Batch::default());for((batch,b),g)in batches.iter_mut().zip(saved[456..].chunks_exact(524)).zip(GEOMETRIES){
   for(x,c)in batch.rows.iter_mut().chain(&mut batch.salts).chain([&mut batch.siblings_start,&mut batch.siblings_end,&mut batch.siblings_count]).zip(b.chunks_exact(4)){*x=u32::from_le_bytes(c.try_into().unwrap())}
   if batch.siblings_start>batch.siblings_end||batch.siblings_end as usize>bytes.len()||batch.siblings_count>1024{return Err(Error::State)}
   for i in 0..64{if batch.rows[i]as usize+g.matrices*(varlen(g.width)+4*g.width)>bytes.len()||batch.salts[i]as usize+g.matrices*65>bytes.len(){return Err(Error::State)}}
  }Ok(Self{bytes,batches,roots,indices})
 }
 /// Requires same immutable source and program-authenticated scanner/index/FRI result.
 #[inline(never)]
 pub fn from_trusted_scan(wire:&'a[u8],format:&[u8],saved_index:&[u8],transcript:&[u8])->Result<Self,Error>{
  Self::from_scan(wire,format,saved_index,transcript,None)
 }
 /// Batch spans must be captured by the same authenticated completed scanner.
 #[inline(never)]
 pub fn from_trusted_indexed_scan(wire:&'a[u8],format:&[u8],saved_index:&[u8],transcript:&[u8],batches:&[u8])->Result<Self,Error>{
  Self::from_scan(wire,format,saved_index,transcript,Some(batches))
 }
 #[inline(never)]
 fn from_scan(wire:&'a[u8],format:&[u8],saved_index:&[u8],transcript:&[u8],batches:Option<&[u8]>)->Result<Self,Error>{
  let proof=wire.get(3945..).ok_or(Error::Format)?;let reader=fri::scan::Reader::resume_trusted(proof,format).map_err(|_|Error::Format)?;if !reader.done(){return Err(Error::Format)}
  let index=fri::Index::resume_trusted(saved_index,&reader).map_err(|_|Error::Format)?;
  if transcript.len()!=768||&transcript[..8]!=b"ZK9FRI01"||transcript[760..]!=[0;8]{return Err(Error::State)}
  let mut indices=[0;64];for(x,b)in indices.iter_mut().zip(transcript[424..680].chunks_exact(4)){*x=u32::from_le_bytes(b.try_into().unwrap());if *x>=HEIGHT as u32{return Err(Error::State)}}
  let v=prefix::views_from_trusted_format(wire,format).map_err(|_|Error::Shape)?;
  let s=index.spans[4];let bytes=proof.get(s.start as usize..s.end as usize).ok_or(Error::Format)?;
  let spans=if let Some(b)=batches{if b.len()!=24{return Err(Error::State)}let mut spans=[(0,0);3];for(x,raw)in spans.iter_mut().zip(b.chunks_exact(8)){let start=read32(raw,0);let end=read32(raw,4);if start<s.start as usize||end>s.end as usize||start>=end{return Err(Error::State)}*x=(start-s.start as usize,end-s.start as usize);}Some(spans)}else{None};
  Self::parse_indexed(bytes,[v.random_commitment,v.trace_commitment,v.quotient_commitment],indices,spans)
 }
 /// Low-level parser; roots and query indices MUST be verifier-derived, never supplied by a proof.
 pub fn parse(bytes:&'a[u8],roots:[Digest;3],indices:[u32;64])->Result<Self,Error>{
  Self::parse_indexed(bytes,roots,indices,None)
 }
 #[inline(never)]
 fn parse_indexed(bytes:&'a[u8],roots:[Digest;3],indices:[u32;64],spans:Option<[(usize,usize);3]>)->Result<Self,Error>{
  if indices.iter().any(|i|*i>=HEIGHT as u32){return Err(Error::Shape)}
  let mut c=Cursor{bytes,at:0};c.count(3)?;let mut batches=core::array::from_fn(|_|Batch::default());
  for(i,(b,g))in batches.iter_mut().zip(GEOMETRIES).enumerate(){
   if spans.is_some_and(|s|s[i].0!=c.at){return Err(Error::State)}
   c.count(64)?;for off in &mut b.rows{c.count(g.matrices)?;*off=u32::try_from(c.at).map_err(|_|Error::Encoding)?;for _ in 0..g.matrices{c.count(g.width)?;c.take(g.width*4)?;}}
   c.count(64)?;for off in &mut b.salts{c.count(g.matrices)?;*off=u32::try_from(c.at).map_err(|_|Error::Encoding)?;for _ in 0..g.matrices{c.count(16)?;c.take(64)?;}}
   b.siblings_count=u32::try_from(c.uint()?).map_err(|_|Error::Encoding)?;if b.siblings_count>1024{return Err(Error::Shape)}
   b.siblings_start=u32::try_from(c.at).map_err(|_|Error::Encoding)?;
   if let Some(s)=spans{let len=s[i].1.checked_sub(c.at).ok_or(Error::State)?;if len<(b.siblings_count as usize)*8||len>(b.siblings_count as usize)*80{return Err(Error::State)}c.take(len)?;}else{for _ in 0..b.siblings_count{c.digest()?;}}
   b.siblings_end=u32::try_from(c.at).map_err(|_|Error::Encoding)?;
  }c.end()?;Ok(Self{bytes,batches,roots,indices})
 }
 pub fn field(&self,batch:usize,q:usize,i:usize)->Result<u32,Error>{
  let g=*GEOMETRIES.get(batch).ok_or(Error::Shape)?;if q>=64||i>=(g.width+16)*g.matrices{return Err(Error::Shape)}let b=&self.batches[batch];let m=i/(g.width+16);let j=i%(g.width+16);
  let at=if j<g.width{b.rows[q]as usize+m*(varlen(g.width)+4*g.width)+varlen(g.width)+4*j}else{b.salts[q]as usize+m*65+1+4*(j-g.width)};
  let raw=self.bytes.get(at..at+4).ok_or(Error::Encoding)?;let x=u32::from_le_bytes(raw.try_into().unwrap());if x>=prefix::PRIME{return Err(Error::Encoding)}Ok(x)
 }
 fn equal(&self,batch:usize,a:usize,b:usize)->Result<bool,Error>{
  let g=GEOMETRIES[batch];let s=&self.batches[batch];
  for(offsets,len)in [(&s.rows,g.matrices*(varlen(g.width)+4*g.width)),(&s.salts,g.matrices*65)]{let x=offsets[a]as usize;let y=offsets[b]as usize;if self.bytes.get(x..x+len).ok_or(Error::Encoding)?!=self.bytes.get(y..y+len).ok_or(Error::Encoding)?{return Ok(false)}}Ok(true)
 }
}
fn read32(b:&[u8],at:usize)->usize{u32::from_le_bytes(b[at..at+4].try_into().unwrap())as usize}
fn write32(b:&mut[u8],at:usize,x:usize){b[at..at+4].copy_from_slice(&(x as u32).to_le_bytes())}
fn node(b:&[u8],slot:usize)->(usize,usize,Digest){let at=256+slot*72;let mut d=[0;8];for(x,c)in d.iter_mut().zip(b[at+8..at+72].chunks_exact(8)){*x=u64::from_le_bytes(c.try_into().unwrap())}(read32(b,at),read32(b,at+4),d)}
fn setnode(b:&mut[u8],slot:usize,index:usize,q:usize,d:Digest){let at=256+slot*72;write32(b,at,index);write32(b,at+4,q);for(x,c)in d.into_iter().zip(b[at+8..at+72].chunks_exact_mut(8)){c.copy_from_slice(&x.to_le_bytes())}}
/// State is caller-owned scratch/account data, never a large SBF stack array.
/// Native callers discard all mutations on Err; Solana transaction rollback does so atomically.
pub struct Progress<'s>{saved:&'s mut[u8]}
impl<'s>Progress<'s>{
 pub fn start(saved:&'s mut[u8],v:&Views,batch:usize)->Result<Self,Error>{
  if saved.len()!=STATE_BYTES||batch>=3||saved.iter().any(|x|*x!=0){return Err(Error::State)}
  let mut order=core::array::from_fn::<_,64,_>(|i|i as u8);order.sort_unstable_by_key(|q|(v.indices[*q as usize],*q));
  let mut count=0;let mut prev=None;for q in order{let q=q as usize;let idx=v.indices[q];if let Some((pi,pq))=prev{if pi==idx{if !v.equal(batch,pq,q)?{return Err(Error::Duplicate)}continue}}
   setnode(saved,count,idx as usize,q,[0;8]);count+=1;prev=Some((idx,q));
  }
  saved[..8].copy_from_slice(b"ZK9MMCS1");saved[8]=batch as u8;saved[9]=1;write32(saved,12,count);write32(saved,32,v.batches[batch].siblings_start as usize);hash::WordHash::default().checkpoint(&mut saved[48..256])?;Ok(Self{saved})
 }
 /// Validates state shape, not authenticity. Bind it to immutable bytes in the owning program.
 pub fn resume_trusted(saved:&'s mut[u8])->Result<Self,Error>{
  if saved.len()!=STATE_BYTES||&saved[..8]!=b"ZK9MMCS1"||saved[8]>=3||!(1..=3).contains(&saved[9])||saved[10..12]!=[0;2]||saved[44..48]!=[0;4]{return Err(Error::State)}
  let count=read32(saved,12);if !(1..=64).contains(&count)||read32(saved,16)>count||read32(saved,24)>16||read32(saved,28)>count||read32(saved,36)>1024||read32(saved,40)>count{return Err(Error::State)}
  let g=GEOMETRIES[saved[8]as usize];if read32(saved,20)>(g.width+16)*g.matrices||read32(saved,20)%2!=0{return Err(Error::State)}
  hash::WordHash::resume_trusted(&saved[48..256])?;
  if saved[9]==3&&(count!=1||read32(saved,24)!=16){return Err(Error::State)}
  Ok(Self{saved})
 }
 pub fn done(&self)->bool{self.saved[9]==3}
 pub fn result(&self)->Option<Digest>{self.done().then(||node(self.saved,0).2)}
 pub fn advance(&mut self,v:&Views,max_fields:usize,max_parents:usize)->Result<bool,Error>{
  if max_fields<2||max_fields>MAX_FIELDS||max_parents==0||max_parents>MAX_PARENTS{return Err(Error::Limit)}if self.done(){return Err(Error::Done)}
  let s=&mut *self.saved;let b=s[8]as usize;let g=GEOMETRIES[b];let count=read32(s,12);
  if s[9]==1{
   let leaf=read32(s,16);if leaf>=count{return Err(Error::State)}let(index,q,_)=node(s,leaf);if q>=64||index!=v.indices[q]as usize{return Err(Error::State)}
   let mut at=read32(s,20);let total=(g.width+16)*g.matrices;let end=core::cmp::min(at+(max_fields&!1),total);let mut h=hash::WordHash::resume_trusted(&s[48..256])?;
   while at<end{let a=v.field(b,q,at)?;let c=if at+1<total{v.field(b,q,at+1)?}else{0};h.word(u64::from(a)|(u64::from(c)<<32));at=(at+2).min(total);}
   if at==total{setnode(s,leaf,index,q,h.finish());write32(s,16,leaf+1);write32(s,20,0);hash::WordHash::default().checkpoint(&mut s[48..256])?;if leaf+1==count{s[9]=2;}}else{write32(s,20,at);h.checkpoint(&mut s[48..256])?;}
   return Ok(false)
  }
  let level=read32(s,24);if level>=16{return Err(Error::State)}let mut input=read32(s,28);let mut output=read32(s,40);let batch=&v.batches[b];let end=batch.siblings_end as usize;
  let mut cursor=Cursor{bytes:v.bytes.get(..end).ok_or(Error::Encoding)?,at:read32(s,32)};let mut used=read32(s,36);
  for _ in 0..max_parents{
   if input>=count{break}let(index,q,digest)=node(s,input);let mut next=input+1;
   let (left,right)=if index&1==0&&next<count&&node(s,next).0==index+1{let right=node(s,next).2;next+=1;(digest,right)}else{if used>=batch.siblings_count as usize{return Err(Error::Siblings)}let sibling=cursor.digest()?;used+=1;if index&1==0{(digest,sibling)}else{(sibling,digest)}};
   setnode(s,output,index>>1,q,hash::compress(left,right));output+=1;input=next;
  }
  write32(s,28,input);write32(s,40,output);write32(s,32,cursor.at);write32(s,36,used);
  if input==count{write32(s,12,output);write32(s,28,0);write32(s,40,0);write32(s,24,level+1);write32(s,16,0);
   if level+1==16{if output!=1||node(s,0).0!=0{return Err(Error::State)}if used!=batch.siblings_count as usize||cursor.at!=end{return Err(Error::Siblings)}if node(s,0).2!=v.roots[b]{return Err(Error::Root)}s[9]=3;}
  }Ok(self.done())
 }
}
