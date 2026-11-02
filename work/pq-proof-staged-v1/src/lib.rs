//! Bounded resumable FORMAT parser. Never a cryptographic verifier.
//! Checkpoints must come from authenticated storage, not from a caller's bytes.
#![no_std]
#![forbid(unsafe_code)]
#[cfg(not(target_pointer_width="64"))]
compile_error!("Pinned schema requires 64-bit usize");
mod schema;
use schema::*;
pub const PRIME:u32=2013265921;
pub const MAX_BYTES:usize=4*1024*1024;
pub const MAX_STEP:u32=4096;
pub const CHECKPOINT_BYTES:usize=640;
const FRAMES:usize=16;
const MAX_WORK:u32=16000000;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]pub enum Error{Encoding,Limit,Checkpoint,Failed,Step}
#[derive(Clone,Copy,Default,Debug,PartialEq,Eq)]pub struct Span{pub start:u32,pub end:u32}
#[derive(Clone,Copy,Default,Debug,PartialEq,Eq)]pub struct Stats{pub fields:u32,pub varints:u32,pub sequences:u32,pub max_sequence:u32,pub max_depth:u32,pub serde_work:u32}
#[derive(Clone,Copy,Default)]struct Frame{id:u8,phase:u8,flags:u8,start:u32,count:u32,index:u32,a:u32,b:u32,data:u32}
#[derive(Clone,Copy,Default)]struct Info{count:u32,present:bool}
/// Provisional callbacks, even across steps. Do not commit application state.
pub trait Observe<'a>{fn field(&mut self,_offset:usize,_bytes:&'a[u8;4]){}fn row(&mut self,_offset:usize,_bytes:&'a[u8],_degree:usize){}}
pub struct Ignore;impl<'a>Observe<'a> for Ignore{}
pub struct Reader<'a>{bytes:&'a[u8],pos:u32,stats:Stats,sections:[Span;5],stack:[Frame;FRAMES],sp:usize,status:u32,ops:u64}
impl<'a>Reader<'a>{
 pub fn new(bytes:&'a[u8])->Result<Self,Error>{
  if bytes.is_empty()||bytes.len()>MAX_BYTES{return Err(Error::Limit)}
  let mut r=Self{bytes,pos:0,stats:Stats::default(),sections:[Span::default();5],stack:[Frame::default();FRAMES],sp:1,status:0,ops:0};
  r.stack[0].id=PROOF;Ok(r)
 }
 pub fn position(&self)->usize{self.pos as usize}pub fn stats(&self)->Stats{self.stats}
 pub fn sections(&self)->[Span;5]{self.sections}pub fn done(&self)->bool{self.status==1}pub fn operations(&self)->u64{self.ops}
 fn charge(&mut self,n:u32)->Result<(),Error>{self.stats.serde_work=self.stats.serde_work.checked_add(n).filter(|x|*x<=MAX_WORK).ok_or(Error::Limit)?;Ok(())}
 fn take(&mut self,n:usize)->Result<&'a[u8],Error>{let start=self.pos as usize;let end=start.checked_add(n).ok_or(Error::Encoding)?;let b=self.bytes.get(start..end).ok_or(Error::Encoding)?;self.pos=end as u32;Ok(b)}
 fn integer(&mut self)->Result<u64,Error>{
  let mut v=0u64;for i in 0..10 {let b=self.take(1)?[0];if i==9&&b>1{return Err(Error::Encoding)}v|=u64::from(b&127)<<(7*i);
   if b&128==0{if i>0&&b==0{return Err(Error::Encoding)}self.stats.varints+=1;return Ok(v)}
  }Err(Error::Encoding)
 }
 fn field<O:Observe<'a>>(&mut self,o:&mut O)->Result<(),Error>{let start=self.pos as usize;let b=<&[u8;4]>::try_from(self.take(4)?).map_err(|_|Error::Encoding)?;if u32::from_le_bytes(*b)>=PRIME{return Err(Error::Encoding)}self.stats.fields+=1;o.field(start,b);Ok(())}
 fn seq_stats(&mut self,n:u32,depth:u32){self.stats.sequences+=1;self.stats.max_sequence=self.stats.max_sequence.max(n);self.stats.max_depth=self.stats.max_depth.max(depth);}
 /// Fixed-size leaves replace nested Serde calls but preserve their exact budget.
 fn atomic<O:Observe<'a>>(&mut self,id:u8,depth:u32,o:&mut O)->Result<Option<Info>,Error>{
  self.stats.max_depth=self.stats.max_depth.max(depth);
  match id{
   FIELD=>{if depth+1>32{return Err(Error::Limit)}self.charge(9)?;self.field(o)?;},
   INT=>{self.charge(1)?;self.integer()?;},UNIT=>{self.charge(1)?;return Ok(Some(Info::default()))},
   DIGEST=>{if depth+1>32{return Err(Error::Limit)}self.charge(17)?;self.seq_stats(8,depth+1);for _ in 0..8{self.integer()?;}return Ok(Some(Info{count:8,present:true}))},
   EXT=>{if depth+3>32{return Err(Error::Limit)}self.charge(85)?;self.seq_stats(2,depth);self.seq_stats(8,depth+2);for _ in 0..8{self.field(o)?;}return Ok(Some(Info{count:2,present:true}))},
   _=>return Ok(None)
  }Ok(Some(Info{count:1,present:true}))
 }
 fn accept_child(&mut self,info:Info,start:u32)->Result<(),Error>{
  let f=self.stack.get_mut(self.sp.checked_sub(1).ok_or(Error::Checkpoint)?).ok_or(Error::Checkpoint)?;
  if f.id==PROOF{let s=self.sections.get_mut(f.index as usize).ok_or(Error::Checkpoint)?;*s=Span{start,end:self.pos};}
  if f.id==CAP&&f.index==0{f.a=info.count;}
  if f.id==OPENINGS{if f.index==2{f.a=info.count;if info.present{f.flags|=1;}}if f.index==3{f.b=info.count;if info.present{f.flags|=2;}}}
  if matches!(shape(f.id),Some(Shape::Opt(_))){f.a=info.count;}
  f.index=f.index.checked_add(1).ok_or(Error::Checkpoint)?;Ok(())
 }
 fn finish(&mut self,info:Info)->Result<(),Error>{let start=self.stack[self.sp-1].start;self.stack[self.sp-1]=Frame::default();self.sp-=1;
  if self.sp==0{if self.pos as usize!=self.bytes.len(){return Err(Error::Encoding)}self.status=1;Ok(())}else{self.accept_child(info,start)}
 }
 fn one<O:Observe<'a>>(&mut self,o:&mut O)->Result<(),Error>{
  if self.sp==0||self.sp>FRAMES{return Err(Error::Checkpoint)}
  let at=self.sp-1;let f=self.stack[at];let depth=at as u32;
  if depth>32{return Err(Error::Limit)}
  let kind=shape(f.id).ok_or(Error::Checkpoint)?;
  if f.phase==0{
   if let Some(info)=self.atomic(f.id,depth,o)?{return self.finish(info)}
   self.charge(1)?;
   let n=match kind{
    Shape::Seq(_)=>u32::try_from(self.integer()?).map_err(|_|Error::Limit)?,
    Shape::Tuple(c)|Shape::Struct(c)=>c.len() as u32,
    Shape::Opt(_)=>{let b=self.take(1)?[0];if b==0{return self.finish(Info::default())}if b!=1{return Err(Error::Encoding)}1},
    _=>return Err(Error::Checkpoint)
   };
   if !matches!(kind,Shape::Opt(_)){
    // Match Postcard's bounded size_hint as well as the per-sequence cap.
    if n>16384||n as usize>self.bytes.len()-self.pos as usize{return Err(Error::Limit)}
    self.charge(n)?;self.seq_stats(n,depth);
   }
   self.stack[at].phase=1;self.stack[at].count=n;self.stack[at].data=self.pos;
   return Ok(())
  }
  if f.index<f.count{
   let child=match kind{Shape::Seq(c)|Shape::Opt(c)=>c,Shape::Tuple(c)|Shape::Struct(c)=>*c.get(f.index as usize).ok_or(Error::Checkpoint)?,_=>return Err(Error::Checkpoint)};
   let start=self.pos;
   // Process fixed leaves in place; no push/pop round trip for every field.
   if let Some(info)=self.atomic(child,depth+1,o)?{return self.accept_child(info,start)}
   if self.sp==FRAMES{return Err(Error::Limit)}self.stack[self.sp]=Frame{id:child,start,..Frame::default()};self.sp+=1;return Ok(())
  }
  if f.index!=f.count{return Err(Error::Checkpoint)}
  if f.id==CAP&&!f.a.is_power_of_two(){return Err(Error::Encoding)}
  if f.id==OPENINGS&&((f.flags&1==0&&f.flags&2!=0)||(f.flags&1!=0&&(f.a==0||(f.flags&2!=0&&f.a!=f.b)))){return Err(Error::Encoding)}
  if let Shape::Seq(c)=kind{let degree=if c==FIELD{1}else if c==EXT{8}else{0};if degree>0{
   let row=self.bytes.get(f.data as usize..self.pos as usize).ok_or(Error::Checkpoint)?;
   if row.len()!=f.count as usize*degree*4{return Err(Error::Encoding)}o.row(f.data as usize,row,degree);
  }}
  self.finish(Info{count:if matches!(kind,Shape::Opt(_)){f.a}else{f.count},present:true})
 }
 pub fn advance(&mut self,limit:u32)->Result<bool,Error>{self.advance_with(limit,&mut Ignore)}
 pub fn advance_with<O:Observe<'a>>(&mut self,limit:u32,o:&mut O)->Result<bool,Error>{
  if limit==0||limit>MAX_STEP{return Err(Error::Step)}if self.status==2{return Err(Error::Failed)}
  for _ in 0..limit{if self.done(){break}self.ops+=1;if let Err(e)=self.one(o){self.status=2;return Err(e)}}Ok(self.done())
 }
 pub fn checkpoint(&self,out:&mut[u8])->Result<(),Error>{
  if out.len()!=CHECKPOINT_BYTES{return Err(Error::Checkpoint)}out.fill(0);out[..8].copy_from_slice(b"ZK9STG1\0");
  let words=[self.bytes.len() as u32,self.pos,self.stats.serde_work,self.stats.fields,self.stats.varints,self.stats.sequences,self.stats.max_sequence,self.stats.max_depth,self.sp as u32,self.status];
  for (i,v) in words.iter().enumerate(){put(out,8+4*i,*v)}out[48..56].copy_from_slice(&self.ops.to_le_bytes());
  for (i,s) in self.sections.iter().enumerate(){put(out,64+8*i,s.start);put(out,68+8*i,s.end);}
  for (i,f) in self.stack.iter().enumerate(){let p=128+32*i;out[p]=f.id;out[p+1]=f.phase;out[p+2]=f.flags;for (j,v) in [f.start,f.count,f.index,f.a,f.b,f.data].iter().enumerate(){put(out,p+4+4*j,*v)}}Ok(())
 }
 /// Structural checks do NOT authenticate a checkpoint. The application MUST
 /// restrict it to its own stored state bound to exactly the same immutable bytes.
 pub fn resume_trusted(bytes:&'a[u8],input:&[u8])->Result<Self,Error>{
  if input.len()!=CHECKPOINT_BYTES||&input[..8]!=b"ZK9STG1\0"{return Err(Error::Checkpoint)}let mut r=Self::new(bytes)?;
  if get(input,8)as usize!=bytes.len(){return Err(Error::Checkpoint)}
  r.pos=get(input,12);r.stats=Stats{serde_work:get(input,16),fields:get(input,20),varints:get(input,24),sequences:get(input,28),max_sequence:get(input,32),max_depth:get(input,36)};
  r.sp=get(input,40)as usize;r.status=get(input,44);r.ops=u64::from_le_bytes(input[48..56].try_into().unwrap());
  if r.pos as usize>bytes.len()||r.stats.serde_work>MAX_WORK||r.stats.max_sequence>16384||r.stats.max_depth>32||r.sp>FRAMES||r.status>1||r.ops>64000000||input[56..64].iter().chain(input[104..128].iter()).any(|b|*b!=0){return Err(Error::Checkpoint)}
  if r.stats.fields>r.stats.serde_work/9||r.stats.varints>r.stats.serde_work||r.stats.sequences>r.stats.serde_work{return Err(Error::Checkpoint)}
  if (r.status==0&&r.sp==0)||(r.status==1&&(r.sp!=0||r.pos as usize!=bytes.len())){return Err(Error::Checkpoint)}
  for i in 0..5{let s=Span{start:get(input,64+8*i),end:get(input,68+8*i)};if s.start>s.end||s.end>r.pos{return Err(Error::Checkpoint)}r.sections[i]=s;}
  for i in 0..FRAMES{let p=128+32*i;
   if i>=r.sp{if input[p..p+32].iter().any(|b|*b!=0){return Err(Error::Checkpoint)}continue}
   let f=Frame{id:input[p],phase:input[p+1],flags:input[p+2],start:get(input,p+4),count:get(input,p+8),index:get(input,p+12),a:get(input,p+16),b:get(input,p+20),data:get(input,p+24)};
   if shape(f.id).is_none()||f.phase>1||f.flags>3||f.start>r.pos||f.data>r.pos||f.count>16384||f.index>f.count||input[p+3]!=0||get(input,p+28)!=0{return Err(Error::Checkpoint)}
   if f.phase==0{
    if f.count!=0||f.index!=0||f.a!=0||f.b!=0||f.flags!=0||f.data!=0{return Err(Error::Checkpoint)}
   }else{
    if f.start>f.data{return Err(Error::Checkpoint)}
    match shape(f.id).ok_or(Error::Checkpoint)?{
     Shape::Tuple(c)|Shape::Struct(c)=>if f.count as usize!=c.len(){return Err(Error::Checkpoint)},
     Shape::Opt(_)=>if f.count!=1{return Err(Error::Checkpoint)},Shape::Seq(_)=>(),_=>return Err(Error::Checkpoint)
    }
   }
   if f.id!=OPENINGS&&f.flags!=0{return Err(Error::Checkpoint)}r.stack[i]=f;
  }
  if r.sp>0&&r.stack[0].id!=PROOF{return Err(Error::Checkpoint)}
  for i in 1..r.sp{let parent=r.stack[i-1];if parent.phase!=1||parent.index>=parent.count{return Err(Error::Checkpoint)}
   let expected=match shape(parent.id).ok_or(Error::Checkpoint)?{Shape::Seq(c)|Shape::Opt(c)=>c,Shape::Tuple(c)|Shape::Struct(c)=>*c.get(parent.index as usize).ok_or(Error::Checkpoint)?,_=>return Err(Error::Checkpoint)};
   if r.stack[i].id!=expected||r.stack[i].start<parent.data{return Err(Error::Checkpoint)}
  }Ok(r)
 }
}
fn put(out:&mut[u8],p:usize,n:u32){out[p..p+4].copy_from_slice(&n.to_le_bytes())}
fn get(input:&[u8],p:usize)->u32{u32::from_le_bytes(input[p..p+4].try_into().unwrap())}
