//! Fixed-profile Fiat-Shamir prefix. NOT a complete cryptographic verifier.
#![no_std]
#![forbid(unsafe_code)]
pub mod challenger;
use tiny_keccak::{Sha3,Hasher};
use zk9_proof_staged::{Reader,Span};
pub const PRIME:u32=2013265921;
pub const WIDTH:usize=7525;
pub const QUOTIENT_CHUNKS:usize=16;
pub const RESULT_BYTES:usize=288;
pub const SEED:&[u8]=include_bytes!("../generated/seed.bin");
const INITIAL:&[u8]=b"ZK9/LAB/PRIVATE-SEND/v3-public-bind-lifetime/SHA3-512/depth32/1or2in2out/private-zero-padding/ciphertext-SHA3-512/p3-f9833168/MMCS512/q64/b8";
#[derive(Debug,Clone,Copy,PartialEq,Eq)]pub enum Error{Context,Envelope,PublicNote,FormatState,Shape,Encoding,ChallengerState}
#[derive(Clone,Copy)]pub struct Context{pub network:[u8;32],pub genesis:[u8;32],pub asset:[u8;32]}
pub struct Public{pub words_montgomery:[u32;276],pub delivery:[[u8;64];2],pub fee:u64}
/// This is an encoding conversion, not a new field or a replacement protocol.
/// R=2^32 mod 2013265921, matching pinned BabyBearParameters::MONTY_BITS=32.
pub fn to_montgomery(canonical:u32)->Result<u32,Error>{if canonical>=PRIME{return Err(Error::Encoding)}Ok(((canonical as u64*268435454)%PRIME as u64)as u32)}
fn append_words(out:&mut[u32;276],at:&mut usize,bytes:&[u8]){
 for c in bytes.chunks_exact(2){out[*at]=to_montgomery(u16::from_le_bytes([c[0],c[1]])as u32).unwrap();*at+=1;}
}
#[inline(never)]
pub fn public_values(expected:&Context,wire:&[u8])->Result<Public,Error>{
 if wire.len()<=3904||wire.len()>3904+zk9_proof_staged::MAX_BYTES||&wire[..8]!=b"ZK9PQS3\0"||wire[8..12]!=3u32.to_le_bytes()||u32::from_le_bytes(wire[436..440].try_into().unwrap())as usize!=wire.len()-3904{return Err(Error::Envelope)}
 if expected.network==[0;32]||expected.genesis==[0;32]||expected.asset==[0;32]||wire[12..44]!=expected.network||wire[44..76]!=expected.genesis||wire[76..108]!=expected.asset{return Err(Error::Context)}
 if wire[180..244]==wire[244..308]||wire[308..372]==wire[372..436]||wire[308..372].iter().all(|x|*x==0)||wire[372..436].iter().all(|x|*x==0){return Err(Error::PublicNote)}
 let fee=u64::from_le_bytes(wire[108..116].try_into().unwrap());let mut words=[0;276];let mut at=0;
 append_words(&mut words,&mut at,&wire[108..116]);append_words(&mut words,&mut at,&wire[12..108]);append_words(&mut words,&mut at,&wire[116..436]);
 let mut delivery=[[0;64];2];
 for (slot,digest) in delivery.iter_mut().enumerate(){
  let mut h=Sha3::v512();h.update(b"ZK9/NOTE-DELIVERY/DIGEST/v1\0");h.update(&wire[12..108]);h.update(&wire[308+64*slot..372+64*slot]);h.update(&[slot as u8]);h.update(&wire[440+1732*slot..440+1732*(slot+1)]);h.finalize(digest);append_words(&mut words,&mut at,digest);
 }
 if at!=276{return Err(Error::Shape)}Ok(Public{words_montgomery:words,delivery,fee})
}
#[derive(Clone,Copy)]pub struct ExtensionRow<'a>{bytes:&'a[u8]}
impl<'a>ExtensionRow<'a>{
 pub fn len(&self)->usize{self.bytes.len()/32}pub fn is_empty(&self)->bool{self.bytes.is_empty()}pub fn bytes(&self)->&'a[u8]{self.bytes}
 pub fn get_montgomery(&self,index:usize)->Option<[u32;8]>{let start=index.checked_mul(32)?;let b=self.bytes.get(start..start.checked_add(32)?)?;let mut row=[0;8];for (i,c) in b.chunks_exact(4).enumerate(){row[i]=u32::from_le_bytes(c.try_into().ok()?);if row[i]>=PRIME{return None}}Some(row)}
}
pub struct Views<'a>{pub trace_commitment:[u64;8],pub quotient_commitment:[u64;8],pub random_commitment:[u64;8],pub trace:ExtensionRow<'a>,pub next:ExtensionRow<'a>,pub quotient:[ExtensionRow<'a>;QUOTIENT_CHUNKS],pub random:ExtensionRow<'a>}
struct Cursor<'a>{b:&'a[u8],pos:usize}
impl<'a>Cursor<'a>{
 fn take(&mut self,n:usize)->Result<&'a[u8],Error>{let end=self.pos.checked_add(n).ok_or(Error::Encoding)?;let b=self.b.get(self.pos..end).ok_or(Error::Encoding)?;self.pos=end;Ok(b)}
 fn uint(&mut self)->Result<u64,Error>{let mut v=0;for i in 0..10{let x=self.take(1)?[0];if i==9&&x>1{return Err(Error::Encoding)}v|=u64::from(x&127)<<(7*i);if x&128==0{if i>0&&x==0{return Err(Error::Encoding)}return Ok(v)}}Err(Error::Encoding)}
 fn tag(&mut self,want:u8)->Result<(),Error>{if self.take(1)?[0]!=want{return Err(Error::Shape)}Ok(())}
 fn cap(&mut self)->Result<[u64;8],Error>{if self.uint()?!=1{return Err(Error::Shape)}let mut x=[0;8];for y in &mut x{*y=self.uint()?}Ok(x)}
 fn row(&mut self,expected:usize)->Result<ExtensionRow<'a>,Error>{if self.uint()?!=expected as u64{return Err(Error::Shape)}Ok(ExtensionRow{bytes:self.take(expected*32)?})}
 fn end(&self)->Result<(),Error>{if self.pos!=self.b.len(){Err(Error::Encoding)}else{Ok(())}}
}
fn section<'a>(proof:&'a[u8],s:Span)->Result<Cursor<'a>,Error>{Ok(Cursor{b:proof.get(s.start as usize..s.end as usize).ok_or(Error::FormatState)?,pos:0})}
/// REQUIRES an authenticated completed checkpoint bound to these exact bytes.
/// The Solana caller must enforce ownership, source commitment and immutability.
#[inline(never)]
pub fn views_from_trusted_format<'a>(wire:&'a[u8],checkpoint:&[u8])->Result<Views<'a>,Error>{
 let proof=wire.get(3904..).ok_or(Error::Envelope)?;let scan=Reader::resume_trusted(proof,checkpoint).map_err(|_|Error::FormatState)?;
 if !scan.done(){return Err(Error::FormatState)}let spans=scan.sections();
 let mut degree=section(proof,spans[3])?;if degree.uint()?!=13{return Err(Error::Shape)}degree.end()?;
 let mut witness=section(proof,spans[4])?;if witness.take(4)?!=[0;4]{return Err(Error::Shape)}witness.end()?;
 let mut c=section(proof,spans[0])?;let trace_commitment=c.cap()?;let quotient_commitment=c.cap()?;c.tag(1)?;let random_commitment=c.cap()?;c.end()?;
 let mut v=section(proof,spans[1])?;let trace=v.row(WIDTH)?;v.tag(1)?;let next=v.row(WIDTH)?;v.tag(0)?;v.tag(0)?;
 if v.uint()?!=QUOTIENT_CHUNKS as u64{return Err(Error::Shape)}let mut quotient=[ExtensionRow{bytes:&[]};QUOTIENT_CHUNKS];for q in &mut quotient{*q=v.row(8)?;}v.tag(1)?;let random=v.row(8)?;v.end()?;
 Ok(Views{trace_commitment,quotient_commitment,random_commitment,trace,next,quotient,random})
}
pub struct Prefix{pub alpha:[u32;8],pub zeta:[u32;8],pub challenger:[u8;80],pub delivery:[[u8;64];2],pub fee:u64}
impl Prefix{
 pub fn encode(&self,out:&mut[u8])->Result<(),Error>{if out.len()!=RESULT_BYTES{return Err(Error::Encoding)}out[..8].copy_from_slice(b"ZK9PFX3\0");for (i,x) in self.alpha.iter().chain(self.zeta.iter()).enumerate(){out[8+4*i..12+4*i].copy_from_slice(&x.to_le_bytes());}out[72..152].copy_from_slice(&self.challenger);out[152..216].copy_from_slice(&self.delivery[0]);out[216..280].copy_from_slice(&self.delivery[1]);out[280..288].copy_from_slice(&self.fee.to_le_bytes());Ok(())}
}
#[inline(never)]
pub fn derive(expected:&Context,wire:&[u8],trusted_checkpoint:&[u8])->Result<Prefix,Error>{
 let public=public_values(expected,wire)?;let views=views_from_trusted_format(wire,trusted_checkpoint)?;
 let mut c=challenger::Challenger::new(INITIAL);c.observe(SEED);
 for x in views.trace_commitment{c.observe(&x.to_le_bytes())}
 for x in public.words_montgomery{c.observe(&x.to_le_bytes())}
 let alpha=c.sample_extension();
 for x in views.quotient_commitment{c.observe(&x.to_le_bytes())}for x in views.random_commitment{c.observe(&x.to_le_bytes())}
 let zeta=c.sample_extension();let challenger=c.checkpoint_after_sample()?;
 Ok(Prefix{alpha,zeta,challenger,delivery:public.delivery,fee:public.fee})
}
