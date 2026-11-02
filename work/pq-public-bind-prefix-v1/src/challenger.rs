//! Streaming implementation of the pinned SHA3-512 HashChallenger byte stream.
//! A checkpoint authenticates nothing; only store it in trusted verifier state.
use tiny_keccak::{Sha3,Hasher};
use crate::{Error,PRIME};
pub const SNAPSHOT_BYTES:usize=80;
#[derive(Clone)]pub struct Challenger{pending:Sha3,digest:[u8;64],remaining:u8,clean:bool}
impl Challenger{
 pub fn new(initial:&[u8])->Self{let mut pending=Sha3::v512();pending.update(initial);Self{pending,digest:[0;64],remaining:0,clean:false}}
 pub fn observe(&mut self,bytes:&[u8]){if !bytes.is_empty(){self.pending.update(bytes);self.remaining=0;self.clean=false;}}
 fn flush(&mut self){let h=core::mem::replace(&mut self.pending,Sha3::v512());h.finalize(&mut self.digest);self.pending.update(&self.digest);self.remaining=64;self.clean=true;}
 pub fn sample_byte(&mut self)->u8{if self.remaining==0{self.flush()}self.remaining-=1;self.digest[self.remaining as usize]}
 pub fn sample_field(&mut self)->u32{loop{let b=[self.sample_byte(),self.sample_byte(),self.sample_byte(),self.sample_byte()];let v=u32::from_le_bytes(b)&0x7fffffff;if v<PRIME{return v}}}
 pub fn sample_extension(&mut self)->[u32;8]{core::array::from_fn(|_|self.sample_field())}
 /// Snapshot only at a clean sample boundary: pending input is the last digest.
 pub fn checkpoint_after_sample(&self)->Result<[u8;SNAPSHOT_BYTES],Error>{
  if !self.clean{return Err(Error::ChallengerState)}let mut out=[0u8;SNAPSHOT_BYTES];out[..8].copy_from_slice(b"ZK9HS01\0");out[8]=self.remaining;out[16..].copy_from_slice(&self.digest);Ok(out)
 }
 pub fn resume_trusted(saved:&[u8])->Result<Self,Error>{
  if saved.len()!=SNAPSHOT_BYTES||&saved[..8]!=b"ZK9HS01\0"||saved[8]>64||saved[9..16].iter().any(|x|*x!=0){return Err(Error::ChallengerState)}
  let digest:[u8;64]=saved[16..].try_into().unwrap();let mut pending=Sha3::v512();pending.update(&digest);Ok(Self{pending,digest,remaining:saved[8],clean:true})
 }
}
