//! Exact p3 PaddingFreeSponge<KeccakF,25,9,8>: overwrite, not SHA3/XOR.
use crate::{Error,Digest};
pub const SNAPSHOT:usize=208;
#[derive(Clone,Default)]
pub struct WordHash { state:[u64;25], pos:usize }
impl WordHash {
 pub fn word(&mut self,x:u64){self.state[self.pos]=x;self.pos+=1;if self.pos==9{tiny_keccak::keccakf(&mut self.state);self.pos=0;}}
 pub fn finish(mut self)->Digest{if self.pos!=0{tiny_keccak::keccakf(&mut self.state);}self.state[..8].try_into().unwrap()}
 pub fn checkpoint(&self,b:&mut[u8])->Result<(),Error>{if b.len()!=SNAPSHOT{return Err(Error::State)}b.fill(0);b[0]=self.pos as u8;for(x,c)in self.state.iter().zip(b[8..].chunks_exact_mut(8)){c.copy_from_slice(&x.to_le_bytes())}Ok(())}
 /// Caller authenticates snapshot ownership and source; this is not a MAC.
 pub fn resume_trusted(b:&[u8])->Result<Self,Error>{if b.len()!=SNAPSHOT||b[0]>=9||b[1..8]!=[0;7]{return Err(Error::State)}let mut s=Self{state:[0;25],pos:b[0]as usize};for(x,c)in s.state.iter_mut().zip(b[8..].chunks_exact(8)){*x=u64::from_le_bytes(c.try_into().unwrap())}Ok(s)}
}
pub fn compress(left:Digest,right:Digest)->Digest{let mut h=WordHash::default();for x in left.into_iter().chain(right){h.word(x)}h.finish()}
