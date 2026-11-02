//! Portable SHA3-512 absorption state using the pinned tiny-keccak permutation.
//! Serialized state is NOT authenticated. It belongs in program-owned state.
use crate::Error;
pub const STATE_BYTES:usize=216;
#[derive(Clone)]
pub struct Absorber{lanes:[u64;25],position:usize}
impl Absorber{
 pub fn new()->Self{Self{lanes:[0;25],position:0}}
 pub fn update(&mut self,mut input:&[u8]){
  while !input.is_empty(){
   let n=(72-self.position).min(input.len());
   for (i,b) in input[..n].iter().enumerate(){let p=self.position+i;self.lanes[p/8]^=u64::from(*b)<<((p%8)*8);}
   self.position+=n;input=&input[n..];
   if self.position==72{tiny_keccak::keccakf(&mut self.lanes);self.position=0;}
  }
 }
 pub fn finish(mut self)->[u8;64]{
  self.lanes[self.position/8]^=6u64<<((self.position%8)*8);self.lanes[8]^=0x8000000000000000;
  tiny_keccak::keccakf(&mut self.lanes);let mut out=[0;64];
  for (b,x) in out.chunks_exact_mut(8).zip(self.lanes){b.copy_from_slice(&x.to_le_bytes());}out
 }
 pub fn checkpoint(&self,out:&mut[u8])->Result<(),Error>{
  if out.len()!=STATE_BYTES{return Err(Error::State)}out.fill(0);out[..8].copy_from_slice(b"ZK9SHA31");out[8]=self.position as u8;
  for (b,x) in out[16..].chunks_exact_mut(8).zip(self.lanes){b.copy_from_slice(&x.to_le_bytes());}Ok(())
 }
 pub fn resume_trusted(saved:&[u8])->Result<Self,Error>{
  if saved.len()!=STATE_BYTES||&saved[..8]!=b"ZK9SHA31"||saved[8]>=72||saved[9..16].iter().any(|x|*x!=0){return Err(Error::State)}
  let mut lanes=[0;25];for(x,b)in lanes.iter_mut().zip(saved[16..].chunks_exact(8)){*x=u64::from_le_bytes(b.try_into().unwrap());}
  Ok(Self{lanes,position:saved[8]as usize})
 }
}
