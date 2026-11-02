//! Fixed-depth append-only tree for the existing ZK9 two-output relation.
//! This library requires authenticated, program-owned state. It does NOT check
//! proofs, accepted historical roots, nullifiers, output uniqueness or backing.
#![no_std]
#![forbid(unsafe_code)]
use tiny_keccak::{Hasher,Sha3};
pub type Digest=[u8;64];
pub const DEPTH:usize=32;
pub const CAPACITY:u64=1u64<<DEPTH;
pub const SPACE:usize=80+64*DEPTH;
const EMPTY:&[u8;33*64]=include_bytes!("../generated/empty.bin");
#[derive(Debug,PartialEq,Eq,Clone,Copy)]
pub enum Error { Shape, Count, Frontier, Output, Full, Stale }
pub fn empty(level:usize)->Digest { EMPTY[level*64..(level+1)*64].try_into().expect("internal bounded tree level") }
#[inline(never)]
pub fn parent(level:usize,left:&Digest,right:&Digest)->Digest {
    let mut h=Sha3::v512();h.update(b"ZK9MRK01");h.update(&(level as u32).to_le_bytes());
    h.update(left);h.update(right);let mut out=[0;64];h.finalize(&mut out);out
}
pub fn initialize(out:&mut[u8])->Result<(),Error> {
    if out.len()!=SPACE || out.iter().any(|b|*b!=0) {return Err(Error::Shape)}
    out[..8].copy_from_slice(b"ZK9TREE1");out[16..80].copy_from_slice(&empty(32));Ok(())
}
pub fn count(state:&[u8])->Result<u64,Error> {
    if state.len()!=SPACE || &state[..8]!=b"ZK9TREE1" {return Err(Error::Shape)}
    let n=u64::from_le_bytes(state[8..16].try_into().unwrap());
    if n>CAPACITY || n&1!=0 {return Err(Error::Count)}
    // Canonical frontier stores only occupied subtrees of the binary count.
    for level in 0..DEPTH {
        if n&(1<<level)==0 && state[80+level*64..144+level*64].iter().any(|b|*b!=0) {return Err(Error::Frontier)}
    }
    Ok(n)
}
pub fn root(state:&[u8])->Result<Digest,Error>{count(state)?;Ok(state[16..80].try_into().unwrap())}

/// Append two adjacent leaves to an even-sized tree using exactly32 parent
/// hashes rather than two separate32-level walks. The first pair is a level1
/// subtree; carry occupied frontier slots until the first vacant slot, then
/// finish the root walk without replacing the older, still-occupied slots.
/// All fallible validation precedes mutation. A stale caller cannot overwrite
/// a later append. Cross-payment duplicate outputs remain a pool responsibility.
#[inline(never)]
pub fn append_pair(state:&mut[u8],expected_count:u64,outputs:&[Digest;2])->Result<Digest,Error> {
    let n=count(state)?;
    if n!=expected_count {return Err(Error::Stale)}
    if n>CAPACITY-2 {return Err(Error::Full)}
    if outputs[0]==[0;64] || outputs[1]==[0;64] || outputs[0]==outputs[1] {return Err(Error::Output)}
    let mut digest=parent(0,&outputs[0],&outputs[1]);
    let mut index=n>>1;let mut carry=true;
    for level in 1..DEPTH {
        let at=80+64*level;
        if index&1==0 {
            if carry {state[at..at+64].copy_from_slice(&digest);carry=false;}
            digest=parent(level,&digest,&empty(level));
        }else{
            let left:Digest=state[at..at+64].try_into().unwrap();
            digest=parent(level,&left,&digest);
            if carry {state[at..at+64].fill(0);}
        }
        index>>=1;
    }
    state[8..16].copy_from_slice(&(n+2).to_le_bytes());state[16..80].copy_from_slice(&digest);
    Ok(digest)
}
