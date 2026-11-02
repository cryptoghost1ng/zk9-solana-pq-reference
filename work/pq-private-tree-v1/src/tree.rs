//! Append-only sparse SHA3 tree. Empty subtrees are derived, never allocated.
use std::collections::BTreeMap;
use crate::model::{Digest,parent};
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct SparseTree<const D:usize> {
    nodes:BTreeMap<(usize,u64),Digest>,
    empty:Vec<Digest>,
    count:u64,
}
impl<const D:usize> SparseTree<D> {
    pub fn new()->Result<Self,String> {
        if !(1..=32).contains(&D) {return Err("tree depth must be1..32".into());}
        let mut empty=vec![[0;64]];
        for level in 0..D {empty.push(parent(level,&empty[level],&empty[level]));}
        Ok(Self{nodes:BTreeMap::new(),empty,count:0})
    }
    pub fn from_leaves(leaves:&[Digest])->Result<Self,String> {
        let mut tree=Self::new()?;
        for leaf in leaves {tree.append(*leaf)?;}
        Ok(tree)
    }
    pub fn capacity(&self)->u64 {1u64<<D}
    pub fn len(&self)->u64 {self.count}
    pub fn stored_nodes(&self)->usize {self.nodes.len()}
    fn node(&self,level:usize,index:u64)->Digest {
        self.nodes.get(&(level,index)).copied().unwrap_or(self.empty[level])
    }
    pub fn root(&self)->Digest {self.node(D,0)}
    pub fn leaf(&self,index:u64)->Result<Digest,String> {
        if index>=self.count {return Err("unallocated leaf".into());}
        Ok(self.node(0,index))
    }
    pub fn path(&self,index:u64)->Result<[Digest;D],String> {
        if index>=self.count {return Err("unallocated leaf".into());}
        Ok(std::array::from_fn(|level|self.node(level,(index>>level)^1)))
    }
    pub fn append(&mut self,leaf:Digest)->Result<u64,String> {
        if leaf==[0;64] {return Err("zero commitment is reserved for empty leaves".into());}
        if self.count>=self.capacity() {return Err("tree is full".into());}
        let index=self.count;let mut at=index;let mut digest=leaf;
        self.nodes.insert((0,at),digest);
        for level in 0..D {
            let sibling=self.node(level,at^1);
            digest=if at&1==0 {parent(level,&digest,&sibling)}else{parent(level,&sibling,&digest)};
            at>>=1;self.nodes.insert((level+1,at),digest);
        }
        self.count+=1;Ok(index)
    }
}
pub fn root_from_path<const D:usize>(leaf:Digest,index:u64,path:&[Digest;D])->Result<Digest,String> {
    if !(1..=32).contains(&D) || index>=1u64<<D {return Err("path index exceeds tree depth".into());}
    let mut digest=leaf;
    for (level,sibling) in path.iter().enumerate() {
        digest=if index>>level&1==0 {parent(level,&digest,sibling)}else{parent(level,sibling,&digest)};
    }
    Ok(digest)
}
