//! In-memory test transition only. No persistence, network or public issuance.
use std::collections::BTreeSet;
use crate::{Config,PaymentProof,verify_payment,model::{Statement,Digest,DEPTH},tree::SparseTree};
use zk9_hiding_balance_component::Statement as Context;
#[derive(Clone,PartialEq,Eq,Debug)]
pub struct Snapshot {pub tree:SparseTree<DEPTH>,pub next_leaf:u64,pub roots:Vec<Digest>,
    pub spent:BTreeSet<Digest>,pub commitments:BTreeSet<Digest>,pub fees:u128}
pub struct Ledger {context:Context,state:Snapshot}
impl Ledger {
    // Authority supplies this genesis state; never accept it from a submitted proof.
    pub fn new(context:Context,leaves:Vec<Digest>,next_leaf:u64)->Result<Self,String> {
        if leaves.len() as u64 != next_leaf {
            return Err("invalid initial tree".into());
        }
        let commitments=leaves.iter().copied().collect::<BTreeSet<_>>();
        if commitments.len() as u64!=next_leaf || commitments.contains(&[0;64]) {return Err("invalid initial commitments".into());}
        let tree=SparseTree::from_leaves(&leaves)?;let root=tree.root();
        Ok(Self{context,state:Snapshot{tree,next_leaf,roots:vec![root],spent:BTreeSet::new(),commitments,fees:0}})
    }
    pub fn snapshot(&self)->Snapshot {self.state.clone()}
    pub fn apply(&mut self,c:&Config,s:&Statement,p:&PaymentProof)->Result<Digest,String> {
        if self.context.network!=s.context.network || self.context.genesis!=s.context.genesis || self.context.asset!=s.context.asset {
            return Err("wrong authenticated context".into());
        }
        if !self.state.roots.contains(&s.root) {return Err("unauthorized or expired anchor".into());}
        if self.state.next_leaf+2>self.state.tree.capacity() {return Err("tree is full".into());}
        if s.nullifiers.iter().any(|n|self.state.spent.contains(n)) {return Err("already spent".into());}
        if s.outputs.iter().any(|n|self.state.commitments.contains(n)||*n==[0;64]) {return Err("output already exists".into());}
        verify_payment(c,s,p)?;
        let mut next=self.state.clone();
        next.fees=next.fees.checked_add(s.context.fee as u128).ok_or("fee overflow")?;
        next.spent.extend(s.nullifiers);
        for cm in s.outputs {next.tree.append(cm)?;next.next_leaf+=1;next.commitments.insert(cm);}
        let root=next.tree.root();
        next.roots.push(root);if next.roots.len()>4 {next.roots.remove(0);}
        self.state=next; // single replacement after every validation succeeds
        Ok(root)
    }
}
