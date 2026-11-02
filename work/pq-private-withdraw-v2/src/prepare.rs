//! Reuses pinned ownership, local paths and OS randomness from the payment builder.
//! Caller still authenticates the root, reserves inputs and encrypts both outputs.
use crate::{Context,model::{self,Digest},tree::SparseTree};
pub use zk9_private_send_lab::prepare::OwnedNote;
pub struct Prepared {
    pub payment:model::Statement,
    pub witness:model::Witness,
    pub selected_indices:Vec<u64>,
    pub amount:u64,
    pub recipient:[u8;32],
}
pub fn prepare(context:&Context,root:Digest,tree:&SparseTree<32>,secret:&[u8;32],selected:&[OwnedNote],recipient:[u8;32],amount:u64)->Result<Prepared,String> {
    if recipient==[0;32] {return Err("empty withdrawal recipient".into());}
    let mut p=zk9_private_send_lab::prepare::prepare(context,root,tree,secret,selected,model::address(secret),amount)?;
    // The first private output becomes zero padding. The original change remains
    // correct because upstream already subtracts amount+fee from selected funds.
    p.witness.outputs[0].amount=0;
    p.statement.outputs=p.witness.outputs.clone().map(|n|n.commitment(context));
    if p.statement.outputs[0]==p.statement.outputs[1] {return Err("random output collision".into());}
    Ok(Prepared{payment:p.statement,witness:p.witness,selected_indices:p.selected_indices,amount,recipient})
}
