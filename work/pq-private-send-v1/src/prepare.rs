//! Native wallet witness construction. The caller must authenticate the root,
//! scan all spent markers, and reserve selected notes durably before signing.
//! This module never fetches paths for individual owned notes from a server.
//! It creates no proof, ciphertext, reservation, or broadcast by itself.
use rand::{TryRng, rngs::SysRng};
use crate::{Context, model::{self, Digest, Note, Spend, Statement, Witness}, tree::SparseTree};

pub struct OwnedNote { pub index:u64, pub note:Note }
pub struct Prepared {
    pub statement:Statement,
    pub witness:Witness,
    pub selected_indices:Vec<u64>,
}
fn random32()->Result<[u8;32],String> {
    let mut bytes=[0;32];
    SysRng.try_fill_bytes(&mut bytes).map_err(|_|"OS entropy unavailable".to_string())?;
    if bytes==[0;32] {return Err("invalid random output".into());}
    Ok(bytes)
}
/// Uses a complete local tree whose root equals the authenticated snapshot.
/// `selected` must already be unspent and exclusively reserved by the caller.
/// Fresh output randomness and padding secrets come from the OS, never UI data.
pub fn prepare(context:&Context,authenticated_root:Digest,tree:&SparseTree<32>,
    sender_secret:&[u8;32],selected:&[OwnedNote],recipient:Digest,amount:u64)->Result<Prepared,String> {
    if context.network==[0;32] || context.genesis==[0;32] || context.asset==[0;32] || context.fee==0 {
        return Err("invalid payment context".into());
    }
    if !(1..=2).contains(&selected.len()) || amount==0 || recipient==[0;64] || *sender_secret==[0;32] {
        return Err("invalid payment request".into());
    }
    if tree.root()!=authenticated_root {return Err("local tree does not match authenticated root".into());}
    let owner=model::address(sender_secret);
    let mut spends=Vec::new();let mut nfs=Vec::new();let mut indices=Vec::new();let mut total=0u64;
    for owned in selected {
        if owned.note.owner!=owner || owned.note.amount==0 || indices.contains(&owned.index) {
            return Err("invalid selected note".into());
        }
        let cm=owned.note.commitment(context);
        if tree.leaf(owned.index)?!=cm {return Err("selected note commitment mismatch".into());}
        let nf=model::nullifier(context,sender_secret,&cm);
        if nfs.contains(&nf) {return Err("duplicate selected nullifier".into());}
        total=total.checked_add(owned.note.amount).ok_or("wallet amount overflow")?;
        spends.push(Spend{secret:*sender_secret,rho:owned.note.rho,amount:owned.note.amount,
            index:owned.index,siblings:tree.path(owned.index)?});
        indices.push(owned.index);nfs.push(nf);
    }
    let cost=amount.checked_add(context.fee).ok_or("payment amount overflow")?;
    let change=total.checked_sub(cost).ok_or("insufficient selected funds")?;
    if spends.len()==1 {
        let secret=random32()?;let rho=random32()?;
        let padding=Note{owner:model::address(&secret),rho,amount:0};
        nfs.push(model::nullifier(context,&secret,&padding.commitment(context)));
        spends.push(Spend{secret,rho,amount:0,index:0,siblings:[[0;64];32]});
    }
    if nfs[0]==nfs[1] {return Err("random padding collision".into());}
    let outputs=[Note{owner:recipient,rho:random32()?,amount},Note{owner,rho:random32()?,amount:change}];
    let cms=outputs.clone().map(|n|n.commitment(context));
    if cms[0]==cms[1] || cms.iter().any(|x|*x==[0;64]) {return Err("random output collision".into());}
    Ok(Prepared{statement:Statement{context:context.clone(),root:authenticated_root,
        nullifiers:[nfs[0],nfs[1]],outputs:cms},
        witness:Witness{inputs:[spends.remove(0),spends.remove(0)],outputs},selected_indices:indices})
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture()->(Context,[u8;32],Vec<OwnedNote>,SparseTree<32>) {
        let c=Context{network:[1;32],genesis:[2;32],asset:[3;32],fee:1};let key=[12;32];
        let notes=vec![OwnedNote{index:0,note:Note{owner:model::address(&key),rho:[41;32],amount:600}},
                       OwnedNote{index:1,note:Note{owner:model::address(&key),rho:[42;32],amount:400}}];
        let tree=SparseTree::from_leaves(&notes.iter().map(|n|n.note.commitment(&c)).collect::<Vec<_>>()).unwrap();
        (c,key,notes,tree)
    }
    #[test]
    fn prepares_real_owned_notes_with_fresh_padding_and_correct_change() {
        let(c,key,notes,tree)=fixture();let target=model::address(&[19;32]);
        let first=prepare(&c,tree.root(),&tree,&key,&notes[..1],target,500).unwrap();
        let again=prepare(&c,tree.root(),&tree,&key,&notes[..1],target,500).unwrap();
        assert_eq!(first.witness.outputs[1].amount,99);
        assert_eq!(first.statement.nullifiers[0],again.statement.nullifiers[0]);
        assert_ne!(first.statement.nullifiers[1],again.statement.nullifiers[1]);
        assert_ne!(first.statement.outputs,again.statement.outputs);
        assert_eq!(first.selected_indices,vec![0]);
        assert_eq!(first.witness.inputs[1].amount,0);
        let both=prepare(&c,tree.root(),&tree,&key,&notes,target,999).unwrap();
        assert_eq!(both.witness.outputs[1].amount,0);
        for p in [first,both] {
            let a=crate::air::PaymentAir::new();
            p3_air::check_constraints(&a,&crate::trace::generate(&a,&p.statement,&p.witness).unwrap(),&p.statement.public_values());
        }
    }
    #[test]
    fn refuses_foreign_notes_missing_leaves_duplicates_and_wrong_snapshot() {
        let(c,key,mut notes,tree)=fixture();let target=model::address(&[19;32]);
        assert!(prepare(&c,tree.root(),&tree,&[13;32],&notes,target,1).is_err());
        assert!(prepare(&c,[0;64],&tree,&key,&notes,target,1).is_err());
        assert!(prepare(&c,tree.root(),&tree,&key,&[],target,1).is_err());
        notes[1].index=0;
        assert!(prepare(&c,tree.root(),&tree,&key,&notes,target,1).is_err());
        notes[1].index=2;
        assert!(prepare(&c,tree.root(),&tree,&key,&notes,target,1).is_err());
        notes[1].index=1;notes[1].note.rho[0]^=1;
        assert!(prepare(&c,tree.root(),&tree,&key,&notes,target,1).is_err());
    }
    #[test]
    fn refuses_underfunding_overflow_and_empty_payments() {
        let(c,key,notes,tree)=fixture();let target=model::address(&[19;32]);
        for amount in [0,1_000,u64::MAX] {
            assert!(prepare(&c,tree.root(),&tree,&key,&notes,target,amount).is_err());
        }
        assert!(prepare(&c,tree.root(),&tree,&key,&notes,[0;64],1).is_err());
        let huge=vec![OwnedNote{index:0,note:Note{owner:model::address(&key),rho:[41;32],amount:u64::MAX}},
                      OwnedNote{index:1,note:Note{owner:model::address(&key),rho:[42;32],amount:1}}];
        let tree=SparseTree::from_leaves(&huge.iter().map(|n|n.note.commitment(&c)).collect::<Vec<_>>()).unwrap();
        assert!(prepare(&c,tree.root(),&tree,&key,&huge,target,1).is_err());
    }
}
