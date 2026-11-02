use super::*;
use p3_field::PrimeCharacteristicRing;
use p3_air::check_constraints;
use model::{fixture,fixture_leaves};
use ledger::Ledger;

#[test]
fn sha3_matches_independent_python_hashlib_vectors() {
    let vectors:serde_json::Value=serde_json::from_str(include_str!("../hash-vectors.json")).unwrap();
    for v in vectors.as_array().unwrap() {
        let data=v["message"].as_array().unwrap().iter().map(|x|x.as_u64().unwrap() as u8).collect::<Vec<_>>();
        let actual=model::hash(&data).map(|b|format!("{b:02x}")).concat();
        assert_eq!(actual,v["sha3_512"].as_str().unwrap());
    }
}
#[test]
fn full_witness_matches_all_constraints() {
    let a=PaymentAir::new();let(s,w)=fixture();
    assert_eq!(a.graph.blocks.len(),148);assert_eq!(a.graph.jobs.len(),72);
    check_constraints(&a,&trace::generate(&a,&s,&w).unwrap(),&s.public_values());
}
#[test]
fn wrong_secrets_paths_recipients_and_amounts_fail_constraints() {
    let a=PaymentAir::new();let(s,w)=fixture();
    for k in 0..9 {
        let mut bad=w.clone();
        match k {
            0=>bad.inputs[0].secret[0]^=1,
            1=>bad.inputs[0].rho[31]^=1,
            2=>bad.inputs[1].siblings[2][8]^=1,
            3=>bad.inputs[1].index^=1,
            4=>bad.outputs[0].owner[5]^=1,
            5=>bad.outputs[1].rho[3]^=1,
            6=>{bad.inputs[0].amount+=1;bad.outputs[0].amount+=1;},
            7=>bad.inputs[0].siblings[31][3]^=1,
            _=>bad.inputs[0].index^=1u64<<31,
        }
        let t=trace::generate(&a,&s,&bad).unwrap();
        assert!(std::panic::catch_unwind(||check_constraints(&a,&t,&s.public_values())).is_err(),"witness mutation {k}");
    }
}
#[test]
fn schedule_absorption_and_boolean_constraints_cannot_be_skipped() {
    let a=PaymentAir::new();let(s,w)=fixture();let base=trace::generate(&a,&s,&w).unwrap();
    for (r,c) in [(0,a.selectors()),(24,a.input()),(23,a.output()),(100,a.global()+a.layout.slots[a.graph.context]),(0,a.global())] {
        let mut t=base.clone();t.values[r*a.width()+c]+=Val::ONE;
        assert!(std::panic::catch_unwind(||check_constraints(&a,&t,&s.public_values())).is_err(),"cell {r}/{c}");
    }
}

#[test]
fn register_lifetimes_and_reuse_are_enforced() {
    use std::borrow::Borrow;
    use p3_keccak_air::{KeccakCols,NUM_KECCAK_COLS};
    let a=PaymentAir::new();let(s,w)=fixture();let base=trace::generate(&a,&s,&w).unwrap();
    assert!(a.layout.columns<a.graph.bits);
    for (bit,&slot) in a.layout.slots.iter().enumerate() {
        let (first,last)=a.layout.live[bit];
        for block in first..=last {assert_eq!(a.layout.owners[block][slot],Some(bit));}
        for block in first..last {assert!(!a.layout.changes[slot].contains(&block));}
    }
    // Attack a long-lived secret between its address hash and nullifier use.
    let secret=a.graph.secrets[0];let slot=a.layout.slots[secret];
    let start=(a.layout.live[secret].0+1)*24;
    let mut bad=base.clone();
    for row in start..a.graph.height() {bad.values[row*a.width()+a.global()+slot]=Val::ONE-bad.values[row*a.width()+a.global()+slot];}
    assert!(std::panic::catch_unwind(||check_constraints(&a,&bad,&s.public_values())).is_err());
    // Preserve every reduced capacity limb across SHA3 absorption boundaries.
    let mut bad=base.clone();
    let indices=(0..NUM_KECCAK_COLS).collect::<Vec<_>>();
    let cols:&KeccakCols<usize>=indices.as_slice().borrow();
    let cap=cols.preimage[1][4][0]; // word9, first capacity word
    bad.values[24*a.width()+cap]+=Val::ONE;
    assert!(std::panic::catch_unwind(||check_constraints(&a,&bad,&s.public_values())).is_err());
}
fn proof_copy(p:&PaymentProof)->PaymentProof {postcard::from_bytes(&postcard::to_allocvec(p).unwrap()).unwrap()}
#[test]
fn real_proof_binding_and_atomic_ledger() {
    let prover=config().unwrap();let verifier=config().unwrap();let(s,w)=fixture();
    let p=prove_payment(&prover,&s,&w).unwrap();verify_payment(&verifier,&s,&p).unwrap();
    for k in 0..9 {
        let mut bad=s.clone();
        match k {0=>bad.context.network[0]^=1,1=>bad.context.genesis[1]^=1,2=>bad.context.asset[2]^=1,
            3=>bad.context.fee+=1,4=>bad.root[3]^=1,5=>bad.nullifiers[0][4]^=1,6=>bad.nullifiers[1][5]^=1,
            7=>bad.outputs[0][6]^=1,_=>bad.outputs[1][7]^=1}
        assert!(verify_payment(&verifier,&bad,&p).is_err(),"public mutation {k}");
    }
    for k in 0..5 {
        let mut bad=proof_copy(&p);
        match k {0=>bad.commitments.random=None,1=>bad.opened_values.random=None,
            2=>bad.commitments.trace=bad.commitments.quotient_chunks.clone(),3=>bad.degree_bits+=1,
            _=>bad.opened_values.trace_local[0]+=config::Challenge::ONE}
        assert!(verify_payment(&verifier,&s,&bad).is_err(),"proof mutation {k}");
    }
    let bytes=postcard::to_allocvec(&p).unwrap();
    assert!(postcard::from_bytes::<PaymentProof>(&bytes[..bytes.len()/2]).is_err());
    let mut ledger=Ledger::new(s.context.clone(),fixture_leaves(&s.context),12).unwrap();
    let before=ledger.snapshot();
    let mut bad=s.clone();bad.outputs[0][0]^=1;
    assert!(ledger.apply(&verifier,&bad,&p).is_err());assert_eq!(ledger.snapshot(),before);
    let mut bad=s.clone();bad.nullifiers[1]=bad.nullifiers[0];
    assert!(ledger.apply(&verifier,&bad,&p).is_err());assert_eq!(ledger.snapshot(),before);
    let mut bad=s.clone();bad.root=[0;64];
    assert!(ledger.apply(&verifier,&bad,&p).is_err());assert_eq!(ledger.snapshot(),before);
    let new_root=ledger.apply(&verifier,&s,&p).unwrap();let after=ledger.snapshot();
    assert_ne!(new_root,s.root);assert_eq!(after.spent.len(),2);assert_eq!(after.next_leaf,14);
    assert_eq!(after.fees,1);assert_eq!(after.tree.leaf(12).unwrap(),s.outputs[0]);assert_eq!(after.tree.leaf(13).unwrap(),s.outputs[1]);
    assert!(ledger.apply(&verifier,&s,&p).is_err());assert_eq!(ledger.snapshot(),after);
    // Spend fresh outputs twice, crossing the former16-leaf capacity. Each
    // payment has fresh commitments, paths, nullifiers and randomized proof.
    let mut received=w.outputs;
    let mut owner_secrets=[[111;32],[113;32]];
    for round in 0..2 {
        let state=ledger.snapshot();let first=state.next_leaf-2;
        let inputs=std::array::from_fn(|i|model::Spend{secret:owner_secrets[i],
            rho:received[i].rho,amount:received[i].amount,index:first+i as u64,
            siblings:state.tree.path(first+i as u64).unwrap()});
        let next_secrets=[[150+round*4;32],[152+round*4;32]];
        let outputs=std::array::from_fn(|i|model::Note{owner:model::address(&next_secrets[i]),
            rho:[151+round*4+i as u8*2;32],amount:received[i].amount-if i==0 {1}else{0}});
        let statement=model::Statement{context:s.context.clone(),root:state.tree.root(),
            nullifiers:std::array::from_fn(|i|model::nullifier(&s.context,&owner_secrets[i],&received[i].commitment(&s.context))),
            outputs:outputs.clone().map(|n|n.commitment(&s.context))};
        let witness=model::Witness{inputs,outputs:outputs.clone()};
        let proof=prove_payment(&prover,&statement,&witness).unwrap();
        ledger.apply(&verifier,&statement,&proof).unwrap();
        let after=ledger.snapshot();
        assert!(ledger.apply(&verifier,&statement,&proof).is_err());assert_eq!(ledger.snapshot(),after);
        received=outputs;owner_secrets=next_secrets;
    }
    let after=ledger.snapshot();assert_eq!(after.next_leaf,18);assert_eq!(after.spent.len(),6);
    assert_eq!(after.fees,3);assert_eq!(after.roots.len(),4);
}

#[test]
fn sparse_tree_matches_dense_oracle_and_capacity_is_atomic() {
    use tree::{SparseTree,root_from_path};
    let mut sparse=SparseTree::<4>::new().unwrap();let mut leaves=vec![[0;64];16];
    for i in 0..16 {
        leaves[i]=model::hash(&(i as u64).to_le_bytes());
        assert_eq!(sparse.append(leaves[i]).unwrap(),i as u64);
        let mut dense=leaves.clone();
        for level in 0..4 {dense=dense.chunks_exact(2).map(|p|model::parent(level,&p[0],&p[1])).collect();}
        assert_eq!(sparse.root(),dense[0]);
        for j in 0..=i {assert_eq!(root_from_path(leaves[j],j as u64,&sparse.path(j as u64).unwrap()).unwrap(),dense[0]);}
    }
    let snapshot=sparse.clone();assert!(sparse.append([1;64]).is_err());assert_eq!(sparse,snapshot);
    assert!(sparse.path(16).is_err());assert!(root_from_path([1;64],16,&[[0;64];4]).is_err());
    let mut empty=SparseTree::<32>::new().unwrap();let snapshot=empty.clone();
    assert!(empty.append([0;64]).is_err());assert_eq!(empty,snapshot);
    assert_eq!(empty.capacity(),4_294_967_296);assert_eq!(empty.stored_nodes(),0);
    assert!(SparseTree::<0>::new().is_err());assert!(SparseTree::<33>::new().is_err());
}

#[test]
fn sparse_tree_matches_independent_python_vectors() {
    let vectors:serde_json::Value=serde_json::from_str(include_str!("../tree-vectors.json")).unwrap();
    for case in vectors.as_array().unwrap() {
        let count=case["count"].as_u64().unwrap();let mut t=tree::SparseTree::<32>::new().unwrap();
        for i in 0..count {t.append(model::hash(&[b"leaf".as_slice(),&i.to_le_bytes()].concat())).unwrap();}
        assert_eq!(t.root().map(|b|format!("{b:02x}")).concat(),case["root"].as_str().unwrap());
        for p in case["paths"].as_array().unwrap() {
            let index=p["index"].as_u64().unwrap();
            let path=t.path(index).unwrap();
            let actual=path.map(|d|d.map(|b|format!("{b:02x}")).concat());
            let expected=p["siblings"].as_array().unwrap().iter().map(|x|x.as_str().unwrap()).collect::<Vec<_>>();
            assert_eq!(actual.as_slice(),expected.as_slice());
        }
    }
}

#[test]
fn sparse_tree_growth_uses_only_allocated_nodes() {
    let mut t=tree::SparseTree::<32>::new().unwrap();
    for i in 0..10_000u64 {t.append(model::hash(&i.to_le_bytes())).unwrap();}
    assert_eq!(t.len(),10_000);assert!(t.stored_nodes()<20_100);
    for i in [0,1,127,255,511,1023,4095,8191,9999] {
        assert_eq!(tree::root_from_path(t.leaf(i).unwrap(),i,&t.path(i).unwrap()).unwrap(),t.root());
    }
    assert!(t.path(10_000).is_err());
}
#[test]
fn invalid_private_path_is_rejected_by_real_verifier() {
    // Bypass the host's notion of correct membership: generate a consistent
    // SHA3 trace for a wrong sibling, prove it in release, retain trusted root.
    let c=config().unwrap();let(s,mut w)=fixture();w.inputs[0].siblings[0][0]^=1;
    let a=PaymentAir::new();let t=trace::generate(&a,&s,&w).unwrap();
    match p3_uni_stark::prove(&c,&a,t,&s.public_values()) {
        Ok(p)=>assert!(verify_payment(&c,&s,&p).is_err()),Err(_)=>(),
    }
}
