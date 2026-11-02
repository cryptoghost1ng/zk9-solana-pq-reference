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
    assert_eq!(a.graph.blocks.len(),36);assert_eq!(a.graph.jobs.len(),16);
    check_constraints(&a,&trace::generate(&a,&s,&w).unwrap(),&s.public_values());
}
#[test]
fn wrong_secrets_paths_recipients_and_amounts_fail_constraints() {
    let a=PaymentAir::new();let(s,w)=fixture();
    for k in 0..7 {
        let mut bad=w.clone();
        match k {
            0=>bad.inputs[0].secret[0]^=1,
            1=>bad.inputs[0].rho[31]^=1,
            2=>bad.inputs[1].siblings[2][8]^=1,
            3=>bad.inputs[1].index^=1,
            4=>bad.outputs[0].owner[5]^=1,
            5=>bad.outputs[1].rho[3]^=1,
            _=>{bad.inputs[0].amount+=1;bad.outputs[0].amount+=1;},
        }
        let t=trace::generate(&a,&s,&bad).unwrap();
        assert!(std::panic::catch_unwind(||check_constraints(&a,&t,&s.public_values())).is_err(),"witness mutation {k}");
    }
}
#[test]
fn schedule_absorption_and_boolean_constraints_cannot_be_skipped() {
    let a=PaymentAir::new();let(s,w)=fixture();let base=trace::generate(&a,&s,&w).unwrap();
    for (r,c) in [(0,a.selectors()),(24,a.input()),(23,a.output()),(100,a.global()+a.graph.context),(0,a.global())] {
        let mut t=base.clone();t.values[r*a.width()+c]+=Val::ONE;
        assert!(std::panic::catch_unwind(||check_constraints(&a,&t,&s.public_values())).is_err(),"cell {r}/{c}");
    }
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
    assert_eq!(after.fees,1);assert_eq!(&after.leaves[12..14],&s.outputs);
    assert!(ledger.apply(&verifier,&s,&p).is_err());assert_eq!(ledger.snapshot(),after);
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
