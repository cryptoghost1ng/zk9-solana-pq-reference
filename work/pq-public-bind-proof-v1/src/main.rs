//! Public synthetic witnesses and placeholder packets ONLY. Native proofs are
//! deliberately separate from the existing network envelope and pool programs.
use std::{fs,path::Path,time::Instant};
use p3_field::{PrimeCharacteristicRing,PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use serde_json::json;
use zk9_private_send_lab as old;
use zk9_public_bind_proof_lab::{self as new,model::{self,Note,Witness},tree::SparseTree,Val};

fn packets()->[Vec<u8>;2] {[vec![21;new::PACKET_BYTES],vec![22;new::PACKET_BYTES]]}
fn statement(mut s:model::Statement,w:&Witness)->new::Statement {
    s.nullifiers=std::array::from_fn(|i|{
        let n=&w.inputs[i];let note=Note{owner:model::address(&n.secret),rho:n.rho,amount:n.amount};
        model::nullifier(&s.context,&n.secret,&note.commitment(&s.context))
    });
    s.outputs=w.outputs.clone().map(|n|n.commitment(&s.context));new::bind(s,&packets()).unwrap()
}
fn fixture()->(new::Statement,Witness) {let(s,w)=model::fixture();(statement(s,&w),w)}
fn single(amount:u64)->(new::Statement,Witness) {
    let(mut s,mut w)=model::fixture();w.inputs[0].amount=amount;
    let note=Note{owner:model::address(&w.inputs[0].secret),rho:w.inputs[0].rho,amount};
    let tree=SparseTree::<32>::from_leaves(&[note.commitment(&s.context)]).unwrap();
    s.root=tree.root();w.inputs[0].index=0;w.inputs[0].siblings=tree.path(0).unwrap();
    w.inputs[1]=model::Spend{secret:[77;32],rho:[78;32],amount:0,index:0,siblings:[[0;64];32]};
    w.outputs[0].amount=amount-1;w.outputs[1].amount=0;(statement(s,&w),w)
}
fn hex(bytes:&[u8])->String {bytes.iter().map(|b|format!("{b:02x}")).collect()}
fn emit(out:&Path,name:&str,value:serde_json::Value) {
    fs::write(out.join(format!("{name}.json")),serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    println!("{}",value);
}

// Both implementations run the same pipeline. Raw verification excludes AIR
// construction; wrapper/roundtrip checks run outside the measured verify time.
macro_rules! measure {
    ($m:ident,$variant:expr,$name:expr,$s:expr,$w:expr,$out:expr) => {{
        let s=$s;let w=$w;let out=$out;let name=$name;
        let start=Instant::now();let prover=$m::config().unwrap();let verifier=$m::config().unwrap();
        let air=$m::DeliveryAir($m::air::PaymentAir::new());let public=s.public_values();
        let initialization_ms=start.elapsed().as_secs_f64()*1000.;
        let start=Instant::now();let trace=$m::trace::generate(&air.0,&s.payment,w).unwrap();
        let trace_ms=start.elapsed().as_secs_f64()*1000.;
        let start=Instant::now();let p=p3_uni_stark::prove(&prover,&air,trace,&public).unwrap();
        let prove_ms=start.elapsed().as_secs_f64()*1000.;
        let start=Instant::now();p3_uni_stark::verify(&verifier,&air,&p,&public).unwrap();
        let verify_ms=start.elapsed().as_secs_f64()*1000.;
        let start=Instant::now();let bytes=postcard::to_allocvec(&p).unwrap();
        let serialize_ms=start.elapsed().as_secs_f64()*1000.;
        let restored:$m::PaymentProof=postcard::from_bytes(&bytes).unwrap();
        $m::verify_payment(&verifier,s,&restored).unwrap();
        assert_eq!(postcard::to_allocvec(&restored).unwrap(),bytes);
        fs::write(out.join(format!("{name}.proof.bin")),&bytes).unwrap();
        emit(out,name,json!({"case":name,"status":"PASS_VALID_PROOF","variant":$variant,
            "initialization_ms":initialization_ms,"trace_ms":trace_ms,"prove_ms":prove_ms,
            "verify_ms":verify_ms,"serialize_ms":serialize_ms,"proof_bytes":bytes.len(),
            "proof_sha3_512":hex(&model::hash(&bytes)),"width":air.0.width(),"height":air.0.graph.height(),
            "public_values":public.iter().map(|v|v.as_canonical_u64()).collect::<Vec<_>>(),
            "roundtrip_verified":true,"native_only":true,"network_envelope":false}));
        bytes
    }}
}
fn flags(a:&new::air::PaymentAir,t:&mut RowMajorMatrix<Val>,v:u8,from:usize) {
    let col=a.global()+a.layout.slots[a.graph.second_active];
    for row in t.values.chunks_exact_mut(a.width()).skip(from) {row[col]=Val::from_u8(v);}
}
fn malicious<F:FnOnce(&new::air::PaymentAir,&mut RowMajorMatrix<Val>)>(
    out:&Path,name:&str,s:&new::Statement,w:&Witness,change:F) {
    let start=Instant::now();let a=new::DeliveryAir(new::air::PaymentAir::new());
    let mut t=new::trace::generate(&a.0,&s.payment,w).unwrap();change(&a.0,&mut t);
    // No host validation shortcut: force the release prover to produce a proof
    // of the malformed trace, then require rejection by the actual verifier.
    let p=p3_uni_stark::prove(&new::config().unwrap(),&a,t,&s.public_values())
        .unwrap_or_else(|e|panic!("{name}: verifier rejection not exercised; prover refused: {e:?}"));
    let error=new::verify_payment(&new::config().unwrap(),s,&p).expect_err(name);
    let bytes=postcard::to_allocvec(&p).unwrap();fs::write(out.join(format!("{name}.proof.bin")),&bytes).unwrap();
    emit(out,name,json!({"case":name,"status":"PASS_MALICIOUS_TRACE_VERIFIER_REJECTION",
        "error":error,"proof_bytes":bytes.len(),"proof_sha3_512":hex(&model::hash(&bytes)),
        "elapsed_ms":start.elapsed().as_secs_f64()*1000.,"prover_returned_proof":true}));
}
fn smoke(out:&Path) {
    let(s,w)=fixture();let baseline=measure!(old,"baseline","baseline-two",&s,&w,out);
    let candidate=measure!(new,"candidate","candidate-two",&s,&w,out);
    let new_as_old:old::PaymentProof=postcard::from_bytes(&candidate).unwrap();
    let old_as_new:new::PaymentProof=postcard::from_bytes(&baseline).unwrap();
    assert!(old::verify_payment(&old::config().unwrap(),&s,&new_as_old).is_err());
    assert!(new::verify_payment(&new::config().unwrap(),&s,&old_as_new).is_err());
    emit(out,"version-isolation",json!({"case":"version-isolation","status":"PASS","directions":2}));
    let proof:new::PaymentProof=postcard::from_bytes(&candidate).unwrap();let c=new::config().unwrap();
    for k in 0..11 {
        let mut bad=s.clone();match k {
            0=>bad.payment.context.network[0]^=1,1=>bad.payment.context.genesis[0]^=1,
            2=>bad.payment.context.asset[0]^=1,3=>bad.payment.context.fee+=1,4=>bad.payment.root[0]^=1,
            5=>bad.payment.nullifiers[0][0]^=1,6=>bad.payment.nullifiers[1][0]^=1,
            7=>bad.payment.outputs[0][0]^=1,8=>bad.payment.outputs[1][0]^=1,
            9=>bad.delivery[0][0]^=1,_=>bad.delivery[1][0]^=1}
        assert!(new::verify_payment(&c,&bad,&proof).is_err(),"public mutation {k}");
    }
    for k in 0..5 {
        let mut bad:new::PaymentProof=postcard::from_bytes(&candidate).unwrap();match k {
            0=>bad.commitments.random=None,1=>bad.opened_values.random=None,
            2=>bad.commitments.trace=bad.commitments.quotient_chunks.clone(),3=>bad.degree_bits+=1,
            _=>bad.opened_values.trace_local[0]+=new::config::Challenge::ONE}
        assert!(new::verify_payment(&c,&s,&bad).is_err(),"proof mutation {k}");
    }
    let mut bad=s.clone();bad.payment.nullifiers[1]=bad.payment.nullifiers[0];
    assert!(new::verify_payment(&c,&bad,&proof).is_err());
    let mut bad=s.clone();bad.payment.outputs[1]=bad.payment.outputs[0];
    assert!(new::verify_payment(&c,&bad,&proof).is_err());
    let mut bad=s.clone();bad.payment.outputs[1]=[0;64];assert!(new::verify_payment(&c,&bad,&proof).is_err());
    emit(out,"public-proof-rejections",json!({"case":"public-proof-rejections","status":"PASS","public_mutations":11,"proof_mutations":5,"shape_guards":3}));
}
fn qualify(out:&Path) {
    smoke(out);
    let(s,w)=single(1_000_000);measure!(new,"candidate","one-input",&s,&w,out);
    let(max_s,max_w)=single(u64::MAX);measure!(new,"candidate","u64-max",&max_s,&max_w,out);
    let(s2,w2)=fixture();
    malicious(out,"nonzero-cannot-be-padding",&s2,&w2,|a,t|flags(a,t,0,0));
    let mut alias=w.clone();alias.inputs[1].amount=2_013_265_921;alias.outputs[0].amount+=2_013_265_921;
    let alias_s=statement(s.payment.clone(),&alias);
    malicious(out,"field-modulus-is-not-zero",&alias_s,&alias,|a,t|flags(a,t,0,0));
    let mut bad=w.clone();bad.inputs[0].siblings[0][0]^=1;
    malicious(out,"first-membership",&s,&bad,|_,_|{});
    let mut bad=w.clone();bad.inputs[0].secret[0]^=1;
    malicious(out,"first-ownership",&s,&bad,|_,_|{});
    malicious(out,"second-active-membership",&s,&w,|a,t|flags(a,t,1,0));
    let mut zero_w=w.clone();
    let leaves=zero_w.inputs.clone().map(|n|Note{owner:model::address(&n.secret),rho:n.rho,amount:n.amount}.commitment(&s.payment.context));
    let tree=SparseTree::<32>::from_leaves(&leaves).unwrap();
    for i in 0..2 {zero_w.inputs[i].index=i as u64;zero_w.inputs[i].siblings=tree.path(i as u64).unwrap();}
    let mut zs=s.payment.clone();zs.root=tree.root();let zs=statement(zs,&zero_w);
    let a=new::DeliveryAir(new::air::PaymentAir::new());
    for v in [0,1] {
        let mut t=new::trace::generate(&a.0,&zs.payment,&zero_w).unwrap();flags(&a.0,&mut t,v,0);
        p3_air::check_constraints(&a,&t,&zs.public_values());
    }
    malicious(out,"flag-boolean",&zs,&zero_w,|a,t|flags(a,t,2,0));
    malicious(out,"flag-stationary",&zs,&zero_w,|a,t|flags(a,t,1,a.graph.height()/2));
    let mut changed=s2.clone();changed.payment.outputs[0][0]^=1;
    malicious(out,"false-public-output",&changed,&w2,|_,_|{});
    let mut changed=s2.clone();changed.payment.nullifiers[1][0]^=1;
    malicious(out,"false-public-nullifier",&changed,&w2,|_,_|{});
    malicious(out,"skip-public-producer",&s2,&w2,|a,t|{
        let b=a.bindings.iter().find(|b|b.name=="output0").unwrap();
        t.values[(b.block*24+23)*a.width()+a.selectors()+b.block]=Val::ZERO;
    });
    malicious(out,"detach-public-output",&s2,&w2,|a,t|{
        let b=a.bindings.iter().find(|b|b.name=="output0").unwrap();
        let i=(b.block*24+23)*a.width()+a.global()+a.layout.slots[b.offset];
        t.values[i]=Val::ONE-t.values[i];
    });
    emit(out,"qualification",json!({"status":"PASS_NATIVE_PROOF_QUALIFICATION","valid_proofs":4,
        "malicious_trace_verifier_rejections":11,"network_wire":false,"sbf_integration":false,"production_ready":false}));
}
fn main() {
    assert!(!cfg!(debug_assertions),"run release to exercise genuine malformed-trace verifier rejection");
    let args=std::env::args().skip(1).collect::<Vec<_>>();assert_eq!(args.len(),2);
    assert!(["smoke","qualify","baseline","candidate"].contains(&args[0].as_str()));
    let out=Path::new(&args[1]);fs::create_dir(out).expect("output directory must be new");
    match args[0].as_str() {
        "smoke"=>smoke(out),"qualify"=>qualify(out),
        "baseline"=>{let(s,w)=fixture();measure!(old,"baseline","sample",&s,&w,out);},
        "candidate"=>{let(s,w)=fixture();measure!(new,"candidate","sample",&s,&w,out);},_=>unreachable!()
    }
    println!("{}",json!({"status":"PASS_NATIVE_COMMAND","command":args[0],"production_ready":false}));
}
