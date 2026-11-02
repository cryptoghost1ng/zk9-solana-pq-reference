use std::{time::Instant,fs,path::Path};
use zk9_private_relation_lab::{air::PaymentAir,model,trace,config,verify_payment};
fn main()->Result<(),String> {
    let args=std::env::args().collect::<Vec<_>>();
    if args.len()!=3 || !["check","prove"].contains(&args[1].as_str()) {return Err("usage: zk9-private-relation-lab check|prove NEW_OUTPUT_DIR".into());}
    let out=Path::new(&args[2]);fs::create_dir(out).map_err(|e|e.to_string())?;
    let air=PaymentAir::new();let(s,w)=model::fixture();
    let start=Instant::now();let trace=trace::generate(&air,&s,&w)?;
    let prepare_ms=start.elapsed().as_secs_f64()*1000.;
    if args[1]=="check" {
        p3_air::check_constraints(&air,&trace,&s.public_values());
        println!("constraints PASS; {} rows, {} columns, {} SHA3 hashes, {} permutations",air.graph.height(),air.width(),air.graph.jobs.len(),air.graph.blocks.len());
        return Ok(());
    }
    let start=Instant::now();let prover=config()?;let verifier=config()?;
    let init_ms=start.elapsed().as_secs_f64()*1000.;
    let start=Instant::now();let proof=p3_uni_stark::prove(&prover,&air,trace,&s.public_values()).map_err(|e|format!("{e:?}"))?;
    let prove_ms=start.elapsed().as_secs_f64()*1000.;
    let start=Instant::now();verify_payment(&verifier,&s,&proof)?;
    let verify_ms=start.elapsed().as_secs_f64()*1000.;
    let bytes=postcard::to_allocvec(&proof).map_err(|e|e.to_string())?;
    let decoded=postcard::from_bytes(&bytes).map_err(|e|e.to_string())?;
    verify_payment(&verifier,&s,&decoded)?;
    fs::write(out.join("proof.postcard"),&bytes).map_err(|e|e.to_string())?;
    let data=serde_json::json!({"scope":"experimental two-input two-output private relation; depth4 synthetic tree",
        "production_ready":false,"pq_security_budget_verified":false,"height":air.graph.height(),"width":air.width(),
        "hashes":air.graph.jobs.len(),"permutations":air.graph.blocks.len(),"prepare_ms":prepare_ms,"init_ms":init_ms,
        "prove_ms":prove_ms,"verify_ms":verify_ms,"proof_bytes":bytes.len(),"verified":true});
    fs::write(out.join("sample.json"),serde_json::to_vec_pretty(&data).unwrap()).map_err(|e|e.to_string())?;
    println!("{data}");Ok(())
}
