use std::{fs::OpenOptions, io::Write, path::Path, time::Instant};
use p3_uni_stark::prove;
use zk9_hiding_balance_component::*;

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 { return Err("usage: zk9-hiding-balance-component SAMPLES NEW_OUTPUT_DIR".into()); }
    let count: usize = args[1].parse().map_err(|_| "invalid sample count")?;
    if !(1..=30).contains(&count) { return Err("sample count must be 1..30".into()); }
    let dir = Path::new(&args[2]);
    std::fs::create_dir(dir).map_err(|e| e.to_string())?;
    let mut rows = Vec::new();
    for i in 0..count {
        let start = Instant::now();
        let prover = config()?;
        let verifier = config()?;
        let init_ms = start.elapsed().as_secs_f64() * 1000.;
        let start = Instant::now();
        let s = Statement { fee: 1, network: [1; 32], genesis: [2; 32], asset: [3; 32] };
        let witness = trace([1000000, 500000], [900000, 599999], s.fee)?;
        let public = s.public_values();
        let prepare_ms = start.elapsed().as_secs_f64() * 1000.;
        let start = Instant::now();
        let proof = prove(&prover, &BalanceAir, witness, &public).map_err(|e| format!("{e:?}"))?;
        let prove_ms = start.elapsed().as_secs_f64() * 1000.;
        let start = Instant::now();
        verify_balance(&verifier, &proof, &s)?;
        let verify_ms = start.elapsed().as_secs_f64() * 1000.;
        let start = Instant::now();
        let bytes = postcard::to_allocvec(&proof).map_err(|e| e.to_string())?;
        let serialize_ms = start.elapsed().as_secs_f64() * 1000.;
        let start = Instant::now();
        let decoded = postcard::from_bytes(&bytes).map_err(|e| e.to_string())?;
        let deserialize_ms = start.elapsed().as_secs_f64() * 1000.;
        verify_balance(&verifier, &decoded, &s)?;
        let mut file = OpenOptions::new().write(true).create_new(true).open(dir.join(format!("proof-{i:02}.postcard"))).map_err(|e| e.to_string())?;
        file.write_all(&bytes).map_err(|e| e.to_string())?;
        rows.push(serde_json::json!({"sample":i,"init_ms":init_ms,"prepare_ms":prepare_ms,
            "prove_ms":prove_ms,"verify_ms":verify_ms,"serialize_ms":serialize_ms,
            "deserialize_ms":deserialize_ms,"proof_bytes":bytes.len(),"verified":true}));
    }
    let result = serde_json::json!({"scope":"synthetic balance AIR component; NOT a private payment",
        "production_ready":false,"pq_bits_certified":null,"height":HEIGHT,"width":WIDTH,
        "samples":rows});
    std::fs::write(dir.join("samples.json"), serde_json::to_vec_pretty(&result).unwrap()).map_err(|e| e.to_string())?;
    println!("{}", result);
    Ok(())
}
