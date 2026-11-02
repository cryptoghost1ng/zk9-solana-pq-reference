//! Reuse qualified synthetic proofs; never generate new proofs in this harness.
use std::{fs, path::Path};
use zk9_public_bind_wire_lab as transport;
use transport::{model::{self, Note}, wire};
use p3_field::PrimeField64;

fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 3, "proof fixture directory and NEW output directory required");
    let source = Path::new(&args[1]);
    let out = Path::new(&args[2]);
    assert!(!out.exists(), "preserve existing evidence");
    fs::create_dir_all(out).unwrap();
    let packets = [vec![21; transport::PACKET_BYTES], vec![22; transport::PACKET_BYTES]];
    let (mut payment, w) = model::fixture();
    payment.nullifiers = std::array::from_fn(|i| {
        let n = &w.inputs[i];
        let note = Note { owner: model::address(&n.secret), rho: n.rho, amount: n.amount };
        model::nullifier(&payment.context, &n.secret, &note.commitment(&payment.context))
    });
    payment.outputs = w.outputs.clone().map(|n| n.commitment(&payment.context));
    let s = transport::bind(payment, &packets).unwrap();
    let context = &s.payment.context;
    let public: Vec<_> = s.public_values().iter().map(|x| x.as_canonical_u64()).collect();
    let proof_bytes = fs::read(source.join("candidate-two.proof.bin")).unwrap();
    let recorded: serde_json::Value = serde_json::from_slice(&fs::read(source.join("candidate-two.json")).unwrap()).unwrap();
    assert_eq!(serde_json::json!(public), recorded["public_values"]);
    assert_eq!(proof_bytes.len(), recorded["proof_bytes"].as_u64().unwrap() as usize);
    let digest: String = model::hash(&proof_bytes).iter().map(|x| format!("{x:02x}")).collect();
    assert_eq!(digest, recorded["proof_sha3_512"].as_str().unwrap());
    // Trusted, hash-matched local fixture input. Network inputs use wire::decode.
    let proof: transport::PaymentProof = postcard::from_bytes(&proof_bytes).unwrap();
    let encoded = wire::encode(&s, &proof, &packets).unwrap();
    let c = transport::config().unwrap();
    let decoded = wire::verify(&c, context, &encoded).unwrap();
    assert_eq!(decoded.statement.public_values(), s.public_values());
    assert_eq!(decoded.packets, packets);
    assert_eq!(wire::encode(&decoded.statement, &decoded.proof, &decoded.packets).unwrap(), encoded);
    fs::write(out.join("candidate-v3.bin"), &encoded).unwrap();
    let profile = transport::profile::Profile::derive();
    assert_eq!((profile.shape.main_width, profile.shape.num_public_values,
        profile.shape.log_degree, profile.shape.log_ext_degree, profile.shape.num_quotient_chunks),
        (7525, 276, 12, 13, 16));
    let seed: Vec<_> = profile.seed_words.iter().flat_map(|w| w.to_le_bytes()).collect();
    fs::write(out.join("seed.bin"), &seed).unwrap();
    fs::write(out.join("profile.json"), serde_json::to_vec_pretty(&profile.evidence()).unwrap()).unwrap();
    let reference = transport::profile::prefix(&profile, context, &encoded).unwrap();
    fs::write(out.join("prefix.json"), serde_json::to_vec_pretty(&reference.evidence()).unwrap()).unwrap();
    let mut controls: Vec<String> = vec![];
    for end in [0, 8, 12, 439, 440, 3903, 3904, encoded.len()-1] {
        assert!(wire::decode(context, &encoded[..end]).is_err());
        controls.push(format!("truncated-{end}"));
    }
    for offset in [0, 8, 12, 44, 76, 436] {
        let mut changed = encoded.clone(); changed[offset] ^= 1;
        assert!(wire::decode(context, &changed).is_err(), "framing/context offset {offset}");
        controls.push(format!("framing-context-{offset}"));
    }
    for offset in [108, 116, 180, 244, 308, 372, 440, 2172] {
        let mut changed = encoded.clone(); changed[offset] ^= 1;
        assert!(wire::verify(&c, context, &changed).is_err(), "public/packet offset {offset}");
        controls.push(format!("public-or-packet-{offset}"));
    }
    for pair in [(180,244), (308,372)] {
        let mut changed = encoded.clone();
        changed.copy_within(pair.0..pair.0+64, pair.1);
        assert!(wire::decode(context, &changed).is_err());
        controls.push(format!("duplicate-{}", pair.1));
    }
    let mut zero = encoded.clone(); zero[308..372].fill(0);
    assert!(wire::decode(context, &zero).is_err()); controls.push("empty-output".into());
    let mut trailing = encoded.clone(); trailing.push(0);
    assert!(wire::decode(context, &trailing).is_err()); controls.push("trailing-envelope".into());
    let len = (trailing.len()-3904) as u32;
    trailing[436..440].copy_from_slice(&len.to_le_bytes());
    assert!(wire::decode(context, &trailing).is_err()); controls.push("trailing-proof".into());
    let mut old_header = encoded.clone(); old_header[..8].copy_from_slice(b"ZK9PQS2\0");
    old_header[8..12].copy_from_slice(&2u32.to_le_bytes());
    assert!(wire::decode(context, &old_header).is_err()); controls.push("old-header".into());
    assert!(old::wire::decode(context, &encoded).is_err()); controls.push("old-decoder-new-header".into());
    assert!(old::wire::verify(&old::config().unwrap(), context, &old_header).is_err());
    controls.push("candidate-proof-relabelled-v2".into());
    let baseline = fs::read(source.join("baseline-two.proof.bin")).unwrap();
    let baseline_proof: old::PaymentProof = postcard::from_bytes(&baseline).unwrap();
    let baseline_wire = old::wire::encode(&s, &baseline_proof, &packets).unwrap();
    old::wire::verify(&old::config().unwrap(), context, &baseline_wire).unwrap();
    let mut old_proof = encoded[..3904].to_vec();
    old_proof[436..440].copy_from_slice(&(baseline.len() as u32).to_le_bytes());
    old_proof.extend(&baseline);
    assert!(wire::decode(context, &old_proof).is_err()); controls.push("baseline-proof-relabelled-v3".into());
    let report = serde_json::json!({"status":"PASS_NATIVE_V3_TRANSPORT", "controls":controls,
        "wire_bytes":encoded.len(), "fixture_proof_sha3_512":digest,
        "baseline_positive_verified":true,
        "native_profile_derived":true,"seed_bytes":seed.len(),
        "synthetic_packets":true,"new_proofs_generated":false,"sbf_integration":false,"production_ready":false});
    fs::write(out.join("report.json"), serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    println!("{report}");
}
