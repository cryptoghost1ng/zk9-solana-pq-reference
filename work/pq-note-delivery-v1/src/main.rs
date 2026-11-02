//! Synthetic interoperability/hostile-input harness. No wallet secrets accepted.
use std::{fs,path::{Path,PathBuf},time::Instant};
use zk9_note_delivery::{self as nd, model, wire};
use serde_json::{Value,json};
fn array<const N:usize>(v:&Value)->[u8;N] {
    let a=v.as_array().expect("fixture byte array");assert_eq!(a.len(),N);
    std::array::from_fn(|i|u8::try_from(a[i].as_u64().unwrap()).unwrap())
}
fn exercise(input:&Path,out:&Path) {
    fs::create_dir(out).expect("destination must be new");
    let fixture:Value=serde_json::from_slice(&fs::read(input.join("fixture.json")).unwrap()).unwrap();
    assert_eq!(fixture["Warning"],"PUBLIC SYNTHETIC SEEDS - NEVER FUND");
    let (mut payment,mut witness)=model::fixture();
    assert_eq!(array::<32>(&fixture["Context"]["Network"]),payment.context.network);
    assert_eq!(array::<32>(&fixture["Context"]["Genesis"]),payment.context.genesis);
    assert_eq!(array::<32>(&fixture["Context"]["Asset"]),payment.context.asset);
    for i in 0..2 {
        let n=&fixture["Notes"][i];
        witness.outputs[i]=model::Note {owner:array(&n["Owner"]),rho:array(&n["Rho"]),amount:n["Amount"].as_u64().unwrap()};
        payment.outputs[i]=witness.outputs[i].commitment(&payment.context);
        assert_eq!(payment.outputs[i],array::<64>(&fixture["Commitments"][i]));
    }
    let packets=std::array::from_fn(|i|fs::read(input.join(format!("packet-{i}.bin"))).unwrap());
    let statement=nd::bind(payment,&packets).unwrap();
    for i in 0..2 {assert_eq!(statement.delivery[i],array::<64>(&fixture["Digests"][i]));}
    assert_eq!(statement.public_values().len(),276);
    let started=Instant::now();let config=nd::config().unwrap();let init_ms=started.elapsed().as_secs_f64()*1000.;
    let started=Instant::now();let proof=nd::prove_payment(&config,&statement,&witness).unwrap();
    let prove_ms=started.elapsed().as_secs_f64()*1000.;
    let verifier=nd::config().unwrap();
    let started=Instant::now();nd::verify_payment(&verifier,&statement,&proof).unwrap();
    let verify_ms=started.elapsed().as_secs_f64()*1000.;
    let encoded=wire::encode(&statement,&proof,&packets).unwrap();
    let d=wire::verify(&verifier,&statement.payment.context,&encoded).unwrap();
    assert_eq!(d.packets,packets);assert_eq!(d.statement.delivery,statement.delivery);
    assert_eq!(wire::encode(&d.statement,&d.proof,&d.packets).unwrap(),encoded);
    let mut rejected=Vec::new();
    // Every appended public limb influences the actual transcript, although it
    // intentionally is not an encryption-correctness AIR constraint.
    for slot in 0..2 {for limb in 0..32 {
        let mut changed=statement.clone();changed.delivery[slot][2*limb]^=1;
        assert!(nd::verify_payment(&verifier,&changed,&proof).is_err(),"unbound ciphertext limb");
        rejected.push(format!("digest-slot{slot}-limb{limb}"));
    }}
    for k in 0..9 {
        let mut changed=statement.clone();let p=&mut changed.payment;
        match k {0=>p.context.network[0]^=1,1=>p.context.genesis[0]^=1,2=>p.context.asset[0]^=1,
            3=>p.context.fee+=1,4=>p.root[0]^=1,5=>p.nullifiers[0][0]^=1,6=>p.nullifiers[1][0]^=1,
            7=>p.outputs[0][0]^=1,_=>p.outputs[1][0]^=1}
        assert!(nd::verify_payment(&verifier,&changed,&proof).is_err());rejected.push(format!("payment-public-{k}"));
    }
    for (name,offset) in [("packet0-header",440),("packet0-kem",449),("packet0-tag",440+1731),
        ("packet1-header",440+1732),("packet1-body",440+2*1732-30),("packet1-tag",440+2*1732-1)] {
        let mut b=encoded.clone();b[offset]^=1;
        assert!(wire::verify(&verifier,&statement.payment.context,&b).is_err(),"{name}");rejected.push(name.to_string());
    }
    let mut swapped=encoded.clone();swapped[440..440+1732].copy_from_slice(&packets[1]);
    swapped[440+1732..440+2*1732].copy_from_slice(&packets[0]);
    assert!(wire::verify(&verifier,&statement.payment.context,&swapped).is_err());rejected.push("swapped-packets".into());
    for size in [0,8,439,440,440+1732,440+2*1732,encoded.len()-1] {
        assert!(wire::decode(&statement.payment.context,&encoded[..size]).is_err());rejected.push(format!("truncated-{size}"));
    }
    let mut b=encoded.clone();b.push(0);assert!(wire::decode(&statement.payment.context,&b).is_err());rejected.push("trailing-byte".into());
    for offset in [0,8,436,439] {let mut b=encoded.clone();b[offset]^=1;assert!(wire::decode(&statement.payment.context,&b).is_err());rejected.push(format!("header-{offset}"));}
    let mut b=encoded.clone();b[440+2*1732]^=1;assert!(wire::verify(&verifier,&statement.payment.context,&b).is_err());rejected.push("proof-mutation".into());
    let mut b=encoded[..440+2*1732].to_vec();let hostile=[0xff,0xff,0xff,0xff,0x0f];
    b[436..440].copy_from_slice(&(hostile.len() as u32).to_le_bytes());b.extend(hostile);
    assert!(wire::decode(&statement.payment.context,&b).is_err());rejected.push("hostile-proof-length-prefix".into());
    // Even with identical payment fields, a delivery-bound proof must not be
    // accepted by the previous unbound protocol / different transcript domain.
    let old:zk9_private_tree_lab::PaymentProof=postcard::from_bytes(&postcard::to_allocvec(&proof).unwrap()).unwrap();
    assert!(zk9_private_tree_lab::verify_payment(&zk9_private_tree_lab::config().unwrap(),&statement.payment,&old).is_err());
    rejected.push("cross-version-old-verifier".into());
    fs::write(out.join("envelope.bin"),&encoded).unwrap();
    fs::copy(input.join("fixture.json"),out.join("fixture.json")).unwrap();
    let report=json!({"status":"PASS_BOUND_DELIVERY_LAB","init_ms":init_ms,"prove_ms_including_trace":prove_ms,
        "verify_ms":verify_ms,"envelope_bytes":encoded.len(),"packet_bytes":nd::PACKET_BYTES,"public_fields":276,
        "recipient_commitments":statement.payment.outputs.map(|d|d.to_vec()),"delivery_hashes":statement.delivery.map(|d|d.to_vec()),
        "rejections":rejected,"notes":2,"amounts":[witness.outputs[0].amount,witness.outputs[1].amount],
        "fee":statement.payment.context.fee,"protection_scope":"proof binds mandatory encrypted packets; NOT proof of correct encryption; recipient validates plaintext"});
    fs::write(out.join("checks.json"),serde_json::to_vec_pretty(&report).unwrap()).unwrap();println!("{report}");
}
fn main(){let args:Vec<String>=std::env::args().collect();assert_eq!(args.len(),4,"exercise FIXTURE NEW_OUTPUT");assert_eq!(args[1],"exercise");exercise(&PathBuf::from(&args[2]),&PathBuf::from(&args[3]));}
