//! Native laboratory proof variant. No wire/RPC/pool compatibility is provided.
pub use zk9_public_bind_liveness_lab::{air,trace,DeliveryAir,Val};
pub use zk9_private_send_lab::{model,tree,Statement,Context,PACKET_BYTES,bind,prepare};
pub mod config;
pub use config::{config,Config,PaymentProof};
pub fn prove_payment(c:&Config,s:&Statement,w:&model::Witness)->Result<PaymentProof,String> {
    let air=DeliveryAir(air::PaymentAir::new());
    let t=trace::generate(&air.0,&s.payment,w)?;
    p3_uni_stark::prove(c,&air,t,&s.public_values()).map_err(|e|format!("{e:?}"))
}
pub fn verify_payment(c:&Config,s:&Statement,p:&PaymentProof)->Result<(),String> {
    let air=DeliveryAir(air::PaymentAir::new());
    if p.degree_bits!=air.0.graph.height().ilog2() as usize+1 {return Err("unexpected trace degree".into());}
    if s.payment.nullifiers[0]==s.payment.nullifiers[1] || s.payment.outputs[0]==s.payment.outputs[1]
        || s.payment.outputs.iter().any(|x|*x==[0;64]) {return Err("duplicate or empty note".into());}
    p3_uni_stark::verify(c,&air,p,&s.public_values()).map_err(|e|format!("{e:?}"))
}
