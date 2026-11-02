pub mod air;
mod builder;
pub mod graph;
pub mod model;
pub mod trace;
pub mod ledger;
pub mod config;
pub mod layout;
pub mod profile;
pub mod tree;
pub use zk9_hiding_balance_component::Val;
pub use config::{config,Config,PaymentProof};
use p3_uni_stark::{prove, verify};
use air::PaymentAir;
use model::{Statement,Witness};
pub fn prove_payment(c:&Config,s:&Statement,w:&Witness)->Result<PaymentProof,String> {
    let air=PaymentAir::new();let trace=trace::generate(&air,s,w)?;
    prove(c,&air,trace,&s.public_values()).map_err(|e|format!("{e:?}"))
}
pub fn verify_payment(c:&Config,s:&Statement,p:&PaymentProof)->Result<(),String> {
    let air=PaymentAir::new();
    if p.degree_bits!=air.graph.height().ilog2() as usize+1 {return Err("unexpected trace degree".into());}
    if s.nullifiers[0]==s.nullifiers[1] {return Err("duplicate input nullifier".into());}
    if s.outputs[0]==s.outputs[1] {return Err("duplicate output commitment".into());}
    verify(c,&air,p,&s.public_values()).map_err(|e|format!("{e:?}"))
}
#[cfg(test)]
mod tests;
