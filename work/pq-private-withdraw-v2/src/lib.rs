//! Experimental native withdrawal relation. No keeper, bank transfer or bridge.
mod bounded;
mod builder;
pub mod balance;
pub mod graph;
pub mod layout;
pub mod air;
pub mod trace;
pub mod config;
pub mod wire;
pub mod prepare;
pub mod ffi;
pub use zk9_private_tree_lab::{Val,model,tree};
pub use zk9_hiding_balance_component::Statement as Context;
pub use config::{config,Config,PaymentProof};
use p3_field::PrimeCharacteristicRing;
pub const PACKET_BYTES:usize=1732;
pub const PUBLIC_VALUES:usize=297;
pub const MODE:u8=1;
#[derive(Clone)]
pub struct Statement {
    pub payment:model::Statement,
    pub delivery:[model::Digest;2],
    pub amount:u64,
    pub recipient:[u8;32],
    pub mode:u8,
}
impl Statement {
    pub fn public_values(&self)->Vec<Val> {
        let mut v=self.payment.public_values();
        for h in &self.delivery {v.extend(h.chunks_exact(2).map(|b|Val::from_u16(u16::from_le_bytes([b[0],b[1]]))));}
        v.extend((0..4).map(|k|Val::from_u16((self.amount>>(16*k)) as u16)));
        v.extend(self.recipient.chunks_exact(2).map(|b|Val::from_u16(u16::from_le_bytes([b[0],b[1]]))));
        v.push(Val::from_u8(self.mode)); v
    }
    pub fn validate(&self)->Result<(),String> {
        let c=&self.payment.context;
        if self.mode!=MODE || self.amount==0 || self.recipient==[0;32] || c.fee==0
            || c.network==[0;32] || c.genesis==[0;32] || c.asset==[0;32] {
            return Err("invalid withdrawal statement".into());
        }
        if self.payment.nullifiers[0]==self.payment.nullifiers[1] || self.payment.outputs[0]==self.payment.outputs[1]
            || self.payment.outputs.iter().any(|x|*x==[0;64]) {return Err("duplicate or empty note".into());}
        Ok(())
    }
}
// Delivery digest definition and packet format intentionally remain compatible
// with the existing native scanner. As before, these are transcript-bound AD;
// the recipient must authenticate/decrypt and recompute each note commitment.
pub use zk9_private_send_lab::digest;
pub fn bind(payment:model::Statement,amount:u64,recipient:[u8;32],packets:&[Vec<u8>;2])->Result<Statement,String> {
    let delivery=[digest(&payment.context,&payment.outputs[0],0,&packets[0])?,digest(&payment.context,&payment.outputs[1],1,&packets[1])?];
    let s=Statement{payment,delivery,amount,recipient,mode:MODE};s.validate()?;Ok(s)
}
pub fn prove_withdrawal(c:&Config,s:&Statement,w:&model::Witness)->Result<PaymentProof,String> {
    s.validate()?;
    let a=air::PaymentAir::new();let t=trace::generate(&a,s,w)?;
    p3_uni_stark::prove(c,&a,t,&s.public_values()).map_err(|e|format!("{e:?}"))
}
pub fn verify_withdrawal(c:&Config,s:&Statement,p:&PaymentProof)->Result<(),String> {
    s.validate()?;let a=air::PaymentAir::new();
    if p.degree_bits!=a.graph.height().ilog2() as usize+1 {return Err("unexpected withdrawal degree".into());}
    p3_uni_stark::verify(c,&a,p,&s.public_values()).map_err(|e|format!("{e:?}"))
}
