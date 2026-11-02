//! Experimental payment-bound note delivery. No node/wallet deployment implied.
mod bounded;
pub mod graph;
pub mod air;
pub mod layout;
pub mod trace;
mod builder;
pub mod config;
pub mod wire;
pub mod prepare;
pub use zk9_private_tree_lab::{Val, model, tree};
pub use zk9_hiding_balance_component::Statement as Context;
pub use config::{config, Config, PaymentProof};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::PrimeCharacteristicRing;
use model::{Digest, Witness};

pub const PACKET_BYTES: usize = 1732;
pub const PUBLIC_VALUES: usize = 276;

#[derive(Clone)]
pub struct Statement {
    pub payment: model::Statement,
    pub delivery: [Digest; 2],
}
impl Statement {
    pub fn public_values(&self) -> Vec<Val> {
        let mut v = self.payment.public_values();
        for hash in &self.delivery {
            v.extend(hash.chunks_exact(2).map(|b| Val::from_u16(u16::from_le_bytes([b[0],b[1]]))));
        }
        v
    }
}

// Ciphertext digests are associated data, not a claim that the sender encrypted
// the correct plaintext. Pinned uni-stark transcript.rs constraint_phase absorbs
// ALL public scalars before alpha (prover and verifier), and binds their count.
// A different digest therefore changes the proof's Fiat-Shamir challenges.
// The recipient must still authenticate/decrypt and recompute the commitment.
pub struct DeliveryAir(pub air::PaymentAir);
impl<F> BaseAir<F> for DeliveryAir {
    fn width(&self) -> usize { self.0.width() }
    fn num_public_values(&self) -> usize { PUBLIC_VALUES }
}
impl<AB: AirBuilder> Air<AB> for DeliveryAir {
    fn eval(&self, b: &mut AB) { self.0.eval(b); }
}

pub fn digest(c: &Context, cm: &Digest, slot: usize, packet: &[u8]) -> Result<Digest,String> {
    if slot >= 2 || packet.len() != PACKET_BYTES { return Err("delivery framing".into()); }
    let mut bytes = b"ZK9/NOTE-DELIVERY/DIGEST/v1\0".to_vec();
    for x in [&c.network,&c.genesis,&c.asset] { bytes.extend(x); }
    bytes.extend(cm); bytes.push(slot as u8); bytes.extend(packet);
    Ok(model::hash(&bytes))
}
pub fn bind(payment: model::Statement, packets: &[Vec<u8>;2]) -> Result<Statement,String> {
    let delivery = [digest(&payment.context,&payment.outputs[0],0,&packets[0])?,
                    digest(&payment.context,&payment.outputs[1],1,&packets[1])?];
    Ok(Statement { payment, delivery })
}
pub fn prove_payment(c: &Config, s: &Statement, w: &Witness) -> Result<PaymentProof,String> {
    let air = DeliveryAir(air::PaymentAir::new());
    let trace = trace::generate(&air.0,&s.payment,w)?;
    p3_uni_stark::prove(c,&air,trace,&s.public_values()).map_err(|e|format!("{e:?}"))
}
pub fn verify_payment(c: &Config, s: &Statement, p: &PaymentProof) -> Result<(),String> {
    let air = DeliveryAir(air::PaymentAir::new());
    if p.degree_bits != air.0.graph.height().ilog2() as usize + 1 { return Err("unexpected trace degree".into()); }
    if s.payment.nullifiers[0] == s.payment.nullifiers[1] || s.payment.outputs[0] == s.payment.outputs[1]
        || s.payment.outputs.iter().any(|x| *x == [0;64]) { return Err("duplicate or empty note".into()); }
    p3_uni_stark::verify(c,&air,p,&s.public_values()).map_err(|e|format!("{e:?}"))
}
