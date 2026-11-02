//! Experimental v3 native transport. No deployed verifier or pool accepts it.
mod bounded;
pub mod wire;
pub mod profile;
pub use candidate::{config, Config, PaymentProof, Context, Statement, PACKET_BYTES,
                    bind, model, verify_payment, DeliveryAir, Val, air};
use p3_field::PrimeCharacteristicRing;

/// Cheap fixed-profile rejection after bounded canonical deserialization.
/// Framing and shape never substitute for cryptographic verification.
fn fixed_shape(p: &PaymentProof) -> Result<(), String> {
    let v = &p.opened_values;
    if p.degree_bits != 13 || p.ood_pow_witness != candidate::Val::ZERO
        || v.trace_local.len() != 7525
        || v.trace_next.as_ref().is_none_or(|x| x.len() != 7525)
        || v.preprocessed_local().is_some() || v.preprocessed_next().is_some()
        || v.quotient_chunks.len() != 16 || v.quotient_chunks.iter().any(|x| x.len() != 8)
        || v.random.as_ref().is_none_or(|x| x.len() != 8)
        || p.commitments.trace.roots().len() != 1
        || p.commitments.quotient_chunks.roots().len() != 1
        || p.commitments.random.as_ref().is_none_or(|x| x.roots().len() != 1)
    {
        return Err("candidate fixed proof profile".into());
    }
    Ok(())
}
