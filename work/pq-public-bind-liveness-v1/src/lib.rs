//! UNVALIDATED laboratory AIR experiment. No verifier, wire format, pool or
//! proving API is exposed here. Never pass this AIR to the existing config:
//! adoption requires a new circuit domain, proofs and verifier implementation.
pub use zk9_private_send_lab::{Val, model, graph};
pub mod air;
pub mod binding;
pub mod layout;
pub mod trace;
mod builder;
use p3_air::{Air, AirBuilder, BaseAir};
pub struct DeliveryAir(pub air::PaymentAir);
impl<F> BaseAir<F> for DeliveryAir {
    fn width(&self)->usize {self.0.width()}
    fn num_public_values(&self)->usize {zk9_private_send_lab::PUBLIC_VALUES}
}
impl<AB:AirBuilder> Air<AB> for DeliveryAir {
    fn eval(&self,b:&mut AB) {self.0.eval(b);}
}
