//! Fixed-profile PCS reductions and FRI arithmetic. Not a complete proof verifier.
#![no_std]
#![forbid(unsafe_code)]
pub mod field;
pub mod claims;
pub mod reduce;
pub mod fold;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Error{Field,Encoding,Shape,State,Limit,Done,UnauthenticatedInputs,ZeroDenominator,ZetaInDomain,FinalPolynomial}
