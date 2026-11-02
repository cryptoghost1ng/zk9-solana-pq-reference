//! Pinned profile: base trace H_4096; quotient coset 31*H_65536 split into 16.
use crate::{Context,Error,Ext,F};
use arithmetic::{field::generator,claims::Claims};
pub fn selectors(zeta: Ext) -> Result<[Ext;4],Error> {
    let vanishing = zeta.pow(4096)-Ext::ONE;
    let inv = vanishing.inverse().ok_or(Error::ZeroDenominator)?;
    let transition = zeta-Ext::base(generator(12)?.inverse().ok_or(Error::ZeroDenominator)?);
    Ok([vanishing*(zeta-Ext::ONE).inverse().ok_or(Error::ZeroDenominator)?,
        vanishing*transition.inverse().ok_or(Error::ZeroDenominator)?,transition,inv])
}
/// One quotient chunk per call; caller sums all sixteen in their pinned order.
pub fn quotient_chunk(claims: &Claims, zeta: Ext, i: usize) -> Result<Ext,Error> {
    if i >= 16 { return Err(Error::Shape); }
    let g = generator(16)?;
    let shift = F::new(31)?*g.pow(i as u32);
    let mut weight = Ext::ONE;
    for j in 0..16 {
        if i == j { continue; }
        let other_inv = (F::new(31)?*g.pow(j as u32)).inverse().ok_or(Error::ZeroDenominator)?;
        let numerator = zeta.scale(other_inv).pow(4096)-Ext::ONE;
        let denominator = (shift*other_inv).pow(4096)-F::ONE;
        weight = (weight*numerator).scale(denominator.inverse().ok_or(Error::ZeroDenominator)?);
    }
    // Each of the eight chunk coefficients is itself an extension evaluation.
    let mut chunk = Ext::ZERO;
    for k in 0..8 { let mut basis = [F::ZERO;8]; basis[k] = F::ONE; chunk = chunk+claims.get(3+i,k)?*Ext(basis); }
    Ok(weight*chunk)
}
/// Native convenience; the SBF integration must bound quotient work separately.
pub fn from_trusted_prefix(prefix: &[u8], claims: &Claims) -> Result<Context,Error> {
    if prefix.len() != 288 || &prefix[..8] != b"ZK9PFXW2" { return Err(Error::State); }
    let alpha = Ext::decode(&prefix[8..40],false)?;
    let zeta = Ext::decode(&prefix[40..72],false)?;
    let [first,last,transition,inv_vanishing] = selectors(zeta)?;
    let mut quotient = Ext::ZERO;
    for i in 0..16 { quotient = quotient+quotient_chunk(claims,zeta,i)?; }
    Ok(Context { alpha,first,last,transition,inv_vanishing,quotient })
}
