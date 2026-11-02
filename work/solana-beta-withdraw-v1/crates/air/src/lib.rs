//! Experimental bounded evaluator for the pinned DeliveryAir. NOT a payment verifier.
//! The schedule is compiler output, never transaction-supplied executable code.
#![no_std]
#![forbid(unsafe_code)]
pub mod domain;
pub use arithmetic::field::{Ext, F};
pub const WIDTH: usize = 10729;
pub const PUBLIC: usize = 297;
pub const HEADER: usize = 256;
pub const MAX_WORK: usize = 64;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error { Encoding, Shape, Schedule, State, Limit, Done, Field, ZeroDenominator, Relation }
impl From<arithmetic::Error> for Error { fn from(_: arithmetic::Error) -> Self { Self::Field } }
fn u32_at(b: &[u8], at: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(b.get(at..at + 4).ok_or(Error::Encoding)?.try_into().unwrap()))
}
fn put(b: &mut [u8], at: usize, n: usize) { b[at..at + 4].copy_from_slice(&(n as u32).to_le_bytes()); }

/// Only construct from compiler-produced, source-pinned immutable bytes.
/// Validation here checks framing; the compiler checks def/use and liveness.
pub struct Program<'a> { bytes: &'a [u8], pub instructions: usize, pub slots: usize, pub constraints: usize }
impl<'a> Program<'a> {
    pub fn from_trusted_compiler(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.get(..8) != Some(b"ZK9AIRW2") || bytes.len() < 64 { return Err(Error::Schedule); }
        if u32_at(bytes, 8)? as usize != WIDTH || u32_at(bytes, 12)? as usize != PUBLIC
            || bytes[28..64].iter().any(|x| *x != 0) { return Err(Error::Schedule); }
        let instructions = u32_at(bytes, 16)? as usize;
        let slots = u32_at(bytes, 20)? as usize;
        let constraints = u32_at(bytes, 24)? as usize;
        if instructions == 0 || slots == 0 || slots > 131072 || constraints == 0
            || constraints > instructions || instructions > 4_000_000
            || bytes.len() != 64 + instructions * 16 { return Err(Error::Schedule); }
        Ok(Self { bytes, instructions, slots, constraints })
    }
    pub fn state_bytes(&self) -> usize { HEADER + self.slots * 32 }
    fn instruction(&self, pc: usize) -> Result<[u32; 4], Error> {
        let at = 64 + pc * 16;
        Ok([u32_at(self.bytes, at)?, u32_at(self.bytes, at+4)?, u32_at(self.bytes, at+8)?, u32_at(self.bytes, at+12)?])
    }
}

pub trait Inputs {
    fn trace(&self, row: usize, column: usize) -> Result<Ext, Error>;
    fn public(&self, index: usize) -> Result<F, Error>;
}
/// Borrows original authenticated proof bytes; no decoding of whole rows into heap Vecs.
pub struct WireInputs<'a> { pub claims: arithmetic::claims::Claims<'a>, pub public: [u32; PUBLIC] }
impl<'a> WireInputs<'a> {
    pub fn from_trusted_format(context: &prefix::Context, wire: &'a [u8], format: &[u8]) -> Result<Self, Error> {
        let public = prefix::public_values(context, wire).map_err(|_| Error::Shape)?.words_montgomery;
        let claims = arithmetic::claims::Claims::from_trusted_format(wire, format)?;
        Ok(Self { claims, public })
    }
}
impl Inputs for WireInputs<'_> {
    fn trace(&self, row: usize, column: usize) -> Result<Ext, Error> {
        if row > 1 || column >= WIDTH { return Err(Error::Shape); }
        Ok(self.claims.get(1 + row, column)?)
    }
    fn public(&self, index: usize) -> Result<F, Error> {
        Ok(F::from_montgomery(*self.public.get(index).ok_or(Error::Shape)?)?)
    }
}
#[derive(Clone, Copy)]
pub struct Context {
    pub alpha: Ext, pub first: Ext, pub last: Ext, pub transition: Ext,
    pub inv_vanishing: Ext, pub quotient: Ext,
}
/// Scratch is owned by the caller. In Solana it must be a program-owned account,
/// bound to the immutable source and a pinned schedule; not a caller checkpoint.
pub struct Progress<'a> { state: &'a mut [u8] }
impl<'a> Progress<'a> {
    pub fn start(state: &'a mut [u8], p: &Program, c: &Context) -> Result<Self, Error> {
        if state.len() != p.state_bytes() || state.iter().any(|x| *x != 0) { return Err(Error::State); }
        state[..8].copy_from_slice(b"ZK9AIPW2");
        for (i, x) in [c.alpha,c.first,c.last,c.transition,c.inv_vanishing,c.quotient,Ext::ZERO].iter().enumerate() {
            x.encode(&mut state[16+i*32..48+i*32])?;
        }
        Ok(Self { state })
    }
    pub fn resume_trusted(state: &'a mut [u8], p: &Program) -> Result<Self, Error> {
        if state.len() != p.state_bytes() || &state[..8] != b"ZK9AIPW2"
            || u32_at(state,8)? as usize > p.instructions || u32_at(state,12)? as usize > p.constraints
            || state[240..256].iter().any(|x| *x != 0) { return Err(Error::State); }
        Ok(Self { state })
    }
    fn get(&self, slot: usize, p: &Program) -> Result<Ext, Error> {
        if slot >= p.slots { return Err(Error::Schedule); }
        Ok(Ext::decode(&self.state[HEADER+slot*32..HEADER+(slot+1)*32], false)?)
    }
    fn context(&self, at: usize) -> Result<Ext, Error> { Ok(Ext::decode(&self.state[at..at+32], false)?) }
    pub fn accumulator(&self) -> Result<Ext, Error> { self.context(208) }
    pub fn pc(&self) -> usize { u32_at(self.state,8).unwrap() as usize }
    pub fn advance(&mut self, p: &Program, inputs: &impl Inputs, work: usize) -> Result<bool, Error> {
        if work == 0 || work > MAX_WORK { return Err(Error::Limit); }
        let pc = self.pc(); if pc == p.instructions { return Err(Error::Done); }
        let end = core::cmp::min(pc+work,p.instructions);
        let mut count = u32_at(self.state,12)? as usize;
        let mut accumulator = self.accumulator()?;
        let alpha = self.context(16)?;
        for i in pc..end {
            let [op,dst,x,y] = p.instruction(i)?;
            let (dst,x,y) = (dst as usize,x as usize,y as usize);
            if op == 9 {
                if dst != 0 || y != 0 { return Err(Error::Schedule); }
                accumulator = accumulator*alpha + self.get(x,p)?; count += 1;
            } else {
                if dst >= p.slots { return Err(Error::Schedule); }
                let v = match op {
                    0 | 1 => { if y != 0 { return Err(Error::Schedule); } inputs.trace(op as usize,x)? },
                    2 => { if y != 0 { return Err(Error::Schedule); } Ext::base(inputs.public(x)?) },
                    3 => { if x > 2 || y != 0 { return Err(Error::Schedule); } self.context(48+x*32)? },
                    4 => { if y != 0 { return Err(Error::Schedule); } Ext::base(F::new(x as u32)?) },
                    5 => self.get(x,p)? + self.get(y,p)?,
                    6 => self.get(x,p)? - self.get(y,p)?,
                    7 => self.get(x,p)? * self.get(y,p)?,
                    8 => { if y != 0 { return Err(Error::Schedule); } -self.get(x,p)? },
                    _ => return Err(Error::Schedule),
                };
                v.encode(&mut self.state[HEADER+dst*32..HEADER+(dst+1)*32])?;
            }
        }
        if count > p.constraints { return Err(Error::Schedule); }
        accumulator.encode(&mut self.state[208..240])?;
        put(self.state,8,end); put(self.state,12,count);
        Ok(end == p.instructions)
    }
    pub fn check_relation(&self, p: &Program) -> Result<(), Error> {
        if self.pc() != p.instructions || u32_at(self.state,12)? as usize != p.constraints { return Err(Error::State); }
        if self.accumulator()? * self.context(144)? != self.context(176)? { return Err(Error::Relation); }
        Ok(())
    }
}
