//! Consumer boundary for the immutable, laboratory ZK9PRF07 (packed-schedule) proof program.
//! A completed proof is not authorization against a pool's current state.
//! The caller MUST still check anchors, nullifiers, capacity, backing and fees,
//! and atomically commit the note-tree transition and any asset settlement.
#![no_std]
#![forbid(unsafe_code)]

use arithmetic::field::F;
use solana_program::{account_info::AccountInfo, bpf_loader_upgradeable, program_error::ProgramError, pubkey::Pubkey};

pub const PROOF_PROGRAM: Pubkey = Pubkey::new_from_array([222, 139, 142, 244, 90, 96, 31, 228, 249, 190, 39, 216, 10, 188, 165, 253, 207, 133, 64, 64, 112, 24, 244, 181, 231, 114, 160, 221, 113, 124, 138, 42]);
pub const BUFFER_PROGRAM: Pubkey = Pubkey::new_from_array([231,138,104,189,143,12,113,233,104,11,207,43,153,194,139,84,167,203,114,202,199,220,160,15,198,101,146,200,130,3,130,73]);
pub const RECEIPT_BYTES: usize = 328732;
pub const PACKET_BYTES: usize = 1732;
const AIR_CONTROL: usize = 86908;
const PUBLIC: usize = 86924;
const AIR_STATE: usize = 88188;
const WIRE_PREFIX: usize = 3904;
const WIRE_HEADER: usize = 440;
pub type Digest = [u8;64];

#[derive(Clone,Copy)]
pub struct Context {
    pub network: [u8;32],
    pub genesis: [u8;32],
    pub asset: [u8;32],
}

/// These must be actual AccountInfos supplied by the Solana runtime. Native
/// fabricated AccountInfos only test parsing, never prove account authenticity.
pub struct Accounts<'a,'info> {
    pub receipt: &'a AccountInfo<'info>,
    pub proof_program: &'a AccountInfo<'info>,
    pub proof_program_data: &'a AccountInfo<'info>,
    pub source: &'a AccountInfo<'info>,
    pub buffer_program: &'a AccountInfo<'info>,
    pub buffer_program_data: &'a AccountInfo<'info>,
}

/// No public constructor or mutable accessors: only the authenticated callback
/// below can expose this value. It deliberately says "proof", not "spend".
pub struct CompletedProof {
    session: Pubkey,
    source: Pubkey,
    fee: u64,
    root: Digest,
    nullifiers: [Digest;2],
    outputs: [Digest;2],
    delivery: [Digest;2],
}
impl CompletedProof {
    pub fn session(&self)->&Pubkey { &self.session }
    pub fn source(&self)->&Pubkey { &self.source }
    pub fn fee(&self)->u64 { self.fee }
    pub fn root(&self)->&Digest { &self.root }
    pub fn nullifiers(&self)->&[Digest;2] { &self.nullifiers }
    pub fn outputs(&self)->&[Digest;2] { &self.outputs }
    pub fn delivery_digests(&self)->&[Digest;2] { &self.delivery }
}

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Error {
    Program = 6000,
    ProgramData,
    ReceiptOwner,
    ReceiptShape,
    Incomplete,
    SourceOwner,
    SourceShape,
    SourceBinding,
    Context,
    PublicField,
    PublicBinding,
}
impl From<Error> for ProgramError {
    fn from(value:Error)->Self { Self::Custom(value as u32) }
}
fn n(bytes:&[u8],at:usize)->usize {
    u32::from_le_bytes(bytes[at..at+4].try_into().expect("checked fixed layout")) as usize
}

#[inline(never)]
fn immutable_program(program:&AccountInfo,code:&AccountInfo,id:&Pubkey)->Result<(),ProgramError> {
    if program.key!=id || !program.executable || program.is_writable || program.owner!=&bpf_loader_upgradeable::id() {
        return Err(Error::Program.into());
    }
    if code.executable || code.is_writable || code.owner!=&bpf_loader_upgradeable::id() {
        return Err(Error::ProgramData.into());
    }
    let p=program.try_borrow_data()?;
    let c=code.try_borrow_data()?;
    if p.len()!=36 || n(&p,0)!=2 || &p[4..36]!=code.key.as_ref() || c.len()<=45 || n(&c,0)!=3 || c[12]!=0 {
        return Err(Error::ProgramData.into());
    }
    Ok(())
}

#[inline(never)]
fn completed(state:&[u8])->Result<(),Error> {
    if state.len()!=RECEIPT_BYTES || &state[..8]!=b"ZK9PRF07" || state[124..128]!=[0;4] {
        return Err(Error::ReceiptShape);
    }
    // Completion is independent of how a caller splits bounded work into
    // transactions. Never require the benchmark's particular sequence counts.
    if n(state,172)!=1 || n(state,120)!=3 || n(state,18992)!=6 || n(state,18996)!=13
        || state[19000..19004]!=[0;4] || n(state,AIR_CONTROL+4)!=4 || n(state,AIR_CONTROL+8)!=16
        || state[AIR_CONTROL+12..PUBLIC]!=[0;4] || &state[AIR_STATE..AIR_STATE+8]!=b"ZK9AIRP3"
        || n(state,AIR_STATE+8)!=332613 || n(state,AIR_STATE+12)!=50343
        || state[AIR_STATE+240..AIR_STATE+256]!=[0;16] {
        return Err(Error::Incomplete);
    }
    Ok(())
}

#[inline(never)]
fn source_offset(data:&[u8])->Result<usize,Error> {
    if data.len()<85 || &data[..8]!=b"ZK9BUF1\0" || data[80]!=2 || data[81..85]!=[0;4] {
        return Err(Error::SourceShape);
    }
    let total=n(data,40);
    if total<=WIRE_PREFIX || total>WIRE_PREFIX+4*1024*1024 { return Err(Error::SourceShape); }
    let count=(total+899)/900;
    let start=85+(count+7)/8+count*32;
    if n(data,44)!=count || data.len()!=start+total { return Err(Error::SourceShape); }
    let wire=&data[start..];
    if &wire[..8]!=b"ZK9PQS3\0" || n(wire,8)!=3 || n(wire,436)!=total-WIRE_PREFIX {
        return Err(Error::SourceShape);
    }
    Ok(start)
}

fn digest(words:&[u16;276],at:usize)->Digest {
    let mut out=[0;64];
    for i in 0..32 { out[2*i..2*i+2].copy_from_slice(&words[at+i].to_le_bytes()); }
    out
}

#[inline(never)]
fn statement(state:&[u8],wire:&[u8],expected:&Context,session:Pubkey,source:Pubkey)->Result<CompletedProof,Error> {
    if expected.network==[0;32] || expected.genesis==[0;32] || expected.asset==[0;32]
        || wire[12..44]!=expected.network || wire[44..76]!=expected.genesis || wire[76..108]!=expected.asset {
        return Err(Error::Context);
    }
    let mut words=[0u16;276];
    for (i,w) in words.iter_mut().enumerate() {
        let canonical=F::from_montgomery(n(state,PUBLIC+4*i) as u32).map_err(|_|Error::PublicField)?.canonical();
        *w=u16::try_from(canonical).map_err(|_|Error::PublicField)?;
    }
    // Public statement layout is fee, network/genesis/asset, root, nullifiers,
    // output commitments and two delivery digests, all little-endian u16 limbs.
    let fee=(0..4).fold(0u64,|v,i|v|((words[i] as u64)<<(i*16)));
    for i in 0..48 {
        if words[4+i].to_le_bytes()!=wire[12+i*2..14+i*2] { return Err(Error::PublicBinding); }
    }
    let out=CompletedProof { session,source,fee,root:digest(&words,52),
        nullifiers:[digest(&words,84),digest(&words,116)],
        outputs:[digest(&words,148),digest(&words,180)],
        delivery:[digest(&words,212),digest(&words,244)] };
    if fee.to_le_bytes()!=wire[108..116] || out.root!=wire[116..180]
        || out.nullifiers[0]!=wire[180..244] || out.nullifiers[1]!=wire[244..308]
        || out.outputs[0]!=wire[308..372] || out.outputs[1]!=wire[372..436]
        || &state[768..776]!=b"ZK9PFX3\0" || out.delivery[0]!=state[920..984]
        || out.delivery[1]!=state[984..1048] || fee.to_le_bytes()!=state[1048..1056]
        || out.nullifiers[0]==out.nullifiers[1] || out.outputs[0]==out.outputs[1]
        || out.outputs.iter().any(|x|*x==[0;64]) {
        return Err(Error::PublicBinding);
    }
    Ok(out)
}

/// Calls `consume` only after checking actual ownership, immutable producer
/// programs, complete proof state, sealed-source binding and public-statement
/// consistency. The expected context MUST come from trusted pool configuration.
///
/// Packet slices borrow the SAME authenticated source while its borrow guard is
/// held. They cannot be supplied separately or escape this callback. Digests were
/// derived by the proof program; this consumer does not repeat that hash work.
/// This callback MUST implement pool-state checks and atomic settlement before
/// returning success. It MUST NOT treat this proof gate alone as a completed spend.
///
/// Borrowed packets cannot escape the guarded callback:
/// ```compile_fail
/// use zk9_solana_beta_receipt::{Accounts, Context, with_completed_proof};
/// use solana_program::program_error::ProgramError;
/// fn escape(a: &Accounts, c: &Context) -> Result<&'static [u8], ProgramError> {
///     with_completed_proof(a, c, |_, packets| Ok(packets[0]))
/// }
/// ```
#[inline(never)]
pub fn with_completed_proof<T>(a:&Accounts,expected:&Context,
    consume:impl FnOnce(&CompletedProof,[&[u8];2])->Result<T,ProgramError>)->Result<T,ProgramError> {
    immutable_program(a.proof_program,a.proof_program_data,&PROOF_PROGRAM)?;
    immutable_program(a.buffer_program,a.buffer_program_data,&BUFFER_PROGRAM)?;
    if a.receipt.owner!=&PROOF_PROGRAM || a.receipt.executable || a.receipt.is_writable {
        return Err(Error::ReceiptOwner.into());
    }
    if a.source.owner!=&BUFFER_PROGRAM || a.source.executable || a.source.is_writable {
        return Err(Error::SourceOwner.into());
    }
    let state=a.receipt.try_borrow_data()?;completed(&state)?;
    let data=a.source.try_borrow_data()?;let start=source_offset(&data)?;
    if &state[40..72]!=a.source.key.as_ref() || state[72..104]!=data[48..80] || state[104..108]!=data[40..44] {
        return Err(Error::SourceBinding.into());
    }
    let wire=&data[start..];
    let payment=statement(&state,wire,expected,*a.receipt.key,*a.source.key)?;
    consume(&payment,[&wire[WIRE_HEADER..WIRE_HEADER+PACKET_BYTES],&wire[WIRE_HEADER+PACKET_BYTES..WIRE_PREFIX]])
}
