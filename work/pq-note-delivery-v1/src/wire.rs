//! Fixed-size delivery sidecars are mandatory and recomputed before proving.
use crate::{Context, Statement, PaymentProof, PACKET_BYTES, bind};
pub const HEADER_BYTES: usize = 440;
pub const MAX_PROOF_BYTES: usize = 4*1024*1024;
pub const MAX_ENVELOPE_BYTES: usize = HEADER_BYTES+2*PACKET_BYTES+MAX_PROOF_BYTES;
const MAGIC: &[u8;8] = b"ZK9PQD1\0";

pub fn encode(s: &Statement,p: &PaymentProof,packets: &[Vec<u8>;2]) -> Result<Vec<u8>,String> {
    let bound = bind(s.payment.clone(),packets)?;
    if bound.delivery != s.delivery { return Err("delivery digest mismatch".into()); }
    let proof = postcard::to_allocvec(p).map_err(|e|e.to_string())?;
    if proof.is_empty() || proof.len()>MAX_PROOF_BYTES { return Err("proof size bound".into()); }
    let s = &s.payment;
    let mut out = Vec::with_capacity(HEADER_BYTES+2*PACKET_BYTES+proof.len());
    out.extend(MAGIC); out.extend(1u32.to_le_bytes());
    for x in [&s.context.network,&s.context.genesis,&s.context.asset] { out.extend(x); }
    out.extend(s.context.fee.to_le_bytes()); out.extend(s.root);
    for x in s.nullifiers { out.extend(x); } for x in s.outputs { out.extend(x); }
    out.extend((proof.len() as u32).to_le_bytes());
    assert_eq!(out.len(),HEADER_BYTES);
    for packet in packets { out.extend(packet); } out.extend(proof); Ok(out)
}
pub struct Decoded { pub statement: Statement, pub proof: PaymentProof, pub packets: [Vec<u8>;2] }
pub fn decode(expected:&Context,bytes:&[u8]) -> Result<Decoded,String> {
    let offset = HEADER_BYTES+2*PACKET_BYTES;
    if bytes.len()<=offset || bytes.len()>MAX_ENVELOPE_BYTES { return Err("envelope size bound".into()); }
    if bytes[..8]!=*MAGIC || bytes[8..12]!=1u32.to_le_bytes() { return Err("unknown delivery version".into()); }
    let c=Context { network:bytes[12..44].try_into().unwrap(),genesis:bytes[44..76].try_into().unwrap(),
        asset:bytes[76..108].try_into().unwrap(),fee:u64::from_le_bytes(bytes[108..116].try_into().unwrap()) };
    if expected.network==[0;32] || expected.genesis==[0;32] || expected.asset==[0;32]
        || c.network!=expected.network || c.genesis!=expected.genesis || c.asset!=expected.asset {
        return Err("wrong authenticated context".into());
    }
    let s=crate::model::Statement { context:c,root:bytes[116..180].try_into().unwrap(),
        nullifiers:[bytes[180..244].try_into().unwrap(),bytes[244..308].try_into().unwrap()],
        outputs:[bytes[308..372].try_into().unwrap(),bytes[372..436].try_into().unwrap()] };
    if s.nullifiers[0]==s.nullifiers[1] || s.outputs[0]==s.outputs[1] || s.outputs.iter().any(|x|*x==[0;64]) {
        return Err("duplicate or empty public note".into());
    }
    let len=u32::from_le_bytes(bytes[436..440].try_into().unwrap()) as usize;
    if len==0 || len>MAX_PROOF_BYTES || len!=bytes.len()-offset { return Err("proof framing mismatch".into()); }
    let packets=[bytes[HEADER_BYTES..HEADER_BYTES+PACKET_BYTES].to_vec(),bytes[HEADER_BYTES+PACKET_BYTES..offset].to_vec()];
    let statement=bind(s,&packets)?;
    let proof=crate::bounded::decode(&bytes[offset..])?;
    Ok(Decoded { statement,proof,packets })
}
pub fn verify(c:&crate::Config,expected:&Context,bytes:&[u8]) -> Result<Decoded,String> {
    let d=decode(expected,bytes)?;
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(||crate::verify_payment(c,&d.statement,&d.proof)))
        .map_err(|_|"malformed proof".to_string())??;
    Ok(d)
}
