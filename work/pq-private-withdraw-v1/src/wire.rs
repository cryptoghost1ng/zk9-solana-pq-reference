//! Version-isolated bounded native withdrawal envelope, little endian integers.
use crate::{Context,Statement,PaymentProof,PACKET_BYTES,bind};
pub const HEADER_BYTES:usize=469;
pub const MAX_PROOF_BYTES:usize=4*1024*1024;
pub const MAX_ENVELOPE_BYTES:usize=HEADER_BYTES+2*PACKET_BYTES+MAX_PROOF_BYTES;
const MAGIC:&[u8;8]=b"ZK9PQW1\0";
pub fn encode(s:&Statement,p:&PaymentProof,packets:&[Vec<u8>;2])->Result<Vec<u8>,String> {
    s.validate()?;
    if bind(s.payment.clone(),s.amount,s.recipient,packets)?.delivery!=s.delivery {return Err("delivery mismatch".into());}
    let proof=postcard::to_allocvec(p).map_err(|e|e.to_string())?;
    if proof.is_empty() || proof.len()>MAX_PROOF_BYTES {return Err("withdrawal proof size".into());}
    let mut out=Vec::with_capacity(HEADER_BYTES+2*PACKET_BYTES+proof.len());
    out.extend(MAGIC);out.extend(1u32.to_le_bytes());
    let c=&s.payment.context;
    for x in [&c.network,&c.genesis,&c.asset] {out.extend(x);}
    out.extend(c.fee.to_le_bytes());out.push(s.mode);out.extend(s.amount.to_le_bytes());out.extend(s.recipient);
    out.extend(s.payment.root);
    for x in s.payment.nullifiers {out.extend(x);} for x in s.payment.outputs {out.extend(x);}
    out.extend((proof.len() as u32).to_le_bytes());assert_eq!(out.len(),HEADER_BYTES);
    for packet in packets {out.extend(packet);}out.extend(proof);Ok(out)
}
pub struct Decoded {pub statement:Statement,pub proof:PaymentProof,pub packets:[Vec<u8>;2]}
pub fn decode(expected:&Context,bytes:&[u8])->Result<Decoded,String> {
    let offset=HEADER_BYTES+2*PACKET_BYTES;
    if bytes.len()<=offset || bytes.len()>MAX_ENVELOPE_BYTES {return Err("withdrawal envelope size".into());}
    if bytes[..8]!=*MAGIC || bytes[8..12]!=1u32.to_le_bytes() || bytes[116]!=crate::MODE {return Err("withdrawal version or mode".into());}
    let c=Context{network:bytes[12..44].try_into().unwrap(),genesis:bytes[44..76].try_into().unwrap(),asset:bytes[76..108].try_into().unwrap(),fee:u64::from_le_bytes(bytes[108..116].try_into().unwrap())};
    if c.network!=expected.network || c.genesis!=expected.genesis || c.asset!=expected.asset || c.fee!=expected.fee {return Err("wrong authenticated withdrawal context or fee".into());}
    let amount=u64::from_le_bytes(bytes[117..125].try_into().unwrap());let recipient=bytes[125..145].try_into().unwrap();
    let s=crate::model::Statement{context:c,root:bytes[145..209].try_into().unwrap(),
        nullifiers:[bytes[209..273].try_into().unwrap(),bytes[273..337].try_into().unwrap()],
        outputs:[bytes[337..401].try_into().unwrap(),bytes[401..465].try_into().unwrap()]};
    let len=u32::from_le_bytes(bytes[465..469].try_into().unwrap()) as usize;
    if len==0 || len>MAX_PROOF_BYTES || len!=bytes.len()-offset {return Err("withdrawal proof framing".into());}
    let packets=[bytes[469..469+PACKET_BYTES].to_vec(),bytes[469+PACKET_BYTES..offset].to_vec()];
    let statement=bind(s,amount,recipient,&packets)?;let proof=crate::bounded::decode(&bytes[offset..])?;
    Ok(Decoded{statement,proof,packets})
}
pub fn verify(c:&crate::Config,expected:&Context,bytes:&[u8])->Result<Decoded,String> {
    let d=decode(expected,bytes)?;
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(||crate::verify_withdrawal(c,&d.statement,&d.proof)))
        .map_err(|_|"malformed withdrawal proof".to_string())??;
    Ok(d)
}
