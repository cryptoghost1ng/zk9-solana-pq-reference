//! Parsing/admission tests with native AccountInfos. Not runtime authentication.
use super::*;
use std::{vec,vec::Vec,fs,path::Path};
use solana_program::hash::hashv;

struct Fixture {
    receipt:Vec<u8>,source:Vec<u8>,proof:Vec<u8>,buffer:Vec<u8>,proof_code:Vec<u8>,buffer_code:Vec<u8>,
    receipt_owner:Pubkey,source_owner:Pubkey,source_key:Pubkey,receipt_writable:bool,source_writable:bool,
    context:Context,
}
impl Fixture {
    fn new()->Self {
        let root=Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        // State produced by all actual wrapper stages, never a fabricated success marker.
        let receipt=fs::read(root.join("evidence/full-native-03-output/single-with-change.state")).unwrap();
        let wire=fs::read(root.join("../pq-private-withdraw-v2/evidence/qualification-02/single-with-change.wire")).unwrap();
        let count=wire.len().div_ceil(900);let start=85+count.div_ceil(8)+32*count;
        let len=(wire.len() as u32).to_le_bytes();
        let leaves:Vec<_>=wire.chunks(900).enumerate().map(|(i,b)|hashv(&[b"ZK9/SOLANA/BUFFER/LEAF/v1\0",&len,&(i as u32).to_le_bytes(),b]).to_bytes()).collect();
        let flat:Vec<_>=leaves.iter().flatten().copied().collect();
        let digest=hashv(&[b"ZK9/SOLANA/BUFFER/ROOT/v1\0",&len,&flat]);
        let mut source=vec![0;start+wire.len()];source[..8].copy_from_slice(b"ZK9BUF1\0");
        source[8..40].copy_from_slice(&[44;32]);source[40..44].copy_from_slice(&len);
        source[44..48].copy_from_slice(&(count as u32).to_le_bytes());source[48..80].copy_from_slice(digest.as_ref());source[80]=2;
        for (i,h) in leaves.iter().enumerate(){source[85+i/8]|=1<<(i%8);source[85+count.div_ceil(8)+32*i..85+count.div_ceil(8)+32*(i+1)].copy_from_slice(h);}
        source[start..].copy_from_slice(&wire);
        assert_eq!(receipt[72..104],source[48..80]);
        let record=|key:&[u8;32]|{let mut b=vec![0;36];b[..4].copy_from_slice(&2u32.to_le_bytes());b[4..].copy_from_slice(key);b};
        let code=||{let mut b=vec![0;46];b[..4].copy_from_slice(&3u32.to_le_bytes());b};
        let context=Context{network:wire[12..44].try_into().unwrap(),genesis:wire[44..76].try_into().unwrap(),asset:wire[76..108].try_into().unwrap()};
        Self{receipt,source,proof:record(&[71;32]),buffer:record(&[72;32]),proof_code:code(),buffer_code:code(),receipt_owner:PROOF_PROGRAM,source_owner:BUFFER_PROGRAM,source_key:Pubkey::new_from_array([43;32]),receipt_writable:false,source_writable:false,context}
    }
    fn run(&mut self)->Result<(u64,Pubkey),ProgramError> {
        let session=Pubkey::new_from_array([42;32]);let pcode=Pubkey::new_from_array([71;32]);let bcode=Pubkey::new_from_array([72;32]);let loader=bpf_loader_upgradeable::id();
        let(mut l0,mut l1,mut l2,mut l3,mut l4,mut l5)=(1,1,1,1,1,1);
        let a=Accounts{
            receipt:&AccountInfo::new(&session,false,self.receipt_writable,&mut l0,&mut self.receipt,&self.receipt_owner,false,0),
            proof_program:&AccountInfo::new(&PROOF_PROGRAM,false,false,&mut l1,&mut self.proof,&loader,true,0),
            proof_program_data:&AccountInfo::new(&pcode,false,false,&mut l2,&mut self.proof_code,&loader,false,0),
            source:&AccountInfo::new(&self.source_key,false,self.source_writable,&mut l3,&mut self.source,&self.source_owner,false,0),
            buffer_program:&AccountInfo::new(&BUFFER_PROGRAM,false,false,&mut l4,&mut self.buffer,&loader,true,0),
            buffer_program_data:&AccountInfo::new(&bcode,false,false,&mut l5,&mut self.buffer_code,&loader,false,0),
        };
        with_completed_withdrawal(&a,&self.context,|proof,packets|{
            assert_eq!(proof.fee(),1);assert_eq!(packets[0].len(),PACKET_BYTES);assert_eq!(packets[1].len(),PACKET_BYTES);
            Ok((proof.amount(),*proof.recipient()))
        })
    }
}
#[test] fn accepts_actual_completed_native_withdrawal(){assert_eq!(Fixture::new().run().unwrap(),(600_000,Pubkey::new_from_array([91;32])));}
#[test] fn rejects_incomplete_or_other_protocol(){
    for at in [0,172,120,18992,18996,AIR_CONTROL+4,AIR_CONTROL+8,AIR_STATE,AIR_STATE+8,AIR_STATE+12]{
        let mut f=Fixture::new();f.receipt[at]^=1;assert!(f.run().is_err(),"offset {at}");
    }
}
#[test] fn rejects_wrong_owners_mutable_or_rebound_accounts(){
    for case in 0..7{let mut f=Fixture::new();match case{
        0=>f.receipt_owner=Pubkey::default(),1=>f.source_owner=Pubkey::default(),2=>f.source_key=Pubkey::new_from_array([99;32]),
        3=>f.receipt_writable=true,4=>f.source_writable=true,5=>f.proof_code[12]=1,_=>f.buffer_code[12]=1,
    }assert!(f.run().is_err(),"case {case}");}
}
#[test] fn rejects_wrong_pool_context(){
    for which in 0..3{let mut f=Fixture::new();match which{0=>f.context.network[0]^=1,1=>f.context.genesis[0]^=1,_=>f.context.asset[0]^=1}assert!(f.run().is_err());}
}
#[test] fn binds_all_withdrawal_public_limbs(){
    for i in 276..297{
        let mut f=Fixture::new();let at=PUBLIC+4*i;
        let old=F::from_montgomery(n(&f.receipt,at) as u32).unwrap().canonical();
        f.receipt[at..at+4].copy_from_slice(&F::new(old^1).unwrap().montgomery().to_le_bytes());
        assert!(f.run().is_err(),"public limb {i}");
    }
}
#[test] fn rejects_recipient_tail_and_amount_envelope_substitution(){
    for at in [116,117,124,125,145,156]{
        let mut f=Fixture::new();let count=n(&f.source,44);let start=85+count.div_ceil(8)+32*count;
        f.source[start+at]^=1;assert!(f.run().is_err(),"wire byte {at}");
    }
}
#[test] fn rejects_noncanonical_public_and_truncated_source(){
    let mut f=Fixture::new();f.receipt[PUBLIC..PUBLIC+4].copy_from_slice(&u32::MAX.to_le_bytes());assert!(f.run().is_err());
    let mut f=Fixture::new();f.source.pop();assert!(f.run().is_err());
}
