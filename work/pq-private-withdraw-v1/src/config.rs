//! Fixed laboratory parameters; no claim of a reviewed end-to-end PQ budget.
use p3_challenger::{HashChallenger,SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters,HidingFriPcs};
use p3_keccak::KeccakF;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{PaddingFreeSponge,SerializingHasher,CompressionFunctionFromHasher,CryptographicHasher};
use p3_uni_stark::{StarkConfig,Proof};
use rand::{SeedableRng,rngs::{StdRng,SysRng}};
use tiny_keccak::{Hasher,Sha3};
use crate::Val;

#[derive(Clone,Debug)]
pub struct Sha3_512;
impl CryptographicHasher<u8,[u8;64]> for Sha3_512 {
    fn hash_iter<I:IntoIterator<Item=u8>>(&self,input:I)->[u8;64] {
        let mut h=Sha3::v512();
        let mut buffer=[0u8;256];let mut len=0;
        for b in input {buffer[len]=b;len+=1;if len==256 {h.update(&buffer);len=0;}}
        h.update(&buffer[..len]);let mut out=[0;64];h.finalize(&mut out);out
    }
}
pub type Challenge=BinomialExtensionField<Val,8>;
type WordHash=PaddingFreeSponge<KeccakF,25,9,8>;
type FieldHash=SerializingHasher<WordHash>;
type Compress=CompressionFunctionFromHasher<WordHash,2,8>;
type Mmcs=MerkleTreeHidingMmcs<[Val;p3_keccak::VECTOR_LEN],[u64;p3_keccak::VECTOR_LEN],FieldHash,Compress,StdRng,2,8,16>;
type ExtMmcs=ExtensionMmcs<Val,Challenge,Mmcs>;
type Pcs=HidingFriPcs<Val,Radix2DitParallel<Val>,Mmcs,ExtMmcs,StdRng>;
type Challenger=SerializingChallenger32<Val,HashChallenger<u8,Sha3_512,64>>;
pub type Config=StarkConfig<Pcs,Challenge,Challenger>;
pub type PaymentProof=Proof<Config>;
pub fn config()->Result<Config,String> {
    fn rng()->Result<StdRng,String> {StdRng::try_from_rng(&mut SysRng).map_err(|e|format!("OS entropy unavailable: {e}"))}
    let hash=WordHash::new(KeccakF{});
    let input=Mmcs::new(FieldHash::new(hash),Compress::new(hash),0,rng()?);
    let fri_mmcs=Mmcs::new(FieldHash::new(hash),Compress::new(hash),0,rng()?);
    let params=FriParameters {log_blowup:3,log_final_poly_len:0,max_log_arity:1,num_queries:64,
        batch_proof_of_work_bits:0,commit_proof_of_work_bits:0,query_proof_of_work_bits:0,mmcs:ExtMmcs::new(fri_mmcs)};
    let pcs=Pcs::new(Radix2DitParallel::default(),input,params,8,rng()?);
    let challenger=Challenger::new(HashChallenger::new(
        b"ZK9/LAB/PRIVATE-WITHDRAW/v1/recipient20/withdrawal-u64/mode1/SHA3-512/depth32/1or2in2out/private-zero-padding/ciphertext-SHA3-512/p3-f9833168/MMCS512/q64/b8".to_vec(),Sha3_512));
    Ok(Config::new(pcs,challenger))
}
