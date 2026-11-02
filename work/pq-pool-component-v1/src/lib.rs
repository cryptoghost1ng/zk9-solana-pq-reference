//! Laboratory component ONLY. No ownership, note membership, nullifiers or ledger.
//! The statement is existential 2-in/2-out u64 balance with a public fee/context.
//! Hash-only dependencies do not establish a quantified post-quantum guarantee.
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{PrimeCharacteristicRing, extension::BinomialExtensionField};
use p3_fri::{FriParameters, HidingFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::{Proof, StarkConfig, prove, verify};
use rand::{SeedableRng, rngs::{StdRng, SysRng}};

pub type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 8>;
type WordHash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
type LeafHash = SerializingHasher<WordHash>;
type Compress = CompressionFunctionFromHasher<WordHash, 2, 4>;
// 16 independent field salts (~494 bits of entropy), not the 4-salt demo default.
type HidingMmcs = MerkleTreeHidingMmcs<
    [Val; p3_keccak::VECTOR_LEN], [u64; p3_keccak::VECTOR_LEN],
    LeafHash, Compress, StdRng, 2, 4, 16>;
type ExtMmcs = ExtensionMmcs<Val, Challenge, HidingMmcs>;
type Pcs = HidingFriPcs<Val, Radix2DitParallel<Val>, HidingMmcs, ExtMmcs, StdRng>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, Keccak256Hash, 32>>;
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;
pub type BalanceProof = Proof<Config>;
pub const HEIGHT: usize = 512;
pub const WIDTH: usize = 326; // 5 * 64 value bits + 3 * 2 signed-carry bits
pub const PUBLIC_VALUES: usize = 52; // fee limbs + network/genesis/asset (32 bytes each)
pub const DOMAIN: &[u8] = b"ZK9/LAB/PRIVATE-BALANCE-COMPONENT/v1/p3-f9833168/bb8/q64/b8/s16";

// Private constructor: verifier settings cannot be supplied by a proof or caller.
// Three independently seeded generators; no deterministic seed or fallback path.
pub fn config() -> Result<Config, String> {
    fn rng() -> Result<StdRng, String> {
        StdRng::try_from_rng(&mut SysRng).map_err(|e| format!("OS entropy unavailable: {e}"))
    }
    let hash = WordHash::new(KeccakF {});
    let input = HidingMmcs::new(LeafHash::new(hash), Compress::new(hash), 0, rng()?);
    let fri_mmcs = HidingMmcs::new(LeafHash::new(hash), Compress::new(hash), 0, rng()?);
    let fri = FriParameters {
        log_blowup: 3, log_final_poly_len: 0, max_log_arity: 1,
        num_queries: 64, batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0, query_proof_of_work_bits: 0,
        mmcs: ExtMmcs::new(fri_mmcs),
    };
    // 8 >= extension degree; 512 >= 2 * (64 + 8 * 2) = 160.
    // Upstream also checks actual opening budgets, including quotient masks.
    Ok(Config::new(Pcs::new(Radix2DitParallel::default(), input, fri, 8, rng()?),
        Challenger::from_hasher(DOMAIN.to_vec(), Keccak256Hash {})))
}

pub struct BalanceAir;
impl<F> BaseAir<F> for BalanceAir {
    fn width(&self) -> usize { WIDTH }
    fn num_public_values(&self) -> usize { PUBLIC_VALUES }
    fn max_constraint_degree(&self) -> Option<usize> { Some(2) }
}
impl<AB: AirBuilder> Air<AB> for BalanceAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let row = main.current_slice();
        let next = main.next_slice();
        let public = b.public_values().to_vec();
        for j in 0..WIDTH {
            b.assert_bool(row[j]);
            b.when_transition().assert_eq(row[j], next[j]);
        }
        let limb = |value: usize, k: usize| -> AB::Expr {
            (0..16).fold(AB::Expr::ZERO, |acc, bit|
                acc + row[value * 64 + k * 16 + bit] * AB::F::from_u32(1 << bit))
        };
        // Carry values -2,-1,0,1 encoded as two boolean bits plus an offset.
        let carry = |k: usize| -> AB::Expr {
            if k == 0 || k == 4 { AB::Expr::ZERO }
            else { row[320 + (k - 1) * 2] + row[321 + (k - 1) * 2] * AB::F::TWO - AB::F::TWO }
        };
        for k in 0..4 {
            b.assert_eq(limb(4, k), public[k]);
            b.assert_eq(limb(0, k) + limb(1, k) + carry(k),
                limb(2, k) + limb(3, k) + limb(4, k) + carry(k + 1) * AB::F::from_u32(65536));
        }
        // Context values are absorbed by uni-STARK before challenges. They do not
        // establish membership, ownership or asset identity of any actual note.
    }
}

#[derive(Clone)]
pub struct Statement {
    pub fee: u64,
    pub network: [u8; 32],
    pub genesis: [u8; 32],
    pub asset: [u8; 32],
}
impl Statement {
    pub fn public_values(&self) -> Vec<Val> {
        let mut out = (0..4).map(|k| Val::from_u16((self.fee >> (16 * k)) as u16)).collect::<Vec<_>>();
        for bytes in [&self.network, &self.genesis, &self.asset] {
            out.extend(bytes.chunks_exact(2).map(|x| Val::from_u16(u16::from_le_bytes([x[0], x[1]]))));
        }
        out
    }
}

pub fn trace(inputs: [u64; 2], outputs: [u64; 2], fee: u64) -> Result<RowMajorMatrix<Val>, String> {
    if inputs.iter().map(|&v| v as u128).sum::<u128>() != outputs.iter().map(|&v| v as u128).sum::<u128>() + fee as u128 {
        return Err("integer value is not conserved".into());
    }
    let values = [inputs[0], inputs[1], outputs[0], outputs[1], fee];
    let mut row = vec![Val::ZERO; WIDTH];
    for (i, value) in values.iter().enumerate() {
        for bit in 0..64 { row[i * 64 + bit] = Val::from_u8(((value >> bit) & 1) as u8); }
    }
    let mut carry = 0i64;
    for k in 0..4 {
        let limbs = values.map(|v| ((v >> (16 * k)) & 65535) as i64);
        let delta = limbs[0] + limbs[1] + carry - limbs[2] - limbs[3] - limbs[4];
        if delta % 65536 != 0 { return Err("nonintegral carry".into()); }
        carry = delta / 65536;
        if k < 3 {
            if !(-2..=1).contains(&carry) { return Err("carry out of range".into()); }
            let code = (carry + 2) as u8;
            row[320 + k * 2] = Val::from_u8(code & 1);
            row[321 + k * 2] = Val::from_u8(code >> 1);
        }
    }
    if carry != 0 { return Err("64-bit overflow".into()); }
    Ok(RowMajorMatrix::new(row.repeat(HEIGHT), WIDTH))
}

pub fn prove_balance(cfg: &Config, inputs: [u64; 2], outputs: [u64; 2], s: &Statement) -> Result<BalanceProof, String> {
    // Never expose reusable private PCS prover data; each call commits afresh.
    prove(cfg, &BalanceAir, trace(inputs, outputs, s.fee)?, &s.public_values()).map_err(|e| format!("{e:?}"))
}
pub fn verify_balance(cfg: &Config, proof: &BalanceProof, s: &Statement) -> Result<(), String> {
    // ZK doubles the trace degree; disallow proof-selected trace sizes.
    if proof.degree_bits != HEIGHT.ilog2() as usize + 1 { return Err("unexpected degree".into()); }
    verify(cfg, &BalanceAir, proof, &s.public_values()).map_err(|e| format!("{e:?}"))
}

#[cfg(test)]
mod tests;
