use std::borrow::Borrow;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_keccak::KeccakF;
use p3_keccak_air::{KeccakCols,NUM_KECCAK_COLS,generate_trace_rows};
use p3_matrix::dense::RowMajorMatrix;
use p3_symmetric::Permutation;
use crate::{Val,air::PaymentAir,model::{self,Statement,Witness,DEPTH}};
fn put(bits:&mut [bool],offset:usize,bytes:&[u8]) {
    for (i,byte) in bytes.iter().enumerate() {for k in 0..8 {bits[offset+i*8+k]=(byte>>k)&1==1;}}
}
fn state_bytes(state:&[u64;25])->Vec<u8> {state.iter().flat_map(|w| w.to_le_bytes()).collect()}
pub fn generate(air:&PaymentAir,s:&Statement,w:&Witness)->Result<RowMajorMatrix<Val>,String> {
    let g=&air.graph;
    if w.inputs.iter().any(|n|n.index>=1<<DEPTH) {return Err("leaf index exceeds fixed tree".into());}
    let balance=zk9_hiding_balance_component::trace(w.inputs.clone().map(|n|n.amount),w.outputs.clone().map(|n|n.amount),s.context.fee)?;
    let mut bits=vec![false;g.bits];
    for i in 0..326 {bits[i]=balance.values[i]==Val::ONE;}
    put(&mut bits,g.context,&[s.context.network,s.context.genesis,s.context.asset].concat());
    for i in 0..2 {
        put(&mut bits,g.secrets[i],&w.inputs[i].secret);
        put(&mut bits,g.rhos[i],&w.inputs[i].rho);
        put(&mut bits,g.rhos[i+2],&w.outputs[i].rho);
        put(&mut bits,g.output_owners[i],&w.outputs[i].owner);
        for l in 0..DEPTH {
            bits[g.directions[i]+l]=(w.inputs[i].index>>l)&1==1;
            put(&mut bits,g.siblings[i][l],&w.inputs[i].siblings[l]);
        }
    }
    let mut permutation_inputs=vec![];
    for job in &g.jobs {
        let mut message=job.message.chunks_exact(8).map(|byte|
            byte.iter().enumerate().fold(0u8,|v,(k,b)|v|((b.value(&bits) as u8)<<k))).collect::<Vec<_>>();
        let digest=model::hash(&message);
        put(&mut bits,job.output,&digest);
        message.push(6);
        while message.len()%72!=0 {message.push(0);}
        *message.last_mut().unwrap()|=0x80;
        let mut state=[0u64;25];
        for block in message.chunks_exact(72) {
            for (i,byte) in block.iter().enumerate() {state[i/8]^=(*byte as u64) << (8*(i%8));}
            permutation_inputs.push(state);
            KeccakF{}.permute_mut(&mut state);
        }
        if state_bytes(&state)[..64]!=digest {return Err("SHA3 sponge disagrees with independent hash API".into());}
    }
    if permutation_inputs.len()!=g.blocks.len() {return Err("hash schedule differs".into());}
    let keccak=generate_trace_rows::<Val>(permutation_inputs,0);
    if keccak.values.len()/NUM_KECCAK_COLS!=g.height() {return Err("trace shape differs".into());}
    let global=bits.iter().map(|b|if *b {Val::ONE}else{Val::ZERO}).collect::<Vec<_>>();
    let mut values=vec![Val::ZERO;g.height()*air.width()];
    for (i,row) in values.chunks_exact_mut(air.width()).enumerate() {
        let native=&keccak.values[i*NUM_KECCAK_COLS..(i+1)*NUM_KECCAK_COLS];
        row[..NUM_KECCAK_COLS].copy_from_slice(native);
        row[air.global()..air.selectors()].copy_from_slice(&global);
        row[air.selectors()+(i/24).min(g.blocks.len())]=Val::ONE;
        let cols:&KeccakCols<Val>=native.borrow();
        for word in 0..25 {for limb in 0..4 {
            let a=cols.preimage[word/5][word%5][limb].as_canonical_u64();
            let z=cols.a_prime_prime_prime(word/5,word%5,limb).as_canonical_u64();
            for bit in 0..16 {
                row[air.input()+word*64+limb*16+bit]=Val::from_u8(((a>>bit)&1) as u8);
                row[air.output()+word*64+limb*16+bit]=Val::from_u8(((z>>bit)&1) as u8);
            }
        }}
    }
    Ok(RowMajorMatrix::new(values,air.width()))
}
