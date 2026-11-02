use tiny_keccak::{Hasher, Sha3};
use zk9_hiding_balance_component::{Statement as Context, Val};
use p3_field::PrimeCharacteristicRing;
pub const DEPTH: usize = 32;
pub type Digest = [u8;64];
pub fn hash(bytes: &[u8]) -> Digest {
    let mut state = Sha3::v512(); state.update(bytes);
    let mut out = [0;64]; state.finalize(&mut out); out
}
pub fn address(secret: &[u8;32]) -> Digest { hash(&[b"ZK9ADR01".as_slice(),secret].concat()) }
#[derive(Clone)]
pub struct Note { pub owner: Digest, pub rho:[u8;32], pub amount:u64 }
impl Note {
    pub fn commitment(&self, c:&Context) -> Digest {
        hash(&[b"ZK9NOT01".as_slice(), &c.network, &c.genesis, &c.asset, &self.owner,
               &self.rho, &self.amount.to_le_bytes()].concat())
    }
}
pub fn nullifier(c:&Context, secret:&[u8;32], cm:&Digest) -> Digest {
    hash(&[b"ZK9NUL01".as_slice(), &c.network, &c.genesis, secret, cm].concat())
}
pub fn parent(level:usize, left:&Digest, right:&Digest) -> Digest {
    hash(&[b"ZK9MRK01".as_slice(), &(level as u32).to_le_bytes(), left, right].concat())
}
#[derive(Clone)]
pub struct Spend { pub secret:[u8;32], pub rho:[u8;32], pub amount:u64,
    pub index:u64, pub siblings:[Digest;DEPTH] }
#[derive(Clone)]
pub struct Witness { pub inputs:[Spend;2], pub outputs:[Note;2] }
#[derive(Clone)]
pub struct Statement { pub context:Context, pub root:Digest,
    pub nullifiers:[Digest;2], pub outputs:[Digest;2] }
impl Statement {
    pub fn public_values(&self) -> Vec<Val> {
        let mut v=self.context.public_values();
        for d in [&self.root, &self.nullifiers[0], &self.nullifiers[1], &self.outputs[0], &self.outputs[1]] {
            v.extend(d.chunks_exact(2).map(|b| Val::from_u16(u16::from_le_bytes([b[0],b[1]]))));
        } v
    }
}
pub fn fixture() -> (Statement, Witness) {
    let c=Context {fee:1,network:[1;32],genesis:[2;32],asset:[3;32]};
    let secrets:Vec<[u8;32]>=(0..16).map(|i| [10+i;32]).collect();
    let notes:Vec<Note>=(0..16).map(|i| Note {owner:address(&secrets[i]),rho:[70+i as u8;32],
        amount:if i==3 {1_000_000} else if i==10 {500_000} else {100+i as u64}}).collect();
    let tree=crate::tree::SparseTree::<DEPTH>::from_leaves(&fixture_leaves(&c)).unwrap();
    let inputs=[3,10].map(|index| Spend {secret:secrets[index],rho:notes[index].rho,
        amount:notes[index].amount,index:index as u64,siblings:tree.path(index as u64).unwrap()});
    let outputs=[Note{owner:address(&[111;32]),rho:[112;32],amount:900_000},
                 Note{owner:address(&[113;32]),rho:[114;32],amount:599_999}];
    let s=Statement {context:c.clone(),root:tree.root(),
        nullifiers:std::array::from_fn(|i| nullifier(&c,&inputs[i].secret,&notes[inputs[i].index as usize].commitment(&c))),
        outputs:outputs.clone().map(|n| n.commitment(&c))};
    (s,Witness {inputs,outputs})
}
pub fn fixture_leaves(c:&Context)->Vec<Digest> {
    (0..12).map(|i| Note{owner:address(&[10+i;32]),rho:[70+i;32],
        amount:if i==3 {1_000_000}else if i==10 {500_000}else{100+i as u64}}.commitment(c)).collect()
}
