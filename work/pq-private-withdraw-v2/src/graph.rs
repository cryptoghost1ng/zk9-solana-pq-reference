use crate::model::DEPTH;
use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;

#[derive(Clone, Copy)]
pub enum Bit {
    Constant(bool), Witness(usize),
    Select { direction:usize, zero:usize, one:usize },
}
impl Bit {
    pub fn value(self, w:&[bool]) -> bool {
        match self {Self::Constant(c)=>c,Self::Witness(i)=>w[i],
            Self::Select{direction,zero,one}=>w[if w[direction]{one}else{zero}]}
    }
    pub fn expr<AB:AirBuilder>(self, w:&[AB::Var]) -> AB::Expr {
        match self {Self::Constant(c)=>if c {AB::Expr::ONE}else{AB::Expr::ZERO},
            Self::Witness(i)=>w[i].into(), Self::Select{direction,zero,one}=>
                w[zero] + w[direction]*(w[one]-w[zero])}
    }
}
pub fn bytes_bits(bytes:&[u8]) -> Vec<Bit> {
    bytes.iter().flat_map(|b| (0..8).map(move |k| Bit::Constant((b>>k)&1==1))).collect()
}
fn range(offset:usize, len:usize) -> Vec<Bit> { (offset..offset+len).map(Bit::Witness).collect() }
pub struct Job { pub message:Vec<Bit>, pub output:usize }
pub struct Block { pub message:Vec<Bit>, pub start:bool, pub output:Option<usize> }
pub struct Graph {
    pub recipient:usize, pub bits:usize, pub second_active:usize, pub context:usize, pub secrets:[usize;2], pub rhos:[usize;4],
    pub output_owners:[usize;2], pub siblings:[[usize;DEPTH];2], pub directions:[usize;2],
    pub jobs:Vec<Job>, pub blocks:Vec<Block>, pub roots:[usize;2], pub nfs:[usize;2], pub cms:[usize;4],
}
impl Graph {
    fn alloc(&mut self,n:usize)->usize { let out=self.bits; self.bits+=n; out }
    fn job(&mut self,message:Vec<Bit>)->usize {
        assert_eq!(message.len()%8,0);
        let output=self.alloc(512);
        self.jobs.push(Job{message,output}); output
    }
    pub fn new()->Self {
        let mut g=Self {recipient:0,bits:crate::balance::WIDTH,second_active:0,context:0,secrets:[0;2],rhos:[0;4],output_owners:[0;2],
            siblings:[[0;DEPTH];2],directions:[0;2],jobs:vec![],blocks:vec![],roots:[0;2],nfs:[0;2],cms:[0;4]};
        g.second_active=g.alloc(1);
        g.context=g.alloc(768);
        g.recipient=g.alloc(256);
        for i in 0..2 {g.secrets[i]=g.alloc(256);g.output_owners[i]=g.alloc(512);
            g.directions[i]=g.alloc(DEPTH);
            for l in 0..DEPTH {g.siblings[i][l]=g.alloc(512);} }
        for i in 0..4 {g.rhos[i]=g.alloc(256);}
        let mut owners=[0;4];
        for i in 0..2 {
            owners[i]=g.job([bytes_bits(b"ZK9ADR01"),range(g.secrets[i],256)].concat());
            owners[i+2]=g.output_owners[i];
        }
        for i in 0..4 {
            g.cms[i]=g.job([bytes_bits(b"ZK9NOT01"),range(g.context,768),range(owners[i],512),
                range(g.rhos[i],256),range(i*64,64)].concat());
        }
        for i in 0..2 {
            g.nfs[i]=g.job([bytes_bits(b"ZK9NUL01"),range(g.context,512),range(g.secrets[i],256),range(g.cms[i],512)].concat());
            let mut current=g.cms[i];
            for l in 0..DEPTH {
                let sibling=g.siblings[i][l];let direction=g.directions[i]+l;
                let left=(0..512).map(|k| Bit::Select{direction,zero:current+k,one:sibling+k}).collect::<Vec<_>>();
                let right=(0..512).map(|k| Bit::Select{direction,zero:sibling+k,one:current+k}).collect::<Vec<_>>();
                current=g.job([bytes_bits(b"ZK9MRK01"),bytes_bits(&(l as u32).to_le_bytes()),left,right].concat());
            } g.roots[i]=current;
        }
        for job in &g.jobs {
            let mut padded=job.message.clone();
            padded.extend(bytes_bits(&[6]));
            while padded.len()%576!=0 {padded.extend(bytes_bits(&[0]));}
            // Domain suffix0x06 and final0x80 occupy distinct bits, even in same byte.
            let end=padded.len()-1;padded[end]=Bit::Constant(true);
            let count=padded.len()/576;
            for (i,message) in padded.chunks_exact(576).enumerate() {
                g.blocks.push(Block{message:message.to_vec(),start:i==0,output:if i+1==count{Some(job.output)}else{None}});
            }
        }
        g
    }
    pub fn height(&self)->usize { (self.blocks.len()*24).next_power_of_two() }
}
