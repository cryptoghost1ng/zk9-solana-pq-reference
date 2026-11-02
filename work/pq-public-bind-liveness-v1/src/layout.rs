//! Fixed register allocation for the immutable SHA3 graph, never proof supplied.
//! Context/balance/active registers stay live throughout. Other bits may reuse a column
//! only after their final consumer. Only permutation boundaries permit changes.
use crate::graph::{Bit, Graph};
#[derive(Clone, Debug)]
pub struct Layout {
    pub columns: usize,
    pub slots: Vec<usize>,
    pub live: Vec<(usize,usize)>,
    /// Logical bit occupying each slot in each permutation, including padding.
    pub owners: Vec<Vec<Option<usize>>>,
    /// Current block indices at whose final round this slot may change owner.
    pub changes: Vec<Vec<usize>>,
}
impl Layout {
    pub fn new(g:&Graph)->Self {
        let n=g.blocks.len();
        let mut live=vec![(usize::MAX,0);g.bits];
        let mut touch=|i:usize,b:usize| {live[i].0=live[i].0.min(b);live[i].1=live[i].1.max(b);};
        for (b,block) in g.blocks.iter().enumerate() {
            for bit in &block.message {
                match *bit {
                    Bit::Constant(_)=>(), Bit::Witness(i)=>touch(i,b),
                    Bit::Select{direction,zero,one}=>{touch(direction,b);touch(zero,b);touch(one,b);}
                }
            }
            if let Some(offset)=block.output {for i in offset..offset+512 {touch(i,b);}}
        }
        // Constraints outside the hash schedule must see stable logical bits.
        for i in 0..326 {live[i]=(0,n);}
        live[g.second_active]=(0,n);
        for i in g.context..g.context+768 {live[i]=(0,n);}
        // Public digest equalities are checked at their fixed producer's final
        // round. Keep the producer/consumer lifetimes found above; do not pin
        // these six outputs through every other hash job and padding block.
        assert!(live.iter().all(|&(a,b)|a<=b));
        let mut order=(0..g.bits).collect::<Vec<_>>();
        order.sort_by_key(|&i|(live[i].0,i));
        let mut ends=Vec::<usize>::new();let mut slots=vec![0;g.bits];
        for i in order {
            let (start,end)=live[i];
            // Strict inequality: variables used in the same block never alias.
            let slot=ends.iter().position(|&last|last<start).unwrap_or(ends.len());
            if slot==ends.len() {ends.push(end);} else {ends[slot]=end;}
            slots[i]=slot;
        }
        assert_eq!(&slots[..326],&(0..326).collect::<Vec<_>>());
        let columns=ends.len();let mut owners=vec![vec![None;columns];n+1];
        for i in 0..g.bits {
            for b in live[i].0..=live[i].1 {
                assert!(owners[b][slots[i]].replace(i).is_none(),"live registers alias");
            }
        }
        let changes=(0..columns).map(|s|(0..n).filter(|&b|owners[b][s]!=owners[b+1][s]).collect()).collect();
        Self{columns,slots,live,owners,changes}
    }
}
