//! Fixed public output bindings. All offsets and producers come from the
//! compiled hash graph; none are supplied by the payment witness or proof.
use crate::graph::Graph;
#[derive(Clone,Debug)]
pub struct PublicBinding {
    pub name: &'static str,
    pub offset:usize,
    pub public_offset:usize,
    pub block:usize,
    pub second_input:bool,
}
pub fn public_bindings(g:&Graph)->Vec<PublicBinding> {
    [
        ("root0",g.roots[0],52,false),
        ("root1",g.roots[1],52,true),
        ("nullifier0",g.nfs[0],84,false),
        ("nullifier1",g.nfs[1],116,false),
        ("output0",g.cms[2],148,false),
        ("output1",g.cms[3],180,false),
    ].into_iter().map(|(name,offset,public_offset,second_input)|{
        let producers=g.blocks.iter().enumerate()
            .filter_map(|(j,b)|(b.output==Some(offset)).then_some(j)).collect::<Vec<_>>();
        assert_eq!(producers.len(),1,"each public digest needs exactly one producer");
        PublicBinding{name,offset,public_offset,block:producers[0],second_input}
    }).collect()
}
