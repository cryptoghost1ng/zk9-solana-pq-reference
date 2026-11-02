use p3_air::{Air,DebugConstraintBuilder,check_all_constraints};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::{dense::{RowMajorMatrix,RowMajorMatrixView},stack::ViewPair};
use zk9_public_bind_liveness_lab::{Val,air::PaymentAir,graph::Bit,model,trace};

fn accepts_row(air:&PaymentAir,t:&RowMajorMatrix<Val>,public:&[Val],row:usize)->bool {
    let width=air.width();let height=t.values.len()/width;
    let current=&t.values[row*width..(row+1)*width];
    let next=((row+1)%height)*width;
    let pair=ViewPair::new(RowMajorMatrixView::new(current,width),RowMajorMatrixView::new(&t.values[next..next+width],width));
    let empty=ViewPair::new(RowMajorMatrixView::new(&[],0),RowMajorMatrixView::new(&[],0));
    let mut b=DebugConstraintBuilder::new(row,pair,empty,public,
        Val::from_bool(row==0),Val::from_bool(row+1==height),Val::from_bool(row+1<height),&[]);
    air.eval(&mut b);!b.has_failures()
}

#[test]
fn every_consumer_and_producer_retains_its_exact_logical_owner() {
    let air=PaymentAir::new();let g=&air.graph;let l=&air.layout;
    let owns=|block:usize,bit:usize|assert_eq!(l.owners[block][l.slots[bit]],Some(bit));
    for (j,block) in g.blocks.iter().enumerate() {
        for bit in &block.message {match *bit {
            Bit::Constant(_)=>(),Bit::Witness(i)=>owns(j,i),
            Bit::Select{direction,zero,one}=>{owns(j,direction);owns(j,zero);owns(j,one);}
        }}
        if let Some(offset)=block.output {for i in offset..offset+512 {owns(j,i);}}
    }
    for i in (0..326).chain(std::iter::once(g.second_active)).chain(g.context..g.context+768) {
        assert_eq!(l.live[i],(0,g.blocks.len()));
    }
    assert_eq!(air.bindings.len(),6);
    assert_eq!(air.bindings.iter().filter(|x|x.second_input).count(),1);
}

#[test]
fn valid_trace_and_all_public_digest_limbs_at_each_producer() {
    let air=PaymentAir::new();let (s,w)=model::fixture();
    let t=trace::generate(&air,&s,&w).unwrap();let public=s.public_values();
    assert!(check_all_constraints(&air,&t,&public,Some(10)).is_ok());
    for binding in &air.bindings {
        let row=binding.block*24+23;
        assert!(accepts_row(&air,&t,&public,row));
        for i in 0..32 {
            let mut changed=public.clone();changed[binding.public_offset+i]+=Val::ONE;
            assert!(!accepts_row(&air,&t,&changed,row),"{} limb {} was not bound",binding.name,i);
        }
        // A prover cannot turn off the new public check by clearing the job
        // selector at its final row: the prior row forces that selector to stay.
        let mut tampered=t.clone();
        tampered.values[row*air.width()+air.selectors()+binding.block]=Val::ZERO;
        assert!(!accepts_row(&air,&tampered,&public,row-1),"{} producer can be skipped",binding.name);
        // The digest register remains tied to the actual hash output on this
        // same row, even though it may be reused in later blocks.
        let mut tampered=t.clone();
        let at=row*air.width()+air.global()+air.layout.slots[binding.offset];
        tampered.values[at]=Val::ONE-tampered.values[at];
        assert!(!accepts_row(&air,&tampered,&public,row),"{} output is detached",binding.name);
    }
}

#[test]
fn zero_second_input_relaxes_only_second_root() {
    let air=PaymentAir::new();let (mut s,mut w)=model::fixture();
    w.inputs[1].amount=0;w.outputs[1].amount=99_999;
    s.outputs=w.outputs.clone().map(|n|n.commitment(&s.context));
    let note=model::Note{owner:model::address(&w.inputs[1].secret),rho:w.inputs[1].rho,amount:0};
    s.nullifiers[1]=model::nullifier(&s.context,&w.inputs[1].secret,&note.commitment(&s.context));
    let t=trace::generate(&air,&s,&w).unwrap();let public=s.public_values();
    assert!(check_all_constraints(&air,&t,&public,Some(10)).is_ok());
    for binding in &air.bindings {
        let mut changed=public.clone();changed[binding.public_offset]+=Val::ONE;
        assert_eq!(accepts_row(&air,&t,&changed,binding.block*24+23),binding.second_input,"{}",binding.name);
    }
    let root1=air.bindings.iter().find(|b|b.second_input).unwrap();
    let row=root1.block*24+23;let mut forged=t.clone();
    let slot=air.global()+air.layout.slots[air.graph.second_active];
    forged.values[row*air.width()+slot]=Val::ONE;
    assert!(!accepts_row(&air,&forged,&public,row),"active flag must remain stationary");
}
