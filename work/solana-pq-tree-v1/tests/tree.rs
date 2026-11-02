use zk9_solana_pq_tree::{self as t,Error};
use original::{model,tree::SparseTree};
fn state()->Vec<u8>{let mut s=vec![0;t::SPACE];t::initialize(&mut s).unwrap();s}
#[test]
fn empty_constants_match_original_and_python(){
    let mut e=[0;64];assert_eq!(t::empty(0),e);
    for i in 0..32 {e=model::parent(i,&e,&e);assert_eq!(t::empty(i+1),e);}
    assert_eq!(t::root(&state()).unwrap(),SparseTree::<32>::new().unwrap().root());
}
#[test]
fn keeper_payments_and_all_frontier_bytes_match_python(){
    let pairs=include_bytes!("../generated/pairs.bin");let expected=include_bytes!("../generated/states.bin");
    let mut s=state();let mut original=SparseTree::<32>::new().unwrap();
    for (i,pair) in pairs.chunks_exact(128).enumerate(){
        let pair=[pair[..64].try_into().unwrap(),pair[64..].try_into().unwrap()];
        original.append(pair[0]).unwrap();original.append(pair[1]).unwrap();
        assert_eq!(t::append_pair(&mut s,(i*2)as u64,&pair).unwrap(),original.root());
        assert_eq!(s,&expected[i*t::SPACE..(i+1)*t::SPACE]);
    }
}
#[test]
fn carries_match_original_for_1024_pairs(){
    let mut s=state();let mut original=SparseTree::<32>::new().unwrap();
    for i in 0..1024u64 {
        let pair=[model::hash(&(2*i).to_le_bytes()),model::hash(&(2*i+1).to_le_bytes())];
        original.append(pair[0]).unwrap();original.append(pair[1]).unwrap();
        assert_eq!(t::append_pair(&mut s,2*i,&pair).unwrap(),original.root());
        assert_eq!(t::count(&s).unwrap(),2*i+2);
    }
}
#[test]
fn invalid_operations_are_atomic(){
    let mut s=state();let before=s.clone();
    for (n,pair,error) in [(2,[[1;64],[2;64]],Error::Stale),(0,[[0;64],[2;64]],Error::Output),(0,[[1;64],[1;64]],Error::Output)]{
        assert_eq!(t::append_pair(&mut s,n,&pair),Err(error));assert_eq!(s,before);
    }
    let mut bad=s.clone();bad[80]=1;let before=bad.clone();
    assert_eq!(t::append_pair(&mut bad,0,&[[1;64],[2;64]]),Err(Error::Frontier));assert_eq!(bad,before);
    assert_eq!(t::initialize(&mut s),Err(Error::Shape));
    for len in [0,7,t::SPACE-1,t::SPACE+1] {assert_eq!(t::count(&vec![0;len]),Err(Error::Shape));}
    for n in [1,t::CAPACITY+2] {let mut bad=state();bad[8..16].copy_from_slice(&n.to_le_bytes());assert_eq!(t::count(&bad),Err(Error::Count));}
}
#[test]
fn final_pair_reaches_capacity_without_overflow(){
    // Synthetic trusted frontier tests the capacity edge; not allocated history.
    let mut s=state();let n=t::CAPACITY-2;s[8..16].copy_from_slice(&n.to_le_bytes());
    for level in 1..32 {s[80+64*level..144+64*level].fill(level as u8);}
    let pair=[[201;64],[202;64]];let mut expected=model::parent(0,&pair[0],&pair[1]);
    for level in 1..32 {expected=model::parent(level,&[level as u8;64],&expected);}
    assert_eq!(t::append_pair(&mut s,n,&pair).unwrap(),expected);assert_eq!(t::count(&s).unwrap(),t::CAPACITY);
    assert!(s[80..].iter().all(|b|*b==0));let before=s.clone();
    assert_eq!(t::append_pair(&mut s,t::CAPACITY,&pair),Err(Error::Full));assert_eq!(s,before);
}
