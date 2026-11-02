use super::*;
#[test]
fn context_isolates_program_mint_and_genesis(){
 let a=Pubkey::new_from_array([1;32]);let b=Pubkey::new_from_array([2;32]);let g=[3;32];
 let p=pool(&a,&g,&MINT).0;
 for other in [pool(&b,&g,&MINT).0,pool(&a,&[5;32],&MINT).0,pool(&a,&g,&b).0]{assert_ne!(p,other);assert_ne!(network(&a,&p),network(&a,&other));}
 assert_ne!(deposit_record(&a,&p,&a,0),deposit_record(&a,&p,&b,0));
 assert_ne!(deposit_record(&a,&p,&a,0),deposit_record(&a,&p,&a,1));
}
#[test]
fn commitment_matches_original_byte_encoding(){
 let mut note=[0u8;104];note[..64].fill(8);note[64..96].fill(9);note[96..].copy_from_slice(&123u64.to_le_bytes());
 let expected=include_str!("../commitment-vector.txt").trim();
 let actual=commitment(&[1;32],&[2;32],&Pubkey::new_from_array([3;32]),&note).unwrap();
 assert_eq!(actual.iter().map(|b|format!("{b:02x}")).collect::<String>(),expected);
 assert!(commitment(&[1;32],&[2;32],&MINT,&note[..103]).is_err());
 note[..64].fill(0);assert!(commitment(&[1;32],&[2;32],&MINT,&note).is_err());
}
#[test]
fn accounting_preserves_deposits_through_send_and_later_deposit(){
 let mut state=vec![0u8;SPACE];state[..8].copy_from_slice(b"ZK9BETA3");tree::initialize(&mut state[TREE_AT..]).unwrap();
 tree::append_pair(&mut state[TREE_AT..],0,&[[1;64],[2;64]]).unwrap();
 put(&mut state,136,100);put(&mut state,144,1);put(&mut state,152,100);assert_eq!(accounting(&state).unwrap(),2);
 tree::append_pair(&mut state[TREE_AT..],2,&[[3;64],[4;64]]).unwrap();
 put(&mut state,152,99);put(&mut state,160,1);put(&mut state,168,1);assert_eq!(accounting(&state).unwrap(),4);
 tree::append_pair(&mut state[TREE_AT..],4,&[[5;64],[6;64]]).unwrap();
 put(&mut state,136,300);put(&mut state,144,2);put(&mut state,152,299);assert_eq!(accounting(&state).unwrap(),6);
 for at in [136,144,152,160,168,176,184]{let mut changed=state.clone();let n=read(&changed,at);put(&mut changed,at,n+1);assert!(accounting(&changed).is_err(),"field {at}");}
 let mut changed=state.clone();put(&mut changed,144,u64::MAX);assert!(accounting(&changed).is_err());
}
#[test]
fn accounting_conserves_value_through_send_withdrawal_and_later_deposit(){
 let mut state=vec![0u8;SPACE];state[..8].copy_from_slice(b"ZK9BETA3");tree::initialize(&mut state[TREE_AT..]).unwrap();
 tree::append_pair(&mut state[TREE_AT..],0,&[[1;64],[2;64]]).unwrap();
 put(&mut state,136,100);put(&mut state,144,1);put(&mut state,152,100);assert_eq!(accounting(&state).unwrap(),2);
 tree::append_pair(&mut state[TREE_AT..],2,&[[3;64],[4;64]]).unwrap();
 put(&mut state,152,99);put(&mut state,160,1);put(&mut state,168,1);assert_eq!(accounting(&state).unwrap(),4);
 tree::append_pair(&mut state[TREE_AT..],4,&[[5;64],[6;64]]).unwrap();
 put(&mut state,152,68);put(&mut state,160,2);put(&mut state,176,30);put(&mut state,184,1);assert_eq!(accounting(&state).unwrap(),6);
 for at in [136,144,152,160,168,176,184]{let mut bad=state.clone();let n=read(&bad,at);put(&mut bad,at,n+1);assert!(accounting(&bad).is_err(),"field {at}");}
 tree::append_pair(&mut state[TREE_AT..],6,&[[7;64],[8;64]]).unwrap();
 put(&mut state,136,300);put(&mut state,144,2);put(&mut state,152,268);assert_eq!(accounting(&state).unwrap(),8);
 let mut bad=state.clone();put(&mut bad,176,u64::MAX);assert!(accounting(&bad).is_err());
 let mut bad=state.clone();put(&mut bad,184,u64::MAX);assert!(accounting(&bad).is_err());
}
