mod meter;
use std::{fs,path::Path};
use p3_field::{PrimeCharacteristicRing,PrimeField32,BasedVectorSpace};
use p3_challenger::{CanObserve,CanSample,HashChallenger};
use original::{Val,config::Challenge};
use candidate::{Context,Prefix,challenger::Challenger};
use serde_json::json;
fn checkpoint(wire:&[u8])->Result<[u8;640],candidate::Error>{
 let b=wire.get(3904..).ok_or(candidate::Error::Envelope)?;let mut r=zk9_proof_staged::Reader::new(b).map_err(|_|candidate::Error::FormatState)?;while !r.done(){r.advance(4096).map_err(|_|candidate::Error::FormatState)?;}let mut out=[0;640];r.checkpoint(&mut out).unwrap();Ok(out)
}
fn run(context:&Context,b:&[u8])->Result<Prefix,candidate::Error>{let c=checkpoint(b)?;candidate::derive(context,b,&c)}
fn compare(reference:&original::profile::Reference,p:&Prefix){
 assert_eq!(reference.alpha,p.alpha);assert_eq!(reference.zeta,p.zeta);
 for i in 0..2{assert_eq!(reference.delivery[i],p.delivery[i]);}
 let mut c=Challenger::resume_trusted(&p.challenger).unwrap();let tail:Vec<_>=(0..64).map(|_|c.sample_field()).collect();assert_eq!(tail,reference.tail);
}
fn main(){
 let args:Vec<_>=std::env::args().collect();let dir=Path::new(&args[1]);let dest=Path::new(&args[2]);assert!(!dest.exists(),"preserve existing evidence");fs::create_dir_all(dest).unwrap();
 let profile=original::profile::Profile::derive();assert_eq!(profile.shape.main_width,candidate::WIDTH);assert_eq!(profile.shape.num_quotient_chunks,candidate::QUOTIENT_CHUNKS);
 let seed:Vec<_>=profile.seed_words.iter().flat_map(|x|x.to_le_bytes()).collect();assert_eq!(seed,candidate::SEED);
 let mut conversions=0;
 for n in (0..65536).chain([candidate::PRIME-1,123456789,987654321]){assert_eq!(candidate::to_montgomery(n).unwrap(),Val::from_u32(n).to_unique_u32());conversions+=1;}
 assert!(candidate::to_montgomery(candidate::PRIME).is_err());assert!(candidate::to_montgomery(u32::MAX).is_err());
 let mut stream_checks=0;
 for size in [0,1,63,64,65,71,72,73,144,1024]{
  let seed:Vec<_>=(0..size).map(|i|(i*37+9)as u8).collect();
  let mut old=HashChallenger::new(seed.clone(),original::config::Sha3_512);let mut new=Challenger::new(&seed);
  assert!(new.checkpoint_after_sample().is_err());
  for round in 0..12{
   for _ in 0..(round*7+1){assert_eq!(CanSample::<u8>::sample(&mut old),new.sample_byte());stream_checks+=1;}
   let snapshot=new.checkpoint_after_sample().unwrap();new=Challenger::resume_trusted(&snapshot).unwrap();
   let bytes:Vec<_>=(0..round*13).map(|i|(i+round)as u8).collect();old.observe_slice(&bytes);new.observe(&bytes);
   if !bytes.is_empty(){assert!(new.checkpoint_after_sample().is_err());}
  }
 }
 let c=Context{network:[1;32],genesis:[2;32],asset:[3;32]};let oc=original::Context{network:c.network,genesis:c.genesis,asset:c.asset,fee:0};
 let mut records=vec![];let mut cases=0;let mut shape_cases=0;
 for name in ["candidate-v3.bin"]{
  let bytes=fs::read(dir.join(name)).unwrap();let completed=checkpoint(&bytes).unwrap();let reference=original::profile::prefix(&profile,&oc,&bytes).unwrap();
  let (p,allocs,requested)=meter::measured(||candidate::derive(&c,&bytes,&completed));let p=p.unwrap();assert_eq!((allocs,requested),(0,0));compare(&reference,&p);
  let public=candidate::public_values(&c,&bytes).unwrap();assert_eq!(reference.public_words,public.words_montgomery);
  let views=candidate::views_from_trusted_format(&bytes,&completed).unwrap();let decoded=original::wire::decode(&oc,&bytes).unwrap();
  for (view,old) in [(views.trace,&decoded.proof.opened_values.trace_local),(views.next,decoded.proof.opened_values.trace_next.as_ref().unwrap()),(views.random,decoded.proof.opened_values.random.as_ref().unwrap())]{
   assert_eq!(view.len(),old.len());for (i,value) in old.iter().enumerate(){let row=view.get_montgomery(i).unwrap();let want=<Challenge as BasedVectorSpace<Val>>::as_basis_coefficients_slice(value);assert!(row.iter().zip(want).all(|(a,b)|*a==b.to_unique_u32()));}assert!(view.get_montgomery(view.len()).is_none());
  }
  for (view,old) in views.quotient.iter().zip(&decoded.proof.opened_values.quotient_chunks){for (i,value) in old.iter().enumerate(){assert!(view.get_montgomery(i).unwrap().iter().zip(<Challenge as BasedVectorSpace<Val>>::as_basis_coefficients_slice(value)).all(|(a,b)|*a==b.to_unique_u32()));}}
  let mut encoded=[0;candidate::RESULT_BYTES];p.encode(&mut encoded).unwrap();let path=dest.join(name);if path.exists(){assert_eq!(fs::read(&path).unwrap(),encoded)}else{fs::write(path,encoded).unwrap();}
  let check=|label:&str,b:&[u8]|{
   let r=original::profile::prefix(&profile,&oc,b);let (q,a,n)=meter::measured(||run(&c,b));assert_eq!((a,n),(0,0),"allocation {label}");assert_eq!(r.is_ok(),q.is_ok(),"acceptance {label}");if let (Ok(r),Ok(q))=(r,q){compare(&r,&q);} 
  };
  for offset in [12,44,76,108,116,180,244,308,372,440,2171,2172,3903,3905]{let mut b=bytes.clone();b[offset]^=1;check("mutated-bound-input",&b);cases+=1;
   if offset>=108&&offset!=3905{let q=run(&c,&b).unwrap();assert_ne!(q.alpha,p.alpha);}
  }
  for (a,b) in [(180,244),(308,372)]{let mut v=bytes.clone();let src=v[a..a+64].to_vec();v[b..b+64].copy_from_slice(&src);check("duplicate-public-note",&v);cases+=1;}
  for len in [0,8,440,3904,bytes.len()-1]{check("truncation",&bytes[..len]);cases+=1;}
  let mut b=bytes.clone();b.push(0);check("trailing",&b);cases+=1;
  for which in 0..7{
   let mut d=original::wire::decode(&oc,&bytes).unwrap();match which{0=>d.proof.degree_bits=12,1=>d.proof.ood_pow_witness=Val::ONE,2=>d.proof.opened_values.trace_next=None,3=>{d.proof.opened_values.trace_local.pop();},4=>{d.proof.opened_values.quotient_chunks.pop();},5=>d.proof.opened_values.random=None,6=>d.proof.commitments.random=None,_=>unreachable!()}
   let proof=postcard::to_allocvec(&d.proof).unwrap();let mut b=bytes[..3904].to_vec();b[436..440].copy_from_slice(&(proof.len()as u32).to_le_bytes());b.extend(proof);check("wrong-fixed-profile-shape",&b);assert!(run(&c,&b).is_err());shape_cases+=1;
  }
  let mut pending=zk9_proof_staged::Reader::new(&bytes[3904..]).unwrap();pending.advance(1).unwrap();let mut cp=[0;640];pending.checkpoint(&mut cp).unwrap();assert!(candidate::derive(&c,&bytes,&cp).is_err());
  let mut wrong=c;wrong.network[0]^=1;assert!(candidate::derive(&wrong,&bytes,&completed).is_err());
  let mut invalid=bytes.clone();invalid[440]^=1;assert!(run(&c,&invalid).is_ok());assert!(original::wire::verify(&original::config().unwrap(),&oc,&invalid).is_err());
  assert!(original::wire::verify(&original::config().unwrap(),&oc,&bytes).is_ok());
  records.push(json!({"fixture":name,"prefix_allocations":allocs,"prefix_requested_bytes":requested,"alpha_canonical":p.alpha,"zeta_canonical":p.zeta,"original_verified":true,"changed_ciphertext_prefix_derives_but_full_crypto_rejects":true}));
 }
 println!("{}",serde_json::to_string_pretty(&json!({"status":"PASS_TRANSCRIPT_PREFIX_ONLY","regenerated_seed_matches":true,"montgomery_conversions":conversions,"byte_stream_comparisons":stream_checks,"mutated_envelope_cases":cases,"profile_shape_rejections":shape_cases,"records":records,"proof_verified_on_solana":false})).unwrap());
}
