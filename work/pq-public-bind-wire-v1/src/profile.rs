//! Native transcript oracle for the qualified public-bind profile.
use crate as original;
use p3_air::{BaseAir,symbolic::AirLayout};
use p3_field::{BasedVectorSpace,PrimeField32,PrimeCharacteristicRing};
use p3_challenger::{CanObserve,CanSample};
use p3_commit::Pcs;
type Pc=<original::Config as StarkGenericConfig>::Pcs;
type Ch=<original::Config as StarkGenericConfig>::Challenger;
use p3_uni_stark::{StarkGenericConfig,StarkShape,StarkVerifierTranscript};
use original::{Val,config::Challenge};
pub struct Profile{pub shape:StarkShape,pub seed_words:Vec<u32>,pub log_quotient:usize}
struct Capture(Vec<u32>);impl CanObserve<Val> for Capture{fn observe(&mut self,v:Val){self.0.push(v.to_unique_u32());}}
impl Profile{
 pub fn derive()->Self{
  let c=original::config().unwrap();let air=original::DeliveryAir(original::air::PaymentAir::new());
  let log_degree=air.0.graph.height().ilog2()as usize;
  let layout=AirLayout{main_width:<original::DeliveryAir as BaseAir<Val>>::width(&air),num_public_values:<original::DeliveryAir as BaseAir<Val>>::num_public_values(&air),..Default::default()};
  let q=p3_uni_stark::get_log_num_quotient_chunks_for_domain::<Val,_>(&air,layout,<Pc as Pcs<Challenge,Ch>>::natural_domain_for_degree(c.pcs(),1<<log_degree),c.is_zk());
  let shape=StarkShape::new::<Val,_>(&air,0,log_degree+c.is_zk(),log_degree,1<<(q+c.is_zk()),true,c.ood_proof_of_work_bits());
  let mut cap=Capture(Vec::new());shape.domain_separator::<Val,Challenge>().seed(&mut cap);
  Self{shape,seed_words:cap.0,log_quotient:q}
 }
 pub fn evidence(&self)->serde_json::Value{let s=&self.shape;serde_json::json!({"log_ext_degree":s.log_ext_degree,"log_degree":s.log_degree,"main_width":s.main_width,"preprocessed_width":s.preprocessed_width,"num_public_values":s.num_public_values,"num_periodic_columns":s.num_periodic_columns,"num_quotient_chunks":s.num_quotient_chunks,"opens_main_next_row":s.opens_main_next_row,"opens_preprocessed_next_row":s.opens_preprocessed_next_row,"has_randomization":s.has_randomization,"ood_pow_bits":s.ood_pow_bits,"log_quotient":self.log_quotient,"seed_words_montgomery":self.seed_words})}
}
pub struct Reference{pub alpha:Vec<u32>,pub zeta:Vec<u32>,pub tail:Vec<u32>,pub public_words:Vec<u32>,pub delivery:Vec<Vec<u8>>}
impl Reference{pub fn evidence(&self)->serde_json::Value{serde_json::json!({"alpha_canonical":self.alpha,"zeta_canonical":self.zeta,"tail_canonical":self.tail,"public_words_montgomery":self.public_words,"delivery_digests":self.delivery})}}
pub fn prefix(profile:&Profile,expected:&original::Context,bytes:&[u8])->Result<Reference,String>{
 let decoded=original::wire::decode(expected,bytes)?;let p=&decoded.proof;let s=&profile.shape;let v=&p.opened_values;
 if p.degree_bits!=s.log_ext_degree||p.ood_pow_witness!=Val::ZERO||v.trace_local.len()!=s.main_width||v.trace_next.as_ref().is_none_or(|x|x.len()!=s.main_width)||v.preprocessed_local().is_some()||v.preprocessed_next().is_some()||v.quotient_chunks.len()!=s.num_quotient_chunks||v.quotient_chunks.iter().any(|q|q.len()!=8)||v.random.as_ref().is_none_or(|x|x.len()!=8)||p.commitments.random.is_none(){return Err("fixed verifier profile shape".into())}
 if p.commitments.trace.roots().len()!=1||p.commitments.quotient_chunks.roots().len()!=1||p.commitments.random.as_ref().unwrap().roots().len()!=1{return Err("fixed cap-height-zero profile".into())}
 let c=original::config().unwrap();let mut challenger=c.initialise_challenger();let public=decoded.statement.public_values();
 let mut transcript=StarkVerifierTranscript::<_,Val,Challenge>::new(&mut challenger,s.clone());
 let alpha=transcript.constraint_phase(p.commitments.trace.clone(),None,&public).unwrap();
 let zeta=transcript.ood_phase(p.commitments.quotient_chunks.clone(),p.commitments.random.clone(),p.ood_pow_witness).unwrap();
 // Bracket markers do not absorb bytes. This samples continuation state, NOT FRI.
 let tail:[Val;64]=transcript.delegate(|c|c.sample_array());transcript.finish();
 Ok(Reference{alpha:<Challenge as BasedVectorSpace<Val>>::as_basis_coefficients_slice(&alpha).iter().map(PrimeField32::as_canonical_u32).collect(),zeta:<Challenge as BasedVectorSpace<Val>>::as_basis_coefficients_slice(&zeta).iter().map(PrimeField32::as_canonical_u32).collect(),tail:tail.iter().map(PrimeField32::as_canonical_u32).collect(),public_words:public.iter().map(PrimeField32::to_unique_u32).collect(),delivery:decoded.statement.delivery.iter().map(|d|d.to_vec()).collect()})
}
