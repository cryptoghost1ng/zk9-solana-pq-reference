use std::{alloc::{GlobalAlloc,Layout,System},sync::atomic::{AtomicBool,AtomicUsize,Ordering::SeqCst},path::Path,fs};
use serde_json::json;
use zk9_proof_view::{inspect,inspect_with,Observe};
type PaymentProof=original::PaymentProof;
#[path="../../../pq-private-send-v1/src/bounded.rs"]mod oracle;
struct Counter;static ACTIVE:AtomicBool=AtomicBool::new(false);static ALLOCS:AtomicUsize=AtomicUsize::new(0);static BYTES:AtomicUsize=AtomicUsize::new(0);
unsafe impl GlobalAlloc for Counter{
 unsafe fn alloc(&self,l:Layout)->*mut u8{if ACTIVE.load(SeqCst){ALLOCS.fetch_add(1,SeqCst);BYTES.fetch_add(l.size(),SeqCst);}unsafe{System.alloc(l)}}
 unsafe fn alloc_zeroed(&self,l:Layout)->*mut u8{if ACTIVE.load(SeqCst){ALLOCS.fetch_add(1,SeqCst);BYTES.fetch_add(l.size(),SeqCst);}unsafe{System.alloc_zeroed(l)}}
 unsafe fn dealloc(&self,p:*mut u8,l:Layout){unsafe{System.dealloc(p,l)}}
 unsafe fn realloc(&self,p:*mut u8,l:Layout,n:usize)->*mut u8{if ACTIVE.load(SeqCst){ALLOCS.fetch_add(1,SeqCst);BYTES.fetch_add(n,SeqCst);}unsafe{System.realloc(p,l,n)}}
}
#[global_allocator]static ALLOC:Counter=Counter;
fn measured<T>(f:impl FnOnce()->T)->(T,usize,usize){ALLOCS.store(0,SeqCst);BYTES.store(0,SeqCst);ACTIVE.store(true,SeqCst);let x=f();ACTIVE.store(false,SeqCst);(x,ALLOCS.load(SeqCst),BYTES.load(SeqCst))}
#[derive(Default)]struct Samples{count:usize,offsets:[usize;12],used:usize,rows:usize,first_row:Option<(usize,usize,usize)>}
impl<'a>Observe<'a> for &mut Samples{
 fn field(&mut self,offset:usize,b:&'a[u8;4]){assert!(u32::from_le_bytes(*b)<zk9_proof_view::PRIME);if (self.count==0||self.count%100000==0)&&self.used<12{self.offsets[self.used]=offset;self.used+=1;}self.count+=1;}
 fn row(&mut self,offset:usize,b:&'a[u8],degree:usize){assert!(degree==1||degree==8);assert_eq!(b.len()%(4*degree),0);if self.first_row.is_none(){self.first_row=Some((offset,b.len(),degree));}self.rows+=1;}
}
#[derive(Debug)]struct Summary{stats:zk9_proof_staged::Stats,sections:[zk9_proof_staged::Span;5],ops:u64,steps:u64}
impl<'a>zk9_proof_staged::Observe<'a> for &mut Samples{
 fn field(&mut self,p:usize,b:&'a[u8;4]){Observe::field(self,p,b)}
 fn row(&mut self,p:usize,b:&'a[u8],d:usize){Observe::row(self,p,b,d)}
}
fn staged(bytes:&[u8],step:u32,restart:bool,mut sample:&mut Samples)->Result<Summary,zk9_proof_staged::Error>{
 let mut r=zk9_proof_staged::Reader::new(bytes)?;let mut checkpoint=[0u8;zk9_proof_staged::CHECKPOINT_BYTES];let mut steps=0;
 while !r.done(){r.advance_with(step,&mut sample)?;steps+=1;if restart{r.checkpoint(&mut checkpoint)?;r=zk9_proof_staged::Reader::resume_trusted(bytes,&checkpoint)?;}}
 let n=r.operations();assert!(r.advance(1)?);assert_eq!(r.operations(),n);
 Ok(Summary{stats:r.stats(),sections:r.sections(),ops:n,steps})
}
fn main(){
 let mut boundary_cases=0;
 let mut minimal=vec![0u8;44];minimal[0]=1;minimal[9]=1;
 let check_small=|b:&[u8]|{let expected=oracle::decode(b).is_ok();assert_eq!(inspect(b).is_ok(),expected);assert_eq!(staged(b,1,true,&mut Samples::default()).is_ok(),expected);expected};
 assert!(check_small(&minimal));boundary_cases+=1;
 for offset in 0..minimal.len(){for bit in 0..8{let mut b=minimal.clone();b[offset]^=1<<bit;check_small(&b);boundary_cases+=1;}}
 for (encoded,want) in [(vec![0x80,0],false),(vec![0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,1],true),(vec![0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,2],false)]{
  let mut b=minimal.clone();b.splice(1..2,encoded);assert_eq!(check_small(&b),want);boundary_cases+=1;
 }
 let mut r=zk9_proof_staged::Reader::new(&minimal).unwrap();assert!(!r.advance(1).unwrap());
 let mut checkpoint=[0u8;zk9_proof_staged::CHECKPOINT_BYTES];r.checkpoint(&mut checkpoint).unwrap();
 let mut checkpoint_cases=0;
 for (offset,value) in [(0,255),(12,255),(20,255),(24,255),(28,255),(40,255),(44,2),(56,1),(104,1),(128,255),(129,2),(130,4),(131,1),(136,255),(160,1)]{
  let mut b=checkpoint;b[offset]=value;assert!(zk9_proof_staged::Reader::resume_trusted(&minimal,&b).is_err(),"checkpoint byte {offset}");checkpoint_cases+=1;
 }
 assert!(r.advance(0).is_err());assert!(r.advance(4097).is_err());assert!(r.advance(4096).unwrap());
 let oversized=vec![0;zk9_proof_staged::MAX_BYTES+1];assert!(zk9_proof_staged::Reader::new(&oversized).is_err());
 let arg=std::env::args().nth(1).expect("fixture directory");let dir=Path::new(&arg);let mut records=vec![];let mut mutations=0;let mut staged_checks=0;
 for name in ["payment-0.bin","payment-1.bin","payment-2.bin","single-1.bin","single-2.bin","single-conflict.bin"]{
  let envelope=fs::read(dir.join(name)).unwrap();let bytes=&envelope[3904..];
  let (old,old_allocs,old_bytes)=measured(||oracle::decode_metered(bytes));let (proof,budget)=old.unwrap();
  let (new,allocs,requested)=measured(||inspect(bytes));let view=new.unwrap();assert_eq!((allocs,requested),(0,0));
  assert_eq!(view.stats.serde_work,budget,"budget {name}");assert_eq!(view.bytes().as_ptr(),bytes.as_ptr());
  let pieces=[postcard::to_allocvec(&proof.commitments).unwrap(),postcard::to_allocvec(&proof.opened_values).unwrap(),postcard::to_allocvec(&proof.opening_proof).unwrap(),postcard::to_allocvec(&proof.degree_bits).unwrap(),postcard::to_allocvec(&proof.ood_pow_witness).unwrap()];
  for (i,piece) in pieces.iter().enumerate(){assert_eq!(view.section(i).unwrap(),piece);assert_eq!(view.section(i).unwrap().as_ptr(),bytes[view.sections[i].start..].as_ptr());}
  let mut sample=Samples::default();let (observed,oa,ob)=measured(||inspect_with(bytes,&mut sample));assert!(observed.is_ok());assert_eq!((oa,ob),(0,0));assert_eq!(sample.count,view.stats.fields);
  let (row_start,row_len,row_degree)=sample.first_row.unwrap();assert_eq!(row_degree,8);
  let serialized=postcard::to_allocvec(&proof.opened_values.trace_local).unwrap();
  assert_eq!(&bytes[row_start..row_start+row_len],&serialized[serialized.len()-row_len..]);
  assert_eq!(row_len,proof.opened_values.trace_local.len()*8*4);
  let mut staged_sample=Samples::default();
  let (resume,sa,sb)=measured(||staged(bytes,4096,true,&mut staged_sample));let resume=resume.unwrap();assert_eq!((sa,sb),(0,0));
  assert_eq!(resume.stats.serde_work as usize,budget);assert_eq!(resume.stats.fields as usize,view.stats.fields);assert_eq!(resume.stats.varints as usize,view.stats.varints);assert_eq!(resume.stats.sequences as usize,view.stats.sequences);assert_eq!(resume.stats.max_sequence as usize,view.stats.max_sequence);assert_eq!(resume.stats.max_depth as usize,view.stats.max_depth);
  for (x,y) in resume.sections.iter().zip(view.sections.iter()){assert_eq!((x.start as usize,x.end as usize),(y.start,y.end));}
  assert_eq!((staged_sample.count,staged_sample.rows,staged_sample.offsets,staged_sample.first_row),(sample.count,sample.rows,sample.offsets,sample.first_row));
  // A one-operation step exercises every suspension boundary on the largest fixture.
  if name=="payment-0.bin"{for step in [1,7,257]{let (v,a,b)=measured(||staged(bytes,step,true,&mut Samples::default()));let v=v.unwrap();assert_eq!((a,b),(0,0));assert_eq!(v.stats,resume.stats);assert_eq!(v.sections,resume.sections);assert_eq!(v.ops,resume.ops);staged_checks+=1;}}
  staged_checks+=1;
  let mut check=|label:&str,data:&[u8],required:Option<bool>|{
   let before=oracle::decode(data).is_ok();
   let (s,a,b)=measured(||staged(data,127,true,&mut Samples::default()));assert_eq!((a,b),(0,0),"staged allocation {label}");assert_eq!(s.is_ok(),before,"staged acceptance {name}:{label}");staged_checks+=1;let (after,ca,cb)=measured(||inspect(data));let accepted=after.is_ok();assert_eq!((ca,cb),(0,0),"allocation on {label}");assert_eq!(accepted,before,"acceptance {name}:{label}");if let Some(want)=required{assert_eq!(accepted,want,"expected {name}:{label}")}mutations+=1;
  };
  for offset in sample.offsets[..sample.used].iter(){let mut b=bytes.to_vec();b[*offset..*offset+4].copy_from_slice(&zk9_proof_view::PRIME.to_le_bytes());check("field-out-of-range",&b,Some(false));}
  for n in [0,1,2,7,8,32,100,bytes.len()/2,bytes.len()-1]{check("truncated",&bytes[..n],Some(false));}
  let mut b=bytes.to_vec();b.push(0);check("trailing",&b,Some(false));
  let mut b=bytes.to_vec();b[0]|=128;b.insert(1,0);check("overlong-first-cap-length",&b,Some(false));
  let mut b=bytes.to_vec();b[0]=0;check("zero-cap",&b,Some(false));
  let mut b=bytes.to_vec();b[0]=3;check("non-power-two-cap",&b,Some(false));
  let mut b=bytes.to_vec();b.splice(0..1,[0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x02]);check("overflow-length",&b,Some(false));
  let cap_len=postcard::to_allocvec(&proof.commitments.trace).unwrap().len();
  let mut b=vec![0];b.extend(&bytes[cap_len..]);check("well-framed-empty-cap",&b,Some(false));
  let mut b=vec![3];for _ in 0..3{b.extend(&bytes[1..cap_len]);}b.extend(&bytes[cap_len..]);check("well-framed-non-power-two-cap",&b,Some(false));
  let mut b=vec![0x80,0x80,0x02];b.extend(vec![0;32768*8]);b.extend(&bytes[cap_len..]);check("sequence-limit-before-allocation",&b,Some(false));
  let prep=view.sections[1].start+postcard::to_allocvec(&proof.opened_values.trace_local).unwrap().len()+postcard::to_allocvec(&proof.opened_values.trace_next).unwrap().len();
  assert_eq!(&bytes[prep..prep+2],&[0,0]);
  let one=postcard::to_allocvec(&proof.opened_values.trace_local[..1]).unwrap();let two=postcard::to_allocvec(&proof.opened_values.trace_local[..2]).unwrap();
  let mut b=bytes[..prep].to_vec();b.extend([0,1]);b.extend(&one);b.extend(&bytes[prep+2..]);check("preprocessed-next-without-local",&b,Some(false));
  let mut b=bytes[..prep].to_vec();b.extend([1,0,0]);b.extend(&bytes[prep+2..]);check("preprocessed-empty-local",&b,Some(false));
  let mut b=bytes[..prep].to_vec();b.push(1);b.extend(&one);b.push(1);b.extend(&two);b.extend(&bytes[prep+2..]);check("preprocessed-width-mismatch",&b,Some(false));
  let mut b=bytes.to_vec();b[prep]=2;check("invalid-option-tag",&b,Some(false));
  // Deterministic dispersed corruptions; not every bit flip is a malformed encoding.
  for i in 0..32 {let mut b=bytes.to_vec();let offset=((i as usize*104729+17)%b.len())as usize;b[offset]^=1;check("dispersed-bit-flip",&b,None);}
  let mut b=bytes.to_vec();b[1]^=1;check("changed-commitment-still-canonical",&b,Some(true));
  let mut changed=envelope.clone();changed[3905]^=1;
  let context=original::Context{network:[1;32],genesis:[2;32],asset:[3;32],fee:1};
  assert!(original::wire::verify(&original::config().unwrap(),&context,&envelope).is_ok());
  assert!(original::wire::verify(&original::config().unwrap(),&context,&changed).is_err());
  records.push(json!({"staged_allocations":sa,"staged_requested_bytes":sb,"staged_operations":resume.ops,"staged_steps_4096":resume.steps,"fixture":name,"proof_bytes":bytes.len(),"old_decode_allocations":old_allocs,"old_requested_bytes_total":old_bytes,"new_allocations":allocs,"new_requested_bytes":requested,"matched_serde_work":budget,"base_fields":view.stats.fields,"canonical_varints":view.stats.varints,"logical_depth":view.stats.max_depth,"sections":view.sections.iter().map(|s|json!({"start":s.start,"end":s.end})).collect::<Vec<_>>()}));
 }
 println!("{}",serde_json::to_string_pretty(&json!({"status":"PASS_STAGED_FORMAT_ONLY","staged_comparisons":staged_checks,"small_schema_boundary_cases":boundary_cases,"malformed_checkpoint_rejections":checkpoint_cases,"valid_fixtures":6,"mutation_cases":mutations,"crypto_invalid_but_parser_accepts_demonstrated":true,"records":records,"full_proof_verification_on_solana":false})).unwrap());
}
