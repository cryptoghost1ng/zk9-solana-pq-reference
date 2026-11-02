//! Recursive allocation/work bounds for the specific fixed proof schema.
//! Unsupported Serde forms fail closed. All nesting must pass our seed wrapper.
use serde::de::{self,DeserializeSeed,Deserializer,SeqAccess,Visitor};
use std::fmt;
const MAX_SEQUENCE:usize=16_384;
// Charges both declared sequence slots and visited scalar/struct operations.
// This is a work budget, not a count of distinct field elements or input bytes.
const MAX_ELEMENTS:usize=16_000_000;
const MAX_DEPTH:usize=32;
struct Budget {left:usize,reason:Option<&'static str>}
impl Budget {
    fn charge<E:de::Error>(&mut self,n:usize)->Result<(),E> {
        match self.left.checked_sub(n){Some(left)=>{self.left=left;Ok(())},None=>{
            self.reason=Some("proof element budget");Err(E::custom("proof element budget"))}}
    }
}
struct Bounded<'a,D>{inner:D,budget:&'a mut Budget,depth:usize}
struct Guard<'a,V>{inner:V,budget:&'a mut Budget,depth:usize}
struct Sequence<'a,A>{inner:A,budget:&'a mut Budget,depth:usize}
struct Seed<'a,S>{inner:S,budget:&'a mut Budget,depth:usize}
impl<'de,S:DeserializeSeed<'de>> DeserializeSeed<'de> for Seed<'_,S> {
    type Value=S::Value;
    fn deserialize<D:Deserializer<'de>>(self,d:D)->Result<Self::Value,D::Error> {
        self.inner.deserialize(Bounded{inner:d,budget:self.budget,depth:self.depth})
    }
}
impl<'de,A:SeqAccess<'de>> SeqAccess<'de> for Sequence<'_,A> {
    type Error=A::Error;
    fn next_element_seed<S:DeserializeSeed<'de>>(&mut self,seed:S)->Result<Option<S::Value>,Self::Error> {
        self.inner.next_element_seed(Seed{inner:seed,budget:self.budget,depth:self.depth+1})
    }
    fn size_hint(&self)->Option<usize>{self.inner.size_hint()}
}
macro_rules! scalar_visit {
    ($($method:ident:$ty:ty),*)=>{$(
        fn $method<E:de::Error>(self,v:$ty)->Result<Self::Value,E>{self.inner.$method(v)}
    )*};
}
impl<'de,V:Visitor<'de>> Visitor<'de> for Guard<'_,V> {
    type Value=V::Value;
    fn expecting(&self,f:&mut fmt::Formatter)->fmt::Result{self.inner.expecting(f)}
    scalar_visit!(visit_bool:bool,visit_u8:u8,visit_u16:u16,visit_u32:u32,visit_u64:u64,
                  visit_i8:i8,visit_i16:i16,visit_i32:i32,visit_i64:i64);
    fn visit_none<E:de::Error>(self)->Result<Self::Value,E>{self.inner.visit_none()}
    fn visit_unit<E:de::Error>(self)->Result<Self::Value,E>{self.inner.visit_unit()}
    fn visit_some<D:Deserializer<'de>>(self,d:D)->Result<Self::Value,D::Error>{
        self.inner.visit_some(Bounded{inner:d,budget:self.budget,depth:self.depth+1})
    }
    fn visit_newtype_struct<D:Deserializer<'de>>(self,d:D)->Result<Self::Value,D::Error>{
        self.inner.visit_newtype_struct(Bounded{inner:d,budget:self.budget,depth:self.depth+1})
    }
    fn visit_seq<A:SeqAccess<'de>>(self,a:A)->Result<Self::Value,A::Error>{
        // Postcard returns None for a length greater than remaining input.
        // Reject before Vec's visitor receives any attacker-controlled hint.
        let n=match a.size_hint(){Some(n)=>n,None=>{self.budget.reason=Some("missing bounded sequence length");return Err(de::Error::custom("missing bounded sequence length"));}};
        if n>MAX_SEQUENCE{self.budget.reason=Some("proof sequence bound");return Err(de::Error::custom("proof sequence bound"));}
        self.budget.charge(n)?;
        self.inner.visit_seq(Sequence{inner:a,budget:self.budget,depth:self.depth})
    }
}
macro_rules! forward {
    ($($method:ident $(($($arg:ident:$ty:ty),*))?),*)=>{$(
        fn $method<V:Visitor<'de>>(self,$($($arg:$ty,)*)?visitor:V)->Result<V::Value,D::Error>{
            if self.depth>MAX_DEPTH{self.budget.reason=Some("proof nesting bound");return Err(de::Error::custom("proof nesting bound"));}
            self.budget.charge(1)?;
            self.inner.$method($($($arg,)*)?Guard{inner:visitor,budget:self.budget,depth:self.depth})
        }
    )*};
}
impl<'de,D:Deserializer<'de>> Deserializer<'de> for Bounded<'_,D> {
    type Error=D::Error;
    fn deserialize_any<V:Visitor<'de>>(self,_:V)->Result<V::Value,D::Error>{
        self.budget.reason=Some("unsupported proof representation");
        Err(de::Error::custom("unsupported proof representation"))
    }
    forward!(deserialize_bool,deserialize_u8,deserialize_u16,deserialize_u32,deserialize_u64,
        deserialize_i8,deserialize_i16,deserialize_i32,deserialize_i64,
        deserialize_option,deserialize_unit,deserialize_seq,
        deserialize_unit_struct(name:&'static str),
        deserialize_newtype_struct(name:&'static str),
        deserialize_tuple(len:usize),
        deserialize_tuple_struct(name:&'static str,len:usize),
        deserialize_struct(name:&'static str,fields:&'static [&'static str]));
    serde::forward_to_deserialize_any!{i128 u128 f32 f64 char str string bytes byte_buf map enum identifier ignored_any}
    fn is_human_readable(&self)->bool{self.inner.is_human_readable()}
}
pub fn decode(bytes:&[u8])->Result<crate::PaymentProof,String>{
    decode_metered(bytes).map(|(proof,_)|proof)
}
pub fn decode_metered(bytes:&[u8])->Result<(crate::PaymentProof,usize),String>{
    use serde::Deserialize;
    let mut input=postcard::Deserializer::from_bytes(bytes);
    let mut budget=Budget{left:MAX_ELEMENTS,reason:None};
    let proof=crate::PaymentProof::deserialize(Bounded{inner:&mut input,budget:&mut budget,depth:0})
        .map_err(|e|format!("bounded proof decoding: {e}; reason={:?}; remaining={}",budget.reason,budget.left))?;
    if !input.finalize().map_err(|e|e.to_string())?.is_empty(){return Err("trailing proof data".into());}
    // Unique public encoding; reject overlong varints and equivalent encodings.
    if postcard::to_allocvec(&proof).map_err(|e|e.to_string())?!=bytes{return Err("noncanonical proof encoding".into());}
    Ok((proof,MAX_ELEMENTS-budget.left))
}
