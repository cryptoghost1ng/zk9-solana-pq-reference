//! Numeric IDs are versioned checkpoint format, not attacker-supplied schema.
#[derive(Clone,Copy)]pub(crate)enum Shape {Field,Int,Unit,Seq(u8),Opt(u8),Tuple(&'static[u8]),Struct(&'static[u8])}
pub(crate)const FIELD:u8=0;pub(crate)const INT:u8=1;pub(crate)const UNIT:u8=2;
pub(crate)const DIGEST:u8=3;pub(crate)const CAP:u8=5;pub(crate)const EXT:u8=9;
pub(crate)const OPENINGS:u8=15;pub(crate)const PROOF:u8=28;
pub(crate)fn shape(id:u8)->Option<Shape>{use Shape::*;Some(match id{
 0=>Field,1=>Int,2=>Unit,3=>Tuple(&[INT;8]),4=>Seq(DIGEST),
 5=>Struct(&[4,UNIT]),6=>Opt(CAP),7=>Struct(&[CAP,CAP,6]),
 8=>Tuple(&[FIELD;8]),9=>Struct(&[8,UNIT]),10=>Seq(EXT),11=>Opt(10),
 12=>Seq(10),13=>Seq(12),14=>Seq(13),
 15=>Struct(&[10,11,11,11,12,11]),
 16=>Seq(FIELD),17=>Seq(16),18=>Seq(17),19=>Struct(&[4]),
 20=>Tuple(&[18,19]),21=>Struct(&[18,20]),22=>Seq(21),
 23=>Struct(&[12,20]),24=>Seq(23),25=>Seq(CAP),
 26=>Struct(&[FIELD,25,16,22,24,10,FIELD]),27=>Tuple(&[14,26]),
 28=>Struct(&[7,OPENINGS,27,INT,FIELD]),_=>return None
})}
