use crate::{Error,field::Ext};
#[derive(Clone,Copy)]struct Point<'a>{public:&'a[u8],hidden:&'a[u8]}
pub struct Claims<'a>{points:[Point<'a>;19]}
impl<'a>Claims<'a>{
 /// Same authenticated, completed format checkpoint as the input MMCS stage.
 pub fn from_trusted_format(wire:&'a[u8],format:&[u8])->Result<Self,Error>{
  let v=prefix::views_from_trusted_format(wire,format).map_err(|_|Error::Shape)?;
  let proof=wire.get(3945..).ok_or(Error::Encoding)?;let reader=fri::scan::Reader::resume_trusted(proof,format).map_err(|_|Error::State)?;if !reader.done(){return Err(Error::State)}
  let span=reader.sections()[2];let bytes=proof.get(span.start as usize..span.end as usize).ok_or(Error::Encoding)?;let mut c=mmcs::Cursor{bytes,at:0};c.count(3).map_err(|_|Error::Shape)?;
  let mut points=[Point{public:&[],hidden:&[]};19];let mut at=0;
  for batch in 0..3{let matrices=if batch==2{16}else{1};c.count(matrices).map_err(|_|Error::Shape)?;
   for m in 0..matrices{let count=if batch==1{2}else{1};c.count(count).map_err(|_|Error::Shape)?;
    for point in 0..count{c.count(8).map_err(|_|Error::Shape)?;let public=match batch{0=>v.random.bytes(),1=>if point==0{v.trace.bytes()}else{v.next.bytes()},_=>v.quotient[m].bytes()};points[at]=Point{public,hidden:c.take(256).map_err(|_|Error::Encoding)?};at+=1;}
   }
  }if at!=19||c.take(4).map_err(|_|Error::Encoding)?!=[0;4]{return Err(Error::Shape)}Ok(Self{points})
 }
 pub fn width(point:usize)->Result<usize,Error>{if point>=19{Err(Error::Shape)}else{Ok(if point==1||point==2{prefix::WIDTH+8}else{16})}}
 pub fn get(&self,point:usize,column:usize)->Result<Ext,Error>{let p=self.points.get(point).ok_or(Error::Shape)?;if column>=Self::width(point)?{return Err(Error::Shape)}let public=p.public.len()/32;let(bytes,i)=if column<public{(p.public,column)}else{(p.hidden,column-public)};Ext::decode(bytes.get(i*32..i*32+32).ok_or(Error::Encoding)?,true)}
}
