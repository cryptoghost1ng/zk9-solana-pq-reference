//! Canonical BabyBear and F_p[X]/(X^8-11); wire Montgomery words are converted explicitly.
use core::ops::{Add,Sub,Mul,Neg};
use crate::Error;
pub const P:u32=2013265921;
#[derive(Clone,Copy,Default,Debug,PartialEq,Eq)]
pub struct F(u32);
impl F{
 pub const ZERO:Self=Self(0);pub const ONE:Self=Self(1);
 pub fn new(x:u32)->Result<Self,Error>{if x<P{Ok(Self(x))}else{Err(Error::Field)}}
 pub fn canonical(self)->u32{self.0}
 pub fn from_montgomery(x:u32)->Result<Self,Error>{Ok(Self::new(x)?*Self(943718400))}
 pub fn montgomery(self)->u32{(self*Self(268435454)).0}
 pub fn pow(self,mut e:u32)->Self{let mut a=self;let mut r=Self::ONE;while e!=0{if e&1!=0{r=r*a}a=a*a;e>>=1;}r}
 pub fn inverse(self)->Option<Self>{(self!=Self::ZERO).then(||self.pow(P-2))}
 pub fn half(self)->Self{Self(if self.0&1==0{self.0>>1}else{(self.0+P)>>1})}
}
impl Add for F{type Output=Self;fn add(self,b:Self)->Self{let sum=self.0+b.0;Self(if sum>=P{sum-P}else{sum})}}
impl Sub for F{type Output=Self;fn sub(self,b:Self)->Self{Self(if self.0>=b.0{self.0-b.0}else{self.0+P-b.0})}}
impl Mul for F{type Output=Self;fn mul(self,b:Self)->Self{Self(((self.0 as u64*b.0 as u64)%P as u64)as u32)}}
impl Neg for F{type Output=Self;fn neg(self)->Self{Self::ZERO-self}}
#[derive(Clone,Copy,Default,Debug,PartialEq,Eq)]
pub struct Ext(pub [F;8]);
impl Ext{
 pub const ZERO:Self=Self([F::ZERO;8]);pub const ONE:Self=Self([F::ONE,F::ZERO,F::ZERO,F::ZERO,F::ZERO,F::ZERO,F::ZERO,F::ZERO]);
 pub fn base(x:F)->Self{let mut a=Self::ZERO;a.0[0]=x;a}
 pub fn canonical(x:[u32;8])->Result<Self,Error>{let mut a=[F::ZERO;8];for(i,v)in x.into_iter().enumerate(){a[i]=F::new(v)?}Ok(Self(a))}
 pub fn words(self)->[u32;8]{self.0.map(F::canonical)}
 pub fn decode(bytes:&[u8],montgomery:bool)->Result<Self,Error>{if bytes.len()!=32{return Err(Error::Encoding)}let mut a=[F::ZERO;8];for(x,b)in a.iter_mut().zip(bytes.chunks_exact(4)){let u=u32::from_le_bytes(b.try_into().unwrap());*x=if montgomery{F::from_montgomery(u)?}else{F::new(u)?};}Ok(Self(a))}
 pub fn encode(self,bytes:&mut[u8])->Result<(),Error>{if bytes.len()!=32{return Err(Error::Encoding)}for(x,b)in self.0.into_iter().zip(bytes.chunks_exact_mut(4)){b.copy_from_slice(&x.canonical().to_le_bytes())}Ok(())}
 pub fn scale(self,x:F)->Self{Self(self.0.map(|a|a*x))}
 pub fn half(self)->Self{Self(self.0.map(F::half))}
 pub fn pow(self,mut e:u32)->Self{let mut a=self;let mut r=Self::ONE;while e!=0{if e&1!=0{r=r*a}a=a*a;e>>=1;}r}
 pub fn inverse(self)->Option<Self>{inverse_poly(self.0,8).map(Self)}
}
impl Add for Ext{type Output=Self;fn add(self,b:Self)->Self{Self(core::array::from_fn(|i|self.0[i]+b.0[i]))}}
impl Sub for Ext{type Output=Self;fn sub(self,b:Self)->Self{Self(core::array::from_fn(|i|self.0[i]-b.0[i]))}}
impl Mul for Ext{type Output=Self;fn mul(self,b:Self)->Self{Self(mul_poly(&self.0,&b.0,8))}}
impl Neg for Ext{type Output=Self;fn neg(self)->Self{Self(self.0.map(|x|-x))}}
fn mul_poly(a:&[F;8],b:&[F;8],n:usize)->[F;8]{let mut r=[F::ZERO;8];for i in 0..n{for j in 0..n{let mut t=a[i]*b[j];let mut k=i+j;if k>=n{k-=n;t=t*F(11)}r[k]=r[k]+t;}}r}
/// Recursive norm under X -> -X. Each step works in Y=X^2, Y^(n/2)=11.
/// The last inverse is in F_p. Zero is explicitly rejected, never divided through.
fn inverse_poly(a:[F;8],n:usize)->Option<[F;8]>{
 if n==1{let mut r=[F::ZERO;8];r[0]=a[0].inverse()?;return Some(r)}
 let h=n/2;let mut even=[F::ZERO;8];let mut odd=[F::ZERO;8];for i in 0..h{even[i]=a[2*i];odd[i]=a[2*i+1];}
 let ee=mul_poly(&even,&even,h);let oo=mul_poly(&odd,&odd,h);let mut norm=[F::ZERO;8];
 norm[0]=ee[0]-oo[h-1]*F(11);for i in 1..h{norm[i]=ee[i]-oo[i-1];}
 let inverse=inverse_poly(norm,h)?;let e=mul_poly(&even,&inverse,h);let o=mul_poly(&odd,&inverse,h);let mut r=[F::ZERO;8];for i in 0..h{r[2*i]=e[i];r[2*i+1]=-o[i];}Some(r)
}
/// Pinned original generators, not an arbitrary primitive root with a different coset order.
pub fn generator(log:usize)->Result<F,Error>{
 const G:[u32;28]=[0x1,0x78000000,0x67055c21,0x5ee99486,0xbb4c4e4,0x2d4cc4da,0x669d6090,0x17b56c64,0x67456167,0x688442f9,0x145e952d,0x4fe61226,0x4c734715,0x11c33e2a,0x62c3d2b1,0x77cad399,0x54c131f4,0x4cabd6a6,0x5cf5713f,0x3e9430e8,0xba067a3,0x18adc27d,0x21fd55bc,0x4b859b3d,0x3bd57996,0x4483d85a,0x3a26eef8,0x1a427a41];
 G.get(log).copied().ok_or(Error::Shape).and_then(F::new)
}
pub fn reverse(index:u32,bits:usize)->Result<u32,Error>{if bits==0{return if index==0{Ok(0)}else{Err(Error::Shape)}}if bits>27||index>=1u32<<bits{return Err(Error::Shape)}Ok(index.reverse_bits()>>(32-bits))}
pub fn query_x(index:u32)->Result<F,Error>{Ok(F::new(31)?*generator(16)?.pow(reverse(index,16)?))}
pub fn fold_binary(parent:u32,log_height:usize,beta:Ext,lo:Ext,hi:Ext)->Result<Ext,Error>{let s=generator(log_height+1)?.pow(reverse(parent,log_height)?);Ok((lo+hi).half()+((lo-hi)*beta).scale((s+s).inverse().ok_or(Error::ZeroDenominator)?))}
