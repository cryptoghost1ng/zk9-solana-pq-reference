//! Integer conservation with a distinct public withdrawal, never disguised as fee.
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use crate::Val;
pub const WIDTH:usize=393; // six u64s + three signed carries encoded in 3 bits
pub struct BalanceAir;
impl<F> BaseAir<F> for BalanceAir {
    fn width(&self)->usize {WIDTH}
    fn num_public_values(&self)->usize {crate::PUBLIC_VALUES}
    fn max_constraint_degree(&self)->Option<usize> {Some(2)}
}
impl<AB:AirBuilder> Air<AB> for BalanceAir {
    fn eval(&self,b:&mut AB) {
        let main=b.main(); let row=main.current_slice(); let next=main.next_slice();
        let public=b.public_values().to_vec();
        for i in 0..WIDTH {b.assert_bool(row[i]); b.when_transition().assert_eq(row[i],next[i]);}
        let limb=|v:usize,k:usize|->AB::Expr {
            (0..16).fold(AB::Expr::ZERO,|a,j|a+row[v*64+k*16+j]*AB::F::from_u32(1<<j))
        };
        let carry=|k:usize|->AB::Expr {
            if k==0 || k==4 {AB::Expr::ZERO} else {
                (0..3).fold(AB::Expr::ZERO,|a,j|a+row[384+(k-1)*3+j]*AB::F::from_u32(1<<j))-AB::F::from_u32(4)
            }
        };
        // Every limb is <=65535; carries in [-4,3]. Each residual has absolute
        // value < 2^20, far below BabyBear's modulus. Hence field equality is
        // integer equality. Telescoping four equations with boundary carry=0
        // proves full 128-bit conservation, without u64 modular wraparound.
        for k in 0..4 {
            b.assert_eq(limb(4,k),public[k]);
            b.assert_eq(limb(5,k),public[276+k]);
            b.assert_eq(limb(0,k)+limb(1,k)+carry(k),
                limb(2,k)+limb(3,k)+limb(4,k)+limb(5,k)+carry(k+1)*AB::F::from_u32(65536));
        }
    }
}
pub fn trace(inputs:[u64;2],outputs:[u64;2],fee:u64,amount:u64)->Result<RowMajorMatrix<Val>,String> {
    if inputs.iter().map(|&x|x as u128).sum::<u128>() != outputs.iter().map(|&x|x as u128).sum::<u128>()+fee as u128+amount as u128 {
        return Err("withdrawal integer conservation".into());
    }
    let values=[inputs[0],inputs[1],outputs[0],outputs[1],fee,amount];
    let mut row=vec![Val::ZERO;WIDTH];
    for (i,v) in values.iter().enumerate() {for j in 0..64 {row[i*64+j]=Val::from_u8(((v>>j)&1) as u8);}}
    let mut carry=0i64;
    for k in 0..4 {
        let v=values.map(|v|((v>>(16*k))&65535) as i64);
        let d=v[0]+v[1]+carry-v[2]-v[3]-v[4]-v[5];
        if d%65536!=0 {return Err("nonintegral withdrawal carry".into());}
        carry=d/65536;
        if k<3 {
            if !(-4..=3).contains(&carry) {return Err("withdrawal carry bound".into());}
            let code=(carry+4) as u8;
            for j in 0..3 {row[384+k*3+j]=Val::from_u8((code>>j)&1);}
        }
    }
    if carry!=0 {return Err("withdrawal overflow".into());}
    Ok(RowMajorMatrix::new(row,WIDTH))
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn boundary_limb_conservation() {
        for v in [1,65535,65536,65537,u32::MAX as u64,u64::MAX-1,u64::MAX] {
            for fee in [0,1] {
                let amount=v-fee;
                let row=trace([v,0],[0,0],fee,amount).unwrap();
                let t=RowMajorMatrix::new(row.values.repeat(4),WIDTH);
                let mut p=vec![Val::ZERO;crate::PUBLIC_VALUES];
                for k in 0..4 {p[k]=Val::from_u16((fee>>(16*k)) as u16);p[276+k]=Val::from_u16((amount>>(16*k)) as u16);}
                p3_air::check_constraints(&BalanceAir,&t,&p);
            }
        }
        // Combined inputs above u64 are valid at the relation layer, provided
        // each individual amount is u64. The wallet may impose a tighter cap.
        assert!(trace([u64::MAX,u64::MAX],[u64::MAX-1,u64::MAX-1],1,1).is_ok());
        assert!(trace([1,0],[0,0],1,1).is_err());
        assert!(trace([0,0],[u64::MAX,0],0,1).is_err());
    }
}
