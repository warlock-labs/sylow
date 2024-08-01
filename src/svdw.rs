use crate::fields::fp::{FieldExtensionTrait, Fp};
use crate::groups::group::{Error, GroupAffine, GroupProjective};
use crate::hasher::HashError;
use crypto_bigint::U256;
use std::array::TryFromSliceError;
use subtle::Choice;

#[derive(Debug)]
pub enum MapError {
    SvdWError,
}
#[derive(Debug)]
pub struct SvdW<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> {
    A: F,
    B: F,
    C1: F,
    C2: F,
    C3: F,
    C4: F,
    Z: F,
}
impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> SvdW<D, N, F> {
    fn map_to_point(&self, u: F) -> Result<GroupProjective<D, N, F>, MapError> {
        let cmov = |x: &F, y: &F, b: &Choice| -> F {
            F::from(!bool::from(*b) as u64) * (*x) + F::from(bool::from(*b) as u64) * (*y)
        };
        let tv1 = u.square();
        let tv1 = u * u;
        let tv1 = tv1 * self.C1;
        let tv2 = F::from(1) + tv1;
        let tv1 = F::from(1) - tv1;
        let tv3 = tv1 * tv2;
        let tv3 = tv3.inv();
        let tv4 = u * tv1;
        let tv4 = tv4 * tv3;
        let tv4 = tv4 * self.C3;
        let x1 = self.C2 - tv4;
        let gx1 = x1 * x1;
        let gx1 = gx1 + self.A;
        let gx1 = gx1 * x1;
        let gx1 = gx1 + self.B;
        let e1 = gx1.is_square();
        let x2 = self.C2 + tv4;
        let gx2 = x2 * x2;
        let gx2 = gx2 + self.A;
        let gx2 = gx2 * x2;
        let gx2 = gx2 + self.B;
        let e2 = gx2.is_square() & !e1; // Avoid short-circuit logic ops
        let x3 = tv2 * tv2;
        let x3 = x3 * tv3;
        let x3 = x3 * x3;
        let x3 = x3 * self.C3;
        let x3 = x3 + self.Z;
        let x = cmov(&x3, &x1, &e1); // x = x1 if gx1 is square, else x = x3;
        let x = cmov(&x, &x2, &e2); // x = x2 if gx2 is square and gx1 is not;
        let gx = x * x;
        let gx = gx + self.A;
        let gx = gx * x;
        let gx = gx + self.B;
        let y = match gx.sqrt().into_option() {
            Some(d) => d,
            _ => return Err(MapError::SvdWError),
        };
        let e3 = Choice::from((bool::from(u.sgn0()) == bool::from(y.sgn0())) as u8);
        let y = cmov(&(-y), &y, &e3); // Select correct sign of y;

        let aff = GroupAffine::new([x, y]).expect("Point not on curve"); //.map_err(|_e: Error| MapError::SvdWError)?;
        Ok(GroupProjective::from(aff))
    }
    fn find_z_svdw(a: F, b: F) -> F {
        let g = |x: &F| -> F { (*x) * (*x) * (*x) + a * (*x) + b };
        let h = |x: &F| -> F { -(F::from(3) * (*x) * (*x) + F::from(4) * a) / (F::from(4) * g(x)) };
        let mut ctr = 1;
        loop {
            for z_cand in [F::from(ctr), -F::from(ctr)] {
                if g(&z_cand).is_zero() {
                    continue;
                }
                if h(&z_cand).is_zero() {
                    continue;
                }
                if !bool::from(h(&z_cand).is_square()) {
                    continue;
                }
                if bool::from(g(&z_cand).is_square())
                    | bool::from(g(&(-z_cand / F::from(2))).is_square())
                {
                    return z_cand;
                }
            }
            ctr += 1;
        }
    }
    fn precompute_constants(a: F, b: F) -> Result<Self, MapError> {
        let g = |x: &F| -> F { (*x) * (*x) * (*x) + a * (*x) + b };
        let z = Self::find_z_svdw(a, b);
        let mgz = -g(&z);
        let c1 = g(&z);
        let c2 = -z / F::from(2);
        let mut c3 = match (-g(&z) * (F::from(3) * z.square() + F::from(4) * a)).sqrt()
            .into_option(){
            Some(d) => d,
            _ => return Err(MapError::SvdWError)
        };
        if bool::from(c3.sgn0()) {
            c3 = -c3;
        }
        // assert!(bool::from(c3.sgn0()));
        let c4 = F::from(4) * mgz / (F::from(3) * z * z + F::from(4) * a);
        Ok(Self {
            A: a,
            B: b,
            C1: c1,
            C2: c2,
            C3: c3,
            C4: c4,
            Z: z,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    mod map_tests {
        use super::*;
        use crate::fields::fp::FinitePrimeField;
        use num_traits::{One, Zero};
        use sha2::Sha256;

        #[test]
        fn test_z_svdw() {
            let z = SvdW::<1, 1, Fp>::find_z_svdw(Fp::from(0), Fp::from(3));
            assert_eq!(z, Fp::one(), "Finding Z failed for BN254");
        }
        #[test]
        fn test_constants() {
            match SvdW::<1, 1, Fp>::precompute_constants(Fp::from(0), Fp::from(3)){
                Ok(BN254_SVDW) => {
                    println!("{:?}", BN254_SVDW.A.value());
                    println!("{:?}", BN254_SVDW.B.value());
                    println!("{:?}", BN254_SVDW.C1.value());
                    println!("{:?}", BN254_SVDW.C2.value());
                    println!("{:?}", BN254_SVDW.C3.value());
                    println!("{:?}", BN254_SVDW.C4.value());
                    println!("{:?}", BN254_SVDW.Z.value());
                },
                Err(e) => {println!("Failed constants: {:#?}", e)}
            }
           
        }
        #[test]
        fn test_svdw() {
            use crate::hasher::{hash_to_field, XMDExpander};
            let dst = b"WARLOCK-CHAOS-V01-CS01-SHA-256";
            let k = 128;
            let msg = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            let expander = XMDExpander::<Sha256>::new(dst, k);
            let scalars = hash_to_field(msg, &expander).expect("Conversion failed");

            let bn254_svdw = SvdW::<1, 1, Fp> {
                A: Fp::zero(),
                B: Fp::from(3u64),
                C1: Fp::from(0x4),
                C2: Fp::new(U256::from_le_hex(
                    "183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3",
                )),
                C3: Fp::new(U256::from_le_hex(
                    "00000000000000016789af3a83522eb353c98fc6b36d713d5d8d1cc5dffffffa",
                )),
                C4: Fp::new(U256::from_le_hex(
                    "10216f7ba065e00de81ac1e7808072c9dd2b2385cd7b438469602eb24829a9bd",
                )),
                Z: Fp::one(),
            };
            for scalar in scalars {
                let p = &bn254_svdw.map_to_point(scalar).expect("SvdW failed");
            }
        }
    }
}
