//! This module implements the ability to take a random point in the base field (scalar),
//! and hash it to an element on the given group. The instantiation of the group element ensures
//! that the targeted point is indeed on the curve, or the code will not instantiate the value at
//! all. The inner workings of this use the algorithm of Shallue and van de Woestijne, found at
//! page 510 of Ref 1 below. It is a deterministic polynomial-time algorithm that computes a
//! nontrivial rational point on an EC over the base field, given the Weiestrass equation for the
//! curve. In our case, we create the SvdW struct below to work for any field, and extension, and
//! therefore any target group and curve. The code is itself capable of determining all constants
//! needed by the algorithm. They may be instantiated with hardcoded values for performance once
//! the target group, curve, and therefore base field are known.
//!
//! References
//! ----------
//! 1. <https://link.springer.com/chapter/10.1007/11792086_36>

use crate::fields::fp::Fp;
use num_traits::{Inv, Zero};
use subtle::Choice;

#[derive(Debug)]
pub(crate) enum MapError {
    SvdWError,
}
#[derive(Debug)]
pub(crate) struct SvdW {
    a: Fp,
    b: Fp,
    c1: Fp,
    c2: Fp,
    c3: Fp,
    c4: Fp,
    z: Fp,
}

pub(crate) trait SvdWTrait: Sized {
    /// This is the actual struct containing the relevant information. There are a few input
    /// constants, namely the coefficients A and B that define the curve in its short Weierstrass
    /// representation. The constants c1-c4 and Z are determined by the algorithm.

    fn find_z_svdw(a: Fp, b: Fp) -> Fp {
        let g = |x: &Fp| -> Fp { (*x) * (*x) * (*x) + a * (*x) + b };
        let h = |x: &Fp| -> Fp { -(Fp::THREE * (*x) * (*x) + Fp::FOUR * a) / (Fp::FOUR * g(x)) };
        let mut ctr = 1;
        loop {
            for z_cand in [Fp::from(ctr), -Fp::from(ctr)] {
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
                    | bool::from(g(&(-z_cand / Fp::from(2))).is_square())
                {
                    return z_cand;
                }
            }
            ctr += 1;
        }
    }

    fn precompute_constants(a: Fp, b: Fp) -> Result<SvdW, MapError> {
        let g = |x: &Fp| -> Fp { (*x) * (*x) * (*x) + a * (*x) + b };
        let z = Self::find_z_svdw(a, b);
        let mgz = -g(&z);
        let c1 = g(&z);
        let c2 = -z / Fp::TWO;
        let mut c3 = match (-g(&z) * (Fp::THREE * z.square() + Fp::FOUR * a))
            .sqrt()
            .into_option()
        {
            Some(d) => d,
            _ => return Err(MapError::SvdWError),
        };
        if c3.sgn0().unwrap_u8() == 1u8 {
            c3 = -c3;
        }
        if c3.sgn0().unwrap_u8() != 0u8 {
            return Err(MapError::SvdWError);
        }
        let c4 = Fp::FOUR * mgz / (Fp::THREE * z * z + Fp::FOUR * a);

        Ok(SvdW {
            a,
            b,
            c1,
            c2,
            c3,
            c4,
            z,
        })
    }
    fn unchecked_map_to_point(&self, u: Fp) -> Result<[Fp; 2], MapError>;
}
impl SvdWTrait for SvdW {
    fn unchecked_map_to_point(&self, u: Fp) -> Result<[Fp; 2], MapError> {
        // Implements the SvdW algorithm for a single scalar point
        let cmov = |x: &Fp, y: &Fp, b: &Choice| -> Fp {
            Fp::from(!bool::from(*b) as u64) * (*x) + Fp::from(bool::from(*b) as u64) * (*y)
        };
        let tv1 = u * u;
        let tv1 = tv1 * self.c1;
        let tv2 = Fp::from(1) + tv1;
        let tv1 = Fp::from(1) - tv1;
        let tv3 = tv1 * tv2;
        let tv3 = tv3.inv();
        let tv4 = u * tv1;
        let tv4 = tv4 * tv3;
        let tv4 = tv4 * self.c3;
        let x1 = self.c2 - tv4;
        let gx1 = x1 * x1;
        let gx1 = gx1 + self.a;
        let gx1 = gx1 * x1;
        let gx1 = gx1 + self.b;
        let e1 = gx1.is_square();
        let x2 = self.c2 + tv4;
        let gx2 = x2 * x2;
        let gx2 = gx2 + self.a;
        let gx2 = gx2 * x2;
        let gx2 = gx2 + self.b;
        let e2 = gx2.is_square() & !e1; // Avoid short-circuit logic ops
        let x3 = tv2 * tv2;
        let x3 = x3 * tv3;
        let x3 = x3 * x3;
        let x3 = x3 * self.c4;
        let x3 = x3 + self.z;
        let x = cmov(&x3, &x1, &e1); // x = x1 if gx1 is square, else x = x3;
        let x = cmov(&x, &x2, &e2); // x = x2 if gx2 is square and gx1 is not;
        let gx = x * x;
        let gx = gx + self.a;
        let gx = gx * x;
        let gx = gx + self.b;
        let y = match gx.sqrt().into_option() {
            Some(d) => d,
            _ => return Err(MapError::SvdWError),
        };
        let e3 = Choice::from((bool::from(u.sgn0()) == bool::from(y.sgn0())) as u8);
        let y = cmov(&(-y), &y, &e3); // Select correct sign of y;
        Ok([x, y])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    mod map_tests {
        use super::*;
        use crate::fields::fp::{FieldExtensionTrait, Fp};
        use crate::hasher::Expander;
        use crypto_bigint::U256;
        use num_traits::One;
        use sha2::Sha256;

        #[test]
        fn test_z_svdw() {
            let z = SvdW::find_z_svdw(
                Fp::ZERO,
                <Fp as FieldExtensionTrait<1, 1>>::curve_constant(),
            );
            assert_eq!(z, Fp::ONE, "Finding Z failed for BN254");
        }
        #[test]
        fn test_constants() {
            let z = U256::one();
            let c1 = U256::from(0x4u64);
            let c2 = U256::from_be_hex(
                "183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3",
            );
            let c3 = U256::from_be_hex(
                "00000000000000016789af3a83522eb353c98fc6b36d713d5d8d1cc5dffffffa",
            );
            let c4 = U256::from_be_hex(
                "10216f7ba065e00de81ac1e7808072c9dd2b2385cd7b438469602eb24829a9bd",
            );
            let res = match SvdW::precompute_constants(Fp::from(0), Fp::from(3)) {
                Ok(bn254_svdw) => {
                    println!("{:?}", bn254_svdw.a.value());
                    println!("{:?}", bn254_svdw.b.value());

                    assert_eq!(bn254_svdw.c1.value(), c1, "SvdW c1 failed");
                    assert_eq!(bn254_svdw.c2.value(), c2, "SvdW c2 failed");
                    assert_eq!(bn254_svdw.c3.value(), c3, "SvdW c3 failed");
                    assert_eq!(bn254_svdw.c4.value(), c4, "SvdW c4 failed");
                    assert_eq!(bn254_svdw.z.value(), z, "SvdW z failed");
                    Ok(())
                }
                Err(e) => {
                    println!("Failed constants: {:#?}", e);
                    Err(e)
                }
            };
            res.expect("Failed to generate constants for curve");
        }
        #[test]
        fn test_svdw() {
            use crate::groups::group::GroupProjective;
            use crate::hasher::XMDExpander;
            let dst = b"WARLOCK-CHAOS-V01-CS01-SHA-256";
            let k = 128;
            let msg = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            let expander = XMDExpander::<Sha256>::new(dst, k);
            let scalars = expander
                .hash_to_field(msg, 2, 48)
                .expect("Conversion failed");

            let res = match SvdW::precompute_constants(Fp::from(0), Fp::from(3)) {
                Ok(bn254_svdw) => {
                    let _d = scalars
                        .iter()
                        .map(|&x| {
                            GroupProjective::<1, 1, Fp>::from(
                                bn254_svdw
                                    .unchecked_map_to_point(x)
                                    .expect("SVDW failed to map to point"),
                            )
                        })
                        .fold(GroupProjective::<1, 1, Fp>::zero(), |acc, x| acc + x);
                    let d =
                        GroupProjective::<1, 1, Fp>::new([_d.x, _d.y, _d.z]).expect("Map failed");
                    println!("{:?}, {:?}, {:?}", d.x.value(), d.y.value(), d.z.value());
                    Ok(())
                }
                Err(e) => {
                    println!("SvdW failed: {:#?}", e);
                    Err(e)
                }
            };
            res.expect("Failed to generate value on curve");
        }
    }
}
