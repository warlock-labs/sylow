//! # Shallue-van de Woestijne (SvdW) Algorithm Implementation
//!
//! This module implements the Shallue-van de Woestijne (SvdW) algorithm, which maps
//! field elements to points on an elliptic curve. This is a crucial component for
//! hashing arbitrary data to curve points, which is essential in many cryptographic
//! protocols, particularly those involving elliptic curve cryptography.
//!
//! The SvdW algorithm provides a deterministic, polynomial-time method to compute
//! a non-trivial rational point on an elliptic curve over a finite field, given
//! the Weierstrass equation of the curve. This implementation is designed to work
//! with any field and its extensions, making it suitable for various elliptic curves
//! and their associated groups.
//!
//! ## Algorithm Overview
//!
//! The SvdW algorithm works by:
//! 1. Precomputing certain constants based on the curve parameters.
//! 2. Using these constants to map a field element to a point on the curve.
//!
//! The algorithm ensures that the resulting point is indeed on the curve, though
//! additional checks may be needed to ensure it's in the correct subgroup for
//! cryptographic applications.
//!
//! ## Usage
//!
//! This module is typically used internally by other parts of the library that need
//! to perform hash-to-curve operations. It's not intended for direct use by end users
//! of the Sylow.
//!
//! ## Performance Considerations
//!
//! Values can be hard-coded for specific curves to improve performance.
//!
//! ## References
//!
//! 1. Shallue, A., & van de Woestijne, C. (2006). Construction of rational points on
//!    elliptic curves over finite fields. In Algorithmic Number Theory Symposium (pp. 510-524).
//!    Springer, Berlin, Heidelberg.
//!    <https://link.springer.com/chapter/10.1007/11792086_36>

use crate::fields::fp::Fp;
use num_traits::{Inv, Zero};
use subtle::Choice;

/// Errors which may occur during the SvdW mapping process.
#[derive(Debug)]
pub(crate) enum MapError {
    /// General error in the SvdW algorithm.
    SvdWError,
}

/// Struct containing precomputed constants for the SvdW algorithm.
#[derive(Debug)]
pub(crate) struct SvdW {
    /// Coefficient A of the elliptic curve equation y^2 = x^3 + Ax + B.
    a: Fp,
    /// Coefficient B of the elliptic curve equation y^2 = x^3 + Ax + B.
    b: Fp,
    /// Precomputed constant c1 for the SvdW algorithm.
    c1: Fp,
    /// Precomputed constant c2 for the SvdW algorithm.
    c2: Fp,
    /// Precomputed constant c3 for the SvdW algorithm.
    c3: Fp,
    /// Precomputed constant c4 for the SvdW algorithm.
    c4: Fp,
    /// The 'z' value found for the SvdW algorithm.
    z: Fp,
}

pub(crate) trait SvdWTrait: Sized {
    /// This is the actual struct containing the relevant information. There are a few input
    /// constants, namely the coefficients A and B that define the curve in its short Weierstrass
    /// representation. The constants c1-c4 and Z are determined by the algorithm.
    /// # Arguments
    /// * `a` - the A coefficient of the curve
    /// * `b` - the B coefficient of the curve
    /// # Returns
    /// * `Result<SvdW, MapError>` - the struct containing the constants for the SvdW algorithm,
    ///                                 or an error otherwise
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

    /// Precomputes the constants needed for the SvdW algorithm.
    ///
    /// This method calculates various constants used in the SvdW mapping based
    /// on the curve parameters and the found 'z' value.
    ///
    /// # Arguments
    ///
    /// * `a` - The A coefficient of the curve equation.
    /// * `b` - The B coefficient of the curve equation.
    ///
    /// # Returns
    ///
    /// * `Result<SvdW, MapError>` - The precomputed SvdW constants or an error
    ///
    /// # Notes
    ///
    /// See reference 1 for more details on the SvdW algorithm.
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

    /// Maps a field element to a point on the curve using the SvdW algorithm.
    ///
    /// This method performs the actual SvdW mapping. Note that it does not check
    /// if the resulting point satisfies the curve equation or is in the correct
    /// subgroup. These checks should be performed by the calling function.
    ///
    /// # Arguments
    ///
    /// * `u` - The field element to be mapped to a curve point.
    ///
    /// # Returns
    ///
    /// * `Result<[Fp; 2], MapError>` - The (x, y) coordinates of the curve point or an error.
    ///
    /// # Notes
    ///
    /// Having determined the constants for the SvdW algorithm, we actually perform the mapping
    /// to an element of the group. The issue here is that we do not explicitly check the result
    /// of this operation to verify that it satisfies the curve equation, since that
    /// functionality is nearly contained in `groups.rs` etc. Therefore, this private method is
    /// called by `g1.rs` etc., which then calls its `new` method to perform the subgroup and
    /// curve checks, meaning that it is ok for those checks to not occur here.
    fn unchecked_map_to_point(&self, u: Fp) -> Result<[Fp; 2], MapError>;
}
impl SvdWTrait for SvdW {
    fn unchecked_map_to_point(&self, u: Fp) -> Result<[Fp; 2], MapError> {
        // Implements the SvdW algorithm for a single scalar point

        // Conditional move operation.
        // Selects `x` if `b` is false, `y` if `b` is true.
        let cmov = |x: &Fp, y: &Fp, b: &Choice| -> Fp {
            Fp::from(!bool::from(*b) as u64) * (*x) + Fp::from(bool::from(*b) as u64) * (*y)
        };

        // Step 1: Compute intermediate values
        let tv1 = u * u;
        let tv1 = tv1 * self.c1;
        let tv2 = Fp::from(1) + tv1;
        let tv1 = Fp::from(1) - tv1;
        let tv3 = tv1 * tv2;
        let tv3 = tv3.inv();
        let tv4 = u * tv1;
        let tv4 = tv4 * tv3;
        let tv4 = tv4 * self.c3;

        // Step 2: Compute potential x-coordinates
        let x1 = self.c2 - tv4;

        // Step 3: Evaluate curve equation at potential x-coordinates
        let gx1 = x1 * x1;
        let gx1 = gx1 + self.a;
        let gx1 = gx1 * x1;
        let gx1 = gx1 + self.b;

        // Step 4: Determine which x-coordinate to use
        // and so forth for x 1..3
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

        // Step 5: Compute y-coordinate
        let y = match gx.sqrt().into_option() {
            Some(d) => d,
            _ => return Err(MapError::SvdWError),
        };

        // Step 6: Ensure correct sign of y
        let e3 = Choice::from((bool::from(u.sgn0()) == bool::from(y.sgn0())) as u8);
        let y = cmov(&(-y), &y, &e3); // Select correct sign of y;

        tracing::trace!(
            ?tv1,
            ?tv2,
            ?tv3,
            ?tv4,
            ?x1,
            ?gx1,
            ?e1,
            ?x2,
            ?gx2,
            ?e2,
            ?x3,
            ?x,
            ?gx,
            ?y,
            ?e3,
            "SvdW::unchecked_map_to_point"
        );
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
