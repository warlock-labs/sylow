//! we likewise define the specifics of the dodectic extension of
//! bn254 here, defined by the tower F_{p^{12}} = F_{p^6}(w) / (w^2 - v)
//! Now, there is some flexibility in how we define this. Why?
//! Well, we can either represent an element of F_{p^{12}} as 2 elements
//! of F_{p^6}, which the tower definition above gives us. OR, we can
//! represent it as 6 elements from F_{p^2}! The equivalent definition
//! would then be F_{p^{12}} = F_{p^2}(w) / (w^6 - (9+u)). This entirely
//! depends on the performance. While requiring two implementations,
//! one may be more efficient than the other. We would have to
//! build both and compare to be totally rigorous. For now,
//! we just do the (F_{p^6}, F_{p^6}) representation for simplicity.

use crate::fields::extensions::FieldExtension;
use crate::fields::fp::{FieldExtensionTrait, Fp};
use crate::fields::fp2::Fp2;
use crate::fields::fp6::Fp6;
use crypto_bigint::{rand_core::CryptoRngCore, subtle::ConditionallySelectable, U256};
use num_traits::{Inv, One, Zero};
use std::ops::{Div, DivAssign, Mul, MulAssign};
use subtle::Choice;
const FROBENIUS_COEFF_FP12_C1: &[Fp2; 12] = &[
    // Fp2::quadratic_non_residue().pow( ( p^0 - 1) / 6)
    Fp2::new(&[Fp::ONE, Fp::ZERO]),
    // Fp2::quadratic_non_residue().pow( ( p^1 - 1) / 6)
    Fp2::new(&[
        Fp::new(U256::from_words([
            0xd60b35dadcc9e470,
            0x5c521e08292f2176,
            0xe8b99fdd76e68b60,
            0x1284b71c2865a7df,
        ])),
        Fp::new(U256::from_words([
            0xca5cf05f80f362ac,
            0x747992778eeec7e5,
            0xa6327cfe12150b8e,
            0x246996f3b4fae7e6,
        ])),
    ]),
    // Fp2::quadratic_non_residue().pow( ( p^2 - 1) / 6)
    Fp2::new(&[
        Fp::new(U256::from_words([
            0xe4bd44e5607cfd49,
            0xc28f069fbb966e3d,
            0x5e6dd9e7e0acccb0,
            0x30644e72e131a029,
        ])),
        Fp::ZERO,
    ]),
    // Fp2::quadratic_non_residue().pow( ( p^3 - 1) / 6)
    Fp2::new(&[
        Fp::new(U256::from_words([
            0xe86f7d391ed4a67f,
            0x894cb38dbe55d24a,
            0xefe9608cd0acaa90,
            0x19dc81cfcc82e4bb,
        ])),
        Fp::new(U256::from_words([
            0x7694aa2bf4c0c101,
            0x7f03a5e397d439ec,
            0x6cbeee33576139d,
            0xabf8b60be77d73,
        ])),
    ]),
    // Fp2::quadratic_non_residue().pow( ( p^4 - 1) / 6)
    Fp2::new(&[
        Fp::new(U256::from_words([
            0xe4bd44e5607cfd48,
            0xc28f069fbb966e3d,
            0x5e6dd9e7e0acccb0,
            0x30644e72e131a029,
        ])),
        Fp::ZERO,
    ]),
    // Fp2::quadratic_non_residue().pow( ( p^5 - 1) / 6)
    Fp2::new(&[
        Fp::new(U256::from_words([
            0x1264475e420ac20f,
            0x2cfa95859526b0d4,
            0x72fc0af59c61f30,
            0x757cab3a41d3cdc,
        ])),
        Fp::new(U256::from_words([
            0xe85845e34c4a5b9c,
            0xa20b7dfd71573c93,
            0x18e9b79ba4e2606c,
            0xca6b035381e35b6,
        ])),
    ]),
    // Fp2::quadratic_non_residue().pow( ( p^6 - 1) / 6)
    Fp2::new(&[
        Fp::new(U256::from_words([
            0x3c208c16d87cfd46,
            0x97816a916871ca8d,
            0xb85045b68181585d,
            0x30644e72e131a029,
        ])),
        Fp::ZERO,
    ]),
    // Fp2::quadratic_non_residue().pow( ( p^7 - 1) / 6)
    Fp2::new(&[
        Fp::new(U256::from_words([
            0x6615563bfbb318d7,
            0x3b2f4c893f42a916,
            0xcf96a5d90a9accfd,
            0x1ddf9756b8cbf849,
        ])),
        Fp::new(U256::from_words([
            0x71c39bb757899a9b,
            0x2307d819d98302a7,
            0x121dc8b86f6c4ccf,
            0xbfab77f2c36b843,
        ])),
    ]),
    // Fp2::quadratic_non_residue().pow( ( p^8 - 1) / 6)
    Fp2::new(&[
        Fp::new(U256::from_words([
            0x5763473177fffffe,
            0xd4f263f1acdb5c4f,
            0x59e26bcea0d48bac,
            0x0,
        ])),
        Fp::ZERO,
    ]),
    // Fp2::quadratic_non_residue().pow( ( p^9 - 1) / 6)
    Fp2::new(&[
        Fp::new(U256::from_words([
            0x53b10eddb9a856c8,
            0xe34b703aa1bf842,
            0xc866e529b0d4adcd,
            0x1687cca314aebb6d,
        ])),
        Fp::new(U256::from_words([
            0xc58be1eae3bc3c46,
            0x187dc4add09d90a0,
            0xb18456d34c0b44c0,
            0x2fb855bcd54a22b6,
        ])),
    ]),
    // Fp2::quadratic_non_residue().pow( ( p^10 - 1) / 6)
    Fp2::new(&[
        Fp::new(U256::from_words([
            0x5763473177ffffff,
            0xd4f263f1acdb5c4f,
            0x59e26bcea0d48bac,
            0x0,
        ])),
        Fp::ZERO,
    ]),
    // Fp2::quadratic_non_residue().pow( ( p^11 - 1) / 6)
    Fp2::new(&[
        Fp::new(U256::from_words([
            0x29bc44b896723b38,
            0x6a86d50bd34b19b9,
            0xb120850727bb392d,
            0x290c83bf3d14634d,
        ])),
        Fp::new(U256::from_words([
            0x53c846338c32a1ab,
            0xf575ec93f71a8df9,
            0x9f668e1adc9ef7f0,
            0x23bd9e3da9136a73,
        ])),
    ]),
];
const FP12_QUADRATIC_NON_RESIDUE: Fp12 = Fp12::new(&[
    Fp6::new(&[
        Fp2::new(&[Fp::ZERO, Fp::ZERO]),
        Fp2::new(&[Fp::ZERO, Fp::ZERO]),
        Fp2::new(&[Fp::ZERO, Fp::ZERO]),
    ]),
    Fp6::new(&[
        Fp2::new(&[Fp::ONE, Fp::ZERO]),
        Fp2::new(&[Fp::ZERO, Fp::ZERO]),
        Fp2::new(&[Fp::ZERO, Fp::ZERO]),
    ]),
]);

pub type Fp12 = FieldExtension<12, 2, Fp6>;

impl FieldExtensionTrait<12, 2> for Fp12 {
    fn quadratic_non_residue() -> Self {
        // Self::new(&[Fp6::zero(), Fp6::one()])
        FP12_QUADRATIC_NON_RESIDUE
    }
    fn rand<R: CryptoRngCore>(rng: &mut R) -> Self {
        Self([
            <Fp6 as FieldExtensionTrait<6, 3>>::rand(rng),
            <Fp6 as FieldExtensionTrait<6, 3>>::rand(rng),
        ])
    }
    fn curve_constant() -> Self {
        unimplemented!()
    }
}

impl<'a, 'b> Mul<&'b Fp12> for &'a Fp12 {
    type Output = Fp12;
    fn mul(self, other: &'b Fp12) -> Self::Output {
        // this is again simple Karatsuba multiplication
        // see comments in Fp2 impl of `Mul` trait
        let t0 = self.0[0] * other.0[0];
        let t1 = self.0[1] * other.0[1];

        Self::Output::new(&[
            t1.residue_mul() + t0,
            (self.0[0] + self.0[1]) * (other.0[0] + other.0[1]) - t0 - t1,
        ])
    }
}
impl Mul for Fp12{
    type Output = Self;
    fn mul(self, other: Self) -> Self::Output {
        (&self).mul(&other)
    }
}
impl MulAssign for Fp12 {
    fn mul_assign(&mut self, other: Self) {
        *self = *self * other;
    }
}
impl Inv for Fp12 {
    type Output = Self;
    fn inv(self) -> Self::Output {
        let tmp = (self.0[0].square()
            - (self.0[1].square().residue_mul()))
        .inv();
        Self([self.0[0] * tmp, -(self.0[1] * tmp)])
    }
}

impl One for Fp12 {
    fn one() -> Self {
        Self::new(&[Fp6::one(), Fp6::zero()])
    }
    fn is_one(&self) -> bool {
        self.0[0].is_one() && self.0[1].is_zero()
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Div for Fp12 {
    type Output = Self;
    fn div(self, other: Self) -> Self::Output {
        self * other.inv()
    }
}
impl DivAssign for Fp12 {
    fn div_assign(&mut self, other: Self) {
        *self = *self / other;
    }
}

impl ConditionallySelectable for Fp12 {
    #[inline(always)]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self::new(&[
            Fp6::conditional_select(&a.0[0], &b.0[0], choice),
            Fp6::conditional_select(&a.0[1], &b.0[1], choice),
        ])
    }
}
/// Below are additional functions needed on Fp12 for the pairing operations
impl Fp12 {
    pub fn unitary_inverse(&self) -> Self {
        Self::new(&[self.0[0], -self.0[1]])
    }
    pub fn pow(&self, arg: &[u64; 4]) -> Self {
        let mut res = Self::one();
        for e in arg.iter().rev() {
            for i in (0..64).rev() {
                res = res.square();
                if ((*e >> i) & 1) == 1 {
                    res *= *self;
                }
            }
        }
        res
    }
    /// Due to the efficiency considerations of storing only the nonzero entries in the sparse
    /// Fp12, there is a need to implement sparse multiplication on Fp12, which is what the
    /// madness below is. It is an amalgamation of Algs 21-25 of <https://eprint.iacr.org/2010/354.pdf>
    /// and is really just un-sparsing the value, and doing the multiplication manually. In order
    /// to get around all the zeros that would arise if we just instantiated the full Fp12,
    /// we have to manually implement all the required multiplication as far down the tower as
    /// we can go.
    ///
    /// The following code relies on a separate representation of an element in Fp12.
    /// Namely, hereunto we have defined Fp12 as a pair of Fp6 elements. However, it is just as
    /// valid to define Fp12 as a pair of Fp2 elements. For f\in Fp12, f = g+hw, where g, h \in Fp6,
    /// with g = g_0 + g_1v + g_2v^2, and h = h_0 + h_1v + h_2v^2, we can then write:
    ///
    /// f = g_0 + h_0w + g_1w^2 + h_1w^3 + g_2w^4 + h_2w^5
    ///
    /// where the representation of Fp12 is not Fp12 = Fp2(w)/(w^6-(9+u))
    ///
    /// This is a massive headache to get correct, and relied on existing implementations tbh.
    /// Unfortunately for me, the performance boost is noticeable by early estimates (100s us).
    /// Therefore, worth it.
    ///
    /// The function below is called by `zcash`, `bn`, and `arkworks` as `mul_by_024`, referring to
    /// the indices of the non-zero elements in the 6x Fp2 representation above for the
    /// multiplication.
    pub fn sparse_mul(&self, ell_0: Fp2, ell_vw: Fp2, ell_vv: Fp2) -> Fp12 {
        let z0 = self.0[0].0[0];
        let z1 = self.0[0].0[1];
        let z2 = self.0[0].0[2];
        let z3 = self.0[1].0[0];
        let z4 = self.0[1].0[1];
        let z5 = self.0[1].0[2];

        let x0 = ell_0;
        let x2 = ell_vv;
        let x4 = ell_vw;

        let d0 = z0 * x0;
        let d2 = z2 * x2;
        let d4 = z4 * x4;
        let t2 = z0 + z4;
        let t1 = z0 + z2;
        let s0 = z1 + z3 + z5;

        let s1 = z1 * x2;
        let t3 = s1 + d4;
        let t4 = t3.residue_mul() + d0;
        let z0 = t4;

        let t3 = z5 * x4;
        let s1 = s1 + t3;
        let t3 = t3 + d2;
        let t4 = t3.residue_mul();
        let t3 = z1 * x0;
        let s1 = s1 + t3;
        let t4 = t4 + t3;
        let z1 = t4;

        let t0 = x0 + x2;
        let t3 = t1 * t0 - d0 - d2;
        let t4 = z3 * x4;
        let s1 = s1 + t4;
        let t3 = t3 + t4;

        let t0 = z2 + z4;
        let z2 = t3;

        let t1 = x2 + x4;
        let t3 = t0 * t1 - d2 - d4;
        let t4 = t3.residue_mul();
        let t3 = z3 * x0;
        let s1 = s1 + t3;
        let t4 = t4 + t3;
        let z3 = t4;

        let t3 = z5 * x2;
        let s1 = s1 + t3;
        let t4 = t3.residue_mul();
        let t0 = x0 + x4;
        let t3 = t2 * t0 - d0 - d4;
        let t4 = t4 + t3;
        let z4 = t4;

        let t0 = x0 + x2 + x4;
        let t3 = s0 * t0 - s1;
        let z5 = t3;

        Fp12::new(&[Fp6::new(&[z0, z1, z2]), Fp6::new(&[z3, z4, z5])])
    }
    pub fn frobenius(&self, exponent: usize) -> Self {
        Self::new(&[
            self.0[0].frobenius(exponent),
            self.0[1].frobenius(exponent)
                .scale(FROBENIUS_COEFF_FP12_C1[exponent % 12]),
        ])
    }
    pub fn square(&self) -> Self {
        // For F_{p^{12}} = F_{p^6}(w)/(w^2-\gamma), and A=a_0 + a_1*w \in F_{p^{12}}, 
        // we determine C=c_0+c_1*w = A^2\in F_{p^{12}}
        // Alg 22 from <https://eprint.iacr.org/2010/354.pdf>
        let c0 = self.0[0] - self.0[1];
        let c3 = self.0[0] - self.0[1].residue_mul();
        let c2 = self.0[0] * self.0[1];
        let c0 = c0 * c3 + c2;
        let c1 = c2 + c2;
        let c2 = c2.residue_mul();
        let c0 = c0 + c2;
        Self::new(&[c0, c1])
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crypto_bigint::{rand_core::OsRng, U256};

    fn create_field(value: [u64; 4]) -> Fp {
        Fp::new(U256::from_words(value))
    }
    fn create_field_extension(v: [[u64; 4]; 12]) -> Fp12 {
        Fp12::new(&[
            Fp6::new(&[
                Fp2::new(&[create_field(v[0]), create_field(v[1])]),
                Fp2::new(&[create_field(v[2]), create_field(v[3])]),
                Fp2::new(&[create_field(v[4]), create_field(v[5])]),
            ]),
            Fp6::new(&[
                Fp2::new(&[create_field(v[6]), create_field(v[7])]),
                Fp2::new(&[create_field(v[8]), create_field(v[9])]),
                Fp2::new(&[create_field(v[10]), create_field(v[11])]),
            ]),
        ])
    }
    mod addition_tests {
        use super::*;
        #[test]
        fn test_addition_closure() {
            let a = Fp12::rand(&mut OsRng);
            let b = Fp12::rand(&mut OsRng);
            let _ = a + b;
        }
    }
    mod subtraction_tests {
        use super::*;
        #[test]
        fn test_subtraction_closure() {
            let a = Fp12::rand(&mut OsRng);
            let b = Fp12::rand(&mut OsRng);
            let _ = a - b;
        }
    }
    mod multiplication_tests {
        use super::*;

        #[test]
        fn test_multiplication_closure() {
            let a = Fp12::rand(&mut OsRng);
            let b = Fp12::rand(&mut OsRng);
            let _ = a * b;
        }

        #[test]
        fn test_multiplication_associativity_commutativity_distributivity() {
            let a = Fp12::rand(&mut OsRng);
            let b = Fp12::rand(&mut OsRng);
            let c = Fp12::rand(&mut OsRng);

            assert_eq!(a * b, b * a, "Multiplication is not commutative");

            assert_eq!(
                (a * b) * c,
                a * (b * c),
                "Multiplication is not associative"
            );

            assert_eq!(
                a * (b + c),
                a * b + a * c,
                "Multiplication is not distributive"
            );
        }

        #[test]
        fn test_multiplication_cases() {
            let a = create_field_extension([
                [1, 0, 0, 0],
                [0, 2, 0, 0],
                [0, 0, 3, 0],
                [0, 0, 0, 4],
                [5, 0, 0, 0],
                [0, 6, 0, 0],
                [1, 0, 0, 0],
                [0, 2, 0, 0],
                [0, 0, 3, 0],
                [0, 0, 0, 4],
                [5, 0, 0, 0],
                [0, 6, 0, 0],
            ]);
            let b = create_field_extension([
                [0, 6, 0, 0],
                [5, 0, 0, 0],
                [0, 0, 0, 4],
                [0, 0, 3, 0],
                [0, 2, 0, 0],
                [1, 0, 0, 0],
                [0, 6, 0, 0],
                [5, 0, 0, 0],
                [0, 0, 0, 4],
                [0, 0, 3, 0],
                [0, 2, 0, 0],
                [1, 0, 0, 0],
            ]);
            assert_eq!(a.square(), a * a, "Squaring and mul failed");
            assert_eq!(b.square(), b * b, "Squaring and mul failed");
        }
        #[test]
        fn test_frobenius() {
            let a = create_field_extension([
                [1, 0, 0, 0],
                [0, 2, 0, 0],
                [0, 0, 3, 0],
                [0, 0, 0, 4],
                [5, 0, 0, 0],
                [0, 6, 0, 0],
                [1, 0, 0, 0],
                [0, 2, 0, 0],
                [0, 0, 3, 0],
                [0, 0, 0, 4],
                [5, 0, 0, 0],
                [0, 6, 0, 0],
            ]);
            assert_eq!(
                a,
                a.frobenius(1)
                    .frobenius(1)
                    .frobenius(1)
                    .frobenius(1)
                    .frobenius(1)
                    .frobenius(1)
                    .frobenius(1)
                    .frobenius(1)
                    .frobenius(1)
                    .frobenius(1)
                    .frobenius(1)
                    .frobenius(1),
                "Frobenius failed at cycle order 12"
            );
            assert_eq!(
                a,
                a.frobenius(2)
                    .frobenius(2)
                    .frobenius(2)
                    .frobenius(2)
                    .frobenius(2)
                    .frobenius(2),
                "Frobenius failed at cycle order 6"
            );
            assert_eq!(
                a,
                a.frobenius(4).frobenius(4).frobenius(4),
                "Frobenius failed at cycle order 3"
            );
            assert_eq!(
                a,
                a.frobenius(6).frobenius(6),
                "Frobenius failed at cycle order 2"
            );
        }
    }
    mod division_tests {
        use super::*;

        #[test]
        fn test_division_closure() {
            let a = Fp12::rand(&mut OsRng);
            let b = Fp12::rand(&mut OsRng);
            let _ = a / b;
        }

        #[test]
        fn test_division_cases() {
            let a = Fp12::rand(&mut OsRng);
            let b = Fp12::rand(&mut OsRng);
            let one = Fp12::one();

            assert_eq!(a / a, one, "Division by self failed");

            assert_eq!(a / one, a, "Division by one failed");
            assert_eq!((a / b) * b, a, "Division-Mult composition failed");
        }
        #[test]
        // #[should_panic(expected = "assertion failed: self.is_some.is_true_vartime()")]
        fn test_divide_by_zero() {
            let a = Fp12::rand(&mut OsRng);
            let b = Fp12::zero();
            let _ = a / b;
        }
    }
}
