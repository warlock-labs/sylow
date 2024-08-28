//! This describes the quadratic field extension of the base field of BN254
//! defined by the tower $F_{p^2} = F_p(X) / (X^2-\beta)$. Further, the quadratic nature implies
//! that elements of this field are represented as $a_0 + a_1*X$. This implements
//! the specific behaviour for this extension, such as multiplication.

use crate::fields::extensions::FieldExtension;
use crate::fields::fp::{FieldExtensionTrait, Fp, BN254_FP_MODULUS, FP_QUADRATIC_NON_RESIDUE};
use crypto_bigint::{rand_core::CryptoRngCore, subtle::ConditionallySelectable, U256};
use num_traits::{Inv, One, Pow, Zero};
use std::ops::{Div, DivAssign, Mul, MulAssign};
use subtle::{Choice, ConstantTimeEq, CtOption};

pub(crate) const TWO_INV: Fp = Fp::new(U256::from_words([
    11389680472494603940,
    14681934109093717318,
    15863968012492123182,
    1743499133401485332,
]));

// (BN254_FP_MODULUS - Fp::THREE)/Fp::FOUR
const P_MINUS_3_OVER_4: Fp = Fp::new(U256::from_words([
    5694840236247301969,
    7340967054546858659,
    7931984006246061591,
    871749566700742666,
]));
// (BN254_FP_MODULUS - Fp::ONE)/Fp::TWO
const P_MINUS_1_OVER_2: Fp = Fp::new(U256::from_words([
    11389680472494603939,
    14681934109093717318,
    15863968012492123182,
    1743499133401485332,
]));
const FP2_TWIST_CURVE_CONSTANT: Fp2 = Fp2::new(&[
    Fp::new(U256::from_words([
        3632125457679333605,
        13093307605518643107,
        9348936922344483523,
        3104278944836790958,
    ])),
    Fp::new(U256::from_words([
        16474938222586303954,
        12056031220135172178,
        14784384838321896948,
        42524369107353300,
    ])),
]);
/// type alias for the quadratic extension of the base field
pub type Fp2 = FieldExtension<2, 2, Fp>;

// there are some specific things that must be defined as
// helper functions for us on this specific extension, but
// don't generalize to any extension.
impl Fp2 {
    /// A simple square and multiply algorithm for exponentiation
    /// # Arguments
    /// * `by` - Fp, the exponent to raise the element to
    ///
    /// Note that the argument is required to be an element of the base field, and the expansion
    /// of this element via `to_words()` always returns &[u64; 4], which lets this run constant time
    /// for any field element.
    pub fn pow(&self, by: &Fp) -> Self {
        let bits = by.value().to_words();
        let mut res = Self::one();
        for e in bits.iter().rev() {
            for i in (0..64).rev() {
                res = res * res;
                if ((*e >> i) & 1) == 1 {
                    res *= *self;
                }
            }
        }
        res
    }
    #[inline(always)]
    pub(crate) fn residue_mul(&self) -> Self {
        // Instead of simply `self * &FP2_QUADRATIC_NON_RESIDUE`, we do
        // the multiplication "manually", namely:
        // (a+bu)*(9+u) = (9a-b)+(a+9b)u, which is cheaper arithmetic in Fp that multiplication
        Self::new(&[
            Fp::NINE * self.0[0] - self.0[1],
            self.0[0] + Fp::NINE * self.0[1],
        ])
    }
    /// Frobenius mapping of a quadratic extension element to a given power
    /// # Arguments
    /// * `exponent` - usize, the power to raise the element to
    #[inline(always)]
    pub fn frobenius(&self, exponent: usize) -> Self {
        let frobenius_coeff_fp2: &[Fp; 2] = &[
            // Fp::quadratic_non_residue()**(((p^0) - 1) / 2)
            Fp::ONE,
            // Fp::quadratic_non_residue()**(((p^1) - 1) / 2)
            FP_QUADRATIC_NON_RESIDUE,
        ];
        match exponent % 2 {
            0 => *self,
            _ => Self::new(&[
                self.0[0] * frobenius_coeff_fp2[0],
                self.0[1] * frobenius_coeff_fp2[1],
            ]),
        }
    }
    pub fn sqrt(&self) -> CtOption<Self> {
        let a1 = self.pow(&P_MINUS_3_OVER_4);

        let alpha = a1 * a1 * (*self);
        let a0 = alpha.pow(&BN254_FP_MODULUS);
        if a0 == -Fp2::one() {
            return CtOption::new(Fp2::zero(), Choice::from(0u8));
        }
        tracing::debug!(?alpha, ?a0, "Fp2::sqrt");

        if alpha == -Fp2::one() {
            let i = Fp2::new(&[Fp::ZERO, Fp::ONE]);
            let sqrt = i * a1 * (*self);
            CtOption::new(sqrt, sqrt.square().ct_eq(self))
        } else {
            let b = (alpha + Fp2::one()).pow(&P_MINUS_1_OVER_2);
            let sqrt = b * a1 * (*self);
            CtOption::new(sqrt, sqrt.square().ct_eq(self))
        }
    }
    pub fn square(&self) -> Self {
        // We implement manual squaring here and avoid multiplications at all costs
        let a = self.0[0] + self.0[1];
        let b = self.0[0] - self.0[1];
        let c = self.0[0] + self.0[0];
        tracing::debug!(?a, "Fp2::square");
        Self([a * b, c * self.0[1]])
    }
    pub fn is_square(&self) -> Choice {
        let legendre = |x: &Fp| -> i32 {
            let res = x.pow(P_MINUS_1_OVER_2.value());

            if res.is_one() {
                1
            } else if res.is_zero() {
                0
            } else {
                -1
            }
        };
        let sum = self.0[0].square() + FP_QUADRATIC_NON_RESIDUE * (-self.0[0]).square();
        tracing::debug!(?sum, "Fp2::is_square");
        Choice::from((legendre(&sum) != -1) as u8)
    }
    /// allows for the conversion of a byte array to a Fp2 element
    /// # Arguments
    /// * `bytes` - &[u8], the byte array to convert
    /// # Returns
    /// * CtOption<Self>, the Fp2 element if the byte array is valid
    pub fn from_be_bytes(arr: &[u8; 64]) -> CtOption<Self> {
        let b = Fp::from_be_bytes(
            &<[u8; 32]>::try_from(&arr[0..32]).expect("Conversion of u8 array failed"),
        );
        let a = Fp::from_be_bytes(
            &<[u8; 32]>::try_from(&arr[32..64]).expect("Conversion of u8 array failed"),
        );
        // the issue is that we must explicitly catch the `is_some` value, and cannot just rely
        // on `unwrap` alone because this will panic if the value is not valid
        if bool::from(a.is_some() & b.is_some()) {
            CtOption::new(Self::new(&[a.unwrap(), b.unwrap()]), Choice::from(1u8))
        } else {
            CtOption::new(Self::zero(), Choice::from(0u8))
        }
    }
    /// this is a helper function to convert the Fp2 element to a byte array
    /// # Returns
    /// * [u8; 64], the byte array representation of the Fp2 element
    pub fn to_be_bytes(self) -> [u8; 64] {
        let mut res = [0u8; 64];
        let a = self.0[0].to_be_bytes();
        let b = self.0[1].to_be_bytes();

        res[0..32].copy_from_slice(&b);
        res[32..64].copy_from_slice(&a);

        res
    }
}
impl FieldExtensionTrait<2, 2> for Fp2 {
    fn rand<R: CryptoRngCore>(rng: &mut R) -> Self {
        Self([
            <Fp as FieldExtensionTrait<1, 1>>::rand(rng),
            <Fp as FieldExtensionTrait<1, 1>>::rand(rng),
        ])
    }
    fn curve_constant() -> Self {
        // this is the curve constant for the twist curve in Fp2. In short Weierstrass form the
        // curve over the twist is $y'^2 = x'^3 + b$, where $b=3/(9+u)$, which is the below.
        FP2_TWIST_CURVE_CONSTANT
    }
}
impl<'a, 'b> Mul<&'b Fp2> for &'a Fp2 {
    type Output = Fp2;
    #[inline]
    fn mul(self, other: &'b Fp2) -> Self::Output {
        // This requires a bit more consideration. In Fp2,
        // in order to multiply, we could implement complex Karatsuba
        // multiplication, see <https://eprint.iacr.org/2006/471.pdf>, Sec 3
        // and then use the addition chain from Alg 1 of <https://eprint.iacr.org/2022/367.pdf>:
        // // let t0 = self.0[0] * other.0[0];
        // // let t1 = self.0[1] * other.0[1];
        // //
        // // Self::Output::new(&[
        // //     t1 * FP_QUADRATIC_NON_RESIDUE + t0,
        // //     (self.0[0] + self.0[1]) * (other.0[0] + other.0[1]) - t0 - t1,
        // // ])
        // BUT this is not constant-time, and turns out slower than not invoking the quadratic residue and
        // simply doing the schoolbook version, known as the sum of products approach. There is
        // an optimized version of this implementation given in Alg 2 of the above reference,
        // which requires more granular control of the limb arithmetic over the multiprecision
        // scalars than is convenient to implement here.
        Self::Output::new(&[
            self.0[0] * other.0[0] - self.0[1] * other.0[1],
            self.0[0] * other.0[1] + self.0[1] * other.0[0],
        ])
    }
}
impl Mul<Fp2> for Fp2 {
    type Output = Self;
    #[inline]
    fn mul(self, other: Fp2) -> Self::Output {
        // TODO linter complains about this being a needless reference if I do &a * &b, so this
        // gets around it
        (&self).mul(&other)
    }
}
impl MulAssign for Fp2 {
    #[inline]
    fn mul_assign(&mut self, other: Self) {
        *self = *self * other;
    }
}

impl Inv for Fp2 {
    type Output = Self;
    #[inline]
    fn inv(self) -> Self {
        let c0_squared = self.0[0].square();
        let c1_squared = self.0[1].square();
        let tmp = (c0_squared - (c1_squared * FP_QUADRATIC_NON_RESIDUE)).inv();
        Self::new(&[self.0[0] * tmp, -(self.0[1] * tmp)])
    }
}

// because mult cannot be implemented generally for all degrees
// this must be defined only for the specific case here, aka not
// in extensions.rs
impl One for Fp2 {
    #[inline]
    fn one() -> Self {
        Self::new(&[Fp::ONE, Fp::ZERO])
    }
    fn is_one(&self) -> bool {
        self.0[0].is_one() && self.0[1].is_zero()
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Div for Fp2 {
    type Output = Self;
    #[inline]
    fn div(self, other: Self) -> Self {
        self * other.inv()
    }
}
impl DivAssign for Fp2 {
    #[inline]
    fn div_assign(&mut self, other: Self) {
        *self = *self / other;
    }
}

impl ConditionallySelectable for Fp2 {
    #[inline(always)]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self::new(&[
            Fp::conditional_select(&a.0[0], &b.0[0], choice),
            Fp::conditional_select(&a.0[1], &b.0[1], choice),
        ])
    }
}

// the below is again to make the quadratic extension visible to
// higher order sextic extension
impl FieldExtensionTrait<6, 3> for Fp2 {
    fn rand<R: CryptoRngCore>(rng: &mut R) -> Self {
        <Fp2 as FieldExtensionTrait<2, 2>>::rand(rng)
    }
    fn curve_constant() -> Self {
        <Fp2 as FieldExtensionTrait<2, 2>>::curve_constant()
    }
}
// Tests of associativity, commutativity, etc., follow directly from
// these properties in the base field, as the extension simply performs
// these operations elementwise. The only tests are really to be done
// with multiplication and division
#[cfg(test)]
mod tests {
    use super::*;
    use crypto_bigint::U256;
    const FP2_QUADRATIC_NON_RESIDUE: Fp2 = Fp2::new(&[Fp::NINE, Fp::ONE]);

    fn create_field(value: [u64; 4]) -> Fp {
        Fp::new(U256::from_words(value))
    }
    fn create_field_extension(v1: [u64; 4], v2: [u64; 4]) -> Fp2 {
        Fp2::new(&[create_field(v1), create_field(v2)])
    }
    mod byte_tests {
        use super::*;
        #[test]
        fn test_conversion() {
            let a = create_field_extension([1, 2, 3, 4], [1,2,3,4]);
            let bytes = a.to_be_bytes();
            let b = Fp2::from_be_bytes(&bytes).unwrap();
            assert_eq!(a, b, "From bytes failed")
        }
        #[test]
        fn test_over_modulus() {
            let a = (BN254_FP_MODULUS - Fp::ONE).value() + U256::from(10u64);
            let mut bytes = [0u8; 64];
            bytes[0..32].copy_from_slice(a.to_be_bytes().as_ref());
            bytes[32..64].copy_from_slice(a.to_be_bytes().as_ref());
            let b = Fp2::from_be_bytes(&bytes);
            assert!(bool::from(b.is_none()), "Over modulus failed")
        }
        #[test]
        #[should_panic(expected = "assertion `left == right` failed")]
        fn test_over_modulus_panic() {
            let a = (BN254_FP_MODULUS - Fp::ONE).value() + U256::from(10u64);
            let mut bytes = [0u8; 64];
            bytes[0..32].copy_from_slice(a.to_be_bytes().as_ref());
            bytes[32..64].copy_from_slice(a.to_be_bytes().as_ref());
            let _b = Fp2::from_be_bytes(&bytes).unwrap();
        }
    }
    mod addition_tests {
        use super::*;
        #[test]
        fn test_addition_closure() {
            let a = create_field_extension([1, 2, 3, 4], [0, 0, 0, 0]);
            let b = create_field_extension([0, 0, 0, 0], [1, 2, 3, 4]);
            let _ = a + b;
        }
    }
    mod subtraction_tests {
        use super::*;
        #[test]
        fn test_subtraction_closure() {
            let a = create_field_extension([1, 2, 3, 4], [0, 0, 0, 0]);
            let b = create_field_extension([0, 0, 0, 0], [1, 2, 3, 4]);
            let _ = a - b;
        }
    }
    mod multiplication_tests {
        use super::*;
        #[test]
        fn test_multiplication_closure() {
            let a = create_field_extension([1, 2, 3, 4], [1, 2, 3, 4]);
            let b = create_field_extension([5, 6, 7, 8], [5, 6, 7, 8]);
            let _ = a * b;
        }
        #[test]
        fn test_multiplication_associativity() {
            let a = create_field_extension([1, 2, 3, 4], [1, 2, 3, 4]);
            let b = create_field_extension([5, 6, 7, 8], [5, 6, 7, 8]);
            let c = create_field_extension([9, 10, 11, 12], [9, 10, 11, 12]);
            assert_eq!(
                (a * b) * c,
                a * (b * c),
                "Multiplication is not associative"
            );
        }
        #[test]
        fn test_multiplication_commutativity() {
            let a = create_field_extension([1, 2, 3, 4], [1, 2, 3, 4]);
            let b = create_field_extension([5, 6, 7, 8], [5, 6, 7, 8]);

            assert_eq!(a * b, b * a, "Multiplication is not commutative");
        }

        #[test]
        fn test_multiplication_distributivity() {
            let a = create_field_extension([1, 2, 3, 4], [1, 2, 3, 4]);
            let b = create_field_extension([5, 6, 7, 8], [5, 6, 7, 8]);
            let c = create_field_extension([9, 10, 11, 12], [9, 10, 11, 12]);
            assert_eq!(
                a * (b + c),
                a * b + a * c,
                "Multiplication is not distributive"
            );
        }

        #[test]
        fn test_multiplication_cases() {
            // simple stuff
            let a = create_field_extension([4, 3, 2, 1], [1, 1, 1, 1]);
            let b = create_field_extension([1, 1, 1, 1], [1, 2, 3, 4]);
            let c = create_field_extension(
                [
                    0x2221d7e243f5a6b7,
                    0xf2dbb3e54415ac43,
                    0xc1c16c86d80ba3fe,
                    0x1ed70a64be2c4cf4,
                ],
                [
                    0xcf869553cd163248,
                    0xe9e0e365974ff82b,
                    0xaa61fb7b7ed75708,
                    0x952882769104fa9,
                ],
            );
            assert_eq!(a * b, c, "Simple multiplication failed");

            // multiplication with carry
            let d = create_field_extension(
                [0xFFFFFFFFFFFFFFFF, 0, 0, 0],
                [0xFFFFFFFFFFFFFFFF, 0, 0, 0],
            );
            let e = create_field_extension([0xFFFFFFFFFFFFFFFF, 0, 0, 0], [2, 0, 0, 0]);
            let f = create_field_extension(
                [0x3, 0xfffffffffffffffc, 0x0, 0x0],
                [0xffffffffffffffff, 0xffffffffffffffff, 0x0, 0x0],
            );
            assert_eq!(
                d * e,
                f,
                "Multiplication with carry and around modulus failed"
            );
        }
        #[test]
        fn test_sqrt() {
            let a = create_field_extension([4, 3, 2, 1], [1, 1, 1, 1]);
            let b = create_field_extension([1, 1, 1, 1], [1, 2, 3, 4]);
            let c = create_field_extension(
                [
                    0x2221d7e243f5a6b7,
                    0xf2dbb3e54415ac43,
                    0xc1c16c86d80ba3fe,
                    0x1ed70a64be2c4cf4,
                ],
                [
                    0xcf869553cd163248,
                    0xe9e0e365974ff82b,
                    0xaa61fb7b7ed75708,
                    0x952882769104fa9,
                ],
            );
            let d = create_field_extension(
                [0xFFFFFFFFFFFFFFFF, 0, 0, 0],
                [0xFFFFFFFFFFFFFFFF, 0, 0, 0],
            );
            let e = create_field_extension([0xFFFFFFFFFFFFFFFF, 0, 0, 0], [2, 0, 0, 0]);
            let f = create_field_extension(
                [0x3, 0xfffffffffffffffc, 0x0, 0x0],
                [0xffffffffffffffff, 0xffffffffffffffff, 0x0, 0x0],
            );
            for i in [a, b, c, d, e, f] {
                let tmp = i.sqrt();
                match tmp.into_option() {
                    Some(d) => {
                        assert_eq!(d * d, i, "Sqrt failed");
                    }
                    _ => continue,
                }
            }
        }
        #[test]
        fn test_square() {
            let a = create_field_extension([4, 3, 2, 1], [1, 1, 1, 1]);
            let b = create_field_extension([1, 1, 1, 1], [1, 2, 3, 4]);
            let c = create_field_extension(
                [
                    0x2221d7e243f5a6b7,
                    0xf2dbb3e54415ac43,
                    0xc1c16c86d80ba3fe,
                    0x1ed70a64be2c4cf4,
                ],
                [
                    0xcf869553cd163248,
                    0xe9e0e365974ff82b,
                    0xaa61fb7b7ed75708,
                    0x952882769104fa9,
                ],
            );
            for i in [a, b, c] {
                assert_eq!(i.square(), i * i, "Squaring failed");
            }
        }
        #[test]
        fn test_frobenius() {
            let q = FP2_QUADRATIC_NON_RESIDUE;
            let a1 = (Fp::new(Fp::characteristic()) - Fp::from(1)) / Fp::from(3);

            let c1_1 = q.pow(&a1);
            let c1_1_real = create_field_extension(
                [
                    0x99e39557176f553d,
                    0xb78cc310c2c3330c,
                    0x4c0bec3cf559b143,
                    0x2fb347984f7911f7,
                ],
                [
                    0x1665d51c640fcba2,
                    0x32ae2a1d0b7c9dce,
                    0x4ba4cc8bd75a0794,
                    0x16c9e55061ebae20,
                ],
            );
            assert_eq!(c1_1, c1_1_real, "Exponentiation failed");
        }
        #[test]
        fn test_multiplication_edge_cases() {
            let a = create_field_extension([4, 3, 2, 1], [1, 1, 1, 1]);
            let one = Fp2::one();
            let zero = Fp2::zero();

            assert_eq!(a * zero, zero, "Multiplication by zero failed");
            assert_eq!(a * one, a, "Multiplication by one failed");
        }
    }

    mod division_tests {
        use super::*;

        #[test]
        fn test_division_closure() {
            let a = create_field_extension([1, 2, 3, 4], [1, 2, 3, 4]);
            let b = create_field_extension([5, 6, 7, 8], [5, 6, 7, 8]);
            let _ = a / b;
        }
        #[test]
        fn test_division_cases() {
            let a = create_field_extension([4, 3, 2, 1], [1, 1, 1, 1]);
            let b = create_field_extension([1, 1, 1, 1], [1, 2, 3, 4]);
            let one = Fp2::one();
            // basics
            assert_eq!(a / a, one, "Division by self failed");

            assert_eq!(a / one, a, "Division by one failed");
            assert_eq!((a / b) * b, a, "Division-Mult composition failed");
            //simple division

            let c = create_field_extension(
                [
                    0xb696614e97737f6c,
                    0xd2799b66974f80d,
                    0x683ffb614c4317bb,
                    0xec4ef6d41a263d3,
                ],
                [
                    0x890b1e56c256dff3,
                    0xbef14351d1d560c0,
                    0xb825b915b766b744,
                    0x2e71120e2f3641f7,
                ],
            );
            assert_eq!(a / b, c, "Simple division failed");
        }
        #[test]
        // #[should_panic(expected = "assertion failed: self.is_some.is_true_vartime()")]
        fn test_divide_by_zero() {
            let a = create_field_extension([4, 3, 2, 1], [1, 1, 1, 1]);
            let zero = Fp2::zero();

            let _ = a / zero;
        }
    }
    mod square_tests {
        use super::*;

        #[test]
        fn test_square() {
            use crypto_bigint::rand_core::OsRng;

            for _ in 0..100 {
                let a = <Fp2 as FieldExtensionTrait<2, 2>>::rand(&mut OsRng);
                let b = a.square();
                assert!(bool::from(b.is_square()), "Is square failed");
            }
        }
    }
    #[test]
    fn test_conditional_select() {
        let a = create_field_extension([4, 3, 2, 1], [1, 1, 1, 1]);
        let b = create_field_extension([1, 1, 1, 1], [1, 2, 3, 4]);
        assert_eq!(
            Fp2::conditional_select(&a, &b, Choice::from(0u8)),
            a,
            "Conditional select failed"
        );
        assert_eq!(
            Fp2::conditional_select(&a, &b, Choice::from(1u8)),
            b,
            "Conditional select failed"
        );
    }
    #[test]
    fn test_equality() {
        fn is_equal(a: &Fp2, b: &Fp2) -> bool {
            let eq = a == b;
            let ct_eq = a.ct_eq(b);
            assert_eq!(eq, bool::from(ct_eq));

            eq
        }
        assert!(
            is_equal(
                &create_field_extension([4, 3, 2, 1], [1, 1, 1, 1]),
                &create_field_extension([4, 3, 2, 1], [1, 1, 1, 1])
            ),
            "Equality failed"
        );
        assert!(
            !is_equal(
                &create_field_extension([4, 3, 2, 1], [1, 1, 1, 1]),
                &create_field_extension([1, 1, 1, 1], [1, 2, 3, 4])
            ),
            "Equality failed"
        );

        let one = Fp2::one();
        assert!(one.is_one(), "One is not one!");
    }
    #[test]
    fn assignment_tests() {
        let mut a = Fp2::from(10);
        let b = Fp2::from(5);

        // addition
        let c = a + b;
        a += b;

        assert_eq!(c, a, "Addition assignment failed");

        // subtraction
        let mut a = Fp2::from(10);
        let c = a - b;
        a -= b;
        assert_eq!(c, a, "Subtraction assignment failed");

        // multiplication
        let mut a = Fp2::from(10);
        let c = a * b;
        a *= b;
        assert_eq!(c, a, "Multiplication assignment failed");

        // division
        let mut a = Fp2::from(10);
        let c = a / b;
        a /= b;
        assert_eq!(c, a, "Division assignment failed");
    }
    #[test]
    fn test_curve_constant() {
        let curve_constant = <Fp2 as FieldExtensionTrait<2, 2>>::curve_constant();
        let also_curve_constant = <Fp2 as FieldExtensionTrait<6, 3>>::curve_constant();

        let tmp = Fp2::new(&[Fp::THREE, Fp::ZERO]) / Fp2::new(&[Fp::NINE, Fp::ONE]);
        assert!(
            bool::from(curve_constant.ct_eq(&tmp) & also_curve_constant.ct_eq(&tmp)),
            "Curve constant is not 3/(9+u)"
        );
    }
}
