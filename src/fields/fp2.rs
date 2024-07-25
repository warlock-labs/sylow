//! This describes the quadratic field extension of the base field of BN254
//! defined by the tower F_{p^2} = F_p(X) / (X^2-\beta). Further, the quadratic nature implies
//! that elements of this field are represented as a_0 + a_1*X. This implements
//! the specific behaviour for this extension, such as multiplication.
use crate::fields::extensions::FieldExtension;
use crate::fields::fp::{FieldExtensionTrait, FinitePrimeField, Fp};
use crate::fields::utils::u256_to_u512;
use crypto_bigint::{rand_core::CryptoRngCore, U512};
use num_traits::{Inv, One, Zero};
use std::ops::{Div, DivAssign, Mul, MulAssign};

pub(crate) type Fp2 = FieldExtension<2, 2, Fp>;

// there are some specific things that must be defined as
// helper functions for us on this specific extension, but
// don't generalize to any extension.
impl Fp2 {
    // variable runtime with respect to the input argument,
    // aka the size of the argument to the exponentiation.
    // the naming convention makes it explicit to us that
    // this should be used only in scenarios where we know
    // precisely what we're doing to not expose vectors
    // for side channel attacks in our api.
    // the below is not exposed publicly
    #[allow(dead_code)]
    pub(crate) fn pow_vartime(&self, by: &[u64]) -> Self {
        let mut res = Self::one();
        for e in by.iter().rev() {
            for i in (0..64).rev() {
                res = res * res;
                if ((*e >> i) & 1) == 1 {
                    res *= *self;
                }
            }
        }
        res
    }
    // type casting must be done on case-by-case basis
    #[allow(dead_code)]
    fn characteristic() -> U512 {
        let wide_p = u256_to_u512(&Fp::characteristic());
        wide_p * wide_p
    }

    pub(crate) fn residue_mul(&self) -> Self {
        *self * <Self as FieldExtensionTrait<2, 2>>::quadratic_non_residue()
    }
}
impl FieldExtensionTrait<2, 2> for Fp2 {
    fn quadratic_non_residue() -> Self {
        Self::new(&[Fp::new_from_u64(9u64), Fp::one()])
    }
    fn frobenius(&self, exponent: usize) -> Self {
        let frobenius_coeff_fp2: &[Fp; 2] = &[
            // Fp::quadratic_non_residue()**(((p^0) - 1) / 2)
            Fp::one(),
            // Fp::quadratic_non_residue()**(((p^1) - 1) / 2)
            <Fp as FieldExtensionTrait<1, 1>>::quadratic_non_residue(),
        ];
        match exponent % 2 {
            0 => *self,
            _ => Self::new(&[
                self.0[0] * frobenius_coeff_fp2[0],
                self.0[1] * frobenius_coeff_fp2[1],
            ]),
        }
    }
    fn sqrt(&self) -> Self {
        let p_minus_3_over_4 = ((Fp::new(Fp::characteristic()) - Fp::new_from_u64(3u64))
            / Fp::new_from_u64(4u64))
        .value();
        let p_minus_1_over_2 = ((Fp::new(Fp::characteristic()) - Fp::new_from_u64(1u64))
            / Fp::new_from_u64(2u64))
        .value();
        let p = Fp::characteristic();
        let a1 = self.pow_vartime(&p_minus_3_over_4.to_words());

        let alpha = a1 * a1 * (*self);
        let a0 = alpha.pow_vartime(&p.to_words());
        if a0 == -Fp2::one() {
            return Fp2::zero();
        }

        if alpha == -Fp2::one() {
            let i = Fp2::new(&[Fp::zero(), Fp::one()]);
            i * a1 * (*self)
        } else {
            let b = (alpha + Fp2::one()).pow_vartime(&p_minus_1_over_2.to_words());
            b * a1 * (*self)
        }
    }
    fn square(&self) -> Self {
        let t0 = self.0[0] * self.0[1];
        Self([
            (self.0[1] * <Fp as FieldExtensionTrait<1, 1>>::quadratic_non_residue() + self.0[0])
                * (self.0[0] + self.0[1])
                - t0
                - t0 * <Fp as FieldExtensionTrait<1, 1>>::quadratic_non_residue(),
            t0 + t0,
        ])
    }
    fn rand<R: CryptoRngCore>(rng: &mut R) -> Self {
        Self([
            <Fp as FieldExtensionTrait<1, 1>>::rand(rng),
            <Fp as FieldExtensionTrait<1, 1>>::rand(rng),
        ])
    }
}

impl Mul for Fp2 {
    type Output = Self;
    fn mul(self, other: Self) -> Self::Output {
        // This requires a bit more consideration. In Fp2,
        // in order to multiply, we must implement complex Karatsuba
        // multiplication.
        // See https://eprint.iacr.org/2006/471.pdf, Sec 3
        // We create the addition chain from Algo 1 of https://eprint.iacr.org/2022/367.pdf
        // TODO: Implement optimized squaring algorithm in base field?
        let t0 = self.0[0] * other.0[0];
        let t1 = self.0[1] * other.0[1];

        Self([
            t1 * <Fp as FieldExtensionTrait<1, 1>>::quadratic_non_residue() + t0,
            (self.0[0] + self.0[1]) * (other.0[0] + other.0[1]) - t0 - t1,
        ])
    }
}
impl MulAssign for Fp2 {
    fn mul_assign(&mut self, other: Self) {
        *self = *self * other;
    }
}

impl Inv for Fp2 {
    type Output = Self;
    fn inv(self) -> Self {
        let c0_squared = <Fp as FieldExtensionTrait<1, 1>>::square(&self.0[0]);
        let c1_squared = <Fp as FieldExtensionTrait<1, 1>>::square(&self.0[1]);
        let tmp = (c0_squared
            - (c1_squared * <Fp as FieldExtensionTrait<1, 1>>::quadratic_non_residue()))
        .inv();
        Self::new(&[self.0[0] * tmp, -(self.0[1] * tmp)])
    }
}

// because mult cannot be implemented generally for all degrees
// this must be defined only for the specific case here, aka not
// in extensions.rs
impl One for Fp2 {
    fn one() -> Self {
        Self::new(&[Fp::one(), Fp::zero()])
    }
    fn is_one(&self) -> bool {
        self.0[0].is_one() && self.0[1].is_zero()
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Div for Fp2 {
    type Output = Self;
    fn div(self, other: Self) -> Self {
        self * other.inv()
    }
}
impl DivAssign for Fp2 {
    fn div_assign(&mut self, other: Self) {
        *self = *self / other;
    }
}
// the below is again to make the quadratic extension visible to
// higher order sextic extension
impl FieldExtensionTrait<6, 3> for Fp2 {
    fn quadratic_non_residue() -> Self {
        <Fp2 as FieldExtensionTrait<2, 2>>::quadratic_non_residue()
    }
    fn frobenius(&self, exponent: usize) -> Self {
        <Fp2 as FieldExtensionTrait<2, 2>>::frobenius(self, exponent)
    }
    fn sqrt(&self) -> Self {
        <Fp2 as FieldExtensionTrait<2, 2>>::sqrt(self)
    }
    fn square(&self) -> Self {
        <Fp2 as FieldExtensionTrait<2, 2>>::square(self)
    }
    fn rand<R: CryptoRngCore>(rng: &mut R) -> Self {
        <Fp2 as FieldExtensionTrait<2, 2>>::rand(rng)
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

    fn create_field(value: [u64; 4]) -> Fp {
        Fp::new(U256::from_words(value))
    }
    fn create_field_extension(v1: [u64; 4], v2: [u64; 4]) -> Fp2 {
        Fp2::new(&[create_field(v1), create_field(v2)])
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
                let tmp = <Fp2 as FieldExtensionTrait<2, 2>>::sqrt(&i);
                assert_eq!(tmp * tmp, i, "Sqrt failed");
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
                assert_eq!(
                    <Fp2 as FieldExtensionTrait<2, 2>>::square(&i),
                    i * i,
                    "Squaring failed"
                );
            }
        }
        #[test]
        fn test_frobenius() {
            let q = <Fp2 as FieldExtensionTrait<2, 2>>::quadratic_non_residue();
            let a1 = (Fp::new(Fp::characteristic()) - Fp::new_from_u64(1)) / Fp::new_from_u64(3);

            let c1_1 = q.pow_vartime(&a1.value().to_words());
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
        #[should_panic(expected = "assertion failed: self.is_some.is_true_vartime()")]
        fn test_divide_by_zero() {
            let a = create_field_extension([4, 3, 2, 1], [1, 1, 1, 1]);
            let zero = Fp2::zero();

            let _ = a / zero;
        }
    }
}
