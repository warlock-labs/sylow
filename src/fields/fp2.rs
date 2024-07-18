#[allow(unused_imports)]
use crate::fields::fp;
#[allow(unused_imports)]
use crypto_bigint::{impl_modulus, modular::ConstMontyParams, NonZero, U256};
#[allow(unused_imports)]
use num_traits::{Euclid, Inv, One, Zero};
#[allow(unused_imports)]
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Rem, Sub, SubAssign};

// the following struct can unfortunately not have much that is const,
// since the underlying Mul, Add, etc, are not, and const traits are in the works
// https://github.com/rust-lang/rust/issues/67792

// This describes the quadratic field extension of the base field of BN254
// defined by the tower Fp^2 = Fp[X] / (X^2-\beta). Further, the quadratic nature implies
// that elements of this field are represented as a_0 + a_1 X
#[allow(unused_macros)]
macro_rules! DefineQuadraticExtension {
    ($wrapper_name:ident, $uint_type:ty, $modulus:expr) => {
        fp::DefineFinitePrimeField!(Fp, $uint_type, $modulus);
        #[derive(Copy, Clone, Debug, PartialEq)]
        pub struct $wrapper_name(Fp, Fp);
        #[allow(dead_code)]
        impl $wrapper_name {
            pub const fn new(c0: Fp, c1: Fp) -> Self {
                Self(c0, c1)
            }
            pub const fn value(&self) -> [$uint_type; 2] {
                [self.0.value(), self.1.value()]
            }
            pub fn scale(&self, factor: Fp) -> Self {
                Self::new(self.0 * factor, self.1 * factor)
            }
            pub fn frobenius(&self, exponent: usize) -> Self {
                let frobenius_coeff_fp2: &[Fp] = &[
                    // NONRESIDUE**(((q^0) - 1) / 2)
                    Fp::ONE,
                    // NONRESIDUE**(((q^1) - 1) / 2)
                    Fp::quadratic_non_residue(),
                ];
                match exponent % 2 {
                    0 => *self,
                    _ => Self::new(
                        self.0 * frobenius_coeff_fp2[0],
                        self.1 * frobenius_coeff_fp2[1],
                    ),
                }
            }
            pub fn square(&self) -> Self {
                (*self) * (*self)
            }
            pub fn quadratic_non_residue() -> Self {
                Self::new(Fp::NINE, Fp::ONE)
            }
            // pub fn sqrt(&self) -> Self {
            //     // we implement shanks method here, which is valid
            //     // on BN254 as p\equiv 3\mod 4 hehe
            //     if self.is_zero() {
            //         return *self;
            //     }
            //     //compute alpha = a^2 + \beta*b^2
            //     let alpha = self.0.square() + Fp::quadratic_non_residue() * self.1.square();

            //     // compute exponent
            //     let p = Fp::characteristic();

            //     // (p-3)/4
            //     let exp1 = (p-3)/4;

            // }
        }
        impl Add for $wrapper_name {
            type Output = Self;
            fn add(self, rhs: Self) -> Self::Output {
                Self::new(self.0 + rhs.0, self.1 + rhs.1)
            }
        }
        impl Sub for $wrapper_name {
            type Output = Self;
            fn sub(self, rhs: Self) -> Self::Output {
                Self::new(self.0 - rhs.0, self.1 - rhs.1)
            }
        }
        impl Neg for $wrapper_name {
            type Output = Self;
            fn neg(self) -> Self::Output {
                Self::new(-self.0, -self.1)
            }
        }
        impl Mul for $wrapper_name {
            type Output = Self;
            fn mul(self, rhs: Self) -> Self::Output {
                // This requires a bit more consideration. In Fp2,
                // in order to multiply, we must implement complex Karatsuba
                // multiplication.
                // See https://eprint.iacr.org/2006/471.pdf, Sec 3
                // We create the addition chain from Algo 1 of https://eprint.iacr.org/2022/367.pdf
                // TODO: Implement optimized squaring algorithm in base field?
                let t0 = self.0 * rhs.0;
                let t1 = self.1 * rhs.1;

                Self(
                    t1 * Fp::quadratic_non_residue() + t0,
                    (self.0 + self.1) * (rhs.0 + rhs.1) - t0 - t1,
                )
            }
        }
        impl Inv for $wrapper_name {
            type Output = Self;
            fn inv(self) -> Self {
                let c0_squared = self.0.square();
                let c1_squared = self.1.square();
                let tmp = (c0_squared - (c1_squared * Fp::quadratic_non_residue())).inv();
                Self::new(self.0 * tmp, -(self.1 * tmp))
            }
        }
        impl Zero for $wrapper_name {
            fn zero() -> Self {
                Self::new(Fp::ZERO, Fp::ZERO)
            }
            fn is_zero(&self) -> bool {
                self.0.is_zero() && self.1.is_zero()
            }
        }
        impl One for $wrapper_name {
            fn one() -> Self {
                Self::new(Fp::ONE, Fp::ZERO)
            }
            fn is_one(&self) -> bool {
                self.0.is_one() && self.1.is_one()
            }
        }
        #[allow(clippy::suspicious_arithmetic_impl)]
        impl Div for $wrapper_name {
            type Output = Self;
            fn div(self, rhs: Self) -> Self {
                self * rhs.inv()
            }
        }
    };
}

// Tests of associativity, commutivity, etc, follow directly from
// these properties in the base field, as the extension simply performs
// these operations elementwise. The only tests are really to be done
// with multiplication and division
#[cfg(test)]
mod tests {
    use super::*;
    const BN254_MOD_STRING: &str =
        "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";
    DefineQuadraticExtension!(Fp2, U256, BN254_MOD_STRING);

    fn create_field(value: [u64; 4]) -> Fp {
        Fp::new(U256::from_words(value))
    }
    fn create_field_extension(v1: [u64; 4], v2: [u64; 4]) -> Fp2 {
        Fp2::new(create_field(v1), create_field(v2))
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
                "Multiplication is not associative"
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
            assert_eq!(((a / b) * b), a, "Division-Mult composition failed");
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
