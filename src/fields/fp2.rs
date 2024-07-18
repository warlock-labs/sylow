#[allow(unused_imports)]
use crate::fields::fp;
use crate::fields::fp::BaseField;
#[allow(unused_imports)]
use crypto_bigint::{impl_modulus, modular::ConstMontyParams, NonZero, U256};
#[allow(unused_imports)]
use num_traits::{Euclid, Inv, One, Zero};
#[allow(unused_imports)]
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Rem, Sub, SubAssign};

const BN254_MOD_STRING: &str = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";
fp::DefineFinitePrimeField!(Fp, U256, 8, BN254_MOD_STRING);

// the following struct can unfortunately not have much that is const,
// since the underlying Mul, Add, etc, are not, and const traits are in the works
// https://github.com/rust-lang/rust/issues/67792

// This describes the quadratic field extension of the base field of BN254
// defined by the tower Fp^2 = Fp[X] / (X^2-\beta). Further, the quadratic nature implies
// that elements of this field are represented as a_0 + a_1 X

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct FieldExtension<const D: usize, const N: usize, F: BaseField<8, U256>>([F; N]);

#[allow(dead_code)]
impl<const D: usize, const N: usize, F: BaseField<8, U256>> FieldExtension<D, N, F> {
    pub fn new(c: &[F; N]) -> Self {
        Self(*c)
    }
    pub fn value(&self) -> [U256; N] {
        let mut i = 0;
        let mut retval = [F::zero().value(); N];
        while i < N {
            retval[i] = self.0[i].value();
            i += 1;
        }
        retval
    }
    pub fn scale(&self, factor: F) -> Self {
        let mut i = 0;
        let mut retval = [F::zero(); N];
        while i < N {
            retval[i] = self.0[i] * factor;
            i += 1;
        }
        Self::new(&retval)
    }
}
#[allow(dead_code)]
impl FieldExtension<2, 2, Fp> {
    pub fn frobenius(&self, exponent: usize) -> Self {
        let frobenius_coeff_fp2: &[Fp; 2] = &[
            // NONRESIDUE**(((q^0) - 1) / 2)
            Fp::one(),
            // NONRESIDUE**(((q^1) - 1) / 2)
            Fp::quadratic_non_residue(),
        ];
        match exponent % 2 {
            0 => *self,
            _ => Self::new(&[
                self.0[0] * frobenius_coeff_fp2[0],
                self.0[1] * frobenius_coeff_fp2[1],
            ]),
        }
    }
    pub fn square(&self) -> Self {
        (*self) * (*self)
    }
    pub fn quadratic_non_residue() -> Self {
        Self::new(&[Fp::new_from_u64(9u64), Fp::one()])
    }
}

impl<const D: usize, const N: usize, F: BaseField<8, U256>> Add for FieldExtension<D, N, F> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        let mut i = 0;
        let mut retval = [F::zero(); N];
        while i < N {
            retval[i] = self.0[i] + rhs.0[i];
            i += 1;
        }
        Self::new(&retval)
    }
}
impl<const D: usize, const N: usize, F: BaseField<8, U256>> Sub for FieldExtension<D, N, F> {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        let mut i = 0;
        let mut retval = [F::zero(); N];
        while i < N {
            retval[i] = self.0[i] - rhs.0[i];
            i += 1;
        }
        Self::new(&retval)
    }
}
impl<const D: usize, const N: usize, F: BaseField<8, U256>> Neg for FieldExtension<D, N, F> {
    type Output = Self;
    fn neg(self) -> Self::Output {
        let mut i = 0;
        let mut retval = [F::zero(); N];
        while i < N {
            retval[i] = -self.0[i];
            i += 1;
        }
        Self::new(&retval)
    }
}
impl Mul for FieldExtension<2, 2, Fp> {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        // This requires a bit more consideration. In Fp2,
        // in order to multiply, we must implement complex Karatsuba
        // multiplication.
        // See https://eprint.iacr.org/2006/471.pdf, Sec 3
        // We create the addition chain from Algo 1 of https://eprint.iacr.org/2022/367.pdf
        // TODO: Implement optimized squaring algorithm in base field?
        let t0 = self.0[0] * rhs.0[0];
        let t1 = self.0[1] * rhs.0[1];

        Self([
            t1 * Fp::quadratic_non_residue() + t0,
            (self.0[0] + self.0[1]) * (rhs.0[0] + rhs.0[1]) - t0 - t1,
        ])
    }
}
impl Inv for FieldExtension<2, 2, Fp> {
    type Output = Self;
    fn inv(self) -> Self {
        let c0_squared = self.0[0].square();
        let c1_squared = self.0[1].square();
        let tmp = (c0_squared - (c1_squared * Fp::quadratic_non_residue())).inv();
        Self::new(&[self.0[0] * tmp, -(self.0[1] * tmp)])
    }
}
impl<const D: usize, const N: usize, F: BaseField<8, U256>> Zero for FieldExtension<D, N, F> {
    fn zero() -> Self {
        Self::new(&[F::zero(); N])
    }
    fn is_zero(&self) -> bool {
        let mut i = 0;
        let mut retval = true;
        while i < N {
            retval &= self.0[i].is_zero();
            i += 1;
        }
        retval
    }
}

impl One for FieldExtension<2, 2, Fp> {
    fn one() -> Self {
        Self::new(&[Fp::one(), Fp::zero()])
    }
    fn is_one(&self) -> bool {
        self.0[0].is_one() && self.0[1].is_one()
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Div for FieldExtension<2, 2, Fp> {
    type Output = Self;
    fn div(self, rhs: Self) -> Self {
        self * rhs.inv()
    }
}

// Tests of associativity, commutivity, etc, follow directly from
// these properties in the base field, as the extension simply performs
// these operations elementwise. The only tests are really to be done
// with multiplication and division
#[cfg(test)]
mod tests {
    use super::*;

    type Fp2 = FieldExtension<2, 2, Fp>;
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
