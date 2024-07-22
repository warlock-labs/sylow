use crate::fields::extensions::{FieldExtension, FieldExtensionTrait};
use crate::fields::fp::{FinitePrimeField, Fp};
use num_traits::{Inv, One, Zero};
use std::ops::{Div, DivAssign, Mul, MulAssign};

// This describes the quadratic field extension of the base field of BN254
// defined by the tower Fp^2 = Fp[X] / (X^2-\beta). Further, the quadratic nature implies
// that elements of this field are represented as a_0 + a_1 X
impl FieldExtensionTrait<1, 1> for Fp {}
impl FieldExtensionTrait<2, 2> for Fp {}
type Fp2 = FieldExtension<2, 2, Fp>;

#[allow(dead_code)]
impl Fp2 {
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
            t1 * Fp::quadratic_non_residue() + t0,
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
        let c0_squared = self.0[0].square();
        let c1_squared = self.0[1].square();
        let tmp = (c0_squared - (c1_squared * Fp::quadratic_non_residue())).inv();
        Self::new(&[self.0[0] * tmp, -(self.0[1] * tmp)])
    }
}

impl One for Fp2 {
    fn one() -> Self {
        Self::new(&[Fp::one(), Fp::zero()])
    }
    fn is_one(&self) -> bool {
        self.0[0].is_one() && self.0[1].is_one()
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
