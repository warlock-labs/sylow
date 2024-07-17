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
        fp::DefineFinitePrimeField!(BaseField, $uint_type, $modulus);
        #[derive(Copy, Clone, Debug, PartialEq)]
        pub struct $wrapper_name(BaseField, BaseField);
        #[allow(dead_code)]
        impl $wrapper_name {
            pub const fn new(c0: BaseField, c1: BaseField) -> Self {
                Self(c0, c1)
            }
            pub fn scale(&self, factor: BaseField) -> Self {
                Self::new(self.0 * factor, self.1 * factor)
            }
            pub fn frobenius(&self, exponent: usize) -> Self {
                let frobenius_coeff_fp2: &[BaseField] = &[
                    // NONRESIDUE**(((q^0) - 1) / 2)
                    BaseField::ONE,
                    // NONRESIDUE**(((q^1) - 1) / 2)
                    BaseField::quadratic_non_residue(),
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
                Self::new(BaseField::NINE, BaseField::ONE)
            }
            // pub fn sqrt(&self) -> Self {
            //     // we implement shanks method here, which is valid
            //     // on BN254 as p\equiv 3\mod 4 hehe
            //     if self.is_zero() {
            //         return *self;
            //     }
            //     //compute alpha = a^2 + \beta*b^2
            //     let alpha = self.0.square() + BaseField::quadratic_non_residue() * self.1.square();

            //     // compute exponent
            //     let p = BaseField::characteristic();

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

                let temp0 = self.0 + self.1;
                let temp1 = rhs.0 + rhs.1;

                let mut t2 = temp0 * temp1;

                let t3 = t0 + t1;
                t2 -= t3;

                let c1 = t2;
                let c0 = t0 - (t1 * BaseField::quadratic_non_residue());

                Self::new(c0, c1)
            }
        }
        impl Inv for $wrapper_name {
            type Output = Self;
            fn inv(self) -> Self {
                let c0_squared = self.0.square();
                let c1_squared = self.1.square();
                let tmp = (c0_squared - (c1_squared * BaseField::quadratic_non_residue())).inv();
                Self::new(self.0 * tmp, -(self.1 * tmp))
            }
        }
        impl Zero for $wrapper_name {
            fn zero() -> Self {
                Self::new(BaseField::ZERO, BaseField::ZERO)
            }
            fn is_zero(&self) -> bool {
                self.0.is_zero() && self.1.is_zero()
            }
        }
        impl One for $wrapper_name {
            fn one() -> Self {
                Self::new(BaseField::ONE, BaseField::ZERO)
            }
            fn is_one(&self) -> bool {
                self.0.is_one() && self.1.is_one()
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    const BN254_MOD_STRING: &str = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";
    DefineQuadraticExtension!(Fp2, U256, BN254_MOD_STRING);
}

