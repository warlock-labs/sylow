use crate::fields::fp::Fp;
use num_traits::{Euclid, Inv, One, Zero};
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Rem, Sub, SubAssign};

// the following struct can unfortunately not have much that is const,
// since the underlying Mul, Add, etc, are not, and const traits are in the works
// https://github.com/rust-lang/rust/issues/67792

// This describes the quadratic field extension of the base field of BN254
// defined by the tower Fp^2 = Fp[X] / (X^2-\beta). Further, the quadratic nature implies
// that elements of this field are represented as a_0 + a_1 X
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Fp2(Fp, Fp);

impl Fp2 {
    // const QUADRATIC_NON_RESIDUE: Self = Self::new(Fp::new())
    pub const fn new(c0: Fp, c1: Fp) -> Self {
        Self(c0, c1)
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
        // This is a specialized version of the Mul below. See docstring there.
        let inner_prod = self.0 * self.1;
        Self::new(
            (self.1 * Fp::quadratic_non_residue() + self.0) * (self.0 + self.1)
                - inner_prod
                - inner_prod * Fp::quadratic_non_residue(),
            inner_prod + inner_prod,
        )
    }
}
impl Add for Fp2 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        Self::new(self.0 + rhs.0, self.1 + rhs.1)
    }
}
impl Sub for Fp2 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self::new(self.0 - rhs.0, self.1 - rhs.1)
    }
}
impl Neg for Fp2 {
    type Output = Self;
    fn neg(self) -> Self::Output {
        Self::new(-self.0, -self.1)
    }
}
impl Mul for Fp2 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        // This requires a bit more consideration. In Fp2,
        // in order to multiply, we must implement complex Karatsuba
        // multiplication.
        // See https://eprint.iacr.org/2006/471.pdf, Sec 3
        // TODO: Implement optimized squaring algorithm in base field?
        let p1 = self.0 * rhs.0;
        let p2 = self.1 * rhs.1;

        Self::new(
            p2 * Fp::quadratic_non_residue() + p1,
            (self.0 + self.1) * (rhs.0 + rhs.1) - p1 - p2,
        )
    }
}
impl Inv for Fp2 {
    type Output = Self;
    fn inv(self) -> Self {
        let c0_squared = self.0 * self.0;
        let c1_squared = self.1 * self.1;
        let tmp = (c0_squared - (c1_squared * Fp::quadratic_non_residue())).inv();
        Self::new(self.0 * tmp, -(self.1 * tmp))
    }
}
impl Zero for Fp2 {
    fn zero() -> Self {
        Self::new(Fp::ZERO, Fp::ZERO)
    }
    fn is_zero(&self) -> bool {
        self.0.is_zero() && self.1.is_zero()
    }
}
impl One for Fp2 {
    fn one() -> Self {
        Self::new(Fp::ONE, Fp::ZERO)
    }
    fn is_one(&self) -> bool {
        self.0.is_one() && self.1.is_one()
    }
}
