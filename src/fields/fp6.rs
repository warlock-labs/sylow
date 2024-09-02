//! Sextic Extension Field 𝔽ₚ⁶ for BN254 Elliptic Curve Cryptography
//!
//! This module implements the sextic extension field of the quadratic extension field of BN254,
//! defined by the tower 𝔽ₚ⁶ = 𝔽ₚ²(v) / (v³ - (9 + u)). Elements of this field are represented
//! as a₀ + a₁v + a₂v², where a₀, a₁, and a₂ are elements of 𝔽ₚ².
//!
//! The implementation provides specific behavior for this extension, such as
//! multiplication, inversion, and operations required for elliptic curve arithmetic.

use crate::fields::extensions::FieldExtension;
use crate::fields::fp::{FieldExtensionTrait, Fp};
use crate::fields::fp2::Fp2;
use crypto_bigint::{rand_core::CryptoRngCore, subtle::ConditionallySelectable, U256};
use num_traits::{Inv, One, Zero};
use std::ops::{Div, DivAssign, Mul, MulAssign};
use subtle::Choice;

// the following values are a bit difficult to compute. The reason
// is that they involve operations up to p^11, which occupy a U4096
// precision integer. This can be done no problem in the current framework.
// However, to execute this in our current setup, the value of p needs to be
// cast to the appropriate precision, and then the operation can be performed
// Even the exponentiation made in Fp2 can handle exponentiating the
// changing number of words. The issue is just doing all of this
// on the fly induces a bit of overhead, so we just hardcode the values for
// clarity and speed here.

// For instance, to compute (p^2-1)/3
// let wide_p = u256_to_512(p);
// define_finite_prime_field!(Fp2, U512, 8, (wide_p*wide_p).to_be_string(), 1, 1)
// let exponent = (wide_p * wide_p - Fp2::ONE)/Fp2::THREE

// This is a lot of overhead, but it is doable with the components already provided
// within should someone be interested

/// Frobenius coefficients for 𝔽ₚ⁶
///
/// These constants are precomputed values used in the Frobenius endomorphism.
/// They are calculated as powers of the quadratic non-residue in 𝔽ₚ².
const FROBENIUS_COEFF_FP6_C1: &[Fp2; 6] = &[
    // Fp2::quadratic_non_residue().pow( ( p^0 - 1) / 3)
    Fp2::new(&[Fp::ONE, Fp::ZERO]),
    // Fp2::quadratic_non_residue().pow( ( p^1 - 1) / 3)
    Fp2::new(&[
        Fp::new(U256::from_words([
            0x99e39557176f553d,
            0xb78cc310c2c3330c,
            0x4c0bec3cf559b143,
            0x2fb347984f7911f7,
        ])),
        Fp::new(U256::from_words([
            0x1665d51c640fcba2,
            0x32ae2a1d0b7c9dce,
            0x4ba4cc8bd75a0794,
            0x16c9e55061ebae20,
        ])),
    ]),
    // Fp2::quadratic_non_residue().pow( ( p^2 - 1) / 3)
    Fp2::new(&[
        Fp::new(U256::from_words([
            0xe4bd44e5607cfd48,
            0xc28f069fbb966e3d,
            0x5e6dd9e7e0acccb0,
            0x30644e72e131a029,
        ])),
        Fp::ZERO,
    ]),
    // Fp2::quadratic_non_residue().pow( ( p^3 - 1) / 3)
    Fp2::new(&[
        Fp::new(U256::from_words([
            0x7b746ee87bdcfb6d,
            0x805ffd3d5d6942d3,
            0xbaff1c77959f25ac,
            0x856e078b755ef0a,
        ])),
        Fp::new(U256::from_words([
            0x380cab2baaa586de,
            0xfdf31bf98ff2631,
            0xa9f30e6dec26094f,
            0x4f1de41b3d1766f,
        ])),
    ]),
    // Fp2::quadratic_non_residue().pow( (p^4 - 1) / 3)
    Fp2::new(&[
        Fp::new(U256::from_words([
            0x5763473177fffffe,
            0xd4f263f1acdb5c4f,
            0x59e26bcea0d48bac,
            0x0,
        ])),
        Fp::ZERO,
    ]),
    // Fp2::quadratic_non_residue().pow( (p^5 - 1) / 3)
    Fp2::new(&[
        Fp::new(U256::from_words([
            0x62e913ee1dada9e4,
            0xf71614d4b0b71f3a,
            0x699582b87809d9ca,
            0x28be74d4bb943f51,
        ])),
        Fp::new(U256::from_words([
            0xedae0bcec9c7aac7,
            0x54f40eb4c3f6068d,
            0xc2b86abcbe01477a,
            0x14a88ae0cb747b99,
        ])),
    ]),
];

/// Additional Frobenius coefficients for 𝔽ₚ⁶
const FROBENIUS_COEFF_FP6_C2: &[Fp2; 6] = &[
    // Fp2::quadratic_non_residue().pow( (2 * p^0 - 2) / 3)
    Fp2::new(&[Fp::ONE, Fp::ZERO]),
    // Fp2::quadratic_non_residue().pow( (2 * p^1 - 2) / 3)
    Fp2::new(&[
        Fp::new(U256::from_words([
            0x848a1f55921ea762,
            0xd33365f7be94ec72,
            0x80f3c0b75a181e84,
            0x5b54f5e64eea801,
        ])),
        Fp::new(U256::from_words([
            0xc13b4711cd2b8126,
            0x3685d2ea1bdec763,
            0x9f3a80b03b0b1c92,
            0x2c145edbe7fd8aee,
        ])),
    ]),
    // Fp2::quadratic_non_residue().pow( (2 * p^2 - 2) / 3)
    Fp2::new(&[
        Fp::new(U256::from_words([
            0x5763473177fffffe,
            0xd4f263f1acdb5c4f,
            0x59e26bcea0d48bac,
            0x0,
        ])),
        Fp::new(U256::from_words([0x0, 0x0, 0x0, 0x0])),
    ]),
    // Fp2::quadratic_non_residue().pow( (2 * p^3 - 2) / 3)
    Fp2::new(&[
        Fp::new(U256::from_words([
            0xe1a92bc3ccbf066,
            0xe633094575b06bcb,
            0x19bee0f7b5b2444e,
            0xbc58c6611c08dab,
        ])),
        Fp::new(U256::from_words([
            0x5fe3ed9d730c239f,
            0xa44a9e08737f96e5,
            0xfeb0f6ef0cd21d04,
            0x23d5e999e1910a12,
        ])),
    ]),
    // Fp2::quadratic_non_residue().pow( (2 * p^4 - 2) / 3)
    Fp2::new(&[
        Fp::new(U256::from_words([
            0xe4bd44e5607cfd48,
            0xc28f069fbb966e3d,
            0x5e6dd9e7e0acccb0,
            0x30644e72e131a029,
        ])),
        Fp::new(U256::from_words([0x0, 0x0, 0x0, 0x0])),
    ]),
    // Fp2::quadratic_non_residue().pow( (2 * p^5 - 2) / 3)
    Fp2::new(&[
        Fp::new(U256::from_words([
            0xa97bda050992657f,
            0xde1afb54342c724f,
            0x1d9da40771b6f589,
            0x1ee972ae6a826a7d,
        ])),
        Fp::new(U256::from_words([
            0x5721e37e70c255c9,
            0x54326430418536d1,
            0xd2b513cdbb257724,
            0x10de546ff8d4ab51,
        ])),
    ]),
];

/// Type alias for the sextic (𝔽ₚ⁶) extension of the base field (𝔽ₚ)
pub type Fp6 = FieldExtension<6, 3, Fp2>;

impl Fp6 {
    /// Multiplies the element by the sextic non-residue of the field.
    ///
    /// This operation is optimized for the specific structure of 𝔽ₚ⁶.
    #[inline(always)]
    pub(crate) fn residue_mul(&self) -> Self {
        Self([self.0[2].residue_mul(), self.0[0], self.0[1]])
    }

    /// Applies the Frobenius endomorphism to the field element.
    ///
    /// # Arguments
    ///
    /// * `exponent` - The power of the Frobenius endomorphism to apply
    ///
    /// # Returns
    ///
    /// The result of applying the Frobenius endomorphism `exponent` times
    #[inline(always)]
    pub(crate) fn frobenius(&self, exponent: usize) -> Self {
        Self::new(&[
            self.0[0].frobenius(exponent),
            self.0[1].frobenius(exponent) * FROBENIUS_COEFF_FP6_C1[exponent % 6],
            self.0[2].frobenius(exponent) * FROBENIUS_COEFF_FP6_C2[exponent % 6],
        ])
    }

    // this is simply the same as the multiplication below
    // however, there are some simple algebraic reductions
    // you can do with squaring. this just implements that,
    // but functionally it is the same as the `Mul` trait below

    /// Computes the square of the field element.
    ///
    /// This method implements an optimized squaring algorithm for 𝔽ₚ⁶ elements.
    pub(crate) fn square(&self) -> Self {
        let t0 = self.0[0].square();
        let cross = self.0[0] * self.0[1];
        let t1 = cross + cross;
        let mut t2 = self.0[0] - self.0[1] + self.0[2];
        t2 = t2.square();
        let bc = self.0[1] * self.0[2];
        let s3 = bc + bc;
        let mut s4 = self.0[2];
        s4 = s4.square();
        tracing::trace!(?t0, ?cross, ?t1, ?t2, ?bc, ?s3, ?s4, "Fp6::square");

        Self([
            t0 + s3.residue_mul(),
            t1 + s4.residue_mul(),
            t1 + t2 + s3 - t0 - s4,
        ])
    }
}

// TODO(Encapsulate crypto-bigint rng to the more general rng if possible)
impl FieldExtensionTrait<6, 3> for Fp6 {
    /// Generates a random element in the 𝔽ₚ⁶ field.
    ///
    /// # Arguments
    ///
    /// * `rng` - A cryptographically secure random number generator
    ///
    /// # Returns
    ///
    /// A random element in 𝔽ₚ⁶
    fn rand<R: CryptoRngCore>(rng: &mut R) -> Self {
        Self([
            <Fp2 as FieldExtensionTrait<2, 2>>::rand(rng),
            <Fp2 as FieldExtensionTrait<2, 2>>::rand(rng),
            <Fp2 as FieldExtensionTrait<2, 2>>::rand(rng),
        ])
    }

    /// Returns the curve constant for 𝔽ₚ⁶.
    ///
    /// # Returns
    ///
    /// The constant 3 in 𝔽ₚ⁶
    fn curve_constant() -> Self {
        Self::from(3)
    }
}
impl<'a, 'b> Mul<&'b Fp6> for &'a Fp6 {
    type Output = Fp6;

    /// Multiplies two elements in 𝔽ₚ⁶.
    ///
    /// This implementation uses an optimized schoolbook multiplication algorithm
    /// tailored for the specific structure of 𝔽ₚ⁶ which runs in constant time.
    ///
    /// # Arguments
    ///
    /// * `other` - Another 𝔽ₚ⁶ element to multiply with
    ///
    /// # Returns
    ///
    /// The product of the two 𝔽ₚ⁶ elements
    #[inline]
    fn mul(self, other: &'b Fp6) -> Self::Output {
        // We could do Karatsuba multiplication here, which would look simpler:
        // // let t0 = self.0[0] * other.0[0];
        // // let t1 = self.0[1] * other.0[1];
        // // let t2 = self.0[2] * other.0[2];
        // // tracing::trace!(?t0, ?t1, ?t2, "Fp6::mul");
        // //
        // // Self::Output::new(&[
        // //     ((self.0[1] + self.0[2]) * (other.0[1] + other.0[2]) - t1 - t2).residue_mul() + t0,
        // //     (self.0[0] + self.0[1]) * (other.0[0] + other.0[1]) - t0 - t1 + t2.residue_mul(),
        // //     (self.0[0] + self.0[2]) * (other.0[0] + other.0[2]) - t0 + t1 - t2,
        // // ])
        //
        // But the issue again is constant-time execution. We opt for schoolbook multiplication
        // here instead following Algo 5 of <https://eprint.iacr.org/2022/367.pdf>, which yields
        // the following results:
        //
        // c0,0 = a0,0b0,0 - a0,1b0,1 + αa1,0b2,0 - αa1,1b2,1 + αa2,0b1,0 - αa2,1b1,1 - a1,0b2,1 - a1,1b2,0
        //        - a2,0b1,1 - a2,1b1,0.
        //      = a0,0b0,0 - a0,1b0,1 + a1,0(αb2,0 - b2,1) - a1,1(b2,0 + αb2,1) + a2,0(αb1,0 - b1,1)
        //        - a2,1(b1,0 + αb1,1).
        // c0,1 = a0,0b0,1 + a0,1b0,0 + αa1,0b2,1 + αa1,1b2,0 + αa2,0b1,1 + αa2,1b1,0 + a1,0b2,0 - a1,1b2,1
        //        + a2,0b1,0 - a2,1b1,1.
        //      = a0,0b0,1 + a0,1b0,0 + a1,0(b2,0 + αb2,1) + a1,1(αb2,0 - b2,1) + a2,0(b1,0 + αb1,1)
        //        + a2,1(αb1,0 - b1,1).
        // c1,0 = a0,0b1,0 - a0,1b1,1 + a1,0b0,0 - a1,1b0,1 + αa2,0b2,0 - αa2,1b2,1 - a2,0b2,1 - a2,1b2,0.
        //      = a0,0b1,0 - a0,1b1,1 + a1,0b0,0 - a1,1b0,1 + a2,0(αb2,0 - b2,1) - a2,1(αb2,1 + b2,0).
        // c1,1 = a0,0b1,1 + a0,1b1,0 + a1,0b0,1 + a1,1b0,0 + αa2,0b2,1 + αa2,1b2,0 + a2,0b2,0 - a2,1b2,1.
        //      = a0,0b1,1 + a0,1b1,0 + a1,0b0,1 + a1,1b0,0 + a2,0(αb2,1 + b2,0) + a2,1(αb2,0 - b2,1).
        // c2,0 = a0,0b2,0 - a0,1b2,1 + a1,0b1,0 - a1,1b1,1 + a2,0b0,0 - a2,1b0,1.
        // c2,1 = a0,0b2,1 + a0,1b2,0 + a1,0b1,1 + a1,1b1,0 + a2,0b0,1 + a2,1b0,0.
        //
        // Here, alpha is \xi=\alpha+u=9+u => alpha = 9

        let a20_m_b21 = Fp::NINE * other.0[2].0[0] - other.0[2].0[1];
        let a10_m_b11 = Fp::NINE * other.0[1].0[0] - other.0[1].0[1];
        let b21_p_b20 = Fp::NINE * other.0[2].0[1] + other.0[2].0[0];
        let b20_m_b21 = Fp::NINE * other.0[2].0[0] - other.0[2].0[1];
        let b11_p_b10 = Fp::NINE * other.0[1].0[1] + other.0[1].0[0];

        let c00 = self.0[0].0[0] * other.0[0].0[0] - self.0[0].0[1] * other.0[0].0[1]
            + self.0[1].0[0] * a20_m_b21
            - self.0[1].0[1] * b21_p_b20
            + self.0[2].0[0] * a10_m_b11
            - self.0[2].0[1] * b11_p_b10;

        let c01 = self.0[0].0[0] * other.0[0].0[1]
            + self.0[0].0[1] * other.0[0].0[0]
            + self.0[1].0[0] * b21_p_b20
            + self.0[1].0[1] * b20_m_b21
            + self.0[2].0[0] * b11_p_b10
            + self.0[2].0[1] * a10_m_b11;

        let c10 = self.0[0].0[0] * other.0[1].0[0] - self.0[0].0[1] * other.0[1].0[1]
            + self.0[1].0[0] * other.0[0].0[0]
            - self.0[1].0[1] * other.0[0].0[1]
            + self.0[2].0[0] * b20_m_b21
            - self.0[2].0[1] * b21_p_b20;

        let c11 = self.0[0].0[0] * other.0[1].0[1]
            + self.0[0].0[1] * other.0[1].0[0]
            + self.0[1].0[0] * other.0[0].0[1]
            + self.0[1].0[1] * other.0[0].0[0]
            + self.0[2].0[0] * b21_p_b20
            + self.0[2].0[1] * a20_m_b21;

        let c20 = self.0[0].0[0] * other.0[2].0[0] - self.0[0].0[1] * other.0[2].0[1]
            + self.0[1].0[0] * other.0[1].0[0]
            - self.0[1].0[1] * other.0[1].0[1]
            + self.0[2].0[0] * other.0[0].0[0]
            - self.0[2].0[1] * other.0[0].0[1];

        let c21 = self.0[0].0[0] * other.0[2].0[1]
            + self.0[0].0[1] * other.0[2].0[0]
            + self.0[1].0[0] * other.0[1].0[1]
            + self.0[1].0[1] * other.0[1].0[0]
            + self.0[2].0[0] * other.0[0].0[1]
            + self.0[2].0[1] * other.0[0].0[0];

        Self::Output::new(&[
            Fp2::new(&[c00, c01]),
            Fp2::new(&[c10, c11]),
            Fp2::new(&[c20, c21]),
        ])
    }
}
impl Mul for Fp6 {
    type Output = Self;

    /// Multiplies two 𝔽ₚ⁶ elements.
    ///
    /// This implementation delegates to the reference multiplication implementation.
    ///
    /// # Arguments
    ///
    /// * `other` - Another 𝔽ₚ⁶ element to multiply with
    ///
    /// # Returns
    ///
    /// The product of the two 𝔽ₚ⁶ elements
    #[inline]
    fn mul(self, other: Self) -> Self::Output {
        (&self).mul(&other)
    }
}
impl MulAssign for Fp6 {
    /// Performs multiplication by assignment in 𝔽ₚ⁶.
    ///
    /// # Arguments
    ///
    /// * `other` - The 𝔽ₚ⁶ element to multiply with
    #[inline]
    fn mul_assign(&mut self, other: Self) {
        *self = *self * other;
    }
}

impl Inv for Fp6 {
    type Output = Self;

    /// Computes the multiplicative inverse of an 𝔽ₚ⁶ element.
    ///
    /// This method implements an optimized inversion algorithm for 𝔽ₚ⁶ elements.
    ///
    /// # Returns
    ///
    /// The multiplicative inverse of the 𝔽ₚ⁶ element
    ///
    /// # References
    ///
    /// * Implements a low-overhead version of Alg 17 of <https://eprint.iacr.org/2010/354.pdf>
    #[inline]
    fn inv(self) -> Self::Output {
        let t0 = self.0[0].square() - self.0[1] * self.0[2].residue_mul();
        let t1 = self.0[2].square().residue_mul() - self.0[0] * self.0[1];
        let t2 = self.0[1].square() - self.0[0] * self.0[2];

        let inverse = ((self.0[2] * t1 + self.0[1] * t2).residue_mul() + self.0[0] * t0).inv();
        tracing::trace!(?t0, ?t1, ?t2, ?inverse, "Fp6::inv");
        Self([inverse * t0, inverse * t1, inverse * t2])
    }
}

impl One for Fp6 {
    /// Returns the multiplicative identity element of 𝔽ₚ⁶.
    ///
    /// # Returns
    ///
    /// The 𝔽ₚ⁶ element representing 1 + 0v + 0v²
    #[inline]
    fn one() -> Self {
        Self::new(&[Fp2::one(), Fp2::zero(), Fp2::zero()])
    }

    /// Checks if the 𝔽ₚ⁶ element is the multiplicative identity.
    ///
    /// # Returns
    ///
    /// The boolean `true` if the element is 1 + 0v + 0v², false otherwise
    fn is_one(&self) -> bool {
        self.0[0].is_one() && self.0[1].is_zero() && self.0[2].is_zero()
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Div for Fp6 {
    type Output = Self;

    /// Performs division in 𝔽ₚ⁶.
    ///
    /// This operation is implemented as multiplication by the inverse, which is possible
    /// in prime cyclic Abelian groups, which feature fully symmetrical multiplication tables.
    ///
    /// # Arguments
    ///
    /// * `other` - The 𝔽ₚ⁶ element to divide by
    ///
    /// # Returns
    ///
    /// The result of the division
    #[inline]
    fn div(self, other: Self) -> Self::Output {
        self * other.inv()
    }
}
impl DivAssign for Fp6 {
    /// Performs division assignment in 𝔽ₚ⁶.
    ///
    /// # Arguments
    ///
    /// * `other` - The 𝔽ₚ⁶ element to divide by
    #[inline]
    fn div_assign(&mut self, other: Self) {
        *self = *self / other;
    }
}

impl ConditionallySelectable for Fp6 {
    /// Performs constant-time conditional selection between two 𝔽ₚ⁶ elements.
    ///
    /// # Arguments
    ///
    /// * `a` - The first 𝔽ₚ⁶ element
    /// * `b` - The second 𝔽ₚ⁶ element
    /// * `choice` - A `Choice` value determining which element to select
    ///
    /// # Returns
    ///
    /// `a` if `choice` is 0, `b` if `choice` is 1
    #[inline(always)]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self::new(&[
            Fp2::conditional_select(&a.0[0], &b.0[0], choice),
            Fp2::conditional_select(&a.0[1], &b.0[1], choice),
            Fp2::conditional_select(&a.0[2], &b.0[2], choice),
        ])
    }
}

// Make the sextic extension "visible" to the dodectic extension
impl FieldExtensionTrait<12, 2> for Fp6 {
    // TODO(Encapsulate crypto-bigint rng to the more general rng if possible)
    /// Generates a random element in the 𝔽ₚ⁶ field.
    ///
    /// This implementation delegates to the FieldExtensionTrait<6, 3> implementation.
    ///
    /// # Arguments
    ///
    /// * `rng` - A cryptographically secure random number generator
    ///
    /// # Returns
    ///
    /// A random element in 𝔽ₚ⁶
    fn rand<R: CryptoRngCore>(rng: &mut R) -> Self {
        <Fp6 as FieldExtensionTrait<6, 3>>::rand(rng)
    }

    /// Returns the curve constant for 𝔽ₚ⁶.
    ///
    /// This implementation delegates to the FieldExtensionTrait<6, 3> implementation.
    ///
    /// # Returns
    ///
    /// The constant 3 in 𝔽ₚ⁶
    fn curve_constant() -> Self {
        <Fp6 as FieldExtensionTrait<6, 3>>::curve_constant()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_bigint::U256;
    use subtle::ConstantTimeEq;

    fn create_field(value: [u64; 4]) -> Fp {
        Fp::new(U256::from_words(value))
    }
    fn create_field_extension(
        v1: [u64; 4],
        v2: [u64; 4],
        v3: [u64; 4],
        v4: [u64; 4],
        v5: [u64; 4],
        v6: [u64; 4],
    ) -> Fp6 {
        Fp6::new(&[
            Fp2::new(&[create_field(v1), create_field(v2)]),
            Fp2::new(&[create_field(v3), create_field(v4)]),
            Fp2::new(&[create_field(v5), create_field(v6)]),
        ])
    }
    mod addition_tests {
        use super::*;

        #[test]
        fn test_addition_closure() {
            let a = create_field_extension(
                [1, 0, 0, 0],
                [0, 2, 0, 0],
                [0, 0, 3, 0],
                [0, 0, 0, 4],
                [5, 0, 0, 0],
                [0, 6, 0, 0],
            );
            let b = create_field_extension(
                [0, 6, 0, 0],
                [5, 0, 0, 0],
                [0, 0, 0, 4],
                [0, 0, 3, 0],
                [0, 2, 0, 0],
                [1, 0, 0, 0],
            );
            let _ = a + b;
        }
    }
    mod subtraction_tests {
        use super::*;

        #[test]
        fn test_subtraction_closure() {
            let a = create_field_extension(
                [1, 0, 0, 0],
                [0, 2, 0, 0],
                [0, 0, 3, 0],
                [0, 0, 0, 4],
                [5, 0, 0, 0],
                [0, 6, 0, 0],
            );
            let b = create_field_extension(
                [0, 6, 0, 0],
                [5, 0, 0, 0],
                [0, 0, 0, 4],
                [0, 0, 3, 0],
                [0, 2, 0, 0],
                [1, 0, 0, 0],
            );
            let _ = a - b;
        }
    }
    mod multiplication_tests {
        use super::*;

        #[test]
        fn test_multiplication_closure() {
            let a = create_field_extension(
                [1, 0, 0, 0],
                [0, 2, 0, 0],
                [0, 0, 3, 0],
                [0, 0, 0, 4],
                [5, 0, 0, 0],
                [0, 6, 0, 0],
            );
            let b = create_field_extension(
                [0, 6, 0, 0],
                [5, 0, 0, 0],
                [0, 0, 0, 4],
                [0, 0, 3, 0],
                [0, 2, 0, 0],
                [1, 0, 0, 0],
            );
            let _ = a * b;
        }

        #[test]
        fn test_multiplication_associativity_commutativity_distributivity() {
            let a = create_field_extension(
                [1, 0, 0, 0],
                [0, 2, 0, 0],
                [0, 0, 3, 0],
                [0, 0, 0, 4],
                [5, 0, 0, 0],
                [0, 6, 0, 0],
            );
            let b = create_field_extension(
                [0, 6, 0, 0],
                [5, 0, 0, 0],
                [0, 0, 0, 4],
                [0, 0, 3, 0],
                [0, 2, 0, 0],
                [1, 0, 0, 0],
            );
            assert_eq!(a * b, b * a, "Multiplication is not commutative");

            let c = create_field_extension(
                [1, 0, 0, 0],
                [5, 0, 0, 0],
                [0, 2, 0, 0],
                [0, 0, 0, 4],
                [0, 0, 3, 0],
                [0, 6, 0, 0],
            );
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
            let a = create_field_extension(
                [1, 0, 0, 0],
                [0, 2, 0, 0],
                [0, 0, 3, 0],
                [0, 0, 0, 4],
                [5, 0, 0, 0],
                [0, 6, 0, 0],
            );
            let b = create_field_extension(
                [0, 6, 0, 0],
                [5, 0, 0, 0],
                [0, 0, 0, 4],
                [0, 0, 3, 0],
                [0, 2, 0, 0],
                [1, 0, 0, 0],
            );
            let c = create_field_extension(
                [
                    0xed9d072bc3003126,
                    0x9bf0c48f5b9081c5,
                    0x654e4b31ffe4ae14,
                    0x229c18498af45bd8,
                ],
                [
                    0x4a5e9416106932a0,
                    0xa91300efa307f9c3,
                    0x7a71433b8b7f4be1,
                    0x1b414a8e45c427d0,
                ],
                [
                    0x3c208c16d87cfd42,
                    0x97816a916871cab1,
                    0xb85045b681815851,
                    0x30644e72e131a025,
                ],
                [
                    0x4e8384eb157ccc4e,
                    0xfb90a6020ce148c7,
                    0x5301fa84819caab4,
                    0xdc83629563d4475,
                ],
                [0x0, 0x0, 0x0, 0x0],
                [
                    0x7bcf82ea8e801788,
                    0x5ce8acfe387071f2,
                    0x3423a8065d60818b,
                    0x99dd9ae870a50e4,
                ],
            );
            assert_eq!(a * b, c, "Multiplication failed");

            let d = create_field_extension(
                [0xffffffffffffffff, 0xffffffffffffffff, 0x0, 0x0],
                [0xffffffffffffffff, 0xffffffffffffffff, 0x0, 0x0],
                [0xffffffffffffffff, 0xffffffffffffffff, 0x0, 0x0],
                [0xffffffffffffffff, 0xffffffffffffffff, 0x0, 0x0],
                [0xffffffffffffffff, 0xffffffffffffffff, 0x0, 0x0],
                [0xffffffffffffffff, 0xffffffffffffffff, 0x0, 0x0],
            );
            let e = create_field_extension(
                [
                    0x2acc09f69abdc416,
                    0x51f287ef9c76823,
                    0xd6e5fdaf211d9813,
                    0x289ebddf5a43c395,
                ],
                [
                    0xca72021005dd2367,
                    0xb6353d4fea7f71b,
                    0x48f943b451719e38,
                    0x13e67cd30093f3e,
                ],
                [
                    0x956604fb4d5ee20b,
                    0x828f943f7ce3b411,
                    0xeb72fed7908ecc09,
                    0x144f5eefad21e1ca,
                ],
                [
                    0xc14085a5e75d3bea,
                    0x595bb61cac703800,
                    0x7ba0694d5163f56b,
                    0x128c73f1f5836d18,
                ],
                [0x0, 0x0, 0x0, 0x0],
                [
                    0xb80f093bc8dd546d,
                    0xa75418645a3878e5,
                    0xae478ee651564c9e,
                    0x23da8016bafd9af2,
                ],
            );
            assert_eq!(d * d, e, "Multiplication around modulus failed")
        }
        #[test]
        fn test_frobenius() {
            let a = create_field_extension(
                [1, 0, 0, 0],
                [0, 2, 0, 0],
                [0, 0, 3, 0],
                [0, 0, 0, 4],
                [5, 0, 0, 0],
                [0, 6, 0, 0],
            );

            assert_eq!(
                a,
                a.frobenius(2).frobenius(2).frobenius(2),
                "Frobenius failed at cycle order 3"
            );
            assert_eq!(
                a,
                a.frobenius(3).frobenius(3),
                "Frobenius failed at cycle order 3"
            );
            assert_eq!(
                a,
                a.frobenius(1)
                    .frobenius(1)
                    .frobenius(1)
                    .frobenius(1)
                    .frobenius(1)
                    .frobenius(1),
                "Frobenius failed at cycle order 6"
            );
        }
    }
    mod division_tests {
        use super::*;

        #[test]
        fn test_division_closure() {
            let a = create_field_extension(
                [1, 0, 0, 0],
                [0, 2, 0, 0],
                [0, 0, 3, 0],
                [0, 0, 0, 4],
                [5, 0, 0, 0],
                [0, 6, 0, 0],
            );
            let b = create_field_extension(
                [0, 6, 0, 0],
                [5, 0, 0, 0],
                [0, 0, 0, 4],
                [0, 0, 3, 0],
                [0, 2, 0, 0],
                [1, 0, 0, 0],
            );
            let _ = a / b;
        }
        #[test]
        fn test_division_cases() {
            let a = create_field_extension(
                [1, 0, 0, 0],
                [0, 2, 0, 0],
                [0, 0, 3, 0],
                [0, 0, 0, 4],
                [5, 0, 0, 0],
                [0, 6, 0, 0],
            );
            let b = create_field_extension(
                [0, 6, 0, 0],
                [5, 0, 0, 0],
                [0, 0, 0, 4],
                [0, 0, 3, 0],
                [0, 2, 0, 0],
                [1, 0, 0, 0],
            );
            let one = Fp6::one();

            assert_eq!(a / a, one, "Division by self failed");

            assert_eq!(a / one, a, "Division by one failed");
            assert_eq!((a / b) * b, a, "Division-Mult composition failed");
            let c = create_field_extension(
                [
                    0x84e6a5203ee06c1f,
                    0xe454d7444c984683,
                    0x6f93b7fbe3a950f2,
                    0x8d38addcc0f23c3,
                ],
                [
                    0x97037fedf337819b,
                    0xbc9270b6b3447c73,
                    0xef69d13908dccbfd,
                    0x183646045c9d4de4,
                ],
                [
                    0xcdd371606cb11cef,
                    0x73bf89f28ff84711,
                    0x2d8b9a2dfafce09e,
                    0x2e16964414763c9c,
                ],
                [
                    0x79b457c7829a90b9,
                    0x1ed5aeb323fb2bd8,
                    0x3216a5bca91f0262,
                    0x23491bb4c5bf7205,
                ],
                [
                    0x7c147d3f60ed789b,
                    0x6d417fc08b9ed71e,
                    0xac50e9ab55b112fd,
                    0x14cb8703533e40c9,
                ],
                [
                    0xe5ceae140b00664c,
                    0x6d499e720e48f860,
                    0x5f1bb5244a2466aa,
                    0x216c40cb063969a4,
                ],
            );
            assert_eq!(a / b, c, "Simple division failed");
        }
        #[test]
        // #[should_panic(expected = "assertion failed: self.is_some.is_true_vartime()")]
        fn test_divide_by_zero() {
            let a = Fp6::one();
            let b = Fp6::zero();
            let _ = a / b;
        }
    }
    #[test]
    fn conditional_select() {
        let a = create_field_extension(
            [1, 0, 0, 0],
            [0, 2, 0, 0],
            [0, 0, 3, 0],
            [0, 0, 0, 4],
            [5, 0, 0, 0],
            [0, 6, 0, 0],
        );
        let b = create_field_extension(
            [0, 6, 0, 0],
            [5, 0, 0, 0],
            [0, 0, 0, 4],
            [0, 0, 3, 0],
            [0, 2, 0, 0],
            [1, 0, 0, 0],
        );
        assert_eq!(
            Fp6::conditional_select(&a, &b, Choice::from(0u8)),
            a,
            "Failed to select a"
        );
        assert_eq!(
            Fp6::conditional_select(&a, &b, Choice::from(1u8)),
            b,
            "Failed to select b"
        );
        let one = Fp6::one();
        assert!(one.is_one(), "One is not one!");
    }

    #[test]
    fn assignment_tests() {
        let mut a = Fp6::from(10);
        let b = Fp6::from(5);

        // addition
        let c = a + b;
        a += b;

        assert_eq!(c, a, "Addition assignment failed");

        // subtraction
        let mut a = Fp6::from(10);
        let c = a - b;
        a -= b;
        assert_eq!(c, a, "Subtraction assignment failed");

        // multiplication
        let mut a = Fp6::from(10);
        let c = a * b;
        a *= b;
        assert_eq!(c, a, "Multiplication assignment failed");

        // division
        let mut a = Fp6::from(10);
        let c = a / b;
        a /= b;
        assert_eq!(c, a, "Division assignment failed");
    }
    #[test]
    fn test_curve_constant() {
        let curve_constant = <Fp6 as FieldExtensionTrait<6, 3>>::curve_constant();
        let also_curve_constant = <Fp6 as FieldExtensionTrait<12, 2>>::curve_constant();

        let tmp = Fp6::from(3);
        assert!(
            bool::from(curve_constant.ct_eq(&tmp) & also_curve_constant.ct_eq(&tmp)),
            "Curve constant is not 3"
        );
    }
}
