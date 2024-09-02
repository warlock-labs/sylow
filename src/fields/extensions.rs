//! Field Extension Implementation for Elliptic Curve Cryptography
//!
//! This module defines the structure and traits for field extensions used in
//! elliptic curve cryptography. It provides a generic implementation that can
//! be used for various degrees of field extensions.
//!
//! The implementation focuses on the core functionality needed for cryptographic
//! operations, including addition, subtraction, negation, and equality checks.
//! More complex operations like multiplication and division are left to be
//! implemented specifically for each field extension, as they depend on the
//! base field and the form of the extension.
//!
//! # Note
//!
//! This implementation does not provide a complete list of all mathematical
//! properties satisfied by field extensions. Instead, it offers a Minimum Working
//! Example (MWE) of the functionality required for the cryptographic operations
//! in this crate. Therefore, the only common functionality we can guarantee
//! is addition, subtraction, equality, negation, default, and the zero element.
//! Other specifics must be dealt with on a case-by-case basis.

use crate::fields::fp::FieldExtensionTrait;
use crypto_bigint::subtle::{Choice, ConstantTimeEq};
use num_traits::Zero;
use std::ops::{Add, AddAssign, Neg, Sub, SubAssign};

/// A generic struct representing a field extension.
///
/// # Type Parameters
///
/// * `D`: The degree of the field extension.
/// * `N`: The number of elements required for a unique representation in the extension.
/// * `F`: The base field type, which must implement `FieldExtensionTrait<D, N>`.
///
/// # Notes
///
/// The struct cannot have `const` fields due to limitations with the underlying
/// `Mul`, `Add`, etc., traits. Const traits are a work in progress in Rust.
/// See: https://github.com/rust-lang/rust/issues/67792
#[derive(Copy, Clone, Debug)]
pub struct FieldExtension<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>>(
    pub(crate) [F; N],
);

impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> From<u64>
    for FieldExtension<D, N, F>
{
    /// Creates a `FieldExtension` from a `u64` value.
    ///
    /// The resulting extension will have the `u64` value in its first component
    /// and zeros in all other components.
    fn from(value: u64) -> Self {
        let mut retval = [F::zero(); N];
        retval[0] = F::from(value);
        Self::new(&retval)
    }
}
impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> FieldExtension<D, N, F> {
    /// Creates a new `FieldExtension` from a slice of field elements.
    ///
    /// This const constructor allows instantiation of any representation of
    /// an extension needed.
    ///
    /// # Arguments
    ///
    /// * `c`: A slice of field elements representing the extension.
    pub const fn new(c: &[F; N]) -> Self {
        Self(*c)
    }

    /// Scales the field extension element by a factor from the base field.
    ///
    /// This operation is useful for performing multiplication across different
    /// field extensions. It corresponds to a basic scaling operation.
    ///
    /// # Arguments
    ///
    /// * `factor`: A field element used to scale the extension element.
    ///
    /// Note: this is different from multiplying two elements from the same extension, and is
    ///       really a "cross-extension multiplication" in a way.
    ///
    /// # References
    ///
    /// See https://eprint.iacr.org/2010/354.pdf for more information.
    pub(crate) fn scale(&self, factor: F) -> Self {
        let mut i = 0;
        let mut retval = [F::zero(); N];
        while i < N {
            retval[i] = self.0[i] * factor;
            i += 1;
        }
        Self::new(&retval)
    }
}

impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> ConstantTimeEq
    for FieldExtension<D, N, F>
{
    /// Performs a constant-time equality check between two field extensions.
    #[inline(always)]
    fn ct_eq(&self, other: &Self) -> Choice {
        let mut retval = Choice::from(1u8);
        let mut i = 0;
        while i < N {
            retval &= self.0[i].ct_eq(&other.0[i]);
            i += 1;
        }
        retval
    }
}

impl<'a, 'b, const D: usize, const N: usize, F: FieldExtensionTrait<D, N>>
    Add<&'b FieldExtension<D, N, F>> for &'a FieldExtension<D, N, F>
{
    type Output = FieldExtension<D, N, F>;

    /// Adds two field extensions element-wise.
    #[inline]
    fn add(self, other: &'b FieldExtension<D, N, F>) -> Self::Output {
        let mut i = 0;
        let mut retval = [F::zero(); N];
        while i < N {
            retval[i] = self.0[i] + other.0[i];
            i += 1;
        }
        Self::Output::new(&retval)
    }
}

impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> Add<FieldExtension<D, N, F>>
    for FieldExtension<D, N, F>
{
    type Output = Self;
    #[inline]
    fn add(self, other: FieldExtension<D, N, F>) -> Self::Output {
        &self + &other
    }
}

impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> AddAssign
    for FieldExtension<D, N, F>
{
    #[inline]
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

impl<'a, 'b, const D: usize, const N: usize, F: FieldExtensionTrait<D, N>>
    Sub<&'b FieldExtension<D, N, F>> for &'a FieldExtension<D, N, F>
{
    type Output = FieldExtension<D, N, F>;
    #[inline]
    fn sub(self, other: &'b FieldExtension<D, N, F>) -> Self::Output {
        let mut i = 0;
        let mut retval = [F::zero(); N];
        while i < N {
            retval[i] = self.0[i] - other.0[i];
            i += 1;
        }
        Self::Output::new(&retval)
    }
}

impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> Sub<FieldExtension<D, N, F>>
    for FieldExtension<D, N, F>
{
    type Output = Self;
    #[inline]
    fn sub(self, other: FieldExtension<D, N, F>) -> Self::Output {
        &self - &other
    }
}

impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> SubAssign
    for FieldExtension<D, N, F>
{
    #[inline]
    fn sub_assign(&mut self, other: Self) {
        *self = *self - other;
    }
}

impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> Default
    for FieldExtension<D, N, F>
{
    /// Returns the default value for the field extension (all zero elements).
    fn default() -> Self {
        Self::new(&[F::default(); N])
    }
}

impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> PartialEq
    for FieldExtension<D, N, F>
{
    /// Checks if two field extensions are equal.
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> Neg for FieldExtension<D, N, F> {
    type Output = Self;

    /// Negates the field extension element-wise.
    #[inline]
    fn neg(self) -> Self {
        let mut i = 0;
        let mut retval = [F::zero(); N];
        while i < N {
            retval[i] = -self.0[i];
            i += 1;
        }
        Self::new(&retval)
    }
}
impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> Zero
    for FieldExtension<D, N, F>
{
    /// Returns the zero element of the field extension, which is also the additive identity.
    #[inline]
    fn zero() -> Self {
        Self::new(&[F::zero(); N])
    }

    /// Checks if the field extension is the zero element.
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
