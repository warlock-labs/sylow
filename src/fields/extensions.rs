//! This file dictates the implementation of the field extension struct that implements
//! the appropriate traits. These are not a total list of the mathematical properties
//! that are satisfied by an extension, but is a MWE of the functionality needed herein.
//! Because of the quotienting on the finite field ring, the functional forms of
//! multiplication and division will be specific to the base field, and the
//! form of the extension. Therefore, the only common functionality we can guarantee
//! is addition, subtraction, equality, negation, default, and the zero element.
//!
//! Other specifics must be dealt with on a case-by-case basis.

use crate::fields::fp::FieldExtensionTrait;
use crypto_bigint::subtle::{Choice, ConstantTimeEq};
use num_traits::Zero;
use std::ops::{Add, AddAssign, Neg, Sub, SubAssign};

// the following struct can unfortunately not have much that is const,
// since the underlying Mul, Add, etc., are not, and const traits are in the works
// https://github.com/rust-lang/rust/issues/67792
#[derive(Copy, Clone, Debug)]
pub struct FieldExtension<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>>(
    pub(crate) [F; N],
);

impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> From<u64> for 
FieldExtension<D, N,
F>{
    fn from(value: u64) -> Self {
        let mut retval = [F::zero(); N];
        retval[0] = F::from(value);
        Self::new(&retval)
    }
}
#[allow(dead_code)]
impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> FieldExtension<D, N, F> {
    pub fn new(c: &[F; N]) -> Self {
        Self(*c)
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
impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> ConstantTimeEq
    for FieldExtension<D, N, F>
{
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
impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> Add for FieldExtension<D, N, F> {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        let mut i = 0;
        let mut retval = [F::zero(); N];
        while i < N {
            retval[i] = self.0[i] + other.0[i];
            i += 1;
        }
        Self::new(&retval)
    }
}
impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> AddAssign
    for FieldExtension<D, N, F>
{
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}
impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> Sub for FieldExtension<D, N, F> {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        let mut i = 0;
        let mut retval = [F::zero(); N];
        while i < N {
            retval[i] = self.0[i] - other.0[i];
            i += 1;
        }
        Self::new(&retval)
    }
}
impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> SubAssign
    for FieldExtension<D, N, F>
{
    fn sub_assign(&mut self, other: Self) {
        *self = *self - other;
    }
}
impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> Default
    for FieldExtension<D, N, F>
{
    fn default() -> Self {
        Self::new(&[F::default(); N])
    }
}
impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> PartialEq
    for FieldExtension<D, N, F>
{
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}
impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> Neg for FieldExtension<D, N, F> {
    type Output = Self;
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
