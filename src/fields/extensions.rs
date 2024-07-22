use num_traits::Zero;
use std::ops::{Add, AddAssign, Neg, Sub, SubAssign};
use crate::fields::fp::FieldExtensionTrait;
// the following struct can unfortunately not have much that is const,
// since the underlying Mul, Add, etc., are not, and const traits are in the works
// https://github.com/rust-lang/rust/issues/67792

//items needed only for field extension
// new, scale, add(assign), sub(assign), default, eq, neg, zero

#[derive(Copy, Clone, Debug)]
pub struct FieldExtension<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>>(
    pub(crate) [F; N],
);

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
impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> Add for FieldExtension<D, N, F> {
    type Output = Self;
    fn add(self, other: Self) -> Self::Output {
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
    fn sub(self, other: Self) -> Self::Output {
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
    fn eq(&self, other: &Self) -> bool {
        let mut i = 0;
        let mut retval = true;
        while i < N {
            retval &= self.0[i] == other.0[i];
            i += 1;
        }
        retval
    }
}
impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> Neg for FieldExtension<D, N, F> {
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
