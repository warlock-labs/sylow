use crypto_bigint::subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use std::ops::Neg;

use crate::fields::fp::FieldExtensionTrait;

#[derive(Debug)]
pub enum Error { NotOnCurve, NotInSubgroup, }

pub(crate) trait GroupTrait<const D: usize, const N: usize, F: FieldExtensionTrait<D,N>>:
Sized
+ Copy
+ Clone
+ std::fmt::Debug
// + Default // cannot be implemented without one
// + One //cannot be implemented without addition, which is very specific to the choice of affine,
//projective, or mixed addition, and therefore cannot be defined for all instances satisfying 
//a group trait
+ Neg
+ ConstantTimeEq
+ ConditionallySelectable
+ PartialEq
{
    fn is_on_curve(&self) -> Choice;
    fn is_torsion_free(&self) -> Choice;
    fn generator() -> Self;
    fn endomorphism(&self) -> Self;
    fn one() -> Self;
    fn is_one(&self) -> bool;
}

#[derive(Copy, Clone, Debug)]
pub struct GroupAffine<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> {
    pub(crate) x: F,
    pub(crate) y: F,
    pub(crate) infinity: Choice,
}

impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> Neg for GroupAffine<D, N, F> {
    type Output = Self;

    fn neg(self) -> Self {
        Self {
            x: self.x,
            y: F::conditional_select(&-self.y, &F::one(), self.infinity),
            infinity: self.infinity,
        }
    }
}

impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> ConstantTimeEq
    for GroupAffine<D, N, F>
{
    fn ct_eq(&self, other: &Self) -> Choice {
        // either they're both infinity, or neither are and the coords match
        (self.infinity & other.infinity)
            | ((!self.infinity)
                & (!other.infinity)
                & self.x.ct_eq(&other.x)
                & self.y.ct_eq(&other.y))
    }
}

impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> ConditionallySelectable
    for GroupAffine<D, N, F>
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            x: F::conditional_select(&a.x, &b.x, choice),
            y: F::conditional_select(&a.y, &b.y, choice),
            infinity: Choice::conditional_select(&a.infinity, &b.infinity, choice),
        }
    }
}

impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> PartialEq
    for GroupAffine<D, N, F>
{
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

#[derive(Copy, Clone, Debug)]
pub struct GroupProjective<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> {
    pub(crate) x: F,
    pub(crate) y: F,
    pub(crate) z: F,
}

impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> Neg
    for GroupProjective<D, N, F>
{
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self {
            x: self.x,
            y: -self.y,
            z: self.z,
        }
    }
}
impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> ConstantTimeEq
    for GroupProjective<D, N, F>
{
    fn ct_eq(&self, other: &Self) -> Choice {
        // are the points the same when converted to affine
        let x0 = self.x * other.z;
        let x1 = other.x * self.z;

        let y0 = self.y * other.z;
        let y1 = other.y * self.z;

        let i_am_zero = self.z.is_zero();
        let you_are_zero = other.z.is_zero();

        let decision = (i_am_zero & you_are_zero) // Both point at infinity
            | ((!i_am_zero) & (!you_are_zero) & bool::from(x0.ct_eq(&x1)) & bool::from(y0.ct_eq
        (&y1)));
        Choice::from(decision as u8)
    }
}
impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> ConditionallySelectable
    for GroupProjective<D, N, F>
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            x: F::conditional_select(&a.x, &b.x, choice),
            y: F::conditional_select(&a.y, &b.y, choice),
            z: F::conditional_select(&a.z, &b.z, choice),
        }
    }
}
impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> PartialEq
    for GroupProjective<D, N, F>
{
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}
