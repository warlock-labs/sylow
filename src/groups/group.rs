//! Implementation of elliptic curve group operations for BN254.
//!
//! Key features:
//! - Generic implementations for affine and projective coordinate systems
//! - Constant-time operations for improved security
//! - Optimized algorithms for BN254's specific properties
//! - Support for scalar multiplication, addition, and other group operations
//!
//! This module implements the basic building blocks of the groups on elliptic curves.
//! The group operation are the tangent and chord rules, see Ref 1. To be consistent
//! with the generic trait usage done in the construction of an element of the underlying base
//! field, we implement as much of the functionality that is common among all groups, all
//! representations, and all base fields into a trait here. Inclusion of underlying guarantees
//! of scalar multiplication, etc., defined are inherited directly from the `FieldExtensionTrait`.
//! The implementation we consider here uses algorithms for the underlying point arithmetic that
//! are modified / optimized for stronger guarantees of constant time execution, and are "complete"
//! algorithms. Here, "complete" refers to the fact that the algorithms themselves have
//! absolutely no exceptions in them, caused by, for example, a value being the point at infinity.
//! In this way, they do not have any internal branches, improving execution performance.
//!
//! The algorithms are further specialise for BN254, in the sense that BN254 is a j-invariant 0
//! curve, and as such we can reduce the computational overhead of doubling and addition (and
//! therefore multiplication). The interested reader is invited to peruse Refs 2-3 for more details.
//!
//! References:
//! 1. [Moonmath Manual](https://github.com/LeastAuthority/moonmath-manual/releases/latest/download/main-moonmath.pdf)
//! 2. [Faster Explicit Formulas for Computing Pairings over Ordinary Curves](https://eprint.iacr.org/2015/1060.pdf)
//! 3. [Faster Computation of the Tate Pairing](https://marcjoye.github.io/papers/BJ02espa.pdf)

use crate::fields::fp::{FieldExtensionTrait, Fp};
use crate::hasher::Expander;
use crypto_bigint::rand_core::CryptoRngCore;
use crypto_bigint::subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use std::ops::{Add, Mul, Neg, Sub};

/// Errors that can occur when working with group elements.
#[derive(Debug, Copy, Clone)]
pub enum GroupError {
    /// The point is not on the curve
    NotOnCurve,
    /// The point is not in the r-torsion subgroup
    NotInSubgroup,
    /// The point cannot be hashed to the group
    CannotHashToGroup,
    /// The point cannot be decoded
    DecodeError,
}

// TODO(Why not just call this `Group`?)
// Also, wen noether?

/// Defines the basic operations for elliptic curve group elements.
///
/// This trait implements the basic requirements of an element to be a group element.
///
/// Unfortunately, `Default` cannot be implemented without `One`, which cannot be implemented
/// without `Add`, which is very specific to the choice of affine,
/// projective, or mixed addition, and therefore cannot be defined for all instances satisfying
/// a group trait
pub trait GroupTrait<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>>:
    Sized
    + Copy
    + Clone
    + std::fmt::Debug
    + Neg
    + ConstantTimeEq
    + ConditionallySelectable
    + PartialEq
    + Default
{
    /// Returns the generator point for the group.
    ///
    /// This is how one may make more elements of the field from a scalar value
    /// The value returned by this will be a hard-coded compile-time constant that will depend on
    /// the specific group
    fn generator() -> Self;

    /// Applies the Frobenius endomorphism to the point.
    ///
    /// This is the "untwist-Frobenius-twist" endomorphism, ψ(q) = u ∘ π ∘ u⁻¹,
    /// where u: E' → E is the isomorphism from the twist to the curve E,
    /// and π is the Frobenius map.
    ///
    /// For BN254, this simplifies to:
    /// (x, y) ↦ (x^p * ξ^((p-1)/3), y^p * ξ^((p-1)/2))
    ///
    /// Note: This function is primarily meaningful for 𝔾₂ elements.
    ///
    /// This is deceptively simple, yet was tedious to get correct. This is the
    /// "untwist-Frobenius-twist" endomorphism, ψ(q) = u o π o u⁻¹ where u:E'→E is the
    /// isomorphism
    /// from the twist to the curve E and π is the Frobenius map. This is a complicated
    /// topic, and a full
    /// description is out of scope for a code comment. Nonetheless, we require the usage of
    /// an endomorphism for subgroup checks in $\mathbb{G}_2$. This one offers nice
    /// computational
    /// benefits, and can be decomposed as follows:
    /// 1. twist:        this is the map u that takes (x', y') |-> (w^2,x', w^3y'), where
    ///                  $w\in\mathbb{F_{p^{12}}$ is a root of $X^6-\xi$. This is an
    ///                  injective map (that is not surjective), that maps the r-torsion to an
    ///                  equivalent subgroup in the algebraic closure of the base field.
    /// 2. Frobenius:    this is the map π that is difficult to succinctly explain, but more or
    ///                  less identifies the kernel of the twist operation, namely those points
    ///                  in the algebraic closure that satisfy rQ=0.
    /// 3. untwist:      having identified the points in the closure that satisfy the r-torsion
    ///                  requirement, we map them back to the curve in Fp2.
    ///
    /// This endomorphism therefore encodes the torsion of a point in a compact,
    /// computationally efficient way. All of this fancy stuff equates simply, and remarkably,
    /// to the following:
    /// (x,y) |-> (x^p * \xi^((p-1)/3), y^p*\xi^((p-1)/2))
    ///
    /// Note that this function will only be meaningful implemented to G2 elements.
    fn endomorphism(&self) -> Self;

    // TODO(Seems like a possible source of leaky abstraction)
    /// Generates a random point on the curve.
    ///
    /// # Arguments
    ///
    /// * `rng` - A cryptographic random number generator
    fn rand<R: CryptoRngCore>(rng: &mut R) -> Self;

    /// Hashes a message to a point on the curve.
    ///
    /// This method uses the `expand_message` and Shallue-van de Woestijne (SvdW) algorithms
    /// as specified in RFC 9380.  see `hasher.rs` and `svdw.rs` for more details.
    ///
    /// # Arguments
    ///
    /// * `exp` - An object implementing the `Expander` trait
    /// * `msg` - The message to be hashed
    ///
    /// # Returns
    ///
    /// A `Result` containing either the hashed point or a `GroupError`
    fn hash_to_curve<E: Expander>(exp: &E, msg: &[u8]) -> Result<Self, GroupError>;

    /// Signs a message using a private key generic over `F`.
    ///
    /// # Arguments
    ///
    /// * `exp` - An object implementing the `Expander` trait
    /// * `msg` - The message to be signed
    /// * `private_key` - The private key used for signing
    ///
    /// # Returns
    ///
    /// A `Result` containing either the signature point or a `GroupError`
    fn sign_message<E: Expander>(exp: &E, msg: &[u8], private_key: F) -> Result<Self, GroupError>;

    // NOTA BENE: the frobenius map does NOT in general map points from the curve back to the curve
    // It is an endomorphism of the algebraic closure of the base field, but NOT of the curve
    // Therefore, these points must bypass curve membership and torsion checks, and therefore
    // directly be instantiated as a struct
    //
    // This performs the operation:
    // (x,y) |-> (x^p, y^p)
    //
    // # Arguments
    // * `exponent` - usize, the exponent to raise the point to
    // #[allow(dead_code)]
    // fn frobenius(&self, exponent: usize) -> Self;
}

/// Affine representation of a point on an elliptic curve.
///
/// This is the implementation of a point on the curve in affine coordinates. It is not possible
/// to directly input a pair of x, y such that infinity is True, since the point at infinity
/// has no unique representation in this form. Generation of the point at infinity is achieved
/// either by calling the `zero` method, or by applying binary operations to 'normal' points to
/// reach the point at infinity with arithmetic.
#[derive(Copy, Clone, Debug)]
pub struct GroupAffine<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> {
    /// x-coordinate
    pub(crate) x: F,
    /// y-coordinate
    pub(crate) y: F,
    /// Flag indicating if this is the point at infinity
    pub(crate) infinity: Choice,
}

// This is the beginning of Rust lifetime magic. The issue is that when we implement
// the arithmetic, we need to explicitly state the lifetime of each operand
// so that they can be dropped immediately after they're not needed for security.
// This subtle point requires that binary operations
// be defined for specific lifetimes, and then we must specialize them for typical
// usage with the symbolic operators (+, -, etc.) so that all arithmetic is defined by reference
// and not by a copy.
//
// One other final note is that we do all required curve and subgroup checks with the usage
//  of the `new` builder. In this case, the code will throw an error at the time of
// instantiation if the inputs do not satisfy the curve equation or r-torsion subgroup check.
// Therefore, negation, conditional selection, and equality defined below don't need to use the
// `new` builder, because to do these arithmetics on points, they must first exist, and
// we design it so that they cannot exist strictly unless they are valid points.
//
// When we define addition, subtraction, multiplication, etc., we use the `new` construct
// to robustly enforce that the result of arithmetic stays on the curve, and in the r-torsion.

impl<'a, const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> Neg
    for &'a GroupAffine<D, N, F>
{
    type Output = GroupAffine<D, N, F>;

    /// Negates the point.
    /// For a point (x, y), the negation is (x, -y) if the point is not at infinity.
    /// If the point is at infinity, it remains unchanged.
    #[inline]
    fn neg(self) -> Self::Output {
        Self::Output {
            x: self.x,
            y: F::conditional_select(&-self.y, &F::one(), self.infinity),
            infinity: self.infinity,
        }
    }
}

impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> Neg for GroupAffine<D, N, F> {
    type Output = GroupAffine<D, N, F>;

    /// Negates the point, deferring to the reference implementation.
    #[inline]
    fn neg(self) -> Self::Output {
        -&self
    }
}

impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> ConstantTimeEq
    for GroupAffine<D, N, F>
{
    /// Compares two points for equality in constant time.
    ///
    /// Points are equal if they are both at infinity, or if neither is at infinity and their coordinates match.
    fn ct_eq(&self, other: &Self) -> Choice {
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
    /// Selects between two points based on a `Choice` value.
    /// This operation is performed in constant time.
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
    /// Checks if two points are equal.
    /// This is a wrapper around the constant-time equality check.
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> GroupAffine<D, N, F> {
    /// Creates a new point at infinity.
    pub(crate) fn zero() -> Self {
        Self {
            x: F::zero(),
            y: F::one(),
            infinity: Choice::from(1u8),
        }
    }

    /// Checks if the point is at infinity.
    #[inline(always)]
    pub(crate) fn is_zero(&self) -> bool {
        bool::from(self.infinity)
    }
}

impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> Default
    for GroupAffine<D, N, F>
{
    /// The default value for a point is the point at infinity.
    fn default() -> Self {
        Self::zero()
    }
}

/// Represents a point on an elliptic curve in projective coordinates.
///
/// In projective coordinates, a point is represented by (X:Y:Z), where the corresponding
/// affine coordinates are (X/Z, Y/Z) when Z ≠ 0. The point at infinity is represented by Z = 0.
///
/// This representation allows for more efficient group operations compared to affine coordinates,
/// as it avoids expensive field inversions in most cases.
#[derive(Copy, Clone, Debug)]
pub struct GroupProjective<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> {
    // We now define the projective representation of a point on the curve. Here, the point(s) at
    // infinity is (are) indicated by `z=0`. This allows the user to therefore directly generate
    // such a point with the associated `new` method. Affine coordinates are those indicated by `z=1`.
    // Therefore, the user could input a `Z>1`, but this would fail the curve check, and therefore
    // make the code panic.
    // Implementing addition and multiplication requires some thought. There are three ways that we
    // could in theory do it: (i) have both points in affine coords, (ii) have both points in
    // projective coords, or (iii) have mixed representations. For security, due to the uniqueness of
    // the representation of the point at infinity, we therefore opt to have
    // all arithmetic done in projective coordinates.
    pub(crate) x: F,
    pub(crate) y: F,
    pub(crate) z: F,
}
impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> GroupProjective<D, N, F> {
    /// Returns the point at infinity (the additive identity of the group).
    pub fn zero() -> Self {
        // This is the point at infinity! This object really is the additive identity of the group,
        // when the group law is addition, which it is here. It satisfies the properties that
        // $zero+a=a$ for some $a$ in the group, as well as $a+(-a)=zero$, which means that the
        // convention zero makes the most sense to me here.
        Self {
            x: F::zero(),
            y: F::one(),
            z: F::zero(),
        }
    }

    /// Checks if this point is the point at infinity.
    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        self.z.is_zero()
    }

    /// Doubles this point using an optimized algorithm for curves with j-invariant 0.
    pub fn double(&self) -> Self {
        // This implementation is based on Algorithm 9 from a Ref (1) above - since BN254 has
        // j-invariant 0, we can use some nice simplifications to the arithmetic.
        //
        // Complexity:
        //        `6M`(ultiplications) + `2S`(quarings)
        //      + `1m`(ultiplication by scalar) + `9A`(dditions)
        let t0 = self.y * self.y;
        let z3 = t0 + t0;
        let z3 = z3 + z3;
        tracing::trace!(?t0, ?z3, "GroupProjective::double 1");

        let z3 = z3 + z3;
        let t1 = self.y * self.z;
        let t2 = self.z * self.z;
        tracing::trace!(?z3, ?t1, ?t2, "GroupProjective::double 2");

        // the magic 3 below is an artifact directly from the algorithm itself,
        // see the main text in Ref (1) Alg. (9)
        let t2 = F::from(3) * F::curve_constant() * t2;
        let x3 = t2 * z3;
        let y3 = t0 + t2;
        tracing::trace!(?t2, ?x3, ?y3, "GroupProjective::double 3");

        let z3 = t1 * z3;
        let t1 = t2 + t2;
        let t2 = t1 + t2;
        tracing::trace!(?z3, ?t1, ?t2, "GroupProjective::double 3");

        let t0 = t0 - t2;
        let y3 = t0 * y3;
        let y3 = x3 + y3;
        tracing::trace!(?t0, ?y3, "GroupProjective::double 4");

        let t1 = self.x * self.y;
        let x3 = t0 * t1;
        let x3 = x3 + x3;
        tracing::trace!(?t1, ?x3, "GroupProjective::double 5");
        Self::conditional_select(
            &Self {
                x: x3,
                y: y3,
                z: z3,
            },
            &Self::zero(),
            Choice::from(self.is_zero() as u8),
        )
    }
}

impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> Default
    for GroupProjective<D, N, F>
{
    /// Returns the default value for this type (the point at infinity).
    fn default() -> Self {
        Self::zero()
    }
}

impl<'a, const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> Neg
    for &'a GroupProjective<D, N, F>
{
    type Output = GroupProjective<D, N, F>;

    /// Negates this point.
    #[inline]
    fn neg(self) -> Self::Output {
        Self::Output {
            x: self.x,
            y: -self.y,
            z: self.z,
        }
    }
}

impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> Neg
    for GroupProjective<D, N, F>
{
    type Output = Self;

    /// Negates this point, deferring to the reference implementation.
    #[inline]
    fn neg(self) -> Self::Output {
        -&self
    }
}

impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> ConstantTimeEq
    for GroupProjective<D, N, F>
{
    /// Compares two points for equality in constant time.
    fn ct_eq(&self, other: &Self) -> Choice {
        // are the points the same when converted to affine
        let x0 = self.x * other.z;
        let x1 = other.x * self.z;

        let y0 = self.y * other.z;
        let y1 = other.y * self.z;
        tracing::trace!(?x0, ?x1, ?y0, ?y1, "GroupProjective::ct_eq");

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
    /// Selects between two points based on a `Choice` value in constant time.
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
    /// Checks if two points are equal.
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

// Allow for conversion between the forms. This will only be used for user interaction and
// debugging.

impl<'a, const D: usize, const N: usize, F: FieldExtensionTrait<D, N>>
    From<&'a GroupProjective<D, N, F>> for GroupAffine<D, N, F>
{
    /// Converts a projective point to affine coordinates.
    fn from(arg: &'a GroupProjective<D, N, F>) -> Self {
        let inverse = arg.z.inv(); // this is either a good value or zero, see `inv` in `fp.rs`
        let x = arg.x * inverse;
        let y = arg.y * inverse;
        tracing::trace!(?x, ?y, "GroupAffine::from(GroupProjective)");

        GroupAffine::conditional_select(
            &GroupAffine {
                x,
                y,
                infinity: Choice::from(0u8),
            },
            &GroupAffine::zero(),
            Choice::from(inverse.is_zero() as u8),
        )
    }
}

impl<const D: usize, const N: usize, F> From<GroupProjective<D, N, F>> for GroupAffine<D, N, F>
where
    F: FieldExtensionTrait<D, N>,
{
    fn from(value: GroupProjective<D, N, F>) -> GroupAffine<D, N, F> {
        GroupAffine::from(&value)
    }
}

impl<'a, const D: usize, const N: usize, F: FieldExtensionTrait<D, N>>
    From<&'a GroupAffine<D, N, F>> for GroupProjective<D, N, F>
{
    /// Converts a projective point to affine coordinates, deferring to the reference implementation.
    fn from(value: &'a GroupAffine<D, N, F>) -> Self {
        Self {
            x: value.x,
            y: value.y,
            z: F::conditional_select(&F::one(), &F::zero(), value.infinity),
        }
    }
}

impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> From<GroupAffine<D, N, F>>
    for GroupProjective<D, N, F>
{
    /// Converts an affine point to projective coordinates.
    fn from(value: GroupAffine<D, N, F>) -> Self {
        GroupProjective::from(&value)
    }
}

impl<'a, 'b, const D: usize, const N: usize, F: FieldExtensionTrait<D, N>>
    Add<&'b GroupProjective<D, N, F>> for &'a GroupProjective<D, N, F>
{
    type Output = GroupProjective<D, N, F>;

    /// Adds two points in projective coordinates.
    #[inline]
    fn add(self, other: &'b GroupProjective<D, N, F>) -> Self::Output {
        // We implement algorithm 7 from Ref (1) above.
        //
        // Complexity:
        //        `12M` + `2m` + `19A`
        let t0 = self.x * other.x;
        let t1 = self.y * other.y;
        let t2 = self.z * other.z;
        tracing::trace!(?t0, ?t1, ?t1, "GroupProjective::add 1");

        let t3 = self.x + self.y;
        let t4 = other.x + other.y;
        let t3 = t3 * t4;
        tracing::trace!(?t3, ?t4, "GroupProjective::add 2");

        let t4 = t0 + t1;
        let t3 = t3 - t4;
        let t4 = self.y + self.z;
        tracing::trace!(?t3, ?t4, "GroupProjective::add 3");

        let x3 = other.y + other.z;
        let t4 = t4 * x3;
        let x3 = t1 + t2;
        tracing::trace!(?x3, ?t4, "GroupProjective::add 4");

        let t4 = t4 - x3;
        let x3 = self.x + self.z;
        let y3 = other.x + other.z;
        tracing::trace!(?t4, ?x3, ?y3, "GroupProjective::add 5");

        let x3 = x3 * y3;
        let y3 = t0 + t2;
        let y3 = x3 - y3;
        tracing::trace!(?x3, ?y3, "GroupProjective::add 6");

        // again, the magic 3 below is an artifact from the algorithm itself,
        // see the main text of Ref (1) Alg. (7) above
        let x3 = t0 + t0;
        let t0 = x3 + t0;
        let t2 = F::from(3) * F::curve_constant() * t2;

        let z3 = t1 + t2;
        let t1 = t1 - t2;
        let y3 = F::from(3) * F::curve_constant() * y3;
        tracing::trace!(?x3, ?t0, ?t2, ?z3, ?t1, ?y3, "GroupProjective::add 7");

        let x3 = t4 * y3;
        let t2 = t3 * t1;
        let x3 = t2 - x3;

        let y3 = y3 * t0;
        let t1 = t1 * z3;
        let y3 = t1 + y3;

        let t0 = t0 * t3;
        let z3 = z3 * t4;
        let z3 = z3 + t0;
        tracing::trace!(?x3, ?t2, ?y3, ?t1, ?t0, ?z3, "GroupProjective::add 8");
        Self::Output {
            x: x3,
            y: y3,
            z: z3,
        }
    }
}

impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> Add<GroupProjective<D, N, F>>
    for GroupProjective<D, N, F>
{
    type Output = Self;

    /// Adds two points, deferring to the reference implementation.
    #[inline]
    fn add(self, rhs: GroupProjective<D, N, F>) -> Self::Output {
        &self + &rhs
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl<'a, 'b, const D: usize, const N: usize, F: FieldExtensionTrait<D, N>>
    Sub<&'b GroupProjective<D, N, F>> for &'a GroupProjective<D, N, F>
{
    type Output = GroupProjective<D, N, F>;

    /// Subtracts one point from another.
    #[inline]
    fn sub(self, other: &'b GroupProjective<D, N, F>) -> Self::Output {
        self + &(-other)
    }
}

impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> Sub<GroupProjective<D, N, F>>
    for GroupProjective<D, N, F>
{
    type Output = Self;

    /// Subtracts one point from another, without lifetimes
    #[inline]
    fn sub(self, rhs: GroupProjective<D, N, F>) -> Self::Output {
        &self - &rhs
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl<'a, 'b, const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> Mul<&'b Fp>
    for &'a GroupProjective<D, N, F>
{
    /// Multiplies a point by a scalar using the double-and-add algorithm.
    ///
    /// This is the elliptic curve equivalent of the square-and-multiply algorithm used in modular exponentiation.
    /// It uses a lower Hamming weight representation of the scalar to reduce the number of operations.
    ///
    /// <https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Double-and-add>
    type Output = GroupProjective<D, N, F>;
    fn mul(self, other: &'b Fp) -> Self::Output {
        let (np, nm) = other.compute_naf();
        let mut res = Self::Output::zero();

        for i in (0..256).rev() {
            res = res.double();

            let np_bit = np.bit(i).into();
            let nm_bit = nm.bit(i).into();

            if np_bit {
                res = &res + self;
            } else if nm_bit {
                res = &res - self;
            }
        }
        res
    }
}

impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> Mul<Fp>
    for GroupProjective<D, N, F>
{
    type Output = Self;

    /// Multiplies a point by a scalar, deferring to the reference implementation.
    #[inline]
    fn mul(self, rhs: Fp) -> Self::Output {
        &self * &rhs
    }
}
