use crate::fields::fp::FieldExtensionTrait;
use crypto_bigint::rand_core::CryptoRngCore;
use crypto_bigint::subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use std::ops::{Add, Mul, Neg, Sub};

#[derive(Debug)]
pub enum Error {
    NotOnCurve,
    NotInSubgroup,
}

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
    fn generator() -> Self;
    fn endomorphism(&self) -> Self;
    fn rand<R: CryptoRngCore>(rng: &mut R) -> Self;
}

#[derive(Copy, Clone, Debug)]
pub(crate) struct GroupAffine<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> {
    pub(crate) x: F,
    pub(crate) y: F,
    pub(crate) infinity: Choice,
}
/// this is the beginning of Rust lifetime magic. The issue is that when we implement
/// the arithmetic, we need to explicitly state the lifetime of each operand
/// so that they can be dropped immediately after they're not needed for security,
/// to prevent rogue curve attacks. This subtle point requires that binary operations
/// be defined for specific lifetimes, and then we must specialize them for typical
/// usage with the symbolic operators (+, -, etc.).
///
/// One other final note is that we do all required curve and subgroup checks with the usage
///  of the `new` builder. In this case, the code will throw an error and the time of
/// instantiation if the inputs do not satisfy the curve equation or r-torsion subgroup check.
/// Therefore, negation, conditional selection, and equality defined below don't need to use the
/// `new` builder, because in order to do these arithmetics on points, they must first exist, and
/// we design it so that they cannot exist strictly unless they are valid points.
///
/// When we define addition, subtraction, multiplication, etc., we use the `new` construct
/// to robustly enforce that the result of arithmetic stays on the curve, and in the r-torsion.
impl<'a, const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> Neg
    for &'a GroupAffine<D, N, F>
{
    type Output = GroupAffine<D, N, F>;

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
    fn neg(self) -> Self::Output {
        -&self
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
impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> GroupAffine<D, N, F> {
    // this needs to be defined in order to have user interaction, but currently
    // is only visible in tests, and therefore is seen by the linter as unused
    #[allow(dead_code)]
    pub fn new(v: [F; 2]) -> Result<Self, Error> {
        let _g1affine_is_on_curve = |x: &F, y: &F, z: &Choice| -> Choice {
            let y2 = F::square(y);
            let x2 = F::square(x);
            let lhs = y2 - (x2 * (*x));
            let rhs = F::from(3u64);
            // println!("{:?}, {:?}", lhs, rhs);
            lhs.ct_eq(&rhs) | *z
        };

        let _g1affine_is_torsion_free = |_x: &F, _y: &F, _z: &Choice| -> Choice {
            // every point in G1 on the curve is in the r-torsion of BN254
            Choice::from(1u8)
        };
        let is_on_curve: Choice = _g1affine_is_on_curve(&v[0], &v[1], &Choice::from(0u8));
        match bool::from(is_on_curve) {
            true => {
                // println!("Is on curve!");
                let is_in_torsion: Choice =
                    _g1affine_is_torsion_free(&v[0], &v[1], &Choice::from(0u8));
                match bool::from(is_in_torsion) {
                    true => Ok(Self {
                        x: v[0],
                        y: v[1],
                        infinity: Choice::from(0u8),
                    }),
                    _ => Err(Error::NotInSubgroup),
                }
            }
            false => Err(Error::NotOnCurve),
        }
    }
    pub(crate) fn zero() -> Self {
        Self {
            x: F::zero(),
            y: F::one(),
            infinity: Choice::from(1u8),
        }
    }
    #[allow(dead_code)]
    pub(crate) fn is_zero(&self) -> bool {
        bool::from(self.infinity)
    }
}
#[derive(Copy, Clone, Debug)]
pub(crate) struct GroupProjective<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> {
    pub(crate) x: F,
    pub(crate) y: F,
    pub(crate) z: F,
}
impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> GroupProjective<D, N, F> {
    pub fn new(v: [F; 3]) -> Result<Self, Error> {
        let _g1projective_is_on_curve = |x: &F, y: &F, z: &F| -> Choice {
            let y2 = F::square(y);
            let x2 = F::square(x);
            let z2 = F::square(z);
            let lhs = y2 * (*z);
            let rhs = x2 * (*x) + z2 * (*z) * F::from(3u64);
            // println!("{:?}, {:?}", lhs.value(), rhs.value());
            lhs.ct_eq(&rhs) | Choice::from(z.is_zero() as u8)
        };
        let _g1projective_is_torsion_free =
            |_x: &F, _y: &F, _z: &F| -> Choice { Choice::from(1u8) };
        let is_on_curve: Choice = _g1projective_is_on_curve(&v[0], &v[1], &v[2]);
        match bool::from(is_on_curve) {
            true => {
                // println!("Is on curve!");
                let is_in_torsion: Choice = _g1projective_is_torsion_free(&v[0], &v[1], &v[2]);
                match bool::from(is_in_torsion) {
                    true => Ok(Self {
                        x: v[0],
                        y: v[1],
                        z: v[2],
                    }),
                    false => Err(Error::NotOnCurve),
                }
            }
            false => Err(Error::NotOnCurve),
        }
    }
    // this is the point at infinity!
    pub(crate) fn zero() -> Self {
        Self {
            x: F::zero(),
            y: F::one(),
            z: F::zero(),
        }
    }
    #[allow(dead_code)]
    pub(crate) fn is_zero(&self) -> bool {
        self.z.is_zero()
    }
    pub(crate) fn double(&self) -> Self {
        let t0 = self.y *self.y;
        let z3 = t0 + t0 ;
        let z3 = z3 + z3;
        
        let z3 = z3 + z3 ;
        let t1 = self.y * self.z ;
        let t2 = self.z*self.z;
        
        let t2 = F::from(9) * t2 ;
        let x3 = t2 * z3 ;
        let y3 = t0 + t2 ;
        
        let z3 = t1 * z3 ;
        let t1 = t2 + t2 ;
        let t2 = t1 + t2 ;
        
        let t0 = t0 - t2 ;
        let y3 = t0 * y3 ;
        let y3 = x3 + y3 ;
        
        let t1 = self.x * self.y ;
        let x3 = t0 * t1 ;
        let x3 = x3 + x3 ;
        Self::new([x3, y3, z3]).expect("Doubling failed")
    }
}

impl<'a, const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> Neg
    for &'a GroupProjective<D, N, F>
{
    type Output = GroupProjective<D, N, F>;

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
    fn neg(self) -> Self::Output {
        -&self
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
/// Allow for conversion between the forms. This will only be used for user interaction and
/// debugging.

impl<'a, const D: usize, const N: usize, F: FieldExtensionTrait<D, N>>
    From<&'a GroupProjective<D, N, F>> for GroupAffine<D, N, F>
{
    fn from(arg: &'a GroupProjective<D, N, F>) -> Self {
        let inverse = arg.z.inv(); // this is either a good value or zero, see `inv` in `fp.rs`
        let x = arg.x * inverse;
        let y = arg.y * inverse;

        GroupAffine::conditional_select(
            &GroupAffine::new([x, y]).expect("Conversion to affine coordinates failed"),
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
    fn from(value: &'a GroupAffine<D, N, F>) -> Self {
        Self::new([
            value.x,
            value.y,
            F::conditional_select(&F::one(), &F::zero(), value.infinity),
        ])
        .expect("Conversion to projective coordinates failed")
    }
}
impl<const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> From<GroupAffine<D, N, F>>
    for GroupProjective<D, N, F>
{
    fn from(value: GroupAffine<D, N, F>) -> Self {
        GroupProjective::from(&value)
    }
}
/// Implementing addition and multiplication requires some thought. There are three ways that we
/// could in theory do it: (i) have both points in affine coords, (ii) have both points in
/// projective coords, or (iii) have mixed representations. For security, we do not want to have
/// point arithmetic done in affine coordinates, because an arbitrary sequence of binary operations
/// is able to generate the point at infinity, which has no uniquely defined representation in
/// affine coordinates, and opens up our implementation to attack vectors, that could be easily
/// avoided with arithmetic in projective coordinates, where affine points are identified
/// with `z=1`, and points at infinity have `z=0`. The uniqueness of the representation of the
/// z coordinate is what provides security. We therefor opt to have all arithmetic done
/// in projective coordinates. All arithmetic is defined only on projective coordinates for
/// security.
///
/// An excellent reference for these formulae lies in (1).
///
/// (1): <https://eprint.iacr.org/2015/1060.pdf>.
///

/// we first define addition / subtraction when coords are both projective.
impl<'a, 'b, const D: usize, const N: usize, F: FieldExtensionTrait<D, N>>
    Add<&'b GroupProjective<D, N, F>> for &'a GroupProjective<D, N, F>
{
    type Output = GroupProjective<D, N, F>;
    #[allow(clippy::collapsible_else_if)]
    fn add(self, other: &'b GroupProjective<D, N, F>) -> Self::Output {
        let t0 = self.x * other.x ;
        let t1 = self.y * other.y ;
        let t2 = self.z * other.z ;
        
        let t3 = self.x + self.y ;
        let t4 = other.x + other.y ;
        let t3 = t3 * t4 ;
        
        let t4 = t0 + t1 ;
        let t3 = t3 - t4 ;
        let t4 = self.y + self.z ;
        
        let x3 = other.y + other.z ;
        let t4 = t4 * x3 ;
        let x3 = t1 + t2 ;
        
        let t4 = t4 - x3 ;
        let x3 = self.x + self.z ;
        let y3 = other.x + other.z ;
        
        let x3 = x3 * y3 ;
        let y3 = t0 + t2 ;
        let y3 = x3 - y3 ;
        
        let x3 = t0 + t0 ;
        let t0 = x3 + t0 ;
        let t2 = F::from(9) * t2 ;
        
        let z3 = t1 + t2 ;
        let t1 = t1 - t2 ;
        let y3 = F::from(9) * y3 ;
        
        let x3 = t4 * y3 ;
        let t2 = t3 * t1 ;
        let x3 = t2 - x3 ;
        
        let y3 = y3 * t0 ;
        let t1 = t1 * z3 ;
        let y3 = t1 + y3 ;
        
        let t0 = t0 * t3 ;
        let z3 = z3 * t4 ;
        let z3 = z3 + t0 ;
        Self::Output::new([x3, y3, z3]).expect("Addition failed")
    }
}
#[allow(clippy::suspicious_arithmetic_impl)]
impl<'a, 'b, const D: usize, const N: usize, F: FieldExtensionTrait<D, N>>
    Sub<&'b GroupProjective<D, N, F>> for &'a GroupProjective<D, N, F>
{
    type Output = GroupProjective<D, N, F>;
    fn sub(self, other: &'b GroupProjective<D, N, F>) -> Self::Output {
        self + &(-other)
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl<'a, 'b, const D: usize, const N: usize, F: FieldExtensionTrait<D, N>> Mul<&'b [u8]>
    for &'a GroupProjective<D, N, F>
{
    type Output = GroupProjective<D, N, F>;
    fn mul(self, other: &'b [u8]) -> Self::Output {
        let mut res = Self::Output::zero();
        for bit in other.iter().rev() {
            for i in (0..8).rev() {
                res = res.double();
                if (bit & (1 << i)) != 0 {
                    res = &res + self;
                }
            }
        }
        res
    }
}
