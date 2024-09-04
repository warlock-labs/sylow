use crate::fields::fp::{FieldExtensionTrait, Fp, Fr};
use crate::fields::fp12::Fp12;
use crate::fields::fp2::Fp2;
use crate::fields::fp6::Fp6;
use crate::groups::group::{GroupError, GroupTrait};
use crate::hasher::Expander;
use crate::pairing::MillerLoopResult;
use crypto_bigint::rand_core::CryptoRngCore;
use crypto_bigint::U256;
use num_traits::{One, Zero};
use std::ops::{Add, Mul, Neg, Sub};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

// Do you have vertigo?
// Then you may want to close your eyes when you scroll by this massive
// wall of text...

/// The result of pairing the generators of 𝔾₁ and 𝔾₂.
/// This constant is the generator of the target group 𝔾₁ ⨯ 𝔾₂ => 𝔾ₜ.
const GT: Fp12 = Fp12::new(&[
    Fp6::new(&[
        Fp2::new(&[
            Fp::new(U256::from_words([
                6782248912058519189,
                17905854633700849845,
                981815359735217878,
                2750332953940282622,
            ])),
            Fp::new(U256::from_words([
                13014616448268208714,
                4142271424844328294,
                728210408904174525,
                207215253209326080,
            ])),
        ]),
        Fp2::new(&[
            Fp::new(U256::from_words([
                5625932731339578848,
                6904745502146605564,
                11939514597710067603,
                1416930562523468429,
            ])),
            Fp::new(U256::from_words([
                12767899052203382315,
                14173989925134591536,
                5418279272259683929,
                291513493445614172,
            ])),
        ]),
        Fp2::new(&[
            Fp::new(U256::from_words([
                17718267794268532699,
                5156438002697560843,
                13706034212316115026,
                791559585771054991,
            ])),
            Fp::new(U256::from_words([
                18000284984309305840,
                15972481252625908291,
                13674726003407472074,
                2041438157648203876,
            ])),
        ]),
    ]),
    Fp6::new(&[
        Fp2::new(&[
            Fp::new(U256::from_words([
                6633055433011767806,
                1993283657624419055,
                2556155685443179097,
                674431358778088128,
            ])),
            Fp::new(U256::from_words([
                1117479660932770634,
                16838289109298230438,
                11753762874743346121,
                1500779265843046736,
            ])),
        ]),
        Fp2::new(&[
            Fp::new(U256::from_words([
                16118194329268941865,
                6475079101949171807,
                9933850523273906263,
                2143968216258907750,
            ])),
            Fp::new(U256::from_words([
                8841354688241740695,
                6537271047255149595,
                11000136646916559527,
                816050994711660747,
            ])),
        ]),
        Fp2::new(&[
            Fp::new(U256::from_words([
                11229723312742192931,
                1787374600849103887,
                7823112569575231955,
                1416575403721338444,
            ])),
            Fp::new(U256::from_words([
                4490955817540267159,
                6696537855995677752,
                13115031265298021014,
                70222861876806950,
            ])),
        ]),
    ]),
]);

/// Represents an element of the target group 𝔾ₜ in the BN254 pairing.
///
/// This is a simple wrapper around [`Fp12`], which is the extension field where 𝔾ₜ elements live.
#[derive(Copy, Clone, Debug, Default)]
pub struct Gt(pub(crate) Fp12);

impl<'a> Neg for &'a Gt {
    type Output = Gt;

    /// Negates a 𝔾ₜ element.
    ///
    /// Since 𝔾ₜ elements are unitary, negation is equivalent to conjugation.
    #[inline]
    fn neg(self) -> Gt {
        Gt(self.0.unitary_inverse())
    }
}

impl Neg for Gt {
    type Output = Gt;

    /// Negates a 𝔾ₜ element, deferring to the reference implementation.
    #[inline]
    fn neg(self) -> Gt {
        -&self
    }
}

impl ConstantTimeEq for Gt {
    /// Compares two 𝔾ₜ elements for equality in constant time.
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for Gt {
    /// Selects between two 𝔾ₜ elements in constant time based on a [`Choice`] value.
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Gt(Fp12::conditional_select(&a.0, &b.0, choice))
    }
}

impl PartialEq for Gt {
    /// Compares two 𝔾ₜ elements for partial equality.
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

// Following the fact that this is a well-ordered set, since we have partial
// equality, we can derive a total equality.
impl Eq for Gt {}

#[allow(clippy::suspicious_arithmetic_impl)]
impl<'a, 'b> Add<&'b Gt> for &'a Gt {
    type Output = Gt;

    /// Adds two 𝔾ₜ elements.
    ///
    /// In the target group, addition is implemented as multiplication in 𝔽ₚ¹².
    #[inline]
    fn add(self, rhs: &'b Gt) -> Gt {
        Gt(self.0 * rhs.0)
    }
}

impl<'a, 'b> Sub<&'b Gt> for &'a Gt {
    type Output = Gt;

    /// Subtracts one 𝔾ₜ element from another.
    #[inline]
    fn sub(self, rhs: &'b Gt) -> Gt {
        self + &(-rhs)
    }
}
#[allow(clippy::suspicious_arithmetic_impl)]
impl<'a, 'b> Mul<&'b Fr> for &'a Gt {
    type Output = Gt;

    /// Multiplies a 𝔾ₜ element by a scalar in the r-torsion of 𝔽ₚ.
    fn mul(self, other: &'b Fr) -> Self::Output {
        // This is simply the `double-and-add` algorithm for multiplication, which is the ECC
        // equivalent of the `square-and-multiply` algorithm used in modular exponentiation. It uses
        //  the lower Hamming weight representation of the scalar to reduce the number of operations
        //
        // <https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Double-and-add>
        let (np, nm) = other.compute_naf();
        let mut res = Self::Output::identity();

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

impl Mul<Fr> for Gt {
    type Output = Self;

    /// Multiplies a 𝔾ₜ element by a scalar in the r-torsion of 𝔽ₚ.
    #[inline]
    fn mul(self, rhs: Fr) -> Self::Output {
        &self * &rhs
    }
}

impl GroupTrait<12, 2, Fp12> for Gt {
    /// Returns the generator of the target group 𝔾ₜ.
    fn generator() -> Self {
        Self(GT)
    }

    /// The endomorphism is not implemented for the target group 𝔾ₜ.
    fn endomorphism(&self) -> Self {
        unimplemented!()
    }

    /// Generates a random element of the target group 𝔾ₜ.
    fn rand<R: CryptoRngCore>(rng: &mut R) -> Self {
        loop {
            let inner = Fp12::rand(rng);
            if !inner.is_zero() {
                return MillerLoopResult(inner).final_exponentiation();
            }
        }
    }

    /// Hashing to the target group 𝔾ₜ is not implemented.
    fn hash_to_curve<E: Expander>(_exp: &E, _msg: &[u8]) -> Result<Self, GroupError> {
        unimplemented!()
    }

    fn sign_message<E: Expander>(
        _exp: &E,
        _msg: &[u8],
        _private_key: Fp12,
    ) -> Result<Self, GroupError> {
        unimplemented!()
    }
}
impl Gt {
    /// Returns the group identity, which is $1$.
    pub fn identity() -> Gt {
        Gt(Fp12::one())
    }

    /// Doubles this group element.
    pub(crate) fn double(&self) -> Gt {
        Gt(self.0.square())
    }
}
