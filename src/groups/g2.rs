//! This creates a specific instance of G2 for BN254. Namely,
//! $\mathbb{G}_2=(r)E(\mathbb{F}_{p^2})$. In this case, the prime order subgroup we wish to deal
//! with is NOT the curve itself. This introduces many security considerations in regard to
//! generating points on the correct subgroup for instance. This is the source of many headaches.
//! There is an unfortunate combination of factors here to consider regarding the representation of
//! group elements. Because, as mentioned in `group.rs`, of the fact that the point at infinity
//! has no unique representation in affine coordinates, all arithmetic must be performed in
//! projective coordinates. However, there are many formulae that we will use in the subgroup
//! checks that require explicit expressions in affine coordinates. Therefore, all arithmetic
//! will be done in projective coordinates, but there will often be translation between the
//! representations. The internal translation does not induce that much overhead really, but it
//! is something to keep in mind.
//!
//! All pub(crate) lic facing methods here implement the subgroup check to ensure that the user cannot
//! input a value in $E^\prime(F_{p^2})$ that is not in the r-torsion.

use crate::fields::fp::{FieldExtensionTrait, Fp, Fr};
use crate::fields::fp2::Fp2;
use crate::groups::group::{GroupAffine, GroupError, GroupProjective, GroupTrait};
use crate::hasher::Expander;
use crypto_bigint::rand_core::CryptoRngCore;
use crypto_bigint::U256;
use num_traits::{One, Zero};
use subtle::{Choice, ConstantTimeEq};

/// This is the X coordinate of the generator for the r-torsion of the twist curve, generated
/// directly from sage
const G2_X: Fp2 = Fp2::new(&[
    Fp::new(U256::from_words([
        5106727233969649389,
        7440829307424791261,
        4785637993704342649,
        1729627375292849782,
    ])),
    Fp::new(U256::from_words([
        10945020018377822914,
        17413811393473931026,
        8241798111626485029,
        1841571559660931130,
    ])),
]);

/// Likewise, this is the y coordinate of the generator for the r-torsion on the twist curve
const G2_Y: Fp2 = Fp2::new(&[
    Fp::new(U256::from_words([
        5541340697920699818,
        16416156555105522555,
        5380518976772849807,
        1353435754470862315,
    ])),
    Fp::new(U256::from_words([
        6173549831154472795,
        13567992399387660019,
        17050234209342075797,
        650358724130500725,
    ])),
]);
// the first constant of the endomorphism, $\xi^((p-1)/3)$, see below
pub(crate) const EPS_EXP0: Fp2 = Fp2::new(&[
    Fp::new(U256::from_words([
        11088870908804158781,
        13226160682434769676,
        5479733118184829251,
        3437169660107756023,
    ])),
    Fp::new(U256::from_words([
        1613930359396748194,
        3651902652079185358,
        5450706350010664852,
        1642095672556236320,
    ])),
]);
// the second constant of the endomorphism, $\xi^((p-1)/2)$, see below
pub(crate) const EPS_EXP1: Fp2 = Fp2::new(&[
    Fp::new(U256::from_words([
        15876315988453495642,
        15828711151707445656,
        15879347695360604601,
        449501266848708060,
    ])),
    Fp::new(U256::from_words([
        9427018508834943203,
        2414067704922266578,
        505728791003885355,
        558513134835401882,
    ])),
]);

// the parameter that generates this member of the BN family
pub(crate) const BLS_X: Fp = Fp::new(U256::from_words([4965661367192848881, 0, 0, 0]));

pub(crate) type G2Affine = GroupAffine<2, 2, Fp2>;

pub type G2Projective = GroupProjective<2, 2, Fp2>;

impl GroupTrait<2, 2, Fp2> for G2Affine {
    // This is the generator of $E^\prime(F_{p^2})$, and NOT of the r-torsion. This is because we
    // need the generator for creating new elements on the curve that are not required to be in the
    // r-torsion. To create elements in the r-torsion, we co-factor clear with the appropriate
    // value, see below in `rand`.
    fn generator() -> Self {
        Self {
            x: G2_X,
            y: G2_Y,
            infinity: Choice::from(0u8),
        }
    }

    fn endomorphism(&self) -> Self {
        if self.is_zero() {
            return *self;
        }
        let x_frob = self.x.frobenius(1);
        let y_frob = self.y.frobenius(1);

        let x_endo = EPS_EXP0 * x_frob;
        let y_endo = EPS_EXP1 * y_frob;

        Self::new_unchecked([x_endo, y_endo]).expect("Endomorphism failed")
    }

    fn rand<R: CryptoRngCore>(rng: &mut R) -> Self {
        Self::from(G2Projective::rand(rng))
    }

    /// Being able to implement a "G1/G2 swap" is in development, where we then will hash a byte
    /// array to G2 (private key + signature in G2), while retaining a public key in G1, which is
    /// why the following two methods are unimplemented for the moment.
    fn hash_to_curve<E: Expander>(_exp: &E, _msg: &[u8]) -> Result<Self, GroupError> {
        unimplemented!()
    }

    fn sign_message<E: Expander>(
        _exp: &E,
        _msg: &[u8],
        _private_key: Fp2,
    ) -> Result<Self, GroupError> {
        unimplemented!()
    }
    fn frobenius(&self, exponent: usize) -> Self {
        let vec: Vec<Fp2> = [self.x, self.y]
            .iter()
            .map(|x| x.frobenius(exponent))
            .collect();
        Self {
            x: vec[0],
            y: vec[1],
            infinity: self.infinity,
        }
    }
}
impl GroupTrait<2, 2, Fp2> for G2Projective {
    fn generator() -> Self {
        let _generator = G2Affine::generator();
        Self {
            x: _generator.x,
            y: _generator.y,
            z: Fp2::one(),
        }
    }
    fn endomorphism(&self) -> Self {
        Self::from(G2Affine::from(self).endomorphism())
    }
    /// This generates a random point in the r-torsion. We first generate a random value in the
    /// twist curve itself with a simple multiplication of the generator, and then co-factor
    /// clear this value to place it in the r-torsion. The return value of this function goes
    /// through the `new` constructor to ensure that the random value does indeed pass the curve
    /// and subgroup checks
    fn rand<R: CryptoRngCore>(rng: &mut R) -> Self {
        // the cofactor of $\mathbb{G}_2$
        const C2: Fp = Fp::new(U256::from_words([
            17887900258952609094,
            8020209761171036667,
            0,
            0,
        ]));
        let rando = Fp::new(Fr::rand(rng).value());
        let mut tmp = Self::generator() * rando;

        // multiplying an element of the larger base field by the cofactor of a prime-ordered
        // subgroup will return an element in the prime-order subgroup, see
        // <https://crypto.stackexchange.com/a/101736> for a nice little explainer
        tmp = tmp * C2; //this is cofactor clearing
        Self::new([tmp.x, tmp.y, tmp.z]).expect("Generator failed to make new value in torsion")
    }
    fn hash_to_curve<E: Expander>(_exp: &E, _msg: &[u8]) -> Result<Self, GroupError> {
        unimplemented!()
    }
    fn sign_message<E: Expander>(
        _exp: &E,
        _msg: &[u8],
        _private_key: Fp2,
    ) -> Result<Self, GroupError> {
        unimplemented!()
    }
    fn frobenius(&self, exponent: usize) -> Self {
        let vec: Vec<Fp2> = [self.x, self.y, self.z]
            .iter()
            .map(|x| x.frobenius(exponent))
            .collect();
        Self {
            x: vec[0],
            y: vec[1],
            z: vec[2],
        }
    }
}
impl G2Affine {
    /// This method is used internally for rapid, low overhead, conversion of types when there
    /// are formulae that don't have clean versions in projective coordinates. The 'unchecked'
    /// refers to the fact that these points are not subjected to a subgroup verification, and
    /// therefore this method is not exposed publicly.
    ///
    /// DON'T USE THIS METHOD UNLESS YOU KNOW WHAT YOU'RE DOING
    ///
    /// # Arguments
    /// * `v` - a tuple of field elements that represent the x and y coordinates of the point
    fn new_unchecked(v: [Fp2; 2]) -> Result<Self, GroupError> {
        let _g2affine_is_on_curve = |x: &Fp2, y: &Fp2, z: &Choice| -> Choice {
            let y2 = y.square();
            let x2 = x.square();
            let lhs = y2 - (x2 * (*x));
            let rhs = <Fp2 as FieldExtensionTrait<2, 2>>::curve_constant();
            lhs.ct_eq(&rhs) | *z
        };

        let is_on_curve = _g2affine_is_on_curve(&v[0], &v[1], &Choice::from(0u8));
        match bool::from(is_on_curve) {
            true => Ok(Self {
                x: v[0],
                y: v[1],
                infinity: Choice::from(0u8),
            }),
            false => Err(GroupError::NotOnCurve),
        }
    }
}
impl G2Projective {
    /// The public entrypoint to making a value in $\mathbb{G}_2$. This takes the (x,y,z) values
    /// from the user, and passes them through a subgroup and curve check to ensure validity.
    /// Values returned from this function are guaranteed to be on the curve and in the r-torsion.
    ///
    /// # Arguments
    /// * `v` - a tuple of field elements that represent the x, y, and z coordinates of the point
    pub fn new(v: [Fp2; 3]) -> Result<Self, GroupError> {
        let _g2projective_is_on_curve = |x: &Fp2, y: &Fp2, z: &Fp2| -> Choice {
            let y2 = y.square();
            let x2 = x.square();
            let z2 = z.square();
            let lhs = y2 * (*z);
            let rhs = x2 * (*x) + z2 * (*z) * <Fp2 as FieldExtensionTrait<2, 2>>::curve_constant();
            lhs.ct_eq(&rhs) | Choice::from(z.is_zero() as u8)
        };
        // This method is where the magic happens. In a naïve approach, in order to check for
        // validity in the r-torsion, one could simply verify the r-torsion condition:
        // $(r)Q = \mathcal{O}$. This can be prohibitively expensive because of the bit length
        // of $r$. We can therefore take a new approach and use the result of Ref (1) below to
        // determine subgroup membership. The formalism states a point is in the subgroup iff
        // $\psi(Q) = 6x^2Q$, where $\psi$ is the endomorphism, and $x$ is the generator of the
        // BN curve, in this case 4965661367192848881.
        //             // let six = Fp::from(6);
        //             // let z = Fp::from(4965661367192848881);
        //             // let six_z_squared = (six * z * z).value();
        //             // let lhs = tmp.endomorphism();
        //             // let rhs = &tmp * &six_z_squared.to_le_bytes();
        //             // Choice::from((&lhs - &rhs).is_zero() as u8)
        //
        // HOWEVER! There is an even better way. Recent work from Ref (2) below shows that
        // subgroup membership is equivalent to the following relation:
        // $(x+1)Q + \psi((x)Q)+\psi^2((x)Q) = \psi^3((2x)Q)$, which is basically a `u64`
        // multiplication instead of the full multi-sized multiplication of 6*x^2. Nice.
        //
        // References
        // ----------
        // 1. <https://eprint.iacr.org/2022/352.pdf>
        // 2. <https://eprint.iacr.org/2022/348.pdf>
        let _g2projective_is_torsion_free = |x: &Fp2, y: &Fp2, z: &Fp2| -> Choice {
            let tmp = G2Projective {
                x: *x,
                y: *y,
                z: *z,
            };
            let mut a = tmp * BLS_X; // xQ
            let b = a.endomorphism(); // ψ(xQ)
            a = a + tmp; // (x+1)Q
            let mut rhs = b.endomorphism(); // ψ^2(xQ)
            let lhs = rhs + b + a; // ψ^2(xQ) + ψ(xQ) + (x+1)Q
            rhs = rhs.endomorphism().double() - lhs; // ψ^3(2xQ) - (ψ^2(xQ) + ψ(xQ) + (x+1)Q)

            // we do two checks: one is to verify that the result is indeed a point at infinity,
            // but we need a second check to verify that it is OUR point at infinity, namely for
            // the curve defined on the twist.
            Choice::from(rhs.is_zero() as u8) & _g2projective_is_on_curve(&rhs.x, &rhs.y, &rhs.z)
        };
        let is_on_curve = _g2projective_is_on_curve(&v[0], &v[1], &v[2]);
        let is_torsion_free = _g2projective_is_torsion_free(&v[0], &v[1], &v[2]);
        match bool::from(is_on_curve) {
            true => match bool::from(is_torsion_free) {
                true => Ok(Self {
                    x: v[0],
                    y: v[1],
                    z: v[2],
                }),
                _ => Err(GroupError::NotInSubgroup),
            },
            false => Err(GroupError::NotOnCurve),
        }
    }
}
