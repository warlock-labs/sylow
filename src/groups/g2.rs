//! Implementation of the 𝔾₂ group for BN254 elliptic curve.
//!
//! This module defines 𝔾₂ = (r)E(𝔽ₚ²), where E is the BN254 elliptic curve over the quadratic
//! extension field 𝔽ₚ². Unlike 𝔾₁, the prime order subgroup is not the entire curve, which
//! introduces additional security considerations and complexity. This introduces many security
//! considerations in regard to generating points on the correct subgroup for instance.
//!
//! This is the source of many headaches.
//!
//! There is an unfortunate combination of factors here to consider regarding the representation of
//! group elements. Because, as mentioned in `group.rs`, of the fact that the point at infinity
//! has no unique representation in affine coordinates, all arithmetic must be performed in
//! projective coordinates. However, there are many formulae that we will use in the subgroup
//! checks that require explicit expressions in affine coordinates. Therefore, all arithmetic
//! will be done in projective coordinates, but there will often be translation between the
//! representations. The internal translation does not induce that much overhead really, but it
//! is something to keep in mind.
//!
//! Key features:
//! - Affine and projective coordinate representations
//! - Point operations (addition, scalar multiplication, etc.)
//! - Subgroup checks to ensure points are in the r-torsion
//! - Serialization and deserialization of curve points
//!
//! Note: All public-facing methods implement subgroup checks to prevent users from
//! inputting values in E'(𝔽ₚ²) that are not in the r-torsion.
//!
//! Implementation details:
//! - Arithmetic is performed in projective coordinates for efficiency.
//! - Conversions between affine and projective representations are used internally.
//! - Subgroup membership is verified using optimized endomorphism-based checks.

use crate::fields::fp::{FieldExtensionTrait, Fp, Fr};
use crate::fields::fp2::Fp2;
use crate::groups::group::{GroupAffine, GroupError, GroupProjective, GroupTrait};
use crate::hasher::Expander;
use crypto_bigint::rand_core::CryptoRngCore;
use crypto_bigint::U256;
use num_traits::{One, Zero};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

/// X-coordinate of the 𝔾₂ group generator for the r-torsion of the twist curve,
/// generated directly from sage
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

/// Y-coordinate of the 𝔾₂ group generator for the r-torsion of the twist curve,
/// generated directly from sage
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

/// First constant of the endomorphism, ξ^((p-1)/3), [`EPS_EXP1`] below
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

/// Second constant of the endomorphism, ξ^((p-1)/2), [`EPS_EXP0`] above
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

/// Parameter that generates this member of the BN family
pub(crate) const BLS_X: Fp = Fp::new(U256::from_words([4965661367192848881, 0, 0, 0]));

/// Affine representation of a point in the 𝔾₂ group on the quadratic extension field
pub type G2Affine = GroupAffine<2, 2, Fp2>;

/// Projective representation of a point on the 𝔾₂ group on the quadratic extension field
pub type G2Projective = GroupProjective<2, 2, Fp2>;

impl GroupTrait<2, 2, Fp2> for G2Affine {
    /// Returns the generator of E'(𝔽ₚ²), which is not necessarily in the r-torsion subgroup.
    ///
    /// This generator is to be used for creating new elements on the curve that are not required
    /// to be in the r-torsion. To create elements in the r-torsion, use the `rand` function
    /// which performs co-factor clearing.
    fn generator() -> Self {
        Self {
            x: G2_X,
            y: G2_Y,
            infinity: Choice::from(0u8),
        }
    }

    /// Applies the Frobenius endomorphism to the point.
    ///
    /// For a point P = (x, y) on E'(𝔽ₚ²), the endomorphism ψ is defined as:
    /// ψ(P) = (x^p * ξ^((p-1)/3), y^p * ξ^((p-1)/2))
    ///
    /// This endomorphism is used in subgroup checks and other optimizations.
    fn endomorphism(&self) -> Self {
        if self.is_zero() {
            return *self;
        }
        let x_frob = self.x.frobenius(1);
        let y_frob = self.y.frobenius(1);

        let x_endo = EPS_EXP0 * x_frob;
        let y_endo = EPS_EXP1 * y_frob;

        tracing::trace!(?x_frob, ?y_frob, ?x_endo, ?y_endo, "G2Affine::endomorphism");
        Self::new_unchecked([x_endo, y_endo]).expect("Endomorphism failed")
    }

    /// Generates a random point in the r-torsion subgroup of 𝔾₂ group.
    fn rand<R: CryptoRngCore>(rng: &mut R) -> Self {
        Self::from(G2Projective::rand(rng))
    }

    // TODO(We should still look at the swap of these and the integration points with SolBLS for savings)

    /// Hashing to 𝔾₂ is currently unimplemented.
    ///
    /// Being able to implement a "G1/G2 swap" is in development, where we then will hash a byte
    /// array to G2 (private key + signature in G2), while retaining a public key in G1, which is
    /// why the following two methods are unimplemented for the moment.
    fn hash_to_curve<E: Expander>(_exp: &E, _msg: &[u8]) -> Result<Self, GroupError> {
        unimplemented!()
    }

    /// Signing messages in 𝔾₂ is currently unimplemented.
    ///
    /// See the comment on `hash_to_curve` for more information.
    fn sign_message<E: Expander>(
        _exp: &E,
        _msg: &[u8],
        _private_key: Fp2,
    ) -> Result<Self, GroupError> {
        unimplemented!()
    }
}

impl GroupTrait<2, 2, Fp2> for G2Projective {
    /// Returns the generator of E'(𝔽ₚ²) in projective coordinates.
    fn generator() -> Self {
        let _generator = G2Affine::generator();
        Self {
            x: _generator.x,
            y: _generator.y,
            z: Fp2::one(),
        }
    }

    /// Applies the Frobenius endomorphism to the projective point.
    fn endomorphism(&self) -> Self {
        Self::from(G2Affine::from(self).endomorphism())
    }

    /// Generates a random point in the r-torsion subgroup of 𝔾₂.
    ///
    /// This function first generates a random point on the twist curve E'(𝔽ₚ²),
    /// then applies cofactor clearing to ensure the result is in the r-torsion subgroup.
    /// It is then passed through the `new` function to ensure it passes the curve and
    /// subgroup checks.
    ///
    /// # Examples
    ///
    /// ```
    /// use sylow::*;
    /// use crypto_bigint::rand_core::OsRng;
    /// let mut rng = OsRng;
    /// let random_point = G2Projective::rand(&mut rng);
    /// ```
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
        tracing::trace!(?rando, ?tmp, "G2Projective::rand");

        // multiplying an element of the larger base field by the cofactor of a prime-ordered
        // subgroup will return an element in the prime-order subgroup, see
        // <https://crypto.stackexchange.com/a/101736> for a nice little explainer
        tmp = tmp * C2; //this is cofactor clearing
        Self::new([tmp.x, tmp.y, tmp.z]).expect("Generator failed to make new value in torsion")
    }

    /// Hashing to 𝔾₂ is currently unimplemented.
    fn hash_to_curve<E: Expander>(_exp: &E, _msg: &[u8]) -> Result<Self, GroupError> {
        unimplemented!()
    }

    /// Signing messages in 𝔾₂ is currently unimplemented.
    fn sign_message<E: Expander>(
        _exp: &E,
        _msg: &[u8],
        _private_key: Fp2,
    ) -> Result<Self, GroupError> {
        unimplemented!()
    }
}
impl G2Affine {
    /// Creates a new point on the curve without subgroup verification.
    ///
    /// This method is used internally for efficient type conversion when certain
    /// formulas don't have clean versions in projective coordinates. It bypasses
    /// the subgroup check, so it should be used with caution.
    ///
    /// # Warning
    ///
    /// DO NOT USE THIS METHOD UNLESS YOU KNOW WHAT YOU'RE DOING
    ///
    /// # Arguments
    ///
    /// * `v` - An array of two Fp2 elements representing the x and y coordinates of the point
    ///
    /// # Returns
    ///
    /// * `Result<Self, GroupError>` - A new point if the coordinates satisfy the curve equation,
    ///    or an error if they don't
    fn new_unchecked(v: [Fp2; 2]) -> Result<Self, GroupError> {
        let is_on_curve = {
            let y2 = v[1].square();
            let x2 = v[0].square();
            let lhs = y2 - (x2 * v[0]);
            let rhs = <Fp2 as FieldExtensionTrait<2, 2>>::curve_constant();
            tracing::trace!(?y2, ?x2, ?lhs, ?rhs, "G2Affine::new_unchecked");
            lhs.ct_eq(&rhs)
        };

        match bool::from(is_on_curve) {
            true => Ok(Self {
                x: v[0],
                y: v[1],
                infinity: Choice::from(0u8),
            }),
            false => Err(GroupError::NotOnCurve),
        }
    }

    // TODO(These to/from methods should be exposed as to/from bytes methods)

    /// Serializes an element of 𝔾₂ into an uncompressed big-endian form.
    ///
    /// The most significant bit is set if the point is the point at infinity.
    /// Elements of 𝔾₂ are two elements of 𝔽ₚ², so the total byte size of a 𝔾₂ element
    /// is (32 + 32) + (32 + 32) = 128 bytes.
    ///
    /// # Returns
    ///
    /// * `[u8; 128]` - A 128-byte array representing the point
    ///
    /// # Examples
    ///
    /// ```
    /// use sylow::*;
    ///
    /// let point = G2Affine::generator();
    /// let point_bytes = point.to_uncompressed();
    /// ```
    pub fn to_uncompressed(self) -> [u8; 128] {
        let mut res = [0u8; 128];

        let x = Fp2::conditional_select(&self.x, &Fp2::zero(), self.infinity);
        let y = Fp2::conditional_select(&self.y, &Fp2::one(), self.infinity);

        res[0..32].copy_from_slice(&x.0[1].to_be_bytes()[..]);
        res[32..64].copy_from_slice(&x.0[0].to_be_bytes()[..]);
        res[64..96].copy_from_slice(&y.0[1].to_be_bytes()[..]);
        res[96..128].copy_from_slice(&y.0[0].to_be_bytes()[..]);

        res[0] |= u8::conditional_select(&0u8, &(1u8 << 7), self.infinity);

        res
    }

    /// Deserializes a point from an uncompressed big-endian form.
    ///
    /// The most significant bit indicates if the point is at infinity, and therefore must be
    ///  explicitly checked to correctly evaluate the bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A 128-byte array representing the point
    ///
    /// # Returns
    ///
    /// * `CtOption<G2Projective>` - A point on the curve or the point at infinity, if the evaluation is valid
    ///
    /// Note: Returns a [`G2Projective`], since this is the version of the elements on which
    ///       arithmetic can be performed.
    ///       Thus, we define this method though on the affine representation
    ///       which requires 64 fewer bytes to instantiate for the same point.
    /// # Examples
    ///
    /// ```
    /// use sylow::*;
    /// let p = G2Affine::generator();
    /// let bytes = p.to_uncompressed();
    /// let p2 = G2Affine::from_uncompressed(&bytes).unwrap();
    /// assert_eq!(p, p2.into(), "Deserialization failed");
    /// ```
    pub fn from_uncompressed(bytes: &[u8; 128]) -> CtOption<G2Projective> {
        Self::from_uncompressed_unchecked(bytes).and_then(|p| {
            let infinity_flag = bool::from(p.infinity);
            if infinity_flag {
                CtOption::new(G2Projective::zero(), Choice::from(1u8))
            } else {
                match G2Projective::new([p.x, p.y, Fp2::one()]) {
                    Ok(valid) => CtOption::new(valid, Choice::from(1u8)),
                    Err(_) => CtOption::new(G2Projective::zero(), Choice::from(0u8)),
                }
            }
        })
    }

    /// This is a helper function to `Self::from_uncompressed` that does the extraction of the
    /// relevant information from the bytes themselves, see the documentation of
    /// `G1Affine::from_uncompressed_unchecked` for more information.
    fn from_uncompressed_unchecked(bytes: &[u8; 128]) -> CtOption<Self> {
        let infinity_flag = Choice::from((bytes[0] >> 7) & 1);

        // try to get the x coordinate
        let xc1 = {
            let mut tmp = [0u8; 32];
            tmp.copy_from_slice(&bytes[0..32]);

            tmp[0] &= 0b0111_1111; // mask away the flag bit

            Fp::from_be_bytes(&tmp)
        };
        let xc0 = {
            let mut tmp = [0u8; 32];
            tmp.copy_from_slice(&bytes[32..64]);

            Fp::from_be_bytes(&tmp)
        };

        // try to get the y coordinate
        let yc1 = {
            let mut tmp = [0u8; 32];
            tmp.copy_from_slice(&bytes[64..96]);

            Fp::from_be_bytes(&tmp)
        };
        let yc0 = {
            let mut tmp = [0u8; 32];
            tmp.copy_from_slice(&bytes[96..128]);

            Fp::from_be_bytes(&tmp)
        };
        xc1.and_then(|xc1| {
            xc0.and_then(|xc0| {
                yc1.and_then(|yc1| {
                    yc0.and_then(|yc0| {
                        let x = Fp2::new(&[xc0, xc1]);
                        let y = Fp2::new(&[yc0, yc1]);

                        let p = G2Affine::conditional_select(
                            &G2Affine {
                                x,
                                y,
                                infinity: infinity_flag,
                            },
                            &G2Affine::zero(),
                            infinity_flag,
                        );
                        let is_some = (!infinity_flag)
                            | (infinity_flag & Choice::from((x.is_zero() & y.is_one()) as u8));
                        CtOption::new(p, is_some)
                    })
                })
            })
        })
    }
}
impl G2Projective {
    /// Creates a new point in 𝔾₂ using projective coordinates.
    ///
    /// This method performs both curve equation and subgroup membership checks
    /// to ensure the resulting point is a valid element of 𝔾₂.
    ///
    /// # Arguments
    ///
    /// * `v` - An array of three Fp2 elements representing the x, y, and z coordinates of the point
    ///
    /// # Returns
    ///
    /// * `Result<Self, GroupError>` - A new point if it's on the curve and in the correct subgroup,
    ///   or an error otherwise
    ///
    /// # Subgroup check
    ///
    /// This method uses an optimized subgroup check based on the endomorphism ψ:
    /// (x+1)Q + ψ(xQ) + ψ²(xQ) = ψ³(2xQ)
    ///
    /// This check is more efficient than the naive approach of verifying (r)Q = 𝒪.
    ///
    /// References:
    /// 1. <https://eprint.iacr.org/2022/352.pdf>
    /// 2. <https://eprint.iacr.org/2022/348.pdf>
    pub fn new(v: [Fp2; 3]) -> Result<Self, GroupError> {
        let is_on_curve = {
            let y2 = v[1].square();
            let x2 = v[0].square();
            let z2 = v[2].square();
            let lhs = y2 * v[2];
            let rhs = x2 * v[0] + z2 * v[2] * <Fp2 as FieldExtensionTrait<2, 2>>::curve_constant();
            tracing::trace!(?y2, ?x2, ?z2, ?lhs, ?rhs, "G2Projective::new");
            lhs.ct_eq(&rhs) | Choice::from(v[2].is_zero() as u8)
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
        let is_torsion_free = {
            let tmp = G2Projective {
                x: v[0],
                y: v[1],
                z: v[2],
            };
            let mut a = tmp * BLS_X; // xQ
            let b = a.endomorphism(); // ψ(xQ)
            a = a + tmp; // (x+1)Q
            let mut rhs = b.endomorphism(); // ψ^2(xQ)
            let lhs = rhs + b + a; // ψ^2(xQ) + ψ(xQ) + (x+1)Q
            rhs = rhs.endomorphism().double() - lhs; // ψ^3(2xQ) - (ψ^2(xQ) + ψ(xQ) + (x+1)Q)
            tracing::trace!(
                ?v,
                ?a,
                ?b,
                ?lhs,
                ?rhs,
                "G2Projective::_g2projective_is_torsion_free"
            );

            // we do two checks: one is to verify that the result is indeed a point at infinity,
            // but we need a second check to verify that it is OUR point at infinity, namely for
            // the curve defined on the twist.
            Choice::from(rhs.is_zero() as u8) & is_on_curve
        };
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
