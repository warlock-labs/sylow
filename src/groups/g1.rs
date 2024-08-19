//! This creates the specific instance of G1 for BN254. Namely,
//! $\mathbb{G}_1=(r)E(\mathbb{F}_p)=E(\mathbb{F}_p)$, where we take advantage of the fact that
//! for BN254's G1, the r-torsion in the base field is the entire curve itself. There are
//! therefore no subgroup checks needed for membership in G1 other than the point being on the
//! curve itself.
//!
//! The curve also has a generator (1,2), which is used to create points on the curve from a scalar
//! value.
//!
//! Notice that there is not much here left to specialise to G1 on BN254! This abstraction should
//! make the implementation of the more complicated G2 easier to handle.

use crate::fields::fp::{FieldExtensionTrait, Fp};
use crate::groups::group::{GroupAffine, GroupError, GroupProjective, GroupTrait};
use crate::hasher::Expander;
use crate::svdw::{SvdW, SvdWTrait};
use crypto_bigint::rand_core::CryptoRngCore;
use num_traits::Zero;
use subtle::{Choice, ConstantTimeEq};

pub(crate) type G1Affine = GroupAffine<1, 1, Fp>;

pub(crate) type G1Projective = GroupProjective<1, 1, Fp>;

impl GroupTrait<1, 1, Fp> for G1Affine {
    fn generator() -> Self {
        Self {
            x: Fp::ONE,
            y: Fp::TWO,
            infinity: Choice::from(0u8),
        }
    }

    /// the endomorphism is used in subgroup checks, but since we don't use this for G1, it
    /// doesn't actually matter what this is set to.
    fn endomorphism(&self) -> Self {
        Self::generator()
    }
    fn rand<R: CryptoRngCore>(rng: &mut R) -> Self {
        Self::from(G1Projective::rand(rng))
    }
    fn hash_to_curve<E: Expander>(exp: &E, msg: &[u8]) -> Result<Self, GroupError> {
        match G1Projective::hash_to_curve(exp, msg) {
            Ok(d) => Ok(Self::from(d)),
            Err(e) => Err(e),
        }
    }
    fn sign_message<E: Expander>(exp: &E, msg: &[u8], private_key: Fp) -> Result<Self, GroupError> {
        match G1Projective::sign_message(exp, msg, private_key) {
            Ok(d) => Ok(Self::from(d)),
            Err(e) => Err(e),
        }
    }
    /// NOTA BENE: the frobenius map does NOT in general map points from the curve back to the curve
    /// It is an endomorphism of the algebraic closure of the base field, but NOT of the curve
    /// Therefore, these points must bypass curve membership and torsion checks, and therefore
    /// directly be instantiated as a struct
    fn frobenius(&self, exponent: usize) -> Self {
        let vec: Vec<Fp> = [self.x, self.y]
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

impl G1Affine {
    /// this needs to be defined in order to have user interaction, but currently
    /// is only visible in tests, and therefore is seen by the linter as unused
    pub fn new(v: [Fp; 2]) -> Result<Self, GroupError> {
        let _g1affine_is_on_curve = |x: &Fp, y: &Fp, z: &Choice| -> Choice {
            let y2 = y.square();
            let x2 = x.square();
            let lhs = y2 - (x2 * (*x));
            let rhs = <Fp as FieldExtensionTrait<1, 1>>::curve_constant();
            lhs.ct_eq(&rhs) | *z
        };

        let _g1affine_is_torsion_free = |_x: &Fp, _y: &Fp, _z: &Choice| -> Choice {
            // every point in G1 on the curve is in the r-torsion of BN254
            Choice::from(1u8)
        };
        let is_on_curve: Choice = _g1affine_is_on_curve(&v[0], &v[1], &Choice::from(0u8));
        match bool::from(is_on_curve) {
            true => {
                let is_in_torsion: Choice =
                    _g1affine_is_torsion_free(&v[0], &v[1], &Choice::from(0u8));
                match bool::from(is_in_torsion) {
                    true => Ok(Self {
                        x: v[0],
                        y: v[1],
                        infinity: Choice::from(0u8),
                    }),
                    _ => Err(GroupError::NotInSubgroup),
                }
            }
            false => Err(GroupError::NotOnCurve),
        }
    }
}
impl GroupTrait<1, 1, Fp> for G1Projective {
    fn generator() -> Self {
        Self::from(G1Affine::generator())
    }
    fn endomorphism(&self) -> Self {
        Self::generator()
    }
    fn rand<R: CryptoRngCore>(rng: &mut R) -> Self {
        Self::generator() * <Fp as FieldExtensionTrait<1, 1>>::rand(rng)
    }
    fn hash_to_curve<E: Expander>(exp: &E, msg: &[u8]) -> Result<Self, GroupError> {
        const COUNT: usize = 2;
        const L: usize = 48;
        let scalars = exp
            .hash_to_field(msg, COUNT, L)
            .expect("Hashing to base field failed");
        match SvdW::precompute_constants(Fp::from(0), Fp::from(3)) {
            Ok(bn254_g1_svdw) => {
                let a = G1Projective::from(
                    bn254_g1_svdw
                        .unchecked_map_to_point(scalars[0])
                        .expect("Failed to hash"),
                );
                let b = G1Projective::from(
                    bn254_g1_svdw
                        .unchecked_map_to_point(scalars[1])
                        .expect("Failed to hash"),
                );
                Ok(a + b)
            }
            _ => Err(GroupError::CannotHashToGroup),
        }
    }
    fn sign_message<E: Expander>(exp: &E, msg: &[u8], private_key: Fp) -> Result<Self, GroupError> {
        if let Ok(d) = Self::hash_to_curve(exp, msg) {
            return Ok(d * private_key);
        }
        Err(GroupError::CannotHashToGroup)
    }
    fn frobenius(&self, exponent: usize) -> Self {
        let vec: Vec<Fp> = [self.x, self.y, self.z]
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
impl G1Projective {
    pub fn new(v: [Fp; 3]) -> Result<Self, GroupError> {
        let _g1projective_is_on_curve = |x: &Fp, y: &Fp, z: &Fp| -> Choice {
            let y2 = y.square();
            let x2 = x.square();
            let z2 = z.square();
            let lhs = y2 * (*z);
            let rhs = x2 * (*x) + z2 * (*z) * <Fp as FieldExtensionTrait<1, 1>>::curve_constant();
            lhs.ct_eq(&rhs) | Choice::from(z.is_zero() as u8)
        };
        let _g1projective_is_torsion_free =
            |_x: &Fp, _y: &Fp, _z: &Fp| -> Choice { Choice::from(1u8) };
        let is_on_curve: Choice = _g1projective_is_on_curve(&v[0], &v[1], &v[2]);
        match bool::from(is_on_curve) {
            true => {
                let is_in_torsion: Choice = _g1projective_is_torsion_free(&v[0], &v[1], &v[2]);
                match bool::from(is_in_torsion) {
                    true => Ok(Self {
                        x: v[0],
                        y: v[1],
                        z: v[2],
                    }),
                    false => Err(GroupError::NotOnCurve),
                }
            }
            false => Err(GroupError::NotOnCurve),
        }
    }
}
impl<'a> From<&'a [Fp; 2]> for G1Projective {
    fn from(value: &'a [Fp; 2]) -> Self {
        G1Affine::new(*value)
            .expect("Conversion to affine failed")
            .into()
    }
}
impl From<[Fp; 2]> for G1Projective {
    fn from(value: [Fp; 2]) -> Self {
        G1Projective::from(&value)
    }
}
