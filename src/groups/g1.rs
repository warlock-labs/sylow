//! This module contains the implementations of the 𝔾₁ group for BN254 elliptic curve.
//!
//! This module defines 𝔾₁ as the r-torsion subgroup of E(𝔽ₚ), where E is the BN254 elliptic curve
//! over the base field 𝔽ₚ. For BN254, the entire curve E(𝔽ₚ) is the r-torsion subgroup, simplifying
//! the implementation as no additional subgroup checks are needed beyond ensuring points are on the curve.
//!
//! Key features:
//! - Affine and projective coordinate representations
//! - Point operations (addition, scalar multiplication, etc.)
//! - Hashing to curve points
//! - Serialization and deserialization of curve points
//!
//! The curve equation is y² = x³ + 3 over 𝔽ₚ.
//! The curve has a generator point (1, 2), which is used as the base for scalar multiplication
//! and other operations.

// TODO(Notably missing here is the representation as 𝔾₁(𝔽ₚ²))
// rather than as projective or affine coordinates

use crate::fields::fp::{FieldExtensionTrait, Fp};
use crate::groups::group::{GroupAffine, GroupError, GroupProjective, GroupTrait};
use crate::hasher::Expander;
use crate::svdw::{MapError, SvdW, SvdWTrait};
use crypto_bigint::rand_core::CryptoRngCore;
use num_traits::{One, Zero};
use std::sync::OnceLock;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

/// Affine representation of a point in the 𝔾₁ group
pub type G1Affine = GroupAffine<1, 1, Fp>;

/// Projective representation of a point in the 𝔾₁ group
pub type G1Projective = GroupProjective<1, 1, Fp>;

/// Static instance of the Shallue-van de Woestijne map for 𝔾₁ on the BN254 curve
static BN254_SVDW: OnceLock<Result<SvdW, MapError>> = OnceLock::new();

/// Returns the Shallue-van de Woestijne map for 𝔾₁ on the BN254 curve
///
/// This function initializes the SvdW map if it hasn't been initialized yet,
/// and returns a reference to it.
///
/// # Returns
///
/// A result containing either a reference to the SvdW map or a reference to a [`MapError`]
pub fn get_bn254_svdw() -> Result<&'static SvdW, &'static MapError> {
    BN254_SVDW
        .get_or_init(|| SvdW::precompute_constants(Fp::ZERO, Fp::THREE))
        .as_ref()
}

impl GroupTrait<1, 1, Fp> for G1Affine {
    /// Returns the generator point (1, 2) for the 𝔾₁ group
    fn generator() -> Self {
        Self {
            x: Fp::ONE,
            y: Fp::TWO,
            infinity: Choice::from(0u8),
        }
    }

    /// Returns the generator point for 𝔾₁
    ///
    /// Note: The endomorphism is not used for 𝔾₁, so this just returns the generator
    fn endomorphism(&self) -> Self {
        Self::generator()
    }

    /// Generates a random point in the 𝔾₁ group
    fn rand<R: CryptoRngCore>(rng: &mut R) -> Self {
        Self::from(G1Projective::rand(rng))
    }

    /// Hashes a message to a point in the 𝔾₁ group
    fn hash_to_curve<E: Expander>(exp: &E, msg: &[u8]) -> Result<Self, GroupError> {
        match G1Projective::hash_to_curve(exp, msg) {
            Ok(d) => Ok(Self::from(d)),
            Err(e) => Err(e),
        }
    }

    /// Signs a message using a private key and returns a point in the 𝔾₁ group
    fn sign_message<E: Expander>(exp: &E, msg: &[u8], private_key: Fp) -> Result<Self, GroupError> {
        match G1Projective::sign_message(exp, msg, private_key) {
            Ok(d) => Ok(Self::from(d)),
            Err(e) => Err(e),
        }
    }
}

impl G1Affine {
    /// Instantiates a new element in affine coordinates in 𝔾₁.
    ///
    /// The input values must pass the curve equation check y² = x³ + 3.
    /// No additional subgroup check is required for 𝔾₁ in BN254 as the entire curve E(𝔽ₚ) is the r-torsion subgroup.
    ///
    /// # Arguments
    ///
    /// * `v` - An array of two field elements representing the x and y coordinates of the point
    ///
    /// # Returns
    ///
    /// * `Result<Self, GroupError>` - A new point if the coordinates are on the curve, or an error if they're not
    ///
    /// # Examples
    ///
    /// ```
    /// use sylow::*;
    /// let generator = G1Affine::new([Fp::ONE, Fp::TWO]);
    /// ```
    pub fn new(v: [Fp; 2]) -> Result<Self, GroupError> {
        let is_on_curve = {
            let y2 = v[1].square();
            let x2 = v[0].square();
            let lhs = y2 - (x2 * v[0]);
            let rhs = <Fp as FieldExtensionTrait<1, 1>>::curve_constant();
            tracing::trace!(?y2, ?x2, ?lhs, ?rhs, "G1Affine::new");
            lhs.ct_eq(&rhs)
        };

        // every point in G1 on the curve is in the r-torsion of BN254,
        // so we don't need to check for subgroup membership
        tracing::trace!(?is_on_curve, "G1Affine::new");
        match bool::from(is_on_curve) {
            true => Ok(Self {
                x: v[0],
                y: v[1],
                infinity: Choice::from(0u8),
            }),
            false => Err(GroupError::NotOnCurve),
        }
    }

    // TODO(Expose this as to bytes big endian)
    /// Serializes an element of 𝔾₁ into uncompressed big-endian form.
    ///
    /// The most significant bit is set if the point is the point at infinity.
    /// Elements in 𝔾₁ are two elements of 𝔽ₚ, so the total byte size of a 𝔾₁ element is 32 + 32 = 64 bytes.
    ///
    /// # Returns
    ///
    /// * `[u8; 64]` - A 64-byte array representing the point
    ///
    /// # Examples
    ///
    /// ```
    /// use sylow::*;
    ///
    /// let point = G1Affine::generator();
    /// let point_bytes = point.to_uncompressed();
    /// ```
    pub fn to_uncompressed(self) -> [u8; 64] {
        let mut res = [0u8; 64];
        res[0..32].copy_from_slice(
            &Fp::conditional_select(&self.x, &Fp::ZERO, self.infinity).to_be_bytes()[..],
        );
        res[32..64].copy_from_slice(
            &Fp::conditional_select(&self.y, &Fp::ONE, self.infinity).to_be_bytes()[..],
        );
        // we need to set the most significant bit if it's the point at infinity
        // the seven below is to set the most significant bit at index 8 - 1 = 7
        res[0] |= u8::conditional_select(&0u8, &(1u8 << 7), self.infinity);

        res
    }

    // TODO(Expose this as from bytes big endian)
    /// Deserializes an element of 𝔾₁ from an uncompressed big-endian form.
    ///
    /// The most significant bit indicates if the point is at infinity.
    ///
    /// # Arguments
    ///
    /// * `bytes` - A 64-byte array representing the point
    ///
    /// # Returns
    ///
    /// * `CtOption<G1Projective>` - A point on the curve or the point at infinity, if the evaluation is valid
    ///
    /// Note: This returns a G1Projective, as it's the representation used for arithmetic operations.
    ///       We define this method though on the affine representation
    ///       which requires 32 fewer bytes to instantiate for the same point.
    ///
    /// # Examples
    ///
    /// ```
    /// use sylow::*;
    /// let p = G1Affine::generator();
    /// let bytes = p.to_uncompressed();
    /// let p2 = G1Affine::from_uncompressed(&bytes).unwrap();
    /// assert_eq!(p, p2.into(), "Deserialization failed");
    /// ```
    ///
    /// # Notes
    ///
    /// This function deserializes a point from an uncompressed big endian form. The most
    /// significant bit is set if the point is the point at infinity, and therefore must be
    /// explicitly checked to correctly evaluate the bytes.
    pub fn from_uncompressed(bytes: &[u8; 64]) -> CtOption<G1Projective> {
        Self::from_uncompressed_unchecked(bytes).and_then(|p| {
            let infinity_flag = bool::from(p.infinity);
            if infinity_flag {
                CtOption::new(G1Projective::zero(), Choice::from(1u8))
            } else {
                match G1Projective::new([p.x, p.y, Fp::ONE]) {
                    Ok(p) => CtOption::new(p, Choice::from(1u8)),
                    Err(_) => CtOption::new(G1Projective::zero(), Choice::from(0u8)),
                }
            }
        })
    }

    /// This is a helper function to `Self::from_uncompressed` that does the extraction of the
    /// relevant information from the bytes themselves. This function can be thought of as
    /// handling the programmatic aspects of the byte array (correct length, correct evaluation
    /// in terms of field components, etc.), but the other functional requirements on these
    /// bytes, like curve and subgroup membership, are enforced by `Self::from_uncompressed`,
    /// which is why this function is not exposed publicly.
    fn from_uncompressed_unchecked(bytes: &[u8; 64]) -> CtOption<Self> {
        let infinity_flag = Choice::from((bytes[0] >> 7) & 1);

        //try to get the x coord
        let x = {
            let mut tmp = [0u8; 32];
            tmp.copy_from_slice(&bytes[0..32]);

            tmp[0] &= 0b0111_1111; // mask away the flag bit
            Fp::from_be_bytes(&tmp)
        };

        //try to get the y coord
        let y = {
            let mut tmp = [0u8; 32];
            tmp.copy_from_slice(&bytes[32..64]);

            Fp::from_be_bytes(&tmp)
        };
        x.and_then(|x| {
            y.and_then(|y| {
                let p = Self::conditional_select(
                    &G1Affine {
                        x,
                        y,
                        infinity: infinity_flag,
                    },
                    &G1Affine::zero(),
                    infinity_flag,
                );

                let is_some = (!infinity_flag)
                    | (infinity_flag & Choice::from((x.is_zero() & y.is_one()) as u8));
                CtOption::new(p, is_some)
            })
        })
    }
}
impl GroupTrait<1, 1, Fp> for G1Projective {
    /// Returns the generator point for 𝔾₁ in projective coordinates
    fn generator() -> Self {
        Self::from(G1Affine::generator())
    }

    // Returns the generator point for 𝔾₁
    ///
    /// Note: The endomorphism is not used for 𝔾₁, so this just returns the generator
    fn endomorphism(&self) -> Self {
        Self::generator()
    }

    /// Generates a random point in the 𝔾₁ group
    fn rand<R: CryptoRngCore>(rng: &mut R) -> Self {
        Self::generator() * <Fp as FieldExtensionTrait<1, 1>>::rand(rng)
    }

    /// Hashes a message to a point on the 𝔾₁ group
    ///
    /// This process involves two steps:
    /// 1. Hash the message to two field elements using the `expand_message` function
    /// 2. Map these field elements to curve points and combine them
    ///
    /// See `hasher.rs` and `svdw.rs` for more details on the underlying algorithms.
    fn hash_to_curve<E: Expander>(exp: &E, msg: &[u8]) -> Result<Self, GroupError> {
        const COUNT: usize = 2;
        const L: usize = 48;
        let scalars = exp
            .hash_to_field(msg, COUNT, L)
            .expect("Hashing to base field failed");
        tracing::trace!(?scalars, "GroupTrait::hash_to_curve");
        match get_bn254_svdw() {
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
                tracing::trace!(?a, ?b, "GroupTrait::hash_to_curve");
                Ok(a + b)
            }
            _ => Err(GroupError::CannotHashToGroup),
        }
    }

    /// Signs a message using a private key in the base field [`Fp`], returning a point on the 𝔾₁ group
    ///
    /// # Examples
    ///
    /// ```
    /// use sylow::*;
    /// use crypto_bigint::rand_core::OsRng;
    /// use sha3::Keccak256;
    ///
    /// const DST: &[u8; 30] = b"WARLOCK-CHAOS-V01-CS01-SHA-256";
    /// const MSG: &[u8; 4] = &20_i32.to_be_bytes();
    /// const K: u64 = 128;
    ///
    /// let expander = XMDExpander::<Keccak256>::new(DST, K);
    /// let rando = <Fp as FieldExtensionTrait<1, 1>>::rand(&mut OsRng);
    ///
    /// if let Ok(d) = G1Projective::sign_message(&expander, MSG, rando) {
    ///     println!("DST: {:?}", String::from_utf8_lossy(DST));
    ///     println!("Message: {:?}", String::from_utf8_lossy(MSG));
    ///     println!("private key: {:?}", rando.value());
    /// }
    /// ```
    fn sign_message<E: Expander>(exp: &E, msg: &[u8], private_key: Fp) -> Result<Self, GroupError> {
        if let Ok(d) = Self::hash_to_curve(exp, msg) {
            return Ok(d * private_key);
        }
        Err(GroupError::CannotHashToGroup)
    }
}
impl G1Projective {
    /// Instantiates a new element in projective coordinates in 𝔾₁.
    ///
    /// The input values must pass the curve equation checks in projective form:
    /// Y²Z = X³ + 3Z³
    ///
    /// # Arguments
    ///
    /// * `v` - An array of three field elements representing the X, Y, and Z coordinates of the point
    ///
    /// # Returns
    ///
    /// * `Result<Self, GroupError>` - A new point if the coordinates satisfy the curve equation, or an error if they don't
    ///
    /// # Examples
    ///
    /// ```
    /// use sylow::*;
    /// let generator = G1Projective::new([Fp::ONE, Fp::TWO, Fp::ONE]);
    /// ```
    #[allow(dead_code)]
    pub fn new(v: [Fp; 3]) -> Result<Self, GroupError> {
        let is_on_curve = {
            let y2 = v[1].square();
            let x2 = v[0].square();
            let z2 = v[2].square();
            let lhs = y2 * v[2];
            let rhs = x2 * v[0] + z2 * v[2] * <Fp as FieldExtensionTrait<1, 1>>::curve_constant();
            tracing::trace!(?y2, ?x2, ?z2, ?lhs, ?rhs, "G1Projective::new");
            lhs.ct_eq(&rhs) | Choice::from(v[2].is_zero() as u8)
        };
        tracing::trace!(?is_on_curve, "G1Projective::new");
        match bool::from(is_on_curve) {
            true => Ok(Self {
                x: v[0],
                y: v[1],
                z: v[2],
            }),
            false => Err(GroupError::NotOnCurve),
        }
    }
}

impl<'a> From<&'a [Fp; 2]> for G1Projective {
    /// Converts an array of two field elements (representing affine coordinates) to a projective point.
    ///
    /// # Arguments
    ///
    /// * `value` - A reference to an array of two field elements [x, y]
    ///
    /// # Returns
    ///
    /// * `G1Projective` - The corresponding point in projective coordinates
    ///
    /// # Panics
    ///
    /// If the affine coordinates do not represent a valid point on the curve.
    fn from(value: &'a [Fp; 2]) -> Self {
        G1Affine::new(*value)
            .expect("Conversion to affine failed")
            .into()
    }
}

impl From<[Fp; 2]> for G1Projective {
    /// Converts an array of two field elements (representing affine coordinates) to a projective point.
    ///
    /// This is a convenience wrapper around the implementation of `From<&[Fp; 2]>`.
    ///
    /// # Arguments
    ///
    /// * `value` - An array of two field elements [x, y]
    ///
    /// # Returns
    ///
    /// * `G1Projective` - The corresponding point in projective coordinates
    ///
    /// # Panics
    ///
    /// If the affine coordinates do not represent a valid point on the curve.
    fn from(value: [Fp; 2]) -> Self {
        G1Projective::from(&value)
    }
}
