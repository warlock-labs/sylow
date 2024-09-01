//! # Sylow: Elliptic Curve Cryptography for BN254
//!
//! Sylow is a Rust library implementing elliptic curve cryptography for the BN254 (alt-bn128) curve.
//! It provides efficient implementations of finite fields, elliptic curve groups, and pairing-based
//! cryptography, suitable for applications in blockchain, zero-knowledge proofs, and other
//! cryptographic systems.
//!
//! ## Quick Start
//!
//! Add Sylow to your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! sylow = "0.1.0"
//! ```
//!
//! ## Key Features
//!
//! - Finite field arithmetic (𝔽ₚ, 𝔽ₚ², 𝔽ₚ⁶, 𝔽ₚ¹²)
//! - Elliptic curve group operations (𝔾₁, 𝔾₂, 𝔾ₜ)
//! - Optimal ate pairing
//! - BLS signature scheme
//! - Hash-to-curve functionality
//!
//! ## Basic Usage
//!
//! Here's an example of generating a key pair, signing a message, and verifying the signature:
//!
//! ```rust
//! use sylow::{KeyPair, sign, verify};
//!
//! // Generate a new key pair
//! let key_pair = KeyPair::generate();
//!
//! // Sign a message
//! let message = b"Hello, Sylow!";
//! let signature = sign(&key_pair.secret_key, message).expect("Signing failed");
//!
//! // Verify the signature
//! let is_valid = verify(&key_pair.public_key, message, &signature).expect("Verification failed");
//! assert!(is_valid, "Signature verification failed");
//! ```
//!
//! ## Core Components
//!
//! - [`Fp`], [`Fp2`], [`Fp6`], [`Fp12`]: Finite field implementations
//! - [`G1Projective`], [`G2Projective`]: Elliptic curve group elements
//! - [`pairing()`]: Bilinear pairing operation
//! - [`KeyPair`]: BLS key pair generation
//! - [`sign`], [`verify`]: BLS signature operations
//!
//! ## Performance and Security
//!
//! Sylow uses optimized algorithms and constant-time implementations to ensure both efficiency and
//! security. It follows best practices outlined in RFC 9380 for operations like hashing to curve points.
//!
//! ## Further Reading
//!
//! For more detailed information, examples, and advanced usage, please refer to the
//! [full documentation](https://docs.rs/sylow) and the [GitHub repository](https://github.com/warlock-labs/sylow).

mod fields;
mod groups;
mod hasher;
mod pairing;
mod svdw;
pub(crate) mod utils;

pub use crate::fields::fp::{FieldExtensionTrait, Fp, Fr};
pub use crate::groups::g1::{G1Affine, G1Projective};
pub use crate::groups::g2::{G2Affine, G2Projective};
pub use crate::groups::group::{GroupError, GroupTrait};
pub use crate::groups::gt::Gt;

pub use crate::fields::fp12::Fp12;
pub use crate::fields::fp2::Fp2;
pub use crate::fields::fp6::Fp6;

pub use crate::hasher::{XMDExpander, XOFExpander};
pub use crate::pairing::{glued_miller_loop, pairing, G2PreComputed};
use crypto_bigint::rand_core::OsRng;
use sha3::Keccak256;
use subtle::ConstantTimeEq;

/// Domain Separation Tag for hash-to-curve operations
const DST: &[u8; 30] = b"WARLOCK-CHAOS-V01-CS01-SHA-256";

/// Security parameter in bits
const SECURITY_BITS: u64 = 128;

/// Represents a pair of secret and public keys for BLS signatures
///
/// This struct contains both the secret key (a scalar in the base field)
/// and the corresponding public key (a point on the G2 curve).
#[derive(Debug, Copy, Clone)]
pub struct KeyPair {
    /// The secret key, represented as a scalar in the base field
    pub secret_key: Fp,
    /// The public key, represented as a point on the G2 curve
    pub public_key: G2Projective,
}

impl KeyPair {
    /// Generates a new random key pair
    ///
    /// This method uses the system's cryptographically secure random number
    /// generator to create a new secret key, and then computes the corresponding
    /// public key.
    ///
    /// # Returns
    ///
    /// A new `KeyPair` instance with randomly generated keys
    ///
    /// # Examples
    ///
    /// ```
    /// use sylow::KeyPair;
    ///
    /// let key_pair = KeyPair::generate();
    /// ```
    pub fn generate() -> KeyPair {
        let secret_key = Fp::new(Fr::rand(&mut OsRng).value());
        let public_key = G2Projective::generator() * secret_key;
        KeyPair {
            secret_key,
            public_key,
        }
    }
}

/// Signs a message using BLS signature scheme
///
/// This function takes a secret key and a message, hashes the message to a
/// point on the G1 curve, and then multiplies this point by the secret key
/// to produce the signature.
///
/// # Arguments
///
/// * `k` - The secret key used for signing
/// * `msg` - The message to be signed, as a byte slice
///
/// # Returns
///
/// * `Ok(G1Projective)` - The BLS signature as a point on the G1 curve
/// * `Err(GroupError)` - If the message cannot be hashed to a curve point
///
/// # Examples
///
/// ```
/// use sylow::{KeyPair, sign};
///
/// let key_pair = KeyPair::generate();
/// let message = b"Hello, world!";
/// match sign(&key_pair.secret_key, message) {
///     Ok(signature) => println!("Signature generated successfully"),
///     Err(e) => println!("Signing error: {:?}", e),
/// }
/// ```
pub fn sign(k: &Fp, msg: &[u8]) -> Result<G1Projective, GroupError> {
    let expander = XMDExpander::<Keccak256>::new(DST, SECURITY_BITS);
    match G1Projective::hash_to_curve(&expander, msg) {
        Ok(hashed_message) => Ok(hashed_message * *k),
        _ => Err(GroupError::CannotHashToGroup),
    }
}

/// Verifies a BLS signature
///
/// This function verifies whether a given signature is valid for a message
/// with respect to a public key. It uses pairing operations to check the
/// validity of the signature.
///
/// # Arguments
///
/// * `pubkey` - The public key used for verification
/// * `msg` - The original message that was signed, as a byte slice
/// * `sig` - The signature to be verified
///
/// # Returns
///
/// * `Ok(bool)` - `true` if the signature is valid, `false` otherwise
/// * `Err(GroupError)` - If the message cannot be hashed to a curve point
///
/// # Examples
///
/// ```
/// use sylow::{KeyPair, sign, verify};
///
/// let key_pair = KeyPair::generate();
/// let message = b"Hello, world!";
/// match sign(&key_pair.secret_key, message) {
///     Ok(signature) => {
///         match verify(&key_pair.public_key, message, &signature) {
///             Ok(is_valid) => println!("Signature is valid: {}", is_valid),
///             Err(e) => println!("Verification error: {:?}", e),
///         }
///     },
///     Err(e) => println!("Signing error: {:?}", e),
/// }
/// ```
pub fn verify(pubkey: &G2Projective, msg: &[u8], sig: &G1Projective) -> Result<bool, GroupError> {
    let expander = XMDExpander::<Keccak256>::new(DST, SECURITY_BITS);
    match G1Projective::hash_to_curve(&expander, msg) {
        Ok(hashed_message) => {
            let lhs = pairing(sig, &G2Projective::generator());
            let rhs = pairing(&hashed_message, pubkey);
            Ok(lhs.ct_eq(&rhs).into())
        }
        _ => Err(GroupError::CannotHashToGroup),
    }
}
