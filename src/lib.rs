//! # Sylow: Elliptic Curve Cryptography Suite for BN254
//!
//! Sylow is a Rust library implementing elliptic curve cryptography for the BN254 (alt-bn128) curve.
//! It provides efficient implementations of finite fields, elliptic curve groups, and pairing-based
//! cryptography, suitable for applications in a blockchain environment,
//! in zero-knowledge proving, and in other cryptographic systems.
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
//! - Highly optimized optimal ate pairing
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
//! security.
//! It follows best practices outlined in RFC 9380 for operations like hashing to curve points.
//!
//! When compiled with the `std` feature, it also uses the `secrets` crate to ensure that keys and
//! signatures are stored securely in memory throughout the entirety of the application runtime.
//!
//! ## Further Reading
//!
//! For more detailed information, examples, and advanced usage, please refer to the
//! [full documentation](https://docs.rs/sylow)
//! and the [GitHub repository](https://github.com/warlock-labs/sylow).
#![deny(dead_code)]
#![no_std]
#![allow(clippy::needless_lifetimes)]
extern crate alloc;

mod fields;
mod groups;
mod hasher;
mod pairing;

#[cfg(feature = "std")]
mod secrets;
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

pub use crate::hasher::{Expander, XMDExpander, XOFExpander};
pub use crate::pairing::{
    glued_miller_loop, glued_pairing, pairing, G2PreComputed, MillerLoopResult,
};

#[cfg(feature = "std")]
use ::secrets::SecretBox;
use crypto_bigint::rand_core::OsRng;
use sha3::Keccak256;
use subtle::ConstantTimeEq;

/// Domain Separation Tag for hash-to-curve operations
const DST: &[u8; 30] = b"WARLOCK-CHAOS-V01-CS01-SHA-256";

/// Security parameter in bits. It should be noted that for BN254, this is technically not true,
/// as the effective bit length was shown to be ~100, but we keep for posterity.
const SECURITY_BITS: u64 = 128;

// Conditional compilation for SecretKey type
#[cfg(feature = "std")]
pub type SecretKey = SecretBox<Fp>;

#[cfg(not(feature = "std"))]
pub type SecretKey = Fp;

// Conditional compilation for Signature type
#[cfg(feature = "std")]
pub type Signature = SecretBox<G1Projective>;

#[cfg(not(feature = "std"))]
pub type Signature = G1Projective;

// Conditional compilation for PublicKey type
#[cfg(feature = "std")]
pub type PublicKey = SecretBox<G2Projective>;

#[cfg(not(feature = "std"))]
pub type PublicKey = G2Projective;

/// Represents a pair of secret and public keys for BLS signatures
///
/// This struct contains both the secret key (a scalar in the 𝔽ₚ base field)
/// and the corresponding public key (a point on the 𝔾₂ curve).
///
/// When compiled with the `std` feature, these are stored as heap-allocated secrets.
/// Otherwise, they are stored directly.
pub struct KeyPair {
    /// The secret key, represented as a scalar in the base field
    pub secret_key: SecretKey,
    /// The public key, represented as a point on the 𝔾₂ curve
    pub public_key: PublicKey,
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
    /// A new [`KeyPair`] instance with randomly generated keys
    ///
    /// # Examples
    ///
    /// ```
    /// use sylow::KeyPair;
    ///
    /// let key_pair = KeyPair::generate();
    /// ```
    pub fn generate() -> KeyPair {
        #[cfg(feature = "std")]
        {
            let secret_key = SecretBox::new(|s| *s = Fp::new(Fr::rand(&mut OsRng).value()));
            let secret_key_clone = secret_key.clone();
            let secret_key_ref = secret_key_clone.borrow();
            let public_key = SecretBox::new(|s| *s = G2Projective::generator() * *secret_key_ref);
            KeyPair {
                secret_key,
                public_key,
            }
        }
        #[cfg(not(feature = "std"))]
        {
            let secret_key = Fp::new(Fr::rand(&mut OsRng).value());
            let public_key = G2Projective::generator() * secret_key;
            KeyPair {
                secret_key,
                public_key,
            }
        }
    }

    // TODO(We should be able to load a key pair from a string here, in addition to just generating one)
    // The use case is when we already have key pair and then wish to use the library to sign, verify,
    // and perform other operations.

    // TODO(We should be able to save the generated key pair to a string here, in addition to just generating one)
    // The use case is when we generate a key pair and then wish to save it for later use.

    // In general, it might be useful here to look at other key pair libraries and see what they offer
    // in terms of functionality for basic key management.
    // It may be useful to have a struct for private key, and a struct for public key, and then a struct for key pair.
}

/// Signs a message using the BLS signature scheme
///
/// This function takes a secret key and a message, hashes the message to a
/// point on the 𝔾₁ curve, and then multiplies this point by the secret key
/// to produce the signature.
///
/// # Arguments
///
/// * `k` - The secret key used for signing
/// * `msg` - The message to be signed, as a byte slice
///
/// # Returns
///
/// * `Ok(`[`Signature`]`)` - The BLS signature as a point on the 𝔾₁ curve
/// * `Err(`[`GroupError`]`)` - If the message cannot be hashed to a curve point
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
pub fn sign(k: &SecretKey, msg: &[u8]) -> Result<Signature, GroupError> {
    // Expand the message to a curve point using the DST and security bits
    let expander = XMDExpander::<Keccak256>::new(DST, SECURITY_BITS);
    // Hash the message to a curve point, returning the point in 𝔾₁ multiplied by the secret key or an error
    match G1Projective::hash_to_curve(&expander, msg) {
        Ok(hashed_message) => {
            #[cfg(feature = "std")]
            let signature = SecretBox::new(|sig| {
                *sig = hashed_message * *k.borrow();
            });
            #[cfg(not(feature = "std"))]
            let signature = hashed_message * *k;
            Ok(signature)
        }
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
/// * `Err(`[`GroupError`]`)` - If the message cannot be hashed to a curve point
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
pub fn verify(pubkey: &PublicKey, msg: &[u8], sig: &Signature) -> Result<bool, GroupError> {
    // Expand the message to a curve point using the DST and security bits
    let expander = XMDExpander::<Keccak256>::new(DST, SECURITY_BITS);
    // Assert that the message can be hashed to a curve point and the pairings compared,
    // returning a boolean or an error
    match G1Projective::hash_to_curve(&expander, msg) {
        Ok(hashed_message) => {
            #[cfg(feature = "std")]
            {
                let lhs = pairing(&sig.borrow(), &G2Projective::generator());
                let rhs = pairing(&hashed_message, &pubkey.borrow());
                Ok(lhs.ct_eq(&rhs).into())
            }
            #[cfg(not(feature = "std"))]
            {
                let lhs = pairing(sig, &G2Projective::generator());
                let rhs = pairing(&hashed_message, pubkey);
                Ok(lhs.ct_eq(&rhs).into())
            }
        }
        _ => Err(GroupError::CannotHashToGroup),
    }
}

// TODO(In the future it would be ideal to have methods here for encrypting and decrypting messages)
// Or general functionality such as ECDH, etc. gated behind feature flags.
#[test]
fn test_high_level_utils() {
    // Generate a new key pair
    let key_pair = KeyPair::generate();

    // Message to be signed
    let message = b"Hello, Sylow!";

    // Sign the message
    match sign(&key_pair.secret_key, message) {
        Ok(signature) => {
            // Verify the signature
            match verify(&key_pair.public_key, message, &signature) {
                Ok(is_valid) => {
                    assert!(is_valid, "Signature verification failed");
                }
                Err(e) => panic!("Verification error: {:?}", e),
            }
        }
        Err(e) => panic!("Signing error: {:?}", e),
    }
}
