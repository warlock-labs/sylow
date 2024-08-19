#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(unsafe_code)]
#![deny(dead_code)]
#![allow(clippy::needless_doctest_main)]
#![warn(
    clippy::unwrap_used,
    missing_docs,
    missing_debug_implementations,
    missing_copy_implementations,
    rust_2021_compatibility,
    trivial_casts,
    trivial_numeric_casts,
    unused_qualifications
)]

mod fields;
mod groups;
mod hasher;
mod pairing;
mod svdw;

pub use crate::fields::fp::{FieldExtensionTrait, Fp, Fr};
pub use crate::groups::g1::{G1Affine, G1Projective};
pub use crate::groups::g2::G2Projective;
pub use crate::groups::group::{GroupError, GroupTrait};
pub use crate::groups::gt::Gt;
use crate::hasher::XMDExpander;
pub use crate::pairing::{pairing, G2PreComputed, glued_miller_loop};
use crypto_bigint::rand_core::OsRng;
use sha3::Keccak256;
use subtle::ConstantTimeEq;

const DST: &[u8; 30] = b"WARLOCK-CHAOS-V01-CS01-SHA-256";
const SECURITY_BITS: u64 = 128;

/// This is a basic struct that simply contains a pair of (private, pub ) keys for later use in
/// the signature and verification
#[derive(Debug, Copy, Clone)]
pub struct KeyPair {
    /// a scalar in the base field
    pub secret_key: Fp,
    /// scalar*g2generator
    pub public_key: G2Projective,
}

impl KeyPair {
    /// This instantiates a random pair from the cryptographic RNG
    pub fn generate() -> KeyPair {
        let secret_key = Fp::new(Fr::rand(&mut OsRng).value());
        let public_key = G2Projective::generator() * secret_key;
        KeyPair {
            secret_key,
            public_key,
        }
    }
}
/// This takes a message, hashes it, and returns the signature based on the key pair struct
pub fn sign(k: &Fp, msg: &[u8]) -> Result<G1Projective, GroupError> {
    let expander = XMDExpander::<Keccak256>::new(DST, SECURITY_BITS);
    match G1Projective::hash_to_curve(&expander, msg) {
        Ok(hashed_message) => Ok(hashed_message * *k),
        _ => Err(GroupError::CannotHashToGroup),
    }
}

/// This takes a pub lic key, message, and a signature, and verifies that the signature is valid
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
