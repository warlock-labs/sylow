//! # ECIES (Elliptic Curve Integrated Encryption Scheme) Example
//!
//! This example demonstrates the implementation of ECIES using the Sylow library.
//! ECIES is a hybrid encryption scheme that combines elliptic curve cryptography
//! with symmetric encryption to provide confidentiality, integrity, and authentication.
//!
//! The implementation includes:
//! - Key generation for parties
//! - Encryption of messages
//! - Decryption of messages
//! - Digital signatures for sender authentication
//! - An example of an impersonation attempt

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::Rng;
use rand_core::OsRng;
use sha3::Keccak256;
use std::convert::TryFrom;
use sylow::{
    sign, verify, Expander, FieldExtensionTrait, Fp, Fr, G1Projective, G2Projective, GroupTrait,
    KeyPair, XMDExpander,
};
use tracing::{debug, error, info, instrument};

/// Domain Separation Tag for hash-to-curve operations
const DST: &[u8; 30] = b"WARLOCK-CHAOS-V01-CS01-SHA-256";
/// Security parameter in bits for the key derivation function
const SECURITY_BITS: u64 = 128;
/// Length of the AES key in bytes (256-bit key)
const KEY_LEN: usize = 32;
/// Length of the AES-GCM nonce in bytes
const NONCE_LEN: usize = 12;

/// Errors that can occur during ECIES operations
#[derive(Debug)]
pub enum ECIESError {
    /// Error during the encryption process (e.g., AES encryption failure)
    EncryptionError,
    /// Error during the decryption process (e.g., AES decryption failure)
    DecryptionError,
    /// Error during the key derivation process
    KeyDerivationError,
    /// Error during signature verification (e.g., invalid signature)
    SignatureVerificationError,
    /// Invalid nonce length encountered
    InvalidNonce,
}

/// Represents a party in the ECIES protocol
pub struct ECIESParty {
    /// The party's key pair (private key and public key)
    key_pair: KeyPair,
}

impl ECIESParty {
    /// Creates a new ECIES party with a randomly generated key pair
    #[instrument]
    pub fn new() -> Self {
        debug!("Generating new ECIES party");
        ECIESParty {
            key_pair: KeyPair::generate(),
        }
    }

    /// Returns the public key of the party
    pub fn public_key(&self) -> G2Projective {
        self.key_pair.public_key
    }

    /// Derives a symmetric key from a shared secret using XMD-Keccak256
    ///
    /// # Arguments
    ///
    /// * `shared_secret` - The shared secret from which to derive the key
    ///
    /// # Returns
    ///
    /// A Result containing the derived key as a Vec<u8> or an ECIESError
    fn derive_key<G, const D: usize, const N: usize, F>(
        &self,
        shared_secret: &G,
    ) -> Result<Vec<u8>, ECIESError>
    where
        G: GroupTrait<D, N, F>,
        F: FieldExtensionTrait<D, N>,
    {
        debug!("Deriving key from shared secret");
        let secret_bytes = format!("{:?}", shared_secret).into_bytes();

        let expander = XMDExpander::<Keccak256>::new(DST, SECURITY_BITS);
        expander
            .expand_message(&secret_bytes, KEY_LEN)
            .map_err(|_| ECIESError::KeyDerivationError)
    }

    /// Encrypts a message for a recipient using ECIES
    ///
    /// # Arguments
    ///
    /// * `recipient_public_key` - The recipient's public key
    /// * `message` - The message to encrypt
    ///
    /// # Returns
    ///
    /// A Result containing a tuple of (ephemeral_public_key, encrypted_message, signature) or an ECIESError
    #[instrument(skip(self, recipient_public_key, message), fields(message_len = message.len()))]
    pub fn encrypt(
        &self,
        recipient_public_key: &G2Projective,
        message: &[u8],
    ) -> Result<(G1Projective, Vec<u8>, G1Projective), ECIESError> {
        // Generate an ephemeral key pair for this encryption
        debug!("Generating ephemeral key pair");
        let ephemeral_private_key = Fp::new(Fr::rand(&mut OsRng).value());
        let ephemeral_public_key = G1Projective::generator() * ephemeral_private_key;

        // Compute the shared secret using ECDH
        debug!("Computing shared secret");
        let shared_secret = *recipient_public_key * ephemeral_private_key;
        let encryption_key = self.derive_key(&shared_secret)?;

        // Encrypt the message using AES-GCM
        debug!("Encrypting message");
        let cipher =
            Aes256Gcm::new_from_slice(&encryption_key).map_err(|_| ECIESError::EncryptionError)?;
        let nonce_bytes: [u8; NONCE_LEN] = OsRng.gen();
        let nonce = Nonce::try_from(&nonce_bytes[..]).map_err(|_| ECIESError::EncryptionError)?;
        let ciphertext = cipher
            .encrypt(&nonce, message)
            .map_err(|_| ECIESError::EncryptionError)?;

        // Combine nonce and ciphertext
        let mut encrypted_message = nonce.to_vec();
        encrypted_message.extend_from_slice(&ciphertext);

        // Sign the encrypted message for authentication
        debug!("Signing ciphertext");
        let signature = sign(&self.key_pair.secret_key, &encrypted_message)
            .map_err(|_| ECIESError::EncryptionError)?;

        Ok((ephemeral_public_key, encrypted_message, signature))
    }

    /// Decrypts a message and verifies the sender's identity
    ///
    /// # Arguments
    ///
    /// * `ephemeral_public_key` - The ephemeral public key used in encryption
    /// * `ciphertext` - The encrypted message (including nonce)
    /// * `signature` - The signature of the ciphertext
    /// * `sender_public_key` - The sender's public key
    ///
    /// # Returns
    ///
    /// A Result containing the decrypted message as a Vec<u8> or an ECIESError
    #[instrument(skip(self, ephemeral_public_key, ciphertext, signature, sender_public_key), fields(ciphertext_len = ciphertext.len()))]
    pub fn decrypt(
        &self,
        ephemeral_public_key: &G1Projective,
        ciphertext: &[u8],
        signature: &G1Projective,
        sender_public_key: &G2Projective,
    ) -> Result<Vec<u8>, ECIESError> {
        // Verify the signature to authenticate the sender
        debug!("Verifying signature");
        if !verify(sender_public_key, ciphertext, signature)
            .map_err(|_| ECIESError::SignatureVerificationError)?
        {
            error!("Signature verification failed");
            return Err(ECIESError::SignatureVerificationError);
        }

        // Compute the shared secret using ECDH
        debug!("Computing shared secret");
        let shared_secret = *ephemeral_public_key * self.key_pair.secret_key;
        let decryption_key = self.derive_key(&shared_secret)?;

        // Prepare for decryption
        debug!("Decrypting message");
        let cipher =
            Aes256Gcm::new_from_slice(&decryption_key).map_err(|_| ECIESError::DecryptionError)?;

        // Ensure the ciphertext is long enough to contain a nonce
        if ciphertext.len() < NONCE_LEN {
            return Err(ECIESError::InvalidNonce);
        }

        // Split the ciphertext into nonce and encrypted data
        let (nonce, encrypted_data) = ciphertext.split_at(NONCE_LEN);
        let nonce = Nonce::try_from(nonce).map_err(|_| ECIESError::DecryptionError)?;

        // Decrypt the message
        let plaintext = cipher
            .decrypt(&nonce, encrypted_data)
            .map_err(|_| ECIESError::DecryptionError)?;

        Ok(plaintext)
    }
}

fn main() -> Result<(), ECIESError> {
    // Initialize tracing for better debugging and logging
    tracing_subscriber::fmt::init();

    info!("Demonstrating ECIES with sender authentication");

    // Create parties (Alice and Bob)
    let alice = ECIESParty::new();
    let bob = ECIESParty::new();

    info!("Created Alice and Bob");
    debug!("Alice's public key: {:?}", alice.public_key());
    debug!("Bob's public key: {:?}", bob.public_key());

    // Alice encrypts a message for Bob
    let message = b"Hello, Bob! This is a secret message from Alice.";
    info!(
        "Alice's original message: {}",
        String::from_utf8_lossy(message)
    );

    let (ephemeral_public_key, ciphertext, signature) = alice
        .encrypt(&bob.public_key(), message)
        .map_err(|_| ECIESError::EncryptionError)?;

    info!("Alice encrypted the message for Bob");
    debug!("Ephemeral public key: {:?}", ephemeral_public_key);
    debug!("Ciphertext length: {} bytes", ciphertext.len());
    debug!("Signature: {:?}", signature);

    // Bob decrypts the message from Alice
    info!("Bob decrypts the message:");
    let decrypted = bob
        .decrypt(
            &ephemeral_public_key,
            &ciphertext,
            &signature,
            &alice.public_key(),
        )
        .map_err(|_| ECIESError::DecryptionError)?;

    info!("Decrypted message: {}", String::from_utf8_lossy(&decrypted));
    info!("Sender (Alice) successfully verified!");

    // Demonstrate an impersonation attempt
    info!("\nDemonstrating an impersonation attempt:");
    let mallory = ECIESParty::new();
    let fake_message = b"Hello Bob, this is Alice (actually Mallory)!";
    let (mallory_ephemeral_key, mallory_ciphertext, mallory_signature) = mallory
        .encrypt(&bob.public_key(), fake_message)
        .map_err(|_| ECIESError::EncryptionError)?;

    info!("Mallory attempts to impersonate Alice...");
    match bob.decrypt(
        &mallory_ephemeral_key,
        &mallory_ciphertext,
        &mallory_signature,
        &alice.public_key(),
    ) {
        Ok(_) => info!("WARNING: Impersonation succeeded!"),
        Err(e) => info!("Impersonation attempt detected and thwarted: {:?}", e),
    }

    Ok(())
}
