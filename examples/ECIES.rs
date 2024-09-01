// IMPORTANT NOTES:
// 1. This implementation is for educational purposes and is not suitable for production use without further enhancements.
// 2. The XOR encryption used here is not secure for real-world applications. A proper symmetric encryption algorithm should be used instead.
// 3. There's no nonce or IV used in the encryption, which can lead to vulnerabilities if the same key is reused.
// 4. The error handling could be more granular and informative in a production environment.
// 5. In a real-world scenario, you'd want to add more robust parameter validation and possibly use a more standardized format for the ciphertext and associated data.
// 6. The key derivation process using XMDExpander is a good start, but for production use, you might want to use a standardized key derivation function like HKDF.
// 7. The signature is computed over the ciphertext, which provides integrity and authenticity. However, you might want to include additional data (like the ephemeral public key) in the signed message for added security.
// 8. This implementation doesn't include any padding schemes, which might be necessary in some cases to prevent certain types of attacks.
// 9. For production use, it's crucial to use constant-time operations to prevent timing attacks.
// 10. Always use peer-reviewed and well-tested cryptographic libraries for any security-critical applications.

use crypto_bigint::rand_core::OsRng;
use sha3::Keccak256;
use sylow::{
    sign, verify, Expander, FieldExtensionTrait, Fp, Fr, G1Projective, G2Projective, GroupTrait,
    KeyPair, XMDExpander,
};
use tracing::{debug, error, info, instrument};

// Constants
/// Domain Separation Tag for hash-to-curve operations
const DST: &[u8; 30] = b"WARLOCK-CHAOS-V01-CS01-SHA-256";
/// Security parameter in bits
const SECURITY_BITS: u64 = 128;
const KEY_LEN: usize = 32;

#[derive(Debug)]
pub enum ECIESError {
    EncryptionError,
    DecryptionError,
    KeyDerivationError,
    SignatureVerificationError,
}

/// Represents a party in the ECIES communication
pub struct ECIESParty {
    key_pair: KeyPair,
}

impl ECIESParty {
    /// Creates a new ECIESParty with randomly generated keys
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

    /// Encrypts a message for a recipient
    fn cipher_text(&self, message: &[u8], key: &[u8]) -> Vec<u8> {
        message
            .iter()
            .zip(key.iter().cycle())
            .map(|(&m, &k)| m ^ k)
            .collect()
    }

    /// Decrypts a message
    fn plain_text(&self, cipher_text: &[u8], key: &[u8]) -> Vec<u8> {
        cipher_text
            .iter()
            .zip(key.iter().cycle())
            .map(|(&c, &k)| c ^ k)
            .collect()
    }

    /// Encrypts a message for a recipient and signs it for sender authentication
    ///
    /// # Arguments
    ///
    /// * `recipient_public_key` - The recipient's public key
    /// * `message` - The message to encrypt
    ///
    /// # Returns
    ///
    /// A tuple containing:
    /// * The ephemeral public key
    /// * The encrypted message (ciphertext)
    /// * The signature of the ciphertext
    #[instrument(skip(self, recipient_public_key, message), fields(message_len = message.len()))]
    pub fn encrypt(
        &self,
        recipient_public_key: &G2Projective,
        message: &[u8],
    ) -> Result<(G1Projective, Vec<u8>, G1Projective), ECIESError> {
        debug!("Generating ephemeral key pair");
        let ephemeral_private_key = Fp::new(Fr::rand(&mut OsRng).value());
        let ephemeral_public_key = G1Projective::generator() * ephemeral_private_key;

        debug!("Computing shared secret");
        let shared_secret = *recipient_public_key * ephemeral_private_key;
        let encryption_key = self.derive_key(&shared_secret)?;

        debug!("Encrypting message");
        let ciphertext: Vec<u8> = self.cipher_text(message, &encryption_key);

        debug!("Signing ciphertext");
        let signature = sign(&self.key_pair.secret_key, &ciphertext)
            .map_err(|_| ECIESError::EncryptionError)?;

        Ok((ephemeral_public_key, ciphertext, signature))
    }

    /// Decrypts a message and verifies the sender's identity
    ///
    /// # Arguments
    ///
    /// * `ephemeral_public_key` - The ephemeral public key used in encryption
    /// * `ciphertext` - The encrypted message
    /// * `signature` - The signature of the ciphertext
    /// * `sender_public_key` - The sender's public key
    ///
    /// # Returns
    ///
    /// An Option containing the decrypted message if decryption and verification succeed,
    /// or None if either fails
    #[instrument(skip(self, ephemeral_public_key, ciphertext, signature, sender_public_key), fields(ciphertext_len = ciphertext.len()))]
    pub fn decrypt(
        &self,
        ephemeral_public_key: &G1Projective,
        ciphertext: &[u8],
        signature: &G1Projective,
        sender_public_key: &G2Projective,
    ) -> Result<Vec<u8>, ECIESError> {
        debug!("Verifying signature");
        if !verify(sender_public_key, ciphertext, signature)
            .map_err(|_| ECIESError::SignatureVerificationError)?
        {
            error!("Signature verification failed");
            return Err(ECIESError::SignatureVerificationError);
        }

        debug!("Computing shared secret");
        let shared_secret = *ephemeral_public_key * self.key_pair.secret_key;
        let decryption_key = self.derive_key(&shared_secret)?;

        debug!("Decrypting message");
        let plaintext: Vec<u8> = self.plain_text(ciphertext, &decryption_key);

        Ok(plaintext)
    }

    /// Derives a symmetric key from a shared secret
    /// using the XMD-Keccak key derivation function
    #[instrument(skip(self, shared_secret))]
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
        let expanded = expander
            .expand_message(&secret_bytes, KEY_LEN)
            .map_err(|_| ECIESError::KeyDerivationError)?;

        Ok(expanded)
    }
}

#[instrument]
fn main() -> Result<(), ECIESError> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    info!("Demonstrating ECIES with sender authentication");

    // Create parties
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
