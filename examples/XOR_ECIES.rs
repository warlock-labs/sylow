use crypto_bigint::rand_core::OsRng;
use sha3::Keccak256;
use sylow::{
    sign, verify, Expander, FieldExtensionTrait, Fp, Fr, G1Projective, G2Projective, GroupTrait,
    KeyPair, XMDExpander,
};
use tracing::{debug, error, info, instrument};

// Constants
const DST: &[u8; 30] = b"WARLOCK-CHAOS-V01-CS01-SHA-256";
const SECURITY_BITS: u64 = 128;
const KEY_LEN: usize = 32;

#[derive(Debug)]
pub enum ECIESError {
    EncryptionError,
    DecryptionError,
    KeyDerivationError,
    SignatureVerificationError,
}

pub struct ECIESParty {
    key_pair: KeyPair,
}

impl ECIESParty {
    #[instrument]
    pub fn new() -> Self {
        debug!("Generating new ECIES party");
        ECIESParty {
            key_pair: KeyPair::generate(),
        }
    }

    pub fn get_public_key(&self) -> G2Projective {
        self.key_pair.public_key
    }

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
        let ciphertext: Vec<u8> = message
            .iter()
            .zip(encryption_key.iter().cycle())
            .map(|(&m, &k)| m ^ k)
            .collect();

        debug!("Signing ciphertext");
        let signature = sign(&self.key_pair.secret_key, &ciphertext)
            .map_err(|_| ECIESError::EncryptionError)?;

        Ok((ephemeral_public_key, ciphertext, signature))
    }

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
        let plaintext: Vec<u8> = ciphertext
            .iter()
            .zip(decryption_key.iter().cycle())
            .map(|(&c, &k)| c ^ k)
            .collect();

        Ok(plaintext)
    }

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
    debug!("Alice's public key: {:?}", alice.get_public_key());
    debug!("Bob's public key: {:?}", bob.get_public_key());

    // Alice encrypts a message for Bob
    let message = b"Hello, Bob! This is a secret message from Alice.";
    info!(
        "Alice's original message: {}",
        String::from_utf8_lossy(message)
    );

    let (ephemeral_public_key, ciphertext, signature) = alice
        .encrypt(&bob.get_public_key(), message)
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
            &alice.get_public_key(),
        )
        .map_err(|_| ECIESError::DecryptionError)?;

    info!("Decrypted message: {}", String::from_utf8_lossy(&decrypted));
    info!("Sender (Alice) successfully verified!");

    // Demonstrate an impersonation attempt
    info!("\nDemonstrating an impersonation attempt:");
    let mallory = ECIESParty::new();
    let fake_message = b"Hello Bob, this is Alice (actually Mallory)!";
    let (mallory_ephemeral_key, mallory_ciphertext, mallory_signature) = mallory
        .encrypt(&bob.get_public_key(), fake_message)
        .map_err(|_| ECIESError::EncryptionError)?;

    info!("Mallory attempts to impersonate Alice...");
    match bob.decrypt(
        &mallory_ephemeral_key,
        &mallory_ciphertext,
        &mallory_signature,
        &alice.get_public_key(),
    ) {
        Ok(_) => info!("WARNING: Impersonation succeeded!"),
        Err(e) => info!("Impersonation attempt detected and thwarted: {:?}", e),
    }

    Ok(())
}
