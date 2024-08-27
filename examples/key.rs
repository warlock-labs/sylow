use sylow::{sign, verify, KeyPair};

fn main() {
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
                    println!("Signature verified successfully!");
                }
                Err(e) => println!("Verification error: {:?}", e),
            }
        }
        Err(e) => println!("Signing error: {:?}", e),
    }
}
