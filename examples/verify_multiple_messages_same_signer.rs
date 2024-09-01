//! This example demonstrates how to efficiently verify multiple signatures using batch verification
//! and precomputed Miller loop coefficients in Sylow, along with the benefits.

// TODO(This RNG still leaks through the abstraction of crypto_bigint)
use crypto_bigint::rand_core::OsRng;
use subtle::ConstantTimeEq;
use sylow::{
    glued_miller_loop, pairing, FieldExtensionTrait, Fp, Fr, G1Affine, G1Projective, G2Affine,
    G2Projective, GroupTrait, Gt,
};
use tracing::info;

fn main() {
    tracing_subscriber::fmt().init();
    // Generate a private key
    let private_key = Fp::new(Fr::rand(&mut OsRng).value());

    // Compute the corresponding public key
    let public_key = G2Projective::generator() * private_key;

    // Precompute the public key for efficient pairing
    let precomputed_pubkey = G2Affine::from(public_key).precompute();

    // Number of messages to sign and verify
    const NUM_MESSAGES: usize = 10;

    // Generate random messages (in a real scenario, these would be actual messages to sign)
    let messages: Vec<G1Affine> = (0..NUM_MESSAGES)
        .map(|_| G1Affine::rand(&mut OsRng))
        .collect();

    // Sign all messages
    let signatures: Vec<G1Projective> = messages
        .iter()
        .map(|msg| G1Projective::from(msg) * private_key)
        .collect();

    info!("Starting batch verification");

    // Prepare points for batch verification
    let mut g1_points = Vec::with_capacity(NUM_MESSAGES * 2);
    let mut g2_points = Vec::with_capacity(NUM_MESSAGES * 2);

    for (sig, msg) in signatures.iter().zip(messages.iter()) {
        g1_points.push(G1Affine::from(*sig));
        g1_points.push(-G1Affine::from(*msg));
        g2_points.push(G2Affine::from(G2Projective::generator()));
        g2_points.push(G2Affine::from(public_key));
    }

    // Precompute G2 points for efficient pairing
    let g2_precomp: Vec<_> = g2_points.iter().map(|p| p.precompute()).collect();

    // Perform batch verification
    let miller_result = glued_miller_loop(&g2_precomp, &g1_points);
    let batch_result = miller_result.final_exponentiation();

    // Check if all signatures are valid
    assert_eq!(batch_result, Gt::identity(), "Batch verification failed");
    info!("Batch verification successful: All signatures are valid!");

    info!("Starting individual verification");

    // For comparison, verify each signature individually
    for (sig, msg) in signatures.iter().zip(messages.iter()) {
        let lhs = pairing(sig, &G2Projective::generator());
        let rhs = precomputed_pubkey.miller_loop(msg).final_exponentiation();
        assert!(
            bool::from(lhs.ct_eq(&rhs)),
            "Individual verification failed"
        );
    }
    info!("Individual verification successful: All signatures are valid!");
}
