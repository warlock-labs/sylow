//! This example shows how to leverage the batch computation of the Miller loops, or otherwise 
//! reuse the same G2 element in the pairing in repeated verifications. 
use crypto_bigint::rand_core::OsRng;
use subtle::ConstantTimeEq;
use sylow::{pairing, FieldExtensionTrait, Fp, Fr, G1Affine, G1Projective, G2Projective, GroupTrait};

fn main() {
    // First, let's generate a shared secret ...
    let private_key = Fp::new(Fr::rand(&mut OsRng).value());
    // ... and a public key from it, at which we evaluate the coefficients of the Miller loops
    let pubkey = (G2Projective::generator() * private_key).precompute();
    // Now, imagine we have 10 signatures we wish to verify.
    let hashed_msgs: Vec<G1Affine> =  (0..10).map(|_| {
       G1Affine::rand(&mut OsRng)
    }).collect();

    let signatures: Vec<G1Projective> = hashed_msgs.iter().map(|x| {
        G1Projective::from(x) * private_key
    }).collect();
    // We can evaluate each of them individually using the precomputed coefficients ...
    for (sig, msg) in signatures.iter().zip(hashed_msgs.iter()) {
        let lhs = pairing(sig, &G2Projective::generator());
        let rhs = pubkey.miller_loop(msg).final_exponentiation();
        assert!(bool::from(lhs.ct_eq(&rhs)));
    }
    println!("All signatures are valid!");
}
