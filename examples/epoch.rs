use crypto_bigint::rand_core::OsRng;
use subtle::ConstantTimeEq;
use sylow::{
    pairing, FieldExtensionTrait, Fp, Fr, G1Affine, G1Projective, G2Affine, G2Projective,
    GroupTrait,
};

fn main() {
    let private_key = Fp::new(Fr::rand(&mut OsRng).value());
    let pubkey = G2Affine::from(G2Projective::generator() * private_key).precompute();

    let signatures: Vec<(G1Affine, G1Projective)> = (0..10)
        .map(|_| {
            let hashed_msg = G1Projective::rand(&mut OsRng);
            (G1Affine::from(hashed_msg), hashed_msg * private_key)
        })
        .collect();

    for (msg, sig) in &signatures {
        let lhs = pairing(sig, &G2Projective::generator());
        let rhs = pubkey.miller_loop(msg).final_exponentiation();
        assert!(bool::from(lhs.ct_eq(&rhs)));
    }
}
