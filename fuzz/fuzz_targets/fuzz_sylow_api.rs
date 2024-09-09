#![no_main]
use libfuzzer_sys::fuzz_target;
use sylow::{
    KeyPair, sign, verify, G1Projective, G2Projective, pairing, Fp, Fr,
    GroupTrait, FieldExtensionTrait, Gt, XMDExpander
};
use sha3::Keccak256;
use crypto_bigint::rand_core::OsRng;

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }

    // Test case from g1::tests::test_addition_commutativity
    let a = G1Projective::rand(&mut OsRng);
    let b = G1Projective::rand(&mut OsRng);
    assert_eq!(a + b, b + a, "G1 addition is not commutative");

    // Test case from g2::tests::test_addition_commutativity
    let c = G2Projective::rand(&mut OsRng);
    let d = G2Projective::rand(&mut OsRng);
    assert_eq!(c + d, d + c, "G2 addition is not commutative");

    // Test case from g1::tests::test_doubling
    assert_eq!(a.double(), a + a, "G1 doubling failed");

    // Test case from g2::tests::test_doubling
    assert_eq!(c.double(), c + c, "G2 doubling failed");

    // Test case from g1::tests::test_scalar_mul
    let three = Fp::from(3u64);
    assert_eq!(a + (a + a), a * three, "G1 scalar multiplication failed");

    // Test case from g2::tests::test_scalar_mul
    assert_eq!(c + (c + c), c * three, "G2 scalar multiplication failed");

    // Test case from gt::tests::test_bilinearity
    let p = G1Projective::rand(&mut OsRng);
    let q = G2Projective::rand(&mut OsRng);
    let s = Fr::rand(&mut OsRng);
    let sp = G1Projective::from(p) * s.into();
    let sq = G2Projective::from(q) * s.into();

    let a = pairing(&p, &q) * s;
    let b = pairing(&sp, &q);
    let c = pairing(&p, &sq);

    assert_eq!(a, b, "Pairing bilinearity property failed");
    assert_eq!(a, c, "Pairing bilinearity property failed");

    let t = -Fr::ONE;
    assert_ne!(a, Gt::identity(), "Pairing result should not be identity");
    assert_eq!(&(a * t) + &a, Gt::identity(), "Pairing inverse property failed");

    // Test case from g1::tests::test_hash_to_curve
    let dst = b"QUUX-V01-CS02-with-expander-SHA256-128";
    let expander = XMDExpander::<Keccak256>::new(dst, 128);
    if let Ok(hash_point) = G1Projective::hash_to_curve(&expander, &data[..32]) {
        assert!(!hash_point.is_zero(), "Hash to curve resulted in zero point");
    }

    // Test BLS signature scheme
    let key_pair = KeyPair::generate();
    match sign(&key_pair.secret_key, &data[32..64]) {
        Ok(signature) => {
            match verify(&key_pair.public_key, &data[32..64], &signature) {
                Ok(is_valid) => assert!(is_valid, "Signature verification failed"),
                Err(_) => panic!("Verification error"),
            }
        }
        Err(_) => println!("Signing error"),
    }
});