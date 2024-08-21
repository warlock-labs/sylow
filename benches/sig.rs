use criterion::{black_box, Criterion};
use crypto_bigint::rand_core::OsRng;
use sha3::Keccak256;
use sylow::{FieldExtensionTrait, Fp, Fr, G1Projective, GroupTrait, XMDExpander};

const DST: &[u8; 30] = b"WARLOCK-CHAOS-V01-CS01-SHA-256";
const MSG: &[u8; 4] = &20_i32.to_be_bytes();
const K: u64 = 128;

pub fn test_signing(c: &mut Criterion) {
    let expander = XMDExpander::<Keccak256>::new(DST, K);
    let private_key = Fp::new(Fr::rand(&mut OsRng).value());

    c.bench_function("test_signing", |b| {
        b.iter(|| {
            if let Ok(hashed_message) = G1Projective::hash_to_curve(&expander, MSG) {
                let _signature = black_box(hashed_message) * black_box(private_key);
            }
        })
    });
}
