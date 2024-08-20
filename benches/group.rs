#![allow(dead_code)]
use criterion::Criterion;
use sylow::{Fp, G1Affine, G1Projective, G2Affine, G2Projective, GroupTrait};

pub mod g1 {
    use super::*;
    use sylow::Fp;

    const KNOWN_VALUES: [Fp; 3] = [Fp::ONE, Fp::TWO, Fp::ONE];

    pub fn test_g1affine_conversion_to_g1projective(c: &mut Criterion) {
        c.bench_function("g1affine_conversion_to_g1projective", |b| {
            b.iter(|| G1Projective::from(G1Affine::generator()))
        });
    }
    pub fn test_g1projective_generation(c: &mut Criterion) {
        c.bench_function("test_g1projective_generation", |b| {
            b.iter(|| G1Projective::new(KNOWN_VALUES).expect("Failed to create G1Projective"))
        });
    }
    pub fn test_g1projective_addition(c: &mut Criterion) {
        c.bench_function("test_g1projective_addition", |b| {
            b.iter(|| {
                let a = G1Projective::generator();
                a + a
            })
        });
    }
    pub fn test_g1projective_multiplication(c: &mut Criterion) {
        c.bench_function("test_g1projective_multiplication", |b| {
            b.iter(|| {
                let g1_projective = G1Projective::generator();
                const SCALAR: Fp = Fp::THREE;
                g1_projective * SCALAR
            })
        });
    }
    pub fn test_g1projective_conversion_to_g1affine(c: &mut Criterion) {
        c.bench_function("g1affine_conversion_to_g1projective", |b| {
            b.iter(|| G1Affine::from(G1Projective::generator()))
        });
    }
}

pub mod g2 {
    use super::*;
    use crypto_bigint::U256;
    use sylow::Fp2;

    const KNOWN_X: Fp2 = Fp2::new(&[
        Fp::new(U256::from_words([
            15176525146662381588,
            16999198464856720888,
            10551491725746096164,
            2109507925758354620,
        ])),
        Fp::new(U256::from_words([
            5829542572658843162,
            6956048341656855305,
            457351042342223481,
            213802418293478404,
        ])),
    ]);
    const KNOWN_Y: Fp2 = Fp2::new(&[
        Fp::new(U256::from_words([
            16717123787957323851,
            9581483432139821434,
            7173403850490595536,
            650007998934857427,
        ])),
        Fp::new(U256::from_words([
            5081543861758110462,
            8687473586797606316,
            15555792616844701404,
            3266271495335422485,
        ])),
    ]);
    const KNOWN_Z: Fp2 = Fp2::new(&[Fp::ONE, Fp::ZERO]);
    pub fn test_g2affine_conversion_to_g1projective(c: &mut Criterion) {
        c.bench_function("g2affine_conversion_to_g1projective", |b| {
            b.iter(|| G2Projective::from(G2Affine::generator()))
        });
    }
    pub fn test_g2projective_valid_generation(c: &mut Criterion) {
        c.bench_function("test_g2projective_generation", |b| {
            b.iter(|| {
                G2Projective::new([KNOWN_X, KNOWN_Y, KNOWN_Z]).expect(
                    "Failed to create \
            G2Projective",
                )
            })
        });
    }
    pub fn test_g2projective_addition(c: &mut Criterion) {
        c.bench_function("test_g2projective_addition", |b| {
            b.iter(|| {
                let a = G2Projective::generator();
                a + a
            })
        });
    }
    pub fn test_g2projective_multiplication(c: &mut Criterion) {
        c.bench_function("test_g2projective_multiplication", |b| {
            b.iter(|| {
                let g2_projective = G2Projective::generator();
                const SCALAR: Fp = Fp::THREE;
                g2_projective * SCALAR
            })
        });
    }
    pub(crate) fn test_g2projective_conversion_to_g1affine(c: &mut Criterion) {
        c.bench_function("g1affine_conversion_to_g2projective", |b| {
            b.iter(|| G2Affine::from(G2Projective::generator()))
        });
    }
}
