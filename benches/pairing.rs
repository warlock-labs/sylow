#![allow(dead_code)]
use criterion::Criterion;
use sylow::{G1Projective, G2Projective, GroupTrait, pairing};

pub fn test_pairing(c: &mut Criterion) {
    c.bench_function("test_pairing", |b| {
        b.iter(|| {
            pairing(
                    &G1Projective::generator(),
                    &G2Projective::generator()
                )
            }
        )
    });
}
