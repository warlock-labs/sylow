#![allow(dead_code)]
use criterion::{black_box, Criterion};
use sylow::{pairing, G1Projective, G2Projective, GroupTrait};

pub fn test_pairing(c: &mut Criterion) {
    let ga = G1Projective::generator();
    let gb = G2Projective::generator();
    c.bench_function("test_pairing", |b| {
        b.iter(|| pairing(&black_box(ga), &black_box(gb)))
    });
}
