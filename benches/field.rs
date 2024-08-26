// Would testing for operations running in const time, e.g. through sampling,
// be feasible as a part of benchmark or other testing?
#![allow(dead_code)]
use criterion::{black_box, Criterion};
use crypto_bigint::rand_core::OsRng;
use crypto_bigint::U256;
use sylow::{FieldExtensionTrait, Fp, Fp12, Fp2, Fp6};
pub mod fp {
    use super::*;
    const A: Fp = Fp::THREE;
    const B: Fp = Fp::FOUR;

    pub fn test_fp_multiplication(c: &mut Criterion) {
        c.bench_function("test_fp_multiplication", |b| {
            b.iter(|| black_box(A) * black_box(B))
        });
    }
    pub fn test_fp_addition(c: &mut Criterion) {
        c.bench_function("test_fp_addition", |b| {
            b.iter(|| black_box(A) + black_box(B))
        });
    }
    pub fn test_fp_subtraction(c: &mut Criterion) {
        c.bench_function("test_fp_subtraction", |b| {
            b.iter(|| black_box(A) - black_box(B))
        });
    }
    pub fn test_fp_division(c: &mut Criterion) {
        c.bench_function("test_fp_division", |b| {
            b.iter(|| black_box(A) / black_box(B))
        });
    }
    pub fn test_fp_random(c: &mut Criterion) {
        let mut rng = OsRng;
        c.bench_function("test_fp_random", |b| {
            b.iter(|| <Fp as FieldExtensionTrait<1, 1>>::rand(&mut rng))
        });
    }
    pub fn test_fp_new(c: &mut Criterion) {
        c.bench_function("test_fp_new", |b| {
            b.iter(|| Fp::new(U256::from_words([1, 2, 3, 4])))
        });
    }
}

pub mod fp2 {
    use super::*;
    const A: Fp2 = Fp2::new(&[Fp::FOUR, Fp::NINE]);
    const B: Fp2 = Fp2::new(&[Fp::NINE, Fp::FOUR]);

    pub fn test_fp2_multiplication(c: &mut Criterion) {
        c.bench_function("test_fp2_multiplication", |b| {
            b.iter(|| black_box(A) * black_box(B))
        });
    }
    pub fn test_fp2_addition(c: &mut Criterion) {
        c.bench_function("test_fp2_addition", |b| {
            b.iter(|| black_box(A) + black_box(B))
        });
    }
    pub fn test_fp2_subtraction(c: &mut Criterion) {
        c.bench_function("test_fp2_subtraction", |b| {
            b.iter(|| black_box(A) - black_box(B))
        });
    }
    pub fn test_fp2_division(c: &mut Criterion) {
        c.bench_function("test_fp2_division", |b| {
            b.iter(|| black_box(A) / black_box(B))
        });
    }
    pub fn test_fp2_random(c: &mut Criterion) {
        let mut rng = OsRng;
        c.bench_function("test_fp2_random", |b| {
            b.iter(|| <Fp2 as FieldExtensionTrait<2, 2>>::rand(&mut rng))
        });
    }
    pub fn test_fp2_new(c: &mut Criterion) {
        c.bench_function("test_fp2_new", |b| {
            b.iter(|| {
                Fp2::new(&[
                    Fp::new(U256::from_words([1, 2, 3, 4])),
                    Fp::new(U256::from_words([1, 2, 3, 4])),
                ])
            })
        });
    }
}
pub mod fp6 {
    use super::*;
    const A: Fp6 = Fp6::new(&[
        Fp2::new(&[Fp::FOUR, Fp::NINE]),
        Fp2::new(&[Fp::FOUR, Fp::NINE]),
        Fp2::new(&[Fp::FOUR, Fp::NINE]),
    ]);

    const B: Fp6 = Fp6::new(&[
        Fp2::new(&[Fp::NINE, Fp::FOUR]),
        Fp2::new(&[Fp::NINE, Fp::FOUR]),
        Fp2::new(&[Fp::NINE, Fp::FOUR]),
    ]);

    pub fn test_fp6_multiplication(c: &mut Criterion) {
        c.bench_function("test_fp6_multiplication", |b| {
            b.iter(|| black_box(A) * black_box(B))
        });
    }
    pub fn test_fp6_addition(c: &mut Criterion) {
        c.bench_function("test_fp6_addition", |b| {
            b.iter(|| black_box(A) + black_box(B))
        });
    }
    pub fn test_fp6_subtraction(c: &mut Criterion) {
        c.bench_function("test_fp6_subtraction", |b| {
            b.iter(|| black_box(A) - black_box(B))
        });
    }
    pub fn test_fp6_division(c: &mut Criterion) {
        c.bench_function("test_fp6_division", |b| {
            b.iter(|| black_box(A) / black_box(B))
        });
    }
    pub fn test_fp6_random(c: &mut Criterion) {
        let mut rng = OsRng;
        c.bench_function("test_fp6_random", |b| {
            b.iter(|| <Fp6 as FieldExtensionTrait<6, 3>>::rand(&mut rng))
        });
    }
    pub fn test_fp6_new(c: &mut Criterion) {
        c.bench_function("test_fp6_new", |b| {
            b.iter(|| {
                Fp6::new(&[
                    Fp2::new(&[
                        Fp::new(U256::from_words([1, 2, 3, 4])),
                        Fp::new(U256::from_words([1, 2, 3, 4])),
                    ]),
                    Fp2::new(&[
                        Fp::new(U256::from_words([1, 2, 3, 4])),
                        Fp::new(U256::from_words([1, 2, 3, 4])),
                    ]),
                    Fp2::new(&[
                        Fp::new(U256::from_words([1, 2, 3, 4])),
                        Fp::new(U256::from_words([1, 2, 3, 4])),
                    ]),
                ])
            })
        });
    }
}
pub mod fp12 {
    use super::*;
    const A: Fp12 = Fp12::new(&[
        Fp6::new(&[
            Fp2::new(&[Fp::FOUR, Fp::NINE]),
            Fp2::new(&[Fp::FOUR, Fp::NINE]),
            Fp2::new(&[Fp::FOUR, Fp::NINE]),
        ]),
        Fp6::new(&[
            Fp2::new(&[Fp::FOUR, Fp::NINE]),
            Fp2::new(&[Fp::FOUR, Fp::NINE]),
            Fp2::new(&[Fp::FOUR, Fp::NINE]),
        ]),
    ]);

    const B: Fp12 = Fp12::new(&[
        Fp6::new(&[
            Fp2::new(&[Fp::NINE, Fp::FOUR]),
            Fp2::new(&[Fp::NINE, Fp::FOUR]),
            Fp2::new(&[Fp::NINE, Fp::FOUR]),
        ]),
        Fp6::new(&[
            Fp2::new(&[Fp::NINE, Fp::FOUR]),
            Fp2::new(&[Fp::NINE, Fp::FOUR]),
            Fp2::new(&[Fp::NINE, Fp::FOUR]),
        ]),
    ]);
    pub fn test_fp12_multiplication(c: &mut Criterion) {
        c.bench_function("test_fp12_multiplication", |b| {
            b.iter(|| black_box(A) * black_box(B))
        });
    }
    pub fn test_fp12_addition(c: &mut Criterion) {
        c.bench_function("test_fp12_addition", |b| {
            b.iter(|| black_box(A) + black_box(B))
        });
    }
    pub fn test_fp12_subtraction(c: &mut Criterion) {
        c.bench_function("test_fp12_subtraction", |b| {
            b.iter(|| black_box(A) - black_box(B))
        });
    }
    pub fn test_fp12_division(c: &mut Criterion) {
        c.bench_function("test_fp12_division", |b| {
            b.iter(|| black_box(A) / black_box(B))
        });
    }
    pub fn test_fp12_random(c: &mut Criterion) {
        let mut rng = OsRng;
        c.bench_function("test_fp12_random", |b| b.iter(|| Fp12::rand(&mut rng)));
    }
    pub fn test_fp12_new(c: &mut Criterion) {
        c.bench_function("test_fp12_new", |b| {
            b.iter(|| {
                Fp12::new(&[
                    Fp6::new(&[
                        Fp2::new(&[
                            Fp::new(U256::from_words([1, 2, 3, 4])),
                            Fp::new(U256::from_words([1, 2, 3, 4])),
                        ]),
                        Fp2::new(&[
                            Fp::new(U256::from_words([1, 2, 3, 4])),
                            Fp::new(U256::from_words([1, 2, 3, 4])),
                        ]),
                        Fp2::new(&[
                            Fp::new(U256::from_words([1, 2, 3, 4])),
                            Fp::new(U256::from_words([1, 2, 3, 4])),
                        ]),
                    ]),
                    Fp6::new(&[
                        Fp2::new(&[
                            Fp::new(U256::from_words([1, 2, 3, 4])),
                            Fp::new(U256::from_words([1, 2, 3, 4])),
                        ]),
                        Fp2::new(&[
                            Fp::new(U256::from_words([1, 2, 3, 4])),
                            Fp::new(U256::from_words([1, 2, 3, 4])),
                        ]),
                        Fp2::new(&[
                            Fp::new(U256::from_words([1, 2, 3, 4])),
                            Fp::new(U256::from_words([1, 2, 3, 4])),
                        ]),
                    ]),
                ])
            })
        });
    }
}
