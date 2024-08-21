use criterion::{criterion_group, criterion_main};

mod group;
use group::g1::*;
use group::g2::*;

mod field;
use field::fp::*;
use field::fp12::*;
use field::fp2::*;
use field::fp6::*;

mod pairing;
use pairing::*;

criterion_group!(pairing_benches, test_pairing,);

criterion_group!(
    g1_benches,
    test_g1affine_conversion_to_g1projective,
    test_g1projective_generation,
    test_g1projective_addition,
    test_g1projective_multiplication,
    test_g1projective_conversion_to_g1affine
);
criterion_group!(
    g2_benches,
    test_g2affine_conversion_to_g2projective,
    test_g2projective_valid_generation,
    test_g2projective_addition,
    test_g2projective_multiplication
);

criterion_group!(
    fp_benches,
    test_fp_multiplication,
    test_fp_addition,
    test_fp_subtraction,
    test_fp_division,
    test_fp_random,
    test_fp_new
);
criterion_group!(
    fp2_benches,
    test_fp2_multiplication,
    test_fp2_addition,
    test_fp2_subtraction,
    test_fp2_division,
    test_fp2_random,
    test_fp2_new
);
criterion_group!(
    fp6_benches,
    test_fp6_multiplication,
    test_fp6_addition,
    test_fp6_subtraction,
    test_fp6_division,
    test_fp6_random,
    test_fp6_new
);
criterion_group!(
    fp12_benches,
    test_fp12_multiplication,
    test_fp12_addition,
    test_fp12_subtraction,
    test_fp12_division,
    test_fp12_random,
    test_fp12_new
);

criterion_main!(
    g1_benches,
    g2_benches,
    fp_benches,
    fp2_benches,
    fp6_benches,
    fp12_benches,
    pairing_benches
);
