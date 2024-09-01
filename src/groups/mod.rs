pub(crate) mod g1;
pub(crate) mod g2;
pub(crate) mod group;
pub(crate) mod gt;

/// This test suite takes time, the biggest culprit of which is the multiplication. Really the
/// biggest bottleneck is assuredly the loading of the reference data from disk. The
/// multiplication just takes time due to the debugging symbols created by default when invoking
/// all the machinery required for multiplication of elements in the group. However, compiling
/// the code in release mode (without debug symbols + optimizations) gives the desired performance
/// of all arithmetic operations.
///
/// For instance, `cargo test --lib groups::g1::tests` takes ~22 seconds, while
/// `cargo test --release --lib groups::g1::tests` takes ~1 second. Keeping in mind that this
/// includes doing reference comparisons to sane values for 1000 values for multiple tests and
/// loads the data and processes it from disk at each test,
/// this means each group operation takes sub millisecond time, which is nice.
#[cfg(test)]
mod tests {
    use lazy_static::lazy_static;
    use serde::{Deserialize, Serialize};
    #[allow(unused_imports)]
    use std::{fs, path::Path};

    use crate::fields::fp::{FieldExtensionTrait, Fp};
    use crate::fields::fp2::Fp2;
    use crate::groups::g1::{G1Affine, G1Projective};
    use crate::groups::g2::G2Projective;

    #[derive(Serialize, Deserialize, Clone)]
    struct _G2Coords {
        c0: String,
        c1: String,
    }
    #[derive(Serialize, Deserialize, Clone)]
    struct _G2Projective {
        x: _G2Coords,
        y: _G2Coords,
        z: _G2Coords,
    }
    #[derive(Serialize, Deserialize)]
    struct _G1Projective {
        x: String,
        y: String,
        z: String,
    }
    #[derive(Serialize, Deserialize)]
    struct _G1 {
        a: Vec<_G1Projective>,
        b: Vec<_G1Projective>,
        r: Vec<String>,
        add: Vec<_G1Projective>,
        dbl: Vec<_G1Projective>,
        mul: Vec<_G1Projective>,
        svdw: Vec<_G1SVDW>,
    }
    #[derive(Serialize, Deserialize)]
    struct _G2 {
        a: Vec<_G2Projective>,
        b: Vec<_G2Projective>,
        r: Vec<String>,
        add: Vec<_G2Projective>,
        dbl: Vec<_G2Projective>,
        mul: Vec<_G2Projective>,
        invalid: Vec<_G2Projective>,
        psi: Vec<_G2Projective>,
    }
    #[derive(Serialize, Deserialize, Clone)]
    struct _G1SVDW {
        i: String,
        x: String,
        y: String,
        z: String,
    }
    struct G1Svdw {
        i: Fp,
        p: G1Projective,
    }
    #[derive(Serialize, Deserialize)]
    struct ReferenceData {
        g1: _G1,
        g2: _G2,
    }

    struct G1ReferenceData {
        a: Vec<G1Projective>,
        b: Vec<G1Projective>,
        r: Vec<Fp>,
        add: Vec<G1Projective>,
        dbl: Vec<G1Projective>,
        mul: Vec<G1Projective>,
        svdw: Vec<G1Svdw>,
    }
    struct G2ReferenceData {
        a: Vec<G2Projective>,
        b: Vec<G2Projective>,
        r: Vec<Fp>,
        add: Vec<G2Projective>,
        dbl: Vec<G2Projective>,
        mul: Vec<G2Projective>,
        psi: Vec<G2Projective>, // invalid: Vec<G2Projective>,
    }

    fn convert_to_g1svdw(svdw: &_G1SVDW) -> G1Svdw {
        let i = convert_to_fp(&svdw.i);
        let p = convert_to_g1projective(&_G1Projective {
            x: svdw.clone().x,
            y: svdw.clone().y,
            z: svdw.clone().z,
        });
        G1Svdw { i, p }
    }
    fn convert_to_g1projective(point: &_G1Projective) -> G1Projective {
        G1Projective::new([
            Fp::new_from_str(point.x.as_str()).expect(
                "failed to convert x coord in \
            g1",
            ),
            Fp::new_from_str(point.y.as_str()).expect("failed to convert y coord in g1"),
            Fp::new_from_str(point.z.as_str()).expect("failed to convert z coord in g1"),
        ])
        .expect("g1 failed")
    }
    fn convert_to_g2projective(point: &_G2Projective) -> G2Projective {
        G2Projective::new([
            Fp2::new(&[
                Fp::new_from_str(point.x.c0.as_str()).expect(
                    "failed to convert x0 coord in \
            g2",
                ),
                Fp::new_from_str(point.x.c1.as_str()).expect(
                    "failed to convert x1 coord in \
            g2",
                ),
            ]),
            Fp2::new(&[
                Fp::new_from_str(point.y.c0.as_str()).expect(
                    "failed to convert y0 coord in \
            g2",
                ),
                Fp::new_from_str(point.y.c1.as_str()).expect(
                    "failed to convert y1 coord in \
            g2",
                ),
            ]),
            Fp2::new(&[
                Fp::new_from_str(point.z.c0.as_str()).expect(
                    "failed to convert z0 coord in \
            g2",
                ),
                Fp::new_from_str(point.z.c1.as_str()).expect(
                    "failed to convert z1 coord in \
            g2",
                ),
            ]),
        ])
        .expect("g2 failed")
    }
    #[allow(clippy::ptr_arg)]
    fn convert_to_fp(r: &String) -> Fp {
        Fp::new_from_str(r).expect("failed to convert r to Fp")
    }
    const FNAME: &str = "./src/bn254_reference.json";
    // very minor, but wondering if this json file should be moved up from the sage dir

    lazy_static! {
        static ref REFERENCE_DATA: ReferenceData = {
            let path = Path::new(FNAME);
            let file_content = fs::read_to_string(path).expect("Failed to read file");
            serde_json::from_str(&file_content).expect("Failed to parse JSON")
        };
        static ref G1_REFERENCE_DATA: G1ReferenceData = G1ReferenceData {
            a: REFERENCE_DATA
                .g1
                .a
                .iter()
                .map(convert_to_g1projective)
                .collect(),
            b: REFERENCE_DATA
                .g1
                .b
                .iter()
                .map(convert_to_g1projective)
                .collect(),
            r: REFERENCE_DATA.g1.r.iter().map(convert_to_fp).collect(),
            add: REFERENCE_DATA
                .g1
                .add
                .iter()
                .map(convert_to_g1projective)
                .collect(),
            dbl: REFERENCE_DATA
                .g1
                .dbl
                .iter()
                .map(convert_to_g1projective)
                .collect(),
            mul: REFERENCE_DATA
                .g1
                .mul
                .iter()
                .map(convert_to_g1projective)
                .collect(),
            svdw: REFERENCE_DATA
                .g1
                .svdw
                .iter()
                .map(convert_to_g1svdw)
                .collect(),
        };
        static ref G2_REFERENCE_DATA: G2ReferenceData = G2ReferenceData {
            a: REFERENCE_DATA
                .g2
                .a
                .iter()
                .map(convert_to_g2projective)
                .collect(),
            b: REFERENCE_DATA
                .g2
                .b
                .iter()
                .map(convert_to_g2projective)
                .collect(),
            r: REFERENCE_DATA.g2.r.iter().map(convert_to_fp).collect(),
            add: REFERENCE_DATA
                .g2
                .add
                .iter()
                .map(convert_to_g2projective)
                .collect(),
            dbl: REFERENCE_DATA
                .g2
                .dbl
                .iter()
                .map(convert_to_g2projective)
                .collect(),
            mul: REFERENCE_DATA
                .g2
                .mul
                .iter()
                .map(convert_to_g2projective)
                .collect(),
            psi: REFERENCE_DATA
                .g2
                .psi
                .iter()
                .map(convert_to_g2projective)
                .collect(),
        };
        static ref G2_INVALIDS: Vec<_G2Projective> = REFERENCE_DATA
            .g2
            .invalid
            .iter()
            .map(|x| (*x).clone())
            .collect();
    }

    mod g1 {
        use super::*;
        use subtle::ConstantTimeEq;
        mod generation {
            use super::*;

            #[test]
            fn test_generation_and_conversion() {
                let _g1_points = &*G1_REFERENCE_DATA;
            }
            #[test]
            #[should_panic(expected = "Conversion to projective failed: NotOnCurve")]
            fn test_malformed_points() {
                let g1_points = &*G1_REFERENCE_DATA;
                for a in &g1_points.a {
                    let mut x = a.x;
                    let y = a.y;
                    let z = a.z;

                    // we intentionally manipulate a single coordinate to knock it
                    // off the curve, to check instantiation is not possible with
                    // a point not on the curve
                    x *= Fp::from(2);
                    let _ = G1Projective::new([x, y, z]).expect("Conversion to projective failed");
                }
            }
        }
        mod special_point_tests {
            use crate::groups::g1::G1Projective;
            use crate::groups::group::GroupTrait;

            #[test]
            fn infinity() {
                let a = &G1Projective::zero();
                let b = &G1Projective::zero();
                let c = a + b;
                assert!(
                    c.is_zero(),
                    "Identities don't add to yield another point at infinity"
                );
            }
            #[test]
            fn generator() {
                let g = &G1Projective::generator().double().double(); //4
                let h = &G1Projective::generator().double(); //2
                let j = g + h;

                let mut d = G1Projective::generator();
                for _ in 0..5 {
                    d = d + G1Projective::generator();
                }
                assert_eq!(j, d, "Generator multiplication not valid");
            }
        }
        mod addition_tests {
            use super::*;
            use crate::groups::group::GroupTrait;

            #[test]
            fn test_addition_closure() {
                let g1_points = &*G1_REFERENCE_DATA;
                for i in &g1_points.a[1..] {
                    let _ = i + &g1_points.a[0];
                }
            }

            #[test]
            fn test_addition_associativity_commutativity() {
                let g1_points = &*G1_REFERENCE_DATA;
                if let [a, b, c] = &g1_points.a[0..3] {
                    assert_eq!(&(a + b) + c, a + &(b + c), "Addition is not associative");
                    assert_eq!(a + b, b + a, "Addition is not commutative");
                }
            }
            #[test]
            fn test_addition_cases() {
                let g1_points = &*G1_REFERENCE_DATA;
                let expected = &g1_points.add;
                for (i, (a, b)) in g1_points.a.iter().zip(&g1_points.b).enumerate() {
                    let result = a + b;
                    assert_eq!(result, expected[i], "Simple addition failed");
                }
            }
            #[test]
            fn test_addition_edge_cases() {
                use crypto_bigint::rand_core::OsRng;
                let r = G1Projective::rand(&mut OsRng);
                let zero = &G1Projective::zero();
                assert_eq!(zero + &r, r, "Adding zero failed");
            }
        }
        mod subtraction_tests {
            use super::*;

            // the test below for additive identity is sufficient, in conjunction with a
            // successful addition test case run, to verify the accuracy of subtraction
            #[test]
            fn test_subtraction_closure() {
                let g1_points = &*G1_REFERENCE_DATA;
                let a = &g1_points.a[0];
                for i in &g1_points.a {
                    let _ = i - a;
                    let b = i - i;
                    assert_eq!(b, G1Projective::zero(), "Additive identity failed");
                }
            }
            #[test]
            fn test_subtraction_associativity() {
                let g1_points = &*G1_REFERENCE_DATA;
                if let [a, b, c] = &g1_points.a[0..3] {
                    assert_eq!(a - &(b - c), &(a - b) + c, "Subtraction is not associative");
                }
            }
        }

        mod multiplication_tests {
            use super::*;
            use crate::groups::group::GroupTrait;

            #[test]
            fn test_doubling() {
                let g1_points = &*G1_REFERENCE_DATA;
                for i in &g1_points.a {
                    assert_eq!(i.double(), i + i, "Doubling failed");
                }
            }

            #[test]
            fn test_scalar_mul() {
                let g1_points = &*G1_REFERENCE_DATA;
                let three = Fp::from(3);
                for i in &g1_points.a {
                    assert_eq!(i + &(i + i), i * &three, "Multiplication failed");
                }
            }
            #[test]
            fn test_random() {
                use crypto_bigint::rand_core::OsRng;
                for _ in 0..100 {
                    let p = G1Projective::rand(&mut OsRng);
                    let _ = G1Projective::new([p.x, p.y, p.z]).expect("Random point not on curve");
                }
            }
            #[test]
            fn test_multiplication_cases() {
                let g1_points = &*G1_REFERENCE_DATA;
                let expected = &g1_points.mul;
                for (i, (a, r)) in g1_points.a.iter().zip(&g1_points.r).enumerate() {
                    let result = a * r;
                    assert_eq!(result, expected[i], "Simple multiplication failed");
                }
                let expected = &g1_points.dbl;
                for (i, a) in g1_points.a.iter().enumerate() {
                    let result = a.double();
                    assert_eq!(result, expected[i], "Simple doubling failed");
                }
            }
        }
        mod hash_tests {
            use super::*;
            use crate::groups::g1::get_bn254_svdw;
            use crate::groups::group::GroupTrait;
            use crate::hasher::XMDExpander;
            use crate::svdw::SvdWTrait;
            use sha2::Sha256;

            const DST: &[u8; 30] = b"WARLOCK-CHAOS-V01-CS01-SHA-256";
            const MSG: &[u8; 4] = &20_i32.to_be_bytes();
            const K: u64 = 128;
            #[test]
            fn test_closure() {
                let expander = XMDExpander::<Sha256>::new(DST, K);
                if let Ok(_d) = G1Projective::hash_to_curve(&expander, MSG) {}
            }

            #[test]
            fn test_signature() {
                use crypto_bigint::rand_core::OsRng;
                use sha3::Keccak256;
                let expander = XMDExpander::<Keccak256>::new(DST, K);
                for _ in 0..1 {
                    let rando = <Fp as FieldExtensionTrait<1, 1>>::rand(&mut OsRng);
                    if let Ok(d) = G1Affine::sign_message(&expander, MSG, rando) {
                        println!("DST: {:?}", String::from_utf8_lossy(DST));
                        println!("Message: {:?}", String::from_utf8_lossy(MSG));
                        println!("private key: {:?}", rando.value());
                        println!(
                            "signature: {:?}, {:?}, {:?}\n",
                            d.x.value(),
                            d.y.value(),
                            d.infinity
                        );
                    }
                }
            }

            #[test]
            fn test_svdw() {
                let g1_points = &*G1_REFERENCE_DATA;

                if let Ok(d) = get_bn254_svdw() {
                    for s in g1_points.svdw.iter() {
                        let r = s.i;
                        let p = s.p;
                        let determined = G1Projective::from(
                            d.unchecked_map_to_point(r)
                                .expect("SVDW failed to map to point"),
                        );
                        assert_eq!(p, determined, "SVDW failed reference check");
                    }
                }
            }
        }
        #[test]
        fn test_equality() {
            let a1 = G1Affine::new([Fp::ONE, Fp::TWO]).expect("Failed to generate point on curve");
            let a2 = G1Affine::new([Fp::ONE, Fp::TWO]).expect("Failed to generate point on curve");
            assert_eq!(a1, a2, "Equality failed");
            assert!(bool::from(a1.ct_eq(&a2)), "Ctequality failed");

            let a3 = G1Affine::zero();
            assert_ne!(a1, a3, "Equality failed");
            assert!(!bool::from(a1.ct_eq(&a3)), "Ctequality failed");
        }
    }
    mod g2 {
        use super::*;
        use subtle::ConstantTimeEq;
        mod generation {
            use super::*;

            #[test]
            fn test_generation_and_conversion() {
                let _g2_points = &*G2_REFERENCE_DATA;
            }
            #[test]
            #[should_panic(expected = "g2 failed: NotInSubgroup")]
            fn invalid_subgroup_check() {
                let _g2_points = &*G2_REFERENCE_DATA;
                let g2_invalids = &*G2_INVALIDS;
                let _p: Vec<G2Projective> =
                    g2_invalids.iter().map(convert_to_g2projective).collect();
            }
            #[test]
            #[should_panic(expected = "Endomorphism failed: NotOnCurve")]
            fn test_malformed_points() {
                let g2_points = &*G2_REFERENCE_DATA;
                for a in &g2_points.a {
                    let mut x = a.x;
                    let y = a.y;
                    let z = a.z;

                    // we intentionally manipulate a single coordinate to knock it
                    // off the curve, to check instantiation is not possible with
                    // a point not on the curve
                    x *= Fp2::from(2);
                    let _ = G2Projective::new([x, y, z]).expect(
                        "Conversion to \
                    projective failed",
                    );
                }
            }
        }
        mod special_point_tests {
            use crate::groups::g2::G2Projective;
            use crate::groups::group::GroupTrait;

            #[test]
            fn infinity() {
                let a = &G2Projective::zero();
                let b = &G2Projective::zero();
                let c = a + b;
                assert!(
                    c.is_zero(),
                    "Identities don't add to yield another point at infinity"
                );
            }
            #[test]
            fn generator() {
                let g = &G2Projective::generator().double().double(); //4
                let h = &G2Projective::generator().double(); //2
                let j = g + h;

                let mut d = G2Projective::generator();
                for _ in 0..5 {
                    d = d + G2Projective::generator();
                }
                assert_eq!(j, d, "Generator multiplication not valid");
            }
        }
        mod addition_tests {
            use super::*;

            #[test]
            fn test_addition_closure() {
                let g2_points = &*G2_REFERENCE_DATA;
                for i in &g2_points.a[1..] {
                    let _ = i + &g2_points.a[0];
                }
            }

            #[test]
            fn test_addition_associativity_commutativity() {
                let g2_points = &*G2_REFERENCE_DATA;
                if let [a, b, c] = &g2_points.a[0..3] {
                    assert_eq!(&(a + b) + c, a + &(b + c), "Addition is not associative");
                    assert_eq!(a + b, b + a, "Addition is not commutative");
                }
            }
            #[test]
            fn test_addition_cases() {
                let g2_points = &*G2_REFERENCE_DATA;
                let expected = &g2_points.add;
                for (i, (a, b)) in g2_points.a.iter().zip(&g2_points.b).enumerate() {
                    let result = a + b;
                    assert_eq!(result, expected[i], "Simple addition failed");
                }
            }
            #[test]
            fn test_addition_edge_cases() {
                let g2_points = &*G2_REFERENCE_DATA;
                let zero = &G2Projective::zero();
                assert_eq!(zero + &g2_points.a[0], g2_points.a[0], "Adding zero failed");
            }
        }
        mod subtraction_tests {
            use super::*;
            #[test]
            fn test_subtraction_closure() {
                let g2_points = &*G2_REFERENCE_DATA;
                let a = &g2_points.a[0];
                for i in &g2_points.a {
                    let _ = i - a;
                    let b = i - i;
                    assert_eq!(b, G2Projective::zero(), "Additive identity failed");
                }
            }
            #[test]
            fn test_subtraction_associativity() {
                let g2_points = &*G2_REFERENCE_DATA;
                if let [a, b, c] = &g2_points.a[0..3] {
                    assert_eq!(a - &(b - c), &(a - b) + c, "Subtraction is not associative");
                }
            }
        }
        mod multiplication_tests {
            use super::*;
            use crate::groups::group::GroupTrait;

            #[test]
            fn test_doubling() {
                let g2_points = &*G2_REFERENCE_DATA;
                for i in &g2_points.a {
                    assert_eq!(i.double(), i + i, "Doubling failed");
                }
            }

            #[test]
            fn test_scalar_mul() {
                let g2_points = &*G2_REFERENCE_DATA;
                let three = Fp::from(3);
                for i in &g2_points.a {
                    assert_eq!(i + &(i + i), i * &three, "Multiplication failed");
                }
            }
            #[test]
            fn test_multiplication_cases() {
                let g2_points = &*G2_REFERENCE_DATA;
                let expected = &g2_points.mul;
                for (i, (a, r)) in g2_points.a.iter().zip(&g2_points.r).enumerate() {
                    let result = a * r;
                    assert_eq!(result, expected[i], "Simple multiplication failed");
                }
                let expected = &g2_points.dbl;
                for (i, a) in g2_points.a.iter().enumerate() {
                    let result = a.double();
                    assert_eq!(result, expected[i], "Simple doubling failed");
                }
            }
            #[test]
            fn test_random() {
                use crypto_bigint::rand_core::OsRng;
                for _ in 0..100 {
                    let _p = G2Projective::rand(&mut OsRng);
                }
            }
        }
        mod endomorphism_tests {
            use super::*;
            use crate::groups::group::GroupTrait;

            #[test]
            fn test_psi() {
                let g2_points = &*G2_REFERENCE_DATA;
                let expected = &g2_points.psi;
                for (i, a) in g2_points.a.iter().enumerate() {
                    let result = a.endomorphism();
                    assert_eq!(result, expected[i], "Endomorphic mapping failed");
                }
            }
        }
        #[test]
        fn test_equality() {
            let a1 = G1Projective::new([Fp::ONE, Fp::TWO, Fp::ONE]).expect(
                "Failed to generate \
            point on \
            curve",
            );
            let a2 = G1Projective::new([Fp::ONE, Fp::TWO, Fp::ONE]).expect(
                "Failed to generate \
            point on \
            curve",
            );
            assert_eq!(a1, a2, "Equality failed");
            assert!(bool::from(a1.ct_eq(&a2)), "Ctequality failed");

            let a3 = G1Projective::zero();
            assert_ne!(a1, a3, "Equality failed");
            assert!(!bool::from(a1.ct_eq(&a3)), "Ctequality failed");
        }
    }
    mod gt {
        use super::*;
        use crate::groups::gt::Gt;
        use crate::Fp12;
        use crypto_bigint::rand_core::OsRng;
        use subtle::{Choice, ConditionallySelectable};

        #[test]
        fn test_conditional_select() {
            let a = Gt(Fp12::rand(&mut OsRng));
            let b = Gt(Fp12::rand(&mut OsRng));
            assert_eq!(Gt::conditional_select(&a, &b, Choice::from(0u8)), a);
            assert_eq!(Gt::conditional_select(&a, &b, Choice::from(1u8)), b);
        }
    }

    mod invariants {
        use super::*;
        use crypto_bigint::rand_core::OsRng;
        use proptest::prelude::*;
        fn arbitrary_fp() -> impl Strategy<Value = Fp> {
            any::<u64>().prop_map(|_x| <Fp as FieldExtensionTrait<1, 1>>::rand(&mut OsRng))
        }

        fn arbitrary_g1() -> impl Strategy<Value = G1Projective> {
            (arbitrary_fp(), arbitrary_fp(), arbitrary_fp())
                .prop_map(|(x, y, z)| G1Projective::new([x, y, z]).unwrap_or(G1Projective::zero()))
        }
        mod g1 {
            use super::*;
            proptest! {
                #[test]
                fn test_addition_commutativity(a in arbitrary_g1(), b in arbitrary_g1()) {
                    prop_assert_eq!(a + b, b + a);
                }

                #[test]
                fn test_scalar_multiplication_distributivity(a in arbitrary_g1(), b in arbitrary_g1(), s in arbitrary_fp()) {
                    prop_assert_eq!((a + b) * s, a * s + b * s);
                }

                #[test]
                fn test_identity_element(a in arbitrary_g1()) {
                    prop_assert_eq!(a + G1Projective::zero(), a);
                }

                #[test]
                fn test_inverse_element(a in arbitrary_g1()) {
                    prop_assert_eq!(a + (-a), G1Projective::zero());
                }
            }
        }
    }

    mod fuzz {
        use super::*;
        use crate::GroupTrait;
        use quickcheck_macros::quickcheck;

        #[quickcheck]
        fn fuzz_addition_associativity(a: u64, b: u64, c: u64) -> bool {
            let g1 = G1Projective::generator();
            let p1 = g1 * Fp::from(a);
            let p2 = g1 * Fp::from(b);
            let p3 = g1 * Fp::from(c);

            let g2 = G2Projective::generator();
            let q1 = g2 * Fp::from(a);
            let q2 = g2 * Fp::from(b);
            let q3 = g2 * Fp::from(c);

            ((p1 + p2) + p3 == p1 + (p2 + p3)) & ((q1 + q2) + q3 == q1 + (q2 + q3))
        }
        #[quickcheck]
        fn fuzz_scalar_multiplication(a: u64, b: u64) -> bool {
            let g1 = G1Projective::generator();
            let s1 = Fp::from(a);
            let s2 = Fp::from(b);

            let g2 = G2Projective::generator();
            let t1 = Fp::from(a);
            let t2 = Fp::from(b);

            ((g1 * s1) * s2 == g1 * (s1 * s2)) & ((g2 * t1) * t2 == g2 * (t1 * t2))
        }
    }
    mod bytes {
        use super::*;
        use crate::G2Affine;

        #[test]
        fn test_g1_uncompressed() {
            let g1_points = &*G1_REFERENCE_DATA;
            for g1 in g1_points.a.iter().map(G1Affine::from) {
                let g1_serialized = g1.to_uncompressed();
                let g1_deserialized =
                    G1Affine::from_uncompressed(&g1_serialized).expect("Deserialization failed");
                assert_eq!(g1, g1_deserialized.into());
            }
        }

        #[test]
        fn test_bad_g1_uncompressed() {
            let g1_points = &*G1_REFERENCE_DATA;
            for g1 in g1_points.a.iter().map(G1Affine::from) {
                let mut g1_serialized = g1.to_uncompressed();
                let g1_serialized_copy = g1_serialized;

                // flip some things around in the x and y coordinates, basically jumbling up the
                // bytes
                g1_serialized[26..32].copy_from_slice(&g1_serialized_copy[32..38]);
                g1_serialized[32..38].copy_from_slice(&g1_serialized_copy[26..32]);

                let g1_deserialized = G1Affine::from_uncompressed(&g1_serialized);
                match bool::from(g1_deserialized.is_some()) {
                    true => panic!("Deserialization should have failed"),
                    false => continue,
                }
            }
        }

        #[test]
        fn test_special_points() {
            let a = G1Affine::zero();
            let a_serialized = a.to_uncompressed();
            let a_deserialized =
                G1Affine::from_uncompressed(&a_serialized).expect("Deserialization failed");

            assert_eq!(
                a,
                a_deserialized.into(),
                "Handling point at infinity failed"
            );

            let a = G2Affine::zero();
            let a_serialized = a.to_uncompressed();
            let a_deserialized =
                G2Affine::from_uncompressed(&a_serialized).expect("Deserialization failed");

            assert_eq!(
                a,
                a_deserialized.into(),
                "Handling point at infinity failed"
            );
        }

        #[test]
        fn test_g2_uncompressed() {
            let g2_points = &*G2_REFERENCE_DATA;
            for g2 in g2_points.a.iter().map(G2Affine::from) {
                let g2_serialized = g2.to_uncompressed();
                let g2_deserialized =
                    G2Affine::from_uncompressed(&g2_serialized).expect("Deserialization failed");
                assert_eq!(g2, g2_deserialized.into());
            }
        }
        //
        #[test]
        #[should_panic(expected = "Endomorphism failed: NotOnCurve")]
        fn test_bad_g2_uncompressed() {
            let g2_points = &*G2_REFERENCE_DATA;
            for g2 in g2_points.a.iter().map(G2Affine::from) {
                let mut g2_serialized = g2.to_uncompressed();
                let g2_serialized_copy = g2_serialized;

                // flip some things around in the x and y coordinates, basically jumbling up the
                // bytes
                g2_serialized[26..32].copy_from_slice(&g2_serialized_copy[32..38]);
                g2_serialized[32..38].copy_from_slice(&g2_serialized_copy[26..32]);

                g2_serialized[58..64].copy_from_slice(&g2_serialized_copy[64..70]);
                g2_serialized[64..70].copy_from_slice(&g2_serialized_copy[58..64]);

                let _g2_deserialized = G2Affine::from_uncompressed(&g2_serialized);
            }
        }
    }
}
