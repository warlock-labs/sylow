use crate::fields::fp::{FieldExtensionTrait, FinitePrimeField, Fp};
use crate::groups::group::{GroupAffine, GroupProjective, GroupTrait};
use crypto_bigint::rand_core::CryptoRngCore;
use num_traits::One;

type G1Affine = GroupAffine<1, 1, Fp>;
type G1Projective = GroupProjective<1, 1, Fp>;

impl GroupTrait<1, 1, Fp> for G1Affine {
    fn generator() -> Self {
        Self::new([Fp::one(), Fp::from(2)]).expect("Generator failed")
    }

    fn endomorphism(&self) -> Self {
        Self::generator()
    }
    fn rand<R: CryptoRngCore>(rng: &mut R) -> Self {
        Self::from(G1Projective::rand(rng))
    }
}
// impl Default for
impl GroupTrait<1, 1, Fp> for G1Projective {
    fn generator() -> Self {
        Self::from(G1Affine::generator())
    }
    fn endomorphism(&self) -> Self {
        Self::generator()
    }
    fn rand<R: CryptoRngCore>(rng: &mut R) -> Self {
        &Self::generator()
            * &<Fp as FieldExtensionTrait<1, 1>>::rand(rng)
                .value()
                .to_le_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fields::fp::FinitePrimeField;
    use serde::{Deserialize, Serialize};
    use std::fs;

    #[derive(Serialize, Deserialize)]
    struct _G1Affine {
        x: String,
        y: String,
    }

    #[derive(Serialize, Deserialize)]
    struct _G2AffineCoordinate {
        c0: String,
        c1: String,
    }

    #[derive(Serialize, Deserialize)]
    struct _G2Affine {
        x: _G2AffineCoordinate,
        y: _G2AffineCoordinate,
    }

    #[derive(Serialize, Deserialize)]
    struct _SVDW {
        i: String,
        x: String,
        y: String,
    }
    #[allow(non_snake_case)]
    #[derive(Serialize, Deserialize)]
    struct ReferenceData {
        G1_signatures: Vec<_G1Affine>,
        G2_public_keys: Vec<_G2Affine>,
        bad_G2_public_keys: Vec<_G2Affine>,
        svdw: Vec<_SVDW>,
    }

    fn convert_to_g1affine(point: &_G1Affine) -> G1Affine {
        G1Affine::new([
            Fp::new_from_str(point.x.as_str()).expect("failed to convert x coord in g1"),
            Fp::new_from_str(point.y.as_str()).expect("failed to convert y coord in g1"),
        ])
        .expect("g1 failed")
    }

    const FNAME: &str = "/home/trbritt/Desktop/warlock/solbls/test/sage_reference\
    /bn254_reference.json";
    macro_rules! load_reference_data {
        ($wrapper_name:ident) => {
            let file_content = fs::read_to_string(FNAME).expect("Failed to read file");
            let reference_data: ReferenceData =
                serde_json::from_str(&file_content).expect("Failed to parse JSON");
            let _affine: Vec<G1Affine> = reference_data
                .G1_signatures
                .iter()
                .map(convert_to_g1affine)
                .collect();
            let $wrapper_name: Vec<G1Projective> =
                _affine.iter().map(|&i| G1Projective::from(i)).collect();
        };
    }
    mod generation {
        use super::*;
        #[test]
        fn test_generation_and_conversion() {
            load_reference_data!(_g1_points);
        }
    }
    mod addition_tests {
        use super::*;
        #[test]
        fn test_addition_closure() {
            load_reference_data!(g1_points);
            for i in &g1_points[1..] {
                let _ = i + &g1_points[0];
            }
        }

        #[test]
        fn test_addition_associativity_commutativity() {
            load_reference_data!(g1_points);
            if let [a, b, c] = &g1_points[0..3] {
                assert_eq!(&(a + b) + c, a + &(b + c), "Addition is not associative");
                assert_eq!(a + b, b + a, "Addition is not commutative");
            }
        }
    }
    mod subtraction_tests {
        use super::*;
        #[test]
        fn test_subtraction_closure() {
            load_reference_data!(g1_points);
            let a = &g1_points[0];
            for i in &g1_points {
                let _ = i - a;
                let b = i - i;
                assert_eq!(b, G1Projective::zero(), "Additive identity failed");
            }
        }
        #[test]
        fn test_subtraction_associativity() {
            load_reference_data!(g1_points);
            if let [a, b, c] = &g1_points[0..3] {
                assert_eq!(a - &(b - c), &(a - b) + c, "Subtraction is not associative");
            }
        }
    }

    mod multiplication_tests {
        use super::*;
        #[test]
        fn test_doubling() {
            load_reference_data!(g1_points);
            for i in &g1_points {
                assert_eq!(i.double(), i + i, "Doubling failed");
            }
        }

        #[test]
        fn test_scalar_mul() {
            load_reference_data!(g1_points);
            let three = Fp::from(3);
            for i in &g1_points {
                assert_eq!(
                    i + &(i + i),
                    i * &three.value().to_le_bytes(),
                    "Multiplication failed"
                );
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
    }
}
