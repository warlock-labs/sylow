use crate::fields::fp::Fp;
use crate::groups::group::{GroupAffine, GroupProjective, GroupTrait};
use crypto_bigint::subtle::Choice;
use num_traits::{One, Zero};

type G1Affine = GroupAffine<1, 1, Fp>;
type G1Projective = GroupProjective<1, 1, Fp>;

impl GroupTrait<1, 1, Fp> for G1Affine {
    fn generator() -> Self {
        todo!()
    }

    fn endomorphism(&self) -> Self {
        Self::one()
    }
}
// impl Default for
impl GroupTrait<1, 1, Fp> for G1Projective {
    // fn is_on_curve(&self) -> Choice {
    //     _g1projective_is_on_curve(&self.x, &self.y, &self.z)
    // }
    // fn is_torsion_free(&self) -> Choice {
    //     _g1projective_is_torsion_free(&self.x, &self.y, &self.z)
    // }
    fn generator() -> Self {
        todo!()
    }
    fn endomorphism(&self) -> Self {
        Self::one()
    }
}

#[cfg(test)]
mod tests {
    use crate::fields::fp::FinitePrimeField;

    #[test]
    fn test_g1() {
        use super::*;
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

        #[derive(Serialize, Deserialize)]
        struct ReferenceData {
            G1_signatures: Vec<_G1Affine>,
            G2_public_keys: Vec<_G2Affine>,
            bad_G2_public_keys: Vec<_G2Affine>,
            svdw: Vec<_SVDW>,
        }

        fn convert_g1_point(point: &_G1Affine) -> G1Affine {
            G1Affine::new([
                Fp::new_from_str(point.x.as_str()).expect("failed to convert x coord in g1"),
                Fp::new_from_str(point.y.as_str()).expect("failed to convert y coord in g1"),
            ])
            .expect("g1 failed")
        }
        let file_content = fs::read_to_string(
            "/home/trbritt/Desktop/warlock/solbls/test/sage_reference/bn254_reference.json",
        )
        .expect(
            "Failed to read \
    file",
        );
        let reference_data: ReferenceData =
            serde_json::from_str(&file_content).expect("Failed to parse JSON");
        let g1_points: Vec<G1Affine> = reference_data
            .G1_signatures
            .iter()
            .map(convert_g1_point)
            .collect();
        let _ = g1_points.iter().map(|&i| {
            assert_eq!(i, G1Affine::from(G1Projective::from(i)),
                       "Conversion failed");
        });
    }
}
