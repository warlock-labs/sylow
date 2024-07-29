use crate::fields::fp::{FieldExtensionTrait, FinitePrimeField, Fp};
use crate::groups::group::{Error, GroupAffine, GroupProjective, GroupTrait};
use crypto_bigint::subtle::Choice;
use num_traits::{One, Zero};
use subtle::ConstantTimeEq;

type G1Affine = GroupAffine<1, 1, Fp>;
type G1Projective = GroupProjective<1, 1, Fp>;

#[inline(always)]
fn _g1affine_is_on_curve(x: &Fp, y: &Fp, z: &Choice) -> Choice {
    let y2 = <Fp as FieldExtensionTrait<1, 1>>::square(y);
    let x2 = <Fp as FieldExtensionTrait<1, 1>>::square(x);
    let lhs = y2 - (x2 * (*x));
    let rhs = Fp::new_from_u64(3u64);
    // println!("{:?}, {:?}", lhs.value(), rhs.value());
    lhs.ct_eq(&rhs) | *z
}

#[inline(always)]
fn _g1affine_is_torsion_free(_x: &Fp, _y: &Fp, _z: &Choice) -> Choice {
    // every point in G1 on the curve is in the r-torsion of BN254
    Choice::from(1u8)
}
#[inline(always)]
fn _g1projective_is_on_curve(x: &Fp, y: &Fp, z: &Fp) -> Choice {
    let y2 = <Fp as FieldExtensionTrait<1, 1>>::square(y);
    let x2 = <Fp as FieldExtensionTrait<1, 1>>::square(x);
    let z2 = <Fp as FieldExtensionTrait<1, 1>>::square(z);
    let lhs = y2 * (*z);
    let rhs = x2 * (*x) + z2 * (*z) * Fp::new_from_u64(3u64);
    // println!("{:?}, {:?}", lhs.value(), rhs.value());
    lhs.ct_eq(&rhs) | Choice::from(z.is_zero() as u8)
}
#[inline(always)]
fn _g1projective_is_torsion_free(_x: &Fp, _y: &Fp, _z: &Fp) -> Choice {
    Choice::from(1u8)
}
impl G1Affine {
    fn new(v: [Fp; 2]) -> Result<Self, Error> {
        let is_on_curve: Choice = _g1affine_is_on_curve(&v[0], &v[1], &Choice::from(0u8));
        match bool::from(is_on_curve) {
            true => {
                // println!("Is on curve!");
                let is_in_torsion: Choice =
                    _g1affine_is_torsion_free(&v[0], &v[1], &Choice::from(0u8));
                match bool::from(is_in_torsion) {
                    true => Ok(Self {
                        x: v[0],
                        y: v[1],
                        infinity: Choice::from(0u8),
                    }),
                    _ => Err(Error::NotInSubgroup),
                }
            }
            false => Err(Error::NotOnCurve),
        }
    }
}
impl GroupTrait<1, 1, Fp> for G1Affine {
    fn is_on_curve(&self) -> Choice {
        _g1affine_is_on_curve(&self.x, &self.y, &self.infinity)
    }

    fn is_torsion_free(&self) -> Choice {
        _g1affine_is_torsion_free(&self.x, &self.y, &self.infinity)
    }

    fn generator() -> Self {
        todo!()
    }

    fn endomorphism(&self) -> Self {
        Self::one()
    }
    fn one() -> Self {
        Self {
            x: Fp::zero(),
            y: Fp::one(),
            infinity: Choice::from(1u8),
        }
    }
    fn is_one(&self) -> bool {
        bool::from(self.infinity)
    }
}
impl G1Projective {
    fn new(v: [Fp; 3]) -> Result<Self, Error> {
        let is_on_curve: Choice = _g1projective_is_on_curve(&v[0], &v[1], &v[2]);
        match bool::from(is_on_curve) {
            true => {
                // println!("Is on curve!");
                let is_in_torsion: Choice = _g1projective_is_torsion_free(&v[0], &v[1], &v[2]);
                match bool::from(is_in_torsion) {
                    true => Ok(Self {
                        x: v[0],
                        y: v[1],
                        z: v[2],
                    }),
                    false => Err(Error::NotOnCurve),
                }
            }
            false => Err(Error::NotOnCurve),
        }
    }
}
// impl Default for
impl GroupTrait<1, 1, Fp> for G1Projective {
    fn is_on_curve(&self) -> Choice {
        _g1projective_is_on_curve(&self.x, &self.y, &self.z)
    }
    fn is_torsion_free(&self) -> Choice {
        _g1projective_is_torsion_free(&self.x, &self.y, &self.z)
    }
    fn generator() -> Self {
        todo!()
    }
    fn endomorphism(&self) -> Self {
        Self::one()
    }
    fn one() -> Self {
        Self {
            x: Fp::zero(),
            y: Fp::one(),
            z: Fp::zero(),
        }
    }
    fn is_one(&self) -> bool {
        self.z.is_zero()
    }
}

#[cfg(test)]
mod tests {
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
        
        fn convert_g1_point(point: &_G1Affine) -> G1Projective {
            G1Projective::new([
                Fp::new_from_str(point.x.as_str()).expect("failed to convert x coord in g1"),
                Fp::new_from_str(point.y.as_str()).expect("failed to convert y coord in g1"),
                Fp::one()
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
        let g1_points: Vec<G1Projective> = reference_data
            .G1_signatures
            .iter()
            .map(convert_g1_point)
            .collect();
        println!("{:?}", g1_points);
    }
}
