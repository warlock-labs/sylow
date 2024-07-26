use crate::fields::fp::{FieldExtensionTrait, FinitePrimeField, Fp};
use crate::groups::group::{Error, GroupAffine, GroupProjective, GroupTrait};
use crypto_bigint::subtle::Choice;
use num_traits::{One, Zero};
use subtle::ConstantTimeEq;

type G1Affine = GroupAffine<1, 1, Fp>;
type G1Projective = GroupProjective<1, 1, Fp>;

fn _g1affine_is_on_curve(x: &Fp, y: &Fp, z: &Choice) -> Choice {
    (<Fp as FieldExtensionTrait<1, 1>>::square(y)
        - (<Fp as FieldExtensionTrait<1, 1>>::square(x) * (*x)))
        .ct_eq(&Fp::new_from_u64(3u64))
        | *z
}
fn _g1projective_is_on_curve(x: &Fp, y: &Fp, z: &Fp) -> Choice {
    (<Fp as FieldExtensionTrait<1, 1>>::square(y) * (*z)).ct_eq(
        &(<Fp as FieldExtensionTrait<1, 1>>::square(x) * (*x)
            + <Fp as FieldExtensionTrait<1, 1>>::square(z) * (*z) * Fp::new_from_u64(3u64)),
    ) | Choice::from(z.is_zero() as u8)
}
impl G1Affine {
    fn new(v: [Fp; 2]) -> Result<Self, Error> {
        let is_on_curve: Choice = _g1affine_is_on_curve(&v[0], &v[1], &Choice::from(0u8));
        match is_on_curve.unwrap_u8() {
            1u8 => Ok(Self {
                x: v[0],
                y: v[1],
                infinity: Choice::from(0u8),
            }),
            _ => Err(Error::NotOnCurve),
        }
    }
}
impl GroupTrait<1, 1, Fp> for G1Affine {
    fn is_on_curve(&self) -> Choice {
        _g1affine_is_on_curve(&self.x, &self.y, &self.infinity)
    }

    fn is_torsion_free(&self) -> Choice {
        // every point in G1 on the curve is in the r-torsion of BN254
        Choice::from(1u8)
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
        match is_on_curve.unwrap_u8() {
            1u8 => Ok(Self {
                x: v[0],
                y: v[1],
                z: v[2],
            }),
            _ => Err(Error::NotOnCurve),
        }
    }
}
// impl Default for
impl GroupTrait<1, 1, Fp> for G1Projective {
    fn is_on_curve(&self) -> Choice {
        _g1projective_is_on_curve(&self.x, &self.y, &self.z)
    }
    fn is_torsion_free(&self) -> Choice {
        // every point in G1 on the curve is in the r-torsion of BN254
        Choice::from(1u8)
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
