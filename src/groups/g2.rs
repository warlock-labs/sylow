use crate::fields::fp::{FieldExtensionTrait, FinitePrimeField, Fp};
use crate::fields::fp2::Fp2;
use crate::groups::group::{GroupAffine, GroupError, GroupProjective, GroupTrait};
use crate::hasher::Expander;
use crypto_bigint::rand_core::CryptoRngCore;
use num_traits::{One, Zero};
use subtle::{Choice, ConstantTimeEq};

#[allow(dead_code)]
pub(crate) type G2Affine = GroupAffine<2, 2, Fp2>;
#[allow(dead_code)]
pub(crate) type G2Projective = GroupProjective<2, 2, Fp2>;

impl GroupTrait<2, 2, Fp2> for G2Affine {
    fn generator() -> Self {
        let x_g2 = Fp2::new(&[
            Fp::new_from_str(
                "10857046999023057135944570762232829481370756359578518086990519993285655852781",
            )
            .expect("G2_x0 failed"),
            Fp::new_from_str(
                "11559732032986387107991004021392285783925812861821192530917403151452391805634",
            )
            .expect("G2_x1 failed"),
        ]);
        let y_g2 = Fp2::new(&[
            Fp::new_from_str(
                "13392588948715843804641432497768002650278120570034223513918757245338268106653",
            )
            .expect("G2_y0 failed"),
            Fp::new_from_str(
                "17805874995975841540914202342111839520379459829704422454583296818431106115052",
            )
            .expect("G2_y1 failed"),
        ]);
        Self {
            x: x_g2,
            y: y_g2,
            infinity: Choice::from(0u8),
        }
    }

    fn endomorphism(&self) -> Self {
        // this computes the endomorphism of the point (x^p * \xi^((p-1)/3), y^p*\xi^((p-1)/2))
        let eps_exp0 = Fp2::new(&[
            Fp::new_from_str(
                "21575463638280843010398324269430826099269044274347216827212613867836435027261",
            )
            .expect("endo arg 0x failed"),
            Fp::new_from_str(
                "10307601595873709700152284273816112264069230130616436755625194854815875713954",
            )
            .expect("endo arg 0y failed"),
        ]);

        let eps_exp1 = Fp2::new(&[
            Fp::new_from_str(
                "2821565182194536844548159561693502659359617185244120367078079554186484126554",
            )
            .expect("endo arg 1x failed"),
            Fp::new_from_str(
                "3505843767911556378687030309984248845540243509899259641013678093033130930403",
            )
            .expect("endo arg 1y failed"),
        ]);
        if self.is_zero() {
            return *self;
        }
        let x_frob = <Fp2 as FieldExtensionTrait<2, 2>>::frobenius(&self.x, 1);
        let y_frob = <Fp2 as FieldExtensionTrait<2, 2>>::frobenius(&self.y, 1);

        let x_endo = eps_exp0 * x_frob;
        let y_endo = eps_exp1 * y_frob;

        Self::new_unchecked([x_endo, y_endo]).expect("Endomorphism failed")
    }

    fn rand<R: CryptoRngCore>(rng: &mut R) -> Self {
        Self::from(G2Projective::rand(rng))
    }

    fn hash_to_curve<E: Expander>(_exp: &E, _msg: &[u8]) -> Result<Self, GroupError> {
        unimplemented!()
    }

    fn sign_message<E: Expander>(
        _exp: &E,
        _msg: &[u8],
        _private_key: Fp2,
    ) -> Result<Self, GroupError> {
        unimplemented!()
    }
}
impl GroupTrait<2, 2, Fp2> for G2Projective {
    fn generator() -> Self {
        let _generator = G2Affine::generator();
        Self {
            x: _generator.x,
            y: _generator.y,
            z: Fp2::one(),
        }
    }
    fn endomorphism(&self) -> Self {
        Self::from(G2Affine::from(self).endomorphism())
    }
    fn rand<R: CryptoRngCore>(rng: &mut R) -> Self {
        let rando = <Fp as FieldExtensionTrait<1, 1>>::rand(rng)
            .value()
            .to_le_bytes();
        let mut tmp = &Self::generator() * &rando;
        let c2 = Fp::new_from_str(
            "21888242871839275222246405745257275088844257914179612981679871602714643921549",
        )
        .expect("Failed to generate c2");
        tmp = &tmp * &c2.value().to_le_bytes();
        Self::new([tmp.x, tmp.y, tmp.z]).expect("Generator failed to make new value in torsion")
    }
    fn hash_to_curve<E: Expander>(_exp: &E, _msg: &[u8]) -> Result<Self, GroupError> {
        unimplemented!()
    }
    fn sign_message<E: Expander>(
        _exp: &E,
        _msg: &[u8],
        _private_key: Fp2,
    ) -> Result<Self, GroupError> {
        unimplemented!()
    }
}
impl G2Affine {
    fn new_unchecked(v: [Fp2; 2]) -> Result<Self, GroupError> {
        let _g2affine_is_on_curve = |x: &Fp2, y: &Fp2, z: &Choice| -> Choice {
            let y2 = <Fp2 as FieldExtensionTrait<2, 2>>::square(y);
            let x2 = <Fp2 as FieldExtensionTrait<2, 2>>::square(x);
            let lhs = y2 - (x2 * (*x));
            let rhs = <Fp2 as FieldExtensionTrait<2, 2>>::curve_constant();
            lhs.ct_eq(&rhs) | *z
        };

        let is_on_curve = _g2affine_is_on_curve(&v[0], &v[1], &Choice::from(0u8));
        match bool::from(is_on_curve) {
            true => Ok(Self {
                x: v[0],
                y: v[1],
                infinity: Choice::from(0u8),
            }),
            false => Err(GroupError::NotOnCurve),
        }
    }
}
impl G2Projective {
    pub(crate) fn new(v: [Fp2; 3]) -> Result<Self, GroupError> {
        let _g2projective_is_on_curve = |x: &Fp2, y: &Fp2, z: &Fp2| -> Choice {
            let y2 = <Fp2 as FieldExtensionTrait<2, 2>>::square(y);
            let x2 = <Fp2 as FieldExtensionTrait<2, 2>>::square(x);
            let z2 = <Fp2 as FieldExtensionTrait<2, 2>>::square(z);
            let lhs = y2 * (*z);
            let rhs = x2 * (*x) + z2 * (*z) * <Fp2 as FieldExtensionTrait<2, 2>>::curve_constant();
            // println!("{:?}, {:?}", lhs.value(), rhs.value());
            lhs.ct_eq(&rhs) | Choice::from(z.is_zero() as u8)
        };
        let _g2projective_is_torsion_free = |x: &Fp2, y: &Fp2, z: &Fp2| -> Choice {
            let tmp = G2Projective {
                x: *x,
                y: *y,
                z: *z,
            };
            let six = Fp::from(6);
            let z = Fp::from(4965661367192848881);
            let six_z_squared = (six * z * z).value();
            let lhs = tmp.endomorphism();
            let rhs = &tmp * &six_z_squared.to_le_bytes();
            Choice::from((&lhs - &rhs).is_zero() as u8)
        };
        let is_on_curve = _g2projective_is_on_curve(&v[0], &v[1], &v[2]);
        let is_torsion_free = _g2projective_is_torsion_free(&v[0], &v[1], &v[2]);
        match bool::from(is_on_curve) {
            true => match bool::from(is_torsion_free) {
                true => Ok(Self {
                    x: v[0],
                    y: v[1],
                    z: v[2],
                }),
                _ => Err(GroupError::NotInSubgroup),
            },
            false => Err(GroupError::NotOnCurve),
        }
    }
}
