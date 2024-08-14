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

impl GroupTrait<2, 2, Fp2> for G2Projective {
    fn generator() -> Self {
        let x_g2 = Fp2::new(&[
            Fp::new_from_str("1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed")
                .expect("G2_x0 failed"),
            Fp::new_from_str("198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2")
                .expect("G2_x1 failed"),
        ]);
        let y_g2 = Fp2::new(&[
            Fp::new_from_str("12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa")
                .expect("G2_y0 failed"),
            Fp::new_from_str("090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b")
                .expect("G2_y1 failed"),
        ]);
        Self {
            x: x_g2,
            y: y_g2,
            z: Fp2::one(),
        }
    }
    fn endomorphism(&self) -> Self {
        // this computes the endomorphism of the point (x^p * \xi^((p-1)/3), y^p*\xi^((p-1)/2))
        let endo = [
            Fp2::new(&[
                Fp::new_from_str(
                    "21575463638280843010398324269430826099269044274347216827212613867836435027261",
                )
                    .expect("Endomorphism failed"),
                Fp::new_from_str(
                    "10307601595873709700152284273816112264069230130616436755625194854815875713954",
                )
                    .expect("Endomorphism failed"),
            ]),
            Fp2::new(&[
                Fp::new_from_str(
                    "2821565182194536844548159561693502659359617185244120367078079554186484126554",
                )
                    .expect("Endomorphism failed"),
                Fp::new_from_str(
                    "3505843767911556378687030309984248845540243509899259641013678093033130930403",
                )
                    .expect("Endomorphism failed"),
            ]),
        ];
        let conjugate = |x: &Fp2| -> Fp2 {
            Fp2::new(&[x.0[0], -x.0[1]])
        };
        let mut p = *self;
        p.x = conjugate(&p.x);
        p.x *= endo[0];

        p.y = conjugate(&p.y);
        p.y *= endo[1];

        p.z = conjugate(&p.z);
        p
    }
    fn rand<R: CryptoRngCore>(rng: &mut R) -> Self {
        todo!()
    }
    fn hash_to_curve<E: Expander>(exp: &E, msg: &[u8]) -> Result<Self, GroupError> {
        todo!()
    }
    fn sign_message<E: Expander>(
        exp: &E,
        msg: &[u8],
        private_key: Fp2,
    ) -> Result<Self, GroupError> {
        unimplemented!()
    }
}
impl G2Affine {
    pub(crate) fn new(v: [Fp2; 2]) -> Result<Self, GroupError> {
        let _g2affine_is_on_curve = |x: &Fp2, y: &Fp2, z: &Choice| -> Choice {
            let y2 = <Fp2 as FieldExtensionTrait<2, 2>>::square(y);
            let x2 = <Fp2 as FieldExtensionTrait<2, 2>>::square(x);
            let lhs = y2 - (x2 * (*x));
            let rhs = <Fp2 as FieldExtensionTrait<2, 2>>::curve_constant();
            lhs.ct_eq(&rhs) | *z
        };
        let _g2affine_is_torsion_free =  |_x: &Fp2, _y: &Fp2, _z: &Choice| -> Choice {
            // every point in G1 on the curve is in the r-torsion of BN254
            Choice::from(1u8)
        };
        let is_on_curve = _g2affine_is_on_curve(&v[0], &v[1], &Choice::from(0u8));
        match bool::from(is_on_curve){
            true => {
                let is_in_torsion = _g2affine_is_torsion_free(&v[0], &v[1], &Choice::from(0u8));
                match bool::from(is_in_torsion) {
                    true => Ok(Self {
                        x: v[0],
                        y: v[1],
                        infinity: Choice::from(0u8)
                    }),
                    _ => Err(GroupError::NotInSubgroup)
                }
            }
        false => Err(GroupError::NotOnCurve)
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
            let tmp = G2Projective{
                x: *x, y: *y, z: *z
            };
            
            let xgen = Fp::new_from_str("147946756881789318990833708069417712966").unwrap();
            let mut a = &tmp * &xgen.value().to_le_bytes();
            let b = G2Projective::endomorphism(&a);
            a = &a + &tmp;
            let mut res = G2Projective::endomorphism(&b);
            let mut c = res;
            c = &c + &b;
            c = &c + &a;
            res = G2Projective::endomorphism(&res).double();
            res = &res - &c;
            _g2projective_is_on_curve(&res.x, &res.y, &res.z) | Choice::from(res.z.is_zero() as u8)
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
                false => Err(GroupError::NotInSubgroup),
            },
            false => Err(GroupError::NotOnCurve),
        }
    }
}
