use std::ops::{Add, AddAssign, Neg};
use crypto_bigint::U256;
use crate::fields::fp::{FieldExtensionTrait, Fp, Fr};
use crate::fields::fp12::Fp12;
use crate::fields::fp2::Fp2;
use crate::fields::fp6::Fp6;
use crate::groups::g1::{G1Affine, G1Projective};
use crate::groups::g2::{BLS_X, EPS_EXP0, EPS_EXP1, G2Affine, G2Projective};
use crate::groups::group::GroupTrait;
use num_traits::{Inv, One, Zero};
use subtle::{Choice, ConditionallySelectable};
const TWIST_MUL_BY_Q_X: Fp2 = EPS_EXP0;
const TWIST_MUL_BY_Q_Y: Fp2 = EPS_EXP1;

#[inline]
fn twist_mul_by_q_y() -> Fp2 {
    Fp2::new(&[
        Fp::new(U256::from_words([
            16482010305593259561,
            13488546290961988299,
            3578621962720924518,
            2681173117283399901,
        ])),
        Fp::new(U256::from_words([
            11661927080404088775,
            553939530661941723,
            7860678177968807019,
            3208568454732775116,
        ])),
    ])
}
impl Fp12 {
    fn unitary_inverse(&self) -> Self {
        Self::new(&[self.0[0], -self.0[1]])
    }
    fn pow(&self, arg: &[u64;4]) -> Self {
        let mut res = Self::one();
        for e in arg.iter().rev() {
            for i in (0..64).rev() {
                res = res.square();
                if ((*e >> i) & 1) == 1 {
                    res *= *self;
                }
            }
        }
        res
    }
    pub fn cyclotomic_squared(&self) -> Self {
        let z0 = self.0[0].0[0];
        let z4 = self.0[0].0[1];
        let z3 = self.0[0].0[2];
        let z2 = self.0[1].0[0];
        let z1 = self.0[1].0[1];
        let z5 = self.0[1].0[2];

        let tmp = z0 * z1;
        let t0 = (z0 + z1) * (z1.residue_mul() + z0) - tmp - tmp.residue_mul();
        let t1 = tmp + tmp;

        let tmp = z2 * z3;
        let t2 = (z2 + z3) * (z3.residue_mul() + z2) - tmp - tmp.residue_mul();
        let t3 = tmp + tmp;

        let tmp = z4 * z5;
        let t4 = (z4 + z5) * (z5.residue_mul() + z4) - tmp - tmp.residue_mul();
        let t5 = tmp + tmp;

        let z0 = t0 - z0;
        let z0 = z0 + z0;
        let z0 = z0 + t0;

        let z1 = t1 + z1;
        let z1 = z1 + z1;
        let z1 = z1 + t1;

        let tmp = t5.residue_mul();
        let z2 = tmp + z2;
        let z2 = z2 + z2;
        let z2 = z2 + tmp;

        let z3 = t4 - z3;
        let z3 = z3 + z3;
        let z3 = z3 + t4;

        let z4 = t2 - z4;
        let z4 = z4 + z4;
        let z4 = z4 + t2;

        let z5 = t3 + z5;
        let z5 = z5 + z5;
        let z5 = z5 + t3;

        Fp12::new(&[
            Fp6::new(&[z0, z4, z3]),
            Fp6::new(&[z2, z1, z5]),
        ])
    }
    pub fn cyclotomic_exp(&self, exponent: &[u64;4]) -> Fp12 {
        let mut res = Fp12::one();
        for e in exponent.iter().rev() {
            for i in (0..64).rev() {
                res = res.cyclotomic_squared();
                if ((*e >> i) & 1) == 1 {
                    res *= *self;
                }
            }
        }
        res
    }
    pub fn mul_by_024(&self, ell_0: Fp2, ell_vw: Fp2, ell_vv: Fp2) -> Fp12 {
        let z0 = self.0[0].0[0];
        let z1 = self.0[0].0[1];
        let z2 = self.0[0].0[2];
        let z3 = self.0[1].0[0];
        let z4 = self.0[1].0[1];
        let z5 = self.0[1].0[2];

        let x0 = ell_0;
        let x2 = ell_vv;
        let x4 = ell_vw;

        let d0 = z0 * x0;
        let d2 = z2 * x2;
        let d4 = z4 * x4;
        let t2 = z0 + z4;
        let t1 = z0 + z2;
        let s0 = z1 + z3 + z5;

        let s1 = z1 * x2;
        let t3 = s1 + d4;
        let t4 = t3.residue_mul() + d0;
        let z0 = t4;

        let t3 = z5 * x4;
        let s1 = s1 + t3;
        let t3 = t3 + d2;
        let t4 = t3.residue_mul();
        let t3 = z1 * x0;
        let s1 = s1 + t3;
        let t4 = t4 + t3;
        let z1 = t4;

        let t0 = x0 + x2;
        let t3 = t1 * t0 - d0 - d2;
        let t4 = z3 * x4;
        let s1 = s1 + t4;
        let t3 = t3 + t4;

        let t0 = z2 + z4;
        let z2 = t3;

        let t1 = x2 + x4;
        let t3 = t0 * t1 - d2 - d4;
        let t4 = t3.residue_mul();
        let t3 = z3 * x0;
        let s1 = s1 + t3;
        let t4 = t4 + t3;
        let z3 = t4;

        let t3 = z5 * x2;
        let s1 = s1 + t3;
        let t4 = t3.residue_mul();
        let t0 = x0 + x4;
        let t3 = t2 * t0 - d0 - d4;
        let t4 = t4 + t3;
        let z4 = t4;

        let t0 = x0 + x2 + x4;
        let t3 = s0 * t0 - s1;
        let z5 = t3;

        Fp12::new(&[
            Fp6::new(&[z0, z1, z2]),
            Fp6::new(&[z3, z4, z5]),
        ])
    }
    pub fn exp_by_neg_z(&self) -> Fp12 {
        self.cyclotomic_exp(&U256::from([4965661367192848881, 0, 0, 0]).to_words())
            .unitary_inverse()
    }
    fn final_exponentiation_first_chunk(&self) -> Option<Fp12> {
        match Some(self.inv()) {
            Some(b) => {
                let a = self.unitary_inverse();
                let c = a * b;
                let d = c.frobenius(2);
                Some(d * c)
            }
            None => None,
        }
    }
    fn final_exponentiation_last_chunk(&self) -> Fp12 {
        let a = self.exp_by_neg_z();
        let b = a.cyclotomic_squared();
        let c = b.cyclotomic_squared();
        let d = c * b;

        let e = d.exp_by_neg_z();
        let f = e.cyclotomic_squared();
        let g = f.exp_by_neg_z();
        let h = d.unitary_inverse();
        let i = g.unitary_inverse();

        let j = i * e;
        let k = j * h;
        let l = k * b;
        let m = k * e;
        let n = *self * m;

        let o = l.frobenius(1);
        let p = o * n;

        let q = k.frobenius(2);
        let r = q * p;

        let s = self.unitary_inverse();
        let t = s * l;
        let u = t.frobenius(3);
        let v = u * r;

        v
    }
    pub fn final_exponentiation(&self) -> Option<Fp12> {
        self.final_exponentiation_first_chunk()
            .map(|a| a.final_exponentiation_last_chunk())
    }
}
const ATE_LOOP_COUNT_NAF : [u8; 64] = [1,0,1,0,0,0,3,0,3,0,0,0,3,0,1,0,3,0,0,3,0,0,0,0,0,1,0,0,3,0,1,0,0,3,0,0,0,0,3,0,1,0,0,0,3,0,3,0,0,1,0,0,0,3,0,0,3,0,1,0,1,0,0,0];
// confirmed good to go
const TWO_INV: Fp = Fp::new(U256::from_words([
    11389680472494603940, 14681934109093717318, 15863968012492123182, 1743499133401485332
]));
#[derive(PartialEq)]
pub struct EllCoeffs {
    pub ell_0: Fp2,
    pub ell_vw: Fp2,
    pub ell_vv: Fp2,
}

#[derive(PartialEq)]
pub struct G2PreComputed {
    pub q: G2Affine,
    pub coeffs: Vec<EllCoeffs>,
}
impl G2PreComputed {
    pub fn miller_loop(&self, g1: &G1Affine) -> Fp12 {
        let mut f = Fp12::one();

        let mut idx = 0;

        for i in ATE_LOOP_COUNT_NAF.iter() {
            let c = &self.coeffs[idx];
            idx += 1;
            f = f.square()
                .mul_by_024(c.ell_0, c.ell_vw.scale(g1.y), c.ell_vv.scale(g1.x));

            if *i != 0 {
                let c = &self.coeffs[idx];
                idx += 1;
                f = f.mul_by_024(c.ell_0, c.ell_vw.scale(g1.y), c.ell_vv.scale(g1.x));
            }
        }

        let c = &self.coeffs[idx];
        idx += 1;
        f = f.mul_by_024(c.ell_0, c.ell_vw.scale(g1.y), c.ell_vv.scale(g1.x));

        let c = &self.coeffs[idx];
        f = f.mul_by_024(c.ell_0, c.ell_vw.scale(g1.y), c.ell_vv.scale(g1.x));

        f
    }
}
impl G2Affine {
    fn mul_by_q(&self) -> Self {
        G2Affine {
            x: TWIST_MUL_BY_Q_X * <Fp2 as FieldExtensionTrait<2,2>>::frobenius(&self.x,
                                                                                 1),
            y: TWIST_MUL_BY_Q_Y * <Fp2 as FieldExtensionTrait<2,2>>::frobenius(&self.y, 1),
            infinity: self.infinity
        }
    }
    fn precompute(&self) -> G2PreComputed {
        let mut r = G2Projective::from(self);

        let mut coeffs = Vec::with_capacity(102);

        let q_neg = self.neg();
        for i in ATE_LOOP_COUNT_NAF.iter() {
            coeffs.push(r.doubling_step_for_flipped_miller_loop());

            if *i == 1 {
                coeffs.push(r.mixed_addition_step_for_flipped_miller_loop(self));
            }
            if *i == 3 {
                coeffs.push(r.mixed_addition_step_for_flipped_miller_loop(&q_neg));
            }
        }
        let q1 = self.mul_by_q();
        let q2 = -(q1.mul_by_q());

        coeffs.push(r.mixed_addition_step_for_flipped_miller_loop(&q1));
        coeffs.push(r.mixed_addition_step_for_flipped_miller_loop(&q2));

        G2PreComputed {
            q: *self,
            coeffs,
        }
    }
}
impl G2Projective {
    fn mixed_addition_step_for_flipped_miller_loop(
        &mut self,
        base: &G2Affine,
    ) -> EllCoeffs {
        let d = self.x - self.z * base.x;
        let e = self.y - self.z * base.y;
        let f = <Fp2 as FieldExtensionTrait<2,2>>::square(&d);
        let g = <Fp2 as FieldExtensionTrait<2,2>>::square(&e);
        let h = d * f;
        let i = self.x * f;
        let j = self.z * g + h - (i + i);

        self.x = d * j;
        self.y = e * (i - j) - h * self.y;
        self.z *= h;

        EllCoeffs {
            ell_0: <Fp2 as FieldExtensionTrait<2,2>>::quadratic_non_residue() * (e * base.x - d * base.y),
            ell_vv: e.neg(),
            ell_vw: d,
        }
    }
    fn doubling_step_for_flipped_miller_loop(&mut self) -> EllCoeffs {
        let a = (self.x * self.y).scale(TWO_INV);
        let b = <Fp2 as FieldExtensionTrait<2,2>>::square(&self.y);
        let c = <Fp2 as FieldExtensionTrait<2,2>>::square(&self.z);
        let d = c + c + c;
        let e = <Fp2 as FieldExtensionTrait<2,2>>::curve_constant() * d;
        let f = e + e + e;
        let g = (b + f).scale(TWO_INV);
        let h = <Fp2 as FieldExtensionTrait<2,2>>::square(&(self.y + self.z)) - (b + c);
        let i = e - b;
        let j = <Fp2 as FieldExtensionTrait<2,2>>::square(&self.x);
        let e_sq = <Fp2 as FieldExtensionTrait<2,2>>::square(&e);

        self.x = a * (b - f);
        self.y = <Fp2 as FieldExtensionTrait<2,2>>::square(&g) - (e_sq + e_sq + e_sq);
        self.z = b * h;

        EllCoeffs {
            ell_0: <Fp2 as FieldExtensionTrait<2,2>>::quadratic_non_residue() * i,
            ell_vw: h.neg(),
            ell_vv: j + j + j,
        }
    }
}
pub(crate) fn pairing(p: &G1Affine, q: &G2Affine) -> Fp12 {
    if p.is_zero() || q.is_zero() {
        return Fp12::one();
    }

    q.precompute()
        .miller_loop(p)
        .final_exponentiation()
        .expect("miller loop cannot produce zero")
}

#[test]
fn test_miller() {
    let g1 = G1Affine::from(&G1Projective::generator()
        * &Fr::new_from_str(
        "18097487326282793650237947474982649264364522469319914492172746413872781676",
    ).unwrap().value().to_le_bytes());
    let g2 = G2Affine::from(&G2Projective::generator()
        * &Fr::new_from_str(
        "20390255904278144451778773028944684152769293537511418234311120800877067946",
    ).unwrap().value().to_le_bytes());

    let gt = pairing(&g1, &g2);

    let expected = Fp12::new(&[
        Fp6::new(&[
            Fp2::new(&[
                Fp::new_from_str(
                    "7520311483001723614143802378045727372643587653754534704390832890681688842501",
                ).unwrap(),
                Fp::new_from_str(
                    "20265650864814324826731498061022229653175757397078253377158157137251452249882",
                ).unwrap(),
            ]),
            Fp2::new(&[
                Fp::new_from_str(
                    "11942254371042183455193243679791334797733902728447312943687767053513298221130",
                ).unwrap(),
                Fp::new_from_str(
                    "759657045325139626991751731924144629256296901790485373000297868065176843620",
                ).unwrap(),
            ]),
            Fp2::new(&[
                Fp::new_from_str(
                    "16045761475400271697821392803010234478356356448940805056528536884493606035236",
                ).unwrap(),
                Fp::new_from_str(
                    "4715626119252431692316067698189337228571577552724976915822652894333558784086",
                ).unwrap(),
            ]),
        ]),
        Fp6::new(&[
            Fp2::new(&[
                Fp::new_from_str(
                    "14901948363362882981706797068611719724999331551064314004234728272909570402962",
                ).unwrap(),
                Fp::new_from_str(
                    "11093203747077241090565767003969726435272313921345853819385060670210834379103",
                ).unwrap(),
            ]),
            Fp2::new(&[
                Fp::new_from_str(
                    "17897835398184801202802503586172351707502775171934235751219763553166796820753",
                ).unwrap(),
                Fp::new_from_str(
                    "1344517825169318161285758374052722008806261739116142912817807653057880346554",
                ).unwrap(),
            ]),
            Fp2::new(&[
                Fp::new_from_str(
                    "11123896897251094532909582772961906225000817992624500900708432321664085800838",
                ).unwrap(),
                Fp::new_from_str(
                    "17453370448280081813275586256976217762629631160552329276585874071364454854650",
                ).unwrap(),
            ]),
        ]),]
    );
    assert_eq!(gt, expected);
    for a in &gt.0 {
        for b in &a.0 {
            for c in &b.0 {
                print!("{:?} ", c.value());
            }
            println!();
        }
    }
}