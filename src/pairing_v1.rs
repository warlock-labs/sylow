use crate::fields::fp::{FieldExtensionTrait, Fp, Fr};
use crate::fields::fp12::Fp12;
use crate::fields::fp2::{Fp2, TWO_INV};
use crate::fields::fp6::Fp6;
use crate::groups::g1::G1Affine;
use crate::groups::g2::{G2Affine, G2Projective, BLS_X};
use crate::groups::group::GroupTrait;
use num_traits::{Inv, One, Zero};
use std::ops::{Add, AddAssign, Neg};
use subtle::{Choice, ConditionallySelectable};

const ATE_LOOP_COUNT_NAF: [u8; 64] = [
    1, 0, 1, 0, 0, 0, 3, 0, 3, 0, 0, 0, 3, 0, 1, 0, 3, 0, 0, 3, 0, 0, 0, 0, 0, 1, 0, 0, 3, 0, 1, 0,
    0, 3, 0, 0, 0, 0, 3, 0, 1, 0, 0, 0, 3, 0, 3, 0, 0, 1, 0, 0, 0, 3, 0, 0, 3, 0, 1, 0, 1, 0, 0, 0,
];
#[derive(Copy, Clone, Debug)]
pub(crate) struct MillerLoopResult(pub(crate) Fp12);
impl Default for MillerLoopResult {
    fn default() -> Self {
        MillerLoopResult(Fp12::one())
    }
}
#[allow(clippy::suspicious_arithmetic_impl)]
impl<'a, 'b> Add<&'b MillerLoopResult> for &'a MillerLoopResult {
    type Output = MillerLoopResult;

    #[inline]
    fn add(self, rhs: &'b MillerLoopResult) -> MillerLoopResult {
        MillerLoopResult(self.0 * rhs.0)
    }
}
impl Add<MillerLoopResult> for MillerLoopResult {
    type Output = MillerLoopResult;

    #[inline]
    fn add(self, rhs: MillerLoopResult) -> MillerLoopResult {
        &self + &rhs
    }
}

impl AddAssign<MillerLoopResult> for MillerLoopResult {
    #[inline]
    fn add_assign(&mut self, rhs: MillerLoopResult) {
        *self = *self + rhs;
    }
}

impl<'b> AddAssign<&'b MillerLoopResult> for MillerLoopResult {
    #[inline]
    fn add_assign(&mut self, rhs: &'b MillerLoopResult) {
        *self = *self + *rhs;
    }
}

impl Zero for MillerLoopResult {
    fn zero() -> Self {
        MillerLoopResult(Fp12::zero())
    }
    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}
/// There are many evaluations in Fp12 throughout this. As you can see directly from Algs. 27 and 28
/// in https://eprint.iacr.org/2010/354.pdf, for example, regarding the double and addition
/// formulae:
/// //      let l0 = Fp6::new(&[t10, Fp2::zero(), Fp2::zero()]);
/// //      let l1 = Fp6::new(&[t1, t9, Fp2::zero()]);
/// //      return Fp12::new(&[l0, l1])
///
/// which is very, very sparse, resulting in many unnecessary multiplications and additions by
/// zero, which is not ideal. We therefore only keep the 3 nonzero coefficients returned by these
/// evaluations. These nonzero coeffs are stored in the struct below.
#[derive(PartialEq)]
pub struct EllCoeffs {
    pub ell_0: Fp2,
    pub ell_vw: Fp2,
    pub ell_vv: Fp2,
}

impl Fp12 {
    fn unitary_inverse(&self) -> Self {
        Self::new(&[self.0[0], -self.0[1]])
    }
    fn pow(&self, arg: &[u64; 4]) -> Self {
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
    /// Due to the efficiency considerations of storing only the nonzero entries in the sparse
    /// Fp12, there is a need to implement sparse multiplication on Fp12, which is what the
    /// madness below is. It is an amalgamation of Algs 21-25 of https://eprint.iacr.org/2010/354.pdf
    /// and is really just un-sparsing the value, and doing the multiplication manually. In order
    /// to get around all the zeros that would arise if we just instantiated the full Fp12,
    /// we have to manually implement all the required multiplication as far down the tower as
    /// we can go.
    ///
    /// The following code relies on a separate representation of an element in Fp12.
    /// Namely, hereunto we have defined Fp12 as a pair of Fp6 elements. However, it is just as
    /// valid to define Fp12 as a pair of Fp2 elements. For f\in Fp12, f = g+hw, where g, h \in Fp6,
    /// with g = g_0 + g_1v + g_2v^2, and h = h_0 + h_1v + h_2v^2, we can then write:
    ///
    /// f = g_0 + h_0w + g_1w^2 + h_1w^3 + g_2w^4 + h_2w^5
    ///
    /// where the representation of Fp12 is not Fp12 = Fp2[w]/(w^6-(9+u))
    ///
    /// This is a massive headache to get correct, and relied on existing implementations tbh.
    /// Unfortunately for me, the performance boost is noticeable by early estimates (100s us).
    /// Therefore, worth it.
    ///
    /// The function below is called by `zcash`, `bn`, and `arkworks` as `mul_by_024`, referring to
    /// the indices of the non-zero elements in the 6x Fp2 representation above for the
    /// multiplication.
    pub fn sparse_mul(&self, ell_0: Fp2, ell_vw: Fp2, ell_vv: Fp2) -> Fp12 {
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

        Fp12::new(&[Fp6::new(&[z0, z1, z2]), Fp6::new(&[z3, z4, z5])])
    }
}
impl MillerLoopResult {
    pub fn final_exponentiation(&self) -> Fp12 {
        /// As part of the cyclotomic acceleration of the final exponentiation step, there is a
        /// shortcut to take when using multiplication in Fp4. We built the tower of extensions using
        /// degrees 2, 6, and 12, but there is an additional way to write Fp12:
        /// Fp4 = Fp2[w^3]/((w^3)^2-(9+u))
        /// Fp12 = Fp4[w]/(w^3-w^3)
        ///
        /// This lets us do magic on points in the twist curve with cheaper operations :)
        /// This implements algorithm 9 from https://eprint.iacr.org/2010/354.pdf, with the notable
        /// difference that instead of passing an element of Fp4 (which I did not implement), we pass
        /// in only the two components from Fp2 that comprise the Fp4 element.
        #[must_use]
        fn fp4_square(a: Fp2, b: Fp2) -> (Fp2, Fp2) {
            // Line 1
            let t0 = <Fp2 as FieldExtensionTrait<2, 2>>::square(&a);
            // Line 2
            let t1 = <Fp2 as FieldExtensionTrait<2, 2>>::square(&b);
            // Line 3
            let c0 = t1.residue_mul();
            // Line 4
            let c0 = c0 + t0;
            // Line 5
            let c1 = a + b;
            // Line 6
            let c1 = <Fp2 as FieldExtensionTrait<2, 2>>::square(&c1) - t0 - t1;
            (c0, c1)
        }
        /// This implements efficient squaring of an element of Fp12 in the cyclotomic subgroup
        /// C_{\phi^6}. It is what's called "Granger-Scott" squaring, and is an implementation of
        /// algorithm 5.5.4 (listing 21) from https://www.math.u-bordeaux.fr/~damienrobert/csi/book/book.pdf
        #[must_use]
        fn cyclotomic_squared(f: Fp12) -> Fp12 {
            // Lines 3-8
            let mut z0 = f.0[0].0[0];
            let mut z4 = f.0[0].0[1];
            let mut z3 = f.0[0].0[2];
            let mut z2 = f.0[1].0[0];
            let mut z1 = f.0[1].0[1];
            let mut z5 = f.0[1].0[2];
            // Line 9
            let (t0, t1) = fp4_square(z0, z1);
            // Line 13-22 for A
            z0 = t0 - z0;
            z0 = z0 + z0 + t0;

            z1 = t1 + z1;
            z1 = z1 + z1 + t1;

            let (mut t0, t1) = fp4_square(z2, z3);
            let (t2, t3) = fp4_square(z4, z5);

            // Lines 25-31, for C
            z4 = t0 - z4;
            z4 = z4 + z4 + t0;

            z5 = t1 + z5;
            z5 = z5 + z5 + t1;

            // Lines 34-41, for B
            t0 = t3.residue_mul();
            z2 = t0 + z2;
            z2 = z2 + z2 + t0;

            z3 = t2 - z3;
            z3 = z3 + z3 + t2;
            Fp12::new(&[Fp6::new(&[z0, z4, z3]), Fp6::new(&[z2, z1, z5])])
        }
        /// This is a simple double and add algorithm for exponentiation. You can get more
        /// complicated algorithms if you go to a compressed representation, such as Algorithm
        /// 5.5.4, listing 27
        pub fn cyclotomic_exp(f: Fp12, exponent: &[u64; 4]) -> Fp12 {
            let mut res = Fp12::one();
            for e in exponent.iter().rev() {
                for i in (0..64).rev() {
                    res = cyclotomic_squared(res);
                    if ((*e >> i) & 1) == 1 {
                        res *= f;
                    }
                }
            }
            res
        }
        /// This is a helper function to determine f^z, where $z$ is the generator of this
        /// particular member of the BN family
        pub fn exp_by_neg_z(f: Fp12) -> Fp12 {
            cyclotomic_exp(f, &BLS_X.value().to_words()).unitary_inverse()
        }
        /// The below is the easy part of the final exponentiation step, corresponding to Lines
        /// 1-4 of Alg 31 from https://eprint.iacr.org/2010/354.pdf.
        fn easy_part(f: Fp12) -> Fp12 {
            let f1 = f.unitary_inverse();
            let f2 = f.inv();
            let f = f1 * f2;
            f.frobenius(2) * f
        }

        /// Hard part follows Laura Fuentes-Castaneda et al. "Faster hashing to G2"
        /// <https://link.springer.com/chapter/10.1007/978-3-642-28496-0_25>
        /// see https://github.com/arkworks-rs/algebra/blob/273bf2130420904cab815544664a539f049d0494/ec/src/models/bn/mod.rs#L141
        fn hard_part(input: Fp12) -> Fp12 {
            let a = exp_by_neg_z(input);
            let b = cyclotomic_squared(a);
            let c = cyclotomic_squared(b);
            let d = c * b;

            let e = exp_by_neg_z(d);
            let f = cyclotomic_squared(e);
            let g = exp_by_neg_z(f);
            let h = d.unitary_inverse();
            let i = g.unitary_inverse();

            let j = i * e;
            let k = j * h;
            let l = k * b;
            let m = k * e;
            let n = input * m;

            let o = l.frobenius(1);
            let p = o * n;

            let q = k.frobenius(2);
            let r = q * p;

            let s = input.unitary_inverse();
            let t = s * l;
            let u = t.frobenius(3);
            let v = u * r;

            v
        }

        hard_part(easy_part(self.0))
    }
}
#[derive(PartialEq)]
pub struct G2PreComputed {
    pub q: G2Affine,
    pub coeffs: Vec<EllCoeffs>,
}
impl G2PreComputed {
    pub fn miller_loop(&self, g1: &G1Affine) -> MillerLoopResult {
        let mut f = Fp12::one();

        let mut idx = 0;

        for i in ATE_LOOP_COUNT_NAF.iter() {
            let c = &self.coeffs[idx];
            idx += 1;
            f = f
                .square()
                .sparse_mul(c.ell_0, c.ell_vw.scale(g1.y), c.ell_vv.scale(g1.x));

            if *i != 0 {
                let c = &self.coeffs[idx];
                idx += 1;
                f = f.sparse_mul(c.ell_0, c.ell_vw.scale(g1.y), c.ell_vv.scale(g1.x));
            }
        }

        let c = &self.coeffs[idx];
        idx += 1;
        f = f.sparse_mul(c.ell_0, c.ell_vw.scale(g1.y), c.ell_vv.scale(g1.x));

        let c = &self.coeffs[idx];
        f = f.sparse_mul(c.ell_0, c.ell_vw.scale(g1.y), c.ell_vv.scale(g1.x));

        MillerLoopResult(f)
    }
}
impl G2Affine {
    fn precompute(&self) -> G2PreComputed {
        let mut r = G2Projective::from(self);

        let mut coeffs = Vec::with_capacity(102);

        let q_neg = self.neg();
        for i in ATE_LOOP_COUNT_NAF.iter() {
            coeffs.push(r.doubling_step());

            if *i == 1 {
                coeffs.push(r.addition_step(self));
            }
            if *i == 3 {
                coeffs.push(r.addition_step(&q_neg));
            }
        }
        let q1 = self.endomorphism();
        let q2 = -(q1.endomorphism());

        coeffs.push(r.addition_step(&q1));
        coeffs.push(r.addition_step(&q2));

        G2PreComputed { q: *self, coeffs }
    }
}
/// The below implements the doubling and addition steps for the Miller loop algorithm. You'll
/// notice that it doesn't return a Fp12, which it should! See notes on efficiency above as to
/// why this returns EllCoeffs instead.
impl G2Projective {
    fn addition_step(&mut self, base: &G2Affine) -> EllCoeffs {
        let d = self.x - self.z * base.x;
        let e = self.y - self.z * base.y;
        let f = <Fp2 as FieldExtensionTrait<2, 2>>::square(&d);
        let g = <Fp2 as FieldExtensionTrait<2, 2>>::square(&e);
        let h = d * f;
        let i = self.x * f;
        let j = self.z * g + h - (i + i);

        self.x = d * j;
        self.y = e * (i - j) - h * self.y;
        self.z *= h;

        EllCoeffs {
            ell_0: <Fp2 as FieldExtensionTrait<2, 2>>::quadratic_non_residue()
                * (e * base.x - d * base.y),
            ell_vv: e.neg(),
            ell_vw: d,
        }
    }
    fn doubling_step(&mut self) -> EllCoeffs {
        let a = (self.x * self.y).scale(TWO_INV);
        let b = <Fp2 as FieldExtensionTrait<2, 2>>::square(&self.y);
        let c = <Fp2 as FieldExtensionTrait<2, 2>>::square(&self.z);
        let d = c + c + c;
        let e = <Fp2 as FieldExtensionTrait<2, 2>>::curve_constant() * d;
        let f = e + e + e;
        let g = (b + f).scale(TWO_INV);
        let h = <Fp2 as FieldExtensionTrait<2, 2>>::square(&(self.y + self.z)) - (b + c);
        let i = e - b;
        let j = <Fp2 as FieldExtensionTrait<2, 2>>::square(&self.x);
        let e_sq = <Fp2 as FieldExtensionTrait<2, 2>>::square(&e);

        self.x = a * (b - f);
        self.y = <Fp2 as FieldExtensionTrait<2, 2>>::square(&g) - (e_sq + e_sq + e_sq);
        self.z = b * h;

        EllCoeffs {
            ell_0: <Fp2 as FieldExtensionTrait<2, 2>>::quadratic_non_residue() * i,
            ell_vw: h.neg(),
            ell_vv: j + j + j,
        }
    }
}
pub(crate) fn pairing(p: &G1Affine, q: &G2Affine) -> Fp12 {
    let either_zero = Choice::from((p.is_zero() | q.is_zero()) as u8);
    let p = G1Affine::conditional_select(p, &G1Affine::generator(), either_zero);
    let q = G2Affine::conditional_select(q, &G2Affine::generator(), either_zero);
    let tmp = q.precompute().miller_loop(&p).0;
    let tmp = MillerLoopResult(Fp12::conditional_select(&tmp, &Fp12::one(), either_zero));
    tmp.final_exponentiation()
}

#[cfg(test)]
mod tests {
    use super::*;

    mod miller_tests {
        use super::*;
        use crate::groups::g1::G1Projective;

        #[test]
        fn test_identities() {
            let g1 = G1Affine::zero();
            let g2 = G2Affine::generator();
            let gt = pairing(&g1, &g2);
            assert_eq!(gt, Fp12::one());

            let g1 = G1Affine::generator();
            let g2 = G2Affine::zero();
            let gt = pairing(&g1, &g2);
            assert_eq!(gt, Fp12::one());

            let g1 = G1Affine::generator();
            let g2 = G2Affine::generator();
            assert_ne!(pairing(&g1, &g2), pairing(&-g1, &g2));
        }
        #[test]
        fn test_cases() {
            let g1 = G1Affine::from(G1Projective::generator()
                * Fp::new(Fr::new_from_str(
                "18097487326282793650237947474982649264364522469319914492172746413872781676",
            ).expect("").value()));
            let g2 = G2Affine::from(G2Projective::generator()
                * Fp::new(Fr::new_from_str(
                "20390255904278144451778773028944684152769293537511418234311120800877067946",
            ).expect("").value()));

            let gt = pairing(&g1, &g2);

            let expected = Fp12::new(&[
                Fp6::new(&[
                    Fp2::new(&[
                        Fp::new_from_str(
                            "7520311483001723614143802378045727372643587653754534704390832890681688842501",
                        ).expect(""),
                        Fp::new_from_str(
                            "20265650864814324826731498061022229653175757397078253377158157137251452249882",
                        ).expect(""),
                    ]),
                    Fp2::new(&[
                        Fp::new_from_str(
                            "11942254371042183455193243679791334797733902728447312943687767053513298221130",
                        ).expect(""),
                        Fp::new_from_str(
                            "759657045325139626991751731924144629256296901790485373000297868065176843620",
                        ).expect(""),
                    ]),
                    Fp2::new(&[
                        Fp::new_from_str(
                            "16045761475400271697821392803010234478356356448940805056528536884493606035236",
                        ).expect(""),
                        Fp::new_from_str(
                            "4715626119252431692316067698189337228571577552724976915822652894333558784086",
                        ).expect(""),
                    ]),
                ]),
                Fp6::new(&[
                    Fp2::new(&[
                        Fp::new_from_str(
                            "14901948363362882981706797068611719724999331551064314004234728272909570402962",
                        ).expect(""),
                        Fp::new_from_str(
                            "11093203747077241090565767003969726435272313921345853819385060670210834379103",
                        ).expect(""),
                    ]),
                    Fp2::new(&[
                        Fp::new_from_str(
                            "17897835398184801202802503586172351707502775171934235751219763553166796820753",
                        ).expect(""),
                        Fp::new_from_str(
                            "1344517825169318161285758374052722008806261739116142912817807653057880346554",
                        ).expect(""),
                    ]),
                    Fp2::new(&[
                        Fp::new_from_str(
                            "11123896897251094532909582772961906225000817992624500900708432321664085800838",
                        ).expect(""),
                        Fp::new_from_str(
                            "17453370448280081813275586256976217762629631160552329276585874071364454854650",
                        ).expect(""),
                    ]),
                ]), ]
            );
            assert_eq!(gt, expected);
        }

        #[test]
        fn test_bilinearity() {
            use crypto_bigint::rand_core::OsRng;

            for _ in 0..10 {
                let p = G1Affine::rand(&mut OsRng);
                let q = G2Affine::rand(&mut OsRng);
                let s = Fp::new(Fr::rand(&mut OsRng).value());
                let sp = G1Affine::from(G1Projective::from(p) * s);
                let sq = G2Affine::from(G2Projective::from(q) * s);

                let a = pairing(&p, &q).pow(&s.value().to_words());
                let b = pairing(&sp, &q);
                let c = pairing(&p, &sq);

                assert_eq!(a, b);
                assert_eq!(a, c);

                let t = -Fr::ONE;
                assert_ne!(a, Fp12::one());
                assert_eq!((a.pow(&t.value().to_words())) * a, Fp12::one());
            }
        }
    }
}
