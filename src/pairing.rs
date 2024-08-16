use crate::fields::fp::{FieldExtensionTrait, Fp};
use crate::fields::fp12::Fp12;
use crate::fields::fp2::{Fp2, TWO_INV};
use crate::fields::fp6::Fp6;
use crate::groups::g1::{G1Affine, G1Projective};
use crate::groups::g2::{G2Affine, G2Projective, BLS_X};
use crate::groups::group::GroupTrait;
use crate::groups::gt::Gt;
use num_traits::{Inv, One};
use std::ops::{Mul, MulAssign, Neg};
use subtle::{Choice, ConditionallySelectable};

/// This is the value 6*BLS_X+2, which is the bound of iterations on the Miller loops. Why weird?
/// Well, great question. This is the (windowed) non-adjacent form of the number 65, meaning that
/// no nonzero digits are adjacent in this form. The benefit is that during the double and add
/// algorithm of multiplication, the number of operations needed to iterate is directly related
/// to the Hamming weight (number of zeros in a binary representation) of a number. In binary
/// base 2, on average half of the digits will be zero, whereas in the trinary base 3 of the NAF,
/// this moves down to 1/3 on average, improving the loop speed.
const ATE_LOOP_COUNT_NAF: [i8; 64] = [
    1, 0, 1, 0, 0, 0, -1, 0, -1, 0, 0, 0, -1, 0, 1, 0, -1, 0, 0, -1, 0, 0, 0, 0, 0, 1, 0, 0, -1, 0,
    1, 0, 0, -1, 0, 0, 0, 0, -1, 0, 1, 0, 0, 0, -1, 0, -1, 0, 0, 1, 0, 0, 0, -1, 0, 0, -1, 0, 1, 0,
    1, 0, 0, 0,
];
#[derive(Copy, Clone, Debug)]
pub(crate) struct MillerLoopResult(pub(crate) Fp12);
impl Default for MillerLoopResult {
    fn default() -> Self {
        MillerLoopResult(Fp12::one())
    }
}
impl<'a, 'b> Mul<&'b MillerLoopResult> for &'a MillerLoopResult {
    type Output = MillerLoopResult;

    #[inline]
    fn mul(self, rhs: &'b MillerLoopResult) -> MillerLoopResult {
        MillerLoopResult(self.0 * rhs.0)
    }
}
impl Mul<MillerLoopResult> for MillerLoopResult {
    type Output = MillerLoopResult;

    #[inline]
    fn mul(self, rhs: MillerLoopResult) -> MillerLoopResult {
        &self * &rhs
    }
}

impl MulAssign<MillerLoopResult> for MillerLoopResult {
    #[inline]
    fn mul_assign(&mut self, rhs: MillerLoopResult) {
        *self = *self * rhs;
    }
}

impl<'b> MulAssign<&'b MillerLoopResult> for MillerLoopResult {
    #[inline]
    fn mul_assign(&mut self, rhs: &'b MillerLoopResult) {
        *self = *self * *rhs;
    }
}

/// There are many evaluations in Fp12 throughout this. As you can see directly from Algs. 27 and 28
/// in <https://eprint.iacr.org/2010/354.pdf>, for example, regarding the double and addition
/// formulae:
/// //      let l0 = Fp6::new(&[t10, Fp2::zero(), Fp2::zero()]);
/// //      let l1 = Fp6::new(&[t1, t9, Fp2::zero()]);
/// //      return Fp12::new(&[l0, l1])
///
/// which is very, very sparse, resulting in many unnecessary multiplications and additions by
/// zero, which is not ideal. We therefore only keep the 3 nonzero coefficients returned by these
/// evaluations. These nonzero coeffs are stored in the struct below.
#[derive(PartialEq, Default, Clone, Copy)]
pub(crate) struct Ell(Fp2, Fp2, Fp2);

impl MillerLoopResult {
    pub fn final_exponentiation(&self) -> Gt {
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
        pub fn cyclotomic_exp(f: Fp12, exponent: &Fp) -> Fp12 {
            let bits = exponent.value().to_words();
            let mut res = Fp12::one();
            for e in bits.iter().rev() {
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
            cyclotomic_exp(f, &BLS_X).unitary_inverse()
        }
        /// The below is the easy part of the final exponentiation step, corresponding to Lines
        /// 1-4 of Alg 31 from https://eprint.iacr.org/2010/354.pdf.
        fn easy_part(f: Fp12) -> Fp12 {
            let f1 = f.unitary_inverse();
            let f2 = f.inv();
            let f = f1 * f2;
            f.frobenius(2) * f
        }

        /// I was originally going to implement lines 5-28 of Alg 31 from <https://eprint.iacr.org/2010/354.pdf>,
        /// which is allegedly fast, but there is another algorithm that came out more recently
        /// that avoids expensive frobenius operations, which is what Arkworks does.
        ///
        /// This is the hard part, and follows Laura Fuentes-Castaneda et al. "Faster hashing to
        /// G2" <https://link.springer.com/chapter/10.1007/978-3-642-28496-0_25>
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
            u * r
        }

        Gt(hard_part(easy_part(self.0)))
    }
}
/// This is a nice little trick we can use. The Miller loops require the evaluation of an affine
/// point along a line betwixt two projective coordinates, with these two points either being R,
/// and R (therefore leading to the doubling step), or R and Q (leading to the addition step).
/// Think of this as determining the discretization of a parametrized function, but notice that
/// for the entire loop, this discretization does not change, only the point at which we evaluate
/// this function! Therefore, we simply precompute the values on the line, and then use a cheap
/// evaluation in each iteration of the Miller loop to avoid recomputing these "constants" each
/// time. Again, because of the sparse nature of the returned Fp12 from the doubling and addition
/// steps, we store only the 3 non-zero coefficients in an arr of EllCoeffs
///
/// But 87? There's 64 total iterations through the NAF representation, each one incurring a
/// doubling step. Further, there are 9 `1` digits (each with an addition step), and 12 `3`
/// digits, each also with an addition step. After the loop, there are 2 more addition steps, so
/// the total number of coefficients we need to store is 64+9+12+2 = 87.
#[derive(PartialEq)]
pub struct G2PreComputed {
    pub q: G2Affine,
    pub coeffs: [Ell; 87],
}
impl G2PreComputed {
    pub fn miller_loop(&self, g1: &G1Affine) -> MillerLoopResult {
        let mut f = Fp12::one();

        let mut idx = 0;

        for i in ATE_LOOP_COUNT_NAF.iter() {
            let c = &self.coeffs[idx];
            idx += 1;
            f = f.square().sparse_mul(c.0, c.1.scale(g1.y), c.2.scale(g1.x));

            if *i != 0 {
                let c = &self.coeffs[idx];
                idx += 1;
                f = f.sparse_mul(c.0, c.1.scale(g1.y), c.2.scale(g1.x));
            }
        }

        let c = &self.coeffs[idx];
        idx += 1;
        f = f.sparse_mul(c.0, c.1.scale(g1.y), c.2.scale(g1.x));

        let c = &self.coeffs[idx];
        f = f.sparse_mul(c.0, c.1.scale(g1.y), c.2.scale(g1.x));

        MillerLoopResult(f)
    }
}
impl G2Affine {
    fn precompute(&self) -> G2PreComputed {
        let mut r = G2Projective::from(self);

        let mut coeffs = [Ell::default(); 87];

        let q_neg = self.neg();
        // in order to get rid of all the idx's all over the place, you COULD do use a mut
        // iterator, but then you'll have coeffs.iter_mut().next().unwrap().expect("") all over,
        // which is worse ...
        let mut idx: usize = 0;
        for i in ATE_LOOP_COUNT_NAF.iter() {
            coeffs[idx] = r.doubling_step();
            idx += 1;
            match *i {
                1 => {
                    coeffs[idx] = r.addition_step(self);
                    idx += 1;
                }
                -1 => {
                    coeffs[idx] = r.addition_step(&q_neg);
                    idx += 1;
                }
                _ => {}
            }
        }
        let q1 = self.endomorphism();
        let q2 = -(q1.endomorphism());

        coeffs[idx] = r.addition_step(&q1);
        idx += 1;
        coeffs[idx] = r.addition_step(&q2);
        G2PreComputed { q: *self, coeffs }
    }
}
/// The below implements the doubling and addition steps for the Miller loop algorithm. You'll
/// notice that it doesn't return a Fp12, which it should! See notes on efficiency above as to
/// why this returns EllCoeffs instead.
///
/// What zkcrypto does is implement Alg 26 and 27 from <https://eprint.iacr.org/2010/354.pdf>,
/// but there was a more memory sensitive algorithm that came out the same year for the same
/// speed so for use as a pre-compile, we stick with that version that's used by zcash / bn.
///
/// It implements the addition step from page 234, and the doubling step from 235 of
/// <https://link.springer.com/chapter/10.1007/978-3-642-13013-7_14>.
impl G2Projective {
    fn addition_step(&mut self, base: &G2Affine) -> Ell {
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

        Ell(
            <Fp2 as FieldExtensionTrait<2, 2>>::quadratic_non_residue() * (e * base.x - d * base.y),
            d,
            e.neg(),
        )
    }
    fn doubling_step(&mut self) -> Ell {
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

        Ell(
            <Fp2 as FieldExtensionTrait<2, 2>>::quadratic_non_residue() * i,
            h.neg(),
            j + j + j,
        )
    }
}
pub(crate) fn pairing(p: &G1Projective, q: &G2Projective) -> Gt {
    let p = &G1Affine::from(p);
    let q = &G2Affine::from(q);
    let either_zero = Choice::from((p.is_zero() | q.is_zero()) as u8);
    let p = G1Affine::conditional_select(p, &G1Affine::generator(), either_zero);
    let q = G2Affine::conditional_select(q, &G2Affine::generator(), either_zero);
    let tmp = q.precompute().miller_loop(&p).0;
    let tmp = MillerLoopResult(Fp12::conditional_select(&tmp, &Fp12::one(), either_zero));
    tmp.final_exponentiation()
}

pub(crate) fn glued_miller_loop(
    g2_precomps: &[G2PreComputed],
    g1s: &[G1Affine],
) -> MillerLoopResult {
    let mut f = Fp12::one();
    let mut idx = 0;
    for i in ATE_LOOP_COUNT_NAF.iter() {
        f = f.square();
        for (g2_precomp, g1) in g2_precomps.iter().zip(g1s.iter()) {
            let c = &g2_precomp.coeffs[idx];
            f = f.sparse_mul(c.0, c.1.scale(g1.y), c.2.scale(g1.x));
        }
        idx += 1;
        if *i != 0 {
            for (g2_precomp, g1) in g2_precomps.iter().zip(g1s.iter()) {
                let c = &g2_precomp.coeffs[idx];
                f = f.sparse_mul(c.0, c.1.scale(g1.y), c.2.scale(g1.x));
            }
            idx += 1;
        }
    }

    for (g2_precompute, g1) in g2_precomps.iter().zip(g1s.iter()) {
        let c = &g2_precompute.coeffs[idx];
        f = f.sparse_mul(c.0, c.1.scale(g1.y), c.2.scale(g1.x));
    }
    idx += 1;
    for (g2_precompute, g1) in g2_precomps.iter().zip(g1s.iter()) {
        let c = &g2_precompute.coeffs[idx];
        f = f.sparse_mul(c.0, c.1.scale(g1.y), c.2.scale(g1.x));
    }
    MillerLoopResult(f)
}
pub(crate) fn glued_pairing(g1s: &[G1Projective], g2s: &[G2Projective]) -> Gt {
    let g1s = g1s.iter().map(G1Affine::from).collect::<Vec<G1Affine>>();
    let g2s = g2s.iter().map(G2Affine::from).collect::<Vec<G2Affine>>();
    let g2_precomps = g2s
        .iter()
        .map(|g2| g2.precompute())
        .collect::<Vec<G2PreComputed>>();
    glued_miller_loop(&g2_precomps, &g1s).final_exponentiation()
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::fields::fp::Fr;
    mod pairing_tests {
        use crypto_bigint::rand_core::OsRng;

        use super::*;
        use crate::groups::g1::G1Projective;
        const DST: &[u8; 30] = b"WARLOCK-CHAOS-V01-CS01-SHA-256";
        const MSG: &[u8; 4] = &20_i32.to_be_bytes();
        const K: u64 = 128;

        #[test]
        fn test_gt_generator() {
            assert_eq!(
                pairing(&G1Projective::generator(), &G2Projective::generator()),
                Gt::generator()
            );
        }
        #[test]
        fn test_signatures() {
            use crate::hasher::XMDExpander;
            use sha3::Keccak256;
            let expander = XMDExpander::<Keccak256>::new(DST, K);
            let private_key = Fp::new(Fr::rand(&mut OsRng).value());
            if let Ok(hashed_message) = G1Projective::hash_to_curve(&expander, MSG) {
                let signature = hashed_message * private_key;
                let public_key = G2Projective::generator() * private_key;

                let lhs = pairing(&signature, &G2Projective::generator());
                let rhs = pairing(&hashed_message, &public_key);
                assert_eq!(lhs, rhs);
            }
        }
        #[test]
        fn test_shared_secret() {
            fn generate_private_key() -> Fr {
                <Fr as FieldExtensionTrait<1, 1>>::rand(&mut OsRng)
            }
            let alice_sk = generate_private_key();
            let bob_sk = generate_private_key();
            let carol_sk = generate_private_key();

            let (alice_pk1, alice_pk2) = (
                G1Projective::generator() * alice_sk.into(),
                G2Projective::generator() * alice_sk.into(),
            );
            let (bob_pk1, bob_pk2) = (
                G1Projective::generator() * bob_sk.into(),
                G2Projective::generator() * bob_sk.into(),
            );
            let (carol_pk1, carol_pk2) = (
                G1Projective::generator() * carol_sk.into(),
                G2Projective::generator() * carol_sk.into(),
            );

            let alice_ss = pairing(&bob_pk1, &carol_pk2) * alice_sk;
            let bob_ss = pairing(&carol_pk1, &alice_pk2) * bob_sk;
            let carol_ss = pairing(&alice_pk1, &bob_pk2) * carol_sk;
            assert!(alice_ss == bob_ss && bob_ss == carol_ss);
        }
        #[test]
        fn test_identities() {
            let g1 = G1Projective::zero();
            let g2 = G2Projective::generator();
            let gt = pairing(&g1, &g2);
            assert_eq!(gt, Gt::identity());

            let g1 = G1Projective::generator();
            let g2 = G2Projective::zero();
            let gt = pairing(&g1, &g2);
            assert_eq!(gt, Gt::identity());

            let g = G1Projective::generator();
            let h = G2Projective::generator();
            let p = -pairing(&g, &h);
            let q = pairing(&g, &-h);
            let r = pairing(&-g, &h);

            assert_eq!(p, q);
            assert_eq!(q, r);
        }
        #[test]
        fn test_cases() {
            let g1 = G1Projective::generator()
                * Fp::new(Fr::new_from_str(
                "18097487326282793650237947474982649264364522469319914492172746413872781676",
            ).expect("").value());
            let g2 = G2Projective::generator()
                * Fp::new(Fr::new_from_str(
                "20390255904278144451778773028944684152769293537511418234311120800877067946",
            ).expect("").value());

            let gt = pairing(&g1, &g2);

            let expected = Gt(Fp12::new(&[
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
            ));
            assert_eq!(gt, expected);
        }

        #[test]
        fn test_bilinearity() {
            use crypto_bigint::rand_core::OsRng;

            for _ in 0..10 {
                let p = G1Projective::rand(&mut OsRng);
                let q = G2Projective::rand(&mut OsRng);
                let s = Fr::rand(&mut OsRng);
                let sp = G1Projective::from(p) * s.into();
                let sq = G2Projective::from(q) * s.into();

                let a = pairing(&p, &q) * s;
                let b = pairing(&sp, &q);
                let c = pairing(&p, &sq);

                assert_eq!(a, b);
                assert_eq!(a, c);

                let t = -Fr::ONE;
                assert_ne!(a, Gt::identity());
                assert_eq!(&(a * t) + &a, Gt::identity());
            }
        }

        #[test]
        fn test_batches() {
            use crypto_bigint::rand_core::OsRng;
            let r = glued_pairing(&[], &[]);
            assert_eq!(r, Gt::identity());

            const RANGE: usize = 50;

            let mut p_arr = [G1Projective::zero(); RANGE];
            let mut q_arr = [G2Projective::zero(); RANGE];
            let mut sp_arr = [G1Projective::zero(); RANGE];
            let mut sq_arr = [G2Projective::zero(); RANGE];

            for i in 0..RANGE {
                let p = G1Projective::rand(&mut OsRng);
                let q = G2Projective::rand(&mut OsRng);
                let s = Fr::rand(&mut OsRng);
                let sp = p * s.into();
                let sq = q * s.into();
                sp_arr[i] = sp;
                q_arr[i] = q;
                sq_arr[i] = sq;
                p_arr[i] = p;
            }
            let b_batch = glued_pairing(&sp_arr, &q_arr);
            let c_batch = glued_pairing(&p_arr, &sq_arr);
            assert_eq!(b_batch, c_batch);
        }
    }
}
