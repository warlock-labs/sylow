// use std::ops::{Add, AddAssign};
// use crate::fields::fp::FieldExtensionTrait;
// use crate::fields::fp12::Fp12;
// use crate::fields::fp2::Fp2;
// use crate::fields::fp6::Fp6;
// use crate::groups::g1::G1Affine;
// use crate::groups::g2::{BLS_X, G2Affine, G2Projective};
// use crate::groups::group::GroupTrait;
// use num_traits::{Inv, One, Zero};
// use subtle::{Choice, ConditionallySelectable};
//
// impl Fp12 {
//     fn unitary_inverse(&self) -> Self {
//         Self::new(&[self.0[0], -self.0[1]])
//     }
//     fn pow(&self, arg: &[u64;4]) -> Self {
//         let mut res = Self::one();
//         for e in arg.iter().rev() {
//             for i in (0..64).rev() {
//                 res = res.square();
//                 if ((*e >> i) & 1) == 1 {
//                     res *= *self;
//                 }
//             }
//         }
//         res
//     }
// }
// const ATE_LOOP_COUNT: u128 = 29793968203157093288;
// const LOG_ATE_LOOP_COUNT: u32 = 63;
// const PSEUDO_BINARY_ENCODING: [i32; 65] = [
//     0, 0, 0, 1, 0, 1, 0, -1, 0, 0, 1, -1, 0, 0, 1, 0, 0, 1, 1, 0, -1, 0, 0, 1, 0, -1, 0, 0, 0, 0,
//     1, 1, 1, 0, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, 1, 1, 0, 0, -1, 0, 0, 0, 1, 1, 0, -1, 0,
//     0, 1, 0, 1, 1,
// ];
//
// #[derive(Copy, Clone, Debug)]
// pub(crate) struct MillerLoopResult(pub(crate) Fp12);
// impl Default for MillerLoopResult{
//     fn default() -> Self {
//         MillerLoopResult(Fp12::one())
//     }
// }
// impl MillerLoopResult {
//     fn final_exponentiation(&self) -> Fp12 {
//         /// As part of the cyclotomic acceleration of the final exponentiation step, there is a
//         /// shortcut to take when using multiplication in Fp4. We built the tower of extensions using
//         /// degrees 2, 6, and 12, but there is an additional way to write Fp12:
//         /// Fp4 = Fp2[w^3]/((w^3)^2-(9+u))
//         /// Fp12 = Fp4[w]/(w^3-w^3)
//         ///
//         /// This lets us do magic on points in the twist curve with cheaper operations :)
//         /// This implements algorithm 9 from https://eprint.iacr.org/2010/354.pdf, with the notable
//         /// difference that instead of passing an element of Fp4 (which I did not implement), we pass
//         /// in only the two components from Fp2 that comprise the Fp4 element.
//         #[must_use]
//         fn fp4_square(a: Fp2, b: Fp2) -> (Fp2, Fp2) {
//             // Line 1
//             let t0 = <Fp2 as FieldExtensionTrait<2, 2>>::square(&a);
//             // Line 2
//             let t1 = <Fp2 as FieldExtensionTrait<2, 2>>::square(&b);
//             // Line 3
//             let c0 = t1.residue_mul();
//             // Line 4
//             let c0 = c0 + t0;
//             // Line 5
//             let c1 = a + b;
//             // Line 6
//             let c1 = <Fp2 as FieldExtensionTrait<2, 2>>::square(&c1) - t0 - t1;
//             (c0, c1)
//         }
//         /// This implements efficient squaring of an element of Fp12 in the cyclotomic subgroup
//         /// C_{\phi^6}. It is what's called "Granger-Scott" squaring, and is an implementation of
//         /// algorithm 5.5.4 (listing 21) from https://www.math.u-bordeaux.fr/~damienrobert/csi/book/book.pdf
//         #[must_use]
//         fn cyclotomic_square(a: Fp12) -> Fp12 {
//             // Lines 3-8
//             let mut z0 = a.0[0].0[0];
//             let mut z4 = a.0[0].0[1];
//             let mut z3 = a.0[0].0[2];
//             let mut z2 = a.0[1].0[0];
//             let mut z1 = a.0[1].0[1];
//             let mut z5 = a.0[1].0[2];
//             // Line 9
//             let (t0, t1) = fp4_square(z0, z1);
//             // Line 13-22 for A
//             z0 = t0 - z0;
//             z0 = z0 + z0 + t0;
//
//             z1 = t1 + z1;
//             z1 = z1 + z1 + t1;
//
//             let (mut t0, t1) = fp4_square(z2, z3);
//             let (t2, t3) = fp4_square(z4, z5);
//
//             // Lines 25-31, for C
//             z4 = t0 - z4;
//             z4 = z4 + z4 + t0;
//
//             z5 = t1 + z5;
//             z5 = z5 + z5 + t1;
//
//             // Lines 34-41, for B
//             t0 = t3.residue_mul();
//             z2 = t0 + z2;
//             z2 = z2 + z2 + t0;
//
//             z3 = t2 - z3;
//             z3 = z3 + z3 + t2;
//             Fp12::new(&[
//                 Fp6::new(&[z0, z4, z3]),
//                 Fp6::new(&[z2, z1, z5]),
//             ])
//         }
//         /// This is a simple double and add algorithm for squaring. You can get more complicated
//         /// algorithms if you go to a compressed representation, such as Algorithm 5.5.4, listing 27
//         #[must_use]
//         fn cyclotomic_exp(f: Fp12, exponent: &[u64;4]) -> Fp12 {
//             let mut res = Fp12::one();
//             for e in exponent.iter().rev() {
//                 for i in (0..64).rev() {
//                     res = cyclotomic_square(res);
//                     if ((*e >> i) & 1) == 1 {
//                         res *= f;
//                     }
//                 }
//             }
//             res
//         }
//         /// The below is the easy part of the final exponentiation step, corresponding to Lines
//         /// 1-4 of Alg 31 from https://eprint.iacr.org/2010/354.pdf.
//         #[must_use]
//         fn easy_part(f: Fp12) -> Fp12 {
//             let f1 = f.unitary_inverse();
//             let f2 = f.inv();
//             let f = f1 * f2;
//             f.frobenius(2) * f
//         }
//         /// This is a helper function to determine f^z, where $z$ is the generator of this
//         /// particlar member of the BN family
//         #[must_use]
//         fn exp_by_negative_bls_z(f: Fp12) -> Fp12 {
//             cyclotomic_exp(f, &BLS_X.value().to_words()).unitary_inverse()
//         }
//         // this is the hard part of the exponentiation, and relies on cyclotomic magic, and is an
//         // implementation of lines 5-28 of Alg 31 from https://eprint.iacr.org/2010/354.pdf
//         #[must_use]
//         fn hard_part(input: Fp12) -> Fp12 {
//             // // Steps 5-7
//             // let ft1 = exp_by_negative_bls_z(f);  // Algorithm 25
//             // let ft2 = exp_by_negative_bls_z(ft1);
//             // let ft3 = exp_by_negative_bls_z(ft2);
//             //
//             // // Steps 8-10
//             // let fp1 = f.frobenius(1);  // Algorithm 28
//             // let fp2 = f.frobenius(2);  // Algorithm 29
//             // let fp3 = f.frobenius(3);  // Algorithm 30
//             //
//             // // Steps 11-14
//             // let y0 = fp1 * fp2 * fp3;
//             // let y1 = f.unitary_inverse();
//             // let y2 = ft2.frobenius(2);  // Algorithm 29
//             // let y3 = ft1.frobenius(1);  // Algorithm 28
//             //
//             // // Steps 15-17
//             // let y3 = y3.unitary_inverse();
//             // let y4 = ft2.frobenius(1) * ft1;  // Algorithm 28
//             // let y4 = y4.unitary_inverse();
//             //
//             // // Steps 18-20
//             // let y5 = ft2;
//             // let y6 = ft3.frobenius(1) * ft3;  // Algorithm 28
//             // let y6 = y6.unitary_inverse();
//             //
//             // // Steps 21-23
//             // let t0 = cyclotomic_square(y6) * y4 * y5;  // Algorithm 24 for squaring
//             // let t1 = y3 * y5 * t0;
//             // let t0 = t0 * y2;
//             //
//             // // Steps 24-26
//             // let t1 = cyclotomic_square(cyclotomic_square(t1) * t0);  // Algorithm 24 for squaring
//             // let t0 = t1 * y1;
//             // let t1 = t1 * y0;
//             //
//             // // Steps 27-29
//             // let t0 = cyclotomic_square(t0);  // Algorithm 24
//             // let f = t1 * t0;
//             //
//             // f
//             let a = exp_by_negative_bls_z(input);
//             let b = cyclotomic_square(a);
//             let c = cyclotomic_square(b);
//             let d = c * b;
//
//             let e = exp_by_negative_bls_z(d);
//             let f = cyclotomic_square(e);
//             let g = exp_by_negative_bls_z(f);
//             let h = d.unitary_inverse();
//             let i = g.unitary_inverse();
//
//             let j = i * e;
//             let k = j * h;
//             let l = k * b;
//             let m = k * e;
//             let n = input * m;
//
//             let o = l.frobenius(1);
//             let p = o * n;
//
//             let q = k.frobenius(2);
//             let r = q * p;
//
//             let s = input.unitary_inverse();
//             let t = s * l;
//             let u = t.frobenius(3);
//
//             u * r
//         }
//         hard_part(easy_part(self.0))
//     }
// }
//
// #[allow(clippy::suspicious_arithmetic_impl)]
// impl<'a, 'b> Add<&'b MillerLoopResult> for &'a MillerLoopResult {
//     type Output = MillerLoopResult;
//
//     #[inline]
//     fn add(self, rhs: &'b MillerLoopResult) -> MillerLoopResult {
//         MillerLoopResult(self.0 * rhs.0)
//     }
// }
// impl Add<MillerLoopResult> for MillerLoopResult {
//     type Output = MillerLoopResult;
//
//     #[inline]
//     fn add(self, rhs: MillerLoopResult) -> MillerLoopResult {
//         &self + &rhs
//     }
// }
//
// impl AddAssign<MillerLoopResult> for MillerLoopResult {
//     #[inline]
//     fn add_assign(&mut self, rhs: MillerLoopResult) {
//         *self = *self + rhs;
//     }
// }
//
// impl<'b> AddAssign<&'b MillerLoopResult> for MillerLoopResult {
//     #[inline]
//     fn add_assign(&mut self, rhs: &'b MillerLoopResult) {
//         *self = *self + *rhs;
//     }
// }
//
// impl Zero for MillerLoopResult{
//     fn zero() -> Self {
//         MillerLoopResult(Fp12::zero())
//     }
//     fn is_zero(&self) -> bool {
//         self.0.is_zero()
//     }
// }
//
// /// This is an adaptation of Algorithm 26. It modifies the input point in place to double it,
// /// and returns the evaluation of the line at that point. Specifically:
// /// Q\i E^\prime(F_{p^2}) and P\in E(F_{p}), this returns Q = 2Q, and \ell_{Q,Q}(P)=l0 + l1*w\in F_{p^12}
// fn doubling_step(q: &G2Projective, p: &G1Affine) -> (Fp12, G2Projective) {
//     // Line 1
//     let tmp0 = <Fp2 as FieldExtensionTrait<2, 2>>::square(&q.x);
//     // Line 2
//     let tmp1 = <Fp2 as FieldExtensionTrait<2, 2>>::square(&q.y);
//     // Line 3
//     let tmp2 = <Fp2 as FieldExtensionTrait<2, 2>>::square(&tmp1);
//     // Line 4
//     let tmp3 = <Fp2 as FieldExtensionTrait<2, 2>>::square(&(tmp1 + q.x)) - tmp0 - tmp2;
//     // Line 5
//     let tmp3 = tmp3 + tmp3;
//     // Line 6
//     let tmp4 = tmp0 + tmp0 + tmp0;
//     // Line 7
//     let tmp6 = q.x + tmp4;
//     // Line 8
//     let tmp5 = <Fp2 as FieldExtensionTrait<2, 2>>::square(&tmp4);
//     // Line 9
//     let zsquared = <Fp2 as FieldExtensionTrait<2, 2>>::square(&q.z);
//
//     let tx = tmp5 - tmp3 - tmp3;
//     // Line 10
//     let tz = <Fp2 as FieldExtensionTrait<2, 2>>::square(&(q.y + q.z)) - tmp1 - zsquared;
//     // Line 11
//     let ty = (tmp3 - q.x) * tmp4 - tmp2 - tmp2 - tmp2 - tmp2 - tmp2 - tmp2 - tmp2 - tmp2; //8tmp2
//
//     // Line 12
//     let tmp3 = tmp4 * zsquared;
//     let tmp3 = tmp3 + tmp3;
//     let tmp3 = -tmp3; // -2(tmp4*zsquared)
//
//     // Line 13
//     let tmp3 = tmp3.scale(p.x); //tmp3 * p.x;
//                                 // Line 14
//     let tmp6 =
//         <Fp2 as FieldExtensionTrait<2, 2>>::square(&tmp6) - tmp0 - tmp5 - tmp1 - tmp1 - tmp1 - tmp1;
//
//     // Line 15
//     let tmp0 = tz * zsquared;
//     let tmp0 = tmp0 + tmp0;
//
//     // Line 16
//     let tmp0 = tmp0.scale(p.y); //tmp0 * p.y;
//                                 // Line 17 just initializes the variables a0, a1.
//                                 // Line 18
//     let a0 = Fp6::new(&[tmp0, Fp2::zero(), Fp2::zero()]);
//     let a1 = Fp6::new(&[tmp3, tmp6, Fp2::zero()]);
//     (
//         Fp12::new(&[a0, a1]),
//         G2Projective {
//             x: tx,
//             y: ty,
//             z: tz,
//         },
//     )
// }
//
// /// This is an adaptation of Algorithm 27, that adds two points, and evaluates the line at an
// /// affine point. Specifically:
// /// Q, R \in E^\prime(F_{p^2}), and P\in E(F_{p}), this returns T = Q+R, and \ell_{R, Q}(P)=l0 + l1*w\in F_{p^12}
// fn addition_step(q: &G2Projective, r: &G2Projective, p: &G1Affine) -> (Fp12, G2Projective) {
//     // Adaptation of Algorithm 27, https://eprint.iacr.org/2010/354.pdf
//
//     let zrsquared = <Fp2 as FieldExtensionTrait<2, 2>>::square(&r.z);
//     let yqsquared = <Fp2 as FieldExtensionTrait<2, 2>>::square(&q.y);
//
//     // Line 1
//     let t0 = q.x * zrsquared;
//     // Line 2
//     let t1 = <Fp2 as FieldExtensionTrait<2, 2>>::square(&(q.y + r.z)) - yqsquared - zrsquared;
//     // Line 3
//     let t1 = t1 * zrsquared;
//     // Line 4
//     let t2 = t0 - r.x;
//     // Line 5
//     let t3 = <Fp2 as FieldExtensionTrait<2, 2>>::square(&t2);
//     // Line 6
//     let t4 = t3 + t3;
//     let t4 = t4 + t4;
//     // Line 7
//     let t5 = t4 * t2;
//     // Line 8
//     let t6 = t1 - r.y - r.y;
//     // Line 9
//     let t9 = t6 * q.x;
//     // Line 10
//     let t7 = r.x * t4;
//     // Line 11
//     let tx = <Fp2 as FieldExtensionTrait<2, 2>>::square(&t6) - t5 - t7 - t7;
//     // Line 12
//     let tz = <Fp2 as FieldExtensionTrait<2, 2>>::square(&(r.z + t2)) - zrsquared - t3;
//     // Line 13
//     let t10 = q.y + tz;
//     // Line 14
//     let t8 = (t7 - tx) * t6;
//     // Line 15
//     let t0 = r.y * t5;
//     let t0 = t0 + t0;
//     // Line 16
//     let ty = t8 - t0;
//     // Line 17
//     let t10 = <Fp2 as FieldExtensionTrait<2, 2>>::square(&t10) - yqsquared;
//     let ztsquared = <Fp2 as FieldExtensionTrait<2, 2>>::square(&tz);
//     let t10 = t10 - ztsquared;
//     // Line 18
//     let t9 = t9 + t9 - t10;
//     // Line 19
//     let t10 = tz.scale(p.y); //tz*p.y;
//     let t10 = t10 + t10;
//     // Line 20
//     let t6 = -t6;
//     // Line 21
//     let t1 = t6.scale(p.x); //t6 * p.x;
//     let t1 = t1 + t1;
//     // Line 22 just initializes the variables l0, l1.
//     // Line 23
//     let l0 = Fp6::new(&[t10, Fp2::zero(), Fp2::zero()]);
//     let l1 = Fp6::new(&[t1, t9, Fp2::zero()]);
//
//     (
//         Fp12::new(&[l0, l1]),
//         G2Projective {
//             x: tx,
//             y: ty,
//             z: tz,
//         },
//     )
// }
//
// fn miller_loop(p: &G1Affine, q: &G2Projective) -> MillerLoopResult {
//     if q.is_zero() | p.is_zero() {
//         return MillerLoopResult(Fp12::one());
//     }
//     // Line 2
//     let mut _t = *q;
//     let mut f = Fp12::one();
//     let mut _ell = Fp12::one();
//     // Line 3
//     for i in (0..LOG_ATE_LOOP_COUNT).rev() {
//         // Line 4
//         (_ell, _t) = doubling_step(&_t, p); // \ell_{T,T}(P), T=2T
//         f = f * f * _ell; // f = f^2
//         match PSEUDO_BINARY_ENCODING[i as usize] {
//             // Line 5
//             -1 => {
//                 // Line 6
//                 (_ell, _t) = addition_step(&_t, &-q, p); // \ell_{T,-Q}(P), T = T
//                                                          // - Q
//                 f *= _ell;
//             }
//             // Line 7
//             1 => {
//                 // Line 8
//                 (_ell, _t) = addition_step(&_t, q, p); // \ell_{T,Q}(P), T = T + Q
//                 f *= _ell;
//             }
//             _ => {}
//         }
//     }
//     // Line 11
//     let q1 = q.frobenius(1);
//     let q2 = q.frobenius(2);
//     // Line 12
//     (_ell, _t) = addition_step(&_t, &q1, p); // \ell_{T,Q'}(P), T = T + Q'
//     f *= _ell;
//     // Line 13
//     (_ell, _t) = addition_step(&_t, &-q2, p); // \ell_{T,-Q''}(P), T = T - Q''
//     f *= _ell;
//     MillerLoopResult(f)
// }
//
// // def e(P,Q):
// //     assert(subgroup_check_G1(P))
// //     assert(subgroup_check_G2(Q))
// //     if ((P == 0) or (Q == 0)) return 1 # Here, 0 is the identity element of E
// //
// //     T = Q
// //     f = 1
// //     for i in range(len(bound)-2,-1,-1): # len(bound)=65
// //         # the following two lines are step 4 of the alg1, and
// //         # can be done with the "doubling step"
// //         f = f * f * line(twist(T),twist(T),P)
// //         T = 2 * T
// //         # the following two lines are step 5 of the alg1, and
// //         # can be done with the "addition step"
// //         if bound[i] == 1:
// //             f = f * line(untwist(T),untwist(Q),P)
// //             T = T + Q
// //         elif bound[i] == -1:
// //             f = f * line(untwist(T),untwist(-Q),P)
// //             T = T - Q
// //
// //     Q1 = Frobenius(Q, 1); # Q'
// //     Q2 = Frobenius(Q, 2); # Q''
// //     f = f * line(twist(T), twist(Q1), P);
// //     T = T + Q1;
// //     f = f * line(twist(T), twist(-Q2), P);
// //     T = T - Q2;
// //
// //     return final_exponentiation(f)
//
// fn pairing(p: &G1Affine, q: &G2Affine) -> Fp12 {
//     let either_zero = Choice::from((p.is_zero() | q.is_zero()) as u8);
//     let p = G1Affine::conditional_select(p, &G1Affine::generator(), either_zero);
//     let q = G2Affine::conditional_select(q, &G2Affine::generator(), either_zero);
//     let f = miller_loop(&p, &G2Projective::from(q));
//     f.final_exponentiation()
// }
// #[cfg(test)]
// mod tests {
//     use super::*;
//
//     mod miller {
//         use crate::fields::fp::Fp;
//         use crate::groups::g1::G1Projective;
//         use super::*;
//
//         #[test]
//         fn test_encoding() {
//             let sum = PSEUDO_BINARY_ENCODING
//                 .iter()
//                 .enumerate()
//                 .map(|(i, x)| (*x as i128) * 2i128.pow(i as u32))
//                 .sum::<i128>();
//             assert_eq!(
//                 sum, ATE_LOOP_COUNT as i128,
//                 "Pseudo binary encoding sum is not equal to the \
//             loop count"
//             );
//         }
//         #[test]
//         fn test_identities() {
//             let a = G1Affine::zero();
//             let b = G2Affine::generator();
//             assert_eq!(pairing(&a, &b), Fp12::one());
//
//             let a = G1Affine::generator();
//             let b = G2Affine::zero();
//             assert_eq!(pairing(&a, &b), Fp12::one());
//         }
//         #[test]
//         fn test_bilinearity() {
//             use crypto_bigint::rand_core::OsRng;
//             for _ in 0..100 {
//                 let a = <Fp as FieldExtensionTrait<1,1>>::rand(&mut OsRng);
//                 let b = <Fp as FieldExtensionTrait<1,1>>::rand(&mut OsRng);
//                 let c = a*b;
//
//                 let g = G1Affine::from(&G1Projective::generator() * &a.value().to_le_bytes());
//                 let h = G2Affine::from(&G2Projective::generator() * &b.value().to_le_bytes());
//                 let p = pairing(&g, &h);
//
//                 let expected = G1Affine::from(&G1Projective::generator() * &c.value().to_le_bytes());
//                 assert_eq!(p, pairing(&expected, &G2Affine::generator()));
//
//                 assert_eq!(
//                     p,
//                     pairing(&G1Affine::generator(), &G2Affine::generator()).pow(&c.value().to_words())
//                 )
//             }
//
//         }
//         // #[test]
//         // fn test_doubling() {
//         //     let one = G2Projective::generator();
//         //     let two = one.double();
//         //     let three = &one + &(&one + &one);
//         //
//         //     let b = one.frobenius(1);
//         //
//         //     let a = addition_step(&one, &two, &G1Affine::generator());
//         //     println!("{:?}", a);
//         // }
//     }
// }
