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

// TODO(The tracing crate could be better applied here, as it will already give the function name)
// instead talking about what is going on at the point the trace is made.

/// The value 6*BLS_X+2, which is the bound of iterations on the Miller loops.
///
/// Why weird? Well, great question.
///
/// This is the (windowed) non-adjacent form of the number 65, meaning that
/// no non-zero digits are adjacent in this form. The benefit is that during the double and add
/// algorithm of multiplication, the number of operations needed to iterate is directly related
/// to the Hamming weight (number of zeros in a binary representation) of a number. In binary
/// base 2, on average half of the digits will be zero, whereas in trinary base 3 of the NAF,
/// this moves down to 1/3 on average, improving the loop speed.
const ATE_LOOP_COUNT_NAF: [i8; 64] = [
    1, 0, 1, 0, 0, 0, -1, 0, -1, 0, 0, 0, -1, 0, 1, 0, -1, 0, 0, -1, 0, 0, 0, 0, 0, 1, 0, 0, -1, 0,
    1, 0, 0, -1, 0, 0, 0, 0, -1, 0, 1, 0, 0, 0, -1, 0, -1, 0, 0, 1, 0, 0, 0, -1, 0, 0, -1, 0, 1, 0,
    1, 0, 0, 0,
];

// TODO(This should be called `BatchPairingIntermediate` and have a `finalize` method)
// The fact that it's a miller loop is cool commentary inside the function comment
// but speaks about what it is, rather than what it does.
// Moreover, if it's a `Result` of some kind, then it should be wrapped in a `Result` type.
// with the intermediate representation inside of it.
// Additionally, making the 𝔽ₚ¹² opaque here leads to a bit of a leaky abstraction.

/// Represents the result of a Miller loop computation in pairing-based cryptography.
///
/// This struct encapsulates an element of the 𝔽ₚ¹² field, which is the result of a Miller loop
/// calculation. It provides a convenient way to handle and manipulate these results, enforcing
/// multiplicative notation for consistency and clarity.
///
/// The `MillerLoopResult` is typically used as an intermediate representation in pairing
/// computations, before the final exponentiation step that produces an element of the target
/// group 𝔾ᴛ.
///
/// # Examples
///
/// ```
/// use sylow::{G1Projective, G2Projective, GroupTrait, pairing};
///
/// let g1 = G1Projective::generator();
/// let g2 = G2Projective::generator();
/// let result = pairing(&g1, &g2);
/// ```
///
/// # Notes
///
/// - This struct helps to distinguish between additive and multiplicative group operations
///   in the context of pairing computations.
/// - Arithmetic operations on [`MillerLoopResult`] are defined by reference to avoid
///   unnecessary copying of the large 𝔽ₚ¹² elements.
///
/// # Safety
///
/// While the inner 𝔽ₚ¹² element is public within the crate for efficiency reasons,
/// it should be treated as an opaque type outside the crate to maintain encapsulation
/// and prevent misuse.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct MillerLoopResult(pub(crate) Fp12);

/// Returns the default value for [`MillerLoopResult`], which is the
/// multiplicative identity element in 𝔽ₚ¹².
///
/// This is useful when initializing accumulators for batch pairing computations.
///
/// # Returns
///
/// Returns a [`MillerLoopResult`] wrapping the multiplicative identity of 𝔽ₚ¹².
///
/// # Examples
///
/// ```
/// use sylow::MillerLoopResult;
///
/// let default_result = MillerLoopResult::default();
/// ```
impl Default for MillerLoopResult {
    fn default() -> Self {
        MillerLoopResult(Fp12::one())
    }
}

impl<'a, 'b> Mul<&'b MillerLoopResult> for &'a MillerLoopResult {
    type Output = MillerLoopResult;

    /// Multiplies two [`MillerLoopResult`] instances by reference.
    ///
    /// This operation performs the multiplication of the underlying 𝔽ₚ¹² elements.
    ///
    /// # Arguments
    ///
    /// * `self` - The left-hand side [`MillerLoopResult`] reference
    /// * `rhs` - The right-hand side [`MillerLoopResult`] reference
    ///
    /// # Returns
    ///
    /// A new [`MillerLoopResult`] containing the product of the two input values.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sylow::MillerLoopResult;
    /// # let a = MillerLoopResult::default();
    /// # let b = MillerLoopResult::default();
    /// let c = &a * &b;
    /// ```
    #[inline]
    fn mul(self, rhs: &'b MillerLoopResult) -> MillerLoopResult {
        MillerLoopResult(self.0 * rhs.0)
    }
}

impl Mul<MillerLoopResult> for MillerLoopResult {
    type Output = MillerLoopResult;

    /// Multiplies two [`MillerLoopResult`] instances by value.
    ///
    /// This operation delegates to the reference multiplication for efficiency.
    ///
    /// # Arguments
    ///
    /// * `self` - The left-hand side [`MillerLoopResult`]
    /// * `rhs` - The right-hand side [`MillerLoopResult`]
    ///
    /// # Returns
    ///
    /// A new [`MillerLoopResult`] containing the product of the two input values.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sylow::MillerLoopResult;
    /// # let a = MillerLoopResult::default();
    /// # let b = MillerLoopResult::default();
    /// let c = a * b;
    /// ```
    #[inline]
    fn mul(self, rhs: MillerLoopResult) -> MillerLoopResult {
        &self * &rhs
    }
}

impl MulAssign<MillerLoopResult> for MillerLoopResult {
    /// Performs in-place multiplication with another [`MillerLoopResult`].
    ///
    /// This operation updates the current instance with the product of itself
    /// and the provided [`MillerLoopResult`].
    ///
    /// # Arguments
    ///
    /// * `self` - The [`MillerLoopResult`] to be updated
    /// * `rhs` - The right-hand side [`MillerLoopResult`] to multiply with
    ///
    /// # Examples
    ///
    /// ```
    /// # use sylow::MillerLoopResult;
    /// # let mut a = MillerLoopResult::default();
    /// # let b = MillerLoopResult::default();
    /// a *= b;
    /// ```
    #[inline]
    fn mul_assign(&mut self, rhs: MillerLoopResult) {
        *self = *self * rhs;
    }
}

impl<'b> MulAssign<&'b MillerLoopResult> for MillerLoopResult {
    /// Performs in-place multiplication with a reference to another [`MillerLoopResult`].
    ///
    /// This operation updates the current instance with the product of itself
    /// and the provided [`MillerLoopResult`] reference.
    ///
    /// # Arguments
    ///
    /// * `self` - The [`MillerLoopResult`] to be updated
    /// * `rhs` - A reference to the right-hand side [`MillerLoopResult`] to multiply with
    ///
    /// # Examples
    ///
    /// ```
    /// # use sylow::MillerLoopResult;
    /// # let mut a = MillerLoopResult::default();
    /// # let b = MillerLoopResult::default();
    /// a *= &b;
    /// ```
    #[inline]
    fn mul_assign(&mut self, rhs: &'b MillerLoopResult) {
        *self = *self * *rhs;
    }
}

/// There are many evaluations in 𝔽ₚ¹² throughout this module.
/// One can see this directly from algorithms
/// 27 and 28 in <https://eprint.iacr.org/2010/354.pdf>,
/// for example, regarding the double and addition
/// formulae:
/// ```text
///      let l0 = Fp6::new(&[t10, Fp2::zero(), Fp2::zero()]);
///      let l1 = Fp6::new(&[t1, t9, Fp2::zero()]);
///      return Fp12::new(&[l0, l1])
///  ```
/// which is very, very sparse, resulting in many unnecessary multiplications and additions by
/// zero, which is not ideal.
/// We therefore only keep the three non-zero coefficients returned by these
/// evaluations.
/// These non-zero coefficients are stored in the struct below.
#[derive(PartialEq, Default, Clone, Copy, Debug)]
pub(crate) struct Ell(Fp2, Fp2, Fp2);

impl MillerLoopResult {
    // TODO(Rename this to `finalize`)
    /// Performs the final exponentiation step of the optimal ate pairing.
    ///
    /// This method computes f^((p^12-1)/r) for BN254, where f is the result of the Miller loop.
    /// Due to the large exponent, naive computation is infeasible. Instead, we use optimizations
    /// involving cyclotomic subgroups to compute this in two main steps:
    /// 1. The "easy" part: f^((p^6-1)(p^2+1))
    /// 2. The "hard" part: f^((p^4-p^2+1)/r)
    ///
    /// # Returns
    ///
    /// Returns an element of the target group [`Gt`], which is the group of r-th roots of unity in [`Fp12`].
    ///
    /// # References
    ///
    /// For a detailed explanation of the algorithm, see:
    /// - Beuchat et al. "High-Speed Software Implementation of the Optimal Ate Pairing over Barreto-Naehrig Curves"
    ///   <https://eprint.iacr.org/2010/354.pdf>
    /// - Scott et al. "On the Final Exponentiation for Calculating Pairings on Ordinary Elliptic Curves"
    ///   <https://eprint.iacr.org/2009/565.pdf>
    pub fn final_exponentiation(&self) -> Gt {
        /// Computes the square of an element in [`Fp4`] using [`Fp2`] arithmetic.
        ///
        /// This function implements Algorithm 9 from Beuchat et al. with a modification
        /// to work directly with [`Fp2`] elements instead of [`Fp4`].
        ///
        ///
        /// # Arguments
        ///
        /// * `a`, `b` - [`Fp2`] elements representing an [`Fp4`] element
        ///
        /// # Returns
        ///
        /// A tuple of [`Fp2`] elements representing the squared [`Fp4`] element
        ///
        /// # Notes
        ///
        /// ```text
        /// As part of the cyclotomic acceleration of the final exponentiation step, there is a
        /// shortcut to take when using multiplication in Fp4. We built the tower of extensions using
        /// degrees 2, 6, and 12, but there is an additional way to write Fp12:
        ///     Fp4 = Fp2[w^3]/((w^3)^2-(9+u))
        ///     Fp12 = Fp4[w]/(w^3-w^3)
        /// This lets us do magic on points in the twist curve with cheaper operations :)
        /// This implements algorithm 9 from https://eprint.iacr.org/2010/354.pdf, with the notable
        /// difference that instead of passing an element of Fp4 (which I did not implement), we pass
        /// in only the two components from Fp2 that comprise the Fp4 element.
        /// ```
        #[must_use]
        fn fp4_square(a: Fp2, b: Fp2) -> (Fp2, Fp2) {
            // Line 1
            let t0 = a.square();
            // Line 2
            let t1 = b.square();
            // Line 3
            let c0 = t1.residue_mul();
            tracing::trace!(?t0, ?t1, ?c0, "MillerLoopResult::fp4_square");
            // Line 4
            let c0 = c0 + t0;
            // Line 5
            let c1 = a + b;
            // Line 6
            let c1 = c1.square() - t0 - t1;
            (c0, c1)
        }

        /// Efficiently squares an element of [`Fp12`] in the cyclotomic subgroup C_{\phi^6}.
        ///
        /// This function implements the Granger-Scott squaring algorithm, which is
        /// more efficient than general [`Fp12`] squaring for elements in the cyclotomic subgroup.
        ///
        /// # Arguments
        ///
        /// * `f` - An [`Fp12`] element in the cyclotomic subgroup
        ///
        /// # Returns
        ///
        /// The squared [`Fp12`] element
        ///
        /// # References
        ///
        /// Granger-Scott, "Faster ECC over F_{2^521-1}", Algorithm 5.5.4 (listing 21)
        /// <https://www.math.u-bordeaux.fr/~damienrobert/csi/book/book.pdf>
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
            tracing::trace!(?t0, ?t1, "MillerLoopResult::cyclotomic_squared");
            // Line 13-22 for A
            z0 = t0 - z0;
            z0 = z0 + z0 + t0;

            z1 = t1 + z1;
            z1 = z1 + z1 + t1;

            let (mut t0, t1) = fp4_square(z2, z3);
            let (t2, t3) = fp4_square(z4, z5);
            tracing::trace!(?t0, ?t1, ?t2, ?t3, "MillerLoopResult::cyclotomic_squared");

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

        /// Computes the cyclotomic exponentiation of an [`Fp12`] element.
        ///
        /// This function uses a simple square-and-multiply algorithm for exponentiation.
        ///
        /// # Arguments
        ///
        /// * `f` - The [`Fp12`] element to exponentiate
        /// * `exponent` - The exponent as an [`Fp`] element
        ///
        /// # Returns
        ///
        /// The exponentiated [`Fp12`] element
        ///
        /// # Notes
        ///
        /// You can get more complicated algorithms if you go to a compressed representation,
        /// such as Algorithm 5.5.4, listing 27
        #[must_use]
        pub(crate) fn cyclotomic_exp(f: Fp12, exponent: &Fp) -> Fp12 {
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

        /// Computes f^(-z) where z is the generator of this
        /// particular member in the BN family
        ///
        /// # Arguments
        ///
        /// * `f` - The [`Fp12`] element to exponentiate
        ///
        /// # Returns
        ///
        /// F^(-z) as an [`Fp12`] element
        pub(crate) fn exp_by_neg_z(f: Fp12) -> Fp12 {
            cyclotomic_exp(f, &BLS_X).unitary_inverse()
        }

        /// Computes the easy part of the final exponentiation.
        ///
        /// This function corresponds to Lines 1-4 of Algorithm 31 from Beuchat et al.
        ///
        /// # Arguments
        ///
        /// * `f` - The [`Fp12`] element to exponentiate
        ///
        /// # Returns
        ///
        /// The result of the easy part exponentiation as an [`Fp12`] element
        ///
        /// # References
        ///
        /// Beuchat et al. "High-Speed Software Implementation of the Optimal Ate Pairing over Barreto-Naehrig Curves" 1-4 of Alg 31
        /// <https://eprint.iacr.org/2010/354.pdf>
        fn easy_part(f: Fp12) -> Fp12 {
            let f1 = f.unitary_inverse();
            let f2 = f.inv();
            let f = f1 * f2;
            f.frobenius(2) * f
        }

        /// Computes the hard part of the final exponentiation.
        ///
        /// This implementation follows the optimized algorithm by
        /// Laura Fuentes-Castañeda et al., which reduces the number of
        /// expensive Frobenius operations.
        ///
        /// # Arguments
        ///
        /// * `input` - The [`Fp12`] element output from the easy part
        ///
        /// # Returns
        ///
        /// The result of the hard part exponentiation as an [`Fp12`] element
        ///
        /// # References
        ///
        /// Fuentes-Castañeda et al. "Faster hashing to G2"
        /// <https://link.springer.com/chapter/10.1007/978-3-642-28496-0_25>
        /// Arkworks implementation:
        /// <https://github.com/arkworks-rs/algebra/blob/273bf2130420904cab815544664a539f049d0494/ec/src/models/bn/mod.rs#L141>
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
            tracing::trace!(
                ?a,
                ?b,
                ?c,
                ?d,
                ?e,
                ?f,
                ?g,
                ?h,
                ?i,
                ?j,
                ?k,
                ?l,
                ?m,
                ?n,
                ?o,
                ?p,
                ?q,
                ?r,
                ?s,
                ?t,
                ?u,
                "MillerLoopResult::hard_part"
            );
            u * r
        }

        Gt(hard_part(easy_part(self.0)))
    }
}

//  This is a nice little trick we can use. The Miller loops require the evaluation of an affine
//  point along a line betwixt two projective coordinates, with these two points either being R,
//  and R (therefore leading to the doubling step), or R and Q (leading to the addition step).
//  Think of this as determining the discretization of a parametrized function, but notice that
//  for the entire loop, this discretization does not change, only the point at which we evaluate
//  this function! Therefore, we simply precompute the values on the line, and then use a cheap
//  evaluation in each iteration of the Miller loop to avoid recomputing these "constants" each
//  time. Again, because of the sparse nature of the returned 𝔽ₚ¹² from the doubling and addition
//  steps, we store only the 3 non-zero coefficients in an arr of EllCoeffs.

/// Precomputed data for efficient Miller loop calculations on 𝔾₂ points.
///
/// This struct stores precomputed line coefficients for a 𝔾₂ point, which are used
/// to optimize pairing calculations, particularly in the Miller loop algorithm.
///
/// # Structure
///
/// The struct consists of two main components:
/// 1. The original 𝔾₂ point in affine coordinates.
/// 2. An array of precomputed line coefficients.
///
/// # Line Coefficients
///
/// The coefficient array contains 87 elements, which is derived from:
/// - 64 iterations through the NAF (Non-Adjacent Form) representation, each requiring a doubling step.
/// - 9 additions for '1' digits in the NAF.
/// - 12 additions for '-1' digits in the NAF.
/// - 2 final addition steps.
///
/// This totals to 64 + 9 + 12 + 2 = 87 coefficients.
///
/// # Optimization Technique
///
/// This precomputation is an optimization for the Miller loop. Instead of computing line
/// equations for each iteration, we precompute these values and store only the non-zero
/// coefficients. This approach significantly reduces the number of field operations
/// required during pairing calculations.
///
/// # Usage
///
/// `G2PreComputed` is typically used in conjunction with 𝔾₁ points for efficient pairing
/// computations, especially in scenarios requiring multiple pairing operations, such as
/// in threshold signature schemes.
///
/// # Example
///
/// ```
/// use sylow::{G2Projective, G2PreComputed, GroupTrait};
///
/// let g2_point = G2Projective::generator();
/// let precomputed = g2_point.precompute();
/// ```
///
/// # References
///
/// For more details on the Miller loop and its optimizations, see:
/// - "High-Speed Software Implementation of the Optimal Ate Pairing over Barreto-Naehrig Curves"
///   by Beuchat et al. <https://eprint.iacr.org/2010/354.pdf>
/// - Miller, V.S., "The Weil Pairing, and Its Efficient Calculation"
///   <https://link.springer.com/article/10.1007/s00145-004-0315-8>
#[derive(PartialEq, Debug, Copy, Clone)]
pub struct G2PreComputed {
    pub(crate) q: G2Affine,
    pub(crate) coeffs: [Ell; 87],
}
impl G2PreComputed {
    /// Evaluates the Miller loop using precomputed line coefficients.
    ///
    /// This method performs an optimized Miller loop calculation for the precomputed 𝔾₂ point
    /// paired with a given 𝔾₁ point.
    ///
    /// # Arguments
    ///
    /// * `g1` - A reference to a 𝔾₁ point in affine coordinates, [`G1Affine`].
    ///
    /// # Returns
    ///
    /// Returns a [`MillerLoopResult`] representing the outcome of the Miller loop calculation.
    ///
    /// # Algorithm
    ///
    /// The method iterates through the precomputed coefficients, performing
    /// efficient sparse multiplications at each step. It follows the NAF (Non-Adjacent Form)
    /// representation of the ate pairing loop count for optimized computation.
    ///
    /// # Performance
    ///
    /// This method is significantly faster than computing the full Miller loop from scratch,
    /// as it uses precomputed values and optimized sparse multiplications.
    ///
    /// # References
    ///
    /// For more information on the Miller loop algorithm and its optimizations, see:
    /// - Miller, V.S., "The Weil Pairing, and Its Efficient Calculation"
    ///   <https://crypto.stanford.edu/miller/miller.pdf>
    pub fn miller_loop(&self, g1: &G1Affine) -> MillerLoopResult {
        let mut f = Fp12::one();

        let mut idx = 0;

        for i in ATE_LOOP_COUNT_NAF.iter() {
            let c = &self.coeffs[idx];
            idx += 1;
            f = f.square().sparse_mul(c.0, c.1.scale(g1.y), c.2.scale(g1.x));
            tracing::trace!(?idx, ?f, "G2PreComputed::miller_loop");

            if *i != 0 {
                let c = &self.coeffs[idx];
                idx += 1;
                f = f.sparse_mul(c.0, c.1.scale(g1.y), c.2.scale(g1.x));
                tracing::trace!(?idx, ?f, "G2PreComputed::miller_loop");
            }
        }

        let c = &self.coeffs[idx];
        idx += 1;
        f = f.sparse_mul(c.0, c.1.scale(g1.y), c.2.scale(g1.x));
        tracing::trace!(?idx, ?f, "G2PreComputed::miller_loop");

        let c = &self.coeffs[idx];
        f = f.sparse_mul(c.0, c.1.scale(g1.y), c.2.scale(g1.x));
        tracing::trace!(?idx, ?f, "G2PreComputed::miller_loop");

        MillerLoopResult(f)
    }
}
impl G2Projective {
    /// Converts the 𝔾₂ point to affine coordinates and computes the [`G2PreComputed`] structure.
    ///
    /// This method is a convenience wrapper that converts the projective point to
    /// affine coordinates before precomputing the line coefficients.
    ///
    /// # Returns
    ///
    /// Returns a [`G2PreComputed`] struct containing precomputed data for this 𝔾₂ point.
    ///
    /// # Example
    ///
    /// ```
    /// use sylow::{G2Projective, G2PreComputed, GroupTrait};
    ///
    /// let g2_point = G2Projective::generator();
    /// let precomputed = g2_point.precompute();
    /// ```
    pub fn precompute(&self) -> G2PreComputed {
        G2Affine::from(self).precompute()
    }
}

impl G2Affine {
    /// Computes the [`G2PreComputed`] structure for this 𝔾₂ affine point.
    ///
    /// This method performs the actual precomputation of line coefficients used
    /// in optimized Miller loop calculations.
    ///
    /// # Algorithm
    ///
    /// 1. Converts the affine point to projective coordinates.
    /// 2. Iterates through the NAF representation of the ate pairing loop count.
    /// 3. Computes and stores line coefficients for each step (doubling and addition).
    /// 4. Performs final computations including endomorphism applications.
    ///
    /// # Returns
    ///
    /// Returns a [`G2PreComputed`] struct containing the original point and
    /// precomputed line coefficients.
    ///
    /// # Performance Considerations
    ///
    /// While this precomputation is computationally intensive, it significantly
    /// speeds up subsequent pairing operations, especially when the same 𝔾₂ point
    /// is used in multiple pairings.
    ///
    /// # Example
    ///
    /// ```
    /// use sylow::{G2Affine, G2Projective, GroupTrait};
    ///
    /// let g2_point = G2Affine::from(G2Projective::generator());
    /// let precomputed = g2_point.precompute();
    /// ```
    pub fn precompute(&self) -> G2PreComputed {
        let mut r = G2Projective::from(self);

        let mut coeffs = [Ell::default(); 87];

        let q_neg = -self;
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

// The below implements the doubling and addition steps for the Miller loop algorithm. You'll
// notice that it doesn't return a Fp12, which it should! See notes on efficiency above as to
// why this returns EllCoeffs instead.
//
// What zkcrypto does is implement Alg 26 and 27 from <https://eprint.iacr.org/2010/354.pdf>,
// but there was a more memory sensitive algorithm that came out the same year for the same
// speed so for use as a pre-compile, we stick with that version that's used by zcash / bn.
//
// It implements the addition step from page 234, and the doubling step from 235 of
// <https://link.springer.com/chapter/10.1007/978-3-642-13013-7_14>.

/// Implementation of addition and doubling steps for the Miller loop algorithm on 𝔾₂ points.
///
/// These methods implement an optimized version of the addition and doubling steps
/// used in the Miller loop calculation for BN254 curves. They are specifically designed
/// for efficiency in precomputation scenarios.
impl G2Projective {
    /// Performs the addition step in the Miller loop algorithm.
    ///
    /// This method adds an affine point (base) to the current projective point (self)
    /// and computes the line coefficients for this addition.
    ///
    /// # Arguments
    ///
    /// * `base` - A reference to a 𝔾₂ point in affine coordinates to be added.
    ///
    /// # Returns
    ///
    /// Returns an `Ell` struct containing the non-zero coefficients of the line
    /// equation resulting from this addition step.
    ///
    /// # Algorithm
    ///
    /// This implements the addition step as described on page 234 of:
    /// Costello et al. "Faster Pairing Computations on Curves with High-Degree Twists"
    /// <https://link.springer.com/chapter/10.1007/978-3-642-13013-7_14>
    ///
    /// # Side Effects
    ///
    /// This method mutates `self`, updating it to the result of the addition.
    ///
    /// # Performance Notes
    ///
    /// This method is optimized for memory usage and computation speed in the
    /// context of pairing calculations.
    fn addition_step(&mut self, base: &G2Affine) -> Ell {
        let d = self.x - self.z * base.x;
        let e = self.y - self.z * base.y;
        let f = d.square();
        let g = e.square();
        let h = d * f;
        let i = self.x * f;
        let j = self.z * g + h - (i + i);
        tracing::trace!(?d, ?e, ?f, ?g, ?h, ?i, ?j, "G2Projective::addition_step");

        self.x = d * j;
        self.y = e * (i - j) - h * self.y;
        self.z *= h;

        // Return the non-zero coefficients of the line equation
        Ell((e * base.x - d * base.y).residue_mul(), d, e.neg())
    }

    /// Performs the doubling step in the Miller loop algorithm.
    ///
    /// This method doubles the current projective point (self) and computes
    /// the line coefficients for this doubling operation.
    ///
    /// # Returns
    ///
    /// Returns an `Ell` struct containing the non-zero coefficients of the line
    /// equation resulting from this doubling step.
    ///
    /// # Algorithm
    ///
    /// This implements the doubling step as described on page 235 of:
    /// Costello et al. "Faster Pairing Computations on Curves with High-Degree Twists"
    /// <https://link.springer.com/chapter/10.1007/978-3-642-13013-7_14>
    ///
    /// # Side Effects
    ///
    /// This method mutates `self`, updating it to the result of the doubling.
    ///
    /// # Performance Notes
    ///
    /// This method uses several optimizations to reduce the number of field operations,
    /// including the use of the `TWO_INV` constant and curve-specific optimizations.
    fn doubling_step(&mut self) -> Ell {
        let a = (self.x * self.y).scale(TWO_INV);
        let b = self.y.square();
        let c = self.z.square();
        let d = c + c + c;
        let e = <Fp2 as FieldExtensionTrait<2, 2>>::curve_constant() * d;
        let f = e + e + e;
        let g = (b + f).scale(TWO_INV);
        let h = (self.y + self.z).square() - (b + c);
        let i = e - b;
        let j = self.x.square();
        let e_sq = e.square();
        tracing::trace!(?f, ?g, ?h, ?i, ?j, ?e_sq, "G2Projective::doubling_step");

        self.x = a * (b - f);
        self.y = g.square() - (e_sq + e_sq + e_sq);
        self.z = b * h;

        // Return the non-zero coefficients of the line equation
        Ell(i.residue_mul(), h.neg(), j + j + j)
    }
}

/// Computes the optimal ate pairing for a pair of points on the BN254 curve.
///
/// This function calculates the bilinear pairing e(P, Q) where P is a point in 𝔾₁ and Q is a point in 𝔾₂.
/// The pairing is an essential operation in many cryptographic protocols, especially those involving
/// zero-knowledge proofs and identity-based encryption.
///
/// # Arguments
///
/// * `p` - A reference to a point P in 𝔾₁, represented as [`G1Projective`].
/// * `q` - A reference to a point Q in 𝔾₂, represented as [`G2Projective`].
///
/// # Returns
///
/// Returns a [`Gt`] element representing the result of the pairing operation.
///
/// # Example
///
/// ```
/// use sylow::{G1Projective, G2Projective, GroupTrait, pairing};
///
/// let p = G1Projective::generator();
/// let q = G2Projective::generator();
/// let result = pairing(&p, &q);
/// ```
///
/// # Implementation Notes
///
/// 1. The function first converts both input points to affine coordinates.
/// 2. It handles the case where either point is the point at infinity (zero) by using conditional selection.
/// 3. The actual pairing computation is done through the Miller loop and final exponentiation.
/// 4. The implementation is constant-time with respect to the input points to prevent timing attacks.
///
/// # Performance Considerations
///
/// Pairing is a computationally expensive operation. For scenarios requiring multiple pairings,
/// consider using batch pairing techniques exposed by [`glued_miller_loop`] and [`MillerLoopResult`]
/// for better performance.
///
/// # Security Notes
///
/// This implementation is designed to be resistant to timing attacks by using constant-time operations
/// where possible. However, users should be aware of the security implications in their specific use cases.
///
/// # References
///
/// - "High-Speed Software Implementation of the Optimal Ate Pairing over Barreto-Naehrig Curves"
///   by J-L. Beuchat et al. <https://eprint.iacr.org/2010/354.pdf>
/// - "Faster Pairing Computations on Curves with High-Degree Twists" by C. Costello et al.
///   <https://eprint.iacr.org/2009/615.pdf>
pub fn pairing(p: &G1Projective, q: &G2Projective) -> Gt {
    // Convert inputs to affine coordinates
    let p = &G1Affine::from(p);
    let q = &G2Affine::from(q);

    // Handle point at infinity (zero) cases
    let either_zero = Choice::from((p.is_zero() | q.is_zero()) as u8);
    let p = G1Affine::conditional_select(p, &G1Affine::generator(), either_zero);
    let q = G2Affine::conditional_select(q, &G2Affine::generator(), either_zero);

    // TODO(Is the Miller loop faster here for a single pairing?)

    // Compute the Miller loop
    let tmp = q.precompute().miller_loop(&p).0;

    // Conditional selection to handle zero cases
    let tmp = MillerLoopResult(Fp12::conditional_select(&tmp, &Fp12::one(), either_zero));

    tracing::trace!(?p, ?q, ?tmp, "pairing");

    // Perform the final exponentiation and return the result
    tracing::trace!(?p, ?q, ?tmp, "pairing");
    tmp.final_exponentiation()
}

// TODO(While the fact that this is a glued miller loop is interesting)
// this would be better named `batch_pairing` or something similar
// indicating what it is, rather than the implementation details.
// With that said, we'd need to preserve the idea that there is a `finalize` step required
// for batch pairings.

/// Performs a batched pairing calculation for multiple pairs of 𝔾₁ and 𝔾₂ points.
///
/// This function uses a glued Miller loop, which is an optimization technique
/// used in pairing-based cryptography to compute multiple pairings using intermediate representations.
/// This function is particularly useful for scenarios like threshold signature verification where
/// multiple pairings need to be calculated and subsequently combined.
///
/// # Algorithm
///
/// The function implements an optimized version of the Miller loop that:
/// 1. Iterates through the NAF (Non-Adjacent Form) representation of the ate pairing loop count.
/// 2. Performs line evaluations for all input pairs in each iteration.
/// 3. Combines the results of these evaluations efficiently.
///
/// # Arguments
///
/// * `g2_precomps` - A slice of precomputed 𝔾₂ points. Each [`G2PreComputed`] contains:
///   - The original 𝔾₂ point
///   - Precomputed line coefficients for efficient evaluation
/// * `g1s` - A slice of 𝔾₁ affine points, [`G1Affine`] to be paired with the 𝔾₂ points
///
/// The number of 𝔾₁ and 𝔾₂ points must be the same.
///
/// # Returns
///
/// * [`MillerLoopResult`] - The combined result of the Miller loop calculations
///
/// # Performance Considerations
///
/// This function is more efficient than calculating individual pairings and then combining
/// the results, as it reduces the number of extension field operations required.
///
/// # Example
///
/// This example demonstrates how to use the [`glued_miller_loop`] function, including
/// point generation, precomputation, and result verification:
///
/// ```
/// use crypto_bigint::{Pow, PowBoundedExp};
/// use sylow::{
///     Fp, Fr, G1Affine, G1Projective, G2Affine, G2Projective, G2PreComputed,
///     glued_miller_loop, FieldExtensionTrait, GroupTrait, pairing
/// };
/// use crypto_bigint::rand_core::OsRng;
///
/// // Number of pairs to generate and compute
/// const NUM_PAIRS: usize = 3;
///
/// // Generate random G1 and G2 points
/// let g1_points: Vec<G1Projective> = (0..NUM_PAIRS)
///     .map(|_| G1Projective::rand(&mut OsRng))
///     .collect();
/// let g2_points: Vec<G2Projective> = (0..NUM_PAIRS)
///     .map(|_| G2Projective::rand(&mut OsRng))
///     .collect();
///
/// // Convert G1 points to affine representation
/// let g1_affine: Vec<G1Affine> = g1_points.iter().map(|p| G1Affine::from(p)).collect();
///
/// // Precompute G2 points
/// let g2_precomps: Vec<G2PreComputed> = g2_points
///     .iter()
///     .map(|g2| G2Affine::from(g2).precompute())
///     .collect();
///
/// // Perform the glued Miller loop
/// let glued_result = glued_miller_loop(&g2_precomps, &g1_affine);
/// let result = glued_result.final_exponentiation();
/// ```
pub fn glued_miller_loop(g2_precomps: &[G2PreComputed], g1s: &[G1Affine]) -> MillerLoopResult {
    // Initialize the accumulator for the Miller loop result
    let mut f = Fp12::one();
    let mut idx = 0;

    // TODO(Check the length of the input slices and return an error if they are not equal)
    // TODO(Dry the 4 repeated code chunks below)
    // TODO(Will this pairing ever be used with secret information? If so, are we concerned here)
    // that this may have variable runtime based on the secret information?
    // do we want to enforce constant time here?

    // Iterate through the NAF representation of the ate pairing loop count
    for i in ATE_LOOP_COUNT_NAF.iter() {
        // Square the accumulator (this is part of the standard Miller loop)
        f = f.square();

        // Perform line evaluations for all pairs and update the accumulator
        for (g2_precomp, g1) in g2_precomps.iter().zip(g1s.iter()) {
            let c = &g2_precomp.coeffs[idx];
            // Sparse multiplication optimization
            f = f.sparse_mul(c.0, c.1.scale(g1.y), c.2.scale(g1.x));
        }
        tracing::trace!(?f, "glued_miller_loop 1");
        idx += 1;

        // Additional step for non-zero NAF digits
        if *i != 0 {
            for (g2_precomp, g1) in g2_precomps.iter().zip(g1s.iter()) {
                let c = &g2_precomp.coeffs[idx];
                f = f.sparse_mul(c.0, c.1.scale(g1.y), c.2.scale(g1.x));
            }
            idx += 1;
        }
        tracing::trace!(?f, "glued_miller_loop 2");
    }

    // Final line evaluations after the main loop
    for (g2_precompute, g1) in g2_precomps.iter().zip(g1s.iter()) {
        let c = &g2_precompute.coeffs[idx];
        f = f.sparse_mul(c.0, c.1.scale(g1.y), c.2.scale(g1.x));
    }
    tracing::trace!(?f, "final_evaluations_miller_loop");
    idx += 1;

    for (g2_precompute, g1) in g2_precomps.iter().zip(g1s.iter()) {
        let c = &g2_precompute.coeffs[idx];
        f = f.sparse_mul(c.0, c.1.scale(g1.y), c.2.scale(g1.x));
    }

    // TODO(Rename this similarly to BatchPairingResult or similar)
    // Wrap the final result in a MillerLoopResult
    MillerLoopResult(f)
}
/// The driver code for the glued miller loop execution, see comments above.
/// # Arguments
/// * `g1s` - an array of G1 points
/// * `g2s` - an array of G2 points
/// # Returns
/// * the result of the pairing, doing each one individually and then aggregating their result
pub fn glued_pairing(g1s: &[G1Projective], g2s: &[G2Projective]) -> Gt {
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
    #[test]
    fn test_miller_assignments() {
        let mut a = MillerLoopResult::default();
        let b = MillerLoopResult::default();
        a *= b;
        assert_eq!(a, MillerLoopResult::default());
    }
}
