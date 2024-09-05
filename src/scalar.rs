use num_traits::{Inv, Zero};
use std::ops::{Add, Div, Mul, Neg, Sub};
use subtle::{CtOption, ConditionallySelectable, ConstantTimeEq, Choice};
type Matrix = [[i64; 2]; 2];

#[derive(Clone, Debug)]
struct Step<const L: usize> {
    delta: i64,
    f: [u64; L],
    g: [u64; L],
    p: [[f64; L]; 4],
}
#[derive(Clone, Copy, Debug, PartialEq)] // Non constant-time Eq
#[repr(C)]
pub struct Words<const L: usize> ([u64; L]);

impl<const L: usize> ConditionallySelectable for Words<L> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut limbs = [0u64; L];
        let mut i = 0;
        while i < L {
            limbs[i] = u64::conditional_select(&a.0[i], &b.0[i], choice);
            i += 1;
        }
        Self(limbs)
    }
}
impl<const L: usize> Words<L>{
    pub fn nbits(&self) -> u32 {
        for i in (0..L).rev() {
            if self.0[i] != 0 {
                return (i as u32 + 1) * 64 - self.0[i].leading_zeros();
            }
        }
        0 // Return 0 if all limbs are zero
    }
    pub fn max_nbits(f: &Words<L>, g: &Words<L>) -> u32 {
        std::cmp::max(f.nbits(), g.nbits())
    }
}
// / A finite field scalar optimized for use in cryptographic operations.
// /
// / All operations feature modular arithmetic, implemented in constant time.
// / Primarily focusing on fields of prime order, non-prime order fields may
// / have undefined behavior at this time.
#[derive(Clone, Copy, Debug)]
pub struct FinitePrimeField<const L: usize, const D: usize> {
    modulus: Words<L>,
    value: Words<L>,
    r_squared: Words<L>,
    n_prime: u64,
}

impl<const L: usize, const D: usize> FinitePrimeField<L, D> {
    pub const fn new(
        modulus: [u64; L],
        value: [u64; L],
        r_squared: [u64; L],
        n_prime: u64,
    ) -> Self {
        if D != 2 * L {
            panic!("Double size D must be twice the size of the field L");
        }
        let mut result = Self {
            modulus: Words(modulus),
            value: Words([0; L]),
            r_squared: Words(r_squared),
            n_prime,
        };
        result.value = result.to_montgomery(&Words(value));
        result
    }
    // fn from(value: u64) -> Self {
    //     let mut retval = Self::zero_array();
    //     retval.0[0] = value;
    //     Self::new(&retval)
    // }
    const fn zero_array() -> Words<L> {
        Words([0; L])
    }
    //
    const fn one_array() -> Words<L> {
        let mut arr = [0; L];
        arr[0] = 1;
        Words(arr)
    }

    const fn to_montgomery(self, a: &Words<L>) -> Words<L> {
        self.montgomery_multiply(a, &self.r_squared)
    }

    const fn from_montgomery(&self, a: &Words<L>) -> [u64; L] {
        self.montgomery_multiply(a, &Self::one_array()).0
    }

    const fn montgomery_multiply(&self, a: &Words<L>, b: &Words<L>) -> Words<L> {
        let mut temp = [0_u64; D];
        let mut result = Self::zero_array().0;

        let mut i = 0;
        let mut j = 0;
        while i < L {
            let mut carry = 0_u64;
            j = 0;
            while j < L {
                let hilo =
                    (a.0[j] as u128) * (b.0[i] as u128) + (temp[i + j] as u128) + (carry as u128);
                temp[i + j] = hilo as u64;
                carry = (hilo >> 64) as u64;
                j += 1;
            }
            temp[i + L] += carry;

            let m: u64 = temp[i].wrapping_mul(self.n_prime);

            let mut carry = 0_u64;
            j = 0;
            while j < L {
                let hilo = (m as u128) * (self.modulus.0[j] as u128)
                    + (temp[i + j] as u128)
                    + (carry as u128);
                temp[i + j] = hilo as u64;
                carry = (hilo >> 64) as u64;
                j += 1;
            }
            temp[i + L] += carry;
            i += 1;
        }

        let mut dec = [0_u64; L];
        let mut borrow = 0_u64;
        i = 0;
        while i < L {
            let (diff, borrow_t0) = temp[i + L].overflowing_sub(self.modulus.0[i] + borrow);
            dec[i] = diff;
            borrow = borrow_t0 as u64;
            i += 1;
        }

        let select_temp = borrow.wrapping_neg();
        i = 0;
        while i < L {
            result[i] = (select_temp & temp[i + L]) | (!select_temp & dec[i]);
            i += 1;
        }
        Words(result)
    }

    const fn add_internal(&self, a: &Words<L>, b: &Words<L>) -> Words<L> {
        let mut sum = [0; L];
        let mut carry = false;
        let mut result = Self::zero_array().0;
        let mut i = 0;
        while i < L {
            let sum_with_other = a.0[i].overflowing_add(b.0[i]);
            let sum_with_carry = sum_with_other.0.overflowing_add(if carry { 1 } else { 0 });
            sum[i] = sum_with_carry.0;
            carry = sum_with_other.1 | sum_with_carry.1;
            i += 1;
        }

        let mut trial = [0; L];
        let mut borrow = false;
        i = 0;
        while i < L {
            let diff_with_borrow =
                sum[i].overflowing_sub(self.modulus.0[i] + if borrow { 1 } else { 0 });
            trial[i] = diff_with_borrow.0;
            borrow = diff_with_borrow.1;
            i += 1;
        }

        let select_mask = (borrow as u64).wrapping_neg();
        i = 0;
        while i < L {
            result[i] = (select_mask & sum[i]) | (!select_mask & trial[i]);
            i += 1;
        }
        Words(result)
    }

    const fn sub_internal(&self, a: &Words<L>, b: &Words<L>) -> Words<L> {
        let mut diff = [0; L];
        let mut borrow = false;
        let mut result = Self::zero_array().0;
        let mut i = 0;
        while i < L {
            let diff_without_borrow = a.0[i].overflowing_sub(b.0[i]);
            let diff_with_borrow =
                diff_without_borrow
                    .0
                    .overflowing_sub(if borrow { 1 } else { 0 });
            diff[i] = diff_with_borrow.0;
            borrow = diff_without_borrow.1 | diff_with_borrow.1;
            i += 1;
        }

        let mask = (borrow as u64).wrapping_neg();
        let mut borrow_fix = false;
        i = 0;
        while i < L {
            let correction = (mask & self.modulus.0[i]) + if borrow_fix { 1 } else { 0 };
            let (corrected_limb, new_borrow) = diff[i].overflowing_add(correction);
            result[i] = corrected_limb;
            borrow_fix = new_borrow;
            i += 1;
        }
        Words(result)
    }
    const fn bernstein_yang_invert(&self, a: &Words<L>) -> CtOption<Words<L>> {
        let adjuster = self.r_squared;
        let inverse = inv_mod2_62(self.modulus.0);

        let (d, f) = self.divsteps(
            adjuster,
            self.modulus,
            *a,
            inverse
        );

        let antiunit = f.eq(&Words([u64::MAX >> (64 - 62); L]));
        let ret = self.norm(d, antiunit);
        let is_some = f.eq(&Words([1u64; L])) | antiunit;
        CtOption::new(ret, Choice::from(is_some as u8))
    }
    /// Returns the Bernstein-Yang transition matrix multiplied by 2^62 and the new value of the
    /// delta variable for the 62 basic steps of the Bernstein-Yang method, which are to be
    /// performed sequentially for specified initial values of f, g and delta
    const fn jump(f: &[u64], g: &[u64], mut delta: i64) -> (i64, Matrix) {
        // This function is defined because the method "min" of the i64 type is not constant
        const fn min(a: i64, b: i64) -> i64 {
            if a > b {
                b
            } else {
                a
            }
        }

        let (mut steps, mut f, mut g) = (62, f[0] as i64, g[0] as i128);
        let mut t: Matrix = [[1, 0], [0, 1]];

        loop {
            let zeros = min(steps, g.trailing_zeros() as i64);
            (steps, delta, g) = (steps - zeros, delta + zeros, g >> zeros);
            t[0] = [t[0][0] << zeros, t[0][1] << zeros];

            if steps == 0 {
                break;
            }
            if delta > 0 {
                (delta, f, g) = (-delta, g as i64, -f as i128);
                (t[0], t[1]) = (t[1], [-t[0][0], -t[0][1]]);
            }

            // The formula (3 * x) xor 28 = -1 / x (mod 32) for an odd integer x in the two's
            // complement code has been derived from the formula (3 * x) xor 2 = 1 / x (mod 32)
            // attributed to Peter Montgomery.
            let mask = (1 << min(min(steps, 1 - delta), 5)) - 1;
            let w = (g as i64).wrapping_mul(f.wrapping_mul(3) ^ 28) & mask;

            t[1] = [t[0][0] * w + t[1][0], t[0][1] * w + t[1][1]];
            g += w as i128 * f as i128;
        }

        (delta, t)
    }
    /// Algorithm `divsteps2` to compute (δₙ, fₙ, gₙ) = divstepⁿ(δ, f, g) as described in Figure 10.1
    /// of <https://eprint.iacr.org/2019/266.pdf>.
    ///
    /// This version runs in a fixed number of iterations relative to the highest bit of `f` or `g`
    /// as described in Figure 11.1.
    fn divsteps(
        self,
        mut e: Words<L>,
        f_0: Words<L>,
        mut g: Words<L>,
        inverse: i64,
    ) -> (Words<L>, Words<L>) {
        let mut d = Self::zero_array();
        let mut f = f_0;
        let mut delta = 1;
        let mut matrix;
        let mut i = 0;
        let m = Self::iterations(&f_0, &g);

        while i < m {
            (delta, matrix) = Self::jump(&f.0, &g.0, delta);
            (f, g) = self.fg(&f, &g, matrix);
            (d, e) = self.de(&f_0, inverse, matrix, &d, &e);
            i += 1;
        }

        debug_assert!(g.eq(&Self::zero_array()));
        (d, f)
    }
    /// Returns the updated values of the variables f and g for specified initial ones and
    /// Bernstein-Yang transition matrix multiplied by 2^62.
    ///
    /// The returned vector is "matrix * (f, g)' / 2^62", where "'" is the transpose operator.
    pub fn fg(&self, f: &Words<L>, g: &Words<L>, t: Matrix) -> (Words<L>, Words<L>) {
        let f_t00 = self.mul_scalar(f, t[0][0]);
        let g_t01 = self.mul_scalar(g, t[0][1]);
        let f_t10 = self.mul_scalar(f, t[1][0]);
        let g_t11 = self.mul_scalar(g, t[1][1]);

        let new_f = self.add_internal(&f_t00, &g_t01);
        let new_g = self.add_internal(&f_t10, &g_t11);

        (self.shr(&new_f), self.shr(&new_g))
    }
    /// Returns the updated values of the variables d and e for specified initial ones and
    /// Bernstein-Yang transition matrix multiplied by 2^62.
    ///
    /// The returned vector is congruent modulo M to "matrix * (d, e)' / 2^62 (mod M)", where M is the
    /// modulus the inverter was created for and "'" stands for the transpose operator.
    ///
    /// Both the input and output values lie in the interval (-2 * M, M).
    pub fn de(&self, modulus: &Words<L>, inverse: i64, t: Matrix, d: &Words<L>, e: &Words<L>)
              ->
              (Words<L>,
               Words<L>) {
        let mask = (1u64 << 63) - 1;
        let mut md = t[0][0] * self.is_negative(d) as i64 + t[0][1] * self.is_negative(e) as i64;
        let mut me = t[1][0] * self.is_negative(d) as i64 + t[1][1] * self.is_negative(e) as i64;

        let cd = (t[0][0].wrapping_mul(d.0[0] as i64).wrapping_add(t[0][1].wrapping_mul(e.0[0] as
            i64))) & mask as i64;
        let ce = (t[1][0].wrapping_mul(d.0[0] as i64).wrapping_add(t[1][1].wrapping_mul(e.0[0] as
            i64))) & mask as i64;

        md -= (inverse.wrapping_mul(cd).wrapping_add(md)) & mask as i64;
        me -= (inverse.wrapping_mul(ce).wrapping_add(me)) & mask as i64;

        let d_t00 = self.mul_scalar(d, t[0][0]);
        let e_t01 = self.mul_scalar(e, t[0][1]);
        let d_t10 = self.mul_scalar(d, t[1][0]);
        let e_t11 = self.mul_scalar(e, t[1][1]);

        let modulus_md = self.mul_scalar(modulus, md);
        let modulus_me = self.mul_scalar(modulus, me);

        let cd = self.add_internal(&self.add_internal(&d_t00, &e_t01), &modulus_md);
        let ce = self.add_internal(&self.add_internal(&d_t10, &e_t11), &modulus_me);

        (self.shr(&cd), self.shr(&ce))
    }
    fn iterations(f: &Words<L>, g: &Words<L>) -> usize {
        let d = Words::<L>::max_nbits(f, g);
        let append = ConditionallySelectable::conditional_select(&80, &57, Choice::from((d < 46) as
            u8));
        ((49*d + append)/17) as usize
    }
    const fn shr(&self, a: &Words<L>) -> Words<L> {
        let mut result = Self::zero_array();
        let mut carry = 0;
        let mut i = 0;
        while i < L {
            result.0[L-i] = (carry << 63) | (a.0[L-i] >> 1);
            carry = a.0[L-i] & 1;
            i += 1;
        }
        result
    }

    const fn is_negative(&self, a: &Words<L>) -> bool {
        (a.0[L-1] as i64) < 0
    }
    fn mul_scalar(&self, a: &Words<L>, b: i64) -> Words<L> {
        let mut value = Self::zero_array();
        let b_abs = b.unsigned_abs();
        let mut i = 0;
        while i < L {
            value.0[i] = a.0[i].wrapping_mul(b_abs);
            i += 1;
        }
        let retval = Self {
            modulus: self.modulus,
            value,
            r_squared: self.r_squared,
            n_prime: self.n_prime,
        };
        if b < 0 {
            retval.value
        } else {
            (-retval).value
        }
    }
}
impl<const L: usize, const D: usize> ConditionallySelectable for FinitePrimeField<L, D>{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            modulus: Words::conditional_select(&a.modulus, &b.modulus, choice),
            value: Words::conditional_select(&a.value, &b.value, choice),
            r_squared: Words::conditional_select(&a.r_squared, &b.r_squared, choice),
            n_prime: u64::conditional_select(&a.n_prime, &b.n_prime, choice),
        }
    }
}
impl<const L: usize, const D: usize> Add for FinitePrimeField<L, D> {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let result = self.add_internal(&self.value, &other.value);
        Self {
            modulus: self.modulus,
            value: result,
            r_squared: self.r_squared,
            n_prime: self.n_prime,
        }
    }
}

impl<const L: usize, const D: usize> Neg for FinitePrimeField<L, D> {
    type Output = Self;

    fn neg(self) -> Self {
        let zero = Self::new(
            self.modulus.0,
            Self::zero_array().0,
            self.r_squared.0,
            self.n_prime,
        );
        let z = self == zero;
        let negated = self.sub_internal(&self.modulus, &self.value);
        if z {
            zero
        } else {
            Self::new(self.modulus.0, negated.0, self.r_squared.0, self.n_prime)
        }
    }
}

impl<const L: usize, const D: usize> Sub for FinitePrimeField<L, D> {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        let result = self.sub_internal(&self.value, &other.value);
        Self {
            modulus: self.modulus,
            value: result,
            r_squared: self.r_squared,
            n_prime: self.n_prime,
        }
    }
}

impl<const L: usize, const D: usize> PartialEq for FinitePrimeField<L, D> {
    fn eq(&self, other: &Self) -> bool {
        self.modulus.0 == other.modulus.0 && self.value.0 == other.value.0
    }
}

impl<const L: usize, const D: usize> Mul for FinitePrimeField<L, D> {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        let result = self.montgomery_multiply(&self.value, &other.value);
        Self {
            modulus: self.modulus,
            value: result,
            r_squared: self.r_squared,
            n_prime: self.n_prime,
        }
    }
}

impl<const L: usize, const D: usize> Inv for FinitePrimeField<L, D> {
    type Output = Self;

    fn inv(self) -> Self {
        let inverted = self.from_montgomery(&self.value);
        let inverted = self.bernstein_yang_invert(&Words(inverted));
        let result = self.to_montgomery(&inverted);
        Self {
            modulus: self.modulus,
            value: result,
            r_squared: self.r_squared,
            n_prime: self.n_prime,
        }
    }
}

impl<const L: usize, const D: usize> Div for FinitePrimeField<L, D> {
    type Output = Self;

    fn div(self, other: Self) -> Self {
        self * other.inv()
    }
}
fn main() {
    println!("Hello, world!");
}
#[cfg(test)]
mod bls12_381_tests {
    use super::*;

    const MODULUS: [u64; 6] = [
        0xb9fe_ffff_ffff_aaab,
        0x1eab_fffe_b153_ffff,
        0x6730_d2a0_f6b0_f624,
        0x6477_4b84_f385_12bf,
        0x4b1b_a7b6_434b_acd7,
        0x1a01_11ea_397f_e69a,
    ];

    const R_SQUARED: [u64; 6] = [
        0xf4df_1f34_1c34_1746,
        0x0a76_e6a6_09d1_04f1,
        0x8de5_476c_4c95_b6d5,
        0x67eb_88a9_939d_83c0,
        0x9a79_3e85_b519_952d,
        0x1198_8fe5_92ca_e3aa,
    ];

    const N_PRIME: u64 = 0x89f3_fffc_fffc_fffd;

    const fn create_field(value: [u64; 6]) -> FinitePrimeField<6, 12> {
        FinitePrimeField::new(MODULUS, value, R_SQUARED, N_PRIME)
    }
    const MODULUS_FIELD_ELEM: FinitePrimeField<6, 12> = create_field(MODULUS);

    mod addition_tests {
        use super::*;
        #[test]
        fn test_addition_closure() {
            let a = create_field([1, 2, 3, 4, 5, 6]);
            let b = create_field([5, 6, 7, 8, 9, 10]);
            let _ = a + b;
        }
        #[test]
        fn test_addition_associativity() {
            let a = create_field([1, 2, 3, 4, 5, 6]);
            let b = create_field([7, 8, 9, 10, 11, 12]);
            let c = create_field([13, 14, 15, 16, 17, 18]);
            assert_eq!((a + b) + c, a + (b + c), "Addition is not associative");
        }
        #[test]
        fn test_addition_commutativity() {
            let a = create_field([1, 2, 3, 4, 5, 6]);
            let b = create_field([7, 8, 9, 10, 11, 12]);
            assert_eq!(a + b, b + a, "Addition is not commutative");
        }
        #[test]
        fn test_addition_cases() {
            // Simple addition
            let a = create_field([1, 0, 0, 0, 0, 0]);
            let b = create_field([2, 0, 0, 0, 0, 0]);
            assert_eq!(
                a.from_montgomery(&(a + b).value),
                [3, 0, 0, 0, 0, 0],
                "Simple addition \
             failed"
            );

            // Addition with carry
            let c = create_field([0xFFFFFFFFFFFFFFFF, 0, 0, 0, 0, 0]);
            let d = create_field([1, 0, 0, 0, 0, 0]);
            assert_eq!(
                a.from_montgomery(&(c + d).value),
                [0, 1, 0, 0, 0, 0],
                "Addition with carry failed"
            );

            // Addition that wraps around the modulus
            let e = MODULUS_FIELD_ELEM;
            let f = create_field([1, 0, 0, 0, 0, 0]);
            assert_eq!(
                a.from_montgomery(&(e + f).value),
                [1, 0, 0, 0, 0, 0],
                "Modular wrap-around failed"
            );
            //
            // Addition that just reaches the modulus
            let g = MODULUS_FIELD_ELEM - create_field([1, 0, 0, 0, 0, 0]);
            let h = create_field([1, 0, 0, 0, 0, 0]);
            assert_eq!(
                a.from_montgomery(&(g + h).value),
                [0, 0, 0, 0, 0, 0],
                "Addition to modulus \
            failed"
            );
        }
    }
    mod subtraction_tests {
        use super::*;

        #[test]
        fn test_subtraction_closure() {
            let a = create_field([1, 2, 3, 4, 5, 6]);
            let b = create_field([7, 8, 9, 10, 11, 12]);
            let _ = a - b;
        }

        #[test]
        fn test_subtraction_cases() {
            // Simple subtraction
            let a = create_field([3, 0, 0, 0, 0, 0]);
            let b = create_field([1, 0, 0, 0, 0, 0]);
            assert_eq!(
                a.from_montgomery(&(a - b).value),
                [2, 0, 0, 0, 0, 0],
                "Simple \
                subtraction failed"
            );

            // Subtraction with borrow
            let c = create_field([0, 1, 0, 0, 0, 0]);
            let d = create_field([1, 0, 0, 0, 0, 0]);
            assert_eq!(
                a.from_montgomery(&(c - d).value),
                [0xFFFFFFFFFFFFFFFF, 0, 0, 0, 0, 0],
                "Subtraction with borrow failed"
            );

            // Subtraction that borrows from the modulus
            let mod_m_1 = MODULUS_FIELD_ELEM - create_field([1, 0, 0, 0, 0, 0]);
            let e = create_field([0, 0, 0, 0, 0, 0]);
            let f = create_field([1, 0, 0, 0, 0, 0]);
            assert_eq!(
                e.from_montgomery(&(e - f).value),
                mod_m_1.from_montgomery(&mod_m_1.value),
                "Modular borrow failed"
            );

            // Subtraction resulting in zero
            let g = MODULUS_FIELD_ELEM;
            assert_eq!(
                g.from_montgomery(&(g - g).value),
                [0, 0, 0, 0, 0, 0],
                "Subtraction to \
                zero failed"
            );
        }

        #[test]
        fn test_subtraction_edge_cases() {
            let a = create_field([1, 2, 3, 4, 5, 6]);
            let zero = create_field([0, 0, 0, 0, 0, 0]);
            assert_eq!(a - zero, a, "Subtracting zero failed");

            let one = create_field([1, 0, 0, 0, 0, 0]);
            let mod_m_1 = MODULUS_FIELD_ELEM - create_field([1, 0, 0, 0, 0, 0]);

            assert_eq!(
                one.from_montgomery(&(zero - one).value),
                mod_m_1.from_montgomery(&mod_m_1.value),
                "Subtracting from zero failed"
            );
        }
    }
    mod multiplication_tests {
        use super::*;

        #[test]
        fn test_multiplication_closure() {
            let a = create_field([1, 2, 3, 4, 5, 6]);
            let b = create_field([7, 8, 9, 10, 11, 12]);
            let _ = a * b;
        }

        #[test]
        fn test_multiplication_associativity() {
            let a = create_field([0x1111111111111111, 0, 0, 0, 0, 0]);
            let b = create_field([0x2222222222222222, 0, 0, 0, 0, 0]);
            let c = create_field([0x3333333333333333, 0, 0, 0, 0, 0]);
            assert_eq!(
                (a * b) * c,
                a * (b * c),
                "Multiplication is not associative"
            );
        }

        #[test]
        fn test_multiplication_commutativity() {
            let a = create_field([0x1234567890ABCDEF, 0xFEDCBA9876543210, 0, 0, 0, 0]);
            let b = create_field([0x9876543210FEDCBA, 0x1234567890ABCDEF, 0, 0, 0, 0]);
            assert_eq!(a * b, b * a, "Multiplication is not commutative");
        }

        #[test]
        fn test_multiplication_distributivity() {
            let a = create_field([0x1111111111111111, 0, 0, 0, 0, 0]);
            let b = create_field([0x2222222222222222, 0, 0, 0, 0, 0]);
            let c = create_field([0x3333333333333333, 0, 0, 0, 0, 0]);
            assert_eq!(
                a * (b + c),
                (a * b) + (a * c),
                "Multiplication is not distributive over addition"
            );
        }

        #[test]
        fn test_multiplication_cases() {
            // Simple multiplication
            let a = create_field([2, 0, 0, 0, 0, 0]);
            let b = create_field([3, 0, 0, 0, 0, 0]);
            assert_eq!(
                a.from_montgomery(&(a * b).value),
                [6, 0, 0, 0, 0, 0],
                "Simple \
            multiplication failed"
            );

            // Multiplication with carry
            let c = create_field([0xFFFFFFFFFFFFFFFF, 0, 0, 0, 0, 0]);
            let d = create_field([2, 0, 0, 0, 0, 0]);
            assert_eq!(
                c.from_montgomery(&(c * d).value),
                [0xFFFFFFFFFFFFFFFE, 1, 0, 0, 0, 0],
                "Multiplication with carry failed"
            );
        }

        #[test]
        fn test_multiplication_edge_cases() {
            let a = create_field([0x1234567890ABCDEF, 0xFEDCBA9876543210, 0, 0, 0, 0]);
            let zero = create_field([0, 0, 0, 0, 0, 0]);
            let one = create_field([1, 0, 0, 0, 0, 0]);

            assert_eq!(a * zero, zero, "Multiplication by zero failed");
            assert_eq!(a * one, a, "Multiplication by one failed");
        }
    }
    mod composite_property_tests {
        use super::*;

        #[test]
        fn test_distributivity() {
            let a = create_field([1, 2, 3, 4, 5, 6]);
            let b = create_field([7, 8, 9, 10, 11, 12]);
            let c = create_field([13, 14, 15, 16, 17, 18]);
            assert_eq!(a * (b + c), (a * b) + (a * c), "Left distributivity failed");
            assert_eq!(
                (a + b) * c,
                (a * c) + (b * c),
                "Right distributivity failed"
            );
        }

        #[test]
        fn test_additive_cancellation() {
            let a = create_field([1, 2, 3, 4, 5, 6]);
            let b = create_field([7, 8, 9, 10, 11, 12]);
            let c = create_field([13, 14, 15, 16, 17, 18]);
            assert_eq!(a + c == b + c, a == b, "Additive cancellation failed");
        }

        #[test]
        fn test_multiplicative_cancellation() {
            let a = create_field([1, 2, 3, 4, 5, 6]);
            let b = create_field([7, 8, 9, 10, 11, 12]);
            let c = create_field([13, 14, 15, 16, 17, 18]);
            let zero = create_field([0, 0, 0, 0, 0, 0]);
            if c != zero {
                assert_eq!(a * c == b * c, a == b, "Multiplicative cancellation failed");
            }
        }

        #[test]
        fn test_field_properties_with_zero_and_one() {
            let zero = create_field([0, 0, 0, 0, 0, 0]);
            let one = create_field([1, 0, 0, 0, 0, 0]);

            // 1 + 0 = 1
            assert_eq!(one + zero, one, "1 + 0 = 1 failed");

            // 1 * 0 = 0
            assert_eq!(one * zero, zero, "1 * 0 = 0 failed");

            // -0 = 0
            assert_eq!(-zero, zero, "-0 = 0 failed");

            // 1^(-1) = 1
            // assert_eq!(one.inv(), one, "1^(-1) = 1 failed");
        }

        #[test]
        fn test_subtraction_and_addition_relationship() {
            let a = create_field([1, 2, 3, 4, 5, 6]);
            let b = create_field([7, 8, 9, 10, 11, 12]);

            // (a - b) + b = a
            assert_eq!((a - b) + b, a, "Subtraction and addition property failed");
        }

        // #[test]
        // fn test_division_and_multiplication_relationship() {
        //     let a = create_field([1, 2, 3, 4, 5, 6]);
        //     let b = create_field([7, 8, 9, 10, 11, 12]);
        //     let zero = create_field([0, 0, 0, 0, 0, 0]);
        //
        //     // (a / b) * b = a (for non-zero b)
        //     if b != zero {
        //         assert_eq!(
        //             (a / b) * b,
        //             a,
        //             "Division and multiplication property failed"
        //         );
        //     }
        // }

        #[test]
        fn test_non_commutativity_of_subtraction_and_division() {
            let a = create_field([1, 2, 3, 4, 5, 6]);
            let b = create_field([7, 8, 9, 10, 11, 12]);
            let zero = create_field([0, 0, 0, 0, 0, 0]);

            // Non-commutativity of subtraction
            assert_ne!(a - b, b - a, "Subtraction should not be commutative");

            // // Non-commutativity of division
            // if a != zero && b != zero {
            //     assert_ne!(a / b, b / a, "Division should not be commutative");
            // }
        }

        #[test]
        fn test_linearity_of_addition() {
            let a = create_field([2, 0, 0, 0, 0, 0]);
            let b = create_field([3, 0, 0, 0, 0, 0]);
            let k = create_field([5, 0, 0, 0, 0, 0]);

            assert_eq!(k * (a + b), k * a + k * b, "Linearity of addition failed");
        }
    }
}

#[cfg(test)]
mod bn254_tests {
    use super::*;

    const MODULUS: [u64; 4] = [
        0x3C208C16D87CFD47,
        0x97816A916871CA8D,
        0xB85045B68181585D,
        0x30644E72E131A029,
    ];

    const R_SQUARED: [u64; 4] = [
        0xf32cfc5b538afa89,
        0xb5e71911d44501fb,
        0x47ab1eff0a417ff6,
        0x06d89f71cab8351f,
    ];

    const N_PRIME: u64 = 0x87d2_0782_e486_6389;

    const fn create_field(value: [u64; 4]) -> FinitePrimeField<4, 8> {
        FinitePrimeField::new(MODULUS, value, R_SQUARED, N_PRIME)
    }
    mod addition_tests {
        use super::*;

        #[test]
        fn test_addition_closure() {
            let a = create_field([1, 2, 3, 4]);
            let b = create_field([5, 6, 7, 8]);
            let _ = a + b;
        }
        #[test]
        fn test_addition_associativity() {
            let a = create_field([1, 2, 3, 4]);
            let b = create_field([5, 6, 7, 8]);
            let c = create_field([9, 10, 11, 12]);
            assert_eq!((a + b) + c, a + (b + c), "Addition is not associative");
        }
        #[test]
        fn test_addition_commutativity() {
            let a = create_field([1, 2, 3, 4]);
            let b = create_field([5, 6, 7, 8]);
            assert_eq!(a + b, b + a, "Addition is not commutative");
        }

        #[test]
        fn test_addition_cases() {
            // Simple addition
            let a = create_field([1, 0, 0, 0]);
            let b = create_field([2, 0, 0, 0]);
            assert_eq!(
                a.from_montgomery(&(a + b).value),
                [3, 0, 0, 0],
                "Simple addition failed"
            );

            // Addition with carry
            let c = create_field([0xFFFFFFFFFFFFFFFF, 0, 0, 0]);
            let d = create_field([1, 0, 0, 0]);
            assert_eq!(
                c.from_montgomery(&(c + d).value),
                [0, 1, 0, 0],
                "Addition with carry \
            failed"
            );

            // Addition that wraps around the modulus
            let e = create_field(MODULUS);
            let f = create_field([1, 0, 0, 0]);
            assert_eq!(
                e.from_montgomery(&(e + f).value),
                [1, 0, 0, 0],
                "Modular wrap-around \
            failed"
            );

            // Addition that just reaches the modulus
            let g = create_field([
                0x3C208C16D87CFD46,
                0x97816A916871CA8D,
                0xB85045B68181585D,
                0x30644E72E131A029,
            ]);
            let h = create_field([1, 0, 0, 0]);
            assert_eq!(
                g.from_montgomery(&(g + h).value),
                [0, 0, 0, 0],
                "Addition to modulus \
            failed"
            );
        }
        #[test]
        fn test_addition_edge_cases() {
            let a = create_field([1, 2, 3, 4]);
            let zero = create_field([0, 0, 0, 0]);
            assert_eq!(a + zero, a, "Adding zero failed");

            let almost_modulus = create_field([
                0x3C208C16D87CFD46,
                0x97816A916871CA8D,
                0xB85045B68181585D,
                0x30644E72E131A029,
            ]);
            let one = create_field([1, 0, 0, 0]);
            assert_eq!(
                a.from_montgomery(&(almost_modulus + one).value),
                [0, 0, 0, 0],
                "Adding to get exact modulus failed"
            );
        }
    }
    mod subtraction_tests {
        use super::*;

        #[test]
        fn test_subtraction_closure() {
            let a = create_field([1, 2, 3, 4]);
            let b = create_field([5, 6, 7, 8]);
            let _ = a - b;
        }

        #[test]
        fn test_subtraction_cases() {
            // Simple subtraction
            let a = create_field([3, 0, 0, 0]);
            let b = create_field([1, 0, 0, 0]);
            assert_eq!(
                a.from_montgomery(&(a - b).value),
                [2, 0, 0, 0],
                "Simple subtraction \
            failed"
            );

            // Subtraction with borrow
            let c = create_field([0, 1, 0, 0]);
            let d = create_field([1, 0, 0, 0]);
            assert_eq!(
                c.from_montgomery(&(c - d).value),
                [0xFFFFFFFFFFFFFFFF, 0, 0, 0],
                "Subtraction with borrow failed"
            );

            // Subtraction that borrows from the modulus
            let e = create_field([0, 0, 0, 0]);
            let f = create_field([1, 0, 0, 0]);
            assert_eq!(
                e.from_montgomery(&(e - f).value),
                [
                    0x3C208C16D87CFD46,
                    0x97816A916871CA8D,
                    0xB85045B68181585D,
                    0x30644E72E131A029,
                ],
                "Modular borrow failed"
            );

            // Subtraction resulting in zero
            let g = create_field(MODULUS);
            assert_eq!(
                g.from_montgomery(&(g - g).value),
                [0, 0, 0, 0],
                "Subtraction to zero \
            failed"
            );
        }

        #[test]
        fn test_subtraction_edge_cases() {
            let a = create_field([1, 2, 3, 4]);
            let zero = create_field([0, 0, 0, 0]);
            assert_eq!(a - zero, a, "Subtracting zero failed");

            let one = create_field([1, 0, 0, 0]);
            assert_eq!(
                one.from_montgomery(&(zero - one).value),
                [
                    0x3C208C16D87CFD46,
                    0x97816A916871CA8D,
                    0xB85045B68181585D,
                    0x30644E72E131A029,
                ],
                "Subtracting from zero failed"
            );
        }
    }

    mod multiplication_tests {
        use super::*;

        #[test]
        fn test_multiplication_closure() {
            let a = create_field([1, 2, 3, 4]);
            let b = create_field([5, 6, 7, 8]);
            let _ = a * b;
        }

        #[test]
        fn test_multiplication_associativity() {
            let a = create_field([0x1111111111111111, 0, 0, 0]);
            let b = create_field([0x2222222222222222, 0, 0, 0]);
            let c = create_field([0x3333333333333333, 0, 0, 0]);
            assert_eq!(
                (a * b) * c,
                a * (b * c),
                "Multiplication is not associative"
            );
        }

        #[test]
        fn test_multiplication_commutativity() {
            let a = create_field([0x1234567890ABCDEF, 0xFEDCBA9876543210, 0, 0]);
            let b = create_field([0x9876543210FEDCBA, 0x1234567890ABCDEF, 0, 0]);
            assert_eq!(a * b, b * a, "Multiplication is not commutative");
        }

        #[test]
        fn test_multiplication_distributivity() {
            let a = create_field([0x1111111111111111, 0, 0, 0]);
            let b = create_field([0x2222222222222222, 0, 0, 0]);
            let c = create_field([0x3333333333333333, 0, 0, 0]);
            assert_eq!(
                a * (b + c),
                (a * b) + (a * c),
                "Multiplication is not distributive over addition"
            );
        }

        #[test]
        fn test_multiplication_cases() {
            // Simple multiplication
            let a = create_field([2, 0, 0, 0]);
            let b = create_field([3, 0, 0, 0]);
            assert_eq!(
                a.from_montgomery(&(a * b).value),
                [6, 0, 0, 0],
                "Simple multiplication \
            failed"
            );

            // Multiplication with carry
            let c = create_field([0xFFFFFFFFFFFFFFFF, 0, 0, 0]);
            let d = create_field([2, 0, 0, 0]);
            assert_eq!(
                c.from_montgomery(&(c * d).value),
                [0xFFFFFFFFFFFFFFFE, 1, 0, 0],
                "Multiplication with carry failed"
            );

            // Multiplication that wraps around the modulus
            let e = create_field([
                0x1E104C0B6C3E7EA3,
                0x4BC0B5488C38E546,
                0x5C28222B40C0AC2E,
                0x18322739709D8814,
            ]);
            let f = create_field([2, 0, 0, 0]);
            assert_eq!(
                e.from_montgomery(&(e * f).value),
                [
                    0x00000BFFFFFFFFFF,
                    0xFFFFFFFFAFFFFFFF,
                    0xFFFFFE9FFFFFFFFE,
                    0x0000000000096FFE
                ],
                "Multiplication wrapping around modulus failed"
            );
        }

        #[test]
        fn test_multiplication_edge_cases() {
            let a = create_field([0x1234567890ABCDEF, 0xFEDCBA9876543210, 0, 0]);
            let zero = create_field([0, 0, 0, 0]);
            let one = create_field([1, 0, 0, 0]);

            assert_eq!(a * zero, zero, "Multiplication by zero failed");
            assert_eq!(a * one, a, "Multiplication by one failed");

            let large = create_field([
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0x3064497359141831,
            ]);
            assert_eq!(
                large.from_montgomery(&(large * large).value),
                [
                    0xB5E10AE6EEFA883B,
                    0x198D06E9A0ECCA3F,
                    0xA1FD4D5C33BDCE95,
                    0x16A2244FF2849823
                ],
                "Multiplication of large numbers failed"
            );
        }
    }
    mod division_tests {
        use super::*;

        #[test]
        fn test_division_closure() {
            let a = create_field([1, 2, 3, 4]);
            let b = create_field([5, 6, 7, 8]);
            let _ = a / b;
        }

        #[test]
        fn test_division_cases() {
            let a = create_field([1, 2, 3, 4]);
            let b = create_field([5, 6, 7, 8]);
            let one = create_field([1, 0, 0, 0]);

            assert_eq!((a / a), one, "Division by self failed");
            assert_eq!((a / one), a, "Division by one failed");
            assert_eq!(
                ((a / b) * b),
                a,
                "Division and multiplication property failed"
            );
        }

        #[test]
        #[should_panic(expected = "attempt to divide by zero")]
        fn test_division_by_zero() {
            let a = create_field([1, 2, 3, 4]);
            let zero = create_field([0, 0, 0, 0]);
            let _ = a / zero;
        }
    }

}
