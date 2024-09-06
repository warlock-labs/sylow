use num_traits::{Inv, Zero};
use std::ops::{Add, Div, Mul, Neg, Sub};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use crate::scalar::inverter::SafeGcdInverter;

#[derive(Clone, Copy, Debug, PartialEq)] // Non constant-time Eq
#[repr(C)]
pub struct Uint<const UNSAT_L: usize>(pub(crate) [u64; UNSAT_L]);

impl<const UNSAT_L: usize> ConditionallySelectable for Uint<UNSAT_L> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut limbs = [0u64; UNSAT_L];
        let mut i = 0;
        while i < UNSAT_L {
            limbs[i] = u64::conditional_select(&a.0[i], &b.0[i], choice);
            i += 1;
        }
        Self(limbs)
    }
}
impl<const UNSAT_L: usize> Uint<UNSAT_L> {
    /// Create a [`Uint`] from an array of [`Word`]s (i.e. word-sized unsigned
    /// integers).
    #[inline]
    pub const fn from_words(arr: [u64; UNSAT_L]) -> Self {
        let mut limbs = [0u64; UNSAT_L];
        let mut i = 0;

        while i < UNSAT_L {
            limbs[i] = arr[i];
            i += 1;
        }

        Self(limbs)
    }

    /// Create an array of [`Word`]s (i.e. word-sized unsigned integers) from
    /// a [`Uint`].
    #[inline]
    pub const fn to_words(self) -> [u64; UNSAT_L] {
        let mut arr = [0; UNSAT_L];
        let mut i = 0;

        while i < UNSAT_L {
            arr[i] = self.0[i];
            i += 1;
        }

        arr
    }

    /// Borrow the inner limbs as an array of [`Word`]s.
    pub const fn as_words(&self) -> &[u64; UNSAT_L] {
        // SAFETY: `Limb` is a `repr(transparent)` newtype for `Word`
        #[allow(unsafe_code)]
        unsafe {
            &*self.0.as_ptr().cast()
        }
    }
}
// / A finite field scalar optimized for use in cryptographic operations.
// /
// / All operations feature modular arithmetic, implemented in constant time.
// / Primarily focusing on fields of prime order, non-prime order fields may
// / have undefined behavior at this time.
#[derive(Clone, Copy, Debug)]
pub struct FinitePrimeField<const UNSAT_L: usize, const SAT_L: usize, const DOUBLE_UNSAT_L: usize> {
    modulus: Uint<UNSAT_L>,
    value: Uint<UNSAT_L>,
    r_squared: Uint<UNSAT_L>,
    n_prime: u64,
    inverter: SafeGcdInverter<UNSAT_L, SAT_L>,
}

impl<const UNSAT_L: usize, const SAT_L: usize, const DOUBLE_UNSAT_L: usize>
    FinitePrimeField<UNSAT_L, SAT_L, DOUBLE_UNSAT_L>
{
    pub const fn new(
        modulus: [u64; UNSAT_L],
        value: [u64; UNSAT_L],
        r_squared: [u64; UNSAT_L],
        n_prime: u64,
    ) -> Self {
        if DOUBLE_UNSAT_L != 2 * UNSAT_L {
            panic!("Double size D must be twice the size of the field L");
        }
        let mut result = Self {
            modulus: Uint(modulus),
            value: Uint([0; UNSAT_L]),
            r_squared: Uint(r_squared),
            n_prime,
            inverter: SafeGcdInverter::<UNSAT_L, SAT_L>::new(&Uint(modulus), &Uint(r_squared)),
        };
        result.value = result.to_montgomery(&Uint(value));
        result
    }
    const fn zero_array() -> Uint<UNSAT_L> {
        Uint([0; UNSAT_L])
    }
    //
    const fn one_array() -> Uint<UNSAT_L> {
        let mut arr = [0; UNSAT_L];
        arr[0] = 1;
        Uint(arr)
    }

    const fn to_montgomery(self, a: &Uint<UNSAT_L>) -> Uint<UNSAT_L> {
        self.montgomery_multiply(a, &self.r_squared)
    }

    const fn from_montgomery(&self, a: &Uint<UNSAT_L>) -> [u64; UNSAT_L] {
        self.montgomery_multiply(a, &Self::one_array()).0
    }

    const fn montgomery_multiply(&self, a: &Uint<UNSAT_L>, b: &Uint<UNSAT_L>) -> Uint<UNSAT_L> {
        let mut temp = [0_u64; DOUBLE_UNSAT_L];
        let mut result = Self::zero_array().0;

        let mut i = 0;
        while i < UNSAT_L {
            let mut carry = 0_u64;
            let mut j = 0;
            while j < UNSAT_L {
                let hilo =
                    (a.0[j] as u128) * (b.0[i] as u128) + (temp[i + j] as u128) + (carry as u128);
                temp[i + j] = hilo as u64;
                carry = (hilo >> 64) as u64;
                j += 1;
            }
            temp[i + UNSAT_L] += carry;

            let m: u64 = temp[i].wrapping_mul(self.n_prime);

            let mut carry = 0_u64;
            j = 0;
            while j < UNSAT_L {
                let hilo = (m as u128) * (self.modulus.0[j] as u128)
                    + (temp[i + j] as u128)
                    + (carry as u128);
                temp[i + j] = hilo as u64;
                carry = (hilo >> 64) as u64;
                j += 1;
            }
            temp[i + UNSAT_L] += carry;
            i += 1;
        }

        let mut dec = [0_u64; UNSAT_L];
        let mut borrow = 0_u64;
        i = 0;
        while i < UNSAT_L {
            let (diff, borrow_t0) = temp[i + UNSAT_L].overflowing_sub(self.modulus.0[i] + borrow);
            dec[i] = diff;
            borrow = borrow_t0 as u64;
            i += 1;
        }

        let select_temp = borrow.wrapping_neg();
        i = 0;
        while i < UNSAT_L {
            result[i] = (select_temp & temp[i + UNSAT_L]) | (!select_temp & dec[i]);
            i += 1;
        }
        Uint(result)
    }

    const fn add_internal(&self, a: &Uint<UNSAT_L>, b: &Uint<UNSAT_L>) -> Uint<UNSAT_L> {
        let mut sum = [0; UNSAT_L];
        let mut carry = false;
        let mut result = Self::zero_array().0;
        let mut i = 0;
        while i < UNSAT_L {
            let sum_with_other = a.0[i].overflowing_add(b.0[i]);
            let sum_with_carry = sum_with_other.0.overflowing_add(if carry { 1 } else { 0 });
            sum[i] = sum_with_carry.0;
            carry = sum_with_other.1 | sum_with_carry.1;
            i += 1;
        }

        let mut trial = [0; UNSAT_L];
        let mut borrow = false;
        i = 0;
        while i < UNSAT_L {
            let diff_with_borrow =
                sum[i].overflowing_sub(self.modulus.0[i] + if borrow { 1 } else { 0 });
            trial[i] = diff_with_borrow.0;
            borrow = diff_with_borrow.1;
            i += 1;
        }

        let select_mask = (borrow as u64).wrapping_neg();
        i = 0;
        while i < UNSAT_L {
            result[i] = (select_mask & sum[i]) | (!select_mask & trial[i]);
            i += 1;
        }
        Uint(result)
    }

    const fn sub_internal(&self, a: &Uint<UNSAT_L>, b: &Uint<UNSAT_L>) -> Uint<UNSAT_L> {
        let mut diff = [0; UNSAT_L];
        let mut borrow = false;
        let mut result = Self::zero_array().0;
        let mut i = 0;
        while i < UNSAT_L {
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
        while i < UNSAT_L {
            let correction = (mask & self.modulus.0[i]) + if borrow_fix { 1 } else { 0 };
            let (corrected_limb, new_borrow) = diff[i].overflowing_add(correction);
            result[i] = corrected_limb;
            borrow_fix = new_borrow;
            i += 1;
        }
        Uint(result)
    }
    fn inverse(&self) -> Self {
        // #[test]
        // fn test_division_closure() {
        //
        //     let g =  create_field(MODULUS) - create_field([12, 12, 12, 12]);
        //
        //     let inverse = FinitePrimeField::<4, 6, 8>{
        //         modulus: g.modulus,
        //         value: INVERTER.inv(&g.value).unwrap(),
        //         r_squared: g.r_squared,
        //         n_prime: g.n_prime,
        //         inverter: g.inverter
        //     };
        //     let result = inverse * g;
        //     assert_eq!(result.from_montgomery(&result.value), [1, 0, 0, 0], "Simple division failed");
        //
        // }
        let maybe_inverse = self.inverter.inv(&self.value).unwrap();
        Self {
            modulus: self.modulus,
            value: maybe_inverse,
            r_squared: self.r_squared,
            n_prime: self.n_prime,
            inverter: self.inverter,
        }

        // unimplemented!("Inverse not implemented")
    }
}
impl<const UNSAT_L: usize, const SAT_L: usize, const DOUBLE_UNSAT_L: usize> ConditionallySelectable
    for FinitePrimeField<UNSAT_L, SAT_L, DOUBLE_UNSAT_L>
{
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            modulus: Uint::conditional_select(&a.modulus, &b.modulus, choice),
            value: Uint::conditional_select(&a.value, &b.value, choice),
            r_squared: Uint::conditional_select(&a.r_squared, &b.r_squared, choice),
            n_prime: u64::conditional_select(&a.n_prime, &b.n_prime, choice),
            //TODO make this conditional as well
            inverter: a.inverter,
        }
    }
}
impl<const UNSAT_L: usize, const SAT_L: usize, const DOUBLE_UNSAT_L: usize> Add
    for FinitePrimeField<UNSAT_L, SAT_L, DOUBLE_UNSAT_L>
{
    type Output = Self;

    fn add(self, other: Self) -> Self {
        let result = self.add_internal(&self.value, &other.value);
        Self {
            modulus: self.modulus,
            value: result,
            r_squared: self.r_squared,
            n_prime: self.n_prime,
            inverter: self.inverter,
        }
    }
}

impl<const UNSAT_L: usize, const SAT_L: usize, const DOUBLE_UNSAT_L: usize> Neg
    for FinitePrimeField<UNSAT_L, SAT_L, DOUBLE_UNSAT_L>
{
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

impl<const UNSAT_L: usize, const SAT_L: usize, const DOUBLE_UNSAT_L: usize> Sub
    for FinitePrimeField<UNSAT_L, SAT_L, DOUBLE_UNSAT_L>
{
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        let result = self.sub_internal(&self.value, &other.value);
        Self {
            modulus: self.modulus,
            value: result,
            r_squared: self.r_squared,
            n_prime: self.n_prime,
            inverter: self.inverter,
        }
    }
}

impl<const UNSAT_L: usize, const SAT_L: usize, const DOUBLE_UNSAT_L: usize> PartialEq
    for FinitePrimeField<UNSAT_L, SAT_L, DOUBLE_UNSAT_L>
{
    fn eq(&self, other: &Self) -> bool {
        self.modulus.0 == other.modulus.0 && self.value.0 == other.value.0
    }
}

impl<const UNSAT_L: usize, const SAT_L: usize, const DOUBLE_UNSAT_L: usize> Mul
    for FinitePrimeField<UNSAT_L, SAT_L, DOUBLE_UNSAT_L>
{
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        let result = self.montgomery_multiply(&self.value, &other.value);
        Self {
            modulus: self.modulus,
            value: result,
            r_squared: self.r_squared,
            n_prime: self.n_prime,
            inverter: self.inverter,
        }
    }
}

impl<const UNSAT_L: usize, const SAT_L: usize, const DOUBLE_UNSAT_L: usize> Inv
    for FinitePrimeField<UNSAT_L, SAT_L, DOUBLE_UNSAT_L>
{
    type Output = Self;

    fn inv(self) -> Self {
        self.inverse()
    }
}
#[allow(clippy::suspicious_arithmetic_impl)]
impl<const UNSAT_L: usize, const SAT_L: usize, const DOUBLE_UNSAT_L: usize> Div
    for FinitePrimeField<UNSAT_L, SAT_L, DOUBLE_UNSAT_L>
{
    type Output = Self;

    fn div(self, other: Self) -> Self {
        self * other.inv()
    }
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

    const fn create_field(value: [u64; 6]) -> FinitePrimeField<6, 8, 12> {
        FinitePrimeField::new(MODULUS, value, R_SQUARED, N_PRIME)
    }
    const MODULUS_FIELD_ELEM: FinitePrimeField<6, 8, 12> = create_field(MODULUS);

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
            assert_eq!(one.inv(), one, "1^(-1) = 1 failed");
        }

        #[test]
        fn test_subtraction_and_addition_relationship() {
            let a = create_field([1, 2, 3, 4, 5, 6]);
            let b = create_field([7, 8, 9, 10, 11, 12]);

            // (a - b) + b = a
            assert_eq!((a - b) + b, a, "Subtraction and addition property failed");
        }

        #[test]
        fn test_division_and_multiplication_relationship() {
            let a = create_field([1, 2, 3, 4, 5, 6]);
            let b = create_field([7, 8, 9, 10, 11, 12]);
            let zero = create_field([0, 0, 0, 0, 0, 0]);

            // (a / b) * b = a (for non-zero b)
            if b != zero {
                assert_eq!(
                    (a / b) * b,
                    a,
                    "Division and multiplication property failed"
                );
            }
        }

        #[test]
        fn test_non_commutativity_of_subtraction_and_division() {
            let a = create_field([1, 2, 3, 4, 5, 6]);
            let b = create_field([7, 8, 9, 10, 11, 12]);
            let zero = create_field([0, 0, 0, 0, 0, 0]);

            // Non-commutativity of subtraction
            assert_ne!(a - b, b - a, "Subtraction should not be commutative");

            // Non-commutativity of division
            if a != zero && b != zero {
                assert_ne!(a / b, b / a, "Division should not be commutative");
            }
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

    const fn create_field(value: [u64; 4]) -> FinitePrimeField<4, 6, 8> {
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
            let g = create_field(MODULUS) - create_field([12, 12, 12, 12]);

            let inverse = g.inv();
            let result = inverse * g;
            assert_eq!(
                result.from_montgomery(&result.value),
                [1, 0, 0, 0],
                "Simple division failed"
            );
        }

        #[test]
        fn test_division_cases() {
            let a = create_field([1, 2, 3, 4]);
            let b = create_field([5, 6, 7, 8]);
            let one = create_field([1, 0, 0, 0]);

            assert_eq!(a / a, one, "Division by self failed");
            assert_eq!(a / one, a, "Division by one failed");
            assert_eq!(
                (a / b) * b,
                a,
                "Division and multiplication property failed"
            );
        }

        // #[test]
        // #[should_panic(expected = "attempt to divide by zero")]
        // fn test_division_by_zero() {
        //     let a = create_field([1, 2, 3, 4]);
        //     let zero = create_field([0, 0, 0, 0]);
        //     let _ = a / zero;
        // }
    }
}
