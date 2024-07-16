use core::fmt;
use num_traits::{Euclid, Inv, One, Zero};
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Rem, Sub, SubAssign};

/// A finite field scalar optimized for use in cryptographic operations.
///
/// All operations feature modular arithmetic, implemented in constant time.
/// Primarily focusing on fields of prime order, non-prime order fields may
/// have undefined behavior at this time.
///
/// `L` is the number of limbs in the field, and `D` is the double size of the field.
///
/// Note: We have to keep the double size `D` as a constant due to generic limitations
/// in rust.
#[derive(Clone, Copy)]
pub struct FinitePrimeField<const L: usize, const D: usize> {
    modulus: [u64; L],
    value: [u64; L],
    correction: [u64; L],
    r_squared: [u64; L],
    n_prime: u64,
}

impl<const L: usize, const D: usize> fmt::Debug for FinitePrimeField<L, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let elements: Vec<String> = self
            .value
            .iter()
            .map(|&x| format!("0x{:016x}", x))
            .collect();
        write!(f, "({})", elements.join(", "))
    }
}

impl<const L: usize, const D: usize> FinitePrimeField<L, D> {
    const ZERO: [u64; L] = Self::zero_array();
    const ONE: [u64; L] = Self::one_array();

    pub const fn new(modulus: [u64; L], value: [u64; L]) -> Self {
        if D != 2 * L {
            panic!("Double size D must be twice the size of the field L");
        }
        // TODO(Cache these for a given modulus for the lifetime of the program)
        // If it can be done in a way which doesn't introduce side-channel attacks
        let mut retval = Self {
            modulus,
            value: [0u64; L],
            correction: [0u64; L],
            r_squared: [0u64; L],
            n_prime: 0u64,
        };
        retval.correction = Self::subtraction_correction(&modulus);
        retval.n_prime = Self::compute_n_prime(&modulus);
        retval.r_squared = retval.compute_r2();
        retval.value = value;
        retval
    }

    /// Computes the correction factor for efficient subtraction.
    ///
    /// This method calculates 2^(64*L) - modulus, which is used to optimize
    /// the subtraction operation in the finite field.
    ///
    /// # Arguments
    ///
    /// * `modulus` - The modulus of the field
    ///
    /// # Returns
    ///
    /// The computed correction factor
    const fn subtraction_correction(modulus: &[u64; L]) -> [u64; L] {
        let mut correction = [0; L];
        let mut carry = 1u64;
        let mut i = 0;
        while i < L {
            let (corrected_limb, new_carry) = (!modulus[i]).overflowing_add(carry);
            correction[i] = corrected_limb;
            carry = if new_carry { 1 } else { 0 };
            i += 1;
        }
        correction
    }

    /// Creates an array representing zero in the field.
    ///
    /// # Returns
    ///
    /// An array of L u64 elements, all set to 0
    const fn zero_array() -> [u64; L] {
        [0; L]
    }

    /// Creates an array representing one in the field.
    ///
    /// # Returns
    ///
    /// An array of L u64 elements, with the least significant limb set to 1 and others to 0
    const fn one_array() -> [u64; L] {
        let mut arr = [0; L];
        arr[0] = 1;
        arr
    }

    pub const fn compute_r(&self) -> [u64; L] {
        let mut r = [0u64; L];
        r[L - 1] = 1u64 << 63;

        if self.greater_than(&r, &self.modulus) {
            self.sub_mod_internal(&r, &self.modulus)
        } else {
            r
        }
    }
    const fn compute_r2(&self) -> [u64; L] {
        let r = self.compute_r();
        let (t, carry) = self._montgomery_multiply(&r, &r);
        self.montgomery_reduce(&t, carry)
    }

    const fn compute_n_prime(modulus: &[u64; L]) -> u64 {
        let mut n_prime = 1u64;
        let mut i = 0;
        while i < 64 {
            n_prime = n_prime.wrapping_mul(modulus[0]);
            n_prime = n_prime.wrapping_mul(2u64.wrapping_sub(modulus[0].wrapping_mul(n_prime)));
            i += 1;
        }
        n_prime.wrapping_neg()
    }

    pub const fn to_montgomery(&self, a: &[u64; L]) -> [u64; L] {
        self.montgomery_multiply(a, &self.r_squared)
    }

    pub const fn from_montgomery(&self, a: &[u64; L]) -> [u64; L] {
        let mut extended = [0u64; D];
        let mut i = 0;
        while i < L {
            extended[i] = a[i];
            i += 1;
        }
        self.montgomery_reduce(&extended, 0)
    }

    /// Performs Montgomery multiplication of two large integers represented as arrays of u64.
    ///
    /// # Arguments
    ///
    /// * `a` - First operand as an array of u64
    /// * `b` - Second operand as an array of u64
    ///
    /// # Returns
    ///
    /// The result of Montgomery multiplication as an array of u64
    ///
    /// Effectively result_mont = (a_mont * b_mont * R^{-1}) mod N
    //  Assumes properly reduced input/output in montgomery form
    pub const fn _montgomery_multiply(&self, a: &[u64; L], b: &[u64; L]) -> ([u64; D], u64) {
        // Compute T = a * b
        let mut t = [0u64; D]; // r + p words
        let mut carry = 0u64; // Extra carry word
        let mut i = 0;
        while i < L {
            let mut local_carry = 0u64;
            let mut j = 0;
            while j < L {
                let product =
                    (a[i] as u128) * (b[j] as u128) + (t[i + j] as u128) + (local_carry as u128);
                t[i + j] = product as u64;
                local_carry = (product >> 64) as u64;
                j += 1;
            }
            let sum = (t[i + L] as u128) + (local_carry as u128) + (carry as u128);
            t[i + L] = sum as u64;
            carry = (sum >> 64) as u64;
            i += 1;
        }
        (t, carry)
    }
    pub const fn montgomery_reduce(&self, temp: &[u64; D], mut carry: u64) -> [u64; L] {
        let mut reduced_t = *temp; // Create a mutable copy of t

        let mut i = 0;
        while i < L {
            // loop1
            let m = ((reduced_t[i] as u128 * self.n_prime as u128) & 0xFFFFFFFFFFFFFFFF) as u64;

            let mut local_carry = 0u64;
            let mut j = 0;
            while j < L {
                // loop2
                let product = (m as u128) * (self.modulus[j] as u128)
                    + (reduced_t[i + j] as u128)
                    + (local_carry as u128);
                reduced_t[i + j] = product as u64;
                local_carry = (product >> 64) as u64;
                j += 1;
            }

            let mut j = L;
            while j < 2 * L - i {
                // loop3
                let sum = (reduced_t[i + j] as u128) + (local_carry as u128);
                reduced_t[i + j] = sum as u64;
                local_carry = (sum >> 64) as u64;
                j += 1;
            }
            let sum = (carry as u128) + (local_carry as u128);
            carry = sum as u64;
            i += 1;
        }

        // Extract result
        let mut s = [0u64; L];
        i = 0;
        while i < L {
            s[i] = reduced_t[i + L];
            i += 1;
        }

        // Final subtraction
        if self.greater_than(&s, &self.modulus) || carry > 0 {
            self.sub_mod_internal(&s, &self.modulus)
        } else {
            s
        }
    }

    pub const fn montgomery_multiply(&self, a: &[u64; L], b: &[u64; L]) -> [u64; L] {
        let a_mont = a; //self.to_montgomery(a);
        let b_mont = b; //self.to_montgomery(b);
        let (tmp, carry) = self._montgomery_multiply(&a_mont, &b_mont);
        self.montgomery_reduce(&tmp, carry)
    }

    pub const fn div_by_two(&self, a: &[u64; L]) -> [u64; L] {
        let mut result = [0u64; L];

        // Check if the number is odd
        let is_odd = a[0] & 1 == 1;

        // If odd, add modulus to make it even
        if is_odd {
            result = self.add_mod_internal(a, &self.modulus);
        } else {
            result = *a;
        }

        // Perform division by 2
        let mut shift = 0u64;
        let mut i = L;
        while i > 0 {
            i -= 1;
            let new_shift = result[i] & 1;
            result[i] = (result[i] >> 1) | (shift << 63);
            shift = new_shift;
        }

        // If the number was odd, the top bit should be set due to the modulus addition
        if is_odd {
            result[L - 1] |= 1u64 << 63;
        }

        result
    }

    pub const fn mul_by_two(&self, a: &[u64; L]) -> [u64; L] {
        let mut double = [0u64; L];
        let mut carry = 0u64;

        // Perform multiplication by 2
        let mut i = 0;
        while i < L {
            let (res, new_carry) = a[i].overflowing_shl(1);
            let (res, overflow) = res.overflowing_add(carry);
            double[i] = res;
            carry = (new_carry as u64) | (overflow as u64);
            i += 1;
        }

        // If there's overflow or result >= modulus, subtract modulus
        if carry > 0 {
            // If there's a carry, we definitely need to subtract the modulus
            self.sub_mod_internal(&double, &self.modulus)
        } else {
            // If no carry, we need to compare with modulus
            let mut result = double;
            let mut should_subtract = true;
            let mut i = L;
            while i > 0 {
                i -= 1;
                if double[i] < self.modulus[i] {
                    should_subtract = false;
                    break;
                }
                if double[i] > self.modulus[i] {
                    break;
                }
            }
            if should_subtract {
                result = self.sub_mod_internal(&double, &self.modulus);
            }
            result
        }
    }

    pub const fn greater_than(&self, a: &[u64; L], b: &[u64; L]) -> bool {
        let mut i = L;
        while i > 0 {
            i -= 1;
            if a[i] >= b[i] {
                return true;
            }
            if a[i] <= b[i] {
                return false;
            }
        }
        false
    }

    pub const fn is_zero(&self, a: &[u64; L]) -> bool {
        let mut retval = true;
        let mut i = 0;
        while i < L {
            retval &= a[i] == 0;
            i += 1;
        }
        retval
    }

    pub const fn add_mod_internal(&self, a: &[u64; L], b: &[u64; L]) -> [u64; L] {
        // Initialize sum to zero
        let mut sum = Self::zero_array();
        let mut carry = 0u64;
        let mut i = 0;

        // Perform addition with carry propagation
        while i < L {
            let sum_with_other = a[i].overflowing_add(b[i]);
            let sum_with_carry = sum_with_other.0.overflowing_add(carry);
            sum[i] = sum_with_carry.0;
            carry = (sum_with_other.1 as u64) | (sum_with_carry.1 as u64);
            i += 1;
        }

        // Perform trial subtraction of modulus
        i = 0;
        let mut trial = Self::zero_array();
        let mut borrow = 0u64;
        while i < L {
            let diff_with_borrow = sum[i].overflowing_sub(self.modulus[i] + borrow);
            trial[i] = diff_with_borrow.0;
            borrow = diff_with_borrow.1 as u64;
            i += 1;
        }

        // Select between sum and trial based on borrow flag
        i = 0;
        let mut result = Self::zero_array();
        let select_mask = borrow.wrapping_neg();
        while i < L {
            // If borrow is 1 (select_mask is all 1s), choose sum, otherwise choose trial
            result[i] = (select_mask & sum[i]) | (!select_mask & trial[i]);
            i += 1;
        }
        result
    }

    pub const fn sub_mod_internal(&self, a: &[u64; L], b: &[u64; L]) -> [u64; L] {
        // Initialize difference to zero
        let mut difference = Self::zero_array();
        let mut borrow = 0u64;
        let mut i = 0;

        // Perform subtraction with borrow propagation
        while i < L {
            let diff_without_borrow = a[i].overflowing_sub(b[i]);
            let diff_with_borrow = diff_without_borrow.0.overflowing_sub(borrow);
            difference[i] = diff_with_borrow.0;
            borrow = (diff_without_borrow.1 as u64) | (diff_with_borrow.1 as u64);
            i += 1;
        }

        // Always subtract the correction, which effectively adds the modulus if borrow occurred
        let correction_mask = borrow.wrapping_neg();
        let mut correction_borrow = 0u64;
        i = 0;
        while i < L {
            let correction_term = (correction_mask & self.correction[i]) + correction_borrow;
            let (corrected_limb, new_borrow) = difference[i].overflowing_sub(correction_term);
            difference[i] = corrected_limb;
            correction_borrow = new_borrow as u64;
            i += 1;
        }
        difference
    }

    pub const fn neg_internal(&self, a: &[u64; L]) -> [u64; L] {
        let zero = Self::zero_array();
        let z = self.is_zero(a);
        let mut negated = Self::zero_array();
        let mut i = 0;
        while i < L {
            negated[i] = self.modulus[i].wrapping_sub(a[i]);
            i += 1;
        }
        if z {
            zero
        } else {
            negated
        }
    }

    pub const fn bernstein_yang_invert(&self, a: &[u64; L]) -> [u64; L] {
        let mut u = *a;
        let mut v = self.modulus;
        let mut r = Self::zero_array();
        let mut s = Self::one_array();

        let mut i = 0;
        while i < 256 * L {
            // Use a fixed upper bound for iterations
            if self.is_zero(&v) {
                break;
            }
            if u[0] & 1 == 0 {
                u = self.div_by_two(&u);
                s = self.mul_by_two(&s);
            } else if v[0] & 1 == 0 {
                v = self.div_by_two(&v);
                r = self.mul_by_two(&r);
            } else if self.greater_than(&u, &v) {
                u = self.div_by_two(&self.sub_mod_internal(&u, &v));
                r = self.add_mod_internal(&r, &s);
                s = self.mul_by_two(&s);
            } else {
                v = self.div_by_two(&self.sub_mod_internal(&v, &u));
                s = self.add_mod_internal(&s, &r);
                r = self.mul_by_two(&r);
            }
            i += 1;
        }

        if self.greater_than(&r, &self.modulus) {
            r = self.sub_mod_internal(&r, &self.modulus);
        }

        self.sub_mod_internal(&self.modulus, &r)
    }
}

impl<const L: usize, const D: usize> Add for FinitePrimeField<L, D> {
    type Output = Self;

    // Performs modular addition.
    ///
    /// This method adds two field elements and reduces the result modulo the field's modulus.
    fn add(self, other: Self) -> Self {
        Self::new(
            self.modulus,
            self.add_mod_internal(&self.value, &other.value),
        )
    }
}

impl<const L: usize, const D: usize> AddAssign for FinitePrimeField<L, D> {
    fn add_assign(&mut self, _rhs: Self) {
        todo!()
    }
}

impl<const L: usize, const D: usize> Zero for FinitePrimeField<L, D> {
    fn zero() -> Self {
        todo!()
    }

    fn is_zero(&self) -> bool {
        todo!()
    }
}

impl<const L: usize, const D: usize> Neg for FinitePrimeField<L, D> {
    type Output = Self;

    fn neg(self) -> Self {
        Self::new(self.modulus, self.neg_internal(&self.value))
    }
}

impl<const L: usize, const D: usize> Sub for FinitePrimeField<L, D> {
    type Output = Self;

    /// Performs modular subtraction.
    ///
    /// This method subtracts one field element from another and ensures the result
    /// is in the correct range by adding the modulus if necessary.
    fn sub(self, other: Self) -> Self {
        Self::new(
            self.modulus,
            self.sub_mod_internal(&self.value, &other.value),
        )
    }
}

impl<const L: usize, const D: usize> SubAssign for FinitePrimeField<L, D> {
    fn sub_assign(&mut self, _rhs: Self) {
        todo!()
    }
}

// TODO(Make this constant time)
// We can make constant time choices with the subtle crate
impl<const L: usize, const D: usize> PartialEq for FinitePrimeField<L, D> {
    fn eq(&self, other: &Self) -> bool {
        // First, check if the moduli are the same
        if self.modulus != other.modulus {
            return false;
        }

        // Then, compare the values
        self.value == other.value
    }
}

impl<const L: usize, const D: usize> Mul for FinitePrimeField<L, D> {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        let result = self.montgomery_multiply(&self.value, &other.value);
        Self::new(self.modulus, result)
    }
}

impl<const L: usize, const D: usize> One for FinitePrimeField<L, D> {
    fn one() -> Self {
        todo!()
    }
}

impl<const L: usize, const D: usize> MulAssign for FinitePrimeField<L, D> {
    fn mul_assign(&mut self, _rhs: Self) {
        todo!()
    }
}

impl<const L: usize, const D: usize> Inv for FinitePrimeField<L, D> {
    type Output = Self;

    fn inv(self) -> Self {
        let inverted = self.bernstein_yang_invert(&self.value);
        Self::new(self.modulus, inverted)
    }
}

impl<const L: usize, const D: usize> Euclid for FinitePrimeField<L, D> {
    fn div_euclid(&self, _v: &Self) -> Self {
        todo!()
    }

    fn rem_euclid(&self, _v: &Self) -> Self {
        todo!()
    }
}

impl<const L: usize, const D: usize> Rem for FinitePrimeField<L, D> {
    type Output = Self;

    fn rem(self, _rhs: Self) -> Self::Output {
        todo!()
    }
}

impl<const L: usize, const D: usize> Div for FinitePrimeField<L, D> {
    type Output = Self;

    fn div(self, other: Self) -> Self {
        // In modular arithmetic division is equivalent to multiplication
        // by the multiplicative inverse.
        self * other.inv()
    }
}

impl<const L: usize, const D: usize> DivAssign<Self> for FinitePrimeField<L, D> {
    fn div_assign(&mut self, _rhs: Self) {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cmp::PartialEq;

    const MODULUS: [u64; 4] = [
        0x3C208C16D87CFD47,
        0x97816A916871CA8D,
        0xB85045B68181585D,
        0x30644E72E131A029,
    ];

    fn create_field(value: [u64; 4]) -> FinitePrimeField<4, 8> {
        FinitePrimeField::new(MODULUS, value)
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
            assert_eq!((a + b).value, [3, 0, 0, 0], "Simple addition failed");

            // Addition with carry
            let c = create_field([0xFFFFFFFFFFFFFFFF, 0, 0, 0]);
            let d = create_field([1, 0, 0, 0]);
            assert_eq!((c + d).value, [0, 1, 0, 0], "Addition with carry failed");

            // Addition that wraps around the modulus
            let e = create_field(MODULUS);
            let f = create_field([1, 0, 0, 0]);
            assert_eq!((e + f).value, [1, 0, 0, 0], "Modular wrap-around failed");

            // Addition that just reaches the modulus
            let g = create_field([
                0x3C208C16D87CFD46,
                0x97816A916871CA8D,
                0xB85045B68181585D,
                0x30644E72E131A029,
            ]);
            let h = create_field([1, 0, 0, 0]);
            assert_eq!((g + h).value, [0, 0, 0, 0], "Addition to modulus failed");
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
                (almost_modulus + one).value,
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
            assert_eq!((a - b).value, [2, 0, 0, 0], "Simple subtraction failed");

            // Subtraction with borrow
            let c = create_field([0, 1, 0, 0]);
            let d = create_field([1, 0, 0, 0]);
            assert_eq!(
                (c - d).value,
                [0xFFFFFFFFFFFFFFFF, 0, 0, 0],
                "Subtraction with borrow failed"
            );

            // Subtraction that borrows from the modulus
            let e = create_field([0, 0, 0, 0]);
            let f = create_field([1, 0, 0, 0]);
            assert_eq!(
                (e - f).value,
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
            assert_eq!((g - g).value, [0, 0, 0, 0], "Subtraction to zero failed");
        }

        #[test]
        fn test_subtraction_edge_cases() {
            let a = create_field([1, 2, 3, 4]);
            let zero = create_field([0, 0, 0, 0]);
            assert_eq!(a - zero, a, "Subtracting zero failed");

            let one = create_field([1, 0, 0, 0]);
            assert_eq!(
                (zero - one).value,
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
        use std::result;

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
        fn test_montgomery() {
            let a = create_field([1, 0, 0, 0]);
            let c = a.to_montgomery(&[1, 0, 0, 0]);
            let d = a.from_montgomery(&c);
            println!("{:?}", c);
            println!("{:?}", d);

            let a0 = create_field([1, 0, 0, 0]);
            print!("{:?}", a0.r_squared);

            let (result, carry) = a0._montgomery_multiply(&[2, 0, 0, 0], &[6, 0, 0, 0]);
            let m = a0.montgomery_reduce(&result, carry);
            let n = a0.to_montgomery(&[12, 0, 0, 0]);
            print!("{:?}", result);
            print!("{:?}", m);
            print!("{:?}", n);
        }
        #[test]
        fn test_multiplication_cases() {
            // Simple multiplication
            let a = create_field([2, 0, 0, 0]);
            let b = create_field([3, 0, 0, 0]);
            assert_eq!((a * b).value, [6, 0, 0, 0], "Simple multiplication failed");

            // Multiplication with carry
            let c = create_field([0xFFFFFFFFFFFFFFFF, 0, 0, 0]);
            let d = create_field([2, 0, 0, 0]);
            assert_eq!(
                (c * d).value,
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
                (e * f).value,
                [
                    0xFFFFFFFFFFFFFFFF,
                    0xFFFFFFFFFFFFFFFF,
                    0xFFFFFFFFFFFFFFFF,
                    0
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
                (large * large).value,
                [1, 0, 0, 0],
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

    mod identity_and_inverse_tests {
        use super::*;

        #[test]
        fn test_additive_identity() {
            let a = create_field([1, 2, 3, 4]);
            let zero = create_field([0, 0, 0, 0]);
            assert_eq!(a + zero, a, "Additive identity failed");
            assert_eq!(zero + a, a, "Additive identity failed");
        }

        #[test]
        fn test_multiplicative_identity() {
            let a = create_field([1, 2, 3, 4]);
            let one = create_field([1, 0, 0, 0]);
            assert_eq!(a * one, a, "Multiplicative identity failed");
            assert_eq!(one * a, a, "Multiplicative identity failed");
        }

        #[test]
        fn test_additive_inverse() {
            let a = create_field([1, 2, 3, 4]);
            let zero = create_field([0, 0, 0, 0]);
            let neg_a = -a;
            assert_eq!(a + neg_a, zero, "Additive inverse failed");
            assert_eq!(neg_a + a, zero, "Additive inverse failed");
        }

        #[test]
        fn test_multiplicative_inverse() {
            let a = create_field([1, 2, 3, 4]);
            let one = create_field([1, 0, 0, 0]);
            let inv_a = a.inv();
            assert_eq!(a * inv_a, one, "Multiplicative inverse failed");
            assert_eq!(inv_a * a, one, "Multiplicative inverse failed");
        }
    }

    mod composite_property_tests {
        use super::*;

        #[test]
        fn test_distributivity() {
            let a = create_field([1, 2, 3, 4]);
            let b = create_field([5, 6, 7, 8]);
            let c = create_field([9, 10, 11, 12]);
            assert_eq!(a * (b + c), (a * b) + (a * c), "Left distributivity failed");
            assert_eq!(
                (a + b) * c,
                (a * c) + (b * c),
                "Right distributivity failed"
            );
        }

        #[test]
        fn test_additive_cancellation() {
            let a = create_field([1, 2, 3, 4]);
            let b = create_field([5, 6, 7, 8]);
            let c = create_field([9, 10, 11, 12]);
            assert_eq!(a + c == b + c, a == b, "Additive cancellation failed");
        }

        #[test]
        fn test_multiplicative_cancellation() {
            let a = create_field([1, 2, 3, 4]);
            let b = create_field([5, 6, 7, 8]);
            let c = create_field([9, 10, 11, 12]);
            let zero = create_field([0, 0, 0, 0]);
            if c != zero {
                assert_eq!(a * c == b * c, a == b, "Multiplicative cancellation failed");
            }
        }

        #[test]
        fn test_field_properties_with_zero_and_one() {
            let zero = create_field([0, 0, 0, 0]);
            let one = create_field([1, 0, 0, 0]);

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
            let a = create_field([1, 2, 3, 4]);
            let b = create_field([5, 6, 7, 8]);

            // (a - b) + b = a
            assert_eq!((a - b) + b, a, "Subtraction and addition property failed");
        }

        #[test]
        fn test_division_and_multiplication_relationship() {
            let a = create_field([1, 2, 3, 4]);
            let b = create_field([5, 6, 7, 8]);
            let zero = create_field([0, 0, 0, 0]);

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
            let a = create_field([1, 2, 3, 4]);
            let b = create_field([5, 6, 7, 8]);
            let zero = create_field([0, 0, 0, 0]);

            // Non-commutativity of subtraction
            assert_ne!(a - b, b - a, "Subtraction should not be commutative");

            // Non-commutativity of division
            if a != zero && b != zero {
                assert_ne!(a / b, b / a, "Division should not be commutative");
            }
        }

        #[test]
        fn test_linearity_of_addition() {
            let a = create_field([2, 0, 0, 0]);
            let b = create_field([3, 0, 0, 0]);
            let k = create_field([5, 0, 0, 0]);

            assert_eq!(k * (a + b), k * a + k * b, "Linearity of addition failed");
        }
    }
}
