use num_traits::Inv;
use std::ops::{Add, Div, Mul, Neg, Sub};

/// A finite field scalar optimized for use in cryptographic operations.
///
/// All operations feature modular arithmetic. Primarily focusing on fields of prime
/// order, non-prime order fields may have undefined behavior at this time.
///
/// Note: We have to keep the double size `D` as a constant due to generic limitations
/// in rust.
#[derive(Clone, Copy, Debug)]
pub struct FiniteField<const L: usize, const D: usize> {
    modulus: [u64; L],
    value: [u64; L],
    correction: [u64; L],
    r_squared: [u64; L],
    n_prime: u64,
}

impl<const L: usize, const D: usize> FiniteField<L, D> {
    const ZERO: [u64; L] = Self::zero_array();
    const ONE: [u64; L] = Self::one_array();

    pub fn new(modulus: [u64; L], value: [u64; L]) -> Self {
        assert_eq!(D, 2 * L, "D must be equal to 2 * L");
        let correction = Self::subtraction_correction(&modulus);
        let r_squared = Self::compute_r_squared(&modulus);
        let n_prime = Self::compute_n_prime(&modulus);
        Self {
            modulus,
            value,
            correction,
            r_squared,
            n_prime,
        }
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
    fn subtraction_correction(modulus: &[u64; L]) -> [u64; L] {
        let mut correction = [0; L];
        let mut carry = 1u64;
        for i in 0..L {
            let (corrected_limb, new_carry) = (!modulus[i]).overflowing_add(carry);
            correction[i] = corrected_limb;
            carry = u64::from(new_carry);
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

    fn compute_r_squared(modulus: &[u64; L]) -> [u64; L] {
        todo!("Implement Montgomery multiplication")
    }

    fn compute_n_prime(modulus: &[u64; L]) -> u64 {
        todo!("Implement Montgomery multiplication")
    }

    pub fn montgomery_reduce(&self, t: &mut [u64; D]) -> [u64; L] {
        todo!("Implement Montgomery multiplication")
    }

    pub fn to_montgomery(&self, a: &[u64; L]) -> [u64; L] {
        todo!("Implement Montgomery multiplication")
    }

    pub fn montgomery_multiply(&self, a: &[u64; L], b: &[u64; L]) -> [u64; L] {
        todo!("Implement Montgomery multiplication")
    }
}

impl<const L: usize, const D: usize> Add for FiniteField<L, D> {
    type Output = Self;

    /// Performs modular addition.
    ///
    /// This method adds two field elements and reduces the result modulo the field's modulus.
    fn add(self, other: Self) -> Self {
        // Initialize sum to zero
        let mut sum = Self::new(self.modulus, Self::zero_array());
        let mut carry = false;

        // Perform addition with carry propagation
        for i in 0..L {
            let sum_with_other = self.value[i].overflowing_add(other.value[i]);
            let sum_with_carry = sum_with_other.0.overflowing_add(if carry { 1 } else { 0 });
            sum.value[i] = sum_with_carry.0;
            carry = sum_with_other.1 | sum_with_carry.1;
        }

        // Perform trial subtraction of modulus
        let mut trial = Self::new(self.modulus, Self::zero_array());
        let mut borrow = false;
        for i in 0..L {
            // Note: a single overflowing_sub is enough because modulus[i]+borrow can never overflow
            let diff_with_borrow =
                sum.value[i].overflowing_sub(self.modulus[i] + if borrow { 1 } else { 0 });
            trial.value[i] = diff_with_borrow.0;
            borrow = diff_with_borrow.1;
        }

        // Select between sum and trial based on borrow flag
        let mut result = Self::new(self.modulus, Self::zero_array());
        let select_mask = u64::from(borrow).wrapping_neg();
        for i in 0..L {
            // If borrow is true (select_mask is all 1s), choose sum, otherwise choose trial
            result.value[i] = (select_mask & sum.value[i]) | (!select_mask & trial.value[i]);
        }
        result
    }
}

impl<const L: usize, const D: usize> Neg for FiniteField<L, D> {
    type Output = Self;

    fn neg(self) -> Self {
        todo!("Implement negation")
    }
}

impl<const L: usize, const D: usize> Sub for FiniteField<L, D> {
    type Output = Self;

    /// Performs modular subtraction.
    ///
    /// This method subtracts one field element from another and ensures the result
    /// is in the correct range by adding the modulus if necessary.
    fn sub(self, other: Self) -> Self {
        // Initialize difference to zero
        let mut difference = Self::new(self.modulus, Self::zero_array());
        let mut borrow = false;

        // Perform subtraction with borrow propagation
        for i in 0..L {
            let diff_without_borrow = self.value[i].overflowing_sub(other.value[i]);
            let diff_with_borrow =
                diff_without_borrow
                    .0
                    .overflowing_sub(if borrow { 1 } else { 0 });
            difference.value[i] = diff_with_borrow.0;
            borrow = diff_without_borrow.1 | diff_with_borrow.1;
        }

        // Always subtract the correction, which effectively adds the modulus if borrow occurred
        let correction_mask = u64::from(borrow).wrapping_neg();
        let mut correction_borrow = false;
        for i in 0..L {
            let correction_term =
                (correction_mask & self.correction[i]) + if correction_borrow { 1 } else { 0 };
            let (corrected_limb, new_borrow) = difference.value[i].overflowing_sub(correction_term);
            difference.value[i] = corrected_limb;
            correction_borrow = new_borrow;
        }

        difference
    }
}

// TODO(Make this constant time)
// We can make constant time choices with the subtle crate
impl<const L: usize, const D: usize> PartialEq for FiniteField<L, D> {
    fn eq(&self, other: &Self) -> bool {
        // First, check if the moduli are the same
        if self.modulus != other.modulus {
            return false;
        }

        // Then, compare the values
        self.value == other.value
    }
}

impl<const L: usize, const D: usize> Mul for FiniteField<L, D> {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        let result = self.montgomery_multiply(&self.value, &other.value);
        Self::new(self.modulus, result)
    }
}

impl<const L: usize, const D: usize> Inv for FiniteField<L, D> {
    type Output = Self;

    fn inv(self) -> Self {
        todo!("Implement multiplicative inverse")
        // This can be implemented with a montgomery inversion
    }
}

impl<const L: usize, const D: usize> Div for FiniteField<L, D> {
    type Output = Self;

    fn div(self, other: Self) -> Self {
        // In modular arithmetic division is equivalent to multiplication
        // by the multiplicative inverse.
        self * other.inv()
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

    fn create_field(value: [u64; 4]) -> FiniteField<4, 8> {
        FiniteField::new(MODULUS, value)
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
