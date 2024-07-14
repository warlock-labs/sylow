use num_traits::{Inv, One, Zero};
use std::ops::{Add, Div, Mul, Neg, Sub};

/// Represents an element of a finite field.
#[derive(Clone, Copy, Debug)]
pub struct FiniteField<const L: usize> {
    /// The modulus of the field
    modulus: [u64; L],
    /// The value of this field element
    value: [u64; L],
    /// Precomputed correction for efficient subtraction
    correction: [u64; L],
    // n_prime: u64,
}

impl<const L: usize> FiniteField<L> {
    // A double width for the limbs is required for Montgomery multiplication
    const DOUBLE_LIMBS: usize = 2 * L;

    /// Creates a new FiniteField element.
    ///
    /// # Arguments
    ///
    /// * `modulus` - The modulus of the field
    /// * `value` - The value of the field element
    ///
    /// # Returns
    ///
    /// A new FiniteField instance
    pub fn new(modulus: [u64; L], value: [u64; L]) -> Self {
        let correction = Self::compute_correction(&modulus);
        Self {
            modulus,
            value,
            correction,
        }
    }

    /// Computes the correction factor for efficient subtraction.
    ///
    /// # Arguments
    ///
    /// * `modulus` - The modulus of the field
    ///
    /// # Returns
    ///
    /// The computed correction factor
    fn compute_correction(modulus: &[u64; L]) -> [u64; L] {
        let mut correction = [0; L];
        let mut carry = 1u64;
        for i in 0..L {
            let (corrected_limb, new_carry) = (!modulus[i]).overflowing_add(carry);
            correction[i] = corrected_limb;
            carry = u64::from(new_carry);
        }
        correction
    }
}

impl<const L: usize> Add for FiniteField<L> {
    type Output = Self;

    /// Performs modular addition.
    fn add(self, other: Self) -> Self {
        // Initialize sum to zero
        let mut sum = Self::new(self.modulus, [0; L]);
        let mut carry = false;

        // Perform addition with carry propagation
        for i in 0..L {
            let sum_with_other = self.value[i].overflowing_add(other.value[i]);
            let sum_with_carry = sum_with_other.0.overflowing_add(if carry { 1 } else { 0 });
            sum.value[i] = sum_with_carry.0;
            carry = sum_with_other.1 | sum_with_carry.1;
        }

        // Perform trial subtraction of modulus
        let mut trial = Self::new(self.modulus, [0; L]);
        let mut borrow = false;
        for i in 0..L {
            // Note: a single overflowing_sub is enough because modulus[i]+borrow can never overflow
            let diff_with_borrow =
                sum.value[i].overflowing_sub(self.modulus[i] + if borrow { 1 } else { 0 });
            trial.value[i] = diff_with_borrow.0;
            borrow = diff_with_borrow.1;
        }

        // Select between sum and trial based on borrow flag
        let mut result = Self::new(self.modulus, [0; L]);
        let select_mask = u64::from(borrow).wrapping_neg();
        for i in 0..L {
            // If borrow is true (select_mask is all 1s), choose sum, otherwise choose trial
            result.value[i] = (select_mask & sum.value[i]) | (!select_mask & trial.value[i]);
        }
        result
    }
}

impl<const L: usize> Sub for FiniteField<L> {
    type Output = Self;

    /// Performs modular subtraction.
    fn sub(self, other: Self) -> Self {
        // Initialize difference to zero
        let mut difference = Self::new(self.modulus, [0; L]);
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

impl<const L: usize> Mul for FiniteField<L> {
    type Output = Self;

    /// Performs modular multiplication using Montgomery multiplication.
    fn mul(self, other: Self) -> Self {
        todo!("Implement multiplication")
    }
}

impl<const L: usize> Neg for FiniteField<L> {
    type Output = Self;

    fn neg(self) -> Self {
        todo!("Implement negation")
    }
}

impl<const L: usize> Inv for FiniteField<L> {
    type Output = Self;

    fn inv(self) -> Self {
        todo!("Implement inversion");
    }
}

/// Implements division for FiniteField elements.
impl<const L: usize> Div for FiniteField<L> {
    type Output = Self;

    /// Performs modular division by multiplying with the inverse.
    fn div(self, other: Self) -> Self {
        todo!("Implement division");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODULUS: [u64; 4] = [
        0x3C208C16D87CFD47,
        0x97816A916871CA8D,
        0xB85045B68181585D,
        0x30644E72E131A029,
    ];

    fn create_field(value: [u64; 4]) -> FiniteField<4> {
        FiniteField::new(MODULUS, value)
    }

    #[test]
    fn test_addition() {
        // Test case 1: Simple addition
        let a = create_field([1, 0, 0, 0]);
        let b = create_field([2, 0, 0, 0]);
        let result = a + b;
        assert_eq!(result.value, [3, 0, 0, 0], "Simple addition failed");

        // Test case 2: Addition with carry
        let c = create_field([0xFFFFFFFFFFFFFFFF, 0, 0, 0]);
        let d = create_field([1, 0, 0, 0]);
        let result = c + d;
        assert_eq!(result.value, [0, 1, 0, 0], "Addition with carry failed");

        // Test case 3: Addition that wraps around the modulus
        let e = create_field(MODULUS);
        let f = create_field([1, 0, 0, 0]);
        let result = e + f;
        assert_eq!(result.value, [1, 0, 0, 0], "Modular wrap-around failed");

        // Test case 4: Addition that just reaches the modulus
        let g = create_field([
            0x3C208C16D87CFD46,
            0x97816A916871CA8D,
            0xB85045B68181585D,
            0x30644E72E131A029,
        ]);
        let h = create_field([1, 0, 0, 0]);
        let result = g + h;
        assert_eq!(result.value, [0, 0, 0, 0], "Addition to modulus failed");
    }

    #[test]
    fn test_subtraction() {
        // Test case 1: Simple subtraction
        let a = create_field([3, 0, 0, 0]);
        let b = create_field([1, 0, 0, 0]);
        let result = a - b;
        assert_eq!(result.value, [2, 0, 0, 0], "Simple subtraction failed");

        // Test case 2: Subtraction with borrow
        let c = create_field([0, 1, 0, 0]);
        let d = create_field([1, 0, 0, 0]);
        let result = c - d;
        assert_eq!(
            result.value,
            [0xFFFFFFFFFFFFFFFF, 0, 0, 0],
            "Subtraction with borrow failed"
        );

        // Test case 3: Subtraction that borrows from the modulus
        let e = create_field([0, 0, 0, 0]);
        let f = create_field([1, 0, 0, 0]);
        let result = e - f;
        assert_eq!(
            result.value,
            [
                0x3C208C16D87CFD46,
                0x97816A916871CA8D,
                0xB85045B68181585D,
                0x30644E72E131A029,
            ],
            "Modular borrow failed"
        );

        // Test case 4: Subtraction resulting in zero
        let g = create_field(MODULUS);
        let result = g - g;
        assert_eq!(result.value, [0, 0, 0, 0], "Subtraction to zero failed");
    }

    #[test]
    fn test_edge_cases() {
        // Test case 1: Adding zero
        let a = create_field([1, 2, 3, 4]);
        let zero = create_field([0, 0, 0, 0]);
        let result = a + zero;
        assert_eq!(result.value, [1, 2, 3, 4], "Adding zero failed");

        // Test case 2: Subtracting zero
        let result = a - zero;
        assert_eq!(result.value, [1, 2, 3, 4], "Subtracting zero failed");

        // Test case 3: Adding to get exact modulus
        let almost_modulus = create_field([
            0x3C208C16D87CFD46,
            0x97816A916871CA8D,
            0xB85045B68181585D,
            0x30644E72E131A029,
        ]);
        let one = create_field([1, 0, 0, 0]);
        let result = almost_modulus + one;
        assert_eq!(
            result.value,
            [0, 0, 0, 0],
            "Adding to get exact modulus failed"
        );

        // Test case 4: Subtracting from zero
        let result = zero - one;
        assert_eq!(
            result.value,
            [
                0x3C208C16D87CFD46,
                0x97816A916871CA8D,
                0xB85045B68181585D,
                0x30644E72E131A029,
            ],
            "Subtracting from zero failed"
        );
    }

    #[test]
    fn test_associativity() {
        let a = create_field([1, 2, 3, 4]);
        let b = create_field([5, 6, 7, 8]);
        let c = create_field([9, 10, 11, 12]);

        // Test associativity of addition
        let result1 = (a + b) + c;
        let result2 = a + (b + c);
        assert_eq!(result1.value, result2.value, "Addition is not associative");

        // Note: Subtraction is not associative in general, so we remove that test
    }

    #[test]
    fn test_commutativity() {
        let a = create_field([1, 2, 3, 4]);
        let b = create_field([5, 6, 7, 8]);

        // Test commutativity of addition
        let result1 = a + b;
        let result2 = b + a;
        assert_eq!(result1.value, result2.value, "Addition is not commutative");
    }
}
