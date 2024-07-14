use num_traits::{Inv, One, Zero};
use std::ops::{Add, Div, Mul, Neg, Sub};

// A finite field over the
struct FiniteField<const L: usize> {
    modulus: [usize; L],
    value: [usize; L],
    correction: [usize; L], // Precomputed correction for efficient subtraction
}

impl<const L: usize> FiniteField<L> {
    fn new(modulus: [usize; L], value: [usize; L]) -> Self {
        let correction = Self::compute_correction(&modulus);
        Self {
            modulus,
            value,
            correction,
        }
    }

    // Compute 2^(BITS_PER_LIMB * L) - modulus, used for efficient modular subtraction
    fn compute_correction(modulus: &[usize; L]) -> [usize; L] {
        let mut correction = [0; L];
        let mut carry = 1; // Start with 1 to compute 2^(BITS_PER_LIMB * L) - modulus
        for i in 0..L {
            let (corrected_limb, new_carry) = (!modulus[i]).overflowing_add(carry);
            correction[i] = corrected_limb;
            carry = new_carry as usize;
        }
        correction
    }
}

/// Addition in a finite field Z_p is modular addition.
impl<const L: usize> Add for FiniteField<L> {
    type Output = Self;

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
        let select_mask = usize::from(borrow).wrapping_neg();
        for i in 0..L {
            // If borrow is true (select_mask is all 1s), choose sum, otherwise choose trial
            result.value[i] = (!select_mask & trial.value[i]) | (select_mask & sum.value[i]);
        }
        result
    }
}

// The additive identity
impl<const L: usize> Zero for FiniteField<L> {
    fn zero() -> Self {
        todo!("Implement zero for FiniteField")
    }

    fn is_zero(&self) -> bool {
        let mut is_zero = 1usize;
        for &limb in &self.value {
            is_zero &= (limb | (!limb).wrapping_add(1)) >> (usize::BITS - 1);
        }
        is_zero != 0
    }
}

// Negation in a finite field is the additive inverse
impl<const L: usize> Neg for FiniteField<L> {
    type Output = Self;

    fn neg(self) -> Self {
        todo!("Implement negation for FiniteField")
    }
}

/// Subtraction in a finite field is addition by the additive inverse
impl<const L: usize> Sub for FiniteField<L> {
    type Output = Self;

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
        let correction_mask = usize::from(borrow).wrapping_neg();
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

/// Multiplication in a finite field Z_p is modular multiplication.
impl<const L: usize> Mul for FiniteField<L> {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        todo!("Implement multiplication for FiniteField")
    }
}

/// The multiplicative identity
impl<const L: usize> One for FiniteField<L> {
    fn one() -> Self {
        todo!("Implement one for FiniteField")
    }
}

/// The multiplicative inverse
impl<const L: usize> Inv for FiniteField<L> {
    type Output = Self;

    fn inv(self) -> Self {
        todo!("Implement inversion for FiniteField")
    }
}

/// Division in a finite field is multiplication by the multiplicative inverse
impl<const L: usize> Div for FiniteField<L> {
    type Output = Self;

    fn div(self, other: Self) -> Self {
        todo!("Implement division for FiniteField")
    }
}
