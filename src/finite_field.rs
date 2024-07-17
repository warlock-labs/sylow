use core::marker::{Send, Sync};
use crypto_bigint::modular::{montgomery_reduction, ConstMontyForm, ConstMontyParams};
use crypto_bigint::{impl_modulus, const_monty_form, Limb, Odd, Word, U256};
use num_traits::Inv;
use std::fmt::Write;
use std::ops::{Add, Deref, Div, Mul, Neg, Sub};

macro_rules! DefineFinitePrimeField {
    ($wrapper_name:ident, $modulus:expr) => {
        impl_modulus!(ModulusStruct, U256, $modulus);
        type Output = crypto_bigint::modular::ConstMontyForm::<ModulusStruct, { ModulusStruct::LIMBS }>;

        #[derive(Clone, Debug)]
        pub struct $wrapper_name(ModulusStruct, Output);
        impl $wrapper_name {
            pub const fn new(value: U256) -> Self {
                Self(ModulusStruct, Output::new(&value))
            }
        }
        impl Add for $wrapper_name {
            type Output = Self;
            fn add(self, other: Self)-> Self {
                Self::new((self.1+other.1).retrieve())
            }
        }
        impl Sub for $wrapper_name {
            type Output = Self;
            fn sub(self, other: Self) -> Self {
                Self::new((self.1-other.1).retrieve())
            }
        }
        impl PartialEq for $wrapper_name {
            fn eq(&self, other: &Self) -> bool {
                self.1.as_montgomery() == other.1.as_montgomery()
            }
        }
        impl Mul for $wrapper_name {
            type Output = Self;
            fn mul(self, other: Self) -> Self {
                Self::new((self.1*other.1).retrieve())
            }
        }
        impl Inv for $wrapper_name {
            type Output = Self;
            fn inv(self) -> Self {
                Self::new((self.1.inv().unwrap()).retrieve())
            }
        }
        impl Div for $wrapper_name {
            type Output = Self;
            fn div(self, other: Self) -> Self {
                self * other.inv()
            }
        }
        impl Neg for $wrapper_name {
            type Output = Self;
            fn neg(self) -> Self {
                Self::new((-self.1).retrieve())
            }
        }
        impl Deref for $wrapper_name {
            type Target = U256;

            fn deref(&self) -> &Self::Target {
                static mut RETRIEVED: Option<U256> = None;
                unsafe {
                    RETRIEVED = Some(self.1.retrieve());
                    RETRIEVED.as_ref().unwrap()
                }
            }
        }
    };
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
    const BN254_MOD_STRING: &str =
    "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";
    DefineFinitePrimeField!(Bn254Field, BN254_MOD_STRING);
    fn create_field(value: [u64;4]) -> Bn254Field {
        Bn254Field::new(U256::from_words(value))
    }
    mod test_modulus_conversion {
        use super::*; 
        #[test]
        fn test_modulus(){
            for i in U256::from_be_hex(BN254_MOD_STRING).as_limbs(){
                println!("{:X}", i.0);
            }
        }

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
            assert_eq!(
                *(a.clone() + b.clone()) + *c,
                *a + *(b + c),
                "Addition is not associative"
            );
        }
        #[test]
        fn test_addition_commutativity() {
            let a = create_field([1, 2, 3, 4]);
            let b = create_field([5, 6, 7, 8]);
            assert_eq!(a.clone() + b.clone(), b + a, "Addition is not commutative");
        }
        #[test]
        fn test_addition_cases() {
            // Simple addition
            let a = create_field([1, 0, 0, 0]);
            let b = create_field([2, 0, 0, 0]);
            assert_eq!(
                *(a + b),
                U256::from_words([3, 0, 0, 0]),
                "Simple addition failed"
            );

            // Addition with carry
            let c = create_field([0xFFFFFFFFFFFFFFFF, 0, 0, 0]);
            let d = create_field([1, 0, 0, 0]);
            assert_eq!(
                *(c + d),
                U256::from_words([0, 1, 0, 0]),
                "Addition with carry failed"
            );

            // Addition that wraps around the modulus
            let e = create_field(MODULUS);
            let f = create_field([1, 0, 0, 0]);
            assert_eq!(
                *(e + f),
                U256::from_words([1, 0, 0, 0]),
                "Modular wrap-around failed"
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
                *(g + h),
                U256::from_words([0, 0, 0, 0]),
                "Addition to modulus failed"
            );
        }

        #[test]
        fn test_addition_edge_cases() {
            let a = create_field([1, 2, 3, 4]);
            let zero = create_field([0, 0, 0, 0]);
            assert_eq!(a.clone() + zero, a, "Adding zero failed");

            let almost_modulus = create_field([
                0x3C208C16D87CFD46,
                0x97816A916871CA8D,
                0xB85045B68181585D,
                0x30644E72E131A029,
            ]);
            let one = create_field([1, 0, 0, 0]);
            assert_eq!(
                *(almost_modulus + one),
                U256::from_words([0, 0, 0, 0]),
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
                *(a - b),
                U256::from_words([2, 0, 0, 0]),
                "Simple subtraction failed"
            );

            // Subtraction with borrow
            let c = create_field([0, 1, 0, 0]);
            let d = create_field([1, 0, 0, 0]);
            assert_eq!(
                *(c - d),
                U256::from_words([0xFFFFFFFFFFFFFFFF, 0, 0, 0]),
                "Subtraction with borrow failed"
            );

            // Subtraction that borrows from the modulus
            let e = create_field([0, 0, 0, 0]);
            let f = create_field([1, 0, 0, 0]);
            assert_eq!(
                *(e - f),
                U256::from_words([
                    0x3C208C16D87CFD46,
                    0x97816A916871CA8D,
                    0xB85045B68181585D,
                    0x30644E72E131A029,
                ]),
                "Modular borrow failed"
            );

            // Subtraction resulting in zero
            let g = create_field(MODULUS);
            assert_eq!(
                *(g.clone() - g),
                U256::from_words([0, 0, 0, 0]),
                "Subtraction to zero failed"
            );
        }

        #[test]
        fn test_subtraction_edge_cases() {
            let a = create_field([1, 2, 3, 4]);
            let zero = create_field([0, 0, 0, 0]);
            assert_eq!(a.clone() - zero.clone(), a, "Subtracting zero failed");

            let one = create_field([1, 0, 0, 0]);
            assert_eq!(
                *(zero - one),
                U256::from_words([
                    0x3C208C16D87CFD46,
                    0x97816A916871CA8D,
                    0xB85045B68181585D,
                    0x30644E72E131A029,
                ]),
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
                (a.clone() * b.clone()) * c.clone(),
                a * (b * c),
                "Multiplication is not associative"
            );
        }

        #[test]
        fn test_multiplication_commutativity() {
            let a = create_field([0x1234567890ABCDEF, 0xFEDCBA9876543210, 0, 0]);
            let b = create_field([0x9876543210FEDCBA, 0x1234567890ABCDEF, 0, 0]);
            assert_eq!(
                a.clone() * b.clone(),
                b * a,
                "Multiplication is not commutative"
            );
        }

        #[test]
        fn test_multiplication_distributivity() {
            let a = create_field([0x1111111111111111, 0, 0, 0]);
            let b = create_field([0x2222222222222222, 0, 0, 0]);
            let c = create_field([0x3333333333333333, 0, 0, 0]);
            assert_eq!(
                a.clone() * (b.clone() + c.clone()),
                (a.clone() * b) + (a * c),
                "Multiplication is not distributive over addition"
            );
        }

        #[test]
        fn test_multiplication_cases() {
            // Simple multiplication
            let a = create_field([2, 0, 0, 0]);
            let b = create_field([3, 0, 0, 0]);
            assert_eq!(
                *(a * b),
                U256::from_words([6, 0, 0, 0]),
                "Simple multiplication failed"
            );

            // Multiplication with carry
            let c = create_field([0xFFFFFFFFFFFFFFFF, 0, 0, 0]);
            let d = create_field([2, 0, 0, 0]);
            assert_eq!(
                *(c * d),
                U256::from_words([0xFFFFFFFFFFFFFFFE, 1, 0, 0]),
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
                *(e * f),
                U256::from_words([
                    0xFFFFFFFFFFFFFFFF,
                    0xFFFFFFFFFFFFFFFF,
                    0xFFFFFFFFFFFFFFFF,
                    0
                ]),
                "Multiplication wrapping around modulus failed"
            );
        }

        #[test]
        fn test_multiplication_edge_cases() {
            let a = create_field([0x1234567890ABCDEF, 0xFEDCBA9876543210, 0, 0]);
            let zero = create_field([0, 0, 0, 0]);
            let one = create_field([1, 0, 0, 0]);

            assert_eq!(
                a.clone() * zero.clone(),
                zero,
                "Multiplication by zero failed"
            );
            assert_eq!(a.clone() * one, a, "Multiplication by one failed");

            let large = create_field([
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0xFFFFFFFFFFFFFFFF,
                0x3064497359141831,
            ]);
            assert_eq!(
                *(large.clone() * large),
                U256::from_words([1, 0, 0, 0]),
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

            assert_eq!(
                *(a.clone() / a.clone()),
                U256::ONE,
                "Division by self failed"
            );
            assert_eq!((a.clone() / one), a, "Division by one failed");
            assert_eq!(
                ((a.clone() / b.clone()) * b),
                a,
                "Division and multiplication property failed"
            );
        }

        #[test]
        #[should_panic(expected = "assertion failed: self.is_some.is_true_vartime()")]
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
            assert_eq!(a.clone() + zero.clone(), a, "Additive identity failed");
            assert_eq!(zero + a.clone(), a, "Additive identity failed");
        }

        #[test]
        fn test_multiplicative_identity() {
            let a = create_field([1, 2, 3, 4]);
            let one = create_field([1, 0, 0, 0]);
            assert_eq!(a.clone() * one.clone(), a, "Multiplicative identity failed");
            assert_eq!(one * a.clone(), a, "Multiplicative identity failed");
        }

        #[test]
        fn test_additive_inverse() {
            let a = create_field([1, 2, 3, 4]);
            let zero = create_field([0, 0, 0, 0]);
            let neg_a = (-a.clone()).clone();
            assert_eq!(a.clone() + neg_a.clone(), zero, "Additive inverse failed");
            assert_eq!(neg_a + a, zero, "Additive inverse failed");
        }

        #[test]
        fn test_multiplicative_inverse() {
            let a = create_field([1, 2, 3, 4]);
            let one = create_field([1, 0, 0, 0]);
            let inv_a = a.clone().inv();
            assert_eq!(
                a.clone() * inv_a.clone(),
                one,
                "Multiplicative inverse failed"
            );
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
            assert_eq!(
                a.clone() * (b.clone() + c.clone()),
                (a.clone() * b.clone()) + (a.clone() * c.clone()),
                "Left distributivity failed"
            );
            assert_eq!(
                (a.clone() + b.clone()) * c.clone(),
                (a * c.clone()) + (b * c),
                "Right distributivity failed"
            );
        }

        #[test]
        fn test_additive_cancellation() {
            let a = create_field([1, 2, 3, 4]);
            let b = create_field([5, 6, 7, 8]);
            let c = create_field([9, 10, 11, 12]);
            assert_eq!(
                a.clone() + c.clone() == b.clone() + c,
                a == b,
                "Additive cancellation failed"
            );
        }

        #[test]
        fn test_multiplicative_cancellation() {
            let a = create_field([1, 2, 3, 4]);
            let b = create_field([5, 6, 7, 8]);
            let c = create_field([9, 10, 11, 12]);
            let zero = create_field([0, 0, 0, 0]);
            if c != zero {
                assert_eq!(
                    a.clone() * c.clone() == b.clone() * c,
                    a == b,
                    "Multiplicative cancellation failed"
                );
            }
        }

        #[test]
        fn test_field_properties_with_zero_and_one() {
            let zero = create_field([0, 0, 0, 0]);
            let one = create_field([1, 0, 0, 0]);

            // 1 + 0 = 1
            assert_eq!(one.clone() + zero.clone(), one, "1 + 0 = 1 failed");

            // 1 * 0 = 0
            assert_eq!(one.clone() * zero.clone(), zero, "1 * 0 = 0 failed");

            // -0 = 0
            assert_eq!(-zero.clone(), zero, "-0 = 0 failed");

            // 1^(-1) = 1
            assert_eq!(one.clone().inv(), one, "1^(-1) = 1 failed");
        }

        #[test]
        fn test_subtraction_and_addition_relationship() {
            let a = create_field([1, 2, 3, 4]);
            let b = create_field([5, 6, 7, 8]);

            // (a - b) + b = a
            assert_eq!(
                (a.clone() - b.clone()) + b,
                a,
                "Subtraction and addition property failed"
            );
        }

        #[test]
        fn test_division_and_multiplication_relationship() {
            let a = create_field([1, 2, 3, 4]);
            let b = create_field([5, 6, 7, 8]);
            let zero = create_field([0, 0, 0, 0]);

            // (a / b) * b = a (for non-zero b)
            if b != zero {
                assert_eq!(
                    (a.clone() / b.clone()) * b,
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
            assert_ne!(
                a.clone() - b.clone(),
                b.clone() - a.clone(),
                "Subtraction should not be commutative"
            );

            // Non-commutativity of division
            if a.clone() != zero && b.clone() != zero {
                assert_ne!(
                    a.clone() / b.clone(),
                    b / a,
                    "Division should not be commutative"
                );
            }
        }

        #[test]
        fn test_linearity_of_addition() {
            let a = create_field([2, 0, 0, 0]);
            let b = create_field([3, 0, 0, 0]);
            let k = create_field([5, 0, 0, 0]);

            assert_eq!(
                k.clone() * (a.clone() + b.clone()),
                k.clone() * a + k * b,
                "Linearity of addition failed"
            );
        }
    }
}