#[allow(unused_imports)]
use crypto_bigint::{impl_modulus, modular::ConstMontyParams, NonZero, U256};
#[allow(unused_imports)]
use num_traits::{Euclid, Inv, One, Zero};
#[allow(unused_imports)]
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Rem, Sub, SubAssign};

#[allow(unused_macros)]
macro_rules! DefineFinitePrimeField {
    ($wrapper_name:ident, $uint_type:ty, $modulus:expr) => {
        impl_modulus!(ModulusStruct, $uint_type, $modulus);
        type Output =
            crypto_bigint::modular::ConstMontyForm<ModulusStruct, { ModulusStruct::LIMBS }>;
        #[derive(Clone, Debug, Copy)] //to be used in const contexts
        pub struct $wrapper_name(ModulusStruct, Output);
        #[allow(dead_code)]
        impl $wrapper_name {
            pub const ZERO: Self = Self::new(<$uint_type>::from_u64(0));
            pub const ONE: Self = Self::new(<$uint_type>::from_u64(1));
            pub const NINE: Self = Self::new(<$uint_type>::from_u64(9));
            pub const __MODULUS: &'static NonZero<$uint_type> = ModulusStruct::MODULUS.as_nz_ref();
            pub const fn new(value: $uint_type) -> Self {
                Self(ModulusStruct, Output::new(&value))
            }
            pub const fn value(&self) -> $uint_type {
                self.1.retrieve()
            }
            pub fn quadratic_non_residue() -> Self {
                //this is p - 1 mod p = -1 mod p = 0 - 1 mod p
                // = -1
                Self::new((-Self::ONE).1.retrieve())
            }
            pub fn square(&self) -> Self {
                (*self) * (*self)
            }
            pub fn sqrt(&self) -> Self {
                Self::new(self.value().sqrt())
            }
            pub fn pow(&self, exponent: &$uint_type) -> Self {
                Self::new(self.1.pow(exponent).retrieve())
            }
            pub fn characteristic() -> $uint_type {
                <$uint_type>::from(Self::__MODULUS.get())
            }
            // pub fn sqrt_exponents() ->  [$uint_type; 2] {
            //     let three = <$uint_type>::from_u64(3u64);
            //     let four = <$uint_type>::from_u64(4u64);

            //     let a = (Self::characteristic() - three) / four;
            //     [a,a]
            // }
        }
        impl Add for $wrapper_name {
            type Output = Self;
            fn add(self, other: Self) -> Self {
                Self::new((self.1 + other.1).retrieve())
            }
        }
        impl AddAssign for $wrapper_name {
            fn add_assign(&mut self, other: Self) {
                *self = *self + other;
            }
        }
        impl Zero for $wrapper_name {
            fn zero() -> Self {
                Self::ZERO
            }
            fn is_zero(&self) -> bool {
                self.1.is_zero()
            }
        }
        impl One for $wrapper_name {
            fn one() -> Self {
                Self::ONE
            }
        }
        impl Default for $wrapper_name {
            fn default() -> Self {
                Self::ZERO
            }
        }
        impl Sub for $wrapper_name {
            type Output = Self;
            fn sub(self, other: Self) -> Self {
                Self::new((self.1 - other.1).retrieve())
            }
        }
        impl SubAssign for $wrapper_name {
            fn sub_assign(&mut self, other: Self) {
                *self = *self - other;
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
                Self::new((self.1 * other.1).retrieve())
            }
        }
        impl MulAssign for $wrapper_name {
            fn mul_assign(&mut self, other: Self) {
                *self = *self * other;
            }
        }
        impl Inv for $wrapper_name {
            type Output = Self;
            fn inv(self) -> Self {
                Self::new((self.1.inv().unwrap()).retrieve())
            }
        }
        #[allow(clippy::suspicious_arithmetic_impl)]
        impl Div for $wrapper_name {
            type Output = Self;
            fn div(self, other: Self) -> Self {
                self * other.inv()
            }
        }
        impl DivAssign for $wrapper_name {
            fn div_assign(&mut self, other: Self) {
                *self = *self / other;
            }
        }
        impl Neg for $wrapper_name {
            type Output = Self;
            fn neg(self) -> Self {
                Self::new((-self.1).retrieve())
            }
        }
        impl Rem for $wrapper_name {
            type Output = Self;
            fn rem(self, other: Self) -> Self::Output {
                //create our own check for zeroness?
                Self::new(
                    self.1
                        .retrieve()
                        .rem(NonZero::<$uint_type>::new(other.1.retrieve()).unwrap()),
                )
            }
        }
        impl Euclid for $wrapper_name {
            fn div_euclid(&self, other: &Self) -> Self {
                if other.is_zero() {
                    return Self::ZERO;
                }
                let (mut _q, mut _r) = self
                    .1
                    .retrieve()
                    .div_rem(&NonZero::<$uint_type>::new(other.1.retrieve()).unwrap());

                if self.1.retrieve().bit(255).into() {
                    _q = _q - <$uint_type>::ONE;
                    _r = other.1.retrieve() - _r;
                }
                Self::new(_q)
            }
            fn rem_euclid(&self, other: &Self) -> Self {
                if other.is_zero() {
                    return Self::ZERO;
                }
                let (mut _q, mut _r) = self
                    .1
                    .retrieve()
                    .div_rem(&NonZero::<$uint_type>::new(other.1.retrieve()).unwrap());

                if self.1.retrieve().bit(255).into() {
                    // _q = _q - <$uint_type>::ONE;
                    _r = other.1.retrieve() - _r;
                }
                Self::new(_r)
            }
        }
    };
}
pub(crate) use DefineFinitePrimeField;
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
    DefineFinitePrimeField!(Fp, U256, BN254_MOD_STRING);
    fn create_field(value: [u64; 4]) -> Fp {
        Fp::new(U256::from_words(value))
    }
    mod test_modulus_conversion {
        use super::*;
        #[test]
        fn test_modulus() {
            for i in U256::from_be_hex(BN254_MOD_STRING).as_limbs() {
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
                (a + b).value(),
                U256::from_words([3, 0, 0, 0]),
                "Simple addition failed"
            );

            // Addition with carry
            let c = create_field([0xFFFFFFFFFFFFFFFF, 0, 0, 0]);
            let d = create_field([1, 0, 0, 0]);
            assert_eq!(
                (c + d).value(),
                U256::from_words([0, 1, 0, 0]),
                "Addition with carry failed"
            );

            // Addition that wraps around the modulus
            let e = create_field(MODULUS);
            let f = create_field([1, 0, 0, 0]);
            assert_eq!(
                (e + f).value(),
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
                (g + h).value(),
                U256::from_words([0, 0, 0, 0]),
                "Addition to modulus failed"
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
                (almost_modulus + one).value(),
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
                (a - b).value(),
                U256::from_words([2, 0, 0, 0]),
                "Simple subtraction failed"
            );

            // Subtraction with borrow
            let c = create_field([0, 1, 0, 0]);
            let d = create_field([1, 0, 0, 0]);
            assert_eq!(
                (c - d).value(),
                U256::from_words([0xFFFFFFFFFFFFFFFF, 0, 0, 0]),
                "Subtraction with borrow failed"
            );

            // Subtraction that borrows from the modulus
            let e = create_field([0, 0, 0, 0]);
            let f = create_field([1, 0, 0, 0]);
            assert_eq!(
                (e - f).value(),
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
                (g - g).value(),
                U256::from_words([0, 0, 0, 0]),
                "Subtraction to zero failed"
            );
        }

        #[test]
        fn test_subtraction_edge_cases() {
            let a = create_field([1, 2, 3, 4]);
            let zero = create_field([0, 0, 0, 0]);
            assert_eq!(a - zero, a, "Subtracting zero failed");

            let one = create_field([1, 0, 0, 0]);
            assert_eq!(
                (zero - one).value(),
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
                (a * b).value(),
                U256::from_words([6, 0, 0, 0]),
                "Simple multiplication failed"
            );

            // Multiplication with carry
            let c = create_field([0xFFFFFFFFFFFFFFFF, 0, 0, 0]);
            let d = create_field([2, 0, 0, 0]);
            assert_eq!(
                (c * d).value(),
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
                (e * f).value(),
                U256::from_words([
                    0x00000BFFFFFFFFFF,
                    0xFFFFFFFFAFFFFFFF,
                    0xFFFFFE9FFFFFFFFE,
                    0x0000000000096FFE
                ]),
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
                (large * large).value(),
                U256::from_words([
                    0xB5E10AE6EEFA883B,
                    0x198D06E9A0ECCA3F,
                    0xA1FD4D5C33BDCE95,
                    0x16A2244FF2849823
                ]),
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

            assert_eq!((a / a).value(), U256::ONE, "Division by self failed");
            assert_eq!((a / one), a, "Division by one failed");
            assert_eq!(
                ((a / b) * b),
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
