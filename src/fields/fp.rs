//! This module implements the basic finite field. The modulus of the finite field
//! is assumed to be prime (and therefore odd). The basic idea is that we use the
//! modulus to generate a struct, instances of which can be added, multiplied, etc.
//! all while conforming to the rules dictated by closed cyclic abelian groups.
//! The generated struct is flexible enough to handle massively large multiprecision
//! moduli and values, and performs all such modular arithmetic internally. The only
//! requirements of the user are to provide the modulus, and the desired bit precision.
//! Due to efficiency considerations, we do not simply "do modular arithmetic" on numbers.
//! There are two levels of performance that we implement.
//!
//! 1. Montgomery arithmetic:
//!     this is a special type of modular arithmetic that
//!     allows for quick execution of binary operations
//!     for a given modulus. This relies on the generation
//!     of additional constants. For more information, see Ref 1.
//! 2. Constant-time operations:
//!     in general, code may be differently executed depending
//!     on the inputs passed to it. unrolling for loops differently
//!     for different inputs allows for side channel attacks. All
//!     this to say that all operations are performed in constant
//!     time with the usage of the `ConstMontyForm` struct of
//!     `crypto_bigint`.
//!                              
//! References
//! ----------
//! 1. <https://cacr.uwaterloo.ca/hac/about/chap14.pdf>
//!
use crypto_bigint::rand_core::CryptoRngCore;
use crypto_bigint::subtle::ConstantTimeEq;
#[allow(unused_imports)]
use crypto_bigint::{
    impl_modulus, modular::ConstMontyParams, ConcatMixed, NonZero, RandomMod, Uint, U256,
};
use num_traits::{Euclid, Inv, One, Pow, Zero};
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Rem, Sub, SubAssign};

/// This defines the key properties of a field extension. Now, mathematically,
/// a finite field satisfies many rigorous mathematical properties. The
/// (non-exhaustive) list below simply suffices to illustrate those properties
/// that are purely relevant to the task at hand here.
pub(crate) trait FieldExtensionTrait<const D: usize, const N: usize>:
    Sized
    + Copy
    + Clone
    + std::fmt::Debug
    + Default
    + Add<Output = Self>
    + AddAssign
    + Sub<Output = Self>
    + SubAssign
    + Mul<Output = Self>
    + MulAssign
    + Div<Output = Self>
    + DivAssign
    + Neg<Output = Self>
    + PartialEq
    + Zero
    + One
    + Inv<Output = Self>
{
    // multiplication in a field extension is dictated
    // heavily by such a value below
    fn quadratic_non_residue() -> Self;
    // this endomorphism is key for twist operations
    #[allow(dead_code)]
    fn frobenius(&self, exponent: usize) -> Self;
    // specialized algorithms exist in each extension
    // for sqrt and square, simply helper functions really
    #[allow(dead_code)]
    fn sqrt(&self) -> Self;
    fn square(&self) -> Self;

    fn rand<R: CryptoRngCore>(rng: &mut R) -> Self;
}
pub(crate) trait FinitePrimeField<const DLIMBS: usize, UintType, const D: usize, const N: usize>:
    FieldExtensionTrait<D, N> + Rem<Output = Self> + Euclid + Pow<U256>
where
    UintType: ConcatMixed<MixedOutput = Uint<DLIMBS>>,
{
    fn new(value: UintType) -> Self;
    fn new_from_u64(value: u64) -> Self;
    #[allow(dead_code)]
    fn value(&self) -> UintType;
    fn characteristic() -> UintType;
}

/// Due to the fact that we use `crypto_bigint` to handle the multiprecision arithmetic
/// we must accept (for now) the fact that it requires the usage of a macro,
/// `impl_modulus!`, which generates and contains all the need information.
/// This means that we roll our implementation into a proc macro that
/// provides all the needed functionality.

#[allow(unused_macros)]
macro_rules! define_finite_prime_field {
    ($wrapper_name:ident, $uint_type:ty, $limbs:expr, $modulus:expr, $degree:expr, $nreps:expr) => {
        impl_modulus!(ModulusStruct, $uint_type, $modulus);

        //special struct for const-time arithmetic on montgomery form integers mod p
        type Output =
            crypto_bigint::modular::ConstMontyForm<ModulusStruct, { ModulusStruct::LIMBS }>;
        #[derive(Clone, Debug, Copy)] //to be used in const contexts
        pub struct $wrapper_name(ModulusStruct, Output);
        #[allow(dead_code)]
        impl FinitePrimeField<$limbs, $uint_type, $degree, $nreps> for $wrapper_name {
            // builder structure to create elements in the base field of a given value
            fn new(value: $uint_type) -> Self {
                Self(ModulusStruct, Output::new(&value))
            }
            fn new_from_u64(value: u64) -> Self {
                Self(ModulusStruct, Output::new(&<$uint_type>::from_u64(value)))
            }
            // take the element and convert it to "normal" form from montgomery form
            fn value(&self) -> $uint_type {
                self.1.retrieve()
            }
            fn characteristic() -> $uint_type {
                <$uint_type>::from(ModulusStruct::MODULUS.as_nz_ref().get())
            }
        }
        // we make the base field an extension of the
        // appropriate degree, in our case degree 1 (with
        // therefore 1 unique representation of an element)
        impl FieldExtensionTrait<$degree, $nreps> for $wrapper_name {
            fn quadratic_non_residue() -> Self {
                //this is p - 1 mod p = -1 mod p = 0 - 1 mod p
                // = -1
                Self::new((-Self::new_from_u64(1u64)).1.retrieve())
            }
            fn frobenius(&self, _exponent: usize) -> Self {
                Self::zero()
            }
            fn sqrt(&self) -> Self {
                Self::new(self.value().sqrt())
            }
            fn square(&self) -> Self {
                (*self) * (*self)
            }
            fn rand<R: CryptoRngCore>(rng: &mut R) -> Self {
                Self::new(<$uint_type>::random_mod(
                    rng,
                    ModulusStruct::MODULUS.as_nz_ref(),
                ))
            }
        }
        /// We now implement binary operations on the base field. This more or less
        /// just wraps the same operations on the underlying montgomery representations
        /// of the field element. All binops with assignment equivalents are given
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
                Self::new_from_u64(0u64)
            }
            fn is_zero(&self) -> bool {
                self.1.is_zero()
            }
        }
        impl One for $wrapper_name {
            fn one() -> Self {
                Self::new_from_u64(1u64)
            }
        }
        impl Default for $wrapper_name {
            fn default() -> Self {
                Self::new_from_u64(0u64)
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
        /// There is a bit of additional consideration here. checking equality
        /// is not generally speaking constant time. therefore, we use
        /// the build in functionality from subtle::ConstantTimeEq to do the
        /// operation in constant time. This does, however, return a Choice
        /// Choice(1u8) if self.0 == other.0
        /// Choice(0u8) if self.0 != other.0
        /// We unwrap and match the choice
        impl PartialEq for $wrapper_name {
            fn eq(&self, other: &Self) -> bool {
                match self.1.ct_eq(&other.1).unwrap_u8() {
                    1u8 => true,
                    _ => false,
                }
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
        /// For inversion, this is in general a difficult problem.
        /// Our goal is to solve, for a field element x, another element
        /// of the field y such that x * y = 1. To do this requires
        /// cleverness to also do in constant time. We use the
        /// Bernstein-Yang algorithm, which you can read more on here:
        /// <https://eprint.iacr.org/2019/266.pdf>
        ///
        /// Due to the numerical complexity, it makes sense that this
        /// returns an Option, for example in the case of an attempt to
        /// determine 1/0. This is a bit unfortunate, since as of now
        /// the code will panic should it fail. We unwrap the option for now.
        /// <https://github.com/RustCrypto/crypto-bigint/blob/be6a3abf7e65279ba0b5e4b1ce09eb0632e443f6/src/const_choice.rs#L237>
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
        impl Pow<U256> for $wrapper_name {
            type Output = Self;
            fn pow(self, rhs: U256) -> Self::Output {
                Self::new(self.1.pow(&rhs).retrieve())
            }
        }
        /// For reasons similar to `inv()` above, the following operations, which
        /// determine the quotient and remainder of a field element into another,
        /// return Options, again for instance in the case of an attempt to do 1/0.
        /// These specific operations require the casting to a `NonZero` struct which
        /// checks the validity of the input, but therefore returns an Option,
        /// which we unwrap. Otherwise, there will be panic.
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
                    return Self::new_from_u64(0u64);
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
                    return Self::new_from_u64(0u64);
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

const BN254_MOD_STRING: &str = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";
define_finite_prime_field!(Fp, U256, 8, BN254_MOD_STRING, 1, 1);
/// the code below makes the base field "visible" to higher
/// order extensions. The issue is really the fact that generic
/// traits cannot enforce arithmetic relations, such as the
/// statement "the child finite field of an extension must have
/// a degree strictly less than the current degree", which would
/// look something like D_1 | D_0 < D_1. In order to get around this
/// we make the extension explicitly usable by the higher order extension
/// by manually specifying the traits D, N. This enforces the logic
/// by means of manual input.
impl FieldExtensionTrait<2, 2> for Fp {
    fn quadratic_non_residue() -> Self {
        <Fp as FieldExtensionTrait<1, 1>>::quadratic_non_residue()
    }
    fn frobenius(&self, exponent: usize) -> Self {
        <Fp as FieldExtensionTrait<1, 1>>::frobenius(self, exponent)
    }
    fn sqrt(&self) -> Self {
        <Fp as FieldExtensionTrait<1, 1>>::sqrt(self)
    }
    fn square(&self) -> Self {
        <Fp as FieldExtensionTrait<1, 1>>::square(self)
    }
    fn rand<R: CryptoRngCore>(rng: &mut R) -> Self {
        <Fp as FieldExtensionTrait<1, 1>>::rand(rng)
    }
}

/// This is a very comprehensive test suite, that checks every binary operation for validity,
/// associativity, commutativity, distributivity, sanity checks, and edge cases.
/// The reference values for non-obvious field elements are generated with Sage.
#[cfg(test)]
mod tests {
    use super::*;
    const MODULUS: [u64; 4] = [
        0x3C208C16D87CFD47,
        0x97816A916871CA8D,
        0xB85045B68181585D,
        0x30644E72E131A029,
    ];

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
            assert_eq!(a / one, a, "Division by one failed");
            assert_eq!(
                (a / b) * b,
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
