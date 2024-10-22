//! Implementation of the base field 𝔽ₚ for elliptic curve cryptography.
//!
//! This module implements the basic finite field. The modulus of the finite field
//! is assumed to be prime (and therefore odd). The basic idea is that we use the
//! modulus to generate a struct, instances of which can be added, multiplied, etc.
//! all while conforming to the rules dictated by closed cyclic abelian groups.
//! The generated struct is flexible enough to handle massively large multiprecision
//! moduli and values, and performs all such modular arithmetic internally. The only
//! requirements of the user are to provide the modulus, and the desired bit precision.
//!
//! Due to efficiency considerations, we do not simply "do modular arithmetic" on numbers.
//! There are two levels of performance that we implement:
//!
//! 1. Montgomery arithmetic:
//!     This is a special type of modular arithmetic that
//!     allows for quick execution of binary operations
//!     for a given modulus. This relies on the generation
//!     of additional constants. For more information, see Ref 1.
//!
//! 2. Constant-time operations:
//!     In general, code may be differently executed depending
//!     on the inputs passed to it. Unrolling for loops differently
//!     for different inputs allows for side channel attacks. All
//!     this to say that all operations are performed in constant
//!     time with the usage of the `ConstMontyForm` struct of
//!     `crypto_bigint`.
//!
//! This module provides:
//! - Efficient arithmetic operations in 𝔽ₚ
//! - Montgomery arithmetic for improved performance
//! - Constant-time operations for enhanced security
//! - Frobenius endomorphism (identity for 𝔽ₚ)
//! - Square root and quadratic residue testing
//!
//! References
//! ----------
//! 1. <https://cacr.uwaterloo.ca/hac/about/chap14.pdf>

use crypto_bigint::subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use crypto_bigint::{
    impl_modulus, modular::ConstMontyParams, rand_core::CryptoRngCore, ConcatMixed, NonZero,
    RandomMod, Uint, U256,
};
use num_traits::{Euclid, Inv, One, Pow, Zero};
use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Rem, Sub, SubAssign};
use subtle::CtOption;

/// The modulus of the BN254 base field as a 256-bit integer in words.
///
/// This effectively constrains the finite prime field from a multiprecision integer
const BN254_FP_MODULUS_WORDS: [u64; 4] = [
    0x3C208C16D87CFD47,
    0x97816A916871CA8D,
    0xB85045B68181585D,
    0x30644E72E131A029,
];

/// The modulus of the r-order subfield as a 256-bit integer in words.
///
const BN254_FR_MODULUS_WORDS: [u64; 4] = [
    0x30644e72e131a029,
    0xb85045b68181585d,
    0x2833e84879b97091,
    0x43e1f593f0000001,
];

/// Instantiated BN254 base field 𝔽ₚ.
pub(crate) const BN254_FP_MODULUS: Fp = Fp::new(U256::from_words(BN254_FP_MODULUS_WORDS));

/// A quadratic non-residue in 𝔽ₚ, used in field extension arithmetic.
pub(crate) const FP_QUADRATIC_NON_RESIDUE: Fp = Fp::new(U256::from_words([
    4332616871279656262,
    10917124144477883021,
    13281191951274694749,
    3486998266802970665,
]));

// TODO(This seems like a misnomer, it should just be `FiniteField`)
// which is then built upon by the prime field, which is then built upon by the extensions

/// Defines operations for field extensions in elliptic curve cryptography.
///
/// This trait provides a common interface for arithmetic operations
/// in finite field extensions 𝔽ₚᵈ of various degrees d.
/// This defines the key properties of a field extension.
///
/// Now, mathematically,
/// a finite field satisfies many rigorous mathematical properties. The
/// (non-exhaustive) list below simply suffices to illustrate those properties
/// that are purely relevant to the task at hand here.
///
/// There are two generic elements that describe the particular field extension one generates:
/// (i) the degree of the extension (what is the highest degree of an element in the ring that is
/// used to generate the quotient field F(x)/f(x)), D, and (ii) the number of elements
/// required for a unique representation of an element in the extension, N. An extension can have
/// many different representations, so it is key to allow this flexibility.
pub trait FieldExtensionTrait<const D: usize, const N: usize>:
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
    + ConstantTimeEq
    + ConditionallySelectable
    + Zero
    + One
    + Inv<Output = Self>
    + From<u64>
{
    // TODO(We must encapsulate this dependency fully)
    /// Generate a random value in the field extension 𝔽ₚᵈ.
    fn rand<R: CryptoRngCore>(rng: &mut R) -> Self;

    /// Return the constant 'b' in the curve equation y² = x³ + b.
    ///
    /// Because each extension is directly used in a j-invariant 0 curve, we define the constant
    /// of that curve over the extension field.
    ///
    /// Namely, it is the value b in the equation y² = x³ + b.
    fn curve_constant() -> Self;
}

// Indeed, this is seen as not used, but it is used in the macro
/// Trait defining operations for a finite prime field 𝔽ₚ.
#[allow(dead_code)]
pub trait FinitePrimeField<const DLIMBS: usize, UintType, const D: usize, const N: usize>:
    FieldExtensionTrait<D, N> + Rem<Output = Self> + Euclid + Pow<U256> + From<u64>
where
    UintType: ConcatMixed<MixedOutput = Uint<DLIMBS>>,
{
}

/// Macro to define a finite prime field and implement various traits and methods for it.
///
/// This macro generates a new type representing elements of a finite field, along with
/// implementations of various traits and methods necessary for field arithmetic.
///
/// # Parameters
///
/// * `$wrapper_name`: The name of the wrapper struct for the field elements.
/// * `$mod_struct`: The name of the modulus struct.
/// * `$output`: The name of the output type for Montgomery form.
/// * `$uint_type`: The underlying unsigned integer type used for field elements.
/// * `$limbs`: The number of limbs in the underlying unsigned integer type.
/// * `$modulus`: The modulus of the field as a string.
/// * `$degree`: The degree of the field extension.
/// * `$nreps`: The number of elements required for a unique representation in the extension.
///
/// # Generated Items
///
/// - A new struct `$wrapper_name` representing field elements.
/// - Implementations of various traits including `Add`, `Sub`, `Mul`, `Div`, `Neg`, etc.
/// - Constants for common values (ZERO, ONE, TWO, etc.).
/// - Methods for creating and manipulating field elements.
///
/// # Note
///
/// Since we use `crypto_bigint` to handle the multiprecision arithmetic
/// we must accept (for now) the fact that it requires the usage of a macro,
/// `impl_modulus!`, which generates and contains all the need information.
/// This means that we roll our implementation into a proc macro that
/// provides all the needed functionality.
#[allow(unused_macros)]
macro_rules! define_finite_prime_field {
    ($wrapper_name:ident, $mod_struct:ident, $output:ident, $uint_type:ty, $limbs:expr,
    $modulus:expr,
    $degree:expr,
    $nreps:expr) => {
        impl_modulus!($mod_struct, $uint_type, $modulus);

        /// Type alias for constant-time arithmetic on Montgomery form integers modulo p
        type $output = crypto_bigint::modular::ConstMontyForm<$mod_struct, { $mod_struct::LIMBS }>;

        /// Represents an element in the base field 𝔽ₚ or the r-torsion subgroup 𝔽ᵣ.
        ///
        /// This is the actual struct that serves as our finite field implementation, containing
        ///  the modulus of the field, as well as the output type that contains the internal
        ///  Montgomery arithmetic logic
        #[derive(Clone, Copy, Eq)] //Clone and Copy to be used in const contexts
        pub struct $wrapper_name($mod_struct, $output);

        impl FinitePrimeField<$limbs, $uint_type, $degree, $nreps> for $wrapper_name {}

        impl $wrapper_name {
            /// Creates a new base field element from the given value
            ///
            /// # Arguments
            /// * `value` - $uint_type - the value to create the element from
            pub const fn new(value: $uint_type) -> Self {
                Self($mod_struct, $output::new(&value))
            }

            /// Creates a new field element from a base-10 string representation
            ///
            /// # Arguments
            /// * `value` - &str - the string representation of the value to create the element from
            pub fn new_from_str(value: &str) -> Option<Self> {
                let ints: Vec<_> = {
                    let mut acc = Self::zero();
                    (0..11)
                        .map(|_| {
                            let tmp = acc;
                            acc += Self::one();
                            tmp
                        })
                        .collect()
                };
                let mut res = Self::zero();
                for c in value.chars() {
                    match c.to_digit(10) {
                        Some(d) => {
                            res *= ints[10];
                            res += ints[d as usize]
                        }
                        None => return None,
                    }
                }
                Some(res)
            }

            /// Returns the value of the field element in standard (non-Montgomery) form
            pub const fn value(&self) -> $uint_type {
                self.1.retrieve()
            }

            /// Returns the characteristic (modulus) of the field as a $uint_type
            pub fn characteristic() -> $uint_type {
                <$uint_type>::from($mod_struct::MODULUS.as_nz_ref().get())
            }

            // TODO(consider)
            // These constants are used in the various implementations. One noteworthy thing
            // here is that we have hardcoded the number of limbs, which could lead to issues
            // down the road using this macro for say 6 words in BLS-12-381, which might
            // not be immediately apparent.

            /// Constant representing zero in the field
            pub const ZERO: Self = Self::new(<$uint_type>::from_words([0x0; 4]));

            /// Constant representing one in the field
            pub const ONE: Self = Self::new(<$uint_type>::from_words([0x1, 0x0, 0x0, 0x0]));

            /// Constant representing two in the field
            pub const TWO: Self = Self::new(<$uint_type>::from_words([0x2, 0x0, 0x0, 0x0]));

            /// Constant representing three in the field
            pub const THREE: Self = Self::new(<$uint_type>::from_words([0x3, 0x0, 0x0, 0x0]));

            /// Constant representing four in the field
            pub const FOUR: Self = Self::new(<$uint_type>::from_words([0x4, 0x0, 0x0, 0x0]));

            /// Constant representing nine in the field
            pub const NINE: Self = Self::new(<$uint_type>::from_words([0x9, 0x0, 0x0, 0x0]));
        }

        // we make the base field an extension of the
        // appropriate degree, in our case degree 1 (with
        // therefore 1 unique representation of an element)
        impl FieldExtensionTrait<$degree, $nreps> for $wrapper_name {
            /// Generates a random field element
            /// # Arguments
            /// * `rng` - R: CryptoRngCore - the random number generator to use
            fn rand<R: CryptoRngCore>(rng: &mut R) -> Self {
                Self::new(<$uint_type>::random_mod(
                    rng,
                    $mod_struct::MODULUS.as_nz_ref(),
                ))
            }

            /// Returns the constant of the j-invariant 0 curve defined over this field
            ///
            /// this is the constant of the j-invariant curve defined over this base field.
            /// Namely, the short Weierstrass curve is of the form $y^2 = x^3 + b$, and the below
            /// is the constant `b`. For BN254, this is 3.
            fn curve_constant() -> Self {
                Self::THREE
            }
        }

        impl From<u64> for $wrapper_name {
            // many often there is a need to create a simple value like `3` in the base field,
            // which is what this accomplishes
            /// Returns an element of the field with a value of `value` up to one word
            fn from(value: u64) -> Self {
                Self($mod_struct, $output::new(&<$uint_type>::from_u64(value)))
            }
        }

        /// Implements binary operations on the base field.
        ///
        /// This more or less just wraps the same operations on the underlying
        /// montgomery representations of the field element. All binops with
        /// assignment equivalents are given.
        impl Add for $wrapper_name {
            type Output = Self;
            #[inline]
            fn add(self, other: Self) -> Self {
                Self::new((self.1 + other.1).retrieve())
            }
        }

        impl AddAssign for $wrapper_name {
            #[inline]
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

            #[inline]
            fn sub(self, other: Self) -> Self {
                Self::new((self.1 - other.1).retrieve())
            }
        }

        impl SubAssign for $wrapper_name {
            #[inline]
            fn sub_assign(&mut self, other: Self) {
                *self = *self - other;
            }
        }

        // There is a bit of additional consideration here. checking equality
        // is not generally speaking constant time. therefore, we use
        // the build in functionality from subtle::ConstantTimeEq to do the
        // operation in constant time. This does, however, return a Choice
        // Choice(1u8) if self.0 == other.0
        // Choice(0u8) if self.0 != other.0
        // We unwrap and match the choice

        impl ConstantTimeEq for $wrapper_name {
            fn ct_eq(&self, other: &Self) -> Choice {
                self.1.ct_eq(&other.1)
            }
        }

        impl PartialEq for $wrapper_name {
            #[inline]
            fn eq(&self, other: &Self) -> bool {
                bool::from(self.ct_eq(other))
            }
        }

        impl ConditionallySelectable for $wrapper_name {
            fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
                Self::new(<$uint_type>::conditional_select(
                    &a.value(),
                    &b.value(),
                    choice,
                ))
            }
        }

        impl Mul for $wrapper_name {
            type Output = Self;
            #[inline]
            fn mul(self, other: Self) -> Self {
                Self::new((self.1 * other.1).retrieve())
            }
        }

        impl MulAssign for $wrapper_name {
            #[inline]
            fn mul_assign(&mut self, other: Self) {
                *self = *self * other;
            }
        }

        // TODO(Disagree, we should throw a divide by zero error when that occurs vs panic and use a result here)

        /// Implements field inversion.
        ///
        /// This is in general a difficult problem.
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
            #[inline]
            fn inv(self) -> Self {
                Self::new((CtOption::from(self.1.inv()).unwrap_or(Self::from(0u64).1)).retrieve())
            }
        }

        #[allow(clippy::suspicious_arithmetic_impl)]
        impl Div for $wrapper_name {
            type Output = Self;
            #[inline]
            fn div(self, other: Self) -> Self {
                self * other.inv()
            }
        }

        impl DivAssign for $wrapper_name {
            #[inline]
            fn div_assign(&mut self, other: Self) {
                *self = *self / other;
            }
        }

        impl Neg for $wrapper_name {
            type Output = Self;

            #[inline]
            fn neg(self) -> Self {
                Self::new((-self.1).retrieve())
            }
        }

        impl Pow<U256> for $wrapper_name {
            type Output = Self;
            #[inline]
            fn pow(self, rhs: U256) -> Self::Output {
                Self::new(self.1.pow(&rhs).retrieve())
            }
        }

        // TODO(Disagree, we should throw a divide by zero error when that occurs vs panic and use a result here)

        /// For reasons similar to `inv()` above, the following operations, which
        /// determine the quotient and remainder of a field element into another,
        /// return Options, again for instance in the case of an attempt to do 1/0.
        /// These specific operations require the casting to a `NonZero` struct which
        /// checks the validity of the input, but therefore returns an Option,
        /// which we unwrap. Otherwise, there will be panic.
        impl Rem for $wrapper_name {
            type Output = Self;
            #[inline]
            fn rem(self, other: Self) -> Self::Output {
                // create our own check for zeroness?
                Self::new(
                    self.1
                        .retrieve()
                        .rem(NonZero::<$uint_type>::new(other.1.retrieve()).unwrap()),
                )
            }
        }

        impl Euclid for $wrapper_name {
            #[inline]
            fn div_euclid(&self, other: &Self) -> Self {
                if other.is_zero() {
                    return Self::from(0u64);
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

            #[inline]
            fn rem_euclid(&self, other: &Self) -> Self {
                if other.is_zero() {
                    return Self::from(0u64);
                }
                let (mut _q, mut _r) = self
                    .1
                    .retrieve()
                    .div_rem(&NonZero::<$uint_type>::new(other.1.retrieve()).unwrap());
                tracing::trace!(?_q, ?_r, "finite_prime_field::rem_euclid");

                if self.1.retrieve().bit(255).into() {
                    // _q = _q - <$uint_type>::ONE;
                    _r = other.1.retrieve() - _r;
                    tracing::trace!(?_r, "finite_prime_field::rem_euclid high bit");
                }
                Self::new(_r)
            }
        }

        impl std::fmt::Debug for $wrapper_name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($wrapper_name))
                    .field(stringify!($uint_type), &self.value())
                    .finish()
            }
        }

        impl std::hash::Hash for $wrapper_name {
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                self.value().hash(state);
            }
        }
    };
}

// TODO(We have this in words above, why needed also as a string here?)
// also, arguable that hex values as strings should have a leading prefix 0x

/// Modulus for the BN254 base field 𝔽ₚ as a string in base-16.
const BN254_MOD_STRING: &str = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";

/// Modulus for the BN254 r-torsion subgroup 𝔽ᵣ as a string in base-16.
const BN254_SUBGROUP_MOD_STRING: &str =
    "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";

// Defines the base field 𝔽ₚ for BN254
define_finite_prime_field!(
    Fp,
    FpModStruct,
    FpOutputType,
    U256,
    8,
    BN254_MOD_STRING,
    1,
    1
);

// Defines the r-torsion field 𝔽ᵣ for BN254
define_finite_prime_field!(
    Fr,
    FrModStruct,
    FrOutputType,
    U256,
    8,
    BN254_SUBGROUP_MOD_STRING,
    1,
    1
);

// TODO(Would be much more erognomic to expose these publicly)
// unless we wrap the private key up right.

// Conversion implementations between 𝔽ₚ and 𝔽ᵣ

impl<'a> From<&'a Fr> for Fp {
    fn from(value: &'a Fr) -> Self {
        Fp::new(value.value())
    }
}

impl From<Fr> for Fp {
    fn from(value: Fr) -> Self {
        Fp::from(&value)
    }
}

impl Fp {
    /// Applies the Frobenius endomorphism to the field element
    ///
    /// This determines the frobenius mapping of the element in the base field, aka x^p. This
    /// function is inherently expensive, and we never call it on the base field, but if
    /// we did, it's only defined for p=1. Specialized versions exist for all extensions which
    /// will require the frobenius transformation.
    #[inline(always)]
    pub fn frobenius(&self, exponent: usize) -> Self {
        match exponent {
            1 => self.pow(BN254_FP_MODULUS.value()),
            _ => *self,
        }
    }

    /// Computes the square root of the field element
    ///
    /// This is an instantiation of Shank's algorithm, which solves congruences of
    /// the form $r^2\equiv n \mod p$, namely the sqrt of n. It does not work for
    /// composite moduli (aka non-prime p), since that is the integer factorization
    /// problem. The full algorithm is not necessary here, and has the additional
    /// simplification that we can exploit in our case. Namely, the BN254 curve has a
    /// prime that is congruent to 3 mod 4. In this case, the sqrt only has the
    /// possible solution of $\pm pow(n, \frac{p+1}{4})$, which is where this magic
    /// number below comes from ;)
    #[inline]
    pub fn sqrt(&self) -> CtOption<Self> {
        let arg = ((Self::new(Self::characteristic()) + Self::one()) / Self::from(4)).value();
        let sqrt = self.pow(arg);
        tracing::trace!(?arg, ?sqrt, "Fp::sqrt");
        CtOption::new(sqrt, sqrt.square().ct_eq(self))
    }

    /// Returns the square of the element in the base field
    #[inline]
    pub fn square(&self) -> Self {
        (*self) * (*self)
    }

    /// Determines if the element is a quadratic residue, i.e. is a square of another element
    pub fn is_square(&self) -> Choice {
        let p_minus_1_div_2 =
            ((Self::new(Self::characteristic()) - Self::from(1)) / Self::from(2)).value();
        let retval = self.pow(p_minus_1_div_2);
        tracing::trace!(?p_minus_1_div_2, ?retval, "Fp::is_square");
        Choice::from((retval == Self::zero() || retval == Self::one()) as u8)
    }

    /// Determines the 'sign' of the field element
    ///
    /// See <https://datatracker.ietf.org/doc/html/rfc9380#section-4.1> for more details.
    pub fn sgn0(&self) -> Choice {
        let a = *self % Self::TWO;
        tracing::trace!(?a, "Fp::sgn0");
        if a.is_zero() {
            Choice::from(0u8)
        } else {
            Choice::from(1u8)
        }
    }

    /// Computes the Non-Adjacent Form (NAF) representation of the field element
    ///
    /// There is a need to at times move to a representation of the field element with
    /// a lower Hamming weight, for instance in the case of multiplication of a group element by
    /// such a scalar. This implements the prodinger algorithm, and returns a string of the
    /// positive bits and a string of negative bits for the NAF representation
    /// see <http://math.colgate.edu/~integers/a8/a8.pdf>
    pub(crate) fn compute_naf(self) -> (U256, U256) {
        let x = self.value();
        let xh = x >> 1;
        let x3 = x + xh;
        let c = xh ^ x3;
        let np = x3 & c;
        let nm = xh & c;

        (np, nm)
    }

    /// Converts a big-endian byte representation to a field element
    ///
    /// This generates an element in the base field from the byte array. It could be as simple as
    /// doing `Self::new(U256::from_be_slice(arr))`, but the issue is that this will
    /// automatically place the value around the modulus if it's greater than `p`, which will
    /// result in the returned value not being the same as what the user input, so we choose to
    /// circumvent this by doing the conversion manually, and returning a null value if the input
    /// would yield a value greater than the modulus. Doing the arithmetic on the limbs
    /// themselves is cheaper than doing it on the full U256 object, but also crypto_bigint will
    /// straight up panic if there is an issue in many places, which is not ideal, so we do things
    /// in u64 to handle the potential errors ourselves.
    ///
    /// The below is inspired by the equivalent implementation in zkcrypto/bls12_381/fp.rs, which
    /// is an implementation of Alg 14.9 of Handbook for Applied Cryptography, Ch 14
    /// <https://cacr.uwaterloo.ca/hac/about/chap14.pdf>
    /// # Arguments
    /// * `arr` - &[u8; 32] - the byte array to convert to an element in the base field
    /// # Returns
    /// * `CtOption<Self>` - the element in the base field, or None if the value is greater than the
    ///                      Note that the CtOption is designed to panic during `unwrap` if the
    ///                      option is none, whichwill require the user to handle the error
    ///                      themselves with the `is_none` or `is_some` methods
    pub fn from_be_bytes(arr: &[u8; 32]) -> CtOption<Self> {
        // a simple subtraction that returns the borrow
        #[inline(always)]
        const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
            let ret = (a as u128).wrapping_sub((b as u128) + ((borrow >> 63) as u128));
            (ret as u64, (ret >> 64) as u64)
        }
        // generate the words themselves from the byte array
        let a4 = u64::from_be_bytes(
            <[u8; 8]>::try_from(&arr[0..8]).expect("Conversion of u8 array failed"),
        );
        let a3 = u64::from_be_bytes(
            <[u8; 8]>::try_from(&arr[8..16]).expect("Conversion of u8 array failed"),
        );
        let a2 = u64::from_be_bytes(
            <[u8; 8]>::try_from(&arr[16..24]).expect("Conversion of u8 array failed"),
        );
        let a1 = u64::from_be_bytes(
            <[u8; 8]>::try_from(&arr[24..32]).expect("Conversion of u8 array failed"),
        );

        // determine if the value is greater than the modulus
        let (_, borrow) = sbb(a1, BN254_FP_MODULUS_WORDS[0], 0);
        let (_, borrow) = sbb(a2, BN254_FP_MODULUS_WORDS[1], borrow);
        let (_, borrow) = sbb(a3, BN254_FP_MODULUS_WORDS[2], borrow);
        let (_, borrow) = sbb(a4, BN254_FP_MODULUS_WORDS[3], borrow);

        // there's underflow if the value is below the modulus, aka borrow != 0
        let is_some = (borrow as u8) & 1;
        CtOption::new(
            Self::new(U256::from_words([a1, a2, a3, a4])),
            Choice::from(is_some),
        )
    }

    /// Converts the field element to a big-endian byte representation
    ///
    /// # Arguments
    /// * `self` - &Self - the element in the base field to convert to a byte array
    /// # Returns
    /// * [u8; 32] - the byte array representation of the element in the base field
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let words = self.value().to_words();
        let mut res = [0; 32];

        res[0..8].copy_from_slice(&words[3].to_be_bytes());
        res[8..16].copy_from_slice(&words[2].to_be_bytes());
        res[16..24].copy_from_slice(&words[1].to_be_bytes());
        res[24..32].copy_from_slice(&words[0].to_be_bytes());

        res
    }
}

/// Implements the r-torsion field elements
impl Fr {
    /// Computes the Non-Adjacent Form (NAF) representation of the field element
    pub(crate) fn compute_naf(self) -> (U256, U256) {
        Fp::from(self).compute_naf()
    }
    pub fn from_be_bytes(arr: &[u8; 32]) -> CtOption<Self> {
        #[inline(always)]
        const fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
            let ret = (a as u128).wrapping_sub((b as u128) + ((borrow >> 63) as u128));
            (ret as u64, (ret >> 64) as u64)
        }
        // generate the words themselves from the byte array
        let a4 = u64::from_be_bytes(
            <[u8; 8]>::try_from(&arr[0..8]).expect("Conversion of u8 array failed"),
        );
        let a3 = u64::from_be_bytes(
            <[u8; 8]>::try_from(&arr[8..16]).expect("Conversion of u8 array failed"),
        );
        let a2 = u64::from_be_bytes(
            <[u8; 8]>::try_from(&arr[16..24]).expect("Conversion of u8 array failed"),
        );
        let a1 = u64::from_be_bytes(
            <[u8; 8]>::try_from(&arr[24..32]).expect("Conversion of u8 array failed"),
        );

        // determine if the value is greater than the modulus
        let (_, borrow) = sbb(a1, BN254_FR_MODULUS_WORDS[0], 0);
        let (_, borrow) = sbb(a2, BN254_FR_MODULUS_WORDS[1], borrow);
        let (_, borrow) = sbb(a3, BN254_FR_MODULUS_WORDS[2], borrow);
        let (_, borrow) = sbb(a4, BN254_FR_MODULUS_WORDS[3], borrow);

        // there's underflow if the value is below the modulus, aka borrow != 0
        let is_some = (borrow as u8) & 1;
        CtOption::new(
            Self::new(U256::from_words([a1, a2, a3, a4])),
            Choice::from(is_some),
        )
    }
}

/// Implementation to make Fp visible to higher order extensions
///
/// The code below makes the base field "visible" to higher
/// order extensions. The issue is really the fact that generic
/// traits cannot enforce arithmetic relations, such as the
/// statement "the child finite field of an extension must have
/// a degree strictly less than the current degree", which would
/// look something like D_1 | D_0 < D_1. In order to get around this
/// we make the extension explicitly usable by the higher order extension
/// by manually specifying the traits D, N. This enforces the logic
/// by means of manual input.
impl FieldExtensionTrait<2, 2> for Fp {
    fn rand<R: CryptoRngCore>(rng: &mut R) -> Self {
        <Fp as FieldExtensionTrait<1, 1>>::rand(rng)
    }
    fn curve_constant() -> Self {
        <Fp as FieldExtensionTrait<1, 1>>::curve_constant()
    }
}

// This is a very comprehensive test suite, that checks every binary operation for validity,
// associativity, commutativity, distributivity, sanity checks, and edge cases.
// The reference values for non-obvious field elements are generated with Sage.
#[cfg(test)]
mod tests {
    use super::*;

    fn create_field(value: [u64; 4]) -> Fp {
        Fp::new(U256::from_words(value))
    }
    mod byte_tests {
        use super::*;
        #[test]
        fn test_conversion() {
            let a = create_field([1, 2, 3, 4]);
            let bytes = a.value().to_be_bytes();
            let b = Fp::from_be_bytes(&bytes).unwrap();
            assert_eq!(a, b, "From bytes failed")
        }
        #[test]
        fn test_over_modulus() {
            let a = (BN254_FP_MODULUS - Fp::ONE).value() + U256::from(10u64);
            let bytes = a.to_be_bytes();
            let b = Fp::from_be_bytes(&bytes);
            assert!(bool::from(b.is_none()), "Over modulus failed")
        }
        #[test]
        #[should_panic(expected = "assertion `left == right` failed")]
        fn test_over_modulus_panic() {
            let a = (BN254_FP_MODULUS - Fp::ONE).value() + U256::from(10u64);
            let bytes = a.to_be_bytes();
            let _b = Fp::from_be_bytes(&bytes).unwrap();
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
            let e = BN254_FP_MODULUS;
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
            let g = BN254_FP_MODULUS;
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
        // #[should_panic(expected = "assertion failed: self.is_some.is_true_vartime()")]
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

    mod square_tests {
        use super::*;
        use crypto_bigint::rand_core::OsRng;

        #[test]
        fn test_square() {
            for _ in 0..100 {
                let a = <Fp as FieldExtensionTrait<1, 1>>::rand(&mut OsRng);
                let b = a.square();
                assert!(bool::from(b.is_square()), "Is square failed");
            }
        }
        #[test]
        fn test_sqrt() {
            for i in 0..100 {
                let a = create_field([i, 2 * i, 3 * i, 4 * i]);
                let b = a.sqrt();
                match b.into_option() {
                    Some(d) => {
                        assert_eq!(d * d, a, "Sqrt failed")
                    }
                    _ => continue,
                }
            }
        }
    }

    mod vss_tests {
        use super::*;

        // The coefficients are [a_0,...,a_n], and so this evaluates sum(a_i x^i).
        fn eval_polynomial(coefficients: &[Fp], x: &Fp) -> Fp {
            let mut val = Fp::zero();
            for (i, c) in coefficients.iter().enumerate() {
                val += *c * x.pow(U256::from_u64(i as u64));
            }
            val
        }

        // This uses Lagrange interpolation to solve for a_0 given a set of t points.
        fn get_secret_lagrange(xa: &[Fp], ya: &[Fp]) -> Fp {
            let mut val = Fp::zero();
            for (j, xj) in xa.iter().enumerate() {
                let mut term_j = ya[j];
                for (k, xk) in xa.iter().enumerate() {
                    if k != j {
                        term_j *= *xk / (*xk - *xj);
                    }
                }
                val += term_j;
            }
            val
        }

        fn check_commitments(commitments: &[Fp], x: &Fp) -> Fp {
            let mut val = Fp::one();
            for (j, cmt_j) in commitments.iter().enumerate() {
                val *= cmt_j.pow(x.pow(U256::from_u64(j as u64)).value());
            }
            val
        }

        fn from_i32(n: i32) -> Fp {
            Fp::new(U256::from_u64(n as u64))
        }

        fn from_vec_i32(v: Vec<i32>) -> Vec<Fp> {
            v.iter().map(|n| from_i32(*n)).collect()
        }

        #[test]
        fn test_vss() {
            let coefficients = from_vec_i32(vec![14, 1, 2, 3, 4]);
            let xa = from_vec_i32(vec![2, 4, 6, 8, 10]);
            let ya: Vec<Fp> = xa
                .iter()
                .map(|x| eval_polynomial(&coefficients, x))
                .collect();

            // example Lagrange interpolation
            assert_eq!(coefficients[0], get_secret_lagrange(&xa, &ya));

            // p-1 guaranteed to be a generator of the multiplicative group Fp^*.
            let generator: Fp = Fp::zero() - Fp::one();
            let commitments: Vec<Fp> = coefficients
                .iter()
                .map(|c| generator.pow(c.value()))
                .collect();
            for (i, xi) in xa.iter().enumerate() {
                let gy = generator.pow(ya[i].value());
                let check_x = check_commitments(&commitments, xi);
                assert_eq!(gy, check_x);
            }
            // TODO: I believe the commitment check can fail if any calculated y or x^i wraps around p.
            // This is because the multiplicative group Fp^* is of order p-1, not p.
            // As per Feldman VSS, I believe we need to select appropriate p and q.
        }
    }

    #[test]
    fn test_conditional_selection() {
        let a = create_field([1, 2, 3, 4]);
        let b = create_field([5, 6, 7, 8]);
        assert_eq!(Fp::conditional_select(&a, &b, Choice::from(0u8)), a);
        assert_eq!(Fp::conditional_select(&a, &b, Choice::from(1u8)), b);
    }
    #[test]
    fn test_conversion() {
        let b = Fr::new(U256::from_words([1, 2, 3, 4]));
        let c = Fp::from(&b);
        assert_eq!(c.value().to_words(), [1, 2, 3, 4]);
    }

    #[test]
    fn test_equality() {
        fn is_equal(a: &Fp, b: &Fp) -> bool {
            let eq = a == b;
            let ct_eq = a.ct_eq(b);

            assert_eq!(eq, bool::from(ct_eq));
            eq
        }
        assert!(is_equal(
            &create_field([1, 2, 3, 4]),
            &create_field([1, 2, 3, 4])
        ));
        assert!(!is_equal(
            &create_field([9, 2, 3, 4]),
            &create_field([1, 2, 3, 4])
        ));
        assert!(!is_equal(
            &create_field([1, 9, 3, 4]),
            &create_field([1, 2, 3, 4])
        ));
        assert!(!is_equal(
            &create_field([1, 2, 9, 4]),
            &create_field([1, 2, 3, 4])
        ));
        assert!(!is_equal(
            &create_field([1, 2, 3, 9]),
            &create_field([1, 2, 3, 4])
        ));
    }

    #[test]
    fn test_characteristic() {
        let char = Fp::characteristic() - U256::from(1u64);
        assert_eq!(char, (BN254_FP_MODULUS - Fp::ONE).value());
    }

    #[test]
    fn test_from_u64() {
        for i in 0..255 {
            let res = Fp::from(i);
            assert_eq!(res.value().to_words(), [i, 0, 0, 0]);
        }
    }

    #[test]
    fn test_debug() {
        let res = Fp::new(U256::from_words([
            0x0,
            0x97816A916871CA8D,
            0x0,
            0x30644E02E131A029,
        ]));
        assert_eq!(
            format!("{:?}", res),
            "Fp { U256: Uint(0x30644E02E131A029000000000000000097816A916871CA8D0000000000000000) }"
        );
    }

    mod euclid_tests {
        use super::*;
        #[test]
        fn test_div_euclid() {
            let test_cases = [
                (10, 3, 3),  // Normal case
                (10, 2, 5),  // Exact division
                (0, 5, 0),   // Zero dividend
                (10, 1, 10), // Divisor is 1
                (10, 11, 0), // Divisor larger than dividend
            ];
            for (a, b, expected) in test_cases.iter() {
                let a = Fp::from(*a as u64);
                let b = Fp::from(*b as u64);
                let expected = Fp::from(*expected as u64);
                assert_eq!(
                    a.div_euclid(&b),
                    expected,
                    "Failed for {} div_euclid {}",
                    a.value(),
                    b.value()
                );
            }
        }
        #[test]
        fn test_rem_euclid() {
            let test_cases = [
                (10, 3, 1),   // Normal case
                (10, 2, 0),   // No remainder
                (0, 5, 0),    // Zero dividend
                (10, 1, 0),   // Divisor is 1
                (10, 11, 10), // Divisor larger than dividend
            ];
            for (a, b, expected) in test_cases.iter() {
                let a = Fp::from(*a as u64);
                let b = Fp::from(*b as u64);
                let expected = Fp::from(*expected as u64);
                assert_eq!(
                    a.rem_euclid(&b),
                    expected,
                    "Failed for {} rem_euclid {}",
                    a.value(),
                    b.value()
                );
            }
        }
    }
    #[test]
    fn assignment_tests() {
        let mut a = Fp::from(10);
        let b = Fp::from(5);

        // addition
        let c = a + b;
        a += b;

        assert_eq!(c, a, "Addition assignment failed");

        // subtraction
        let mut a = Fp::from(10);
        let c = a - b;
        a -= b;
        assert_eq!(c, a, "Subtraction assignment failed");

        // multiplication
        let mut a = Fp::from(10);
        let c = a * b;
        a *= b;
        assert_eq!(c, a, "Multiplication assignment failed");

        // division
        let mut a = Fp::from(10);
        let c = a / b;
        a /= b;
        assert_eq!(c, a, "Division assignment failed");
    }

    mod hash_tests {
        use super::*;
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        fn calculate_hash<T: Hash>(t: &T) -> u64 {
            let mut s = DefaultHasher::new();
            t.hash(&mut s);
            s.finish()
        }
        #[test]
        fn test_equality() {
            let v1 = Fp::from(123456789u64);
            let v2 = Fp::from(123456789u64);

            assert_eq!(
                calculate_hash(&v1),
                calculate_hash(&v2),
                "Hash not consistent for equal values"
            );
        }
        #[test]
        fn test_hash_set_insertion() {
            use std::collections::HashSet;
            let mut set = HashSet::new();
            let v1 = Fp::from(123456789u64);
            let v2 = Fp::from(123456789u64);

            set.insert(v1);
            assert!(set.contains(&v2), "HashSet insertion failed");
            assert!(
                !set.insert(v1),
                "Shouldn't be able to add the same element twice"
            );
        }
    }

    #[test]
    fn test_curve_constant() {
        let curve_constant = <Fp as FieldExtensionTrait<1, 1>>::curve_constant();
        let also_curve_constant = <Fp as FieldExtensionTrait<2, 2>>::curve_constant();
        assert!(
            bool::from(curve_constant.ct_eq(&Fp::THREE) & also_curve_constant.ct_eq(&Fp::THREE)),
            "Curve constant is not 3"
        );
    }

    #[test]
    fn test_frobenius() {
        let a = Fp::from(10);
        assert_eq!(
            Fp::ONE,
            a.frobenius(1).frobenius(1),
            "Frobenius squared should be equal to one"
        );
    }
}
