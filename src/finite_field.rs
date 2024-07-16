use num_traits::{Inv, Zero};
use std::ops::{Add, Div, Mul, Neg, Sub, Deref};
use crypto_bigint::{FixedInteger, Limb, Odd, Word, U256};
use crypto_bigint::modular::{montgomery_reduction, ConstMontyForm, ConstMontyParams, Retrieve};
use core::marker::{Send, Sync};
use std::str::FromStr;
use std::fmt::Write;

fn hex_str_to_u64_array<const L: usize>(input: &str) -> [u64; L] {
    let mut n_array = [0u64; L];
    let n_hex = input.strip_prefix("0x").unwrap();
    
    for (i, chunk) in n_hex.as_bytes().rchunks(16).enumerate() {
        if i >= L {
            break;
        }
        let limb_hex = std::str::from_utf8(chunk).unwrap();
        n_array[i] = u64::from_str_radix(limb_hex, 16).unwrap();
    }
    
    n_array
}
pub fn u64_array_to_hex_str<const L: usize>(arr: &[u64; L]) -> String {
    let mut hex = String::with_capacity(2 + L * 16);
    hex.push_str("0x");

    let mut started = false;
    for &limb in arr.iter().rev() {
        if started {
            write!(hex, "{:016x}", limb).unwrap();
        } else if limb != 0 {
            write!(hex, "{:x}", limb).unwrap();
            started = true;
        }
    }

    if !started {
        hex.push('0');
    }

    hex
}



pub trait ModulusTrait: std::cmp::Eq + std::default::Default + std::fmt::Debug + std::marker::Copy + Send + Sync + 'static {}

impl<T: std::cmp::Eq + std::default::Default + std::fmt::Debug + std::marker::Copy + Send + Sync + 'static> ModulusTrait for T {}

pub trait ModulusConfig {
    const MODULUS_HEX: &'static str;
}

#[derive(PartialEq, Eq, Default, Debug, Clone, Copy)]
pub struct Modulus<T: ModulusConfig> {
    _phantom: std::marker::PhantomData<T>
}

impl<T: ModulusConfig> Modulus<T> {
    pub const fn new() -> Self {
        Self { _phantom: std::marker::PhantomData}
    }
}

impl<T: ModulusConfig + 'static + ModulusTrait> ConstMontyParams<{ U256::LIMBS }> for Modulus<T> {
    const LIMBS: usize = U256::LIMBS;
    
    const MODULUS: Odd<U256> = Odd::<U256>::from_be_hex(T::MODULUS_HEX);

    const ONE: U256 = U256::MAX
        .rem_vartime(Self::MODULUS.as_nz_ref())
        .wrapping_add(&U256::ONE);

    const R2: U256 = U256::rem_wide_vartime(Self::ONE.square_wide(), Self::MODULUS.as_nz_ref());

    const MOD_NEG_INV: Limb = Limb(
        Word::MIN.wrapping_sub(
            Self::MODULUS
                .as_ref()
                .inv_mod2k_vartime(Word::BITS)
                .expect("modulus ensured odd")
                .as_limbs()[0]
                .0,
        )
    );

    const R3: U256 = montgomery_reduction(
        &Self::R2.square_wide(),
        &Self::MODULUS,
        Self::MOD_NEG_INV,
    );
}

pub type MontgomeryForm<T> = ConstMontyForm<Modulus<T>, { U256::LIMBS }>;


#[derive(Clone, Debug)]
pub struct FinitePrimeField<const L: usize, const D: usize, T: ModulusConfig + ModulusTrait> (MontgomeryForm<T>);

impl<const L: usize, const D: usize, T: ModulusConfig + ModulusTrait> FinitePrimeField<L, D, T>{
    const ZERO: U256 = U256::ZERO;
    const ONE: U256 = U256::ONE;

    pub const fn new(value: U256) -> Self {
        if D != 2 * L {
            panic!("Double size D must be twice the size of the field L");
        }

        let _modulus = Modulus::<T>::new();
        let _value = MontgomeryForm::<T>::new(&value);
        
        // let value = ConstMontyForm::<mymod, {mymod::LIMBS}>::new(&value);
        Self(_value)
    }
}
// TODO: UNSAFE, needed to use self.0.retrieve() every time I call to th efunction
impl<const L: usize, const D: usize, T:ModulusConfig + ModulusTrait> Deref for FinitePrimeField<L, D, T>{
    type Target = U256;

    fn deref(&self) -> &Self::Target {
        static mut RETRIEVED: Option<U256> = None;
        unsafe {
            RETRIEVED = Some(self.0.retrieve());
            RETRIEVED.as_ref().unwrap()
        }
    }
}

impl<const L: usize, const D: usize, T:ModulusConfig + ModulusTrait> Add for FinitePrimeField<L, D, T> {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        Self::new((self.0+other.0).retrieve())
    }
}
impl<const L: usize, const D: usize,  T:ModulusConfig + ModulusTrait> PartialEq for FinitePrimeField<L, D, T> {
    fn eq(&self, other: &Self) -> bool {
        // First compare the montgomery values, which encodes the modulus
        self.0.as_montgomery() == other.0.as_montgomery()
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::PartialEq;
    use super::*;
    const L: usize = 4;
    const MODULUS: [u64; 4] = [
        0x3C208C16D87CFD47,
        0x97816A916871CA8D,
        0xB85045B68181585D,
        0x30644E72E131A029,
    ];
    const BN254_MOD_STRING: &str = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    struct BN254Modulus;
    impl ModulusConfig for BN254Modulus {
        const MODULUS_HEX: &'static str = BN254_MOD_STRING;
    }

    fn create_field(value: [u64; 4]) -> FinitePrimeField<4, 8, BN254Modulus>{
        FinitePrimeField::new(U256::from_words(value))
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
            assert_eq!(*(a.clone() + b.clone()) + *c, *a + *(b + c), "Addition is not associative");
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
            assert_eq!(*(a + b), U256::from_words([3, 0, 0, 0]), "Simple addition failed");

            // Addition with carry
            let c = create_field([0xFFFFFFFFFFFFFFFF, 0, 0, 0]);
            let d = create_field([1, 0, 0, 0]);
            assert_eq!(*(c + d), U256::from_words([0, 1, 0, 0]), "Addition with carry failed");

            // Addition that wraps around the modulus
            let e = create_field(MODULUS);
            let f = create_field([1, 0, 0, 0]);
            assert_eq!(*(e + f), U256::from_words([1, 0, 0, 0]), "Modular wrap-around failed");

            // Addition that just reaches the modulus
            let g = create_field([
                0x3C208C16D87CFD46,
                0x97816A916871CA8D,
                0xB85045B68181585D,
                0x30644E72E131A029,
            ]);
            let h = create_field([1, 0, 0, 0]);
            assert_eq!(*(g + h), U256::from_words([0, 0, 0, 0]), "Addition to modulus failed");
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

}
