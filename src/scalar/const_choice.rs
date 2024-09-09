use crate::scalar::scalar::ModularUint;
use subtle::{Choice, ConditionallySelectable, CtOption};

/// A boolean value returned by constant-time `const fn`s.
// TODO: should be replaced by `subtle::Choice` or `CtOption`
// when `subtle` starts supporting const fns.
#[derive(Debug, Copy, Clone)]
pub struct ConstChoice(u64);

impl ConstChoice {
    /// The falsy value.
    pub const FALSE: Self = Self(0);

    /// The truthy value.
    pub const TRUE: Self = Self(u64::MAX);

    #[inline]
    #[allow(trivial_numeric_casts)]
    pub(crate) const fn as_u32_mask(&self) -> u32 {
        self.0 as u32
    }

    #[inline]
    pub(crate) const fn as_u64_mask(&self) -> u64 {
        self.0
    }

    /// Returns the truthy value if `value == 1`, and the falsy value if `value == 0`.
    /// Panics for other values.
    #[inline]
    pub(crate) const fn from_word_lsb(value: u64) -> Self {
        debug_assert!(value == 0 || value == 1);
        Self(value.wrapping_neg())
    }

    #[inline]
    pub(crate) const fn from_u32_lsb(value: u32) -> Self {
        debug_assert!(value == 0 || value == 1);
        #[allow(trivial_numeric_casts)]
        Self((value as u64).wrapping_neg())
    }

    #[inline]
    pub(crate) const fn from_u64_lsb(value: u64) -> Self {
        debug_assert!(value == 0 || value == 1);
        #[allow(trivial_numeric_casts)]
        Self((value as u64).wrapping_neg())
    }

    /// Returns the truthy value if `value != 0`, and the falsy value otherwise.
    #[inline]
    pub(crate) const fn from_u64_nonzero(value: u64) -> Self {
        Self::from_u64_lsb((value | value.wrapping_neg()) >> (u64::BITS - 1))
    }

    /// Returns the truthy value if `x == y`, and the falsy value otherwise.
    #[inline]
    pub(crate) const fn from_u64_eq(x: u64, y: u64) -> Self {
        Self::from_u64_nonzero(x ^ y).not()
    }

    /// Returns the truthy value if `x < y`, and the falsy value otherwise.
    #[inline]
    pub(crate) const fn from_u32_lt(x: u32, y: u32) -> Self {
        // See "Hacker's Delight" 2nd ed, section 2-12 (Comparison predicates)
        let bit = (((!x) & y) | (((!x) | y) & (x.wrapping_sub(y)))) >> (u32::BITS - 1);
        Self::from_u32_lsb(bit)
    }

    /// Returns the truthy value if `x < y`, and the falsy value otherwise.
    #[inline]
    pub(crate) const fn from_u64_lt(x: u64, y: u64) -> Self {
        // See "Hacker's Delight" 2nd ed, section 2-12 (Comparison predicates)
        let bit = (((!x) & y) | (((!x) | y) & (x.wrapping_sub(y)))) >> (u64::BITS - 1);
        Self::from_u64_lsb(bit)
    }

    /// Returns the truthy value if `x > y`, and the falsy value otherwise.
    #[inline]
    pub(crate) const fn from_u64_gt(x: u64, y: u64) -> Self {
        Self::from_u64_lt(y, x)
    }

    #[inline]
    pub(crate) const fn not(&self) -> Self {
        Self(!self.0)
    }

    #[inline]
    pub(crate) const fn or(&self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[inline]
    pub(crate) const fn and(&self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Return `b` if `self` is truthy, otherwise return `a`.
    #[inline]
    pub(crate) const fn select_u32(&self, a: u32, b: u32) -> u32 {
        a ^ (self.as_u32_mask() & (a ^ b))
    }

    /// Return `b` if `self` is truthy, otherwise return `a`.
    #[inline]
    pub(crate) const fn select_u64(&self, a: u64, b: u64) -> u64 {
        a ^ (self.as_u64_mask() & (a ^ b))
    }

    /// Return `x` if `self` is truthy, otherwise return 0.
    #[inline]
    pub(crate) const fn if_true_u32(&self, x: u32) -> u32 {
        x & self.as_u32_mask()
    }

    #[inline]
    pub(crate) const fn is_true_vartime(&self) -> bool {
        self.0 == ConstChoice::TRUE.0
    }

    #[inline]
    pub(crate) const fn to_u8(self) -> u8 {
        (self.0 as u8) & 1
    }

    /// WARNING: this method should only be used in contexts that aren't constant-time critical!
    #[inline]
    pub(crate) const fn to_bool_vartime(self) -> bool {
        self.to_u8() != 0
    }
}

impl From<ConstChoice> for Choice {
    #[inline]
    fn from(choice: ConstChoice) -> Self {
        Choice::from(choice.to_u8())
    }
}

impl From<Choice> for ConstChoice {
    #[inline]
    fn from(choice: Choice) -> Self {
        ConstChoice::from_word_lsb(choice.unwrap_u8() as u64)
    }
}

impl From<ConstChoice> for bool {
    fn from(choice: ConstChoice) -> Self {
        choice.is_true_vartime()
    }
}

impl PartialEq for ConstChoice {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

/// An equivalent of `subtle::CtOption` usable in a `const fn` context.
#[derive(Debug, Clone)]
pub struct ConstCtOption<T> {
    value: T,
    is_some: ConstChoice,
}

impl<T> ConstCtOption<T> {
    #[inline]
    pub(crate) const fn new(value: T, is_some: ConstChoice) -> Self {
        Self { value, is_some }
    }

    /// Returns a true [`ConstChoice`] if this value is `Some`.
    #[inline]
    pub const fn is_some(&self) -> ConstChoice {
        self.is_some
    }

    /// Returns a true [`ConstChoice`] if this value is `None`.
    #[inline]
    pub const fn is_none(&self) -> ConstChoice {
        self.is_some.not()
    }

    /// This returns the underlying value but panics if it is not `Some`.
    #[inline]
    pub fn unwrap(self) -> T {
        assert!(self.is_some.is_true_vartime());
        self.value
    }
}

impl<T> From<ConstCtOption<T>> for CtOption<T> {
    #[inline]
    fn from(value: ConstCtOption<T>) -> Self {
        CtOption::new(value.value, value.is_some.into())
    }
}

impl<T> From<ConstCtOption<T>> for Option<T> {
    #[inline]
    fn from(value: ConstCtOption<T>) -> Self {
        if value.is_some.into() {
            Some(value.value)
        } else {
            None
        }
    }
}

// Need specific implementations to work around the
// "destructors cannot be evaluated at compile-time" error
// See https://github.com/rust-lang/rust/issues/66753

impl<const LIMBS: usize> ConstCtOption<ModularUint<LIMBS>> {
    /// This returns the underlying value if it is `Some` or the provided value otherwise.
    #[inline]
    pub fn unwrap_or(self, def: ModularUint<LIMBS>) -> ModularUint<LIMBS> {
        ModularUint::conditional_select(&def, &self.value, self.is_some.into())
    }

    /// Returns the contained value, consuming the `self` value.
    ///
    /// # Panics
    ///
    /// Panics if the value is none with a custom panic message provided by
    /// `msg`.
    #[inline]
    pub fn expect(self, msg: &str) -> ModularUint<LIMBS> {
        assert!(self.is_some.is_true_vartime(), "{}", msg);
        self.value
    }
}

#[cfg(test)]
mod tests {
    use super::ConstChoice;

    #[test]
    fn from_u64_lsb() {
        assert_eq!(ConstChoice::from_u64_lsb(0), ConstChoice::FALSE);
        assert_eq!(ConstChoice::from_u64_lsb(1), ConstChoice::TRUE);
    }

    #[test]
    fn select_u32() {
        let a: u32 = 1;
        let b: u32 = 2;
        assert_eq!(ConstChoice::TRUE.select_u32(a, b), b);
        assert_eq!(ConstChoice::FALSE.select_u32(a, b), a);
    }

    #[test]
    fn select_u64() {
        let a: u64 = 1;
        let b: u64 = 2;
        assert_eq!(ConstChoice::TRUE.select_u64(a, b), b);
        assert_eq!(ConstChoice::FALSE.select_u64(a, b), a);
    }
}
