use crate::scalar::const_choice::{ConstChoice, ConstCtOption};
use crate::scalar::scalar::ModularUint;
use subtle::CtOption;
macro_rules! safegcd_nlimbs {
    ($bits:expr) => {
        ($bits + 64).div_ceil(62)
    };
}

#[derive(Clone, Copy, Debug)]
pub(super) struct NonModularUInt<const UNSAT_L: usize>(pub [u64; UNSAT_L]);

impl<const UNSAT_L: usize> NonModularUInt<UNSAT_L> {
    /// Number of bits in each limb.
    pub const LIMB_BITS: usize = 62;

    /// Mask, in which the 62 lowest bits are 1.
    pub const MASK: u64 = u64::MAX >> (64 - Self::LIMB_BITS);

    /// Representation of -1.
    pub const MINUS_ONE: Self = Self([Self::MASK; UNSAT_L]);

    /// Representation of 0.
    pub const ZERO: Self = Self([0; UNSAT_L]);

    /// Representation of 1.
    pub const ONE: Self = {
        let mut ret = Self::ZERO;
        ret.0[0] = 1;
        ret
    };

    /// Convert from 32/64-bit saturated representation used by `Uint` to the 62-bit unsaturated
    /// representation used by `UnsatInt`.
    ///
    /// Returns a big unsigned integer as an array of 62-bit chunks, which is equal modulo
    /// 2 ^ (62 * S) to the input big unsigned integer stored as an array of 64-bit chunks.
    ///
    /// The ordering of the chunks in these arrays is little-endian.
    #[allow(clippy::unnecessary_cast, clippy::wrong_self_convention, clippy::eq_op)]
    pub const fn from_uint<const SAT_L: usize>(input: &ModularUint<SAT_L>) -> Self {
        if UNSAT_L != safegcd_nlimbs!(SAT_L * u64::BITS as usize) {
            panic!("incorrect number of limbs");
        }
        let mut output = [0; UNSAT_L];
        {
            const fn min(a: usize, b: usize) -> usize {
                if a > b {
                    b
                } else {
                    a
                }
            }
            let total = min(
                input.as_words().len() * u64::BITS as usize,
                output.len() * 62,
            );
            let mut bits = 0;
            while bits < total {
                let (i, o) = (bits % u64::BITS as usize, bits % 62);
                output[bits / 62] |=
                    ((input.as_words()[bits / u64::BITS as usize] >> i) as u64) << o;
                bits += min(u64::BITS as usize - i, 62 - o);
            }
            let mask = (<u64>::MAX as u64) >> (<u64>::BITS as usize - 62);
            let mut filled = total / 62 + if total % 62 > 0 { 1 } else { 0 };
            while filled > 0 {
                filled -= 1;
                output[filled] &= mask;
            }
        };
        Self(output)
    }

    /// Convert from 62-bit unsaturated representation used by `UnsatInt` to the 32/64-bit saturated
    /// representation used by `Uint`.
    ///
    /// Returns a big unsigned integer as an array of 32/64-bit chunks, which is equal modulo
    /// 2 ^ (64 * S) to the input big unsigned integer stored as an array of 62-bit chunks.
    ///
    /// The ordering of the chunks in these arrays is little-endian.
    #[allow(clippy::unnecessary_cast, clippy::wrong_self_convention, clippy::eq_op)]
    pub const fn to_uint<const SAT_LIMBS: usize>(&self) -> ModularUint<SAT_LIMBS> {
        debug_assert!(
            !self.is_negative().to_bool_vartime(),
            "can't convert negative number to Uint"
        );

        if UNSAT_L != safegcd_nlimbs!(SAT_LIMBS * u64::BITS as usize) {
            panic!("incorrect number of limbs");
        }
        let mut ret = [0u64; SAT_LIMBS];
        {
            const fn min(a: usize, b: usize) -> usize {
                if a > b {
                    b
                } else {
                    a
                }
            }
            let total = min(self.0.len() * 62, ret.len() * u64::BITS as usize);
            let mut bits = 0;
            while bits < total {
                let (i, o) = (bits % 62, bits % u64::BITS as usize);
                ret[bits / u64::BITS as usize] |= (((&self.0)[bits / 62] >> i) as u64) << o;
                bits += min(62 - i, u64::BITS as usize - o);
            }
            let mask = (<u64>::MAX as u64) >> (<u64>::BITS as usize - u64::BITS as usize);
            let mut filled =
                total / u64::BITS as usize + if total % u64::BITS as usize > 0 { 1 } else { 0 };
            while filled > 0 {
                filled -= 1;
                ret[filled] &= mask;
            }
        };
        ModularUint::from_words(ret)
    }
    pub const fn add(&self, other: &Self) -> Self {
        let (mut ret, mut carry) = (Self::ZERO, 0);
        let mut i = 0;

        while i < UNSAT_L {
            let sum = self.0[i] + other.0[i] + carry;
            ret.0[i] = sum & Self::MASK;
            carry = sum >> Self::LIMB_BITS;
            i += 1;
        }

        ret
    }
    pub const fn mul(&self, other: i64) -> Self {
        let mut ret = Self::ZERO;
        let (other, mut carry, mask) = if other < 0 {
            (-other, -other as u64, Self::MASK)
        } else {
            (other, 0, 0)
        };

        let mut i = 0;
        while i < UNSAT_L {
            let sum = (carry as u128) + ((self.0[i] ^ mask) as u128) * (other as u128);
            ret.0[i] = sum as u64 & Self::MASK;
            carry = (sum >> Self::LIMB_BITS) as u64;
            i += 1;
        }

        ret
    }

    /// Const fn equivalent for `Neg::neg`.
    pub const fn neg(&self) -> Self {
        let (mut ret, mut carry) = (Self::ZERO, 1);
        let mut i = 0;

        while i < UNSAT_L {
            let sum = (self.0[i] ^ Self::MASK) + carry;
            ret.0[i] = sum & Self::MASK;
            carry = sum >> Self::LIMB_BITS;
            i += 1;
        }

        ret
    }
    pub const fn shr(&self) -> Self {
        let mut ret = Self::ZERO;
        ret.0[UNSAT_L - 1] = self
            .is_negative()
            .select_u64(ret.0[UNSAT_L - 1], Self::MASK);

        let mut i = 0;
        while i < UNSAT_L - 1 {
            ret.0[i] = self.0[i + 1];
            i += 1;
        }

        ret
    }

    pub const fn eq(&self, other: &Self) -> ConstChoice {
        let mut ret = ConstChoice::TRUE;
        let mut i = 0;

        while i < UNSAT_L {
            ret = ret.and(ConstChoice::from_u64_eq(self.0[i], other.0[i]));
            i += 1;
        }

        ret
    }

    pub const fn is_negative(&self) -> ConstChoice {
        ConstChoice::from_u64_gt(self.0[UNSAT_L - 1], Self::MASK >> 1)
    }

    /// Returns the lowest 62 bits of the current number.
    pub const fn lowest(&self) -> u64 {
        self.0[0]
    }
    pub const fn select(a: &Self, b: &Self, choice: ConstChoice) -> Self {
        let mut ret = Self::ZERO;
        let mut i = 0;

        while i < UNSAT_L {
            ret.0[i] = choice.select_u64(a.0[i], b.0[i]);
            i += 1;
        }

        ret
    }
    pub const fn leading_zeros(&self) -> u32 {
        let mut count = 0;
        let mut i = UNSAT_L;
        let mut nonzero_limb_not_encountered = ConstChoice::TRUE;

        while i > 0 {
            i -= 1;
            let l = self.0[i];
            let z = l.leading_zeros() - 2;
            count += nonzero_limb_not_encountered.if_true_u32(z);
            nonzero_limb_not_encountered =
                nonzero_limb_not_encountered.and(ConstChoice::from_u64_nonzero(l).not());
        }

        count
    }

    /// Calculate the number of bits in this value (i.e. index of the highest bit) in constant time.
    pub const fn bits(&self) -> u32 {
        (UNSAT_L as u32 * 62) - self.leading_zeros()
    }
}
#[derive(Clone, Debug, Copy)]
pub struct BernsteinYangInverter<const SAT_L: usize, const UNSAT_L: usize> {
    pub(super) modulus: NonModularUInt<UNSAT_L>,
    adjuster: NonModularUInt<UNSAT_L>,
    /// Multiplicative inverse of the modulus modulo 2^62
    inverse: i64,
}
/// Type of the Bernstein-Yang transition matrix multiplied by 2^62
type Matrix = [[i64; 2]; 2];

impl<const SAT_L: usize, const UNSAT_L: usize> BernsteinYangInverter<SAT_L, UNSAT_L> {
    /// Creates the inverter for specified modulus and adjusting parameter.
    pub const fn new(modulus: &ModularUint<SAT_L>, adjuster: &ModularUint<SAT_L>) -> Self {
        Self {
            modulus: NonModularUInt::from_uint(modulus),
            adjuster: NonModularUInt::from_uint(adjuster),
            inverse: inv_mod2_62(modulus.as_words()),
        }
    }

    /// Returns either the adjusted modular multiplicative inverse for the argument or `None`
    /// depending on invertibility of the argument, i.e. its coprimality with the modulus
    pub const fn inv(&self, value: &ModularUint<SAT_L>) -> ConstCtOption<ModularUint<SAT_L>> {
        let (d, f) = divsteps(
            self.adjuster,
            self.modulus,
            NonModularUInt::from_uint(value),
            self.inverse,
        );

        // At this point the absolute value of "f" equals the greatest common divisor of the
        // integer to be inverted and the modulus the inverter was created for.
        // Thus, if "f" is neither 1 nor -1, then the sought inverse does not exist.
        let antiunit = f.eq(&NonModularUInt::MINUS_ONE);
        let ret = self.norm(d, antiunit);
        let is_some = f.eq(&NonModularUInt::ONE).or(antiunit);
        ConstCtOption::new(ret.to_uint(), is_some)
    }

    /// Returns either "value (mod M)" or "-value (mod M)", where M is the modulus the inverter
    /// was created for, depending on "negate", which determines the presence of "-" in the used
    /// formula. The input integer lies in the interval (-2 * M, M).
    const fn norm(
        &self,
        mut value: NonModularUInt<UNSAT_L>,
        negate: ConstChoice,
    ) -> NonModularUInt<UNSAT_L> {
        value = NonModularUInt::select(&value, &value.add(&self.modulus), value.is_negative());
        value = NonModularUInt::select(&value, &value.neg(), negate);
        value = NonModularUInt::select(&value, &value.add(&self.modulus), value.is_negative());
        value
    }
}
impl<const SAT_L: usize, const UNSAT_L: usize> BernsteinYangInverter<SAT_L, UNSAT_L> {
    #[allow(dead_code)]
    fn invert(&self, value: &ModularUint<SAT_L>) -> CtOption<ModularUint<SAT_L>> {
        self.inv(value).into()
    }
}

/// Returns the multiplicative inverse of the argument modulo 2^62. The implementation is based
/// on the Hurchalla's method for computing the multiplicative inverse modulo a power of two.
///
/// For better understanding the implementation, the following paper is recommended:
/// J. Hurchalla, "An Improved Integer Multiplicative Inverse (modulo 2^w)",
/// <https://arxiv.org/pdf/2204.04342.pdf>
///
/// Variable time with respect to the number of words in `value`, however that number will be
/// fixed for a given integer size.
const fn inv_mod2_62(value: &[u64]) -> i64 {
    let value = value[0];

    let x = value.wrapping_mul(3) ^ 2;
    let y = 1u64.wrapping_sub(x.wrapping_mul(value));
    let (x, y) = (x.wrapping_mul(y.wrapping_add(1)), y.wrapping_mul(y));
    let (x, y) = (x.wrapping_mul(y.wrapping_add(1)), y.wrapping_mul(y));
    let (x, y) = (x.wrapping_mul(y.wrapping_add(1)), y.wrapping_mul(y));
    (x.wrapping_mul(y.wrapping_add(1)) & (u64::MAX >> 2)) as i64
}

/// Algorithm `divsteps2` to compute (δₙ, fₙ, gₙ) = divstepⁿ(δ, f, g) as described in Figure 10.1
/// of <https://eprint.iacr.org/2019/266.pdf>.
///
/// This version runs in a fixed number of iterations relative to the highest bit of `f` or `g`
/// as described in Figure 11.1.
const fn divsteps<const L: usize>(
    mut e: NonModularUInt<L>,
    f_0: NonModularUInt<L>,
    mut g: NonModularUInt<L>,
    inverse: i64,
) -> (NonModularUInt<L>, NonModularUInt<L>) {
    let mut d = NonModularUInt::ZERO;
    let mut f = f_0;
    let mut delta = 1;
    let mut matrix;
    let mut i = 0;
    let m = iterations(f_0.bits(), g.bits());

    while i < m {
        (delta, matrix) = jump(&f.0, &g.0, delta);
        (f, g) = fg(f, g, matrix);
        (d, e) = de(&f_0, inverse, matrix, d, e);
        i += 1;
    }

    debug_assert!(g.eq(&NonModularUInt::ZERO).to_bool_vartime());
    (d, f)
}

/// Returns the Bernstein-Yang transition matrix multiplied by 2^62 and the new value of the
/// delta variable for the 62 basic steps of the Bernstein-Yang method, which are to be
/// performed sequentially for specified initial values of f, g and delta
const fn jump(f: &[u64], g: &[u64], mut delta: i64) -> (i64, Matrix) {
    // This function is defined because the method "min" of the i64 type is not constant
    const fn min(a: i64, b: i64) -> i64 {
        if a > b {
            b
        } else {
            a
        }
    }

    let (mut steps, mut f, mut g) = (62, f[0] as i64, g[0] as i128);
    let mut t: Matrix = [[1, 0], [0, 1]];

    loop {
        let zeros = min(steps, g.trailing_zeros() as i64);
        (steps, delta, g) = (steps - zeros, delta + zeros, g >> zeros);
        t[0] = [t[0][0] << zeros, t[0][1] << zeros];

        if steps == 0 {
            break;
        }
        if delta > 0 {
            (delta, f, g) = (-delta, g as i64, -f as i128);
            (t[0], t[1]) = (t[1], [-t[0][0], -t[0][1]]);
        }

        // The formula (3 * x) xor 28 = -1 / x (mod 32) for an odd integer x in the two's
        // complement code has been derived from the formula (3 * x) xor 2 = 1 / x (mod 32)
        // attributed to Peter Montgomery.
        let mask = (1 << min(min(steps, 1 - delta), 5)) - 1;
        let w = (g as i64).wrapping_mul(f.wrapping_mul(3) ^ 28) & mask;

        t[1] = [t[0][0] * w + t[1][0], t[0][1] * w + t[1][1]];
        g += w as i128 * f as i128;
    }

    (delta, t)
}

/// Returns the updated values of the variables f and g for specified initial ones and
/// Bernstein-Yang transition matrix multiplied by 2^62.
///
/// The returned vector is "matrix * (f, g)' / 2^62", where "'" is the transpose operator.
const fn fg<const L: usize>(
    f: NonModularUInt<L>,
    g: NonModularUInt<L>,
    t: Matrix,
) -> (NonModularUInt<L>, NonModularUInt<L>) {
    (
        f.mul(t[0][0]).add(&g.mul(t[0][1])).shr(),
        f.mul(t[1][0]).add(&g.mul(t[1][1])).shr(),
    )
}

/// Returns the updated values of the variables d and e for specified initial ones and
/// Bernstein-Yang transition matrix multiplied by 2^62.
///
/// The returned vector is congruent modulo M to "matrix * (d, e)' / 2^62 (mod M)", where M is the
/// modulus the inverter was created for and "'" stands for the transpose operator.
///
/// Both the input and output values lie in the interval (-2 * M, M).
const fn de<const L: usize>(
    modulus: &NonModularUInt<L>,
    inverse: i64,
    t: Matrix,
    d: NonModularUInt<L>,
    e: NonModularUInt<L>,
) -> (NonModularUInt<L>, NonModularUInt<L>) {
    let mask = NonModularUInt::<L>::MASK as i64;
    let mut md =
        t[0][0] * d.is_negative().to_u8() as i64 + t[0][1] * e.is_negative().to_u8() as i64;
    let mut me =
        t[1][0] * d.is_negative().to_u8() as i64 + t[1][1] * e.is_negative().to_u8() as i64;

    let cd = t[0][0]
        .wrapping_mul(d.lowest() as i64)
        .wrapping_add(t[0][1].wrapping_mul(e.lowest() as i64))
        & mask;

    let ce = t[1][0]
        .wrapping_mul(d.lowest() as i64)
        .wrapping_add(t[1][1].wrapping_mul(e.lowest() as i64))
        & mask;

    md -= (inverse.wrapping_mul(cd).wrapping_add(md)) & mask;
    me -= (inverse.wrapping_mul(ce).wrapping_add(me)) & mask;

    let cd = d.mul(t[0][0]).add(&e.mul(t[0][1])).add(&modulus.mul(md));
    let ce = d.mul(t[1][0]).add(&e.mul(t[1][1])).add(&modulus.mul(me));

    (cd.shr(), ce.shr())
}

/// Compute the number of iterations required to compute Bernstein-Yang on the two values.
///
/// Adapted from Fig 11.1 of <https://eprint.iacr.org/2019/266.pdf>
///
/// The paper proves that the algorithm will converge (i.e. `g` will be `0`) in all cases when
/// the algorithm runs this particular number of iterations.
///
/// Once `g` reaches `0`, continuing to run the algorithm will have no effect.
// TODO(tarcieri): improved bounds using https://github.com/sipa/safegcd-bounds
pub(crate) const fn iterations(f_bits: u32, g_bits: u32) -> usize {
    // Select max of `f_bits`, `g_bits`
    let d = ConstChoice::from_u32_lt(f_bits, g_bits).select_u32(f_bits, g_bits);
    let addend = ConstChoice::from_u32_lt(d, 46).select_u32(57, 80);
    ((49 * d + addend) / 17) as usize
}

#[cfg(test)]
mod tests {
    use super::iterations;

    type UnsatInt = super::NonModularUInt<4>;

    impl<const L: usize> PartialEq for super::NonModularUInt<L> {
        fn eq(&self, other: &Self) -> bool {
            self.eq(other).to_bool_vartime()
        }
    }

    #[test]
    fn iterations_boundary_conditions() {
        assert_eq!(iterations(0, 0), 4);
        assert_eq!(iterations(0, 45), 134);
        assert_eq!(iterations(0, 46), 135);
    }

    #[test]
    fn unsatint_add() {
        assert_eq!(UnsatInt::ZERO, UnsatInt::ZERO.add(&UnsatInt::ZERO));
        assert_eq!(UnsatInt::ONE, UnsatInt::ONE.add(&UnsatInt::ZERO));
        assert_eq!(UnsatInt::ZERO, UnsatInt::MINUS_ONE.add(&UnsatInt::ONE));
    }

    #[test]
    fn unsatint_mul() {
        assert_eq!(UnsatInt::ZERO, UnsatInt::ZERO.mul(0));
        assert_eq!(UnsatInt::ZERO, UnsatInt::ZERO.mul(1));
        assert_eq!(UnsatInt::ZERO, UnsatInt::ONE.mul(0));
        assert_eq!(UnsatInt::ZERO, UnsatInt::MINUS_ONE.mul(0));
        assert_eq!(UnsatInt::ONE, UnsatInt::ONE.mul(1));
        assert_eq!(UnsatInt::MINUS_ONE, UnsatInt::MINUS_ONE.mul(1));
    }

    #[test]
    fn unsatint_neg() {
        assert_eq!(UnsatInt::ZERO, UnsatInt::ZERO.neg());
        assert_eq!(UnsatInt::MINUS_ONE, UnsatInt::ONE.neg());
        assert_eq!(UnsatInt::ONE, UnsatInt::MINUS_ONE.neg());
    }

    #[test]
    fn unsatint_is_negative() {
        assert!(!UnsatInt::ZERO.is_negative().to_bool_vartime());
        assert!(!UnsatInt::ONE.is_negative().to_bool_vartime());
        assert!(UnsatInt::MINUS_ONE.is_negative().to_bool_vartime());
    }

    #[test]
    fn unsatint_shr() {
        let n = super::NonModularUInt([
            0,
            1211048314408256470,
            1344008336933394898,
            3913497193346473913,
            2764114971089162538,
            4,
        ]);

        assert_eq!(
            &n.shr().0,
            &[
                1211048314408256470,
                1344008336933394898,
                3913497193346473913,
                2764114971089162538,
                4,
                0
            ]
        );
    }
}
