use crate::fields::extensions::FieldExtension;
use crate::fields::fp::{FieldExtensionTrait, FinitePrimeField, Fp};
use crate::fields::fp2::Fp2;
use crypto_bigint::{U2048, U256};
use num_traits::{Inv, One, Zero};
use std::ops::{Div, DivAssign, Mul, MulAssign};
use crate::fields::utils::u256_to_u2048;

pub(crate) type Fp6 = FieldExtension<6, 3, Fp2>;

impl Fp6 {
    pub(crate) fn residue_mul(&self) -> Self {
        Self([self.0[2].residue_mul(), self.0[0], self.0[1]])
    }
    fn characteristic() -> U2048 {
        let wide_p = u256_to_u2048(&Fp::characteristic());
        let wide_p2 = wide_p * wide_p;
        wide_p2 * wide_p2 * wide_p2
    }
}
impl FieldExtensionTrait<6, 3> for Fp6 {
    fn quadratic_non_residue() -> Self {
        Self::new(&[Fp2::zero(), Fp2::one(), Fp2::zero()])
    }
    fn frobenius(&self, exponent: usize) -> Self {
        // the following values are a bit difficult to compute. The reason
        // is that they involve operations up to p^11, which occupy a U4096
        // precision integer. This can be done no problem in the current framework.
        // However, to execute this in our current setup, the value of p needs to be
        // cast to the appropriate precision, and then the operation can be performed
        // Even the exponentiation made in Fp2 can handle exponentiating the
        // changing number of words. The issue is just doing all of this
        // on the fly induces a bit of overhead, so we just hardcode the values for
        // clarity and speed here.

        // For instance, to compute (p^2-1)/3
        // let wide_p = u256_to_512(p);
        // define_finite_prime_field!(Fp2, U512, 8, (wide_p*wide_p).to_be_string(), 1, 1)
        // let exponent = (wide_p * wide_p - Fp2::ONE)/Fp2::THREE

        // This is a lot of overhead, but it is doable with the components already provided
        // within should someone be interested
        let frobenius_coeff_fp6_c1: &[Fp2; 6] = &[
            //Fp2::quadratic_non_residue().pow( ( p^0 - 1) / 3)
            Fp2::new(&[Fp::one(), Fp::zero()]),
            //Fp2::quadratic_non_residue().pow( ( p^1 - 1) / 3)
            Fp2::new(&[
                Fp::new(U256::from_words([
                    0x99e39557176f553d,
                    0xb78cc310c2c3330c,
                    0x4c0bec3cf559b143,
                    0x2fb347984f7911f7,
                ])),
                Fp::new(U256::from_words([
                    0x1665d51c640fcba2,
                    0x32ae2a1d0b7c9dce,
                    0x4ba4cc8bd75a0794,
                    0x16c9e55061ebae20,
                ])),
            ]),
            //Fp2::quadratic_non_residue().pow( ( p^2 - 1) / 3)
            Fp2::new(&[
                Fp::new(U256::from_words([
                    0xe4bd44e5607cfd48,
                    0xc28f069fbb966e3d,
                    0x5e6dd9e7e0acccb0,
                    0x30644e72e131a029,
                ])),
                Fp::zero(),
            ]),
            //Fp2::quadratic_non_residue().pow( ( p^3 - 1) / 3)
            Fp2::new(&[
                Fp::new(U256::from_words([
                    0x7b746ee87bdcfb6d,
                    0x805ffd3d5d6942d3,
                    0xbaff1c77959f25ac,
                    0x856e078b755ef0a,
                ])),
                Fp::new(U256::from_words([
                    0x380cab2baaa586de,
                    0xfdf31bf98ff2631,
                    0xa9f30e6dec26094f,
                    0x4f1de41b3d1766f,
                ])),
            ]),
            //Fp2::quadratic_non_residue().pow( (p^4 - 1) / 3)
            Fp2::new(&[
                Fp::new(U256::from_words([
                    0x5763473177fffffe,
                    0xd4f263f1acdb5c4f,
                    0x59e26bcea0d48bac,
                    0x0,
                ])),
                Fp::zero(),
            ]),
            //Fp2::quadratic_non_residue().pow( (p^5 - 1) / 3)
            Fp2::new(&[
                Fp::new(U256::from_words([
                    0x62e913ee1dada9e4,
                    0xf71614d4b0b71f3a,
                    0x699582b87809d9ca,
                    0x28be74d4bb943f51,
                ])),
                Fp::new(U256::from_words([
                    0xedae0bcec9c7aac7,
                    0x54f40eb4c3f6068d,
                    0xc2b86abcbe01477a,
                    0x14a88ae0cb747b99,
                ])),
            ]),
        ];
        let frobenius_coeff_fp6_c2: &[Fp2; 6] = &[
            // Fp2::quadratic_non_residue().pow( (2 * p^0 - 2) / 3)
            Fp2::new(&[Fp::one(), Fp::zero()]),
            // Fp2::quadratic_non_residue().pow( (2 * p^1 - 2) / 3)
            Fp2::new(&[
                Fp::new(U256::from_words([
                    0x848a1f55921ea762,
                    0xd33365f7be94ec72,
                    0x80f3c0b75a181e84,
                    0x5b54f5e64eea801,
                ])),
                Fp::new(U256::from_words([
                    0xc13b4711cd2b8126,
                    0x3685d2ea1bdec763,
                    0x9f3a80b03b0b1c92,
                    0x2c145edbe7fd8aee,
                ])),
            ]),
            // Fp2::quadratic_non_residue().pow( (2 * p^2 - 2) / 3)
            Fp2::new(&[
                Fp::new(U256::from_words([
                    0x5763473177fffffe,
                    0xd4f263f1acdb5c4f,
                    0x59e26bcea0d48bac,
                    0x0,
                ])),
                Fp::new(U256::from_words([0x0, 0x0, 0x0, 0x0])),
            ]),
            // Fp2::quadratic_non_residue().pow( (2 * p^3 - 2) / 3)
            Fp2::new(&[
                Fp::new(U256::from_words([
                    0xe1a92bc3ccbf066,
                    0xe633094575b06bcb,
                    0x19bee0f7b5b2444e,
                    0xbc58c6611c08dab,
                ])),
                Fp::new(U256::from_words([
                    0x5fe3ed9d730c239f,
                    0xa44a9e08737f96e5,
                    0xfeb0f6ef0cd21d04,
                    0x23d5e999e1910a12,
                ])),
            ]),
            // Fp2::quadratic_non_residue().pow( (2 * p^4 - 2) / 3)
            Fp2::new(&[
                Fp::new(U256::from_words([
                    0xe4bd44e5607cfd48,
                    0xc28f069fbb966e3d,
                    0x5e6dd9e7e0acccb0,
                    0x30644e72e131a029,
                ])),
                Fp::new(U256::from_words([0x0, 0x0, 0x0, 0x0])),
            ]),
            // Fp2::quadratic_non_residue().pow( (2 * p^5 - 2) / 3)
            Fp2::new(&[
                Fp::new(U256::from_words([
                    0xa97bda050992657f,
                    0xde1afb54342c724f,
                    0x1d9da40771b6f589,
                    0x1ee972ae6a826a7d,
                ])),
                Fp::new(U256::from_words([
                    0x5721e37e70c255c9,
                    0x54326430418536d1,
                    0xd2b513cdbb257724,
                    0x10de546ff8d4ab51,
                ])),
            ]),
        ];
        Self::new(&[
            <Fp2 as FieldExtensionTrait<2, 2>>::frobenius(&self.0[0], exponent),
            <Fp2 as FieldExtensionTrait<2, 2>>::frobenius(&self.0[1], exponent)
                * frobenius_coeff_fp6_c1[exponent],
            <Fp2 as FieldExtensionTrait<2, 2>>::frobenius(&self.0[2], exponent)
                * frobenius_coeff_fp6_c2[exponent],
        ])
    }

    fn sqrt(&self) -> Self {
        todo!()
    }

    fn square(&self) -> Self {
        let t0 = <Fp2 as FieldExtensionTrait<2, 2>>::square(&self.0[0]);
        let cross = self.0[0] * self.0[1];
        let t1 = cross + cross;
        let mut t2 = self.0[0] - self.0[1] + self.0[2];
        t2 = <Fp2 as FieldExtensionTrait<2, 2>>::square(&t2);
        let bc = self.0[1] * self.0[2];
        let s3 = bc + bc;
        let mut s4 = self.0[2];
        s4 = <Fp2 as FieldExtensionTrait<2, 2>>::square(&s4);

        Self([
            t0 + s3.residue_mul(),
            t1 + s4.residue_mul(),
            t1 + t2 + s3 - t0 - s4,
        ])
    }
}
impl Mul for Fp6 {
    type Output = Self;
    fn mul(self, other: Self) -> Self::Output {
        // This is the exact same strategy as multiplication in Fp2
        // see the doc string therefore more details
        let t0 = self.0[0] * other.0[0];
        let t1 = self.0[1] * other.0[1];
        let t2 = self.0[2] * other.0[2];

        Self([
            ((self.0[1] + self.0[2]) * (other.0[1] + other.0[2]) - t1 - t2).residue_mul() + t0,
            (self.0[0] + self.0[1]) * (other.0[0] + other.0[1]) - t0 - t1 + t2.residue_mul(),
            (self.0[0] + self.0[2]) * (other.0[0] + other.0[2]) - t0 + t1 - t2,
        ])
    }
}
impl MulAssign for Fp6 {
    fn mul_assign(&mut self, other: Self) {
        *self = *self * other;
    }
}

impl Inv for Fp6 {
    type Output = Self;
    fn inv(self) -> Self::Output {
        let t0 = <Fp2 as FieldExtensionTrait<2, 2>>::square(&self.0[0])
            - self.0[1] * self.0[2].residue_mul();
        let t1 = <Fp2 as FieldExtensionTrait<2, 2>>::square(&self.0[2]).residue_mul()
            - self.0[0] * self.0[1];
        let t2 = <Fp2 as FieldExtensionTrait<2, 2>>::square(&self.0[1]) - self.0[0] * self.0[2];

        let inverse = ((self.0[2] * t1 + self.0[1] * t2).residue_mul() + self.0[0] * t0).inv();
        Self([inverse * t0, inverse * t1, inverse * t2])
    }
}

impl One for Fp6 {
    fn one() -> Self {
        Self::new(&[Fp2::one(), Fp2::zero(), Fp2::zero()])
    }
    fn is_one(&self) -> bool {
        self.0[0].is_one() && self.0[0].is_zero() && self.0[0].is_zero()
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Div for Fp6 {
    type Output = Self;
    fn div(self, other: Self) -> Self::Output {
        self * other.inv()
    }
}
impl DivAssign for Fp6 {
    fn div_assign(&mut self, other: Self) {
        *self = *self / other;
    }
}

impl FieldExtensionTrait<12, 2> for Fp6 {
    fn quadratic_non_residue() -> Self {
        <Fp6 as FieldExtensionTrait<6, 3>>::quadratic_non_residue()
    }
    fn frobenius(&self, exponent: usize) -> Self {
        <Fp6 as FieldExtensionTrait<6, 3>>::frobenius(self, exponent)
    }
    fn sqrt(&self) -> Self {
        <Fp6 as FieldExtensionTrait<6, 3>>::sqrt(self)
    }
    fn square(&self) -> Self {
        <Fp6 as FieldExtensionTrait<6, 3>>::square(self)
    }
}
