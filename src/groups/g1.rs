//! This creates the specific instance of G1 for BN254. Namely,
//! $\mathbb{G}_1=(r)E(\mathbb{F}_p)=E(\mathbb{F}_p)$, where we take advantage of the fact that
//! for BN254's G1, the r-torsion in the base field is the entire curve itself. There are
//! therefore no subgroup checks needed for membership in G1 other than the point being on the
//! curve itself.
//!
//! The curve also has a generator (1,2), which is used to create points on the curve from a scalar
//! value.
//!
//! Notice that there is not much here left to specialise to G1 on BN254! This abstraction should
//! make the implementation of the more complicated G2 easier to handle.

use crate::fields::fp::{FieldExtensionTrait, FinitePrimeField, Fp};
use crate::groups::group::{GroupAffine, GroupError, GroupProjective, GroupTrait};
use crate::hasher::Expander;
use crate::svdw::{SvdW, SvdWTrait};
use crypto_bigint::rand_core::CryptoRngCore;
use num_traits::{One, Zero};
use subtle::{Choice, ConstantTimeEq};

#[allow(dead_code)]
type G1Affine = GroupAffine<1, 1, Fp>;
#[allow(dead_code)]
type G1Projective = GroupProjective<1, 1, Fp>;

impl GroupTrait<1, 1, Fp> for G1Affine {
    fn generator() -> Self {
        Self {
            x: Fp::one(),
            y: Fp::from(2),
            infinity: Choice::from(0u8),
        }
    }

    /// the endomorphism is used in subgroup checks, but since we don't use this for G1, it
    /// doesn't actually matter what this is set to.
    fn endomorphism(&self) -> Self {
        Self::generator()
    }
    fn rand<R: CryptoRngCore>(rng: &mut R) -> Self {
        Self::from(G1Projective::rand(rng))
    }
    fn hash_to_curve<E: Expander>(exp: &E, msg: &[u8]) -> Result<Self, GroupError> {
        match G1Projective::hash_to_curve(exp, msg) {
            Ok(d) => Ok(Self::from(d)),
            Err(e) => Err(e),
        }
    }
    fn sign_message<E: Expander>(exp: &E, msg: &[u8], private_key: Fp) -> Result<Self, GroupError> {
        match G1Projective::sign_message(exp, msg, private_key) {
            Ok(d) => Ok(Self::from(d)),
            Err(e) => Err(e),
        }
    }
}
#[allow(dead_code)]
impl G1Affine {
    /// this needs to be defined in order to have user interaction, but currently
    /// is only visible in tests, and therefore is seen by the linter as unused
    pub(crate) fn new(v: [Fp; 2]) -> Result<Self, GroupError> {
        let _g1affine_is_on_curve = |x: &Fp, y: &Fp, z: &Choice| -> Choice {
            let y2 = <Fp as FieldExtensionTrait<1, 1>>::square(y);
            let x2 = <Fp as FieldExtensionTrait<1, 1>>::square(x);
            let lhs = y2 - (x2 * (*x));
            let rhs = <Fp as FieldExtensionTrait<1, 1>>::curve_constant();
            // println!("{:?}, {:?}", lhs, rhs);
            lhs.ct_eq(&rhs) | *z
        };

        let _g1affine_is_torsion_free = |_x: &Fp, _y: &Fp, _z: &Choice| -> Choice {
            // every point in G1 on the curve is in the r-torsion of BN254
            Choice::from(1u8)
        };
        let is_on_curve: Choice = _g1affine_is_on_curve(&v[0], &v[1], &Choice::from(0u8));
        match bool::from(is_on_curve) {
            true => {
                // println!("Is on curve!");
                let is_in_torsion: Choice =
                    _g1affine_is_torsion_free(&v[0], &v[1], &Choice::from(0u8));
                match bool::from(is_in_torsion) {
                    true => Ok(Self {
                        x: v[0],
                        y: v[1],
                        infinity: Choice::from(0u8),
                    }),
                    _ => Err(GroupError::NotInSubgroup),
                }
            }
            false => Err(GroupError::NotOnCurve),
        }
    }
}
impl GroupTrait<1, 1, Fp> for G1Projective {
    fn generator() -> Self {
        Self::from(G1Affine::generator())
    }
    fn endomorphism(&self) -> Self {
        Self::generator()
    }
    fn rand<R: CryptoRngCore>(rng: &mut R) -> Self {
        &Self::generator()
            * &<Fp as FieldExtensionTrait<1, 1>>::rand(rng)
                .value()
                .to_le_bytes()
    }
    fn hash_to_curve<E: Expander>(exp: &E, msg: &[u8]) -> Result<Self, GroupError> {
        const COUNT: usize = 2;
        const L: usize = 48;
        let scalars = exp
            .hash_to_field(msg, COUNT, L)
            .expect("Hashing to base field failed");
        match SvdW::<1, 1, Fp>::precompute_constants(Fp::from(0), Fp::from(3)) {
            Ok(bn254_g1_svdw) => {
                let a = G1Projective::from(
                    bn254_g1_svdw
                        .unchecked_map_to_point(scalars[0])
                        .expect("Failed to hash"),
                );
                let b = G1Projective::from(
                    bn254_g1_svdw
                        .unchecked_map_to_point(scalars[1])
                        .expect("Failed to hash"),
                );
                Ok(&a + &b)
            }
            _ => Err(GroupError::CannotHashToGroup),
        }
    }
    fn sign_message<E: Expander>(exp: &E, msg: &[u8], private_key: Fp) -> Result<Self, GroupError> {
        if let Ok(d) = Self::hash_to_curve(exp, msg) {
            return Ok(&d * &private_key.value().to_le_bytes());
        }
        Err(GroupError::CannotHashToGroup)
    }
}
impl G1Projective {
    pub(crate) fn new(v: [Fp; 3]) -> Result<Self, GroupError> {
        let _g1projective_is_on_curve = |x: &Fp, y: &Fp, z: &Fp| -> Choice {
            let y2 = <Fp as FieldExtensionTrait<1, 1>>::square(y);
            let x2 = <Fp as FieldExtensionTrait<1, 1>>::square(x);
            let z2 = <Fp as FieldExtensionTrait<1, 1>>::square(z);
            let lhs = y2 * (*z);
            let rhs = x2 * (*x) + z2 * (*z) * <Fp as FieldExtensionTrait<1, 1>>::curve_constant();
            // println!("{:?}, {:?}", lhs.value(), rhs.value());
            lhs.ct_eq(&rhs) | Choice::from(z.is_zero() as u8)
        };
        let _g1projective_is_torsion_free =
            |_x: &Fp, _y: &Fp, _z: &Fp| -> Choice { Choice::from(1u8) };
        let is_on_curve: Choice = _g1projective_is_on_curve(&v[0], &v[1], &v[2]);
        match bool::from(is_on_curve) {
            true => {
                // println!("Is on curve!");
                let is_in_torsion: Choice = _g1projective_is_torsion_free(&v[0], &v[1], &v[2]);
                match bool::from(is_in_torsion) {
                    true => Ok(Self {
                        x: v[0],
                        y: v[1],
                        z: v[2],
                    }),
                    false => Err(GroupError::NotOnCurve),
                }
            }
            false => Err(GroupError::NotOnCurve),
        }
    }
}
impl<'a> From<&'a [Fp; 2]> for G1Projective {
    fn from(value: &'a [Fp; 2]) -> Self {
        G1Affine::new(*value)
            .expect("Conversion to affine failed")
            .into()
    }
}
impl From<[Fp; 2]> for G1Projective {
    fn from(value: [Fp; 2]) -> Self {
        G1Projective::from(&value)
    }
}
/// This test suite takes time, the biggest culprit of which is the multiplication. Really the
/// biggest bottleneck is assuredly the loading of the reference data from disk. The
/// multiplication just takes time due to the debugging symbols created by default when invoking
/// all the machinery required for multiplication of elements in the group. However, compiling
/// the code in release mode (without debug symbols + optimizations) gives the desired performance
/// of all arithmetic operations.
///
/// For instance, `cargo test --lib groups::g1::tests` takes ~22 seconds, while
/// `cargo test --release --lib groups::g1::tests` takes ~1 second. Keeping in mind that this
/// includes doing reference comparisons to sane values for 1000 values for multiple tests and
/// loads the data and processes it from disk at each test,
/// this means each group operation takes sub millisecond time, which is nice.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::fields::fp::FinitePrimeField;
    use serde::{Deserialize, Serialize};
    #[allow(unused_imports)]
    use std::{fs, path::Path};

    #[derive(Serialize, Deserialize)]
    struct _G1Projective {
        x: String,
        y: String,
        z: String,
    }
    #[derive(Serialize, Deserialize)]
    struct _G1 {
        a: Vec<_G1Projective>,
        b: Vec<_G1Projective>,
        r: Vec<String>,
        add: Vec<_G1Projective>,
        dbl: Vec<_G1Projective>,
        mul: Vec<_G1Projective>,
    }
    #[derive(Serialize, Deserialize, Clone)]
    struct _SVDW {
        i: String,
        x: String,
        y: String,
        z: String,
    }
    struct Svdw {
        i: Fp,
        p: G1Projective,
    }
    #[derive(Serialize, Deserialize)]
    struct ReferenceData {
        g1: _G1,
        svdw: Vec<_SVDW>,
    }

    struct G1ReferenceData {
        a: Vec<G1Projective>,
        b: Vec<G1Projective>,
        r: Vec<Fp>,
        add: Vec<G1Projective>,
        dbl: Vec<G1Projective>,
        mul: Vec<G1Projective>,
    }

    fn convert_to_svdw(svdw: &_SVDW) -> Svdw {
        let i = convert_to_fp(&svdw.i);
        let p = convert_to_g1projective(&_G1Projective {
            x: svdw.clone().x,
            y: svdw.clone().y,
            z: svdw.clone().z,
        });
        Svdw { i, p }
    }
    fn convert_to_g1projective(point: &_G1Projective) -> G1Projective {
        G1Projective::new([
            Fp::new_from_str(point.x.as_str()).expect(
                "failed to convert x coord in \
            g1",
            ),
            Fp::new_from_str(point.y.as_str()).expect("failed to convert y coord in g1"),
            Fp::new_from_str(point.z.as_str()).expect("failed to convert z coord in g1"),
        ])
        .expect("g1 failed")
    }
    #[allow(clippy::ptr_arg)]
    fn convert_to_fp(r: &String) -> Fp {
        Fp::new_from_str(r).expect("failed to convert r to Fp")
    }
    const FNAME: &str = "./src/sage_reference/bn254_reference.json";

    /// Loading from disk is not a const operation (so we therefore cannot just run this code
    /// once in the beginning of the `tests` module definition), so we roll the loading
    /// and processing into a macro so that it can be performed at the beginning of each test as
    /// needed.
    macro_rules! load_reference_data {
        ($wrapper_name:ident) => {
            let path = Path::new(FNAME);
            let file_content = fs::read_to_string(path).expect("Failed to read file");
            let reference_data: ReferenceData =
                serde_json::from_str(&file_content).expect("Failed to parse JSON");
            let $wrapper_name: G1ReferenceData = G1ReferenceData {
                a: reference_data
                    .g1
                    .a
                    .iter()
                    .map(convert_to_g1projective)
                    .collect(),
                b: reference_data
                    .g1
                    .b
                    .iter()
                    .map(convert_to_g1projective)
                    .collect(),
                r: reference_data.g1.r.iter().map(convert_to_fp).collect(),
                add: reference_data
                    .g1
                    .add
                    .iter()
                    .map(convert_to_g1projective)
                    .collect(),
                dbl: reference_data
                    .g1
                    .dbl
                    .iter()
                    .map(convert_to_g1projective)
                    .collect(),
                mul: reference_data
                    .g1
                    .mul
                    .iter()
                    .map(convert_to_g1projective)
                    .collect(),
            };
        };
    }
    mod generation {
        use super::*;
        #[test]
        fn test_generation_and_conversion() {
            load_reference_data!(_g1_points);
        }
        #[test]
        #[should_panic(expected = "Conversion to projective failed: NotOnCurve")]
        fn test_malformed_points() {
            load_reference_data!(g1_points);
            for a in &g1_points.a {
                let mut x = a.x;
                let y = a.y;
                let z = a.z;

                // we intentionally manipulate a single coordinate to knock it
                // off the curve, to check instantiation is not possible with
                // a point not on the curve
                x *= Fp::from(2);
                let _ = G1Projective::new([x, y, z]).expect("Conversion to projective failed");
            }
        }
    }
    mod special_point_tests {
        use super::*;
        #[test]
        fn infinity() {
            let a = &G1Projective::zero();
            let b = &G1Projective::zero();
            let c = a + b;
            assert!(
                c.is_zero(),
                "Identities don't add to yield another point at infinity"
            );
        }
        #[test]
        fn generator() {
            let g = &G1Projective::generator().double().double(); //4
            let h = &G1Projective::generator().double(); //2
            let j = g + h;

            let mut d = G1Projective::generator();
            for _ in 0..5 {
                d = &d + &G1Projective::generator();
            }
            assert_eq!(j, d, "Generator multiplication not valid");
        }
    }
    mod addition_tests {
        use super::*;
        #[test]
        fn test_addition_closure() {
            load_reference_data!(g1_points);
            for i in &g1_points.a[1..] {
                let _ = i + &g1_points.a[0];
            }
        }

        #[test]
        fn test_addition_associativity_commutativity() {
            load_reference_data!(g1_points);
            if let [a, b, c] = &g1_points.a[0..3] {
                assert_eq!(&(a + b) + c, a + &(b + c), "Addition is not associative");
                assert_eq!(a + b, b + a, "Addition is not commutative");
            }
        }
        #[test]
        fn test_addition_cases() {
            load_reference_data!(g1_points);
            let expected = g1_points.add;
            for (i, (a, b)) in g1_points.a.iter().zip(&g1_points.b).enumerate() {
                let result = a + b;
                assert_eq!(result, expected[i], "Simple addition failed");
            }
        }
        #[test]
        fn test_addition_edge_cases() {
            use crypto_bigint::rand_core::OsRng;
            let r = G1Projective::rand(&mut OsRng);
            let zero = &G1Projective::zero();
            assert_eq!(zero + &r, r, "Adding zero failed");
        }
    }
    mod subtraction_tests {
        use super::*;
        // the test below for additive identity is sufficient, in conjunction with a
        // successful addition test case run, to verify the accuracy of subtraction
        #[test]
        fn test_subtraction_closure() {
            load_reference_data!(g1_points);
            let a = &g1_points.a[0];
            for i in &g1_points.a {
                let _ = i - a;
                let b = i - i;
                assert_eq!(b, G1Projective::zero(), "Additive identity failed");
            }
        }
        #[test]
        fn test_subtraction_associativity() {
            load_reference_data!(g1_points);
            if let [a, b, c] = &g1_points.a[0..3] {
                assert_eq!(a - &(b - c), &(a - b) + c, "Subtraction is not associative");
            }
        }
    }

    mod multiplication_tests {
        use super::*;
        #[test]
        fn test_doubling() {
            load_reference_data!(g1_points);
            for i in &g1_points.a {
                assert_eq!(i.double(), i + i, "Doubling failed");
            }
        }

        #[test]
        fn test_scalar_mul() {
            load_reference_data!(g1_points);
            let three = Fp::from(3);
            for i in &g1_points.a {
                assert_eq!(
                    i + &(i + i),
                    i * &three.value().to_le_bytes(),
                    "Multiplication failed"
                );
            }
        }
        #[test]
        fn test_random() {
            use crypto_bigint::rand_core::OsRng;
            for _ in 0..100 {
                let p = G1Projective::rand(&mut OsRng);
                let _ = G1Projective::new([p.x, p.y, p.z]).expect("Random point not on curve");
            }
        }
        #[test]
        fn test_multiplication_cases() {
            load_reference_data!(g1_points);
            let expected = g1_points.mul;
            for (i, (a, r)) in g1_points.a.iter().zip(&g1_points.r).enumerate() {
                let result = a * &r.value().to_le_bytes();
                assert_eq!(result, expected[i], "Simple multiplication failed");
            }
            let expected = g1_points.dbl;
            for (i, a) in g1_points.a.iter().enumerate() {
                let result = a.double();
                assert_eq!(result, expected[i], "Simple doubling failed");
            }
        }
    }
    mod hash_tests {
        use super::*;
        use crate::hasher::XMDExpander;
        use sha2::Sha256;
        const DST: &[u8; 30] = b"WARLOCK-CHAOS-V01-CS01-SHA-256";
        const MSG: &[u8; 4] = &20_i32.to_be_bytes();
        const K: u64 = 128;
        #[test]
        fn test_closure() {
            let expander = XMDExpander::<Sha256>::new(DST, K);
            if let Ok(d) = G1Projective::hash_to_curve(&expander, MSG) {
                println!("{:?}", d)
            }
        }

        #[test]
        fn test_signature() {
            use crypto_bigint::rand_core::OsRng;
            use sha3::Keccak256;
            let expander = XMDExpander::<Keccak256>::new(DST, K);
            for _ in 0..1 {
                let rando = <Fp as FieldExtensionTrait<1, 1>>::rand(&mut OsRng);
                if let Ok(d) = G1Affine::sign_message(&expander, MSG, rando) {
                    println!("DST: {:?}", String::from_utf8_lossy(DST));
                    println!("Message: {:?}", String::from_utf8_lossy(MSG));
                    println!("private key: {:?}", rando.value());
                    println!(
                        "signature: {:?}, {:?}, {:?}\n",
                        d.x.value(),
                        d.y.value(),
                        d.infinity
                    );
                }
            }
        }

        #[test]
        fn test_svdw() {
            let path = Path::new(FNAME);
            let file_content = fs::read_to_string(path).expect("Failed to read file");
            let reference_data: ReferenceData =
                serde_json::from_str(&file_content).expect("Failed to parse JSON");
            let svdw_vecs: Vec<Svdw> = reference_data.svdw.iter().map(convert_to_svdw).collect();

            if let Ok(d) = SvdW::<1, 1, Fp>::precompute_constants(Fp::from(0), Fp::from(3)) {
                for s in svdw_vecs.iter() {
                    let r = s.i;
                    let p = s.p;
                    let determined = G1Projective::from(
                        d.unchecked_map_to_point(r)
                            .expect("SVDW failed to map to point"),
                    );
                    assert_eq!(p, determined, "SVDW failed reference check");
                }
            }
        }
    }
}
