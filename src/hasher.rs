// //! This module implements the message expansion as dictated by RFC9380.
// //! Specifically, we take a domain separation tag (DST), and the binary string
// //! and convert it into an element in the base field.

use crate::fields::fp::{FinitePrimeField, Fp};
use crate::fields::utils::u256_to_u512;
use crypto_bigint::{Encoding, NonZero, U256, U512};
use num_traits::Zero;
use sha3::digest::crypto_common::BlockSizeUser;
use sha3::digest::{ExtendableOutput, FixedOutput};
use std::array::TryFromSliceError;
#[derive(Debug)]
pub enum HashError {
    CastToField,
    ExpandMessage,
    ConvertInt,
}
#[allow(dead_code)]
fn to_hex(bytes: &[u8]) -> String {
    // A simple utility function to convert a byte array into a big endian hex string
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut acc, &b| {
            acc.push_str(&format!("{:02x}", b));
            acc
        })
}

fn i2osp(val: u64, length: usize) -> Result<Vec<u8>, HashError> {
    // this is an integer to octet representation of the given length
    if val >= (1 << (8 * length)) {
        return Err(HashError::ConvertInt);
    }
    Ok(val.to_be_bytes()[8 - length..].to_vec())
}
pub(crate) trait Expander {
    const OVERSIZE_DST_PREFIX: &'static [u8] = b"H2C-OVERSIZE-DST-";

    fn expand_message(&self, msg: &[u8], len_in_bytes: usize) -> Result<Vec<u8>, HashError>;
}

pub(crate) struct XMDExpander<D: Default + FixedOutput + BlockSizeUser> {
    /// This implements the XMD function, which produces a uniformly random
    /// byte string using a hash function that outputs b bits.
    /// Usage of this function is recommended only with Sha2 and Sha3 hashes.
    /// <https://datatracker.ietf.org/doc/html/rfc9380#name-expand_message_xmd>
    dst_prime: Vec<u8>,
    hash_fn: std::marker::PhantomData<D>,
    security_param: u64,
}

impl<D: Default + FixedOutput + BlockSizeUser> XMDExpander<D> {
    #[allow(dead_code)]
    pub(crate) fn new(dst: &[u8], security_param: u64) -> Self {
        let dst_prime = if dst.len() > 255 {
            let mut hasher = D::default();
            hasher.update(Self::OVERSIZE_DST_PREFIX);
            hasher.update(dst);
            hasher.finalize_fixed().to_vec()
        } else {
            dst.to_vec()
        };

        XMDExpander {
            dst_prime,
            hash_fn: std::marker::PhantomData,
            security_param,
        }
    }
}

impl<D: Default + FixedOutput + BlockSizeUser> Expander for XMDExpander<D> {
    fn expand_message(&self, msg: &[u8], len_in_bytes: usize) -> Result<Vec<u8>, HashError> {
        let b_in_bytes = D::output_size();
        let r_in_bytes = D::block_size();
        let ell = (len_in_bytes + b_in_bytes - 1) / b_in_bytes;
        let dst_prime = [
            self.dst_prime.as_slice(),
            &i2osp(self.dst_prime.len() as u64, 1)?,
        ]
        .concat();
        if 8 * b_in_bytes < 2 * self.security_param as usize
            || ell > 255
            || dst_prime.len() != self.dst_prime.len() + 1
        {
            return Err(HashError::ExpandMessage);
        }

        let z_pad = vec![0; r_in_bytes];
        let l_i_b_str = i2osp(len_in_bytes as u64, 2)?;

        let msg_prime = [&z_pad, msg, &l_i_b_str, &i2osp(0, 1)?, &dst_prime].concat();

        let b_0 = D::default().chain(msg_prime).finalize_fixed().to_vec();
        let mut b_vals = vec![Vec::new(); ell];
        b_vals[0] = D::default()
            .chain(b_0.clone())
            .chain(i2osp(1, 1)?.iter())
            .chain(dst_prime.iter())
            .finalize_fixed()
            .to_vec();

        for i in 1..ell {
            let xored: Vec<u8> = b_0
                .iter()
                .zip(&b_vals[i - 1])
                .map(|(&x, &y)| x ^ y)
                .collect();
            let b_i: Vec<u8> = xored
                .iter()
                .chain(i2osp((i + 1) as u64, 1)?.iter())
                .chain(dst_prime.iter())
                .cloned()
                .collect();
            b_vals[i] = D::default().chain(b_i).finalize_fixed().to_vec();
        }

        Ok(b_vals.into_iter().flatten().take(len_in_bytes).collect())
    }
}

struct XOFExpander<D: Default + ExtendableOutput> {
    /// This implements the XOF function, which produces a uniformly random
    /// byte string using an extendable output function (XOF) H. In this instance,
    /// the Shake XOF family are the only recommended choices.
    /// <https://datatracker.ietf.org/doc/html/rfc9380#name-expand_message_xof>
    dst_prime: Vec<u8>,
    hash_fn: std::marker::PhantomData<D>,
}

impl<D: Default + ExtendableOutput> XOFExpander<D> {
    #[allow(dead_code)]
    fn new(dst: &[u8], security_param: u64) -> Self {
        let dst_prime = if dst.len() > 255 {
            let mut hasher = D::default();
            hasher.update(Self::OVERSIZE_DST_PREFIX);
            hasher.update(dst);
            let output_len = (2 * security_param).div_ceil(8) as usize;
            hasher.finalize_boxed(output_len).to_vec()
        } else {
            dst.to_vec()
        };

        XOFExpander {
            dst_prime,
            hash_fn: std::marker::PhantomData,
        }
    }
}

impl<D: Default + ExtendableOutput> Expander for XOFExpander<D> {
    fn expand_message(&self, msg: &[u8], len_in_bytes: usize) -> Result<Vec<u8>, HashError> {
        let dst_prime = [
            self.dst_prime.as_slice(),
            &i2osp(self.dst_prime.len() as u64, 1)?,
        ]
        .concat();
        let msg_prime = [msg, &i2osp(len_in_bytes as u64, 2)?, &dst_prime].concat();

        let mut hasher = D::default();
        hasher.update(&msg_prime);
        Ok(hasher.finalize_boxed(len_in_bytes).to_vec())
    }
}

#[allow(dead_code)]
pub(crate) fn hash_to_field<E: Expander>(msg: &[u8], expander: &E) -> Result<[Fp; 2], HashError> {
    const COUNT: usize = 2;
    const L: usize = 48;
    const LEN_IN_BYTES: usize = COUNT * L;

    let exp_msg = expander.expand_message(msg, LEN_IN_BYTES)?;

    let mut retval = [Fp::zero(); 2];
    for (i, f) in retval.iter_mut().enumerate() {
        let elm_offset = L * i;
        let tv = &exp_msg[elm_offset..elm_offset + L];
        let mut bs = [0u8; 64];
        bs[16..].copy_from_slice(tv);

        let cast_value = U512::from_be_bytes(bs);
        let modulus = NonZero::<U512>::new(u256_to_u512(&Fp::characteristic())).unwrap();

        let scalar = U256::from_words(
            (cast_value % modulus).to_words()[0..4]
                .try_into()
                .map_err(|_e: TryFromSliceError| HashError::CastToField)?,
        );
        *f = Fp::new(scalar);
    }
    Ok(retval)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::OnceLock;
    fn short_xof_hashmap() -> &'static HashMap<&'static str, &'static str> {
        static HASHMAP: OnceLock<HashMap<&str, &str>> = OnceLock::new();
        HASHMAP.get_or_init(|| {
            let mut m = HashMap::new();
            m.insert("", "86518c9cd86581486e9485aa74ab35ba150d1c75c88e26b7043e44e2acd735a2");
            m.insert("abc",
                     "8696af52a4d862417c0763556073f47bc9b9ba43c99b505305cb1ec04a9ab468");
            m.insert("q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", "1adbcc448aef2a0cebc71dac9f756b22e51839d348e031e63b33ebb50faeaf3f");
            m
        })
    }
    fn long_xof_hashmap() -> &'static HashMap<&'static str, &'static str> {
        static HASHMAP: OnceLock<HashMap<&str, &str>> = OnceLock::new();
        HASHMAP.get_or_init(|| {
            let mut m = HashMap::new();
            m.insert("", "827c6216330a122352312bccc0c8d6e7a146c5257a776dbd9ad9d75cd880fc53");
            m.insert("abc",
                     "690c8d82c7213b4282c6cb41c00e31ea1d3e2005f93ad19bbf6da40f15790c5c");
            m.insert("q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", "c5a9220962d9edc212c063f4f65b609755a1ed96e62f9db5d1fd6adb5a8dc52b");
            m
        })
    }
    fn short_xmd_hashmap() -> &'static HashMap<&'static str, &'static str> {
        static HASHMAP: OnceLock<HashMap<&str, &str>> = OnceLock::new();
        HASHMAP.get_or_init(|| {
            let mut m = HashMap::new();
            m.insert("", "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235");
            m.insert("abc",
                     "d8ccab23b5985ccea865c6c97b6e5b8350e794e603b4b97902f53a8a0d605615");
            m.insert("q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", "b23a1d2b4d97b2ef7785562a7e8bac7eed54ed6e97e29aa51bfe3f12ddad1ff9");
            m
        })
    }
    fn long_xmd_hashmap() -> &'static HashMap<&'static str, &'static str> {
        static HASHMAP: OnceLock<HashMap<&str, &str>> = OnceLock::new();
        HASHMAP.get_or_init(|| {
            let mut m = HashMap::new();
            m.insert("", "e8dc0c8b686b7ef2074086fbdd2f30e3f8bfbd3bdf177f73f04b97ce618a3ed3");
            m.insert("abc",
                     "52dbf4f36cf560fca57dedec2ad924ee9c266341d8f3d6afe5171733b16bbb12");
            m.insert("q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", "01b637612bb18e840028be900a833a74414140dde0c4754c198532c3a0ba42bc");
            m
        })
    }
    mod xof {
        use super::*;
        use sha3::Shake128;

        #[test]
        fn test_short_xof() {
            let len_in_bytes = 0x20;
            let k = 128;
            let dst = b"QUUX-V01-CS02-with-expander-SHAKE128";

            let expander = XOFExpander::<Shake128>::new(dst, k);
            for (msg, expected_expanded_msg) in short_xof_hashmap().iter() {
                let expanded_msg = expander
                    .expand_message(msg.as_bytes(), len_in_bytes)
                    .expect("Hashing for short XOF failed");
                assert_eq!(
                    to_hex(expanded_msg.as_slice()),
                    *expected_expanded_msg,
                    "Conversion for short XOF failed"
                );
            }
        }
        #[test]
        fn test_long_xof() {
            let len_in_bytes = 0x20;
            let k = 128;
            let dst = b"QUUX-V01-CS02-with-expander-SHAKE128-long-DST-111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";

            let expander = XOFExpander::<Shake128>::new(dst, k);
            for (msg, expected_expanded_msg) in long_xof_hashmap().iter() {
                let expanded_msg = expander
                    .expand_message(msg.as_bytes(), len_in_bytes)
                    .expect("Hashing for long XOF failed");
                assert_eq!(
                    to_hex(expanded_msg.as_slice()),
                    *expected_expanded_msg,
                    "Conversion for long XOF failed"
                );
            }
        }
    }
    mod xmd {
        use super::*;
        use sha2::Sha256;

        #[test]
        fn test_short_xmd() {
            let k = 128;
            let len_in_bytes = 0x20;
            let dst = b"QUUX-V01-CS02-with-expander-SHA256-128";

            let expander = XMDExpander::<Sha256>::new(dst, k);
            for (msg, expected_expanded_msg) in short_xmd_hashmap().iter() {
                let expanded_msg = expander
                    .expand_message(msg.as_bytes(), len_in_bytes)
                    .expect("Hashing fort short XMD failed");
                assert_eq!(
                    to_hex(expanded_msg.as_slice()),
                    *expected_expanded_msg,
                    "Conversion for short XMD failed"
                );
                let res = hash_to_field(msg.as_bytes(), &expander).expect(
                    "Short XMD failed to \
                cast to field",
                );
                for r in res {
                    println!("{:?}", r);
                }
            }
        }
        #[test]
        fn test_long_xmd() {
            let k = 128;
            let len_in_bytes = 0x20;
            let dst = b"QUUX-V01-CS02-with-expander-SHA256-128-long-DST-1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
            let expander = XMDExpander::<Sha256>::new(dst, k);
            for (msg, expected_expanded_msg) in long_xmd_hashmap().iter() {
                let expanded_msg = expander
                    .expand_message(msg.as_bytes(), len_in_bytes)
                    .expect("Hashing for long XMD failed");
                assert_eq!(
                    to_hex(expanded_msg.as_slice()),
                    *expected_expanded_msg,
                    "Conversion for long XMD failed"
                );
            }
        }
    }
}
