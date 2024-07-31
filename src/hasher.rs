// //! This module implements the message expansion as dictated by RFC9380.
// //! Specifically, we take a domain separation tag (DST), and the binary string
// //! and convert it into an element in the base field.

use sha3::digest::{ExtendableOutput, FixedOutput};

// use rand::Rng;

const OVERSIZE_DST_PREFIX: &[u8] = b"H2C-OVERSIZE-DST-";

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn i2osp(val: u64, length: usize) -> Vec<u8> {
    if val >= (1 << (8 * length)) {
        panic!("bad I2OSP call: val={} length={}", val, length);
    }
    val.to_be_bytes()[8 - length..].to_vec()
}

trait Expander {
    fn expand_message(&self, msg: &[u8], len_in_bytes: usize) -> String;
    fn hash_name(&self) -> String;
    fn name(&self) -> &str;
    fn dst(&self) -> &[u8];
    fn security_param(&self) -> u64;
}

struct XMDExpander<D: Default + FixedOutput> {
    name: String,
    dst: Vec<u8>,
    dst_prime: Vec<u8>,
    hash_fn: std::marker::PhantomData<D>,
    security_param: u64,
}

impl<D: Default + FixedOutput> XMDExpander<D> {
    fn new(dst: &[u8], security_param: u64) -> Self {
        let dst_prime = if dst.len() > 255 {
            let mut hasher = D::default();
            hasher.update(OVERSIZE_DST_PREFIX);
            hasher.update(dst);
            hasher.finalize_fixed().to_vec()
        } else {
            dst.to_vec()
        };

        XMDExpander {
            name: "expand_message_xmd".to_string(),
            dst: dst.to_vec(),
            dst_prime,
            hash_fn: std::marker::PhantomData,
            security_param,
        }
    }
}

impl<D: Default + FixedOutput> Expander for XMDExpander<D> {
    fn expand_message(&self, msg: &[u8], len_in_bytes: usize) -> String {
        let b_in_bytes = D::output_size();
        let r_in_bytes = D::output_size();
        assert!(8 * b_in_bytes >= 2 * self.security_param as usize);

        let ell = (len_in_bytes + b_in_bytes - 1) / b_in_bytes;
        assert!(ell <= 255, "bad expand_message_xmd call: ell was {}", ell);

        let dst_prime = [
            self.dst_prime.as_slice(),
            &i2osp(self.dst_prime.len() as u64, 1),
        ]
        .concat();
        let z_pad = vec![0u8; r_in_bytes];
        let l_i_b_str = i2osp(len_in_bytes as u64, 2);

        let msg_prime = [&z_pad, msg, &l_i_b_str, &i2osp(0, 1), &dst_prime].concat();

        let b_0 = D::default().chain(msg_prime).finalize_fixed().to_vec();
        let mut b_vals = vec![Vec::new(); ell];
        b_vals[0] = D::default()
            .chain(b_0.clone())
            .chain(i2osp(1, 1).iter())
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
                .chain(i2osp((i + 1) as u64, 1).iter())
                .chain(dst_prime.iter())
                .cloned()
                .collect();
            b_vals[i] = D::default().chain(b_i).finalize_fixed().to_vec();
        }

        to_hex(
            b_vals
                .into_iter()
                .flatten()
                .take(len_in_bytes)
                .collect::<Vec<_>>()
                .as_slice(),
        )
    }

    fn hash_name(&self) -> String {
        self.name.to_string()
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn dst(&self) -> &[u8] {
        &self.dst
    }

    fn security_param(&self) -> u64 {
        self.security_param
    }
}

struct XOFExpander<D: Default + ExtendableOutput> {
    name: String,
    dst: Vec<u8>,
    dst_prime: Vec<u8>,
    hash_fn: std::marker::PhantomData<D>,
    security_param: u64,
}

impl<D: Default + ExtendableOutput> XOFExpander<D> {
    fn new(dst: &[u8], security_param: u64) -> Self {
        let dst_prime = if dst.len() > 255 {
            let mut hasher = D::default();
            hasher.update(OVERSIZE_DST_PREFIX);
            hasher.update(dst);
            let output_len = (2 * security_param).div_ceil(8) as usize;
            hasher.finalize_boxed(output_len).to_vec()
        } else {
            dst.to_vec()
        };

        XOFExpander {
            name: "expand_message_xof".to_string(),
            dst: dst.to_vec(),
            dst_prime,
            hash_fn: std::marker::PhantomData,
            security_param,
        }
    }
}

impl<D: Default + ExtendableOutput> Expander for XOFExpander<D> {
    fn expand_message(&self, msg: &[u8], len_in_bytes: usize) -> String {
        let dst_prime = [
            self.dst_prime.as_slice(),
            &i2osp(self.dst_prime.len() as u64, 1),
        ]
        .concat();
        let msg_prime = [msg, &i2osp(len_in_bytes as u64, 2), &dst_prime].concat();

        let mut hasher = D::default();
        hasher.update(&msg_prime);
        to_hex(hasher.finalize_boxed(len_in_bytes).to_vec().as_slice())
    }

    fn hash_name(&self) -> String {
        self.name.to_string()
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn dst(&self) -> &[u8] {
        &self.dst
    }

    fn security_param(&self) -> u64 {
        self.security_param
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    mod xof {
        use super::*;
        use sha3::Shake128;
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
        #[test]
        fn test_short_xof() {
            let len_in_bytes = 0x20;
            let k = 128;
            let dst = b"QUUX-V01-CS02-with-expander-SHAKE128";

            let expander = XOFExpander::<Shake128>::new(dst, k);
            for (msg, expected_expanded_msg) in short_xof_hashmap().iter() {
                let expanded_msg = expander.expand_message(msg.as_bytes(), len_in_bytes);
                assert_eq!(
                    expanded_msg.as_str(),
                    *expected_expanded_msg,
                    "Conversion for XOF \
                failed"
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
                let expanded_msg = expander.expand_message(msg.as_bytes(), len_in_bytes);
                assert_eq!(
                    expanded_msg.as_str(),
                    *expected_expanded_msg,
                    "Conversion for XOF \
                failed"
                );
            }
        }
    }
    mod xmd {
        use super::*;
        use sha3::{Sha3_512, Sha3_256};
        use std::collections::HashMap;
        use std::sync::OnceLock;
        fn short_xmd_hashmap() -> &'static HashMap<&'static str, &'static str> {
            static HASHMAP: OnceLock<HashMap<&str, &str>> = OnceLock::new();
            HASHMAP.get_or_init(|| {
                let mut m = HashMap::new();
                m.insert("", "6b9a7312411d92f921c6f68ca0b6380730a1a4d982c507211a90964c394179ba");
                m.insert("abc",
                         "0da749f12fbe5483eb066a5f595055679b976e93abe9be6f0f6318bce7aca8dc");
                m.insert("q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", "7336234ee9983902440f6bc35b348352013becd88938d2afec44311caf8356b3");
                m
            })
        }
        #[test]
        fn test_xmd_dst(){
            let k = 256;
            let short_dst = b"QUUX-V01-CS02-with-expander-SHA512-256";
            
            let expander = XMDExpander::<Sha3_512>::new(short_dst, k);
            println!("{:?}", to_hex(expander.dst_prime.as_slice()));
            
            let k = 128;
            let dst = b"QUUX-V01-CS02-with-expander-SHA256-128-long-DST-1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
            let expander = XMDExpander::<Sha3_256>::new(dst, k);
            println!("{:?}", to_hex(expander.dst_prime.as_slice()));
            
        }
    }
}