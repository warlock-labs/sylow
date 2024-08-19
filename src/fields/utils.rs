use crypto_bigint::{Encoding, U256, U512};

pub fn to_larger_uint<const N: usize, const M: usize>(smaller_bytes: &[u8; N]) -> [u8; M] {
    assert!(M > N, "Target size must be larger than source size");
    let mut larger_bytes = [0u8; M];
    larger_bytes[M - N..].copy_from_slice(smaller_bytes);
    larger_bytes
}

// Specific conversion functions
pub fn u256_to_u512(u256: &U256) -> U512 {
    U512::from_be_bytes(to_larger_uint::<32, 64>(&u256.to_be_bytes()))
}
