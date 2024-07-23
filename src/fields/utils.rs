use crypto_bigint::{Encoding, U1024, U2048, U256, U4096, U512};

pub(crate) fn to_larger_uint<const N: usize, const M: usize>(smaller_bytes: &[u8; N]) -> [u8; M] {
    assert!(M > N, "Target size must be larger than source size");
    let mut larger_bytes = [0u8; M];
    larger_bytes[M - N..].copy_from_slice(smaller_bytes);
    larger_bytes
}

// Specific conversion functions
pub(crate) fn u256_to_u512(u256: &U256) -> U512 {
    U512::from_be_bytes(to_larger_uint::<32, 64>(&u256.to_be_bytes()))
}
#[allow(dead_code)]
pub(crate) fn u256_to_u1024(u256: &U256) -> U1024 {
    U1024::from_be_bytes(to_larger_uint::<32, 128>(&u256.to_be_bytes()))
}
#[allow(dead_code)]
pub(crate) fn u256_to_u2048(u256: &U256) -> U2048 {
    U2048::from_be_bytes(to_larger_uint::<32, 256>(&u256.to_be_bytes()))
}
#[allow(dead_code)]
pub(crate) fn u256_to_u4096(u256: &U256) -> U4096 {
    U4096::from_be_bytes(to_larger_uint::<32, 512>(&u256.to_be_bytes()))
}
