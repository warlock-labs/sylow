use crypto_bigint::{Encoding, U256, U512};

/// This function is used to convert a smaller byte array to a larger one
/// It's mainly useful for upcasting arithmetic. For example, in order to compute p^2 in
/// non-modular arithmetic, having p as a U256 will cause overflow in p^2, so we up-cast it toa
/// U512, and then do the squaring to contain the result. The below simply does this conversion
/// for a given input and output dimension.
/// # Generics
/// * `N` - the size of the input slice
/// * `M` - the size of the output slice
/// # Arguments
/// * `smaller_bytes` - a slice of bytes that is to be converted to a larger slice
pub(crate) fn to_larger_uint<const N: usize, const M: usize>(smaller_bytes: &[u8; N]) -> [u8; M] {
    assert!(M > N, "Target size must be larger than source size");
    let mut larger_bytes = [0u8; M];
    larger_bytes[M - N..].copy_from_slice(smaller_bytes);
    larger_bytes
}

/// A specific instantiation of casting from U256 to U512, used in the hashing operations
// Specific conversion functions
pub(crate) fn u256_to_u512(u256: &U256) -> U512 {
    U512::from_be_bytes(to_larger_uint::<32, 64>(&u256.to_be_bytes()))
}
