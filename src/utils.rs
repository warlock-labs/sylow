use crypto_bigint::{Encoding, U256, U512};

/// Converts a smaller byte array to a larger one, padding with zeros.
///
/// This function is useful for upcasting arithmetic operations. For example, when computing p^2
/// in non-modular arithmetic, having p as a U256 will cause overflow. By upcasting to U512,
/// we can perform the squaring operation without overflow.
///
/// # Type Parameters
/// * `N`: The size of the input byte array
/// * `M`: The size of the output byte array
///
/// # Arguments
/// * `smaller_bytes`: A reference to the input byte array of size `N`
///
/// # Returns
/// A new byte array of size `M` with the input bytes copied to the least significant positions
///
/// # Panics
/// If `M` is not greater than `N`
pub(crate) fn to_larger_uint<const N: usize, const M: usize>(smaller_bytes: &[u8; N]) -> [u8; M] {
    assert!(M > N, "Target size must be larger than source size");
    let mut larger_bytes = [0u8; M];
    larger_bytes[M - N..].copy_from_slice(smaller_bytes);
    larger_bytes
}

/// Converts a U256 to a U512.
///
/// This function is a specific instantiation of the `to_larger_uint` function,
/// used in hashing operations where a larger uint is needed to avoid overflow.
///
/// # Arguments
/// * `u256`: A reference to the U256 value to be converted
///
/// # Returns
/// A new U512 value with the U256 value in the least significant bits
pub(crate) fn u256_to_u512(u256: &U256) -> U512 {
    U512::from_be_bytes(to_larger_uint::<32, 64>(&u256.to_be_bytes()))
}
