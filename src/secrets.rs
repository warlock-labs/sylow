//! The goal of the implementations in this file are to ultimately allow for the usage of
//! group elements into secrets such that they are under strict `mprotect` status when stored in memory
//! and are only read in the minimum scope that is necessary. Because `secrets`, and therefore
//! `libsodium`, requires fine-grained control over the underlying memory of these objects,
//! it must involve unsafe rust. Oof!
use crate::{Fp, Fp2, G1Projective, G2Projective};
use num_traits::Zero;
use secrets::traits::Bytes;

unsafe impl Bytes for Fp {
    /// Create an uninitialized field element
    /// This is used by the secrets crate when allocating protected memory
    fn uninitialized() -> Self {
        Fp::zero()
    }
    fn size() -> usize {
        32 // a size of the underlying U256 in bytes
    }
    /// Get a pointer to the underlying bytes
    /// This allows the secrets crate to access the raw memory
    fn as_u8_ptr(&self) -> *const u8 {
        self.value().as_words().as_ptr() as *const u8
    }
    /// Get a mutable pointer to the underlying bytes
    /// This allows the secrets crate to modify the protected memory
    fn as_mut_u8_ptr(&mut self) -> *mut u8 {
        self.value().as_words().as_ptr() as *mut u8
    }
}
unsafe impl Bytes for Fp2 {
    /// Create an uninitialized Fp2 element
    /// This creates space for two Fp elements (two U256 values)
    fn uninitialized() -> Self {
        // Create an Fp2 with two zero Fp elements
        Fp2::zero()
    }

    /// Get the size in bytes of the Fp2 element
    /// Since Fp2 contains two Fp elements, each 32 bytes (256 bits),
    /// the total size is 64 bytes (512 bits)
    fn size() -> usize {
        64 // Size of two U256 values in bytes
    }

    /// Get a pointer to the underlying bytes
    /// This provides access to both Fp elements' bytes consecutively
    fn as_u8_ptr(&self) -> *const u8 {
        // Get pointer to the first of the two internal Fp elements
        // FieldExtension stores elements in self.0[0] and self.0[1]
        self.0.as_ptr() as *const u8
    }

    /// Get a mutable pointer to the underlying bytes
    /// This provides mutable access to both Fp elements' bytes consecutively
    fn as_mut_u8_ptr(&mut self) -> *mut u8 {
        // Get mutable pointer to the first of the two internal Fp elements
        self.0.as_mut_ptr() as *mut u8
    }
}

unsafe impl Bytes for G1Projective {
    /// Create an uninitialized G1Projective point
    /// This creates space for three Fp elements (x, y, z coordinates)
    fn uninitialized() -> Self {
        // Create point with three zero Fp elements
        // This creates the point at infinity by default
        G1Projective {
            x: Fp::zero(),
            y: Fp::zero(),
            z: Fp::zero(),
        }
    }

    /// Get the size in bytes of the G1Projective point
    /// Since G1Projective contains three Fp elements, each 32 bytes,
    /// the total size is 96 bytes (768 bits)
    fn size() -> usize {
        96 // Size of three U256 values in bytes (32 * 3)
    }

    /// Get a pointer to the underlying bytes
    /// This provides access to all three Fp elements' bytes consecutively
    fn as_u8_ptr(&self) -> *const u8 {
        // Get pointer to first coordinate (x)
        // Relies on x, y, z being stored contiguously
        &self.x as *const Fp as *const u8
    }

    /// Get a mutable pointer to the underlying bytes
    /// This provides mutable access to all three Fp elements' bytes
    fn as_mut_u8_ptr(&mut self) -> *mut u8 {
        // Get mutable pointer to first coordinate (x)
        &mut self.x as *mut Fp as *mut u8
    }
}
unsafe impl Bytes for G2Projective {
    /// Create an uninitialized G2Projective point
    /// This creates space for three Fp2 elements (x, y, z coordinates),
    /// each containing two Fp elements, for a total of six Fp elements
    fn uninitialized() -> Self {
        // Create point with three zero Fp2 elements
        // This creates the point at infinity by default
        G2Projective {
            x: Fp2::zero(),
            y: Fp2::zero(),
            z: Fp2::zero(),
        }
    }

    /// Get the size in bytes of the G2Projective point
    /// Each Fp2 contains two Fp elements of 32 bytes each
    /// Total size: 3 coordinates * 2 Fp elements * 32 bytes = 192 bytes (1536 bits)
    fn size() -> usize {
        192 // Size of six U256 values in bytes (32 * 6)
    }

    /// Get a pointer to the underlying bytes
    /// This provides access to all six Fp elements' bytes consecutively
    fn as_u8_ptr(&self) -> *const u8 {
        // Get pointer to first Fp2 coordinate (x)
        // Relies on x, y, z being stored contiguously and each Fp2 being contiguous
        &self.x as *const Fp2 as *const u8
    }

    /// Get a mutable pointer to the underlying bytes
    /// This provides mutable access to all six Fp elements' bytes
    fn as_mut_u8_ptr(&mut self) -> *mut u8 {
        // Get mutable pointer to first Fp2 coordinate (x)
        &mut self.x as *mut Fp2 as *mut u8
    }
}
// Safety verification tests
#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;
    mod fp_bytes {
        use super::*;

        #[test]
        fn verify_fp_size_and_alignment() {
            // Verify size is exactly 32 bytes (256 bits)
            assert_eq!(Fp::size(), 32);
            // Verify alignment is at least 8 bytes for efficient access
            assert_eq!(mem::align_of::<Fp>(), 8);
        }

        #[test]
        fn verify_fp_pointer_consistency() {
            let mut fp = Fp::uninitialized();

            // Get both pointers
            let const_ptr = fp.as_u8_ptr();
            let mut_ptr = fp.as_mut_u8_ptr();

            unsafe {
                // Force memory fence to prevent reordering
                std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);

                // Write through mut pointer
                *mut_ptr = 0xAA;
                std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);

                // Read through const pointer
                let read_val = *const_ptr;
                std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);

                assert_eq!(read_val, 0xAA, "Pointers should access same memory");

                // Verify again with different value
                *mut_ptr = 0x55;
                std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);

                let read_val2 = *const_ptr;
                assert_eq!(read_val2, 0x55, "Pointers should access same memory");
            }
        }
    }
    mod fp2_bytes {
        use super::*;

        #[test]
        fn verify_fp2_size_and_alignment() {
            // Verify size is exactly 64 bytes (2 * 256 bits)
            assert_eq!(Fp2::size(), 64);
            // Verify alignment matches or exceeds base field alignment
            assert!(mem::align_of::<Fp2>() >= mem::align_of::<Fp>());
        }

        #[test]
        fn verify_fp2_coefficient_layout() {
            let fp2 = Fp2::uninitialized();
            let base_ptr = fp2.as_u8_ptr();

            // Verify coefficients are stored contiguously
            unsafe {
                let c0_ptr = &fp2.0[0] as *const Fp as *const u8;
                let c1_ptr = &fp2.0[1] as *const Fp as *const u8;

                assert_eq!(base_ptr, c0_ptr, "First coefficient should start at base");
                assert_eq!(
                    c0_ptr.add(32),
                    c1_ptr,
                    "Second coefficient should immediately follow first"
                );
            }
        }
    }
    mod g1_bytes {
        use super::*;
        use std::slice;
        #[test]
        fn verify_g1_projective_layout() {
            // Verify total size is 96 bytes (3 * 32)
            assert_eq!(mem::size_of::<G1Projective>(), 96);

            // Verify alignment matches Fp
            assert_eq!(mem::align_of::<G1Projective>(), mem::align_of::<Fp>());

            // Verify coordinates are contiguous with no padding
            let point = G1Projective::uninitialized();
            let base_ptr = &point as *const G1Projective as *const u8;
            let x_ptr = &point.x as *const Fp as *const u8;
            let y_ptr = &point.y as *const Fp as *const u8;
            let z_ptr = &point.z as *const Fp as *const u8;

            unsafe {
                // Check x coordinate starts at beginning
                assert_eq!(base_ptr, x_ptr);
                // Check y coordinate follows x immediately
                assert_eq!(x_ptr.add(32), y_ptr);
                // Check z coordinate follows y immediately
                assert_eq!(y_ptr.add(32), z_ptr);
            }
        }

        #[test]
        fn verify_initialization_is_infinity() {
            let point = G1Projective::uninitialized();
            // Verify this creates point at infinity
            assert!(point.is_zero());
        }
        #[test]
        fn verify_g1_coordinates() {
            let point = G1Projective::uninitialized();

            // Get pointers to each coordinate
            let base_ptr = point.as_u8_ptr();
            unsafe {
                // Verify x coordinate
                let x_bytes = slice::from_raw_parts(base_ptr, 32);
                assert!(
                    x_bytes.iter().all(|&b| b == 0),
                    "x coordinate should be zero"
                );

                // Verify y coordinate
                let y_bytes = slice::from_raw_parts(base_ptr.add(32), 32);
                assert!(
                    y_bytes.iter().all(|&b| b == 0),
                    "y coordinate should be zero"
                );

                // Verify z coordinate
                let z_bytes = slice::from_raw_parts(base_ptr.add(64), 32);
                assert!(
                    z_bytes.iter().all(|&b| b == 0),
                    "z coordinate should be zero"
                );
            }
        }
        #[test]
        fn verify_g1_pointer_manipulation() {
            let mut point = G1Projective::uninitialized();

            // Test pointer arithmetic
            unsafe {
                let base_ptr = point.as_u8_ptr();
                let mut_ptr = point.as_mut_u8_ptr();

                // Verify pointer alignment
                assert_eq!(
                    base_ptr as usize % mem::align_of::<G1Projective>(),
                    0,
                    "Pointer should be properly aligned"
                );

                // Verify const and mut pointers refer to same memory
                assert_eq!(base_ptr as usize, mut_ptr as usize, "Pointers should match");

                // Verify we can access the full memory range
                for i in 0..G1Projective::size() {
                    *mut_ptr.add(i) = i as u8;
                }

                // Verify written values
                for i in 0..G1Projective::size() {
                    assert_eq!(*base_ptr.add(i), i as u8, "Memory access failed");
                }
            }
        }
    }
    mod g2_bytes {
        use super::*;
        use std::slice;

        #[test]
        fn verify_g2_projective_layout() {
            // Verify total size is 192 bytes (6 * 32)
            assert_eq!(mem::size_of::<G2Projective>(), 192);

            // Verify alignment matches Fp2
            assert_eq!(mem::align_of::<G2Projective>(), mem::align_of::<Fp2>());

            // Verify coordinates are contiguous with no padding
            let point = G2Projective::uninitialized();
            let base_ptr = &point as *const G2Projective as *const u8;
            let x_ptr = &point.x as *const Fp2 as *const u8;
            let y_ptr = &point.y as *const Fp2 as *const u8;
            let z_ptr = &point.z as *const Fp2 as *const u8;

            unsafe {
                // Check x coordinate starts at beginning
                assert_eq!(base_ptr, x_ptr);
                // Check y coordinate follows x immediately
                assert_eq!(x_ptr.add(64), y_ptr); // Each Fp2 is 64 bytes
                                                  // Check z coordinate follows y immediately
                assert_eq!(y_ptr.add(64), z_ptr);

                // Verify internal Fp2 layout
                let x0_ptr = &point.x.0[0] as *const Fp as *const u8;
                let x1_ptr = &point.x.0[1] as *const Fp as *const u8;
                assert_eq!(x_ptr, x0_ptr);
                assert_eq!(x0_ptr.add(32), x1_ptr);
            }
        }

        #[test]
        fn verify_initialization_is_infinity() {
            let point = G2Projective::uninitialized();
            // Verify this creates point at infinity
            assert!(point.is_zero());
        }
        #[test]
        fn verify_g2_coordinates() {
            let point = G2Projective::uninitialized();

            // Get pointers to each coordinate pair
            let base_ptr = point.as_u8_ptr();
            unsafe {
                // Verify x coordinate (2 * 32 bytes)
                let x_bytes = slice::from_raw_parts(base_ptr, 64);
                assert!(
                    x_bytes.iter().all(|&b| b == 0),
                    "x coordinate should be zero"
                );

                // Verify y coordinate (2 * 32 bytes)
                let y_bytes = slice::from_raw_parts(base_ptr.add(64), 64);
                assert!(
                    y_bytes.iter().all(|&b| b == 0),
                    "y coordinate should be zero"
                );

                // Verify z coordinate (2 * 32 bytes)
                let z_bytes = slice::from_raw_parts(base_ptr.add(128), 64);
                assert!(
                    z_bytes.iter().all(|&b| b == 0),
                    "z coordinate should be zero"
                );
            }
        }
        #[test]
        fn verify_g2_pointer_manipulation() {
            let mut point = G2Projective::uninitialized();

            unsafe {
                let base_ptr = point.as_u8_ptr();
                let mut_ptr = point.as_mut_u8_ptr();

                // Verify pointer alignment
                assert_eq!(
                    base_ptr as usize % mem::align_of::<G2Projective>(),
                    0,
                    "Pointer should be properly aligned"
                );

                // Verify const and mut pointers refer to same memory
                assert_eq!(base_ptr as usize, mut_ptr as usize, "Pointers should match");

                // Write unique test pattern for each Fp element
                for i in 0..6 {
                    // 6 Fp elements total (3 coordinates * 2 coefficients each)
                    let offset = i * 32;
                    for j in 0..32 {
                        *mut_ptr.add(offset + j) = ((i * 32 + j) % 256) as u8;
                    }
                }

                // Verify patterns
                for i in 0..6 {
                    let offset = i * 32;
                    for j in 0..32 {
                        assert_eq!(
                            *base_ptr.add(offset + j),
                            ((i * 32 + j) % 256) as u8,
                            "Memory access failed at Fp element {} byte {}",
                            i,
                            j
                        );
                    }
                }
            }
        }
    }
}
