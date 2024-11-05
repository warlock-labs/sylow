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

    mod g1_bytes {
        use super::*;
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
    }
    mod g2_bytes {
        use super::*;

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
    }
}
