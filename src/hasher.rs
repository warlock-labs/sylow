//! This module implements the message expansion as dictated by RFC9380.
//! Specifically, we take a domain separation tag (DST), and the binary string
//! and convert it into an element in the base field.

use sha3::{
    digest::{ExtendableOutput, FixedOutput, XofReader},
    Shake128,
};

// use digest::{XofReader, FixedOutput};
/// Types which consume data with byte granularity.

// there are constants that are specified for the DST
const DST_MAX_LENGTH: usize = 255;
const OVERSIZED_DST_PREFIX: &[u8] = b"H2C-OVERSIZE-DST-";

#[derive(Debug)]
pub enum ExpandMessageError {
    DstTooLong,
    LenTooLarge,
    EllTooLarge,
}
#[derive(Debug)]
struct DomainSeparationTag {
    msg: [u8; DST_MAX_LENGTH],
    len: usize,
}
impl DomainSeparationTag {
    fn new(
        init: impl FnOnce(&mut [u8; DST_MAX_LENGTH]) -> Result<usize, ExpandMessageError>,
    ) -> Result<Self, ExpandMessageError> {
        let mut slf = DomainSeparationTag {
            msg: [0u8; DST_MAX_LENGTH],
            len: 0,
        };
        slf.len = init(&mut slf.msg)?;
        match slf.len <= DST_MAX_LENGTH {
            true => Ok(slf),
            _ => Err(ExpandMessageError::DstTooLong),
        }
    }

    fn for_xof<H: Default + ExtendableOutput>(
        dst: &[u8],
        security_param: usize,
    ) -> Result<Self, ExpandMessageError> {
        let input_len = dst.len();
        DomainSeparationTag::new(|buf| {
            if input_len > DST_MAX_LENGTH {
                let hash_len = (2 * security_param + 7) / 8;
                let mut xof = H::default();
                xof.update(OVERSIZED_DST_PREFIX);
                xof.update(dst);
                let mut reader = xof.finalize_xof();
                reader.read(&mut buf[..hash_len]);
                Ok(hash_len)
            } else {
                buf[..input_len].copy_from_slice(dst);
                Ok(input_len)
            }
        })
    }

    fn for_xmd<H: Default + FixedOutput>(dst: &[u8]) -> Result<Self, ExpandMessageError> {
        let input_len = dst.len();
        DomainSeparationTag::new(|buf| {
            if input_len > DST_MAX_LENGTH {
                let mut hash = H::default();
                hash.update(OVERSIZED_DST_PREFIX);
                hash.update(dst);
                let hashed = hash.finalize_fixed();
                let len = hashed.len();
                buf[..len].copy_from_slice(&hashed);
                Ok(len)
            } else {
                buf[..input_len].copy_from_slice(dst);
                Ok(input_len)
            }
        })
    }

    fn data(&self) -> &[u8] {
        &self.msg[..self.len]
    }

    fn len(&self) -> usize {
        self.len
    }
}
