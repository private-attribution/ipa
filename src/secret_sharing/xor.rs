use std::io;
use std::io::ErrorKind;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XorReplicated {
    left: u64,
    right: u64,
}

impl XorReplicated {
    pub const SIZE_IN_BYTES: usize = 2 * std::mem::size_of::<u64>();

    #[must_use]
    pub fn new(left: u64, right: u64) -> Self {
        Self { left, right }
    }

    #[must_use]
    pub fn left(&self) -> u64 {
        self.left
    }

    #[must_use]
    pub fn right(&self) -> u64 {
        self.right
    }

    /// Deserializes this instance from a slice of bytes
    ///
    /// ## Errors
    /// if buffer does not have enough capacity to hold a valid value of this instance.
    #[allow(clippy::missing_panics_doc)]
    pub fn deserialize(buf: &[u8]) -> io::Result<Self> {
        if buf.len() < Self::SIZE_IN_BYTES {
            Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "not enough buffer capacity",
            ))
        } else {
            let left_buf: [u8; 8] = buf[..8].try_into().unwrap();
            let right_buf: [u8; 8] = buf[8..16].try_into().unwrap();

            Ok(Self {
                left: u64::from_le_bytes(left_buf),
                right: u64::from_le_bytes(right_buf),
            })
        }
    }

    /// Serializes this instance into a mutable slice of bytes, writing from index 0.
    ///
    /// ## Errors
    /// if buffer capacity is not sufficient to hold all the bytes.
    pub fn serialize(&self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.len() < Self::SIZE_IN_BYTES {
            Err(io::Error::new(
                ErrorKind::WriteZero,
                "not enough buffer capacity",
            ))
        } else {
            buf[..8].copy_from_slice(&self.left.to_le_bytes());
            buf[8..16].copy_from_slice(&self.right.to_le_bytes());

            Ok(Self::SIZE_IN_BYTES)
        }
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::*;
    use proptest::proptest;

    #[test]
    fn deserialize_large_buf() {
        let mut buf = Vec::with_capacity(33);
        let expected = XorReplicated {
            left: u64::from(u32::MAX),
            right: u64::MAX - 1,
        };
        buf.extend_from_slice(&expected.left.to_le_bytes());
        buf.extend_from_slice(&expected.right.to_le_bytes());

        assert_eq!(expected, XorReplicated::deserialize(&buf).unwrap());
    }

    #[test]
    fn deserialize_small_buf() {
        let buf = vec![0u8; 15];
        assert_eq!(
            XorReplicated::deserialize(&buf).unwrap_err().kind(),
            ErrorKind::UnexpectedEof
        );
    }

    fn serde_internal(a: u64, b: u64) {
        let v = XorReplicated { left: a, right: b };
        let mut buf = [0u8; 16];
        v.serialize(&mut buf).unwrap();
        assert_eq!(v, XorReplicated::deserialize(&buf).unwrap());
    }

    proptest! {
        #[test]
        fn serde(a in 0..u64::MAX, b in 0..u64::MAX) {
            serde_internal(a, b);
        }
    }
}
