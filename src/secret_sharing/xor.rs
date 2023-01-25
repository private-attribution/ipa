use crate::bits::Serializable;
use std::io;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XorReplicated {
    left: u64,
    right: u64,
}

impl XorReplicated {
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
}

impl Serializable for XorReplicated {
    const SIZE_IN_BYTES: usize = 2 * std::mem::size_of::<u64>();

    fn serialize(self, buf: &mut [u8]) -> io::Result<()> {
        if buf.len() < Self::SIZE_IN_BYTES {
            Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "not enough buffer capacity",
            ))
        } else {
            buf[..8].copy_from_slice(&self.left.to_le_bytes());
            buf[8..16].copy_from_slice(&self.right.to_le_bytes());

            Ok(())
        }
    }

    fn deserialize(buf: &[u8]) -> io::Result<Self> {
        if buf.len() < Self::SIZE_IN_BYTES {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
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
}
