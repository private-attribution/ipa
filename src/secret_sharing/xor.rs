use bitvec::prelude::*;
use std::{
    fmt::Debug,
    ops::{BitXor, BitXorAssign, Index},
};

#[derive(Clone, Copy, Debug)]
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

/// Bit store size of `XorSecretShare` in bytes.
const BIT_STORE_SIZE_IN_BYTES: usize = 4;

/// XOR secret share.
///
/// Bits are stored in the Little-Endian format. Accessing the first element
/// like `s[0]` will return the LSB.
///
/// ## Example
/// ```
/// use raw_ipa::secret_sharing::XorSecretShare;
///
/// let s = XorSecretShare::from(2_u128);
/// let b0 = s[0];
/// let b1 = s[1];
///
/// assert_eq!(b0, 0);
/// assert_eq!(b1, 1);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct XorSecretShare(BitArray<[u8; BIT_STORE_SIZE_IN_BYTES], Lsb0>);

impl XorSecretShare {
    const SIZE_IN_BYTES: usize = BIT_STORE_SIZE_IN_BYTES;
    #[allow(dead_code)]
    const ZERO: Self = Self(BitArray::<[u8; Self::SIZE_IN_BYTES], Lsb0>::ZERO);
}

impl BitXor for XorSecretShare {
    type Output = Self;

    fn bitxor(mut self, rhs: Self) -> Self::Output {
        self ^= rhs;
        self
    }
}

impl BitXorAssign for XorSecretShare {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self.0.as_mut_bitslice() ^= rhs.0;
    }
}

impl<T: Into<u128>> From<T> for XorSecretShare {
    fn from(v: T) -> Self {
        Self(BitArray::<_, Lsb0>::new(
            v.into().to_le_bytes()[0..Self::SIZE_IN_BYTES]
                .try_into()
                .unwrap(),
        ))
    }
}

impl Index<usize> for XorSecretShare {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        if self.0.as_bitslice()[index] {
            &1
        } else {
            &0
        }
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use crate::secret_sharing::xor::BIT_STORE_SIZE_IN_BYTES;

    use super::XorSecretShare;
    use bitvec::prelude::*;
    use rand::{thread_rng, Rng};

    fn secret_share(a: u128, b: u128, c: u128) -> (XorSecretShare, XorSecretShare, XorSecretShare) {
        (
            XorSecretShare::from(a),
            XorSecretShare::from(b),
            XorSecretShare::from(c),
        )
    }

    #[test]
    pub fn basic() {
        assert_eq!(XorSecretShare::ZERO.0, bitarr!(u32, Lsb0; 0));
        assert_eq!(
            XorSecretShare::from(1_u128).0.as_bitslice(),
            bits![
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0
            ],
        );
        assert_eq!(
            XorSecretShare::from((1_u128 << (BIT_STORE_SIZE_IN_BYTES * 8)) + 1)
                .0
                .as_bitslice(),
            bits![
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0
            ],
        );
    }

    #[test]
    pub fn index() {
        let byte: u8 = 0b1010_1010;
        let s = XorSecretShare::from(byte);
        assert_eq!(s[0], 0);
        assert_eq!(s[1], 1);
        assert_eq!(s[2], 0);
        assert_eq!(s[3], 1);
        assert_eq!(s[4], 0);
        assert_eq!(s[5], 1);
        assert_eq!(s[6], 0);
        assert_eq!(s[7], 1);
    }

    #[test]
    pub fn xor_secret_sharing() {
        let mut rng = thread_rng();
        for _ in 0..1000 {
            let secret = rng.gen::<u128>();
            let a = rng.gen::<u128>();
            let b = rng.gen::<u128>();
            let c = secret ^ a ^ b;
            let (s0, s1, s2) = secret_share(a, b, c);
            assert_eq!(XorSecretShare::from(secret), s0 ^ s1 ^ s2);
        }
    }
}
