use super::{BitArray, BooleanOps};
use bitvec::prelude::{BitArr, Lsb0};
use std::{
    fmt::Debug,
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Index, Not},
};

/// Bit store size of `XorSecretShare` in bytes.
const BIT_STORE_SIZE_IN_BYTES: usize = 4;
type U8_4 = BitArr!(for BIT_STORE_SIZE_IN_BYTES * 8, in u8, Lsb0);

/// 32-bit array of bits. Similar to `u32`, but supports boolean algebra, and
/// provides access to individual bits via index.
///
/// Bits are stored in the Little-Endian format. Accessing the first element
/// like `s[0]` will return the LSB.
///
/// ## Example
/// ```
/// use raw_ipa::bits::BitArray32;
///
/// let s = BitArray32::from(2_u128);
/// let b0 = s[0];
/// let b1 = s[1];
///
/// assert_eq!(b0, 0);
/// assert_eq!(b1, 1);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BitArray32(U8_4);

impl BitArray for BitArray32 {
    const SIZE_IN_BYTES: usize = BIT_STORE_SIZE_IN_BYTES;

    #[allow(dead_code)]
    const ZERO: Self = Self(U8_4::ZERO);
}

impl BooleanOps for BitArray32 {}

impl BitAnd for BitArray32 {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl BitAndAssign for BitArray32 {
    fn bitand_assign(&mut self, rhs: Self) {
        *self.0.as_mut_bitslice() &= rhs.0;
    }
}

impl BitOr for BitArray32 {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for BitArray32 {
    fn bitor_assign(&mut self, rhs: Self) {
        *self.0.as_mut_bitslice() |= rhs.0;
    }
}

impl BitXor for BitArray32 {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl BitXorAssign for BitArray32 {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self.0.as_mut_bitslice() ^= rhs.0;
    }
}

impl Not for BitArray32 {
    type Output = Self;
    fn not(self) -> Self::Output {
        Self(!self.0)
    }
}

impl<T: Into<u128>> From<T> for BitArray32 {
    fn from(v: T) -> Self {
        Self(U8_4::new(
            v.into().to_le_bytes()[0..<Self as BitArray>::SIZE_IN_BYTES]
                .try_into()
                .unwrap(),
        ))
    }
}

impl Index<usize> for BitArray32 {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        if self.0.as_bitslice()[index] {
            &1
        } else {
            &0
        }
    }
}

#[cfg(test)]
impl PartialEq<u128> for BitArray32 {
    fn eq(&self, other: &u128) -> bool {
        self.0 == Self::from(*other).0
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::BitArray32;
    use crate::bits::BitArray;
    use bitvec::prelude::*;
    use rand::{thread_rng, Rng};

    #[test]
    pub fn basic() {
        assert_eq!(BitArray32::ZERO.0, bitarr!(u32, Lsb0; 0));
        assert_eq!(
            BitArray32::from(1_u128).0.as_bitslice(),
            bits![
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0
            ],
        );
        assert_eq!(
            BitArray32::from((1_u128 << (BitArray32::SIZE_IN_BYTES * 8)) + 1)
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
        let s = BitArray32::from((1_u128 << (BitArray32::SIZE_IN_BYTES * 8)) + 1);
        assert_eq!(s[0], 1);
        assert_eq!(s[31], 0);
    }

    #[test]
    #[should_panic]
    pub fn out_of_count_index() {
        let s = BitArray32::from(1_u128);
        // below assert should panic
        assert_eq!(s[32], 0);
    }

    #[test]
    pub fn boolean_ops() {
        let mut rng = thread_rng();
        for _ in 0..1000 {
            let a = rng.gen::<u128>();
            let b = rng.gen::<u128>();

            // Mask the first 32 bits
            let and = (a & b) & u128::from(u32::MAX);
            let or = (a | b) & u128::from(u32::MAX);
            let xor = (a ^ b) & u128::from(u32::MAX);
            let not = !a & u128::from(u32::MAX);

            let a = BitArray32::from(a);
            let b = BitArray32::from(b);

            assert_eq!(a & b, and);
            assert_eq!(a | b, or);
            assert_eq!(a ^ b, xor);
            assert_eq!(!a, not);
        }
    }
}
