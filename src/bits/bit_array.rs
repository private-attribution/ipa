use super::{BitArray, BooleanOps};
use bitvec::prelude::{BitArr, Lsb0};
use std::{
    fmt::Debug,
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Index, Not},
};

/// Bit store type definition. Eight `u8` blocks.
type U8_8 = BitArr!(for 64, in u8, Lsb0);

/// 64-bit array of bits. Similar to `u64`, but supports boolean algebra, and
/// provides access to individual bits via index.
///
/// Bits are stored in the Little-Endian format. Accessing the first element
/// like `s[0]` will return the LSB.
///
/// ## Example
/// ```
/// use raw_ipa::bits::BitArray64;
///
/// let s = BitArray64::from(2_u128);
/// let b0 = s[0_usize];
/// let b1 = s[1_usize];
///
/// assert_eq!(b0, 0);
/// assert_eq!(b1, 1);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BitArray64(U8_8);

impl BitArray for BitArray64 {
    const SIZE_IN_BYTES: usize = std::mem::size_of::<Self>();

    #[allow(dead_code)]
    const ZERO: Self = Self(U8_8::ZERO);
}

impl BooleanOps for BitArray64 {}

impl BitAnd for BitArray64 {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl BitAndAssign for BitArray64 {
    fn bitand_assign(&mut self, rhs: Self) {
        *self.0.as_mut_bitslice() &= rhs.0;
    }
}

impl BitOr for BitArray64 {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for BitArray64 {
    fn bitor_assign(&mut self, rhs: Self) {
        *self.0.as_mut_bitslice() |= rhs.0;
    }
}

impl BitXor for BitArray64 {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl BitXorAssign for BitArray64 {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self.0.as_mut_bitslice() ^= rhs.0;
    }
}

impl Not for BitArray64 {
    type Output = Self;
    fn not(self) -> Self::Output {
        Self(!self.0)
    }
}

impl<T: Into<u128>> From<T> for BitArray64 {
    fn from(v: T) -> Self {
        Self(U8_8::new(
            v.into().to_le_bytes()[0..<Self as BitArray>::SIZE_IN_BYTES]
                .try_into()
                .unwrap(),
        ))
    }
}

impl Index<usize> for BitArray64 {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        if self.0.as_bitslice()[index] {
            &1
        } else {
            &0
        }
    }
}

impl Index<u32> for BitArray64 {
    type Output = u8;

    fn index(&self, index: u32) -> &Self::Output {
        &self[index as usize]
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::BitArray64;
    use crate::bits::BitArray;
    use bitvec::prelude::*;
    use rand::{thread_rng, Rng};

    #[test]
    pub fn basic() {
        assert_eq!(BitArray64::ZERO.0, bitarr!(u64, Lsb0; 0));
        assert_eq!(BitArray64::from(1_u128).0, bitarr!(u64, Lsb0; 1));
        assert_eq!(
            BitArray64::from((1_u128 << (BitArray64::SIZE_IN_BYTES * 8)) + 1).0,
            bitarr!(u64, Lsb0; 1)
        );
    }

    #[test]
    pub fn index() {
        let s = BitArray64::from((1_u128 << (BitArray64::SIZE_IN_BYTES * 8)) + 1);
        assert_eq!(s[0_usize], 1);
        assert_eq!(s[63_u32], 0);
    }

    #[test]
    #[should_panic]
    pub fn out_of_count_index() {
        let s = BitArray64::from(1_u128);
        // Below assert doesn't matter. The indexing should panic
        assert_eq!(s[64_usize], 0);
    }

    #[test]
    pub fn boolean_ops() {
        let mut rng = thread_rng();
        for _ in 0..1000 {
            let a = rng.gen::<u128>();
            let b = rng.gen::<u128>();

            let and = BitArray64::from(a & b);
            let or = BitArray64::from(a | b);
            let xor = BitArray64::from(a ^ b);
            let not = BitArray64::from(!a);

            let a = BitArray64::from(a);
            let b = BitArray64::from(b);

            assert_eq!(a & b, and);
            assert_eq!(a | b, or);
            assert_eq!(a ^ b, xor);
            assert_eq!(!a, not);
        }
    }
}
