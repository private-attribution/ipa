use super::BitArray;
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
/// let s = BitArray64::try_from(2_u128).unwrap();
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
    const BITS: u32 = 64;

    const ZERO: Self = Self(U8_8::ZERO);

    fn truncate_from<T: Into<u128>>(v: T) -> Self {
        Self(U8_8::new(
            v.into().to_le_bytes()[0..<Self as BitArray>::SIZE_IN_BYTES]
                .try_into()
                .unwrap(),
        ))
    }
}

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

impl TryFrom<u128> for BitArray64 {
    type Error = String;

    /// Fallible conversion from `u128` to this data type. The input value must
    /// be at most `Self::BITS` long. That is, the integer value must be less than
    /// or equal to `2^Self::BITS`, or it will return an error.
    fn try_from(v: u128) -> Result<Self, Self::Error> {
        if 128 - v.leading_zeros() <= Self::BITS {
            Ok(Self::truncate_from(v))
        } else {
            Err(format!(
                "Bit array size {} is too small to hold the value {}.",
                Self::BITS,
                v
            ))
        }
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
        let one = bitarr!(u64, Lsb0; 1);

        assert_eq!(BitArray64::ZERO.0, bitarr!(u64, Lsb0; 0));
        assert_eq!(BitArray64::try_from(1_u128).unwrap().0, one);

        let b65 = (1_u128 << BitArray64::BITS) + 1;
        assert!(BitArray64::try_from(b65).is_err());
        assert_eq!(
            BitArray64::try_from(b65 & u128::from(u64::MAX)).unwrap().0,
            one
        );

        assert_eq!(BitArray64::truncate_from(b65).0, one);
    }

    #[test]
    pub fn index() {
        let s = BitArray64::try_from(1_u128).unwrap();
        assert_eq!(s[0_usize], 1);
        assert_eq!(s[63_u32], 0);
    }

    #[test]
    #[should_panic]
    pub fn out_of_count_index() {
        let s = BitArray64::try_from(1_u128).unwrap();
        // Below assert doesn't matter. The indexing should panic
        assert_eq!(s[64_usize], 0);
    }

    #[test]
    pub fn boolean_ops() {
        let mut rng = thread_rng();
        let a = rng.gen::<u128>();
        let b = rng.gen::<u128>();

        let and = BitArray64::truncate_from(a & b);
        let or = BitArray64::truncate_from(a | b);
        let xor = BitArray64::truncate_from(a ^ b);
        let not = BitArray64::truncate_from(!a);

        let a = BitArray64::try_from(a & u128::from(u64::MAX)).unwrap();
        let b = BitArray64::try_from(b & u128::from(u64::MAX)).unwrap();

        assert_eq!(a & b, and);
        assert_eq!(a | b, or);
        assert_eq!(a ^ b, xor);
        assert_eq!(!a, not);
    }
}
