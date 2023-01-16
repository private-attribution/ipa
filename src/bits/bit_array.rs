use super::BitArray;
use crate::secret_sharing::SharedValue;
use bitvec::prelude::{BitArr, Lsb0};

/// Bit store type definition. Five `u8` blocks.
type U8_5 = BitArr!(for 40, in u8, Lsb0);
/// Bit store type definition. Eight `u8` blocks.
type U8_8 = BitArr!(for 64, in u8, Lsb0);

macro_rules! bit_array_impl {
    ( $modname:ident, $name:ident, $store:ty, $bits:expr ) => {
        mod $modname {
            use super::*;

            /// N-bit array of bits. It supports boolean algebra, and provides access
            /// to individual bits via index.
            ///
            /// Bits are stored in the Little-Endian format. Accessing the first element
            /// like `b[0]` will return the LSB.
            #[derive(std::fmt::Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
            pub struct $name($store);

            impl SharedValue for $name {
                const SIZE_IN_BYTES: usize = std::mem::size_of::<Self>();
                const BITS: u32 = $bits;
            }

            impl BitArray for $name {
                const ZERO: Self = Self(<$store>::ZERO);

                fn truncate_from<T: Into<u128>>(v: T) -> Self {
                    Self(<$store>::new(
                        v.into().to_le_bytes()[0..<Self as SharedValue>::SIZE_IN_BYTES]
                            .try_into()
                            .unwrap(),
                    ))
                }
            }

            impl std::ops::BitAnd for $name {
                type Output = Self;
                fn bitand(self, rhs: Self) -> Self::Output {
                    Self(self.0 & rhs.0)
                }
            }

            impl std::ops::BitAndAssign for $name {
                fn bitand_assign(&mut self, rhs: Self) {
                    *self.0.as_mut_bitslice() &= rhs.0;
                }
            }

            impl std::ops::BitOr for $name {
                type Output = Self;
                fn bitor(self, rhs: Self) -> Self::Output {
                    Self(self.0 | rhs.0)
                }
            }

            impl std::ops::BitOrAssign for $name {
                fn bitor_assign(&mut self, rhs: Self) {
                    *self.0.as_mut_bitslice() |= rhs.0;
                }
            }

            impl std::ops::BitXor for $name {
                type Output = Self;
                fn bitxor(self, rhs: Self) -> Self::Output {
                    Self(self.0 ^ rhs.0)
                }
            }

            impl std::ops::BitXorAssign for $name {
                fn bitxor_assign(&mut self, rhs: Self) {
                    *self.0.as_mut_bitslice() ^= rhs.0;
                }
            }

            impl std::ops::Not for $name {
                type Output = Self;
                fn not(self) -> Self::Output {
                    Self(!self.0)
                }
            }

            impl TryFrom<u128> for $name {
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

            impl std::ops::Index<usize> for $name {
                type Output = bool;

                fn index(&self, index: usize) -> &Self::Output {
                    &self.0.as_bitslice()[index]
                }
            }

            impl std::ops::Index<u32> for $name {
                type Output = bool;

                fn index(&self, index: u32) -> &Self::Output {
                    &self[index as usize]
                }
            }

            #[cfg(all(test, not(feature = "shuttle")))]
            mod tests {
                use super::*;
                use crate::{bits::BitArray, secret_sharing::SharedValue};
                use bitvec::prelude::*;
                use rand::{thread_rng, Rng};

                const MASK: u128 = u128::MAX >> (128 - $name::BITS);

                #[test]
                pub fn basic() {
                    let zero = bitarr!(u8, Lsb0; 0; $bits);
                    let mut one = bitarr!(u8, Lsb0; 0; $bits);
                    *one.first_mut().unwrap() = true;

                    assert_eq!($name::ZERO.0, zero);
                    assert_eq!($name::try_from(1_u128).unwrap().0, one);

                    let max_plus_one = (1_u128 << $name::BITS) + 1;
                    assert!($name::try_from(max_plus_one).is_err());
                    assert_eq!(
                        $name::try_from(max_plus_one & MASK).unwrap().0,
                        one
                    );

                    assert_eq!($name::truncate_from(max_plus_one).0, one);
                }

                #[test]
                pub fn index() {
                    let s = $name::try_from(1_u128).unwrap();
                    assert_eq!(s[0_usize], true);
                    assert_eq!(s[($bits - 1) as u32], false);
                }

                #[test]
                #[should_panic]
                pub fn out_of_count_index() {
                    let s = $name::try_from(1_u128).unwrap();
                    // Below assert doesn't matter. The indexing should panic
                    assert_eq!(s[$bits as usize], false);
                }

                #[test]
                pub fn boolean_ops() {
                    let mut rng = thread_rng();
                    let a = rng.gen::<u128>();
                    let b = rng.gen::<u128>();

                    let and = $name::truncate_from(a & b);
                    let or = $name::truncate_from(a | b);
                    let xor = $name::truncate_from(a ^ b);
                    let not = $name::truncate_from(!a);

                    let a = $name::truncate_from(a);
                    let b = $name::truncate_from(b);

                    assert_eq!(a & b, and);
                    assert_eq!(a | b, or);
                    assert_eq!(a ^ b, xor);
                    assert_eq!(!a, not);
                }
            }
        }

        pub use $modname::$name;
    };
}

bit_array_impl!(bit_array_64, BitArray64, U8_8, 64);
bit_array_impl!(bit_array_40, BitArray40, U8_5, 40);
