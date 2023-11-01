use bitvec::{prelude::{bitarr, BitArr, Lsb0}, slice::Iter};
use generic_array::GenericArray;
use typenum::{Unsigned, U8};

use crate::{
    ff::boolean::Boolean
};


/// The implementation below cannot be constrained without breaking Rust's
/// macro processor.  This noop ensures that the instance of `GenericArray` used
/// is `Copy`.  It should be - it's the same size as the `BitArray` instance.
fn assert_copy<C: Copy>(c: C) -> C {
    c
}

macro_rules! store_impl {
    ( $arraylength:ty, $bits:expr ) => {
        //type $store = BitArr!(for $bits, in u8, Lsb0);
        use crate::{
            secret_sharing::Block,
        };

        impl Block for BitArr!(for $bits, in u8, Lsb0) {
            type Size = $arraylength;
        }

    };
}

pub struct BAIterator<'a> {
    iterator: Iter<'a,u8,Lsb0>,
}

impl<'a> Iterator for BAIterator<'a> {
    type Item = Boolean;

    fn next(&mut self) -> Option<Self::Item> {
        match self.iterator.next() {
            Some(v) => Some(Boolean::from(*v)),
            None => None,
        }
    }
}

macro_rules! boolean_array_impl {
    ( $modname:ident, $name:ident, $bits:expr, $one:expr ) => {

        mod $modname {
            use super::*;

            use crate::{
                ff::{Field, Serializable, boolean::Boolean, ArrayAccess},
                secret_sharing::{replicated::{semi_honest::AdditiveShare,ReplicatedSecretSharing},SharedValue},
            };



            type Store = BitArr!(for $bits, in u8, Lsb0);

            ///
            #[derive(Clone, Copy, PartialEq, Eq, Debug)]
            pub struct $name(Store);

            impl ArrayAccess for $name
            {
                type Element = Boolean;

                fn get(&self, index: usize) -> Self::Element
                {
                    debug_assert!(index < usize::try_from(<$name>::BITS).unwrap());
                    self.0[index].into()
                }

                fn set(&mut self, index: usize, e: Self::Element)
                {
                    debug_assert!(index < usize::try_from(<$name>::BITS).unwrap());
                    self.0.set(index ,bool::from(e));
                }
            }

            impl From<Boolean> for $name
            {
                fn from(s: Boolean) -> Self {
                    let mut result = <$name>::ZERO;
                    for i in 0..usize::try_from(<$name>::BITS).unwrap()
                    {
                        result.set(i,s);
                    }
                    result
                }
            }

            impl SharedValue for $name {
                type Storage = Store;
                const BITS: u32 = $bits;
                const ZERO: Self = Self(<Store>::ZERO);
            }

            impl Serializable for $name {
                type Size = <Store as Block>::Size;

                fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
                    buf.copy_from_slice(self.0.as_raw_slice());
                }

                fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Self {
                    Self(<Store>::new(assert_copy(*buf).into()))
                }
            }

            impl std::ops::Add for $name {
                type Output = Self;
                fn add(self, rhs: Self) -> Self::Output {
                    Self(self.0 ^ rhs.0)
                }
            }

            impl std::ops::AddAssign for $name {
                fn add_assign(&mut self, rhs: Self) {
                    *self.0.as_mut_bitslice() ^= rhs.0;
                }
            }

            impl std::ops::Sub for $name {
                type Output = Self;
                fn sub(self, rhs: Self) -> Self::Output {
                    self + rhs
                }
            }

            impl std::ops::SubAssign for $name {
                fn sub_assign(&mut self, rhs: Self) {
                    *self += rhs;
                }
            }

            impl std::ops::Neg for $name {
                type Output = Self;
                fn neg(self) -> Self::Output {
                    Self(self.0)
                }
            }

            impl Field for $name {
                const ONE: Self = Self($one);

                fn as_u128(&self) -> u128 {
                    (*self).into()
                }

                fn truncate_from<T: Into<u128>>(v: T) -> Self {
                    const MASK: u128 = u128::MAX >> (u128::BITS - <$name>::BITS);
                    let v = &(v.into() & MASK).to_le_bytes()[..<Self as Serializable>::Size::to_usize()];
                    Self(<Store>::new(v.try_into().unwrap()))
                }
            }

            impl rand::distributions::Distribution<$name> for rand::distributions::Standard {
                fn sample<R: crate::rand::Rng + ?Sized>(&self, rng: &mut R) -> $name {
                    <$name>::truncate_from(rng.gen::<u128>())
                }
            }

            impl std::ops::Mul for $name {
                type Output = Self;
                fn mul(self, rhs: Self) -> Self::Output {
                    Self(self.0 & rhs.0)
                }
            }

            impl std::ops::MulAssign for $name {
                fn mul_assign(&mut self, rhs: Self) {
                    *self = *self * rhs;
                }
            }

            impl TryFrom<u128> for $name {
                type Error = crate::error::Error;

                /// Fallible conversion from `u128` to this data type. The input value must
                /// be at most `Self::BITS` long. That is, the integer value must be less than
                /// or equal to `2^Self::BITS`, or it will return an error.
                fn try_from(v: u128) -> Result<Self, Self::Error> {
                    if u128::BITS - v.leading_zeros() <= Self::BITS {
                        Ok(Self::truncate_from(v))
                    } else {
                        Err(crate::error::Error::FieldValueTruncation(format!(
                            "Bit array size {} is too small to hold the value {}.",
                            Self::BITS,
                            v
                        )))
                    }
                }
            }

            impl From<$name> for Store {
                fn from(v: $name) -> Self {
                    v.0
                }
            }

            #[allow(clippy::from_over_into)]
            impl Into<u128> for $name {
                /// Infallible conversion from this data type to `u128`. We assume that the
                /// inner value is at most 128-bit long. That is, the integer value must be
                /// less than or equal to `2^Self::BITS`. Should be long enough for our use
                /// case.
                fn into(self) -> u128 {
                    debug_assert!(<$name>::BITS <= 128);
                    self
                        .0
                        .iter()
                        .by_refs()
                        .enumerate()
                        .fold(0_u128, |acc, (i, b)| acc + ((*b as u128) << i))
                }
            }


            impl<'a> IntoIterator for &'a $name {
                type Item = Boolean;
                type IntoIter = BAIterator<'a>;

                fn into_iter(self) -> Self::IntoIter {
                    BAIterator{iterator: self.0.iter()}
                }
            }

            impl From<AdditiveShare<Boolean>> for AdditiveShare<$name>
            {
                fn from(s: AdditiveShare<Boolean>) -> Self
                {
                    AdditiveShare::<$name>::new(s.left().into(),s.right().into())
                }
            }


            #[cfg(all(test, unit_test))]
            mod tests {
                use super::*;
                use rand::{thread_rng, Rng};

                #[test]
                fn set_boolean_array(){
                    let mut rng = thread_rng();
                    let i = rng.gen::<usize>()% usize::try_from(<$name>::BITS).unwrap();
                    let a = rng.gen::<Boolean>();
                    let mut ba = rng.gen::<$name>();
                    ba.set(i,a);
                    assert_eq!(ba.get(i),a);
                }

                #[test]
                fn iterate_boolean_array(){
                    let bits = $name::ONE;
                    let iter = bits.into_iter();
                    for (i,j) in iter.enumerate() {
                        if i==0 {
                            assert_eq!(j, Boolean::ONE);
                        } else {
                            assert_eq!(j, Boolean::ZERO);
                        }
                    }
                }
            }
        }

        pub use $modname::$name;
        };
}


//impl store for U6
store_impl!(U8, 64);

//impl BA48
boolean_array_impl! (
    boolean_array_64,
    BA64,
    64,
    bitarr ! ( const u8, Lsb0;
        1, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0)
    );

