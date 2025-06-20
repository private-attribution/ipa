use std::{
    fmt::{Debug, Formatter},
    iter::repeat_with,
};

use bitvec::{
    prelude::{BitArr, BitSlice, Lsb0},
    slice::Iter,
};
use generic_array::GenericArray;
use typenum::{U2, U8, U12, U14, U18, U32, Unsigned};

use crate::{
    error::LengthError,
    ff::{ArrayAccess, Expand, Field, Gf32Bit, Serializable, U128Conversions, boolean::Boolean},
    protocol::prss::{FromRandom, FromRandomU128},
    secret_sharing::{Block, SharedValue, StdArray, Vectorizable},
};

/// The implementation below cannot be constrained without breaking Rust's
/// macro processor.  This noop ensures that the instance of `GenericArray` used
/// is `Copy`.  It should be - it's the same size as the `BitArray` instance.
fn assert_copy<C: Copy>(c: C) -> C {
    c
}

/// this might clash with Galois field, i.e. `galois_field.rs`
/// so only use it for byte sizes for which Block has not been defined yet
macro_rules! store_impl {
    ($arraylength:ty, $bits:expr) => {
        impl Block for BitArr!(for $bits, in u8, Lsb0) {
            type Size = $arraylength;
        }
    };
}

pub trait BooleanArray:
    SharedValue
    + ArrayAccess<Output = Boolean>
    + Expand<Boolean>
    + FromIterator<Boolean>
    + TryInto<Vec<Gf32Bit>, Error = LengthError>
    + for<'a> TryFrom<&'a BitSlice<u8, Lsb0>, Error = LengthError>
{
    #[must_use]
    fn as_bitslice(&self) -> &BitSlice<u8, Lsb0>;

    #[must_use]
    fn as_mut_bitslice(&mut self) -> &mut BitSlice<u8, Lsb0>;
}

/// Iterator returned by `.iter()` on Boolean arrays
pub struct BAIterator<'a> {
    iterator: std::iter::Take<Iter<'a, u8, Lsb0>>,
}

/// Iterator returned by `.into_iter()` on Boolean arrays
pub struct BAOwnedIterator<S: IntoIterator> {
    iterator: std::iter::Take<S::IntoIter>,
}

///impl Iterator for all Boolean arrays
impl Iterator for BAIterator<'_> {
    type Item = Boolean;

    fn next(&mut self) -> Option<Self::Item> {
        self.iterator.next().map(|v| Boolean::from(*v))
    }
}

impl ExactSizeIterator for BAIterator<'_> {
    fn len(&self) -> usize {
        self.iterator.len()
    }
}

impl<S> Iterator for BAOwnedIterator<S>
where
    S: IntoIterator,
    S::IntoIter: ExactSizeIterator,
    <S::IntoIter as Iterator>::Item: Into<Boolean>,
{
    type Item = Boolean;

    fn next(&mut self) -> Option<Self::Item> {
        self.iterator.next().map(Into::into)
    }
}

impl<S> ExactSizeIterator for BAOwnedIterator<S>
where
    S: IntoIterator,
    S::IntoIter: ExactSizeIterator,
    <S::IntoIter as Iterator>::Item: Into<Boolean>,
{
    fn len(&self) -> usize {
        self.iterator.len()
    }
}

/// Utility for writing multiple values into a `BooleanArray`.
pub struct BooleanArrayWriter<'a>(&'a mut BitSlice<u8, Lsb0>);

impl<'a> BooleanArrayWriter<'a> {
    pub fn new<T: BooleanArray>(inner: &'a mut T) -> Self {
        Self(inner.as_mut_bitslice())
    }

    /// Append a single Boolean to our `BooleanArray`.
    ///
    /// ## Panics
    /// If the write goes past the end of the `BooleanArray`.
    #[allow(clippy::return_self_not_must_use, clippy::must_use_candidate)]
    pub fn write_boolean(self, bit: Boolean) -> Self {
        self.0.set(0, bit.into());
        Self(&mut self.0[1..])
    }

    /// Append a `BooleanArray` to our `BooleanArray`.
    ///
    /// ## Panics
    /// If the write goes past the end of the `BooleanArray`.
    #[allow(clippy::return_self_not_must_use)]
    pub fn write<T: BooleanArray>(self, data: &T) -> Self {
        let len = usize::try_from(T::BITS).unwrap();
        self.0[..len].copy_from_bitslice(data.as_bitslice());
        Self(&mut self.0[len..])
    }
}

/// Utility for reading multiple values from a `BooleanArray`.
pub struct BooleanArrayReader<'a>(&'a BitSlice<u8, Lsb0>);

impl<'a> BooleanArrayReader<'a> {
    pub fn new<T: BooleanArray>(inner: &'a T) -> Self {
        Self(inner.as_bitslice())
    }

    /// Read a single Boolean from our `BooleanArray`.
    ///
    /// ## Panics
    /// If the read goes past the end of the `BooleanArray`.
    #[must_use]
    pub fn read_boolean(self) -> (Boolean, Self) {
        let result = self.0[0].into();
        (result, Self(self.0.get(1..).unwrap()))
    }

    /// Read a `BooleanArray` from our `BooleanArray`.
    ///
    /// ## Panics
    /// If the read goes past the end of the `BooleanArray`.
    #[must_use]
    pub fn read<T: BooleanArray>(self) -> (T, Self) {
        let len = usize::try_from(T::BITS).unwrap();
        let result = T::try_from(&self.0[..len]).unwrap();
        (result, Self(self.0.get(len..).unwrap()))
    }
}

// Macro for boolean arrays ≤ 128 bits.
macro_rules! boolean_array_impl_small {
    ($modname:ident, $name:ident, $bits:tt, $deser_type:tt) => {
        boolean_array_impl!($modname, $name, $bits, $deser_type);

        impl U128Conversions for $name {
            fn truncate_from<T: Into<u128>>(v: T) -> Self {
                let v = v.into();
                let mut val = <Self as SharedValue>::ZERO;
                for i in 0..std::cmp::min(128, $bits) {
                    val.set(i, Boolean::from((v >> i & 1) == 1));
                }

                val
            }

            fn as_u128(&self) -> u128 {
                (*self).into()
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

        impl From<$name> for u128 {
            /// Infallible conversion from this data type to `u128`.
            fn from(v: $name) -> u128 {
                debug_assert!(<$name>::BITS <= 128);
                v.0.iter()
                    .by_refs()
                    .enumerate()
                    .fold(0_u128, |acc, (i, b)| acc + (u128::from(*b) << i))
            }
        }

        #[cfg(any(test, unit_test))]
        impl std::cmp::PartialEq<u128> for $name {
            fn eq(&self, other: &u128) -> bool {
                self.as_u128() == *other
            }
        }

        impl rand::distributions::Distribution<$name> for rand::distributions::Standard {
            fn sample<R: crate::rand::Rng + ?Sized>(&self, rng: &mut R) -> $name {
                <$name>::from_random_u128(rng.r#gen::<u128>())
            }
        }

        impl FromRandomU128 for $name {
            fn from_random_u128(src: u128) -> Self {
                Self::truncate_from(src)
            }
        }
    };
}

#[derive(thiserror::Error, Debug)]
#[error("The provided byte slice contains non-zero value(s) {0:?} in padding bits [{1}..]")]
pub struct NonZeroPadding<B: Block>(pub GenericArray<u8, B::Size>, pub usize);

/// Macro to implement `Serializable` trait for boolean arrays. Depending on the size, conversion from [u8; N] to `BAXX`
/// can be fallible (if N is not a multiple of 8) or infallible. This macro takes care of it and provides the correct
/// implementation. Because macros can't do math, a hint is required to advise it which implementation it should provide.
#[macro_export]
macro_rules! impl_serializable_trait {
    ($name: ident, $bits: tt, $store: ty, fallible) => {
        impl Serializable for $name {
            type Size = <$store as Block>::Size;
            type DeserializationError = NonZeroPadding<$store>;

            fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
                buf.copy_from_slice(self.0.as_raw_slice());
            }

            fn deserialize(
                buf: &GenericArray<u8, Self::Size>,
            ) -> Result<Self, Self::DeserializationError> {
                let raw_val = <$store>::new(assert_copy(*buf).into());

                // make sure trailing bits (padding) are zeroes.
                if raw_val[$bits..].not_any() {
                    Ok(Self(raw_val))
                } else {
                    Err(NonZeroPadding(
                        GenericArray::from_array(raw_val.into_inner()),
                        $bits,
                    ))
                }
            }
        }

        #[cfg(all(test, unit_test))]
        mod fallible_serialization_tests {
            use super::*;

            /// [`https://github.com/private-attribution/ipa/issues/911`]
            #[test]
            fn deals_with_padding() {
                fn deserialize(val: $store) -> Result<$name, NonZeroPadding<$store>> {
                    $name::deserialize(&GenericArray::from_array(val.into_inner()))
                }

                assert_ne!(
                    0,
                    $bits % 8,
                    "Padding only makes sense for lengths that are not multiples of 8."
                );

                let mut non_zero_padding = $name::ZERO.0;
                non_zero_padding.set($bits, true);
                assert_eq!(
                    GenericArray::from_array(non_zero_padding.into_inner()),
                    deserialize(non_zero_padding).unwrap_err().0
                );

                let min_value = $name::ZERO.0;
                deserialize(min_value).unwrap();

                let mut max_value = $name::ZERO.0;
                max_value[..$bits].fill(true);
                deserialize(max_value).unwrap();
            }
        }
    };

    ($name: ident, $bits: tt, $store: ty, infallible) => {
        $crate::const_assert_eq!(
            $bits % 8,
            0,
            "Infallible deserialization is defined for lengths that are multiples of 8 only"
        );

        impl Serializable for $name {
            type Size = <$store as Block>::Size;
            type DeserializationError = std::convert::Infallible;

            fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
                buf.copy_from_slice(self.0.as_raw_slice());
            }

            fn deserialize(
                buf: &GenericArray<u8, Self::Size>,
            ) -> Result<Self, Self::DeserializationError> {
                Ok(Self(<$store>::new(assert_copy(*buf).into())))
            }
        }
    };
}

// macro for implementing Boolean array, only works for a byte size for which Block is defined
macro_rules! boolean_array_impl {
    ($modname:ident, $name:ident, $bits:tt, $deser_type: tt) => {
        #[allow(clippy::suspicious_arithmetic_impl)]
        #[allow(clippy::suspicious_op_assign_impl)]
        mod $modname {
            use super::*;
            use crate::{
                ff::{boolean::Boolean, ArrayAccess, Expand, Serializable, Gf32Bit},
                impl_shared_value_common,
                secret_sharing::{
                    replicated::semi_honest::{BAASIterator, AdditiveShare},
                    FieldArray, SharedValue, SharedValueArray,
                },
            };

            type Store = BitArr!(for $bits, in u8, Lsb0);

            /// A Boolean array with $bits bits.
            #[derive(Clone, Copy, PartialEq, Eq)]
            pub struct $name(pub(super) Store);

            impl BooleanArray for $name {
                fn as_bitslice(&self) -> &BitSlice<u8, Lsb0> {
                    Self::as_bitslice(self)
                }

                fn as_mut_bitslice(&mut self) -> &mut BitSlice<u8, Lsb0> {
                    Self::as_mut_bitslice(self)
                }
            }

            impl Default for $name {
                fn default() -> Self {
                    Self::ZERO
                }
            }

            impl Debug for $name {
                fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                    f.write_str(stringify!($name))?;
                    self.0.data.fmt(f)
                }
            }

            impl $name {
                #[cfg(all(test, unit_test))]
                const STORE_LEN: usize = bitvec::mem::elts::<u8>($bits);

                #[inline]
                #[must_use]
                pub fn as_raw_slice(&self) -> &[u8] {
                    self.0.as_raw_slice()
                }

                #[inline]
                #[must_use]
                pub fn as_raw_mut_slice(&mut self) -> &mut [u8] {
                    self.0.as_raw_mut_slice()
                }

                #[inline]
                #[must_use]
                pub fn as_bitslice(&self) -> &BitSlice<u8, Lsb0> {
                    self.0.as_bitslice().get(0..$bits).unwrap()
                }

                #[inline]
                #[must_use]
                pub fn as_mut_bitslice(&mut self) -> &mut BitSlice<u8, Lsb0> {
                    self.0.as_mut_bitslice().get_mut(0..$bits).unwrap()
                }
            }

            impl ArrayAccess for $name {
                type Output = Boolean;
                type Iter<'a> = BAIterator<'a>;

                fn get(&self, index: usize) -> Option<Self::Output> {
                    if index < usize::try_from(<$name>::BITS).unwrap() {
                        Some(self.0[index].into())
                    } else {
                        None
                    }
                }

                fn set(&mut self, index: usize, e: Self::Output) {
                    debug_assert!(index < usize::try_from(<$name>::BITS).unwrap());
                    self.0.set(index, bool::from(e));
                }

                fn iter(&self) -> Self::Iter<'_> {
                    BAIterator {
                        iterator: self.0.iter().take(<$name>::BITS as usize),
                    }
                }
            }

            impl SharedValue for $name {
                type Storage = Store;
                const BITS: u32 = $bits;
                const ZERO: Self = Self(<Store>::ZERO);

                impl_shared_value_common!();
            }

            impl_serializable_trait!($name, $bits, Store, $deser_type);

            impl std::ops::Add<&Self> for $name {
                type Output = Self;
                fn add(self, rhs: &Self) -> Self::Output {
                    Self(self.0 ^ rhs.0)
                }
            }

            impl std::ops::Add for $name {
                type Output = Self;
                fn add(self, rhs: Self) -> Self::Output {
                    std::ops::Add::add(self, &rhs)
                }
            }

            impl std::ops::Add<$name> for &$name {
                type Output = $name;
                fn add(self, rhs: $name) -> Self::Output {
                    $name(self.0 ^ rhs.0)
                }
            }

            impl<'a, 'b> std::ops::Add<&'b $name> for &'a $name {
                type Output = $name;
                fn add(self, rhs: &'b $name) -> Self::Output {
                    $name(self.0 ^ rhs.0)
                }
            }

            impl std::ops::AddAssign<&Self> for $name {
                fn add_assign(&mut self, rhs: &Self) {
                    *self.0.as_mut_bitslice() ^= rhs.0;
                }
            }

            impl std::ops::AddAssign for $name {
                fn add_assign(&mut self, rhs: Self) {
                    std::ops::AddAssign::add_assign(self, &rhs);
                }
            }

            impl std::ops::Sub<&Self> for $name {
                type Output = Self;
                fn sub(self, rhs: &Self) -> Self::Output {
                    std::ops::Add::add(self, rhs)
                }
            }

            impl std::ops::Sub for $name {
                type Output = Self;
                fn sub(self, rhs: Self) -> Self::Output {
                    std::ops::Add::add(self, rhs)
                }
            }

            impl std::ops::SubAssign<&Self> for $name {
                fn sub_assign(&mut self, rhs: &Self) {
                    std::ops::AddAssign::add_assign(self, rhs);
                }
            }

            impl std::ops::SubAssign for $name {
                fn sub_assign(&mut self, rhs: Self) {
                    std::ops::SubAssign::sub_assign(self, &rhs);
                }
            }

            impl std::ops::Neg for $name {
                type Output = Self;
                fn neg(self) -> Self::Output {
                    Self(self.0)
                }
            }

            impl Vectorizable<1> for $name {
                type Array = StdArray<$name, 1>;
            }

            impl std::ops::Mul<&Self> for $name {
                type Output = Self;
                fn mul(self, rhs: &Self) -> Self::Output {
                    Self(self.0 & rhs.0)
                }
            }

            impl std::ops::Mul for $name {
                type Output = Self;
                fn mul(self, rhs: Self) -> Self::Output {
                    std::ops::Mul::mul(self, &rhs)
                }
            }

            impl std::ops::MulAssign for $name {
                fn mul_assign(&mut self, rhs: Self) {
                    self.0 &= rhs.0;
                }
            }

            impl std::ops::Mul<&Boolean> for $name {
                type Output = Self;
                fn mul(self, rhs: &Boolean) -> Self::Output {
                    if *rhs == Boolean::ONE {
                        self
                    } else {
                        <Self as SharedValue>::ZERO
                    }
                }
            }

            impl std::ops::Mul<Boolean> for $name {
                type Output = Self;
                fn mul(self, rhs: Boolean) -> Self::Output {
                    std::ops::Mul::mul(self, &rhs)
                }
            }

            impl From<$name> for Store {
                fn from(v: $name) -> Self {
                    v.0
                }
            }

            impl TryFrom<&BitSlice<u8, Lsb0>> for $name {
                type Error = LengthError;

                fn try_from(value: &BitSlice<u8, Lsb0>) -> Result<Self, Self::Error> {
                    if value.len() != usize::try_from(Self::BITS).unwrap() {
                        return Err(LengthError {
                            expected: $bits,
                            actual: value.len(),
                        });
                    }
                    let mut result = Self::ZERO;
                    result.as_mut_bitslice().copy_from_bitslice(value);
                    Ok(result)
                }
            }

            impl Expand<Boolean> for $name {
                fn expand(v: &Boolean) -> Self {
                    let mut result = <$name as SharedValue>::ZERO;
                    for i in 0..usize::try_from(<$name>::BITS).unwrap() {
                        result.0.set(i, bool::from(*v));
                    }
                    result
                }
            }

            impl TryFrom<Vec<Boolean>> for $name {
                type Error = LengthError;
                fn try_from(value: Vec<Boolean>) -> Result<Self, Self::Error> {
                    if value.len() == $bits {
                        Ok(value.into_iter().collect::<Self>())
                    } else {
                        Err(LengthError {
                            expected: $bits,
                            actual: value.len(),
                        })
                    }
                }
            }

            /// This function converts an `BA` type into a vector of `32 bit` Galois field elements.
            ///
            /// ##Errors
            /// Outputs an error when conversion from raw slice to Galois field element fails.
            impl TryFrom<$name> for Vec<Gf32Bit> {
                type Error = LengthError;

                fn try_from(value: $name) -> Result<Self, Self::Error> {
                    // len() returns bits, so divide by 8
                    // further divide by 4 since Gf32Bit has 4 byte
                    let length = value.0.len().div_ceil(32);
                    let mut chunks = Vec::<Gf32Bit>::with_capacity(length);
                    let last_chunk_start = length-1;
                    for i in 0..last_chunk_start {
                        chunks.push(Gf32Bit::try_from(
                            &value.0.as_raw_slice()[4 * i..4 * (i + 1)],
                        )?);
                    }
                    chunks.push(Gf32Bit::try_from(
                        &value.0.as_raw_slice()[4 * last_chunk_start..],
                    )?);
                    Ok(chunks)
                }
            }

            impl SharedValueArray<Boolean> for $name {
                const ZERO_ARRAY: Self = <$name as SharedValue>::ZERO;

                fn from_fn<F: FnMut(usize) -> Boolean>(mut f: F) -> Self {
                    let mut res = <Self as SharedValueArray<Boolean>>::ZERO_ARRAY;

                    for i in 0..$bits {
                        res.0.set(i, bool::from(f(i)));
                    }

                    res
                }
            }

            impl FieldArray<Boolean> for $name {}

            // Panics if the iterator terminates before producing N items.
            impl FromIterator<Boolean> for $name {
                fn from_iter<T: IntoIterator<Item = Boolean>>(iter: T) -> Self {
                    let mut res = <Self as SharedValueArray<Boolean>>::ZERO_ARRAY;
                    let mut iter = iter.into_iter();

                    for i in 0..$bits {
                        res.0.set(
                            i,
                            bool::from(iter.next().unwrap_or_else(|| {
                                panic!("Expected iterator to produce {} items, got only {i}", $bits)
                            })),
                        );
                    }

                    res
                }
            }

            impl IntoIterator for $name {
                type Item = Boolean;
                type IntoIter = BAOwnedIterator<Store>;

                fn into_iter(self) -> Self::IntoIter {
                    BAOwnedIterator {
                        iterator: self
                            .0
                            .into_iter()
                            .take(usize::try_from(<$name>::BITS).unwrap()),
                    }
                }
            }

            /// `clippy` does not recognize `iter` method coming from another trait. It is a false alarm
            /// therefore suppressed here.
            #[allow(clippy::into_iter_without_iter)]
            impl<'a> IntoIterator for &'a AdditiveShare<$name> {
                type Item = AdditiveShare<Boolean>;
                type IntoIter = BAASIterator<'a, $name>;

                fn into_iter(self) -> Self::IntoIter {
                    self.iter()
                }
            }

            impl std::ops::Not for $name {
                type Output = Self;

                fn not(self) -> Self::Output {
                    Self(self.0.not())
                }
            }

            #[cfg(all(test, unit_test))]
            mod tests {
                use proptest::{
                    prelude::{prop, Arbitrary, Strategy},
                    proptest,
                };
                use rand::{thread_rng, Rng};
                use bitvec::{bits, bitarr};

                use super::*;

                impl Arbitrary for $name {
                    type Parameters = <[u8; $name::STORE_LEN] as Arbitrary>::Parameters;
                    type Strategy = prop::strategy::Map<
                        <[u8; $name::STORE_LEN] as Arbitrary>::Strategy,
                        fn([u8; $name::STORE_LEN]) -> Self,
                    >;

                    fn arbitrary_with(args: Self::Parameters) -> Self::Strategy {
                        <[u8; $name::STORE_LEN]>::arbitrary_with(args)
                            .prop_map(|arr| {
                                let mut v = Store::from(arr);
                                // make sure the value does not overflow
                                v[$bits..].fill(false);
                                $name(v)
                            })
                    }
                }

                #[test]
                pub fn zero() {
                    let zero = bitarr!(u8, Lsb0; 0; <$name>::BITS as usize);
                    assert_eq!($name::ZERO.0, zero);
                    assert_eq!($name::default(), $name::ZERO);
                }

                proptest! {
                    #[test]
                    fn add_sub(a: $name, b: $name) {
                        let xor = $name(a.0 ^ b.0);

                        assert_eq!(&a + &b, xor);
                        assert_eq!(&a + b.clone(), xor);
                        assert_eq!(a.clone() + &b, xor);
                        assert_eq!(a.clone() + b.clone(), xor);

                        let mut tmp = a.clone();
                        tmp += &b;
                        assert_eq!(tmp, xor);

                        let mut tmp = a.clone();
                        tmp += b;
                        assert_eq!(tmp, xor);

                        // Sub not implemented yet for &BA
                        //assert_eq!(&a - &b, xor);
                        //assert_eq!(&a - b.clone(), xor);
                        assert_eq!(a.clone() - &b, xor);
                        assert_eq!(a.clone() - b.clone(), xor);

                        let mut tmp = a.clone();
                        tmp -= &b;
                        assert_eq!(tmp, xor);

                        let mut tmp = a.clone();
                        tmp -= b;
                        assert_eq!(tmp, xor);

                        assert_eq!(-a, a);
                        assert_eq!(a + (-a), $name::ZERO);
                    }

                    #[test]
                    fn mul(mut a: $name, b: $name, c: Boolean) {
                        let prod = $name(a.0 & b.0);

                        a *= b;
                        assert_eq!(a, prod);

                        assert_eq!(a * Boolean::from(false), $name::ZERO);
                        assert_eq!(a * Boolean::from(true), a);
                        assert_eq!(a * c, if bool::from(c) { a } else { $name::ZERO });
                        assert_eq!(a * &c, if bool::from(c) { a } else { $name::ZERO });
                    }

                    #[test]
                    fn serde_prop(a: $name) {
                        let mut buf = GenericArray::default();
                        a.serialize(&mut buf);
                        assert_eq!(
                            a,
                            $name::deserialize(&buf).unwrap(),
                            "Failed to deserialize a valid value: {a:?}"
                        );
                    }
                }

                #[test]
                fn set_boolean_array() {
                    let mut rng = thread_rng();
                    let i = rng.r#gen::<usize>() % usize::try_from(<$name>::BITS).unwrap();
                    let a = rng.r#gen::<Boolean>();
                    let mut ba = rng.r#gen::<$name>();
                    ba.set(i, a);
                    assert_eq!(ba.get(i), Some(a));
                }

                #[test]
                fn convert_to_galois_field() {
                    let mut rng = thread_rng();
                    let ba = rng.r#gen::<$name>();
                    let mut vec = ba.as_raw_slice().to_vec();
                    // append with zeros when necessary
                    for _ in 0..(4-vec.len()%4)%4 {
                        vec.push(0u8);
                    }
                    let converted = <Vec<Gf32Bit>>::try_from(ba).unwrap();
                    for (i,element) in converted.iter().enumerate() {
                        let mut buf = GenericArray::default();
                        element.serialize(&mut buf);
                        assert_eq!(vec[4*i..4*(i+1)],buf.to_vec());
                    }

                }

                proptest! {
                    #[test]
                    fn iterate_boolean_array(a: $name) {
                        let mut iter = a.iter().enumerate();
                        assert_eq!(iter.len(), $bits);
                        while let Some((i, b)) = iter.next() {
                            assert_eq!(bool::from(b), a.0[i]);
                            assert_eq!(iter.len(), $bits - 1 - i);
                        }
                    }

                    #[test]
                    fn iterate_secret_shared_boolean_array(a: AdditiveShare<$name>) {
                        use crate::secret_sharing::replicated::ReplicatedSecretSharing;
                        let mut iter = a.iter().enumerate();
                        assert_eq!(iter.len(), $bits);
                        while let Some((i, sb)) = iter.next() {
                            let left = Boolean::from(a.left().0[i]);
                            let right = Boolean::from(a.right().0[i]);
                            assert_eq!(sb, AdditiveShare::new(left, right));
                            assert_eq!(iter.len(), $bits - 1 - i);
                        }
                    }

                    #[test]
                    fn iterate_secret_shared_boolean_array_ref(a: AdditiveShare<$name>) {
                        use crate::secret_sharing::replicated::ReplicatedSecretSharing;
                        let mut iter = (&a).into_iter().enumerate();
                        assert_eq!(iter.len(), $bits);
                        while let Some((i, sb)) = iter.next() {
                            let left = Boolean::from(a.left().0[i]);
                            let right = Boolean::from(a.right().0[i]);
                            assert_eq!(sb, AdditiveShare::new(left, right));
                            assert_eq!(iter.len(), $bits - 1 - i);
                        }
                    }

                    #[test]
                    fn owned_iterator(a: $name) {
                        let mut iter = a.into_iter().enumerate();
                        assert_eq!(iter.len(), $bits);
                        while let Some((i, b)) = iter.next() {
                            assert_eq!(bool::from(b), a.0[i]);
                            assert_eq!(iter.len(), $bits - 1 - i);
                        }
                    }
                }

                #[test]
                fn serde() {
                    let ba = thread_rng().r#gen::<$name>();
                    let mut buf = GenericArray::default();
                    ba.serialize(&mut buf);
                    assert_eq!(
                        ba,
                        $name::deserialize(&buf).unwrap(),
                        "Failed to deserialize a valid value: {ba:?}"
                    );
                }

                #[test]
                fn debug() {
                    let expected = format!("{}{:?}", stringify!($name), $name::ZERO.0.data);
                    let actual = format!("{:?}", $name::ZERO);
                    assert_eq!(expected, actual);
                }

                #[test]
                fn bitslice() {
                    let zero = $name::ZERO;
                    let random = thread_rng().r#gen::<$name>();

                    // generate slices
                    let slice_zero = zero.as_bitslice();
                    let slice_random = random.as_bitslice();

                    // check length
                    assert_eq!(slice_zero.len(), $bits);
                    assert_eq!(slice_random.len(), $bits);

                    // // check content
                    assert_eq!(*slice_zero, bits![0;$bits]);
                    slice_random.iter().enumerate().for_each(|(i,bit)| {
                        assert_eq!(bit,bool::from(random.get(i).unwrap()));
                    });
                }

                #[test]
                #[should_panic(expected = "out of bounds")]
                fn bitslice_out_of_range() {
                    let zero = $name::ZERO;
                    zero.as_bitslice()[$bits];
                }

                #[test]
                #[should_panic(expected = "out of range")]
                fn bitslice_out_of_range_mut() {
                    let mut zero = $name::ZERO;
                    zero.as_mut_bitslice().set($bits, true);
                }
            }
        }

        pub use $modname::$name;
    };
}

macro_rules! boolean_array_impl_large {
    ($modname:ident, $name:ident, $bits:tt, $deser_type:tt, $bytelength:ty, $wordlength:ty) => {
        boolean_array_impl!($modname, $name, $bits, $deser_type);

        $crate::const_assert!(
            $bits % 8 == 0,
            "Large BooleanArrays only support whole bytes."
        );

        impl FromRandom for $name {
            type SourceLength = $wordlength;

            fn from_random(src: GenericArray<u128, $wordlength>) -> Self {
                let iter = src
                    .into_iter()
                    .flat_map(u128::to_le_bytes)
                    .take(<$bytelength>::USIZE);
                let arr = GenericArray::<u8, $bytelength>::try_from_iter(iter).unwrap();
                Self::deserialize_infallible(&arr)
            }
        }

        impl rand::distributions::Distribution<$name> for rand::distributions::Standard {
            fn sample<R: crate::rand::Rng + ?Sized>(&self, rng: &mut R) -> $name {
                <$name>::from_random(
                    repeat_with(|| rng.r#gen())
                        .take(<$wordlength>::USIZE)
                        .collect(),
                )
            }
        }
    };
}

// Other store impls can be found in `galois_field.rs`. Each storage type must have only one impl.

//impl store for U8
store_impl!(U8, 64);

//impl store for U12
store_impl!(U12, 96);

//impl store for U14
store_impl!(U14, 112);

//impl store for U18
store_impl!(U18, 144);

//impl store for U32
store_impl!(U32, 256);

// These macro invocations define the supported boolean array sizes. Sizes ≤ 128 should use
// `boolean_array_impl_small!` to get `u128` conversions and helpers. Larger sizes must
// use `boolean_array_impl!`. At any size, you may need to add `store_impl!`, and for large
// sizes, additional manual impls may be necessary (see manual `BA256` impls below).
//
// If you also want support `AdditiveShare<Boolean, N>` vectorization, that needs to be added to
// `secret_sharing::vector::impls`.

//impl BA3
boolean_array_impl_small!(boolean_array_3, BA3, 3, fallible);
boolean_array_impl_small!(boolean_array_4, BA4, 4, fallible);
boolean_array_impl_small!(boolean_array_5, BA5, 5, fallible);
boolean_array_impl_small!(boolean_array_6, BA6, 6, fallible);
boolean_array_impl_small!(boolean_array_7, BA7, 7, fallible);
boolean_array_impl_small!(boolean_array_8, BA8, 8, infallible);
boolean_array_impl_small!(boolean_array_16, BA16, 16, infallible);
boolean_array_impl_small!(boolean_array_20, BA20, 20, fallible);
boolean_array_impl_small!(boolean_array_32, BA32, 32, infallible);
boolean_array_impl_small!(boolean_array_64, BA64, 64, infallible);
boolean_array_impl_small!(boolean_array_96, BA96, 96, infallible);
boolean_array_impl_small!(boolean_array_112, BA112, 112, infallible);
boolean_array_impl_large!(boolean_array_144, BA144, 144, infallible, U18, U2);
boolean_array_impl_large!(boolean_array_256, BA256, 256, infallible, U32, U2);

impl Vectorizable<256> for BA64 {
    type Array = StdArray<BA64, 256>;
}

impl Vectorizable<256> for BA256 {
    type Array = StdArray<BA256, 256>;
}

#[cfg(all(test, unit_test))]
mod tests {
    use super::*;
    use crate::secret_sharing::SharedValueArray;

    #[test]
    fn boolean_array_from_vec() {
        let v = [false, false, true].map(Boolean::from).to_vec();
        assert_eq!(BA3::try_from(v.clone()), Ok(BA3::truncate_from(4_u128)));
        assert_eq!(
            BA8::try_from(v),
            Err(LengthError {
                expected: 8,
                actual: 3
            })
        );
    }

    #[test]
    fn boolean_array_from_fn() {
        assert_eq!(
            BA3::from_fn(|i| Boolean::from(i == 2)),
            BA3::truncate_from(4_u128)
        );
    }

    #[test]
    fn boolean_array_from_iter() {
        let iter = [false, false, true].into_iter().map(Boolean::from);
        assert_eq!(iter.collect::<BA3>(), BA3::truncate_from(4_u128));
    }

    #[test]
    #[should_panic(expected = "Expected iterator to produce 3 items, got only 2")]
    fn boolean_array_from_short_iter() {
        let iter = [false, false].into_iter().map(Boolean::from);
        assert_eq!(iter.collect::<BA3>(), BA3::truncate_from(4_u128));
    }
}
