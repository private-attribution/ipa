use std::{
    array,
    borrow::Borrow,
    fmt::Debug,
    ops::{Add, AddAssign, Mul, Neg, Not, Sub, SubAssign},
};

use generic_array::{ArrayLength, GenericArray};
use typenum::{Unsigned, U16, U256, U32, U64};

use crate::{
    const_assert_eq,
    error::LengthError,
    ff::{ec_prime_field::Fp25519, Field, Fp32BitPrime, Gf32Bit, Serializable},
    protocol::{ipa_prf::PRF_CHUNK, prss::FromRandom},
    secret_sharing::{FieldArray, Sendable, SharedValue, SharedValueArray},
};

/// Wrapper around `[V; N]`.
///
/// This wrapper serves two purposes:
///  * It enables us to implement the `std::ops` traits, which the coherence rules
///    don't let us implement for `[V; N]`.
///  * It disables by-index access to individual elements of the array, which
///    should never be necessary in properly vectorized code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StdArray<V: SharedValue, const N: usize>(pub(super) [V; N]);

impl<V, T, const N: usize> PartialEq<T> for StdArray<V, N>
where
    V: SharedValue,
    T: Borrow<[V]>,
{
    fn eq(&self, other: &T) -> bool {
        self.0.as_slice() == other.borrow()
    }
}

impl<V: SharedValue, const N: usize> PartialEq<StdArray<V, N>> for Vec<V> {
    fn eq(&self, other: &StdArray<V, N>) -> bool {
        other.eq(self)
    }
}

impl<V: SharedValue, const N: usize> PartialEq<StdArray<V, N>> for [V; N] {
    fn eq(&self, other: &StdArray<V, N>) -> bool {
        other.eq(self)
    }
}

impl<V: SharedValue, const N: usize> StdArray<V, N> {
    pub fn first(&self) -> &V {
        &self.0[0]
    }

    pub fn first_mut(&mut self) -> &mut V {
        &mut self.0[0]
    }
}

impl<V: SharedValue, const N: usize> Sendable for StdArray<V, N> where Self: Serializable {}

impl<V: SharedValue, const N: usize> SharedValueArray<V> for StdArray<V, N>
where
    Self: Sendable,
{
    const ZERO_ARRAY: Self = Self([V::ZERO; N]);

    fn from_fn<F: FnMut(usize) -> V>(f: F) -> Self {
        Self(array::from_fn(f))
    }
}

impl<F: Field, const N: usize> FieldArray<F> for StdArray<F, N> where Self: FromRandom + Sendable {}

impl<V: SharedValue, const N: usize> TryFrom<Vec<V>> for StdArray<V, N> {
    type Error = LengthError;
    fn try_from(value: Vec<V>) -> Result<Self, Self::Error> {
        match value.try_into() {
            Ok(arr) => Ok(Self(arr)),
            Err(vec) => Err(LengthError {
                expected: N,
                actual: vec.len(),
            }),
        }
    }
}

// Panics if the iterator terminates before producing N items.
impl<V: SharedValue, const N: usize> FromIterator<V> for StdArray<V, N>
where
    Self: Sendable, // required for `<Self as SharedValueArray>::ZERO`
{
    fn from_iter<T: IntoIterator<Item = V>>(iter: T) -> Self {
        let mut res = Self::ZERO_ARRAY;
        let mut iter = iter.into_iter();

        for i in 0..N {
            res.0[i] = iter
                .next()
                .unwrap_or_else(|| panic!("Expected iterator to produce {N} items, got only {i}"));
        }

        res
    }
}

impl<V: SharedValue, const N: usize> StdArray<V, N>
where
    Self: Sendable, // required for `<Self as SharedValueArray>::ZERO`
{
    /// Build a pair of `StdArray`s from an iterator over tuples.
    ///
    /// # Panics
    /// If the iterator terminates before producing N items.
    pub fn from_tuple_iter<T: IntoIterator<Item = (V, V)>>(iter: T) -> (Self, Self) {
        let mut l_res = Self::ZERO_ARRAY;
        let mut r_res = Self::ZERO_ARRAY;
        let mut iter = iter.into_iter();

        for i in 0..N {
            let (l, r) = iter
                .next()
                .unwrap_or_else(|| panic!("Expected iterator to produce {N} items, got only {i}"));
            l_res.0[i] = l;
            r_res.0[i] = r;
        }

        (l_res, r_res)
    }
}

impl<V: SharedValue, const N: usize> IntoIterator for StdArray<V, N> {
    type Item = V;
    type IntoIter = std::array::IntoIter<V, N>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'b, V: SharedValue, const N: usize> Add<&'b StdArray<V, N>> for &StdArray<V, N> {
    type Output = StdArray<V, N>;

    fn add(self, rhs: &'b StdArray<V, N>) -> Self::Output {
        StdArray(array::from_fn(|i| self.0[i] + rhs.0[i]))
    }
}

impl<V: SharedValue, const N: usize> Add<Self> for StdArray<V, N> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Add::add(&self, &rhs)
    }
}

// add(owned, ref) should be preferred over this.
impl<V: SharedValue, const N: usize> Add<StdArray<V, N>> for &StdArray<V, N> {
    type Output = StdArray<V, N>;

    fn add(self, rhs: StdArray<V, N>) -> Self::Output {
        Add::add(self, &rhs)
    }
}

impl<V: SharedValue, const N: usize> Add<&StdArray<V, N>> for StdArray<V, N> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        Add::add(&self, rhs)
    }
}

impl<V: SharedValue, const N: usize> AddAssign<&Self> for StdArray<V, N> {
    fn add_assign(&mut self, rhs: &Self) {
        for (a, b) in self.0.iter_mut().zip(rhs.0.iter()) {
            *a += *b;
        }
    }
}

impl<V: SharedValue, const N: usize> AddAssign<Self> for StdArray<V, N> {
    fn add_assign(&mut self, rhs: Self) {
        AddAssign::add_assign(self, &rhs);
    }
}

impl<V: SharedValue, const N: usize> Neg for &StdArray<V, N> {
    type Output = StdArray<V, N>;

    fn neg(self) -> Self::Output {
        StdArray(array::from_fn(|i| -self.0[i]))
    }
}

impl<V: SharedValue, const N: usize> Neg for StdArray<V, N> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Neg::neg(&self)
    }
}

impl<V: SharedValue, const N: usize> Sub<Self> for &StdArray<V, N> {
    type Output = StdArray<V, N>;

    fn sub(self, rhs: Self) -> Self::Output {
        StdArray(array::from_fn(|i| self.0[i] - rhs.0[i]))
    }
}

impl<V: SharedValue, const N: usize> Sub<Self> for StdArray<V, N> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Sub::sub(&self, &rhs)
    }
}

impl<V: SharedValue, const N: usize> Sub<&Self> for StdArray<V, N> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        Sub::sub(&self, rhs)
    }
}

impl<V: SharedValue, const N: usize> Sub<StdArray<V, N>> for &StdArray<V, N> {
    type Output = StdArray<V, N>;

    fn sub(self, rhs: StdArray<V, N>) -> Self::Output {
        Sub::sub(self, &rhs)
    }
}

impl<V: SharedValue, const N: usize> SubAssign<&Self> for StdArray<V, N> {
    fn sub_assign(&mut self, rhs: &Self) {
        for (a, b) in self.0.iter_mut().zip(rhs.0.iter()) {
            *a -= *b;
        }
    }
}

impl<V: SharedValue, const N: usize> SubAssign<Self> for StdArray<V, N> {
    fn sub_assign(&mut self, rhs: Self) {
        SubAssign::sub_assign(self, &rhs);
    }
}

impl<'b, F: Field, const N: usize> Mul<&'b F> for &StdArray<F, N> {
    type Output = StdArray<F, N>;

    fn mul(self, rhs: &'b F) -> Self::Output {
        StdArray(array::from_fn(|i| self.0[i] * *rhs))
    }
}

impl<F: Field, const N: usize> Mul<F> for StdArray<F, N> {
    type Output = Self;

    fn mul(self, rhs: F) -> Self::Output {
        Mul::mul(&self, &rhs)
    }
}

impl<F: Field, const N: usize> Mul<&F> for StdArray<F, N> {
    type Output = Self;

    fn mul(self, rhs: &F) -> Self::Output {
        Mul::mul(&self, rhs)
    }
}

impl<F: Field, const N: usize> Mul<F> for &StdArray<F, N> {
    type Output = StdArray<F, N>;

    fn mul(self, rhs: F) -> Self::Output {
        Mul::mul(self, &rhs)
    }
}

impl<'a, F: Field, const N: usize> Mul<&'a StdArray<F, N>> for StdArray<F, N> {
    type Output = StdArray<F, N>;

    fn mul(self, rhs: &'a StdArray<F, N>) -> Self::Output {
        StdArray(array::from_fn(|i| self.0[i] * rhs.0[i]))
    }
}

impl<V: SharedValue + Not<Output = V>, const N: usize> Not for StdArray<V, N> {
    type Output = StdArray<V, N>;

    fn not(self) -> Self::Output {
        StdArray(array::from_fn(|i| !self.0[i]))
    }
}

impl<F: SharedValue + FromRandom> FromRandom for StdArray<F, 1> {
    type SourceLength = <F as FromRandom>::SourceLength;
    fn from_random(src: GenericArray<u128, Self::SourceLength>) -> Self {
        Self([F::from_random(src)])
    }
}

/// Implement `FromRandom` for a share array.
///
/// The third argument, `$source_len`, is the total amount of randomness required,
/// counted in `u128`s.
///
/// The fourth argument, `$item_len`, is the amount of randomness required for each
/// element, also in `u128`s.
///
/// Note that smaller `SharedValue` types still require an entire `u128` of
/// randomness.
macro_rules! impl_from_random {
    ($value_ty:ty, $width:expr, $source_len:ty, $item_len:expr) => {
        impl FromRandom for StdArray<$value_ty, $width> {
            type SourceLength = $source_len;

            fn from_random(src: GenericArray<u128, Self::SourceLength>) -> Self {
                Self(array::from_fn(|i| {
                    <$value_ty>::from_random(
                        GenericArray::from_slice(&src[$item_len * i..$item_len * (i + 1)]).clone(),
                    )
                }))
            }
        }
    };
}

const_assert_eq!(
    PRF_CHUNK,
    16,
    "Appropriate FromRandom implementation required"
);
impl_from_random!(Fp25519, 16, U32, 2);

impl_from_random!(Fp32BitPrime, 32, U32, 1);
impl_from_random!(Gf32Bit, 32, U32, 1);

impl<V: SharedValue> Serializable for StdArray<V, 1> {
    type Size = <V as Serializable>::Size;
    type DeserializationError = <V as Serializable>::DeserializationError;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        self.0[0].serialize(buf);
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Result<Self, Self::DeserializationError> {
        Ok(StdArray([V::deserialize(buf)?]))
    }
}

macro_rules! impl_serializable {
    ($width:expr, $width_ty:ty) => {
        impl<V: SharedValue> Serializable for StdArray<V, $width>
        where
            V: SharedValue,
            <V as Serializable>::Size: Mul<$width_ty>,
            <<V as Serializable>::Size as Mul<$width_ty>>::Output: ArrayLength,
        {
            type Size = <<V as Serializable>::Size as Mul<$width_ty>>::Output;
            type DeserializationError = <V as Serializable>::DeserializationError;

            fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
                let sz: usize = <V as Serializable>::Size::USIZE;
                for i in 0..$width {
                    self.0[i].serialize(
                        GenericArray::try_from_mut_slice(&mut buf[sz * i..sz * (i + 1)]).unwrap(),
                    );
                }
            }

            fn deserialize(
                buf: &GenericArray<u8, Self::Size>,
            ) -> Result<Self, Self::DeserializationError> {
                let sz: usize = <V as Serializable>::Size::USIZE;
                let mut res = [V::ZERO; $width];
                for i in 0..$width {
                    res[i] = V::deserialize(GenericArray::from_slice(&buf[sz * i..sz * (i + 1)]))?;
                }
                Ok(StdArray(res))
            }
        }
    };
}

impl_serializable!(16, U16);
impl_serializable!(32, U32);
impl_serializable!(64, U64);
impl_serializable!(256, U256);

#[cfg(all(test, unit_test))]
mod test {
    use std::iter;

    use proptest::{
        prelude::{prop, Arbitrary, Strategy},
        proptest,
    };

    use super::*;
    use crate::ff::boolean_array::BA3;

    impl<V: SharedValue, const N: usize> Arbitrary for StdArray<V, N>
    where
        [V; N]: Arbitrary,
    {
        type Parameters = <[V; N] as Arbitrary>::Parameters;
        type Strategy = prop::strategy::Map<<[V; N] as Arbitrary>::Strategy, fn([V; N]) -> Self>;

        fn arbitrary_with(args: Self::Parameters) -> Self::Strategy {
            <[V; N]>::arbitrary_with(args).prop_map(Self)
        }
    }

    proptest! {
        #[test]
        fn add(a: StdArray<Fp32BitPrime, 2>, b: StdArray<Fp32BitPrime, 2>) {
            let expected = StdArray([a.0[0] + b.0[0], a.0[1] + b.0[1]]);
            let sum1 = &a + &b;
            let sum2 = &a + b.clone();
            let sum3 = a.clone() + &b;
            let sum4 = a + b;
            assert_eq!(sum1, expected);
            assert_eq!(sum2, expected);
            assert_eq!(sum3, expected);
            assert_eq!(sum4, expected);
        }

        #[test]
        fn add_assign(a: StdArray<Fp32BitPrime, 2>, b: StdArray<Fp32BitPrime, 2>) {
            let expected = StdArray([a.0[0] + b.0[0], a.0[1] + b.0[1]]);
            let mut sum1 = a.clone();
            let mut sum2 = a.clone();
            sum1 += &b;
            sum2 += b;
            assert_eq!(sum1, expected);
            assert_eq!(sum2, expected);
        }

        #[test]
        fn sub(a: StdArray<Fp32BitPrime, 2>, b: StdArray<Fp32BitPrime, 2>) {
            let expected = StdArray([a.0[0] - b.0[0], a.0[1] - b.0[1]]);
            let diff1 = &a - &b;
            let diff2 = &a - b.clone();
            let diff3 = a.clone() - &b;
            let diff4 = a - b;
            assert_eq!(diff1, expected);
            assert_eq!(diff2, expected);
            assert_eq!(diff3, expected);
            assert_eq!(diff4, expected);
        }

        #[test]
        fn sub_assign(a: StdArray<Fp32BitPrime, 2>, b: StdArray<Fp32BitPrime, 2>) {
            let expected = StdArray([a.0[0] - b.0[0], a.0[1] - b.0[1]]);
            let mut diff1 = a.clone();
            let mut diff2 = a.clone();
            diff1 -= &b;
            diff2 -= b;
            assert_eq!(diff1, expected);
            assert_eq!(diff2, expected);
        }

        #[test]
        fn mul_scalar(a: StdArray<Fp32BitPrime, 2>, b: Fp32BitPrime) {
            let expected = StdArray([a.0[0] * b, a.0[1] * b]);
            let b_ref = &b; // clippy complains inline ref to Copy type is needless
            let prod1 = &a * b_ref;
            let prod2 = &a * b;
            let prod3 = a.clone() * b_ref;
            let prod4 = a * b;
            assert_eq!(prod1, expected);
            assert_eq!(prod2, expected);
            assert_eq!(prod3, expected);
            assert_eq!(prod4, expected);
        }

        #[test]
        fn into_iter(a: StdArray<Fp32BitPrime, 2>) {
            let expected = a.clone();
            let copy: StdArray<Fp32BitPrime, 2> = a.into_iter()
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            assert_eq!(copy, expected);
        }

        #[test]
        #[allow(clippy::from_iter_instead_of_collect)]
        fn from_iter(a: StdArray<Fp32BitPrime, 32>) {
            let iter = a.0.iter().copied();
            let copy = StdArray::<Fp32BitPrime, 32>::from_iter(iter);
            assert_eq!(copy, a);
        }

        #[test]
        fn serde(a: StdArray<BA3, 32>) {
            let mut buf = GenericArray::default();
            a.serialize(&mut buf);
            assert_eq!(a, StdArray::deserialize(&buf).unwrap());
        }
    }

    #[test]
    #[should_panic(expected = "Expected iterator to produce 32 items, got only 0")]
    #[allow(clippy::from_iter_instead_of_collect)]
    fn from_short_iter() {
        StdArray::<Fp32BitPrime, 32>::from_iter(iter::empty());
    }
}
