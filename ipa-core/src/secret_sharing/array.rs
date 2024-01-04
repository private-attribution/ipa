use std::{
    array,
    borrow::Borrow,
    fmt::Debug,
    ops::{Add, AddAssign, Mul, Neg, Not, Sub, SubAssign},
};

use generic_array::{ArrayLength, GenericArray};
use typenum::{U1, U32};

use crate::{
    ff::{Field, Fp32BitPrime, Serializable},
    helpers::Message,
    protocol::prss::{FromRandom, FromRandomU128},
    secret_sharing::{FieldArray, SharedValue, SharedValueArray},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StdArray<V: SharedValue, const N: usize>([V; N]);

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

impl<V: SharedValue, const N: usize> SharedValueArray<V> for StdArray<V, N>
where
    Self: Serializable,
{
    const ZERO: Self = Self([V::ZERO; N]);

    fn from_fn<F: FnMut(usize) -> V>(f: F) -> Self {
        Self(array::from_fn(f))
    }

    fn get(&self, index: usize) -> V {
        self.0[index]
    }

    fn get_mut(&mut self, index: usize) -> &mut V {
        &mut self.0[index]
    }

    fn set(&mut self, index: usize, value: V) {
        self.0[index] = value;
    }
}

impl<F: Field, const N: usize> FieldArray<F> for StdArray<F, N> where Self: FromRandom + Serializable
{}

impl<V: SharedValue, const N: usize> TryFrom<Vec<V>> for StdArray<V, N> {
    type Error = ();
    fn try_from(value: Vec<V>) -> Result<Self, Self::Error> {
        value.try_into().map(Self).map_err(|_| ())
    }
}

// Panics if the iterator terminates before producing N items.
impl<V: SharedValue, const N: usize> FromIterator<V> for StdArray<V, N>
where
    Self: Serializable,
{
    fn from_iter<T: IntoIterator<Item = V>>(iter: T) -> Self {
        let mut res = Self::ZERO;
        let mut iter = iter.into_iter();

        for i in 0..N {
            res.0[i] = iter.next().unwrap();
        }

        res
    }
}

impl<V: SharedValue, const N: usize> IntoIterator for StdArray<V, N> {
    type Item = V;
    type IntoIter = std::array::IntoIter<V, N>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, 'b, V: SharedValue, const N: usize> Add<&'b StdArray<V, N>> for &'a StdArray<V, N> {
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

impl<'a, 'b, F: Field, const N: usize> Mul<&'b F> for &'a StdArray<F, N> {
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

impl<F: SharedValue + FromRandom<SourceLength = U1>> FromRandom for StdArray<F, 1> {
    type SourceLength = U1;
    fn from_random(src: GenericArray<u128, U1>) -> Self {
        Self([F::from_random(src)])
    }
}

impl FromRandom for StdArray<Fp32BitPrime, 32> {
    type SourceLength = U32;

    fn from_random(src: GenericArray<u128, U32>) -> Self {
        Self(array::from_fn(|i| Fp32BitPrime::from_random_u128(src[i])))
    }
}

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

impl<V: SharedValue> Serializable for StdArray<V, 32>
where
    V: SharedValue,
    <V as Serializable>::Size: Mul<U32>,
    <<V as Serializable>::Size as Mul<U32>>::Output: ArrayLength,
{
    type Size = <<V as Serializable>::Size as Mul<U32>>::Output;
    type DeserializationError = <V as Serializable>::DeserializationError;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        let sz: usize = (<V as SharedValue>::BITS / 8).try_into().unwrap();
        for i in 0..32 {
            self.0[i].serialize(
                GenericArray::try_from_mut_slice(&mut buf[sz * i..sz * (i + 1)]).unwrap(),
            );
        }
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Result<Self, Self::DeserializationError> {
        let sz: usize = (<V as SharedValue>::BITS / 8).try_into().unwrap();
        let mut res = [V::ZERO; 32];
        for i in 0..32 {
            res[i] = V::deserialize(GenericArray::from_slice(&buf[sz * i..sz * (i + 1)]))?;
        }
        Ok(StdArray(res))
    }
}

impl<V: SharedValue, const N: usize> Message for StdArray<V, N> where Self: Serializable {}
