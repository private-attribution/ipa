use std::{
    convert::Infallible,
    fmt::{Debug, Formatter},
    ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign},
};

use generic_array::{ArrayLength, GenericArray};
use typenum::Unsigned;

use crate::{
    error::UnwrapInfallible,
    ff::{ArrayAccess, Expand, Field, Serializable},
    secret_sharing::{
        replicated::ReplicatedSecretSharing, Linear as LinearSecretSharing, SecretSharing,
        SharedValue,
    },
};

#[derive(Clone, PartialEq, Eq)]
pub struct AdditiveShare<V: SharedValue>(pub V, pub V);

#[derive(Clone, PartialEq, Eq)]
pub struct ASIterator<T: Iterator>(pub T, pub T);

impl<V: SharedValue> SecretSharing<V> for AdditiveShare<V> {
    const ZERO: Self = AdditiveShare::ZERO;
}
impl<F: Field> LinearSecretSharing<F> for AdditiveShare<F> {}

impl<V: SharedValue + Debug> Debug for AdditiveShare<V> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "({:?}, {:?})", self.0, self.1)
    }
}

impl<V: SharedValue> Default for AdditiveShare<V> {
    fn default() -> Self {
        AdditiveShare::new(V::ZERO, V::ZERO)
    }
}

impl<V: SharedValue> AdditiveShare<V> {
    /// Replicated secret share where both left and right values are `F::ZERO`
    pub const ZERO: Self = Self(V::ZERO, V::ZERO);

    pub fn as_tuple(&self) -> (V, V) {
        (self.0, self.1)
    }
}

impl<V: SharedValue> ReplicatedSecretSharing<V> for AdditiveShare<V> {
    fn new(a: V, b: V) -> Self {
        Self(a, b)
    }

    fn left(&self) -> V {
        self.0
    }

    fn right(&self) -> V {
        self.1
    }
}

impl<V: SharedValue> AdditiveShare<V>
where
    Self: Serializable,
{
    // Deserialize a slice of bytes into an iterator of replicated shares
    pub fn from_byte_slice(
        from: &[u8],
    ) -> impl Iterator<Item = Result<Self, <Self as Serializable>::DeserError>> + '_ {
        debug_assert!(from.len() % <AdditiveShare<V> as Serializable>::Size::USIZE == 0);

        from.chunks(<AdditiveShare<V> as Serializable>::Size::USIZE)
            .map(|chunk| Serializable::deserialize(GenericArray::from_slice(chunk)))
    }

    pub fn from_byte_slice_infallible(from: &[u8]) -> impl Iterator<Item = Self> + '_
    where
        Infallible: From<<Self as Serializable>::DeserError>,
    {
        Self::from_byte_slice(from).map(|x| x.map_err(Into::into).unwrap_infallible())
    }
}

impl<'a, 'b, V: SharedValue> Add<&'b AdditiveShare<V>> for &'a AdditiveShare<V> {
    type Output = AdditiveShare<V>;

    fn add(self, rhs: &'b AdditiveShare<V>) -> Self::Output {
        AdditiveShare(self.0 + rhs.0, self.1 + rhs.1)
    }
}

impl<V: SharedValue> Add<Self> for AdditiveShare<V> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Add::add(&self, &rhs)
    }
}

impl<V: SharedValue> Add<AdditiveShare<V>> for &AdditiveShare<V> {
    type Output = AdditiveShare<V>;

    fn add(self, rhs: AdditiveShare<V>) -> Self::Output {
        Add::add(self, &rhs)
    }
}

impl<V: SharedValue> Add<&AdditiveShare<V>> for AdditiveShare<V> {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        Add::add(&self, rhs)
    }
}

impl<V: SharedValue> AddAssign<&Self> for AdditiveShare<V> {
    fn add_assign(&mut self, rhs: &Self) {
        self.0 += rhs.0;
        self.1 += rhs.1;
    }
}

impl<V: SharedValue> AddAssign<Self> for AdditiveShare<V> {
    fn add_assign(&mut self, rhs: Self) {
        AddAssign::add_assign(self, &rhs);
    }
}

impl<V: SharedValue> Neg for &AdditiveShare<V> {
    type Output = AdditiveShare<V>;

    fn neg(self) -> Self::Output {
        AdditiveShare(-self.0, -self.1)
    }
}

impl<V: SharedValue> Neg for AdditiveShare<V> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Neg::neg(&self)
    }
}

impl<V: SharedValue> Sub<Self> for &AdditiveShare<V> {
    type Output = AdditiveShare<V>;

    fn sub(self, rhs: Self) -> Self::Output {
        AdditiveShare(self.0 - rhs.0, self.1 - rhs.1)
    }
}

impl<V: SharedValue> Sub<Self> for AdditiveShare<V> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Sub::sub(&self, &rhs)
    }
}

impl<V: SharedValue> Sub<&Self> for AdditiveShare<V> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        Sub::sub(&self, rhs)
    }
}

impl<V: SharedValue> Sub<AdditiveShare<V>> for &AdditiveShare<V> {
    type Output = AdditiveShare<V>;

    fn sub(self, rhs: AdditiveShare<V>) -> Self::Output {
        Sub::sub(self, &rhs)
    }
}

impl<V: SharedValue> SubAssign<&Self> for AdditiveShare<V> {
    fn sub_assign(&mut self, rhs: &Self) {
        self.0 -= rhs.0;
        self.1 -= rhs.1;
    }
}

impl<V: SharedValue> SubAssign<Self> for AdditiveShare<V> {
    fn sub_assign(&mut self, rhs: Self) {
        SubAssign::sub_assign(self, &rhs);
    }
}

impl<'a, 'b, F: Field> Mul<&'b F> for &'a AdditiveShare<F> {
    type Output = AdditiveShare<F>;

    fn mul(self, rhs: &'b F) -> Self::Output {
        AdditiveShare(self.0 * *rhs, self.1 * *rhs)
    }
}

impl<F: Field> Mul<F> for AdditiveShare<F> {
    type Output = Self;

    fn mul(self, rhs: F) -> Self::Output {
        Mul::mul(&self, &rhs)
    }
}

impl<F: Field> Mul<&F> for AdditiveShare<F> {
    type Output = Self;

    fn mul(self, rhs: &F) -> Self::Output {
        Mul::mul(&self, rhs)
    }
}

impl<F: Field> Mul<F> for &AdditiveShare<F> {
    type Output = AdditiveShare<F>;

    fn mul(self, rhs: F) -> Self::Output {
        Mul::mul(self, &rhs)
    }
}

impl<V: SharedValue> From<(V, V)> for AdditiveShare<V> {
    fn from(s: (V, V)) -> Self {
        AdditiveShare::new(s.0, s.1)
    }
}

impl<V: std::ops::Not<Output = V> + SharedValue> std::ops::Not for AdditiveShare<V> {
    type Output = Self;

    fn not(self) -> Self::Output {
        AdditiveShare(!(self.0), !(self.1))
    }
}

impl<V: SharedValue> Serializable for AdditiveShare<V>
where
    V::Size: Add<V::Size>,
    <V::Size as Add<V::Size>>::Output: ArrayLength,
{
    type Size = <V::Size as Add<V::Size>>::Output;
    type DeserError = <V as Serializable>::DeserError;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        let (left, right) = buf.split_at_mut(V::Size::USIZE);
        self.left().serialize(GenericArray::from_mut_slice(left));
        self.right().serialize(GenericArray::from_mut_slice(right));
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Result<Self, Self::DeserError> {
        let left = V::deserialize(GenericArray::from_slice(&buf[..V::Size::USIZE]))?;
        let right = V::deserialize(GenericArray::from_slice(&buf[V::Size::USIZE..]))?;

        Ok(Self::new(left, right))
    }
}

/// Implement `ArrayAccess` for `AdditiveShare` over `SharedValue` that implements `ArrayAccess`
impl<S> ArrayAccess for AdditiveShare<S>
where
    S: ArrayAccess + SharedValue,
    <S as ArrayAccess>::Output: SharedValue,
{
    type Output = AdditiveShare<<S as ArrayAccess>::Output>;
    type Iter<'a> = ASIterator<S::Iter<'a>>;

    fn get(&self, index: usize) -> Option<Self::Output> {
        self.0
            .get(index)
            .zip(self.1.get(index))
            .map(|v| AdditiveShare(v.0, v.1))
    }

    fn set(&mut self, index: usize, e: Self::Output) {
        self.0.set(index, e.0);
        self.1.set(index, e.1);
    }

    fn iter(&self) -> Self::Iter<'_> {
        ASIterator(self.0.iter(), self.1.iter())
    }
}

impl<S> Expand for AdditiveShare<S>
where
    S: Expand + SharedValue,
    <S as Expand>::Input: SharedValue,
{
    type Input = AdditiveShare<<S as Expand>::Input>;

    fn expand(v: &Self::Input) -> Self {
        AdditiveShare(S::expand(&v.0), S::expand(&v.1))
    }
}

impl<T> Iterator for ASIterator<T>
where
    T: Iterator,
    T::Item: SharedValue,
{
    type Item = AdditiveShare<T::Item>;

    fn next(&mut self) -> Option<Self::Item> {
        match (self.0.next(), self.1.next()) {
            (Some(left), Some(right)) => Some(AdditiveShare(left, right)),
            _ => None,
        }
    }
}

impl<S> FromIterator<AdditiveShare<<S as ArrayAccess>::Output>> for AdditiveShare<S>
where
    S: SharedValue + ArrayAccess,
    <S as ArrayAccess>::Output: SharedValue,
{
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = AdditiveShare<<S as ArrayAccess>::Output>>,
    {
        let mut result = AdditiveShare::<S>::ZERO;
        for (i, v) in iter.into_iter().enumerate() {
            result.set(i, v);
        }
        result
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use super::AdditiveShare;
    use crate::{
        ff::{Field, Fp31},
        secret_sharing::replicated::ReplicatedSecretSharing,
    };

    fn secret_share(
        a: u8,
        b: u8,
        c: u8,
    ) -> (
        AdditiveShare<Fp31>,
        AdditiveShare<Fp31>,
        AdditiveShare<Fp31>,
    ) {
        (
            AdditiveShare::new(Fp31::truncate_from(a), Fp31::truncate_from(b)),
            AdditiveShare::new(Fp31::truncate_from(b), Fp31::truncate_from(c)),
            AdditiveShare::new(Fp31::truncate_from(c), Fp31::truncate_from(a)),
        )
    }

    fn assert_valid_secret_sharing(
        res1: &AdditiveShare<Fp31>,
        res2: &AdditiveShare<Fp31>,
        res3: &AdditiveShare<Fp31>,
    ) {
        assert_eq!(res1.1, res2.0);
        assert_eq!(res2.1, res3.0);
        assert_eq!(res3.1, res1.0);
    }

    fn assert_secret_shared_value(
        a1: &AdditiveShare<Fp31>,
        a2: &AdditiveShare<Fp31>,
        a3: &AdditiveShare<Fp31>,
        expected_value: u128,
    ) {
        assert_eq!(a1.0 + a2.0 + a3.0, Fp31::truncate_from(expected_value));
        assert_eq!(a1.1 + a2.1 + a3.1, Fp31::truncate_from(expected_value));
    }

    fn addition_test_case(a: (u8, u8, u8), b: (u8, u8, u8), expected_output: u128) {
        let (a1, a2, a3) = secret_share(a.0, a.1, a.2);
        let (b1, b2, b3) = secret_share(b.0, b.1, b.2);

        // Compute r1 + r2
        let res1 = a1 + &b1;
        let res2 = a2 + &b2;
        let res3 = a3 + &b3;

        assert_valid_secret_sharing(&res1, &res2, &res3);
        assert_secret_shared_value(&res1, &res2, &res3, expected_output);
    }

    #[test]
    fn test_simple_addition() {
        addition_test_case((1, 0, 0), (1, 0, 0), 2);
        addition_test_case((1, 0, 0), (0, 1, 0), 2);
        addition_test_case((1, 0, 0), (0, 0, 1), 2);

        addition_test_case((0, 1, 0), (1, 0, 0), 2);
        addition_test_case((0, 1, 0), (0, 1, 0), 2);
        addition_test_case((0, 1, 0), (0, 0, 1), 2);

        addition_test_case((0, 0, 1), (1, 0, 0), 2);
        addition_test_case((0, 0, 1), (0, 1, 0), 2);
        addition_test_case((0, 0, 1), (0, 0, 1), 2);

        addition_test_case((0, 0, 0), (1, 0, 0), 1);
        addition_test_case((0, 0, 0), (0, 1, 0), 1);
        addition_test_case((0, 0, 0), (0, 0, 1), 1);

        addition_test_case((1, 0, 0), (0, 0, 0), 1);
        addition_test_case((0, 1, 0), (0, 0, 0), 1);
        addition_test_case((0, 0, 1), (0, 0, 0), 1);

        addition_test_case((0, 0, 0), (0, 0, 0), 0);

        addition_test_case((1, 3, 5), (10, 0, 2), 21);
    }

    fn subtraction_test_case(a: (u8, u8, u8), b: (u8, u8, u8), expected_output: u128) {
        let (a1, a2, a3) = secret_share(a.0, a.1, a.2);
        let (b1, b2, b3) = secret_share(b.0, b.1, b.2);

        // Compute r1 - r2
        let res1 = a1 - &b1;
        let res2 = a2 - &b2;
        let res3 = a3 - &b3;

        assert_valid_secret_sharing(&res1, &res2, &res3);
        assert_secret_shared_value(&res1, &res2, &res3, expected_output);
    }

    #[test]
    fn test_simple_subtraction() {
        subtraction_test_case((1, 0, 0), (1, 0, 0), 0);
        subtraction_test_case((1, 0, 0), (0, 1, 0), 0);
        subtraction_test_case((1, 0, 0), (0, 0, 1), 0);

        subtraction_test_case((0, 1, 0), (1, 0, 0), 0);
        subtraction_test_case((0, 1, 0), (0, 1, 0), 0);
        subtraction_test_case((0, 1, 0), (0, 0, 1), 0);

        subtraction_test_case((0, 0, 1), (1, 0, 0), 0);
        subtraction_test_case((0, 0, 1), (0, 1, 0), 0);
        subtraction_test_case((0, 0, 1), (0, 0, 1), 0);

        subtraction_test_case((0, 0, 0), (1, 0, 0), 30);
        subtraction_test_case((0, 0, 0), (0, 1, 0), 30);
        subtraction_test_case((0, 0, 0), (0, 0, 1), 30);

        subtraction_test_case((1, 0, 0), (0, 0, 0), 1);
        subtraction_test_case((0, 1, 0), (0, 0, 0), 1);
        subtraction_test_case((0, 0, 1), (0, 0, 0), 1);

        subtraction_test_case((0, 0, 0), (0, 0, 0), 0);

        subtraction_test_case((1, 3, 5), (10, 0, 2), 28);
    }

    fn mult_by_constant_test_case(a: (u8, u8, u8), c: u8, expected_output: u128) {
        let (a1, a2, a3) = secret_share(a.0, a.1, a.2);

        let res1 = a1 * Fp31::truncate_from(c);
        let res2 = a2 * Fp31::truncate_from(c);
        let res3 = a3 * Fp31::truncate_from(c);

        assert_valid_secret_sharing(&res1, &res2, &res3);
        assert_secret_shared_value(&res1, &res2, &res3, expected_output);
    }

    #[test]
    fn test_mult_by_constant() {
        mult_by_constant_test_case((1, 0, 0), 2, 2);
        mult_by_constant_test_case((0, 1, 0), 2, 2);
        mult_by_constant_test_case((0, 0, 1), 2, 2);
        mult_by_constant_test_case((0, 0, 0), 2, 0);
    }
}
