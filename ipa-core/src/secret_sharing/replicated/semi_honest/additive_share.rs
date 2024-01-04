use std::{
    fmt::{Debug, Formatter},
    ops::{Add, AddAssign, Mul, Neg, Range, Sub, SubAssign},
};

use generic_array::{ArrayLength, GenericArray};
use typenum::Unsigned;

use crate::{
    ff::{ArrayAccess, Expand, Field, Serializable},
    secret_sharing::{
        replicated::ReplicatedSecretSharing, FieldSimd, Linear as LinearSecretSharing,
        SecretSharing, SharedValue, SharedValueArray, Vectorizable,
    },
};

/// Additive secret sharing.
///
/// `AdditiveShare` holds two out of three shares of an additive secret sharing, either of a single
/// value with type `V`, or a vector of such values.
#[derive(Clone, PartialEq, Eq)]
pub struct AdditiveShare<V: SharedValue + Vectorizable<N>, const N: usize = 1>(
    <V as Vectorizable<N>>::Array,
    <V as Vectorizable<N>>::Array,
);

#[derive(Clone, PartialEq, Eq)]
pub struct ASIterator<'a, S: SharedValue + ArrayAccess> {
    range: Range<usize>,
    share: &'a AdditiveShare<S>,
}

impl<V: SharedValue + Vectorizable<N>, const N: usize> SecretSharing<V> for AdditiveShare<V, N> {
    const ZERO: Self = Self(
        <V as Vectorizable<N>>::Array::ZERO,
        <V as Vectorizable<N>>::Array::ZERO,
    );
}

impl<F, const N: usize> LinearSecretSharing<F> for AdditiveShare<F, N> where F: Field + FieldSimd<N> {}

impl<V: SharedValue + Vectorizable<N> + Debug, const N: usize> Debug for AdditiveShare<V, N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "({:?}, {:?})", self.0, self.1)
    }
}

impl<V: SharedValue> Default for AdditiveShare<V> {
    fn default() -> Self {
        AdditiveShare::new(V::ZERO, V::ZERO)
    }
}

impl<V: SharedValue + Vectorizable<N>, const N: usize> AdditiveShare<V, N> {
    /// Replicated secret share where both left and right values are `V::ZERO`
    pub const ZERO: Self = Self(
        <V as Vectorizable<N>>::Array::ZERO,
        <V as Vectorizable<N>>::Array::ZERO,
    );
}

impl<V: SharedValue> AdditiveShare<V> {
    pub fn as_tuple(&self) -> (V, V) {
        (V::from_array(&self.0), V::from_array(&self.1))
    }
}

impl<V> ReplicatedSecretSharing<V> for AdditiveShare<V>
where
    V: SharedValue + Vectorizable<1>,
{
    fn new(a: V, b: V) -> Self {
        Self(a.into_array(), b.into_array())
    }

    fn left(&self) -> V {
        V::from_array(&self.0)
    }

    fn right(&self) -> V {
        V::from_array(&self.1)
    }
}

impl<V: SharedValue + Vectorizable<N>, const N: usize> AdditiveShare<V, N> {
    pub fn new_arr(a: <V as Vectorizable<N>>::Array, b: <V as Vectorizable<N>>::Array) -> Self {
        Self(a, b)
    }

    pub fn left_arr(&self) -> &<V as Vectorizable<N>>::Array {
        &self.0
    }

    pub fn right_arr(&self) -> &<V as Vectorizable<N>>::Array {
        &self.1
    }
}

impl<V: SharedValue> AdditiveShare<V>
where
    Self: Serializable,
{
    // Deserialize a slice of bytes into an iterator of replicated shares
    pub fn from_byte_slice(
        from: &[u8],
    ) -> impl Iterator<Item = Result<Self, <Self as Serializable>::DeserializationError>> + '_ {
        debug_assert!(from.len() % <AdditiveShare<V> as Serializable>::Size::USIZE == 0);

        from.chunks(<AdditiveShare<V> as Serializable>::Size::USIZE)
            .map(|chunk| Serializable::deserialize(GenericArray::from_slice(chunk)))
    }

    /// Same as [`from_byte_slice`] but ignores runtime errors.
    ///
    /// [`from_byte_slice`]: Self::from_byte_slice
    ///
    /// ## Panics
    /// If one or more elements fail to deserialize.
    #[cfg(any(test, unit_test))]
    pub fn from_byte_slice_unchecked(from: &[u8]) -> impl Iterator<Item = Self> + '_ {
        Self::from_byte_slice(from).map(Result::unwrap)
    }
}

impl<'a, 'b, V: SharedValue + Vectorizable<N>, const N: usize> Add<&'b AdditiveShare<V, N>>
    for &'a AdditiveShare<V, N>
{
    type Output = AdditiveShare<V, N>;

    fn add(self, rhs: &'b AdditiveShare<V, N>) -> Self::Output {
        AdditiveShare(
            Add::add(self.0.clone(), &rhs.0),
            Add::add(self.1.clone(), &rhs.1),
        )
    }
}

impl<V: SharedValue + Vectorizable<N>, const N: usize> Add<Self> for AdditiveShare<V, N> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Add::add(&self, &rhs)
    }
}

impl<V: SharedValue + Vectorizable<N>, const N: usize> Add<AdditiveShare<V, N>>
    for &AdditiveShare<V, N>
{
    type Output = AdditiveShare<V, N>;

    fn add(self, rhs: AdditiveShare<V, N>) -> Self::Output {
        Add::add(self, &rhs)
    }
}

impl<V: SharedValue + Vectorizable<N>, const N: usize> Add<&AdditiveShare<V, N>>
    for AdditiveShare<V, N>
{
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        Add::add(&self, rhs)
    }
}

impl<V: SharedValue + Vectorizable<N>, const N: usize> AddAssign<&Self> for AdditiveShare<V, N> {
    fn add_assign(&mut self, rhs: &Self) {
        self.0 += &rhs.0;
        self.1 += &rhs.1;
    }
}

impl<V: SharedValue + Vectorizable<N>, const N: usize> AddAssign<Self> for AdditiveShare<V, N> {
    fn add_assign(&mut self, rhs: Self) {
        AddAssign::add_assign(self, &rhs);
    }
}

impl<V: SharedValue + Vectorizable<N>, const N: usize> Neg for &AdditiveShare<V, N> {
    type Output = AdditiveShare<V, N>;

    fn neg(self) -> Self::Output {
        AdditiveShare(-self.0.clone(), -self.1.clone())
    }
}

impl<V: SharedValue + Vectorizable<N>, const N: usize> Neg for AdditiveShare<V, N> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Neg::neg(&self)
    }
}

impl<V: SharedValue + Vectorizable<N>, const N: usize> Sub<Self> for &AdditiveShare<V, N> {
    type Output = AdditiveShare<V, N>;

    fn sub(self, rhs: Self) -> Self::Output {
        AdditiveShare(
            Sub::sub(self.0.clone(), &rhs.0),
            Sub::sub(self.1.clone(), &rhs.1),
        )
    }
}

impl<V: SharedValue + Vectorizable<N>, const N: usize> Sub<Self> for AdditiveShare<V, N> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Sub::sub(&self, &rhs)
    }
}

impl<V: SharedValue + Vectorizable<N>, const N: usize> Sub<&Self> for AdditiveShare<V, N> {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        Sub::sub(&self, rhs)
    }
}

impl<V: SharedValue + Vectorizable<N>, const N: usize> Sub<AdditiveShare<V, N>>
    for &AdditiveShare<V, N>
{
    type Output = AdditiveShare<V, N>;

    fn sub(self, rhs: AdditiveShare<V, N>) -> Self::Output {
        Sub::sub(self, &rhs)
    }
}

impl<V: SharedValue + Vectorizable<N>, const N: usize> SubAssign<&Self> for AdditiveShare<V, N> {
    fn sub_assign(&mut self, rhs: &Self) {
        self.0 -= &rhs.0;
        self.1 -= &rhs.1;
    }
}

impl<V: SharedValue + Vectorizable<N>, const N: usize> SubAssign<Self> for AdditiveShare<V, N> {
    fn sub_assign(&mut self, rhs: Self) {
        SubAssign::sub_assign(self, &rhs);
    }
}

impl<'a, 'b, F, const N: usize> Mul<&'b F> for &'a AdditiveShare<F, N>
where
    F: Field + FieldSimd<N>,
{
    type Output = AdditiveShare<F, N>;

    fn mul(self, rhs: &'b F) -> Self::Output {
        AdditiveShare(self.0.clone() * rhs, self.1.clone() * rhs)
    }
}

impl<F: Field, const N: usize> Mul<F> for AdditiveShare<F, N>
where
    F: Field + FieldSimd<N>,
{
    type Output = Self;

    fn mul(self, rhs: F) -> Self::Output {
        Mul::mul(&self, rhs)
    }
}

impl<'a, F: Field + FieldSimd<N>, const N: usize> Mul<&'a F> for AdditiveShare<F, N> {
    type Output = Self;

    fn mul(self, rhs: &F) -> Self::Output {
        Mul::mul(&self, *rhs)
    }
}

impl<F, const N: usize> Mul<F> for &AdditiveShare<F, N>
where
    F: Field + FieldSimd<N>,
{
    type Output = AdditiveShare<F, N>;

    fn mul(self, rhs: F) -> Self::Output {
        Mul::mul(self, &rhs)
    }
}

impl<V: SharedValue> From<(V, V)> for AdditiveShare<V> {
    fn from(s: (V, V)) -> Self {
        AdditiveShare::new(s.0, s.1)
    }
}

impl<V, const N: usize> std::ops::Not for AdditiveShare<V, N>
where
    V: SharedValue + Vectorizable<N>,
    <V as Vectorizable<N>>::Array: std::ops::Not<Output = <V as Vectorizable<N>>::Array>,
{
    type Output = Self;

    fn not(self) -> Self::Output {
        AdditiveShare(!self.0, !self.1)
    }
}

impl<V: SharedValue> Serializable for AdditiveShare<V>
where
    V::Size: Add<V::Size>,
    <V::Size as Add<V::Size>>::Output: ArrayLength,
{
    type Size = <V::Size as Add<V::Size>>::Output;
    type DeserializationError = <V as Serializable>::DeserializationError;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        let (left, right) = buf.split_at_mut(V::Size::USIZE);
        self.left().serialize(GenericArray::from_mut_slice(left));
        self.right().serialize(GenericArray::from_mut_slice(right));
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Result<Self, Self::DeserializationError> {
        let left = V::deserialize(GenericArray::from_slice(&buf[..V::Size::USIZE]))?;
        let right = V::deserialize(GenericArray::from_slice(&buf[V::Size::USIZE..]))?;

        Ok(Self::new(left, right))
    }
}

/// Implement `ArrayAccess` for `AdditiveShare` over `SharedValue` that implements `ArrayAccess`
// You can think of S as a Boolean array type and V as Boolean.
impl<S, V, A> ArrayAccess for AdditiveShare<S>
where
    S: SharedValue + ArrayAccess<Output = V>,
    V: SharedValue + Vectorizable<1, Array = A>,
    A: SharedValueArray<V>,
{
    type Output = AdditiveShare<V>;
    type Iter<'a> = ASIterator<'a, S>;

    fn get(&self, index: usize) -> Option<Self::Output> {
        S::from_array(&self.0)
            .get(index)
            .zip(S::from_array(&self.1).get(index))
            .map(|v| AdditiveShare(v.0.into_array(), v.1.into_array()))
    }

    fn set(&mut self, index: usize, e: Self::Output) {
        S::from_array_mut(&mut self.0).set(index, V::from_array(&e.0));
        S::from_array_mut(&mut self.1).set(index, V::from_array(&e.1));
    }

    fn iter(&self) -> Self::Iter<'_> {
        ASIterator {
            range: Range {
                start: 0,
                end: S::from_array(&self.0).iter().len(),
            },
            share: self,
        }
    }
}

impl<S, A, T> Expand for AdditiveShare<S>
where
    S: Expand<Input = T> + SharedValue + Vectorizable<1, Array = A>,
    A: SharedValueArray<S>,
    T: SharedValue,
{
    type Input = AdditiveShare<<S as Expand>::Input>;

    fn expand(v: &Self::Input) -> Self {
        AdditiveShare(
            S::expand(&T::from_array(&v.0)).into_array(),
            S::expand(&T::from_array(&v.1)).into_array(),
        )
    }
}

impl<'a, S, T> Iterator for ASIterator<'a, S>
where
    S: SharedValue + ArrayAccess<Output = T>,
    T: SharedValue,
{
    type Item = AdditiveShare<T>;

    fn next(&mut self) -> Option<Self::Item> {
        self.range.next().map(|i| {
            AdditiveShare(
                S::from_array(&self.share.0).get(i).unwrap().into_array(),
                S::from_array(&self.share.1).get(i).unwrap().into_array(),
            )
        })
    }
}

impl<'a, S> ExactSizeIterator for ASIterator<'a, S>
where
    S: SharedValue + ArrayAccess,
    <S as ArrayAccess>::Output: SharedValue,
{
    fn len(&self) -> usize {
        self.range.len()
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
        assert_eq!(
            a1.left() + a2.left() + a3.left(),
            Fp31::truncate_from(expected_value)
        );
        assert_eq!(
            a1.right() + a2.right() + a3.right(),
            Fp31::truncate_from(expected_value)
        );
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
