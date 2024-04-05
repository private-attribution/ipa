use std::{
    fmt::{Debug, Formatter},
    marker::PhantomData,
    ops::{Add, AddAssign, Mul, Neg, Range, Sub, SubAssign},
};

use generic_array::{ArrayLength, GenericArray};
use typenum::Unsigned;

use crate::{
    ff::{ArrayAccess, ArrayAccessRef, ArrayBuild, ArrayBuilder, Expand, Field, Serializable},
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

// The `V` type parameter allows ASIterator to convert array elements to a new type before
// returning. It is used for Galois fields, which use `bool` as the native array element type.
#[derive(Clone, PartialEq, Eq)]
pub struct ASIterator<'a, S, V = <S as ArrayAccess>::Output>
where
    S: SharedValue + ArrayAccess,
    V: From<<S as ArrayAccess>::Output>,
{
    range: Range<usize>,
    share: &'a AdditiveShare<S>,
    phantom_data: PhantomData<V>,
}

impl<V: SharedValue + Vectorizable<N>, const N: usize> SecretSharing<V> for AdditiveShare<V, N> {
    const ZERO: Self = Self(
        <V as Vectorizable<N>>::Array::ZERO_ARRAY,
        <V as Vectorizable<N>>::Array::ZERO_ARRAY,
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
        <V as Vectorizable<N>>::Array::ZERO_ARRAY,
        <V as Vectorizable<N>>::Array::ZERO_ARRAY,
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

    pub(in crate::secret_sharing) fn left_arr_mut(&mut self) -> &mut <V as Vectorizable<N>>::Array {
        &mut self.0
    }

    pub(in crate::secret_sharing) fn right_arr_mut(
        &mut self,
    ) -> &mut <V as Vectorizable<N>>::Array {
        &mut self.1
    }

    pub fn from_fns<LF: FnMut(usize) -> V, RF: FnMut(usize) -> V>(lf: LF, rf: RF) -> Self {
        Self(
            <V as Vectorizable<N>>::Array::from_fn(lf),
            <V as Vectorizable<N>>::Array::from_fn(rf),
        )
    }

    // Providing this as IntoIterator results in conflicting malicious upgrade implementations for
    // AdditiveShare. It's not clear that the unpacking iterator is a universally appropriate thing
    // to return from IntoIterator anyways.
    pub fn into_unpacking_iter(self) -> UnpackIter<V, N> {
        let Self(left, right) = self;
        UnpackIter(left.into_iter(), right.into_iter())
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
            phantom_data: PhantomData,
        }
    }
}

impl<S, V, A> ArrayAccessRef for AdditiveShare<S>
where
    S: SharedValue + ArrayAccess<Output = V>,
    V: SharedValue + Vectorizable<1, Array = A>,
    A: SharedValueArray<V>,
{
    type Element = AdditiveShare<V>;
    type Ref<'a> = AdditiveShare<V>;
    type Iter<'a> = ASIterator<'a, S>;

    fn get(&self, index: usize) -> Option<Self::Ref<'_>> {
        ArrayAccess::get(self, index)
    }

    fn set(&mut self, index: usize, e: Self::Ref<'_>) {
        ArrayAccess::set(self, index, e);
    }

    fn iter(&self) -> Self::Iter<'_> {
        ArrayAccess::iter(self)
    }

    fn make_ref(src: &Self::Element) -> Self::Ref<'_> {
        src.clone()
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

impl<'a, S, V> Iterator for ASIterator<'a, S, V>
where
    S: SharedValue + ArrayAccess,
    V: SharedValue + From<<S as ArrayAccess>::Output>,
{
    type Item = AdditiveShare<V>;

    fn next(&mut self) -> Option<Self::Item> {
        self.range.next().map(|i| {
            AdditiveShare(
                V::from(S::from_array(&self.share.0).get(i).unwrap()).into_array(),
                V::from(S::from_array(&self.share.1).get(i).unwrap()).into_array(),
            )
        })
    }
}

impl<'a, S, V> ExactSizeIterator for ASIterator<'a, S, V>
where
    S: SharedValue + ArrayAccess,
    V: SharedValue + From<<S as ArrayAccess>::Output>,
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
            // Disambiguate ArrayAccess vs. ArrayAccessRef
            ArrayAccess::set(&mut result, i, v);
        }
        result
    }
}

pub struct UnpackIter<S: SharedValue + Vectorizable<N>, const N: usize>(
    <<S as Vectorizable<N>>::Array as IntoIterator>::IntoIter,
    <<S as Vectorizable<N>>::Array as IntoIterator>::IntoIter,
);

impl<S: SharedValue + Vectorizable<N>, const N: usize> Iterator for UnpackIter<S, N> {
    type Item = AdditiveShare<S>;

    fn next(&mut self) -> Option<Self::Item> {
        match (self.0.next(), self.1.next()) {
            (None, None) => None,
            (Some(left), Some(right)) => Some(AdditiveShare::new(left, right)),
            _ => unreachable!("unequal left/right length in vectorized AdditiveShare"),
        }
    }
}

pub struct AdditiveShareArrayBuilder<B>
where
    B: ArrayBuilder,
    B::Array: SharedValue,
    B::Element: SharedValue,
{
    left_builder: B,
    right_builder: B,
}

impl<B> ArrayBuilder for AdditiveShareArrayBuilder<B>
where
    B: ArrayBuilder,
    B::Array: SharedValue,
    B::Element: SharedValue,
{
    type Element = AdditiveShare<B::Element>;
    type Array = AdditiveShare<B::Array>;

    fn push(&mut self, value: Self::Element) {
        self.left_builder.push(value.left());
        self.right_builder.push(value.right());
    }

    fn build(self) -> Self::Array {
        let Self {
            left_builder,
            right_builder,
        } = self;
        AdditiveShare::new(left_builder.build(), right_builder.build())
    }
}

impl<A> ArrayBuild for AdditiveShare<A>
where
    A: SharedValue + ArrayBuild,
    <A as ArrayBuild>::Input: SharedValue,
{
    type Input = AdditiveShare<<A as ArrayBuild>::Input>;
    type Builder = AdditiveShareArrayBuilder<<A as ArrayBuild>::Builder>;

    fn builder() -> Self::Builder {
        AdditiveShareArrayBuilder {
            left_builder: A::builder(),
            right_builder: A::builder(),
        }
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use proptest::{
        prelude::{prop, Arbitrary, Strategy},
        proptest,
    };

    use crate::{
        ff::{Fp31, Fp32BitPrime, U128Conversions},
        secret_sharing::{
            replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing},
            SharedValue, StdArray, Vectorizable,
        },
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

    impl<V: SharedValue, const N: usize> Arbitrary for AdditiveShare<V, N>
    where
        V: Vectorizable<N, Array = StdArray<V, N>>,
        StdArray<V, N>: Arbitrary,
    {
        type Parameters = <(StdArray<V, N>, StdArray<V, N>) as Arbitrary>::Parameters;
        type Strategy = prop::strategy::Map<
            <(StdArray<V, N>, StdArray<V, N>) as Arbitrary>::Strategy,
            fn((StdArray<V, N>, StdArray<V, N>)) -> Self,
        >;

        fn arbitrary_with(args: Self::Parameters) -> Self::Strategy {
            <(StdArray<V, N>, StdArray<V, N>)>::arbitrary_with(args)
                .prop_map(|(l, r)| AdditiveShare::new_arr(l, r))
        }
    }

    proptest! {
        #[test]
        fn vector_add_assign_proptest(a: AdditiveShare<Fp32BitPrime, 32>, b: AdditiveShare<Fp32BitPrime, 32>) {
            let left_sum = a.left_arr() + b.left_arr();
            let right_sum = a.right_arr() + b.right_arr();
            let expected = AdditiveShare::new_arr(left_sum, right_sum);
            let mut sum1 = a.clone();
            let mut sum2 = a;
            sum1 += &b;
            sum2 += b;
            assert_eq!(sum1, expected);
            assert_eq!(sum2, expected);
        }

        #[test]
        fn sub_proptest(a: AdditiveShare<Fp32BitPrime>, b: AdditiveShare<Fp32BitPrime>) {
            let left_diff = a.left() - b.left();
            let right_diff = a.right() - b.right();
            let expected = AdditiveShare::new(left_diff, right_diff);
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
        fn vector_sub_proptest(a: AdditiveShare<Fp32BitPrime, 32>, b: AdditiveShare<Fp32BitPrime, 32>) {
            let left_diff = a.left_arr() - b.left_arr();
            let right_diff = a.right_arr() - b.right_arr();
            let expected = AdditiveShare::new_arr(left_diff, right_diff);
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
        fn vector_sub_assign_proptest(a: AdditiveShare<Fp32BitPrime, 32>, b: AdditiveShare<Fp32BitPrime, 32>) {
            let left_diff = a.left_arr() - b.left_arr();
            let right_diff = a.right_arr() - b.right_arr();
            let expected = AdditiveShare::new_arr(left_diff, right_diff);
            let mut diff1 = a.clone();
            let mut diff2 = a;
            diff1 -= &b;
            diff2 -= b;
            assert_eq!(diff1, expected);
            assert_eq!(diff2, expected);
        }

        #[test]
        fn vector_mul_scalar_proptest(a: AdditiveShare<Fp32BitPrime, 32>, b: Fp32BitPrime) {
            let left_prod = a.left_arr() * b;
            let right_prod = a.right_arr() * b;
            let expected = AdditiveShare::new_arr(left_prod, right_prod);
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
    }
}
