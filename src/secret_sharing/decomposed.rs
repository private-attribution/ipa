use std::{fmt::Debug, ops::Deref};

use crate::{
    error::Error,
    ff::PrimeField,
    secret_sharing::{Linear as LinearSecretSharing, LinearRefOps},
};

#[derive(Clone, Debug, PartialEq)]
pub struct BitDecomposed<S> {
    bits: Vec<S>,
}

impl<S> BitDecomposed<S> {
    const MAX: usize = 64;

    /// Create a new value from an iterator.
    /// # Panics
    /// If the iterator produces more than `Self::MAX` items.
    pub fn new<I: IntoIterator<Item = S>>(bits: I) -> Self {
        let bits = bits.into_iter().collect::<Vec<_>>();
        assert!(bits.len() <= Self::MAX);
        Self { bits }
    }

    /// Decompose `count` values from context, using a counter from `[0, count)`.
    /// # Panics
    /// If `count` is greater than `Self::MAX`.
    pub fn decompose<I, F>(count: I, f: F) -> Self
    where
        I: From<u8> + Copy,
        u8: TryFrom<I>,
        <u8 as TryFrom<I>>::Error: Debug,
        F: Fn(I) -> S,
    {
        let max = u8::try_from(count).unwrap();
        assert!(usize::from(max) <= Self::MAX);

        Self::try_from((0..max).map(I::from).map(f).collect::<Vec<_>>()).unwrap()
    }

    /// Translate this into a different form.
    pub fn map<F: Fn(S) -> T, T>(self, f: F) -> BitDecomposed<T> {
        BitDecomposed::new(self.bits.into_iter().map(f))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.bits.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bits.is_empty()
    }

    /// The inner vector of this type is a list any field type (e.g. Z2, Zp) and
    /// each element is (should be) a share of 1 or 0. This function iterates
    /// over the shares of bits and computes `Σ(2^i * b_i)`.
    pub fn to_additive_sharing_in_large_field<F>(&self) -> S
    where
        S: LinearSecretSharing<F>,
        for<'a> &'a S: LinearRefOps<'a, S, F>,
        F: PrimeField,
    {
        self.iter().enumerate().fold(S::ZERO, |acc, (i, b)| {
            acc + (b * F::truncate_from(1_u128 << i))
        })
    }

    // Same as above, but without the need to HRTB, as this doesn't used references
    // but rather takes ownership over the BitDecomposed
    pub fn to_additive_sharing_in_large_field_consuming<F>(bits: BitDecomposed<S>) -> S
    where
        S: LinearSecretSharing<F>,
        F: PrimeField,
    {
        bits.into_iter().enumerate().fold(S::ZERO, |acc, (i, b)| {
            acc + (b * F::truncate_from(1_u128 << i))
        })
    }
}

impl<S> TryFrom<Vec<S>> for BitDecomposed<S> {
    type Error = Error;
    fn try_from(bits: Vec<S>) -> Result<Self, Self::Error> {
        if bits.len() <= Self::MAX {
            Ok(Self { bits })
        } else {
            Err(Error::Internal)
        }
    }
}

impl<S> Deref for BitDecomposed<S> {
    type Target = [S];
    fn deref(&self) -> &Self::Target {
        &self.bits
    }
}

impl<S> IntoIterator for BitDecomposed<S> {
    type Item = S;
    type IntoIter = <Vec<S> as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        self.bits.into_iter()
    }
}
