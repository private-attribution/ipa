use std::{fmt::Debug, ops::Deref};

use crate::error::Error;

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
