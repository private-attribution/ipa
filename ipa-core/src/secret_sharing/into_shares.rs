use std::fmt::Debug;

use crate::{
    rand::{Rng, thread_rng},
    secret_sharing::BitDecomposed,
};

pub trait IntoShares<T>: Sized {
    fn share(self) -> [T; 3] {
        self.share_with(&mut thread_rng())
    }
    fn share_with<R: Rng>(self, rng: &mut R) -> [T; 3];
}

fn vec_shares<I, U, T, R>(values: I, rng: &mut R) -> [Vec<T>; 3]
where
    I: IntoIterator<Item = U>,
    U: IntoShares<T>,
    R: Rng,
{
    let (i0, (i1, i2)) = values
        .into_iter()
        .map(|v| {
            let [v0, v1, v2] = v.share_with(rng);
            (v0, (v1, v2))
        })
        .unzip();
    [i0, i1, i2]
}

impl<U, T> IntoShares<Option<T>> for Option<U>
where
    U: IntoShares<T>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [Option<T>; 3] {
        if let Some(v) = self {
            v.share_with(rng).map(|v| Some(v))
        } else {
            <[_; 3]>::default() // [None; 3] doesn't work because T: !Copy
        }
    }
}

#[cfg(test)]
impl<U, T> IntoShares<Result<T, crate::error::Error>> for Result<U, crate::error::Error>
where
    U: IntoShares<T>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [Result<T, crate::error::Error>; 3] {
        if let Ok(v) = self {
            v.share_with(rng).map(Ok)
        } else {
            // This is not great, but is sufficient for tests, and it's hard
            // to do better without `Clone` for the error type.
            std::array::from_fn(|_| Err(crate::error::Error::Internal))
        }
    }
}

impl<I, U, T> IntoShares<Vec<T>> for I
where
    I: Iterator<Item = U>,
    U: IntoShares<T>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [Vec<T>; 3] {
        vec_shares(self, rng)
    }
}

impl<U, T> IntoShares<BitDecomposed<T>> for BitDecomposed<U>
where
    U: IntoShares<T>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [BitDecomposed<T>; 3] {
        vec_shares(self, rng).map(BitDecomposed::new)
    }
}

impl<U, T, const N: usize> IntoShares<[T; N]> for [U; N]
where
    U: IntoShares<T>,
    T: Debug,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [[T; N]; 3] {
        vec_shares(self, rng).map(|x| x.try_into().unwrap())
    }
}

// TODO: make a macro so we can use arbitrary-sized tuples
impl IntoShares<()> for () {
    fn share_with<R: Rng>(self, _rng: &mut R) -> [(); 3] {
        [(), (), ()]
    }
}

impl<T, U, V, W> IntoShares<(T, U)> for (V, W)
where
    T: Sized,
    U: Sized,
    V: IntoShares<T>,
    W: IntoShares<U>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [(T, U); 3] {
        let [a0, a1, a2] = self.0.share_with(rng);
        let [b0, b1, b2] = self.1.share_with(rng);
        [(a0, b0), (a1, b1), (a2, b2)]
    }
}
