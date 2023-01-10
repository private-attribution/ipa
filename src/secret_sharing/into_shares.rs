use crate::ff::Field;
use crate::rand::{thread_rng, Rng};
use crate::secret_sharing::ReplicatedAdditiveShares;
use rand::distributions::{Distribution, Standard};

pub trait IntoShares<T>: Sized {
    fn share(self) -> [T; 3] {
        self.share_with(&mut thread_rng())
    }
    fn share_with<R: Rng>(self, rng: &mut R) -> [T; 3];
}

impl<F> IntoShares<ReplicatedAdditiveShares<F>> for F
where
    F: Field,
    Standard: Distribution<F>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [ReplicatedAdditiveShares<F>; 3] {
        let x1 = rng.gen::<F>();
        let x2 = rng.gen::<F>();
        let x3 = self - (x1 + x2);

        [
            ReplicatedAdditiveShares::new(x1, x2),
            ReplicatedAdditiveShares::new(x2, x3),
            ReplicatedAdditiveShares::new(x3, x1),
        ]
    }
}

impl<U, V, T> IntoShares<Vec<T>> for V
where
    U: IntoShares<T>,
    V: IntoIterator<Item = U>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [Vec<T>; 3] {
        let it = self.into_iter();
        let (lower_bound, upper_bound) = it.size_hint();
        let len = upper_bound.unwrap_or(lower_bound);
        let mut res = [
            Vec::with_capacity(len),
            Vec::with_capacity(len),
            Vec::with_capacity(len),
        ];
        for u in it {
            for (i, s) in u.share_with(rng).into_iter().enumerate() {
                res[i].push(s);
            }
        }
        res
    }
}

// TODO: make a macro so we can use arbitrary-sized tuples
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
