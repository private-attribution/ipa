use std::ops::Add;
use generic_array::GenericArray;
use super::{replicated::ReplicatedSecretSharing, SharedValue};
use crate::{
    rand::{thread_rng, Rng},
    secret_sharing::replicated::semi_honest::AdditiveShare,
};
use rand::distributions::{Distribution, Standard};
use crate::ff::Serializable;

pub trait IntoShares<T>: Sized {
    fn share(self) -> [T; 3] {
        self.share_with(&mut thread_rng())
    }
    fn share_with<R: Rng>(self, rng: &mut R) -> [T; 3];
}



// pub trait IntoByteShares: Sized {
//     type Share<T: AsRef<[u8]>>: IntoShares<T>;
//
//     fn share(self) -> [Vec<u8>; 3] {
//         self.share_with(&mut thread_rng())
//     }
//     fn share_with<R: Rng>(self, rng: &mut R) -> [Vec<u8>; 3];
// }

impl<V> IntoShares<AdditiveShare<V>> for V
where
    V: SharedValue,
    Standard: Distribution<V>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [AdditiveShare<V>; 3] {
        let x1 = rng.gen::<V>();
        let x2 = rng.gen::<V>();
        let x3 = self - (x1 + x2);

        [
            AdditiveShare::new(x1, x2),
            AdditiveShare::new(x2, x3),
            AdditiveShare::new(x3, x1),
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

// impl <V, T> IntoByteShares for V where V: IntoShares<T>, T: AsRef<[u8]> {
//     type Share = T;
//     fn share_with<R: Rng>(self, rng: &mut R) -> [Vec<u8>; 3] {
//         todo!()
//     }
// }

// // impl<F> IntoShares<Replicated<F>> for SparseField<F>
// impl <V: SharedValue> IntoByteShares for V {
//     type Share<V> = AdditiveShare<V>;
//
//     fn share_with<R: Rng>(self, rng: &mut R) -> [Vec<u8>; 3] {
//         todo!()
//     }
// }

// impl<V, T> IntoByteShares<T> for V
//     where
//         V: IntoShares<T>,
//         Vec<u8>: From<T>,
// {
// }

