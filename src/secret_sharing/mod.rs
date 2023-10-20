pub mod replicated;

mod decomposed;
mod into_shares;
mod scheme;

use std::{
    fmt::Debug,
    ops::{Mul, MulAssign, Neg},
};

pub use decomposed::BitDecomposed;
use generic_array::ArrayLength;
pub use into_shares::IntoShares;
#[cfg(any(test, feature = "test-fixture", feature = "cli"))]
use rand::{
    distributions::{Distribution, Standard},
    Rng,
};
#[cfg(any(test, feature = "test-fixture", feature = "cli"))]
use replicated::{semi_honest::AdditiveShare, ReplicatedSecretSharing};
pub use scheme::{Bitwise, Linear, LinearRefOps, SecretSharing};

use crate::ff::{AddSub, AddSubAssign, Serializable};

/// Operations supported for shared values.
pub trait Arithmetic<Rhs = Self, Output = Self>:
    AddSub<Rhs, Output>
    + AddSubAssign<Rhs>
    + Mul<Rhs, Output = Output>
    + MulAssign<Rhs>
    + Neg<Output = Output>
{
}

impl<T, Rhs, Output> Arithmetic<Rhs, Output> for T where
    T: AddSub<Rhs, Output>
        + AddSubAssign<Rhs>
        + Mul<Rhs, Output = Output>
        + MulAssign<Rhs>
        + Neg<Output = Output>
{
}

// Trait for primitive integer types used to represent the underlying type for shared values
pub trait Block: Sized + Copy + Debug {
    /// Size of a block in bytes big enough to hold the shared value. `Size * 8 >= VALID_BIT_LENGTH`.
    type Size: ArrayLength;
}

pub trait SharedValue:
    Clone + Copy + PartialEq + Debug + Send + Sync + Sized + Arithmetic + Serializable + 'static
{
    type Storage: Block;

    const BITS: u32;

    const ZERO: Self;
}

#[cfg(any(test, feature = "test-fixture", feature = "cli"))]
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

#[cfg(all(test, unit_test))]
mod tests {
    use crate::{
        ff::Fp31,
        secret_sharing::{
            replicated::{malicious, semi_honest},
            Linear, LinearRefOps, SharedValue,
        },
    };

    fn arithmetic<L: Linear<V> + PartialEq, V: SharedValue>()
    where
        for<'a> &'a L: LinearRefOps<'a, L, V>,
    {
        let a = L::ZERO;
        let b = L::ZERO;

        assert_eq!(L::ZERO, &a + &b);
        assert_eq!(L::ZERO, a.clone() + &b);
        assert_eq!(L::ZERO, &a + b.clone());
        assert_eq!(L::ZERO, a + b);
    }

    fn trait_bounds<L: Linear<V> + PartialEq, V: SharedValue>()
    where
        for<'a> &'a L: LinearRefOps<'a, L, V>,
    {
        fn sum_owned<S: Linear<V>, V: SharedValue>(a: S, b: S) -> S {
            a + b
        }

        fn sum_ref_ref<S, V>(a: &S, b: &S) -> S
        where
            S: Linear<V>,
            V: SharedValue,
            for<'a> &'a S: LinearRefOps<'a, S, V>,
        {
            a + b
        }

        fn sum_owned_ref<S: Linear<V>, V: SharedValue>(a: S, b: &S) -> S {
            a + b
        }

        fn sum_ref_owned<S, V>(a: &S, b: S) -> S
        where
            S: Linear<V>,
            V: SharedValue,
            for<'a> &'a S: LinearRefOps<'a, S, V>,
        {
            a + b
        }

        assert_eq!(L::ZERO, sum_owned(L::ZERO, L::ZERO));
        assert_eq!(L::ZERO, sum_ref_ref(&L::ZERO, &L::ZERO));
        assert_eq!(L::ZERO, sum_owned_ref(L::ZERO, &L::ZERO));
        assert_eq!(L::ZERO, sum_ref_owned(&L::ZERO, L::ZERO));
    }

    #[test]
    fn semi_honest() {
        arithmetic::<semi_honest::AdditiveShare<Fp31>, _>();
        trait_bounds::<semi_honest::AdditiveShare<Fp31>, _>();
    }

    #[test]
    fn malicious() {
        arithmetic::<malicious::AdditiveShare<Fp31>, _>();
        trait_bounds::<malicious::AdditiveShare<Fp31>, _>();
    }
}
