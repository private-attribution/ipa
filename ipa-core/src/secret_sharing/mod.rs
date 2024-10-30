pub mod replicated;

mod decomposed;
mod into_shares;
mod scheme;
#[cfg(not(feature = "enable-benches"))]
mod vector;
#[cfg(feature = "enable-benches")]
pub mod vector;

use std::{
    fmt::Debug,
    ops::{Mul, MulAssign, Neg},
};

pub(crate) use decomposed::BitDecomposed;
use generic_array::ArrayLength;
pub use into_shares::IntoShares;
#[cfg(any(test, feature = "test-fixture", feature = "cli"))]
use rand::{
    distributions::{Distribution, Standard},
    Rng,
};
pub use scheme::{Bitwise, Linear, LinearRefOps, SecretSharing};
pub use vector::{
    FieldArray, FieldSimd, FieldVectorizable, SharedValueArray, StdArray, TransposeFrom,
    Vectorizable,
};

#[cfg(any(test, feature = "test-fixture", feature = "cli"))]
use crate::secret_sharing::replicated::semi_honest::AdditiveShare;
use crate::{
    ff::{AddSub, AddSubAssign, Serializable},
    secret_sharing::replicated::ReplicatedSecretSharing,
};

/// Operations supported for weak shared values.
pub trait Additive<Rhs = Self, Output = Self>:
    AddSub<Rhs, Output> + for<'a> AddSub<&'a Rhs, Output> + AddSubAssign<Rhs> + Neg<Output = Output>
{
}

impl<T, Rhs, Output> Additive<Rhs, Output> for T where
    T: AddSub<Rhs, Output>
        + for<'a> AddSub<&'a Rhs, Output>
        + AddSubAssign<Rhs>
        + Neg<Output = Output>
{
}

/// Operations supported for shared values.
pub trait Arithmetic<Rhs = Self, Output = Self>:
    Additive<Rhs, Output> + Mul<Rhs, Output = Output> + MulAssign<Rhs>
{
}

impl<T, Rhs, Output> Arithmetic<Rhs, Output> for T where
    T: Additive<Rhs, Output> + Mul<Rhs, Output = Output> + MulAssign<Rhs>
{
}

// Trait for primitive integer types used to represent the underlying type for shared values
pub trait Block: Sized + Copy + Debug {
    /// Size of a block in bytes big enough to hold the shared value. `Size * 8 >= VALID_BIT_LENGTH`.
    type Size: ArrayLength;
}

pub trait Sendable: Send + Sync + Debug + Serializable + 'static {}

impl<V: SharedValue> Sendable for V {}

/// Trait for types that are input to our additive secret sharing scheme.
///
/// Additive secret sharing requires an addition operation. In cases where arithmetic secret sharing
/// (capable of supporting addition and multiplication) is desired, the `Field` trait extends
/// `SharedValue` to require multiplication.
pub trait SharedValue:
    Clone
    + Copy
    + Default
    + Eq
    + Debug
    + Send
    + Sync
    + Sized
    + Additive
    + Sendable
    + Vectorizable<1>
    + 'static
{
    type Storage: Block;

    const BITS: u32;

    const ZERO: Self;

    // Note the trait bound of `Vectorizable<1>` here, i.e., these
    // helpers only apply to arrays of a single element.
    fn into_array(self) -> <Self as Vectorizable<1>>::Array
    where
        Self: Vectorizable<1>;

    fn from_array(array: &<Self as Vectorizable<1>>::Array) -> Self
    where
        Self: Vectorizable<1>;

    fn from_array_mut(array: &mut <Self as Vectorizable<1>>::Array) -> &mut Self
    where
        Self: Vectorizable<1>;
}

#[macro_export]
macro_rules! impl_shared_value_common {
    () => {
        // Note the trait bound of `Vectorizable<1>` here, i.e., these
        // helpers only apply to arrays of a single element.
        fn into_array(self) -> <Self as Vectorizable<1>>::Array
        where
            Self: Vectorizable<1>,
        {
            std::iter::once(self).collect()
        }

        fn from_array(array: &<Self as Vectorizable<1>>::Array) -> Self
        where
            Self: Vectorizable<1>,
        {
            *array.first()
        }

        fn from_array_mut(array: &mut <Self as Vectorizable<1>>::Array) -> &mut Self
        where
            Self: Vectorizable<1>,
        {
            array.first_mut()
        }
    };
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

#[cfg(any(test, feature = "test-fixture", feature = "cli"))]
impl<V, const N: usize> IntoShares<AdditiveShare<V, N>> for [V; N]
where
    V: SharedValue + Vectorizable<N>,
    Standard: Distribution<V>,
{
    fn share_with<R: Rng>(self, rng: &mut R) -> [AdditiveShare<V, N>; 3] {
        // For arrays large enough that the compiler doesn't just unroll everything, it might be
        // more efficient to avoid the intermediate vector by implementing this as a specialized
        // hybrid of the impls for `F as IntoShares<Replicated<F>>` and `<V: IntoIterator> as
        // IntoShares<Vec<T>>`. Not bothering since this is test-support functionality.
        let [v1, v2, v3] = self.into_iter().share_with(rng);
        let (v1l, v1r): (Vec<V>, Vec<V>) = v1.iter().map(AdditiveShare::as_tuple).unzip();
        let (v2l, v2r): (Vec<V>, Vec<V>) = v2.iter().map(AdditiveShare::as_tuple).unzip();
        let (v3l, v3r): (Vec<V>, Vec<V>) = v3.iter().map(AdditiveShare::as_tuple).unzip();
        [
            AdditiveShare::new_arr(v1l.try_into().unwrap(), v1r.try_into().unwrap()),
            AdditiveShare::new_arr(v2l.try_into().unwrap(), v2r.try_into().unwrap()),
            AdditiveShare::new_arr(v3l.try_into().unwrap(), v3r.try_into().unwrap()),
        ]
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use crate::{
        ff::{Field, Fp31},
        secret_sharing::{
            replicated::{malicious, semi_honest},
            Linear, LinearRefOps,
        },
    };

    fn arithmetic<L: Linear<F> + PartialEq, F: Field>()
    where
        for<'a> &'a L: LinearRefOps<'a, L, F>,
    {
        let a = L::ZERO;
        let b = L::ZERO;

        assert_eq!(L::ZERO, &a + &b);
        assert_eq!(L::ZERO, a.clone() + &b);
        assert_eq!(L::ZERO, &a + b.clone());
        assert_eq!(L::ZERO, a + b);
    }

    fn trait_bounds<L: Linear<F> + PartialEq, F: Field>()
    where
        for<'a> &'a L: LinearRefOps<'a, L, F>,
    {
        fn sum_owned<S: Linear<F>, F: Field>(a: S, b: S) -> S {
            a + b
        }

        fn sum_ref_ref<S, F>(a: &S, b: &S) -> S
        where
            S: Linear<F>,
            F: Field,
            for<'a> &'a S: LinearRefOps<'a, S, F>,
        {
            a + b
        }

        fn sum_owned_ref<S: Linear<F>, F: Field>(a: S, b: &S) -> S {
            a + b
        }

        fn sum_ref_owned<S, F>(a: &S, b: S) -> S
        where
            S: Linear<F>,
            F: Field,
            for<'a> &'a S: LinearRefOps<'a, S, F>,
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
