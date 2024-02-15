//! # Vectorization
//!
//! Vectorization refers to adapting an implementation that previously operated on one value at a
//! time, to instead operate on `N` values at a time. Vectorization improves performance in two ways:
//!
//!  1. Vectorized code can make use of special CPU instructions (Intel AVX, ARM NEON) that operate
//!     on multiple values at a time. This reduces the CPU time required to perform computations.
//!     We also use vectorization to refer to "bit packing" of boolean values, i.e., packing
//!     64 boolean values into a single u64 rather than using a byte (or even a word) for each
//!     value.
//!  2. Aside from the core arithmetic operations that are involved in our MPC, a substantial
//!     amount of other code is needed to send values between helpers, schedule futures for
//!     execution, etc. Vectorization can result in a greater amount of arithmetic work being
//!     performed for a given amount of overhead work, thus increasing the efficiency of the
//!     implementation.
//!
//! ## Vectorization traits
//!
//! There are two sets of traits related to vectorization.
//!
//! If you are writing protocols, the trait of interest is `FieldSimd<N>`, which can be specified in
//! a trait bound, something like `F: Field + FieldSimd<N>`.
//!
//! The other traits are `Vectorizable` (for `SharedValue`s) and `FieldVectorizable`. These traits
//! are needed to work around a limitation in the rust type system. See the `FieldVectorizable`
//! documentation for details.
//!
//! We require that each supported vectorization configuration (i.e. combination of data type and
//! width) be explicitly identified, by implementing the `Vectorizable` and/or `FieldVectorizable`
//! traits for base data type (e.g. `Fp32BitPrime`). This is for two reasons:
//!  1. Rust doesn't yet support evaluating expressions involving const parameters at compile time,
//!     which makes it difficult or impossible to write generic serialization routines for
//!     arbitrary widths.
//!  2. As a measure of protection against inadvertently using a configuration that will not be
//!     efficient (i.e. an excessive vector width).
//!
//! ## Adding a new supported vectorization
//!
//! To add a new supported vectorization:
//!
//!  1. Add `FieldSimd` impl (in `secret_sharing/mod.rs`)
//!  2. Add `FromRandom` impl (in `array.rs` or `boolean_array.rs`)
//!  3. Add `Serializable` impl (in `array.rs` or `boolean_array.rs`)
//!  4. Add `Vectorizable` and `FieldVectorizable` impls (with the primitive type def in e.g. `galois_field.rs`

pub mod replicated;

mod array;
mod decomposed;
mod into_shares;
mod scheme;

use std::{
    fmt::Debug,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

pub use array::StdArray;
pub(crate) use decomposed::BitDecomposed;
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

use crate::{
    error::LengthError,
    ff::{AddSub, AddSubAssign, Field, Fp32BitPrime, Serializable},
    protocol::prss::FromRandom,
};

/// Operations supported for weak shared values.
pub trait Additive<Rhs = Self, Output = Self>:
    AddSub<Rhs, Output> + AddSubAssign<Rhs> + Neg<Output = Output>
{
}

impl<T, Rhs, Output> Additive<Rhs, Output> for T where
    T: AddSub<Rhs, Output> + AddSubAssign<Rhs> + Neg<Output = Output>
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

pub trait Sendable: Send + Debug + Serializable + 'static {}

impl<V: SharedValue> Sendable for V {}

/// Trait for types that are input to our additive secret sharing scheme.
///
/// Additive secret sharing requires an addition operation. In cases where arithmetic secret sharing
/// (capable of supporting addition and multiplication) is desired, the `Field` trait extends
/// `SharedValue` to require multiplication.
pub trait SharedValue:
    Clone + Copy + Eq + Debug + Send + Sync + Sized + Additive + Sendable + Vectorizable<1> + 'static
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

// Note that we can either make `trait Vectorizable<N>: SharedValue`, or we can make `trait
// SharedValue: Vectorizable<1>`, but doing both creates a cycle. (Similarly for
// `FieldVectorizable` / `Field`.)
//
// Although it is somewhat unnatural, we choose to do the latter, because it allows existing
// high-level protocols unaware of vectorization to call vectorized versions of core protocols (with
// width of 1) without updating all of the trait bounds. This does mean that the trait definitions
// do not prevent implementing `Vectorizable` for something that is not a `SharedValue`, but please
// don't do that.

/// Trait for `SharedValue`s supporting operations on `N`-wide vectors.
pub trait Vectorizable<const N: usize>: Sized {
    type Array: SharedValueArray<Self>;
}

/// Trait for `Field`s supporting operations on `N`-wide vectors.
///
/// We would like `F` to be `FieldVectorizable` if it satisfies all of the following:
///  1. `F: Field`.
///  2. `<F as Vectorizable<N>>::Array: FieldArray<Self>`. Rust does not support expressing a
///     constraint on a super-trait's associated type directly. Instead, this effect is achieved
///     by constraining the `ArrayAlias` associated type and then constraining that
///     `Vectorizable::Array == FieldVectorizable::ArrayAlias` where necessary (e.g. in the
///     definition and blanket impl of the `FieldSimd` trait. We call it `ArrayAlias` instead of
///     `Array` so that references to the `Array` associated type do not require qualification
///     with a trait name.
///  3. `F: Vectorizable<N>`. This is implied by the previous two, because `FieldArray`
///     is a sub-trait of `SharedValueArray`.
pub trait FieldVectorizable<const N: usize>: SharedValue + Sized {
    type ArrayAlias: FieldArray<Self>;
}

// We could define a `SharedValueSimd` trait that is the analog of this for `SharedValue`s, but
// there are not currently any protocols that need it.
pub trait FieldSimd<const N: usize>:
    Field + Vectorizable<N, Array = <Self as FieldVectorizable<N>>::ArrayAlias> + FieldVectorizable<N>
{
}

// Portions of the implementation treat non-vectorized operations as a vector with `N = 1`. This
// blanket impl (and the fact that `F: Field` is the only trait bound) is important in allowing code
// that writes `F: Field` to continue working without modification.
impl<F: Field> FieldSimd<1> for F {}

// Supported vectorizations

impl FieldSimd<32> for Fp32BitPrime {}

pub trait SharedValueArray<V>:
    Clone
    + Eq
    + Debug
    + Send
    + Sync
    + Sized
    + Sendable
    + TryFrom<Vec<V>, Error = LengthError>
    + FromIterator<V>
    + IntoIterator<Item = V>
    + Add<Self, Output = Self>
    + for<'a> Add<&'a Self, Output = Self>
    + AddAssign<Self>
    + for<'a> AddAssign<&'a Self>
    + Neg<Output = Self>
    + Sub<Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + SubAssign<Self>
    + for<'a> SubAssign<&'a Self>
{
    const ZERO: Self;

    fn from_fn<F: FnMut(usize) -> V>(f: F) -> Self;
}

// Some `SharedValue` types (and thus their arrays) implement `FromRandom`, but `RP25519` does not.
// We overload this distinction on `FieldArray` instead of creating a separate `ArrayFromRandom` trait,
// to avoid making the `Vectorizable` / `FieldVectorizable` situation that much more complicated.
pub trait FieldArray<F: SharedValue>:
    SharedValueArray<F>
    + FromRandom
    + for<'a> Mul<&'a F, Output = Self>
    + for<'a> Mul<&'a Self, Output = Self>
{
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
